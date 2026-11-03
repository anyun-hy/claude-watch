//! Window-independent DNS/WebRTC collection. It never grants launch permission
//! or controls an application: validated receipts are consumed by the existing guard.
use crate::{
    commands::{ReadCommand, ReadRunner},
    config_store::{guard_policy_digest, ConfigStore},
    receipt_store::ReceiptStore,
    release_native::{FixedCommand, FixedCommandExecutor, FixedOutput},
    session_store::SessionStore,
    storage::{sha256, strict_json, StateStore},
};
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
    policy::PolicyCatalog,
    processes::Provider,
    session::{Desktop, Phase, Session},
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use subprocess::{Communicator, Exec, ExecExt, Job, JobExt, Redirection};

pub const WORKER: &str = "watch-leak-worker";
pub const ASSETS: [&str; 3] = [
    "netcoffee_probe.html",
    "netcoffee_probe.js",
    "netcoffee_probe.css",
];
pub const EXTRA_FILES: [&str; 4] = [WORKER, ASSETS[0], ASSETS[1], ASSETS[2]];
pub const EXTRA_FILES_V2: [&str; 6] = [
    WORKER,
    ASSETS[0],
    ASSETS[1],
    ASSETS[2],
    "ipleak_probe.html",
    "ipleak_probe.js",
];

/// Legacy five-component bundles remain recognizable for rollback. A new
/// bundle must explicitly advertise and contain the complete background set.
pub fn supported_manifest(manifest: &Value) -> Result<bool> {
    match manifest.get("BackgroundEvidenceSchema") {
        None => Ok(false),
        Some(v) if v == 1 || v == 2 => Ok(true),
        _ => Err(err("evidence_runtime_invalid", "后台检测组件版本无效")),
    }
}
pub fn extra_files(manifest: &Value) -> Result<&'static [&'static str]> {
    match manifest.get("BackgroundEvidenceSchema") {
        None => Ok(&[]),
        Some(v) if v == 1 => Ok(&EXTRA_FILES),
        Some(v) if v == 2 => Ok(&EXTRA_FILES_V2),
        _ => Err(err("evidence_runtime_invalid", "后台检测组件版本无效")),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    Dns,
    WebRtc,
}
impl ProbeKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::WebRtc => "webrtc",
        }
    }
    fn argument(self) -> &'static str {
        match self {
            Self::Dns => "--dns",
            Self::WebRtc => "--webrtc",
        }
    }
    fn refresh_age(self) -> f64 {
        match self {
            // Start early enough for the complete, bounded IPLeak round to
            // finish before the existing launch evidence expires.
            Self::Dns => 10.0,
            Self::WebRtc => 60.0,
        }
    }
}
pub trait EvidenceSystem {
    fn now(&self) -> f64;
    fn local(&mut self, config: &Config) -> Result<Value>;
    fn desktop_matches(&mut self, desktop: &Desktop) -> Result<bool>;
    fn desktop_unique_stamp(&mut self, desktop: &Desktop) -> Result<Option<String>>;
    fn collect(&mut self, kind: ProbeKind) -> Result<Value>;
    /// The full launch-grade audit runs here, never on the fast guard thread.
    fn revalidate(&mut self) -> Result<(Value, Value)> {
        Err(err("revalidation_unavailable", "新进程的完整校验不可用"))
    }
    fn cancelled(&self) -> bool {
        false
    }
    /// The service whose session is revalidated; its policy family decides
    /// what the lease records. Defaults to the supervised Claude desktop and
    /// is overridden by adapters that supervise other families.
    fn supervised_provider(&self) -> Provider {
        Provider::Claude
    }
    /// Fixed-target test/CLI adapters cannot silently collect another family.
    fn set_family(&mut self, family: &str) -> Result<()> {
        if PolicyCatalog::family_for(self.supervised_provider()).map(|f| f.id) == Some(family) {
            Ok(())
        } else {
            Err(err("evidence_family_unavailable", "证据适配器不能切换到该服务"))
        }
    }
}
fn err(code: &str, detail: &str) -> CoreError {
    CoreError::new(code, detail)
}
fn context(local: &Value) -> Option<&str> {
    if local["proxy"] != "ok"
        || local["tun"] != "ok"
        || local["observation_unavailable"]
            .as_array()
            .is_some_and(|v| !v.is_empty())
    {
        return None;
    }
    local
        .get("context_id")
        .or_else(|| local.get("context"))?
        .as_str()
        .filter(|s| !s.is_empty())
}
fn fresh(store: &StateStore, kind: ProbeKind, ctx: &str, now: f64, since: Option<f64>) -> bool {
    let (name, stamp, ctx_key) = match kind {
        ProbeKind::Dns => ("dns-leak-receipt.json", "finished_at", "context"),
        ProbeKind::WebRtc => ("webrtc-risk-receipt.json", "sampled_at", "context_id"),
    };
    store
        .read_json(&store.paths.base().join(name), Value::Null)
        .ok()
        .is_some_and(|v| {
            let receipts = ReceiptStore {
                storage: store.clone(),
            };
            let verified = match kind {
                ProbeKind::Dns => receipts.dns_status(ctx, false, now, |t| format!("{t:.0}")),
                ProbeKind::WebRtc => receipts.webrtc_status(ctx, now),
            };
            matches!(verified["state"].as_str(), Some("ok" | "fail"))
                && v["status"] == "complete"
                && v[ctx_key] == ctx
                && v[stamp].as_f64().is_some_and(|t| {
                    (0.0..kind.refresh_age()).contains(&(now - t)) && since.is_none_or(|s| t >= s)
                })
        })
}

/// A notice does not stop supervision. Only warn-only locks may refresh;
/// mandatory close/force locks stay latched and are never resumed here.
fn refreshable(session: &Session, config: &Config, provider: Provider) -> bool {
    match session.state {
        Phase::Active | Phase::Rechecking => true,
        Phase::Locked => session.reason.as_ref()
            .is_some_and(|reason| config.close_action(&reason.code, provider) == "warn"),
        Phase::Pending | Phase::Ended => false,
    }
}

/// One worker services all declared families. Receipts may be reused only
/// when their verified context and freshness match; sessions and locks never
/// cross families. A failure in one family must not starve the next one.
pub fn refresh_supervised_sessions<S: EvidenceSystem>(store: &StateStore, system: &mut S) -> Result<Value> {
    let mut reports = Vec::new();
    for family in PolicyCatalog::families() {
        if system.cancelled() { break; }
        if PolicyCatalog::guard_target(family).is_none() { continue; }
        let result = system.set_family(family.id).and_then(|()| {
            if PolicyCatalog::family_for(system.supervised_provider()).map(|f| f.id) != Some(family.id) {
                return Err(err("evidence_family_mismatch", "证据适配器与会话服务不一致"));
            }
            refresh_active_session(store, system)
        });
        let mut report = match result {
            Ok(value) => value,
            Err(error) => json!({"status":"incomplete","count":0,"code":error.code}),
        };
        report["family"] = json!(family.id);
        reports.push(report);
    }
    let has = |status: &str| reports.iter().any(|v| v["status"] == status);
    let status = if has("risk") { "risk" } else if has("incomplete") { "incomplete" }
        else if has("ok") { "ok" } else { "idle" };
    let count: u64 = reports.iter().filter_map(|v| v["count"].as_u64()).sum();
    let probes = |key: &str| -> Vec<&str> {
        ["dns", "webrtc"].into_iter().filter(|kind| reports.iter().any(|v| {
            v[key].as_array().is_some_and(|names| names.iter().any(|name| name.as_str() == Some(*kind)))
        })).collect()
    };
    Ok(json!({"status":status,"count":count,"failed_probes":probes("failed_probes"),
        "risk_probes":probes("risk_probes"),"families":reports}))
}

/// Called by one independent worker on a bounded cadence. GUI-produced fresh
/// receipts are reused, so opening the window does not double probe frequency.
pub fn refresh_active_session<S: EvidenceSystem>(
    store: &StateStore,
    system: &mut S,
) -> Result<Value> {
    let config = ConfigStore {
        storage: store.clone(),
    }
    .load()?;
    if !config.enabled || !config.guard_enabled || system.cancelled() {
        return Ok(json!({"status":"idle","count":0}));
    }
    let provider = system.supervised_provider();
    let family = PolicyCatalog::family_for(provider)
        .ok_or_else(|| err("evidence_family_unavailable", "证据服务未声明会话策略"))?;
    let sessions = SessionStore::for_family(store.clone(), family.id);
    let Some(session) = sessions
        .load(system.now())?
        .filter(|s| refreshable(s, &config, provider))
    else {
        return Ok(json!({"status":"idle","count":0}));
    };
    let Some(desktop) = session.desktop.as_ref() else {
        return Err(err("evidence_identity_unknown", "受控会话缺少主进程身份"));
    };
    if session.state != Phase::Rechecking
        && [ProbeKind::Dns, ProbeKind::WebRtc]
            .iter()
            .all(|kind| fresh(store, *kind, &session.context_id, system.now(), None))
    {
        return Ok(json!({"status":"ok","count":0,"failed_probes":[]}));
    }
    if !system.desktop_matches(desktop)? {
        return Ok(json!({"status":"idle","count":0}));
    }
    let policy = guard_policy_digest(&config)?;
    let evidence_context = if session.state == Phase::Rechecking {
        let local = system.local(&config)?;
        let current_context = context(&local)
            .ok_or_else(|| err("evidence_context_unconfirmed", "新进程网络上下文未确认"))?
            .to_owned();
        if !sessions.recheck_context(
            &session.session_id,
            desktop,
            &current_context,
            system.now(),
        )? {
            return Err(err("evidence_session_changed", "新进程会话已变化"));
        }
        current_context
    } else {
        session.context_id.clone()
    };
    let mut count = 0u32;
    let mut errors = Vec::new();
    let mut risks = Vec::new();
    for kind in [ProbeKind::Dns, ProbeKind::WebRtc] {
        if system.cancelled() {
            break;
        }
        let since = (session.state == Phase::Rechecking).then_some(session.created_at);
        if fresh(store, kind, &evidence_context, system.now(), since) {
            continue;
        }
        let before = system.local(&config)?;
        if context(&before) != Some(evidence_context.as_str()) {
            return Err(err(
                "evidence_context_unconfirmed",
                "当前网络未能与受控会话核对，未更新保护证据",
            ));
        }
        let collected = system.collect(kind);
        let current = ConfigStore {
            storage: store.clone(),
        }
        .load()?;
        if system.cancelled()
            || !current.enabled
            || !current.guard_enabled
            || guard_policy_digest(&current)? != policy
        {
            return Err(err(
                "evidence_policy_changed",
                "采集期间保护设置已变更，未覆盖回执",
            ));
        }
        let active = sessions.load(system.now())?;
        if !active.as_ref().is_some_and(|s| {
            refreshable(s, &current, provider)
                && s.context_id == evidence_context
                && s.session_id == session.session_id
                && s.desktop.as_ref() == Some(desktop)
        }) || !system.desktop_matches(desktop)?
        {
            return Err(err(
                "evidence_session_changed",
                "采集期间受控会话已变化，未覆盖回执",
            ));
        }
        let after = system.local(&current)?;
        if context(&after) != context(&before) {
            return Err(err(
                "evidence_context_changed",
                "采集前后网络身份未持续确认，未覆盖回执",
            ));
        }
        let result = collected.and_then(|probe| {
            // Use exactly the selected family's session lock. No network work
            // is performed inside it, and a newer lock/replacement wins.
            sessions.close_if_current(Some(&session.session_id), system.now(), || {
                let latest = ConfigStore { storage: store.clone() }.load()?;
                if !latest.enabled || !latest.guard_enabled || guard_policy_digest(&latest)? != policy {
                    return Err(err("evidence_policy_changed", "采集期间保护策略已变化"));
                }
                if !sessions.load(system.now())?.as_ref().is_some_and(|s| {
                    refreshable(s, &latest, provider)
                        && s.context_id == evidence_context
                        && s.desktop.as_ref() == Some(desktop)
                }) {
                    return Err(err("evidence_session_changed", "采集期间受控会话已变化"));
                }
                let receipts = ReceiptStore { storage: store.clone() };
                match kind {
                    ProbeKind::Dns => receipts.record_dns(&probe, &after, None, system.now()),
                    ProbeKind::WebRtc => receipts.record_webrtc(&probe, &after, Some(&evidence_context), system.now()),
                }
            })?.ok_or_else(|| err("evidence_session_changed", "采集期间受控会话已变化"))
        });
        match result {
            Ok(receipt) => {
                count += 1;
                let state = match kind {
                    ProbeKind::Dns => receipt.pointer("/comparison/state"),
                    ProbeKind::WebRtc => receipt.pointer("/risk/state"),
                }
                .and_then(Value::as_str);
                match state {
                    Some("fail") => risks.push(kind.label()),
                    Some("ok") => {}
                    _ => errors.push(kind.label()),
                }
            }
            Err(e) if e.code == "superseded_receipt" => {}
            Err(e)
                if matches!(
                    e.code.as_str(),
                    "evidence_session_changed" | "evidence_policy_changed"
                ) =>
            {
                return Err(e)
            }
            Err(_) => errors.push(kind.label()),
        }
    }
    if session.state == Phase::Rechecking
        && errors.is_empty()
        && risks.is_empty()
        && !system.cancelled()
    {
        let (audit, egress) = system.revalidate()?;
        let Some(stamp) = system.desktop_unique_stamp(desktop)? else {
            return Err(err("evidence_session_changed", "重新校验期间进程已变化"));
        };
        if system.cancelled() {
            return Err(err("evidence_session_changed", "重新校验期间进程已变化"));
        }
        if sessions
            .complete_recheck(
                &session.session_id,
                desktop,
                &stamp,
                &audit,
                &egress,
                system.now(),
                system.supervised_provider(),
            )?
            .is_none()
        {
            return Err(err("evidence_session_changed", "重新校验结果已过期"));
        }
    }
    Ok(
        json!({"status":if !risks.is_empty(){"risk"}else if errors.is_empty(){"ok"}else{"incomplete"},"count":count,"failed_probes":errors,"risk_probes":risks}),
    )
}

/// One resident helper, owned only by the evidence thread. Requests remain
/// bounded and correlated; a timeout or damaged channel discards the helper.
pub struct ProbeExecutor {
    stop: Arc<AtomicBool>,
    diagnostics: Option<StateStore>,
    resident: Option<ResidentProbe>,
}
#[derive(PartialEq, Eq)]
struct WorkerStamp {
    path: PathBuf,
    binary: (u64, u64, u64, i64, i64),
    manifest: Option<String>,
}
impl WorkerStamp {
    fn read(path: &std::path::Path) -> Result<Self> {
        let stamp = |m: fs::Metadata| (m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec());
        let binary = fs::symlink_metadata(path)
            .map_err(|_| err("evidence_worker_unavailable", "后台检测组件不可读取"))?;
        if !binary.is_file() || binary.file_type().is_symlink() {
            return Err(err("evidence_runtime_invalid", "后台检测组件不是普通文件"));
        }
        let manifest = match fs::File::open(path.with_file_name("BuildInfo.plist")) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(256 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| err("evidence_runtime_invalid", "后台检测清单不可读取"))?;
                if bytes.len() > 256 * 1024 {
                    return Err(err("evidence_runtime_invalid", "后台检测清单超限"));
                }
                Some(sha256(&bytes))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return Err(err("evidence_runtime_invalid", "后台检测清单不可读取")),
        };
        Ok(Self {
            path: path.into(),
            binary: stamp(binary),
            manifest,
        })
    }
}
struct ResidentProbe {
    job: Option<Job>,
    input: fs::File,
    io: Option<Communicator>,
    stamp: WorkerStamp,
}
fn stop_group(job: &Job) {
    // Signal before reaping: the still-owned leader reserves the group ID.
    let _ = job.send_signal_group(signal_hook::consts::SIGTERM);
    std::thread::sleep(Duration::from_millis(200));
    let _ = job.send_signal_group(signal_hook::consts::SIGKILL);
    if !matches!(job.wait_timeout(Duration::from_millis(500)), Ok(Some(_))) {
        job.detach();
    }
}
impl Drop for ResidentProbe {
    fn drop(&mut self) {
        if let Some(job) = self.job.take() {
            stop_group(&job);
        }
    }
}
impl ResidentProbe {
    fn spawn(stamp: WorkerStamp) -> Result<Self> {
        let mut job = Exec::cmd(&stamp.path)
            .args(["--serve"])
            .setpgid()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(Redirection::Pipe)
            .stdout(Redirection::Pipe)
            .stderr(Redirection::Pipe)
            .start()
            .map_err(|_| err("evidence_worker_unavailable", "后台检测组件无法启动"))?;
        let input = job.stdin.take();
        let io = job.communicate();
        match (input, io) {
            (Some(input), Ok(io)) => Ok(Self {
                job: Some(job),
                input,
                io: Some(io),
                stamp,
            }),
            _ => {
                stop_group(&job);
                Err(err("evidence_probe_failed", "后台检测通道不可用"))
            }
        }
    }
    fn frame(
        &mut self,
        stop: &AtomicBool,
        deadline: Instant,
        errors: &mut Vec<u8>,
    ) -> Result<Value> {
        let mut io = self
            .io
            .take()
            .ok_or_else(|| err("evidence_probe_failed", "后台检测通道已关闭"))?
            .limit_time(Duration::from_millis(100));
        let mut out = Vec::new();
        let result = loop {
            if stop.load(Ordering::Acquire) {
                break Err(err("evidence_cancelled", "后台检测已停止"));
            }
            if Instant::now() >= deadline {
                break Err(err("evidence_probe_timeout", "后台检测超过时限"));
            }
            io = io.limit_size(1_048_577usize.saturating_sub(out.len() + errors.len()));
            let read = io.read_to(&mut out, &mut *errors);
            if out.len() + errors.len() > 1_048_576 {
                break Err(err("evidence_probe_oversize", "后台检测输出超限"));
            }
            if let Some(end) = out.iter().position(|b| *b == b'\n') {
                if out[end + 1..].iter().any(|b| !b.is_ascii_whitespace()) {
                    break Err(err("evidence_probe_invalid", "后台检测返回了多余消息"));
                }
                break strict_json(&out[..end])
                    .map_err(|_| err("evidence_probe_invalid", "后台检测消息无效"));
            }
            match read {
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                _ => {
                    break Err(err(
                        "evidence_probe_failed",
                        "后台检测组件提前退出或通道失败",
                    ))
                }
            }
        };
        self.io = Some(io);
        result
    }
}
impl ProbeExecutor {
    pub fn new(stop: Arc<AtomicBool>) -> Self {
        Self {
            stop,
            diagnostics: None,
            resident: None,
        }
    }
    pub fn with_diagnostics(mut self, store: StateStore) -> Self {
        self.diagnostics = Some(store);
        self
    }
    fn record_trace(&self, kind: &str, run: &str, started: f64, raw: &[u8], incomplete: bool) {
        let Some(store) = &self.diagnostics else {
            return;
        };
        let events = crate::events::EventStore::new(store.clone());
        let mut recorded = 0;
        for line in raw.split(|b| *b == b'\n').take(4096) {
            if recorded >= 64 {
                break;
            }
            let Ok(v) = serde_json::from_slice::<Value>(line) else {
                continue;
            };
            if v["request_id"] != run {
                continue;
            }
            let (Some(event), Some(attached), Some(ms)) = (
                v["cw_trace"].as_str(),
                v["attached"].as_bool(),
                v["elapsed_ms"].as_f64(),
            ) else {
                continue;
            };
            if !incomplete && !matches!(event, "http_retry" | "view_reused") {
                continue;
            }
            if !(0.0..=120_000.0).contains(&ms) {
                continue;
            }
            if events
                .record_worker_trace(
                    kind,
                    run,
                    event,
                    attached,
                    ms / 1000.0,
                    started + ms / 1000.0,
                )
                .is_ok()
            {
                recorded += 1;
            }
        }
    }
}
impl FixedCommandExecutor for ProbeExecutor {
    fn run(&mut self, command: FixedCommand) -> Result<FixedOutput> {
        if command.program.file_name().and_then(|v| v.to_str()) != Some(WORKER)
            || !command.program.is_absolute()
            || command.timeout.is_zero()
            || command.timeout > Duration::from_secs(80)
            || !(command.args == ["--dns"] || command.args == ["--webrtc"])
        {
            return Err(err("evidence_command_invalid", "后台检测命令不是固定入口"));
        }
        let kind = if command.args == ["--dns"] {
            "dns"
        } else {
            "webrtc"
        };
        let run = uuid::Uuid::new_v4().to_string();
        let mut started = crate::native::now();
        let mut errors = Vec::new();
        let deadline = Instant::now() + command.timeout;
        let result = (|| {
            if self.stop.load(Ordering::Acquire) {
                return Err(err("evidence_cancelled", "后台检测已停止"));
            }
            let stamp = WorkerStamp::read(&command.program)?;
            if !self.resident.as_ref().is_some_and(|r| r.stamp == stamp) {
                self.resident = None;
                self.resident = Some(ResidentProbe::spawn(stamp)?);
                let ready =
                    self.resident
                        .as_mut()
                        .unwrap()
                        .frame(&self.stop, deadline, &mut errors)?;
                if ready != json!({"schema":1,"ready":true}) {
                    return Err(err("evidence_probe_invalid", "后台检测组件不支持常驻协议"));
                }
                errors.clear();
            }
            started = crate::native::now();
            let worker = self.resident.as_mut().unwrap();
            let request = format!("{}\n", json!({"schema":1,"id":run,"kind":kind}));
            worker
                .input
                .write_all(request.as_bytes())
                .and_then(|_| worker.input.flush())
                .map_err(|_| err("evidence_probe_failed", "后台检测请求无法发送"))?;
            let response = worker.frame(&self.stop, deadline, &mut errors)?;
            if response["schema"] != 1
                || response["id"] != run
                || response["kind"] != kind
                || !response["result"].is_object()
                || response["result"]["kind"] != kind
                || response.as_object().is_none_or(|v| v.len() != 4)
            {
                return Err(err("evidence_probe_invalid", "后台检测结果轮次或类型不符"));
            }
            Ok(FixedOutput {
                status: 0,
                stdout: response["result"].to_string(),
                stderr: String::new(),
            })
        })();
        let incomplete = result.as_ref().map_or(true, |out| {
            serde_json::from_str::<Value>(&out.stdout)
                .ok()
                .is_none_or(|v| {
                    v["status"] != "complete"
                        || v["errors"].as_array().is_none_or(|e| !e.is_empty())
                })
        });
        if incomplete {
            self.resident = None;
        }
        self.record_trace(kind, &run, started, &errors, incomplete);
        result
    }
}

/// Check the installed manifest and fixed files before executing the helper.
/// Paths and arguments are never supplied by an API response or preference.
pub fn collect_native<R: ReadRunner, E: FixedCommandExecutor>(
    store: &StateStore,
    reader: &R,
    executor: &mut E,
    kind: ProbeKind,
) -> Result<Value> {
    let runtime = store.paths.watch().join("runtime");
    let manifest_path = runtime.join("BuildInfo.plist");
    store.guarded(&manifest_path)?;
    let uid = fs::metadata(&store.paths.home)
        .map_err(|_| err("evidence_runtime_invalid", "运行用户不可确认"))?
        .uid();
    let output = reader.run(
        ReadCommand::Plist(manifest_path),
        &[],
        Duration::from_secs(3),
        256 * 1024,
    )?;
    if output.status != 0 {
        return Err(err("evidence_runtime_invalid", "后台检测清单不可读取"));
    }
    let manifest = strict_json(&output.stdout)?;
    if manifest["BackendVariant"] != "rust-candidate"
        || manifest["RuntimeSchema"] != 2
        || manifest["Architecture"] != "arm64"
        || uid == 0
        || !supported_manifest(&manifest)?
    {
        return Err(err("evidence_runtime_invalid", "后台检测运行清单无效"));
    }
    for name in extra_files(&manifest)?
        .iter()
        .copied()
        .chain(["watch-engine"])
    {
        let path = runtime.join(name);
        store.guarded(&path)?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| err("evidence_worker_missing", "缺少后台检测组件"))?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.mode() & 0o022 != 0
            || (matches!(name, WORKER | "watch-engine") && metadata.mode() & 0o100 == 0)
        {
            return Err(err(
                "evidence_runtime_invalid",
                "后台检测组件身份或权限无效",
            ));
        }
        let bytes = store
            .read_bytes(&path, 128 * 1024 * 1024)?
            .ok_or_else(|| err("evidence_worker_missing", "缺少后台检测组件"))?;
        if manifest["RuntimeHashes"][name] != sha256(&bytes) {
            return Err(err("evidence_runtime_invalid", "后台检测组件校验失败"));
        }
    }
    let output = executor.run(FixedCommand {
        program: runtime.join(WORKER),
        args: vec![kind.argument().into()],
        timeout: Duration::from_secs(80),
    })?;
    if output.status != 0 || output.stdout.len() > 1_048_576 {
        return Err(err("evidence_probe_failed", "后台检测未完成"));
    }
    let probe = strict_json(output.stdout.as_bytes())?;
    if probe["kind"] != kind.label() {
        return Err(err("evidence_probe_invalid", "后台检测结果类型不符"));
    }
    Ok(probe)
}
