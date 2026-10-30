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
    session::{Desktop, Phase},
};
use serde_json::{json, Value};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use subprocess::{Exec, ExecExt, Job, JobExt, Redirection};

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
    fn collect(&mut self, kind: ProbeKind) -> Result<Value>;
    fn cancelled(&self) -> bool {
        false
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
fn fresh(store: &StateStore, kind: ProbeKind, ctx: &str, now: f64) -> bool {
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
                && v[stamp]
                    .as_f64()
                    .is_some_and(|t| (0.0..kind.refresh_age()).contains(&(now - t)))
        })
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
    let sessions = SessionStore::new(store.clone());
    let Some(session) = sessions
        .load(system.now())?
        .filter(|s| s.state == Phase::Active)
    else {
        return Ok(json!({"status":"idle","count":0}));
    };
    let Some(desktop) = session.desktop.as_ref() else {
        return Err(err("evidence_identity_unknown", "受控会话缺少主进程身份"));
    };
    if [ProbeKind::Dns, ProbeKind::WebRtc]
        .iter()
        .all(|kind| fresh(store, *kind, &session.context_id, system.now()))
    {
        return Ok(json!({"status":"ok","count":0,"failed_probes":[]}));
    }
    if !system.desktop_matches(desktop)? {
        return Ok(json!({"status":"idle","count":0}));
    }
    let policy = guard_policy_digest(&config)?;
    let mut count = 0u32;
    let mut errors = Vec::new();
    let mut risks = Vec::new();
    for kind in [ProbeKind::Dns, ProbeKind::WebRtc] {
        if system.cancelled() {
            break;
        }
        if fresh(store, kind, &session.context_id, system.now()) {
            continue;
        }
        let before = system.local(&config)?;
        if context(&before) != Some(session.context_id.as_str()) {
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
            s.state == Phase::Active
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
            // Serialise the final session check with replacement/locking of a
            // session. The network observations above remain outside this lock.
            let _session_lock = store.lock("session-guard", None)?;
            if !sessions.load(system.now())?.as_ref().is_some_and(|s| {
                s.state == Phase::Active
                    && s.session_id == session.session_id
                    && s.desktop.as_ref() == Some(desktop)
            }) {
                return Err(err("evidence_session_changed", "采集期间受控会话已变化"));
            }
            if guard_policy_digest(
                &ConfigStore {
                    storage: store.clone(),
                }
                .load()?,
            )? != policy
            {
                return Err(err("evidence_policy_changed", "采集期间保护策略已变化"));
            }
            let receipts = ReceiptStore {
                storage: store.clone(),
            };
            match kind {
                // The two verified local observations bind this background
                // collection; no UI token or cached context is trusted here.
                ProbeKind::Dns => receipts.record_dns(&probe, &after, None, system.now()),
                ProbeKind::WebRtc => {
                    receipts.record_webrtc(&probe, &after, Some(&session.context_id), system.now())
                }
            }
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
    Ok(
        json!({"status":if !risks.is_empty(){"risk"}else if errors.is_empty(){"ok"}else{"incomplete"},"count":count,"failed_probes":errors,"risk_probes":risks}),
    )
}

/// One owned process group, cancellable without waiting for a long probe.
/// Signals only the group created here, before reaping its leader (PID reuse
/// cannot retarget an unrelated group). The worker's CoffeeRequest children
/// inherit this group and cannot outlive a timeout or daemon shutdown.
pub struct ProbeExecutor {
    stop: Arc<AtomicBool>,
    diagnostics: Option<StateStore>,
}
impl ProbeExecutor {
    pub fn new(stop: Arc<AtomicBool>) -> Self {
        Self { stop, diagnostics: None }
    }
    pub fn with_diagnostics(mut self, store: StateStore) -> Self {
        self.diagnostics = Some(store);
        self
    }
}
fn stop_group(job: &Job) {
    let _ = job.send_signal_group(signal_hook::consts::SIGTERM);
    std::thread::sleep(Duration::from_millis(200));
    let _ = job.send_signal_group(signal_hook::consts::SIGKILL);
    if !matches!(job.wait_timeout(Duration::from_millis(500)), Ok(Some(_))) {
        job.detach();
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
        if self.stop.load(Ordering::Acquire) {
            return Err(err("evidence_cancelled", "后台检测已停止"));
        }
        let mut job = Exec::cmd(&command.program)
            .args(&command.args)
            .setpgid()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdout(Redirection::Pipe)
            .stderr(Redirection::Pipe)
            .start()
            .map_err(|_| err("evidence_worker_unavailable", "后台检测组件无法启动"))?;
        let started_at = crate::native::now();
        let mut error_output = Vec::new();
        let result = (|| -> Result<FixedOutput> {
            let mut io = job
                .communicate()
                .map_err(|_| err("evidence_probe_failed", "后台检测通道不可用"))?
                .limit_time(Duration::from_millis(100));
            let deadline = Instant::now() + command.timeout;
            let mut out = Vec::new();
            loop {
                if self.stop.load(Ordering::Acquire) {
                    return Err(err("evidence_cancelled", "后台检测已停止"));
                }
                if Instant::now() >= deadline {
                    return Err(err("evidence_probe_timeout", "后台检测超过时限"));
                }
                let remaining = 1_048_577usize.saturating_sub(out.len() + error_output.len());
                io = io.limit_size(remaining);
                let read = io.read_to(&mut out, &mut error_output);
                if out.len() + error_output.len() > 1_048_576 {
                    return Err(err("evidence_probe_oversize", "后台检测输出超限"));
                }
                match read {
                    Ok(()) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                    Err(_) => return Err(err("evidence_probe_failed", "后台检测通道失败")),
                }
            }
            // EOF is the protocol end. Clean up any descendant before reaping
            // the group leader, including a worker that crashed unexpectedly.
            let _ = job.send_signal_group(signal_hook::consts::SIGTERM);
            std::thread::sleep(Duration::from_millis(100));
            let _ = job.send_signal_group(signal_hook::consts::SIGKILL);
            let status = job
                .wait_timeout(Duration::from_millis(500))
                .ok()
                .flatten()
                .ok_or_else(|| err("evidence_probe_failed", "后台检测组件未退出"))?;
            Ok(FixedOutput {
                status: status.code().map(|v| v as i32).unwrap_or(-1),
                stdout: String::from_utf8(out)
                    .map_err(|_| err("evidence_probe_invalid", "后台检测结果编码无效"))?,
                stderr: String::new(),
            })
        })();
        if result.is_err() {
            stop_group(&job);
        }
        // Keep detailed worker phases for an unsuccessful collection, and
        // retain the single bounded HTTP-retry event even after recovery.
        // stderr can contain system output: accept only the fixed JSON fields
        // and event vocabulary, never persist arbitrary stderr text.
        let incomplete = result.as_ref().map_or(true, |output| {
            output.status != 0 || serde_json::from_str::<Value>(&output.stdout).ok()
                .and_then(|value| value["status"].as_str().map(str::to_owned))
                .as_deref() != Some("complete")
        });
        if incomplete || !error_output.is_empty() {
            if let Some(store) = &self.diagnostics {
                let events = crate::events::EventStore::new(store.clone());
                let run = uuid::Uuid::new_v4().to_string();
                let kind = if command.args == ["--dns"] { "dns" } else { "webrtc" };
                let mut recorded = 0;
                for line in error_output.split(|b| *b == b'\n').take(4096) {
                    if recorded >= 64 { break; }
                    let Ok(value) = serde_json::from_slice::<Value>(line) else { continue };
                    let (Some(event), Some(attached), Some(ms)) = (value["cw_trace"].as_str(), value["attached"].as_bool(), value["elapsed_ms"].as_f64()) else { continue };
                    if !incomplete && event != "http_retry" { continue; }
                    if !(0.0..=120_000.0).contains(&ms) { continue; }
                    if events.record_worker_trace(kind, &run, event, attached, ms / 1000.0, started_at + ms / 1000.0).is_ok() {
                        recorded += 1;
                    }
                }
            }
        }
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
