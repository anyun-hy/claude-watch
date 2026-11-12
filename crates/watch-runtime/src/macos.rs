//! Production macOS facts and explicitly authorized OS adapters.
#![forbid(unsafe_code)]

use crate::{
    audit_store::AuditSystem,
    commands::{ReadCommand, ReadRunner, ServiceLabel},
    native::{self, Observer},
    network_client::{NetworkClient, Transport},
    onboarding::OnboardingSystem,
    repair::RepairSystem,
    sampler::{pinned_node, ProcessRound, Sampler, SocketRound},
    services::ServiceSystem,
    storage::{sha256, StateStore},
};
use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, io::Read, os::unix::fs::{MetadataExt, OpenOptionsExt}, time::Duration};

/// Match complete executable prefixes, never a display name or command argument.
pub(crate) fn proxy_mode(executable: &str) -> Option<&'static str> {
    for (mode, prefixes) in [
        ("tag", &["/Applications/TAG.app/Contents/"][..]),
        (
            "clash-verge",
            &[
                "/Applications/Clash Verge.app/Contents/",
                "/Library/PrivilegedHelperTools/io.github.clash-verge",
            ][..],
        ),
        ("shadowrocket", &["/Applications/Shadowrocket.app/"][..]),
        (
            "sing-box",
            &[
                "/opt/homebrew/Cellar/sing-box/",
                "/usr/local/Cellar/sing-box/",
                "/usr/local/bin/sing-box",
            ][..],
        ),
        (
            "clashx",
            &[
                "/Applications/ClashX.app/",
                "/Library/PrivilegedHelperTools/com.west2online.ClashX",
            ][..],
        ),
        (
            "surge",
            &[
                "/Applications/Surge.app/",
                "/Library/PrivilegedHelperTools/com.nssurge.",
            ][..],
        ),
    ] {
        if prefixes.iter().any(|prefix| executable.starts_with(prefix))
            && (!matches!(mode, "tag" | "clash-verge")
                || executable
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .contains("mihomo"))
        {
            return Some(mode);
        }
    }
    None
}

fn route_interface(route: &str) -> Option<&str> {
    route
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
        .filter(|v| !v.is_empty())
}

fn fake_ip_interface(interfaces: &str, wanted: &str) -> bool {
    let mut current = "";
    for line in interfaces.lines() {
        if !line.starts_with(char::is_whitespace) {
            current = line.split(':').next().unwrap_or("");
        } else if current == wanted {
            let mut fields = line.split_whitespace();
            if fields.next() == Some("inet")
                && fields.next().is_some_and(|ip| {
                    ip.parse::<std::net::Ipv4Addr>()
                        .is_ok_and(|ip| ip.octets()[0] == 198 && matches!(ip.octets()[1], 18 | 19))
                })
            {
                return true;
            }
        }
    }
    false
}

pub use crate::macos_mutations::FixedMacosMutator;

/// Writes are impossible unless the host explicitly hands this adapter a
/// permit. The desktop's normal read-only construction uses `ReadOnly`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    ReadOnly,
    ExplicitPermit,
}
pub trait Mutator: Send {
    fn apply(&mut self, action: &Value) -> Result<()>;
    fn restore(&mut self, action: &Value) -> Result<bool>;
}
pub struct Macos<R: ReadRunner, T: Transport, M: Mutator> {
    pub runner: R,
    pub network: NetworkClient<T>,
    pub storage: StateStore,
    pub authority: Authority,
    pub mutator: M,
    pub probes: std::sync::Arc<dyn crate::online_probes::OnlineProbes>,
}

fn observed_identity(identity: &claude_watch_system::ProcessKernelIdentity) -> Value {
    json!({"pid":identity.pid,"uid":identity.uid,"executable":identity.executable_path,
        "start_seconds":identity.start_seconds,"start_microseconds":identity.start_microseconds,"audit_token":identity.audit_token})
}

fn guard_process_candidate(row: &Value, uid: u32, backend: &std::path::Path) -> bool {
    let executable = row["executable"].as_str().unwrap_or("");
    ((row["uid"] == 0 || row["uid"] == uid) && proxy_mode(executable).is_some())
        || Some(executable) == backend.to_str()
}

/// Compare only the proxy/backend set from an in-flight round with a newer
/// primary observation. Missing or stale input is never an unchanged context.
pub fn guard_round_matches(current: &ProcessRound, newer: &ProcessRound, backend: &std::path::Path) -> bool {
    let context = |round: &ProcessRound| -> Option<Value> {
        let observation = round.system_processes.as_ref()?;
        let now = native::now();
        if ![round.observed_at, observation.observed_at].iter()
            .all(|at| (0.0..=crate::process_disposition::INTENT_TTL).contains(&(now - at))) { return None; }
        let processes = observation.processes.as_ref().ok()?.iter()
            .filter(|(_, row)| guard_process_candidate(row, round.uid, backend))
            .map(|(pid, row)| json!({"pid":pid,"uid":row["uid"],"executable":row["executable"],"stamp":row["stamp"],
                "birth":if row["uid"] == 0 { observation.root_starts.get(pid).map(|start| json!(start)) }
                    else { round.identities.get(pid).map(|identity| json!((identity.start_seconds,identity.start_microseconds))) }}))
            .collect::<Vec<_>>();
        Some(json!({"uid":round.uid,"processes":processes}))
    };
    context(current).zip(context(newer)).is_some_and(|(current, newer)| current == newer)
}

struct BackendFacts {
    sampling_healthy: bool,
    guard_healthy: bool,
    sampling_native: bool,
    guard_native: bool,
    sampling_detail: &'static str,
    guard_detail: &'static str,
    diagnostics: Value,
}

/// A fresh observation and independently verified backend are both required;
/// a matching policy alone never makes an unhealthy guard ready.
pub fn guard_heartbeat_confirmed(
    config: &Config,
    backend: bool,
    now: f64,
    heartbeat: &Value,
) -> bool {
    let age = heartbeat["time"].as_f64().map(|time| now - time);
    config.enabled
        && config.guard_enabled
        && backend
        && age.is_some_and(|age| (0.0..=35.0).contains(&age))
        && heartbeat["status"] == "ok"
        && crate::config_store::guard_heartbeat_policy_matches(heartbeat, config) == Some(true)
}

/// The service pulse is independent of collector completion. A present but
/// invalid pulse cannot fall back to an older sampling heartbeat.
fn guard_service_pulse(pulse: &Value, pid: u32, stamp: &str, sample_fresh: bool, now: f64) -> bool {
    if pulse.is_null() { return sample_fresh; }
    pulse["schema"] == 1 && pulse["pid"] == pid
        && pulse["start_stamp"].as_str().is_some_and(|s| s.split_whitespace().eq(stamp.split_whitespace()))
        && pulse["time"].as_f64().is_some_and(|at| at.is_finite() && (0.0..=15.0).contains(&(now - at)))
}

#[cfg(test)]
mod service_liveness_tests {
    use super::*;
    #[test]
    fn authority_pulse_survives_slow_sampling_without_refreshing_protection_evidence() {
        let pulse = json!({"schema":1,"pid":42,"start_stamp":"same-start","time":999.0});
        assert!(guard_service_pulse(&pulse,42,"same-start",false,1000.0));
        let config = Config { enabled:true, guard_enabled:true, ..Config::default_for_new_install() };
        let evidence = json!({"status":"ok","time":900.0,"completed_at":1000.0,
            "guard_policy_v1":crate::config_store::guard_policy_digest(&config).unwrap()});
        assert!(!guard_heartbeat_confirmed(&config,true,1000.0,&evidence));
        assert!(!guard_service_pulse(&pulse,42,"same-start",true,1015.0));
        assert!(!guard_service_pulse(&pulse,43,"same-start",true,1000.0));
        assert!(!guard_service_pulse(&pulse,42,"reused-pid",true,1000.0));
        assert!(!guard_service_pulse(&pulse,42,"same-start",true,998.0));
        assert!(!guard_service_pulse(&json!({"invalid":true}),42,"same-start",true,1000.0));
        assert!(guard_service_pulse(&Value::Null,42,"same-start",true,1000.0));
        assert!(!guard_service_pulse(&Value::Null,42,"same-start",false,1000.0));
    }
}

/// Observe the original tool's existing receipt only. This never installs,
/// starts, configures, or writes to that independent service.
pub fn read_original_guard_receipt(path: &std::path::Path, expected_uid: u32) -> Option<Value> {
    // The independent writer replaces this file atomically every second. One
    // bounded retry handles a rename during the metadata sandwich without
    // relaxing ownership, no-follow, size, or content validation.
    (0..2).find_map(|_| read_original_guard_receipt_once(path, expected_uid))
}

fn read_original_guard_receipt_once(path: &std::path::Path, expected_uid: u32) -> Option<Value> {
    #[cfg(target_os = "macos")]
    const NOFOLLOW: i32 = 0x100;
    #[cfg(not(target_os = "macos"))]
    const NOFOLLOW: i32 = 0x20000;
    let before = fs::symlink_metadata(path).ok()?;
    let trusted = |m: &fs::Metadata| m.is_file() && !m.file_type().is_symlink()
        && m.uid() == expected_uid && m.mode() & 0o022 == 0 && m.len() > 0 && m.len() <= 4096;
    if !trusted(&before) { return None; }
    let file = fs::OpenOptions::new().read(true).custom_flags(NOFOLLOW).open(path).ok()?;
    let opened = file.metadata().ok()?;
    if !trusted(&opened) || before.dev() != opened.dev() || before.ino() != opened.ino() { return None; }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes).ok()?;
    let after = fs::symlink_metadata(path).ok()?;
    if bytes.len() > 4096 || !trusted(&after) || before.dev() != after.dev()
        || before.ino() != after.ino() || before.mode() != after.mode()
        || before.mtime() != after.mtime() || before.mtime_nsec() != after.mtime_nsec()
        || before.len() != after.len() { return None; }
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(&bytes).ok()?.lines() {
        let (key, value) = line.split_once('=')?;
        if fields.insert(key, value).is_some() { return None; }
    }
    if fields.get("schema") != Some(&"1") { return None; }
    let at = fields.get("time")?.parse::<f64>().ok()?;
    if !at.is_finite() || at <= 0.0 { return None; }
    let mode = *fields.get("mode")?;
    let result = *fields.get("result")?;
    if mode.is_empty() || mode.len() > 32 || !mode.bytes().all(|v| v.is_ascii_alphanumeric() || v == b'-')
        || result.is_empty() || result.len() > 64 || !result.bytes().all(|v| v.is_ascii_alphanumeric() || matches!(v, b'-' | b'_')) { return None; }
    Some(json!({"schema":1,"time":at,"mode":mode,"result":result}))
}
impl<R: ReadRunner, T: Transport, M: Mutator> Macos<R, T, M> {
    pub fn environment(&self) -> Result<Value> {
        Observer {
            runner: &self.runner,
        }
        .environment()
    }
    fn read(&self, command: ReadCommand) -> Option<String> {
        let output = self
            .runner
            .run(command, &[], Duration::from_secs(3), 256 * 1024)
            .ok()?;
        (output.status == 0)
            .then(|| output.text().ok().map(str::to_owned))
            .flatten()
    }
    fn helper(&self) -> Value {
        let path =
            std::path::Path::new("/Library/Application Support/ClaudeWatch/claude-watch-admin.sh");
        let meta = fs::symlink_metadata(path).ok();
        let parent = path.parent().and_then(|p| fs::symlink_metadata(p).ok());
        let root = meta.as_ref().is_some_and(|m| {
            m.is_file()
                && !m.file_type().is_symlink()
                && m.uid() == 0
                && (m.mode() & 0o022) == 0
                && m.len() <= 1024 * 1024
        }) && parent.is_some_and(|m| {
            m.is_dir() && !m.file_type().is_symlink() && m.uid() == 0 && m.mode() & 0o022 == 0
        });
        let hash = if root {
            fs::read(path).ok().map(|b| sha256(&b))
        } else {
            None
        };
        let expected = sha256(include_bytes!("../../../monitor/Resources/watch-admin.sh"));
        // This pinned source implements ABI 1. Reading its exact hash needs no
        // administrator prompt; executing its root-only `status` as a normal
        // user would falsely label every installed helper unavailable.
        let trusted = root && hash.as_deref() == Some(expected.as_str());
        json!({"trusted":trusted,"abi":if trusted{Some(1)}else{None},"root_owned":root,"sha256":hash,"expected_sha256":expected,"source":"root-owned helper / exact bundled ABI 1 hash"})
    }
    fn job(&self, label: ServiceLabel) -> Value {
        self.job_observation(ReadCommand::LaunchctlSystem { label })
    }
    fn job_observation(&self, command: ReadCommand) -> Value {
        match self
            .runner
            .run(command, &[], Duration::from_secs(3), 256 * 1024)
        {
            Ok(out) if out.status == 0 => {
                let text = out.text().unwrap_or("");
                let field = |name: &str| {
                    text.lines()
                        .find_map(|line| line.trim().strip_prefix(name).map(str::trim))
                };
                json!({"registered":true,"trusted":false,"state":field("state =").unwrap_or("unknown"),"last_exit":field("last exit code =").and_then(|v|v.parse::<i32>().ok()),"pid":field("pid =").and_then(|v|v.parse::<u32>().ok()),"definition":null,"detail":"已读取任务；定义文件仍需独立验证"})
            }
            Ok(out)
                if out
                    .error_text()
                    .ok()
                    .is_some_and(|v| v.contains("Could not find service")) =>
            {
                json!({"registered":false,"trusted":false,"state":"absent","definition":null})
            }
            _ => {
                json!({"registered":null,"trusted":false,"state":"unknown","definition":null,"detail":"系统任务状态读取失败，不能判定为已停止"})
            }
        }
    }
    fn gui_updater(&self) -> Value {
        let uid = self
            .environment()
            .ok()
            .and_then(|v| v["uid"].as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v > 0);
        uid.map(|uid| self.job_observation(ReadCommand::LaunchctlGuiUpdater { uid }))
            .unwrap_or_else(
                || json!({"registered":null,"trusted":false,"state":"unknown","definition":null}),
            )
    }
    fn backend_facts(&self) -> BackendFacts { self.backend_facts_using(None) }

    fn backend_facts_using(&self, table: Option<&Result<BTreeMap<u32, Value>>>) -> BackendFacts {
        let mut diagnostics = json!({"reason":"unavailable","observed_at":native::now()});
        let unavailable = |reason, detail, mut diagnostics: Value| {
            diagnostics["reason"] = json!(reason);
            diagnostics["detail"] = json!(detail);
            if diagnostics["sampling_state"] != "stale" {
                diagnostics["sampling_state"] = json!("incomplete");
            }
            diagnostics["backend_alive"] = json!(false);
            BackendFacts {
                sampling_healthy: false,
                guard_healthy: false,
                sampling_native: false,
                guard_native: false,
                sampling_detail: detail,
                guard_detail: detail,
                diagnostics,
            }
        };
        let sample = self.storage.read_bytes(&self.storage.paths.watch().join("state/heartbeat"), 4096);
        let bytes = sample.as_ref().ok().and_then(Option::as_deref);
        diagnostics["heartbeat_present"] = json!(bytes.is_some());
        let monitor = bytes.and_then(|raw| std::str::from_utf8(raw).ok()).and_then(|text| {
            let fields: Vec<_> = text.trim().split('|').collect();
            if fields.len() != 5 || !matches!(fields[3], "ok" | "error") { return None; }
            Some((fields[0].parse::<u32>().ok()?, fields[1], fields[2].parse::<f64>().ok()?, fields[3]))
        });
        let now = native::now();
        let pulse = self.storage.read_json(
            &self.storage.paths.watch().join("state/guard-service-heartbeat.json"), Value::Null,
        ).unwrap_or_else(|_| json!({"invalid":true}));
        let service_identity = pulse["pid"].as_u64().and_then(|pid| u32::try_from(pid).ok())
            .zip(pulse["start_stamp"].as_str().filter(|stamp| !stamp.is_empty()))
            .filter(|(pid, stamp)| guard_service_pulse(&pulse, *pid, stamp, false, now));
        let Some((pid, stamp)) = service_identity.or(monitor.map(|(pid, stamp, _, _)| (pid,stamp))) else {
            let reason = match &sample {
                Err(error) => {
                    diagnostics["source_error_code"] = json!(error.code);
                    "heartbeat_unreadable"
                }
                Ok(Some(_)) => "heartbeat_format",
                Ok(None) => "heartbeat_missing",
            };
            return unavailable(reason, "采样和保护监督均未取得可核对的心跳身份", diagnostics);
        };
        let matching_sample = monitor.filter(|(sample_pid, sample_stamp, _, _)|
            *sample_pid == pid && sample_stamp.split_whitespace().eq(stamp.split_whitespace()));
        let age = matching_sample.map(|(_,_,at,_)| now - at).filter(|age| age.is_finite());
        let sampling_fresh = age.is_some_and(|age| (0.0..=30.0).contains(&age));
        let sampling_complete = matching_sample.is_some_and(|(_,_,_,status)| status == "ok");
        let sampling_healthy = sampling_fresh && sampling_complete;
        diagnostics["heartbeat_pid"] = json!(pid);
        diagnostics["heartbeat_status"] = json!(matching_sample.map(|(_,_,_,status)| status));
        diagnostics["heartbeat_age_seconds"] = json!(age);
        diagnostics["sampling_state"] = json!(if age.is_some() && !sampling_fresh { "stale" }
            else if sampling_healthy { "complete" } else { "incomplete" });
        let service_fresh = guard_service_pulse(&pulse, pid, stamp, sampling_fresh, now);
        diagnostics["service_heartbeat_present"] = json!(!pulse.is_null());
        diagnostics["service_heartbeat_age_seconds"] = pulse["time"].as_f64()
            .and_then(|at| (now - at).is_finite().then_some(json!(now - at))).unwrap_or(Value::Null);
        let sampled_table;
        let table = match match table {
            Some(table) => table,
            None => {
                sampled_table = Sampler::new(&self.runner, self.storage.paths.clone()).process_table();
                &sampled_table
            }
        } {
            Ok(table) => table,
            Err(e) => {
                diagnostics["source_error_code"] = json!(e.code);
                return unavailable("process_sample_failed", "系统进程采样失败", diagnostics);
            }
        };
        diagnostics["process_found"] = json!(table.contains_key(&pid));
        let Some(process) = table.get(&pid) else {
            return unavailable("pid_unconfirmed", "心跳 PID 已退出或无法确认", diagnostics);
        };
        let Some(uid) = process["uid"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v > 0)
        else {
            return unavailable("uid_invalid", "采集后台用户身份无效", diagnostics);
        };
        let same_stamp = process["stamp"]
            .as_str()
            .is_some_and(|v| v.split_whitespace().eq(stamp.split_whitespace()));
        let job = self.job_observation(ReadCommand::LaunchctlGuiAgent { uid });
        diagnostics["start_identity_matches"] = json!(same_stamp);
        diagnostics["launchd_registered"] = job["registered"].clone();
        diagnostics["launchd_state"] = job["state"].clone();
        diagnostics["launchd_pid"] = job["pid"].clone();
        let direct_job = job["registered"] == true && job["state"] == "running" && job["pid"] == pid;
        let worker = if same_stamp && !direct_job {
            let result = crate::native_listener::registered_worker_result(&self.storage, &self.runner, pid);
            diagnostics["worker_verified"] = json!(result.is_ok());
            if let Err(ref e) = result {
                diagnostics["worker_error_code"] = json!(e.code);
            }
            result.is_ok()
        } else {
            false
        };
        let identity_healthy = same_stamp && (direct_job || worker);
        diagnostics["sampling_state"] = json!(if age.is_some() && !sampling_fresh { "stale" }
            else if sampling_complete && identity_healthy { "complete" } else { "incomplete" });
        let guard_native = identity_healthy && service_fresh
            && process["executable"].as_str()
                == self
                    .storage
                    .paths
                    .watch()
                    .join("runtime/watch-engine")
                    .to_str();
        let guard_detail = if !same_stamp {
            "心跳 PID 的启动身份不匹配"
        } else if !identity_healthy {
            "launchd 任务、PID 或运行状态未通过核对"
        } else if !service_fresh {
            "保护监督循环心跳已过期或身份不匹配"
        } else if !guard_native {
            "当前采集后台为旧组件，不支持原生观察租约"
        } else if !sampling_healthy {
            "原生采集后台身份已核对；本轮监控采样未完整"
        } else {
            "原生采集后台身份与心跳已核对"
        };
        diagnostics["native_path_matches"] = json!(process["executable"].as_str() == self.storage.paths.watch().join("runtime/watch-engine").to_str());
        diagnostics["backend_alive"] = json!(guard_native);
        diagnostics["reason"] = json!(if !same_stamp { "identity_mismatch" } else if !identity_healthy { "job_unconfirmed" } else if !service_fresh { "guard_service_heartbeat_stale" } else if !guard_native { "native_path_mismatch" } else { "confirmed" });
        diagnostics["detail"] = json!(guard_detail);
        BackendFacts {
            // Preserve the strict historical monitor verdict: sampling health
            // binds heartbeat quality and daemon identity, but does not make a
            // path mismatch look like a complete monitoring round.
            sampling_healthy: sampling_healthy && identity_healthy,
            guard_healthy: guard_native,
            sampling_native: sampling_healthy && guard_native,
            guard_native,
            sampling_detail: if sampling_healthy {
                guard_detail
            } else {
                "心跳未报告完整监控采样"
            },
            guard_detail,
            diagnostics,
        }
    }
    fn guard_heartbeat(&self, config: &Config, backend: bool) -> bool {
        let at = native::now();
        let frame = crate::channel_policy_status::read_frame(&self.storage);
        let evidence = crate::channel_policy_status::guard_summary(&frame, config, at);
        guard_heartbeat_confirmed(config, backend, at, &evidence)
    }
    pub fn backend_health_from_frame(&self, frame: &crate::channel_policy_status::StatusFrame<'_>, evidence: &Value) -> crate::services::BackendHealthSnapshot {
        let mut facts = self.backend_facts();
        let guard_healthy = guard_heartbeat_confirmed(frame.config, facts.guard_healthy, frame.now, evidence);
        facts.diagnostics["guard"] = crate::guard_readiness::read(
            frame, facts.guard_healthy, guard_healthy, evidence,
        );
        crate::services::BackendHealthSnapshot {
            sampling_healthy: facts.sampling_healthy,
            guard_backend_healthy: facts.guard_healthy,
            guard_healthy,
            diagnostics: facts.diagnostics,
        }
    }
    fn local_facts(&self, c: &Config) -> Result<Value> {
        self.local_facts_from_round(c, None)
    }
    fn local_facts_from_round(&self, c: &Config, round: Option<&ProcessRound>) -> Result<Value> {
        let env = self.environment()?;
        let uid = env["uid"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| CoreError::new("invalid_native_observation", "未取得当前用户身份"))?;
        let sampler = Sampler::new(&self.runner, self.storage.paths.clone());
        let table_at = round.and_then(|round| round.system_processes.as_ref()).map_or_else(native::now, |observation| observation.observed_at);
        let mut guard_identities = Vec::new();
        let table = if let Some(round) = round {
            let observation = round.system_processes.as_ref().ok_or_else(||
                CoreError::new("process_observation_missing", "本轮系统进程观察缺失"))?;
            let now = native::now();
            if round.uid != uid || ![round.observed_at, observation.observed_at].iter()
                .all(|at| (0.0..=crate::process_disposition::INTENT_TTL).contains(&(now - at))) {
                return Err(CoreError::new("process_observation_stale", "本轮进程观察已过期或用户身份不符"));
            }
            let table = observation.processes.as_ref().map_err(Clone::clone)?;
            guard_identities = self.guard_process_identities(round, table, &sampler)?;
            Ok(table.clone())
        } else { sampler.process_table() };
        let native_identities = if let Some(round) = round {
            Ok((round.uid, round.identities.clone()))
        } else {
            Observer { runner: &self.runner }.inventory().map(|inventory|
                (inventory.uid, inventory.processes.into_iter().map(|(pid, record)| (pid, record.identity)).collect()))
        };
        let mut identity_unavailable = !native_identities.as_ref().is_ok_and(|(owner, _)| *owner == uid);
        let mut candidates = BTreeMap::<&str, Vec<Value>>::new();
        if let Ok(table) = &table {
            for (pid, process) in table {
                if process["uid"] != 0 && process["uid"] != uid {
                    continue;
                }
                if let Some(mode) = proxy_mode(process["executable"].as_str().unwrap_or("")) {
                    if c.proxy_mode == "auto" || c.proxy_mode == mode {
                        let mut identity = process.clone();
                        identity["pid"] = json!(pid);
                        identity["start_stamp"] = identity["stamp"].clone();
                        if process["uid"] == uid {
                            if let Some(identity_record) = native_identities
                                .as_ref()
                                .ok()
                                .and_then(|(_, identities)| identities.get(pid))
                                .filter(|record| {
                                    record.uid == uid
                                        && record.executable
                                            == process["executable"].as_str().unwrap_or("")
                                        && claude_watch_core::processes::normalized_stamp(
                                            &record.start_stamp,
                                        ) == claude_watch_core::processes::normalized_stamp(
                                            process["stamp"].as_str().unwrap_or(""),
                                        )
                                })
                            {
                                identity["start_seconds"] = json!(identity_record.start_seconds);
                                identity["start_microseconds"] =
                                    json!(identity_record.start_microseconds);
                                identity["native_identity"] = json!(true);
                            } else {
                                identity_unavailable = true;
                            }
                        }
                        candidates.entry(mode).or_default().push(identity);
                    }
                }
            }
        }
        let selected = if candidates.len() == 1 {
            candidates.keys().next().copied().unwrap_or("")
        } else {
            ""
        };
        let mut unavailable: Vec<&str> = Vec::new();
        let mut proxy = if table.is_err() || candidates.len() > 1 || identity_unavailable {
            "unknown"
        } else if selected.is_empty() {
            "fail"
        } else {
            "ok"
        };
        let mut detail = if proxy == "ok" {
            format!("已识别 {selected}")
        } else {
            "代理未运行、身份不完整或存在多个候选".into()
        };
        let route = self.read(ReadCommand::Route(std::net::IpAddr::from([198, 18, 0, 1])));
        let interfaces = self.read(ReadCommand::Interfaces);
        let interface = route.as_deref().and_then(route_interface).unwrap_or("");
        let tun = match (&route, &interfaces) {
            (Some(_), Some(interfaces))
                if !selected.is_empty() && fake_ip_interface(interfaces, interface) =>
            {
                "ok"
            }
            (Some(_), Some(_)) => "fail",
            _ => "unknown",
        };
        if tun == "unknown" {
            unavailable.push("tun_sampling");
        }
        let mut tag = json!({});
        if selected == "tag" {
            // Environment checks need the controller identity, not all AI app sockets.
            let round = ProcessRound {
                id: uuid::Uuid::new_v4().to_string(),
                uid,
                targets: vec![],
                identities: BTreeMap::new(),
                roles: json!({}), match_evidence: BTreeMap::new(),
                unavailable: vec![],
                diagnostic_reasons: BTreeMap::new(),
                confirmed_exited_count: 0,
                complete: true,
                observed_at: native::now(),
                discovery: None,
                system_processes: Some(crate::sampler::ProcessTableObservation { observed_at: table_at, processes: table.clone(), root_starts: BTreeMap::new() }),
            };
            let sockets = SocketRound {
                flows: vec![],
                receipt: json!({}),
            };
            let pin = pinned_node(&sampler.paths, &c.proxy_group);
            tag = sampler.tag_report(&round, &sockets, &c.proxy_group, &pin);
            if tag["entry"]["state"] != "verified"
                || tag["api"]["state"] != "available"
                || tag["api"]["covers_7890"] != true
            {
                proxy = "unknown";
                detail = "TAG 7890 监听者、控制接口或该入口覆盖范围未确认".into();
                unavailable.push("tag_snapshot");
            }
            // 节点漂移仅提醒：selectionChanged 经 monitor_snapshot 进入公开快照，
            // 控制面板可见；断开只由 egress_ip_changed（出口 IP 确认变化）触发。
        }
        if proxy == "unknown" && unavailable.is_empty() {
            unavailable.push("proxy_sampling");
        }
        let processes: Vec<_> = candidates.values().flatten().cloned().collect();
        // Preserve the mature digest contract. Parent PID, collection source
        // and network-service metadata are not proxy identity. The old native
        // inventory supplied microseconds but no display start_stamp; its root
        // ps supplement supplied only start_stamp, never invented precision.
        let mut context_processes=processes.iter().map(|p|json!({"pid":p["pid"],"uid":p["uid"],"executable":p["executable"],"start_stamp":if p["native_identity"]==true{Value::Null}else{p["start_stamp"].clone()},"start_seconds":p["start_seconds"],"start_microseconds":p["start_microseconds"]})).collect::<Vec<_>>();
        context_processes
            .sort_by_key(|p| (p["pid"].as_u64().unwrap_or(0), p["start_stamp"].to_string()));
        let mut identity =
            json!({"mode":selected,"tun":tun,"interface":interface,"processes":context_processes});
        if selected == "tag" {
            identity["selection"] = json!({"mode":tag["api"]["mode"],"selected_node":tag["api"]["selected_node"],"global_node":tag["api"]["global_node"]});
            identity["group"] = tag["expected_group"].clone();
        }
        let context = crate::config_store::policy_digest(&identity)?;
        let backend = self.backend_facts_using(Some(&table));
        let guard = self.guard_heartbeat(c, backend.guard_healthy);
        let mut out = json!({"proxy":proxy,"proxy_detail":detail,"tun":tun,"mode":selected,"candidates":candidates.keys().collect::<Vec<_>>(),"context":context,"context_id":context,"timezone":env.get("timezone"),"locale":env.get("locale"),"language":env.get("language"),"app_language":env.get("app_language"),"date_format":env.get("date_format"),"ipv6":env.get("ipv6"),"ipv6_method":env.get("ipv6_method"),"network":env.get("network"),"network_identity":identity,"service":env.pointer("/network/service"),"interface":interface,"processes":processes,"tag":tag,"observation_unavailable":unavailable,"backend_healthy":backend.sampling_healthy,"backend_native":backend.sampling_native,"backend_detail":backend.sampling_detail,"guard_backend_healthy":backend.guard_healthy,"guard_backend_native":backend.guard_native,"guard_backend_detail":backend.guard_detail,"guard":guard,"guard_state":if guard{"ok"}else if !c.guard_enabled{"disabled"}else{"unknown"},"guard_detail":if guard{"保护心跳已确认"}else if !c.guard_enabled{"保护策略已禁用"}else{"保护心跳或后台身份未能确认"}});
        out["verified_proxy_url"] = if selected == "tag"
            && proxy == "ok"
            && tag["entry"]["state"] == "verified"
            && tag["api"]["covers_7890"] == true
        {
            json!(crate::network_client::DEFAULT_PROXY)
        } else {
            Value::Null
        };
        let entries = tag
            .pointer("/rules/entries")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            });
        out["rules"] = if selected == "tag" && tag["api"]["state"] == "available" {
            crate::rules::inspect_tag_rules(entries.as_deref(), &[], &tag["api"])
        } else {
            json!({"state":"unknown","detail":"未取得当前代理的实际规则证据"})
        };
        if let Some(round) = round {
            // TAG/controller and launchd reads also perform I/O. Recheck the
            // same identities at the end, including exec generation, rather
            // than treating the pre-I/O identity as a new observation.
            let mut environment_at = round.observed_at.min(table_at);
            if selected == "tag" {
                out["guard_listener"] = tag["entry"]["owners"].clone();
                let listener_at = tag["listener_observed_at"].as_f64()
                    .filter(|at| (0.0..=crate::vpn_observer::DEFAULT_VPN_OBSERVATION_TTL_SECONDS).contains(&(native::now() - at)))
                    .ok_or_else(|| CoreError::new("proxy_listener_unavailable", "TAG监听观察不可读或已经过期"))?;
                out["guard_listener_observed_at"] = json!(listener_at);
                environment_at = environment_at.min(listener_at);
            }
            if selected != "tag" && proxy == "ok" {
                let endpoint = if c.proxy_url.trim().is_empty() { crate::network_client::DEFAULT_PROXY } else { &c.proxy_url };
                let url = url::Url::parse(endpoint).ok()
                    .filter(|_| claude_watch_core::config::valid_loopback_proxy(endpoint))
                    .ok_or_else(|| CoreError::new("proxy_listener_unavailable", "未取得受控代理监听端点"))?;
                let port = url.port_or_known_default().ok_or_else(|| CoreError::new("proxy_listener_unavailable", "代理端口无效"))?;
                let address = match url.host() {
                    Some(url::Host::Ipv4(address)) => std::net::IpAddr::V4(address),
                    Some(url::Host::Ipv6(address)) => std::net::IpAddr::V6(address),
                    _ => return Err(CoreError::new("proxy_listener_unavailable", "代理必须使用明确的回环地址")),
                };
                let listener_at = native::now();
                let listener = sampler.command_evidence(ReadCommand::LsofTcpListener { port }, Duration::from_secs(3), "lsof");
                let (owner, listener_at) = match listener.as_ref().ok().and_then(|listener| crate::vpn_observer::listener_owner_at(listener, port, Some(address))) {
                    Some(owner) => (Some(owner), listener_at),
                    None => {
                        // Reuse the VPN observer's authenticated kernel-frame
                        // fallback for root listeners that lsof cannot expose.
                        let kernel = crate::vpn_observer::read_vpn_kernel_snapshot(&self.runner, Duration::from_secs(3))
                            .filter(|kernel| (0.0..=crate::vpn_observer::DEFAULT_VPN_OBSERVATION_TTL_SECONDS)
                                .contains(&(native::now() - kernel.captured_at)))
                            .ok_or_else(|| CoreError::new("proxy_listener_unavailable", "代理监听快照不可读或已经过期"))?;
                        (crate::vpn_observer::kernel_listener_owner_at(&kernel.evidence, port, address), kernel.captured_at)
                    }
                };
                let owner = owner
                    .filter(|owner| processes.iter().any(|process| process["pid"] == *owner))
                    .ok_or_else(|| CoreError::new("proxy_listener_changed", "代理监听者不属于本轮已核验候选"))?;
                out["guard_listener"] = json!({"endpoint":endpoint,"owner":owner});
                out["guard_listener_observed_at"] = json!(listener_at);
                environment_at = environment_at.min(listener_at);
            }
            let current = self.guard_process_identities(round, table.as_ref().map_err(Clone::clone)?, &sampler)?;
            if current != guard_identities {
                return Err(CoreError::new("process_identity_changed", "环境采样期间代理或后台身份已经变化"));
            }
            out["process_observed_at"] = json!(round.observed_at.min(table_at));
            out["environment_observed_at"] = json!(environment_at);
            out["process_round_id"] = json!(round.id);
            out["guard_identity_evidence"] = json!(guard_identities);
        }
        Ok(out)
    }
    fn guard_process_identities(
        &self, round: &ProcessRound, table: &BTreeMap<u32, Value>, sampler: &Sampler<&R>,
    ) -> Result<Vec<Value>> {
        let changed = || CoreError::new("process_identity_changed", "本轮代理或后台进程身份已经变化或无法复核");
        let backend = self.storage.paths.watch().join("runtime/watch-engine");
        let candidates = table.iter().filter(|(_, row)| guard_process_candidate(row, round.uid, &backend)).collect::<Vec<_>>();
        let root_pids = candidates.iter().filter_map(|(pid, row)| (row["uid"] == 0).then_some(**pid)).collect::<Vec<_>>();
        // A root helper normally cannot expose a Mach task token to this UID.
        // Keep its existing ps path/UID proof, bound on both sides to the
        // already available any-user microsecond birth-time observation.
        let root_before = root_pids.iter().map(|pid| self.runner.process_start_time_any_user(*pid)
            .map(|start| (*pid, start)).ok_or_else(changed)).collect::<Result<BTreeMap<_, _>>>()?;
        let root_table = sampler.process_table_pids(&root_pids)?;
        let mut identities = Vec::new();
        for (pid, row) in candidates {
            if row["uid"] == 0 {
                let start = root_before.get(pid).copied().ok_or_else(changed)?;
                let current = root_table.get(pid).ok_or_else(changed)?;
                if round.system_processes.as_ref().and_then(|observation| observation.root_starts.get(pid)).copied() != Some(start)
                    || self.runner.process_start_time_any_user(*pid) != Some(start)
                    || ["uid", "executable", "stamp"].iter().any(|key| current[*key] != row[*key])
                    || claude_watch_system::process_start_stamp(start.0).as_deref().map(claude_watch_core::processes::normalized_stamp)
                        != row["stamp"].as_str().map(claude_watch_core::processes::normalized_stamp) {
                    return Err(changed());
                }
                identities.push(json!({"pid":pid,"uid":0,"executable":row["executable"],
                    "start_seconds":start.0,"start_microseconds":start.1,"audit_token":Value::Null}));
                continue;
            }
            let current = self.runner.observed_process_identity(*pid).ok_or_else(changed)?;
            let stamp = claude_watch_system::process_start_stamp(current.start_seconds);
            if row["uid"] != current.uid || row["executable"] != current.executable_path
                || stamp.as_deref().map(claude_watch_core::processes::normalized_stamp)
                    != row["stamp"].as_str().map(claude_watch_core::processes::normalized_stamp)
                || !round.identities.get(pid).is_some_and(|expected|
                    expected.uid == current.uid && expected.executable == current.executable_path
                        && expected.start_seconds == current.start_seconds && expected.start_microseconds == current.start_microseconds) {
                return Err(changed());
            }
            identities.push(observed_identity(&current));
        }
        Ok(identities)
    }
    fn local_for_target_using(
        &self, c: &Config, target: claude_watch_core::processes::LaunchTarget,
        round: Option<&ProcessRound>,
    ) -> Result<Value> {
        let mut local = self.local_facts_from_round(c, round)?;
        if target.cli() {
            let overrides = if target == claude_watch_core::processes::LaunchTarget::ClaudeCli {
                crate::config_store::cli_proxy_overrides(&self.runner, &self.storage.paths.home)
            } else { Ok(Vec::new()) };
            local["cli_proxy"] = match overrides {
                Ok(values) => claude_watch_core::audit::cli_proxy_state(local["verified_proxy_url"].as_str(), &values),
                Err(error) => json!({"state":"unknown","detail":error.message}),
            };
        }
        Ok(local)
    }
    fn online_facts(
        &self,
        _: &Config,
        local: &Value,
        include_claude: bool,
        include_chatgpt: bool,
    ) -> Result<Value> {
        let context = local
            .get("context_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let egress = self.network.fast_egress();
        let raw_trace = egress.data.clone().unwrap_or(Value::Null);
        let trace = json!({"ip":raw_trace["ip"],"loc":raw_trace["country"],"observed_at":raw_trace["observed_at"]});
        let ip = trace.get("ip").and_then(Value::as_str).unwrap_or("");
        let measured_at = trace
            .get("observed_at")
            .and_then(Value::as_f64)
            .unwrap_or(0.);
        let lookup_receipt = (!ip.is_empty()).then(|| {
            self.network
                .metadata_for_context("lookup", context, ip, measured_at)
        });
        let lookup = lookup_receipt
            .as_ref()
            .map(crate::network_client::Receipt::display_value)
            .unwrap_or(Value::Null);
        let mut query_errors = if egress.status == "complete" {
            json!({})
        } else {
            json!({"egress":{"source":egress.source_url,"message":egress.error}})
        };
        let mut geo = json!({"ip":ip,"country":Value::Null,"timezone":Value::Null});
        let mut geo_sampled_at = None;
        let lookup_data = lookup_receipt.as_ref().and_then(|receipt| {
            (receipt.status == "complete" && receipt.http_status == Some(200))
                .then_some(receipt.data.as_ref())
                .flatten()
                .filter(|data| data.is_object())
        });
        let lookup_bound = lookup_data.is_some_and(|data| {
            lookup_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.query == ip)
                && data
                    .get("ip")
                    .and_then(Value::as_str)
                    .and_then(claude_watch_core::network::public_unicast)
                    .as_deref()
                    == Some(ip)
        });
        let mut conflict = false;
        if let Some(data) = lookup_data.filter(|_| lookup_bound) {
            let country = data
                .get("countryCode")
                .or_else(|| data.get("country_code"))
                .and_then(Value::as_str)
                .map(|country| country.to_ascii_uppercase())
                .filter(|country| {
                    country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase())
                });
            let timezone = data
                .get("timezone")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| {
                    let zones = data
                        .get("geo_sources")?
                        .as_array()?
                        .iter()
                        .filter_map(|row| row.get("timezone").and_then(Value::as_str))
                        .collect::<std::collections::BTreeSet<_>>();
                    (zones.len() == 1).then(|| zones.into_iter().next().unwrap().to_owned())
                });
            if country
                .as_deref()
                .is_some_and(|country| country != trace["loc"].as_str().unwrap_or(""))
            {
                conflict = true;
                query_errors["egress_consistency"] = json!({"source":"Cloudflare trace / Net.Coffee","message":"Cloudflare 与 Net.Coffee 出口国家不一致"});
            }
            geo = json!({"ip":ip,"country":country,"timezone":timezone,
                "country_source":"Net.Coffee lookup","timezone_source":"Net.Coffee lookup"});
            geo_sampled_at = lookup_receipt.as_ref().map(|value| value.finished_at);
        } else if lookup_receipt.is_some() {
            // A positive mismatch rejected by NetworkClient must not disappear
            // when the display data is cleared; malformed fields are different.
            let returned = lookup_receipt
                .as_ref()
                .filter(|r| r.http_status == Some(200))
                .and_then(|r| crate::storage::strict_json(r.raw.as_bytes()).ok());
            let other_ip = lookup_data
                .or(returned.as_ref())
                .and_then(|data| data["ip"].as_str())
                .and_then(claude_watch_core::network::public_unicast);
            let actual_conflict = other_ip.as_deref().is_some_and(|other| other != ip);
            let (source, message) = if actual_conflict {
                (
                    "Cloudflare trace / Net.Coffee",
                    "Cloudflare 与 Net.Coffee 出口 IP 不一致",
                )
            } else {
                ("Net.Coffee lookup", "Net.Coffee 查询未完成")
            };
            query_errors[if actual_conflict {
                "egress_consistency"
            } else {
                "netcoffee"
            }] = json!({"source":source,"message":message});
            conflict = actual_conflict;
        }
        // A valid primary lookup is authoritative. Only genuinely absent geo
        // fields may use the cached geoip fallback; a known IP/country conflict
        // remains visible and cannot be overwritten by another source.
        // A country with exactly one IANA zone already resolves the timezone
        // (same rule as 2.9.5), so a missing `timezone` there is not a gap and
        // must not trigger a fallback.
        let single_zone_country = geo["country"].as_str().is_some_and(|country| {
            crate::region_catalog::system_catalog()
                .get(country)
                .is_some_and(|zones| zones.len() == 1)
        });
        if !ip.is_empty()
            && !conflict
            && (geo["country"].is_null() || (geo["timezone"].is_null() && !single_zone_country))
        {
            let fallback = self
                .network
                .metadata_for_context("geoip", context, ip, measured_at);
            if let Some(data) = fallback.data.as_ref().filter(|data| data.is_object()) {
                // `/api/geoip/` answers for the IP in the path and returns no
                // `ip` field, so provenance comes from the receipt query.  A
                // returned `ip` still has to match when the source provides it.
                let returned_ip = data
                    .get("ip")
                    .and_then(Value::as_str)
                    .and_then(claude_watch_core::network::public_unicast);
                let ip_bound = match returned_ip.as_deref() {
                    Some(value) => value == ip,
                    None => fallback.query == ip,
                };
                let bound =
                    fallback.status == "complete" && fallback.http_status == Some(200) && ip_bound;
                // `/api/geoip/` reports the full country name in `country` and
                // the ISO code in `country_code`, so the code wins; a
                // name-shaped value must never be read as a country code.
                let country = ["countryCode", "country_code", "country"]
                    .iter()
                    .filter_map(|key| data.get(*key).and_then(Value::as_str))
                    .map(|country| country.trim().to_ascii_uppercase())
                    .find(|country| {
                        country.len() == 2 && country.bytes().all(|byte| byte.is_ascii_uppercase())
                    });
                if bound && country.as_deref() == trace["loc"].as_str() {
                    geo = json!({"ip":ip,"country":country,"timezone":data.get("timezone").cloned().unwrap_or(Value::Null),
                        "country_source":"Net.Coffee geoip fallback","timezone_source":"Net.Coffee geoip fallback"});
                    geo_sampled_at = Some(fallback.finished_at);
                } else if country.is_some() && returned_ip.is_some() {
                    query_errors["egress_consistency"] = json!({"source":"Cloudflare trace / Net.Coffee geoip","message":"Cloudflare 与 Net.Coffee 备用出口资料不一致"});
                } else {
                    query_errors["geo"] = json!({"source":"Net.Coffee geoip","message":"备用地理响应缺少有效 IP 或国家字段"});
                }
            } else {
                query_errors["geo"] =
                    json!({"source":"Net.Coffee geoip","message":"备用地理查询未完成"});
            }
        }
        let asn = lookup_receipt
            .as_ref()
            .filter(|_| lookup_bound)
            .and_then(crate::network_client::lookup_asn);
        let organization = lookup_data
            .filter(|_| lookup_bound)
            .and_then(|data| {
                data.get("asOrganization")
                    .or_else(|| data.get("asn_org"))
                    .or_else(|| data.get("org"))
            })
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut asn_value =
            json!({"number":asn,"organization":organization,"source":"Net.Coffee lookup"});
        if let Some(receipt) = lookup_receipt.as_ref().filter(|_| asn.is_some()) {
            asn_value["queried_at"] = json!(receipt.finished_at);
            let number = asn.unwrap();
            let registration = self.network.ripe_asn(number);
            if let Some(country) =
                crate::network_client::ripe_registered_country(&registration, number)
            {
                asn_value["registered_country"] = json!(country);
                asn_value["registered_queried_at"] = json!(registration.finished_at);
                asn_value["result_time"] = json!(registration
                    .data
                    .as_ref()
                    .and_then(|v| v.pointer("/data/result_time"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .chars()
                    .take(80)
                    .collect::<String>());
            } else {
                query_errors["asn"] = json!({"source":"RIPEstat ASN","message":registration.error.unwrap_or_else(||"ASN 注册国家没有返回完整结果".into())});
            }
        }
        let services = include_claude.then(|| {
            (
                self.network.claude_homepage(),
                self.network.service_metadata("api"),
            )
        });
        let openai_services = include_chatgpt.then(|| {
            (
                self.network.chatgpt_homepage(),
                self.network.service_metadata("openai_api"),
            )
        });
        let stun = self.stun_fact(context);
        let mut result = json!({"stun":stun,"trace":trace,"geo":geo,"asn":asn_value,"netcoffee_lookup":lookup,"query_errors":query_errors,
            "source_times":{"trace":egress.finished_at,"geo":geo_sampled_at,"asn":asn_value.get("registered_queried_at").or_else(||asn_value.get("queried_at"))}});
        if let Some((claude, api)) = services {
            result["source_times"]["claude"] = json!(claude.queried_at);
            result["source_times"]["api"] = json!(api.queried_at);
            result["service_responses"] = json!({"claude":crate::network_client::service_observation("claude",&claude),"api":crate::network_client::service_observation("api",&api)});
        }
        if let Some((chatgpt, openai_api)) = openai_services {
            result["source_times"]["chatgpt"] = json!(chatgpt.queried_at);
            result["source_times"]["openai_api"] = json!(openai_api.queried_at);
            if !result["service_responses"].is_object() {
                result["service_responses"] = json!({});
            }
            result["service_responses"]["chatgpt"] =
                crate::network_client::service_observation("chatgpt", &chatgpt);
            result["service_responses"]["openai_api"] =
                crate::network_client::service_observation("openai_api", &openai_api);
        }
        Ok(result)
    }

    /// The UDP/STUN probe is the one online fact that used to be re-run every
    /// round, so a single server's packet loss flipped the whole row.  It now
    /// reuses a context-bound receipt for `STUN_RECEIPT_TTL` — the same shape
    /// as the DNS/WebRTC receipts — and probes only when no fresh receipt
    /// exists.  `refresh_stun` (launch only) writes a fresh receipt first, so
    /// the launch gate never judges a cached round.
    fn stun_fact(&self, context: &str) -> Value {
        let store = crate::receipt_store::ReceiptStore {
            storage: self.storage.clone(),
        };
        let now = native::now();
        if let Some(fact) = store.stun_fact(context, now) {
            return fact;
        }
        let probe = self.probes.stun();
        // Persisting keeps the periodic view stable for the next window; a
        // failed write must not lose the observation we already paid for.
        let _ = store.record_stun(&probe, context, now);
        probe
    }
    fn write(&mut self, a: &Value) -> Result<()> {
        if self.authority != Authority::ExplicitPermit {
            return Err(CoreError::new(
                "write_not_authorized",
                "macOS 适配器处于只读模式",
            ));
        }
        if matches!(
            a.get("id").and_then(Value::as_str),
            Some("start_proxy" | "reload_proxy" | "enable_tun" | "rules")
        ) {
            return Err(CoreError::new(
                "vpn_managed_externally",
                "VPN 与代理配置由外部客户端管理，Watch 仅执行只读观测与通道断流",
            ));
        }
        self.mutator.apply(a)
    }
}
fn network_identity(environment: &Value) -> Value {
    json!({"service":environment.pointer("/network/service"),"interface":environment.pointer("/network/interface"),
        "service_id":environment.pointer("/network/service_id")})
}
impl<R: ReadRunner, T: Transport, M: Mutator> AuditSystem for Macos<R, T, M> {
    fn now(&self) -> f64 {
        native::now()
    }
    fn network(&self) -> Result<Value> {
        let e = self.environment()?;
        Ok(network_identity(&e))
    }
    fn local(&self, c: &Config) -> Result<Value> {
        self.local_facts(c)
    }
    fn local_for_target(
        &self,
        c: &Config,
        target: claude_watch_core::processes::LaunchTarget,
    ) -> Result<Value> {
        self.local_for_target_using(c, target, None)
    }
    fn local_from_process_round(
        &self, c: &Config, target: claude_watch_core::processes::LaunchTarget,
        round: &ProcessRound,
    ) -> Result<Value> {
        self.local_for_target_using(c, target, Some(round))
    }
    fn network_and_local(&self, c: &Config, target: claude_watch_core::processes::LaunchTarget) -> Result<(Value, Value)> {
        let local = self.local_for_target(c, target)?;
        Ok((network_identity(&local), local))
    }
    fn online(&mut self, c: &Config, l: &Value) -> Result<Value> {
        // The environment view is not tied to one family: it reports both
        // services so the grid can show a ChatGPT card beside the Claude one.
        self.online_facts(c, l, true, true)
    }
    fn online_for_target(
        &mut self,
        c: &Config,
        l: &Value,
        target: claude_watch_core::processes::LaunchTarget,
    ) -> Result<Value> {
        // A launch audit only measures the service this target supervises: the
        // other family's endpoint must never decide whether this one launches.
        // The environment view opts into both explicitly through `online`.
        let openai = matches!(
            target.provider(),
            claude_watch_core::processes::Provider::Codex
                | claude_watch_core::processes::Provider::Chatgpt
                | claude_watch_core::processes::Provider::Openai
        );
        self.online_facts(c, l, !openai, openai)
    }
    fn refresh_dns(&mut self) -> Result<Option<Value>> {
        let token = std::env::var("CLAUDE_WATCH_DNS_REFRESH_TOKEN").ok();
        if token.is_none() {
            return Ok(None);
        }
        let env = self.environment()?;
        let uid = env["uid"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| CoreError::new("invalid_native_observation", "当前用户身份未确认"))?;
        crate::leak_refresh::refresh_for_launch(
            &self.storage,
            uid,
            token.as_deref(),
            Duration::from_secs(85),
        )?;
        // The GUI records the result through the receipt command. Revalidate the
        // persisted receipt in AuditStore; an acknowledgement cannot grant launch.
        Ok(None)
    }
    fn refresh_stun(&mut self, context: &str) -> Result<Option<Value>> {
        // A launch gate must judge a fresh round, so probe now and persist the
        // receipt; `online_facts` then reads this just-written observation.
        let probe = crate::online_probes::default_stun_value();
        let store = crate::receipt_store::ReceiptStore {
            storage: self.storage.clone(),
        };
        store.record_stun(&probe, context, native::now())?;
        Ok(Some(probe))
    }
}
impl<R: ReadRunner, T: Transport, M: Mutator> RepairSystem for Macos<R, T, M> {
    fn local(&self, c: &Config) -> Result<Value> {
        let mut facts = self.local_facts(c)?;
        let saved = crate::config_store::ConfigStore {
            storage: self.storage.clone(),
        }
        .load()?;
        facts["accepted_locale"] = json!(saved.locale);
        facts["saved_config_hash"] = json!(crate::config_store::policy_digest(&saved.value()?)?);
        facts["watchdog"] = self.watchdog_state()?;
        facts["updater"] = self.service_job("updater")?;
        if facts["mode"] == "clash-verge" || c.proxy_mode == "clash-verge" {
            let proxy = crate::proxy_mutations::read_clash_verge_config_facts(&self.storage)?;
            // Repair-only inputs. AuditSystem::local deliberately excludes
            // these credential-bearing configuration strings from UI receipts.
            facts["clash_verge_config"] = json!(proxy.clash_verge_config);
            facts["merge_text"] = json!(proxy.merge_text);
        }
        Ok(facts)
    }
    fn apply(&mut self, a: &Value) -> Result<()> {
        self.write(a)
    }
    fn egress_reference(&self, c: &Config) -> Result<Value> {
        let local = self.local_facts(c)?;
        self.egress_for_local(c, &local)
    }
    fn restore(&mut self, a: &Value) -> Result<bool> {
        if self.authority != Authority::ExplicitPermit {
            return Ok(false);
        }
        if matches!(
            a.get("id").and_then(Value::as_str),
            Some("start_proxy" | "reload_proxy" | "enable_tun" | "rules")
        ) {
            return Err(CoreError::new(
                "vpn_managed_externally",
                "VPN 与代理配置由外部客户端管理，Watch 仅执行只读观测与通道断流",
            ));
        }
        self.mutator.restore(a)
    }
}
impl<R: ReadRunner, T: Transport, M: Mutator> OnboardingSystem for Macos<R, T, M> {
    fn egress_for_local(&self, config: &Config, local: &Value) -> Result<Value> {
        // The caller already checked this local sample. Exit confirmation
        // needs the exit and its metadata, not another Claude service probe.
        let online = self.online_facts(config, local, false, false)?;
        let trace = &online["trace"];
        Ok(json!({"trace":{"ip":trace["ip"],"loc":trace["loc"]},"geo":online["geo"]}))
    }
    fn setup_watchdog_state(&self, _: &Config) -> Result<Value> {
        ServiceSystem::watchdog_state(self)
    }
    fn packaged_backend(&self) -> Option<claude_watch_core::channel::NetworkBackendKind> {
        let mut directories = vec![self.storage.paths.watch().join("runtime"), self.storage.paths.base().join("bin")];
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() { directories.push(parent.to_path_buf()); }
        }
        // Same precedence as daemon assembly: do not skip an installed but
        // unrecognized runtime and silently select another backend.
        directories.into_iter().find(|path| path.join("BuildInfo.plist").is_file()
            || path.join("components.json").is_file() || path.join("watch-sandbox-launcher").is_file())
            .and_then(|path| crate::sandbox_launch::lookup_packaged_network_backend(&path))
    }
    fn vpn_observation(&self, expectation: &claude_watch_core::vpn::VpnExpectation) -> Result<claude_watch_core::vpn::VpnObservation> {
        use crate::vpn_observer::{resolve_vpn_controller_credentials, HttpControllerVpnReader};
        if expectation.proxy_mode != "tag" {
            return Err(CoreError::new("vpn_observation_unavailable", "首次 VPN 预期确认目前仅支持已核验的 TAG 入口"));
        }
        let credentials = resolve_vpn_controller_credentials(&self.storage, &expectation.proxy_mode)?;
        // TAG may run Mihomo as root; supply the kernel listener table so the
        // reader can anchor the controller owner's lifetime across users.
        let reader = HttpControllerVpnReader::new_live(&expectation.proxy_mode, credentials);
        let snapshot_probe = |timeout| crate::vpn_observer::read_vpn_kernel_snapshot(&self.runner, timeout);
        // The reader records the real start time; slow or stale samples must
        // expire instead of being renewed at the time setup receives them.
        Ok(reader.read_observation_with_snapshot_probe(expectation, true, 1, claude_watch_core::vpn::VpnEpoch {
            observer_boot_id: uuid::Uuid::new_v4().to_string(), change_generation: 1,
        }, native::now(), &snapshot_probe))
    }
    fn network(&self) -> Result<Value> {
        AuditSystem::network(self)
    }
    fn network_and_local(&self, config: &Config) -> Result<(Value, Value)> {
        let local = RepairSystem::local(self, config)?;
        Ok((network_identity(&local), local))
    }
    fn now(&self) -> f64 {
        native::now()
    }
    fn baseline_data(&self) -> Result<String> {
        let input = crate::environment_capture::EnvironmentInput {
            home: self.storage.paths.home.clone(),
            environment: std::env::vars().collect(),
        };
        Ok(crate::environment_capture::capture(&self.runner, &input)?.data)
    }
}
impl<R: ReadRunner, T: Transport, M: Mutator> ServiceSystem for Macos<R, T, M> {
    fn now(&self) -> f64 {
        native::now()
    }
    fn backend_healthy(&self) -> bool {
        self.backend_facts().sampling_healthy
    }
    fn guard_backend_healthy(&self) -> bool {
        self.backend_facts().guard_healthy
    }
    fn guard_status(&self, config: &Config) -> Result<bool> {
        Ok(self.guard_heartbeat(config, self.guard_backend_healthy()))
    }
    fn backend_health_snapshot(
        &self,
        config: &Config,
    ) -> Result<crate::services::BackendHealthSnapshot> {
        let at = native::now();
        let frame = crate::channel_policy_status::read_frame(&self.storage);
        let frame = crate::channel_policy_status::StatusFrame::new(&frame, config, at);
        Ok(self.backend_health_from_frame(&frame, &frame.guard_summary()))
    }
    fn service_job(&self, name: &str) -> Result<Value> {
        let mut observation = match name {
            "watchdog" => self.job(ServiceLabel::Timezone),
            "original" => self.job(ServiceLabel::LegacyBodyguard),
            "legacy_watchdog" => self.job(ServiceLabel::LegacyTimezone),
            "updater" => self.gui_updater(),
            _ => json!({"registered":null,"trusted":false}),
        };
        match crate::service_native::read_job_definition(&self.storage, name, &self.runner) {
            Ok(value) => {
                for key in [
                    "trusted",
                    "definition",
                    "definition_present",
                    "label",
                    "interval",
                ] {
                    observation[key] = value[key].clone();
                }
            }
            Err(error) => {
                observation["trusted"] = json!(false);
                observation["definition_error"] = json!(error.message);
            }
        }
        if name == "original" {
            observation["execution_receipt"] = read_original_guard_receipt(
                std::path::Path::new("/Library/Application Support/claude-switcher/claude-bodyguard-health"), 0,
            ).unwrap_or(Value::Null);
        }
        Ok(observation)
    }
    fn watchdog_state(&self) -> Result<Value> {
        let job = self.service_job("watchdog")?;
        let target =
            std::path::Path::new("/Library/Application Support/ClaudeWatch/timezone.target");
        let value = fs::symlink_metadata(target)
            .ok()
            .filter(|m| {
                m.is_file()
                    && !m.file_type().is_symlink()
                    && m.uid() == 0
                    && m.mode() & 0o022 == 0
                    && m.len() < 1024
            })
            .and_then(|_| fs::read_to_string(target).ok())
            .map(|v| v.trim().to_owned());
        let last_success =
            std::path::Path::new("/Library/Application Support/ClaudeWatch/timezone.last-success");
        let last_success_at = crate::service_native::read_receipt_timestamp(last_success, 0);
        Ok(
            json!({"registered":job["registered"],"target":value,"last_success_at":last_success_at,"trusted":job["trusted"],"source":"root timezone target and fixed launchd definition"}),
        )
    }
    fn admin_helper_status(&self) -> Result<Value> {
        Ok(self.helper())
    }
    fn runtime_present(&self) -> bool {
        self.storage
            .paths
            .home
            .join("Library/Application Support/ClaudeWatch/runtime/watch-engine")
            .is_file()
    }
    fn apply_service(&mut self, a: &Value) -> Result<()> {
        self.write(a)
    }
    fn restore_service(&mut self, a: &Value) -> Result<bool> {
        if self.authority != Authority::ExplicitPermit {
            return Ok(false);
        }
        self.mutator.restore(a)
    }
}
