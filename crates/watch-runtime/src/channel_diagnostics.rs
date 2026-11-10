//! Bounded, asynchronous channel history. No filesystem work occurs on a producer.
use crate::{events::{EventFields, EventStore}, storage::StateStore};
use claude_watch_core::{channel::PolicyVersion, error::{CoreError, Result}};
use serde::{Deserialize, Serialize};
use std::sync::{atomic::{AtomicU64, Ordering}, mpsc::{self, SyncSender}, Arc, Mutex};
use std::{thread, time::Duration};

fn label(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

/// Only structured identifiers and fixed explanatory text are retained. Never
/// copy an error's arbitrary message: it can contain proxy credentials or URLs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticFailure {
    pub code: String,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::Paths;
    use std::{fs, time::Instant};

    fn store() -> StateStore {
        let root = std::env::temp_dir().join(format!("cw-channel-log-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        StateStore::new(Paths::new(root).unwrap())
    }
    fn event(stage: &str) -> ChannelDiagnostic {
        ChannelDiagnostic { component: "channel_enforcer".into(), stage: stage.into(),
            executor_boot_id: Some("boot-log-fixture".into()), family: Some("claude".into()),
            session_id: Some(uuid::Uuid::nil().to_string()), flow_id: Some("flow-claude-1".into()),
            policy_version: Some(PolicyVersion { policy_digest: "policy-1".into(), guard_policy_digest: "guard-1".into() }),
            permit_generation: Some(7), command_seq: Some(9), ..Default::default() }
    }
    fn wait_until(check: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !check() { assert!(Instant::now() < deadline, "diagnostic writer did not complete"); thread::sleep(Duration::from_millis(10)); }
    }
    #[test]
    fn channel_history_survives_restart_and_rotation_with_strict_redaction() {
        let storage = store();
        let logger = ChannelDiagnostics::new(storage.clone());
        let mut first = event("command_failed");
        first.failure = Some(DiagnosticFailure::from_error(&CoreError::new("upstream_connect_failed", "http://user:secret@host/path?token=secret /Users/private/file")));
        logger.record(first.clone(), 100.0);
        wait_until(|| logger.health().written == 1);
        let events = EventStore::new(storage.clone());
        assert_eq!(events.history().unwrap().events.iter().find_map(|e| e.fields.channel_diagnostic.clone()), Some(first));
        let path = storage.paths.base().join("diagnostic-events.jsonl");
        let original = fs::read(&path).unwrap();
        let mut padded = original.clone(); padded.extend(vec![b' '; 1_048_576]);
        fs::write(&path, padded).unwrap();
        drop(logger);
        let restarted = ChannelDiagnostics::new(storage.clone());
        restarted.record(event("termination_confirmed"), 101.0);
        wait_until(|| restarted.health().written == 1);
        let history = events.history().unwrap();
        let rows: Vec<_> = history.events.iter().filter_map(|e| e.fields.channel_diagnostic.as_ref()).collect();
        assert!(rows.iter().any(|d| d.stage == "command_failed" && d.command_seq == Some(9)));
        assert!(rows.iter().any(|d| d.stage == "termination_confirmed" && d.flow_id.as_deref() == Some("flow-claude-1")));
        assert!(storage.paths.base().join("diagnostic-events.previous.jsonl").is_file());
        let encoded = serde_json::to_string(&history.events).unwrap();
        for secret in ["secret", "user:secret", "/Users/private", "host/path"] { assert!(!encoded.contains(secret)); }
        let mut rejected = event("failure"); rejected.flow_id = Some("https://secret.example/token".into());
        assert!(events.append("channel-diagnostic", EventFields { channel_diagnostic: Some(rejected), ..Default::default() }, 102.0).is_err());
    }

    #[test]
    fn stalled_writer_does_not_block_control_and_losses_survive_restart() {
        let storage = store();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let writer_store = storage.clone();
        let mut first = true;
        let logger = ChannelDiagnostics::with_writer(1, storage.clone(), move |event, at| {
            if first { first = false; entered_tx.send(()).unwrap(); release_rx.recv().unwrap();
                return Err(CoreError::new("state_io_failed", "credential=secret")); }
            EventStore::new(writer_store.clone()).append("channel-diagnostic", EventFields {
                channel_diagnostic: Some(event), ..Default::default()
            }, at).map(|_| ())
        });
        logger.record(event("permit_verified"), 100.0);
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let started = Instant::now();
        logger.record(event("revocation_requested"), 101.0);
        logger.record(event("termination_confirmed"), 102.0);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(logger.health().dropped, 1);
        assert!(logger.health_message().unwrap().contains("丢弃 1 条"));
        release_tx.send(()).unwrap();
        wait_until(|| logger.health().write_failed == 1 && logger.health().written == 1);
        let events = EventStore::new(storage.clone());
        wait_until(|| events.history().unwrap().events.iter().any(|e| e.fields.channel_diagnostic.as_ref()
            .and_then(|d| d.log_health.as_ref()).is_some_and(|h| h.dropped == 1 && h.write_failed == 1)));
        drop(logger);
        let restarted_reader = EventStore::new(storage);
        assert!(restarted_reader.history().unwrap().events.iter().any(|e| e.fields.channel_diagnostic.as_ref()
            .and_then(|d| d.log_health.as_ref()).is_some_and(|h| h.last_failure.as_ref().is_some_and(|f| f.code == "state_io_failed"))));
    }
}
impl DiagnosticFailure {
    pub fn from_error(error: &CoreError) -> Self {
        let code = if label(&error.code, 160) { error.code.clone() } else { "invalid_error_code".into() };
        let reason = Self::reason_for(&code).to_string();
        Self { code, reason }
    }
    fn reason_for(code: &str) -> &'static str {
        match code {
            "state_io_failed" => "受管理状态文件读写失败",
            "unsafe_path" | "home_owner_mismatch" => "状态路径或属主校验失败",
            "busy" => "状态记录锁正在被占用",
            "upstream_connect_failed" => "指定上游连接失败，未回退直连",
            "upstream_connect_rejected" => "指定上游拒绝代理握手",
            "upstream_connect_handshake_timeout" => "指定上游代理握手超时或响应读取失败",
            "upstream_connect_handshake_failed" => "向指定上游发送代理握手失败",
            "gateway_endpoint_unverified_i03" => "系统托管网关端点未通过身份与占用核验",
            "enforcer_listener_mode_failed" | "enforcer_listener_thread_failed" => "受控网关监听启动失败",
            "tunnel_bridge_pair_failed" | "socket_clone_failed" => "受控连接所需的本地套接字创建失败",
            "process_attribution_rejected" => "进程归属核验失败",
            "channel_changed_during_dial" => "建连期间授权或上下文已变化",
            "invalid_upstream_endpoint" => "受控上游地址无效",
            "enforcer_poisoned" | "receipt_publication_poisoned" => "执行器内部状态不可用",
            "diagnostic_writer_unavailable" => "诊断写入线程不可用",
            _ => "操作失败；按原始错误码定位，敏感原始说明未落盘",
        }
    }
    fn valid(&self) -> bool { label(&self.code, 160) && self.reason == Self::reason_for(&self.code) }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChannelDiagnostic {
    pub component: String,
    pub stage: String,
    pub producer_boot_id: Option<String>,
    pub executor_boot_id: Option<String>,
    pub family: Option<String>,
    pub session_id: Option<String>,
    pub flow_id: Option<String>,
    pub policy_version: Option<PolicyVersion>,
    pub permit_generation: Option<u64>,
    pub command_seq: Option<u64>,
    pub event_seq: Option<u64>,
    pub pid: Option<u32>,
    pub state: Option<String>,
    pub reason_code: Option<String>,
    pub source_observed_at: Option<f64>,
    pub failure: Option<DiagnosticFailure>,
    pub log_health: Option<ChannelLogHealth>,
}
impl ChannelDiagnostic {
    fn event_fields(self) -> EventFields {
        EventFields { operation: Some(self.component.clone()), stage: Some(self.stage.clone()),
            status: self.state.clone().or_else(|| self.failure.as_ref().map(|_| "failed".into())),
            code: self.failure.as_ref().map(|e| e.code.clone()).or_else(|| self.reason_code.clone()),
            channel_diagnostic: Some(self), ..Default::default() }
    }
    pub fn validate(&self) -> Result<()> {
        let identifiers = [&self.producer_boot_id, &self.executor_boot_id, &self.family,
            &self.session_id, &self.flow_id, &self.state, &self.reason_code];
        if !matches!(self.component.as_str(), "channel_enforcer" | "channel_supervisor" | "channel_diagnostics")
            || !label(&self.stage, 80)
            || identifiers.into_iter().flatten().any(|s| !label(s, 160))
            || self.policy_version.as_ref().is_some_and(|p| !label(&p.policy_digest, 128) || !label(&p.guard_policy_digest, 128))
            || self.failure.as_ref().is_some_and(|f| !f.valid())
            || self.source_observed_at.is_some_and(|t| !t.is_finite() || t < 0.0)
            || self.log_health.as_ref().and_then(|h| h.last_failure.as_ref()).is_some_and(|f| !f.valid())
        { return Err(CoreError::new("invalid_event", "通道诊断字段无效或包含非结构化内容")); }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelLogHealth {
    pub dropped: u64,
    pub write_failed: u64,
    pub state_write_failed: u64,
    pub health_write_failed: u64,
    pub written: u64,
    pub last_failure: Option<DiagnosticFailure>,
}
#[derive(Default)]
struct Health {
    dropped: AtomicU64, failed: AtomicU64, state_failed: AtomicU64,
    health_failed: AtomicU64, written: AtomicU64, last_failure: Mutex<Option<DiagnosticFailure>>,
}
impl Health {
    fn snapshot(&self) -> ChannelLogHealth {
        ChannelLogHealth { dropped: self.dropped.load(Ordering::Relaxed),
            write_failed: self.failed.load(Ordering::Relaxed),
            state_write_failed: self.state_failed.load(Ordering::Relaxed),
            health_write_failed: self.health_failed.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            last_failure: self.last_failure.try_lock().ok().and_then(|v| v.clone()) }
    }
    fn error(&self, err: &CoreError) {
        if let Ok(mut last) = self.last_failure.try_lock() { *last = Some(DiagnosticFailure::from_error(err)); }
    }
}
struct Entry { diagnostic: ChannelDiagnostic, at: f64 }

#[derive(Clone)]
pub struct ChannelDiagnostics { sender: SyncSender<Entry>, health: Arc<Health> }
impl ChannelDiagnostics {
    pub fn new(storage: StateStore) -> Self {
        Self::with_writer(128, storage.clone(), move |diagnostic, at| {
            EventStore::new(storage.clone()).append("channel-diagnostic", diagnostic.event_fields(), at).map(|_| ())
        })
    }
    fn with_writer<F>(capacity: usize, storage: StateStore, mut write: F) -> Self
    where F: FnMut(ChannelDiagnostic, f64) -> Result<()> + Send + 'static {
        let (sender, receiver) = mpsc::sync_channel::<Entry>(capacity);
        let health = Arc::new(Health::default());
        let worker_health = health.clone();
        let writer_boot_id = format!("log-writer-{}", uuid::Uuid::new_v4());
        let worker = thread::Builder::new().name("channel-diagnostic-writer".into()).spawn(move || {
            let mut last_health = None;
            let mut last_loss_record = (0, 0, 0, 0);
            let mut last_health_write = std::time::Instant::now();
            loop {
                let disconnected = match receiver.recv_timeout(Duration::from_millis(500)) {
                    Ok(entry) => {
                        match write(entry.diagnostic, entry.at) {
                            Ok(()) => { worker_health.written.fetch_add(1, Ordering::Relaxed); }
                            Err(error) => { worker_health.failed.fetch_add(1, Ordering::Relaxed); worker_health.error(&error); }
                        }
                        false
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => false,
                    Err(mpsc::RecvTimeoutError::Disconnected) => true,
                };
                let snapshot = worker_health.snapshot();
                let losses = (snapshot.dropped, snapshot.write_failed, snapshot.state_write_failed, snapshot.health_write_failed);
                if losses != last_loss_record {
                    // Retain losses in the same rotated history so a later
                    // boot cannot overwrite the only evidence of missing logs.
                    let diagnostic = ChannelDiagnostic { component: "channel_diagnostics".into(),
                        stage: "log_health".into(), producer_boot_id: Some(writer_boot_id.clone()),
                        log_health: Some(snapshot.clone()), ..Default::default() };
                    if EventStore::new(storage.clone()).append("channel-diagnostic", diagnostic.event_fields(),
                        crate::native::now()).is_ok() { last_loss_record = losses; }
                }
                if last_health.as_ref() != Some(&snapshot)
                    && (last_health.is_none() || losses != (0, 0, 0, 0) || last_health_write.elapsed() >= Duration::from_secs(1)) {
                    let value = serde_json::json!({"captured_at":crate::native::now(),
                        "pid":std::process::id(),"writer_boot_id":writer_boot_id,"health":snapshot,
                        "scope":"current_writer_lifetime","shutdown_flush_guaranteed":false});
                    if let Err(error) = storage.atomic_json(&storage.paths.watch().join("state/channel-log-health.json"), &value) {
                        worker_health.health_failed.fetch_add(1, Ordering::Relaxed);
                        worker_health.error(&error);
                    } else { last_health = Some(snapshot); last_health_write = std::time::Instant::now(); }
                }
                if disconnected { break; }
            }
        });
        if worker.is_err() {
            health.failed.fetch_add(1, Ordering::Relaxed);
            health.error(&CoreError::new("diagnostic_writer_unavailable", "诊断线程不可用"));
        }
        Self { sender, health }
    }
    /// Never waits for disk, an available queue slot, or the writer's mutex.
    pub fn record(&self, diagnostic: ChannelDiagnostic, at: f64) {
        if self.sender.try_send(Entry { diagnostic, at }).is_err() {
            self.health.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn persistence_failed(&self, mut diagnostic: ChannelDiagnostic, error: &CoreError, at: f64) {
        self.health.state_failed.fetch_add(1, Ordering::Relaxed);
        self.health.error(error);
        diagnostic.failure = Some(DiagnosticFailure::from_error(error));
        self.record(diagnostic, at);
    }
    pub fn health(&self) -> ChannelLogHealth { self.health.snapshot() }
    pub fn health_message(&self) -> Option<String> {
        let h = self.health();
        (h.dropped + h.write_failed + h.state_write_failed + h.health_write_failed > 0).then(|| format!(
            "通道日志丢弃 {} 条、事件写入失败 {} 次、状态保存失败 {} 次、日志健康保存失败 {} 次（{}）；本次运行未落盘记录可能缺失。",
            h.dropped, h.write_failed, h.state_write_failed, h.health_write_failed,
            h.last_failure.map(|e| e.code).unwrap_or_else(|| "queue_full_or_closed".into())))
    }
}
