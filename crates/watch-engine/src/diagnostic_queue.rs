//! Best-effort, bounded event writer. Producers never wait for filesystem I/O.
use claude_watch_runtime::{
    events::{EventFields, EventStore},
    storage::StateStore,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender},
        Arc,
    },
    thread,
};
use uuid::Uuid;

struct Entry {
    category: &'static str,
    fields: EventFields,
    at: f64,
}
#[derive(Clone)]
pub struct DiagnosticQueue {
    sender: SyncSender<Entry>,
    dropped: Arc<AtomicU64>,
    failed: Arc<AtomicU64>,
}
impl DiagnosticQueue {
    pub fn new(store: StateStore) -> Self {
        let (sender, receiver) = mpsc::sync_channel::<Entry>(128);
        let dropped = Arc::new(AtomicU64::new(0));
        let failed = Arc::new(AtomicU64::new(0));
        let writer_failed = failed.clone();
        if thread::Builder::new()
            .name("watch-diagnostic-writer".into())
            .spawn(move || {
                let events = EventStore::new(store);
                while let Ok(entry) = receiver.recv() {
                    if events
                        .append(entry.category, entry.fields, entry.at)
                        .is_err()
                    {
                        writer_failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
            .is_err()
        {
            failed.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            sender,
            dropped,
            failed,
        }
    }
    fn send(&self, category: &'static str, fields: EventFields, at: f64) {
        if self
            .sender
            .try_send(Entry {
                category,
                fields,
                at,
            })
            .is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn health_message(&self) -> Option<String> {
        let lost = self.dropped.load(Ordering::Relaxed);
        let failed = self.failed.load(Ordering::Relaxed);
        (lost > 0 || failed > 0).then(|| format!("本次后台运行的诊断日志丢弃 {lost} 条、写入失败 {failed} 条；重启前后的未落盘记录可能缺失。"))
    }
}
fn uuid(value: &Value) -> Option<String> {
    value
        .as_str()
        .filter(|v| Uuid::parse_str(v).is_ok())
        .map(str::to_owned)
}
fn state(value: &Value, allowed: &[&str]) -> String {
    value
        .as_str()
        .filter(|s| allowed.contains(s))
        .unwrap_or("unknown")
        .to_owned()
}
fn reasons(value: &Value) -> BTreeMap<String, u32> {
    let mut counts = BTreeMap::<String, u32>::new();
    for (key, value) in value.as_object().into_iter().flatten() {
        let Some(count) = value.as_u64().and_then(|v| u32::try_from(v).ok()) else {
            continue;
        };
        let key = if [
            "process_exited",
            "identity_changed",
            "missing_target_sample",
            "fd_inventory_unavailable",
            "socket_deadline",
            "socket_info_unavailable",
            "fd_closed_during_sample",
            "fd_list_truncated",
            "foreign_socket_pid",
            "socket_sample_partial",
        ]
        .contains(&key.as_str())
        {
            key.as_str()
        } else {
            "other"
        };
        let n = counts.entry(key.into()).or_default();
        *n = n.saturating_add(count);
    }
    counts
}
#[derive(Default)]
pub struct SamplingHistory {
    health: Option<(String, f64)>,
    connection: Option<(String, f64)>,
    last_summary: f64,
    last_round: Option<String>,
    exited_total: u32,
    reason_totals: BTreeMap<String, u32>,
    partial_reasons: Vec<String>,
}
impl SamplingHistory {
    pub fn observe(&mut self, queue: &DiagnosticQueue, snapshot: &Value, at: f64) {
        let health = state(&snapshot["health"]["state"], &["running", "degraded"]);
        let observation = &snapshot["proxy"]["connectionObservation"];
        let connection = state(
            &observation["collectorState"],
            &["ok", "partial", "empty", "no_targets", "failed", "unknown"],
        );
        let round = uuid(&observation["roundID"]);
        let counts = reasons(&observation["dropped"]);
        let exited = observation["confirmedExitedCount"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(0);
        if round.is_some() && round != self.last_round {
            self.exited_total = self.exited_total.saturating_add(exited);
            for (key, value) in &counts {
                let n = self.reason_totals.entry(key.clone()).or_default();
                *n = n.saturating_add(*value);
            }
            self.last_round = round.clone();
        }
        let reason_set: Vec<_> = counts
            .iter()
            .filter(|(_, v)| **v > 0)
            .map(|(k, _)| k.clone())
            .collect();
        let reason_changed = connection == "partial"
            && self.connection.as_ref().is_some_and(|v| v.0 == "partial")
            && self.partial_reasons != reason_set;
        let summary = self.last_summary == 0.0 || at - self.last_summary >= 300.0;
        let summary_span = (self.last_summary > 0.0).then_some((at - self.last_summary).max(0.0));
        for (operation, current, previous) in [
            ("health", health, &mut self.health),
            ("connection", connection.clone(), &mut self.connection),
        ] {
            let changed = previous.as_ref().is_none_or(|(old, _)| old != &current)
                || (operation == "connection" && reason_changed);
            if changed {
                queue.send(
                    "sampling-state",
                    EventFields {
                        operation: Some(operation.into()),
                        status: Some(current.clone()),
                        action: Some("transition".into()),
                        previous_state: previous.as_ref().map(|v| v.0.clone()),
                        elapsed_seconds: previous.as_ref().map(|v| (at - v.1).max(0.0)),
                        round_id: round.clone(),
                        confirmed_exited_count: (operation == "connection").then_some(exited),
                        reason_counts: (operation == "connection").then(|| counts.clone()),
                        ..Default::default()
                    },
                    at,
                );
            }
            if summary {
                queue.send(
                    "sampling-state",
                    EventFields {
                        operation: Some(operation.into()),
                        status: Some(current.clone()),
                        action: Some("summary".into()),
                        elapsed_seconds: summary_span,
                        round_id: round.clone(),
                        confirmed_exited_count: (operation == "connection")
                            .then_some(self.exited_total),
                        reason_counts: (operation == "connection")
                            .then(|| self.reason_totals.clone()),
                        ..Default::default()
                    },
                    at,
                );
            }
            if previous.as_ref().is_none_or(|(old, _)| old != &current) {
                *previous = Some((current, at));
            }
        }
        self.partial_reasons = if connection == "partial" {
            reason_set
        } else {
            Vec::new()
        };
        if summary {
            self.last_summary = at;
            self.exited_total = 0;
            self.reason_totals.clear();
        }
    }
}
#[derive(Default)]
pub struct GuardHistory {
    last: Option<(Option<String>, String, String)>,
    last_failed: Option<String>,
}
impl GuardHistory {
    pub fn observe(&mut self, queue: &DiagnosticQueue, receipt: &Value, at: f64) {
        let session = uuid(&receipt["session_id"]);
        let guard = &receipt["session_guard"];
        let current = state(
            &guard["state"],
            &[
                "idle", "safe", "risk", "locked", "unknown", "missing", "pending",
            ],
        );
        let code = match guard["reason"]["code"].as_str() {
            None => "none",
            Some(
                code @ ("egress_ip_changed"
                | "egress_country_cn"
                | "session_identity_changed"
                | "proxy_or_tun_failed"
                | "egress_risk_persist_failed"
                | "evidence_expired"
                | "dns_risk"
                | "webrtc_risk"
                | "egress_unconfirmed"
                | "proxy_or_tun_unconfirmed"
                | "guard_sampling_failed"
                | "session_identity_unconfirmed"
                | "session_pending"
                | "risk_evidence_unavailable"
                | "risk_evidence_missing"),
            ) => code,
            _ => "other",
        };
        let changed = self
            .last
            .as_ref()
            .is_none_or(|v| v.0 != session || v.1 != current || v.2 != code);
        if changed || current == "risk" {
            queue.send(
                "guard-decision",
                EventFields {
                    session_id: session.clone(),
                    status: Some(current.clone()),
                    previous_state: self
                        .last
                        .as_ref()
                        .filter(|v| v.0 == session)
                        .map(|v| v.1.clone()),
                    code: Some(code.into()),
                    action: Some("post_action".into()),
                    egress_sampled_at: guard["current"]["observed_at"]
                        .as_f64()
                        .filter(|v| v.is_finite() && *v > 0.0 && *v <= at),
                    dns_sampled_at: guard["risk_evidence"]["sources"]["dns"]["observed_at"]
                        .as_f64()
                        .filter(|v| v.is_finite() && *v > 0.0 && *v <= at),
                    webrtc_sampled_at: guard["risk_evidence"]["sources"]["webrtc"]["observed_at"]
                        .as_f64()
                        .filter(|v| v.is_finite() && *v > 0.0 && *v <= at),
                    ..Default::default()
                },
                at,
            );
        }
        if matches!(receipt["stop_state"].as_str(), Some("confirmed" | "failed"))
            && receipt["stop_started_at"]
                .as_f64()
                .is_some_and(|v| v.is_finite() && v > 0.0 && v <= at)
            && receipt["stop_completed_at"].as_f64().is_some_and(|v| {
                v.is_finite() && v >= receipt["stop_started_at"].as_f64().unwrap() && v <= at
            })
        {
            let action_id = Uuid::new_v4().to_string();
            let duration = receipt["stop_elapsed_seconds"]
                .as_f64()
                .filter(|v| v.is_finite() && *v >= 0.0);
            let start = receipt["stop_started_at"]
                .as_f64()
                .filter(|v| v.is_finite() && *v > 0.0 && *v <= at)
                .unwrap_or(at);
            let completed = receipt["stop_completed_at"]
                .as_f64()
                .filter(|v| v.is_finite() && *v >= start && *v <= at)
                .unwrap_or(at);
            let stop_code = if receipt["stop_state"] == "failed" {
                Some(
                    match receipt["stop_error"].as_str() {
                        Some("claude_still_running") => "claude_still_running",
                        Some("write_not_authorized" | "protected_scope_mismatch") => {
                            "permission_denied"
                        }
                        Some("process_component_missing" | "command_not_found") => {
                            "component_unavailable"
                        }
                        Some("desktop_inventory_incomplete" | "process_metadata_unavailable") => {
                            "identity_unconfirmed"
                        }
                        _ => "other",
                    }
                    .to_owned(),
                )
            } else {
                None
            };
            let retry = session.is_some() && self.last_failed == session;
            queue.send(
                "guard-stop",
                EventFields {
                    session_id: session.clone(),
                    correlation_id: Some(action_id.clone()),
                    action: Some(
                        if retry {
                            "retry_post_action"
                        } else {
                            "request_post_action"
                        }
                        .into(),
                    ),
                    ..Default::default()
                },
                start,
            );
            queue.send(
                "guard-stop",
                EventFields {
                    session_id: session.clone(),
                    correlation_id: Some(action_id),
                    action: Some("result_post_action".into()),
                    status: receipt["stop_state"].as_str().map(str::to_owned),
                    code: stop_code,
                    elapsed_seconds: duration,
                    ..Default::default()
                },
                completed,
            );
            self.last_failed = if receipt["stop_state"] == "failed" {
                session.clone()
            } else {
                None
            };
        }
        self.last = Some((session, current, code.into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claude_watch_runtime::storage::Paths;
    use serde_json::json;
    use std::{fs, time::Duration};
    fn fixture() -> (std::path::PathBuf, StateStore) {
        let path = std::env::temp_dir().join(format!("cw-queue-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        let store = StateStore::new(Paths::new(&path).unwrap());
        (path, store)
    }
    fn wait_for(mut ready: impl FnMut() -> bool) {
        for _ in 0..100 {
            if ready() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready());
    }
    #[test]
    fn transitions_recovery_and_guard_attempts_remain_correlated() {
        let (path, store) = fixture();
        let queue = DiagnosticQueue::new(store.clone());
        let mut sampling = SamplingHistory::default();
        let round = Uuid::new_v4().to_string();
        let snapshot = |state| json!({"health":{"state":"running"},"proxy":{"connectionObservation":{"roundID":round,"collectorState":state,"confirmedExitedCount":3,"dropped":{"identity_changed":1}}}});
        sampling.observe(&queue, &snapshot("ok"), 1000.0);
        sampling.observe(&queue, &snapshot("partial"), 1002.0);
        sampling.observe(&queue, &snapshot("ok"), 1012.0);
        let session = Uuid::new_v4().to_string();
        let mut guard = GuardHistory::default();
        let receipt = |state, stop| json!({"session_id":session,"session_guard":{"state":state,"reason":{"code":"egress_ip_changed"}},"stop_state":stop,"stop_error":"claude_still_running","stop_elapsed_seconds":0.1,"stop_started_at":1019.0,"stop_completed_at":1019.5});
        guard.observe(&queue, &receipt("risk", "failed"), 1020.0);
        guard.observe(&queue, &receipt("locked", "confirmed"), 1021.0);
        let events = EventStore::new(store.clone());
        wait_for(|| {
            events.history().is_ok_and(|h| {
                h.events
                    .iter()
                    .filter(|e| e.category == "guard-stop")
                    .count()
                    == 4
            })
        });
        let history = events.history().unwrap().events;
        let recovery = history
            .iter()
            .find(|e| {
                e.category == "sampling-state"
                    && e.fields.operation.as_deref() == Some("connection")
                    && e.fields.previous_state.as_deref() == Some("partial")
            })
            .unwrap();
        assert_eq!(recovery.fields.status.as_deref(), Some("ok"));
        assert_eq!(recovery.fields.elapsed_seconds, Some(10.0));
        let stops: Vec<_> = history
            .iter()
            .filter(|e| e.category == "guard-stop")
            .collect();
        assert_eq!(stops.len(), 4);
        for status in ["failed", "confirmed"] {
            let result = stops
                .iter()
                .find(|e| e.fields.status.as_deref() == Some(status))
                .unwrap();
            assert_eq!(result.fields.session_id.as_deref(), Some(session.as_str()));
            assert!(stops.iter().any(|e| matches!(
                e.fields.action.as_deref(),
                Some("request_post_action" | "retry_post_action")
            ) && e.fields.correlation_id
                == result.fields.correlation_id));
        }
        let failed = stops
            .iter()
            .find(|e| e.fields.status.as_deref() == Some("failed"))
            .unwrap();
        let confirmed = stops
            .iter()
            .find(|e| e.fields.status.as_deref() == Some("confirmed"))
            .unwrap();
        assert_eq!(failed.fields.code.as_deref(), Some("claude_still_running"));
        assert_ne!(
            failed.fields.correlation_id,
            confirmed.fields.correlation_id
        );
        drop(queue);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn full_queue_and_write_failure_are_visible_without_blocking_producer() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let queue = DiagnosticQueue {
            sender,
            dropped: Arc::new(AtomicU64::new(0)),
            failed: Arc::new(AtomicU64::new(0)),
        };
        queue.send("sampling-state", EventFields::default(), 1.0);
        let before = std::time::Instant::now();
        queue.send("sampling-state", EventFields::default(), 2.0);
        assert!(before.elapsed() < Duration::from_millis(100));
        assert!(queue.health_message().unwrap().contains("丢弃 1"));
        drop(receiver);
        let (path, store) = fixture();
        store.initialize().unwrap();
        fs::create_dir(store.paths.base().join("events.jsonl")).unwrap();
        let failing = DiagnosticQueue::new(store);
        failing.send(
            "sampling-state",
            EventFields {
                operation: Some("health".into()),
                status: Some("running".into()),
                action: Some("transition".into()),
                ..Default::default()
            },
            1.0,
        );
        wait_for(|| failing.failed.load(Ordering::Relaxed) > 0);
        assert!(failing.health_message().unwrap().contains("写入失败 1"));
        drop(failing);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn controller_quit_precedes_full_or_failed_log_queue() {
        use claude_watch_core::{
            config::Config,
            error::Result,
            session::{self, Desktop, Launcher},
        };
        use claude_watch_runtime::controlled::{Controller, DesktopSystem};
        struct Fake {
            running: bool,
        }
        impl DesktopSystem for Fake {
            fn now(&self) -> f64 {
                1001.0
            }
            fn monotonic(&self) -> Duration {
                Duration::from_secs(1001)
            }
            fn wait(&mut self, _: Duration) {}
            fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>> {
                Ok(if self.running {
                    vec![(
                        Desktop {
                            pid: 77,
                            start_seconds: 10,
                            start_microseconds: 20,
                        },
                        true,
                        "fixture".into(),
                    )]
                } else {
                    vec![]
                })
            }
            fn launcher(&mut self) -> Result<Launcher> {
                unreachable!()
            }
            fn full_audit(&mut self) -> Result<Value> {
                unreachable!()
            }
            fn egress(&mut self) -> Value {
                panic!("locked session must not probe")
            }
            fn local_guard(&mut self) -> Result<Value> {
                panic!("locked session must not sample")
            }
            fn backend_healthy(&mut self) -> Result<bool> {
                Ok(true)
            }
            fn launcher_matches(&mut self, _: &Launcher) -> Result<bool> {
                Ok(false)
            }
            fn open_desktop(&mut self) -> Result<()> {
                unreachable!()
            }
            fn quit_desktop(&mut self) -> Result<()> {
                self.running = false;
                Ok(())
            }
        }
        let (path, store) = fixture();
        let config = Config {
            guard_enabled: true,
            ..Default::default()
        };
        store
            .atomic_json(&store.paths.config(), &config.value().unwrap())
            .unwrap();
        let reference = json!({"ip":"1.1.1.1","country":"JP","checked_at":1000.0,"context":"ctx","source":"fixture"});
        let audit = json!({"ready":true,"observed_at":1000.0,"expires_at":1030.0,"context_id":"ctx","context_transition":{"state":"stable"},"egress_reference":reference});
        let exit = json!({"ip":"1.1.1.1","country":"JP","observed_at":1000.0});
        let session = session::begin(
            &audit,
            &exit,
            &json!({"state":"safe","observed_at":1000.0}),
            &Uuid::new_v4().to_string(),
            1000.0,
        )
        .unwrap();
        let locked = session::lock(session, "egress_ip_changed", "fixture", 1000.5, None, None);
        store
            .atomic_json(
                &store.paths.session(),
                &serde_json::to_value(locked).unwrap(),
            )
            .unwrap();
        let controller = Controller::new(store.clone());
        let (sender, receiver) = mpsc::sync_channel(1);
        let queue = DiagnosticQueue {
            sender,
            dropped: Arc::new(AtomicU64::new(0)),
            failed: Arc::new(AtomicU64::new(0)),
        };
        queue.send("sampling-state", EventFields::default(), 1000.0);
        let mut fake = Fake { running: true };
        let receipt = controller.guard_tick(&mut fake).unwrap();
        assert!(!fake.running);
        assert_eq!(receipt["stop_state"], "confirmed");
        GuardHistory::default().observe(&queue, &receipt, 1001.0);
        assert!(queue.dropped.load(Ordering::Relaxed) > 0);
        drop(receiver);
        fs::create_dir(store.paths.base().join("events.jsonl")).unwrap();
        let failing = DiagnosticQueue::new(store);
        fake.running = true;
        let receipt = controller.guard_tick(&mut fake).unwrap();
        assert!(!fake.running);
        assert_eq!(receipt["stop_state"], "confirmed");
        GuardHistory::default().observe(&failing, &receipt, 1001.0);
        wait_for(|| failing.failed.load(Ordering::Relaxed) > 0);
        drop(failing);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn stable_rounds_are_counted_once_and_empty_stop_does_not_invent_a_request() {
        let (path, store) = fixture();
        let queue = DiagnosticQueue::new(store.clone());
        let mut history = SamplingHistory::default();
        let r1 = Uuid::new_v4().to_string();
        let r2 = Uuid::new_v4().to_string();
        let snapshot = |round: &str| json!({"health":{"state":"running"},"proxy":{"connectionObservation":{"roundID":round,"collectorState":"ok","confirmedExitedCount":3,"dropped":{}}}});
        history.observe(&queue, &snapshot(&r1), 1000.0);
        history.observe(&queue, &snapshot(&r1), 1002.0);
        history.observe(&queue, &snapshot(&r2), 1004.0);
        history.observe(&queue, &snapshot(&r2), 1300.0);
        let mut guard = GuardHistory::default();
        guard.observe(&queue, &json!({"session_id":Uuid::new_v4().to_string(), "session_guard":{"state":"locked"}, "stop_state":"confirmed"}), 1301.0);
        let events = EventStore::new(store.clone());
        wait_for(|| {
            events
                .history()
                .is_ok_and(|h| h.events.iter().any(|e| e.category == "guard-decision"))
        });
        let rows = events.history().unwrap().events;
        let summary = rows
            .iter()
            .find(|e| {
                e.category == "sampling-state"
                    && e.fields.operation.as_deref() == Some("connection")
                    && e.fields.action.as_deref() == Some("summary")
                    && e.time == 1300.0
            })
            .unwrap();
        assert_eq!(summary.fields.confirmed_exited_count, Some(3));
        assert_eq!(summary.fields.elapsed_seconds, Some(300.0));
        assert!(!rows.iter().any(|e| e.category == "guard-stop"));
        drop(queue);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn reason_changes_record_once_without_resetting_outage_duration() {
        let (path, store) = fixture();
        let queue = DiagnosticQueue::new(store.clone());
        let mut samples = SamplingHistory::default();
        let round = Uuid::new_v4().to_string();
        let sample = |state: &str, reason: &str| json!({"health":{"state":"running"},"proxy":{"connectionObservation":{"roundID":round,"collectorState":state,"confirmedExitedCount":0,"dropped":{reason:1}}}});
        samples.observe(&queue, &sample("partial", "identity_changed"), 1000.0);
        samples.observe(&queue, &sample("partial", "socket_deadline"), 1002.0);
        samples.observe(&queue, &sample("ok", "socket_deadline"), 1010.0);
        let mut guard = GuardHistory::default();
        let sid = Uuid::new_v4().to_string();
        let receipt = |reason| json!({"session_id":sid,"session_guard":{"state":"unknown","reason":{"code":reason}}});
        guard.observe(&queue, &receipt("egress_unconfirmed"), 1011.0);
        guard.observe(&queue, &receipt("guard_sampling_failed"), 1012.0);
        guard.observe(&queue, &receipt("guard_sampling_failed"), 1013.0);
        let events = EventStore::new(store);
        wait_for(|| {
            events.history().is_ok_and(|h| {
                h.events
                    .iter()
                    .filter(|e| e.category == "guard-decision")
                    .count()
                    == 2
            })
        });
        let rows = events.history().unwrap().events;
        let guards: Vec<_> = rows
            .iter()
            .filter(|e| e.category == "guard-decision")
            .collect();
        assert_eq!(guards.len(), 2);
        assert!(guards
            .iter()
            .any(|e| e.fields.code.as_deref() == Some("egress_unconfirmed")));
        assert!(guards
            .iter()
            .any(|e| e.fields.code.as_deref() == Some("guard_sampling_failed")));
        let recovery = rows
            .iter()
            .find(|e| {
                e.category == "sampling-state"
                    && e.fields.operation.as_deref() == Some("connection")
                    && e.fields.status.as_deref() == Some("ok")
            })
            .unwrap();
        assert_eq!(recovery.fields.elapsed_seconds, Some(10.0));
        drop(queue);
        fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn transition_at_summary_deadline_does_not_carry_counts_into_next_window() {
        let (path, store) = fixture();
        let queue = DiagnosticQueue::new(store.clone());
        let mut h = SamplingHistory::default();
        let r1 = Uuid::new_v4().to_string();
        let r2 = Uuid::new_v4().to_string();
        let sample = |round: &str, state: &str, exits: u32| json!({"health":{"state":"running"},"proxy":{"connectionObservation":{"roundID":round,"collectorState":state,"confirmedExitedCount":exits,"dropped":{}}}});
        h.observe(&queue, &sample(&r1, "ok", 1), 1000.0);
        h.observe(&queue, &sample(&r2, "partial", 3), 1300.0);
        h.observe(&queue, &sample(&r2, "partial", 3), 1600.0);
        let events = EventStore::new(store);
        wait_for(|| events.history().is_ok_and(|h| h.events.len() >= 9));
        let rows = events.history().unwrap().events;
        let at_boundary: Vec<_> = rows
            .iter()
            .filter(|e| {
                e.category == "sampling-state"
                    && e.fields.operation.as_deref() == Some("connection")
                    && e.time == 1300.0
            })
            .collect();
        assert_eq!(at_boundary.len(), 2);
        assert!(at_boundary
            .iter()
            .any(|e| e.fields.action.as_deref() == Some("transition")));
        assert!(at_boundary
            .iter()
            .any(|e| e.fields.action.as_deref() == Some("summary")
                && e.fields.confirmed_exited_count == Some(3)));
        assert!(rows.iter().any(|e| e.time == 1600.0
            && e.fields.operation.as_deref() == Some("connection")
            && e.fields.confirmed_exited_count == Some(0)));
        drop(queue);
        fs::remove_dir_all(path).unwrap();
    }
}
