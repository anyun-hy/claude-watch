use claude_watch_runtime::{
    events::*,
    storage::{Paths, StateStore},
};
use std::{
    fs,
    sync::atomic::{AtomicUsize, Ordering},
};
fn store(name: &str) -> (EventStore, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("watch-events-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    (
        EventStore::new(StateStore::new(Paths::new(&root).unwrap())),
        root,
    )
}

#[test]
fn channel_failure_history_remains_searchable_and_retains_build_and_execution_identity() {
    use claude_watch_runtime::{channel_diagnostics::{ChannelDiagnostic, DiagnosticFailure}, monitor_snapshot::{event_history, EventHistoryQuery}};
    let (events, root) = store("channel-build-history");
    events.append("channel-diagnostic", EventFields { channel_diagnostic: Some(ChannelDiagnostic {
        component: "channel_enforcer".into(), stage: "termination_failed".into(),
        producer_boot_id: Some("producer-123".into()), executor_boot_id: Some("executor-456".into()),
        family: Some("claude".into()), flow_id: Some("flow-789".into()), command_seq: Some(12),
        failure: Some(DiagnosticFailure::from_error(&claude_watch_core::error::CoreError::new("state_io_failed", "secret-not-retained"))),
        ..Default::default()
    }), ..Default::default() }, 10.0).unwrap();
    let path = root.join("Library/Application Support/ClaudeWatch/switcher/diagnostic-events.jsonl");
    let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    record["build_identity"] = serde_json::json!({"schema":1,"app_version":"3.0.0","app_build":"381", "source_revision":"a".repeat(40),"source_dirty":true,"source_tree_digest":"b".repeat(64)});
    fs::write(&path, format!("{}\n", record)).unwrap();
    assert_eq!(events.history().unwrap().events[0].build_identity.as_ref().unwrap().app_build, "381");
    let history = event_history(&StateStore::new(Paths::new(&root).unwrap()), &EventHistoryQuery {
        filter: "attention".into(), query: "flow-789".into(), offset: 0,
    }).unwrap();
    assert_eq!(history["total"], 1);
    assert_eq!(history["events"][0]["severity"], "error");
    assert_eq!(history["events"][0]["category"], "network");
    let event = history["events"][0].to_string();
    for expected in ["state_io_failed", "executor-456", "producer-123", "381", "termination_failed"] { assert!(event.contains(expected)); }
    assert!(!event.contains("secret-not-retained"));
    // Historical records without a build receipt remain readable.
    record.as_object_mut().unwrap().remove("build_identity");
    fs::write(&path, format!("{}\n", record)).unwrap();
    assert!(events.history().unwrap().events[0].build_identity.is_none());
    record["build_identity"] = serde_json::json!({"schema":1,"app_version":"secret://private", "app_build":"381", "source_revision":null,"source_dirty":null,"source_tree_digest":"b".repeat(64)});
    fs::write(&path, format!("{}\n", record)).unwrap();
    let invalid = events.history().unwrap();
    assert!(invalid.events.is_empty());
    assert_eq!(invalid.invalid_records, 1);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn rotation_preserves_only_one_previous_private_history_and_reads_are_bounded() {
    let (events, root) = store("rotation");
    let path = root.join("Library/Application Support/ClaudeWatch/switcher");
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("events.jsonl"), vec![b'x'; 1_048_577]).unwrap();
    events
        .append("rotate", EventFields::default(), 9.0)
        .unwrap();
    assert!(path.join("events.previous.jsonl").exists());
    assert_eq!(events.recent(30).unwrap().len(), 1);
    assert!(
        events.export(400).unwrap()["events"]
            .as_array()
            .unwrap()
            .len()
            <= 400
    );
    fs::remove_dir_all(root).unwrap();
}
struct Fake {
    calls: AtomicUsize,
    ok: bool,
}
impl Notifier for Fake {
    fn notify(&self, _: &Alert) -> std::result::Result<(), NotifyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.ok {
            Ok(())
        } else {
            Err(NotifyError {
                code: "unavailable".into(),
                detail: "fixture".into(),
            })
        }
    }
}
#[test]
fn event_schema_drops_secret_shaped_unstructured_data_and_exports_bounded_history() {
    let (events, root) = store("redact");
    assert!(events
        .append(
            "audit",
            EventFields {
                operation: Some("safe".into()),
                ..Default::default()
            },
            1.0
        )
        .is_ok());
    assert!(events
        .append(
            "audit",
            EventFields {
                operation: Some("token=secret".into()),
                ..Default::default()
            },
            2.0
        )
        .is_err());
    assert_eq!(
        events.export(1).unwrap()["events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(events.export(1).unwrap()["sensitive_fields"], "excluded");
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn muted_and_failed_alerts_do_not_consume_cooldown_and_clock_rollback_is_suppressed() {
    let (events, root) = store("cooldown");
    let ok = Fake {
        calls: AtomicUsize::new(0),
        ok: true,
    };
    let fail = Fake {
        calls: AtomicUsize::new(0),
        ok: false,
    };
    let alert = Alert {
        title: "network-change".into(),
        message: "token=never-persisted".into(),
        severity: Severity::Warning,
    };
    events.pause(10.0).unwrap();
    assert_eq!(events.emit(&ok, &alert, 11.0).unwrap(), AlertOutcome::Muted);
    events.arm("round-1", 12.0).unwrap();
    assert_eq!(
        events.emit(&fail, &alert, 13.0).unwrap(),
        AlertOutcome::Failed("notification_failed".into())
    );
    assert_eq!(events.emit(&ok, &alert, 14.0).unwrap(), AlertOutcome::Sent);
    assert_eq!(
        events.emit(&ok, &alert, 15.0).unwrap(),
        AlertOutcome::Cooldown
    );
    assert_eq!(
        events.emit(&ok, &alert, 1.0).unwrap(),
        AlertOutcome::ClockRollback
    );
    assert_eq!(ok.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fail.calls.load(Ordering::SeqCst), 1);
    let raw = fs::read_to_string(
        root.join("Library/Application Support/ClaudeWatch/switcher/events.jsonl"),
    )
    .unwrap();
    assert!(!raw.contains("never-persisted"));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn snooze_and_test_alert_follow_cli_semantics_without_platform_calls() {
    let (events, root) = store("mode");
    let fake = Fake {
        calls: AtomicUsize::new(0),
        ok: true,
    };
    assert_eq!(
        events.snooze(2, 100.0).unwrap(),
        Mode::Snoozed { until: 220 }
    );
    assert!(!events.notifications_enabled(219.0));
    assert!(events.notifications_enabled(220.0));
    assert_eq!(events.test_alert(&fake, 220.0).unwrap(), AlertOutcome::Sent);
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    assert!(events.snooze(0, 1.0).is_err());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn legacy_pause_is_preserved_and_new_events_have_distinct_ids() {
    let (events, root) = store("legacy-mode");
    let old = root.join("Library/Application Support/ClaudeWatch/state/mode");
    fs::create_dir_all(old.parent().unwrap()).unwrap();
    fs::write(&old, b"paused\n").unwrap();
    assert!(!events.notifications_enabled(100.));
    assert!(!root
        .join("Library/Application Support/ClaudeWatch/switcher/alert-mode.json")
        .exists());
    events.arm("native", 101.).unwrap();
    assert!(events.notifications_enabled(102.));
    let a = events
        .append(
            "traffic-counter",
            EventFields {
                pid: Some(77),
                bytes_in: Some(1),
                ..Default::default()
            },
            103.,
        )
        .unwrap();
    let b = events
        .append(
            "traffic-counter",
            EventFields {
                pid: Some(77),
                bytes_in: Some(1),
                ..Default::default()
            },
            103.,
        )
        .unwrap();
    assert_ne!(a.id, b.id);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn failed_critical_dialog_reserves_cooldown_before_the_next_tick() {
    let (events, root) = store("critical-cooldown");
    let fail = Fake {
        calls: AtomicUsize::new(0),
        ok: false,
    };
    let alert = Alert {
        title: "Claude Watch：监控异常".into(),
        message: "请查看本轮检测来源。".into(),
        severity: Severity::Critical,
    };
    assert!(matches!(
        events.emit(&fail, &alert, 100.).unwrap(),
        AlertOutcome::Failed(_)
    ));
    assert_eq!(
        events.emit(&fail, &alert, 102.).unwrap(),
        AlertOutcome::Cooldown
    );
    assert_eq!(fail.calls.load(Ordering::SeqCst), 1);
    fs::remove_dir_all(root).unwrap();
}
