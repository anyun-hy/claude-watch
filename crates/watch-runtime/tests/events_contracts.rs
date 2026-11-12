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
fn muted_alerts_do_not_consume_cooldown_and_failed_alerts_back_off_before_recovery() {
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
    assert_eq!(events.emit(&ok, &alert, 14.0).unwrap(), AlertOutcome::Cooldown);
    assert_eq!(events.emit(&fail, &alert, 43.0).unwrap(), AlertOutcome::Failed("notification_failed".into()));
    assert_eq!(events.emit(&ok, &alert, 102.0).unwrap(), AlertOutcome::Cooldown);
    assert_eq!(events.emit(&ok, &alert, 103.0).unwrap(), AlertOutcome::Sent);
    assert_eq!(
        events.emit(&ok, &alert, 104.0).unwrap(),
        AlertOutcome::Cooldown
    );
    assert_eq!(
        events.emit(&ok, &alert, 1.0).unwrap(),
        AlertOutcome::ClockRollback
    );
    assert_eq!(ok.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fail.calls.load(Ordering::SeqCst), 2);
    let history = events.history().unwrap().events;
    assert_eq!(history.iter().filter(|e| e.category == "alert-failed").count(), 2);
    assert_eq!(history.iter().filter(|e| e.category == "alert-dispatched").count(), 1);
    // A successful delivery resets failure backoff; the next independent
    // failure after the normal cooldown gets the first retry delay again.
    assert!(matches!(events.emit(&fail, &alert, 404.).unwrap(), AlertOutcome::Failed(_)));
    assert_eq!(events.emit(&ok, &alert, 433.).unwrap(), AlertOutcome::Cooldown);
    assert_eq!(events.emit(&ok, &alert, 434.).unwrap(), AlertOutcome::Sent);
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

#[test]
fn warning_failure_backoff_survives_restart_is_capped_and_does_not_claim_delivery() {
    let (events, root) = store("failure-persistence");
    let fail = Fake { calls: AtomicUsize::new(0), ok: false };
    let alert = Alert { title: "warning-fixture".into(), message: "not stored".into(), severity: Severity::Warning };
    let mut at = 100.;
    for delay in [30., 60., 120., 240., 300., 300.] {
        let restarted = EventStore::new(StateStore::new(Paths::new(&root).unwrap()));
        assert!(matches!(restarted.emit(&fail, &alert, at).unwrap(), AlertOutcome::Failed(_)));
        assert_eq!(restarted.emit(&fail, &alert, at - 1.).unwrap(), AlertOutcome::ClockRollback);
        assert_eq!(restarted.emit(&fail, &alert, at + delay - 1.).unwrap(), AlertOutcome::Cooldown);
        at += delay;
    }
    assert_eq!(fail.calls.load(Ordering::SeqCst), 6);
    let history = events.history().unwrap();
    assert_eq!(history.events.iter().filter(|e| e.category == "alert-failed").count(), 6);
    assert!(!history.events.iter().any(|e| e.category == "alert-dispatched"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_warning_does_not_suppress_a_new_critical_alert() {
    let (events, root) = store("failure-severity");
    let fail = Fake { calls: AtomicUsize::new(0), ok: false };
    let ok = Fake { calls: AtomicUsize::new(0), ok: true };
    let mut alert = Alert { title: "severity-fixture".into(), message: "fixture".into(), severity: Severity::Warning };
    assert!(matches!(events.emit(&fail, &alert, 100.).unwrap(), AlertOutcome::Failed(_)));
    alert.severity = Severity::Critical;
    assert_eq!(events.emit(&ok, &alert, 101.).unwrap(), AlertOutcome::Sent);
    assert_eq!(ok.calls.load(Ordering::SeqCst), 1);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn guard_events_accept_only_known_families_and_keep_strict_field_validation() {
    let (events, root) = store("guard-families");
    for family in ["claude", "openai"] {
        let decision = EventFields { family: Some(family.into()), action: Some("post_action".into()),
            status: Some("idle".into()), code: Some("none".into()), ..Default::default() };
        let event = events.append("guard-decision", decision.clone(), 100.).unwrap();
        assert_eq!(event.fields.family.as_deref(), Some(family));
        let stop = EventFields { family: Some(family.into()), correlation_id: Some(uuid::Uuid::new_v4().to_string()),
            action: Some("request_post_action".into()), ..Default::default() };
        events.append("guard-stop", stop, 101.).unwrap();
        let mut extra = decision;
        extra.pid = Some(123);
        assert!(events.append("guard-decision", extra, 102.).is_err());
    }
    assert!(events.append("guard-decision", EventFields { family: Some("private-fixture".into()),
        action: Some("post_action".into()), status: Some("idle".into()), code: Some("none".into()), ..Default::default() }, 103.).is_err());
    assert_eq!(events.history().unwrap().events.len(), 4);
    fs::remove_dir_all(root).unwrap();
}
