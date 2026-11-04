use claude_watch_core::{config::Config, policy::PolicyCatalog, processes::Provider};
use claude_watch_runtime::{
    events::{EventFields, EventStore},
    storage::{Paths, StateStore},
};
use std::fs;
use uuid::Uuid;

#[test]
fn terminal_lifecycle_failures_use_the_existing_session_policy() {
    for code in ["session_pending", "launch_failed"] {
        let criterion = PolicyCatalog::criterion_for(code).expect(code);
        assert_eq!(criterion.id, "session");
        assert_eq!(Config::default().close_action(code, Provider::Codex), "close");
        assert_eq!(Config::default().close_action(code, Provider::Claude), "close");
    }
    assert_eq!(Config::default().close_action("unregistered_future_reason", Provider::Codex), "warn");
}

#[test]
fn normal_lifecycle_events_are_preserved_by_the_real_event_writer() {
    let root = std::env::temp_dir().join(format!("cw-lifecycle-events-{}", Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let store = EventStore::new(StateStore::new(Paths::new(&root).unwrap()));
    let session = Uuid::new_v4().to_string();
    for (i, (state, code)) in [
        ("active", "session_adopted"),
        ("locked", "dns_egress_changed"),
        ("active", "session_resumed"),
    ].into_iter().enumerate() {
        store.append("guard-decision", EventFields {
            session_id: Some(session.clone()),
            status: Some(state.into()),
            code: Some(code.into()),
            action: Some("post_action".into()),
            previous_state: (i > 0).then(|| if i == 1 { "active" } else { "locked" }.into()),
            ..Default::default()
        }, 1000.0 + i as f64).unwrap();
    }
    let history = store.history().unwrap();
    assert_eq!(history.invalid_records, 0);
    assert_eq!(history.events.len(), 3);
    assert!(history.events.iter().any(|e| e.fields.status.as_deref() == Some("active")
        && e.fields.code.as_deref() == Some("session_adopted")));
    assert!(history.events.iter().any(|e| e.fields.status.as_deref() == Some("active")
        && e.fields.code.as_deref() == Some("session_resumed")));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unregistered_guard_labels_are_not_accepted_as_structured_events() {
    let root = std::env::temp_dir().join(format!("cw-lifecycle-reject-{}", Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let store = EventStore::new(StateStore::new(Paths::new(&root).unwrap()));
    assert!(store.append("guard-decision", EventFields {
        status: Some("private-state".into()),
        code: Some("cookie=secret".into()),
        action: Some("post_action".into()),
        ..Default::default()
    }, 1000.0).is_err());
    fs::remove_dir_all(root).unwrap();
}
