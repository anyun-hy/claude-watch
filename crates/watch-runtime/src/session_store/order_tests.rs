use crate as claude_watch_runtime;
use claude_watch_core::session::{CheckInput, Desktop, Identity};
use claude_watch_runtime::{
    session_store::SessionStore,
    storage::{Paths, StateStore},
};
use serde_json::json;
use std::fs;
fn audit(now: f64) -> serde_json::Value {
    json!({"ready":true,"observed_at":now,"expires_at":now+30.,"context_id":"ctx","observation_id":"round","context_transition":{"state":"stable"},"egress_reference":{"ip":"1.1.1.1","country":"JP","checked_at":now,"context":"ctx"}})
}
fn egress(now: f64) -> serde_json::Value {
    json!({"ip":"1.1.1.1","country":"JP","observed_at":now})
}
fn safe(now: f64) -> serde_json::Value {
    json!({"state":"safe","observed_at":now,"sources":{"dns":{"state":"ok"},"webrtc":{"state":"ok"}}})
}
#[test]
fn late_same_session_safe_check_cannot_erase_newer_guard_state() {
    let root = std::env::temp_dir().join(format!("session-order-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let store = SessionStore::new(StateStore::new(Paths::new(&root).unwrap()));
    let session = store
        .begin(&audit(100.), &egress(100.), &safe(100.), 100.)
        .unwrap();
    store
        .bind_desktop(
            &session.session_id,
            Desktop {
                pid: 9,
                start_seconds: 1,
                start_microseconds: 0,
            },
            100.1,
        )
        .unwrap();
    let current = store
        .apply_check(
            Some(&session.session_id),
            &CheckInput {
                now: 110.,
                launcher_live: false,
                identity: Identity::Matches,
                egress: egress(110.),
                risk: safe(110.),
            },
        )
        .unwrap();
    assert_eq!(current.state, "safe");
    let late = store
        .apply_check(
            Some(&session.session_id),
            &CheckInput {
                now: 109.,
                launcher_live: false,
                identity: Identity::Matches,
                egress: egress(109.),
                risk: safe(109.),
            },
        )
        .unwrap_err();
    assert_eq!(late.code, "superseded_check");
    assert_eq!(
        store
            .load(111.)
            .unwrap()
            .unwrap()
            .last_check
            .unwrap()
            .observed_at,
        110.
    );
    fs::remove_dir_all(root).unwrap();
}
