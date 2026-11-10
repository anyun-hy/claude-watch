use claude_watch_core::{channel::{BackendCoverageScope, NetworkBackendKind}, processes::Identity};
use claude_watch_runtime::{channel_supervisor::{ChannelSupervisor, SupervisionEvent}, monitor_snapshot, sampler::Sampler, storage::{Paths, StateStore}};
use serde_json::json;
use std::{fs, os::unix::fs::PermissionsExt, sync::{Arc, Mutex}};
#[path = "support/fixture_inventory.rs"]
mod fixture_inventory;
use fixture_inventory::{FixtureInventory, FixtureProcess};

#[test]
fn rust_monitor_coverage_snapshot_and_events_match_wire_contract() {
    let home = std::env::temp_dir().join(format!("cw-coverage-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&home).unwrap();
    let home=fs::canonicalize(home).unwrap();
    let bundle=home.join("Applications/Claude Fixture.app");
    fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
    let executable=bundle.join("Contents/MacOS/FixtureMain");fs::write(&executable,b"private fixture; never executed").unwrap();
    fs::set_permissions(&executable,fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(bundle.join("Contents/Info.plist"),r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>FixtureMain</string></dict></plist>"#).unwrap();
    let store = StateStore::new(Paths::new(&home).unwrap());
    let mut supervisor = ChannelSupervisor::new_with_config(store.clone(), claude_watch_core::config::Config::default_for_new_install(), None, None, None).unwrap();
    let at = 1_790_000_000.;
    let scope = BackendCoverageScope {
        backend: NetworkBackendKind::Seatbelt,
        configured_entries: vec!["claude-cli".into()],
        protected_pids: vec![4101], unprotected_pids: vec![4102],
        uncovered_boundaries: vec!["unmanaged_existing_processes".into(), "direct_launch_outside_controlled_entry".into()],
        server_identity_verified: false, gateway_endpoint_protection_verified: true,
        gateway_endpoint_protection_method: Some("system_launchd_socket".into()),
    };
    supervisor.set_family_coverage_scope("claude", Some(scope.clone()), at);
    supervisor.set_family_unmanaged_pids("claude", vec![4102], at);
    let controlled = claude_watch_core::channel::BoundProcessToken::with_system_identity(4101, 501, 100, 1, claude_watch_core::processes::ProcessRole::Cli)
        .with_audit_token([501,501,20,501,20,4101,0,9]);
    let snapshot = supervisor.handle_event(SupervisionEvent::ProcessInventoryUpdated { family: "claude".into(), desktops:vec![], processes:vec![controlled], observed_at:at }).unwrap();
    let events = supervisor.drain_emitted_events();
    assert_eq!(snapshot.families["claude"].coverage_scope, scope);
    assert_eq!(events.last().unwrap().family_state.coverage_scope, scope);
    let producer = Identity { pid: 4000, parent: 1, uid: 501, executable: "/fixture/watch-engine".into(), start_seconds: 100, start_microseconds: 1, start_stamp: "fixture".into() };
    let records = [4101, 4102].into_iter().map(|pid| FixtureProcess {
        identity: Identity { pid, parent: 1, uid: 501, executable: executable.to_string_lossy().into_owned(),
            start_seconds: 100, start_microseconds: 1, start_stamp: "fixture".into() },
        bundle: Some((bundle.to_string_lossy().into_owned(), "com.anthropic.claudefordesktop".into())),
        arguments: vec!["Claude".into(), "PRIVATE_DO_NOT_EMIT".into()],
    }).collect();
    let mut sampler = Sampler::new(FixtureInventory(Arc::new(Mutex::new(records))), store.paths.clone());
    let round = sampler.processes().unwrap();
    let monitor = monitor_snapshot::assemble(&store, &round, &json!({}), &producer, "fixture", true, at);
    assert_eq!(monitor["channelSupervision"]["families"]["claude"]["coverage_scope"], json!(scope));
    assert_eq!(monitor["processes"][0]["matchReason"], "verified_bundle");
    assert_ne!(monitor["processes"][0]["protection"]["state"], "protected");
    assert!(!monitor.to_string().contains("PRIVATE_DO_NOT_EMIT"));
    let wire = json!({"snapshot":snapshot,"events":events,"monitor":monitor});
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::create_dir_all(&dir).unwrap();
        let path = std::path::Path::new(&dir).join("monitor-coverage-wire.json");
        fs::write(&path, serde_json::to_vec_pretty(&wire).unwrap()).unwrap();
        println!("production coverage wire: {}", path.display());
    }
    fs::remove_dir_all(home).unwrap();
}
