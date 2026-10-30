use claude_watch_core::processes::{Identity, Kind, Lease, Provider, Target};
use claude_watch_runtime::{
    daemon::DaemonLease,
    lease_store::LeaseStore,
    storage::{Paths, StateStore},
};
use serde_json::json;
use std::{collections::BTreeMap, fs};
fn identity(pid: u32) -> Identity {
    Identity {
        pid,
        parent: 1,
        uid: 501,
        executable: "/test/watch-engine".into(),
        start_seconds: 1000,
        start_microseconds: pid,
        start_stamp: format!("stamp-{pid}"),
    }
}
struct Home(std::path::PathBuf);
impl Home {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("cw-daemon-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn store(&self) -> StateStore {
        StateStore::new(Paths::new(&self.0).unwrap())
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn daemon_owner_is_exclusive_and_failure_never_publishes_healthy_heartbeat() {
    let home = Home::new();
    let store = home.store();
    let me = identity(77);
    let inv = BTreeMap::from([(77, me.clone())]);
    let owner = DaemonLease::acquire(store.clone(), me.clone(), &inv).unwrap();
    assert!(DaemonLease::acquire(store.clone(), me.clone(), &inv).is_err());
    owner
        .publish(
            Ok(json!({"capturedAt":1100.0,"health":{"state":"running","mode":"GUARD"}})),
            1100.0,
        )
        .unwrap();
    assert!(String::from_utf8(
        store
            .read_bytes(&store.paths.watch().join("state/heartbeat"), 4096)
            .unwrap()
            .unwrap()
    )
    .unwrap()
    .contains("|ok|GUARD"));
    let out = owner
        .publish(
            Err(claude_watch_core::error::CoreError::new(
                "sampling_failed",
                "fixture",
            )),
            1102.0,
        )
        .unwrap();
    assert_eq!(out["health"]["state"], "unavailable");
    assert!(String::from_utf8(
        store
            .read_bytes(&store.paths.watch().join("state/heartbeat"), 4096)
            .unwrap()
            .unwrap()
    )
    .unwrap()
    .contains("|error|UNKNOWN"));
    drop(owner);
    assert!(DaemonLease::acquire(store, me, &inv).is_ok());
}
#[test]
fn live_legacy_daemon_is_not_overwritten_and_reused_pid_does_not_block_restart() {
    let home = Home::new();
    let store = home.store();
    let me = identity(77);
    let old = identity(88);
    store
        .atomic_bytes(
            &store.paths.watch().join("state/heartbeat"),
            b"88|stamp-88|1000|ok|GUARD\n",
            0o600,
        )
        .unwrap();
    let mut inv = BTreeMap::from([(77, me.clone()), (88, old)]);
    assert_eq!(
        DaemonLease::acquire(store.clone(), me.clone(), &inv)
            .err()
            .unwrap()
            .code,
        "daemon_already_running"
    );
    inv.get_mut(&88).unwrap().start_stamp = "new-start".into();
    assert!(DaemonLease::acquire(store, me, &inv).is_ok());
}
#[test]
fn leases_survive_partial_observation_and_expire_only_on_complete_identity_evidence() {
    let home = Home::new();
    let store = home.store();
    let leases = LeaseStore {
        storage: store.clone(),
    };
    let root = identity(77);
    let owner = identity(88);
    let inv = BTreeMap::from([(77, root.clone()), (88, owner.clone())]);
    let id = leases
        .save(
            &Lease {
                provider: Provider::Claude,
                root: root.clone(),
                owner: Some(owner),
                cli: true,
            },
            1000.,
        )
        .unwrap();
    assert_eq!(leases.load(&inv, 501, true).unwrap().len(), 1);
    assert!(leases
        .load(&BTreeMap::new(), 501, false)
        .unwrap()
        .is_empty());
    assert!(store
        .paths
        .watch()
        .join(format!("state/sessions/{id}.json"))
        .exists());
    let mut reused = inv;
    reused.get_mut(&77).unwrap().start_microseconds += 1;
    assert!(leases.load(&reused, 501, true).unwrap().is_empty());
    assert!(!store
        .paths
        .watch()
        .join(format!("state/sessions/{id}.json"))
        .exists());
    let targets = vec![Target {
        identity: root,
        kind: Kind::ClaudeMain,
    }];
    leases.save_tracked(&targets, true).unwrap();
    leases.save_tracked(&[], false).unwrap();
    assert_eq!(leases.tracked().unwrap(), targets);
}
#[test]
fn legacy_claude_only_lease_does_not_authorize_another_provider() {
    let home = Home::new();
    let store = home.store();
    let root = identity(77);
    let inv = BTreeMap::from([(77, root.clone())]);
    store
        .atomic_bytes(
            &store.paths.watch().join("state/sessions/old.session"),
            b"desktop|77|stamp-77|0|-|1000\n",
            0o600,
        )
        .unwrap();
    let leases = LeaseStore {
        storage: store.clone(),
    }
    .load(&inv, 501, true)
    .unwrap();
    assert_eq!(leases.len(), 1);
    assert_eq!(leases[0].provider, Provider::Claude);
    let targets = vec![Target {
        identity: root,
        kind: Kind::CodexMain,
    }];
    let auth = claude_watch_core::processes::authorization(&targets, &leases, &inv, 501);
    assert!(auth["active_pids"].as_array().unwrap().is_empty());
}
