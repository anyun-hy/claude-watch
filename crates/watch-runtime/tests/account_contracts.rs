use claude_watch_core::{
    config::Config,
    error::{CoreError, Result},
};
use claude_watch_runtime::{
    accounts::{AccountOs, AccountStore},
    storage::{Paths, StateStore},
};
use std::{
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};
use uuid::Uuid;

struct Fake {
    running: bool,
    launch_fails: bool,
    clones: usize,
    fail_preflight: bool,
    fail_stage: Option<&'static str>,
    quits: usize,
}
impl AccountOs for Fake {
    fn claude_version(&mut self) -> Result<Option<String>> {
        Ok(Some("1.0".into()))
    }
    fn quit_claude(&mut self) -> Result<()> {
        self.quits += 1;
        self.running = false;
        Ok(())
    }
    fn claude_running(&mut self) -> Result<bool> {
        Ok(self.running)
    }
    fn launch_claude(&mut self) -> Result<()> {
        if self.launch_fails {
            Err(CoreError::new("launch_failed", "fixture"))
        } else {
            self.running = true;
            Ok(())
        }
    }
    fn preflight(&mut self) -> Result<()> {
        if self.fail_preflight {
            Err(CoreError::new("preflight_failed", "fixture"))
        } else {
            Ok(())
        }
    }
    fn clone_file(&mut self, source: &Path, target: &Path) -> Result<bool> {
        if self.running {
            return Err(CoreError::new("copied_while_running", "fixture"));
        }
        fs::copy(source, target).unwrap();
        self.clones += 1;
        Ok(true)
    }
    fn checkpoint(&mut self, stage: &str) -> Result<()> {
        if self.fail_stage == Some(stage) {
            Err(CoreError::new("stage_failed", "fixture"))
        } else {
            Ok(())
        }
    }
}
struct Fixture {
    home: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!("cw-accounts-{}", Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        Self {
            home: fs::canonicalize(home).unwrap(),
        }
    }
    fn storage(&self) -> StateStore {
        StateStore::new(Paths::new(&self.home).unwrap())
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}
fn config() -> Config {
    Config {
        verified_claude_versions: vec!["1.0".into()],
        ..Config::default()
    }
}
fn file(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap()
}

#[test]
fn legacy_import_first_save_switch_and_status_are_isolated() {
    let f = Fixture::new();
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/B/Cookie"), "B");
    file(&legacy.join("current"), "B");
    let mut store = AccountStore::new(
        f.storage(),
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    assert!(store.import_legacy(&legacy, false).unwrap().accounts[1].stored);
    assert_eq!(
        store
            .import_legacy(&legacy, true)
            .unwrap()
            .current
            .as_deref(),
        Some("B")
    );
    file(&store.storage.paths.active().join("Cookie"), "live-A");
    // A is a first-save only when state is absent; imported B remains current and does not overwrite it.
    assert_eq!(store.status().unwrap().current.as_deref(), Some("B"));
    let result = store.switch("B", &config(), false).unwrap();
    assert_eq!(result.current, "B");
    assert_eq!(
        fs::read_to_string(store.profile_path("B").unwrap().join("Cookie")).unwrap(),
        "B"
    );
}

#[test]
fn rejects_symlink_and_failed_launch_recovers_original_profile() {
    let f = Fixture::new();
    let storage = f.storage();
    file(&storage.paths.active().join("Cookie"), "A");
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/B/Cookie"), "B");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    store.import_legacy(&legacy, true).unwrap();
    symlink("Cookie", store.storage.paths.active().join("link")).unwrap();
    assert_eq!(
        store.switch("B", &config(), false).unwrap_err().code,
        "unsupported_account_entry"
    );
    fs::remove_file(store.storage.paths.active().join("link")).unwrap();
    store.os.launch_fails = true;
    assert_eq!(
        store.switch("B", &config(), false).unwrap_err().code,
        "launch_failed"
    );
    assert_eq!(
        fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
        "A"
    );
    assert!(!store.storage.paths.journal().exists());
}

#[test]
fn compatibility_and_preflight_fail_before_snapshot_or_quit() {
    let f = Fixture::new();
    let storage = f.storage();
    file(&storage.paths.active().join("Cookie"), "A");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    assert_eq!(
        store
            .switch("A", &Config::default(), false)
            .unwrap_err()
            .code,
        "account_compatibility_unverified"
    );
    assert!(!store.storage.paths.accounts().join("A").exists());
    assert_eq!(store.os.quits, 0);
    store.os.fail_preflight = true;
    assert_eq!(
        store.switch("A", &config(), false).unwrap_err().code,
        "preflight_failed"
    );
    assert!(!store.storage.paths.accounts().join("A").exists());
    assert_eq!(store.os.quits, 0);
}

#[test]
fn first_save_quits_before_copy_relaunches_a_and_can_initialize_b() {
    let f = Fixture::new();
    let storage = f.storage();
    file(&storage.paths.active().join("Cookie"), "live-A");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: true,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    // Fake clone_file rejects a running source, so success proves quit happened
    // before first-save copying; the successful operation also goes through launch.
    store.switch("A", &config(), false).unwrap();
    assert_eq!(store.os.quits, 1);
    assert!(store.os.running);
    assert_eq!(store.status().unwrap().current.as_deref(), Some("A"));
    assert_eq!(
        fs::read_to_string(store.profile_path("A").unwrap().join("Cookie")).unwrap(),
        "live-A"
    );
    assert_eq!(
        fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
        "live-A"
    );

    let g = Fixture::new();
    let storage = g.storage();
    file(&storage.paths.active().join("Cookie"), "live-A");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: true,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    store.switch("B", &config(), false).unwrap();
    assert_eq!(store.status().unwrap().current.as_deref(), Some("B"));
    assert!(!store.profile_path("B").unwrap().exists());
    assert_eq!(
        fs::read_to_string(store.profile_path("A").unwrap().join("Cookie")).unwrap(),
        "live-A"
    );
    assert!(fs::read_dir(store.storage.paths.active())
        .unwrap()
        .next()
        .is_none());
}

#[test]
fn initialized_same_target_needs_no_version_ack_and_first_save_rollback_removes_new_state() {
    let f = Fixture::new();
    let storage = f.storage();
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/A/Cookie"), "A");
    file(&legacy.join("current"), "A");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    store.import_legacy(&legacy, true).unwrap();
    assert_eq!(
        store
            .switch("A", &Config::default(), false)
            .unwrap()
            .current,
        "A"
    );
    assert_eq!(store.os.quits, 0);

    let g = Fixture::new();
    let storage = g.storage();
    file(&storage.paths.active().join("Cookie"), "A");
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: Some("installed"),
            quits: 0,
        },
    );
    assert_eq!(
        store.switch("A", &config(), false).unwrap_err().code,
        "stage_failed"
    );
    assert!(!store.storage.paths.base().join("accounts.json").exists());
    assert_eq!(
        fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
        "A"
    );
}

#[test]
fn schema_three_recovery_refuses_external_state_rewrite() {
    let f = Fixture::new();
    let storage = f.storage();
    storage.initialize().unwrap();
    let token = "0123456789abcdef0123456789abcdef";
    let work = storage
        .paths
        .accounts()
        .join(format!(".transaction-{token}"));
    file(&storage.paths.active().join("Cookie"), "new");
    file(&work.join("previous-active/Cookie"), "old");
    storage
        .atomic_json(
            &storage.paths.base().join("accounts.json"),
            &serde_json::json!({"schema":1,"current":"B"}),
        )
        .unwrap();
    storage
        .atomic_json(
            &storage.paths.journal(),
            &serde_json::json!({"schema":3,"token":token,"phase":"installed","target":"B",
                "workspace":work,"previous":{"schema":1,"current":"A"},"state_existed":true,
                "records":{"active_before":null,"slot_before":null,"slot":null}}),
        )
        .unwrap();
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    assert_eq!(store.recover().unwrap_err().code, "recovery_conflict");
    assert_eq!(
        fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
        "new"
    );
    assert!(store.storage.paths.journal().exists());
}

#[test]
fn transaction_stage_failures_restore_active_and_remove_journal() {
    for stage in [
        "prepared",
        "old_moved",
        "installed",
        "launched",
        "archived",
        "committed",
    ] {
        let f = Fixture::new();
        let storage = f.storage();
        file(&storage.paths.active().join("Cookie"), "A");
        let legacy = f.home.join(".claude-switcher");
        file(&legacy.join("accounts/B/Cookie"), "B");
        let mut store = AccountStore::new(
            storage,
            Fake {
                running: false,
                launch_fails: false,
                clones: 0,
                fail_preflight: false,
                fail_stage: Some(stage),
                quits: 0,
            },
        );
        store.import_legacy(&legacy, true).unwrap();
        let error = store.switch("B", &config(), false).unwrap_err();
        assert_eq!(error.code, "stage_failed", "{stage}");
        assert_eq!(
            fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
            if stage == "committed" { "B" } else { "A" },
            "{stage}"
        );
        assert!(!store.storage.paths.journal().exists(), "{stage}");
    }
}

#[test]
fn status_is_read_only_and_legacy_journals_reject_redirects() {
    let f = Fixture::new();
    let store = AccountStore::new(
        f.storage(),
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    let value = store.status().unwrap().value();
    assert_eq!(value["login_verified"], false);
    assert!(!store.storage.paths.accounts().exists());
    // A malformed old record must not make recovery follow its supplied paths.
    store.storage.initialize().unwrap();
    store.storage.atomic_json(&store.storage.paths.journal(),&serde_json::json!({"schema":1,"token":"0123456789abcdef0123456789abcdef","stage":"/tmp/no","old":"/tmp/no","previous":{"current":"A"}})).unwrap();
    let mut store = store;
    assert_eq!(store.recover().unwrap_err().code, "invalid_journal");
}

#[test]
fn schema_one_two_and_three_recovery_shapes_are_bounded() {
    for schema in [1, 2] {
        let f = Fixture::new();
        let storage = f.storage();
        storage.initialize().unwrap();
        let token = "0123456789abcdef0123456789abcdef";
        let parent = storage.paths.active().parent().unwrap().to_path_buf();
        file(&storage.paths.active().join("Cookie"), "new");
        file(
            &parent
                .join(format!(".claude-watch-old-{token}"))
                .join("Cookie"),
            "old",
        );
        storage.atomic_json(&storage.paths.journal(),&serde_json::json!({"schema":schema,"token":token,"stage":parent.join(format!(".claude-watch-stage-{token}")),"old":parent.join(format!(".claude-watch-old-{token}")),"previous":{"current":"A"},"phase":"installed"})).unwrap();
        let mut store = AccountStore::new(
            storage,
            Fake {
                running: false,
                launch_fails: false,
                clones: 0,
                fail_preflight: false,
                fail_stage: None,
                quits: 0,
            },
        );
        store.recover().unwrap();
        assert_eq!(
            fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
            "old"
        );
        assert!(store
            .storage
            .paths
            .accounts()
            .join(format!("recovered-{token}"))
            .is_dir());
    }
    let f = Fixture::new();
    let storage = f.storage();
    storage.initialize().unwrap();
    let token = "fedcba9876543210fedcba9876543210";
    let work = storage
        .paths
        .accounts()
        .join(format!(".transaction-{token}"));
    file(&storage.paths.active().join("Cookie"), "new");
    file(&work.join("previous-active/Cookie"), "old");
    storage.atomic_json(&storage.paths.journal(),&serde_json::json!({"schema":3,"token":token,"previous":{"current":"A"},"phase":"installed"})).unwrap();
    let mut store = AccountStore::new(
        storage,
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    store.recover().unwrap();
    assert_eq!(
        fs::read_to_string(store.storage.paths.active().join("Cookie")).unwrap(),
        "old"
    );
}

#[test]
fn import_conflicts_and_nested_legacy_links_do_not_publish_partial_slots() {
    let f = Fixture::new();
    let legacy = f.home.join(".claude-switcher");
    file(&legacy.join("accounts/A/nested/data"), "A");
    symlink("data", legacy.join("accounts/A/nested/link")).unwrap();
    let mut store = AccountStore::new(
        f.storage(),
        Fake {
            running: false,
            launch_fails: false,
            clones: 0,
            fail_preflight: false,
            fail_stage: None,
            quits: 0,
        },
    );
    assert_eq!(
        store.import_legacy(&legacy, true).unwrap_err().code,
        "unsupported_account_entry"
    );
    assert!(!store.storage.paths.accounts().join("A").exists());
    fs::remove_file(legacy.join("accounts/A/nested/link")).unwrap();
    store.import_legacy(&legacy, true).unwrap();
    assert_eq!(
        store.import_legacy(&legacy, true).unwrap_err().code,
        "import_conflict"
    );
}
