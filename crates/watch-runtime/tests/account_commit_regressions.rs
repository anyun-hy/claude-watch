//! Fault injection into real account file transactions with a mock AccountOs.
//! No real account data, process, login, keychain or network is touched.
use claude_watch_core::{config::Config, error::{CoreError, Result}};
use claude_watch_runtime::{accounts::{AccountOs, AccountStore}, storage::{Paths, StateStore}};
use serde_json::{json, Value};
use std::{fs, path::{Path, PathBuf}, panic::{catch_unwind, AssertUnwindSafe}};

#[derive(Default)]
struct Mock {
    running: bool,
    launches: usize,
    quits: usize,
    crash: Option<&'static str>,
    fail: Option<&'static str>,
}
impl AccountOs for Mock {
    fn claude_version(&mut self) -> Result<Option<String>> { Ok(Some("fixture-1".into())) }
    fn preflight(&mut self) -> Result<()> { Ok(()) }
    fn claude_running(&mut self) -> Result<bool> { Ok(self.running) }
    fn quit_claude(&mut self) -> Result<()> { self.quits += 1; self.running = false; Ok(()) }
    fn launch_claude(&mut self) -> Result<()> { self.launches += 1; self.running = true; Ok(()) }
    fn checkpoint(&mut self, stage: &str) -> Result<()> {
        if self.crash == Some(stage) { std::panic::panic_any(format!("injected:{stage}")); }
        if self.fail == Some(stage) { return Err(CoreError::new("injected_failure", "fixture")); }
        Ok(())
    }
}
struct Fixture { root: PathBuf, store: AccountStore<Mock> }
fn file(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap(); fs::write(path, text).unwrap();
}
fn config() -> Config { Config { verified_claude_versions: vec!["fixture-1".into()], ..Default::default() } }
impl Fixture {
    fn new(initialized: bool, active: bool) -> Self {
        let path = std::env::temp_dir().join(format!("cw-account-commit-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        let root = fs::canonicalize(path).unwrap();
        let storage = StateStore::new(Paths::new(&root).unwrap());
        let mut store = AccountStore::new(storage, Mock::default());
        if initialized {
            let legacy = root.join("legacy");
            file(&legacy.join("accounts/A/Cookie"), "older-A");
            file(&legacy.join("accounts/B/Cookie"), "saved-B");
            file(&legacy.join("current"), "A");
            store.import_legacy(&legacy, true).unwrap();
        }
        if active { file(&store.storage.paths.active().join("Cookie"), "live-A"); }
        Self { root, store }
    }
    fn state_path(&self) -> PathBuf { self.store.storage.paths.base().join("accounts.json") }
    fn state(&self) -> Value { self.store.storage.read_json(&self.state_path(), Value::Null).unwrap() }
    fn journal(&self) -> Value {
        self.store.storage.read_json(&self.store.storage.paths.journal(), Value::Null).unwrap()
    }
    fn work(&self) -> PathBuf { PathBuf::from(self.journal()["workspace"].as_str().unwrap()) }
    fn write_journal(&self, value: &Value) {
        self.store.storage.atomic_json(&self.store.storage.paths.journal(), value).unwrap();
    }
    fn interrupt(&mut self, stage: &'static str) {
        self.store.os.crash = Some(stage);
        let caught = catch_unwind(AssertUnwindSafe(|| self.store.switch("B", &config(), false)))
            .expect_err("checkpoint must interrupt the real transaction before automatic recovery");
        let expected = format!("injected:{stage}");
        assert_eq!(caught.downcast_ref::<String>().map(String::as_str), Some(expected.as_str()));
        self.store.os.crash = None;
        // Only the mock is stopped to model a later recovery invocation.
        self.store.os.running = false;
    }
    fn recover_without_process_actions(&mut self) -> Result<()> {
        let before = (self.store.os.launches, self.store.os.quits);
        let result = self.store.recover();
        assert_eq!((self.store.os.launches, self.store.os.quits), before);
        result
    }
    fn assert_preserved_on_conflict(&mut self) {
        let state = fs::read(self.state_path()).unwrap();
        let journal = fs::read(self.store.storage.paths.journal()).unwrap();
        let work = self.work();
        assert!(self.recover_without_process_actions().is_err());
        assert_eq!(fs::read(self.state_path()).unwrap(), state);
        assert_eq!(fs::read(self.store.storage.paths.journal()).unwrap(), journal);
        assert!(work.exists());
    }
}
impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); } }

#[test]
fn published_marker_finishes_the_lagging_journal_without_rolling_back() {
    let mut f = Fixture::new(true, true); f.interrupt("state_saved");
    assert_eq!(f.journal()["phase"], "archived"); assert_eq!(f.state()["current"], "B");
    let state = f.state(); let work = f.work();
    f.recover_without_process_actions().unwrap();
    assert_eq!(f.state(), state);
    assert_eq!(fs::read_to_string(f.store.storage.paths.active().join("Cookie")).unwrap(), "saved-B");
    assert_eq!(fs::read_to_string(f.store.profile_path("A").unwrap().join("Cookie")).unwrap(), "live-A");
    assert!(!work.exists()); assert!(!f.store.storage.paths.journal().exists());
    f.recover_without_process_actions().unwrap();
}
#[test]
fn a_failure_before_marker_publication_still_rolls_back() {
    let mut f = Fixture::new(true, true); f.interrupt("commit_prepared");
    f.recover_without_process_actions().unwrap();
    assert_eq!(f.state()["current"], "A");
    assert_eq!(fs::read_to_string(f.store.storage.paths.active().join("Cookie")).unwrap(), "live-A");
    assert_eq!(fs::read_to_string(f.store.profile_path("A").unwrap().join("Cookie")).unwrap(), "older-A");
}
#[test]
fn automatic_recovery_handles_an_error_immediately_after_marker_write() {
    let mut f = Fixture::new(true, true); f.store.os.fail = Some("state_saved");
    assert_eq!(f.store.switch("B", &config(), false).unwrap_err().code, "injected_failure");
    assert_eq!(f.state()["current"], "B"); assert!(!f.store.storage.paths.journal().exists());
}
#[test]
fn interrupted_recovery_commit_can_be_retried_after_partial_cleanup() {
    let mut f = Fixture::new(true, true); f.interrupt("state_saved");
    let work = f.work(); f.store.os.fail = Some("recovery_committed");
    assert_eq!(f.recover_without_process_actions().unwrap_err().code, "injected_failure");
    assert_eq!(f.journal()["phase"], "committed"); assert!(work.exists());
    // Model a cleanup interruption, not an external profile overwrite.
    fs::remove_dir_all(work.join("previous-active")).unwrap();
    f.store.os.fail = None; f.recover_without_process_actions().unwrap();
    assert_eq!(f.state()["current"], "B"); assert!(!work.exists());
}
#[test]
fn existing_schema_three_marker_window_is_recoverable_without_new_fields() {
    let mut f = Fixture::new(true, true); f.interrupt("state_saved");
    let mut j = f.journal(); j.as_object_mut().unwrap().remove("commit_backups_v1"); f.write_journal(&j);
    f.recover_without_process_actions().unwrap(); assert_eq!(f.state()["current"], "B");
}
#[test]
fn first_initialization_without_an_old_profile_can_finish_launching_phase() {
    let mut f = Fixture::new(false, false); f.interrupt("state_saved");
    assert_eq!(f.journal()["phase"], "launching");
    f.recover_without_process_actions().unwrap(); assert_eq!(f.state()["current"], "B");
    assert!(f.store.storage.paths.active().is_dir());
}
#[test]
fn first_save_preserves_the_archived_live_profile() {
    let mut f = Fixture::new(false, true); f.interrupt("state_saved");
    f.recover_without_process_actions().unwrap();
    assert_eq!(fs::read_to_string(f.store.profile_path("A").unwrap().join("Cookie")).unwrap(), "live-A");
    assert_eq!(f.state()["current"], "B");
}
#[test]
fn an_unselected_existing_slot_is_bound_by_the_new_backup_snapshot() {
    let mut f = Fixture::new(true, true); fs::remove_file(f.state_path()).unwrap();
    f.interrupt("state_saved"); assert!(f.work().join("previous-slot").exists());
    f.recover_without_process_actions().unwrap(); assert_eq!(f.state()["current"], "B");
}
#[test]
fn foreign_or_missing_transaction_tokens_remain_conflicts() {
    for token in [Value::Null, json!("a".repeat(32))] {
        let mut f = Fixture::new(true, true); f.interrupt("state_saved");
        let mut state = f.state(); state["transaction_id"] = token;
        f.store.storage.atomic_json(&f.state_path(), &state).unwrap(); f.assert_preserved_on_conflict();
    }
}
#[test]
fn a_matching_token_does_not_authorize_a_different_or_malformed_state() {
    for key in ["current", "schema", "extra"] {
        let mut f = Fixture::new(true, true); f.interrupt("state_saved");
        let mut state = f.state(); state[key] = if key == "current" { json!("A") } else { json!(2) };
        f.store.storage.atomic_json(&f.state_path(), &state).unwrap(); f.assert_preserved_on_conflict();
    }
}
#[test]
fn an_early_phase_cannot_claim_marker_commit_authority() {
    for phase in ["preparing", "publishing", "installed"] {
        let mut f = Fixture::new(true, true); f.interrupt("state_saved");
        let mut j = f.journal(); j["phase"] = json!(phase); f.write_journal(&j); f.assert_preserved_on_conflict();
    }
}
#[test]
fn changed_backups_or_archive_keep_the_recovery_evidence() {
    for name in ["previous-active/Cookie", "previous-slot/profile/Cookie", "archive"] {
        let mut f = Fixture::new(true, true); f.interrupt("state_saved");
        let path = if name == "archive" { f.store.profile_path("A").unwrap().join("Cookie") }
            else { f.work().join(name) };
        fs::write(path, "external change").unwrap(); f.assert_preserved_on_conflict();
    }
}
#[test]
fn missing_archive_or_backup_does_not_discard_the_remaining_data() {
    for archive in [true, false] {
        let mut f = Fixture::new(true, true); f.interrupt("state_saved");
        fs::remove_dir_all(if archive { f.store.profile_path("A").unwrap() }
            else { f.work().join("previous-active") }).unwrap();
        f.assert_preserved_on_conflict();
    }
}
#[test]
fn a_backup_symlink_is_never_followed_or_cleaned_up() {
    let mut f = Fixture::new(true, true); f.interrupt("state_saved");
    let backup = f.work().join("previous-active"); let outside = f.root.join("preserve");
    fs::rename(&backup, &outside).unwrap(); std::os::unix::fs::symlink(&outside, &backup).unwrap();
    f.assert_preserved_on_conflict(); assert_eq!(fs::read_to_string(outside.join("Cookie")).unwrap(), "live-A");
}
#[test]
fn running_application_blocks_recovery_without_a_quit_request() {
    let mut f = Fixture::new(true, true); f.interrupt("state_saved"); f.store.os.running = true;
    assert_eq!(f.recover_without_process_actions().unwrap_err().code, "claude_still_running");
    assert!(f.work().exists());
}
#[test]
fn post_launch_writes_to_the_selected_profile_are_preserved() {
    let mut f = Fixture::new(true, true); f.interrupt("state_saved");
    file(&f.store.storage.paths.active().join("new-work"), "keep this");
    f.recover_without_process_actions().unwrap();
    assert_eq!(fs::read_to_string(f.store.storage.paths.active().join("new-work")).unwrap(), "keep this");
}
#[test]
fn committed_cleanup_requires_the_target_as_well_as_the_token() {
    let mut f = Fixture::new(true, true); f.interrupt("committed");
    let mut state = f.state(); state["current"] = json!("A");
    f.store.storage.atomic_json(&f.state_path(), &state).unwrap(); f.assert_preserved_on_conflict();
}
#[test]
fn successful_switch_and_same_target_idempotence_are_unchanged() {
    let mut f = Fixture::new(true, true); f.store.switch("B", &config(), false).unwrap();
    let count = (f.store.os.launches, f.store.os.quits);
    f.store.switch("B", &Config::default(), false).unwrap();
    assert_eq!((f.store.os.launches, f.store.os.quits), count);
    assert_eq!(f.state()["current"], "B"); assert!(!f.store.storage.paths.journal().exists());
}
