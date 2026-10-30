use claude_watch_core::error::Result;
use claude_watch_runtime::{
    agent_install,
    release_native::{FixedCommand, FixedCommandExecutor, FixedOutput},
    storage::{sha256, Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, os::unix::fs::MetadataExt};
struct Fake {
    manifest: Value,
    loaded: bool,
    fail: bool,
    bootstrap: usize,
    calls: Vec<FixedCommand>,
    linger: Option<(u32, std::path::PathBuf)>,
    corrupt_on_failure: Option<std::path::PathBuf>,
    fail_ps: bool,
    empty_ps: bool,
    startup_pending_prints: usize,
}
impl FixedCommandExecutor for Fake {
    fn run(&mut self, c: FixedCommand) -> Result<FixedOutput> {
        let name = c.program.to_string_lossy().into_owned();
        let mut status = 0;
        let mut stderr = String::new();
        let stdout = if name == "/usr/bin/plutil" {
            self.manifest.to_string()
        } else if name.ends_with("/watch-engine") {
            json!({"status":"ok","engine":"rust","component_integrity":true}).to_string()
        } else if name == "/bin/ps" && self.fail_ps {
            status = 1;
            String::new()
        } else if name == "/bin/ps" && self.empty_ps {
            String::new()
        } else if name == "/bin/ps" {
            self.linger
                .as_ref()
                .map(|(uid, path)| {
                    if c.args[1] == "pid=" {
                        "123\n".to_owned()
                    } else {
                        format!("123 {uid} {}\n", path.display())
                    }
                })
                .unwrap_or_else(|| {
                    if c.args[1] == "pid=" {
                        "999\n".into()
                    } else {
                        "999 0 /usr/bin/true\n".into()
                    }
                })
        } else if c.args[0] == "print" {
            if self.loaded {
                if self.startup_pending_prints > 0 {
                    self.startup_pending_prints -= 1;
                    "state = starting\nlast exit code = 0\n".into()
                } else {
                    "state = running\npid = 123\n".into()
                }
            } else {
                status = 113;
                stderr = "Could not find service".into();
                String::new()
            }
        } else if c.args[0] == "bootstrap" {
            self.bootstrap += 1;
            if self.fail && self.bootstrap == 1 {
                status = 1;
                if let Some(path) = &self.corrupt_on_failure {
                    fs::write(path.join("external-change"), b"keep").unwrap();
                }
            } else {
                self.loaded = true;
            }
            String::new()
        } else if c.args[0] == "bootout" {
            self.loaded = false;
            String::new()
        } else {
            String::new()
        };
        self.calls.push(c);
        Ok(FixedOutput {
            status,
            stdout,
            stderr,
        })
    }
}
fn fixture() -> (
    std::path::PathBuf,
    StateStore,
    std::path::PathBuf,
    Fake,
    u32,
) {
    let root = std::env::temp_dir().join(format!("cw-install-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&root).unwrap();
    let uid = fs::metadata(&root).unwrap().uid();
    let home = root.join("home");
    fs::create_dir(&home).unwrap();
    let store = StateStore::new(Paths::new(&home).unwrap());
    let source = root.join("resources");
    fs::create_dir(&source).unwrap();
    let mut hashes = serde_json::Map::new();
    for name in [
        "watch-engine",
        "watch-native-observer",
        "watch-process-control",
        "watch-admin.sh",
        "watch-native-collector.zsh",
    ] {
        fs::write(source.join(name), name).unwrap();
        hashes.insert(name.into(), json!(sha256(name.as_bytes())));
    }
    let manifest = json!({"Architecture":"arm64","BackendVariant":"rust-candidate","RuntimeSchema":2,"RuntimeHashes":hashes});
    fs::write(
        source.join("BuildInfo.plist"),
        b"fixture only; fake plutil parses",
    )
    .unwrap();
    let fake = Fake {
        manifest,
        loaded: false,
        fail: false,
        bootstrap: 0,
        calls: vec![],
        linger: None,
        corrupt_on_failure: None,
        fail_ps: false,
        empty_ps: false,
        startup_pending_prints: 0,
    };
    (root, store, source, fake, uid)
}
#[test]
fn native_runtime_installs_without_legacy_backend_or_account_mutation() {
    let (root, store, source, mut fake, uid) = fixture();
    let account = store.paths.accounts().join("A/profile/Cookie");
    store.atomic_bytes(&account, b"keep-login", 0o600).unwrap();
    let result = agent_install::install(&store, &source, uid, &mut fake).unwrap();
    assert_eq!(result["engine"], "rust");
    assert_eq!(fs::read(account).unwrap(), b"keep-login");
    assert!(store.paths.watch().join("runtime/watch-engine").is_file());
    assert!(!store
        .paths
        .watch()
        .join("agent-install-transaction.json")
        .exists());
    assert!(fake
        .calls
        .iter()
        .all(|c| c.program.to_string_lossy() != "/bin/bash"));
    let plist = fs::read_to_string(
        store
            .paths
            .home
            .join("Library/LaunchAgents/io.local.claudewatch.agent.plist"),
    )
    .unwrap();
    assert!(plist.contains("<string>daemon</string><string>--apply</string>"));
    assert!(plist.contains("<key>RunAtLoad</key><true/>"));
    assert!(plist.contains("<key>KeepAlive</key><true/>"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn background_components_are_hash_checked_and_installed_with_correct_modes() {
    let (root, store, source, mut fake, uid) = fixture();
    fake.manifest["BackgroundEvidenceSchema"] = json!(1);
    for name in claude_watch_runtime::background_evidence::EXTRA_FILES {
        fs::write(source.join(name), name.as_bytes()).unwrap();
        fake.manifest["RuntimeHashes"][name] = json!(sha256(name.as_bytes()));
    }
    agent_install::install(&store, &source, uid, &mut fake).unwrap();
    for name in claude_watch_runtime::background_evidence::EXTRA_FILES {
        let target = store.paths.watch().join("runtime").join(name);
        assert_eq!(fs::read(&target).unwrap(), name.as_bytes());
        assert_eq!(
            fs::metadata(target).unwrap().mode() & 0o777,
            if name == "watch-leak-worker" {
                0o700
            } else {
                0o600
            }
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn advertised_background_worker_cannot_install_with_missing_assets() {
    let (root, store, source, mut fake, uid) = fixture();
    fake.manifest["BackgroundEvidenceSchema"] = json!(1);
    let error = agent_install::install(&store, &source, uid, &mut fake).unwrap_err();
    assert_eq!(error.code, "runtime_missing");
    assert_eq!(fake.bootstrap, 0);
    assert!(!store.paths.watch().join("runtime").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn install_waits_for_delayed_agent_and_preserves_existing_logs() {
    let (root, store, source, mut fake, uid) = fixture();
    let logs = store.paths.watch().join("logs");
    store.private_dir(&logs).unwrap();
    let out = logs.join("native-agent.out.log");
    store
        .atomic_bytes(&out, b"existing diagnostic\n", 0o600)
        .unwrap();
    fake.startup_pending_prints = 2;
    let started = std::time::Instant::now();
    agent_install::install(&store, &source, uid, &mut fake).unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_millis(450));
    assert_eq!(fs::read(&out).unwrap(), b"existing diagnostic\n");
    let err = logs.join("native-agent.err.log");
    assert!(err.is_file());
    assert_eq!(fs::metadata(&err).unwrap().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&logs).unwrap().mode() & 0o777, 0o700);
    let plist = fs::read_to_string(
        store
            .paths
            .home
            .join("Library/LaunchAgents/io.local.claudewatch.agent.plist"),
    )
    .unwrap();
    assert!(plist.contains(&out.display().to_string()));
    assert!(plist.contains(&err.display().to_string()));
    let bootstrap = fake
        .calls
        .iter()
        .position(|call| call.args.first().is_some_and(|value| value == "bootstrap"))
        .unwrap();
    let post_bootstrap_prints = fake.calls[bootstrap + 1..]
        .iter()
        .filter(|call| call.args.first().is_some_and(|value| value == "print"))
        .count();
    assert!(post_bootstrap_prints >= 3);
    assert!(fake.calls[bootstrap + 1..]
        .iter()
        .filter(|call| call.args.first().is_some_and(|value| value == "print"))
        .all(|call| call.timeout == std::time::Duration::from_secs(3)));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unfinished_install_only_allows_the_coordinated_recovery_capability() {
    let (root, store, _source, _fake, _uid) = fixture();
    let journal = store.paths.watch().join("agent-install-transaction.json");
    store
        .atomic_json(&journal, &json!({"schema":1,"status":"pending"}))
        .unwrap();
    for kind in [
        None,
        Some("update"),
        Some("account"),
        Some("setup"),
        Some("service"),
        Some("agent"),
        Some("unknown"),
    ] {
        assert_eq!(
            store.lock("operation", kind).err().unwrap().code,
            "recovery_required",
            "{kind:?}"
        );
    }
    store
        .atomic_json(
            &store.paths.base().join("update-transaction.json"),
            &json!({"schema":1}),
        )
        .unwrap();
    let lock = store.lock("operation", Some("maintenance")).unwrap();
    assert_eq!(
        store.read_json(&journal, Value::Null).unwrap()["status"],
        "pending"
    );
    drop(lock);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn failed_native_start_restores_exact_old_runtime_and_agent_definition() {
    let (root, store, source, mut fake, uid) = fixture();
    let runtime = store.paths.watch().join("runtime");
    store
        .atomic_bytes(&runtime.join("old.txt"), b"old-runtime", 0o600)
        .unwrap();
    let plist = store
        .paths
        .home
        .join("Library/LaunchAgents/io.local.claudewatch.agent.plist");
    store
        .atomic_bytes(&plist, b"old-definition", 0o600)
        .unwrap();
    fake.loaded = true;
    fake.fail = true;
    assert!(agent_install::install(&store, &source, uid, &mut fake).is_err());
    assert_eq!(fs::read(runtime.join("old.txt")).unwrap(), b"old-runtime");
    assert!(!runtime.join("watch-engine").exists());
    assert_eq!(fs::read(plist).unwrap(), b"old-definition");
    assert_eq!(fake.bootstrap, 2);
    assert!(!store
        .paths
        .watch()
        .join("agent-install-transaction.json")
        .exists());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn app_validation_can_reject_deferred_runtime_and_restore_old_components() {
    let (root, store, source, mut fake, uid) = fixture();
    let runtime = store.paths.watch().join("runtime");
    store
        .atomic_bytes(&runtime.join("old.txt"), b"old-runtime", 0o600)
        .unwrap();
    let plist = store
        .paths
        .home
        .join("Library/LaunchAgents/io.local.claudewatch.agent.plist");
    store
        .atomic_bytes(&plist, b"old-definition", 0o600)
        .unwrap();
    let result = agent_install::install_deferred(&store, &source, uid, &mut fake).unwrap();
    assert_eq!(result["commit_required"], true);
    assert!(store
        .paths
        .watch()
        .join(".runtime.previous/old.txt")
        .is_file());
    agent_install::recover(&store, uid, &mut fake).unwrap();
    assert_eq!(fs::read(runtime.join("old.txt")).unwrap(), b"old-runtime");
    assert!(!runtime.join("watch-engine").exists());
    assert_eq!(fs::read(plist).unwrap(), b"old-definition");
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn deferred_commit_discards_previous_runtime_only_after_validation() {
    let (root, store, source, mut fake, uid) = fixture();
    let runtime = store.paths.watch().join("runtime");
    store
        .atomic_bytes(&runtime.join("old.txt"), b"old-runtime", 0o600)
        .unwrap();
    agent_install::install_deferred(&store, &source, uid, &mut fake).unwrap();
    agent_install::commit(&store, uid, &mut fake).unwrap();
    assert!(runtime.join("watch-engine").is_file());
    assert!(!store.paths.watch().join(".runtime.previous").exists());
    assert!(!store
        .paths
        .watch()
        .join("agent-install-transaction.json")
        .exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn first_install_failure_preserves_an_externally_replaced_runtime() {
    let (root, store, source, mut fake, uid) = fixture();
    let runtime = store.paths.watch().join("runtime");
    fake.fail = true;
    fake.corrupt_on_failure = Some(runtime.clone());
    assert_eq!(
        agent_install::install(&store, &source, uid, &mut fake)
            .unwrap_err()
            .code,
        "runtime_rollback_conflict"
    );
    assert_eq!(fs::read(runtime.join("external-change")).unwrap(), b"keep");
    assert!(store
        .paths
        .watch()
        .join("agent-install-transaction.json")
        .exists());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn failed_install_keeps_journal_while_unregistered_runtime_is_still_running() {
    let (root, store, source, mut fake, uid) = fixture();
    let runtime = store.paths.watch().join("runtime");
    fake.fail = true;
    fake.linger = Some((uid, runtime.join("watch-engine")));
    assert_eq!(
        agent_install::install(&store, &source, uid, &mut fake)
            .unwrap_err()
            .code,
        "agent_process_still_running"
    );
    assert!(runtime.join("watch-engine").exists());
    assert!(store
        .paths
        .watch()
        .join("agent-install-transaction.json")
        .exists());
    assert!(fake
        .calls
        .iter()
        .any(|c| c.program == std::path::Path::new("/bin/ps")));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn recovery_keeps_components_when_backend_exit_cannot_be_verified() {
    let (root, store, source, mut fake, uid) = fixture();
    agent_install::install_deferred(&store, &source, uid, &mut fake).unwrap();
    fake.fail_ps = true;
    assert_eq!(
        agent_install::recover(&store, uid, &mut fake)
            .unwrap_err()
            .code,
        "agent_state_unavailable"
    );
    assert!(store.paths.watch().join("runtime/watch-engine").exists());
    assert!(store
        .paths
        .watch()
        .join("agent-install-transaction.json")
        .exists());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn recovery_preserves_transaction_when_process_table_is_empty() {
    let (root, store, source, mut fake, uid) = fixture();
    agent_install::install_deferred(&store, &source, uid, &mut fake).unwrap();
    fake.empty_ps = true;
    assert_eq!(
        agent_install::recover(&store, uid, &mut fake)
            .unwrap_err()
            .code,
        "agent_state_unavailable"
    );
    assert!(store.paths.watch().join("runtime/watch-engine").exists());
    assert!(store
        .paths
        .watch()
        .join("agent-install-transaction.json")
        .exists());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn recovery_accepts_previous_direct_native_agent_layout_without_weakening_conflicts() {
    let (root, store, source, mut fake, uid) = fixture();
    agent_install::install_deferred(&store, &source, uid, &mut fake).unwrap();
    let runtime = store.paths.watch().join("runtime");
    fs::remove_file(runtime.join("watch-native-collector.zsh")).unwrap();
    let journal = store.paths.watch().join("agent-install-transaction.json");
    let mut record: Value = serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
    record["expected"]
        .as_object_mut()
        .unwrap()
        .remove("watch-native-collector.zsh");
    fs::write(&journal, serde_json::to_vec(&record).unwrap()).unwrap();
    let plist = store
        .paths
        .home
        .join("Library/LaunchAgents/io.local.claudewatch.agent.plist");
    let actual = fs::read_to_string(&plist)
        .unwrap()
        .replace("<string>/bin/zsh</string><string>-f</string>", "")
        .replace("watch-native-collector.zsh", "watch-engine")
        .replace(
            &format!(
                "<key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string>",
                runtime.parent().unwrap().join("logs/native-agent.out.log").display(),
                runtime.parent().unwrap().join("logs/native-agent.err.log").display(),
            ),
            "",
        );
    fs::write(&plist, actual).unwrap();
    agent_install::recover(&store, uid, &mut fake).unwrap();
    assert!(!runtime.exists());
    assert!(!journal.exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovery_accepts_previous_supervised_layout_without_log_paths() {
    let (root, store, source, mut fake, uid) = fixture();
    agent_install::install_deferred(&store, &source, uid, &mut fake).unwrap();
    let runtime = store.paths.watch().join("runtime");
    let journal = store.paths.watch().join("agent-install-transaction.json");
    let plist = store
        .paths
        .home
        .join("Library/LaunchAgents/io.local.claudewatch.agent.plist");
    let actual = fs::read_to_string(&plist)
        .unwrap()
        .replace(
            &format!(
                "<key>StandardOutPath</key><string>{}</string><key>StandardErrorPath</key><string>{}</string>",
                runtime.parent().unwrap().join("logs/native-agent.out.log").display(),
                runtime.parent().unwrap().join("logs/native-agent.err.log").display(),
            ),
            "",
        );
    fs::write(&plist, actual).unwrap();
    agent_install::recover(&store, uid, &mut fake).unwrap();
    assert!(!runtime.exists());
    assert!(!journal.exists());
    fs::remove_dir_all(root).unwrap();
}
