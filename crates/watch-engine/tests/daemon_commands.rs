use serde_json::Value;
use std::{fs, process::Command};
#[test]
fn native_single_observation_publishes_only_in_private_home_and_cannot_impersonate_installed_daemon(
) {
    let home = std::env::temp_dir().join(format!("cw-engine-daemon-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&home).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_claude-watch-engine"))
            .args(args)
            .arg("--home")
            .arg(&home)
            .output()
            .unwrap()
    };
    let rejected = run(&["daemon", "--once", "--observe-only"]);
    assert_eq!(rejected.status.code(), Some(4));
    assert!(!home.join("Library").exists());
    let result = run(&["daemon", "--apply", "--once", "--observe-only"]);
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["rounds"], 1);
    assert_eq!(value["protection"], "observation_only");
    assert!(home
        .join("Library/Application Support/ClaudeWatch/state/runtime-snapshot.json")
        .is_file());
    assert!(home
        .join("Library/Application Support/ClaudeWatch/state/heartbeat")
        .is_file());
    let read = run(&["snapshot"]);
    assert!(read.status.success());
    let snapshot: Value = serde_json::from_slice(&read.stdout).unwrap();
    assert_ne!(
        snapshot["health"]["state"], "running",
        "exited foreground observer cannot be presented as the installed daemon"
    );
    fs::remove_dir_all(home).unwrap();
}
