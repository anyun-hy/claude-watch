use serde_json::{json, Value};
use std::{fs, path::PathBuf, process::Command};
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("cw-maintenance-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn call(&self, args: &[&str]) -> (i32, Value) {
        let out = Command::new(env!("CARGO_BIN_EXE_claude-watch-engine"))
            .args(args)
            .arg("--home")
            .arg(&self.0)
            .output()
            .unwrap();
        (
            out.status.code().unwrap(),
            serde_json::from_slice(&out.stdout).unwrap(),
        )
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn notification_controls_change_only_private_notification_and_observation_state() {
    let home = Home::new();
    let (c, v) = home.call(&["pause"]);
    assert_eq!(c, 0);
    assert_eq!(v["mode"], "Paused");
    let (c, v) = home.call(&["snooze", "5"]);
    assert_eq!(c, 0);
    assert!(v["mode"]["Snoozed"]["until"].as_i64().is_some());
    let (c, v) = home.call(&["arm"]);
    assert_eq!(c, 0);
    assert!(v["mode"]["Armed"]["session"].is_string());
    assert!(!home
        .0
        .join("Library/Application Support/ClaudeWatch/switcher/config.json")
        .exists());
}
#[test]
fn service_recovery_is_visible_and_uses_the_existing_setup_recovery_entry() {
    let home = Home::new();
    let base = home
        .0
        .join("Library/Application Support/ClaudeWatch/switcher");
    fs::create_dir_all(&base).unwrap();
    let (_, before) = home.call(&["config", "show"]);
    fs::write(
        base.join("config.json"),
        serde_json::to_vec(&before).unwrap(),
    )
    .unwrap();
    let mut after = before.clone();
    after["guard_enabled"] = json!(false);
    fs::write(base.join("service-transaction.json"),serde_json::to_vec(&json!({"schema":1,"origin":"protection","config_before":before,"config_after":after,"actions":[]})).unwrap()).unwrap();
    let (c, status) = home.call(&["status"]);
    assert_eq!(c, 0);
    assert_eq!(status["setup_recovery_required"], true);
    let (c, v) = home.call(&["setup", "recover", "--apply"]);
    assert_eq!(c, 0, "{v}");
    assert_eq!(v["status"], "ok");
    assert!(!base.join("service-transaction.json").exists());
    let (c, status) = home.call(&["status"]);
    assert_eq!(c, 0);
    assert_eq!(status["setup_recovery_required"], false);
    assert_eq!(status["config"], before);
}
#[test]
fn privileged_services_are_gated_before_os_mutation() {
    let home = Home::new();
    for action in [
        "update-on",
        "update-off",
        "refresh-admin",
        "disable-legacy",
        "recover",
    ] {
        let (code, v) = home.call(&["services", action]);
        assert_eq!(code, 4);
        assert_eq!(v["code"], "explicit_apply_required");
    }
    assert!(!home.0.join("Library").exists());
}

#[test]
fn unfinished_native_install_is_visible_and_blocks_regular_writes() {
    let home = Home::new();
    let base = home.0.join("Library/Application Support/ClaudeWatch");
    fs::create_dir_all(&base).unwrap();
    fs::write(
        base.join("agent-install-transaction.json"),
        br#"{"schema":999}"#,
    )
    .unwrap();
    let (code, status) = home.call(&["status"]);
    assert_eq!(code, 0);
    assert_eq!(status["setup_recovery_required"], true);
    // Only a temporary-home config write is attempted; no process or system
    // control command is needed to prove the shared mutation gate.
    use std::{io::Write, process::Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_claude-watch-engine"))
        .args([
            "--home",
            home.0.to_str().unwrap(),
            "config",
            "set",
            "--apply",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"enabled":false}"#)
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(value["code"], "recovery_required");
    assert!(!base.join("switcher/config.json").exists());
    let (code, value) = home.call(&["update", "--recover", "--apply"]);
    assert_eq!(code, 4);
    assert_eq!(value["code"], "recovery_required");
    assert!(base.join("agent-install-transaction.json").exists());
    let (code, value) = home.call(&["setup", "recover"]);
    assert_eq!(code, 4);
    assert_eq!(value["code"], "explicit_apply_required");
    let (code, value) = home.call(&["setup", "recover", "--apply"]);
    assert_eq!(code, 4);
    assert_eq!(value["code"], "invalid_install_journal");
    assert!(base.join("agent-install-transaction.json").exists());
}
