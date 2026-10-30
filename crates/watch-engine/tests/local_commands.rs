use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};
struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("cw-engine-contract-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&p).unwrap();
        Self(fs::canonicalize(p).unwrap())
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn call(home: &Home, args: &[&str], input: Option<Value>) -> (i32, Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_claude-watch-engine"));
    command
        .args(["--home", home.0.to_str().unwrap()])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    if let Some(input) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&input).unwrap())
            .unwrap();
    } else {
        drop(child.stdin.take());
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        output.status.code().unwrap(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}
#[test]
fn event_commands_are_bounded_readonly_or_apply_only_and_keep_sensitive_payloads_out() {
    let home = Home::new();
    let query = json!({"filter":"all","query":"","offset":0});
    let (code, empty) = call(&home, &["event-history"], Some(query.clone()));
    assert_eq!(code, 0);
    assert_eq!(empty["total"], 0);
    assert!(!home.0.join("Library").exists());
    let input = json!({"kind":"dns","source":"ipleak","outcome":"incomplete","reason":"timeout",
        "stage":"dns","elapsed_seconds":2.0});
    let (code, failure) = call(&home, &["event-diagnostic"], Some(input.clone()));
    assert_eq!(code, 4);
    assert_eq!(failure["code"], "explicit_apply_required");
    assert!(!home.0.join("Library").exists());
    let mut unsafe_input = input.clone();
    unsafe_input["message"] = json!("private-token");
    assert_eq!(call(&home, &["event-diagnostic", "--apply"], Some(unsafe_input)).0, 4);
    let (code, saved) = call(&home, &["event-diagnostic", "--apply"], Some(input));
    assert_eq!(code, 0);
    assert_eq!(saved["recorded"], true);
    let (_, result) = call(&home, &["event-history"], Some(query));
    assert_eq!(result["total"], 1);
    assert_eq!(result["events"][0]["severity"], "warning");
    let raw = fs::read_to_string(home.0.join("Library/Application Support/ClaudeWatch/switcher/diagnostic-events.jsonl")).unwrap();
    assert!(!raw.contains("private-token"));
    assert!(!raw.contains(":null"));
}
#[test]
fn guard_diagnostic_writes_only_bounded_telemetry_and_preserves_live_state() {
    let home = Home::new();
    let base = home
        .0
        .join("Library/Application Support/ClaudeWatch/switcher");
    fs::create_dir_all(&base).unwrap();
    let protected = ["config.json", "guard-heartbeat.json", "last-audit.json"];
    for name in protected {
        fs::write(base.join(name), b"fixture-protected-data").unwrap();
    }
    let tag_config = home.0.join("fixture-tag/config.yaml");
    fs::create_dir_all(tag_config.parent().unwrap()).unwrap();
    fs::write(&tag_config, b"fixture-tag-settings").unwrap();
    let phase = json!({"decision":"ok","backend_healthy":true,"backend_native":true,
        "backend_reason":"confirmed","enabled":true,"guard_enabled":true,"sampled_at":1000.0,
        "backend_heartbeat_status":"ok","backend_heartbeat_age_seconds":1.0,
        "guard_heartbeat_status":"ok","guard_heartbeat_age_seconds":2.0,"policy_matches":true});
    let mut round =
        json!({"observation_id":uuid::Uuid::new_v4().to_string(),"before":phase,"after":phase});
    round["after"]["decision"] = json!("unknown");
    let (code, error) = call(&home, &["guard-diagnostic"], Some(round.clone()));
    assert_eq!(code, 4);
    assert_eq!(error["code"], "explicit_apply_required");
    let mut unsafe_round = round.clone();
    unsafe_round["after"]["node"] = json!("private-token");
    assert_eq!(
        call(&home, &["guard-diagnostic", "--apply"], Some(unsafe_round)).0,
        4
    );
    assert!(!base.join("diagnostic-events.jsonl").exists());
    let (code, result) = call(&home, &["guard-diagnostic", "--apply"], Some(round));
    assert_eq!(code, 0);
    assert_eq!(result["recorded"], true);
    for name in protected {
        assert_eq!(
            fs::read(base.join(name)).unwrap(),
            b"fixture-protected-data"
        );
    }
    assert_eq!(fs::read(tag_config).unwrap(), b"fixture-tag-settings");
    let (_, history) = call(
        &home,
        &["event-history"],
        Some(json!({"filter":"attention","query":"保护后台","offset":0})),
    );
    assert_eq!(history["total"], 1);
    assert_eq!(history["events"][0]["severity"], "warning");
    let log = fs::read_to_string(base.join("diagnostic-events.jsonl")).unwrap();
    assert!(!log.contains("private-token"));
}
#[test]
fn actual_engine_local_commands_preserve_readonly_and_apply_contracts() {
    let home = Home::new();
    let (code, config) = call(&home, &["config", "show"], None);
    assert_eq!(code, 0);
    assert_eq!(config["enabled"], true);
    assert!(!home.0.join("Library").exists());
    let (code, status) = call(&home, &["account", "status"], None);
    assert_eq!(code, 0);
    assert_eq!(status["current"], Value::Null);
    assert_eq!(status["login_verified"], false);
    assert!(!home.0.join("Library").exists());
    let (code, error) = call(&home, &["config", "set"], Some(json!({"enabled":false})));
    assert_eq!(code, 4);
    assert_eq!(error["code"], "explicit_apply_required");
    assert!(!home.0.join("Library").exists());
    let (code, saved) = call(
        &home,
        &["config", "set", "--apply"],
        Some(json!({"enabled":false})),
    );
    assert_eq!(code, 0);
    assert_eq!(saved["config"]["enabled"], false);
    let (code, enabled) = call(&home, &["config", "enabled"], None);
    assert_eq!(code, 3);
    assert_eq!(enabled["enabled"], false);
}
#[test]
fn actual_engine_rejects_unknown_controls_and_does_not_overwrite_exports() {
    let home = Home::new();
    let (code, error) = call(&home, &["launch", "--skip-check"], None);
    assert_eq!(code, 2);
    assert_eq!(error["code"], "invalid_arguments");
    let target = home.0.join("existing.json");
    fs::write(&target, b"keep").unwrap();
    let (code, error) = call(&home, &["logs", "--export", target.to_str().unwrap()], None);
    assert_eq!(code, 4);
    assert_eq!(error["code"], "export_failed");
    assert_eq!(fs::read(target).unwrap(), b"keep");
}

#[test]
fn native_mutation_commands_require_apply_before_sampling_or_writing() {
    let home = Home::new();
    for args in [
        vec!["launch"],
        vec!["account", "switch", "A"],
        vec!["account", "recover"],
        vec!["dns-leak-record"],
        vec!["webrtc-risk-record"],
    ] {
        let (code, error) = call(&home, &args, None);
        assert_eq!(code, 4, "{args:?}");
        assert_eq!(
            error["code"], "explicit_apply_required",
            "{args:?}: {error}"
        );
        assert!(!home.0.join("Library").exists());
    }
    let (code, preview) = call(&home, &["account", "import"], None);
    assert_eq!(code, 0, "{preview}");
    assert_eq!(preview["login_verified"], false);
    assert!(!home.0.join("Library").exists());
}

#[test]
fn updater_without_a_pinned_source_never_downloads_or_creates_runtime_state() {
    let home = Home::new();
    let (code, value) = call(&home, &["update"], None);
    assert_eq!(code, 0);
    assert_eq!(value["status"], "unavailable");
    let (code, value) = call(&home, &["update", "--auto", "--apply"], None);
    assert_eq!(code, 0);
    assert_eq!(value["status"], "disabled");
    assert!(!home.0.join("Library").exists());
    let (code, value) = call(&home, &["update", "--recover"], None);
    assert_eq!(code, 4);
    assert_eq!(value["code"], "explicit_apply_required");
}

#[test]
fn application_installer_rejects_missing_or_relative_sources_before_writes() {
    let home = Home::new();
    let (code, value) = call(&home, &["app-install"], None);
    assert_eq!(code, 2);
    assert_eq!(value["code"], "invalid_arguments");
    let (code, value) = call(
        &home,
        &["app-install", "--source", "relative.app", "--apply"],
        None,
    );
    assert_eq!(code, 4);
    assert_eq!(value["code"], "invalid_source");
    assert!(!home.0.join("Library").exists());
}

#[test]
fn retired_baseline_and_bypass_paths_cannot_write_or_authorize_launch() {
    let home = Home::new();
    for args in [
        vec!["baseline", "--apply"],
        vec!["baseline-data"],
        vec!["preflight", "--allow-changes"],
        vec!["launch-desktop", "--apply", "--allow-changes"],
        vec!["dns-check", "--expected-resolvers", "1.1.1.1"],
        vec!["dns-check", "--browser-report", "/tmp/old-report"],
    ] {
        let (code, value) = call(&home, &args, None);
        assert_eq!(code, 2, "{args:?}: {value}");
        assert_eq!(value["grants_launch_permission"], false);
        assert!(!home.0.join("Library").exists());
    }
    let (code, value) = call(&home, &["launch-desktop"], None);
    assert_eq!(code, 4);
    assert_eq!(value["code"], "explicit_apply_required");
    assert!(!home.0.join("Library").exists());
}

#[test]
fn native_check_commands_ignore_old_baselines_and_return_non_authorizing_audits() {
    let home = Home::new();
    let base = home.0.join("Library/Application Support/ClaudeWatch");
    fs::create_dir_all(base.join("switcher")).unwrap();
    fs::create_dir_all(base.join("state")).unwrap();
    fs::write(
        base.join("switcher/config.json"),
        br#"{"online_enabled":false}"#,
    )
    .unwrap();
    let old = base.join("state/baseline.conf");
    fs::write(&old, b"invalid old baseline\nformat=1\n").unwrap();
    for command in ["preflight", "audit"] {
        let (code, value) = call(&home, &[command, "--no-report"], None);
        assert_eq!(
            code,
            if command == "preflight" { 4 } else { 0 },
            "{command}: {value}"
        );
        assert_eq!(value["grants_launch_permission"], false);
        assert_eq!(value["purpose"], "launch_requirements_preview");
        assert_eq!(value["rows"].as_array().unwrap().len(), 14);
        assert!(value["observation_id"].is_string());
        assert!(value["context_transition"].is_object());
        assert_eq!(fs::read(&old).unwrap(), b"invalid old baseline\nformat=1\n");
    }
    for (command, count) in [("proxy-check", 3), ("dns-check", 1)] {
        let (code, value) = call(&home, &[command], None);
        assert!([0, 3, 4].contains(&code), "{command}: {value}");
        assert_eq!(value["purpose"], "scoped_detection");
        assert_eq!(value["grants_launch_permission"], false);
        assert!(value.get("ready").is_none());
        assert_eq!(value["rows"].as_array().unwrap().len(), count);
        assert!(value["observation_id"].is_string());
        assert_eq!(fs::read(&old).unwrap(), b"invalid old baseline\nformat=1\n");
    }
    assert!(!base.join("switcher/last-audit.json").exists());
    assert!(!base.join("switcher/session-guard.json").exists());
}

#[test]
fn launch_target_is_explicit_and_cannot_bypass_apply_or_use_arbitrary_apps() {
    let home = Home::new();
    for target in ["claude-desktop", "codex-desktop", "chatgpt-desktop"] {
        let (code, value) = call(&home, &["launch", "--target", target], None);
        assert_eq!(code, 4);
        assert_eq!(value["code"], "explicit_apply_required");
    }
    let (code, value) = call(&home, &["launch", "--target", "safari", "--apply"], None);
    assert_eq!(code, 2);
    assert_eq!(value["code"], "invalid_arguments");
    assert!(!home.0.join("Library").exists());
    let (code, value) = call(
        &home,
        &["checkdetail", "--target", "codex-desktop", "--no-report"],
        None,
    );
    assert_eq!(code, 0);
    assert_eq!(value["launch_target"], "codex-desktop");
    assert_eq!(value["grants_launch_permission"], false);
    assert!(!home.0.join("Library").exists());
}

#[test]
fn cli_targets_need_parent_apply_and_cannot_borrow_it_from_opaque_child_args() {
    let home = Home::new();
    for target in ["claude-cli", "codex-cli"] {
        let (code, value) = call(
            &home,
            &[
                "launch",
                "--target",
                target,
                "--",
                "--apply",
                "--home",
                "/not-the-parent-home",
            ],
            None,
        );
        assert_eq!(code, 4);
        assert_eq!(value["code"], "explicit_apply_required");
        assert!(!home.0.join("Library").exists());
        let (code, value) = call(
            &home,
            &["checkdetail", "--target", target, "--no-report"],
            None,
        );
        assert_eq!(code, 0);
        assert_eq!(value["grants_launch_permission"], false);
        assert!(value["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == "cli_proxy"));
    }
}
