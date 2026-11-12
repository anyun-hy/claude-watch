use serde_json::Value;
use std::{fs, path::PathBuf, process::Command};
use uuid::Uuid;

struct Home(PathBuf);
impl Home {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("cw-engine-read-{}", Uuid::new_v4()));
        fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn run(&self, args: &[&str]) -> Value {
        let out = Command::new(env!("CARGO_BIN_EXE_claude-watch-engine"))
            .args(args)
            .args(["--home", self.0.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "exit {:?}, stderr: {}, stdout: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        assert!(
            !out.stdout.is_empty(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fields(v: &Value, keys: &[&str]) {
    for key in keys {
        assert!(v.get(*key).is_some(), "missing {key}: {v}");
    }
}

#[test]
fn process_inventory_observation_has_no_network_or_write_authority() {
    let home = Home::new();
    let receipt = home.run(&["observe", "--processes-only"]);
    assert_eq!(receipt["schema"], 1);
    assert_eq!(receipt["mode"], "read_only");
    assert_eq!(receipt["grants_launch_permission"], false);
    assert_eq!(receipt["grants_close_permission"], false);
    assert!(receipt["targets"].is_array());
    assert!(receipt.get("tag").is_none());
    assert!(receipt.get("sockets").is_none());
    assert_eq!(fs::read_dir(&home.0).unwrap().count(), 0, "read-only classification wrote application state");
}

#[test]
fn diagnostic_export_reads_offline_without_overwrite_or_runtime_mutation() {
    let home = Home::new();
    let destination = fs::canonicalize(&home.0).unwrap().join("diagnostics.json");
    let out = home.run(&["diagnostic-export", "--export", destination.to_str().unwrap()]);
    assert_eq!(out["status"], "ok");
    assert_eq!(out["grants_launch_permission"], false);
    let original = fs::read(&destination).unwrap();
    let value: Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(value["kind"], "claude_watch_diagnostics");
    assert!(value["sources"].as_array().unwrap().iter().any(|source| source["status"] == "missing"));
    assert!(!home.0.join("Library/Application Support/ClaudeWatch").exists());
    let repeated = Command::new(env!("CARGO_BIN_EXE_claude-watch-engine"))
        .args(["diagnostic-export", "--export", destination.to_str().unwrap(), "--home", home.0.to_str().unwrap()])
        .output().unwrap();
    assert!(!repeated.status.success());
    assert_eq!(fs::read(&destination).unwrap(), original);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(fs::metadata(&destination).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn read_commands_emit_gui_json_shapes_without_apply() {
    let home = Home::new();
    let status = home.run(&["status"]);
    fields(
        &status,
        &[
            "status",
            "config",
            "accounts",
            "service_status",
            "setup_recovery_required",
            "update_recovery_required",
        ],
    );
    fields(
        &status["accounts"],
        &["current", "recovery_required", "accounts", "detail"],
    );
    let services = home.run(&["service-status"]);
    fields(
        &services,
        &[
            "status",
            "observed_at",
            "backend_healthy",
            "services",
            "policy_issues",
            "update_source_ready",
        ],
    );
    let snapshot = home.run(&["snapshot"]);
    fields(&snapshot, &["capturedAt", "processes", "proxy", "health"]);
    let check = home.run(&["checkdetail"]);
    fields(
        &check,
        &[
            "observed_at",
            "expires_at",
            "ready",
            "rows",
            "blocked",
            "message",
        ],
    );
    let environment = home.run(&["environment"]);
    fields(
        &environment,
        &[
            "purpose",
            "grants_launch_permission",
            "observed_at",
            "expires_at",
            "rows",
            "candidates",
            "message",
        ],
    );
    assert_eq!(environment["grants_launch_permission"], false);
}

#[test]
fn status_does_not_promote_legacy_heartbeat_or_local_readiness_to_applied_policy() {
    let home = Home::new();
    let watch = home.0.join("Library/Application Support/ClaudeWatch");
    fs::create_dir_all(watch.join("switcher")).unwrap();
    fs::create_dir_all(watch.join("state")).unwrap();
    fs::write(watch.join("switcher/guard-heartbeat.json"),
        br#"{"time":1,"status":"ok"}"#).unwrap();
    fs::write(watch.join("state/seatbelt-runtime.json"),
        br#"{"executor_boot_id":"old-boot","sandbox_ready":true,"updated_at":1}"#).unwrap();
    let status = home.run(&["status"]);
    assert_eq!(status["policy_sync_state"], "pending_apply");
}
