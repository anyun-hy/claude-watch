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
