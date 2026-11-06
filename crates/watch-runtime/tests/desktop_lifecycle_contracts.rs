#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use claude_watch_core::{
    error::{CoreError, Result},
    processes::Identity,
    session::Desktop,
};
use claude_watch_runtime::{
    commands::{ObserverAction, Output, ReadCommand, ReadRunner, SystemRunner},
    desktop_native::NativeDesktop,
    macos::Authority,
    native::{self, Observer},
};
use serde_json::{json, Value};
use std::{
    process::Command,
    thread,
    time::{Duration, Instant},
};

struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct FixtureRunner {
    records: Vec<Value>,
    complete: bool,
}
impl ReadRunner for FixtureRunner {
    fn run(
        &self,
        command: ReadCommand,
        _: &[u8],
        _: Duration,
        _: usize,
    ) -> claude_watch_core::error::Result<Output> {
        assert!(matches!(
            command,
            ReadCommand::Observer(ObserverAction::Inventory)
        ));
        let now = native::now();
        let value = json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now,
            "state":if self.complete {"ok"} else {"partial"},"truncated":false,"processes":self.records,
            "unavailable":if self.complete {json!([])} else {json!([{"pid":999,"code":"identity_unavailable"}])},
            "exited":[],"requested_count":self.records.len() + usize::from(!self.complete)});
        Ok(Output {
            status: 0,
            stdout: serde_json::to_vec(&value).unwrap(),
            stderr: Vec::new(),
        })
    }
}

// Scope this fixture to the owned PID using real native identity receipts.
// Unknown identities stay incomplete; only an explicit native exit is absent.
struct OwnedIdentityRunner {
    runner: SystemRunner,
    identity: Identity,
}
impl ReadRunner for OwnedIdentityRunner {
    fn run(
        &self,
        command: ReadCommand,
        _: &[u8],
        timeout: Duration,
        max_bytes: usize,
    ) -> Result<Output> {
        assert!(matches!(
            command,
            ReadCommand::Observer(ObserverAction::Inventory)
        ));
        let round = uuid::Uuid::new_v4().to_string();
        let request = json!({"schema":1,"round_id":round,"targets":[self.identity]});
        let mut output = self.runner.run(
            ReadCommand::Observer(ObserverAction::Identities),
            &serde_json::to_vec(&request).unwrap(),
            timeout,
            max_bytes,
        )?;
        let invalid = || {
            CoreError::new("fixture_identity_receipt_invalid", "自有进程原生身份回执无效")
        };
        if output.status != 0 || !output.stderr.is_empty() {
            return Err(invalid());
        }
        let mut value: Value = serde_json::from_slice(&output.stdout).map_err(|_| invalid())?;
        if value["schema"] != 1
            || value["status"] != "ok"
            || value["uid"] != self.identity.uid
            || value["round_id"] != round
            || value["identities"].as_array().map(Vec::len) != Some(1)
            || value["identities"][0]["pid"] != self.identity.pid
        {
            return Err(invalid());
        }
        let row = &value["identities"][0];
        let (processes, exited, unavailable) = match row["state"].as_str() {
            Some("ok") => {
                let current: Identity = serde_json::from_value(row["identity"].clone())
                    .map_err(|_| invalid())?;
                if !current.same_process(&self.identity) {
                    return Err(invalid());
                }
                (json!([current]), json!([]), json!([]))
            }
            Some("unknown") if row["code"] == "process_exited" => {
                (json!([]), json!([self.identity.pid]), json!([]))
            }
            Some("unknown") => {
                let code = row["code"].as_str().ok_or_else(invalid)?;
                (
                    json!([]),
                    json!([]),
                    json!([{"pid":self.identity.pid,"code":code}]),
                )
            }
            _ => return Err(invalid()),
        };
        value["state"] = json!(if unavailable == json!([]) { "ok" } else { "partial" });
        value["processes"] = processes;
        value["exited"] = exited;
        value["unavailable"] = unavailable;
        value["truncated"] = json!(false);
        value["requested_count"] = json!(1);
        output.stdout = serde_json::to_vec(&value).unwrap();
        Ok(output)
    }
}

#[test]
fn incomplete_inventory_never_confirms_exit_and_helpers_remain_visible() {
    let root = std::env::temp_dir().join(format!("cw-desktop-lifecycle-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let helper = root.join("watch-process-control");
    std::fs::write(&helper, b"fixture").unwrap();
    let record = |pid: u32, path: &str| {
        json!({"pid":pid,"parent":1,"uid":501,"executable":path,
        "start_seconds":1000,"start_microseconds":1,"start_stamp":"fixture"})
    };
    let expected = Desktop {
        pid: 77,
        start_seconds: 1000,
        start_microseconds: 1,
    };
    let hidden = NativeDesktop::new(
        FixtureRunner {
            records: vec![record(77, "/Applications/Claude.app/Contents/MacOS/Claude")],
            complete: false,
        },
        helper.clone(),
        Authority::ReadOnly,
    )
    .unwrap();
    assert_eq!(
        hidden.desktop_alive(&expected).unwrap_err().code,
        "desktop_inventory_incomplete"
    );
    assert_eq!(
        hidden.desktop_tree_running().unwrap_err().code,
        "desktop_inventory_incomplete"
    );
    let only_helper = NativeDesktop::new(FixtureRunner { records:vec![record(88,"/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper")], complete:true },helper.clone(),Authority::ReadOnly).unwrap();
    assert!(!only_helper.desktop_alive(&expected).unwrap());
    assert!(only_helper.desktop_tree_running().unwrap());
    let unrelated = NativeDesktop::new(
        FixtureRunner {
            records: vec![record(
                89,
                "/Applications/Claude.app.fake/Contents/MacOS/other",
            )],
            complete: true,
        },
        helper,
        Authority::ReadOnly,
    )
    .unwrap();
    assert!(!unrelated.desktop_tree_running().unwrap());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn quit_is_confirmed_by_the_full_tree_even_when_the_request_was_accepted() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("cw-desktop-quit-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let helper = root.join("watch-process-control");
    std::fs::write(&helper, "#!/bin/sh\nprintf '%s\\n' '{\"schema\":1,\"product\":\"claude\",\"status\":\"ok\",\"code\":\"\",\"planned\":1,\"requested\":1,\"skipped\":0,\"failed\":0,\"remaining\":0,\"identity_unconfirmed\":0,\"force_requested\":0,\"force_skipped\":0,\"force_failed\":0}'\n").unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let record = json!({"pid":88,"parent":1,"uid":501,
        "executable":"/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper",
        "start_seconds":1000,"start_microseconds":1,"start_stamp":"fixture"});
    let lingering = NativeDesktop::new(
        FixtureRunner {
            records: vec![record],
            complete: true,
        },
        helper.clone(),
        Authority::ExplicitPermit,
    )
    .unwrap();
    assert_eq!(lingering.quit().unwrap_err().code, "target_still_running");
    let mut forced = None;
    assert_eq!(
        lingering
            .quit_for_confirmed_ip_risk(&mut forced)
            .unwrap_err()
            .code,
        "target_still_running"
    );
    std::fs::write(
        &helper,
        "#!/bin/sh\n\
        if [ \"$1\" = 'guard-close-desktop' ]; then\n\
            printf '%s\\n' '{\"schema\":1,\"product\":\"claude\",\"status\":\"error\",\"code\":\"target_still_running\",\"planned\":1,\"requested\":1,\"skipped\":0,\"failed\":0,\"remaining\":1,\"identity_unconfirmed\":0,\"force_requested\":1,\"force_skipped\":0,\"force_failed\":0}'\n\
        else\n\
            printf '%s\\n' '{\"schema\":1,\"product\":\"claude\",\"status\":\"ok\",\"code\":\"\",\"planned\":1,\"requested\":1,\"skipped\":0,\"failed\":0,\"remaining\":0,\"identity_unconfirmed\":0,\"force_requested\":0,\"force_skipped\":0,\"force_failed\":0}'\n\
        fi\n",
    )
    .unwrap();
    assert_eq!(
        lingering
            .quit_for_confirmed_ip_risk(&mut forced)
            .unwrap_err()
            .code,
        "target_still_running"
    );
    assert_eq!(
        forced,
        Some(1),
        "a failed overall stop still reports force requests"
    );
    let unknown = NativeDesktop::new(
        FixtureRunner {
            records: vec![],
            complete: false,
        },
        helper.clone(),
        Authority::ExplicitPermit,
    )
    .unwrap();
    assert_eq!(
        unknown.quit().unwrap_err().code,
        "desktop_inventory_incomplete"
    );
    let gone = NativeDesktop::new(
        FixtureRunner {
            records: vec![],
            complete: true,
        },
        helper.clone(),
        Authority::ExplicitPermit,
    )
    .unwrap();
    gone.quit().unwrap();
    std::fs::write(&helper, "#!/bin/sh\nexit 7\n").unwrap();
    assert!(gone.quit().is_err());
    assert!(gone.quit_for_confirmed_ip_risk(&mut forced).is_err());
    std::fs::write(
        &helper,
        "#!/bin/sh\n[ \"$1\" = guard-close-desktop ] || exit 9\n\
        printf '%s\\n' '{\"schema\":1,\"product\":\"claude\",\"status\":\"ok\",\"code\":\"\",\"planned\":1,\"requested\":1,\"skipped\":0,\"failed\":0,\"remaining\":0,\"identity_unconfirmed\":0,\"force_requested\":1,\"force_skipped\":0,\"force_failed\":0}'\n",
    )
    .unwrap();
    gone.quit_for_confirmed_ip_risk(&mut forced).unwrap();
    assert_eq!(forced, Some(1));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn forced_helper_entry_is_separate_and_rejected_without_explicit_authority() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("cw-force-routing-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let helper = root.join("watch-process-control");
    let calls = root.join("calls");
    let script = format!(
        "#!/bin/sh\n\
        printf '%s\\n' \"$1\" >> '{}'\n\
        if [ \"$1\" = 'guard-close-desktop' ]; then\n\
            printf '%s\\n' '{{\"schema\":1,\"product\":\"claude\",\"status\":\"error\",\"code\":\"target_still_running\",\"planned\":1,\"requested\":1,\"skipped\":0,\"failed\":0,\"remaining\":1,\"identity_unconfirmed\":0,\"force_requested\":1,\"force_skipped\":0,\"force_failed\":0}}'\n\
        else\n\
            printf '%s\\n' '{{\"schema\":1,\"product\":\"claude\",\"status\":\"error\",\"code\":\"target_still_running\",\"planned\":1,\"requested\":1,\"skipped\":0,\"failed\":0,\"remaining\":1,\"identity_unconfirmed\":0,\"force_requested\":0,\"force_skipped\":0,\"force_failed\":0}}'\n\
        fi\n",
        calls.display()
    );
    std::fs::write(&helper, script).unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let record = json!({"pid":88,"parent":1,"uid":501,
        "executable":"/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper",
        "start_seconds":1000,"start_microseconds":1,"start_stamp":"fixture"});
    let adapter = NativeDesktop::new(
        FixtureRunner {
            records: vec![record.clone()],
            complete: true,
        },
        helper.clone(),
        Authority::ExplicitPermit,
    )
    .unwrap();
    assert_eq!(adapter.quit().unwrap_err().code, "target_still_running");
    let mut forced = None;
    assert_eq!(
        adapter
            .quit_for_confirmed_ip_risk(&mut forced)
            .unwrap_err()
            .code,
        "target_still_running"
    );
    assert_eq!(forced, Some(1));
    assert_eq!(
        std::fs::read_to_string(&calls).unwrap(),
        "close-desktop\nguard-close-desktop\n"
    );
    let readonly = NativeDesktop::new(
        FixtureRunner {
            records: vec![record],
            complete: true,
        },
        helper,
        Authority::ReadOnly,
    )
    .unwrap();
    assert_eq!(
        readonly
            .quit_for_confirmed_ip_risk(&mut forced)
            .unwrap_err()
            .code,
        "write_not_authorized"
    );
    assert_eq!(std::fs::read_to_string(&calls).unwrap().lines().count(), 2);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_identity_tracks_only_the_owned_test_process_lifetime() {
    let mut child = OwnedChild(Command::new("/bin/sleep").arg("300").spawn().unwrap());
    let runner = SystemRunner::development().unwrap();
    let observer = Observer { runner: &runner };
    let deadline = Instant::now() + Duration::from_secs(8);
    let identity = loop {
        let inventory = observer.inventory().unwrap();
        // A validated positive identity does not require unrelated PIDs to be readable.
        if let Some(record) = inventory.processes.get(&child.0.id()) {
            break record.identity.clone();
        }
        assert!(
            Instant::now() < deadline,
            "native inventory did not identify the owned child; complete={}, reasons={:?}",
            inventory.complete,
            inventory.diagnostic_reasons,
        );
        thread::sleep(Duration::from_millis(100));
    };
    let expected = Desktop {
        pid: identity.pid,
        start_seconds: identity.start_seconds,
        start_microseconds: identity.start_microseconds,
    };
    let desktop = NativeDesktop::new(
        OwnedIdentityRunner { runner, identity },
        native::built_process_control_path().unwrap().into(),
        Authority::ReadOnly,
    )
    .unwrap();
    assert!(desktop.desktop_alive(&expected).unwrap());
    let mut other_start = expected.clone();
    other_start.start_microseconds = (other_start.start_microseconds + 1) % 1_000_000;
    assert!(
        !desktop.desktop_alive(&other_start).unwrap(),
        "reused PID with a different start must not match"
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match desktop.desktop_alive(&expected) {
            Ok(false) => break,
            Ok(true) | Err(_) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(100))
            }
            other => panic!("did not confirm the owned child exit: {:?}", other),
        }
    }
}
