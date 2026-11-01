#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use claude_watch_core::session::Desktop;
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
    std::fs::write(&helper, "#!/bin/sh\nprintf '%s\\n' '{\"status\":\"ok\"}'\n").unwrap();
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
    assert_eq!(lingering.quit().unwrap_err().code, "claude_still_running");
    let mut forced = None;
    assert_eq!(
        lingering
            .quit_for_confirmed_ip_risk(&mut forced)
            .unwrap_err()
            .code,
        "claude_still_running"
    );
    std::fs::write(
        &helper,
        "#!/bin/sh\nprintf '%s\\n' '{\"status\":\"error\",\"force_requested\":1}'\n",
    )
    .unwrap();
    assert_eq!(
        lingering
            .quit_for_confirmed_ip_risk(&mut forced)
            .unwrap_err()
            .code,
        "claude_still_running"
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
    gone.quit().unwrap(); // Another protector already stopped the entire tree.
    gone.quit_for_confirmed_ip_risk(&mut forced).unwrap();
    assert_eq!(forced, None);
    std::fs::write(&helper, "#!/bin/sh\n[ \"$1\" = guard-close-desktop ] || exit 9\nprintf '%s\\n' '{\"status\":\"ok\",\"force_requested\":1}'\n").unwrap();
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
    std::fs::write(&helper, format!("#!/bin/sh\nprintf '%s\\n' \"$1\" >> '{}'\nprintf '%s\\n' '{{\"status\":\"error\",\"force_requested\":1}}'\n", calls.display())).unwrap();
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
    assert_eq!(adapter.quit().unwrap_err().code, "claude_still_running");
    let mut forced = None;
    assert_eq!(
        adapter
            .quit_for_confirmed_ip_risk(&mut forced)
            .unwrap_err()
            .code,
        "claude_still_running"
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
        if inventory.complete {
            if let Some(record) = inventory.processes.get(&child.0.id()) {
                break record.identity.clone();
            }
        }
        assert!(
            Instant::now() < deadline,
            "complete native inventory did not include the owned child"
        );
        thread::sleep(Duration::from_millis(100));
    };
    let expected = Desktop {
        pid: identity.pid,
        start_seconds: identity.start_seconds,
        start_microseconds: identity.start_microseconds,
    };
    let desktop = NativeDesktop::new(
        runner,
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
