use claude_watch_core::{
    error::{CoreError, Result},
    session::{Desktop, Launcher, Phase},
};
use claude_watch_runtime::{
    controlled::{Controller, DesktopSystem},
    receipt_store::ReceiptStore,
    session_store::SessionStore,
    storage::{Paths, StateStore},
};
use serde_json::{json, Value};
use std::{fs, path::PathBuf, time::Duration};
use uuid::Uuid;

struct Fixture {
    home: PathBuf,
    storage: StateStore,
}
impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!("cw-controlled-{}", Uuid::new_v4()));
        fs::create_dir(&home).unwrap();
        let storage = StateStore::new(Paths::new(&home).unwrap());
        let this = Self { home, storage };
        this.receipts(1000.0);
        let config = claude_watch_core::config::Config {
            guard_enabled: true,
            ..Default::default()
        };
        this.storage
            .atomic_json(&this.storage.paths.config(), &config.value().unwrap())
            .unwrap();
        this
    }
    fn receipts(&self, now: f64) {
        let receipts = ReceiptStore {
            storage: self.storage.clone(),
        };
        let local = json!({"context":"ctx","context_id":"ctx","proxy":"ok","tun":"ok"});
        let probe = json!({"kind":"dns","status":"complete","contextChanged":false,"startedAt":now-1.0,"finishedAt":now,"errors":[],"observations":[{"kind":"http","address":"1.1.1.1"},{"kind":"resolver","address":"8.8.8.8"}],"externalJSON":serde_json::to_string(&json!({
            "session":"a".repeat(40),"dns_servers":{"8.8.8.8":5},"http":{"address":"1.1.1.1","country":"JP"},"geoip":[{"ip":"8.8.8.8","country_code":"JP"}]
        })).unwrap()});
        receipts.record_dns(&probe, &local, None, now).unwrap();
        receipts.record_webrtc(&json!({"kind":"webrtc","status":"complete","contextChanged":false,"startedAt":now-1.0,"finishedAt":now,"errors":[],"observations":[{"kind":"http","address":"1.1.1.1","country":"JP"},{"kind":"srflx","address":"1.1.1.1","country":"JP"}]}),&local,None,now).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}
fn audit(now: f64) -> Value {
    json!({"ready":true,"observed_at":now,"expires_at":now+30.0,"context_id":"ctx","observation_id":"actual-audit-round","context_transition":{"state":"stable"},"egress_reference":{"ip":"1.1.1.1","country":"JP","checked_at":now,"context":"ctx","source":"fixture"}})
}
struct Fake {
    now: f64,
    running: bool,
    opens: u32,
    closes: u32,
    ip_force_calls: u32,
    ready: bool,
    fail_open: bool,
    fail_quit: bool,
    egress_calls: u32,
    freeze_session: Option<PathBuf>,
    proxy: &'static str,
    ip: &'static str,
    country: &'static str,
    egress_age: f64,
    replace_on_open: Option<StateStore>,
    target: claude_watch_core::processes::LaunchTarget,
    root_kind: Option<claude_watch_core::processes::Kind>,
    root_uid: u32,
    no_main: bool,
    desktop_pid: u32,
    hide_main: bool,
    alive_override: Option<bool>,
    tree_running_override: Option<bool>,
    native_liveness: bool,
    native_start: Option<(u64, u32)>,
    reuse_root: bool,
    root_reads: u32,
    audits: u32,
    start_during_audit: bool,
    cli_store: Option<StateStore>,
    cli_args: Vec<String>,
    cli_code: i32,
    fail_spawn: bool,
    fail_wait: bool,
    interrupt_code: Option<i32>,
    spawn_test_process: bool,
    test_child: Option<TestChild>,
}
impl Default for Fake {
    fn default() -> Self {
        Self {
            now: 1000.0,
            running: false,
            opens: 0,
            closes: 0,
            ip_force_calls: 0,
            ready: true,
            fail_open: false,
            fail_quit: false,
            egress_calls: 0,
            freeze_session: None,
            proxy: "ok",
            ip: "1.1.1.1",
            country: "JP",
            egress_age: 0.0,
            replace_on_open: None,
            target: Default::default(),
            root_kind: None,
            root_uid: 501,
            no_main: false,
            desktop_pid: 77,
            hide_main: false,
            alive_override: None,
            tree_running_override: None,
            native_liveness: false,
            native_start: None,
            reuse_root: false,
            root_reads: 0,
            audits: 0,
            start_during_audit: false,
            cli_store: None,
            cli_args: Vec::new(),
            cli_code: 7,
            fail_spawn: false,
            fail_wait: false,
            interrupt_code: None,
            spawn_test_process: false,
            test_child: None,
        }
    }
}
struct TestChild(std::process::Child);
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_test_start(pid: u32) -> Result<(u64, u32)> {
    let runner = claude_watch_runtime::commands::SystemRunner::development()?;
    let inventory = claude_watch_runtime::native::Observer { runner: &runner }.inventory()?;
    let record = inventory
        .processes
        .get(&pid)
        .ok_or_else(|| CoreError::new("fixture_process_missing", "测试进程未被原生采样识别"))?;
    Ok((
        record.identity.start_seconds,
        record.identity.start_microseconds,
    ))
}
impl std::ops::Deref for TestChild {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for TestChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for TestChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct FakeCliChild {
    storage: StateStore,
    owner: claude_watch_core::processes::Identity,
    code: i32,
    fail_wait: bool,
}
impl claude_watch_runtime::controlled::CliProcess for FakeCliChild {
    fn wait(&mut self) -> Result<i32> {
        let operation = self.storage.lock("operation", None)?;
        let launch = self.storage.lock("launch", None)?;
        drop(operation);
        drop(launch);
        let inventory = std::collections::BTreeMap::from([(self.owner.pid, self.owner.clone())]);
        assert!(claude_watch_runtime::lease_store::LeaseStore {
            storage: self.storage.clone()
        }
        .load(&inventory, self.owner.uid, false)?
        .iter()
        .any(|l| l.cli && l.root.same_process(&self.owner)));
        if self.fail_wait {
            Err(CoreError::new("cli_wait_failed", "fixture"))
        } else {
            Ok(self.code)
        }
    }
}
impl DesktopSystem for Fake {
    fn prepare_cli(&mut self) -> Result<()> {
        Ok(())
    }
    fn cli_interrupted(&self) -> Option<i32> {
        self.interrupt_code
    }
    fn spawn_cli(
        &mut self,
        args: &[String],
    ) -> Result<Box<dyn claude_watch_runtime::controlled::CliProcess>> {
        self.cli_args = args.to_vec();
        self.opens += 1;
        if self.fail_spawn {
            return Err(CoreError::new("cli_spawn_failed", "fixture"));
        }
        Ok(Box::new(FakeCliChild {
            storage: self.cli_store.clone().unwrap(),
            owner: self.observation_owner()?,
            code: self.cli_code,
            fail_wait: self.fail_wait,
        }))
    }

    fn launch_target(&self) -> claude_watch_core::processes::LaunchTarget {
        self.target
    }
    fn observation_owner(&mut self) -> Result<claude_watch_core::processes::Identity> {
        Ok(claude_watch_core::processes::Identity {
            pid: 88,
            parent: 1,
            uid: 501,
            executable: "/fixture/watch-engine".into(),
            start_seconds: 800,
            start_microseconds: 7,
            start_stamp: "owner".into(),
        })
    }
    fn observation_roots(&mut self) -> Result<Vec<claude_watch_core::processes::Target>> {
        use claude_watch_core::processes::{Identity, Kind, LaunchTarget, Target};
        if !self.running || self.no_main {
            return Ok(vec![]);
        }
        self.root_reads += 1;
        Ok(vec![Target {
            kind: self.root_kind.unwrap_or(match self.target {
                LaunchTarget::CodexDesktop => Kind::CodexMain,
                LaunchTarget::ChatgptDesktop => Kind::ChatgptMain,
                _ => Kind::ClaudeMain,
            }),
            identity: Identity {
                pid: self
                    .test_child
                    .as_ref()
                    .map(|child| child.id())
                    .unwrap_or(77),
                parent: 1,
                uid: self.root_uid,
                executable: "/fixture/ChatGPT.app/Contents/MacOS/ChatGPT".into(),
                start_seconds: 900,
                start_microseconds: if self.reuse_root && self.root_reads > 1 {
                    2
                } else {
                    1
                },
                start_stamp: "target".into(),
            },
        }])
    }
    fn now(&self) -> f64 {
        self.now
    }
    fn monotonic(&self) -> Duration {
        Duration::from_secs_f64(self.now)
    }
    fn wait(&mut self, d: Duration) {
        self.now += d.as_secs_f64()
    }
    fn desktops(&mut self) -> Result<Vec<(Desktop, bool, String)>> {
        Ok(if self.running {
            vec![(
                Desktop {
                    pid: self
                        .test_child
                        .as_ref()
                        .map(|child| child.id())
                        .unwrap_or(self.desktop_pid),
                    start_seconds: self.native_start.map_or(900, |v| v.0),
                    start_microseconds: self.native_start.map_or(1, |v| v.1),
                },
                !self.hide_main,
                "Tue Nov 14 22:12:50 2023".into(),
            )]
        } else {
            vec![]
        })
    }
    fn desktop_alive(&mut self, expected: &Desktop) -> Result<bool> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if self.native_liveness {
            let runner = claude_watch_runtime::commands::SystemRunner::development()?;
            let helper = claude_watch_runtime::native::built_process_control_path().unwrap();
            let desktop = claude_watch_runtime::desktop_native::NativeDesktop::new(
                runner,
                helper.into(),
                claude_watch_runtime::macos::Authority::ReadOnly,
            )?;
            return desktop.desktop_alive(expected);
        }
        if let Some(value) = self.alive_override {
            return Ok(value);
        }
        Ok(self
            .desktops()?
            .iter()
            .any(|(desktop, main, _)| *main && desktop == expected))
    }
    fn desktop_tree_running(&mut self) -> Result<bool> {
        Ok(self.tree_running_override.unwrap_or(self.running))
    }
    fn launcher(&mut self) -> Result<Launcher> {
        Ok(Launcher {
            pid: 88,
            start: "Tue Nov 14 22:12:49 2023".into(),
        })
    }
    fn full_audit(&mut self) -> Result<Value> {
        self.audits += 1;
        if self.start_during_audit {
            self.running = true;
        }
        let mut value = audit(self.now);
        value["ready"] = json!(self.ready);
        if !self.target.protected() {
            value["launch_target"] = json!(self.target);
            value["authorization_scope"] = json!("observation");
        }
        Ok(value)
    }
    fn egress(&mut self) -> Value {
        self.egress_calls += 1;
        if let Some(path) = self.freeze_session.take() {
            assert!(std::process::Command::new("/usr/bin/chflags")
                .arg("uchg")
                .arg(path)
                .status()
                .unwrap()
                .success());
        }
        json!({"ip":self.ip,"country":self.country,"observed_at":self.now - self.egress_age,"source":"fixture HTTP exit"})
    }
    fn local_guard(&mut self) -> Result<Value> {
        Ok(json!({"proxy":self.proxy,"tun":"ok"}))
    }
    fn backend_healthy(&mut self) -> Result<bool> {
        Ok(true)
    }
    fn launcher_matches(&mut self, _: &Launcher) -> Result<bool> {
        Ok(true)
    }
    fn open_desktop(&mut self) -> Result<()> {
        self.opens += 1;
        self.now += 0.1;
        if let Some(storage) = self.replace_on_open.take() {
            SessionStore::new(storage.clone()).begin_verified(
                &ReceiptStore { storage },
                &audit(self.now),
                &self.egress(),
                self.now,
            )?;
            return Err(CoreError::new("fixture_open_failed", "fixture"));
        }
        if self.fail_open {
            return Err(CoreError::new("fixture_open_failed", "fixture"));
        }
        if self.spawn_test_process {
            self.test_child = Some(TestChild(
                std::process::Command::new("/bin/sleep")
                    .arg("300")
                    .spawn()
                    .map_err(|_| {
                        CoreError::new("test_child_failed", "isolated test child failed to start")
                    })?,
            ));
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            if self.native_liveness {
                self.native_start =
                    Some(native_test_start(self.test_child.as_ref().unwrap().id())?);
            }
        }
        self.running = true;
        Ok(())
    }
    fn quit_desktop(&mut self) -> Result<()> {
        self.closes += 1;
        if self.fail_quit {
            return Err(CoreError::new("fixture_quit_failed", "fixture"));
        }
        if let Some(mut child) = self.test_child.take() {
            child.kill().map_err(|_| {
                CoreError::new(
                    "test_child_stop_failed",
                    "isolated test child failed to stop",
                )
            })?;
            child.wait().map_err(|_| {
                CoreError::new(
                    "test_child_wait_failed",
                    "isolated test child failed to exit",
                )
            })?;
        }
        self.running = false;
        Ok(())
    }
    fn quit_for_confirmed_ip_risk(&mut self, forced: &mut Option<u32>) -> Result<()> {
        self.ip_force_calls += 1;
        let had_child = self.test_child.is_some();
        *forced = Some(u32::from(had_child));
        self.quit_desktop()
    }
}

#[test]
fn enabled_guard_resumes_from_saved_config_and_explicit_disable_persists() {
    let fixture = Fixture::new();
    let mut system = Fake::default();
    let first = Controller::new(fixture.storage.clone())
        .guard_tick(&mut system)
        .unwrap();
    assert_eq!(first["status"], "ok");
    assert!(first["guard_policy_v1"].is_string());

    // A newly constructed worker reads the saved intent, as it does at login.
    let resumed = Controller::new(fixture.storage.clone())
        .guard_tick(&mut system)
        .unwrap();
    assert_eq!(resumed["status"], "ok");
    let mut config = claude_watch_runtime::config_store::ConfigStore {
        storage: fixture.storage.clone(),
    }
    .load()
    .unwrap()
    .value()
    .unwrap();
    config["guard_enabled"] = json!(false);
    fixture
        .storage
        .atomic_json(&fixture.storage.paths.config(), &config)
        .unwrap();
    let disabled = Controller::new(fixture.storage.clone())
        .guard_tick(&mut system)
        .unwrap();
    assert_eq!(disabled["status"], "disabled");
}

#[test]
fn enabling_timezone_keeps_the_running_guard_and_session() {
    use claude_watch_runtime::{
        macos::guard_heartbeat_confirmed,
        services::{self, ServiceSystem},
    };
    struct Clock {
        target: Value,
    }
    impl ServiceSystem for Clock {
        fn now(&self) -> f64 {
            1001.0
        }
        fn backend_healthy(&self) -> bool {
            true
        }
        fn guard_status(&self, config: &claude_watch_core::config::Config) -> Result<bool> {
            Ok(config.enabled && config.guard_enabled)
        }
        fn service_job(&self, name: &str) -> Result<Value> {
            if name == "watchdog" {
                Ok(
                    json!({"registered":!self.target.is_null(),"trusted":true,"definition":"fixture"}),
                )
            } else {
                Ok(json!({"registered":false,"trusted":true}))
            }
        }
        fn watchdog_state(&self) -> Result<Value> {
            Ok(json!({"target":self.target,"registered":!self.target.is_null()}))
        }
        fn admin_helper_status(&self) -> Result<Value> {
            Ok(json!({"trusted":true,"abi":1}))
        }
        fn runtime_present(&self) -> bool {
            true
        }
        fn apply_service(&mut self, action: &Value) -> Result<()> {
            self.target = action["after"].clone();
            Ok(())
        }
    }
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut desktop = Fake::default();
    controller.launch(&mut desktop).unwrap();
    desktop.now = 1001.0;
    let previous = controller.guard_tick(&mut desktop).unwrap();
    assert_eq!(previous["status"], "ok");
    fixture
        .storage
        .atomic_json(
            &fixture.storage.paths.base().join("last-audit.json"),
            &json!({"ready":true,"context_transition":{"state":"stable"},
                "egress_reference":{"checked_at":1001.,"country":"JP","timezone":"Asia/Tokyo"}}),
        )
        .unwrap();
    let mut clock = Clock {
        target: Value::Null,
    };
    let changes = json!({"timezone_watchdog":true});
    let plan = services::protection_preview(&fixture.storage, &clock, &changes).unwrap();
    services::protection_apply(
        &fixture.storage,
        &mut clock,
        &changes,
        plan["id"].as_str().unwrap(),
    )
    .unwrap();
    let config = claude_watch_runtime::config_store::ConfigStore {
        storage: fixture.storage.clone(),
    }
    .load()
    .unwrap();
    assert!(config.guard_enabled && config.timezone_watchdog);
    assert!(guard_heartbeat_confirmed(&config, true, 1001.0, &previous));
    desktop.now = 1002.0;
    let next = controller.guard_tick(&mut desktop).unwrap();
    assert_eq!(next["status"], "ok", "{next}");
    assert_eq!(next["action"], "observe");
    assert!(desktop.running);
    assert_eq!(desktop.closes, 0);
}
#[test]
fn isolated_process_protection_handles_retry_recovery_and_confirmed_ip_change() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake {
        spawn_test_process: true,
        ..Fake::default()
    };
    controller.launch(&mut system).unwrap();
    let pid = system.test_child.as_ref().unwrap().id();
    system.now += 1.0;
    assert_eq!(
        controller.guard_tick(&mut system).unwrap()["action"],
        "observe"
    );
    system.proxy = "unknown";
    system.now += 1.0;
    let transient = controller.guard_tick(&mut system).unwrap();
    assert_eq!(transient["session_guard"]["state"], "unknown");
    assert!(system
        .test_child
        .as_mut()
        .unwrap()
        .try_wait()
        .unwrap()
        .is_none());
    system.proxy = "ok";
    system.now += 1.0;
    assert_eq!(
        controller.guard_tick(&mut system).unwrap()["action"],
        "observe"
    );
    assert_eq!(system.test_child.as_ref().unwrap().id(), pid);
    system.ip = "8.8.8.8";
    system.now += 1.0;
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["action"], "close-desktop");
    assert!(system.test_child.is_none());
    assert_eq!(system.closes, 1);
    assert_eq!(
        SessionStore::new(fixture.storage.clone())
            .load(system.now)
            .unwrap()
            .unwrap()
            .state,
        Phase::Locked
    );
    system.ip = "1.1.1.1";
    system.now += 1.0;
    fixture.receipts(system.now);
    assert_eq!(controller.launch(&mut system).unwrap()["status"], "ok");
    assert!(system
        .test_child
        .as_mut()
        .unwrap()
        .try_wait()
        .unwrap()
        .is_none());
    assert_eq!(
        SessionStore::new(fixture.storage.clone())
            .load(system.now)
            .unwrap()
            .unwrap()
            .state,
        Phase::Active
    );
}

#[test]
fn externally_exited_process_ends_session_and_replacement_keeps_fast_ip_guard() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake {
        spawn_test_process: true,
        ..Fake::default()
    };
    controller.launch(&mut system).unwrap();
    let old = SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .unwrap();
    let mut child = system.test_child.take().unwrap();
    child.kill().unwrap();
    child.wait().unwrap();
    system.running = false;
    system.now += 1.0;
    let ended = controller.guard_tick(&mut system).unwrap();
    assert_eq!(ended["session_guard"]["state"], "idle");
    assert_eq!(ended["ended_session_id"], old.session_id);
    assert_eq!(
        system.closes, 0,
        "an already-exited process needs no duplicate stop"
    );
    assert_eq!(
        SessionStore::new(fixture.storage.clone())
            .load(system.now)
            .unwrap()
            .unwrap()
            .state,
        Phase::Ended
    );

    system.test_child = Some(TestChild(
        std::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .unwrap(),
    ));
    system.running = true;
    system.now += 1.0;
    let pending = controller.guard_tick(&mut system).unwrap();
    let replacement = SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .unwrap();
    assert_eq!(replacement.state, Phase::Rechecking);
    assert_ne!(replacement.session_id, old.session_id);
    assert_eq!(pending["session_guard"]["state"], "pending");
    assert_eq!(
        system.closes, 0,
        "a new process is rechecked, not closed merely for a new PID"
    );

    system.ip = "8.8.8.8";
    system.now += 1.0;
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["action"], "close-desktop");
    assert_eq!(risk["session_guard"]["reason"]["code"], "egress_ip_changed");
    assert_eq!(system.ip_force_calls, 1);
    assert_eq!(risk["stop_force_requested"], 1);
    assert!(
        system.test_child.is_none(),
        "confirmed IP change stops the owned test process"
    );
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn native_identity_and_owned_process_drive_the_guard_lifecycle() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake {
        spawn_test_process: true,
        native_liveness: true,
        ..Fake::default()
    };
    controller.launch(&mut system).unwrap();
    let mut old = system.test_child.take().unwrap();
    old.kill().unwrap();
    old.wait().unwrap();
    system.running = false;
    for _ in 0..5 {
        system.now += 1.0;
        controller.guard_tick(&mut system).unwrap();
        if SessionStore::new(fixture.storage.clone())
            .load(system.now)
            .unwrap()
            .unwrap()
            .state
            == Phase::Ended
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        SessionStore::new(fixture.storage.clone())
            .load(system.now)
            .unwrap()
            .unwrap()
            .state,
        Phase::Ended
    );
    assert_eq!(system.closes, 0);
    system.test_child = Some(TestChild(
        std::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .unwrap(),
    ));
    system.native_start =
        Some(native_test_start(system.test_child.as_ref().unwrap().id()).unwrap());
    system.running = true;
    system.now += 1.0;
    assert_eq!(
        controller.guard_tick(&mut system).unwrap()["session_guard"]["state"],
        "pending"
    );
    system.ip = "8.8.8.8";
    system.now += 1.0;
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["action"], "close-desktop");
    assert_eq!(risk["session_guard"]["reason"]["code"], "egress_ip_changed");
    assert!(system.test_child.is_none());
}

#[test]
fn missing_main_metadata_does_not_end_or_stop_a_still_live_process() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.now += 1.0;
    system.hide_main = true;
    system.alive_override = Some(true);
    let result = controller.guard_tick(&mut system).unwrap();
    assert_eq!(result["session_guard"]["state"], "unknown");
    assert_eq!(system.closes, 0);
    assert_eq!(
        SessionStore::new(fixture.storage.clone())
            .load(system.now)
            .unwrap()
            .unwrap()
            .state,
        Phase::Active
    );
}

#[test]
fn exited_main_with_lingering_helper_does_not_look_like_a_new_main() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.now += 1.0;
    system.hide_main = true;
    system.alive_override = Some(false);
    let partial = controller.guard_tick(&mut system).unwrap();
    assert_eq!(partial["session_guard"]["state"], "unknown");
    assert_eq!(system.closes, 0);
    let ended = SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .unwrap();
    assert_eq!(ended.state, Phase::Ended);
    assert_eq!(
        claude_watch_core::session::status(&ended, system.now, Some(true))["state"],
        "unknown"
    );
    assert_eq!(
        claude_watch_core::session::status(&ended, system.now, Some(false))["state"],
        "idle"
    );
    system.now += 1.0;
    system.hide_main = false;
    system.desktop_pid = 78;
    let recheck = controller.guard_tick(&mut system).unwrap();
    assert_eq!(recheck["session_guard"]["state"], "pending");
    assert_eq!(system.closes, 0);
}

#[test]
fn lingering_helpers_are_still_stopped_if_ip_changes_after_main_exit() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.now += 1.0;
    system.hide_main = true;
    system.alive_override = Some(false);
    system.tree_running_override = Some(true);
    let waiting = controller.guard_tick(&mut system).unwrap();
    assert_eq!(waiting["session_guard"]["state"], "unknown");
    assert_eq!(system.closes, 0);
    system.ip = "8.8.8.8";
    system.now += 1.0;
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["action"], "close-desktop");
    assert_eq!(risk["session_guard"]["reason"]["code"], "egress_ip_changed");
    assert_eq!(system.closes, 1);
}

#[test]
fn native_tree_only_helpers_remain_guarded_after_the_main_is_gone() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.running = false;
    system.alive_override = Some(false);
    system.tree_running_override = Some(true);
    system.now += 1.0;
    let waiting = controller.guard_tick(&mut system).unwrap();
    assert_eq!(waiting["session_guard"]["state"], "unknown");
    assert_eq!(system.closes, 0);
    system.ip = "8.8.8.8";
    system.now += 1.0;
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["action"], "close-desktop");
    assert_eq!(risk["session_guard"]["reason"]["code"], "egress_ip_changed");
    assert_eq!(system.closes, 1);
}

#[test]
fn confirmed_proxy_failure_still_stops_lingering_helpers() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.running = false;
    system.alive_override = Some(false);
    system.tree_running_override = Some(true);
    system.proxy = "fail";
    system.now += 1.0;
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["action"], "close-desktop");
    assert_eq!(
        risk["session_guard"]["reason"]["code"],
        "proxy_or_tun_failed"
    );
    assert_eq!(
        system.ip_force_calls, 0,
        "non-IP failures use the existing normal-exit path"
    );
}

#[test]
fn replacement_uses_its_own_exit_baseline_after_old_session_ended() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.running = false;
    system.now += 1.0;
    controller.guard_tick(&mut system).unwrap();
    system.running = true;
    system.desktop_pid = 78;
    system.ip = "8.8.8.8"; // Changed while the previous session was already closed.
    system.now += 1.0;
    let pending = controller.guard_tick(&mut system).unwrap();
    let value = SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .unwrap();
    assert_eq!(pending["session_guard"]["state"], "pending");
    assert_eq!(value.baseline.ip, "8.8.8.8");
    assert_eq!(
        system.closes, 0,
        "an old session baseline must not stop a new session"
    );
    system.ip = "9.9.9.9";
    system.now += 1.0;
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["action"], "close-desktop");
    assert_eq!(risk["session_guard"]["reason"]["code"], "egress_ip_changed");
}

#[test]
fn replacement_seen_in_same_round_as_old_exit_is_rechecked_not_closed() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    let old = SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .unwrap();
    system.desktop_pid = 78;
    system.now += 1.0;
    let result = controller.guard_tick(&mut system).unwrap();
    let new = SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .unwrap();
    assert_eq!(result["session_guard"]["state"], "pending");
    assert_eq!(new.state, Phase::Rechecking);
    assert_ne!(new.session_id, old.session_id);
    assert_eq!(system.closes, 0);
}

#[test]
fn replacement_cannot_absorb_a_changed_ip_without_a_confirmed_empty_tree() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.desktop_pid = 78;
    system.ip = "8.8.8.8";
    system.now += 1.0;
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["session_guard"]["reason"]["code"], "egress_ip_changed");
    assert_eq!(risk["action"], "close-desktop");
    assert_eq!(system.ip_force_calls, 1);
}

#[test]
fn unknown_sample_cannot_discard_previous_baseline_during_immediate_replacement() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.desktop_pid = 78;
    system.ip = "";
    system.now += 1.0;
    let unknown = controller.guard_tick(&mut system).unwrap();
    assert_eq!(unknown["session_guard"]["state"], "unknown");
    assert_eq!(system.closes, 0);
    system.ip = "8.8.8.8";
    system.now += 1.0;
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["session_guard"]["reason"]["code"], "egress_ip_changed");
    assert_eq!(risk["action"], "close-desktop");
    assert_eq!(system.ip_force_calls, 1);
}

#[test]
fn replacement_with_confirmed_cn_exit_is_closed_before_recheck() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.running = false;
    system.now += 1.0;
    controller.guard_tick(&mut system).unwrap();
    system.running = true;
    system.desktop_pid = 78;
    system.country = "CN";
    system.now += 1.0;
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["action"], "close-desktop");
    assert_eq!(risk["session_guard"]["reason"]["code"], "egress_country_cn");
    assert_eq!(system.ip_force_calls, 1);
}

#[test]
fn confirmed_risk_stays_latched_until_remaining_desktop_tree_has_exited() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.ip = "8.8.8.8";
    system.fail_quit = true;
    system.now += 1.0;
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["session_guard"]["state"], "risk");
    assert_eq!(risk["stop_state"], "failed");
    assert_eq!(system.closes, 1);

    // Another protector has stopped the old main, but helpers still exist.
    system.running = false;
    system.alive_override = Some(false);
    system.tree_running_override = Some(true);
    system.now += 1.0;
    let pending = controller.guard_tick(&mut system).unwrap();
    assert_eq!(pending["stop_state"], "failed");
    assert_eq!(
        system.closes, 2,
        "confirmed risk keeps requesting full exit"
    );
    assert_eq!(
        SessionStore::new(fixture.storage.clone())
            .load(system.now)
            .unwrap()
            .unwrap()
            .state,
        Phase::Locked
    );

    // Once the tree is gone, whoever closed it, no duplicate stop is sent.
    system.tree_running_override = Some(false);
    system.now += 1.0;
    let ended = controller.guard_tick(&mut system).unwrap();
    assert_eq!(ended["session_guard"]["state"], "idle");
    assert_eq!(system.closes, 2);
    assert_eq!(
        SessionStore::new(fixture.storage.clone())
            .load(system.now)
            .unwrap()
            .unwrap()
            .state,
        Phase::Ended
    );
}

#[test]
fn slow_new_process_audit_does_not_delay_stopping_owned_child_on_ip_change() {
    use claude_watch_core::config::Config;
    use claude_watch_runtime::background_evidence::{self, EvidenceSystem, ProbeKind};
    use std::time::Instant;
    struct BlockedAudit {
        now: f64,
        started: std::sync::mpsc::Sender<()>,
        resume: std::sync::mpsc::Receiver<()>,
    }
    impl EvidenceSystem for BlockedAudit {
        fn now(&self) -> f64 {
            self.now
        }
        fn local(&mut self, _: &Config) -> Result<Value> {
            Ok(json!({"context_id":"ctx","proxy":"ok","tun":"ok","observation_unavailable":[]}))
        }
        fn desktop_matches(&mut self, _: &Desktop) -> Result<bool> {
            Ok(true)
        }
        fn desktop_unique_stamp(&mut self, _: &Desktop) -> Result<Option<String>> {
            Ok(Some("fixture".into()))
        }
        fn collect(&mut self, _: ProbeKind) -> Result<Value> {
            panic!("fresh fixture receipts should be reused")
        }
        fn revalidate(&mut self) -> Result<(Value, Value)> {
            self.started.send(()).unwrap();
            self.resume.recv_timeout(Duration::from_secs(3)).unwrap();
            Ok((json!({}), json!({})))
        }
    }
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake {
        spawn_test_process: true,
        ..Fake::default()
    };
    controller.launch(&mut system).unwrap();
    let mut old = system.test_child.take().unwrap();
    old.kill().unwrap();
    old.wait().unwrap();
    system.running = false;
    system.now += 1.0;
    controller.guard_tick(&mut system).unwrap();
    system.test_child = Some(TestChild(
        std::process::Command::new("/bin/sleep")
            .arg("300")
            .spawn()
            .unwrap(),
    ));
    system.running = true;
    system.now += 1.0;
    controller.guard_tick(&mut system).unwrap();
    fixture.receipts(system.now);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let store = fixture.storage.clone();
    let at = system.now + 0.1;
    let worker = std::thread::spawn(move || {
        let mut adapter = BlockedAudit {
            now: at,
            started: started_tx,
            resume: resume_rx,
        };
        background_evidence::refresh_active_session(&store, &mut adapter)
    });
    started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    system.ip = "8.8.8.8";
    system.now += 1.0;
    let start = Instant::now();
    let result = controller.guard_tick(&mut system).unwrap();
    assert_eq!(result["action"], "close-desktop");
    assert_eq!(
        result["session_guard"]["reason"]["code"],
        "egress_ip_changed"
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(system.test_child.is_none());
    resume_tx.send(()).unwrap();
    assert!(
        worker.join().unwrap().is_err(),
        "late audit cannot revive the stopped session"
    );
}

#[test]
fn isolated_process_protection_stops_on_confirmed_cn_exit() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake {
        spawn_test_process: true,
        ..Fake::default()
    };
    controller.launch(&mut system).unwrap();
    system.now += 1.0;
    system.country = "CN";
    let risk = controller.guard_tick(&mut system).unwrap();
    assert_eq!(risk["action"], "close-desktop");
    assert_eq!(risk["session_guard"]["reason"]["code"], "egress_country_cn");
    assert!(system.test_child.is_none());
    assert_eq!(system.closes, 1);
    assert_eq!(
        SessionStore::new(fixture.storage.clone())
            .load(system.now)
            .unwrap()
            .unwrap()
            .state,
        Phase::Locked
    );
}
#[test]
fn controlled_launch_builds_immutable_baseline_and_legacy_lease_only_after_full_audit() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    let result = controller.launch(&mut system).unwrap();
    assert_eq!(result["status"], "ok");
    assert_eq!(system.opens, 1);
    let session = SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .unwrap();
    assert_eq!(session.state, Phase::Active);
    assert_eq!(session.baseline.ip, "1.1.1.1");
    assert_eq!(session.desktop.as_ref().unwrap().pid, 77);
    assert!(!fixture
        .storage
        .paths
        .watch()
        .join("state/desktop-pending")
        .exists());
    let entries = fs::read_dir(fixture.storage.paths.watch().join("state/sessions"))
        .unwrap()
        .count();
    assert_eq!(entries, 1);
    system.now += 1.0;
    system.ip = "8.8.8.8";
    let guarded = controller.guard_tick(&mut system).unwrap();
    assert_eq!(guarded["action"], "close-desktop");
    assert_eq!(system.closes, 1);
    let locked = SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .unwrap();
    assert_eq!(locked.state, Phase::Locked);
    assert_eq!(locked.baseline.ip, "1.1.1.1");
}

#[test]
fn a_stalled_resident_webview_does_not_delay_confirmed_ip_change_protection() {
    use claude_watch_runtime::{
        background_evidence::{ProbeExecutor, WORKER},
        release_native::{FixedCommand, FixedCommandExecutor},
    };
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Instant,
    };
    let fixture = Fixture::new();
    let script = fixture.home.join(WORKER);
    let ready = fixture.home.join("probe-waiting");
    fs::write(
        &script,
        format!(
            r#"#!/usr/bin/python3
import json,sys,time
from pathlib import Path
print(json.dumps({{'schema':1,'ready':True}}),flush=True)
for line in sys.stdin:
 Path({:?}).write_text('waiting')
 time.sleep(30)
"#,
            ready.to_str().unwrap()
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let cancel = stop.clone();
    let probe = std::thread::spawn(move || {
        ProbeExecutor::new(stop).run(FixedCommand {
            program: script,
            args: vec!["--dns".into()],
            timeout: Duration::from_secs(30),
        })
    });
    let wait = Instant::now();
    while !ready.exists() && wait.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.now += 1.0;
    system.ip = "8.8.8.8";
    let started = Instant::now();
    let protected = controller.guard_tick(&mut system).unwrap();
    let elapsed = started.elapsed();
    cancel.store(true, Ordering::Release);
    assert!(probe.join().unwrap().is_err());
    assert!(
        ready.exists(),
        "the isolated helper must be stalled during the guard check"
    );
    assert_eq!(protected["action"], "close-desktop");
    assert_eq!(system.closes, 1);
    assert!(
        elapsed < Duration::from_secs(2),
        "confirmed IP change must not wait for the WebView"
    );
}

#[test]
fn failed_audit_or_incomplete_risk_never_opens_and_never_weakens_launch_gate() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake {
        ready: false,
        ..Fake::default()
    };
    assert_eq!(
        controller.launch(&mut system).unwrap_err().code,
        "preflight_blocked"
    );
    assert_eq!(system.opens, 0);
    let path = fixture
        .storage
        .paths
        .base()
        .join("webrtc-risk-receipt.json");
    fs::remove_file(path).unwrap();
    system.ready = true;
    // Missing probe evidence no longer vetoes a launch: the probes measure
    // their own path, the launch gate is the audit plus the egress agreement,
    // and running drift detection handles the rest.
    let launched = controller.launch(&mut system).unwrap();
    assert_eq!(system.opens, 1);
    assert_eq!(launched["status"], "ok");
}
#[test]
fn launch_failure_locks_its_session_and_late_failure_cannot_close_a_new_session() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake {
        fail_open: true,
        ..Fake::default()
    };
    assert!(controller.launch(&mut system).is_err());
    let state = SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .unwrap();
    assert_eq!(state.state, Phase::Locked);
    assert_eq!(system.closes, 1);
    let mut replacement = Fake {
        replace_on_open: Some(fixture.storage.clone()),
        ..Fake::default()
    };
    assert!(controller.launch(&mut replacement).is_err());
    let state = SessionStore::new(fixture.storage.clone())
        .load(replacement.now)
        .unwrap()
        .unwrap();
    assert_eq!(state.state, Phase::Pending);
    assert_eq!(replacement.closes, 0);
}
#[test]
fn sampling_failure_retries_then_closes_without_claiming_ip_changed_and_normal_close_is_idle() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.now += 1.0;
    system.proxy = "unknown";
    let first = controller.guard_tick(&mut system).unwrap();
    assert_eq!(first["action"], "observe");
    assert_eq!(first["session_guard"]["state"], "unknown");
    assert_eq!(system.closes, 0);
    system.now += 1.0;
    let second = controller.guard_tick(&mut system).unwrap();
    assert_eq!(second["action"], "observe");
    system.now += 14.0;
    let third = controller.guard_tick(&mut system).unwrap();
    assert_eq!(third["action"], "close-desktop");
    assert_eq!(
        system.ip_force_calls, 0,
        "unconfirmed sampling does not use forced exit"
    );
    assert_eq!(
        third["session_guard"]["reason"]["code"],
        "proxy_or_tun_unconfirmed"
    );
    let fixture2 = Fixture::new();
    let controller2 = Controller::new(fixture2.storage.clone());
    let mut normal = Fake::default();
    controller2.launch(&mut normal).unwrap();
    normal.now += 1.0;
    normal.running = false;
    assert_eq!(
        controller2.guard_tick(&mut normal).unwrap()["session_guard"]["state"],
        "idle"
    );
}

#[test]
fn corrupt_session_fails_closed_without_overwriting_the_damaged_evidence() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.now += 1.0;
    fs::write(fixture.storage.paths.session(), b"{corrupt-session").unwrap();
    let result = controller.guard_tick(&mut system).unwrap();
    assert_eq!(result["action"], "close-desktop");
    assert_eq!(
        result["session_guard"]["reason"]["code"],
        "session_state_invalid"
    );
    assert_eq!(system.closes, 1);
    assert_eq!(
        system.ip_force_calls, 0,
        "session corruption is not a confirmed IP risk"
    );
    assert_eq!(
        fs::read(fixture.storage.paths.session()).unwrap(),
        b"{corrupt-session"
    );
}

#[test]
fn invalid_configuration_is_sampling_failure_not_a_guard_disable_or_an_ip_change() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    system.now += 1.0;
    fs::write(fixture.storage.paths.config(), b"{invalid-config").unwrap();
    let first = controller.guard_tick(&mut system).unwrap();
    assert_eq!(first["action"], "observe");
    assert_eq!(system.closes, 0);
    system.now += 1.0;
    let second = controller.guard_tick(&mut system).unwrap();
    assert_eq!(second["action"], "observe");
    system.now += 14.0;
    let third = controller.guard_tick(&mut system).unwrap();
    assert_eq!(third["action"], "close-desktop");
    assert_eq!(
        third["session_guard"]["reason"]["code"],
        "guard_sampling_failed"
    );
    assert_eq!(system.closes, 1);
}
#[test]
fn display_preview_cannot_be_reused_as_launch_authority() {
    let f = Fixture::new();
    let store = SessionStore::new(f.storage.clone());
    let receipts = ReceiptStore {
        storage: f.storage.clone(),
    };
    for purpose in ["environment_detection", "launch_requirements_preview"] {
        let mut value = audit(1000.);
        value["purpose"] = json!(purpose);
        value["grants_launch_permission"] = json!(false);
        value["expires_at"] = json!(1300.);
        let result = store.begin_verified(
            &receipts,
            &value,
            &json!({"ip":"1.1.1.1","country":"JP","observed_at":1000.}),
            1000.,
        );
        assert_eq!(result.unwrap_err().code, "display_receipt_not_authority");
        assert!(!f.storage.paths.session().exists());
    }
}

#[test]
fn monitor_and_protection_share_the_validated_automatic_session_reference() {
    let fixture = Fixture::new();
    let store = &fixture.storage;
    store
        .atomic_bytes(
            &store.paths.watch().join("state/baseline.conf"),
            b"format=2\ntimezone=Asia/Tokyo\n",
            0o600,
        )
        .unwrap();
    let mut system = Fake::default();
    assert_eq!(
        claude_watch_runtime::monitor_snapshot::empty(store, system.now, "fixture")["hasBaseline"],
        false
    );
    Controller::new(store.clone()).launch(&mut system).unwrap();
    assert_eq!(
        SessionStore::new(store.clone())
            .load(system.now)
            .unwrap()
            .unwrap()
            .baseline
            .ip,
        "1.1.1.1"
    );
    assert_eq!(
        claude_watch_runtime::monitor_snapshot::empty(store, system.now, "fixture")["hasBaseline"],
        true
    );
    store
        .atomic_bytes(&store.paths.session(), b"damaged session record", 0o600)
        .unwrap();
    assert_eq!(
        claude_watch_runtime::monitor_snapshot::empty(store, system.now, "fixture")["hasBaseline"],
        false
    );
    assert_eq!(
        fs::read(store.paths.session()).unwrap(),
        b"damaged session record"
    );
}

#[test]
fn observed_desktop_uses_shared_fresh_gate_and_only_creates_identity_leases() {
    use claude_watch_core::processes::{Kind, LaunchTarget};
    use claude_watch_runtime::lease_store::LeaseStore;
    for target in [LaunchTarget::CodexDesktop, LaunchTarget::ChatgptDesktop] {
        let fixture = Fixture::new();
        let storage = &fixture.storage;
        storage
            .atomic_bytes(
                &storage.paths.session(),
                b"existing Claude session unchanged",
                0o600,
            )
            .unwrap();
        storage
            .atomic_bytes(
                &storage.paths.accounts().join("A/profile/Cookies"),
                b"saved login unchanged",
                0o600,
            )
            .unwrap();
        let controller = Controller::new(storage.clone());
        let mut system = Fake {
            target,
            root_kind: Some(Kind::OpenaiMain),
            ..Default::default()
        };
        let receipt = controller.launch(&mut system).unwrap();
        assert_eq!(system.audits, 1);
        assert_eq!(system.opens, 1);
        assert_eq!(system.closes, 0);
        assert_eq!(receipt["authorization_scope"], "observation");
        assert_eq!(receipt["provider"], "openai");
        assert!(receipt.get("session_id").is_none());
        assert_eq!(
            fs::read(storage.paths.session()).unwrap(),
            b"existing Claude session unchanged"
        );
        assert_eq!(
            fs::read(storage.paths.accounts().join("A/profile/Cookies")).unwrap(),
            b"saved login unchanged"
        );
        let root = system.observation_roots().unwrap().remove(0);
        let mut inventory =
            std::collections::BTreeMap::from([(root.identity.pid, root.identity.clone())]);
        let leases = LeaseStore {
            storage: storage.clone(),
        };
        assert_eq!(leases.load(&inventory, 501, false).unwrap().len(), 1);
        inventory.get_mut(&77).unwrap().start_microseconds += 1;
        assert!(leases.load(&inventory, 501, true).unwrap().is_empty());
        assert_eq!(
            controller.guard_tick(&mut system).unwrap_err().code,
            "protected_scope_mismatch"
        );
        let risk = ReceiptStore {
            storage: storage.clone(),
        };
        assert_eq!(
            SessionStore::new(storage.clone())
                .begin_verified(&risk, &receipt["audit"], &system.egress(), system.now)
                .unwrap_err()
                .code,
            "launch_target_mismatch"
        );
        assert_eq!(system.closes, 0);
    }
}

#[test]
fn observed_start_failure_or_unknown_never_grants_or_closes_an_app() {
    use claude_watch_core::processes::LaunchTarget;
    for case in [
        "blocked",
        "running",
        "timeout",
        "pid-reused",
        "other-uid",
        "open-failed",
        "changed-ip",
    ] {
        let fixture = Fixture::new();
        let controller = Controller::new(fixture.storage.clone());
        let mut system = Fake {
            target: LaunchTarget::CodexDesktop,
            ..Default::default()
        };
        match case {
            "blocked" => system.ready = false,
            "running" => system.running = true,
            "timeout" => system.no_main = true,
            "pid-reused" => system.reuse_root = true,
            "other-uid" => system.root_uid = 999,
            "open-failed" => system.fail_open = true,
            "changed-ip" => system.ip = "8.8.8.8",
            _ => {}
        }
        assert!(controller.launch(&mut system).is_err(), "{case}");
        assert_eq!(system.closes, 0, "{case}");
        assert!(!fixture.storage.paths.session().exists(), "{case}");
        let dir = fixture.storage.paths.watch().join("state/sessions");
        assert!(
            !dir.exists() || fs::read_dir(dir).unwrap().next().is_none(),
            "{case}"
        );
        if matches!(case, "blocked" | "running" | "changed-ip") {
            assert_eq!(system.opens, 0);
        }
        if case == "running" {
            assert_eq!(system.audits, 0);
        }
    }
}

#[test]
fn a_process_started_outside_the_controller_during_audit_is_never_adopted() {
    use claude_watch_core::processes::LaunchTarget;
    for target in [
        LaunchTarget::ClaudeDesktop,
        LaunchTarget::CodexDesktop,
        LaunchTarget::ChatgptDesktop,
    ] {
        let fixture = Fixture::new();
        let mut system = Fake {
            target,
            start_during_audit: true,
            ..Default::default()
        };
        assert!(Controller::new(fixture.storage.clone())
            .launch(&mut system)
            .is_err());
        assert_eq!(system.audits, 1);
        assert_eq!(system.opens, 0);
        assert_eq!(system.closes, 0);
        assert!(!fixture.storage.paths.session().exists());
        let leases = fixture.storage.paths.watch().join("state/sessions");
        assert!(!leases.exists() || fs::read_dir(leases).unwrap().next().is_none());
    }
}

#[test]
fn cli_uses_shared_gate_releases_interactive_locks_and_removes_only_its_own_lease() {
    use claude_watch_core::processes::{Identity as P, LaunchTarget, Lease, Provider};
    use claude_watch_runtime::{events::EventStore, lease_store::LeaseStore};
    for target in [LaunchTarget::ClaudeCli, LaunchTarget::CodexCli] {
        let fixture = Fixture::new();
        let storage = &fixture.storage;
        storage
            .atomic_bytes(&storage.paths.session(), b"preserve Claude session", 0o600)
            .unwrap();
        let other = P {
            pid: 99,
            parent: 1,
            uid: 501,
            executable: "/fixture/other".into(),
            start_seconds: 800,
            start_microseconds: 9,
            start_stamp: "other".into(),
        };
        LeaseStore {
            storage: storage.clone(),
        }
        .save(
            &Lease {
                provider: Provider::Codex,
                root: other.clone(),
                owner: None,
                cli: false,
            },
            1000.,
        )
        .unwrap();
        let mut system = Fake {
            target,
            cli_store: Some(storage.clone()),
            ..Default::default()
        };
        let args = vec![
            "--home".into(),
            "--apply".into(),
            "SYNTHETIC_PRIVATE_PROMPT\n$(not-a-shell)".into(),
        ];
        let result = Controller::new(storage.clone())
            .launch_cli(&mut system, &args)
            .unwrap();
        assert_eq!(result.exit_code, 7);
        assert!(result.diagnostic.is_none());
        assert_eq!(system.cli_args, args);
        assert_eq!(system.audits, 1);
        assert_eq!(system.closes, 0);
        let owner = system.observation_owner().unwrap();
        let inventory = std::collections::BTreeMap::from([(owner.pid, owner), (other.pid, other)]);
        let leases = LeaseStore {
            storage: storage.clone(),
        }
        .load(&inventory, 501, false)
        .unwrap();
        assert_eq!(leases.len(), 1);
        assert!(!leases[0].cli);
        assert_eq!(
            fs::read(storage.paths.session()).unwrap(),
            b"preserve Claude session"
        );
        let log =
            serde_json::to_string(&EventStore::new(storage.clone()).export(100).unwrap()).unwrap();
        assert!(!log.contains("SYNTHETIC_PRIVATE_PROMPT"));
    }
}
#[test]
fn cli_refusal_spawn_failure_wait_failure_and_interrupts_never_leave_authority() {
    use claude_watch_core::processes::LaunchTarget;
    for case in ["blocked", "changed-ip", "spawn", "wait", "int", "term"] {
        let fixture = Fixture::new();
        let mut system = Fake {
            target: LaunchTarget::CodexCli,
            cli_store: Some(fixture.storage.clone()),
            ..Default::default()
        };
        match case {
            "blocked" => system.ready = false,
            "changed-ip" => system.ip = "8.8.8.8",
            "spawn" => system.fail_spawn = true,
            "wait" => system.fail_wait = true,
            "int" => system.interrupt_code = Some(130),
            "term" => system.interrupt_code = Some(143),
            _ => {}
        }
        let result = Controller::new(fixture.storage.clone()).launch_cli(&mut system, &[]);
        match case {
            "wait" => {
                let value = result.unwrap();
                assert_eq!(value.exit_code, 4);
                assert!(value.diagnostic.is_some());
            }
            "int" => assert_eq!(result.unwrap().exit_code, 130),
            "term" => assert_eq!(result.unwrap().exit_code, 143),
            _ => assert!(result.is_err(), "{case}"),
        }
        assert_eq!(system.closes, 0);
        assert!(!fixture.storage.paths.session().exists());
        let leases = fixture.storage.paths.watch().join("state/sessions");
        assert!(
            !leases.exists() || fs::read_dir(leases).unwrap().next().is_none(),
            "{case}"
        );
    }
}

#[test]
fn locked_session_retries_failed_stop_without_another_probe() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    fixture.receipts(system.now);
    controller.launch(&mut system).unwrap();
    system.fail_quit = true;
    system.proxy = "unknown";
    system.ip = "8.8.8.8";
    system.now += 1.0;
    let first = controller.guard_tick(&mut system).unwrap();
    assert_eq!(first["session_guard"]["state"], "risk");
    assert_eq!(first["stop_state"], "failed");
    assert_eq!(first["action"], "observe");
    let calls = system.egress_calls;
    system.ip = "1.1.1.1";
    system.fail_quit = false;
    system.now += 1.0;
    let second = controller.guard_tick(&mut system).unwrap();
    assert_eq!(second["session_guard"]["state"], "locked");
    assert_eq!(second["stop_state"], "confirmed");
    assert_eq!(system.egress_calls, calls);
}

#[cfg(target_os = "macos")]
#[test]
fn confirmed_exit_stops_even_when_session_write_fails() {
    struct Immutable(PathBuf);
    impl Drop for Immutable {
        fn drop(&mut self) {
            let _ = std::process::Command::new("/usr/bin/chflags")
                .arg("nouchg")
                .arg(&self.0)
                .status();
        }
    }
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    let path = fixture.storage.paths.session();
    let _restore = Immutable(path.clone());
    system.freeze_session = Some(path);
    system.ip = "8.8.8.8";
    system.now += 1.0;
    let receipt = controller.guard_tick(&mut system).unwrap();
    assert_eq!(receipt["persistence_error"], "state_io_failed");
    assert_eq!(receipt["stop_state"], "confirmed");
    assert_eq!(receipt["action"], "close-desktop");
    assert_eq!(
        system.ip_force_calls, 1,
        "confirmed IP risk still uses force fallback if state persistence fails"
    );
    assert!(!system.running);
}

#[cfg(target_os = "macos")]
#[test]
fn failed_write_and_failed_stop_latch_same_session_until_retry() {
    struct Immutable(PathBuf);
    impl Drop for Immutable {
        fn drop(&mut self) {
            let _ = std::process::Command::new("/usr/bin/chflags")
                .arg("nouchg")
                .arg(&self.0)
                .status();
        }
    }
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    let path = fixture.storage.paths.session();
    let _restore = Immutable(path.clone());
    system.freeze_session = Some(path);
    system.ip = "8.8.8.8";
    system.fail_quit = true;
    system.now += 1.0;
    let first = controller.guard_tick(&mut system).unwrap();
    assert_eq!(first["persistence_error"], "state_io_failed");
    assert_eq!(first["stop_state"], "failed");
    let calls = system.egress_calls;
    system.ip = "1.1.1.1";
    system.fail_quit = false;
    system.now += 1.0;
    let second = controller.guard_tick(&mut system).unwrap();
    assert_eq!(second["session_guard"]["state"], "locked");
    assert_eq!(second["stop_state"], "confirmed");
    assert_eq!(system.egress_calls, calls);
    assert!(!system.running);
    // The failure latch belongs only to the original session.
    assert!(std::process::Command::new("/usr/bin/chflags")
        .arg("nouchg")
        .arg(&fixture.storage.paths.session())
        .status()
        .unwrap()
        .success());
    system.now += 1.0;
    fixture.receipts(system.now);
    controller.launch(&mut system).unwrap();
    system.now += 1.0;
    let new_session = controller.guard_tick(&mut system).unwrap();
    assert_eq!(new_session["action"], "observe");
    assert_ne!(new_session["session_guard"]["state"], "locked");
    assert!(system.running);
}

#[test]
fn a_manually_started_claude_is_adopted_into_supervision() {
    let fixture = Fixture::new();
    let mut system = Fake {
        running: true,
        ..Default::default()
    };
    let receipt = Controller::new(fixture.storage.clone())
        .guard_tick(&mut system)
        .unwrap();
    assert_eq!(receipt["action"], "observe");
    assert_eq!(
        receipt["session_guard"]["reason"]["code"],
        "session_adopted"
    );
    // Adoption is supervision, not a stop: the running app is left alone.
    assert_eq!(system.closes, 0);
    assert!(system.running);
    let session = SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .expect("adopted session");
    assert_eq!(session.state, Phase::Active);
    assert_eq!(session.extra["adopted_from"], json!("running_desktop"));
    assert_eq!(session.baseline.ip, "1.1.1.1");
}

#[test]
fn adoption_refuses_an_unverified_preflight() {
    let fixture = Fixture::new();
    let mut system = Fake {
        running: true,
        ready: false,
        ..Default::default()
    };
    let receipt = Controller::new(fixture.storage.clone())
        .guard_tick(&mut system)
        .unwrap();
    assert_eq!(receipt["adopt_error"], "preflight_blocked");
    // The unadopted process is not allowed to run unguarded.
    assert_eq!(system.closes, 1);
}

#[test]
fn an_adopted_claude_is_force_stopped_when_the_exit_changes() {
    let fixture = Fixture::new();
    let mut system = Fake {
        running: true,
        ..Default::default()
    };
    let controller = Controller::new(fixture.storage.clone());
    controller.guard_tick(&mut system).unwrap();
    system.ip = "2.2.2.2";
    let receipt = controller.guard_tick(&mut system).unwrap();
    assert_eq!(
        receipt["session_guard"]["reason"]["code"],
        "egress_ip_changed"
    );
    assert_eq!(system.ip_force_calls, 1);
    assert_eq!(system.closes, 1);
    assert!(!system.running);
}

#[test]
fn adoption_refuses_a_cn_exit() {
    let fixture = Fixture::new();
    let mut system = Fake {
        running: true,
        country: "CN",
        ..Default::default()
    };
    let receipt = Controller::new(fixture.storage.clone())
        .guard_tick(&mut system)
        .unwrap();
    // A mainland exit is never a supervision baseline, even with a clean
    // preflight: adopting it would bless the leak this guard exists to stop.
    assert!(receipt["adopt_error"].is_null());
    assert_ne!(
        receipt["session_guard"]["reason"]["code"],
        "session_adopted"
    );
    assert_eq!(system.closes, 1);
    assert!(!system.running);
    assert!(SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .is_none());
}

#[test]
fn adoption_refuses_a_stale_exit() {
    let fixture = Fixture::new();
    let mut system = Fake {
        running: true,
        // Older than GUARD_EGRESS_TTL, so the exit cannot anchor a session.
        egress_age: 11.0,
        ..Default::default()
    };
    let receipt = Controller::new(fixture.storage.clone())
        .guard_tick(&mut system)
        .unwrap();
    assert!(receipt["adopt_error"].is_null());
    assert_ne!(
        receipt["session_guard"]["reason"]["code"],
        "session_adopted"
    );
    assert_eq!(system.closes, 1);
    assert!(SessionStore::new(fixture.storage.clone())
        .load(system.now)
        .unwrap()
        .is_none());
}

fn policy_config(fixture: &Fixture, dns: &str, webrtc: &str) {
    let config = claude_watch_core::config::Config {
        guard_enabled: true,
        claude_close_dns: dns.into(),
        claude_close_webrtc: webrtc.into(),
        ..Default::default()
    };
    fixture
        .storage
        .atomic_json(&fixture.storage.paths.config(), &config.value().unwrap())
        .unwrap();
}
/// Re-record fresh probe receipts with the given drift: DNS country set and
/// WebRTC srflx address. The original Fixture baseline is JP / 1.1.1.1.
fn drifted_receipts(fixture: &Fixture, now: f64, dns_country: &'static str, srflx: &'static str) {
    let receipts = ReceiptStore {
        storage: fixture.storage.clone(),
    };
    let local = json!({"context":"ctx","context_id":"ctx","proxy":"ok","tun":"ok"});
    let probe = json!({"kind":"dns","status":"complete","contextChanged":false,"startedAt":now-1.0,"finishedAt":now,"errors":[],"observations":[{"kind":"http","address":"1.1.1.1"},{"kind":"resolver","address":"9.9.9.9"}],"externalJSON":serde_json::to_string(&json!({
        "session":"a".repeat(40),"dns_servers":{"9.9.9.9":5},"http":{"address":"1.1.1.1","country":dns_country},"geoip":[{"ip":"9.9.9.9","country_code":dns_country}]
    })).unwrap()});
    receipts.record_dns(&probe, &local, None, now).unwrap();
    receipts.record_webrtc(
        &json!({"kind":"webrtc","status":"complete","contextChanged":false,"startedAt":now-1.0,"finishedAt":now,"errors":[],"observations":[{"kind":"http","address":"1.1.1.1","country":"JP"},{"kind":"srflx","address":srflx,"country":"JP"}]}),
        &local,
        None,
        now,
    )
    .unwrap();
}

#[test]
fn warn_configured_probe_drift_notifies_without_closing() {
    let fixture = Fixture::new();
    policy_config(&fixture, "warn", "force");
    let mut system = Fake {
        running: true,
        ..Default::default()
    };
    let controller = Controller::new(fixture.storage.clone());
    controller.guard_tick(&mut system).unwrap();
    drifted_receipts(&fixture, system.now + 1.0, "US", "1.1.1.1");
    system.now += 2.0;
    let receipt = controller.guard_tick(&mut system).unwrap();
    // A warn-configured criterion reports but never closes: the session
    // survives and the next round re-evaluates.
    assert_eq!(receipt["session_notice"]["code"], "dns_egress_changed");
    assert_eq!(receipt["action"], "observe");
    assert_eq!(receipt["stop_state"], "skipped_warn_only");
    assert_eq!(system.closes, 0);
    assert!(system.running);
}

#[test]
fn combined_probe_drift_forces_by_default_and_never_softens() {
    // Regression: the combined dns+webrtc code must inherit the stricter of
    // the two configured actions. Before the fix it fell through to a plain
    // close even with the default all-force policy.
    let fixture = Fixture::new();
    let mut system = Fake {
        running: true,
        ..Default::default()
    };
    let controller = Controller::new(fixture.storage.clone());
    controller.guard_tick(&mut system).unwrap();
    drifted_receipts(&fixture, system.now + 1.0, "US", "3.3.3.3");
    system.now += 2.0;
    let receipt = controller.guard_tick(&mut system).unwrap();
    assert_eq!(
        receipt["session_guard"]["reason"]["code"],
        "dns_and_webrtc_egress_changed"
    );
    assert_eq!(receipt["stop_action"], "force");
    assert_eq!(system.ip_force_calls, 1);
    assert_eq!(system.closes, 1);
    assert!(!system.running);
}

#[test]
fn combined_probe_drift_applies_the_stricter_of_the_two_policies() {
    let fixture = Fixture::new();
    policy_config(&fixture, "warn", "force");
    let mut system = Fake {
        running: true,
        ..Default::default()
    };
    let controller = Controller::new(fixture.storage.clone());
    controller.guard_tick(&mut system).unwrap();
    drifted_receipts(&fixture, system.now + 1.0, "US", "3.3.3.3");
    system.now += 2.0;
    let receipt = controller.guard_tick(&mut system).unwrap();
    // DNS is warn but WebRTC is force: the wider drift keeps the strict tier.
    assert_eq!(receipt["stop_action"], "force");
    assert_eq!(system.ip_force_calls, 1);
    assert!(!system.running);
}
