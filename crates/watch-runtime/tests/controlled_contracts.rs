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
        let probe = json!({"kind":"dns","status":"complete","contextChanged":false,"startedAt":now-1.0,"finishedAt":now,"errors":[],"observations":[{"kind":"http","address":"1.1.1.1"},{"kind":"resolver","address":"8.8.8.8"}],"externalJSON":serde_json::to_string(&json!([
            {"kind":"geoip","status":"complete","query":"1.1.1.1","data":{"country_code":"JP"}},{"kind":"geoip","status":"complete","query":"8.8.8.8","data":{"country_code":"JP"}}
        ])).unwrap()});
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
    ready: bool,
    fail_open: bool,
    proxy: &'static str,
    ip: &'static str,
    country: &'static str,
    replace_on_open: Option<StateStore>,
    target: claude_watch_core::processes::LaunchTarget,
    root_kind: Option<claude_watch_core::processes::Kind>,
    root_uid: u32,
    no_main: bool,
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
            ready: true,
            fail_open: false,
            proxy: "ok",
            ip: "1.1.1.1",
            country: "JP",
            replace_on_open: None,
            target: Default::default(),
            root_kind: None,
            root_uid: 501,
            no_main: false,
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
                        .unwrap_or(77),
                    start_seconds: 900,
                    start_microseconds: 1,
                },
                true,
                "Tue Nov 14 22:12:50 2023".into(),
            )]
        } else {
            vec![]
        })
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
        json!({"ip":self.ip,"country":self.country,"observed_at":self.now,"source":"fixture HTTP exit"})
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
        }
        self.running = true;
        Ok(())
    }
    fn quit_desktop(&mut self) -> Result<()> {
        self.closes += 1;
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
    assert_eq!(
        controller.launch(&mut system).unwrap_err().code,
        "risk_evidence_unavailable"
    );
    assert_eq!(system.opens, 0);
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
