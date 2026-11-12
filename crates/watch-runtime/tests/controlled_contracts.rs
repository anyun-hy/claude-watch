use claude_watch_core::{
    channel::{ChannelEnforcementReceipt, ChannelEnforcementState, ChannelPermit, ChannelPermitState},
    error::{CoreError, Result},
    session::{Desktop, Launcher, Phase},
};
use claude_watch_runtime::{
    channel_policy_status::read_guard_summary,
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
    family: &'static str,
    /// When true, the OpenAI family also reports a running desktop so a test
    /// can drive its automatic disposition. Defaults false so the existing
    /// Claude-only contracts keep the OpenAI tick idle.
    supervise_openai: bool,
    channel_mode_enabled: bool,

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
            family: "claude",
            supervise_openai: false,
            channel_mode_enabled: false,
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
    fn channel_mode(&self) -> bool {
        self.channel_mode_enabled
    }
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
    fn set_family(&mut self, family_id: &str) -> Result<()> {
        // Mirror the real system: a family's tick runs against that family's
        // own guard target, and the audit it collects declares that target.
        // Keeping the target on ClaudeDesktop here is what let a test pass
        // while production rejected the same audit with
        // `launch_target_mismatch`.
        // Even if this fixture has no running members in the selected family,
        // its target must switch exactly as the production adapter does. The
        // process-presence toggle affects inventory only, never audit target.
        let family = claude_watch_core::policy::PolicyCatalog::family(family_id)
            .ok_or_else(|| CoreError::new("target_adapter_unavailable", "测试目标家族不存在"))?;
        let target = claude_watch_core::policy::PolicyCatalog::guard_target(family)
            .ok_or_else(|| CoreError::new("target_adapter_unavailable", "测试目标不可监管"))?;
        self.family = family.id;
        self.target = target;
        Ok(())
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
        let present = if self.supervise_openai {
            self.family == "openai"
        } else {
            self.family == "claude"
        };
        if !self.running || self.no_main || !present {
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
        // `supervise_openai` repurposes `running` as the OpenAI family's
        // process state and leaves the Claude family empty, so a test can
        // drive the OpenAI disposition in isolation. The default (false)
        // keeps the original Claude-only fixture semantics.
        let present = if self.supervise_openai {
            self.running && self.family == "openai"
        } else {
            self.running && self.family == "claude"
        };
        Ok(if present {
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
            // A wait receipt for this exact owned child proves its exit without
            // depending on whether unrelated host processes are readable.
            if self.native_start == Some((expected.start_seconds, expected.start_microseconds)) {
                if let Some(child) = self.test_child.as_mut().filter(|c| c.id() == expected.pid) {
                    if child.try_wait().map_err(|_| {
                        CoreError::new("fixture_child_wait_failed", "无法确认自有测试进程的退出状态")
                    })?.is_some() {
                        return Ok(false);
                    }
                }
            }
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
        let present = if self.supervise_openai {
            self.family == "openai"
        } else {
            self.family == "claude"
        };
        Ok(self.tree_running_override.unwrap_or(self.running && present))
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

}

#[test]
fn enabled_guard_resumes_from_saved_config_and_explicit_disable_persists() {
    let fixture = Fixture::new();
    let first = read_guard_summary(&fixture.storage, 1000.0);
    assert_eq!(first["status"], "unknown");
    assert_eq!(first["session_guard"]["state"], "pending_verification");
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
    let disabled = read_guard_summary(&fixture.storage, 1000.0);
    assert_eq!(disabled["status"], "disabled");
}

#[test]
fn enabling_timezone_keeps_the_running_guard_and_session() {
    use claude_watch_runtime::{
        config_store::{guard_policy_digest, ConfigStore},
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
    let session = fs::read(fixture.storage.paths.session()).unwrap();
    let configs = ConfigStore { storage: fixture.storage.clone() };
    let previous_policy = guard_policy_digest(&configs.load().unwrap()).unwrap();
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
    assert_eq!(guard_policy_digest(&config).unwrap(), previous_policy);
    assert_eq!(fs::read(fixture.storage.paths.session()).unwrap(), session);
    assert!(desktop.running);
    assert_eq!(desktop.closes, 0);
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
fn invalid_configuration_reports_without_authorising_a_stop() {
    let fixture = Fixture::new();
    let controller = Controller::new(fixture.storage.clone());
    let mut system = Fake::default();
    controller.launch(&mut system).unwrap();
    let before = fs::read(fixture.storage.paths.session()).unwrap();
    fs::write(fixture.storage.paths.config(), b"{invalid-config").unwrap();
    let result = read_guard_summary(&fixture.storage, 1016.0);
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["action"], "observe");
    assert!(result["code"].is_string());
    assert_eq!(system.closes, 0);
    assert!(system.running);
    assert_eq!(fs::read(fixture.storage.paths.session()).unwrap(), before);
    assert!(!fixture.storage.paths.base().join("last-guard-stop.json").exists());
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
fn fake_family_switches_target_even_without_a_running_member() {
    use claude_watch_core::processes::LaunchTarget;
    // The absence of an OpenAI process does not exempt the adapter from
    // reporting the actual OpenAI target during its guard tick.
    let mut fake = Fake::default();
    assert!(!fake.supervise_openai);
    DesktopSystem::set_family(&mut fake, "openai").unwrap();
    assert_eq!(DesktopSystem::launch_target(&fake), LaunchTarget::CodexDesktop);
    let audit = DesktopSystem::full_audit(&mut fake).unwrap();
    assert_eq!(audit["launch_target"], "codex-desktop");
    assert_eq!(audit["authorization_scope"], "observation");
    assert!(DesktopSystem::desktops(&mut fake).unwrap().is_empty());

    DesktopSystem::set_family(&mut fake, "claude").unwrap();
    assert_eq!(DesktopSystem::launch_target(&fake), LaunchTarget::ClaudeDesktop);
    let claude_audit = DesktopSystem::full_audit(&mut fake).unwrap();
    assert!(claude_audit.get("launch_target").is_none());
    assert!(claude_audit.get("authorization_scope").is_none());

    let before = DesktopSystem::launch_target(&fake);
    assert_eq!(
        DesktopSystem::set_family(&mut fake, "unregistered").unwrap_err().code,
        "target_adapter_unavailable"
    );
    assert_eq!(DesktopSystem::launch_target(&fake), before);
}

#[test]
fn n4_supervisor_does_not_import_disk_process_receipt() {
    let fixture = Fixture::new();
    let receipt = claude_watch_core::channel::ProcessDispositionReceipt {
        intent_id: "intent-test-1".into(),
        family: "claude".into(),
        session_id: "s-1".into(),
        action: "force_quit".into(),
        process_execution_state: "terminated".into(),
        process_preserved: false,
        observed_at: 1000.0,
        error_code: None,
        authority: None,
        target_results: vec![
            claude_watch_core::channel::TargetProcessDispositionResult {
                pid: 9999,
                requested_action: "force_quit".into(),
                terminated: true,
                process_state: "terminated".into(),
                timestamp: 1000.0,
                signal_sent_at: None,
            }
        ],
    };
    fixture.storage.atomic_json(
        &fixture.storage.paths.watch().join("state/process-receipt-claude.json"),
        &serde_json::to_value(&receipt).unwrap(),
    ).unwrap();

    let supervisor = claude_watch_runtime::channel_supervisor::ChannelSupervisor::new(fixture.storage.clone(), None, None).unwrap();
    let snapshot = supervisor.snapshot(1000.0);
    let monitor = &snapshot.families["claude"];

    assert!(monitor.process_disposition_receipt.is_none());
    assert!(monitor.process_execution_state.is_none());
    assert!(monitor.process_disposition_action.is_none());
}

fn blocked_guard_fixture(fixture: &Fixture, mut permit: ChannelPermit) -> (ChannelPermit, ChannelEnforcementReceipt) {
    let config = claude_watch_runtime::config_store::ConfigStore { storage: fixture.storage.clone() }.load().unwrap();
    permit.policy_version = claude_watch_runtime::channel_supervisor::ChannelSupervisor::compute_policy_version(&config).unwrap();
    let receipt = ChannelEnforcementReceipt {
        family: permit.family.clone(), session_id: permit.session_id.clone(), policy_version: permit.policy_version.clone(),
        permit_generation: permit.permit_generation, command_seq: permit.command_seq, executor_boot_id: "fixture-executor".into(),
        receipt_seq: 1, permit_state: ChannelPermitState::Revoked, enforcement_state: ChannelEnforcementState::Blocked,
        interception_active: true, local_proxy_ready: true, system_extension_active: false, new_connections_blocked: true,
        active_flows_closed: true, direct_fallback_blocked: true, active_flows_count: 0, terminated_flows_count: 0,
        blocked_new_connections: 0, observed_at: permit.issued_at, error_code: None, backend: permit.backend,
        vpn_epoch: permit.vpn_epoch.clone(), coverage_scope: permit.coverage_scope.clone(), sandbox_ready: true,
    };
    (permit, receipt)
}

fn publish_guard_fixture(fixture: &Fixture, permit: &ChannelPermit, receipt: &ChannelEnforcementReceipt) {
    let identity = claude_watch_system::inspect_process_identity(std::process::id()).unwrap();
    let family = &permit.family;
    let frame = json!({
        "captured_at": 1000.0, "producer_boot_id": "fixture-supervisor",
        "producer_identity": {"pid": identity.pid, "uid": identity.uid,
            "start_seconds": identity.start_seconds, "start_microseconds": identity.start_microseconds,
            "executable_path": identity.executable_path, "audit_token": identity.audit_token},
        "executor_boot_id": receipt.executor_boot_id, "saved_policy_version": permit.policy_version,
        "families": {(family): {
            "producer_boot_id": "fixture-supervisor", "session_id": permit.session_id,
            "saved_policy_version": permit.policy_version,
            "command_seq": permit.command_seq, "permit_generation": permit.permit_generation,
            "process_preserved": true,
        }},
        "authoritative_permits": {(family): permit},
        "enforcement_receipts": {(family): receipt},
    });
    let path = fixture.storage.paths.watch().join(claude_watch_runtime::channel_policy_status::FRAME_PATH);
    fixture.storage.atomic_json(&path, &frame).unwrap();
}

fn channel_collector_fixture(fixture: &Fixture) -> (Value, ChannelPermit, ChannelEnforcementReceipt) {
    use claude_watch_core::channel::{BoundProcessToken, NetworkBackendKind, PolicyVersion};
    let token = BoundProcessToken::with_system_identity(8822, 501, 1000, 0,
        claude_watch_core::processes::ProcessRole::Cli).with_audit_token([501,501,20,501,20,8822,0,9]);
    let session = json!({"schema":1,"state":"locked","session_id":"collector-channel",
        "baseline":{"ip":"1.1.1.1","country":"JP","observed_at":1000.,"source":"fixture"},
        "reason":{"code":"egress_ip_changed","detail":"fixture risk","source":"fixture","observed_at":1000.},
        "channel_processes_v1":[token]});
    let permit = ChannelPermit { family:"claude".into(), session_id:Some("collector-channel".into()),
        context_id:None, policy_version:PolicyVersion { policy_digest: String::new(), guard_policy_digest: String::new() }, permit_generation:3, command_seq:41,
        state:ChannelPermitState::Revoked, reason_code:"egress_ip_changed".into(), issued_at:1000., valid_until:1030.,
        baseline_ip:None, members:vec![], backend:NetworkBackendKind::Seatbelt, vpn_epoch:None, coverage_scope:None };
    let (permit, receipt) = blocked_guard_fixture(fixture, permit);
    (session, permit, receipt)
}

#[test]
fn guard_reader_uses_only_the_supervisor_frame_and_never_changes_the_session() {
    let fixture = Fixture::new();
    let (session, permit, mut receipt) = channel_collector_fixture(&fixture);
    let store = &fixture.storage;
    let session_path = store.paths.session_for("claude");
    store.atomic_json(&session_path, &session).unwrap();
    let session_bytes = fs::read(&session_path).unwrap();
    store.atomic_json(&store.paths.watch().join("state/channel-permits.json"), &json!({"claude": permit})).unwrap();
    store.atomic_json(&store.paths.base().join("guard-heartbeat.json"), &json!({"status":"ok","time":1000.0})).unwrap();

    let status = || read_guard_summary(store, 1000.0)["families"][0].clone();
    assert_eq!(status()["session_guard"]["state"], "pending_verification");
    assert!(status()["channel_receipt"].is_null());

    publish_guard_fixture(&fixture, &permit, &receipt);
    let blocked = status();
    assert_eq!(blocked["channel_receipt"]["command_seq"], 41);
    assert_eq!(blocked["channel_supervision"]["verdict"], "isolated_keep_process");
    assert_eq!(blocked["process_preserved"], true);
    assert!(blocked["process_disposition_receipt"].is_null());

    receipt.observed_at = 900.0;
    publish_guard_fixture(&fixture, &permit, &receipt);
    let expired = status();
    assert_eq!(expired["channel_execution_state"], "pending_verification");
    assert_eq!(expired["channel_supervision"]["code"], "enforcement_receipt_expired");
    assert_eq!(expired["channel_permit"]["state"], "revoked");

    receipt.observed_at = 1000.0;
    receipt.enforcement_state = ChannelEnforcementState::Failed;
    receipt.error_code = Some("enforcement_reported_failure".into());
    publish_guard_fixture(&fixture, &permit, &receipt);
    let failed = status();
    assert_eq!(failed["status"], "protection_unavailable");
    assert_eq!(failed["channel_supervision"]["code"], "enforcement_reported_failure");
    assert_eq!(fs::read(&session_path).unwrap(), session_bytes);
}
