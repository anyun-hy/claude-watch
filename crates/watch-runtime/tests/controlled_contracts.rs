use claude_watch_core::{
    channel::{ChannelEnforcementReceipt, ChannelEnforcementState, ChannelPermit, ChannelPermitState},
    error::{CoreError, Result},
    session::Desktop,
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

    egress_calls: u32,

    ip: &'static str,
    country: &'static str,
    egress_age: f64,

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

    family: &'static str,
    /// When true, the OpenAI family also reports a running desktop so a test
    /// can drive its automatic disposition. Defaults false so the existing
    /// Claude-only contracts keep the OpenAI tick idle.
    supervise_openai: bool,

    desktop_reads: u32,

    supervisor_receipt_reads: u32,
    terminated_supervised: Vec<claude_watch_core::channel::BoundProcessToken>,

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

            egress_calls: 0,

            ip: "1.1.1.1",
            country: "JP",
            egress_age: 0.0,

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

            family: "claude",
            supervise_openai: false,

            desktop_reads: 0,

            supervisor_receipt_reads: 0,
            terminated_supervised: Vec::new(),

        }
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
                pid: 77,
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
        json!({"ip":self.ip,"country":self.country,"observed_at":self.now - self.egress_age,"source":"fixture HTTP exit"})
    }

    fn backend_healthy(&mut self) -> Result<bool> {
        Ok(true)
    }

    fn open_desktop(&mut self) -> Result<()> {
        self.opens += 1;
        self.now += 0.1;
        if self.fail_open {
            return Err(CoreError::new("fixture_open_failed", "fixture"));
        }
        self.running = true;
        Ok(())
    }

}

#[test]
fn desktop_launch_creates_only_observation_lease_not_supervisor_authority() {
    let fixture=Fixture::new(); let mut system=Fake::default();
    let result=Controller::new(fixture.storage.clone()).launch(&mut system).unwrap();
    assert_eq!(result["status"],"ok"); assert_eq!(result["authorization_scope"],"observation");
    assert_eq!((system.opens,system.audits),(1,1));
    assert!(!fixture.storage.paths.session().exists());
    assert!(!fixture.storage.paths.watch().join("state/desktop-pending").exists());
    assert_eq!(fs::read_dir(fixture.storage.paths.watch().join("state/sessions")).unwrap().count(),1);
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
fn launch_failure_preserves_preexisting_session_without_granting_a_lease() {
    let fixture=Fixture::new();
    let before=b"existing supervisor state is not launcher authority";
    fixture.storage.atomic_bytes(&fixture.storage.paths.session(),before,0o600).unwrap();
    let mut system=Fake { fail_open:true,..Default::default() };
    assert!(Controller::new(fixture.storage.clone()).launch(&mut system).is_err());
    assert_eq!(fs::read(fixture.storage.paths.session()).unwrap(),before);
    assert!(!fixture.storage.paths.watch().join("state/sessions").exists());
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
    let sessions=SessionStore::new(store.clone());
    let pending=sessions.begin_verified(&ReceiptStore { storage:store.clone() },&audit(system.now),&system.egress(),system.now).unwrap();
    sessions.bind_desktop(&pending.session_id,Desktop { pid:77,start_seconds:900,start_microseconds:1 },system.now).unwrap();
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
        // Guard reporting cannot infer process effects from a corrupt legacy
        // session or manufacture authority without a published frame.
        let guard_receipt = controller.guard_tick(&mut system).unwrap();
        assert_eq!(guard_receipt["action"], "observe");
        assert_eq!(system.closes, 0);
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
fn delegated_channel_session_skips_failing_desktop_inventory_and_reads_authority_receipt() {
    let fixture = Fixture::new();
    let (session, permit, authority_receipt) = channel_collector_fixture(&fixture);
    publish_guard_fixture(&fixture, &permit, &authority_receipt);
    fixture.storage.atomic_json(&fixture.storage.paths.session_for("claude"), &session).unwrap();
    let mut system = Fake { running:true, ..Fake::default() };
    let receipt = Controller::new(fixture.storage.clone()).guard_tick_for_family(&mut system, "claude").unwrap();
    assert_eq!(system.desktop_reads, 0, "supervisor-owned sessions do not require a second desktop inventory");
    assert_eq!(system.supervisor_receipt_reads, 0, "the published frame is the only receipt source");
    assert_eq!(receipt["channel_receipt"]["command_seq"], 41);
    assert_eq!(receipt["channel_supervision"]["verdict"], "isolated_keep_process");
    assert_eq!(fixture.storage.read_json(&fixture.storage.paths.session_for("claude"), Value::Null).unwrap(), session);
    assert_eq!((system.closes, system.ip_force_calls), (0,0));
    assert!(system.terminated_supervised.is_empty());
}

#[test]
fn missing_frame_does_not_import_a_legacy_receipt() {
    let fixture = Fixture::new();
    let (session, _, authority_receipt) = channel_collector_fixture(&fixture);
    fixture.storage.atomic_json(&fixture.storage.paths.watch().join("state/channel-receipts.json"),
        &json!({"claude":authority_receipt})).unwrap();
    fixture.storage.atomic_json(&fixture.storage.paths.session_for("claude"), &session).unwrap();
    let mut system = Fake { running:true, ..Fake::default() };
    let receipt = Controller::new(fixture.storage.clone()).guard_tick_for_family(&mut system, "claude").unwrap();
    assert_eq!((system.desktop_reads, system.supervisor_receipt_reads), (0, 0));
    assert_eq!(receipt["session_guard"]["state"], "pending_verification");
    assert!(receipt["channel_receipt"].is_null());
    assert_eq!(fixture.storage.read_json(&fixture.storage.paths.session_for("claude"), Value::Null).unwrap(), session);
    assert_eq!((system.closes, system.ip_force_calls), (0,0));
    assert!(system.terminated_supervised.is_empty());
}

#[test]
fn delegated_channel_expired_receipt_stays_closed_and_projects_pending_verification() {
    let fixture = Fixture::new();
    let (session, permit, mut authority_receipt) = channel_collector_fixture(&fixture);
    authority_receipt.observed_at = 900.;
    publish_guard_fixture(&fixture, &permit, &authority_receipt);
    fixture.storage.atomic_json(&fixture.storage.paths.session_for("claude"), &session).unwrap();
    let mut system = Fake { running:true, ..Fake::default() };
    let receipt = Controller::new(fixture.storage.clone()).guard_tick_for_family(&mut system, "claude").unwrap();
    assert_eq!(receipt["status"], "pending");
    assert_eq!(receipt["session_guard"]["state"], "pending_verification");
    assert_eq!(receipt["channel_state"], "pending_verification");
    assert_eq!(receipt["channel_execution_state"], "pending_verification");
    assert_eq!(receipt["channel_supervision"]["verdict"], "enforcement_failed");
    assert_eq!(receipt["channel_supervision"]["code"], "enforcement_receipt_expired");
    assert_eq!(receipt["channel_permit"]["state"], "revoked");
    assert_eq!(receipt["action"], "disconnect-channel");
    assert_eq!(fixture.storage.read_json(&fixture.storage.paths.session_for("claude"), Value::Null).unwrap(), session);
    assert_eq!((system.closes, system.ip_force_calls), (0,0));
}

#[test]
fn delegated_channel_reported_execution_failure_keeps_failure_projection() {
    let fixture = Fixture::new();
    let (session, permit, mut authority_receipt) = channel_collector_fixture(&fixture);
    authority_receipt.enforcement_state = ChannelEnforcementState::Failed;
    authority_receipt.error_code = Some("enforcement_reported_failure".into());
    publish_guard_fixture(&fixture, &permit, &authority_receipt);
    fixture.storage.atomic_json(&fixture.storage.paths.session_for("claude"), &session).unwrap();
    let mut system = Fake { running:true, ..Fake::default() };
    let receipt = Controller::new(fixture.storage.clone()).guard_tick_for_family(&mut system, "claude").unwrap();
    assert_eq!(receipt["status"], "protection_unavailable");
    assert_eq!(receipt["session_guard"]["state"], "unknown");
    assert_eq!(receipt["channel_state"], "failed");
    assert_eq!(receipt["channel_execution_state"], "failed");
    assert_eq!(receipt["channel_supervision"]["code"], "enforcement_reported_failure");
    assert_eq!(receipt["channel_permit"]["state"], "revoked");
    assert_eq!((system.closes, system.ip_force_calls), (0,0));
}
