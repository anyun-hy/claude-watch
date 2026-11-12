#[path = "hardened_helper.rs"]
mod hardened_helper;

use super::*;
use crate::{
    channel_enforcer::LocalTunnelEnforcer,
    managed_cli_supervisor_fixture as fixture,
    managed_entry::DesktopManagedEntrySpec,
    receipt_store::ReceiptStore,
    sandbox_launch::build_helper_verifier_for_path,
    storage::Paths,
};
use claude_watch_core::{
    channel::{ChannelPermitState, PolicyVersion},
    config::Config,
    controlled_launch::{ControlledLaunchRequest, ProxyAdaptationKind},
    processes::LaunchTarget,
};
use claude_watch_system::{inspect_process_identity, sha256_file_hex};
use serde_json::{json, Value};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

#[path = "managed_entry_live_members.rs"]
mod live_members;

const BOOT: &str = "owned-entry-and-disposition-executor";

struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Fixture {
    root: PathBuf,
    storage: StateStore,
    config: Config,
    policy: PolicyVersion,
    helper: PathBuf,
    registry: Arc<SandboxLaunchRegistry>,
    enforcer: Arc<LocalTunnelEnforcer>,
    gateway: SocketAddr,
    _upstream: TcpListener,
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for worker in self.workers.drain(..) { let _ = worker.join(); }
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    fn start() -> Self {
        let root = PathBuf::from("/private/tmp").join(format!("cw-x-{}", &uuid::Uuid::new_v4().simple().to_string()[..12]));
        fs::create_dir(&root).unwrap();
        let storage = StateStore::new(Paths::new(&root).unwrap());
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut config = fixture::config(&storage, &upstream.local_addr().unwrap().to_string());
        config.policy_actions.insert("claude_close_ip".into(), "force".into());
        let config = (ConfigStore { storage: storage.clone() }).save(config.value().unwrap()).unwrap();
        let policy = ChannelSupervisor::compute_policy_version(&config).unwrap();
        let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/watch-sandbox-launcher").canonicalize().unwrap();
        let helper = hardened_helper::copy_signed(&helper, &root.join("watch-sandbox-launcher"));
        let verifier = build_helper_verifier_for_path(&helper).unwrap();
        let registry = Arc::new(SandboxLaunchRegistry::new(BOOT, policy.clone(), verifier, Some(storage.clone())));
        let enforcer = Arc::new(LocalTunnelEnforcer::new(BOOT));
        let stop = Arc::new(AtomicBool::new(false));
        let now = native::now();
        // Isolated component readiness. No production I03 or launchd override.
        enforcer.configure_seatbelt_backend(true, now).unwrap();
        enforcer.set_clock(native::now).unwrap();
        let registry_for_gateway = registry.clone();
        enforcer.set_accepted_connection_attributor(move |context|
            registry_for_gateway.attribute_accepted_connection(context, native::now())).unwrap();
        let (gateway, tunnel) = enforcer.start_local_proxy_listener("127.0.0.1:0", stop.clone(), now).unwrap();
        let registrations = registry.start_registration_listener(&root.join("reg.sock"), stop.clone()).unwrap();
        Self { root, storage, config, policy, helper, registry, enforcer, gateway, _upstream: upstream, stop, workers: vec![tunnel, registrations] }
    }

    fn launch(&self, target: LaunchTarget, image: &Path, args: Vec<String>) -> Owned {
        let executable = image.canonicalize().unwrap().to_string_lossy().into_owned();
        let fingerprint = sha256_file_hex(image).unwrap();
        self.registry.approve_target_executable(&executable, &fingerprint);
        self.registry.refresh_executable_verifications();
        let request = ControlledLaunchRequest {
            entry_id: DesktopManagedEntrySpec::entry_bundle_id_for(target).into(),
            target,
            target_executable: executable.clone(),
            target_fingerprint: fingerprint,
            args,
            cwd: Some(self.root.to_string_lossy().into_owned()),
            proxy_adaptation: ProxyAdaptationKind::EnvOnly,
            gateway_endpoint: self.gateway.to_string(),
            policy_version: self.policy.clone(),
            vpn_epoch: Some(claude_watch_core::vpn::VpnEpoch::new("vpn-obs-boot-1", 1)),
            launch_nonce: uuid::Uuid::new_v4().to_string(),
            executor_boot_id: BOOT.into(),
            script_entry: None, script_fingerprint: None, interpreter: None, interpreter_fingerprint: None, script_source: None,
        };
        let mut owned = Owned(Command::new(&self.helper).arg("--launch-json").arg(serde_json::to_string(&request).unwrap())
            .arg("--registration-socket").arg(self.root.join("reg.sock")).stdin(Stdio::null()).spawn().unwrap());
        let until = Instant::now() + Duration::from_secs(3);
        loop {
            self.registry.reconcile_process_trees(native::now());
            if self.registry.instances().iter().any(|i| i.pid == owned.0.id()
                && i.has_verified_main_protection(BOOT, &self.policy)) { break; }
            assert!(owned.0.try_wait().unwrap().is_none(), "owned helper exited before verification");
            assert!(Instant::now() < until, "owned helper not verified: {:?}", self.registry.instances());
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(inspect_process_identity(owned.0.id()).unwrap().executable_path, executable);
        owned
    }

    fn compile(&self, source: &str, executable: &Path) {
        let source_path = self.root.join(format!("{}.c", uuid::Uuid::new_v4()));
        fs::write(&source_path, source).unwrap();
        let output = Command::new("xcrun").args(["clang", "-O0", "-Wall", "-Werror"])
            .arg(&source_path).arg("-o").arg(executable).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    }

    fn sleeper(&self) -> PathBuf {
        let image = self.root.join("owned-sleeper");
        self.compile("#include <unistd.h>\nint main(void){for(;;)pause();}\n", &image);
        image
    }

    fn observation(&self, supervisor: &mut ChannelSupervisor, seq: u64, now: f64) {
        let mut observation = fixture::sample_vpn_observation(now, 1);
        observation.sample_seq = seq;
        observation.upstream_endpoint = Some(self.config.proxy_url.clone());
        supervisor.handle_event(SupervisionEvent::VpnObservationUpdated { observation, observed_at: now }).unwrap();
    }

    fn environment(&self, supervisor: &mut ChannelSupervisor, family: &str, ip: &str, now: f64) {
        let mut egress = fixture::controlled_egress(&self.config, now, ip, "US",
            Some(claude_watch_core::vpn::VpnEpoch::new("vpn-obs-boot-1", 1)));
        egress["family"] = json!(family);
        supervisor.handle_event(SupervisionEvent::EnvironmentUpdated {
            egress, local_guard: json!({"proxy":"ok","tun":"disabled","context_id":"ctx-vpn"}), observed_at: now,
        }).unwrap();
    }

    fn inventory(&self, supervisor: &mut ChannelSupervisor, family: &str, now: f64) {
        let tokens = self.registry.verified_family_tokens(family, now);
        supervisor.handle_event(SupervisionEvent::ProcessInventoryUpdated {
            family: family.into(), desktops: vec![], processes: tokens, observed_at: now,
        }).unwrap();
    }

    fn bind(&self, supervisor: &mut ChannelSupervisor, family: &'static str, now: f64) {
        let mut audit = fixture::fixture_audit_val(&self.storage, now, "1.1.1.1", "US");
        audit["launch_target"] = json!(if family == "claude" { "claude-cli" } else { "codex-cli" });
        audit["authorization_scope"] = json!("observation");
        let current = fixture::controlled_egress(&self.config, now, "1.1.1.1", "US",
            Some(claude_watch_core::vpn::VpnEpoch::new("vpn-obs-boot-1", 1)));
        let tokens = self.registry.verified_family_tokens(family, now);
        SessionStore::for_family(self.storage.clone(), family).begin_channel_verified(
            &ReceiptStore { storage: self.storage.clone() }, &audit, &current, &tokens, now,
        ).unwrap();
        self.inventory(supervisor, family, now);
        let state = &supervisor.snapshot(now).families[family];
        assert_eq!(state.permit_state, ChannelPermitState::Permitted, "{state:?}");
    }

    fn supervisor(&self, families: &[&'static str]) -> ChannelSupervisor {
        let mut supervisor = ChannelSupervisor::new(self.storage.clone(), Some(self.enforcer.clone()), None).unwrap();
        let now = native::now();
        fixture::seed_probe_receipts(&self.storage, now, "US");
        self.observation(&mut supervisor, 1, now);
        self.environment(&mut supervisor, "*", "1.1.1.1", now);
        for family in families { self.bind(&mut supervisor, family, now); }
        supervisor
    }
}

fn export(name: &str, value: &Value) {
    println!("{value}");
    if let Some(directory) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::write(Path::new(&directory).join(name), serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }
}

fn wait_until_exited(identity: &ProcessKernelIdentity) {
    let until = Instant::now() + Duration::from_millis(500);
    while !claude_watch_system::bound_lifetime_exited(identity) {
        assert!(Instant::now() < until, "signal must really end the owned fixture");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn v1_worker_delivery_preserves_partial_result_in_both_policy_orders() {
    let mut cases = Vec::new();
    for policy_first in [true, false] {
        let mut fixture = Fixture::start();
        let image = fixture.sleeper();
        let a = fixture.launch(LaunchTarget::ClaudeCli, &image, vec![]);
        let b = fixture.launch(LaunchTarget::ClaudeCli, &image, vec![]);
        let other = fixture.launch(LaunchTarget::CodexCli, &image, vec![]);
        let ordinary = Owned(Command::new(&image).spawn().unwrap());
        let mut identities = [inspect_process_identity(a.0.id()).unwrap(), inspect_process_identity(b.0.id()).unwrap()];
        identities.sort_by_key(|p| p.pid);
        let [first, second] = identities;
        let other_identity = inspect_process_identity(other.0.id()).unwrap();
        let ordinary_identity = inspect_process_identity(ordinary.0.id()).unwrap();
        let mut supervisor = fixture.supervisor(&["claude", "openai"]);
        let before = supervisor.snapshot(native::now());
        let (events, receipts) = mpsc::channel();
        let (entered, waiting) = mpsc::sync_channel(1);
        let (resume, barrier) = mpsc::sync_channel(1);
        let barrier = Mutex::new(barrier);
        let (dispatcher, worker) = ProcessDispositionDispatcher::start_with(
            fixture.storage.clone(), fixture.stop.clone(), events, move |storage, job, stop| {
                execute_batch(storage, job, stop, |index| {
                    if index == 1 {
                        entered.send(Instant::now()).unwrap();
                        barrier.lock().unwrap().recv_timeout(Duration::from_millis(1500)).unwrap();
                    }
                }, |token, actual, now| job.registry.current_disposition_member(&job.intent, token, actual, now),
                claude_watch_system::bound_lifetime_exited)
            },
        ).unwrap();
        fixture.workers.push(worker);
        supervisor.install_process_disposition_dispatcher(dispatcher);
        supervisor.set_process_disposition_registry(fixture.registry.clone());
        supervisor.drain_emitted_events();
        fixture.environment(&mut supervisor, "claude", "9.9.9.9", native::now());
        let requested = supervisor.snapshot(native::now());
        assert_eq!(requested.families["claude"].process_execution_state.as_deref(), Some("executing"), "{:?}", requested.families["claude"]);
        let waiting_since = waiting.recv_timeout(Duration::from_secs(2)).expect("actual worker after signal #1");
        wait_until_exited(&first);
        assert_eq!(inspect_process_identity(second.pid), Some(second.clone()));
        assert!(receipts.try_recv().is_err(), "worker is paused before target 2");

        // Advance an actual OpenAI inventory event and apply a fresh same-epoch
        // lease before the original force batch can finish.
        let renewal_start = Instant::now();
        fixture.inventory(&mut supervisor, "openai", native::now());
        fixture.observation(&mut supervisor, 2, native::now());
        let renewed = supervisor.snapshot(native::now());
        let renewal_finished = Instant::now();
        assert!(receipts.try_recv().is_err());
        let old = &before.families["openai"];
        let new = &renewed.families["openai"];
        assert_eq!(new.permit_state, ChannelPermitState::Permitted);
        assert_eq!(new.policy_sync_state, claude_watch_core::channel::PolicySyncState::Applied);
        assert_eq!(old.session_id, new.session_id);
        assert!(new.command_seq > old.command_seq && new.valid_until.unwrap() > old.valid_until.unwrap());
        let disk = fixture.storage.read_json(&fixture.storage.paths.watch().join("state/channel-supervision.json"), Value::Null).unwrap();
        assert_eq!(disk["enforcement_receipts"]["openai"]["command_seq"], new.command_seq);
        assert!(supervisor.drain_emitted_events().iter().any(|e| e.family_state.family == "openai" && e.family_state.command_seq == new.command_seq));

        let mut warn = fixture.config.clone();
        warn.policy_actions.insert("claude_close_ip".into(), "warn".into());
        let warn = (ConfigStore { storage: fixture.storage.clone() }).save(warn.value().unwrap()).unwrap();
        let policy_update = |supervisor: &mut ChannelSupervisor| {
            supervisor.handle_event(SupervisionEvent::PolicyUpdated { config: warn.clone(), observed_at: native::now() }).unwrap();
        };
        if policy_first { policy_update(&mut supervisor); }
        let paused_before_resume = waiting_since.elapsed();
        resume.send(()).unwrap();
        let event = receipts.recv_timeout(Duration::from_secs(3)).unwrap();
        let SupervisionEvent::ProcessReceiptArrived { receipt, received_at } = &event else { panic!("{event:?}"); };
        assert_eq!(receipt.process_execution_state, "partially_terminated", "{receipt:?}");
        assert_eq!(receipt.target_results[0].pid, first.pid);
        assert!(receipt.target_results[0].terminated && receipt.target_results[0].signal_sent_at.is_some());
        assert_eq!(receipt.target_results[1].pid, second.pid);
        assert_eq!(receipt.target_results[1].process_state, "cancelled");
        assert!(receipt.target_results[1].signal_sent_at.is_none());

        let mut forged = receipt.clone();
        forged.authority.as_mut().unwrap().command_seq += 1;
        supervisor.ingest_process_receipt(forged, *received_at).unwrap();
        assert!(supervisor.snapshot(native::now()).families["claude"].previous_process_disposition_receipts.is_empty());
        let policy_before_receipt = supervisor.authoritative_state_for_family("claude").unwrap();
        let observed = supervisor.handle_event(event.clone()).unwrap();
        assert_eq!(supervisor.authoritative_state_for_family("claude").unwrap(), policy_before_receipt);
        if !policy_first {
            assert_eq!(observed.families["claude"].process_disposition_receipt.as_ref(), Some(receipt));
            policy_update(&mut supervisor);
        }
        let snapshot = supervisor.snapshot(native::now());
        let final_state = &snapshot.families["claude"];
        assert_eq!(final_state.permit_state, ChannelPermitState::Revoked);
        assert!(final_state.process_disposition_action.is_none() && final_state.process_disposition_receipt.is_none());
        assert_eq!(final_state.previous_process_disposition_receipts.as_slice(), std::slice::from_ref(receipt));
        let history = supervisor.drain_emitted_events();
        assert!(history.iter().any(|e| e.family_state.previous_process_disposition_receipts.as_slice() == std::slice::from_ref(receipt)));
        supervisor.handle_event(event.clone()).unwrap();
        assert!(supervisor.drain_emitted_events().is_empty(), "replay must not publish a second result");
        assert_eq!(inspect_process_identity(second.pid), Some(second.clone()));
        assert_eq!(inspect_process_identity(other_identity.pid), Some(other_identity));
        assert_eq!(inspect_process_identity(ordinary_identity.pid), Some(ordinary_identity));
        cases.push(json!({
            "policy_first":policy_first, "snapshot":snapshot, "events":history, "now":native::now(),
            "first":first.pid,"second":second.pid,"worker_blocked_before_second_ms":paused_before_resume.as_secs_f64()*1000.0,
            "renewal_ms":(renewal_finished - renewal_start).as_secs_f64()*1000.0,
            "openai_old_until":old.valid_until,"openai_new_until":new.valid_until,
            "openai_old_seq":old.command_seq,"openai_new_seq":new.command_seq,
        }));
    }
    export("process-disposition-delivery.json", &json!(cases));
}

#[test]
fn v1_worker_deadline_retains_unconfirmed_exit_when_observation_is_withheld() {
    let mut fixture = Fixture::start();
    let image = fixture.sleeper();
    let child = fixture.launch(LaunchTarget::ClaudeCli, &image, vec![]);
    let actual = inspect_process_identity(child.0.id()).unwrap();
    let mut supervisor = fixture.supervisor(&["claude"]);
    let (events, receipts) = mpsc::channel();
    let (dispatcher, worker) = ProcessDispositionDispatcher::start_with(
        fixture.storage.clone(), fixture.stop.clone(), events, |storage, job, stop| {
            // Model a missing exit observation with a real signal and the real
            // wait limit. No unkillable process or fabricated kernel exit.
            execute_batch(storage, job, stop, |_| {},
                |token, actual, now| job.registry.current_disposition_member(&job.intent, token, actual, now),
                |_| false)
        },
    ).unwrap();
    fixture.workers.push(worker);
    supervisor.install_process_disposition_dispatcher(dispatcher);
    supervisor.set_process_disposition_registry(fixture.registry.clone());
    let started = Instant::now();
    fixture.environment(&mut supervisor, "claude", "9.9.9.9", native::now());
    let requested = supervisor.snapshot(native::now());
    assert_eq!(requested.families["claude"].process_execution_state.as_deref(), Some("executing"), "{:?}", requested.families["claude"]);
    let event = receipts.recv_timeout(Duration::from_secs(4)).unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed >= WAIT_FOR_EXIT && elapsed < Duration::from_secs(4), "{elapsed:?}");
    let snapshot = supervisor.handle_event(event).unwrap();
    let state = &snapshot.families["claude"];
    let receipt = state.process_disposition_receipt.as_ref().unwrap();
    assert_eq!(receipt.process_execution_state, "unknown");
    assert_eq!(receipt.target_results[0].process_state, "exit_unconfirmed");
    assert!(!receipt.target_results[0].terminated && receipt.target_results[0].signal_sent_at.is_some());
    wait_until_exited(&actual);
    export("process-disposition-deadline.json", &json!({"snapshot":snapshot,"elapsed_ms":elapsed.as_secs_f64()*1000.0}));
}
