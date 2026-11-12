//! Production receiver/registry with a private loopback gateway and owned targets.
#[path = "../../../watch-runtime/tests/support/hardened_helper.rs"]
mod hardened_helper;

use super::{
    assemble_production_channel_stack, default_registration_socket_path, native,
    GuardObservation, ProductionChannelStack, SupervisionEvent,
};
use claude_watch_core::{
    channel::{ChannelEnforcementState, ChannelPermitState, CLOCK_ROLLBACK_TOLERANCE_SECONDS},
    config::Config,
    controlled_launch::{ControlledLaunchRequest, ProxyAdaptationKind},
    processes::LaunchTarget,
};
use claude_watch_runtime::{
    channel_enforcer::ChannelEnforcer,
    config_store::ConfigStore,
    managed_entry::DesktopManagedEntrySpec,
    storage::{Paths, StateStore},
};
use claude_watch_system::{inspect_process_identity, sha256_file_hex};
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[allow(dead_code)]
#[path = "../../../watch-runtime/tests/support/managed_cli_supervisor.rs"]
mod fixture;

struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Stack(Option<ProductionChannelStack>);
impl Drop for Stack {
    fn drop(&mut self) {
        if let Some(stack) = self.0.take() {
            stack.shutdown();
        }
    }
}

struct Unmanaged(Child);
impl Drop for Unmanaged {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}

struct EchoServer {
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    eof: mpsc::Receiver<usize>,
}
impl EchoServer {
    fn start(listener: TcpListener) -> Self {
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let (eof_tx, eof) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut peers = Vec::new();
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let index = peers.len();
                        let eof_tx = eof_tx.clone();
                        peers.push(thread::spawn(move || {
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_secs(4)))
                                .unwrap();
                            let mut bytes = [0; 64];
                            loop {
                                match stream.read(&mut bytes) {
                                    Ok(0) => {
                                        let _ = eof_tx.send(index);
                                        break;
                                    }
                                    Ok(n) if stream.write_all(&bytes[..n]).is_ok() => {}
                                    _ => break,
                                }
                            }
                        }));
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("private upstream accept: {e}"),
                }
            }
            for peer in peers {
                peer.join().unwrap();
            }
        });
        Self {
            stop,
            worker: Some(worker),
            eof,
        }
    }
}
impl Drop for EchoServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.worker.take().unwrap().join();
    }
}

struct Target {
    child: Child,
    stdout: mpsc::Receiver<String>,
    stdout_worker: Option<thread::JoinHandle<()>>,
}
impl Target {
    fn start(
        stack: &ProductionChannelStack,
        helper: &Path,
        image: &Path,
        target: LaunchTarget,
        upstream_port: u16,
        epoch: claude_watch_core::vpn::VpnEpoch,
    ) -> Self {
        let store = &stack.supervisor.storage;
        let gateway_port = stack.enforcer.local_proxy_port().unwrap();
        let policy = stack.supervisor.saved_policy_version().clone();
        let boot = stack.enforcer.boot_id().unwrap();
        let request = ControlledLaunchRequest {
            entry_id: DesktopManagedEntrySpec::entry_bundle_id_for(target).into(),
            target,
            target_executable: image.to_str().unwrap().into(),
            target_fingerprint: sha256_file_hex(image).unwrap(),
            args: vec![gateway_port.to_string(), upstream_port.to_string()],
            cwd: Some(store.paths.home.to_str().unwrap().into()),
            proxy_adaptation: ProxyAdaptationKind::EnvOnly,
            gateway_endpoint: format!("127.0.0.1:{gateway_port}"),
            policy_version: policy.clone(),
            vpn_epoch: Some(epoch),
            launch_nonce: uuid::Uuid::new_v4().to_string(),
            executor_boot_id: boot.clone(),
            script_entry: None,
            script_fingerprint: None,
            interpreter: None,
            interpreter_fingerprint: None,
            script_source: None,
        };
        let mut child = Command::new(helper)
            .env_clear()
            .arg("--launch-json")
            .arg(serde_json::to_string(&request).unwrap())
            .arg("--registration-socket")
            .arg(default_registration_socket_path(&store.paths.watch()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, stdout) = mpsc::channel();
        let stdout_worker = thread::spawn(move || {
            for line in BufReader::new(out)
                .lines()
                .map_while(std::result::Result::ok)
            {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let result = Self { child, stdout, stdout_worker: Some(stdout_worker) };
        assert_eq!(result.line(), format!("READY {} A", result.child.id()));
        let registry = stack.sandbox_registry.as_ref().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            registry.reconcile_process_trees(native::now());
            if registry.instances().iter().any(|i| {
                i.pid == result.child.id() && i.has_verified_main_protection(&boot, &policy)
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "registered fixture did not acquire kernel identity"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            inspect_process_identity(result.child.id())
                .unwrap()
                .executable_path,
            image.to_str().unwrap()
        );
        result
    }
    fn line(&self) -> String {
        self.stdout
            .recv_timeout(Duration::from_secs(4))
            .expect("owned target response")
    }
    fn command(&mut self, input: &str, expected: &str) {
        writeln!(self.child.stdin.as_mut().unwrap(), "{input}").unwrap();
        let output = self.line();
        println!("owned target {}: {input} -> {output}", self.child.id());
        assert_eq!(output, expected);
    }
    fn ping(&mut self, sequence: u64) {
        self.command(
            &format!("PING {sequence}"),
            &format!("PONG {} {sequence}", self.child.id()),
        );
    }
    fn finish(mut self) {
        writeln!(self.child.stdin.as_mut().unwrap(), "QUIT").unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "owned fixture must exit normally: {status}");
                break;
            }
            assert!(Instant::now() < deadline, "owned fixture did not exit");
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(worker) = self.stdout_worker.take() { let _ = worker.join(); }
    }
}

fn sample(stack: &mut ProductionChannelStack, cfg: &Config, sequence: &mut u64) {
    *sequence += 1;
    let now = native::now();
    let mut observation = fixture::sample_vpn_observation(now, 1);
    observation.sample_seq = *sequence;
    observation.upstream_endpoint = Some(cfg.proxy_url.clone());
    let egress =
        fixture::controlled_egress(cfg, now, "1.1.1.1", "US", Some(observation.epoch.clone()));
    stack
        .supervisor
        .handle_event(SupervisionEvent::VpnObservationUpdated {
            observation,
            observed_at: now,
        })
        .unwrap();
    stack
        .supervisor
        .handle_event(SupervisionEvent::EnvironmentUpdated {
            egress,
            local_guard: json!({"proxy":"ok","tun":"disabled","context_id":"ctx-vpn"}),
            observed_at: native::now(),
        })
        .unwrap();
}

fn ordinary_round_trip(ordinary: &mut TcpStream) {
    ordinary.write_all(b"ordinary").unwrap();
    let mut reply = [0; 8];
    ordinary.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"ordinary");
    println!("ordinary existing direct socket: echo OK");
}

#[test]
fn queued_inventory_failure_keeps_other_family_and_ordinary_connections() {
    use claude_watch_system::network_events::{NetworkEventKind, NetworkEventWatcher};
    let root = Root(PathBuf::from("/private/tmp").join(format!(
        "cw-rdy-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    )));
    let home = root.0.join("h");
    let bin = home.join(".local/bin");
    let claude_path = home.join(".local/share/claude/versions/owned");
    let codex_path = home.join("owned-codex");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(claude_path.parent().unwrap()).unwrap();
    fs::write(root.0.join("owned-fixture"), b"test-only").unwrap();
    let store = StateStore::new(Paths::new(&home).unwrap());
    let runtime = store.paths.watch().join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let helper = runtime.join("watch-sandbox-launcher");
    hardened_helper::copy_signed(&repo.join("target/debug/watch-sandbox-launcher"), &helper);
    fs::write(runtime.join("components.json"), hardened_helper::components(&helper).to_string()).unwrap();
    let out = Command::new("xcrun")
        .args(["clang", "-O0", "-Wall", "-Werror"])
        .arg(repo.join("crates/watch-runtime/tests/support/controlled_cli_fixture.c"))
        .arg("-o")
        .arg(&claude_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "compile owned fixture: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::copy(&claude_path, &codex_path).unwrap();
    symlink(&claude_path, bin.join("claude")).unwrap();
    symlink(&codex_path, bin.join("codex")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = listener.local_addr().unwrap();
    let server = EchoServer::start(listener);
    let mut cfg = fixture::config(&store, &upstream.to_string());
    for action in cfg.policy_actions.values_mut() {
        *action = "close".into();
    }
    let cfg = (ConfigStore {
        storage: store.clone(),
    })
    .save(cfg.value().unwrap())
    .unwrap();
    let audit_store = store.clone();
    let audit_cfg = cfg.clone();
    let audit_calls = Arc::new(AtomicUsize::new(0));
    let calls = audit_calls.clone();
    let hold_first_claude = AtomicBool::new(true);
    let audit_child_file = root.0.join("owned-audit-child.pid");
    let worker_child_file = audit_child_file.clone();
    let (audit_started_tx, audit_started_rx) = mpsc::channel();
    let (audit_cancelled_tx, audit_cancelled_rx) = mpsc::channel();
    let channel_started = Instant::now();
    let mut owned = Stack(Some(
        assemble_production_channel_stack(
            store.clone(),
            Arc::new(AtomicBool::new(false)),
            false,
            move |req| {
                calls.fetch_add(1, Ordering::SeqCst);
                if req.family == "claude" && hold_first_claude.swap(false, Ordering::AcqRel) {
                    let cancel = req.cancellation.clone().expect("production scheduler supplies cancellation");
                    audit_started_tx.send(cancel.clone()).unwrap();
                    let result = claude_watch_runtime::audit_process::run_json(
                        Command::new("/bin/sh").args(["-c", "printf '%s' \"$$\" > \"$1\"; exec /bin/sleep 30", "--"])
                            .arg(&worker_child_file), &json!({}),
                        Instant::now() + Duration::from_secs(10), &cancel);
                    let code = result.as_ref().err().map(|e| e.code.clone());
                    let _ = audit_cancelled_tx.send(code);
                    return result.map(|value| (value, Value::Null, native::now()));
                }
                let now = native::now();
                let mut audit = fixture::fixture_audit_val(&audit_store, now, "1.1.1.1", "US");
                audit["launch_target"] = json!(req.target);
                audit["authorization_scope"] = json!("observation");
                let mut egress = fixture::controlled_egress(
                    &audit_cfg,
                    now,
                    "1.1.1.1",
                    "US",
                    req.vpn_epoch.clone(),
                );
                egress["family"] = json!(req.family);
                Ok((audit, egress, now))
            },
        )
        .unwrap(),
    ));
    let stack = owned.0.as_mut().unwrap();
    // Observe the actual periodic worker's wall samples without substituting
    // a timestamp or driving an extra check from the fixture.
    let (watchdog_tx, watchdog_rx) = mpsc::channel();
    stack.enforcer.set_clock(move || {
        let now = native::now();
        if thread::current().name() == Some("channel-lease-watchdog") {
            let _ = watchdog_tx.send(now);
        }
        now
    }).unwrap();
    stack.start_private_loopback_backend().unwrap();
    let registry = stack.sandbox_registry.as_ref().unwrap().clone();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !registry.is_target_approved(claude_path.to_str().unwrap())
        || !registry.is_target_approved(codex_path.to_str().unwrap())
        || registry.executable_verification_counts().1 < 2
    {
        assert!(
            Instant::now() < deadline,
            "production target refresh did not approve both owned CLIs"
        );
        thread::sleep(Duration::from_millis(10));
    }
    // The fixture supplies a real ordinary lifetime as observed desktop input.
    // The production adapter, registry, Supervisor and worker decide whether it
    // is protected and whether an audit may be dispatched.
    let ordinary_target = Unmanaged(Command::new("/bin/sleep").arg("60").spawn().unwrap());
    let ordinary_identity = inspect_process_identity(ordinary_target.0.id()).unwrap();
    let ordinary_token = claude_watch_core::channel::BoundProcessToken::with_system_identity(
        ordinary_identity.pid, ordinary_identity.uid, ordinary_identity.start_seconds,
        ordinary_identity.start_microseconds, claude_watch_core::processes::ProcessRole::DesktopMain)
        .with_audit_token(ordinary_identity.audit_token);
    let ordinary_desktop = (claude_watch_core::session::Desktop { pid:ordinary_identity.pid,
        start_seconds:ordinary_identity.start_seconds, start_microseconds:ordinary_identity.start_microseconds },
        true, "owned-unmanaged-observation".into());
    fixture::seed_probe_receipts(&store, native::now(), "US");
    let mut vpn_sequence = 0;
    for _ in 0..3 {
        sample(stack, &cfg, &mut vpn_sequence);
        stack.step_with_observations(vec![GuardObservation::Inventory {
            family:"claude".into(), desktops:vec![ordinary_desktop.clone()],
            processes:vec![ordinary_token.clone()], observed_at:native::now(),
        }], native::now()).unwrap();
        let snapshot = stack.supervisor.snapshot(native::now());
        let family = &snapshot.families["claude"];
        assert!(family.active_members.is_empty() && family.active_member_pids.is_empty());
        assert!(family.unmanaged_member_pids.contains(&ordinary_identity.pid));
        assert!(family.coverage_scope.unprotected_pids.contains(&ordinary_identity.pid));
        assert_eq!(family.permit_state, ChannelPermitState::PendingVerification);
        assert_eq!(family.reason_code, "unmanaged_existing_processes");
        assert_eq!(family.display_label_zh, "未受保护");
        assert_ne!(family.display_state, claude_watch_core::channel::ChannelMonitorDisplayState::Blocked);
    }
    thread::sleep(Duration::from_millis(75));
    assert_eq!(audit_calls.load(Ordering::SeqCst), 0, "unmanaged observations must never dispatch a full audit");
    assert!(registry.instances().is_empty());
    let epoch = fixture::sample_vpn_observation(native::now(), 1).epoch;
    let mut claude = Target::start(
        stack,
        &helper,
        &claude_path,
        LaunchTarget::ClaudeCli,
        upstream.port(),
        epoch.clone(),
    );
    let mut codex = Target::start(
        stack,
        &helper,
        &codex_path,
        LaunchTarget::CodexCli,
        upstream.port(),
        epoch,
    );
    fixture::seed_probe_receipts(&store, native::now(), "US");
    sample(stack, &cfg, &mut vpn_sequence);
    for (family, pid) in [("claude", claude.child.id()), ("openai", codex.child.id())] {
        let now = native::now();
        let tokens = registry.verified_family_tokens(family, now);
        assert!(
            tokens.iter().any(|token| token.pid == pid),
            "{family}: {tokens:?}"
        );
        // Establish the precondition without queueing either inventory update;
        // the delayed event under test is the Claude-only failure below.
        let mut observed = tokens;
        let desktops = if family == "claude" { observed.push(ordinary_token.clone()); vec![ordinary_desktop.clone()] } else { vec![] };
        stack.apply_guard_observation(GuardObservation::Inventory {
            family:family.into(), desktops, processes:observed, observed_at:now,
        }, native::now()).unwrap();
    }
    let cancellation = audit_started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let audit_child_pid: u32 = loop {
        if let Some(pid) = fs::read_to_string(&audit_child_file).ok().and_then(|raw| raw.parse().ok()) {
            if inspect_process_identity(pid).is_some() { break pid; }
        }
        assert!(Instant::now() < deadline, "in-flight audit child did not start");
        thread::sleep(Duration::from_millis(5));
    };
    // A later timestamp for the identical managed set must keep this audit.
    stack.apply_guard_observation(GuardObservation::Inventory {
        family:"claude".into(), desktops:vec![ordinary_desktop.clone()],
        processes:vec![ordinary_token.clone()], observed_at:native::now(),
    }, native::now()).unwrap();
    assert!(!cancellation.load(Ordering::Acquire));
    assert!(inspect_process_identity(audit_child_pid).is_some());
    let removed_pid = claude.child.id();
    claude.finish();
    registry.reconcile_process_trees(native::now());
    let cancellation_started = Instant::now();
    stack.apply_guard_observation(GuardObservation::Inventory {
        family:"claude".into(), desktops:vec![ordinary_desktop.clone()],
        processes:vec![ordinary_token.clone()], observed_at:native::now(),
    }, native::now()).unwrap();
    assert!(cancellation.load(Ordering::Acquire));
    assert_eq!(audit_cancelled_rx.recv_timeout(Duration::from_secs(2)).unwrap().as_deref(), Some("audit_cancelled"));
    assert!(!claude_watch_system::list_user_pids(claude_watch_system::effective_uid()).contains(&audit_child_pid),
        "removed target's real audit child must be waited for, not left alive or as a zombie");
    let removed_audit_cancel_seconds = cancellation_started.elapsed().as_secs_f64();
    assert_eq!(stack.supervisor.snapshot(native::now()).families["claude"].permit_state, ChannelPermitState::PendingVerification);
    claude = Target::start(stack, &helper, &claude_path, LaunchTarget::ClaudeCli, upstream.port(),
        fixture::sample_vpn_observation(native::now(), 1).epoch);
    let now = native::now();
    stack.apply_guard_observation(GuardObservation::Inventory {
        family:"claude".into(), desktops:vec![ordinary_desktop.clone()],
        processes:vec![ordinary_token.clone()], observed_at:now,
    }, now).unwrap();
    let initial_identity = inspect_process_identity(claude.child.id()).unwrap();
    assert_ne!(claude.child.id(), removed_pid);
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        stack.drain_background_events().unwrap();
        let snapshot = stack.supervisor.snapshot(native::now());
        if ["claude", "openai"]
            .iter()
            .all(|f| snapshot.families[*f].permit_state == ChannelPermitState::Permitted)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fixture adoption did not become ready: {}",
            json!(snapshot)
        );
        thread::sleep(Duration::from_millis(10));
    }
    let channel_ready_seconds = channel_started.elapsed().as_secs_f64();
    assert!(audit_calls.load(Ordering::SeqCst) >= 3, "new real members require fresh production audits");
    let ready = stack.supervisor.snapshot(native::now());
    assert!(ready.families["claude"].active_members.iter().any(|p| p.pid == claude.child.id()));
    assert!(ready.families["claude"].unmanaged_member_pids.contains(&ordinary_identity.pid));
    let helper_cdhash = hardened_helper::cdhash(&helper);
    let instances = registry.instances().into_iter().filter(|instance|
        instance.has_verified_main_protection(&stack.enforcer.boot_id().unwrap(), stack.supervisor.saved_policy_version()))
        .collect::<Vec<_>>();
    assert_eq!(instances.len(), 2);
    assert!(instances.iter().all(|instance| instance.sandbox_evidence.as_ref()
        .is_some_and(|e| e.helper_cdhash == helper_cdhash && e.verified_helper_origin)));
    println!("both protected instances use the private hardened ad-hoc helper's verified live CDHash");
    claude.command("DIRECT", "DIRECT_DENIED");
    codex.command("DIRECT", "DIRECT_DENIED");
    claude.command("OPEN", "OPENED");
    codex.command("OPEN", "OPENED");
    let mut ordinary = TcpStream::connect(upstream).unwrap();
    ordinary
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    ordinary_round_trip(&mut ordinary);
    stack.drain_background_events().unwrap();

    let revocation_started = Instant::now();
    let queued_at = native::now();
    stack
        .event_tx
        .send(SupervisionEvent::ProcessInventoryUnavailable {
            family: "claude".into(),
            observed_at: queued_at,
        })
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let watchdog_at = loop {
        let tick = watchdog_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("the automatic watchdog must advance beyond the queued event");
        if tick - queued_at > CLOCK_ROLLBACK_TOLERANCE_SECONDS {
            break tick;
        }
    };
    assert!(!stack.lease_watchdog.is_finished());
    let before_claude = stack
        .enforcer
        .receipt_for("claude", watchdog_at)
        .unwrap()
        .unwrap();
    let before_openai = stack
        .enforcer
        .receipt_for("openai", watchdog_at)
        .unwrap()
        .unwrap();
    for receipt in [&before_claude, &before_openai] {
        assert_eq!(
            receipt.enforcement_state,
            ChannelEnforcementState::Forwarding
        );
        assert_eq!(receipt.active_flows_count, 1);
    }
    stack.drain_background_events().unwrap();
    let after = native::now();
    let after_openai = stack
        .enforcer
        .receipt_for("openai", after)
        .unwrap()
        .unwrap();
    let after_claude = stack
        .enforcer
        .receipt_for("claude", after)
        .unwrap()
        .unwrap();
    let state = store
        .read_json(
            &store.paths.watch().join("state/channel-supervision.json"),
            Value::Null,
        )
        .unwrap();
    let evidence = json!({
        "queued_at": queued_at, "watchdog_at": watchdog_at, "automatic_watchdog": true,
        "before": {"claude":before_claude, "openai":before_openai},
        "after": {"claude":after_claude, "openai":after_openai},
        "authoritative_permits": state["authoritative_permits"],
    });
    println!("queue clock evidence: {evidence}");
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::write(
            Path::new(&dir).join("queued-family-clock.json"),
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();
    }
    assert_eq!(
        after_openai.enforcement_state,
        ChannelEnforcementState::Forwarding
    );
    assert_eq!(after_openai.permit_state, ChannelPermitState::Permitted);
    assert_eq!(after_openai.command_seq, before_openai.command_seq);
    assert_eq!(after_openai.active_flows_count, 1);
    assert_eq!(
        state["authoritative_permits"]["claude"]["reason_code"],
        "channel_inventory_incomplete"
    );
    assert!(
        state["authoritative_permits"]["claude"]["issued_at"]
            .as_f64()
            .unwrap()
            >= watchdog_at
    );

    claude.command("EOF", "EOF 1");
    assert_eq!(
        server.eof.recv_timeout(Duration::from_secs(3)).unwrap(),
        0,
        "Claude upstream must also see EOF"
    );
    let revocation_eof_seconds = revocation_started.elapsed().as_secs_f64();
    // The process still passes identity attribution (403 would indicate
    // attribution failure); the channel gate explicitly denies its request.
    claude.command("RECONNECT 502", "DENIED");
    let denied = stack
        .enforcer
        .receipt_for("claude", native::now())
        .unwrap()
        .unwrap();
    assert_eq!(denied.blocked_new_connections, after_claude.blocked_new_connections + 1);
    assert!(denied.active_flows_closed && denied.new_connections_blocked);
    codex.command("USE", "STILL_OPEN");
    ordinary_round_trip(&mut ordinary);
    let notification_name = format!("io.local.claudewatch.test.lifecycle.{}", uuid::Uuid::new_v4());
    let mut notifications = NetworkEventWatcher::new(&[&notification_name]);
    let preserved_since = Instant::now();
    let mut notification_max_seconds = 0.0f64;
    for seq in 2..=6 {
        thread::sleep(Duration::from_secs(1));
        let posted = Instant::now();
        for _ in 0..64 { claude_watch_system::post_darwin_notification(&notification_name).unwrap(); }
        assert!(notifications.wait(Duration::from_secs(1)).contains(
            &NetworkEventKind::DarwinNotification(notification_name.clone())));
        notification_max_seconds = notification_max_seconds.max(posted.elapsed().as_secs_f64());
        sample(stack, &cfg, &mut vpn_sequence);
        stack.drain_background_events().unwrap();
        claude.ping(seq);
        codex.command("USE", "STILL_OPEN");
        ordinary_round_trip(&mut ordinary);
    }
    assert!(preserved_since.elapsed() >= Duration::from_secs(5));
    let notification_duration_seconds = preserved_since.elapsed().as_secs_f64();
    assert_eq!(
        inspect_process_identity(claude.child.id()),
        Some(initial_identity)
    );
    assert_eq!(
        stack
            .enforcer
            .receipt_for("claude", native::now())
            .unwrap()
            .unwrap()
            .enforcement_state,
        ChannelEnforcementState::Blocked
    );
    assert_eq!(
        stack
            .enforcer
            .receipt_for("openai", native::now())
            .unwrap()
            .unwrap()
            .enforcement_state,
        ChannelEnforcementState::Forwarding
    );
    assert!(
        server.eof.try_recv().is_err(),
        "neither OpenAI nor the ordinary upstream was closed"
    );
    let trace = fs::read_to_string(store.paths.base().join("diagnostic-events.jsonl")).unwrap();
    assert!(!trace.contains("clock_rollback_detected"));

    // A real wake signal must still revoke the healthy family's open flow.
    stack
        .event_tx
        .send(SupervisionEvent::LeaseExpired {
            observed_at: native::now(),
            woke_from_sleep: true,
        })
        .unwrap();
    stack.drain_background_events().unwrap();
    codex.command("EOF", "EOF 1");
    assert_eq!(server.eof.recv_timeout(Duration::from_secs(3)).unwrap(), 1);
    let wake = stack
        .enforcer
        .receipt_for("openai", native::now())
        .unwrap()
        .unwrap();
    println!("wake receipt: {}", json!(wake));
    assert_eq!(wake.enforcement_state, ChannelEnforcementState::Blocked);
    assert_eq!(
        wake.error_code.as_deref(),
        Some("sleep_wake_reverify_required")
    );
    codex.ping(7);
    ordinary_round_trip(&mut ordinary);

    // Supply new observations to the same receiver. Only the production audit
    // worker and recovery transaction may reopen these revoked generations.
    let recovery_started = Instant::now();
    sample(stack, &cfg, &mut vpn_sequence);
    fixture::seed_probe_receipts(&store, native::now(), "US");
    for family in ["claude", "openai"] {
        let now = native::now();
        stack.event_tx.send(SupervisionEvent::ProcessInventoryUpdated {
            family: family.into(), desktops: vec![],
            processes: registry.verified_family_tokens(family, now), observed_at: now,
        }).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        stack.drain_background_events().unwrap();
        let snapshot = stack.supervisor.snapshot(native::now());
        if ["claude", "openai"].iter().all(|family|
            snapshot.families[*family].permit_state == ChannelPermitState::Permitted) { break; }
        assert!(Instant::now() < deadline, "production recovery did not finish: {}", json!(snapshot));
        thread::sleep(Duration::from_millis(10));
    }
    claude.command("OPEN", "OPENED");
    codex.command("OPEN", "OPENED");
    let recovery_seconds = recovery_started.elapsed().as_secs_f64();
    for family in ["claude", "openai"] {
        let receipt = stack.enforcer.receipt_for(family, native::now()).unwrap().unwrap();
        assert_eq!(receipt.enforcement_state, ChannelEnforcementState::Forwarding);
        assert_eq!(receipt.active_flows_count, 1);
    }
    let stopped_enforcer = stack.enforcer.clone();
    let stopped_gateway = stopped_enforcer.local_listener_addr().unwrap().unwrap().parse().unwrap();
    let shutdown_started = Instant::now();
    owned.0.take().unwrap().shutdown();
    let shutdown_seconds = shutdown_started.elapsed().as_secs_f64();
    assert!(shutdown_seconds < 5.0, "production stack did not stop within the existing 5-second fixture budget");
    claude.command("EOF", "EOF 1");
    codex.command("EOF", "EOF 1");
    let mut closed = vec![server.eof.recv_timeout(Duration::from_secs(3)).unwrap(),
        server.eof.recv_timeout(Duration::from_secs(3)).unwrap()];
    closed.sort_unstable();
    assert_eq!(closed, [3, 4]);
    let stopped_receipts = loop {
        let receipts = ["claude", "openai"].map(|family|
            stopped_enforcer.receipt_for(family, native::now()).unwrap().unwrap());
        if receipts.iter().all(|receipt| receipt.active_flows_count == 0 && receipt.active_flows_closed) {
            break receipts;
        }
        assert!(shutdown_started.elapsed() < Duration::from_secs(5),
            "shutdown must confirm the real relay holders have exited: {}", json!(receipts));
        thread::sleep(Duration::from_millis(5));
    };
    // Blocked describes a live executor enforcing a revoked permit. Once the
    // listener is stopped, the same receipt must explicitly withdraw readiness
    // instead of advertising ongoing protection. Closed flows remain required.
    for receipt in &stopped_receipts {
        assert_eq!(receipt.permit_state, ChannelPermitState::Revoked);
        assert_eq!(receipt.enforcement_state, ChannelEnforcementState::Failed);
        assert_eq!(receipt.error_code.as_deref(), Some("gateway_listener_stopped"));
        assert!(!receipt.interception_active && !receipt.local_proxy_ready && !receipt.sandbox_ready);
        assert!(!receipt.new_connections_blocked && !receipt.direct_fallback_blocked);
    }
    let stopped_dial = TcpStream::connect_timeout(&stopped_gateway, Duration::from_millis(250));
    assert_eq!(stopped_dial.unwrap_err().kind(), io::ErrorKind::ConnectionRefused,
        "the private gateway listener must actually be closed after shutdown");
    let shutdown_eof_seconds = shutdown_started.elapsed().as_secs_f64();
    assert!(shutdown_eof_seconds < 5.0, "real EOF and closed receipts must meet the same stop budget");
    ordinary_round_trip(&mut ordinary);
    let owned_target_pids = [claude.child.id(), codex.child.id()];
    claude.finish();
    codex.finish();
    let remaining_user_pids = claude_watch_system::list_user_pids(claude_watch_system::effective_uid());
    assert!(!owned_target_pids.iter().any(|pid| remaining_user_pids.contains(pid)),
        "waited fixture targets must leave neither a live process nor a zombie");
    let lifecycle = json!({"clock":"monotonic", "channel_ready_seconds":channel_ready_seconds,
        "queued_revocation_to_both_eof_seconds":revocation_eof_seconds,
        "recovery_to_real_forwarding_seconds":recovery_seconds, "stack_shutdown_seconds":shutdown_seconds,
        "shutdown_to_both_eof_and_closed_receipts_seconds":shutdown_eof_seconds,
        "shutdown_receipts":stopped_receipts, "stopped_listener_connection_refused":true,
        "notification_duration_seconds":notification_duration_seconds, "notification_bursts":5,
        "notification_posts":320, "notification_max_seconds":notification_max_seconds,
        "remaining_owned_targets":0, "ordinary_connection_preserved":true,
        "unmanaged_observation_rounds":3, "unmanaged_audit_dispatches":0,
        "removed_audit_cancel_seconds":removed_audit_cancel_seconds,
        "boundary":"private production channel stack; fixture audit/VPN inputs; not installed AI protection"});
    println!("private channel lifecycle: {lifecycle}");
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::create_dir_all(&dir).unwrap();
        fs::write(Path::new(&dir).join("queued-channel-lifecycle.json"), serde_json::to_vec_pretty(&lifecycle).unwrap()).unwrap();
    }
}
