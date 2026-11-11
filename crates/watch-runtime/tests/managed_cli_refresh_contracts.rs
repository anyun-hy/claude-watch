#[path = "support/managed_cli_supervisor.rs"]
mod managed_cli_supervisor;
#[path = "support/fixture_inventory.rs"]
mod fixture_inventory;

#[path = "support/hardened_helper.rs"]
mod hardened_helper;

use claude_watch_core::{channel::{BoundProcessToken, ChannelPermitState, PolicyVersion},
    controlled_launch::{ControlledLaunchRequest, ProxyAdaptationKind}, processes::LaunchTarget};
use claude_watch_runtime::{channel_enforcer::{LocalTunnelEnforcer, TunnelStream},
    channel_supervisor::{ChannelSupervisor, SupervisionEvent}, native, sandbox_launch::{ApprovedCliSource, SandboxLaunchRegistry, build_helper_verifier_from_manifest},
    storage::{Paths, StateStore}};
use claude_watch_system::{inspect_process_identity, sha256_file_hex, ProcessKernelIdentity};
use serde_json::json;
use std::{collections::BTreeMap, fs, io::{BufRead, BufReader, Read, Write}, net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::symlink, path::{Path, PathBuf}, process::{Child, ChildStdin, Command, Stdio},
    sync::{Arc, mpsc::{self, Receiver}, atomic::{AtomicBool, Ordering}}, thread, time::{Duration, Instant}};

struct TargetProcess { child: Child, input: ChildStdin, output: Receiver<String>, identity: ProcessKernelIdentity }
struct UnmanagedChild(Child);
impl Drop for UnmanagedChild { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
impl TargetProcess {
    fn command(&mut self, command: &str, expected: &str) -> String {
        writeln!(self.input, "{command}").unwrap(); self.input.flush().unwrap();
        let line = self.output.recv_timeout(Duration::from_secs(5)).expect("owned target must respond");
        assert!(line.starts_with(expected), "{command}: expected {expected}, got {line}");
        line
    }
    fn assert_same_identity(&self) {
        // proc_pidpath becomes unavailable after unlink. Birth + UID + kernel
        // audit token still prove this is the same responding exec lifetime;
        // this never substitutes for the missing FILE proof in network admission.
        assert!(claude_watch_system::process_audit_token_matches(self.identity.pid, self.identity.uid,
            self.identity.start_seconds, self.identity.start_microseconds, &self.identity.audit_token));
        if let Some(current) = inspect_process_identity(self.child.id()) { assert_eq!(current, self.identity); }
    }
}
impl Drop for TargetProcess { fn drop(&mut self) { let _ = writeln!(self.input, "QUIT"); let _ = self.input.flush(); let _ = self.child.kill(); let _ = self.child.wait(); } }

struct Fixture {
    root: PathBuf, store: StateStore, registry: Arc<SandboxLaunchRegistry>, enforcer: Arc<LocalTunnelEnforcer>,
    supervisor: Option<ChannelSupervisor>, policy: PolicyVersion, helper: PathBuf, alias: PathBuf, a: PathBuf, b: PathBuf,
    gateway: SocketAddr, upstream: SocketAddr, stop: Arc<AtomicBool>, workers: Vec<thread::JoinHandle<()>>, now: f64,
    upstream_eof: Receiver<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) { self.stop.store(true, Ordering::Release); for worker in self.workers.drain(..) { let _ = worker.join(); } let _ = fs::remove_dir_all(&self.root); }
}
impl Fixture {
    fn new() -> Self {
        Self::with_ip_action(None)
    }
    fn with_ip_action(action: Option<&str>) -> Self {
        let root = PathBuf::from("/private/tmp").join(format!("cwm-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]));
        fs::create_dir_all(root.join(".local/bin")).unwrap();
        let a = root.join("image-a"); let b = root.join("image-b");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/controlled_cli_fixture.c");
        for (path, version) in [(&a, "A"), (&b, "B")] {
            let output = Command::new("xcrun").args(["clang", "-O0", "-Wall", "-Werror"])
                .arg(format!("-DFIXTURE_VERSION=\"{version}\"" )).arg(&source).arg("-o").arg(path).output().unwrap();
            println!("fixture compiler {}: {}\n{}", path.display(), output.status, String::from_utf8_lossy(&output.stderr));
            assert!(output.status.success());
        }
        let alias = root.join(".local/bin/claude"); symlink(&a, &alias).unwrap();
        let store = StateStore::new(Paths::new(&root).unwrap());
        let helper = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/watch-sandbox-launcher").canonicalize().expect("build actual nono helper");
        let helper = hardened_helper::copy_signed(&helper, &root.join("watch-sandbox-launcher"));
        let manifest = root.join("manifest"); fs::create_dir(&manifest).unwrap();
        fs::write(manifest.join("components.json"), hardened_helper::components(&helper).to_string()).unwrap();
        let verifier = build_helper_verifier_from_manifest(&manifest, &helper).unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = upstream_listener.local_addr().unwrap(); upstream_listener.set_nonblocking(true).unwrap();
        let mut cfg = managed_cli_supervisor::config(&store, &upstream.to_string());
        if let Some(action) = action {
            cfg.policy_actions.insert("claude_close_ip".into(), action.into());
            cfg = (claude_watch_runtime::config_store::ConfigStore { storage: store.clone() })
                .save(cfg.value().unwrap()).unwrap();
        }
        let policy = ChannelSupervisor::compute_policy_version(&cfg).unwrap();
        let registry = Arc::new(SandboxLaunchRegistry::new("managed-cli-boot", policy.clone(), verifier, Some(store.clone())));
        let now = native::now();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_echo = stop.clone();
        let (eof_tx, upstream_eof) = mpsc::channel();
        let echo_worker = thread::spawn(move || {
            while !stop_echo.load(Ordering::Acquire) {
                match upstream_listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
                        let closed = eof_tx.clone();
                        thread::spawn(move || {
                            let mut first = [0]; if stream.read_exact(&mut first).is_err() { return; }
                            let tunneled = matches!(first[0], b'C' | b'p' | b'e' | b'f');
                            if first[0] == b'C' {
                                let mut head = vec![first[0]];
                                while !head.ends_with(b"\r\n\r\n") { stream.read_exact(&mut first).unwrap(); head.push(first[0]); }
                                stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
                            } else { stream.write_all(&first).unwrap(); }
                            let mut buffer = [0; 512];
                            loop { match stream.read(&mut buffer) { Ok(0) => { if tunneled { let _ = closed.send(()); } break; }, Ok(n) => { if stream.write_all(&buffer[..n]).is_err() { break; } }, Err(_) => break } }
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                    Err(error) => panic!("fixture accept: {error}"),
                }
            }
        });
        let enforcer = Arc::new(LocalTunnelEnforcer::new("managed-cli-boot", Some(store.clone())));
        // Component fixture readiness only. The production I03 report is still closed.
        enforcer.configure_seatbelt_backend(true, now).unwrap(); enforcer.set_clock(move || now + 0.5).unwrap();
        let reg = registry.clone(); enforcer.set_accepted_connection_attributor(move |ctx| reg.attribute_accepted_connection(ctx, now + 0.5)).unwrap();
        enforcer.set_upstream_connector(move |_| Ok(TunnelStream::Tcp(TcpStream::connect(upstream)?))).unwrap();
        let (gateway, proxy_worker) = enforcer.start_local_proxy_listener("127.0.0.1:0", stop.clone(), now).unwrap();
        let registration_worker = registry.start_registration_listener(&root.join("reg.sock"), stop.clone()).unwrap();
        let mut fixture = Self { root, store, registry, enforcer, supervisor:None, policy, helper, alias, a, b, gateway, upstream, stop,
            workers:vec![echo_worker, proxy_worker, registration_worker], now, upstream_eof };
        assert!(fixture.manifest(false).is_empty()); fixture.registry.refresh_executable_verifications();
        fixture
    }
    fn manifest(&mut self, use_b: bool) -> Vec<String> {
        let executable = if use_b { &self.b } else { &self.a };
        let path = executable.to_string_lossy().into_owned(); let sha = sha256_file_hex(executable).unwrap();
        self.registry.replace_approved_targets_with_cli_sources(BTreeMap::from([(path.clone(), sha.clone())]), BTreeMap::new(),
            vec![ApprovedCliSource { entry_path:self.alias.to_string_lossy().into_owned(), target:LaunchTarget::ClaudeCli, executable:path, fingerprint:sha }])
    }
    fn discovery_manifest(&self,discovery:&claude_watch_runtime::target_discovery::DiscoveryHandle)->Vec<String> {
        let reader=claude_watch_runtime::commands::SystemRunner::new(native::built_observer_path().unwrap()).unwrap();
        let snapshot=discovery.refresh(&reader,native::now());
        let manifest=discovery.approved_manifest(&snapshot).unwrap();
        println!("dynamic discovery revision {}: {} current targets, {:?}",manifest.revision,manifest.targets.len(),manifest.selection_issues);
        self.registry.replace_discovery_approvals(manifest.targets,manifest.children,manifest.cli_sources,manifest.script_combos)
    }
    fn request(&self, executable: &Path) -> ControlledLaunchRequest {
        ControlledLaunchRequest { entry_id:"io.local.watchpanel.entry.claude-cli".into(), target:LaunchTarget::ClaudeCli,
            target_executable:executable.to_string_lossy().into_owned(), target_fingerprint:sha256_file_hex(executable).unwrap(),
            args:vec![self.gateway.port().to_string(), self.upstream.port().to_string()], cwd:Some(self.root.to_string_lossy().into_owned()),
            proxy_adaptation:ProxyAdaptationKind::EnvOnly, gateway_endpoint:self.gateway.to_string(), policy_version:self.policy.clone(),
            vpn_epoch:Some(claude_watch_core::vpn::VpnEpoch::new("vpn-obs-boot-1", 1)), launch_nonce:uuid::Uuid::new_v4().to_string(), executor_boot_id:"managed-cli-boot".into(),
            script_entry: None, script_fingerprint: None, interpreter: None, interpreter_fingerprint: None, script_source: None }
    }
    fn launch_command(&self, executable: &Path) -> Command {
        let mut command = Command::new(&self.helper);
        command.arg("--launch-json").arg(serde_json::to_string(&self.request(executable)).unwrap())
            .arg("--registration-socket").arg(self.root.join("reg.sock")).arg("--deny-port").arg(self.upstream.port().to_string());
        command
    }
    fn launch(&self, executable: &Path) -> TargetProcess {
        let mut child = self.launch_command(executable).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
        let input = child.stdin.take().unwrap(); let stdout = child.stdout.take().unwrap();
        let (tx, output) = mpsc::channel();
        thread::spawn(move || { for line in BufReader::new(stdout).lines() { let Ok(line) = line else { break; }; println!("target: {line}"); if tx.send(line).is_err() { break; } } });
        let ready = output.recv_timeout(Duration::from_secs(6)).expect("actual nono target must exec");
        assert!(ready.starts_with("READY "), "{ready}");
        let identity = inspect_process_identity(child.id()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !self.tokens().iter().any(|token| token.pid == child.id()) { assert!(Instant::now() < deadline); thread::sleep(Duration::from_millis(10)); }
        TargetProcess { child, input, output, identity }
    }
    fn tokens(&self) -> Vec<BoundProcessToken> { self.registry.verified_family_tokens("claude", self.now + 0.1) }
    fn activate(&mut self) {
        let cfg = (claude_watch_runtime::config_store::ConfigStore { storage: self.store.clone() }).load().unwrap();
        self.supervisor = Some(managed_cli_supervisor::activate(&self.store, &cfg, self.enforcer.clone(), self.tokens(), self.now));
    }
    fn retarget(&mut self) {
        fs::remove_file(&self.alias).unwrap(); symlink(&self.b, &self.alias).unwrap();
        assert!(self.manifest(true).is_empty(), "a proven live A must survive an alias retarget");
        self.registry.refresh_executable_verifications();
    }
    fn dispatch_invalidated(&mut self, invalidated: Vec<String>) {
        assert_eq!(invalidated, vec!["claude"]);
        for family in invalidated { let snapshot = self.supervisor.as_mut().unwrap().handle_event(SupervisionEvent::ProcessInventoryUnavailable { family, observed_at:self.now+0.2 }).unwrap();
            assert_eq!(snapshot.families["claude"].permit_state, ChannelPermitState::Revoked); }
    }
    fn ordinary_control(&self) {
        let mut connection = TcpStream::connect(self.upstream).unwrap(); connection.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        connection.write_all(b"ordinary").unwrap(); let mut echo = [0;8]; connection.read_exact(&mut echo).unwrap(); assert_eq!(&echo,b"ordinary");
    }
    fn verify_cutoff_and_liveness(&self, target: &mut TargetProcess, flows: usize, label: &str) {
        self.verify_cutoff_with_status(target, flows, label, 403);
    }
    fn verify_cutoff_with_status(&self, target: &mut TargetProcess, flows: usize, label: &str, status: u16) {
        assert_eq!(target.command("EOF", "EOF"), format!("EOF {flows}"));
        for _ in 0..flows { self.upstream_eof.recv_timeout(Duration::from_secs(3)).expect("actual remote EOF"); }
        for _ in 0..3 { target.command(&format!("RECONNECT {status}"), "DENIED"); }
        let start = Instant::now(); let mut responses = 0;
        while start.elapsed() < Duration::from_secs(5) {
            let nonce = format!("{label}-{responses}"); let response = target.command(&format!("PING {nonce}"), "PONG");
            assert_eq!(response, format!("PONG {} {nonce}", target.identity.pid));
            target.assert_same_identity(); self.ordinary_control(); responses += 1; thread::sleep(Duration::from_millis(100));
        }
        let result = json!({"scenario":label,"true_eof_flows":flows,"reconnect_rejections":3,"same_process_responses":responses,
            "response_window_seconds":start.elapsed().as_secs_f64(),"ordinary_control":"passed","content_verifications":self.registry.executable_verification_counts()});
        println!("{result}");
        if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") { fs::create_dir_all(&dir).unwrap(); fs::write(Path::new(&dir).join(format!("managed-cli-{label}.json")), serde_json::to_vec_pretty(&result).unwrap()).unwrap(); }
    }
}

#[test]
fn dynamic_caller_source_retarget_then_removal_uses_real_supervisor_cutoff() {
    use claude_watch_runtime::target_discovery::{DiscoveryHandle,DiscoveryInputs};
    use std::os::unix::fs::PermissionsExt;
    let mut fixture=Fixture::new();
    let versions=fixture.root.join(".local/share/claude/versions");fs::create_dir_all(&versions).unwrap();
    let a=versions.join("private-A");let b=versions.join("private-B");
    fs::rename(&fixture.a,&a).unwrap();fs::rename(&fixture.b,&b).unwrap();fs::remove_file(&fixture.alias).unwrap();
    let bin=fixture.root.join("custom-caller/bin");fs::create_dir_all(&bin).unwrap();let alias=bin.join("claude");symlink(&a,&alias).unwrap();
    fixture.a=a;fixture.b=b;fixture.alias=alias;
    let mut inputs=DiscoveryInputs::for_home(&fixture.root);inputs.caller_paths.insert("claude-cli".into(),vec![bin]);
    let discovery=DiscoveryHandle::new(inputs);
    assert!(fixture.discovery_manifest(&discovery).is_empty());fixture.registry.refresh_executable_verifications();
    let mut old=fixture.launch(&fixture.a);fixture.activate();old.command("DIRECT","DIRECT_DENIED");old.command("OPEN","OPENED");
    fs::remove_file(&fixture.alias).unwrap();symlink(&fixture.b,&fixture.alias).unwrap();
    assert!(fixture.discovery_manifest(&discovery).is_empty(),"same dynamic source can retain only proven live A");fixture.registry.refresh_executable_verifications();
    old.command("OPEN","OPENED");let mut current=fixture.launch(&fixture.b);
    let tokens=fixture.tokens();managed_cli_supervisor::inventory(fixture.supervisor.as_mut().unwrap(),tokens,fixture.now+0.1);
    current.command("OPEN","OPENED");
    let rejected=fixture.launch_command(&fixture.a).output().unwrap();
    assert!(!rejected.status.success());assert!(String::from_utf8_lossy(&rejected.stderr).contains("unapproved_target_executable"));
    println!("dynamic source A->B: same entry retained live A, new B active, independent historical A rejected: {}",rejected.status);
    let broken=fixture.root.join("Applications/Unrelated.app/Contents/MacOS/Main");
    fs::create_dir_all(broken.parent().unwrap()).unwrap();fs::write(&broken,b"private discovery-only executable; never launched").unwrap();
    fs::set_permissions(&broken,fs::Permissions::from_mode(0o111)).unwrap();
    assert!(fs::File::open(&broken).is_err());
    fs::write(broken.parent().unwrap().parent().unwrap().join("Info.plist"),
        r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.openai.codex</string><key>CFBundleExecutable</key><string>Main</string></dict></plist>"#).unwrap();
    fs::remove_file(&fixture.alias).unwrap();
    let invalidated=fixture.discovery_manifest(&discovery);fixture.dispatch_invalidated(invalidated);
    fixture.verify_cutoff_and_liveness(&mut old,2,"dynamic-source-removed-old");
    fixture.verify_cutoff_and_liveness(&mut current,1,"dynamic-source-removed-current");
    assert!(!fixture.registry.identity_report(true,true,true).can_enable_production_backend(),"isolated fixture is never actual I03 acceptance");
}

#[test]
fn unchanged_image_connections_reuse_verification_and_mutation_fails_closed() {
    let mut fixture = Fixture::new(); let mut target = fixture.launch(&fixture.a); fixture.activate();
    target.command("DIRECT", "DIRECT_DENIED");
    let before = fixture.registry.executable_verification_counts();
    for _ in 0..12 { target.command("OPEN", "OPENED"); }
    let after = fixture.registry.executable_verification_counts();
    assert_eq!(before.0, after.0, "unchanged real connections must not perform SHA reads");
    println!("cache reads before/after 12 actual connections: {} / {}", before.0, after.0);
    fs::rename(&fixture.b, &fixture.a).unwrap();
    target.command("RECONNECT 403", "DENIED");
    fixture.registry.reconcile_process_trees(fixture.now + 0.2);
    let invalidated = fixture.registry.take_invalidated_families(); fixture.dispatch_invalidated(invalidated);
    fixture.verify_cutoff_and_liveness(&mut target, 12, "atomic-replacement");
}

#[test]
fn alias_retarget_keeps_only_verified_live_old_instances() {
    let mut fixture = Fixture::new(); let mut old = fixture.launch(&fixture.a); fixture.activate(); old.command("OPEN", "OPENED");
    use fixture_inventory::{FixtureInventory, FixtureProcess};
    use claude_watch_core::processes::Identity;
    use std::sync::Mutex;
    let record = |kernel: &ProcessKernelIdentity| FixtureProcess { identity:Identity { pid:kernel.pid, parent:kernel.ppid, uid:kernel.uid,
        executable:kernel.executable_path.clone(), start_seconds:kernel.start_seconds, start_microseconds:kernel.start_microseconds, start_stamp:"owned-fixture".into() }, bundle:None, arguments:vec!["PRIVATE_FIXTURE_ARGUMENT".into()] };
    let records = Arc::new(Mutex::new(vec![record(&old.identity)]));
    let mut sampler = claude_watch_runtime::sampler::Sampler::new(FixtureInventory(records.clone()), fixture.store.paths.clone());
    sampler.processes().unwrap();
    fixture.retarget(); old.command("OPEN", "OPENED");
    let mut current = fixture.launch(&fixture.b);
    let tokens = fixture.tokens(); managed_cli_supervisor::inventory(fixture.supervisor.as_mut().unwrap(), tokens, fixture.now + 0.1);
    current.command("OPEN", "OPENED");
    let mut external = UnmanagedChild(Command::new(&fixture.b).args([fixture.gateway.port().to_string(), fixture.upstream.port().to_string()])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap());
    let mut ready = String::new(); BufReader::new(external.0.stdout.take().unwrap()).read_line(&mut ready).unwrap(); assert!(ready.starts_with("READY "));
    let external_identity = inspect_process_identity(external.0.id()).unwrap();
    *records.lock().unwrap() = vec![record(&old.identity), record(&current.identity), record(&external_identity)];
    let round = sampler.processes().unwrap();
    let tokens = fixture.tokens();
    let report = fixture.registry.identity_report(true, true, true);
    assert!(!report.can_enable_production_backend(), "component fixture cannot establish actual I03");
    fixture.supervisor.as_mut().unwrap().set_family_coverage_scope("claude", Some(claude_watch_core::channel::BackendCoverageScope {
        backend:claude_watch_core::channel::NetworkBackendKind::Seatbelt, configured_entries:vec!["claude-cli".into()],
        protected_pids:tokens.iter().map(|token| token.pid).collect(), unprotected_pids:vec![external_identity.pid],
        uncovered_boundaries:vec!["unmanaged_existing_processes".into()], server_identity_verified:report.gateway_server_identity_verified,
        gateway_endpoint_protection_verified:report.gateway_endpoint_protection_verified, gateway_endpoint_protection_method:report.gateway_endpoint_protection_method,
    }), fixture.now + 0.1);
    managed_cli_supervisor::inventory(fixture.supervisor.as_mut().unwrap(), tokens, fixture.now + 0.1);
    let producer = Identity { pid:std::process::id(), parent:1, uid:old.identity.uid, executable:"/fixture/test-producer".into(), start_seconds:1, start_microseconds:0, start_stamp:"fixture".into() };
    let monitor = claude_watch_runtime::monitor_snapshot::assemble(&fixture.store, &round, &json!({}), &producer, "fixture", true, fixture.now + 0.2);
    let rows = monitor["processes"].as_array().unwrap();
    let external_row = rows.iter().find(|row| row["pid"] == external_identity.pid).unwrap();
    assert_eq!(external_row["matchReason"], "supported_cli_alias"); assert_eq!(external_row["protection"]["state"], "unprotected");
    assert_eq!(external_row["protection"]["reason_code"], "external_unmanaged_process");
    let retained_row = rows.iter().find(|row| row["pid"] == old.identity.pid).unwrap();
    assert_eq!(retained_row["matchReason"], "retained_lifetime"); assert_eq!(retained_row["protection"]["reason_code"], "gateway_endpoint_proof_missing");
    assert!(rows.iter().all(|row| row["protection"]["state"] != "protected"));
    assert!(!monitor.to_string().contains("PRIVATE_FIXTURE_ARGUMENT"));
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") { fs::create_dir_all(&dir).unwrap(); fs::write(Path::new(&dir).join("managed-cli-process-projection.json"), serde_json::to_vec_pretty(rows).unwrap()).unwrap(); }
    let rejected = fixture.launch_command(&fixture.a).output().unwrap();
    println!("independent retired A registration: {} {}", rejected.status, String::from_utf8_lossy(&rejected.stderr));
    assert!(!rejected.status.success()); assert!(String::from_utf8_lossy(&rejected.stderr).contains("unapproved_target_executable"));
    old.assert_same_identity(); current.assert_same_identity();
    fs::remove_file(&fixture.a).unwrap(); fixture.registry.reconcile_process_trees(fixture.now + 0.2);
    let invalidated = fixture.registry.take_invalidated_families(); fixture.dispatch_invalidated(invalidated);
    // Real proc_pidpath is unavailable for an unlinked image on this host.
    // Model that inventory omission and require current lifetime-bound visibility.
    records.lock().unwrap().retain(|record| record.identity.pid != old.identity.pid);
    let missing_image_round = sampler.processes().unwrap();
    assert!(!missing_image_round.targets.iter().any(|target| target.identity.pid == old.identity.pid));
    let visible = claude_watch_runtime::monitor_snapshot::assemble(&fixture.store, &missing_image_round, &json!({}), &producer, "fixture", true, native::now());
    let failed = visible["processes"].as_array().unwrap().iter().find(|row| row["pid"] == old.identity.pid).expect("live failed instance must remain visible after image unlink");
    assert_eq!(failed["startSeconds"], old.identity.start_seconds); assert_eq!(failed["startMicroseconds"], old.identity.start_microseconds);
    assert_eq!(failed["matchReason"], "retained_lifetime"); assert_eq!(failed["protection"]["state"], "unprotected");
    assert_eq!(failed["protection"]["reason_code"], "executable_evidence_changed");
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") { fs::write(Path::new(&dir).join("managed-cli-unlinked-visible.json"), serde_json::to_vec_pretty(failed).unwrap()).unwrap(); }
    fixture.verify_cutoff_and_liveness(&mut old, 2, "retired-file-deleted");
    current.command("EOF", "EOF 1"); current.command("RECONNECT 502", "DENIED"); current.assert_same_identity();
}

#[test]
fn explicit_removal_and_policy_change_revoke_retired_instances_without_killing_processes() {
    for scenario in ["explicit-source-removal", "policy-change"] {
        let mut fixture = Fixture::new(); let mut target = fixture.launch(&fixture.a); fixture.activate(); fixture.retarget(); target.command("OPEN", "OPENED");
        if scenario == "explicit-source-removal" {
            fs::remove_file(&fixture.alias).unwrap();
            let invalidated = fixture.registry.replace_approved_targets(BTreeMap::from([(fixture.b.to_string_lossy().into_owned(), sha256_file_hex(&fixture.b).unwrap())]), BTreeMap::new());
            fixture.dispatch_invalidated(invalidated);
        } else {
            let mut policy = fixture.policy.clone(); policy.policy_digest = "new-policy".into(); fixture.registry.update_policy_version(policy);
            let invalidated = fixture.registry.take_invalidated_families(); fixture.dispatch_invalidated(invalidated);
        }
        fixture.verify_cutoff_and_liveness(&mut target, 1, scenario);
    }
}

#[test]
fn retired_image_mutation_and_exec_change_reject_old_proofs_and_keep_process_alive() {
    for scenario in ["retired-content-replacement", "exec-identity-change"] {
        let mut fixture = Fixture::new(); let mut target = fixture.launch(&fixture.a); fixture.activate();
        let mut stale = fixture.request(&fixture.a); stale.executor_boot_id = "previous-boot".into();
        let denied = Command::new(&fixture.helper).arg("--launch-json").arg(serde_json::to_string(&stale).unwrap())
            .arg("--registration-socket").arg(fixture.root.join("reg.sock")).output().unwrap();
        assert!(!denied.status.success()); assert!(String::from_utf8_lossy(&denied.stderr).contains("executor_boot_id_mismatch"));
        fixture.retarget(); target.command("OPEN", "OPENED");
        if scenario == "retired-content-replacement" {
            let replacement = fixture.root.join("replacement"); fs::copy(&fixture.b, &replacement).unwrap(); fs::rename(replacement, &fixture.a).unwrap();
        } else {
            target.command(&format!("EXEC {}", fixture.b.display()), "READY");
            let current = inspect_process_identity(target.child.id()).unwrap();
            assert_eq!((current.pid,current.uid,current.start_seconds,current.start_microseconds),
                (target.identity.pid,target.identity.uid,target.identity.start_seconds,target.identity.start_microseconds));
            assert_ne!(current.audit_token, target.identity.audit_token, "exec must invalidate the old audit identity");
            target.identity = current;
        }
        fixture.registry.reconcile_process_trees(fixture.now + 0.2);
        let invalidated = fixture.registry.take_invalidated_families(); fixture.dispatch_invalidated(invalidated);
        fixture.verify_cutoff_and_liveness(&mut target, 1, scenario);
        let (_, approved_images, cached_images) = fixture.registry.executable_verification_counts();
        assert_eq!(approved_images, 1); assert!(cached_images <= approved_images, "retired proofs must be pruned");
    }
}

struct OwnedFork(ProcessKernelIdentity);
impl Drop for OwnedFork {
    fn drop(&mut self) { let _ = claude_watch_system::signal_bound_process(&self.0); }
}

fn export_case(name: &str, value: serde_json::Value) {
    println!("{}", serde_json::to_string(&value).unwrap());
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::create_dir_all(&dir).unwrap();
        fs::write(Path::new(&dir).join(name), serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }
}

#[test]
fn v1_supervisor_force_reaps_real_owned_main_and_fork_and_projects_receipt() {
    use claude_watch_runtime::process_disposition::ProcessDispositionDispatcher;
    let mut fixture = Fixture::new();
    let mut target = fixture.launch(&fixture.a);
    let child_pid = target.command("FORK", "FORKED ").split_whitespace().nth(1).unwrap().parse().unwrap();
    let child = OwnedFork(inspect_process_identity(child_pid).expect("actual fork"));
    assert_eq!(child.0.ppid, target.identity.pid);
    let mut ordinary_process = UnmanagedChild(Command::new("/bin/sleep").arg("20").spawn().unwrap());
    fixture.now = native::now();
    fixture.enforcer.set_clock(native::now).unwrap();
    fixture.activate();
    let (tx, rx) = mpsc::channel();
    let (dispatcher, worker) = ProcessDispositionDispatcher::start(fixture.store.clone(), fixture.stop.clone(), tx).unwrap();
    fixture.workers.push(worker);
    let supervisor = fixture.supervisor.as_mut().unwrap();
    supervisor.install_process_disposition_dispatcher(dispatcher);
    supervisor.set_process_disposition_registry(fixture.registry.clone());
    assert!(fixture.registry.verified_family_tokens("claude", native::now()).iter().any(|t| t.pid == child_pid));

    let observed_at = native::now();
    let cfg = (claude_watch_runtime::config_store::ConfigStore { storage: fixture.store.clone() }).load().unwrap();
    assert_eq!(cfg.close_action("egress_ip_changed", LaunchTarget::ClaudeCli.provider()), "force");
    let fresh_risk = managed_cli_supervisor::controlled_egress(&cfg, observed_at, "9.9.9.9", "US",
        Some(claude_watch_core::vpn::VpnEpoch::new("vpn-obs-boot-1", 1)));
    let awaiting = supervisor.handle_event(SupervisionEvent::EnvironmentUpdated { egress:fresh_risk,
        local_guard:json!({"proxy":"ok","tun":"disabled","context_id":"ctx-vpn"}), observed_at }).unwrap();
    assert_eq!(awaiting.families["claude"].process_execution_state.as_deref(), Some("executing"),
        "{:?}", awaiting.families["claude"]);
    let event = rx.recv_timeout(Duration::from_secs(5)).expect("actual process worker completion event");
    let SupervisionEvent::ProcessReceiptArrived { receipt, received_at } = &event else { panic!("{event:?}"); };
    println!("real force outcomes: {}", serde_json::to_string(&receipt.target_results).unwrap());

    let mut reordered = receipt.clone();
    reordered.authority.as_mut().unwrap().command_seq += 1;
    supervisor.ingest_process_receipt(reordered, *received_at).unwrap();
    assert!(supervisor.snapshot(*received_at).families["claude"].process_disposition_receipt.is_none());
    let mut prior_boot = receipt.clone();
    prior_boot.authority.as_mut().unwrap().executor_boot_id = "previous-executor".into();
    supervisor.ingest_process_receipt(prior_boot, *received_at).unwrap();
    assert!(supervisor.snapshot(*received_at).families["claude"].process_disposition_receipt.is_none());
    let mut previous_session = receipt.clone();
    previous_session.session_id = "previous-session".into();
    supervisor.ingest_process_receipt(previous_session, *received_at).unwrap();
    assert!(supervisor.snapshot(*received_at).families["claude"].process_disposition_receipt.is_none());
    let mut previous_policy = receipt.clone();
    previous_policy.authority.as_mut().unwrap().policy_version.policy_digest = "0".repeat(64);
    supervisor.ingest_process_receipt(previous_policy, *received_at).unwrap();
    assert!(supervisor.snapshot(*received_at).families["claude"].process_disposition_receipt.is_none());

    let duplicate = event.clone();
    let result = supervisor.handle_event(event).unwrap();
    let state = &result.families["claude"];
    assert_eq!(state.process_execution_state.as_deref(), Some("confirmed"));
    assert_eq!(state.permit_state, ChannelPermitState::Revoked);
    let outcome = state.process_disposition_receipt.as_ref().unwrap();
    assert_eq!(outcome.target_results.len(), 2);
    let authority = outcome.authority.as_ref().unwrap();
    assert_eq!(authority.target_instances.len(), 2);
    assert_eq!(authority.target_instances.get(&target.identity.pid), authority.target_instances.get(&child_pid));
    assert_eq!(authority.instance_id.as_ref(), authority.target_instances.get(&child_pid));
    for observed in &outcome.target_results {
        assert!(observed.terminated && observed.process_state == "terminated");
        assert!(observed.signal_sent_at.unwrap() <= observed.timestamp);
    }
    assert!(!target.child.wait().unwrap().success());
    assert!(claude_watch_system::bound_lifetime_exited(&child.0));
    let events = supervisor.drain_emitted_events();
    assert!(events.iter().any(|e| e.family_state.process_disposition_receipt.as_ref() == Some(outcome)));
    supervisor.handle_event(duplicate).unwrap();
    assert!(supervisor.drain_emitted_events().is_empty(), "duplicate cannot publish or execute again");
    assert!(ordinary_process.0.try_wait().unwrap().is_none());
    fixture.ordinary_control();
    export_case("process-disposition-wire.json", json!({"now":native::now(),"awaiting":awaiting,"snapshot":result,
        "events":events,"verified_target_exits":[target.identity.pid,child_pid],"ordinary_process_alive":true}));
}

#[test]
fn v1_warn_vpn_mismatch_cuts_actual_flow_and_keeps_owned_process() {
    let mut fixture = Fixture::with_ip_action(Some("warn"));
    let mut target = fixture.launch(&fixture.a);
    fixture.activate();
    target.command("OPEN", "OPENED");
    let at = fixture.now + 0.2;
    let config = (claude_watch_runtime::config_store::ConfigStore { storage: fixture.store.clone() }).load().unwrap();
    assert_eq!(config.close_action("egress_ip_changed", LaunchTarget::ClaudeCli.provider()), "warn");
    let mut observation = managed_cli_supervisor::sample_vpn_observation(at, 2);
    observation.upstream_endpoint = Some(config.proxy_url.clone());
    observation.selected_node = claude_watch_core::vpn::ObservedField::Known("other-node".into());
    let before_cut = Instant::now();
    let snapshot = fixture.supervisor.as_mut().unwrap().handle_event(SupervisionEvent::VpnObservationUpdated {
        observation, observed_at:at }).unwrap();
    let cut_command_ms = before_cut.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(snapshot.families["claude"].permit_state, ChannelPermitState::Revoked);
    assert!(snapshot.families["claude"].process_disposition_receipt.is_none());
    println!("fixture VPN observation through revoke command: {cut_command_ms:.3} ms");
    fixture.verify_cutoff_with_status(&mut target, 1, "vpn-current-ip-mismatch", 502);
}

struct ForkChannel {
    input: fs::File,
    output: Receiver<String>,
    _keep_output: fs::File,
}
impl ForkChannel {
    fn new(root: &Path, label: &str) -> (Self, PathBuf, PathBuf) {
        let input = root.join(format!("fork-{label}-in"));
        let output = root.join(format!("fork-{label}-out"));
        assert!(Command::new("/usr/bin/mkfifo").arg(&input).arg(&output).status().unwrap().success());
        let open = |p: &Path| fs::OpenOptions::new().read(true).write(true).open(p).unwrap();
        let keep_output = open(&output);
        let output_file = fs::File::open(&output).unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(output_file).lines() {
                let Ok(line) = line else { break; };
                if tx.send(line).is_err() { break; }
            }
        });
        (Self { input: open(&input), output: rx, _keep_output: keep_output }, input, output)
    }
    fn command(&mut self, code: u8, want: &str) {
        self.input.write_all(&[code]).unwrap();
        assert_eq!(self.output.recv_timeout(Duration::from_secs(4)).unwrap(), want);
    }
}
impl Drop for ForkChannel {
    fn drop(&mut self) { let _ = self.input.write_all(b"Q"); }
}

fn spawn_script_fixture(mut command: Command) -> (TargetProcess, String) {
    let mut process = command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
    let input = process.stdin.take().unwrap();
    let stdout = process.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break; }; println!("Node fixture: {line}"); if tx.send(line).is_err() { break; }
        }
    });
    let ready = rx.recv_timeout(Duration::from_secs(6)).ok().filter(|line| line.starts_with("READY "));
    let identity = inspect_process_identity(process.id());
    let (Some(identity), Some(line)) = (identity, ready) else {
        let _ = process.kill();
        let _ = process.wait();
        panic!("real approved script did not reach the readiness barrier");
    };
    (TargetProcess { child:process, input, output:rx, identity }, line)
}

#[test]
fn v3_node_esm_discovery_sandbox_gateway_fork_and_current_source_cutoff() {
    use claude_watch_runtime::{commands::SystemRunner, target_discovery::{DiscoveryHandle, DiscoveryInputs}};
    use std::os::unix::{fs::PermissionsExt, net::UnixListener};
    let mut fixture = Fixture::new();
    let node = fs::canonicalize("/opt/homebrew/bin/node").expect("already-installed Node 26 interpreter");
    let support = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support");
    let npm = fixture.root.join(".nvm/versions/node/v26.8.2");
    let node_bin = npm.join("bin");
    let pkg = npm.join("lib/node_modules/@anthropic-ai/claude-code");
    fs::create_dir_all(&node_bin).unwrap();
    fs::create_dir_all(&pkg).unwrap();
    symlink(&node, node_bin.join("node")).unwrap();
    let daemon_bin = fixture.root.join("daemon-bin");
    fs::create_dir(&daemon_bin).unwrap();
    symlink(&fixture.b, daemon_bin.join("node")).unwrap();

    let script = pkg.join("cli.js");
    fs::copy(support.join("node_cli_fixture.mjs"), &script).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(pkg.join("package.json"), br#"{"name":"@anthropic-ai/claude-code","type":"module","bin":{"claude":"cli.js"}}"#).unwrap();
    fs::write(pkg.join("relative.js"), b"export const relativeFixture = 'owned-relative-module';").unwrap();
    fs::remove_file(&fixture.alias).unwrap();
    symlink(&script, &fixture.alias).unwrap();
    let other = fixture.root.join("other.cjs");
    fs::copy(support.join("node_other_fixture.cjs"), &other).unwrap();
    let preload = fixture.root.join("preload.cjs");
    fs::write(&preload, b"require('node:fs').writeFileSync(process.env.CW_FIXTURE_PRELOAD_MARKER, 'preload ran')").unwrap();
    let preload_marker = fixture.root.join("preload-marker");
    let addon = fixture.root.join("fork.node");
    let compile = Command::new("xcrun").args(["clang","-O0","-Wall","-Wextra","-Werror","-dynamiclib",
        "-undefined","dynamic_lookup","-I","/opt/homebrew/include/node"])
        .arg(support.join("node_fork_fixture.c")).arg("-o").arg(&addon).output().unwrap();
    println!("native fork addon compile: {}\n{}", compile.status, String::from_utf8_lossy(&compile.stderr));
    assert!(compile.status.success());
    let (mut fork_channel, fork_in, fork_out) = ForkChannel::new(&fixture.root, "primary");

    let reader = SystemRunner::new(native::built_observer_path().unwrap()).unwrap();
    let mut inputs = DiscoveryInputs::for_home(&fixture.root);
    inputs.daemon_path = vec![daemon_bin];
    let caller = DiscoveryHandle::new(inputs.clone());
    let env = BTreeMap::from([("PATH".into(),
        std::env::join_paths([fixture.alias.parent().unwrap(), &node_bin]).unwrap().into_string().unwrap())]);
    let (selection, record) = caller.select_cli(&reader, LaunchTarget::ClaudeCli, &env, native::now()).unwrap();
    let (_, proof) = caller.selected_cli_proof(&selection, &record).unwrap();
    let combo = proof.expect("supported official-shaped Node ESM fixture");
    assert_eq!(Path::new(&combo.interpreter_path), node);
    assert_eq!(Path::new(&combo.interpreter_entry_path), node_bin.join("node"));
    caller.publish_caller_hint(LaunchTarget::ClaudeCli).unwrap();
    let daemon = DiscoveryHandle::new(inputs);
    let snapshot = daemon.refresh(&reader, native::now());
    let manifest = daemon.approved_manifest(&snapshot).unwrap();
    assert_eq!(manifest.script_combos, vec![combo.clone()], "caller and daemon must agree on the exact script and interpreter");
    assert!(!manifest.targets.contains_key(&combo.interpreter_path));
    assert!(!manifest.children.contains_key(&combo.interpreter_path));
    assert!(fixture.registry.replace_discovery_approvals(manifest.targets, manifest.children,
        manifest.cli_sources, manifest.script_combos).is_empty());

    let mut request = fixture.request(&script);
    request.script_entry = Some(combo.script_path.clone());
    request.script_fingerprint = Some(combo.script_fingerprint.clone());
    request.interpreter = Some(combo.interpreter_path.clone());
    request.interpreter_fingerprint = Some(combo.interpreter_fingerprint.clone());
    request.script_source = Some(combo.source_proof());
    request.args.extend([fork_in, fork_out, addon, other].into_iter().map(|p| p.to_string_lossy().into_owned()));
    request.args.extend(["arg with spaces".into(), "--literal-node-option".into()]);
    let helper = fixture.helper.clone();
    let socket = fixture.root.join("reg.sock");
    let cmd = |req: &ControlledLaunchRequest, socket: &Path| {
        let mut command = Command::new(&helper);
        command.arg("--launch-json").arg(serde_json::to_string(req).unwrap())
            .arg("--registration-socket").arg(socket);
        command
    };
    let no_exec = |req: &ControlledLaunchRequest, expected: &str| {
        let out = cmd(req, &socket).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        println!("negative {}: {}\n{}", expected, out.status, err);
        assert!(!out.status.success() && out.stdout.is_empty() && err.contains(expected), "{err}");
    };
    let mut stale = request.clone();
    stale.script_source.as_mut().unwrap().source_revision = "0".repeat(64);
    no_exec(&stale, "unapproved_script_combination");
    let mut wrong_interpreter = request.clone();
    wrong_interpreter.interpreter = Some(fixture.b.to_string_lossy().into_owned());
    wrong_interpreter.interpreter_fingerprint = sha256_file_hex(&fixture.b);
    no_exec(&wrong_interpreter, "unapproved_script_combination");
    let mut native_shape = request.clone();
    native_shape.script_entry = None; native_shape.script_fingerprint = None; native_shape.interpreter = None;
    native_shape.interpreter_fingerprint = None; native_shape.script_source = None;
    no_exec(&native_shape, "script_launch_contract_required");

    // connect() is after the real helper captured and hashed the bytes. Hold
    // the registration reply until the fixture replaces the original pathname.
    let original = fs::read(&script).unwrap();
    let gate_path = fixture.root.join("gate.sock");
    let gate = UnixListener::bind(&gate_path).unwrap();
    gate.set_nonblocking(true).unwrap();
    let mut changed = request.clone();
    changed.launch_nonce = uuid::Uuid::new_v4().to_string();
    let replaced_child = cmd(&changed, &gate_path).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let end = Instant::now() + Duration::from_secs(3);
    let stream = loop {
        match gate.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < end => thread::sleep(Duration::from_millis(5)),
            Err(e) => panic!("helper never reached verification barrier: {e}"),
        }
    };
    fs::write(&script, b"#!/usr/bin/env node\nthrow new Error('replaced-entry-must-not-run');").unwrap();
    let rejected = fixture.registry.handle_helper_registration_stream(stream, native::now()).unwrap();
    assert!(!rejected.accepted);
    let replaced_result = replaced_child.wait_with_output().unwrap();
    assert!(!replaced_result.status.success() && replaced_result.stdout.is_empty());
    let replaced_err = String::from_utf8_lossy(&replaced_result.stderr);
    assert!(!replaced_err.contains("replaced-entry-must-not-run"));
    println!("after capture before registration: {}\n{replaced_err}", replaced_result.status);
    fs::write(&script, original).unwrap();

    let mut scripted = cmd(&request, &socket);
    scripted.env("NODE_OPTIONS", format!("--require={}", preload.display()))
        .env("CW_FIXTURE_PRELOAD_MARKER", &preload_marker);
    let (mut main, line) = spawn_script_fixture(scripted);
    let (_, payload) = line.split_once(' ').unwrap().1.split_once(' ').unwrap();
    let ready: serde_json::Value = serde_json::from_str(payload).unwrap();
    assert_eq!(ready["marker"], "owned-relative-module");
    assert_eq!(ready["path"], script.to_str().unwrap());
    assert_eq!(ready["cwd"], fixture.root.to_str().unwrap());
    assert_eq!(ready["main"], true);
    assert_eq!(ready["execPath"], node.to_str().unwrap());
    assert_eq!(ready["argv"], json!(["arg with spaces","--literal-node-option"]));
    assert_eq!(ready["startupOption"], false);
    assert!(!preload_marker.exists());

    let forked = main.command("FORK", "FORKED ").split_whitespace().nth(1).unwrap().parse().unwrap();
    let owned_fork = OwnedFork(inspect_process_identity(forked).unwrap());
    assert!(claude_watch_system::bound_fork_only(&owned_fork.0));
    let execed = main.command("EXEC_OTHER", "EXECED ").split_whitespace().nth(1).unwrap().parse().unwrap();
    let exec_identity = inspect_process_identity(execed).unwrap();
    assert!(!claude_watch_system::bound_fork_only(&exec_identity));
    assert_eq!(exec_identity.executable_path, owned_fork.0.executable_path);

    // A second instance proves permission survives parent exit when the
    // child was already attributed, before the source itself is revoked.
    let (mut orphan_channel, orphan_in, orphan_out) = ForkChannel::new(&fixture.root, "orphan");
    let mut second_request = request.clone();
    second_request.launch_nonce = uuid::Uuid::new_v4().to_string();
    second_request.args[2] = orphan_in.to_string_lossy().into_owned();
    second_request.args[3] = orphan_out.to_string_lossy().into_owned();
    let (mut second, _) = spawn_script_fixture(cmd(&second_request, &socket));
    let orphan_pid = second.command("FORK", "FORKED ").split_whitespace().nth(1).unwrap().parse().unwrap();
    let orphan = OwnedFork(inspect_process_identity(orphan_pid).unwrap());
    assert!(fixture.tokens().iter().any(|t| t.pid == orphan_pid));
    writeln!(second.input, "QUIT").unwrap();
    second.input.flush().unwrap();
    assert_eq!(second.child.wait().unwrap().code(), Some(23));
    assert!(fixture.tokens().iter().any(|t| t.pid == orphan_pid), "verified child must remain scoped after the parent exited");
    assert!(inspect_process_identity(orphan_pid).is_some_and(|p| p.ppid != orphan.0.ppid
        && p.start_seconds == orphan.0.start_seconds && p.audit_token == orphan.0.audit_token));
    fixture.now = native::now();
    fixture.enforcer.set_clock(native::now).unwrap();
    let live = fixture.tokens();
    assert!(live.iter().any(|t| t.pid == main.identity.pid), "main must match the loaded interpreter and exact approved script: {:?}", fixture.registry.instances());
    assert!(live.iter().any(|t| t.pid == forked), "fork-only instance descendant must be verified");
    assert!(!live.iter().any(|t| t.pid == execed));
    fixture.activate();
    main.command("OTHER_DENIED", "OTHER_DENIED");
    let mut independent = Command::new(&node).arg(fixture.root.join("other.cjs"))
        .arg(fixture.gateway.port().to_string()).arg(fixture.upstream.port().to_string())
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
    independent.stdin.as_mut().unwrap().write_all(b"check\n").unwrap();
    let result = independent.wait_with_output().unwrap();
    assert!(result.status.success() && String::from_utf8_lossy(&result.stdout).contains("OTHER_DENIED"));
    main.command("OPEN", "OPENED");
    fork_channel.command(b'O', "OPENED");
    orphan_channel.command(b'O', "OPENED");
    // Revoke the exact combination by replacing the resolved interpreter
    // alias. The ordinary direct control does not use the Watch gateway.
    let cut_start = Instant::now();
    fs::remove_file(node_bin.join("node")).unwrap();
    symlink(&fixture.b, node_bin.join("node")).unwrap();
    fixture.registry.reconcile_process_trees(native::now());
    let invalidated = fixture.registry.take_invalidated_families();
    assert_eq!(invalidated, vec!["claude"]);
    let cutoff = fixture.supervisor.as_mut().unwrap().handle_event(SupervisionEvent::ProcessInventoryUnavailable {
        family:"claude".into(), observed_at:native::now(),
    }).unwrap();
    assert_eq!(cutoff.families["claude"].display_state, claude_watch_core::channel::ChannelMonitorDisplayState::Blocked);
    assert_eq!(cutoff.families["claude"].policy_sync_state, claude_watch_core::channel::PolicySyncState::Applied);
    assert_eq!(main.command("EOF", "EOF"), "EOF 1");
    fork_channel.command(b'E', "EOF 1");
    orphan_channel.command(b'E', "EOF 1");
    for _ in 0..3 { fixture.upstream_eof.recv_timeout(Duration::from_secs(3)).expect("actual remote tunnel EOF"); }
    let cutoff_ms = cut_start.elapsed().as_secs_f64()*1000.0;
    main.command("RECONNECT 403", "DENIED");
    fork_channel.command(b'D', "DENIED");
    orphan_channel.command(b'D', "DENIED");
    let start = Instant::now();
    let mut samples = 0;
    while start.elapsed() < Duration::from_secs(5) {
        let nonce = format!("script-{samples}");
        assert_eq!(main.command(&format!("PING {nonce}"), "PONG"), format!("PONG {} {nonce}",main.identity.pid));
        main.assert_same_identity();
        fork_channel.command(b'P', "PONG");
        orphan_channel.command(b'P', "PONG");
        assert!(claude_watch_system::process_audit_token_matches(orphan_pid, orphan.0.uid, orphan.0.start_seconds,
            orphan.0.start_microseconds, &orphan.0.audit_token));
        assert!(claude_watch_system::process_audit_token_matches(forked, owned_fork.0.uid, owned_fork.0.start_seconds,
            owned_fork.0.start_microseconds, &owned_fork.0.audit_token));
        fixture.ordinary_control();
        samples += 1;
        thread::sleep(Duration::from_millis(100));
    }
    writeln!(main.input, "QUIT").unwrap();
    main.input.flush().unwrap();
    assert_eq!(main.child.wait().unwrap().code(), Some(23));
    fork_channel.command(b'P', "PONG");
    assert!(inspect_process_identity(forked).is_some_and(|p| p.ppid != owned_fork.0.ppid
        && p.start_seconds == owned_fork.0.start_seconds && p.audit_token == owned_fork.0.audit_token));
    export_case("script-gateway-wire.json", json!({"now":native::now(),"supported_form":combo.launcher_format,
        "source_id":combo.source_id,"ready":ready,"main_pid":main.identity.pid,"fork_pid":forked,"exec_rejected_pid":execed,
        "tunnels_ended":3,"reconnect_denials":3,"cutoff_ms":cutoff_ms,"orphan_verified_before_cutoff":orphan_pid,"same_process_samples":samples,
        "same_process_window_s":start.elapsed().as_secs_f64(),"orphan_response":true,
        "ordinary_control":true,"snapshot":cutoff}));
}

#[test]
fn v1_gateway_apply_failure_neither_authorizes_force_nor_hides_an_independent_exit() {
    use claude_watch_core::{
        channel::{ChannelEnforcementCommand, ChannelEnforcementReceipt, ChannelMonitorDisplayState},
        error::{CoreError, Result},
    };
    use claude_watch_runtime::{channel_enforcer::ChannelEnforcer, process_disposition::ProcessDispositionDispatcher};

    struct DenyRevocation(Arc<LocalTunnelEnforcer>, AtomicBool);
    impl ChannelEnforcer for DenyRevocation {
        fn boot_id(&self) -> Result<String> { self.0.boot_id() }
        fn is_ready(&self) -> Result<bool> { self.0.is_ready() }
        fn apply_command(&self, command: &ChannelEnforcementCommand, now: f64) -> Result<ChannelEnforcementReceipt> {
            if self.1.load(Ordering::Acquire) && command.permit.state == ChannelPermitState::Revoked {
                return Err(CoreError::new("fixture_apply_failed", "Injected executor failure for an owned fixture"));
            }
            self.0.apply_command(command, now)
        }
        fn receipt_for(&self, family: &str, now: f64) -> Result<Option<ChannelEnforcementReceipt>> {
            self.0.receipt_for(family, now)
        }
        fn enforce_active_deadlines(&self, now: f64, woke: bool) -> Result<Vec<ChannelEnforcementReceipt>> {
            self.0.enforce_active_deadlines(now, woke)
        }
        fn local_proxy_port(&self) -> Option<u16> { self.0.local_proxy_port() }
    }

    for independently_authorized in [false,true] {
        let mut fixture = Fixture::new();
        let mut target = fixture.launch(&fixture.a);
        fixture.now = native::now();
        fixture.enforcer.set_clock(native::now).unwrap();
        let cfg = (claude_watch_runtime::config_store::ConfigStore { storage: fixture.store.clone() }).load().unwrap();
        let injected = Arc::new(DenyRevocation(fixture.enforcer.clone(), AtomicBool::new(false)));
        let mut supervisor = managed_cli_supervisor::activate(&fixture.store,&cfg,injected.clone(),fixture.tokens(),fixture.now);
        let (tx, rx) = mpsc::channel();
        let (dispatcher, worker) = ProcessDispositionDispatcher::start(fixture.store.clone(), fixture.stop.clone(), tx).unwrap();
        fixture.workers.push(worker);
        supervisor.install_process_disposition_dispatcher(dispatcher);
        supervisor.set_process_disposition_registry(fixture.registry.clone());
        injected.1.store(true,Ordering::Release);
        let at = native::now();
        let mut observation = managed_cli_supervisor::sample_vpn_observation(at,1);
        observation.upstream_endpoint = Some(cfg.proxy_url.clone());
        let initial = if independently_authorized {
            supervisor.handle_event(SupervisionEvent::EnvironmentUpdated {
                egress:managed_cli_supervisor::controlled_egress(&cfg,at,"9.9.9.9","US",Some(observation.epoch)),
                local_guard:json!({"proxy":"ok","tun":"disabled","context_id":"ctx-vpn"}),observed_at:at,
            }).unwrap()
        } else {
            observation.sample_seq += 1;
            observation.epoch.change_generation += 1;
            observation.selected_node = claude_watch_core::vpn::ObservedField::Known("different".into());
            supervisor.handle_event(SupervisionEvent::VpnObservationUpdated { observation,observed_at:at }).unwrap()
        };
        assert_eq!(initial.families["claude"].display_state,ChannelMonitorDisplayState::Failed);
        if independently_authorized {
            let event = rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let result = supervisor.handle_event(event).unwrap();
            let state = &result.families["claude"];
            assert_eq!(state.display_state,ChannelMonitorDisplayState::Failed);
            assert_eq!(state.process_execution_state.as_deref(),Some("confirmed"));
            assert!(!target.child.wait().unwrap().success());
            export_case("process-disposition-network-failure.json",json!({"snapshot":result,"now":native::now()}));
        } else {
            assert_eq!(initial.families["claude"].process_execution_state,None);
            assert!(rx.try_recv().is_err());
            target.command("PING no-force", "PONG");
            target.assert_same_identity();
        }
        fixture.ordinary_control();
    }
}
