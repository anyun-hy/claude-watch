#[path = "support/managed_cli_supervisor.rs"]
mod managed_cli_supervisor;
#[path = "support/fixture_inventory.rs"]
mod fixture_inventory;

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
        let manifest = root.join("manifest"); fs::create_dir(&manifest).unwrap();
        fs::write(manifest.join("components.json"), json!({"hashes":{"watch-sandbox-launcher":sha256_file_hex(&helper).unwrap()}}).to_string()).unwrap();
        let verifier = build_helper_verifier_from_manifest(&manifest, &helper).unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream = upstream_listener.local_addr().unwrap(); upstream_listener.set_nonblocking(true).unwrap();
        let cfg = managed_cli_supervisor::config(&store, &upstream.to_string());
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
                            if first[0] == b'C' {
                                let mut head = vec![first[0]];
                                while !head.ends_with(b"\r\n\r\n") { stream.read_exact(&mut first).unwrap(); head.push(first[0]); }
                                stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
                            } else { stream.write_all(&first).unwrap(); }
                            let mut buffer = [0; 512];
                            loop { match stream.read(&mut buffer) { Ok(0) => { let _ = closed.send(()); break; }, Ok(n) => { if stream.write_all(&buffer[..n]).is_err() { break; } }, Err(_) => break } }
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
        self.registry.replace_approved_targets_with_cli_sources(manifest.targets,manifest.children,manifest.cli_sources)
    }
    fn request(&self, executable: &Path) -> ControlledLaunchRequest {
        ControlledLaunchRequest { entry_id:"io.local.watchpanel.entry.claude-cli".into(), target:LaunchTarget::ClaudeCli,
            target_executable:executable.to_string_lossy().into_owned(), target_fingerprint:sha256_file_hex(executable).unwrap(),
            args:vec![self.gateway.port().to_string(), self.upstream.port().to_string()], cwd:Some(self.root.to_string_lossy().into_owned()),
            proxy_adaptation:ProxyAdaptationKind::EnvOnly, gateway_endpoint:self.gateway.to_string(), policy_version:self.policy.clone(),
            vpn_epoch:Some(claude_watch_core::vpn::VpnEpoch::new("vpn-obs-boot-1", 1)), launch_nonce:uuid::Uuid::new_v4().to_string(), executor_boot_id:"managed-cli-boot".into() }
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
        let cfg = managed_cli_supervisor::config(&self.store, &self.upstream.to_string());
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
        assert_eq!(target.command("EOF", "EOF"), format!("EOF {flows}"));
        for _ in 0..flows { self.upstream_eof.recv_timeout(Duration::from_secs(3)).expect("actual remote EOF"); }
        for _ in 0..3 { target.command("RECONNECT 403", "DENIED"); }
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
