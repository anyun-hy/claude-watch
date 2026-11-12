//! Test build only. The real engine CLI/dispatch and NativeDesktop are
//! retained. External readiness/audit inputs are synthetic; process inventory
//! is scoped to the private home and comes from live kernel identities.
#![allow(dead_code)] // Also compiled by the engine's ordinary libtest target.
#[path = "../../../watch-runtime/tests/support/hardened_helper.rs"]
mod hardened_helper;

use super::{
    channel_audit,
    daemon_run::{assemble_production_channel_stack_with_vpn_reader, ProductionChannelStack},
    runtime::{self, OperationOutcome},
};
use claude_watch_core::{
    channel::{ChannelMonitorDisplayState, ChannelPermitState},
    cli::Request,
    config::Config,
    error::{CoreError, Result},
    processes::LaunchTarget,
    session::{Egress, Phase, GUARD_EGRESS_TTL},
    vpn::{VpnEpoch, VpnExpectation, VpnObservation},
};
use claude_watch_runtime::{
    audit_store::{AuditOptions, AuditStore, AuditSystem},
    channel_enforcer::{registered_production_enforcer, ChannelEnforcer, TunnelStream},
    channel_supervisor::{AsyncAuditRequest, ChannelSupervisor},
    commands::{ObserverAction, ReadCommand, ReadRunner, SystemRunner},
    config_store::ConfigStore,
    desktop_native::DesktopRuntime,
    macos::Authority,
    managed_entry::snapshot_running_processes,
    native,
    network_client::{self, NetworkClient, Transport, TransportError},
    region_catalog::load_system_catalog,
    services::ServiceSystem,
    session_store::SessionStore,
    storage::{Paths, StateStore},
    target_discovery::DiscoveryHandle,
    vpn_observer::VpnSourceReader,
};
use claude_watch_system::{inspect_process_identity, sha256_file_hex, ProcessKernelIdentity};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{atomic::{AtomicBool, AtomicU64, Ordering}, mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

#[path = "../../../watch-runtime/tests/support/managed_cli_supervisor.rs"]
mod fixtures;

const PRIVATE_HOME: &str = "CW_READY_ENTRY_FIXTURE_HOME";
pub fn is_fixture_child() -> bool { std::env::var_os(PRIVATE_HOME).is_some() }

pub(crate) fn is_private_fixture_home(home: &Path) -> bool {
    home.parent().is_some_and(|root| root.parent() == Some(Path::new("/private/tmp"))
        && root.file_name().and_then(|name| name.to_str()).is_some_and(|name| name.starts_with("cw-rdy-"))
        && root.join("owned-fixture").is_file())
}

pub fn validate_child(request: &Request, paths: &Paths) -> Result<()> {
    let valid = std::env::var_os(PRIVATE_HOME).as_deref() == Some(paths.home.as_os_str())
        && is_private_fixture_home(&paths.home)
        && matches!(request.command.as_str(), "entry" | "launch")
        && ["target-bundle", "shims-dir", "applications-dir"].iter().all(|key|
            request.value(key).is_none_or(|p| Path::new(p).starts_with(&paths.home) && !Path::new(p).components().any(|c| c == std::path::Component::ParentDir)));
    if !valid { return Err(CoreError::new("fixture_home_required", "入口验证仅支持本轮自有临时目录")); }
    Ok(())
}

struct FixtureSystem { collector_ready: bool }
impl AuditSystem for FixtureSystem {
    fn now(&self) -> f64 { native::now() }
    fn network(&self) -> Result<Value> { Ok(json!({"service":"fixture","interface":"lo0"})) }
    fn local(&self, cfg: &Config) -> Result<Value> {
        Ok(json!({
            "proxy":"ok","tun":"ok","mode":"fixture","context":"ctx-vpn","context_id":"ctx-vpn",
            "network_identity":{"entry":cfg.proxy_url},"timezone":"Asia/Tokyo","locale":"ja_JP",
            "ipv6":"ok","language":"en-US","backend_healthy":true,"backend_native":true,
            "guard":true,"guard_state":"ok","rules":{"state":"ok","detail":"private fixture"},
            "cli_proxy":{"state":"ok","detail":"private fixture"},"verified_proxy_url":cfg.proxy_url,
            "date_format":{"state":"available","configured_locale":"ja_JP",
                "patterns":{"short":"y/MM/dd","medium":"y/MM/dd","long":"y年M月d日"},
                "reference_patterns":{"ja_JP":{"short":"y/MM/dd","medium":"y/MM/dd","long":"y年M月d日"}},
                "short_sample":"2026/11/11","reference_samples":{"ja_JP":"2026/11/11"}}
        }))
    }
    fn online(&mut self, _: &Config, _: &Value) -> Result<Value> {
        Ok(json!({
            "trace":{"ip":"1.1.1.1","loc":"JP"},
            "geo":{"ip":"1.1.1.1","country":"JP","timezone":"Asia/Tokyo"},
            "stun":{"complete":true,"observations":[{"status":"ok","address":"1.1.1.1"}]},
            "service_responses":{
                "claude":{"status":"ok","transport_reached":true,"http_status":403,"access":"challenge",
                    "source":"https://claude.ai/","challenge":{"provider":"cloudflare","mitigated":"challenge"}},
                "api":{"status":"ok","transport_reached":true,"http_status":401,"access":"authentication_required",
                    "source":"https://api.anthropic.com/v1/models"}
            }
        }))
    }
}

impl ServiceSystem for FixtureSystem {
    fn now(&self) -> f64 { native::now() }
    fn backend_healthy(&self) -> bool { self.collector_ready }
    fn guard_status(&self, _: &Config) -> Result<bool> { Ok(true) }
    fn service_job(&self, _: &str) -> Result<Value> { panic!("no service calls in entry fixture") }
    fn watchdog_state(&self) -> Result<Value> { panic!("no service calls in entry fixture") }
    fn admin_helper_status(&self) -> Result<Value> { panic!("no admin helper in entry fixture") }
    fn runtime_present(&self) -> bool { true }
    fn apply_service(&mut self, _: &Value) -> Result<()> { panic!("no service writes in entry fixture") }
}

struct FixtureTransport;
impl Transport for FixtureTransport {
    fn get(&self, request: &network_client::Request) -> std::result::Result<network_client::Response, TransportError> {
        assert_eq!(request.url, network_client::FAST_EGRESS_URL, "never issue an external network request");
        Ok(network_client::Response { status:200, headers:Default::default(), body:b"ip=1.1.1.1\nloc=JP\n".to_vec() })
    }
}

struct ScopedReader {
    system: Arc<SystemRunner>,
    home: PathBuf,
}
impl ReadRunner for ScopedReader {
    fn run(&self, command: ReadCommand, input: &[u8], timeout: Duration, limit: usize) -> Result<claude_watch_runtime::commands::Output> {
        if !matches!(command, ReadCommand::Observer(ObserverAction::Inventory)) {
            return self.system.run(command, input, timeout, limit);
        }
        let start = native::now();
        // The ordinary host inventory can be partial for unrelated, transient
        // processes. This fixture has a closed scope: the private target home
        // and the fixture engine itself. Preserve real identities in that scope.
        let mut rows: Vec<_> = snapshot_running_processes()?.into_iter()
            .filter(|p| p.pid == std::process::id() || Path::new(&p.executable).starts_with(&self.home))
            .map(|p| json!({"pid":p.pid,"parent":p.ppid,"uid":p.uid,"executable":p.executable,
                "start_seconds":p.start_seconds,"start_microseconds":p.start_microseconds,
                "start_stamp":format!("{}.{:06}",p.start_seconds,p.start_microseconds)})).collect();
        let mut unavailable = Vec::new();
        if let Ok(pid) = fs::read_to_string(self.home.parent().unwrap().join("unreadable-owned-process")) {
            let pid: u32 = pid.trim().parse().unwrap();
            let index = rows.iter().position(|row| row["pid"] == pid).expect("owned ordinary process must exist");
            assert_ne!(pid, std::process::id());
            rows.remove(index);
            unavailable.push(json!({"pid":pid,"code":"identity_unavailable"}));
        }
        let bytes = serde_json::to_vec(&json!({
            "schema":1,"status":"ok","uid":claude_watch_system::effective_uid(),
            "started_at":start,"finished_at":native::now(),"state":"ok","truncated":false,
            "requested_count":rows.len()+unavailable.len(),"unavailable":unavailable,"exited":[],"processes":rows,
        })).unwrap();
        assert!(bytes.len() <= limit);
        Ok(claude_watch_runtime::commands::Output { status:0, stdout:bytes, stderr:vec![] })
    }
}

pub fn fixture_launch(request: &Request, storage: &StateStore, system_runner: Arc<SystemRunner>,
    process_helper: PathBuf, authority: Authority) -> Result<OperationOutcome> {
    validate_child(request, &storage.paths)?;
    let reader = ScopedReader { system:system_runner, home:storage.paths.home.clone() };
    let mut desktop = runtime::native_desktop_for_request(request, storage, reader, process_helper, authority)?;
    let network = NetworkClient::new(Arc::new(FixtureTransport), None)
        .map_err(|error| CoreError::new(&error.code, &error.detail))?
        .with_state_store(storage.clone());
    let mut system = FixtureSystem {
        collector_ready: storage.paths.home.parent().unwrap().join("collector-ready").is_file(),
    };
    let mut desktop = DesktopRuntime {
        desktop: &mut desktop, network, system: &mut system, storage: storage.clone(), started: Instant::now(), cli: None,
    };
    runtime::dispatch_launch(request, storage, &mut desktop)
}

struct Root(PathBuf);
impl Drop for Root { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
}
struct OwnedTarget(ProcessKernelIdentity);
impl Drop for OwnedTarget {
    fn drop(&mut self) { let _ = claude_watch_system::signal_bound_process(&self.0); }
}
struct Workers(Arc<AtomicBool>, Vec<thread::JoinHandle<()>>);
impl Drop for Workers {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
        for worker in self.1.drain(..) { let _ = worker.join(); }
    }
}

struct OwnedStack(Option<ProductionChannelStack>);
impl Drop for OwnedStack {
    fn drop(&mut self) {
        if let Some(stack) = self.0.take() {
            let log = stack.supervisor.storage.paths.base().join("diagnostic-events.jsonl");
            stack.shutdown();
            if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
                let name = format!("ready-entry-channel-{}.jsonl", uuid::Uuid::new_v4().simple());
                let path = Path::new(&dir).join(name);
                if fs::copy(log, &path).is_ok() { println!("private channel trace: {}", path.display()); }
            }
        }
    }
}

struct FixtureVpn { revision: Arc<AtomicU64> }
impl VpnSourceReader for FixtureVpn {
    fn read_observation(&self, expectation: &VpnExpectation, _: bool, sample_seq: u64,
        epoch: VpnEpoch, now: f64) -> VpnObservation {
        let mut sample = fixtures::sample_vpn_observation(now, self.revision.load(Ordering::Acquire));
        sample.sample_seq = sample_seq;
        sample.epoch = epoch;
        sample.upstream_endpoint = Some(expectation.proxy_url.clone());
        sample
    }
}

fn run_fixture_audit(storage: &StateStore, req: &AsyncAuditRequest) -> Result<(Value, Value, f64)> {
    let enforcer = registered_production_enforcer(&storage.paths.watch()).expect("production stack enforcer");
    let config = (ConfigStore { storage: storage.clone() }).load()?;
    assert_eq!(req.policy_version, ChannelSupervisor::compute_policy_version(&config)?);
    assert_eq!(req.upstream_endpoint, config.proxy_url);
    channel_audit::run_with_worker(&storage.paths, &enforcer, req, |kind, input, _, _| {
        assert_eq!(input["home"], json!(storage.paths.home));
        assert_eq!(input["launch_target"], json!(req.target));
        match kind {
            "audit" => AuditStore::new(storage.clone()).collect_target(
                &mut FixtureSystem { collector_ready: true }, &load_system_catalog(), req.target,
                AuditOptions { online: true, persist: false, launch: true },
            ),
            "egress" => {
                assert_eq!(input["proxy"], config.proxy_url);
                assert_eq!(input["context_id"], "ctx-vpn");
                let network = NetworkClient::new(Arc::new(FixtureTransport), None).unwrap();
                network.fast_egress_via(Some(&config.proxy_url)).data
                    .ok_or_else(|| CoreError::new("fixture_egress_missing", "夹具出口未取得"))
            }
            _ => unreachable!("unexpected audit worker action"),
        }
    })
}

fn output(label: &str, result: Output) -> Output {
    println!("{label}: {}\nstdout: {}\nstderr: {}", result.status,
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
    result
}

fn plist(path: &Path, body: &Value) {
    let tmp = path.with_extension("fixture-json");
    fs::write(&tmp, serde_json::to_vec(body).unwrap()).unwrap();
    assert!(output("private plist", Command::new("/usr/bin/plutil").args(["-convert", "xml1", "-o"])
        .arg(path).arg(&tmp).output().unwrap()).status.success());
    fs::remove_file(tmp).unwrap();
}

fn wait_read(path: &Path, expected: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let text = fs::read_to_string(path).unwrap_or_default();
        assert!(!text.starts_with("FAILED "), "{}: {text}", path.display());
        if text.starts_with(expected) && text.ends_with('\n') { return text; }
        assert!(Instant::now() < deadline, "{}: expected {expected}, found {text:?}", path.display());
        thread::sleep(Duration::from_millis(10));
    }
}

fn persisted_egress(egress: Egress) -> Egress {
    // SessionStore persists and reloads JSON. Apply that same representation
    // to worker evidence before exact equality (no timestamp epsilon): the
    // JSON parser can otherwise differ by one f64 ULP from the in-memory row.
    serde_json::from_slice(&serde_json::to_vec(&egress).unwrap()).unwrap()
}

fn upstream(mut stream: TcpStream) {
    stream.set_nonblocking(false).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") && head.len() < 4096 {
        let mut byte = [0]; stream.read_exact(&mut byte).unwrap(); head.push(byte[0]);
    }
    assert!(head.starts_with(b"CONNECT fixture.invalid:443 HTTP/1.1\r\n"), "{head:?}");
    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").unwrap();
    let mut payload = [0; 6];
    stream.read_exact(&mut payload).unwrap();
    assert_eq!(&payload, b"owned!");
    stream.write_all(&payload).unwrap();
}

pub fn run_contract() {
    println!("running 1 test");
    let root = Root(PathBuf::from("/private/tmp").join(format!("cw-rdy-{}", &uuid::Uuid::new_v4().simple().to_string()[..8])));
    // Use the real state/socket layout, with a short enough Unix socket path.
    let home = root.0.join("h");
    fs::create_dir_all(&home).unwrap();
    let storage = StateStore::new(Paths::new(&home).unwrap());
    let runtime_dir = storage.paths.watch().join("runtime");
    fs::create_dir_all(&runtime_dir).unwrap();
    fs::write(root.0.join("owned-fixture"), b"test-only").unwrap();
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let engine = runtime_dir.join("watch-engine");
    let helper = runtime_dir.join("watch-sandbox-launcher");
    let wrapper_component = runtime_dir.join("ControlledEntry");
    fs::copy(std::env::current_exe().unwrap(), &engine).unwrap();
    let helper_cdhash = hardened_helper::cdhash(&hardened_helper::copy_signed(&repo.join("target/debug/watch-sandbox-launcher"), &helper));
    fs::copy(native::built_observer_path().unwrap(), runtime_dir.join("watch-native-observer")).unwrap();
    fs::copy(native::built_process_control_path().unwrap(), runtime_dir.join("watch-process-control")).unwrap();
    assert!(output("compile production AppKit wrapper", Command::new("xcrun").args([
        "--sdk", "macosx", "swiftc", "-parse-as-library", "-target", "arm64-apple-macosx26.0", "-module-cache-path"
    ]).arg(root.0.join("swift-cache")).arg(repo.join("monitor/ControlledEntry/ControlledEntryApp.swift"))
        .arg(repo.join("monitor/Sources/BoundedDiagnosticLog.swift")).arg("-o").arg(&wrapper_component).output().unwrap()).status.success());
    let hashes = ["watch-engine","watch-sandbox-launcher","watch-process-control","ControlledEntry"].into_iter()
        .map(|name| (name, sha256_file_hex(&runtime_dir.join(name)).unwrap())).collect::<std::collections::BTreeMap<_,_>>();
    plist(&runtime_dir.join("BuildInfo.plist"), &json!({"Architecture":"arm64","NetworkBackend":"seatbelt","RuntimeHashes":hashes,"RuntimeCDHashes":{"watch-sandbox-launcher":helper_cdhash}}));
    fs::write(runtime_dir.join("components.json"), hardened_helper::components(&helper).to_string()).unwrap();
    let endpoint = TcpListener::bind("127.0.0.1:0").unwrap();
    endpoint.set_nonblocking(true).unwrap();
    let endpoint_addr = endpoint.local_addr().unwrap();
    let mut config = fixtures::config(&storage, &endpoint_addr.to_string());
    config.online_enabled = true;
    (ConfigStore { storage:storage.clone() }).save(config.value().unwrap()).unwrap();
    let mut workers = Workers(Arc::new(AtomicBool::new(false)), Vec::new());
    let worker_stop = workers.0.clone();
    workers.1.push(thread::spawn(move || {
        while !worker_stop.load(Ordering::Acquire) {
            match endpoint.accept() {
                Ok((stream, _)) => upstream(stream),
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(5)),
                Err(err) => panic!("private echo accept: {err}"),
            }
        }
    }));

    let bin = home.join(".local/bin");
    let cli = home.join(".local/share/claude/versions/fixture");
    let app = home.join("Applications/Claude.app");
    let desktop = app.join("Contents/MacOS/Claude");
    let helper_image = app.join("Contents/Frameworks/Owned Helper.app/Contents/MacOS/OwnedHelper");
    let ordinary_image = home.join("ordinary-tool");
    let entries = home.join("Entries");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(cli.parent().unwrap()).unwrap();
    fs::create_dir_all(desktop.parent().unwrap()).unwrap();
    fs::create_dir_all(helper_image.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&cli, bin.join("claude")).unwrap();
    plist(&app.join("Contents/Info.plist"), &json!({"CFBundleIdentifier":"com.anthropic.claudefordesktop",
        "CFBundleName":"Claude","CFBundleExecutable":"Claude","CFBundlePackageType":"APPL"}));
    for (role, path) in [("cli",&cli),("desktop",&desktop),("helper",&helper_image),("ordinary",&ordinary_image)] {
        assert!(output("compile private target", Command::new("xcrun").args(["clang", "-Wall", "-Werror", "-O0"])
            .arg(format!("-DFIXTURE_ROOT=\"{}\"", root.0.display())).arg(format!("-DFIXTURE_ROLE=\"{role}\""))
            .arg(format!("-DFIXTURE_UPSTREAM={}", endpoint_addr.port()))
            .arg(format!("-DFIXTURE_HELPER=\"{}\"", helper_image.display()))
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/support/ready_entry_target.c")).arg("-o").arg(path).output().unwrap()).status.success());
    }
    let audit_ready = Arc::new(AtomicBool::new(false));
    let release_audit = Arc::clone(&audit_ready);
    let audit_store = storage.clone();
    let (audits, audit_records) = mpsc::channel();
    let vpn_revision = Arc::new(AtomicU64::new(1));
    let mut production = OwnedStack(Some(assemble_production_channel_stack_with_vpn_reader(
        storage.clone(), workers.0.clone(), false, Some(Arc::new(FixtureVpn { revision: vpn_revision.clone() })),
        move |req| {
            let until = Instant::now() + Duration::from_secs(3);
            while !release_audit.load(Ordering::Acquire) {
                if Instant::now() >= until || req.cancellation.as_ref().is_some_and(|flag| flag.load(Ordering::Acquire)) {
                    return Err(CoreError::new("fixture_audit_cancelled", "等待夹具观察待验证状态超时"));
                }
                thread::sleep(Duration::from_millis(5));
            }
            let result = run_fixture_audit(&audit_store, req);
            let row = match &result {
                Ok((audit, egress, completed_at)) => json!({
                    "request_id":req.request_id,"family":req.family,"target":req.target,"session_id":req.session_id,
                    "requested_at":req.requested_at,"request_vpn_epoch":req.vpn_epoch,"policy_version":req.policy_version,
                    "audit_observation_id":audit["observation_id"],"audit_ready":audit["ready"],
                    "audit_context":audit["context_id"],"egress":egress,"completed_at":completed_at,
                }),
                Err(err) => json!({"request_id":req.request_id,"error":err.code,"detail":err.message}),
            };
            let _ = audits.send(row);
            result
        },
    ).unwrap()));
    let stack = production.0.as_mut().unwrap();
    let registry = stack.sandbox_registry.as_ref().unwrap().clone();
    stack.enforcer.set_upstream_connector(move |_| Ok(TunnelStream::Tcp(TcpStream::connect(endpoint_addr)?))).unwrap();
    let source_deadline = Instant::now() + Duration::from_secs(5);
    let staged = storage.paths.watch().join("entries/entries-manifest.json");
    while !staged.is_file() || !registry.is_target_approved(cli.to_str().unwrap()) ||
        !registry.is_target_approved(desktop.to_str().unwrap()) || registry.executable_verification_counts().2 < 3 {
        assert!(Instant::now() < source_deadline, "production discovery did not stage and verify fixture executables");
        thread::sleep(Duration::from_millis(10));
    }

    let private_command = |path: &Path| {
        let mut c = Command::new(path);
        c.env_clear().env("HOME", &home).env(PRIVATE_HOME, &home).env("PATH", "/usr/bin:/bin").current_dir(&home);
        c
    };
    let entry = |action: &str, target: LaunchTarget| {
        let mut c = private_command(&engine);
        c.args(["entry",action,"--target",target.as_str(),"--home"]).arg(&home);
        if !target.cli() { c.arg("--target-bundle").arg(&app).arg("--applications-dir").arg(&entries); }
        if action == "activate" { c.arg("--apply"); }
        let out = output("engine entry dispatch", c.output().unwrap());
        assert!(out.status.success(), "{out:?}");
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };
    let shim = PathBuf::from(entry("activate", LaunchTarget::ClaudeCli)["result"]["installed_path"].as_str().unwrap());
    let bundle = PathBuf::from(entry("activate", LaunchTarget::ClaudeDesktop)["result"]["installed_path"].as_str().unwrap());
    let wrapper = bundle.join("Contents/MacOS/ControlledEntry");
    let runtime_path = storage.paths.watch().join("state/seatbelt-runtime.json");
    let mut ordinary = OwnedChild(private_command(&ordinary_image).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(2);
    let ordinary_identity = loop {
        if let Some(identity) = inspect_process_identity(ordinary.0.id()).filter(|id| Path::new(&id.executable_path) == ordinary_image) { break identity; }
        assert!(Instant::now() < deadline, "ordinary owned process did not exec");
        thread::sleep(Duration::from_millis(10));
    };
    let no_collector = output("desktop entry refuses missing collector readiness",
        private_command(&wrapper).arg("--reopen").output().unwrap());
    assert!(!no_collector.status.success()
        && String::from_utf8_lossy(&no_collector.stdout).contains("backend_unhealthy"));
    assert!(!root.0.join("desktop.ready").exists() && registry.instances().is_empty());
    fs::write(root.0.join("collector-ready"), b"private fixture only").unwrap();
    let unresolved = root.0.join("unreadable-owned-process");
    fs::write(&unresolved, ordinary_identity.pid.to_string()).unwrap();
    let partial = output("ready collector with one unreadable owned identity still refuses desktop launch",
        private_command(&wrapper).arg("--reopen").output().unwrap());
    let partial_output = String::from_utf8_lossy(&partial.stdout);
    assert!(!partial.status.success() && partial_output.contains("target_inventory_incomplete")
        && partial_output.contains("unavailable_count=1") && partial_output.contains("identity_unavailable:1")
        && partial_output.contains("unaccounted_count=0"));
    assert!(!root.0.join("desktop.ready").exists() && registry.instances().is_empty());
    assert_eq!(inspect_process_identity(ordinary.0.id()), Some(ordinary_identity.clone()));
    fs::remove_file(unresolved).unwrap();
    let runtime_closed = storage.read_json(&runtime_path, Value::Null).unwrap();
    assert_eq!(runtime_closed["sandbox_ready"], false);
    assert_eq!(runtime_closed["identity_report"]["blocker_code"], "gateway_server_identity_unverified_i03");
    fixtures::seed_probe_receipts(&storage, native::now(), "JP");
    let denied = output("I03 remains closed in the same engine dispatch", private_command(&shim).arg("private-argument").output().unwrap());
    assert!(!denied.status.success() && String::from_utf8_lossy(&denied.stdout).contains("seatbelt_identity_gate_blocked"));
    assert!(registry.instances().is_empty());

    stack.start_private_loopback_backend().unwrap();
    let ready = storage.read_json(&runtime_path, Value::Null).unwrap();
    assert_eq!(ready["sandbox_ready"], true, "{ready}");
    assert_eq!(ready["identity_report"]["gateway_endpoint_protection_verified"], false);
    let reader = ScopedReader { system: Arc::new(SystemRunner::new(&runtime_dir.join("watch-native-observer")).unwrap()), home: home.clone() };
    let mut native_desktop = claude_watch_runtime::desktop_native::NativeDesktop::new(
        reader, runtime_dir.join("watch-process-control"), Authority::ExplicitPermit,
    ).unwrap();
    native_desktop.set_discovery(DiscoveryHandle::for_home(&home));
    let mut fixture_system = FixtureSystem { collector_ready: true };
    let mut system = DesktopRuntime {
        desktop: &mut native_desktop, network: NetworkClient::new(Arc::new(FixtureTransport), None).unwrap(),
        system: &mut fixture_system, storage: storage.clone(), started: Instant::now(), cli: None,
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let startup = stack.step_with_system(&mut system).unwrap();
        if startup.families["claude"].vpn_match.as_ref().is_some_and(|m| m.is_matched()) { break; }
        assert!(Instant::now() < deadline, "production VPN observation did not arrive");
        stack.wait_or_drain(deadline, &workers.0);
    }
    let sessions = SessionStore::for_family(storage.clone(), "claude");
    let mut proof = Vec::new();
    for (role, target, path, image) in [("cli",LaunchTarget::ClaudeCli,&shim,&cli), ("desktop",LaunchTarget::ClaudeDesktop,&wrapper,&desktop)] {
        audit_ready.store(false, Ordering::Release);
        assert!(sessions.load(native::now()).unwrap().is_none_or(|s| s.state == Phase::Ended));
        fixtures::seed_probe_receipts(&storage, native::now(), "JP");
        let mut command = private_command(path);
        command.arg(if target.cli() { "private-argument" } else { "--reopen" });
        let mut launcher = OwnedChild(command.stdout(Stdio::inherit()).stderr(Stdio::inherit()).spawn().unwrap());
        let ready = wait_read(&root.0.join(format!("{role}.ready")), "READY ");
        let pid = ready.split_whitespace().nth(1).unwrap().parse().unwrap();
        let identity = inspect_process_identity(pid).unwrap();
        assert_eq!(Path::new(&identity.executable_path), image);
        let own_target = OwnedTarget(identity.clone());
        let helper_pid: Option<u32> = (!target.cli()).then(|| {
            wait_read(&root.0.join("helper.ready"), "READY ").split_whitespace().nth(1).unwrap().parse().unwrap()
        });
        let own_helper = helper_pid.map(|pid| {
            let identity = inspect_process_identity(pid).unwrap();
            assert_eq!(identity.ppid, own_target.0.pid);
            assert_eq!(Path::new(&identity.executable_path), helper_image);
            OwnedTarget(identity)
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        let pending = loop {
            let snapshot = stack.step_with_system(&mut system).unwrap();
            let state = &snapshot.families["claude"];
            if state.active_members.iter().any(|member| member.pid == pid)
                && helper_pid.is_none_or(|pid| state.active_members.iter().any(|t| t.pid == pid)) { break snapshot; }
            assert!(Instant::now() < deadline, "production stack did not discover registered fixture: {state:?}");
            stack.wait_or_drain(deadline, &workers.0);
        };
        assert_eq!(pending.families["claude"].permit_state, ChannelPermitState::PendingVerification, "{pending:?}");
        assert!(sessions.load(native::now()).unwrap().is_none_or(|s| s.state == Phase::Ended));
        stack.supervisor.drain_emitted_events();
        audit_ready.store(true, Ordering::Release);
        // Wait for the worker's real result, then leave it queued while the
        // executor's deadline clock advances. No event or session is injected.
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut known_audits = Vec::new();
        let completed_before_delivery = loop {
            let row = audit_records.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| panic!("no initial audit for {target:?}: {known_audits:?}"));
            let completed = row["completed_at"].as_f64().filter(|_| row["audit_ready"] == true
                && row["target"] == json!(target) && row["session_id"].is_null());
            known_audits.push(row);
            if let Some(completed) = completed { break completed; }
        };
        thread::sleep(Duration::from_millis(120));
        let watchdog_at = native::now();
        assert!(watchdog_at - completed_before_delivery > claude_watch_core::channel::CLOCK_ROLLBACK_TOLERANCE_SECONDS);
        stack.enforcer.enforce_active_deadlines(watchdog_at, false).unwrap();
        assert!(sessions.load(watchdog_at).unwrap().is_none_or(|s| s.state == Phase::Ended));
        let deadline = Instant::now() + Duration::from_secs(6);
        let mut events = Vec::new();
        let mut refresh = None;
        let projection = loop {
            let snapshot = stack.step_with_system(&mut system).unwrap();
            events.extend(stack.supervisor.drain_emitted_events());
            let state = &snapshot.families["claude"];
            if refresh.is_none() {
                if let Some(adoption) = events.iter().find(|event| event.family_state.family == "claude"
                    && event.family_state.reason_code == "session_adopted") {
                    // Reproduce the original race deterministically through the
                    // synthetic reader, not an injected permit/session/event.
                    let revision = vpn_revision.fetch_add(1, Ordering::AcqRel) + 1;
                    refresh = Some((revision, adoption.family_state.vpn_epoch.clone()));
                }
            }
            if state.permit_state == ChannelPermitState::Permitted && state.display_state == ChannelMonitorDisplayState::Forwarding {
                if let Some((revision, adopted_epoch)) = &refresh {
                    let vpn: Value = claude_watch_runtime::channel_policy_status::read_frame(&storage)["vpn_supervision"].clone();
                    if state.vpn_epoch != *adopted_epoch && vpn["observation"]["source_revision"] == format!("rev-{revision}") {
                        break snapshot;
                    }
                }
            }
            if Instant::now() >= deadline {
                let timeline: Vec<_> = events.iter()
                    .filter(|event| event.family_state.family == "claude")
                    .map(|event| (event.family_state.updated_at, event.family_state.command_seq,
                        event.family_state.permit_state, &event.family_state.reason_code, &event.family_state.vpn_epoch)).collect();
                eprintln!("production adoption event timeline: {timeline:?}");
                known_audits.extend(audit_records.try_iter());
                panic!("no automatically adopted and reverified session: {state:?}; audits={known_audits:?}");
            }
            stack.wait_or_drain(deadline, &workers.0);
        };
        let state = &projection.families["claude"];
        let adopted = sessions.load(native::now()).unwrap().unwrap();
        // A completed request can have been superseded before the supervisor
        // saw its result. Attribute the adoption to the actual audit ID in
        // the new session, rather than the next record on the worker channel.
        let audit_deadline = Instant::now() + Duration::from_secs(1);
        let audit = loop {
            if let Some(index) = known_audits.iter().position(|row| row["audit_observation_id"] == adopted.audit_observation_id) {
                break known_audits[index].clone();
            }
            let row = audit_records.recv_timeout(audit_deadline.saturating_duration_since(Instant::now())).unwrap_or_else(|_| {
                panic!("audit for adopted observation {} not captured: {known_audits:?}", adopted.audit_observation_id)
            });
            known_audits.push(row);
        };
        assert_eq!(audit["target"], json!(target), "adopted session must bind this target: {audit}");
        assert_eq!(audit["audit_ready"], true);
        assert_eq!(audit["session_id"], Value::Null, "new adoption cannot start with a hand-built session");
        let adoption = events.iter().find(|event| {
            let state = &event.family_state;
            state.family == "claude" && state.session_id.as_deref() == Some(adopted.session_id.as_str())
                && state.reason_code == "session_adopted" && state.permit_state == ChannelPermitState::Permitted
        }).expect("the production supervisor must emit this session's adoption");
        assert!(adoption.family_state.vpn_epoch.as_ref().is_some_and(VpnEpoch::is_valid));
        assert_eq!(audit["request_vpn_epoch"], json!(adoption.family_state.vpn_epoch));
        assert_eq!(audit["egress"]["vpn_epoch"], json!(adoption.family_state.vpn_epoch));
        assert_eq!(audit["policy_version"], json!(adoption.family_state.saved_policy_version));
        assert_eq!(audit["egress"]["policy_version"], audit["policy_version"]);
        assert_eq!(audit["egress"]["via_controlled_path"], true);
        let queue_age = watchdog_at - audit["completed_at"].as_f64().unwrap();
        assert!(queue_age > claude_watch_core::channel::CLOCK_ROLLBACK_TOLERANCE_SECONDS,
            "expected the adopted audit to have waited past the executor's clock tolerance: {queue_age}");
        assert_eq!(audit["audit_observation_id"], adopted.audit_observation_id);
        assert_eq!(adopted.state, Phase::Active);
        assert_eq!(adopted.extra["adopted_from"], "running_processes");
        assert_eq!(adopted.extra["channel_processes_v1"], json!(state.active_members));
        assert_eq!(state.session_id.as_deref(), Some(adopted.session_id.as_str()));
        // The observer may invalidate/refresh its epoch before Forwarding is
        // visible. Recovery preserves the initial audit ID but replaces the
        // session baseline. Bind the final permission to that actual baseline,
        // rather than falsely requiring the adoption epoch to last forever.
        let current_audit = loop {
            if let Some(row) = known_audits.iter().find(|row|
                Egress::parse(&row["egress"], projection.captured_at).map(persisted_egress).as_ref() == Some(&adopted.baseline)) {
                break row.clone();
            }
            let row = audit_records.recv_timeout(audit_deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| panic!("audit for current session baseline not captured: {adopted:?}; audits={known_audits:?}"));
            known_audits.push(row);
        };
        let current_authority = events.iter().rev().find(|event| {
            let authority = &event.family_state;
            authority.family == "claude" && authority.session_id == state.session_id
                && authority.permit_generation == state.permit_generation
                && authority.permit_state == ChannelPermitState::Permitted
                && matches!(authority.reason_code.as_str(), "session_adopted" | "channel_recovered")
        }).expect("current permission must come from an observed adoption or verified recovery");
        assert_eq!(current_authority.family_state.reason_code, "channel_recovered");
        assert_ne!(current_authority.family_state.vpn_epoch, adoption.family_state.vpn_epoch);
        assert_eq!(current_authority.family_state.vpn_epoch, state.vpn_epoch);
        assert!(current_authority.family_state.command_seq <= state.command_seq);
        assert_eq!(current_audit["target"], json!(target));
        assert_eq!(current_audit["audit_ready"], true);
        assert_eq!(current_audit["request_vpn_epoch"], json!(state.vpn_epoch));
        assert_eq!(current_audit["egress"]["vpn_epoch"], json!(state.vpn_epoch));
        assert_eq!(current_audit["policy_version"], json!(state.saved_policy_version));
        assert_eq!(current_audit["egress"]["policy_version"], current_audit["policy_version"]);
        assert_eq!(current_audit["egress"]["via_controlled_path"], true);
        assert_eq!(current_audit["audit_context"], adopted.context_id);
        assert_eq!(Egress::fresh(&current_audit["egress"], projection.captured_at, GUARD_EGRESS_TTL).map(persisted_egress), Some(adopted.baseline.clone()));
        assert!(current_audit["completed_at"].as_f64().unwrap() <= current_authority.family_state.updated_at);
        if current_authority.family_state.reason_code == "session_adopted" {
            assert_eq!(current_audit["audit_observation_id"], audit["audit_observation_id"]);
            assert_eq!(current_audit["session_id"], Value::Null);
        } else {
            assert_ne!(current_audit["audit_observation_id"], audit["audit_observation_id"]);
            assert_eq!(current_audit["session_id"], adopted.session_id);
        }
        let vpn: Value = claude_watch_runtime::channel_policy_status::read_frame(&storage)["vpn_supervision"].clone();
        assert_eq!(vpn["observation"]["epoch"], json!(state.vpn_epoch));
        assert!(vpn["observation"]["valid_until"].as_f64().unwrap() > projection.captured_at);
        assert!(state.vpn_match.as_ref().is_some_and(|m| m.is_matched()));
        let receipt = stack.enforcer.receipt_for("claude", native::now()).unwrap().unwrap();
        assert_eq!(receipt.session_id, state.session_id);
        assert_eq!(receipt.command_seq, state.command_seq);
        assert_eq!(receipt.vpn_epoch, state.vpn_epoch);
        assert_eq!(receipt.executor_boot_id, stack.enforcer.boot_id().unwrap());
        assert_eq!(current_audit["egress"]["executor_boot_id"], receipt.executor_boot_id);
        let observed = entry("status", target);
        assert_eq!(observed["status_report"]["active_managed_count"], 1);
        assert_eq!(observed["status_report"]["protected_instance_count"], 0, "fixture readiness is not I03");
        assert_eq!(observed["status_report"]["unmanaged_pids"], json!([]));
        assert_eq!(observed["status_report"]["pending_pids"], json!([]));
        if helper_pid.is_some() {
            assert_eq!(entry("activate", target)["status"], "ok", "update must accept a verified live helper");
        }
        fs::write(root.0.join(format!("{role}.go")), b"go").unwrap();
        let tunneled = wait_read(&root.0.join(format!("{role}.result")), "TUNNEL_OK ");
        assert_eq!(tunneled.trim(), format!("TUNNEL_OK {pid}"));
        assert!(inspect_process_identity(pid).is_some_and(|live| live.uid == identity.uid && live.audit_token == identity.audit_token));
        fs::write(root.0.join(format!("{role}.stop")), b"stop").unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        let exit = loop {
            if let Some(exit) = launcher.0.try_wait().unwrap() { break exit; }
            assert!(Instant::now() < deadline, "entry did not complete");
            thread::sleep(Duration::from_millis(10));
        };
        assert!(exit.success(), "generated {role} entry: {exit}");
        proof.push(json!({"role":role,"pid":pid,"helper_pid":helper_pid,"native_registry":true,"gateway_round_trip":tunneled.trim(),
            "fixture_readiness_only":true,"entry_exit":exit.code(),"status_report":observed["status_report"],
            "pending":pending,"audit":audit,"adoption_event":adoption,"current_audit":current_audit,
            "current_authority_event":current_authority,"vpn_observation":vpn["observation"],"events":events,
            "other_audit_count":known_audits.len().saturating_sub(1),"queue_age_seconds":queue_age,
            "watchdog_at_before_delivery":watchdog_at,
            "adopted":adopted,"applied":projection,"enforcer_receipt":receipt}));
        drop(own_helper);
        drop(own_target);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let snapshot = stack.step_with_system(&mut system).unwrap();
            if snapshot.families["claude"].active_members.is_empty() {
                assert_eq!(sessions.load(native::now()).unwrap().unwrap().state, Phase::Ended);
                break;
            }
            assert!(Instant::now() < deadline, "owned target did not leave production inventory");
            stack.wait_or_drain(deadline, &workers.0);
        }
    }
    assert!(ordinary.0.try_wait().unwrap().is_none());
    assert_eq!(inspect_process_identity(ordinary.0.id()), Some(ordinary_identity));
    println!("{}", json!(proof));
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::write(Path::new(&dir).join("ready-entry-production-adoption.json"), serde_json::to_vec_pretty(&proof).unwrap()).unwrap();
    }
    println!("test generated_cli_and_desktop_entries_use_engine_helper_and_gateway ... ok\n\ntest result: ok. 1 passed; 0 failed");
}
