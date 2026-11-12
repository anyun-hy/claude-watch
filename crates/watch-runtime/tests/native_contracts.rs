use claude_watch_core::{
    process_roots::{self, Classification, RootEvidence, TrustedCliPaths},
    processes::{Identity, Kind},
};
use claude_watch_runtime::{
    commands::{ObserverAction, Output, ReadCommand, ReadRunner, SystemRunner},
    native::{self, Observer},
    sampler::{parse_process_table, Sampler},
    storage::Paths,
};
use serde_json::{json, Value};
use std::{
    fs,
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;
#[path = "support/fixture_inventory.rs"]
mod fixture_inventory;

#[test]
fn sampler_refreshes_supported_cli_aliases_without_broadening_ordinary_processes() {
    use claude_watch_core::processes::MatchReason;
    use fixture_inventory::{FixtureInventory, FixtureProcess};
    use std::{os::unix::{fs::{symlink, PermissionsExt}}, sync::{Arc, Mutex}};
    let home = PathBuf::from("/private/tmp").join(format!("cw-alias-{}", Uuid::new_v4()));
    fs::create_dir_all(home.join(".local/bin")).unwrap();
    let a = home.join("image-a"); let b = home.join("image-b");
    for path in [&a, &b] { fs::write(path, b"private fixture").unwrap(); fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap(); }
    let alias = home.join(".local/bin/codex");
    let process = |pid, path: &Path| { let mut p = identity(); p.pid = pid; p.executable = path.to_string_lossy().into_owned(); FixtureProcess { identity:p, bundle:None, arguments:vec!["ordinary".into()] } };
    let mut node = process(78, Path::new("/usr/local/bin/node"));
    node.arguments = vec!["node".into(), "/other/script.js".into(), "/node_modules/@openai/codex/bin/codex.js".into()];
    let ordinary = vec![node, process(79, Path::new("/usr/bin/python3")), process(80, Path::new("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal"))];
    let records = Arc::new(Mutex::new(ordinary.clone()));
    records.lock().unwrap().push(process(77, &a));
    let mut sampler = Sampler::new(FixtureInventory(records.clone()), Paths::new(&home).unwrap());
    assert!(sampler.processes().unwrap().targets.is_empty());
    symlink(&a, &alias).unwrap();
    let created = sampler.processes().unwrap();
    assert_eq!(created.targets.len(), 1);
    assert_eq!(created.match_evidence[&77].reason, MatchReason::SupportedCliAlias);
    fs::remove_file(&alias).unwrap(); symlink(&b, &alias).unwrap();
    records.lock().unwrap().extend([process(81, &b), process(82, &a)]);
    let retargeted = sampler.processes().unwrap();
    assert_eq!(retargeted.match_evidence[&81].reason, MatchReason::SupportedCliAlias);
    assert_eq!(retargeted.match_evidence[&77].reason, MatchReason::RetainedLifetime);
    assert!(!retargeted.targets.iter().any(|p| p.identity.pid == 82));
    // New lifetimes cannot inherit either the old trusted alias or tracking.
    fs::remove_file(&alias).unwrap(); symlink(home.join("missing"), &alias).unwrap();
    *records.lock().unwrap() = ordinary.clone(); records.lock().unwrap().push(process(83, &b));
    assert!(sampler.processes().unwrap().targets.is_empty());
    fs::remove_file(&alias).unwrap();
    *records.lock().unwrap() = ordinary; records.lock().unwrap().push(process(84, &b));
    assert!(sampler.processes().unwrap().targets.is_empty());
    fs::remove_dir_all(home).unwrap();
}

fn identity() -> Identity {
    Identity {
        pid: 77,
        parent: 1,
        uid: 501,
        executable: "/Applications/Claude.app/Contents/MacOS/Claude".into(),
        start_seconds: 1000,
        start_microseconds: 1,
        start_stamp: "Tue Nov 14 22:12:50 2023".into(),
    }
}
fn envelope() -> Value {
    json!({"schema":1,"status":"ok","uid":501,"started_at":1001.0,"finished_at":1002.0,"round_id":"round"})
}
#[test]
fn root_classification_requires_bundle_or_real_script_entry_not_argument_substrings() {
    let home = Path::new("/fixture");
    let trusted = TrustedCliPaths::default();
    let mut p = identity();
    let classify =
        |p: &Identity, args: Option<&[String]>, bundle: Option<&str>, id: Option<&str>| {
            process_roots::classify(
                RootEvidence {
                    identity: p,
                    arguments: args,
                    bundle_path: bundle,
                    bundle_id: id,
                    cwd: Some("/fixture"),
                },
                home,
                &trusted,
                |_| None,
            )
        };
    assert_eq!(
        classify(
            &p,
            None,
            Some("/Applications/Claude.app"),
            Some("com.anthropic.claudefordesktop")
        ),
        Classification::Root(Kind::ClaudeMain)
    );
    assert_eq!(
        classify(
            &p,
            None,
            Some("/Applications/Claude.app"),
            Some("wrong.identifier")
        ),
        Classification::NotTarget
    );
    p.executable = "/usr/local/bin/node".into();
    assert_eq!(
        classify(&p, None, None, None),
        Classification::NeedArguments
    );
    for args in [
        vec![
            "node",
            "-e",
            "/tmp/node_modules/@anthropic-ai/claude-code/cli.js",
        ],
        vec![
            "node",
            "/other/script",
            "/tmp/node_modules/@anthropic-ai/claude-code/cli.js",
        ],
        vec!["node", "--eval", "anything"],
    ] {
        let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
        assert_eq!(
            classify(&p, Some(&args), None, None),
            Classification::NotTarget
        );
    }
    let args = vec![
        "node".into(),
        "--require".into(),
        "safe-loader".into(),
        "/tmp/node_modules/@anthropic-ai/claude-code/cli.js".into(),
    ];
    assert_eq!(
        classify(&p, Some(&args), None, None),
        Classification::Root(Kind::ClaudeCode)
    );
}

#[test]
fn root_classification_emits_the_reason_of_the_selected_branch() {
    use claude_watch_core::processes::MatchReason;
    let home = Path::new("/fixture");
    let mut trusted = TrustedCliPaths::default(); trusted.codex.insert("/fixture/image".into());
    let mut p = identity();
    let cases = [
        ("/fixture/image", None, None, vec![], MatchReason::SupportedCliAlias),
        ("/opt/homebrew/Caskroom/codex/v/bin/codex", None, None, vec![], MatchReason::KnownCliLayout),
        ("/Applications/Claude.app/Contents/MacOS/Claude", Some("/Applications/Claude.app"), Some("com.anthropic.claudefordesktop"), vec![], MatchReason::VerifiedBundle),
        ("/Applications/Codex.app/Contents/Resources/codex", Some("/Applications/Codex.app"), Some("com.openai.codex"), vec![], MatchReason::VerifiedBundleComponent),
        ("/usr/local/bin/node", None, None, vec!["node", "/fixture/node_modules/@openai/codex/bin/codex.js"], MatchReason::ScriptEntry),
        ("/fixture/.codex/packages/app-server-daemon/releases/v/bin/codex", None, None, vec!["codex", "app-server", "daemon"], MatchReason::ManagedAppServer),
    ];
    for (path, bundle, id, args, reason) in cases {
        p.executable = path.into(); let args: Vec<_> = args.into_iter().map(str::to_owned).collect();
        let found = process_roots::classify_with_evidence(RootEvidence { identity:&p, bundle_path:bundle, bundle_id:id, arguments:Some(&args), cwd:Some("/fixture") }, home, &trusted, |_| None);
        assert!(matches!(found.classification, Classification::Root(_))); assert_eq!(found.reason, Some(reason));
    }
    p.executable = "/usr/local/bin/node".into();
    let args = vec!["node".into(), "-e".into(), "/fixture/node_modules/@openai/codex/bin/codex.js".into()];
    let ordinary = process_roots::classify_with_evidence(RootEvidence { identity:&p, bundle_path:None, bundle_id:None, arguments:Some(&args), cwd:Some("/fixture") }, home, &trusted, |_| None);
    assert_eq!(ordinary.classification, Classification::NotTarget); assert_eq!(ordinary.reason, None);
}
#[test]
fn native_protocol_rejects_replay_foreign_identity_duplicates_and_conflicting_rounds() {
    let p = identity();
    let mut inv = envelope();
    inv["state"] = json!("ok");
    inv["truncated"] = json!(false);
    inv["processes"] = json!([p]);
    inv["unavailable"] = json!([]);
    inv["exited"] = json!([]);
    inv["requested_count"] = json!(1);
    assert!(
        native::decode_inventory(&inv, 1000.0, 1003.0)
            .unwrap()
            .complete
    );
    let mut ended_inventory = inv.clone();
    ended_inventory["exited"] = json!([99]); ended_inventory["requested_count"] = json!(2);
    let ended_result = native::decode_inventory(&ended_inventory, 1000.0, 1003.0).unwrap();
    assert!(ended_result.complete);
    assert_eq!(ended_result.confirmed_exited_count, 1);
    assert!(ended_result.diagnostic_reasons.is_empty());
    let mut duplicate = inv.clone();
    duplicate["processes"] = json!([p, p]);
    assert!(native::decode_inventory(&duplicate, 1000.0, 1003.0).is_err());
    let mut foreign = inv.clone();
    foreign["processes"][0]["uid"] = json!(502);
    assert!(native::decode_inventory(&foreign, 1000.0, 1003.0).is_err());
    assert!(native::decode_inventory(&inv, 1010.0, 1011.0).is_err());
    let mut sockets = envelope();
    sockets["socket_samples"] = json!([{"pid":77,"state":"ok","identity":p,"sockets":[{"pid":77,"fd":5,"socket_state":4,"protocol":"tcp","local":["198.18.0.1",50000],"peer":["198.18.1.10",443]}],"dropped":{}}]);
    let result =
        native::decode_sockets(&sockets, std::slice::from_ref(&p), "round", 1000.0, 1003.0)
            .unwrap();
    assert!(result.complete);
    assert_eq!(result.flows.len(), 1);
    assert!(
        native::decode_sockets(&sockets, std::slice::from_ref(&p), "wrong", 1000.0, 1003.0)
            .is_err()
    );
    sockets["socket_samples"][0]["identity"]["start_microseconds"] = json!(2);
    let changed =
        native::decode_sockets(&sockets, std::slice::from_ref(&p), "round", 1000.0, 1003.0)
            .unwrap();
    assert!(!changed.complete);
    assert!(changed.flows.is_empty());
}
struct FakeRunner { bundle:PathBuf }
impl FakeRunner {
    fn new(home:&Path)->Self {
        use std::os::unix::fs::PermissionsExt;
        let bundle=fs::canonicalize(home).unwrap().join("Applications/Private Client.app");
        fs::create_dir_all(bundle.join("Contents/MacOS")).unwrap();
        let file=bundle.join("Contents/MacOS/PrivateMain");fs::write(&file,b"private native fixture; never executed").unwrap();
        fs::set_permissions(file,fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(bundle.join("Contents/Info.plist"),r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.anthropic.claudefordesktop</string><key>CFBundleExecutable</key><string>PrivateMain</string></dict></plist>"#).unwrap();
        Self {bundle}
    }
}
impl ReadRunner for FakeRunner {
    fn run(
        &self,
        command: ReadCommand,
        input: &[u8],
        _timeout: Duration,
        _limit: usize,
    ) -> claude_watch_core::error::Result<Output> {
        let now = native::now();
        let mut p = identity();p.executable=self.bundle.join("Contents/MacOS/PrivateMain").to_string_lossy().into_owned();
        let mut v = json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now});
        match command {
            ReadCommand::Observer(ObserverAction::Inventory) => {
                let mut record = json!(p);
                record["bundle_path"] = json!(self.bundle);
                record["bundle_id"] = json!("com.anthropic.claudefordesktop");
                v["state"] = json!("ok");
                v["truncated"] = json!(false);
                v["processes"] = json!([record]);
                v["unavailable"] = json!([]);
                v["exited"] = json!([]);
                v["requested_count"] = json!(1);
            }
            ReadCommand::Observer(ObserverAction::Arguments) => {
                let request: Value = serde_json::from_slice(input).unwrap();
                v["round_id"] = request["round_id"].clone();
                v["argument_prefixes"] = json!([{"pid":77,"state":"ok","identity":p,"arguments":["Claude","DO_NOT_EMIT_token"],"cwd":"/fixture","truncated":false}]);
            }
            ReadCommand::Observer(ObserverAction::Sockets) => {
                let request: Value = serde_json::from_slice(input).unwrap();
                v["round_id"] = request["round_id"].clone();
                v["socket_samples"] =
                    json!([{"pid":77,"state":"ok","identity":p,"sockets":[],"dropped":{}}]);
            }
            ReadCommand::Plist(path)=> {
                assert_eq!(path,self.bundle.join("Contents/Info.plist"));
                return SystemRunner::development()?.run(ReadCommand::Plist(path),input,_timeout,_limit);
            }
            _ => panic!("unexpected native test command"),
        }
        Ok(Output {
            status: 0,
            stdout: serde_json::to_vec(&v).unwrap(),
            stderr: Vec::new(),
        })
    }
}
#[test]
fn sampler_strips_private_argv_and_empty_socket_sample_is_not_a_network_change() {
    let home = std::env::temp_dir().join(format!("cw-native-fixture-{}", Uuid::new_v4()));
    fs::create_dir(&home).unwrap();
    let mut sampler = Sampler::new(FakeRunner::new(&home), Paths::new(&home).unwrap());
    let process = sampler.processes().unwrap();
    assert!(process.complete);
    assert_eq!(process.targets.len(), 1);
    assert!(!process.public_value().to_string().contains("DO_NOT_EMIT"));
    let socket = sampler.sockets(&process).unwrap();
    assert_eq!(socket.receipt["collector_state"], "empty");
    assert_eq!(socket.receipt["target_count"], 1);
    assert!(!home.join("Library").exists());
    fs::remove_dir_all(home).unwrap();
}
#[test]
fn ps_metadata_keeps_executable_spaces_and_rejects_duplicate_pid_identity() {
    let line =
        " 77 1 501 Tue Nov 14 22:12:50 2023 /fixture/Some Application.app/Contents/MacOS/Client\n";
    let rows = parse_process_table(line).unwrap();
    assert_eq!(rows[&77]["stamp"], "Tue Nov 14 22:12:50 2023");
    assert_eq!(
        rows[&77]["executable"],
        "/fixture/Some Application.app/Contents/MacOS/Client"
    );
    assert!(parse_process_table(&format!("{line}{line}")).is_err());
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn real_native_observer_reads_only_bound_self_socket_and_rejects_reused_identity() {
    let runner = SystemRunner::development().unwrap();
    let observer = Observer { runner: &runner };
    let inv = observer.inventory().unwrap();
    let current = inv
        .processes
        .get(&std::process::id())
        .expect("test process in owned native inventory")
        .identity
        .clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).unwrap();
    let (server, _) = listener.accept().unwrap();
    let result = observer
        .sockets(std::slice::from_ref(&current), "real-socket-round")
        .unwrap();
    assert!(result
        .flows
        .iter()
        .any(|f| f.pid == current.pid && f.peer.0 == "127.0.0.1" && f.peer.1 == address.port()));
    let arguments = observer
        .arguments(std::slice::from_ref(&current), "real-arguments-round")
        .unwrap();
    assert!(arguments.contains_key(&current.pid));
    let mut reused = current;
    reused.start_microseconds = (reused.start_microseconds + 1) % 1_000_000;
    let rejected = observer.sockets(&[reused], "reused-round").unwrap();
    assert!(!rejected.complete);
    assert!(rejected.flows.is_empty());
    drop((client, server));
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn own_sampling_child_has_output_and_time_limits_without_signaling_target_apps() {
    use std::time::Instant;
    // Isolate the test's process tree from other parallel Rust tests. The child
    // runs this same production-path contract, with no alternate runner logic.
    if std::env::var_os("CW_OWNED_SAMPLING_CHILD").is_none() {
        use std::os::unix::process::CommandExt;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "own_sampling_child_has_output_and_time_limits_without_signaling_target_apps", "--nocapture"])
            .env("CW_OWNED_SAMPLING_CHILD", "1").process_group(0).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() { assert!(status.success()); return; }
            if Instant::now() >= deadline {
                claude_watch_system::terminate_owned_group(&child); let _ = child.wait();
                panic!("owned sampling contract exceeded its 30-second total budget");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let children = || claude_watch_system::list_descendant_pids(
        &[std::process::id()], claude_watch_system::effective_uid());
    let before = children();
    assert!(before.is_empty(), "isolated sampling contract must start without children");
    let runner = SystemRunner::development().unwrap();
    let started = Instant::now();
    let error = runner
        .run(
            ReadCommand::Observer(ObserverAction::Inventory),
            &[],
            Duration::from_secs(8),
            64,
        )
        .err()
        .expect("native inventory exceeds tiny test limit");
    assert_eq!(error.code, "command_output_oversize");
    let oversize_seconds = started.elapsed().as_secs_f64();
    assert_eq!(children(), before, "output-limit return must reap its owned Observer, including zombies");
    let started = Instant::now();
    let error = runner
        .run(
            ReadCommand::Observer(ObserverAction::Inventory),
            &[],
            Duration::from_millis(1),
            8 * 1024 * 1024,
        )
        .err()
        .expect("native inventory cannot finish in 1ms");
    assert_eq!(error.code, "command_timeout");
    let timeout_seconds = started.elapsed().as_secs_f64();
    assert_eq!(children(), before, "timeout return must reap its owned Observer, including zombies");
    // Exercise the same command owner after both failure paths, then normal
    // plutil completion. These are real helpers, not a second subprocess mock.
    let started = Instant::now();
    let inventory = Observer { runner: &runner }.inventory().unwrap();
    assert!(inventory.processes.contains_key(&std::process::id()));
    let recovery_seconds = started.elapsed().as_secs_f64();
    assert_eq!(children(), before, "successful Observer completion must be waited for");
    struct Plist(PathBuf);
    impl Drop for Plist { fn drop(&mut self) { let _ = fs::remove_file(&self.0); } }
    let plist = Plist(std::env::temp_dir().join(format!("cw-owned-sampling-{}.plist", Uuid::new_v4())));
    fs::write(&plist.0, b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>owned</key><true/></dict></plist>").unwrap();
    let started = Instant::now();
    for _ in 0..16 {
        let output = runner.run(ReadCommand::Plist(plist.0.clone()), &[], Duration::from_secs(3), 1024).unwrap();
        assert_eq!(output.status, 0);
        assert_eq!(serde_json::from_slice::<Value>(&output.stdout).unwrap()["owned"], true);
        assert_eq!(children(), before, "normal plutil return must reap its owned child, including zombies");
    }
    let plutil_seconds = started.elapsed().as_secs_f64();
    // Stop the actual audit worker while its owned process is still running.
    // This checks cancellation/reaping, not just the idle worker's join path.
    use claude_watch_runtime::channel_supervisor::{AsyncAuditRequest, ChannelSupervisor};
    use std::sync::{atomic::{AtomicBool, Ordering}, mpsc, Arc};
    let stop = Arc::new(AtomicBool::new(false));
    let (events, _event_rx) = mpsc::channel();
    let (finished, completed) = mpsc::channel();
    let (requests, worker) = ChannelSupervisor::spawn_async_audit_worker(stop.clone(), events, move |request| {
        let result = claude_watch_runtime::audit_process::run_json(
            std::process::Command::new("/bin/sleep").arg("30"), &json!({}),
            Instant::now() + Duration::from_secs(10), request.cancellation.as_deref().unwrap());
        let _ = finished.send(result.as_ref().err().map(|error| error.code.clone()));
        result.map(|value| (value, Value::Null, native::now()))
    }).unwrap();
    requests.send(AsyncAuditRequest {
        request_id: 1, family: "claude".into(), target: claude_watch_core::processes::LaunchTarget::ClaudeCli,
        session_id: None, context_id: None,
        policy_version: claude_watch_core::channel::PolicyVersion { policy_digest:"owned-fixture".into(), guard_policy_digest:"owned-fixture".into() },
        vpn_epoch: None, upstream_endpoint: "http://127.0.0.1:1".into(), requested_at:native::now(),
        timeout_seconds:10.0, cancellation:None,
    }).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut running_child = None;
    while Instant::now() < deadline && running_child.is_none() {
        running_child = children().into_iter().find(|pid| claude_watch_system::inspect_process_identity(*pid)
            .is_some_and(|identity| identity.executable_path == "/bin/sleep"));
        if running_child.is_none() { std::thread::sleep(Duration::from_millis(5)); }
    }
    let started = Instant::now();
    stop.store(true, Ordering::Release);
    worker.join().unwrap();
    let audit_cancel_seconds = started.elapsed().as_secs_f64();
    assert!(running_child.is_some(), "cancellation must interrupt a real in-flight owned child");
    assert_eq!(completed.recv_timeout(Duration::from_millis(50)).unwrap().as_deref(), Some("audit_cancelled"));
    assert!(audit_cancel_seconds < 2.0, "audit stop must honor its existing one-second cleanup allowance");
    assert_eq!(children(), before, "audit cancellation must finish reaping before shutdown is acknowledged");
    let evidence = json!({"clock":"monotonic", "observer_output_limit_seconds":oversize_seconds,
        "observer_timeout_seconds":timeout_seconds, "observer_recovery_seconds":recovery_seconds,
        "plutil_calls":16, "plutil_total_seconds":plutil_seconds, "inflight_audit_cancel_seconds":audit_cancel_seconds,
        "remaining_owned_descendants":0});
    println!("sampling child lifecycle: {evidence}");
    if let Some(dir) = std::env::var_os("CW_CHANNEL_CONTRACT_DIR") {
        fs::create_dir_all(&dir).unwrap();
        fs::write(Path::new(&dir).join("sampling-child-lifecycle.json"), serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();
    }
    assert!(runner
        .run(
            ReadCommand::DnsA {
                host: "claude.ai;command".into(),
                port: 53
            },
            &[],
            Duration::from_secs(1),
            1024
        )
        .is_err());
}

#[test]
fn confirmed_exit_is_distinct_from_missing_or_unverified_target() {
    let p = identity();
    let mut second = p.clone();
    second.pid = 78;
    let mut wire = envelope();
    wire["socket_samples"] = json!([
        {"pid":77,"state":"unknown","code":"process_exited"},
        {"pid":78,"state":"ok","identity":second,"sockets":[{"pid":78,"protocol":"tcp","local":["198.18.0.1",50000],"peer":["198.18.1.10",443]}],"dropped":{}}
    ]);
    let result =
        native::decode_sockets(&wire, &[p.clone(), second.clone()], "round", 1000.0, 1003.0)
            .unwrap();
    assert!(result.complete);
    assert_eq!(result.confirmed_exited_count, 1);
    assert_eq!(result.flows.len(), 1);
    assert_eq!(result.flows[0].pid, 78);
    let mut contradictory = wire.clone();
    contradictory["socket_samples"][0]["sockets"] = json!([{"pid":77}]);
    assert!(native::decode_sockets(
        &contradictory,
        &[p.clone(), second.clone()],
        "round",
        1000.0,
        1003.0
    )
    .is_err());
    contradictory = wire.clone();
    contradictory["socket_samples"][0]["state"] = json!("ok");
    assert!(native::decode_sockets(
        &contradictory,
        &[p.clone(), second.clone()],
        "round",
        1000.0,
        1003.0
    )
    .is_err());
    for code in [
        "identity_changed",
        "identity_unavailable",
        "fd_inventory_unavailable",
        "socket_deadline",
    ] {
        wire["socket_samples"][0]["code"] = json!(code);
        let unknown =
            native::decode_sockets(&wire, &[p.clone(), second.clone()], "round", 1000.0, 1003.0)
                .unwrap();
        assert!(!unknown.complete);
        assert_eq!(unknown.confirmed_exited_count, 0);
    }
    wire["socket_samples"] = json!([wire["socket_samples"][1]]);
    let missing = native::decode_sockets(&wire, &[p, second], "round", 1000.0, 1003.0).unwrap();
    assert!(!missing.complete);
    assert_eq!(missing.dropped["missing_target_sample"], 1);
}

struct ExitedRunner(FakeRunner);
impl ReadRunner for ExitedRunner {
    fn run(
        &self,
        command: ReadCommand,
        input: &[u8],
        timeout: Duration,
        limit: usize,
    ) -> claude_watch_core::error::Result<Output> {
        let is_socket = matches!(command, ReadCommand::Observer(ObserverAction::Sockets));
        let mut output = self.0.run(command, input, timeout, limit)?;
        if is_socket {
            let mut body: Value = serde_json::from_slice(&output.stdout).unwrap();
            body["socket_samples"] = json!([{"pid":77,"state":"unknown","code":"process_exited"}]);
            output.stdout = serde_json::to_vec(&body).unwrap();
        }
        Ok(output)
    }
}
#[test]
fn sampler_reports_confirmed_exit_without_claiming_incomplete_round() {
    let home = std::env::temp_dir().join(format!("cw-exit-fixture-{}", Uuid::new_v4()));
    fs::create_dir(&home).unwrap();
    let mut sampler = Sampler::new(ExitedRunner(FakeRunner::new(&home)), Paths::new(&home).unwrap());
    let process = sampler.processes().unwrap();
    let socket = sampler.sockets(&process).unwrap();
    assert_eq!(socket.receipt["collector_state"], "empty");
    assert_eq!(socket.receipt["confirmed_exited_count"], 1);
    assert!(socket.flows.is_empty());
    let projected = claude_watch_runtime::monitor_snapshot::connection_observation(
        &socket.receipt,
        socket.receipt["observed_at"].as_f64().unwrap(),
    );
    assert_eq!(projected["collectorState"], "empty");
    assert_eq!(projected["confirmedExitedCount"], 1);
    let mut invalid = socket.receipt.clone();
    invalid["confirmed_exited_count"] = json!(2);
    assert_eq!(
        claude_watch_runtime::monitor_snapshot::connection_observation(
            &invalid,
            invalid["observed_at"].as_f64().unwrap()
        )["collectorState"],
        "unknown"
    );
    fs::remove_dir_all(home).unwrap();
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn real_exited_child_does_not_hide_other_owned_socket() {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Child(
        std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap(),
    );
    let runner = SystemRunner::development().unwrap();
    let observer = Observer { runner: &runner };
    let inventory = observer.inventory().unwrap();
    let ended = inventory
        .processes
        .get(&child.0.id())
        .expect("owned child in inventory")
        .identity
        .clone();
    let current = inventory
        .processes
        .get(&std::process::id())
        .unwrap()
        .identity
        .clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let client = TcpStream::connect(address).unwrap();
    let (server, _) = listener.accept().unwrap();
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    let result = observer
        .sockets(&[ended, current.clone()], "ended-and-live")
        .unwrap();
    assert!(result.complete);
    assert_eq!(result.confirmed_exited_count, 1);
    assert!(result
        .flows
        .iter()
        .any(|f| f.pid == current.pid && f.peer.0 == "127.0.0.1" && f.peer.1 == address.port()));
    drop((client, server));
}

#[test]
fn managed_codex_app_server_requires_exact_path_and_entry() {
    use claude_watch_core::processes::{self, Target};
    use std::collections::{BTreeMap, BTreeSet};
    let home = Path::new("/fixture");
    let trusted = TrustedCliPaths::default();
    let mut daemon = identity();
    daemon.executable = "/fixture/.codex/packages/app-server-daemon/releases/0.166.0-aarch64-apple-darwin/bin/codex".into();
    let classify = |p: &Identity, args: Option<&[String]>| {
        process_roots::classify(
            RootEvidence {
                identity: p,
                arguments: args,
                cwd: Some("/fixture"),
                bundle_path: None,
                bundle_id: None,
            },
            home,
            &trusted,
            |_| None,
        )
    };
    assert_eq!(classify(&daemon, None), Classification::NeedArguments);
    for args in [
        vec!["codex", "app-server", "daemon"],
        vec!["codex", "app-server", "--listen", "unix:///tmp/socket"],
    ] {
        let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
        assert_eq!(
            classify(&daemon, Some(&args)),
            Classification::Root(Kind::CodexCli)
        );
    }
    for args in [
        vec!["codex", "-e", "app-server daemon"],
        vec!["codex", "app-server", "--listen"],
        vec!["codex", "app-server", "other"],
        vec!["other", "app-server", "daemon"],
    ] {
        let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
        assert_eq!(classify(&daemon, Some(&args)), Classification::NotTarget);
    }
    for path in [
        "/fixture2/.codex/packages/app-server-daemon/releases/v/bin/codex",
        "/fixture/.codex/packages/app-server-daemon/releases/v/extra/bin/codex",
        "/fixture/.codex/packages/app-server-daemon/releases/v/bin/codex-other",
        "/fixture/.codex/packages/app-server-daemon/releases/../bin/codex",
    ] {
        let mut near = daemon.clone();
        near.executable = path.into();
        assert_eq!(classify(&near, None), Classification::NotTarget);
    }
    let mut desktop = identity();
    desktop.pid = 78;
    desktop.executable = "/Applications/Codex.app/Contents/MacOS/Codex".into();
    daemon.parent = desktop.pid;
    let inventory = BTreeMap::from([(desktop.pid, desktop.clone()), (daemon.pid, daemon.clone())]);
    let targets = processes::targets(
        &inventory,
        &[
            Target {
                identity: desktop,
                kind: Kind::CodexMain,
            },
            Target {
                identity: daemon,
                kind: Kind::CodexCli,
            },
        ],
        &[],
        501,
        &BTreeSet::new(),
    );
    assert_eq!(
        targets.iter().find(|p| p.identity.pid == 77).unwrap().kind,
        Kind::CodexChild
    );
}

#[test]
fn sampler_discovers_managed_codex_servers_with_bound_arguments() {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    struct ManagedRunner {
        home: PathBuf,
        missing_arguments: Arc<AtomicBool>,
    }
    impl ReadRunner for ManagedRunner {
        fn run(
            &self,
            command: ReadCommand,
            input: &[u8],
            _: Duration,
            _: usize,
        ) -> claude_watch_core::error::Result<Output> {
            let now = native::now();
            let mut front = identity();
            front.pid = 71;
            front.executable = self.home.join("independent-codex-image").to_string_lossy().into_owned();
            let mut daemon = identity();
            daemon.pid = 72;
            daemon.executable = self
                .home
                .join(".codex/packages/app-server-daemon/releases/v/bin/codex")
                .to_string_lossy()
                .into_owned();
            let mut server = daemon.clone();
            server.pid = 73;
            server.parent = 72;
            let mut body =
                json!({"schema":1,"status":"ok","uid":501,"started_at":now,"finished_at":now});
            match command {
                ReadCommand::Observer(ObserverAction::Inventory) => {
                    body["state"] = json!("ok");
                    body["truncated"] = json!(false);
                    body["processes"] = json!([front, daemon, server]);
                    body["unavailable"] = json!([]);
                    body["exited"] = json!([]);
                    body["requested_count"] = json!(3);
                }
                ReadCommand::Observer(ObserverAction::Arguments) => {
                    let request: Value = serde_json::from_slice(input).unwrap();
                    body["round_id"] = request["round_id"].clone();
                    body["argument_prefixes"] = json!([
                        {"pid":71,"state":"ok","identity":front,"arguments":["codex"],"cwd":"/fixture","truncated":false},
                        {"pid":72,"state":"ok","identity":daemon,"arguments":["codex","app-server","daemon"],"cwd":"/fixture","truncated":false},
                        {"pid":73,"state":"ok","identity":server,"arguments":["codex","app-server","--listen","unix:///tmp/socket"],"cwd":"/fixture","truncated":false}
                    ]);
                    if self.missing_arguments.load(Ordering::Relaxed) {
                        body["argument_prefixes"][1] = json!({"pid":72,"state":"unknown"});
                        body["argument_prefixes"][2] = json!({"pid":73,"state":"unknown"});
                    }
                }
                _ => panic!("unexpected command"),
            }
            Ok(Output {
                status: 0,
                stdout: serde_json::to_vec(&body).unwrap(),
                stderr: Vec::new(),
            })
        }
    }
    // The test home must match the executable's exact installation prefix.
    let temp = std::env::temp_dir().join(format!("cw-managed-{}", Uuid::new_v4()));
    fs::create_dir(&temp).unwrap();
    let temp=fs::canonicalize(temp).unwrap();
    use std::os::unix::fs::{symlink,PermissionsExt};
    fs::create_dir_all(temp.join(".local/bin")).unwrap();
    let front=temp.join("independent-codex-image");fs::write(&front,b"private independent CLI fixture; never executed").unwrap();
    fs::set_permissions(&front,fs::Permissions::from_mode(0o755)).unwrap();symlink(&front,temp.join(".local/bin/codex")).unwrap();
    // The independent CLI has real discovery evidence. Managed server paths
    // keep the existing exact-path + actual-entrypoint classification contract.
    let paths = Paths::new(&temp).unwrap();
    let missing_arguments = Arc::new(AtomicBool::new(false));
    let mut sampler = Sampler::new(
        ManagedRunner {
            home: paths.home.clone(),
            missing_arguments: missing_arguments.clone(),
        },
        paths,
    );
    let round = sampler.processes().unwrap();
    assert!(round.complete);
    assert_eq!(round.roles["72"]["runtimeRole"], "codex_managed");
    assert_eq!(round.roles["73"]["roleEvidence"], "managed_app_server");
    assert!(round.roles.get("71").is_none(), "independent CLI is not a managed server");
    let rows = claude_watch_runtime::monitor_snapshot::process_rows(&round, &[]);
    assert_eq!(rows.iter().find(|row| row["pid"] == 73).unwrap()["runtimeRole"], "codex_managed");
    for pid in [71, 72, 73] {
        assert_eq!(
            round
                .targets
                .iter()
                .find(|t| t.identity.pid == pid)
                .unwrap()
                .kind,
            Kind::CodexCli
        );
    }
    missing_arguments.store(true, Ordering::Relaxed);
    let incomplete = sampler.processes().unwrap();
    assert!(!incomplete.complete);
    assert_eq!(incomplete.roles["72"]["runtimeRole"], "codex_managed_unconfirmed");
    assert_eq!(incomplete.roles["73"]["roleEvidence"], "managed_path_only");
    assert!(incomplete.roles.get("71").is_none());
    fs::remove_dir_all(temp).unwrap();
}

#[test]
fn incomplete_process_round_keeps_causes_separate_from_complete_socket_sample() {
    struct Incomplete(FakeRunner);
    impl ReadRunner for Incomplete {
        fn run(&self, command: ReadCommand, input: &[u8], timeout: Duration, limit: usize) -> claude_watch_core::error::Result<Output> {
            let is_inventory = matches!(command, ReadCommand::Observer(ObserverAction::Inventory));
            let mut output = self.0.run(command, input, timeout, limit)?;
            if is_inventory {
                let mut body: Value = serde_json::from_slice(&output.stdout).unwrap();
                body["unavailable"] = json!([{"pid":88,"code":"identity_unavailable"}]);
                body["requested_count"] = json!(2);
                output.stdout = serde_json::to_vec(&body).unwrap();
            }
            Ok(output)
        }
    }
    let home = std::env::temp_dir().join(format!("cw-partial-process-{}", Uuid::new_v4()));
    fs::create_dir(&home).unwrap();
    let mut sampler = Sampler::new(Incomplete(FakeRunner::new(&home)), Paths::new(&home).unwrap());
    let process = sampler.processes().unwrap();
    assert!(!process.complete);
    assert_eq!(process.diagnostic_reasons["identity_unavailable"], 1);
    assert_eq!(process.diagnostic_reasons["inventory_count_mismatch"], 1);
    let socket = sampler.sockets(&process).unwrap();
    assert_eq!(socket.receipt["collector_state"], "partial");
    assert_eq!(socket.receipt["dropped"], json!({}));
    assert_eq!(socket.receipt["process_reason_counts"]["identity_unavailable"], 1);
    let view = claude_watch_runtime::monitor_snapshot::connection_observation(&socket.receipt, socket.receipt["observed_at"].as_f64().unwrap());
    assert_eq!(view["processReasonCounts"]["identity_unavailable"], 1);
    fs::remove_dir_all(home).unwrap();
}
