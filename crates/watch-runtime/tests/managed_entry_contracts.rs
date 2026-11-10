use claude_watch_core::{
    channel::PolicyVersion,
    controlled_launch::{
        AcceptedConnectionContext, ControlledLaunchRequest, ManagedInstanceState,
        ProxyAdaptationKind,
    },
    processes::LaunchTarget,
    vpn::VpnEpoch,
};
use claude_watch_runtime::{
    managed_entry::{
        build_claude_code_process_wrapper_plan, classify_process_protection_state,
        execute_cli_via_sandbox_launcher_with_stdin, prepare_desktop_managed_launch,
        resolve_real_cli_skipping_shim, snapshot_running_processes, stage_cli_entry_shim,
        stage_desktop_entry_bundle, DesktopEntryPreparation, DesktopManagedEntrySpec,
    },
    sandbox_launch::{
        build_helper_verifier_for_path, generate_nono_seatbelt_profile,
        register_helper_with_daemon, SandboxLaunchRegistry,
    },
    storage::{Paths, StateStore},
};
use claude_watch_system::{effective_uid, sha256_file_hex, SandboxPeerVerifier};
use std::{
    collections::BTreeMap,
    fs,
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

struct TempRoot(PathBuf);
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn make_temp_store(prefix: &str) -> (TempRoot, StateStore) {
    let short_id = &uuid::Uuid::new_v4().simple().to_string()[..8];
    let dir = std::env::temp_dir().join(format!("{prefix}-{short_id}"));
    fs::create_dir_all(&dir).unwrap();
    let store = StateStore::new(Paths::new(&dir).unwrap());
    (TempRoot(dir), store)
}

fn test_policy_version() -> PolicyVersion {
    PolicyVersion {
        policy_digest: "policy-entry-v1".into(),
        guard_policy_digest: "guard-entry-v1".into(),
    }
}

#[test]
fn d02_already_running_unmanaged_desktop_is_reported_unprotected_and_never_claimed_protected() {
    let (tmp, store) = make_temp_store("cw-entry-d02");
    let app_bundle = tmp.0.join("Claude.app");
    let macos_dir = app_bundle.join("Contents/MacOS");
    fs::create_dir_all(&macos_dir).unwrap();
    let exe_path = macos_dir.join("Claude");
    // Copy a real Mach-O binary (`/bin/sleep`) so kernel proc_pidpath matches `Claude.app/Contents/MacOS/Claude`!
    fs::copy("/bin/sleep", &exe_path).unwrap();
    fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755)).unwrap();

    let spec = DesktopManagedEntrySpec::resolve_from_app_bundle(
        LaunchTarget::ClaudeDesktop,
        &app_bundle,
        "com.anthropic.claudefordesktop",
        "Claude",
    )
    .expect("resolve spec");
    assert_eq!(
        spec.entry_bundle_id,
        "io.local.watchpanel.entry.claude-desktop"
    );
    assert_eq!(
        spec.proxy_adaptation,
        ProxyAdaptationKind::EnvAndElectronSwitches
    );

    let exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .unwrap();
    let verifier = SandboxPeerVerifier {
        expected_uid: effective_uid(),
        expected_helper_executable: exe.to_string_lossy().into_owned(),
        expected_helper_sha256: sha256_file_hex(&exe).unwrap(),
        require_code_signature_identifier: None,
    };
    let pv = test_policy_version();
    let registry = SandboxLaunchRegistry::new("boot-d02", pv.clone(), verifier, Some(store));

    // Spawn a REAL unmanaged process running `Claude.app/Contents/MacOS/Claude` (`D02`)
    let mut unmanaged_child = Command::new(&spec.target_executable)
        .arg("30")
        .spawn()
        .expect("spawn real unmanaged desktop process");
    let unmanaged_pid = unmanaged_child.id();

    let running = snapshot_running_processes().expect("live running process snapshot");
    let gw: SocketAddr = "127.0.0.1:18901".parse().unwrap();
    let prep = prepare_desktop_managed_launch(
        &spec,
        &running,
        &registry,
        "boot-d02",
        &pv,
        Some(VpnEpoch::new("vpn-1", 1)),
        gw,
        vec![],
    )
    .expect("prepare with real unmanaged process");

    match prep {
        DesktopEntryPreparation::AlreadyRunningUnmanaged {
            code,
            state,
            unmanaged_pids,
            ..
        } => {
            assert_eq!(code, "already_running_unmanaged");
            assert_eq!(state, ManagedInstanceState::RunningUnprotected);
            assert!(
                unmanaged_pids.contains(&unmanaged_pid),
                "expected live unmanaged pid {unmanaged_pid} in {unmanaged_pids:?}"
            );
        }
        other => panic!("expected AlreadyRunningUnmanaged, got: {other:?}"),
    }
    // Verify the unmanaged process is STILL alive (never killed automatically)
    assert!(
        unmanaged_child.try_wait().unwrap().is_none(),
        "unmanaged process must never be killed by prepare_desktop_managed_launch"
    );
    let _ = unmanaged_child.kill();
    let _ = unmanaged_child.wait();

    assert!(
        registry.instances().is_empty(),
        "unmanaged process must never be registered as a protected instance"
    );

    // Case 2: After unmanaged instance exits, `snapshot_running_processes()` -> ReadyToLaunch
    let running_after = snapshot_running_processes().expect("running after exit");
    let prep_clean = prepare_desktop_managed_launch(
        &spec,
        &running_after,
        &registry,
        "boot-d02",
        &pv,
        Some(VpnEpoch::new("vpn-1", 1)),
        gw,
        vec!["--flag".into()],
    )
    .expect("prepare clean");
    match prep_clean {
        DesktopEntryPreparation::ReadyToLaunch { request } => {
            assert_eq!(request.entry_id, "io.local.watchpanel.entry.claude-desktop");
            assert_eq!(request.target, LaunchTarget::ClaudeDesktop);
            assert_eq!(request.args, vec!["--flag".to_string()]);
        }
        other => panic!("expected ReadyToLaunch, got: {other:?}"),
    }
}

#[test]
fn d03_and_d04_direct_child_inherits_protection_while_out_of_tree_launchd_process_stays_unprotected() {
    let (tmp, store) = make_temp_store("cw-entry-d03-d04");
    let exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .unwrap();
    let exe_str = exe.to_string_lossy().into_owned();
    let exe_sha = sha256_file_hex(&exe).unwrap();
    let verifier = SandboxPeerVerifier {
        expected_uid: effective_uid(),
        expected_helper_executable: exe_str.clone(),
        expected_helper_sha256: exe_sha.clone(),
        require_code_signature_identifier: None,
    };
    let pv = test_policy_version();
    let boot_id = "boot-d03";
    let registry = Arc::new(SandboxLaunchRegistry::new(
        boot_id,
        pv.clone(),
        verifier,
        Some(store),
    ));
    registry.approve_target_executable(&exe_str, &exe_sha);
    let sleep_real = fs::canonicalize("/bin/sleep").unwrap();
    registry.approve_target_executable(
        sleep_real.to_string_lossy(),
        sha256_file_hex(&sleep_real).unwrap(),
    );

    // Register current process and promote to ExecVerified via live loopback TCP socket
    let sock_path = tmp.0.join("reg-d03.sock");
    let stop = Arc::new(AtomicBool::new(false));
    let reg_handle = registry
        .start_registration_listener(&sock_path, Arc::clone(&stop))
        .unwrap();

    let gw_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let gw_addr = gw_listener.local_addr().unwrap();
    let sbpl = generate_nono_seatbelt_profile(gw_addr, &[7890]).unwrap();

    let req = ControlledLaunchRequest {
        entry_id: "io.local.watchpanel.entry.claude-desktop".into(),
        target: LaunchTarget::ClaudeDesktop,
        target_executable: exe_str.clone(),
        target_fingerprint: exe_sha,
        args: vec![],
        cwd: None,
        proxy_adaptation: ProxyAdaptationKind::EnvAndElectronSwitches,
        gateway_endpoint: gw_addr.to_string(),
        policy_version: pv.clone(),
        vpn_epoch: Some(VpnEpoch::new("vpn-d03", 1)),
        launch_nonce: "nonce-d03-001".into(),
        executor_boot_id: boot_id.into(),
    };
    let resp = register_helper_with_daemon(&sock_path, req, true, &sbpl).unwrap();
    assert!(resp.accepted);

    let client = TcpStream::connect(gw_addr).unwrap();
    let peer_addr = client.local_addr().unwrap();
    let (_accepted, _) = gw_listener.accept().unwrap();
    let ctx = AcceptedConnectionContext {
        connection_id: 1,
        protocol: claude_watch_core::channel::FlowTransportProtocol::TcpIpv4,
        peer_addr,
        local_addr: gw_addr,
        listener_boot_id: boot_id.into(),
        accepted_at: 1_700_000_200.0,
        socket_fd: None,
    };
    let attr = registry
        .attribute_accepted_connection(&ctx, 1_700_000_200.0)
        .expect("attribute main process");
    assert_eq!(attr.0, "claude");

    // D03: Spawn a REAL child process (`fork` + `exec` of `/bin/sleep`) from this registered parent
    let mut real_child = Command::new(&sleep_real)
        .arg("30")
        .spawn()
        .expect("spawn real child process");
    let real_child_pid = real_child.id();

    // D04: Spawn a detached/out-of-tree process whose parent exits immediately (so its ppid becomes 1 / launchd)
    let out_of_tree_pid_file = tmp.0.join("out_of_tree.pid");
    let status = Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "/bin/sleep 30 >/dev/null 2>&1 & echo $! > '{}'",
            out_of_tree_pid_file.display()
        ))
        .status()
        .expect("spawn detached out-of-tree process");
    assert!(status.success());
    let out_of_tree_pid: u32 = fs::read_to_string(&out_of_tree_pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    // Also spawn a child running an UNAPPROVED executable (`/usr/bin/tail -f /dev/null`) and verify R3.1 rejects it!
    let mut unapproved_child = Command::new("/usr/bin/tail")
        .args(["-f", "/dev/null"])
        .spawn()
        .expect("spawn unapproved child");
    let unapproved_child_pid = unapproved_child.id();

    // Reconcile live kernel process trees and snapshot real running processes
    registry.reconcile_process_trees(1_700_000_201.0);
    let managed = registry.instances();
    assert_eq!(managed.len(), 1);
    assert!(
        managed[0]
            .controlled_subtree_pids
            .contains(&real_child_pid),
        "real forked child PID {real_child_pid} with approved SHA-256 must be registered in managed instance controlled_subtree_pids"
    );
    assert!(
        !managed[0]
            .controlled_subtree_pids
            .contains(&unapproved_child_pid),
        "unapproved child executable PID {unapproved_child_pid} must NOT be registered in controlled_subtree_pids"
    );
    let _ = unapproved_child.kill();
    let _ = unapproved_child.wait();

    let live_procs = snapshot_running_processes().expect("live processes");
    let live_child_snap = live_procs
        .iter()
        .find(|p| p.pid == real_child_pid)
        .expect("find real child in kernel process table");
    assert_eq!(
        classify_process_protection_state(live_child_snap, &managed, boot_id, &pv),
        ManagedInstanceState::ExecVerified
    );

    let live_out_of_tree_snap = live_procs
        .iter()
        .find(|p| p.pid == out_of_tree_pid)
        .expect("find detached process in kernel process table");
    assert_eq!(
        classify_process_protection_state(live_out_of_tree_snap, &managed, boot_id, &pv),
        ManagedInstanceState::RunningUnprotected,
        "out-of-tree process (ppid != managed tree) must be classified as RunningUnprotected"
    );

    // Clean up real child and verify `reconcile_process_trees` prunes exited child
    let _ = real_child.kill();
    let _ = real_child.wait();
    unsafe {
        libc::kill(out_of_tree_pid as i32, libc::SIGKILL);
    }
    registry.reconcile_process_trees(1_700_000_202.0);
    assert!(
        !registry.instances()[0]
            .controlled_subtree_pids
            .contains(&real_child_pid),
        "exited child PID must be pruned from controlled_subtree_pids"
    );

    stop.store(true, Ordering::Release);
    let _ = reg_handle.join();
}

#[test]
fn c01_cli_shim_skips_self_in_path_streams_stdin_stdout_stderr_and_executes_via_watch_sandbox_launcher() {
    let (tmp, store) = make_temp_store("cw-entry-c01");
    let shim_dir = tmp.0.join("shim-bin");
    let real_dir = tmp.0.join("real-bin");
    let work_dir = tmp.0.join("workspace");
    fs::create_dir_all(&shim_dir).unwrap();
    fs::create_dir_all(&real_dir).unwrap();
    fs::create_dir_all(&work_dir).unwrap();

    // Stage production CLI shim at `shim_dir/claude`
    let fake_watch = tmp.0.join("claude-watch");
    fs::write(&fake_watch, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&fake_watch, fs::Permissions::from_mode(0o755)).unwrap();
    let shim_claude =
        stage_cli_entry_shim(&shim_dir, LaunchTarget::ClaudeCli, &fake_watch).expect("stage shim");

    // Create the real target CLI script at `real_dir/claude` that reads stdin, prints args, cwd, env, and stderr
    let real_claude = real_dir.join("claude");
    fs::write(
        &real_claude,
        b"#!/bin/sh\nread STDIN_LINE\necho \"STDIN=$STDIN_LINE\"\necho \"ARGS=$*\"\necho \"CWD=$(pwd)\"\necho \"CUSTOM=$CW_CUSTOM_VAR\"\necho \"PROXY=$HTTP_PROXY\"\necho \"SANDBOX=$CW_CONTROLLED_SANDBOX\"\necho \"STDERR_DIAG=ok\" >&2\nexit 42\n",
    )
    .unwrap();
    fs::set_permissions(&real_claude, fs::Permissions::from_mode(0o755)).unwrap();

    let search_paths = vec![shim_dir.clone(), real_dir.clone()];
    let (resolved, resolved_sha) =
        resolve_real_cli_skipping_shim("claude", &shim_claude, &search_paths)
            .expect("resolve real claude skipping shim");
    assert_eq!(resolved, fs::canonicalize(&real_claude).unwrap());

    // Locate the built `watch-sandbox-launcher` binary next to current test binary's deps parent
    let current_exe = std::env::current_exe().unwrap();
    let debug_dir = current_exe.parent().unwrap().parent().unwrap();
    let launcher_bin = debug_dir.join("watch-sandbox-launcher");
    assert!(
        launcher_bin.is_file(),
        "expected watch-sandbox-launcher binary at {}",
        launcher_bin.display()
    );

    let verifier = build_helper_verifier_for_path(&launcher_bin).expect("helper verifier");
    let pv = test_policy_version();
    let boot_id = "boot-c01";
    let registry = Arc::new(SandboxLaunchRegistry::new(
        boot_id,
        pv.clone(),
        verifier,
        Some(store),
    ));
    registry.approve_target_executable(resolved.to_string_lossy(), &resolved_sha);

    let reg_sock = tmp.0.join("reg-c01.sock");
    let stop = Arc::new(AtomicBool::new(false));
    let reg_handle = registry
        .start_registration_listener(&reg_sock, Arc::clone(&stop))
        .unwrap();

    let gw: SocketAddr = "127.0.0.1:18955".parse().unwrap();
    let args = vec!["--print".to_string(), "hello-world".to_string()];
    let mut extra_env = BTreeMap::new();
    extra_env.insert("CW_CUSTOM_VAR".to_string(), "preserve-env-ok".to_string());
    let (res, stdout, stderr) = execute_cli_via_sandbox_launcher_with_stdin(
        &launcher_bin,
        Some(&reg_sock),
        LaunchTarget::ClaudeCli,
        &shim_claude,
        &search_paths,
        &args,
        Some(&work_dir),
        &extra_env,
        Some(b"streamed-stdin-payload\n"),
        gw,
        boot_id,
        pv,
        Some(VpnEpoch::new("vpn-c01", 1)),
        &[7890],
    )
    .expect("execute cli via sandbox launcher with stdin");

    let out_str = String::from_utf8_lossy(&stdout);
    let err_str = String::from_utf8_lossy(&stderr);
    assert_eq!(
        res.exit_code, 42,
        "expected child exit code 42, stdout={out_str}, stderr={err_str}"
    );
    assert!(out_str.contains("STDIN=streamed-stdin-payload"));
    assert!(out_str.contains("ARGS=--print hello-world"));
    assert!(out_str.contains(&format!(
        "CWD={}",
        fs::canonicalize(&work_dir).unwrap().display()
    )));
    assert!(out_str.contains("CUSTOM=preserve-env-ok"));
    assert!(out_str.contains("PROXY=http://127.0.0.1:18955"));
    assert!(out_str.contains("SANDBOX=1"));
    assert!(err_str.contains("STDERR_DIAG=ok"));

    // Verify helper registered the sandboxed instance in SandboxLaunchRegistry
    let instances = registry.instances();
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].state, ManagedInstanceState::SandboxApplied);

    let wrapper_plan = build_claude_code_process_wrapper_plan(&launcher_bin, gw).unwrap();
    assert_eq!(wrapper_plan.proxy_url, "http://127.0.0.1:18955");

    stop.store(true, Ordering::Release);
    let _ = reg_handle.join();
}

#[test]
fn controlled_entry_async_batches_keep_later_file_receipts_out_of_earlier_actions() {
    let (tmp, _) = make_temp_store("cw-entry-batch");
    let production_source = include_str!("../../../monitor/ControlledEntry/ControlledEntryApp.swift");
    let main_marker = "@main\nstruct ControlledEntryApp";
    assert_eq!(production_source.matches(main_marker).count(), 1);
    // Compile the real production batch state in the same Swift file, making
    // private state accessible to this narrow regression without a public hook.
    let mut source = production_source.replacen(main_marker, "struct ControlledEntryApp", 1);
    source.push_str(r#"
extension ControlledEntryDelegate {
    static func assertIndependentBatches() async {
        let entry = ControlledEntryDelegate()
        entry.enqueueURLs([URL(string: "cw-fixture://first")!])
        let first = entry.takePendingActionBatch()
        precondition(first.urls == ["cw-fixture://first"] && first.files.isEmpty)
        precondition(first.incomingReplies.isEmpty)
        // These opaque IDs are state-only markers and are never passed to
        // AppKit. A separate real event fixture verifies suspend/resume.
        // Model an AppKit file event arriving while the prior action is awaiting
        // its target reply. The prior batch must not acknowledge that new file.
        let arrival = Task { @MainActor in
            entry.enqueueFiles(["/private/tmp/next-document.md"])
            entry.pendingIncomingReplies.append(IncomingAppleEventReply(
                suspensionID: OpaquePointer(bitPattern: 1)!, returnID: 101))
        }
        await arrival.value
        precondition(first.incomingReplies.isEmpty && first.files.isEmpty)
        precondition(entry.pendingIncomingReplies.map(\.returnID) == [101])
        let second = entry.takePendingActionBatch()
        precondition(second.files == ["/private/tmp/next-document.md"])
        precondition(second.incomingReplies.map(\.returnID) == [101] && second.urls.isEmpty)
        precondition(entry.pendingIncomingReplies.isEmpty)
        // A third request remains independent of the file operation's result;
        // finishing/failing the immutable second batch cannot consume it.
        entry.enqueueFiles(["/private/tmp/third-document.md"])
        entry.pendingIncomingReplies.append(IncomingAppleEventReply(
            suspensionID: OpaquePointer(bitPattern: 2)!, returnID: 102))
        precondition(second.files == ["/private/tmp/next-document.md"])
        let third = entry.takePendingActionBatch()
        precondition(third.files == ["/private/tmp/third-document.md"] && third.incomingReplies.map(\.returnID) == [102])
        let empty = entry.takePendingActionBatch()
        precondition(empty.files.isEmpty && empty.urls.isEmpty && empty.incomingReplies.isEmpty)
        print("BATCH_REPLY_OWNERSHIP_OK")
    }
}
@main struct ControlledEntryBatchRegression {
    @MainActor static func main() async {
        await ControlledEntryDelegate.assertIndependentBatches()
    }
}
"#);
    let source_path = tmp.0.join("ControlledEntryBatchRegression.swift");
    let binary = tmp.0.join("ControlledEntryBatchRegression");
    let cache = tmp.0.join("swift-module-cache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(&source_path, source).unwrap();
    let compile = Command::new("xcrun").args(["swiftc", "-swift-version", "5", "-parse-as-library",
        "-module-cache-path", cache.to_str().unwrap(), source_path.to_str().unwrap(),
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../monitor/Sources/BoundedDiagnosticLog.swift"),
        "-framework", "AppKit", "-framework", "Foundation", "-o", binary.to_str().unwrap()])
        .output().expect("compile actual entry batch state");
    assert!(compile.status.success(), "{}", String::from_utf8_lossy(&compile.stderr));
    let run = Command::new(&binary).output().expect("run batch state regression");
    assert!(run.status.success(), "{}", String::from_utf8_lossy(&run.stderr));
    assert!(String::from_utf8_lossy(&run.stdout).contains("BATCH_REPLY_OWNERSHIP_OK"));
}

#[test]
fn controlled_entry_appkit_component_reopens_real_window_and_checks_standard_event_results() {
    // Acceptance requirement remains explicit. A received/read file without a
    // standard completion reply does NOT satisfy it, even when the wrapper
    // correctly reports that uncertainty. Do not ignore or weaken this case.
    run_controlled_entry_appkit_fixture(true);
}

#[test]
fn controlled_entry_async_transport_preserves_file_completion_uncertainty_without_retry() {
    // A separate negative case deliberately reads without presenting a document.
    // On this host AppKit waits for window ordering before completing odoc;
    // receipt of the file alone must never be promoted to completed opening.
    run_controlled_entry_appkit_fixture(false);
}

fn run_controlled_entry_appkit_fixture(require_file_completion: bool) {
    let (tmp, store) = make_temp_store("cw-entry-d01");
    let current_exe = std::env::current_exe().unwrap();
    let debug_dir = current_exe.parent().unwrap().parent().unwrap();
    let launcher_bin = debug_dir.join("watch-sandbox-launcher");
    assert!(
        launcher_bin.is_file(),
        "expected watch-sandbox-launcher at {}",
        launcher_bin.display()
    );

    // 1. Compile the real `ControlledEntry` binary from `monitor/ControlledEntry/ControlledEntryApp.swift`
    let swift_src = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../monitor/ControlledEntry/ControlledEntryApp.swift"
    ));
    let plist_tpl = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../monitor/ControlledEntry/Info.plist.in"
    ));
    let controlled_entry_bin = tmp.0.join("ControlledEntry");
    let module_cache = tmp.0.join("swift-module-cache");
    fs::create_dir_all(&module_cache).unwrap();
    let compile_status = Command::new("swiftc")
        .args([
            "-module-cache-path",
            &module_cache.to_string_lossy(),
            "-target",
            "arm64-apple-macosx26.0",
            "-O",
            "-parse-as-library",
            &swift_src.to_string_lossy(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../monitor/Sources/BoundedDiagnosticLog.swift"),
            "-o",
            &controlled_entry_bin.to_string_lossy(),
            "-framework",
            "AppKit",
            "-framework",
            "Foundation",
        ])
        .status()
        .expect("compile ControlledEntryApp.swift");
    assert!(compile_status.success(), "swiftc failed to compile ControlledEntryApp.swift");

    // 2. Build a self-owned AppKit target with an actual window and standard
    //    document/URL handlers. It stays alive only while our fixture flag exists.
    let orig_app = tmp.0.join("WatchFixture.app");
    let orig_macos = orig_app.join("Contents/MacOS");
    fs::create_dir_all(&orig_macos).unwrap();
    let orig_exe = orig_macos.join("WatchFixture");
    fs::write(orig_app.join("Contents/Info.plist"),
        "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>io.local.watchpanel.fixture.target</string><key>CFBundleExecutable</key><string>WatchFixture</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>").unwrap();
    let document_file = tmp.0.join("document.md");
    fs::write(&document_file, "controlled-entry-document").unwrap();
    let window_state_file = tmp.0.join("window_state.txt");
    let keep_alive_file = tmp.0.join("keep_alive.flag");
    fs::write(&keep_alive_file, "1").unwrap();
    let gw_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let gw_addr = gw_listener.local_addr().unwrap();
    let target_src = tmp.0.join("MockDesktopTarget.swift");
    fs::write(
        &target_src,
        r#"import AppKit
let app = NSApplication.shared
app.setActivationPolicy(.regular)
let env = ProcessInfo.processInfo.environment
let stateFile = env["CW_MOCK_WINDOW_STATE"] ?? ""
let keepAliveFile = env["CW_MOCK_KEEP_ALIVE"] ?? ""
let closeFile = keepAliveFile + ".close"
let myPid = ProcessInfo.processInfo.processIdentifier
func record(_ line: String) {
    let previous = (try? String(contentsOfFile: stateFile, encoding: .utf8)) ?? ""
    try? (previous + line + "\n").write(toFile: stateFile, atomically: true, encoding: .utf8)
}
final class MockAppDelegate: NSObject, NSApplicationDelegate {
    var documentWindows: [NSWindow] = []
    let window = NSWindow(contentRect: NSRect(x: 120, y: 120, width: 360, height: 180),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
    override init() {
        super.init()
        window.title = "Watch controlled entry fixture"
        window.isReleasedWhenClosed = false
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        window.makeKeyAndOrderFront(nil)
        record("RECEIVED_REOPEN_PID=\(myPid) VISIBLE=\(window.isVisible ? 1 : 0)")
        return window.isVisible
    }
    // Exercise AppKit's standard odoc decoding, not a private string protocol.
    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        let contents = filenames.map { try? String(contentsOfFile: $0, encoding: .utf8) }
        let readable = !contents.isEmpty && contents.allSatisfy { $0 == "controlled-entry-document" }
        record("RECEIVED_FILES_PID=\(myPid) FILES=\(filenames.joined(separator: ",")) READABLE=\(readable ? 1 : 0)")
        if readable && env["CW_MOCK_PRESENT_DOCUMENT"] == "1" {
            // Exercise an actual document open. Current AppKit defers the
            // standard odoc reply until its window-ordering completion runs.
            // No private acknowledgment or sender-side success substitute.
            let document = NSWindow(contentRect: NSRect(x: 160, y: 160, width: 360, height: 180),
                                    styleMask: [.titled, .closable], backing: .buffered, defer: false)
            document.isReleasedWhenClosed = false
            document.title = "Watch document fixture"
            let text = NSTextView(frame: document.contentView!.bounds)
            text.string = contents[0] ?? ""
            document.contentView = text
            documentWindows.append(document)
            document.makeKeyAndOrderFront(nil)
            record("DOCUMENT_OPENED_PID=\(myPid) VISIBLE=\(document.isVisible ? 1 : 0)")
        }
        sender.reply(toOpenOrPrint: readable ? .success : .failure)
    }
    @objc func handleGetURL(_ event: NSAppleEventDescriptor, reply: NSAppleEventDescriptor) {
        guard let url = event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue else {
            reply.setParam(NSAppleEventDescriptor(int32: -1700), forKeyword: AEKeyword(keyErrorNumber))
            return
        }
        if url == "cw-fixture://reject" {
            record("TARGET_REJECTED_URL_PID=\(myPid)")
            // Use a handled-but-failed result. -1708 means not handled and
            // can trigger another AppKit dispatch, not a sender retry.
            reply.setParam(NSAppleEventDescriptor(int32: -10000), forKeyword: AEKeyword(keyErrorNumber))
        } else {
            record("RECEIVED_URL_PID=\(myPid) URL=\(url)")
            reply.setParam(NSAppleEventDescriptor(int32: 0), forKeyword: AEKeyword(keyErrorNumber))
        }
    }
}
let delegate = MockAppDelegate()
app.delegate = delegate
NSAppleEventManager.shared().setEventHandler(delegate,
    andSelector: #selector(MockAppDelegate.handleGetURL(_:reply:)),
    forEventClass: AEEventClass(kInternetEventClass), andEventID: AEEventID(kAEGetURL))
app.finishLaunching()
delegate.window.makeKeyAndOrderFront(nil)
record("WINDOW_READY=\(delegate.window.isVisible ? 1 : 0) PID=\(myPid)")
record("PROXY=\(env["HTTP_PROXY"] ?? "") SANDBOX=\(env["CW_CONTROLLED_SANDBOX"] ?? "")")
let lifecycleTimer = Timer.scheduledTimer(withTimeInterval: 0.025, repeats: true) { _ in
    guard FileManager.default.fileExists(atPath: keepAliveFile) else { exit(0) }
    if FileManager.default.fileExists(atPath: closeFile) {
        try? FileManager.default.removeItem(atPath: closeFile)
        delegate.window.close()
        record("WINDOW_CLOSED_PID=\(myPid) VISIBLE=\(delegate.window.isVisible ? 1 : 0)")
    }
}
app.run()
"#,
    )
    .unwrap();
    let target_compile = Command::new("swiftc")
        .args([
            "-module-cache-path",
            &module_cache.to_string_lossy(),
            "-target",
            "arm64-apple-macosx26.0",
            "-O",
            target_src.to_str().unwrap(),
            "-o",
            orig_exe.to_str().unwrap(),
        ])
        .status()
        .expect("compile MockDesktopTarget.swift");
    assert!(target_compile.success(), "swiftc failed to compile MockDesktopTarget.swift");
    let orig_sha_before = sha256_file_hex(&orig_exe).unwrap();

    // 3. Start the real registry listener and helper. The shell adapter below
    //    substitutes for watch-engine, so this is not production engine acceptance.
    let verifier = build_helper_verifier_for_path(&launcher_bin).expect("helper verifier");
    let pv = test_policy_version();
    let boot_id = "boot-d01-real";
    let state_dir = store.paths.watch().join("state");
    fs::create_dir_all(&state_dir).unwrap();
    store
        .atomic_json(
            &state_dir.join("seatbelt-runtime.json"),
            &serde_json::json!({
                "executor_boot_id": boot_id,
                "gateway_endpoint": gw_addr.to_string(),
                "sandbox_ready": true
            }),
        )
        .unwrap();
    let registry = Arc::new(SandboxLaunchRegistry::new(
        boot_id,
        pv.clone(),
        verifier,
        Some(store.clone()),
    ));
    let orig_exe_canon = fs::canonicalize(&orig_exe).unwrap();
    registry.approve_target_executable(
        orig_exe_canon.to_string_lossy(),
        &orig_sha_before,
    );

    let reg_sock = tmp.0.join("reg-d01.sock");
    let stop = Arc::new(AtomicBool::new(false));
    let reg_handle = registry
        .start_registration_listener(&reg_sock, Arc::clone(&stop))
        .unwrap();

    // Create a thin watch-engine launch adapter that spawns the real `watch-sandbox-launcher`
    // in the background (matching desktop `.app` launch behavior) and waits until the window is ready.
    let req_template = ControlledLaunchRequest {
        entry_id: "io.local.watchpanel.entry.claude-desktop".into(),
        target: LaunchTarget::ClaudeDesktop,
        target_executable: orig_exe_canon.to_string_lossy().into_owned(),
        target_fingerprint: orig_sha_before.clone(),
        args: vec![],
        cwd: None,
        proxy_adaptation: ProxyAdaptationKind::EnvAndElectronSwitches,
        gateway_endpoint: gw_addr.to_string(),
        policy_version: pv.clone(),
        vpn_epoch: Some(VpnEpoch::new("vpn-d01", 1)),
        launch_nonce: "nonce-d01-real-001".into(),
        executor_boot_id: boot_id.into(),
    };
    let req_json = serde_json::to_string(&req_template).unwrap();
    let real_helper_dispatch = tmp.0.join("watch-helper-dispatch");
    let events_log_file = tmp.0.join("forwarded_events.log");
    let target_stdout = tmp.0.join("target.stdout");
    let target_stderr = tmp.0.join("target.stderr");
    fs::write(
        &real_helper_dispatch,
        format!(
            "#!/bin/sh\nCW_MOCK_PRESENT_DOCUMENT='{}' CW_MOCK_WINDOW_STATE='{}' CW_MOCK_KEEP_ALIVE='{}' '{}' --launch-json '{}' --registration-socket '{}' >'{}' 2>'{}' &\nfor i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do\n  if [ -f '{}' ]; then break; fi\n  sleep 0.05\ndone\necho '{{\"status\":\"ok\"}}'\nexit 0\n",
            if require_file_completion { "1" } else { "0" },
            window_state_file.display(),
            keep_alive_file.display(),
            launcher_bin.display(),
            req_json,
            reg_sock.display(),
            target_stdout.display(),
            target_stderr.display(),
            window_state_file.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&real_helper_dispatch, fs::Permissions::from_mode(0o755)).unwrap();

    // 4. Stage the real `Claude (Controlled).app` bundle using production `stage_desktop_entry_bundle`
    let spec = DesktopManagedEntrySpec::resolve_from_app_bundle(
        LaunchTarget::ClaudeDesktop,
        &orig_app,
        "io.local.watchpanel.fixture.target",
        "WatchFixture",
    )
    .expect("resolve spec for D01");
    let _ = plist_tpl;
    let apps_dir = store.paths.watch().join("entries/apps");
    let wrapper_app = stage_desktop_entry_bundle(
        &apps_dir,
        &spec,
        &real_helper_dispatch,
        &launcher_bin,
        Some(&controlled_entry_bin),
    )
    .expect("stage desktop entry bundle");
    let wrapper_exe = wrapper_app.join("Contents/MacOS/ControlledEntry");
    assert!(wrapper_exe.is_file());

    // Component smoke uses the generated plist without state-dir overrides.
    // Finder and the actual engine/production identity gate are not exercised here.
    // 5. Execute the staged controlled-entry binary:
    //    `ControlledEntry -> fixture adapter -> watch-sandbox-launcher -> Seatbelt -> WatchFixture`
    let output = Command::new(&wrapper_exe)
        .env("CW_ENTRY_TARGET", "claude-desktop")
        .env("CW_TARGET_EXECUTABLE", &orig_exe_canon)
        .env("CW_WATCH_BINARY", &real_helper_dispatch)
        .env("CW_TARGET_STATE_FILE", &window_state_file)
        .env("CW_ENTRY_EVENT_LOG", &events_log_file)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run staged ControlledEntry");
    assert!(
        output.status.success(),
        "ControlledEntry launch failed: status={:?}, stdout={}, stderr={}, events={}, target_stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        fs::read_to_string(&events_log_file).unwrap_or_default(),
        fs::read_to_string(&target_stderr).unwrap_or_default()
    );

    // Verify target desktop `.app` ran inside Seatbelt and wrote its window state file!
    let window_state = fs::read_to_string(&window_state_file).expect("read window_state.txt");
    assert!(window_state.contains("WINDOW_READY=1"));
    assert!(window_state.contains(&format!("PROXY=http://{gw_addr}")));
    assert!(window_state.contains("SANDBOX=1"));

    // Verify `SandboxLaunchRegistry` recorded the registered desktop instance,
    // and transition it to `ExecVerified` via `reconcile_process_trees()` (R3/R5.2)
    let instances_before = registry.instances();
    assert_eq!(instances_before.len(), 1);
    assert_eq!(instances_before[0].state, ManagedInstanceState::SandboxApplied);
    registry.reconcile_process_trees(1_700_000_300.0);
    let instances = registry.instances();
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0].state, ManagedInstanceState::ExecVerified);
    let managed_pid = instances[0].pid;

    // Close a real NSWindow inside the live target, then reopen the same PID.
    fs::write(keep_alive_file.with_extension("flag.close"), "close").unwrap();
    let mut closed_state = String::new();
    for _ in 0..80 {
        closed_state = fs::read_to_string(&window_state_file).unwrap_or_default();
        if closed_state.contains(&format!("WINDOW_CLOSED_PID={managed_pid} VISIBLE=0")) { break; }
        thread::sleep(Duration::from_millis(25));
    }
    assert!(closed_state.contains(&format!("WINDOW_CLOSED_PID={managed_pid} VISIBLE=0")), "actual target window was not closed: {closed_state}");
    let reopen_out = Command::new(&wrapper_exe)
        .env("CW_ENTRY_EVENT_LOG", &events_log_file)
        .args(["--reopen", "--open-url", "cw-fixture://open"])
        .output().expect("run controlled window reopen and standard URL delivery");
    let events_logged = fs::read_to_string(&events_log_file).unwrap_or_default();
    assert!(reopen_out.status.success(), "entry failed: {:?}, stderr={}, log={events_logged}, target_state={}, target_stderr={}",
        reopen_out.status.code(), String::from_utf8_lossy(&reopen_out.stderr),
        fs::read_to_string(&window_state_file).unwrap_or_default(),
        fs::read_to_string(&target_stderr).unwrap_or_default());
    let target_received = fs::read_to_string(&window_state_file).unwrap();
    assert!(target_received.contains(&format!("RECEIVED_REOPEN_PID={managed_pid} VISIBLE=1")), "window was not reopened in same target: {target_received}");
    assert!(target_received.contains(&format!("RECEIVED_URL_PID={managed_pid} URL=cw-fixture://open")), "target did not receive URL: {target_received}");
    eprintln!("AppKit fixture: real window closed/reopened in same PID; standard URL received");

    // A delivered AppleEvent can still contain an application-level error.
    // It must fail the wrapper, without retrying and duplicating the action.
    let rejected = Command::new(&wrapper_exe)
        .env("CW_ENTRY_EVENT_LOG", &events_log_file)
        .args(["--open-url", "cw-fixture://reject"])
        .output().expect("send rejected URL event");
    assert_eq!(rejected.status.code(), Some(74));
    let target_after_rejection = fs::read_to_string(&window_state_file).unwrap();
    assert_eq!(target_after_rejection.matches("TARGET_REJECTED_URL_PID=").count(), 1, "target_state={target_after_rejection}, wrapper_log={}", fs::read_to_string(&events_log_file).unwrap_or_default());
    let error_log = fs::read_to_string(&events_log_file).unwrap();
    assert!(error_log.contains("apple_event_target_failed") && error_log.contains("-10000"), "target error was not surfaced: {error_log}");
    eprintln!("AppKit fixture: target errn=-10000 surfaced once with wrapper exit 74");

    let file_out = Command::new(&wrapper_exe)
        .env("CW_ENTRY_EVENT_LOG", &events_log_file)
        .args(["--open-file", document_file.to_str().unwrap()])
        .output().expect("deliver one standard file event");
    let target_received = fs::read_to_string(&window_state_file).unwrap();
    let received_file = target_received.lines().find_map(|line| {
        line.strip_prefix(&format!("RECEIVED_FILES_PID={managed_pid} FILES="))
            .and_then(|value| value.strip_suffix(" READABLE=1"))
    }).expect("AppKit must receive and read the standard file event");
    assert_eq!(fs::canonicalize(received_file).unwrap(), fs::canonicalize(&document_file).unwrap(), "AppKit must decode the requested file URL");
    assert_eq!(target_received.matches("RECEIVED_FILES_PID=").count(), 1, "one input file event must be delivered once");
    eprintln!("AppKit fixture: standard file URL decoded/read exactly once by the managed PID");
    let file_events = fs::read_to_string(&events_log_file).unwrap_or_default();
    if require_file_completion {
        assert!(target_received.contains(&format!("DOCUMENT_OPENED_PID={managed_pid} VISIBLE=1")),
            "successful document open must present its window: {target_received}");
        assert!(file_out.status.success(), "standard file reply unconfirmed: status={:?}, wrapper_log={file_events}, target_state={target_received}", file_out.status.code());
        let events: Vec<serde_json::Value> = file_events.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        let forwarded_files: Vec<_> = events.iter().filter(|event| event["event"] == "forward_open_items" && event["file_count"].as_u64().is_some_and(|count| count > 0)).collect();
        assert_eq!(forwarded_files.len(), 1);
        assert_eq!(forwarded_files[0]["apple_event_reply_confirmed"], true);
        assert_eq!(forwarded_files[0]["status"], "ok");
        eprintln!("AppKit fixture: actual document window opened and standard completion reply confirmed");
    } else {
        assert!(!target_received.contains("DOCUMENT_OPENED_PID="));
        assert_eq!(file_out.status.code(), Some(74), "missing completion must not become success: {file_events}");
        let events: Vec<serde_json::Value> = file_events.lines().map(|line| serde_json::from_str(line).unwrap()).collect();
        assert_eq!(events.iter().filter(|event| event["error"] == "apple_event_reply_timeout" && event["outcome"] == "unconfirmed").count(), 1,
            "one missing reply must produce one unconfirmed timeout: {file_events}");
        let forwarded_files: Vec<_> = events.iter().filter(|event| event["event"] == "forward_open_items" && event["file_count"].as_u64().is_some_and(|count| count > 0)).collect();
        assert_eq!(forwarded_files.len(), 1, "file delivery must not retry: {file_events}");
        assert_eq!(forwarded_files[0]["apple_event_reply_confirmed"], false);
        assert_ne!(forwarded_files[0]["status"], "ok");
        eprintln!("AppKit transport: missing file completion remains unconfirmed/74, no retry or false success");
    }

    // Clean up background desktop script
    let _ = fs::remove_file(&keep_alive_file);

    // 7. Verify original `.app` binary was NEVER modified
    let orig_sha_after = sha256_file_hex(&orig_exe).unwrap();
    assert_eq!(
        orig_sha_before, orig_sha_after,
        "original .app binary must never be modified by the wrapper entry"
    );

    // 8. Verify R5.1 `stage_deliverable_entries` creates `<watch_dir>/entries/{apps,bin}` and `entries-manifest.json`
    let deliverables = claude_watch_runtime::managed_entry::stage_deliverable_entries(
        &store.paths.watch().join("entries"),
        std::slice::from_ref(&spec),
        &real_helper_dispatch,
        &launcher_bin,
        Some(&controlled_entry_bin),
    )
    .expect("stage deliverable entries");
    assert_eq!(deliverables.desktop_bundles.len(), 1);
    assert!(Path::new(&deliverables.desktop_bundles[0]).is_dir());
    assert_eq!(deliverables.cli_shims.len(), 2);
    assert!(store
        .paths
        .watch()
        .join("entries/entries-manifest.json")
        .is_file());

    stop.store(true, Ordering::Release);
    let _ = reg_handle.join();
}
