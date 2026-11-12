#![cfg(target_os = "macos")]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ENTRY_SOURCE: &str =
    include_str!("../../../monitor/ControlledEntry/ControlledEntryApp.swift");

struct FixtureChild(Child);
impl Drop for FixtureChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn wait_for(path: &Path, marker: &str) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if fs::read_to_string(path)
            .unwrap_or_default()
            .contains(marker)
        {
            return;
        }
        thread::sleep(Duration::from_millis(15));
    }
    panic!(
        "missing {marker} in {}: {}",
        path.display(),
        fs::read_to_string(path).unwrap_or_default()
    );
}

fn compile(source: &Path, binary: &Path, root: &Path) {
    let output = Command::new("swiftc")
        .args([
            "-parse-as-library",
            "-target",
            "arm64-apple-macosx26.0",
            "-module-cache-path",
        ])
        .arg(root.join("swift-cache"))
        .arg(source)
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/../../monitor/Sources/BoundedDiagnosticLog.swift"))
        .arg("-o")
        .arg(binary)
        .output()
        .unwrap();
    fs::write(binary.with_extension("compile.log"), &output.stderr).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn sender(helper: &Path, pid: u32, mode: &str, value: &str) -> Command {
    let mut command = Command::new(helper);
    command.args(["send", &pid.to_string(), mode, value]);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command
}

fn assert_reply(output: Output, expected: i32) {
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{text}, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.contains(&format!("TRANSPORT=0 ERROR={expected}")),
        "{text}"
    );
}

fn start_wrapper(root: &Path, target: &Path, label: &str) -> (FixtureChild, PathBuf) {
    let log = root.join(format!("wrapper-{label}.jsonl"));
    let child = Command::new(root.join("ControlledEntry"))
        .env("CW_ENTRY_TARGET", "receipt-fixture")
        .env("CW_TARGET_BUNDLE_ID", "io.local.watchpanel.receipt-fixture")
        .env("CW_TARGET_EXECUTABLE", target)
        .env("CW_WATCH_STATE_DIR", root)
        .env("CW_ENTRY_EVENT_LOG", &log)
        .env("CW_ENTRY_EVENT_LOOP_MS", "10000")
        .stdout(Stdio::from(
            fs::File::create(root.join(format!("wrapper-{label}.stdout"))).unwrap(),
        ))
        .stderr(Stdio::from(
            fs::File::create(root.join(format!("wrapper-{label}.stderr"))).unwrap(),
        ))
        .spawn()
        .unwrap();
    let child = FixtureChild(child);
    wait_for(&log, "apple_event_reply_confirmed");
    (child, log)
}

#[test]
fn controlled_entry_standard_incoming_receipts_follow_forwarding_results() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("cw-entry-incoming-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    eprintln!("incoming AppleEvent evidence: {}", root.display());
    let entry_source = root.join("ControlledEntry.swift");
    fs::write(&entry_source, ENTRY_SOURCE).unwrap();
    compile(&entry_source, &root.join("ControlledEntry"), &root);
    let helper_source = root.join("ReceiptFixture.swift");
    let marker = "@main\nstruct ControlledEntryApp";
    assert_eq!(ENTRY_SOURCE.matches(marker).count(), 1);
    fs::write(
        &helper_source,
        format!(
            "{}\n{FIXTURE_SOURCE}",
            ENTRY_SOURCE.replacen(marker, "struct ControlledEntryApp", 1)
        ),
    )
    .unwrap();
    let helper = root.join("ReceiptFixture");
    compile(&helper_source, &helper, &root);
    let target = root.join("DocumentTarget");
    fs::copy(&helper, &target).unwrap();
    let state = root.join("target.state");
    let mut target_child = FixtureChild(
        Command::new(&target)
            .env("CW_RECEIPT_TARGET_ROOT", &root)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                fs::File::create(root.join("target.stderr")).unwrap(),
            ))
            .spawn()
            .unwrap(),
    );
    wait_for(&state, "READY");
    assert!(target_child.0.try_wait().unwrap().is_none());

    // Real sender -> production raw ingress -> verified PID -> native AppKit
    // document window -> standard reply all the way back to the first sender.
    let document = root.join("document.md");
    fs::write(&document, "receipt-fixture-document").unwrap();
    let (mut wrapper, log) = start_wrapper(&root, &target, "success");
    assert_reply(
        sender(&helper, wrapper.0.id(), "file", document.to_str().unwrap())
            .output()
            .unwrap(),
        0,
    );
    wait_for(&state, "DOCUMENT_OPENED");
    assert_eq!(
        fs::read_to_string(&state)
            .unwrap()
            .matches("FILE_READ=")
            .count(),
        1
    );
    wait_for(&log, "incoming_apple_event_completed");

    // No-reply requests still run, but do not create an artificial reply owner.
    let replies_before = fs::read_to_string(&log)
        .unwrap()
        .matches("incoming_apple_event_completed")
        .count();
    assert_reply(
        sender(&helper, wrapper.0.id(), "no-reply", "cw-fixture://no-reply")
            .output()
            .unwrap(),
        0,
    );
    wait_for(&state, "URL=cw-fixture://no-reply");
    // Production diagnostics deliberately remove raw URLs. Wait for the actual
    // structured forwarding completion rather than demanding leaked payloads.
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let events: Vec<serde_json::Value> = fs::read_to_string(&log).unwrap().lines()
            .map(|line| serde_json::from_str(line).unwrap()).collect();
        let forwarded: Vec<_> = events.iter().filter(|event|
            event["event"] == "forward_open_items" && event["url_count"] == 1).collect();
        if let Some(event) = forwarded.first() {
            assert_eq!(forwarded.len(), 1, "no-reply input must be forwarded exactly once");
            assert_eq!(event["status"], "ok");
            assert_eq!(event["apple_event_reply_confirmed"], true);
            break;
        }
        assert!(Instant::now() < deadline, "missing no-reply forwarding completion: {events:?}");
        thread::sleep(Duration::from_millis(15));
    }
    assert!(!fs::read_to_string(&log).unwrap().contains("cw-fixture://no-reply"),
        "diagnostic logs must not retain the raw URL");
    assert_eq!(
        fs::read_to_string(&log)
            .unwrap()
            .matches("incoming_apple_event_completed")
            .count(),
        replies_before
    );

    // Invalid standard payloads fail synchronously without reaching the target.
    let state_before = fs::read_to_string(&state).unwrap();
    for mode in [
        "empty-files",
        "bad-files",
        "missing",
        "empty-url",
        "relative-url",
    ] {
        assert_reply(
            sender(&helper, wrapper.0.id(), mode, "").output().unwrap(),
            -1700,
        );
    }
    assert_eq!(fs::read_to_string(&state).unwrap(), state_before);
    assert!(wrapper.0.try_wait().unwrap().is_none());
    drop(wrapper);

    // The second event arrives while the first forwarding operation is awaiting
    // its target reply. Its failure must never inherit the first batch's success.
    let (mut wrapper, late_log) = start_wrapper(&root, &target, "late-failure");
    let first = sender(&helper, wrapper.0.id(), "url", "cw-fixture://slow")
        .spawn()
        .unwrap();
    wait_for(&state, "SLOW_RECEIVED");
    let second = sender(&helper, wrapper.0.id(), "url", "cw-fixture://reject")
        .spawn()
        .unwrap();
    assert_reply(first.wait_with_output().unwrap(), 0);
    assert_reply(second.wait_with_output().unwrap(), -10000);
    assert_eq!(wrapper.0.wait().unwrap().code(), Some(74));
    let late_events = fs::read_to_string(&late_log).unwrap();
    assert_eq!(
        late_events
            .matches("incoming_apple_event_completed")
            .count(),
        2
    );
    assert!(late_events.contains("apple_event_target_failed"));
    drop(wrapper);

    // A native target which reads but does not present a document can withhold
    // AppKit completion. The wrapper must return failure after its timeout and
    // must not resend or convert delivery into successful completion.
    let withheld = root.join("withhold.md");
    fs::write(&withheld, "receipt-fixture-document").unwrap();
    let (mut wrapper, timeout_log) = start_wrapper(&root, &target, "timeout");
    assert_reply(
        sender(&helper, wrapper.0.id(), "file", withheld.to_str().unwrap())
            .output()
            .unwrap(),
        -10000,
    );
    assert_eq!(wrapper.0.wait().unwrap().code(), Some(74));
    let timeout_events = fs::read_to_string(&timeout_log).unwrap();
    assert_eq!(
        timeout_events.matches("apple_event_reply_timeout").count(),
        1
    );
    assert_eq!(
        timeout_events
            .matches("incoming_apple_event_completed")
            .count(),
        1
    );
    assert_eq!(
        fs::read_to_string(&state)
            .unwrap()
            .matches("FILE_READ=")
            .count(),
        2
    );

    // A source-level batch check covers pre-launch argv projections/duplicates;
    // it does not substitute for the real AppleEvent round trips above.
    let unit = Command::new(&helper).arg("startup-state").output().unwrap();
    assert!(
        unit.status.success(),
        "{}",
        String::from_utf8_lossy(&unit.stderr)
    );
    assert!(String::from_utf8_lossy(&unit.stdout).contains("STARTUP_DUPLICATES_OK"));
    eprintln!("standard inbound file success, no-reply, malformed payloads, late failure, and target timeout passed");
}

const FIXTURE_SOURCE: &str = r#"
@MainActor
final class ReceiptTargetDelegate: NSObject, NSApplicationDelegate {
    let root: URL
    var windows: [NSWindow] = []
    init(root: URL) { self.root = root }
    func record(_ line: String) {
        let url = root.appendingPathComponent("target.state")
        let before = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
        try! (before + line + "\n").write(to: url, atomically: true, encoding: .utf8)
    }
    func showWindow() {
        let window = NSWindow(contentRect: NSRect(x: 80, y: 80, width: 260, height: 100),
                              styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Controlled entry receipt fixture"
        window.isReleasedWhenClosed = false
        windows.append(window)
        window.makeKeyAndOrderFront(nil)
    }
    func applicationWillFinishLaunching(_ notification: Notification) {
        NSAppleEventManager.shared().setEventHandler(self, andSelector: #selector(getURL(_:reply:)),
            forEventClass: AEEventClass(kInternetEventClass), andEventID: AEEventID(kAEGetURL))
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        let identity = ControlledEntryDelegate().inspectKernelProcessIdentity(pid: getpid())!
        let instance: [String: Any] = ["instance_id":"receipt-fixture", "entry_id":"receipt-fixture",
            "target":"receipt-fixture", "pid":getpid(), "uid":getuid(),
            "start_seconds":identity.startSec, "start_microseconds":identity.startUsec,
            "expected_executable":identity.canonicalPath, "verified_executable":identity.canonicalPath,
            "state":"exec_verified", "executor_boot_id":"receipt-test-boot"]
        try! JSONSerialization.data(withJSONObject: [instance]).write(to: root.appendingPathComponent("managed-launch-instances.json"))
        try! JSONSerialization.data(withJSONObject: ["executor_boot_id":"receipt-test-boot"]).write(to: root.appendingPathComponent("seatbelt-runtime.json"))
        showWindow()
        record("READY")
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows: Bool) -> Bool {
        windows.first?.makeKeyAndOrderFront(nil)
        return true
    }
    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        for filename in filenames {
            let contents = try? String(contentsOfFile: filename, encoding: .utf8)
            record("FILE_READ=\(filename)")
            guard contents == "receipt-fixture-document" else {
                sender.reply(toOpenOrPrint: .failure)
                return
            }
            if !filename.hasSuffix("withhold.md") { showWindow(); record("DOCUMENT_OPENED") }
        }
        sender.reply(toOpenOrPrint: .success)
    }
    @objc func getURL(_ event: NSAppleEventDescriptor, reply: NSAppleEventDescriptor) {
        let url = event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))!.stringValue!
        record("URL=\(url)")
        if url == "cw-fixture://slow" {
            let manager = NSAppleEventManager.shared()
            let suspensionID = manager.suspendCurrentAppleEvent()!
            record("SLOW_RECEIVED")
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                manager.replyAppleEvent(forSuspensionID: suspensionID).setParam(NSAppleEventDescriptor(int32: 0), forKeyword: AEKeyword(keyErrorNumber))
                manager.resume(withSuspensionID: suspensionID)
            }
        } else {
            reply.setParam(NSAppleEventDescriptor(int32: url == "cw-fixture://reject" ? -10000 : 0), forKeyword: AEKeyword(keyErrorNumber))
        }
    }
}

extension ControlledEntryDelegate {
    static func checkStartupState() {
        let delegate = ControlledEntryDelegate()
        let file = URL(fileURLWithPath: "/private/tmp/receipt-duplicate.md")
        delegate.application(NSApplication.shared, open: [file])
        delegate.enqueueFiles([file.path])
        precondition(!delegate.actionRunning && !delegate.hasFinishedLaunching)
        let batch = delegate.takePendingActionBatch()
        precondition(batch.files == [file.path] && batch.incomingReplies.isEmpty)
        let invalid = NSAppleEventDescriptor.appleEvent(withEventClass: AEEventClass(kCoreEventClass),
            eventID: AEEventID(kAEOpenDocuments), targetDescriptor: nil,
            returnID: AEReturnID(kAutoGenerateReturnID), transactionID: AETransactionID(kAnyTransactionID))
        let reply = NSAppleEventDescriptor.appleEvent(withEventClass: AEEventClass(kCoreEventClass),
            eventID: AEEventID(kAEAnswer), targetDescriptor: nil,
            returnID: AEReturnID(kAutoGenerateReturnID), transactionID: AETransactionID(kAnyTransactionID))
        delegate.receiveOpenDocuments(invalid, reply: reply)
        precondition(delegate.receivedStandardOpenEvent && delegate.pendingFiles.isEmpty && delegate.pendingIncomingReplies.isEmpty)
        precondition(reply.paramDescriptor(forKeyword: AEKeyword(keyErrorNumber))?.int32Value == -1700)
        print("STARTUP_DUPLICATES_OK")
    }
}

@main struct ReceiptFixtureMain {
    @MainActor static func main() {
        let args = CommandLine.arguments
        if let root = ProcessInfo.processInfo.environment["CW_RECEIPT_TARGET_ROOT"] {
            let app = NSApplication.shared
            app.setActivationPolicy(.regular)
            let delegate = ReceiptTargetDelegate(root: URL(fileURLWithPath: root))
            app.delegate = delegate
            app.run()
            return
        }
        if args[1] == "startup-state" { ControlledEntryDelegate.checkStartupState(); return }
        var pid = Int32(args[2])!
        let mode = args[3], value = args[4]
        let filesMode = ["file", "empty-files", "bad-files", "missing"].contains(mode)
        let target = NSAppleEventDescriptor(descriptorType: DescType(typeKernelProcessID), bytes: &pid, length: MemoryLayout<Int32>.size)
        let event = NSAppleEventDescriptor.appleEvent(
            withEventClass: filesMode ? AEEventClass(kCoreEventClass) : AEEventClass(kInternetEventClass),
            eventID: filesMode ? AEEventID(kAEOpenDocuments) : AEEventID(kAEGetURL), targetDescriptor: target,
            returnID: AEReturnID(kAutoGenerateReturnID), transactionID: AETransactionID(kAnyTransactionID))
        if filesMode {
            let list = NSAppleEventDescriptor.list()
            if mode == "file" { list.insert(NSAppleEventDescriptor(fileURL: URL(fileURLWithPath: value)), at: 1) }
            if mode == "bad-files" { list.insert(NSAppleEventDescriptor(int32: 42), at: 1) }
            if mode != "missing" { event.setParam(list, forKeyword: AEKeyword(keyDirectObject)) }
        } else {
            event.setParam(NSAppleEventDescriptor(string: mode == "empty-url" ? "" : mode == "relative-url" ? "relative-path" : value), forKeyword: AEKeyword(keyDirectObject))
        }
        var reply = AEDesc()
        let noReply = mode == "no-reply"
        let status = AESendMessage(event.aeDesc!, &reply, AESendMode(noReply ? kAENoReply : kAEWaitReply), 420)
        var error: Int32 = 0
        if status == noErr && !noReply {
            let descriptor = NSAppleEventDescriptor(aeDescNoCopy: &reply)
            error = descriptor.paramDescriptor(forKeyword: AEKeyword(keyErrorNumber))?.int32Value ?? 0
        } else { AEDisposeDesc(&reply) }
        print("TRANSPORT=\(status) ERROR=\(error)")
    }
}
"#;
