import AppKit
import ApplicationServices
import Carbon
import Darwin
import Foundation

struct ControlledEntryLaunchBinding {
    static func arguments(target: String, bundlePath: String) -> [String] {
        var arguments = ["launch", "--target", target, "--apply"]
        if !bundlePath.isEmpty { arguments += ["--target-bundle", bundlePath] }
        return arguments
    }
}

#if !CONTROLLED_ENTRY_BINDING_TESTS
/// Controlled desktop wrapper entry (`io.local.watchpanel.entry.<target-id>`).
///
/// Key invariants (`Section 四.3 & 四.4`, `R3`, `R5`, `D01`–`D06`):
/// 1. Runs a real `NSApplication` + `NSApplicationDelegate` lifecycle supporting:
///    - Dock / Finder reopen (`applicationShouldHandleReopen(_:hasVisibleWindows:)`)
///    - Standard URL/file events via `NSAppleEventManager`, with explicit
///      suspension ownership while forwarding asynchronously.
///    - AppKit URL/file delegate callbacks for direct-invocation arguments.
/// 2. Strictly verifies running target instances against Watch's `managed-launch-instances.json`,
///    `seatbelt-runtime.json`, and live kernel `proc_pidinfo` / `proc_pidpath` identity:
///    - Requires `seatbelt-runtime.json` with non-empty `executor_boot_id`.
///    - Requires `rec.state == "exec_verified"` and `rec.executor_boot_id == rtBootId`.
///    - Verifies live kernel `uid`, `pid`, `start_seconds`, `start_microseconds`, and canonical
///      executable path (`verified_executable` / `expected_executable`).
///    - Only activates or forwards events to the verified main target PID (`R3.2`).
///    - If an unmanaged instance of the target is running (`D02`), outputs
///      `already_running_unmanaged` (`running_unprotected`), NEVER terminates the user's
///      unmanaged window, and NEVER activates or forwards files/URLs to it.

struct ManagedInstanceRecord: Decodable {
    let instance_id: String
    let entry_id: String
    let target: String
    let pid: UInt32
    let uid: UInt32
    let start_seconds: UInt64
    let start_microseconds: UInt32
    let expected_executable: String
    let verified_executable: String?
    let state: String
    let executor_boot_id: String
    let controlled_subtree_pids: [UInt32]?
}

struct SeatbeltRuntimeRecord: Decodable {
    let executor_boot_id: String
    let gateway_endpoint: String?
    let registration_socket: String?
    let sandbox_ready: Bool?
}

enum InstanceAuditResult {
    case noneRunning
    case verifiedManaged(pid: pid_t, instanceId: String)
    case unmanagedRunning(pids: [pid_t])
}

@MainActor
final class ControlledEntryDelegate: NSObject, NSApplicationDelegate {
    let env = ProcessInfo.processInfo.environment
    let info = Bundle.main.infoDictionary ?? [:]

    lazy var target: String = {
        env["CW_ENTRY_TARGET"]
            ?? (info["CWTarget"] as? String)
            ?? (info["CWManagedEntryTarget"] as? String)
            ?? "claude-desktop"
    }()

    lazy var targetBundleId: String = {
        env["CW_TARGET_BUNDLE_ID"]
            ?? (info["CWTargetBundleId"] as? String)
            ?? defaultBundleId(for: target)
    }()

    lazy var targetExecutable: String = {
        env["CW_TARGET_EXECUTABLE"]
            ?? (info["CWTargetExecutable"] as? String)
            ?? ""
    }()

    lazy var targetBundlePath: String = {
        env["CW_TARGET_BUNDLE_PATH"] ?? (info["CWTargetBundlePath"] as? String) ?? ""
    }()

    lazy var watchBin: String = {
        env["CW_WATCH_BINARY"]
            ?? (info["CWWatchBin"] as? String)
            ?? (info["CWWatchBinaryPath"] as? String)
            ?? "\(NSHomeDirectory())/.local/bin/claude-watch"
    }()

    lazy var watchStateDir: String = {
        if let dir = env["CW_WATCH_STATE_DIR"], !dir.isEmpty {
            return dir
        }
        return (info["CWWatchStateDirPath"] as? String)
            ?? "\(NSHomeDirectory())/Library/Application Support/ClaudeWatch/state"
    }()

    lazy var eventLogPath: String? = {
        env["CW_ENTRY_EVENT_LOG"]
    }()

    private var pendingURLs: [URL] = []
    private var pendingFiles: [String] = []
    private var hasCompletedInitialAction = false
    private var hasFinishedLaunching = false
    private var receivedStandardOpenEvent = false
    private struct IncomingAppleEventReply {
        let suspensionID: NSAppleEventManager.SuspensionID
        let returnID: Int32?
    }
    private var pendingIncomingReplies: [IncomingAppleEventReply] = []
    private var actionRunning = false
    private var actionFailureExitCode: Int32 = 74
    private var requestedTrigger: String?
    private var idleGeneration: UInt64 = 0
    private struct EntryActionBatch {
        let urls: [String]
        let files: [String]
        let incomingReplies: [IncomingAppleEventReply]
    }

    private func takePendingActionBatch() -> EntryActionBatch {
        let batch = EntryActionBatch(urls: pendingURLs.map(\.absoluteString), files: pendingFiles,
                                     incomingReplies: pendingIncomingReplies)
        pendingURLs.removeAll()
        pendingFiles.removeAll()
        pendingIncomingReplies.removeAll()
        return batch
    }

    private func completeIncomingReplies(_ replies: [IncomingAppleEventReply], success: Bool) {
        let manager = NSAppleEventManager.shared()
        for incoming in replies {
            // The suspension ID, not the current event or a copied descriptor,
            // owns this original sender's reply across asynchronous forwarding.
            let reply = manager.replyAppleEvent(forSuspensionID: incoming.suspensionID)
            reply.setParam(NSAppleEventDescriptor(int32: success ? 0 : Int32(errAEEventFailed)),
                           forKeyword: AEKeyword(keyErrorNumber))
            manager.resume(withSuspensionID: incoming.suspensionID)
            var log: [String: Any] = ["event": "incoming_apple_event_completed", "status": success ? "ok" : "error"]
            if let returnID = incoming.returnID { log["return_id"] = returnID }
            appendEventLog(log)
        }
    }

    private func rejectIncomingEvent(_ reply: NSAppleEventDescriptor) {
        if reply.descriptorType != DescType(typeNull) {
            reply.setParam(NSAppleEventDescriptor(int32: Int32(errAECoercionFail)),
                           forKeyword: AEKeyword(keyErrorNumber))
        }
        appendEventLog(["event": "incoming_apple_event_rejected", "status": "error", "os_status": Int(errAECoercionFail)])
    }

    private func acceptIncomingItems(_ urls: [URL], event: NSAppleEventDescriptor,
                                     reply: NSAppleEventDescriptor, trigger: String) {
        if reply.descriptorType != DescType(typeNull) {
            let returnID = event.attributeDescriptor(forKeyword: AEKeyword(keyReturnIDAttr))?.int32Value
            guard let suspensionID = NSAppleEventManager.shared().suspendCurrentAppleEvent() else {
                reply.setParam(NSAppleEventDescriptor(int32: Int32(errAEEventFailed)),
                               forKeyword: AEKeyword(keyErrorNumber))
                return
            }
            pendingIncomingReplies.append(IncomingAppleEventReply(
                suspensionID: suspensionID,
                returnID: returnID
            ))
        }
        // A no-reply sender still requests the operation. Only reply ownership
        // is omitted. Deduplicating payloads never deduplicates sender receipts.
        enqueueURLs(urls)
        if hasFinishedLaunching { requestAction(trigger: trigger) }
    }

    @objc private func receiveOpenDocuments(_ event: NSAppleEventDescriptor, reply: NSAppleEventDescriptor) {
        receivedStandardOpenEvent = true
        guard let list = event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject)),
              list.descriptorType == DescType(typeAEList), list.numberOfItems > 0 else {
            rejectIncomingEvent(reply)
            return
        }
        var urls: [URL] = []
        for index in 1...list.numberOfItems {
            guard let url = list.atIndex(index)?.fileURLValue, url.isFileURL, !url.path.isEmpty else {
                rejectIncomingEvent(reply)
                return
            }
            urls.append(url)
        }
        acceptIncomingItems(urls, event: event, reply: reply, trigger: "open_file")
    }

    @objc private func receiveGetURL(_ event: NSAppleEventDescriptor, reply: NSAppleEventDescriptor) {
        receivedStandardOpenEvent = true
        guard let rawURL = event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue,
              !rawURL.isEmpty, let url = URL(string: rawURL),
              let scheme = url.scheme, !scheme.isEmpty else {
            rejectIncomingEvent(reply)
            return
        }
        acceptIncomingItems([url], event: event, reply: reply, trigger: "open_url")
    }

    private struct PendingAppleEvent {
        let pid: pid_t
        let uid: UInt32
        let startSeconds: UInt64
        let startMicroseconds: UInt32
        let executable: String
        let complete: (Bool) -> Void
    }
    private var pendingAppleEvents: [Int32: PendingAppleEvent] = [:]
    private lazy var commandLineURLFileProjections: Set<String> = {
        let args = Array(CommandLine.arguments.dropFirst())
        return Set(args.indices.compactMap { index in
            guard args[index] == "--open-url", index + 1 < args.count else { return nil }
            return URL(fileURLWithPath: args[index + 1]).standardizedFileURL.path
        })
    }()

    private func enqueueFiles(_ filenames: [String], fromAppKit: Bool = false) {
        for name in filenames {
            let path = URL(fileURLWithPath: name).standardizedFileURL.path
            // Direct invocation can make AppKit project a --open-url argv
            // value into a bogus document path before didFinishLaunching.
            if fromAppKit && !hasCompletedInitialAction && commandLineURLFileProjections.contains(path) {
                continue
            }
            if !pendingFiles.contains(path) { pendingFiles.append(path) }
        }
    }

    private func enqueueURLs(_ urls: [URL], fromAppKit: Bool = false) {
        for url in urls {
            if url.isFileURL {
                enqueueFiles([url.path], fromAppKit: fromAppKit)
            } else if !pendingURLs.contains(url) {
                pendingURLs.append(url)
            }
        }
    }

    private func defaultBundleId(for target: String) -> String {
        switch target {
        case "codex-desktop":
            return "com.openai.codex"
        case "chatgpt-desktop":
            return "com.openai.chat"
        default:
            return "com.anthropic.claudefordesktop"
        }
    }

    func appendEventLog(_ payload: [String: Any]) {
        guard let logPath = eventLogPath, !logPath.isEmpty else { return }
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]),
              var line = String(data: data, encoding: .utf8) else {
            return
        }
        line.append("\n")
        let url = URL(fileURLWithPath: logPath)
        if FileManager.default.fileExists(atPath: logPath),
           let fh = try? FileHandle(forWritingTo: url) {
            fh.seekToEndOfFile()
            fh.write(Data(line.utf8))
            try? fh.close()
        } else {
            try? Data(line.utf8).write(to: url, options: .atomic)
        }
    }

    func inspectKernelProcessIdentity(pid: pid_t) -> (uid: UInt32, ppid: UInt32, startSec: UInt64, startUsec: UInt32, canonicalPath: String)? {
        if pid <= 1 { return nil }
        var bsd = proc_bsdinfo()
        let bsdSize = proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            &bsd,
            Int32(MemoryLayout<proc_bsdinfo>.size)
        )
        if bsdSize != Int32(MemoryLayout<proc_bsdinfo>.size) {
            return nil
        }
        var pathBuf = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let pathLen = proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count))
        guard pathLen > 0 else { return nil }
        let rawPath = String(cString: pathBuf)
        let canonPath = URL(fileURLWithPath: rawPath).resolvingSymlinksInPath().path
        return (
            uid: bsd.pbi_uid,
            ppid: bsd.pbi_ppid,
            startSec: bsd.pbi_start_tvsec,
            startUsec: UInt32(bsd.pbi_start_tvusec),
            canonicalPath: canonPath
        )
    }

    func loadVerifiedInstances() -> (bootId: String?, instances: [ManagedInstanceRecord]) {
        let rtURL = URL(fileURLWithPath: "\(watchStateDir)/seatbelt-runtime.json")
        guard let rtData = try? Data(contentsOf: rtURL),
              let rt = try? JSONDecoder().decode(SeatbeltRuntimeRecord.self, from: rtData) else {
            return (nil, [])
        }
        let rtBootId = rt.executor_boot_id.trimmingCharacters(in: .whitespacesAndNewlines)
        if rtBootId.isEmpty {
            return (nil, [])
        }

        let instURL = URL(fileURLWithPath: "\(watchStateDir)/managed-launch-instances.json")
        guard let data = try? Data(contentsOf: instURL),
              let list = try? JSONDecoder().decode([ManagedInstanceRecord].self, from: data) else {
            return (rtBootId, [])
        }
        let currentUid = getuid()
        let canonConfiguredTarget = targetExecutable.isEmpty
            ? nil
            : URL(fileURLWithPath: targetExecutable).resolvingSymlinksInPath().path
        let entryBundleId = Bundle.main.bundleIdentifier
        let valid = list.filter { rec in
            guard rec.state == "exec_verified",
                  rec.executor_boot_id == rtBootId,
                  rec.uid == currentUid,
                  rec.target == target || (entryBundleId != nil && rec.entry_id == entryBundleId) else {
                return false
            }
            guard let live = inspectKernelProcessIdentity(pid: pid_t(rec.pid)) else {
                return false
            }
            guard live.uid == currentUid,
                  live.uid == rec.uid,
                  live.startSec == rec.start_seconds,
                  live.startUsec == rec.start_microseconds else {
                return false
            }
            let expectedExec = URL(fileURLWithPath: rec.verified_executable ?? rec.expected_executable)
                .resolvingSymlinksInPath().path
            if live.canonicalPath != expectedExec {
                return false
            }
            if let configured = canonConfiguredTarget, live.canonicalPath != configured {
                return false
            }
            return true
        }
        return (rtBootId, valid)
    }

    func discoverRunningTargetPids() -> [pid_t] {
        var pids = Set<pid_t>()
        let myPid = getpid()
        for app in NSWorkspace.shared.runningApplications {
            let pid = app.processIdentifier
            if pid <= 1 || pid == myPid { continue }
            if app.bundleIdentifier == targetBundleId {
                pids.insert(pid)
            } else if !targetExecutable.isEmpty,
                      let exeURL = app.executableURL,
                      exeURL.resolvingSymlinksInPath().path == URL(fileURLWithPath: targetExecutable).resolvingSymlinksInPath().path {
                pids.insert(pid)
            }
        }

        if !targetExecutable.isEmpty {
            let canonTarget = URL(fileURLWithPath: targetExecutable).resolvingSymlinksInPath().path
            let count = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
            if count > 0 {
                let capacity = Int(count) / MemoryLayout<pid_t>.size + 64
                var buf = [pid_t](repeating: 0, count: capacity)
                let actual = proc_listpids(
                    UInt32(PROC_ALL_PIDS),
                    0,
                    &buf,
                    Int32(capacity * MemoryLayout<pid_t>.size)
                )
                if actual > 0 {
                    let num = Int(actual) / MemoryLayout<pid_t>.size
                    let uid = getuid()
                    for i in 0..<num {
                        let pid = buf[i]
                        if pid <= 1 || pid == myPid { continue }
                        if let live = inspectKernelProcessIdentity(pid: pid),
                           live.uid == uid,
                           live.canonicalPath == canonTarget {
                            pids.insert(pid)
                        }
                    }
                }
            }
        }
        return Array(pids).sorted()
    }

    func auditRunningInstances() -> InstanceAuditResult {
        let runningPids = discoverRunningTargetPids()
        if runningPids.isEmpty {
            return .noneRunning
        }
        let (_, verified) = loadVerifiedInstances()
        var unmanaged: [pid_t] = []
        var matchedMain: (pid_t, String)?
        let currentUid = getuid()
        for pid in runningPids {
            let uPid = UInt32(pid)
            if let inst = verified.first(where: { $0.pid == uPid }) {
                if matchedMain == nil {
                    matchedMain = (pid, inst.instance_id)
                }
            } else if let parentInst = verified.first(where: { inst in
                guard inst.controlled_subtree_pids?.contains(uPid) ?? false,
                      let childLive = inspectKernelProcessIdentity(pid: pid) else {
                    return false
                }
                let expectedExec = URL(fileURLWithPath: inst.verified_executable ?? inst.expected_executable)
                    .resolvingSymlinksInPath().path
                return childLive.uid == currentUid
                    && childLive.uid == inst.uid
                    && (childLive.ppid == inst.pid || (inst.controlled_subtree_pids?.contains(childLive.ppid) ?? false))
                    && childLive.canonicalPath == expectedExec
            }) {
                // Inherited child in a verified main instance's subtree is managed,
                // but activation/forwarding ONLY targets the verified main PID (`R3.2`).
                if matchedMain == nil {
                    matchedMain = (pid_t(parentInst.pid), parentInst.instance_id)
                }
            } else {
                unmanaged.append(pid)
            }
        }
        if !unmanaged.isEmpty {
            return .unmanagedRunning(pids: unmanaged)
        }
        if let (mainPid, instId) = matchedMain {
            return .verifiedManaged(pid: mainPid, instanceId: instId)
        }
        return .noneRunning
    }

    func rejectUnmanaged(pids: [pid_t], trigger: String) {
        let errPayload: [String: Any] = [
            "status": "error",
            "code": "already_running_unmanaged",
            "state": "running_unprotected",
            "trigger": trigger,
            "target": target,
            "unmanaged_pids": pids,
            "message": "检测到未受控的已有应用实例正在运行（running_unprotected）；不会自动关闭或向其转发请求"
        ]
        appendEventLog(errPayload)
        if let data = try? JSONSerialization.data(withJSONObject: errPayload, options: [.sortedKeys]),
           let text = String(data: data, encoding: .utf8) {
            FileHandle.standardError.write(Data((text + "\n").utf8))
        }
    }

    private func finishAppleEvent(_ returnID: Int32, success: Bool) {
        // Removal makes timeout, duplicate and late replies idempotent.
        pendingAppleEvents.removeValue(forKey: returnID)?.complete(success)
    }

    @objc private func receiveAppleEventReply(_ event: NSAppleEventDescriptor, reply: NSAppleEventDescriptor) {
        guard let returnDescriptor = event.attributeDescriptor(forKeyword: AEKeyword(keyReturnIDAttr)) else { return }
        let returnID = returnDescriptor.int32Value
        guard let pending = pendingAppleEvents[returnID] else {
            appendEventLog(["event": "apple_event_reply_ignored", "reason": "unknown_or_finished_request", "return_id": returnID])
            return
        }
        // These attributes are supplied by the Apple Event transport, not by
        // application payload. Bind the reply to the same live kernel process.
        let senderPID = event.attributeDescriptor(forKeyword: AEKeyword(keySenderPIDAttr))?.int32Value
        let auditData = event.attributeDescriptor(forKeyword: AEKeyword(keySenderAuditTokenAttr))?.data
        var auditWords = [UInt32](repeating: 0, count: 8)
        if let data = auditData, data.count == MemoryLayout<UInt32>.size * 8 {
            _ = auditWords.withUnsafeMutableBytes { data.copyBytes(to: $0) }
        }
        guard senderPID == pending.pid, auditData?.count == 32,
              auditWords[5] == UInt32(pending.pid), auditWords[3] == pending.uid,
              let live = inspectKernelProcessIdentity(pid: pending.pid),
              live.uid == pending.uid, live.startSec == pending.startSeconds,
              live.startUsec == pending.startMicroseconds,
              live.canonicalPath == pending.executable else {
            appendEventLog(["event": "apple_event_reply_ignored", "reason": "sender_identity_mismatch", "return_id": returnID])
            return
        }
        if let error = event.paramDescriptor(forKeyword: AEKeyword(keyErrorNumber)) {
            guard let number = error.coerce(toDescriptorType: DescType(typeSInt32)) else {
                appendEventLog(["status": "error", "error": "apple_event_reply_invalid", "pid": pending.pid])
                finishAppleEvent(returnID, success: false)
                return
            }
            if number.int32Value != 0 {
                appendEventLog(["status": "error", "error": "apple_event_target_failed", "os_status": number.int32Value, "pid": pending.pid])
                finishAppleEvent(returnID, success: false)
                return
            }
        }
        appendEventLog(["event": "apple_event_reply_confirmed", "return_id": returnID, "verified_pid": pending.pid])
        finishAppleEvent(returnID, success: true)
    }

    private func sendTargetedAppleEvent(_ event: NSAppleEventDescriptor, toPid pid: pid_t, instanceId: String) async -> Bool {
        // Previous actions can await a reply for seconds. Recheck the actual
        // managed instance before each subsequent send, not just at action entry.
        guard loadVerifiedInstances().instances.contains(where: { $0.instance_id == instanceId && $0.pid == UInt32(pid) }),
              let identity = inspectKernelProcessIdentity(pid: pid),
              let eventPtr = event.aeDesc,
              let returnDescriptor = event.attributeDescriptor(forKeyword: AEKeyword(keyReturnIDAttr)) else {
            appendEventLog(["status": "error", "error": "target_identity_unverified", "pid": Int(pid)])
            return false
        }
        let returnID = returnDescriptor.int32Value
        guard pendingAppleEvents[returnID] == nil else { return false }
        return await withCheckedContinuation { continuation in
            pendingAppleEvents[returnID] = PendingAppleEvent(
                pid: pid, uid: identity.uid, startSeconds: identity.startSec,
                startMicroseconds: identity.startUsec, executable: identity.canonicalPath,
                complete: { continuation.resume(returning: $0) }
            )
            // A single send with a queued standard reply keeps AppKit's main
            // loop available for reply delivery. Successful send is not completion.
            let status = AESendMessage(eventPtr, nil, AESendMode(kAEQueueReply | kAECanInteract | kAECanSwitchLayer), 180)
            guard status == noErr else {
                appendEventLog(["status": "error", "error": "apple_event_send_failed", "outcome": "unconfirmed", "os_status": Int(status), "pid": Int(pid)])
                finishAppleEvent(returnID, success: false)
                return
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) { [weak self] in
                guard let self, self.pendingAppleEvents[returnID] != nil else { return }
                self.appendEventLog(["status": "error", "error": "apple_event_reply_timeout", "outcome": "unconfirmed", "os_status": Int(errAETimeout), "pid": Int(pid)])
                self.finishAppleEvent(returnID, success: false)
            }
        }
    }

    @discardableResult
    func activateVerifiedInstance(pid: pid_t, instanceId: String, reason: String) async -> Bool {
        let activated = NSRunningApplication(processIdentifier: pid)?
            .activate(options: [.activateAllWindows]) ?? false
        var targetPid = pid
        let targetDesc = NSAppleEventDescriptor(
            descriptorType: DescType(typeKernelProcessID),
            bytes: &targetPid,
            length: MemoryLayout<pid_t>.size
        )
        let reopenEvent = NSAppleEventDescriptor.appleEvent(
            withEventClass: AEEventClass(kCoreEventClass),
            eventID: AEEventID(kAEReopenApplication),
            targetDescriptor: targetDesc,
            returnID: AEReturnID(kAutoGenerateReturnID),
            transactionID: AETransactionID(kAnyTransactionID)
        )
        let aeSent = await sendTargetedAppleEvent(reopenEvent, toPid: pid, instanceId: instanceId)
        let ok = aeSent
        appendEventLog([
            "status": ok ? "ok" : "error",
            "event": reason,
            "verified_pid": pid,
            "instance_id": instanceId,
            "appkit_activated": activated,
            "apple_event_reply_confirmed": aeSent
        ])
        return ok
    }

    @discardableResult
    func forwardItemsToVerifiedInstance(pid: pid_t, instanceId: String, urls: [String], files: [String]) async -> Bool {
        guard !urls.isEmpty || !files.isEmpty else { return true }
        var targetPid = pid
        let targetDesc = NSAppleEventDescriptor(
            descriptorType: DescType(typeKernelProcessID),
            bytes: &targetPid,
            length: MemoryLayout<pid_t>.size
        )
        var allSent = true

        for u in urls {
            let getUrlEvent = NSAppleEventDescriptor.appleEvent(
                withEventClass: AEEventClass(kInternetEventClass),
                eventID: AEEventID(kAEGetURL),
                targetDescriptor: targetDesc,
                returnID: AEReturnID(kAutoGenerateReturnID),
                transactionID: AETransactionID(kAnyTransactionID)
            )
            getUrlEvent.setParam(NSAppleEventDescriptor(string: u), forKeyword: AEKeyword(keyDirectObject))
            if !(await sendTargetedAppleEvent(getUrlEvent, toPid: pid, instanceId: instanceId)) {
                allSent = false
            }
        }

        if !files.isEmpty {
            let openDocsEvent = NSAppleEventDescriptor.appleEvent(
                withEventClass: AEEventClass(kCoreEventClass),
                eventID: AEEventID(kAEOpenDocuments),
                targetDescriptor: targetDesc,
                returnID: AEReturnID(kAutoGenerateReturnID),
                transactionID: AETransactionID(kAnyTransactionID)
            )
            let listDesc = NSAppleEventDescriptor.list()
            for (idx, filePath) in files.enumerated() {
                let fileDesc = NSAppleEventDescriptor(fileURL: URL(fileURLWithPath: filePath))
                listDesc.insert(fileDesc, at: idx + 1)
            }
            openDocsEvent.setParam(listDesc, forKeyword: AEKeyword(keyDirectObject))
            if !(await sendTargetedAppleEvent(openDocsEvent, toPid: pid, instanceId: instanceId)) {
                allSent = false
            }
        }

        appendEventLog([
            "status": allSent ? "ok" : "partial_error",
            "event": "forward_open_items",
            "verified_pid": pid,
            "instance_id": instanceId,
            "urls": urls,
            "files": files,
            "apple_event_reply_confirmed": allSent
        ])
        return allSent
    }

    func performControlledLaunch() async -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: watchBin)
        process.arguments = ControlledEntryLaunchBinding.arguments(target: target, bundlePath: targetBundlePath)
        // Inherit the wrapper's streams. Do not wait before draining a bounded
        // pipe or block the AppKit event loop while the engine starts its child.
        process.standardOutput = FileHandle.standardOutput
        process.standardError = FileHandle.standardError
        let code: Int32 = await withCheckedContinuation { continuation in
            process.terminationHandler = { child in
                DispatchQueue.main.async { continuation.resume(returning: child.terminationStatus) }
            }
            do {
                try process.run()
            } catch {
                process.terminationHandler = nil
                self.appendEventLog(["status": "error", "code": "controlled_entry_spawn_failed", "detail": error.localizedDescription])
                continuation.resume(returning: 70)
            }
        }
        appendEventLog(["status": code == 0 ? "ok" : "error", "event": "controlled_launch_completed", "target": target, "exit_code": code])
        return code
    }

    @discardableResult
    private func handleInitialOrPendingAction(trigger: String, batch: EntryActionBatch) async -> Bool {
        switch auditRunningInstances() {
        case .unmanagedRunning(let pids):
            rejectUnmanaged(pids: pids, trigger: trigger)
            actionFailureExitCode = 75
            return false
        case .verifiedManaged(let pid, let instanceId):
            let actOk = await activateVerifiedInstance(pid: pid, instanceId: instanceId, reason: trigger)
            let fwdOk = await forwardItemsToVerifiedInstance(
                pid: pid,
                instanceId: instanceId,
                urls: batch.urls,
                files: batch.files
            )
            return actOk && fwdOk
        case .noneRunning:
            let code = await performControlledLaunch()
            if code != 0 {
                actionFailureExitCode = code
                return false
            }
            if !batch.urls.isEmpty || !batch.files.isEmpty {
                let deadline = Date().addingTimeInterval(3.0)
                while Date() < deadline {
                    if case .verifiedManaged(let pid, let instanceId) = auditRunningInstances() {
                        return await forwardItemsToVerifiedInstance(
                            pid: pid,
                            instanceId: instanceId,
                            urls: batch.urls,
                            files: batch.files
                        )
                    }
                    try? await Task.sleep(nanoseconds: 50_000_000)
                }
                return false
            }
            return true
        }
    }

    func applicationWillFinishLaunching(_ notification: Notification) {
        // Install after AppKit's defaults and before launch AppleEvents. The
        // wrapper has no document window: it owns completion explicitly rather
        // than relying on AppKit's window-ordering completion heuristic.
        let manager = NSAppleEventManager.shared()
        manager.setEventHandler(self, andSelector: #selector(receiveOpenDocuments(_:reply:)),
                                forEventClass: AEEventClass(kCoreEventClass), andEventID: AEEventID(kAEOpenDocuments))
        manager.setEventHandler(self, andSelector: #selector(receiveGetURL(_:reply:)),
                                forEventClass: AEEventClass(kInternetEventClass), andEventID: AEEventID(kAEGetURL))
        manager.setEventHandler(self, andSelector: #selector(receiveAppleEventReply(_:reply:)),
                                forEventClass: AEEventClass(kCoreEventClass), andEventID: AEEventID(kAEAnswer))
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // Parse CLI flags passed to ControlledEntry (--reopen, --open-url <u1>, --open-file <f1>)
        let rawArgs = Array(CommandLine.arguments.dropFirst())
        var idx = 0
        var explicitTrigger = "launch"
        while idx < rawArgs.count {
            switch rawArgs[idx] {
            case "--reopen":
                explicitTrigger = "reopen_window"
                idx += 1
            case "--open-url":
                if idx + 1 < rawArgs.count, let u = URL(string: rawArgs[idx + 1]) {
                    enqueueURLs([u])
                    explicitTrigger = "open_url"
                }
                idx += 2
            case "--open-file":
                if idx + 1 < rawArgs.count {
                    enqueueFiles([rawArgs[idx + 1]])
                    explicitTrigger = "open_file"
                }
                idx += 2
            default:
                idx += 1
            }
        }

        hasFinishedLaunching = true
        // A malformed external open request must not turn into a bare launch.
        if receivedStandardOpenEvent && pendingURLs.isEmpty && pendingFiles.isEmpty && explicitTrigger == "launch" {
            scheduleIdleTermination()
            return
        }
        // Return from launch notification before starting inter-application work.
        DispatchQueue.main.async { self.requestAction(trigger: explicitTrigger) }
    }

    private func requestAction(trigger: String) {
        requestedTrigger = trigger
        idleGeneration &+= 1
        guard !actionRunning else { return }
        actionRunning = true
        Task { @MainActor in
            while let nextTrigger = self.requestedTrigger {
                self.requestedTrigger = nil
                // Freeze the payload and its completion responsibility together
                // BEFORE any await. Later AppKit events belong to the next drain
                // and must never receive this earlier action's success reply.
                let batch = self.takePendingActionBatch()
                let actionOk = await self.handleInitialOrPendingAction(trigger: nextTrigger, batch: batch)
                self.hasCompletedInitialAction = true
                self.completeIncomingReplies(batch.incomingReplies, success: actionOk)
                if !actionOk {
                    // Later events have not run. Fail each original request
                    // before exit; none may inherit this batch's success.
                    let abandoned = self.takePendingActionBatch()
                    self.completeIncomingReplies(abandoned.incomingReplies, success: false)
                    self.appendEventLog(["status": "error", "error": "entry_action_failed", "trigger": nextTrigger])
                    exit(self.actionFailureExitCode)
                }
            }
            self.actionRunning = false
            self.scheduleIdleTermination()
        }
    }

    private func scheduleIdleTermination() {
        let generation = idleGeneration
        let stayInLoopMs = Int(env["CW_ENTRY_EVENT_LOOP_MS"] ?? "50") ?? 50
        DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(max(10, stayInLoopMs))) {
            guard !self.actionRunning, self.idleGeneration == generation else { return }
            NSApplication.shared.terminate(nil)
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        requestAction(trigger: "reopen_window")
        // The wrapper has no window to reopen; the queued action targets only
        // the verified managed PID and records its own confirmed result.
        return false
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        enqueueURLs(urls, fromAppKit: true)
        // AppKit may project direct-invocation argv through these callbacks.
        // Real odoc/GURL events use the raw handlers and carry their own reply.
        if hasFinishedLaunching { requestAction(trigger: "open_url") }
    }

    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        enqueueFiles(filenames, fromAppKit: true)
        if hasFinishedLaunching { requestAction(trigger: "open_file") }
    }
}

@main
struct ControlledEntryApp {
    @MainActor
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        let delegate = ControlledEntryDelegate()
        app.delegate = delegate
        app.run()
    }
}
#endif
