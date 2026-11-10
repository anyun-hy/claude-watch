import Darwin
import Foundation

@MainActor private final class FlowLogChecks: InitializationChecking {
    var failedStep: InitializationStep?
    var approvalNeeded = false
    var invalidations: [InitializationStep: InitializationResult] = [:]
    var refreshOutcome: InitializationRefreshOutcome = .passed(validUntil: Date().timeIntervalSince1970 + 120)
    let request = InitializationApproval(id: "secret-plan-id", action: .protection, title: "private-title",
                                         detail: "https://user:private-password@private.example/path", changes: ["private-file"])
    func begin() {}
    func check(_ step: InitializationStep) async -> InitializationResult {
        if failedStep == step { return .failed(code: step == .verification ? "protection_not_ready" : "fixture_failure", detail: "private-password 203.0.113.99 /private/file") }
        if step == .protection && approvalNeeded { return .approval(request) }
        return .passed("private-password", validUntil: step == .verification ? Date().timeIntervalSince1970 + 120 : nil)
    }
    func approve(_ request: InitializationApproval, progress: @escaping SetupProgressObserver) async -> InitializationResult {
        progress(.verifyEgress); approvalNeeded = false; return .passed("private-password")
    }
    func validateCurrentEvidence() -> InitializationResult { .passed("private-password", validUntil: Date().timeIntervalSince1970 + 120) }
    func currentEvidenceFailures() -> [InitializationStep: InitializationResult] { invalidations }
    func refreshWaitingEvidence() async -> InitializationRefreshOutcome { refreshOutcome }
    func diagnosticReason(for step: InitializationStep) -> String? { step == .verification ? "gateway_not_installed" : nil }
    func finish() {}
}

@main struct InitializationFlowLogTests {
    @MainActor static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cw-flow-log-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let logs = root.appendingPathComponent("logs")
        let identity: [String: Any] = ["AppBuild": "381", "CFBundleShortVersionString": "3.0.0",
            "SourceRevision": String(repeating: "a", count: 40), "SourceTreeDigest": String(repeating: "b", count: 64), "SourceDirty": true]
        var assertions = 0
        func expect(_ condition: Bool, _ label: String) {
            assertions += 1
            if !condition { fputs("FAIL: \(label)\n", stderr); exit(1) }
        }
        func records(_ directory: URL, prefix: String) throws -> [[String: Any]] {
            try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
                .filter { $0.lastPathComponent.hasPrefix(prefix) && $0.pathExtension == "jsonl" }
                .flatMap { try String(contentsOf: $0, encoding: .utf8).split(separator: "\n").map {
                    try JSONSerialization.jsonObject(with: Data($0.utf8)) as! [String: Any]
                } }
        }
        // Every real coordinator step records start and failed result before
        // returning; the exact protection cause survives without UI text.
        for step in InitializationStep.allCases {
            let checks = FlowLogChecks(); checks.failedStep = step
            let log = BoundedDiagnosticLog(component: "initialization_flow", directory: logs, identity: identity)
            let flow = FirstRunInitialization(checks: checks, completed: false, diagnosticLog: log, saveCompletion: {})
            await flow.start()
            let rows = try records(logs, prefix: "initialization-flow-").filter { $0["attempt_id"] as? String == log.runID }
            expect(rows.contains { $0["event"] as? String == "step_started" && $0["step"] as? String == step.rawValue }, "step start retained")
            let result = rows.first { $0["event"] as? String == "step_result" && $0["step"] as? String == step.rawValue && $0["status"] as? String == "failed" }
            expect(result != nil && !flow.entered, "each step's failure persisted without passing gate")
            if step == .verification { expect(result?["cause_code"] as? String == "gateway_not_installed", "specific underlying guard failure retained") }
            expect(rows.allSatisfy { $0["app_build"] as? String == "381" && $0["source_dirty"] as? Bool == true }, "build identity on every record")
            expect(!flow.diagnosticReport.contains("private-password") && !flow.diagnosticReport.contains("203.0.113.99"), "flow report excludes sensitive details")
        }
        let checks = FlowLogChecks(); checks.failedStep = .dns
        let log = BoundedDiagnosticLog(component: "initialization_flow", directory: logs, identity: identity)
        let flow = FirstRunInitialization(checks: checks, completed: false, diagnosticLog: log, saveCompletion: {})
        await flow.start()
        let originalAttempt = log.runID
        let failurePath = URL(fileURLWithPath: log.paths.last!)
        let failureBytes = try Data(contentsOf: failurePath)
        checks.failedStep = nil; checks.approvalNeeded = true
        await flow.retry()
        expect(log.runID != originalAttempt && flow.approval != nil, "retry has distinct attempt and retains approval gate")
        await flow.authorize(checks.request)
        expect(flow.allPassed && flow.canEnter(at: Date().timeIntervalSince1970), "logging does not change readiness")
        let preserved = try Data(contentsOf: failurePath)
        expect(preserved == failureBytes, "successful retry preserves original failed attempt")
        checks.invalidations = [.connection: .failed(code: "context_changed", detail: "private-password")]
        flow.refreshReadiness()
        expect(!flow.allPassed && !flow.canEnter(at: Date().timeIntervalSince1970), "evidence invalidation remains blocking")
        let history = try records(logs, prefix: "initialization-flow-")
        expect(history.contains { $0["event"] as? String == "authorization_progress" }, "authorization progress logged")
        expect(history.contains { $0["event"] as? String == "evidence_invalidated" && $0["step"] as? String == "connection" }, "lost evidence logged")
        checks.invalidations = [:]
        await flow.retry(); await flow.enter()
        expect(flow.entered && flow.diagnosticReport.contains("initialization_completed"), "successful completion persisted")
        // Automatic multi-row refresh changes also have durable results.
        let refreshChecks = FlowLogChecks()
        let refreshLog = BoundedDiagnosticLog(component: "initialization_flow", directory: logs)
        let refresh = FirstRunInitialization(checks: refreshChecks, completed: false, diagnosticLog: refreshLog, saveCompletion: {})
        await refresh.start()
        refreshChecks.refreshOutcome = .failed(step: .dns, code: "fixture_dns_timeout", detail: "private-password")
        refresh.refreshReadiness(at: Date().addingTimeInterval(3600))
        refresh.refreshReadiness(at: Date().addingTimeInterval(3601))
        for _ in 0..<50 where refresh.running { try await Task.sleep(nanoseconds: 1_000_000) }
        expect(refresh.rows.first { $0.step == .dns }?.status == .failed, "automatic refresh failed as supplied")
        expect(refreshLog.report.contains("refresh_result") && refreshLog.report.contains("fixture_dns_timeout"), "automatic refresh results persisted")

        // Actual production factory must write by default without the old
        // CW_ENTRY_EVENT_LOG environment opt-in. It still uses an owned temp root.
        let runtime = root.appendingPathComponent("runtime")
        try FileManager.default.createDirectory(at: runtime, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let build: [String: Any] = ["app_build": "381", "source_revision": String(repeating: "c", count: 40), "source_dirty": true,
                                    "source_tree_digest": String(repeating: "d", count: 64)]
        try JSONSerialization.data(withJSONObject: build).write(to: runtime.appendingPathComponent("BuildIdentity.json"))
        let entry = ControlledEntryDiagnosticFields.logger(stateDirectory: root.appendingPathComponent("state").path)
        let instance = "sandbox-inst-" + UUID().uuidString.lowercased()
        let sanitized = ControlledEntryDiagnosticFields.sanitize([
            "event": "forward_open_items", "status": "error", "files": ["/Users/private/secret.txt"],
            "urls": ["https://private-user:private-password@private.example/?token=secret"], "detail": "private-password",
            "message": "private-message", "instance_id": instance, "pid": Int32(42), "os_status": -1712,
            "error": "apple_event_reply_timeout", "apple_event_reply_confirmed": false])
        entry.append(sanitized)
        let entryRows = try records(logs, prefix: "controlled-entry-")
        let row = entryRows.first!
        expect(row["file_count"] as? Int == 1 && row["url_count"] as? Int == 1, "desktop records counts only")
        expect(row["os_status"] as? Int == -1712 && row["pid"] as? Int == 42 && row["instance_id"] as? String == instance, "desktop correlation and failure codes retained")
        expect(row["app_build"] as? String == "381" && row["source_revision"] as? String == String(repeating: "c", count: 40), "entry reads runtime build identity")
        expect(!entry.report.contains("private-password") && !entry.report.contains("secret.txt") && !entry.report.contains("private.example"), "default entry log excludes payloads")
        // Rotation bounds total bytes and count, including repeated attempts.
        let rotation = root.appendingPathComponent("rotation")
        try FileManager.default.createDirectory(at: rotation, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let oldLargeFile = rotation.appendingPathComponent("initialization-flow-" + UUID().uuidString + ".jsonl")
        FileManager.default.createFile(atPath: oldLargeFile.path, contents: Data(repeating: 32, count: 16 * 1024), attributes: [.posixPermissions: 0o600])
        let bounded = BoundedDiagnosticLog(component: "initialization_flow", directory: rotation, maxBytes: 4096, maxFiles: 2)
        for index in 0..<80 { if index % 10 == 0 { bounded.begin() }; bounded.append(["event": "fixture", "index": index]) }
        let rotated = try FileManager.default.contentsOfDirectory(at: rotation, includingPropertiesForKeys: [.fileSizeKey])
        let total = try rotated.reduce(0) { try $0 + $1.resourceValues(forKeys: [.fileSizeKey]).fileSize! }
        expect(rotated.count <= 2 && total <= 8192 && bounded.writeError.isEmpty, "total log count and byte budget enforced")
        expect(!FileManager.default.fileExists(atPath: oldLargeFile.path), "old larger log format also respects aggregate budget")
        let newest = try records(rotation, prefix: "initialization-flow-")
        expect(newest.contains { $0["index"] as? Int == 79 }, "rotation retains latest record")
        for path in rotated + [URL(fileURLWithPath: entry.paths.last!)] {
            let attributes = try FileManager.default.attributesOfItem(atPath: path.path)
            expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600, "private log file permissions")
        }
        let link = root.appendingPathComponent("linked")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: logs)
        let rejected = BoundedDiagnosticLog(component: "initialization_flow", directory: link)
        rejected.append(["event": "fixture"])
        expect(!rejected.writeError.isEmpty && rejected.report.contains("日志写入失败"), "write rejection is visible")
        let target = root.appendingPathComponent("secret-file")
        try Data("unchanged".utf8).write(to: target)
        let fileLink = root.appendingPathComponent("entry-link.jsonl")
        try FileManager.default.createSymbolicLink(at: fileLink, withDestinationURL: target)
        let rejectedFile = ControlledEntryDiagnosticFields.logger(stateDirectory: root.appendingPathComponent("state").path, overridePath: fileLink.path)
        rejectedFile.append(sanitized)
        let targetBytes = try String(contentsOf: target, encoding: .utf8)
        expect(!rejectedFile.writeError.isEmpty && targetBytes == "unchanged", "fixture override cannot follow a file symlink")
        let lockedFile = root.appendingPathComponent("locked-entry.jsonl")
        let lockFD = open(lockedFile.path, O_WRONLY | O_CREAT | O_EXCL, mode_t(0o600))
        expect(lockFD >= 0 && flock(lockFD, LOCK_EX | LOCK_NB) == 0, "owned fixture holds log file lock")
        let released = DispatchSemaphore(value: 0)
        // A broken blocking implementation fails after a bounded delay instead
        // of hanging the fixture forever. Keep this fd alive until release.
        DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
            _ = flock(lockFD, LOCK_UN); released.signal()
        }
        let busy = ControlledEntryDiagnosticFields.logger(stateDirectory: root.appendingPathComponent("state").path, overridePath: lockedFile.path)
        let began = Date()
        busy.append(sanitized)
        let elapsed = Date().timeIntervalSince(began)
        released.wait(); close(lockFD)
        expect(elapsed < 0.5 && busy.writeError == "diagnostic_write_failed_\(EWOULDBLOCK)", "busy logger returns without waiting and exposes lock failure")
        print("InitializationFlowLogTests: \(assertions) assertions passed; eight steps, retry, approval, invalidation, default entry, privacy and bounded persistence")
    }
}
