import Foundation

@MainActor
private final class LogTestChecks: InitializationChecking {
    let real: FirstRunChecks
    init(_ real: FirstRunChecks) { self.real = real }
    func begin() { real.store.beginInitialization(startSnapshotPolling: false) }
    func check(_ step: InitializationStep) async -> InitializationResult { await real.check(step) }
    func approve(_ request: InitializationApproval, progress: @escaping SetupProgressObserver) async -> InitializationResult {
        await real.approve(request, progress: progress)
    }
    func validateCurrentEvidence() -> InitializationResult { real.validateCurrentEvidence() }
    var connectionDiagnosticReport: String { real.connectionDiagnosticReport }
    func finish() { real.finish() }
}

@main
struct InitializationConnectionLogTests {
    @MainActor static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cw-initialization-log-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("logs")
        let logger = InitializationConnectionLog(directory: directory)
        let data = Data("""
        {"reason":"job_unconfirmed","heartbeat_pid":42,"heartbeat_age_seconds":1.5,"process_found":true,
         "start_identity_matches":true,"launchd_pid":40,"launchd_state":"running","worker_verified":false,
         "worker_error_code":"native_listener_worker_mismatch","ip":"203.0.113.11","token":"private-token","detail":"private-detail"}
        """.utf8)
        let diagnostic = try JSONDecoder().decode(BackendInitializationDiagnostics.self, from: data)
        logger.begin()
        logger.append(.init(event: "poll_end", phase: "waiting_first_sample", code: "backend_unverified", time: 100,
                            backend: diagnostic.sanitized))
        logger.append(.init(event: "failed", phase: "waiting_first_sample", code: "backend_unverified", time: 101))
        precondition(logger.writeError.isEmpty)
        let first = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).first!
        let failedData = try Data(contentsOf: first)
        logger.begin()
        logger.append(.init(event: "passed", phase: "waiting_next_sample", code: "passed", time: 110))
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        let preserved = try Data(contentsOf: first)
        precondition(files.count == 2 && preserved == failedData, "retry must preserve the failure file")
        let firstRow = String(decoding: failedData, as: UTF8.self).split(separator: "\n").first!
        let object = try JSONSerialization.jsonObject(with: Data(firstRow.utf8)) as! [String: Any]
        let backend = object["backend"] as! [String: Any]
        precondition(backend["heartbeat_pid"] as? Int == 42 && backend["worker_error_code"] as? String == "native_listener_worker_mismatch")
        precondition(!logger.report.contains("private-token") && !logger.report.contains("203.0.113.11") && !logger.report.contains("private-detail"))
        precondition(logger.report.contains("backend_unverified") && logger.report.contains("passed"))
        for file in files {
            let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
            precondition((attrs[.posixPermissions] as! NSNumber).intValue == 0o600)
        }
        let linked = root.appendingPathComponent("linked")
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: directory)
        let blocked = InitializationConnectionLog(directory: linked)
        blocked.begin()
        blocked.append(.init(event: "failed", phase: "status_read", code: "status_unavailable", time: 120))
        precondition(!blocked.writeError.isEmpty && blocked.report.contains("日志写入失败"))
        let afterBlockedWrite = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        precondition(afterBlockedWrite.count == 2)

        // The real first-run entry must log failure before it returns, and
        // its existing Copy/Save report must contain the backend cause.
        let switcher = SwitcherStore(isFixture: true)
        switcher.loadReviewScenario(.normal)
        var payload = try JSONSerialization.jsonObject(with: SwitcherStore.fixtureBackground()) as! [String: Any]
        let started = Date().timeIntervalSince1970
        payload["observed_at"] = started
        payload["guard_backend_healthy"] = false
        payload["backend_diagnostics"] = try JSONSerialization.jsonObject(with: data)
        let receipt = try JSONDecoder().decode(BackgroundServiceReceipt.self, from: JSONSerialization.data(withJSONObject: payload))
        switcher.loadReviewReceipts(switcher.currentEnvironment!, background: receipt)
        let store = MonitorStore(leakChecks: LeakCheckStore(isFixture: true), aiChecks: AIProbeStore(isFixture: true), switcher: switcher)
        let integratedLog = InitializationConnectionLog(directory: directory)
        var now = started
        let checks = FirstRunChecks(store: store, componentCheck: {}, accessibilityTrusted: { true }, requestAccessibility: {},
            connectionNow: { now }, waitForConnectionPoll: { now += 1 }, connectionLog: integratedLog)
        let initialization = FirstRunInitialization(checks: LogTestChecks(checks), completed: false, saveCompletion: { fatalError("No completion writes") })
        await initialization.start()
        let failed = initialization.rows.first { $0.step == .connection }!
        precondition(failed.status == .failed && failed.code == "backend_unverified")
        precondition(failed.detail.contains("native_listener_worker_mismatch"))
        precondition(initialization.diagnosticReport.contains("heartbeat_pid") && initialization.diagnosticReport.contains("worker_error_code"))
        precondition(initialization.diagnosticReport.contains("poll_begin") && initialization.diagnosticReport.contains("poll_end"))
        precondition(initialization.diagnosticReport.contains("\"event\":\"failed\"") && !initialization.entered)
        print("InitializationConnectionLogTests: persisted failure, preserved retry, field privacy, private permissions and visible write failure passed")
    }
}
