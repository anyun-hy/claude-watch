import Foundation
import Darwin

/// A bounded per-process trace, separate from the deduplicated event history.
/// The event vocabulary is fixed and no network or account values are accepted.
@MainActor
final class LeakDiagnosticTrace {
    static let shared = LeakDiagnosticTrace()
    private static let allowed: Set<String> = [
        "schedule_ready", "schedule_running", "schedule_context_missing", "schedule_source_manual",
        "schedule_wait_interval", "schedule_deferred", "schedule_busy", "schedule_disabled", "schedule_initializing", "snapshot_failed",
        "start", "source_ipleak", "source_netcoffee", "source_local", "cancelled", "host_attached", "host_detached", "navigation_finished", "navigation_failed",
        "webcontent_terminated", "script_started", "script_failed", "message_rejected", "payload_invalid",
        "payload_received", "watchdog_timeout", "dns_retry", "phase_http", "phase_dns", "phase_dns_images",
        "phase_dns_records", "phase_geoip", "phase_ice", "phase_collector", "result_matched",
        "result_difference", "result_incomplete", "result_other", "receipt_submitting",
        "receipt_accepted", "receipt_rejected", "context_missing", "context_changed", "trace_limit_reached",
        "receipt_backend_error", "receipt_superseded", "receipt_conflict", "receipt_invalid", "receipt_transport_error",
        "dns_request_timeout", "dns_request_network", "dns_request_http_status", "dns_request_invalid_response",
        "http_request_timeout", "http_request_network", "http_request_http_status", "http_request_invalid_response",
        "geoip_request_timeout", "geoip_request_network", "geoip_request_http_status", "geoip_request_invalid_response"
    ]
    private var file: FileHandle?
    private var directoryFD: Int32 = -1
    private var count = 0
    private let limit: Int
    private(set) var error: String?
    private var lastSchedule: [String: (String, Date)] = [:]

    init(directory: URL? = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/ClaudeWatch/logs", isDirectory: true), enabled: Bool = true,
         recordLimit: Int = 50_000) {
        self.limit = max(1, recordLimit)
        guard enabled, let directory else { return }
        do {
            func privateDirectory(_ url: URL) -> Bool {
                var info = stat()
                guard lstat(url.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
                      info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { return false }
                return true
            }
            guard privateDirectory(directory.deletingLastPathComponent()) else { throw CocoaError(.fileWriteNoPermission) }
            if !FileManager.default.fileExists(atPath: directory.path) {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
            }
            guard privateDirectory(directory) else { throw CocoaError(.fileWriteNoPermission) }
            let dirFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            guard dirFD >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            directoryFD = dirFD
            try openNextFile()
        } catch {
            self.error = "leak_diagnostic_open_failed"
            NSLog("Claude Watch: leak diagnostic log unavailable (%d).", (error as NSError).code)
        }
    }
    deinit { if directoryFD >= 0 { close(directoryFD) } }
    private func openNextFile() throws {
        let name = "leak-diagnostics-\(UUID().uuidString).jsonl"
        let fd = openat(directoryFD, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        count = 0
    }

    func schedule(kind: String, event: String, now: Date = Date()) {
        if let previous = lastSchedule[kind], previous.0 == event, now.timeIntervalSince(previous.1) < 300 { return }
        lastSchedule[kind] = (event, now)
        record(kind: kind, event: event)
    }

    func record(kind: String, event: String, run: UUID? = nil, attached: Bool? = nil) {
        guard file != nil, ["dns", "webrtc", "all"].contains(kind), Self.allowed.contains(event) else { return }
        var row: [String: Any] = ["schema": 1, "time": Date().timeIntervalSince1970,
                                  "kind": kind, "event": event]
        if let run { row["run_id"] = run.uuidString }
        if let attached { row["view_attached"] = attached }
        func safeVersion(_ value: Any?) -> String? {
            guard let value = value as? String, !value.isEmpty, value.utf8.count <= 32,
                  value.utf8.allSatisfy({ (48...57).contains($0) || $0 == 46 }) else { return nil }
            return value
        }
        if let version = safeVersion(Bundle.main.infoDictionary?["CFBundleShortVersionString"]) { row["version"] = version }
        if let build = safeVersion(Bundle.main.infoDictionary?["CFBundleVersion"]) { row["build"] = build }
        do {
            if count >= limit { try file?.close(); file = nil; try openNextFile() }
            let data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]) + Data([10])
            try file?.write(contentsOf: data)
            count += 1
        } catch {
            self.error = "leak_diagnostic_write_failed"
            NSLog("Claude Watch: leak diagnostic write failed (%d).", (error as NSError).code)
            try? file?.close(); file = nil
        }
    }
}

/// This deliberately cannot carry an address, URL, account, token, or error message.
struct EventDiagnosticInput: Encodable, Sendable {
    let kind, source, outcome, reason: String
    let stage: String?
    let elapsed_seconds: Double?

    static func make(kind: LeakKind, source: String, result: LeakProbeResult,
                     verdict: LeakVerdictState) -> EventDiagnosticInput? {
        let outcome: String
        switch verdict {
        case .matched: outcome = "matched"
        case .difference: outcome = "difference"
        case .incomplete, .unconfigured: outcome = "incomplete"
        default: return nil
        }
        let codes = Set(result.errors.map(\.code))
        let reason: String
        if outcome != "incomplete" { reason = outcome }
        else if result.status == "timeout" || codes.contains("timeout") { reason = "timeout" }
        else if result.contextChanged { reason = "context_changed" }
        else if codes.contains("component_missing") { reason = "component_missing" }
        else if codes.contains("invalid_result") { reason = "invalid_result" }
        else if codes.contains("page_failed") { reason = "page_failed" }
        else if codes.contains("script_failed") || codes.contains("javascript_unavailable") { reason = "script_failed" }
        else if codes.contains("service_failed") { reason = "network_error" }
        else { reason = "incomplete" }

        let stage = result.errors.lazy.compactMap { error -> String? in
            // Some upstream stage names contain an IP or endpoint after ':'.
            let prefix = error.stage.split(separator: ":", maxSplits: 1).first.map(String.init) ?? ""
            return ["dns", "dns_images", "dns_records", "http", "geoip", "ice", "collector"].contains(prefix) ? prefix : nil
        }.first
        let elapsed = result.finishedAt - result.startedAt
        return EventDiagnosticInput(kind: kind.rawValue, source: source, outcome: outcome, reason: reason,
                                    stage: stage, elapsed_seconds: elapsed.isFinite && (0...120).contains(elapsed) ? elapsed : nil)
    }
}

enum DiagnosticLogRunner {
    static func submit(_ data: Data, command: String) {
        guard case .rustCandidate? = BundledBackendVariant.current(),
              let engine = Bundle.main.url(forResource: "watch-engine", withExtension: nil) else { return }
        // Logging is independent of the detection and protection result.
        Task.detached(priority: .utility) {
            do {
                let task = Process(), incoming = Pipe(), outgoing = Pipe()
                task.executableURL = engine; task.arguments = [command, "--apply"]
                task.standardInput = incoming; task.standardOutput = outgoing; task.standardError = FileHandle.nullDevice
                try task.run()
                incoming.fileHandleForWriting.write(data)
                try? incoming.fileHandleForWriting.close()
                let output = outgoing.fileHandleForReading.readDataToEndOfFile()
                task.waitUntilExit()
                guard let response = try JSONSerialization.jsonObject(with: output) as? [String: Any],
                      task.terminationStatus == 0, response["status"] as? String == "ok" else {
                    NSLog("Claude Watch: diagnostic event could not be recorded.")
                    return
                }
            } catch {
                NSLog("Claude Watch: diagnostic event could not be recorded.")
            }
        }
    }
}

enum EventDiagnosticLogger {
    static func submit(_ input: EventDiagnosticInput) {
        guard let data = try? JSONEncoder().encode(input) else { return }
        DiagnosticLogRunner.submit(data, command: "event-diagnostic")
    }
}
