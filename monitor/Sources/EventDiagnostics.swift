import Foundation

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
