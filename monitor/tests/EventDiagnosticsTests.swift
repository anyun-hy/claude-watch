import Foundation

@main
struct EventDiagnosticsTests {
    static func main() throws {
        func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
            guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }
        let result = LeakProbeResult(kind: "dns", status: "timeout", startedAt: 10, finishedAt: 12,
            scope: "https://private.example/token", observations: [
                .init(address: "203.0.113.9", kind: "resolver", source: "secret-source")
            ], errors: [.init(stage: "geoip:203.0.113.9", code: "timeout", message: "secret-token-123")],
            contextChanged: false, details: ["private-detail"], externalJSON: "private-payload")
        let summary = EventDiagnosticInput.make(kind: .dns, source: "ipleak", result: result, verdict: .incomplete)!
        expect(summary.kind == "dns" && summary.source == "ipleak", "fixed source and kind")
        expect(summary.outcome == "incomplete" && summary.reason == "timeout", "timeout outcome")
        expect(summary.stage == "geoip" && summary.elapsed_seconds == 2, "safe stage and elapsed time")
        for stage in ["dns_images", "dns_records"] {
            let timed = LeakProbeResult(kind: "dns", status: "timeout", startedAt: 10, finishedAt: 79,
                scope: "fixture", observations: [], errors: [.init(stage: stage, code: "timeout", message: "fixture")],
                contextChanged: false, details: [])
            let logged = EventDiagnosticInput.make(kind: .dns, source: "netcoffee", result: timed, verdict: .incomplete)!
            expect(logged.stage == stage && logged.elapsed_seconds == 69, "DNS budget keeps stage and actual duration")
        }
        let encoded = try JSONEncoder().encode(summary)
        let text = String(decoding: encoded, as: UTF8.self)
        for secret in ["203.0.113.9", "secret", "private", "https://"] {
            expect(!text.contains(secret), "probe data must not enter log input")
        }
        var changed = result
        changed.contextChanged = true
        let changedSummary = EventDiagnosticInput.make(kind: .dns, source: "netcoffee", result: changed, verdict: .incomplete)!
        expect(changedSummary.reason == "context_changed", "context changes take priority over timeout")
        expect(EventDiagnosticInput.make(kind: .dns, source: "ipleak", result: result, verdict: .cancelled) == nil,
               "cancelled runs do not create a result")
        if CommandLine.arguments.count == 2 {
            let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("cw-diagnostic-swift-\(UUID())")
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let task = Process(), incoming = Pipe(), outgoing = Pipe()
            task.executableURL = URL(fileURLWithPath: CommandLine.arguments[1])
            task.arguments = ["--home", root.path, "event-diagnostic", "--apply"]
            task.standardInput = incoming; task.standardOutput = outgoing; task.standardError = FileHandle.nullDevice
            try task.run(); incoming.fileHandleForWriting.write(encoded); try incoming.fileHandleForWriting.close()
            let output = outgoing.fileHandleForReading.readDataToEndOfFile(); task.waitUntilExit()
            let response = try JSONSerialization.jsonObject(with: output) as? [String: Any]
            expect(task.terminationStatus == 0 && response?["status"] as? String == "ok", "Rust accepts the Swift summary")
            let log = try String(contentsOf: root.appendingPathComponent("Library/Application Support/ClaudeWatch/switcher/diagnostic-events.jsonl"), encoding: .utf8)
            for secret in ["203.0.113.9", "secret", "private", "https://"] {
                expect(!log.contains(secret), "persisted event excludes probe data")
            }
        }
        print("EventDiagnosticsTests passed")
    }
}
