import Foundation

@main
struct GuardDiagnosticsTests {
    static func main() throws {
        func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
            guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }
        let phase: [String: Any] = [
            "decision": "unknown", "backend_healthy": false, "backend_native": false,
            "backend_reason": "sample_not_ok", "enabled": true, "guard_enabled": true,
            "sampled_at": 1000.0, "backend_heartbeat_status": "error", "backend_heartbeat_age_seconds": 1.0,
            "guard_heartbeat_status": "ok", "guard_heartbeat_age_seconds": 2.0, "policy_matches": true,
            "node": "private-node", "ip": "203.0.113.9"
        ]
        let response: [String: Any] = [
            "guard_diagnostics": ["observation_id": UUID().uuidString, "before": phase, "after": phase],
            "account": "private-account", "token": "private-token"
        ]
        let source = try JSONSerialization.data(withJSONObject: response)
        guard let payload = GuardDiagnosticLogger.input(from: source) else { throw NSError(domain: "fixture", code: 1) }
        let text = String(decoding: payload, as: UTF8.self)
        for privateValue in ["private-node", "203.0.113.9", "private-account", "private-token"] {
            expect(!text.contains(privateValue), "diagnostic payload excludes unrelated private fields")
        }
        let decoded = try JSONDecoder().decode(GuardDiagnosticRound.self, from: payload)
        expect(decoded.before.decision == "unknown" && decoded.before.guard_heartbeat_status == "ok",
               "the decision and subsequent heartbeat observation remain distinct")
        expect(GuardDiagnosticLogger.input(from: Data("{}".utf8)) == nil, "older responses produce no diagnostic")
        if CommandLine.arguments.count == 2 {
            let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("cw-guard-swift-\(UUID())")
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: root) }
            let task = Process(), incoming = Pipe(), outgoing = Pipe()
            task.executableURL = URL(fileURLWithPath: CommandLine.arguments[1])
            task.arguments = ["--home", root.path, "guard-diagnostic", "--apply"]
            task.standardInput = incoming; task.standardOutput = outgoing; task.standardError = FileHandle.nullDevice
            try task.run(); incoming.fileHandleForWriting.write(payload); try incoming.fileHandleForWriting.close()
            let output = outgoing.fileHandleForReading.readDataToEndOfFile(); task.waitUntilExit()
            let reply = try JSONSerialization.jsonObject(with: output) as? [String: Any]
            expect(task.terminationStatus == 0 && reply?["status"] as? String == "ok", "Rust accepts the Swift guard summary")
            let log = try String(contentsOf: root.appendingPathComponent("Library/Application Support/ClaudeWatch/switcher/diagnostic-events.jsonl"), encoding: .utf8)
            for privateValue in ["private-node", "203.0.113.9", "private-account", "private-token"] {
                expect(!log.contains(privateValue), "persisted event excludes private fields")
            }
        }
        print("GuardDiagnosticsTests passed")
    }
}
