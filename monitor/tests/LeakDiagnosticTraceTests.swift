import Darwin
import Foundation

@main
struct LeakDiagnosticTraceTests {
    @MainActor static func main() throws {
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            guard value() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("cw-trace-test-\(UUID())")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("logs")
        let log = LeakDiagnosticTrace(directory: directory)
        let id = UUID()
        log.record(kind: "dns", event: "start", run: id)
        log.record(kind: "dns", event: "phase_dns", run: id, attached: true)
        log.record(kind: "dns", event: "secret-ip-203.0.113.9", run: id)
        let clock = Date(timeIntervalSince1970: 1000)
        log.schedule(kind: "webrtc", event: "schedule_context_missing", now: clock)
        log.schedule(kind: "webrtc", event: "schedule_context_missing", now: clock.addingTimeInterval(10))
        log.schedule(kind: "webrtc", event: "schedule_context_missing", now: clock.addingTimeInterval(301))
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        expect(files.count == 1, "one session file")
        let attributes = try FileManager.default.attributesOfItem(atPath: files[0].path)
        expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600, "private file permissions")
        let content = try String(contentsOf: files[0], encoding: .utf8)
        let rows = try content.split(separator: "\n").map { try JSONSerialization.jsonObject(with: Data($0.utf8)) as! [String: Any] }
        expect(rows.count == 4, "repeated schedule state is rate limited")
        expect(rows[0]["run_id"] as? String == id.uuidString && rows[1]["view_attached"] as? Bool == true, "correlates run and view attachment")
        expect(!content.contains("203.0.113.9") && !content.contains("secret"), "rejects unrecognized and potentially sensitive data")
        let rotating = root.appendingPathComponent("rotating")
        let bounded = LeakDiagnosticTrace(directory: rotating, recordLimit: 2)
        bounded.record(kind: "dns", event: "start", run: id)
        bounded.record(kind: "dns", event: "phase_dns", run: id)
        bounded.record(kind: "dns", event: "payload_received", run: id)
        let parts = try FileManager.default.contentsOfDirectory(at: rotating, includingPropertiesForKeys: nil)
        expect(parts.count == 2, "starts a new bounded file and keeps prior evidence")
        let combined = try parts.map { try String(contentsOf: $0, encoding: .utf8) }.joined()
        expect(combined.contains("start") && combined.contains("payload_received"), "records continue after the file limit")
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: directory)
        let refused = LeakDiagnosticTrace(directory: link)
        expect(refused.error == "leak_diagnostic_open_failed", "rejects a symlink log directory")
        print("LeakDiagnosticTraceTests passed")
    }
}
