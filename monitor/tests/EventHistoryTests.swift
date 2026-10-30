import Foundation

// Connects the production Swift decoder to the real Rust command using an isolated home.
enum SwitcherCommandRunner {
    static var engine = ""
    static var home = ""
    static func run(_ args: [String], input: Data? = nil) throws -> Data {
        let task = Process(), incoming = Pipe(), outgoing = Pipe()
        task.executableURL = URL(fileURLWithPath: engine)
        task.arguments = ["--home", home] + args
        task.standardInput = incoming; task.standardOutput = outgoing; task.standardError = FileHandle.nullDevice
        try task.run()
        if let input { incoming.fileHandleForWriting.write(input) }
        try incoming.fileHandleForWriting.close()
        let output = outgoing.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        guard task.terminationStatus == 0 else { throw NSError(domain: "fixture", code: 1) }
        return output
    }
}

@main
struct EventHistoryTests {
    static func main() throws {
        func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
            guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }
        guard CommandLine.arguments.count == 2 else { throw NSError(domain: "fixture", code: 2) }
        SwitcherCommandRunner.engine = CommandLine.arguments[1]
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("cw-history-swift-\(UUID())")
        defer { try? FileManager.default.removeItem(at: root) }
        let dir = root.appendingPathComponent("Library/Application Support/ClaudeWatch/switcher")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        SwitcherCommandRunner.home = root.path
        try "{\"id\":\"warning\",\"time\":1,\"category\":\"activity-unavailable\",\"status\":\"partial\"}\n"
            .write(to: dir.appendingPathComponent("events.previous.jsonl"), atomically: true, encoding: .utf8)
        let samples = (0..<150).map { "{\"id\":\"sample-\($0)\",\"time\":\($0 + 100),\"category\":\"traffic-counter\",\"pid\":\($0 + 2000)}\n" }.joined()
        try samples.write(to: dir.appendingPathComponent("events.jsonl"), atomically: true, encoding: .utf8)
        guard case .success(let warnings) = EventHistoryRunner.read(.init(filter: "attention", query: "", offset: 0)) else {
            throw NSError(domain: "fixture", code: 3)
        }
        expect(warnings.total == 1 && warnings.events.first?.id == "warning", "previous warning remains visible")
        expect(warnings.events.first?.severity == "warning", "severity decoded")
        expect(warnings.events.first?.rawDetail?.contains("partial") == true, "raw detail decoded separately")
        expect(warnings.events.first?.detail.contains("null") == false, "summary contains no empty fields")
        guard case .success(let samplesPage) = EventHistoryRunner.read(.init(filter: "sample", query: "", offset: 0)) else {
            throw NSError(domain: "fixture", code: 4)
        }
        expect(samplesPage.total == 150 && samplesPage.events.count == 100 && samplesPage.hasMore, "samples page")
        guard case .success(let nextPage) = EventHistoryRunner.read(.init(filter: "sample", query: "", offset: samplesPage.nextOffset)) else {
            throw NSError(domain: "fixture", code: 6)
        }
        expect(nextPage.events.count == 50 && !nextPage.hasMore, "second page reaches oldest samples")
        guard case .success(let filtered) = EventHistoryRunner.read(.init(filter: "sample", query: "PID 2000", offset: 0)) else {
            throw NSError(domain: "fixture", code: 5)
        }
        expect(filtered.total == 1 && filtered.events.first?.id == "sample-0", "search before paging")
        print("EventHistoryTests passed")
    }
}
