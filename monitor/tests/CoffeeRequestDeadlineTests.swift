import Foundation

@main
struct CoffeeRequestDeadlineTests {
    static func main() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cw-coffee-deadline-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let engine = root.appendingPathComponent("watch-engine")
        try Data("#!/bin/sh\nexec /bin/sleep 5\n".utf8).write(to: engine)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: engine.path)
        let request = CoffeeRequest(resourceDirectory: root, backendVariant: .rustCandidate)
        let start = ProcessInfo.processInfo.systemUptime
        let receipt = request.run(kind: "trace", query: "", timeout: 0.15)
        precondition(receipt.status == "timeout")
        precondition(ProcessInfo.processInfo.systemUptime - start < 2)
        precondition(request.cancelAndWait(until: .now() + .milliseconds(100)))
        // An invalid budget must not start the child at all.
        let rejected = CoffeeRequest(resourceDirectory: root, backendVariant: .rustCandidate)
            .run(kind: "trace", query: "", timeout: 0)
        precondition(rejected.status == "timeout")
        print("CoffeeRequestDeadlineTests: owned child deadline and reap passed; no network")
    }
}
