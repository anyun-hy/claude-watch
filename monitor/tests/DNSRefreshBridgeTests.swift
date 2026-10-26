import Foundation

@main
struct DNSRefreshBridgeTests {
    static func main() throws {
        func expect(_ value: Bool, _ message: String) {
            guard value else { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("dns-refresh-bridge-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let token = "0123456789abcdef0123456789abcdef"
        let bridge = try DNSRefreshBridge(root: root, token: token)
        let request = DNSRefreshRequest(schema: 1, id: "fedcba9876543210fedcba9876543210")
        let requestURL = bridge.directory.appendingPathComponent("request.json")
        try JSONEncoder().encode(request).write(to: requestURL)
        expect(bridge.pendingRequestID() == request.id, "valid request id is read from token-bound directory")
        try bridge.writeReply(id: request.id, ready: false)
        let reply = try JSONDecoder().decode(DNSRefreshReply.self, from: Data(contentsOf: bridge.directory.appendingPathComponent("reply.json")))
        expect(reply.id == request.id && !reply.ready, "failure reply preserves request id and ready=false")
        try JSONEncoder().encode(DNSRefreshRequest(schema: 1, id: "not-valid")).write(to: requestURL, options: .atomic)
        expect(bridge.pendingRequestID() == nil, "invalid request id is not answered")
        bridge.cleanup()
        expect(!FileManager.default.fileExists(atPath: bridge.directory.path), "only owned bridge directory is cleaned")
        let duplicate = root.appendingPathComponent(".dns-refresh-" + token)
        try FileManager.default.createDirectory(at: duplicate, withIntermediateDirectories: false)
        expect((try? DNSRefreshBridge(root: root, token: token)) == nil, "existing token directory is rejected")
        print("DNSRefreshBridgeTests: 5 assertions passed")
    }
}
