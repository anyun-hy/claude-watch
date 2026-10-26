import Foundation

struct DNSRefreshRequest: Codable, Equatable {
    let schema: Int
    let id: String
}

struct DNSRefreshReply: Codable, Equatable {
    let schema: Int
    let id: String
    let ready: Bool
}

/// A private, per-account-switch rendezvous. The token names only a child of
/// the app-owned switcher directory; it never changes global networking state.
final class DNSRefreshBridge {
    let token: String
    let directory: URL
    private let requestURL: URL
    private let replyURL: URL

    init(root: URL, token: String = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()) throws {
        guard Self.validID(token) else { throw NSError(domain: "DNSRefreshBridge", code: 1) }
        let normalizedRoot = root.standardizedFileURL
        self.token = token
        self.directory = normalizedRoot.appendingPathComponent(".dns-refresh-" + token, isDirectory: true)
        self.requestURL = directory.appendingPathComponent("request.json")
        self.replyURL = directory.appendingPathComponent("reply.json")
        guard !FileManager.default.fileExists(atPath: directory.path) else {
            throw NSError(domain: "DNSRefreshBridge", code: 3)
        }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
    }

    func pendingRequestID() -> String? {
        guard let bytes = try? Data(contentsOf: requestURL),
              let request = try? JSONDecoder().decode(DNSRefreshRequest.self, from: bytes),
              request.schema == 1, Self.validID(request.id) else { return nil }
        return request.id
    }

    func writeReply(id: String, ready: Bool) throws {
        guard Self.validID(id) else { throw NSError(domain: "DNSRefreshBridge", code: 2) }
        let bytes = try JSONEncoder().encode(DNSRefreshReply(schema: 1, id: id, ready: ready))
        try bytes.write(to: replyURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: replyURL.path)
    }

    func cleanup() {
        try? FileManager.default.removeItem(at: directory)
    }

    static func validID(_ value: String) -> Bool {
        value.utf8.count == 32 && value.unicodeScalars.allSatisfy {
            (48...57).contains($0.value) || (97...102).contains($0.value)
        }
    }
}
