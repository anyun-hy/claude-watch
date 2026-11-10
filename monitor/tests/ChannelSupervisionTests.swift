import Foundation

@main
struct ChannelSupervisionTests {
    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }
    static func main() throws {
        let original = ChannelProcessIdentity(pid: 1234, uid: 501, start_seconds: 50, start_microseconds: 1,
            audit_token: [501, 501, 20, 501, 20, 1234, 0, 9])
        let child = ChannelProcessIdentity(pid: 1235, uid: 501, start_seconds: 51, start_microseconds: 1,
            audit_token: [501, 501, 20, 501, 20, 1235, 0, 10])
        let execed = ChannelProcessIdentity(pid: 1234, uid: 501, start_seconds: 50, start_microseconds: 1,
            audit_token: [501, 501, 20, 501, 20, 1234, 0, 11])
        let policy = ChannelPolicy(policy_digest: "policy", guard_policy_digest: "guard")
        func update(_ processes: [ChannelProcessIdentity], generation: UInt64 = 1,
                    policy nextPolicy: ChannelPolicy? = nil, session: String = "session",
                    allowed: Bool = true, changedBoot: Bool = false, wasClosing: Bool = false) -> ChannelFlowUpdate {
            let command = ChannelCommand(family: "claude", policy_version: nextPolicy ?? policy, command_seq: 2,
                permit_generation: generation, issued_at: 100, valid_until: 110,
                permit_state: allowed ? "permitted" : "revoked", allowed_pids: processes.map { $0.pid },
                allowed_processes: processes, session_id: session, command_binding: String(repeating: "a", count: 64), reason: nil)
            return ChannelFlowUpdate(command: command, allowed: allowed, changedBoot: changedBoot,
                previousGeneration: 1, previousPolicy: policy, previousSession: "session", wasClosing: wasClosing)
        }
        expect(update([original, child]).keeps(original), "joining child cannot disconnect an existing chat")
        expect(update([child, original]).keeps(original), "order change cannot disconnect an existing flow")
        expect(update([original]).keeps(original), "unrelated member exit preserves existing flow")
        expect(!update([child]).keeps(original), "removed process must lose its old connection")
        expect(!update([execed, child]).keeps(original), "exec invalidates the old image's flow")
        expect(update([execed, child]).keeps(child), "exec must not disconnect an unaffected member")
        expect(!update([original], generation: 2).keeps(original), "authority generation change drains")
        expect(!update([original], policy: .init(policy_digest: "new", guard_policy_digest: "guard")).keeps(original), "policy change drains")
        expect(!update([original], session: "another").keeps(original), "new session drains")
        expect(!update([original], allowed: false).keeps(original), "risk revocation drains")
        expect(!update([original], changedBoot: true).keeps(original), "executor restart drains")
        expect(!update([original], wasClosing: true).keeps(original), "incomplete drain cannot reopen a flow")

        let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let catalog = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let home = catalog["home"] as! String
        expect(Set(channelCLIAliases(home: home)) == Set(catalog["aliases"] as! [String]), "every Rust-supported alias must be captured before inventory")
        let aliases = Set(catalog["resolved_aliases"] as! [String])
        let cases = catalog["cases"] as! [[String: Any]]
        for row in cases {
            let path = row["executable"] as! String
            let managed = channelIsManagedExecutable(path, home: home, aliases: aliases, bundleID: row["bundle_id"] as? String)
                || channelIsManagedInvocation(executable: path, arguments: row["arguments"] as! [String], cwd: row["cwd"] as? String, home: home)
            expect(managed == row["managed"] as! Bool, "Swift/Rust capture mismatch: \(row)")
        }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cw-alias-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root.appendingPathComponent(".local/bin"), withIntermediateDirectories: true)
        let image = root.appendingPathComponent("native-image")
        let replacement = root.appendingPathComponent("replacement-image")
        try Data("fixture".utf8).write(to: image)
        try Data("fixture".utf8).write(to: replacement)
        for cli in ["claude", "codex"] {
            let alias = root.appendingPathComponent(".local/bin/" + cli)
            let imagePath = image.resolvingSymlinksInPath().path
            let replacementPath = replacement.resolvingSymlinksInPath().path
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: image)
            let initial = channelResolvedCLIAliases(home: root.path)
            expect(initial.contains(imagePath), "\(cli): first flow resolves a supported native alias")
            expect(channelIsManagedExecutable(imagePath, home: root.path, aliases: initial), "\(cli): resolved image is captured")
            try FileManager.default.removeItem(at: alias)
            try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: replacement)
            let refreshed = channelResolvedCLIAliases(home: root.path)
            expect(refreshed.contains(replacementPath) && !refreshed.contains(imagePath), "\(cli): an updated alias is captured before the next inventory")
            expect(!channelIsManagedExecutable(imagePath, home: root.path, aliases: refreshed), "\(cli): old alias target cannot capture an independent process")
            try FileManager.default.removeItem(at: alias)
            let removed = channelResolvedCLIAliases(home: root.path)
            expect(!removed.contains(replacementPath), "\(cli): deleted alias does not retain its target")
            expect(!channelIsManagedExecutable(replacementPath, home: root.path, aliases: removed), "\(cli): unaliased ordinary image remains unmanaged")
            expect(!channelIsManagedExecutable(root.appendingPathComponent("ordinary/" + cli).path, home: root.path, aliases: removed), "\(cli): an unrelated same-named executable is not captured")
        }
        // No global uncertainty rule may capture ordinary unsigned programs.
        expect(channelOwnership(targetEvidence: false, identityConfirmed: false) == .unmanaged, "ordinary software remains usable during identity uncertainty")
        expect(channelOwnership(targetEvidence: true, identityConfirmed: false) == .uncertain, "positively identified AI remains held without verified identity")
        print("PASS: selective flow updates, \(cases.count) Rust/Swift capture cases, ordinary-software controls")
    }
}
