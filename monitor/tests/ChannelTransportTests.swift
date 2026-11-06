import Foundation
import Darwin

@main
struct ChannelTransportTests {
    static func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
        if !condition() { fatalError(message) }
    }
    static func rejected(_ payload: [String: Any]) -> Bool {
        do { _ = try ChannelCommandEnvelope.decode(JSONSerialization.data(withJSONObject: payload)); return false }
        catch { return true }
    }
    static func main() throws {
        let bytes = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let envelope = try ChannelCommandEnvelope.decode(bytes)
        expect(envelope.commands.count == 2, "Both Rust families must survive decoding")
        expect(envelope.commands[0].allowed_pids == [1234], "PID must not narrow to UInt8")
        expect(envelope.commands[0].policy_version.guard_policy_digest == "guard", "Full policy must survive decoding")
        var payload = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        var commands = payload["commands"] as! [[String: Any]]
        commands[0]["permit_generation"] = -1
        payload["commands"] = commands
        expect(rejected(payload), "Negative generations must be rejected before mutation")
        commands[0]["permit_generation"] = 1
        commands[0]["policy_version"] = ["policy_digest": "only-one-digest"]
        payload["commands"] = commands
        expect(rejected(payload), "Missing guard policy must not decode")
        expect(channelDrainStatus(remaining: 1, started: 100, now: 102) == "failed", "A drain timeout cannot prove closed")
        expect(channelDrainStatus(remaining: 0, started: 100, now: 102) == "revoked", "Confirmed drain can finish")
        expect(channelIsManagedSigningID("com.anthropic.claudefordesktop.helper"), "Claim an actual desktop helper")
        expect(channelIsManagedProcessName("Claude Helper (GPU)"), "Claim a fresh helper before inventory")
        expect(channelIsManagedProcessName("claude"), "Claim the native Code entrypoint")
        expect(!channelIsManagedProcessName("ClaudeWatchMonitor"), "The monitor parent must not intercept its own gateway")
        expect(!channelIsManagedProcessName("claude_watch_engine"), "The gateway must not intercept itself")
        expect(!channelIsManagedSigningID("com.example.claude-wrapper"), "A keyword is not a managed signing ID")
        expect(channelIsManagedExecutable("/Applications/Claude.app/Contents/MacOS/Claude", home: nil, bundleID: "com.anthropic.claudefordesktop"), "Desktop bundle is captured without a Watch launch")
        expect(channelIsManagedExecutable("/Users/fixture/.local/share/claude/versions/2.1.0", home: "/Users/fixture"), "Native version-named Code executable is captured")
        expect(!channelIsManagedExecutable("/tmp/claude", home: "/Users/fixture"), "A name alone must not block unrelated software")

        expect(channelMayBypass(ownership: .unmanaged), "Confirmed ordinary application may bypass")
        expect(!channelMayBypass(ownership: .managed), "Managed sources cannot bypass")
        expect(!channelMayBypass(ownership: .uncertain), "Known targets with unconfirmed identity cannot bypass")
        expect(ChannelCodeIdentity.words(Data(repeating: 0, count: 31)) == nil, "Malformed identity rejected")
        expect(channelOwnership(targetEvidence: false, identityConfirmed: false) == .unmanaged, "Unknown ordinary software is not blocked")
        expect(channelOwnership(targetEvidence: false, identityConfirmed: true) == .unmanaged, "Unsigned scripts remain outside AI scope")
        expect(channelOwnership(targetEvidence: true, identityConfirmed: false) == .uncertain, "Known AI with missing identity stays blocked")
        expect(channelOwnership(targetEvidence: true, identityConfirmed: true) == .managed, "A discovered AI is managed regardless of who launched it")
        let claudeEntry = "/opt/lib/node_modules/@anthropic-ai/claude-code/cli.js"
        let codexEntry = "/opt/lib/node_modules/@openai/codex/bin/codex.js"
        expect(channelIsManagedInvocation(executable: "/opt/bin/node", arguments: ["node", "--no-warnings", claudeEntry], cwd: nil), "External Node Code entrypoint captured before inventory")
        expect(channelIsManagedInvocation(executable: "/opt/bin/bun", arguments: ["bun", "--", "node_modules/@openai/codex/bin/codex.js"], cwd: "/opt/lib"), "Relative Code entrypoint captured")
        expect(!channelIsManagedInvocation(executable: "/opt/bin/node", arguments: ["node", "/tmp/server.js", claudeEntry], cwd: nil), "Mentioning AI as an argument does not capture an ordinary script")
        expect(!channelIsManagedInvocation(executable: "/opt/bin/node", arguments: ["node", "--require", codexEntry, "/tmp/server.js"], cwd: nil), "A runtime option is not the script entrypoint")
        expect(!channelIsManagedInvocation(executable: "/opt/bin/python3", arguments: ["python3", "/tmp/tool.py"], cwd: nil), "Ordinary Python remains unaffected")
        var rawArgs = withUnsafeBytes(of: Int32(2)) { Data($0) }
        rawArgs.append(contentsOf: Array(("/opt/bin/node\0\0node\0" + claudeEntry + "\0PRIVATE=value\0").utf8))
        expect(channelProcessArguments(rawArgs) == ["node", claudeEntry], "Kernel argv parser excludes environment")
        expect(channelProcessArguments(Data([1, 2])) == nil, "Truncated argv is rejected")
        var registry = ChannelOwnershipRegistry()
        let original = ChannelProcessIdentity(pid: 1234, uid: 501, start_seconds: 50, start_microseconds: 1, audit_token: [0, 501, 0, 501, 0, 1234, 0, 9])
        let reused = ChannelProcessIdentity(pid: 1234, uid: 501, start_seconds: 51, start_microseconds: 1, audit_token: [0, 501, 0, 501, 0, 1234, 0, 10])
        let execed = ChannelProcessIdentity(pid: 1234, uid: 501, start_seconds: 50, start_microseconds: 1, audit_token: [0, 501, 0, 501, 0, 1234, 0, 11])
        registry.remember(original)
        expect(registry.contains(original), "A retained orphan remains managed after permit removal")
        expect(registry.contains(execed) && !original.matches(execed), "Exec retains ownership but invalidates old permission")
        expect(!registry.contains(reused), "PID reuse cannot inherit ownership")
        registry.prune(current: { _ in nil }, exited: { _ in false })
        expect(registry.contains(original), "An unreadable process must retain managed ownership")
        registry.prune(current: { _ in reused }, exited: { _ in false })
        expect(!registry.contains(original), "Exited identity removed")
        expect(channelCommandAdvances(generation: 5, sequence: 15, previousGeneration: 5, previousSequence: 14), "Ordinary renewal advances")
        expect(!channelCommandAdvances(generation: 6, sequence: 13, previousGeneration: 5, previousSequence: 14), "A new generation cannot reuse an old sequence")
        expect(!channelCommandAdvances(generation: 4, sequence: 15, previousGeneration: 5, previousSequence: 14), "An old generation cannot advance by sequence alone")
        let grant = ChannelCommand(family: "claude", policy_version: envelope.commands[0].policy_version,
            command_seq: 15, permit_generation: 5, issued_at: 100, valid_until: 110,
            permit_state: "permitted", allowed_pids: [1234], allowed_processes: [original], session_id: "session",
            command_binding: String(repeating: "a", count: 64), reason: nil)
        expect(grant.canGrant(providerStartedAt: 99, now: 101), "Current-boot grant may apply")
        expect(!grant.canGrant(providerStartedAt: 100.5, now: 101), "Disk permit from before provider restart cannot authorize traffic")
        expect(!grant.canGrant(providerStartedAt: 99, now: 111), "Expired grant cannot apply")
        expect(!grant.canGrant(providerStartedAt: 99, now: 98), "Clock rollback cannot make a future command valid")
        expect(channelPermitIsLive(permitted: true, issuedAt: 100, deadline: 110, monotonicDeadline: 20, now: 101, uptime: 11), "Live permit allows callback continuation")
        expect(!channelPermitIsLive(permitted: false, issuedAt: 100, deadline: 110, monotonicDeadline: 20, now: 101, uptime: 11), "A callback arriving after revocation cannot resume")
        expect(!channelPermitIsLive(permitted: true, issuedAt: 100, deadline: 110, monotonicDeadline: 20, now: 101, uptime: 21), "Monotonic expiry wins even if wall time stalls")

        let directory = "/tmp/cw-channel-contract-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let path = directory + "/gateway.sock"
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(path.utf8) + [0]) }
        let listener = socket(AF_UNIX, SOCK_STREAM, 0)
        expect(listener >= 0, "Listener creation")
        defer { Darwin.close(listener) }
        let bound = withUnsafePointer(to: &address) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        expect(bound == 0 && listen(listener, 4) == 0, "Listener bind")
        do { _ = try GatewayConnection(path: path, expectedUID: getuid()); fatalError("Same UID forged gateway was trusted") }
        catch { }
        let peer = accept(listener, nil, nil)
        expect(peer >= 0, "Accept")
        let liveClient = socket(AF_UNIX, SOCK_STREAM, 0)
        defer { Darwin.close(liveClient) }
        let connected = withUnsafePointer(to: &address) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(liveClient, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        expect(connected == 0, "Owned live connection for OS identity checks")
        let livePeer = accept(listener, nil, nil)
        defer { Darwin.close(livePeer) }
        let peerToken = ChannelCodeIdentity.peerAuditWords(fd: livePeer, uid: getuid())
        expect(peerToken?[5] == UInt32(getpid()), "Kernel audit token identifies the actual Unix peer")
        expect(ChannelCodeIdentity.peerAuditWords(fd: liveClient, uid: getuid())?[5] == UInt32(getpid()), "Server identity available to the Unix client")
        expect(ChannelCodeIdentity.peerAuditWords(fd: livePeer, uid: getuid() + 1) == nil, "Kernel UID mismatch rejected")
        defer { Darwin.close(peer) }
        let own = ChannelCodeIdentity.process(pid: UInt32(getpid()))
        expect(own?.identity.start_seconds ?? 0 > 0, "Live process birth identity obtained from the kernel")
        expect(own?.identity.audit_token?[5] == UInt32(getpid()), "Real process audit token, not a synthetic array")
        var pair = [Int32](repeating: -1, count: 2)
        expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0, "Transport-only socket pair")
        let connection = GatewayConnection(testSocket: pair[0])
        let transportPeer = pair[1]
        defer { Darwin.close(transportPeer) }
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(transportPeer, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        let written = DispatchSemaphore(value: 0)
        connection.write(Data("request".utf8)) { error in
            expect(error == nil, "Write must reach real Unix peer"); written.signal()
        }
        expect(written.wait(timeout: .now() + 1) == .success, "Bounded write")
        var buffer = [UInt8](repeating: 0, count: 32)
        let count = Darwin.read(transportPeer, &buffer, buffer.count)
        expect(count == 7 && String(bytes: buffer.prefix(7), encoding: .utf8) == "request", "Actual data delivery")
        let readStopped = DispatchSemaphore(value: 0)
        connection.readMinimumLength(1, maximumLength: 32) { _, _ in readStopped.signal() }
        expect(readStopped.wait(timeout: .now() + 0.05) == .timedOut, "Read is genuinely in flight")
        expect(connection.cancel(), "Actual shutdown and close must succeed")
        expect(readStopped.wait(timeout: .now() + 1) == .success, "Shutdown releases a blocked duplicated descriptor")
        expect(Darwin.read(transportPeer, &buffer, buffer.count) == 0, "Upstream sees EOF")
        do { _ = try GatewayConnection(path: path, expectedUID: getuid() + 1); fatalError("Wrong UID accepted") }
        catch { }
        let snapshot = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        let home = snapshot["control_home"] as! String
        let gateway = snapshot["gateway_socket"] as! String
        let response = try JSONSerialization.data(withJSONObject: ["nonce":"one", "envelope":snapshot])
        let decoded = try GatewayConnection.decodeControlResponse(response, nonce: "one", path: gateway, home: home)
        let decodedEnvelope = try ChannelCommandEnvelope.decode(decoded)
        expect(decodedEnvelope.commands.count == 2, "Fresh bound RPC decodes")
        for (nonce, location, owner) in [("old", gateway, home), ("one", path, home), ("one", gateway, "/different-user")] {
            do { _ = try GatewayConnection.decodeControlResponse(response, nonce: nonce, path: location, home: owner); fatalError("Replayed or redirected control accepted") }
            catch { }
        }
        print("PASS: wire identities, ownership/exec/PID reuse, same-UID spoof rejection, bound CONTROL response, ordering, lease, transport cancellation")
    }
}
