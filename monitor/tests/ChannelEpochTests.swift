import Foundation

@main
struct ChannelEpochTests {
    static func expect(_ value: @autoclosure () -> Bool, _ message: String) {
        if !value() { fatalError(message) }
    }

    static func command(_ state: String, _ seq: UInt64, _ issued: Double, family: String = "claude") -> ChannelCommand {
        let process = ChannelProcessIdentity(pid: 1234, uid: 501, start_seconds: 50, start_microseconds: 1,
            audit_token: [501, 501, 20, 501, 20, 1234, 0, 9])
        return ChannelCommand(family: family, policy_version: .init(policy_digest: "policy", guard_policy_digest: "guard"),
            command_seq: seq, permit_generation: 1, issued_at: issued, valid_until: issued + 8,
            permit_state: state, allowed_pids: [1234], allowed_processes: [process], session_id: "session",
            command_binding: String(repeating: "a", count: 64), reason: nil)
    }

    static func main() throws {
        var epoch = ChannelExecutionEpoch(startedAt: 90, bootID: "before")
        let inFlight = command("permitted", 11, 100)
        expect(epoch.permits(inFlight, acknowledgedBoot: "before", now: 100.1), "Initial verified grant is usable")
        epoch.suspend()
        expect(!epoch.permits(command("permitted", 12, 100.2), acknowledgedBoot: "before", now: 100.3), "A timer/RPC during sleep cannot reopen")
        epoch.wake(at: 100.4, bootID: "after")
        expect(!epoch.permits(inFlight, acknowledgedBoot: "before", now: 100.5), "An RPC captured before wake cannot grant")
        expect(!epoch.permits(inFlight, acknowledgedBoot: "after", now: 100.5), "Acknowledging the epoch cannot refresh a pre-wake command")
        let renewal = command("permitted", 13, 100.6)
        expect(!epoch.permits(renewal, acknowledgedBoot: "after", now: 100.7), "A fresh ordinary renewal is not recovery")
        expect(!epoch.permits(command("revoked", 14, 100.3), acknowledgedBoot: "after", now: 100.7), "A pre-wake revoke cannot satisfy the fence")
        expect(!epoch.permits(command("revoked", 14, 100.7), acknowledgedBoot: "before", now: 100.8), "An old-epoch revoke cannot satisfy the fence")
        expect(!epoch.permits(command("pending_verification", 14, 100.7), acknowledgedBoot: "after", now: 100.8), "Pending is not an explicit authority revoke")
        expect(!epoch.permits(renewal, acknowledgedBoot: "after", now: 100.8), "Invalid revokes must leave recovery latched")
        expect(!epoch.permits(command("revoked", 15, 100.8), acknowledgedBoot: "after", now: 100.9), "A current revoke stays denied")
        expect(epoch.permits(command("permitted", 16, 100.9), acknowledgedBoot: "after", now: 101), "A new grant after current-epoch revoke can recover")
        expect(!epoch.permits(command("permitted", 16, 100.9, family: "openai"), acknowledgedBoot: "after", now: 101), "One family cannot clear another family's fence")
        expect(!epoch.permits(command("revoked", 17, 101, family: "openai"), acknowledgedBoot: "after", now: 101), "Second family revoke stays denied")
        expect(epoch.permits(command("permitted", 18, 101, family: "openai"), acknowledgedBoot: "after", now: 101), "Second family independently recovers")
        epoch.wake(at: 101.1, bootID: "again")
        expect(!epoch.permits(command("permitted", 19, 101.2), acknowledgedBoot: "again", now: 101.3), "Every wake reinstates the fence")
        epoch.wake(at: 99, bootID: "clock-rollback")
        expect(!epoch.permits(command("revoked", 20, 99.1), acknowledgedBoot: "clock-rollback", now: 99.2), "Clock rollback cannot lower the issue-time fence")

        let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let envelope = try ChannelCommandEnvelope.decode(data)
        expect(envelope.extension_boot_id == "extension-after-wake", "Rust echoes the observed wake epoch")
        var fromWire = ChannelExecutionEpoch(startedAt: 90, bootID: "before-wire")
        fromWire.wake(at: 99, bootID: "extension-after-wake")
        for revoke in envelope.commands {
            expect(!fromWire.permits(revoke, acknowledgedBoot: envelope.extension_boot_id, now: 101), "Serialized Rust revokes never grant")
            expect(fromWire.permits(command("permitted", revoke.command_seq + 1, 101, family: revoke.family),
                acknowledgedBoot: envelope.extension_boot_id, now: 101), "Each decoded family revoke can enable subsequent recovery")
        }
        print("PASS: wake fencing, delayed RPC/renewal denial, family recovery, and Rust epoch decoding")
    }
}
