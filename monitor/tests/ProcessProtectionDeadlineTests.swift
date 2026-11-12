import Foundation

@main
struct ProcessProtectionDeadlineTests {
    struct Case: Decodable {
        let name, expected: String
        let now: Double
        let process: WatchedProcess
        let family: FamilyChannelMonitorState
        let executor_boot_id: String
        let receipt_observed_at: Double
    }
    struct Wire: Decodable { let cases: [Case] }

    static func main() throws {
        func require(_ condition: Bool, _ message: String) {
            if !condition { fatalError(message) }
        }
        let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let wire = try JSONDecoder().decode(Wire.self, from: data)
        require(wire.cases.count == 20, "missing Rust projection cases")
        for item in wire.cases {
            let label = item.process.protectionExplanation(state: item.family, executorBootId: item.executor_boot_id, now: item.now, live: true)
            switch item.expected {
            case "blocked_verified":
                require(item.family.valid_until! < item.now, "revoke must already have expired")
                require(item.now - item.receipt_observed_at < 10, "receipt must still be fresh")
                require(label == "已保护：已确认断流，进程保留", "\(item.name): \(label)")
            case "forwarding_verified":
                require(label == "已保护：当前身份获准转发", "\(item.name): \(label)")
            default:
                require(!label.hasPrefix("已保护"), "\(item.name): stale or incomplete evidence claimed protection")
            }
        }
        let blocked = wire.cases.first { $0.name == "expired_revoke_fresh_receipt" }!
        let forwarding = wire.cases.first { $0.name == "current_forwarding_lease" }!
        func label(_ item: Case, at: Double, state: FamilyChannelMonitorState? = nil, boot: String? = nil, live: Bool = true) -> String {
            item.process.protectionExplanation(state: state ?? item.family, executorBootId: boot ?? item.executor_boot_id, now: at, live: live)
        }
        // The receipt deadline remains strict for blocking, including the exact
        // boundary before the ten-second process projection itself goes stale.
        let receiptDeadline = blocked.process.protection!.valid_until!
        require(receiptDeadline == blocked.receipt_observed_at + 10, "blocked deadline must follow receipt freshness")
        require(!label(blocked, at: receiptDeadline).hasPrefix("已保护"), "expired blocked receipt")
        require(!label(blocked, at: blocked.now, boot: "old").hasPrefix("已保护"), "old executor boot")
        require(!label(blocked, at: blocked.now, live: false).hasPrefix("已保护"), "disconnected source")
        require(!label(blocked, at: blocked.now - 2).hasPrefix("已保护"), "future projection")
        require(!label(forwarding, at: forwarding.family.valid_until!).hasPrefix("已保护"), "expired forwarding permit")

        // A family update can arrive after the process row. It must not let a
        // still-fresh row override an expired forwarding command or live flows.
        func changedFamily(_ item: Case, _ key: String, _ value: Any) throws -> FamilyChannelMonitorState {
            var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(item.family)) as! [String: Any]
            json[key] = value
            return try JSONDecoder().decode(FamilyChannelMonitorState.self, from: JSONSerialization.data(withJSONObject: json))
        }
        let expiredForward = try changedFamily(forwarding, "valid_until", forwarding.now - 1)
        require(!label(forwarding, at: forwarding.now, state: expiredForward).hasPrefix("已保护"), "fresh proof overrode expired current permit")
        let closing = try changedFamily(blocked, "active_flows_count", 1)
        require(!label(blocked, at: blocked.now, state: closing).hasPrefix("已保护"), "unclosed flow shown as confirmed blocked")
        let oldProducer = try changedFamily(blocked, "producer_boot_id", "old")
        require(!label(blocked, at: blocked.now, state: oldProducer).hasPrefix("已保护"), "old producer")
        let oldPolicy = try changedFamily(blocked, "saved_policy_version", ["policy_digest":"old", "guard_policy_digest":"old"])
        require(!label(blocked, at: blocked.now, state: oldPolicy).hasPrefix("已保护"), "old policy")

        let graphData = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2]))
        let graph = try JSONDecoder().decode(ChannelMonitorSnapshot.self, from: graphData)
        var subscription = ChannelMonitorSubscriptionStore()
        subscription.applySnapshot(graph)
        let family = graph.families["claude"]!
        let until = family.blocked_evidence_valid_until!
        require(family.valid_until! < graph.captured_at, "graph fixture must have an expired revoke lease")
        require(subscription.effectiveState(for: "claude", now: until - 0.01, live: true)?
            .isConfirmedFlowBlocked(at: until - 0.01) == true, "fresh receipt must confirm blocking")
        require(subscription.effectiveState(for: "claude", now: until, live: true)?
            .isConfirmedFlowBlocked(at: until) == false, "graph must expire with the actual receipt")
        require(!blocked.family.isConfirmedFlowBlocked(at: blocked.now), "legacy snapshot without receipt deadline")
        print("ProcessProtectionDeadlineTests: 20 process projection cases and production graph receipt deadline passed")
    }
}
