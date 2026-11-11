import Foundation

private struct ForceWire: Decodable {
    let now: Double
    let awaiting: ChannelMonitorSnapshot
    let snapshot: ChannelMonitorSnapshot
    let events: [ChannelMonitorEvent]
    let verified_target_exits: [UInt32]
}
private struct CutoffWire: Decodable {
    let now: Double
    let snapshot: ChannelMonitorSnapshot
}
private struct DesktopEntryWire: Decodable {
    let plist: [String: String]
}
private struct DeliveryWire: Decodable {
    let policy_first: Bool
    let snapshot: ChannelMonitorSnapshot
    let events: [ChannelMonitorEvent]
    let now: Double
    let first: UInt32
    let second: UInt32
}
private struct DeadlineWire: Decodable {
    let snapshot: ChannelMonitorSnapshot
}

@main
struct ProcessDispositionWireTests {
    static func require(_ condition: @autoclosure () -> Bool, _ detail: String) {
        guard condition() else {
            FileHandle.standardError.write(Data(("FAIL: \(detail)\n").utf8))
            exit(1)
        }
    }

    static func main() throws {
        require(CommandLine.arguments.count == 8, "expected real Rust force, partial, failed network, script, entry, delivery and deadline evidence")
        func decode<T: Decodable>(_ type: T.Type, _ index: Int) throws -> T {
            try JSONDecoder().decode(type, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[index])))
        }
        let force = try decode(ForceWire.self, 1)
        let initial = force.awaiting.families["claude"]!
        let settled = force.snapshot.families["claude"]!
        let result = settled.process_disposition_receipt!
        require(initial.processDispositionLabel(now: initial.updated_at) == "退出处置进行中", "intent was shown as exit")
        require(result.process_execution_state == "confirmed", "missing verified process exit")
        require(Set(result.target_results.map(\.pid)) == Set(force.verified_target_exits), "result did not cover exact real target set")
        require(result.target_results.allSatisfy { $0.terminated && $0.signal_sent_at != nil && $0.statusLabel == "已确认退出" },
                "per-target evidence was not decoded")
        require(settled.processDispositionLabel(now: force.now).contains("已核验目标退出"), "exit label missing")
        require(force.events.contains { $0.family_state.process_disposition_receipt == result }, "snapshot/event results differ")
        require(!settled.processDispositionLabel(now: result.observed_at + 16).contains("已核验目标退出"), "stale force result still confirmed")

        var bad = try JSONSerialization.jsonObject(with: JSONEncoder().encode(settled)) as! [String: Any]
        var badReceipt = bad["process_disposition_receipt"] as! [String: Any]
        var badAuthority = badReceipt["authority"] as! [String: Any]
        badAuthority["command_seq"] = settled.command_seq + 1
        badReceipt["authority"] = badAuthority
        bad["process_disposition_receipt"] = badReceipt
        let outOfOrder = try JSONDecoder().decode(FamilyChannelMonitorState.self, from: JSONSerialization.data(withJSONObject: bad))
        require(!outOfOrder.processDispositionLabel(now: force.now).contains("已核验目标退出"), "mismatched sequence looked current")

        var subscription = ChannelMonitorSubscriptionStore()
        require(subscription.applySnapshot(force.snapshot), "snapshot not accepted")
        let disconnected = subscription.effectiveState(for: "claude", now: force.now, live: false)!
        require(disconnected.process_disposition_receipt == nil && disconnected.display_state == .pendingVerification,
                "disconnected subscription reused a verified receipt")

        let partial = try decode(ProcessDispositionReceiptModel.self, 2)
        require(partial.process_execution_state == "partially_terminated", "real partial worker fact not preserved")
        require(partial.target_results.map(\.statusLabel) == ["已确认退出","未发信号，处置已取消"], "partial targets collapsed")

        let failed = try decode(CutoffWire.self, 3)
        let failureState = failed.snapshot.families["claude"]!
        require(failureState.display_state == .failed && !failureState.isConfirmedFlowBlocked, "process exit hid failed network enforcement")
        require(failureState.processDispositionLabel(now: failed.now).contains("已核验目标退出"), "network failure hid real exit")

        let script = try decode(CutoffWire.self, 4)
        let scriptState = script.snapshot.families["claude"]!
        require(scriptState.isConfirmedFlowBlocked && scriptState.process_disposition_receipt == nil
                && scriptState.processDispositionLabel(now: scriptState.updated_at) == "进程保留", "script cutoff was shown as process exit")

        let entry = try decode(DesktopEntryWire.self, 5)
        let args = ControlledEntryLaunchBinding.arguments(target: entry.plist["CWTarget"]!,
            bundlePath: entry.plist["CWTargetBundlePath"]!, home: entry.plist["CWWatchHomePath"])
        require(args.suffix(2) == ["--home", entry.plist["CWWatchHomePath"]!], "wrapper lost private state binding")
        require(args.contains(entry.plist["CWTargetBundlePath"]!), "wrapper lost selected bundle")

        let orders = try decode([DeliveryWire].self, 6)
        require(Set(orders.map(\.policy_first)) == [true, false], "both policy and receipt orders must be exported")
        for order in orders {
            let state = order.snapshot.families["claude"]!
            let previous = state.previous_process_disposition_receipts!.first!
            require(previous.authority!.policy_version != state.saved_policy_version, "historical policy looked current")
            require(previous.target_results.map(\.pid) == [order.first, order.second], "ordered target identity lost")
            require(previous.target_results[0].terminated && previous.target_results[0].signal_sent_at != nil
                && previous.target_results[1].signal_sent_at == nil, "cancelled target must stay unsignalled")
            let label = state.previousProcessDispositionLabel(now: order.now)!
            require(label.contains("先前批次") && label.contains("已确认退出") && label.contains("处置已取消"),
                    "historical partial result was not explained")
            require(state.process_disposition_action == nil && state.process_disposition_receipt == nil
                && !state.isPermitted && !state.processDispositionLabel(now: order.now).contains("退出"),
                "old result appeared as current process or network authority")
            require(order.events.contains { $0.family_state.previous_process_disposition_receipts == [previous] },
                    "historical receipt did not reach the monitor event")
            require(state.previousProcessDispositionLabel(now: previous.observed_at + 16) == nil,
                    "stale history was displayed as recent")
            var store = ChannelMonitorSubscriptionStore()
            require(store.applySnapshot(order.snapshot), "actual history snapshot failed to apply")
            let disconnected = store.effectiveState(for: "claude", now: order.now, live: false)!
            require(disconnected.previousProcessDispositionLabel(now: order.now) == nil,
                    "disconnected monitor reported old results as live")
        }
        let timeout = try decode(DeadlineWire.self, 7)
        let expired = timeout.snapshot.families["claude"]!
        require(expired.process_disposition_receipt?.target_results.first?.statusLabel == "已发信号，退出未确认"
                && !expired.processDispositionLabel(now: expired.updated_at).contains("已核验目标退出"),
                "deadline result was shown as an exit")
        print("ProcessDispositionWireTests: current force, both historical delivery orders, deadline, network failure, script cutoff and entry payloads passed")
    }
}
