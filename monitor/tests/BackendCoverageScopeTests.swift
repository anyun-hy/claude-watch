import Foundation

@main
struct BackendCoverageScopeTests {
    static func main() throws {
        func require(_ value: Bool, _ message: String) {
            if !value { fatalError(message) }
        }
        struct Wire: Decodable {
            let snapshot: ChannelMonitorSnapshot
            let events: [ChannelMonitorEvent]
            let monitor: MonitorSnapshot
        }
        let decoder = JSONDecoder()
        let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let wire = try decoder.decode(Wire.self, from: data)
        let unlinked = try decoder.decode(WatchedProcess.self, from: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2])))
        require(unlinked.matchReason == "retained_lifetime" && unlinked.startSeconds != nil && unlinked.uid != nil, "unlinked live identity lost")
        require(unlinked.protection?.state == "unprotected" && unlinked.protection?.reason_code == "executable_evidence_changed", "unlinked image appears protected")
        require(unlinked.protectionExplanation(state:nil, executorBootId:nil, now:unlinked.protection!.observed_at, live:true).hasPrefix("未保护"), "real unlinked row explanation lost")
        let scope = wire.snapshot.families["claude"]!.coverage_scope!
        require(scope.backend == "seatbelt", "backend lost")
        require(scope.configured_entries == ["claude-cli"], "configured entries lost")
        require(scope.protected_pids == [4101] && scope.unprotected_pids == [4102], "mixed coverage lost")
        require(scope.uncovered_boundaries.count == 2, "boundaries lost")
        require(!scope.server_identity_verified && scope.gateway_endpoint_protection_verified, "endpoint facts lost")
        require(scope.gateway_endpoint_protection_method == "system_launchd_socket", "endpoint method lost")
        require(!scope.allDiscoveredProtected, "mixed scope cannot claim full coverage")
        require(wire.events.last!.family_state.coverage_scope == scope, "event wire differs")
        require(wire.monitor.channelSupervision!.families["claude"]!.coverage_scope == scope, "outer projection differs")
        require(wire.monitor.vpnSupervision?.vpn_match?.state == "unknown", "Rust VPN verdict was not decoded")
        require(wire.monitor.vpnSupervision!.unknownOrStaleReasons.contains("vpn_expectation_unconfigured"), "VPN unknown reason lost")
        let conflictingVpn = try decoder.decode(VpnMatchModel.self, from: Data(#"{"verdict":"unknown","state":"matched"}"#.utf8))
        require(conflictingVpn.state == "unknown" && conflictingVpn.reasons == ["vpn_match_wire_conflict"], "conflicting legacy VPN success")
        let legacyVpn = try decoder.decode(VpnMatchModel.self, from: Data(#"{"state":"stale"}"#.utf8))
        require(legacyVpn.state == "stale", "legacy VPN result lost")
        require(wire.monitor.processes.count == 2, "production process rows missing")
        require(wire.monitor.processes.allSatisfy { $0.matchReason == "verified_bundle" }, "selected classifier reason lost")
        require(wire.monitor.processes.allSatisfy { $0.protection?.state != "protected" }, "discovery masquerades as protection")
        require(wire.monitor.processes[0].discoveryExplanation == "应用包身份", "discovery explanation not wired")
        require(!String(decoding: data, as: UTF8.self).contains("PRIVATE_DO_NOT_EMIT"), "private argv leaked")
        var subscriber = ChannelMonitorSubscriptionStore()
        require(subscriber.applySnapshot(wire.snapshot), "snapshot apply")
        require(subscriber.applyEvent(wire.events.last!) == .ignoredStaleEvent, "stale event accepted")
        var object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let original = object["snapshot"] as! [String: Any]
        func familyWithScope(_ replacement: Any?) throws -> FamilyChannelMonitorState {
            var family = (original["families"] as! [String: Any])["claude"] as! [String: Any]
            family["coverage_scope"] = replacement
            return try decoder.decode(FamilyChannelMonitorState.self, from: JSONSerialization.data(withJSONObject: family))
        }
        require(try familyWithScope(nil).coverage_scope == nil, "missing scope")
        require(try familyWithScope(NSNull()).coverage_scope == nil, "null scope")
        let legacy: [String: Any] = ["backend":"seatbelt", "covers_controlled_cli_launch":true]
        require(try !familyWithScope(legacy).coverage_scope!.allDiscoveredProtected, "legacy booleans imply coverage")
        var facts = (try JSONSerialization.jsonObject(with: JSONEncoder().encode(scope))) as! [String: Any]
        facts["unprotected_pids"] = []
        facts["protected_pids"] = []
        require(try !familyWithScope(facts).coverage_scope!.allDiscoveredProtected, "empty means all")
        facts["protected_pids"] = [4101]
        facts["gateway_endpoint_protection_verified"] = false
        require(try !familyWithScope(facts).coverage_scope!.allDiscoveredProtected, "missing endpoint proof")
        facts["gateway_endpoint_protection_verified"] = true
        facts["backend"] = "future_backend"
        require(try !familyWithScope(facts).coverage_scope!.allDiscoveredProtected, "unknown backend")
        facts["protected_pids"] = "corrupt"
        do { _ = try familyWithScope(facts); fatalError("corrupt fact swallowed") }
        catch is DecodingError { }
        // Presentation-only fixtures below exercise positive/stale UI bindings;
        // they do not assert an OS endpoint proof or actual target protection.
        let now = wire.snapshot.captured_at
        let token = BoundProcessTokenModel(pid: 4101, uid: 501, start_seconds: 100, start_microseconds: 1,
                                          role: "cli", audit_token: [501,501,20,501,20,4101,0,9])
        var familyJSON = (original["families"] as! [String: Any])["claude"] as! [String: Any]
        familyJSON["backend"] = "seatbelt"
        familyJSON["policy_sync_state"] = "applied"
        familyJSON["applied_policy_version"] = familyJSON["saved_policy_version"]
        familyJSON["display_state"] = "forwarding"
        familyJSON["permit_state"] = "permitted"
        familyJSON["active_members"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode([token]))
        let epoch: [String: Any] = ["observer_boot_id":"unit-vpn", "change_generation":1]
        familyJSON["vpn_epoch"] = epoch
        let family = try decoder.decode(FamilyChannelMonitorState.self, from: JSONSerialization.data(withJSONObject: familyJSON))
        var row = ((object["monitor"] as! [String: Any])["processes"] as! [[String: Any]])[0]
        row["protection"] = ["state":"protected", "reason_code":"forwarding_verified", "observed_at":now,
            "valid_until":now+5, "producer_boot_id":family.producer_boot_id, "executor_boot_id":"unit-executor",
            "policy_version":familyJSON["saved_policy_version"]!, "audit_identity_digest":token.auditIdentityDigest!,
            "command_seq":family.command_seq, "permit_generation":family.permit_generation, "vpn_epoch":epoch] as [String: Any]
        func process(_ json: [String: Any]) throws -> WatchedProcess {
            try decoder.decode(WatchedProcess.self, from: JSONSerialization.data(withJSONObject: json))
        }
        func label(_ json: [String: Any], state: FamilyChannelMonitorState? = nil, useDefaultState: Bool = true, boot: String? = "unit-executor", at: Double? = nil) throws -> String {
            try process(json).protectionExplanation(state: useDefaultState ? family : state, executorBootId: boot, now: at ?? now, live: true)
        }
        require(try label(row).hasPrefix("已保护"), "fresh presentation proof rejected")
        require(try !label(row, useDefaultState:false).hasPrefix("已保护"), "no authority implies protected")
        require(try !label(row, boot:"old").hasPrefix("已保护"), "old executor")
        require(try !label(row, at:now+11).hasPrefix("已保护"), "expired proof")
        for key in ["uid", "startSeconds", "startMicroseconds"] {
            var stale = row; stale[key] = 123456789
            require(try !label(stale).hasPrefix("已保护"), "PID-only protection: \(key)")
        }
        for key in ["producer_boot_id", "audit_identity_digest", "command_seq", "permit_generation", "policy_version", "vpn_epoch"] {
            var stale = row; var proof = stale["protection"] as! [String: Any]
            if key == "command_seq" || key == "permit_generation" { proof[key] = UInt64.max }
            else if key == "policy_version" { proof[key] = ["policy_digest":"old", "guard_policy_digest":"old"] }
            else if key == "vpn_epoch" { proof[key] = ["observer_boot_id":"old", "change_generation":1] }
            else { proof[key] = "old" }
            stale["protection"] = proof
            require(try !label(stale).hasPrefix("已保护"), "stale binding: \(key)")
        }
        var external = row
        external["protection"] = ["state":"unprotected", "reason_code":"external_unmanaged_process", "observed_at":now]
        require(try label(external).hasPrefix("发现但未保护"), "match was confused with protection")
        let legacyRow = try process(["id":"legacy", "pid":4101, "started":"old", "kind":"code"])
        require(legacyRow.protectionExplanation(state: family, executorBootId:"unit-executor", now:now, live:true).hasPrefix("保护未知"), "legacy PID authorized")
        object.removeAll()
        print("BackendCoverageScopeTests: production snapshot/events/processes, conservative decoding and current protection bindings passed")
    }
}
