import Foundation

@main
struct GraphModelTests {
    static func main() {
        var passed = 0
        func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
            guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
            passed += 1
        }
        let process = WatchedProcess(id: "p1", pid: 42, started: "now", kind: "code", authorized: true)
        let codexProcess = WatchedProcess(id: "codex", pid: 43, started: "now", kind: "codex-cli", authorized: true)
        let chatGPTProcess = WatchedProcess(id: "chatgpt", pid: 44, started: "now", kind: "chatgpt-desktop-main", authorized: true)
        let sharedProcess = WatchedProcess(id: "shared", pid: 45, started: "now", kind: "openai-desktop-main", authorized: nil)
        func flow(id: String = "f1", pid: Int = 42, association: String = "correlated", policy: String = "match", host: String = "api.anthropic.com", peer: String = "127.0.0.1:7890", route: String? = "local_proxy", interface: String? = nil, chains: [String] = ["海外AI", "日本节点"]) -> Flow {
            Flow(id: id, pid: pid, host: host, peer: peer, local: "127.0.0.1:52134", transport: "TCP", association: association, policy: policy, reason: "sample", chains: chains, routePath: route, interfaceName: interface)
        }
        func proxy(_ flows: [Flow], entry: String = "verified", covers: Bool = true) -> ProxySnapshot {
            ProxySnapshot(observedAt: 1, entryState: entry, entryReason: "listener", entrySource: "snapshot", endpoint: "127.0.0.1:7890", listenerPID: 7, listenerPath: "/mihomo", apiState: "available", apiReason: "", mode: "global", coversProxy: covers, expectedGroup: "海外AI", expectedNode: "预期节点", selectedNode: "", globalNode: "配置节点", pinned: false, selectionChanged: false, flows: flows)
        }

        let empty = ConnectionGraphProjection(proxy: proxy([]), processes: [], selectedFlowID: nil, fresh: true)
        expect(empty.flow == nil, "empty has no flow")
        expect(empty.gatewayState == .confirmed, "verified listener independent")
        expect(empty.gatewayEdgeState == .pending, "no path does not light gateway edge")
        expect(empty.nodeState == .configuration, "node is config only")
        expect(empty.routePresentation == "idle", "no flow is idle")

        let unselectedLocal = ConnectionGraphProjection(proxy: proxy([flow(association: "local_service", route: nil)]), processes: [process], selectedFlowID: nil, fresh: true)
        expect(unselectedLocal.flow == nil, "an unselected local service is not promoted into the graph")
        expect(!unselectedLocal.supportsPathAnimation, "an unselected local service cannot animate as a platform route")
        let unselectedSinglePlatform = ConnectionGraphProjection(proxy: proxy([flow()]), processes: [process], selectedFlowID: nil, fresh: true)
        expect(unselectedSinglePlatform.flow == nil, "a single sample is never promoted without an explicit selection")
        expect(!unselectedSinglePlatform.supportsPathAnimation, "an unselected single sample cannot animate")
        let noConfigReference = ConnectionGraphProjection(proxy: proxy([flow(association: "local_service", route: nil, chains: [])]), processes: [process], selectedFlowID: "f1", fresh: true, showConfigurationReference: false)
        expect(noConfigReference.nodeTitle == "节点待确认" && noConfigReference.nodeState == .pending, "no chain never borrows a configuration node for route evidence")

        let confirmed = ConnectionGraphProjection(proxy: proxy([flow()]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(confirmed.sourceKind == "code", "source kind")
        expect(confirmed.gatewayEdgeState == .confirmed, "local proxy gateway")
        expect(confirmed.nodeEdgeState == .confirmed, "actual node")
        expect(confirmed.targetEdgeState == .confirmed, "actual target")
        expect(confirmed.nodeTitle == "日本节点", "chains already group to leaf")
        expect(confirmed.routePresentation == "proxy", "explicit local proxy presentation")
        expect(confirmed.supportsPathAnimation, "a fully evidenced proxy path can animate")
        expect(codexProcess.product == .openAI && codexProcess.sourceRole == .cli, "codex cli belongs to unified page with CLI source")
        let managedProcess = WatchedProcess(id: "managed", pid: 52, started: "now", kind: "codex-cli", authorized: nil,
                                            runtimeRole: "codex_managed", serviceName: "Codex 托管后台", roleEvidence: "managed_app_server")
        expect(managedProcess.sourceRole == .desktop && managedProcess.sourceDisplay == "桌面应用",
               "verified app-server joins the desktop source rather than becoming an independent CLI or a third source")
        var unverifiedManaged = managedProcess; unverifiedManaged.roleEvidence = "unknown"
        expect(unverifiedManaged.sourceRole == .cli, "an unverified hint does not change the existing process classification")
        var missingArguments = managedProcess; missingArguments.runtimeRole = "codex_managed_unconfirmed"; missingArguments.roleEvidence = "managed_path_only"
        expect(missingArguments.sourceRole == .child && missingArguments.name.contains("待确认"), "a retained managed-path target without arguments is not displayed as CLI")
        expect(chatGPTProcess.product == .openAI && chatGPTProcess.sourceRole == .desktop, "chatgpt desktop belongs to unified page")
        expect(sharedProcess.product == .openAI && sharedProcess.sourceRole == .desktop, "unified shell is a desktop source")
        let desktopHelper = WatchedProcess(id: "helper", pid: 46, started: "now", kind: "desktop-helper", authorized: nil)
        let codexHelper = WatchedProcess(id: "codex-helper", pid: 47, started: "now", kind: "codex-desktop-helper", authorized: nil)
        expect(desktopHelper.sourceRole == .desktop && codexHelper.sourceRole == .desktop, "desktop helpers project to desktop source")
        expect(MonitoredProduct.allCases.map(\.title) == ["Claude", "ChatGPT / Codex"], "only two product tabs, no shared desktop tab")

        let bundledService = WatchedProcess(id: "bundled", pid: 48, started: "now", kind: "openai-child", authorized: nil)
        let chatGPTChild = WatchedProcess(id: "chatgpt-child", pid: 49, started: "now", kind: "chatgpt-child", authorized: nil)
        let unknownChild = WatchedProcess(id: "unknown", pid: 50, started: "now", kind: "codex-child", authorized: nil)
        let legacyDesktop = WatchedProcess(id: "legacy", pid: 51, started: "now", kind: "codex-desktop-main", authorized: nil)
        expect(bundledService.sourceRole == .desktop, "backend desktop descendant is never a standalone CLI")
        expect(chatGPTChild.sourceRole == .desktop, "classic ChatGPT descendants remain desktop")
        expect(unknownChild.sourceRole == .child && unknownChild.sourceDisplay == "来源待确认", "ambiguous Codex child is not guessed as CLI or desktop")
        expect(legacyDesktop.product == .openAI && legacyDesktop.sourceRole == .desktop, "legacy Codex desktop uses unified page")
        expect(codexHelper.product == .openAI, "legacy Codex helper uses unified page")
        expect(MonitoredProduct.openAI.covered(by: ["claude", "codex", "chatgpt"]), "unified page requires both backend capabilities")
        expect(!MonitoredProduct.openAI.covered(by: ["claude", "codex"]), "partial capability cannot claim unified coverage")
        expect(!MonitoredProduct.openAI.covered(by: ["claude"]), "legacy backend never claims OpenAI coverage")
        expect(MonitoredProduct.claude.covered(by: ["claude"]), "Claude coverage unchanged")

        let mixedProcesses = [process, codexProcess, chatGPTProcess, sharedProcess, bundledService, unknownChild, legacyDesktop]
        // Identical hosts deliberately exercise process ownership, not domain guesses.
        let mixedFlows = [flow(), flow(id: "cli", pid: 43), flow(id: "classic", pid: 44),
                          flow(id: "shell", pid: 45), flow(id: "bundled", pid: 48),
                          flow(id: "unknown", pid: 50), flow(id: "legacy", pid: 51),
                          flow(id: "ended", pid: 999)]
        let openAIScope = ConnectionGraphScope(product: .openAI, processes: mixedProcesses, flows: mixedFlows)
        let claudeScope = ConnectionGraphScope(product: .claude, processes: mixedProcesses, flows: mixedFlows)
        expect(openAIScope.processes.count == 6, "all OpenAI kind variants share one scope")
        expect(openAIScope.flows.count == 6, "each OpenAI connection counted once")
        expect(Set(openAIScope.flows.map(\.pid)) == [43, 44, 45, 48, 50, 51], "unified scope filters by PID and excludes ended source")
        expect(claudeScope.flows.map(\.id) == ["f1"] && claudeScope.processes.map(\.pid) == [42], "Claude scope unchanged despite matching domains")
        expect(Set(openAIScope.flows.map(\.id)).isDisjoint(with: claudeScope.flows.map(\.id)), "families never duplicate flows")
        let bundledProjection = ConnectionGraphProjection(proxy: proxy(openAIScope.flows), processes: openAIScope.processes, selectedFlowID: "bundled", fresh: true)
        expect(bundledProjection.sourceKind == "desktop" && bundledProjection.sourcePID == 48, "internal service connection originates at desktop tile")
        expect(bundledProjection.sourceEdgeState == .confirmed, "verified bundled service retains real path evidence")
        let unknownProjection = ConnectionGraphProjection(proxy: proxy(openAIScope.flows), processes: openAIScope.processes, selectedFlowID: "unknown", fresh: true)
        expect(unknownProjection.sourceKind == "other" && unknownProjection.sourceEdgeState == .pending, "ambiguous child cannot certify a source tile")
        expect(unknownProjection.summary.contains("来源待确认"), "ambiguous source explicitly disclosed")
        expect(unknownProjection.nodeEdgeState == .confirmed, "source uncertainty does not erase independent TAG chain evidence")
        let staleBundled = ConnectionGraphProjection(proxy: proxy(openAIScope.flows), processes: openAIScope.processes, selectedFlowID: "bundled", fresh: false)
        expect(staleBundled.sourceEdgeState == .pending && staleBundled.nodeEdgeState == .pending, "unified desktop stale flow cannot stay confirmed")
        let codexFlow = Flow(id: "codex-flow", pid: 43, host: "api.openai.com", peer: "127.0.0.1:7890", local: "127.0.0.1:52135", transport: "TCP", association: "correlated", policy: "match", reason: "sample", chains: ["海外AI", "日本节点"], routePath: "local_proxy", interfaceName: nil)
        let codexProjection = ConnectionGraphProjection(proxy: proxy([codexFlow]), processes: [codexProcess], selectedFlowID: "codex-flow", fresh: true)
        expect(codexProjection.sourceKind == "code" && codexProjection.sourcePID == 43, "codex flow keeps its PID source")

        let ended = ConnectionGraphProjection(proxy: proxy([flow()]), processes: [], selectedFlowID: "f1", fresh: true)
        expect(ended.sourceEdgeState == .pending, "ended process removes source evidence")
        expect(ended.gatewayEdgeState == .pending, "ended process removes proxy evidence")
        expect(ended.summary.contains("进程样本已结束"), "ended process summary")
        expect(ended.gatewayState == .confirmed, "listener remains independently confirmed")

        let multi = ConnectionGraphProjection(proxy: proxy([flow(), flow(id: "f2")]), processes: [process], selectedFlowID: "f2", fresh: true)
        expect(multi.gatewayEdgeState == .confirmed, "each correlated match can confirm when selected")

        let mismatch = ConnectionGraphProjection(proxy: proxy([flow(policy: "mismatch")]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(mismatch.nodeEdgeState == .mismatch, "mismatch orange")
        expect(mismatch.targetEdgeState == .mismatch, "mismatch target")

        let listenerMissing = ConnectionGraphProjection(proxy: proxy([flow()], entry: "unconfirmed"), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(listenerMissing.sourceEdgeState == .pending, "unverified listener blocks whole local path")
        expect(listenerMissing.nodeEdgeState == .pending, "listener blocks node path")

        let policyMissing = ConnectionGraphProjection(proxy: proxy([flow()], covers: false), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(policyMissing.gatewayEdgeState == .pending, "missing proxy coverage blocks local path")

        let inconsistentLocal = ConnectionGraphProjection(proxy: proxy([flow(peer: "104.18.1.2:443")]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(inconsistentLocal.gatewayEdgeState == .pending, "local proxy label with remote peer is rejected")
        expect(inconsistentLocal.targetEdgeState == .pending, "rejected local proxy cannot certify target")

        let tun = ConnectionGraphProjection(proxy: proxy([flow(peer: "203.0.113.9:443", route: "Tun", interface: "utun4")]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(tun.gatewayTitle == "TUN 通道", "tun replaces central gateway")
        expect(tun.gatewayEndpoint == "utun4", "tun exposes observed interface")
        expect(tun.gatewayEdgeState == .confirmed, "explicit tun route evidence")
        expect(tun.nodeEdgeState == .confirmed, "explicit tun node evidence")
        expect(tun.routePresentation == "tun", "explicit tun presentation")
        expect(tun.supportsPathAnimation, "a fully evidenced TUN path can animate")

        let interfaceOnly = ConnectionGraphProjection(proxy: proxy([flow(route: nil, interface: "utun4")]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(interfaceOnly.gatewayEdgeState == .pending, "interface alone is not TUN proof")
        let tunLoopback = ConnectionGraphProjection(proxy: proxy([flow(route: "Tun", interface: "utun4")]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(tunLoopback.gatewayTitle != "TUN 通道", "Tun with loopback peer is rejected")
        expect(tunLoopback.nodeEdgeState == .pending, "Tun loopback path cannot be green")
        expect(!tunLoopback.supportsPathAnimation, "loopback-labelled TUN cannot animate as a TUN platform path")
        let tunOtherLoopback = ConnectionGraphProjection(proxy: proxy([flow(peer: "127.0.0.2:443", route: "Tun", interface: "utun4")]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(tunOtherLoopback.gatewayTitle != "TUN 通道", "127 slash 8 peer is rejected for TUN")
        let tunLocalhost = ConnectionGraphProjection(proxy: proxy([flow(peer: "localhost:443", route: "Tun", interface: "utun4")]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(tunLocalhost.routePresentation == "unresolved", "localhost is rejected for TUN")
        let notTun = ConnectionGraphProjection(proxy: proxy([flow(peer: "203.0.113.9:443", route: "not_tun", interface: "utun4")]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(notTun.gatewayTitle != "TUN 通道", "similar route name is not TUN")
        expect(notTun.gatewayEdgeState == .pending, "similar route name cannot confirm path")

        let unconfirmed = ConnectionGraphProjection(proxy: proxy([flow(association: "unconfirmed", route: nil)]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(unconfirmed.sourceEdgeState == .pending, "unconfirmed cannot pass")
        expect(unconfirmed.gatewayEdgeState == .pending, "unconfirmed proxy")
        expect(!unconfirmed.supportsPathAnimation, "unconfirmed platform-looking traffic remains static")

        let stale = ConnectionGraphProjection(proxy: proxy([flow()]), processes: [process], selectedFlowID: "f1", fresh: false)
        expect(stale.gatewayState == .pending, "stale listener is not confirmed")
        expect(stale.nodeEdgeState == .pending, "stale graph not confirmed")

        let unknownTarget = ConnectionGraphProjection(proxy: proxy([flow(host: "", peer: "127.0.0.1:7890")]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(unknownTarget.serviceEndpoint == "目标 IP 待确认", "gateway is not destination IP")
        expect(unknownTarget.targetEdgeState == .pending, "unknown target pending")
        let hostGateway = ConnectionGraphProjection(proxy: proxy([flow(host: "127.0.0.1:7890", peer: "127.0.0.1:7890")]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(hostGateway.serviceTitle == "目标服务待确认", "gateway host is not target host")
        let leafOnly = ConnectionGraphProjection(proxy: proxy([flow(chains: ["日本节点"])]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(leafOnly.groupState == .configuration, "leaf is not a group")
        let unresolved = ConnectionGraphProjection(proxy: proxy([flow(peer: "203.0.113.10:443", route: nil, interface: "utun9")]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(unresolved.gatewayTitle == "路径待关联", "non proxy non tun path is unresolved")
        expect(unresolved.gatewayEndpoint.contains("仅参考"), "interface is only a reference")
        expect(unresolved.routePresentation == "unresolved", "unresolved presentation")
        let localService = ConnectionGraphProjection(proxy: proxy([flow(association: "local_service", route: nil)]), processes: [process], selectedFlowID: "f1", fresh: true)
        expect(localService.gatewayTitle == "本机服务", "local service has its own center")
        expect(localService.gatewayEdgeState == .pending, "local service is not a proxy path")
        expect(localService.routePresentation == "localService", "local service presentation")
        func channel(_ changes: [String: Any] = [:]) -> FamilyChannelMonitorState {
            var row: [String: Any] = ["producer_boot_id":"fixture", "family":"openai", "session_id":NSNull(),
                "local_proxy_ready":true, "system_extension_active":false,
                "saved_policy_version":["policy_digest":"p", "guard_policy_digest":"g"],
                "applied_policy_version":["policy_digest":"p", "guard_policy_digest":"g"],
                "policy_sync_state":"applied", "policy_sync_label_zh":"执行器已应用", "permit_generation":1,
                "command_seq":1, "permit_state":"revoked", "display_state":"blocked", "display_label_zh":"已阻断",
                "reason_code":"vpn_observation_stale", "process_preserved":true, "active_member_pids":[],
                "active_members":[], "active_flows_count":0, "terminated_flows_count":40, "blocked_new_connections":10,
                "updated_at":1000, "backend":"seatbelt", "unmanaged_member_pids":Array(1000..<1090)]
            for (key, value) in changes { row[key] = value }
            return try! JSONDecoder().decode(FamilyChannelMonitorState.self, from: JSONSerialization.data(withJSONObject: row))
        }
        let unowned = channel()
        expect(!unowned.isConfirmedFlowBlocked, "an empty gateway cannot claim all 90 unmanaged processes are blocked")
        expect(unowned.protectionScopeLabel == "发现但未接管" && unowned.managedMemberCount == 0, "empty scope names discovery, not enforcement")
        expect(unowned.scopeSummary.contains("未接管 90 个") && !unowned.scopeSummary.contains("1000"), "summary shows counts instead of a long PID list")
        expect(unowned.gatewayCountsLabel.contains("受控网关") && unowned.gatewayCountsLabel.contains("累计断开 40"), "gateway historical counters are scoped and explicitly cumulative")
        expect(channel(["unmanaged_member_pids":[]]).protectionScopeLabel == "受控网关待命", "an idle gateway is distinct from blocking a managed application")
        let member: [String: Any] = ["pid":77,"uid":501,"start_seconds":900,"start_microseconds":1,
                                    "role":"desktop_main","audit_token":[501,501,20,501,20,77,0,9]]
        let coverage: [String: Any] = ["backend":"seatbelt","configured_entries":["openai"],"protected_pids":[77],
            "unprotected_pids":Array(1000..<1090),"uncovered_boundaries":["direct_launch_outside_controlled_entry"],
            "server_identity_verified":true,"gateway_endpoint_protection_verified":true,"gateway_endpoint_protection_method":"fixture"]
        let managedFields: [String: Any] = ["session_id":"current", "active_member_pids":[77], "active_members":[member], "coverage_scope":coverage]
        let mixed = channel(managedFields)
        expect(mixed.isConfirmedFlowBlocked && mixed.managedMemberCount == 1, "current identity and coverage establish blocking for one managed member")
        var cliMember = member; cliMember["role"] = "cli"
        var cliFields = managedFields; cliFields["active_member_pids"] = []; cliFields["active_members"] = [cliMember]
        expect(channel(cliFields).isConfirmedFlowBlocked && channel(cliFields).managedMemberCount == 1,
               "an independently controlled CLI is counted even when the desktop compatibility PID list is empty")
        var cliCoverage = coverage; cliCoverage["configured_entries"] = ["codex-cli"]
        cliFields["coverage_scope"] = cliCoverage
        expect(channel(cliFields).isConfirmedFlowBlocked, "a controlled entry identifier is not required to equal the family name")
        expect(mixed.protectionScopeLabel == "受控通道：已阻断" && mixed.scopeSummary.contains("未接管 90 个"), "partial coverage never becomes all-application protection")
        var changed = managedFields; changed["session_id"] = NSNull()
        expect(!channel(changed).isConfirmedFlowBlocked, "member evidence without a session does not establish protection")
        changed = managedFields; changed["active_members"] = []
        expect(!channel(changed).isConfirmedFlowBlocked, "PID-only coverage cannot substitute for bound identities")
        var forgedMember = member; forgedMember["audit_token"] = [501,501,20,501,20,999,0,9]
        changed = managedFields; changed["active_members"] = [forgedMember]
        expect(!channel(changed).isConfirmedFlowBlocked, "an audit token for another PID is not a verified member")
        changed = managedFields; changed["active_flows_count"] = 1
        expect(!channel(changed).isConfirmedFlowBlocked, "one remaining managed flow prevents confirmed blocking")
        changed = managedFields; changed["applied_policy_version"] = ["policy_digest":"old", "guard_policy_digest":"old"]
        expect(!channel(changed).isConfirmedFlowBlocked, "an applied flag cannot override mismatched policy identity")
        changed = managedFields; changed["coverage_scope"] = ["backend":"seatbelt","protected_pids":[77]]
        expect(!channel(changed).isConfirmedFlowBlocked, "incomplete coverage remains unverified")
        changed = managedFields; changed["unmanaged_member_pids"] = [77]
        expect(!channel(changed).isConfirmedFlowBlocked, "contradictory unmanaged identity is not counted as protected")
        changed = managedFields; changed["display_state"] = "pending_verification"
        expect(!channel(changed).isConfirmedFlowBlocked, "stale or pending evidence never retains confirmed blocking")
        changed = managedFields; changed["reason_code"] = "subscription_stale_or_disconnected"
        let expired = channel(changed)
        expect(!expired.isConfirmedFlowBlocked && expired.scopedDisplayState == .pendingVerification,
               "a disconnected subscription cannot retain blocking merely because its last status was blocked")
        expect(expired.scopeSummary.hasPrefix("上次") && expired.gatewayCountsLabel.contains("当前连接数待核验"),
               "retained scope and counters are historical when channel subscription evidence expires")
        print("GraphModelTests: \(passed) assertions passed")
    }
}
