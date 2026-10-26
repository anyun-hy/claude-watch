import Foundation

@main
struct NetworkGraphSelectionTests {
    static func main() {
        var passed = 0
        func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
            guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
            passed += 1
        }

        let claude = WatchedProcess(id: "claude", pid: 10, started: "now", kind: "desktop-main", authorized: true)
        let desktop = WatchedProcess(id: "desktop", pid: 20, started: "now", kind: "openai-desktop-main", authorized: true)
        let replacementDesktop = WatchedProcess(id: "desktop-new", pid: 21, started: "later", kind: "openai-desktop-main", authorized: true)
        let cli = WatchedProcess(id: "cli", pid: 30, started: "now", kind: "codex-cli", authorized: true)
        let networkComponent = WatchedProcess(id: "network", pid: 31, started: "now", kind: "openai-desktop-helper", authorized: nil,
                                              runtimeRole: "chromium_network", serviceName: "Chromium 网络服务", roleEvidence: "runtime_component")
        let claudeNetworkComponent = WatchedProcess(id: "claude-network", pid: 32, started: "now", kind: "desktop-helper", authorized: nil,
                                                    runtimeRole: "chromium_network", serviceName: "Chromium 网络服务", roleEvidence: "runtime_component")

        func flow(_ id: String, pid: Int = 20, host: String = "chatgpt.com", local: String = "127.0.0.1:51001", peer: String = "127.0.0.1:7890", policy: String = "match", association: String = "correlated", route: String? = "local_proxy", chains: [String] = ["海外AI", "日本11"], interface: String? = nil) -> Flow {
            Flow(id: id, pid: pid, host: host, peer: peer, local: local, transport: "TCP", association: association, policy: policy, reason: "fixture", chains: chains, routePath: route, interfaceName: interface)
        }
        func proxy(_ flows: [Flow]) -> ProxySnapshot {
            ProxySnapshot(observedAt: 1, entryState: "verified", entryReason: "listener", entrySource: "fixture", endpoint: "127.0.0.1:7890", listenerPID: 7, listenerPath: "/mihomo", apiState: "available", apiReason: "", mode: "rule", coversProxy: true, expectedGroup: "海外AI", expectedNode: "日本11", selectedNode: "日本11", globalNode: "日本09", pinned: false, selectionChanged: false, flows: flows)
        }

        let local = flow("local", host: "127.0.0.1:9876", local: "127.0.0.1:54000", peer: "127.0.0.1:9876", association: "local_service", route: nil, chains: [])
        let noChain = flow("no-chain", chains: [])
        let fakeTun = flow("fake-tun", peer: "127.0.0.1:7890", route: "tun")
        let japan09Mismatch = flow("old-09", local: "127.0.0.1:51002", policy: "mismatch", chains: ["海外AI", "日本09"])
        let japan11Match = flow("new-11", local: "127.0.0.1:51003", policy: "match", chains: ["海外AI", "日本11"])

        var selection = NetworkGraphSelection()
        selection.reconcile(proxy: proxy([local, noChain, fakeTun, japan09Mismatch]), processes: [desktop], fresh: true)
        expect(selection.selectedFlowID(for: .openAI) == "old-09", "automatic OpenAI ignores local, no-chain, and fake-TUN samples")
        expect(selection.selectedFlowID(for: .claude) == nil, "products retain independent empty selections")

        selection.reconcile(proxy: proxy([japan11Match, local, japan09Mismatch]), processes: [desktop], fresh: true)
        expect(selection.selectedFlowID(for: .openAI) == "new-11", "a fresh confirmed path replaces an older mismatch")

        selection.reconcile(proxy: proxy([japan09Mismatch, japan11Match, local]), processes: [desktop], fresh: true)
        expect(selection.selectedFlowID(for: .openAI) == "new-11", "array reordering does not move an equally ranked live selection")

        let refreshedID = flow("new-11-reconnected", pid: 21, local: "127.0.0.1:59991", chains: ["海外AI", "日本11"])
        selection.reconcile(proxy: proxy([japan09Mismatch, refreshedID]), processes: [replacementDesktop], fresh: true)
        expect(selection.selectedFlowID(for: .openAI) == "new-11-reconnected", "PID, port, and connection-ID replacement continues the same named route")

        selection.product = .claude
        selection.reconcile(proxy: proxy([flow("claude-old", pid: 10, host: "api.anthropic.com"), refreshedID]), processes: [claude, replacementDesktop], fresh: true)
        expect(selection.selectedFlowID(for: .claude) == "claude-old", "Claude automatically selects the same evidenced route class as OpenAI")
        expect(selection.selectedFlowID(for: .openAI) == "new-11-reconnected", "switching product does not disturb the OpenAI route")

        let claudeTun = flow("claude-tun", pid: 32, host: "api.anthropic.com", peer: "203.0.113.20:443", route: "tun", interface: "utun4")
        let openAITun = flow("openai-tun", pid: 30, host: "api.openai.com", peer: "203.0.113.21:443", route: "tun", interface: "utun4")
        let fakeClaudeTun = flow("claude-fake-tun", pid: 32, host: "api.anthropic.com", route: "tun")
        let fakeOpenAITun = flow("openai-fake-tun", pid: 30, host: "api.openai.com", route: "tun")
        var tunSelection = NetworkGraphSelection()
        tunSelection.reconcile(proxy: proxy([claudeTun, openAITun]), processes: [claudeNetworkComponent, cli], fresh: true)
        expect(tunSelection.selectedFlowID(for: .claude) == "claude-tun", "Claude helper selects an evidenced non-loopback TUN route")
        expect(tunSelection.selectedFlowID(for: .openAI) == "openai-tun", "ChatGPT / Codex selects the same evidenced non-loopback TUN route")
        tunSelection.reconcile(proxy: proxy([fakeClaudeTun, fakeOpenAITun]), processes: [claudeNetworkComponent, cli], fresh: true)
        expect(tunSelection.selectedFlowID(for: .claude) == nil, "Claude never falls back to a loopback-labelled TUN route")
        expect(tunSelection.selectedFlowID(for: .openAI) == nil, "ChatGPT / Codex never falls back to a loopback-labelled TUN route")

        let helperTun = flow("helper-tun", pid: 31, host: "api.openai.com", peer: "203.0.113.22:443", route: "tun", interface: "utun4")
        tunSelection.reconcile(proxy: proxy([helperTun]), processes: [networkComponent], fresh: true)
        expect(tunSelection.selectedFlowID(for: .openAI) == "helper-tun", "a verified platform request from Chromium network process can select the same TUN path")
        let genericComponentTun = flow("component-tun", pid: 31, host: "www.gstatic.com", peer: "203.0.113.23:443", route: "tun", interface: "utun4")
        tunSelection.reconcile(proxy: proxy([genericComponentTun]), processes: [networkComponent], fresh: true)
        expect(tunSelection.selectedFlowID(for: .openAI) == nil, "a generic Chromium component cannot select or animate as platform traffic")

        selection.select(flowID: "local", product: .openAI)
        selection.reconcile(proxy: proxy([local, refreshedID]), processes: [desktop, replacementDesktop], fresh: true)
        expect(selection.selectedFlowID(for: .openAI) == "new-11-reconnected", "local IPC cannot displace a named AI platform route")

        selection.reconcile(proxy: proxy([refreshedID]), processes: [replacementDesktop], fresh: true)
        expect(selection.selectedFlowID(for: .openAI) == "new-11-reconnected", "an ended manual sample returns to an evidenced automatic path")

        let remembered = selection.selectedFlowID(for: .openAI)
        selection.reconcile(proxy: nil, processes: [], fresh: false)
        expect(selection.selectedFlowID(for: .openAI) == remembered, "temporary snapshot loss retains selection memory")

        selection.reconcile(proxy: proxy([refreshedID]), processes: [], fresh: true)
        expect(selection.selectedFlowID(for: .openAI) == nil, "a PID that ended supplies no replacement graph path")

        selection.reconcile(proxy: proxy([local, noChain, fakeTun]), processes: [desktop], fresh: true)
        expect(selection.selectedFlowID(for: .openAI) == nil, "OpenAI never promotes local or unproven paths into animation")

        let cliFlow = flow("cli-flow", pid: 30, host: "api.openai.com", local: "127.0.0.1:61001")
        selection.reconcile(proxy: proxy([cliFlow, japan11Match]), processes: [cli, desktop], fresh: true)
        expect(selection.selectedFlowID(for: .openAI) == "new-11", "same-rank candidates retain the prior named path instead of mixing nodes")

        print("NetworkGraphSelectionTests: \(passed) assertions passed")
    }
}
