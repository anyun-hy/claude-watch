import Foundation

@main
struct ConnectionInventoryTests {
    static func main() {
        var passed = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            guard value() else { fputs("FAIL: \(message)\n", stderr); exit(1) }; passed += 1
        }
        let desktop = WatchedProcess(id: "main", pid: 20, started: "now", kind: "openai-desktop-main", authorized: true)
        let renewed = WatchedProcess(id: "new", pid: 21, started: "later", kind: "openai-desktop-main", authorized: true)
        let network = WatchedProcess(id: "network", pid: 30, started: "now", kind: "openai-desktop-helper", authorized: nil,
                                     runtimeRole: "chromium_network", serviceName: "Chromium 网络服务", roleEvidence: "runtime_component")
        let claudeNetwork = WatchedProcess(id: "claude-network", pid: 31, started: "now", kind: "desktop-helper", authorized: nil,
                                           runtimeRole: "chromium_network", serviceName: "Chromium 网络服务", roleEvidence: "runtime_component")
        let mcp = WatchedProcess(id: "tool", pid: 40, started: "now", kind: "openai-child", authorized: nil,
                                 runtimeRole: "mcp", serviceName: "REA", roleEvidence: "configured_mcp_entry")
        func flow(_ id: String, pid: Int = 20, host: String = "chatgpt.com", peer: String = "127.0.0.1:7890",
                  local: String = "127.0.0.1:50000", policy: String = "match", association: String = "correlated",
                  chains: [String] = ["海外AI", "日本11"]) -> Flow {
            .init(id: id, pid: pid, host: host, peer: peer, local: local, transport: "TCP", association: association,
                  policy: policy, reason: "fixture", chains: chains, routePath: "local_proxy", interfaceName: nil)
        }
        func grouped(_ processes: [WatchedProcess], _ flows: [Flow]) -> [ConnectionServiceGroup] {
            ConnectionInventory.groups(product: .openAI, processes: processes, flows: flows)
        }
        let old = grouped([desktop], [flow("one"), flow("two", local: "127.0.0.1:59999")])
        let new = grouped([renewed], [flow("replacement", pid: 21, local: "127.0.0.1:60001")])
        expect(old.count == 1 && old[0].flows.count == 2, "same named service aggregates sockets")
        expect(old[0].id == new[0].id, "PID, source port and connection IDs do not change group identity")
        expect(old[0].name == "chatgpt.com", "human service name replaces PID label")
        expect(ConnectionInventory.purpose(flow("tool", pid: 40), process: mcp) == .mcp, "configured MCP process is not counted as platform")
        let local = flow("local", host: "127.0.0.1:9876", peer: "127.0.0.1:9876", policy: "not_applicable", association: "local_service", chains: [])
        let localGroup = grouped([desktop], [local])[0]
        expect(localGroup.purpose == .local && localGroup.status == "本机通信", "local not-applicable never renders pending proxy")
        expect(ConnectionInventory.purpose(flow("gateway"), process: desktop) == .platform, "7890 loopback proxy is not a local IPC service")
        expect(ConnectionInventory.purpose(flow("spoof", host: "chatgpt.com.evil.org"), process: desktop) != .platform, "domain boundary respected")
        expect(!ConnectionInventory.loopback("127.evil.org:9876"), "domain prefix cannot impersonate loopback")
        expect(ConnectionInventory.loopback("[::1]:9876"), "IPv6 loopback is local")
        let helper = flow("helper", pid: 30, host: "198.18.0.6:5228", peer: "198.18.0.6:5228", policy: "unconfirmed", association: "unconfirmed", chains: [])
        expect(grouped([network], [helper])[0].purpose == .unidentified, "a helper with an unknown target remains unidentified, not a known component request")
        expect(grouped([network], [helper])[0].status == "用途未识别", "process ownership is distinct from request purpose")
        expect(ConnectionGraphScope(product: .openAI, processes: [network], flows: [helper]).platformFlows.isEmpty, "auxiliary flow never supplies model server diagram")
        let componentTun = Flow(id: "network-platform-tun", pid: 30, host: "api.openai.com", peer: "203.0.113.44:443", local: "127.0.0.1:50001", transport: "TCP", association: "correlated", policy: "match", reason: "fixture", chains: ["海外AI", "日本11"], routePath: "tun", interfaceName: "utun4")
        expect(ConnectionInventory.purpose(componentTun, process: network) == .platform, "a Chromium network process can carry a verified platform request")
        expect(ConnectionGraphScope(product: .openAI, processes: [network], flows: [componentTun]).platformFlows.map(\.id) == ["network-platform-tun"], "a verified helper TUN platform request remains eligible for the graph")
        let claudeHelperTun = Flow(id: "claude-helper-tun", pid: 31, host: "claude.ai", peer: "203.0.113.46:443", local: "127.0.0.1:50003", transport: "TCP", association: "correlated", policy: "match", reason: "fixture", chains: ["海外AI", "日本11"], routePath: "tun", interfaceName: "utun4")
        expect(ConnectionInventory.purpose(claudeHelperTun, process: claudeNetwork) == .platform, "a Claude Chromium helper can carry a verified platform request")
        expect(ConnectionGraphScope(product: .claude, processes: [claudeNetwork], flows: [claudeHelperTun]).platformFlows.map(\.id) == ["claude-helper-tun"], "a verified Claude helper TUN request remains eligible for the graph")
        let genericComponentTun = Flow(id: "network-gstatic-tun", pid: 30, host: "www.gstatic.com", peer: "203.0.113.45:443", local: "127.0.0.1:50002", transport: "TCP", association: "correlated", policy: "match", reason: "fixture", chains: ["海外AI", "日本11"], routePath: "tun", interfaceName: "utun4")
        expect(ConnectionInventory.purpose(genericComponentTun, process: network) == .component, "a generic Chromium TUN request remains a component")
        expect(ConnectionGraphScope(product: .openAI, processes: [network], flows: [genericComponentTun]).platformFlows.isEmpty, "a generic component TUN sample cannot supply the platform graph")
        let mixed = grouped([desktop], [flow("match"), flow("difference", policy: "mismatch", chains: ["海外AI", "日本09"])])[0]
        expect(mixed.routes.count == 2 && mixed.status == "路径差异", "aggregation preserves different routes and adverse evidence")
        let toolGroup = grouped([mcp], [flow("tool", pid: 40)])[0]
        expect(toolGroup.name == "REA" && toolGroup.flows.count == 1, "MCP is named by configured tool")
        expect(ConnectionGraphScope(product: .openAI, processes: [mcp], flows: [flow("tool", pid: 40)]).platformFlows.isEmpty, "MCP cannot drive AI platform graph")
        expect(grouped([desktop], [flow("foreign", pid: 99)]).isEmpty, "foreign or ended PID supplies no current group")
        expect(desktop.componentKey == renewed.componentKey, "process component grouping is stable through PID replacement")
        print("ConnectionInventoryTests: \(passed) assertions passed")
    }
}
