import AppKit
import SwiftUI

@main
struct ClaudeWatchUIReviewApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var session = UIReviewSession()

    var body: some Scene {
        WindowGroup("Claude Watch UI Review") {
            UIReviewRoot(session: session)
        }
        .defaultSize(width: 1240, height: 820)
        .windowStyle(.titleBar)
        .windowToolbarStyle(.unifiedCompact)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("验收场景") {
                ForEach(Array(UIReviewScenario.allCases.enumerated()), id: \.element) { index, scenario in
                    if index < 9 {
                        Button(scenario.title) { session.apply(scenario) }
                            .keyboardShortcut(KeyEquivalent(Character(String(index + 1))), modifiers: [.command, .shift])
                    } else { Button(scenario.title) { session.apply(scenario) } }
                }
            }
            CommandMenu("连接连续性验收") {
                ForEach(GraphReviewScenario.allCases) { scenario in
                    Button(scenario.rawValue) { session.applyGraphScenario(scenario) }
                }
            }
            CommandMenu("验收页面") {
                ForEach(Array(Page.orderedPages.enumerated()), id: \.element) { index, page in
                    if index < 10 {
                        Button(page.rawValue) { session.store.page = page }
                            .keyboardShortcut(KeyEquivalent(Character(index == 9 ? "0" : String(index + 1))), modifiers: .command)
                    } else { Button(page.rawValue) { session.store.page = page } }
                }
            }
            CommandMenu("验收尺寸") {
                Button("1000 × 680") { session.resize(width: 1000, height: 680) }
                    .keyboardShortcut("1", modifiers: [.command, .option])
                Button("1240 × 820") { session.resize(width: 1240, height: 820) }
                    .keyboardShortcut("2", modifiers: [.command, .option])
                Button("1440 × 900") { session.resize(width: 1440, height: 900) }
                    .keyboardShortcut("3", modifiers: [.command, .option])
            }
            CommandMenu("泄漏检测验收") {
                ForEach(LeakFixtureScenario.allCases, id: \.rawValue) { scenario in
                    Button(scenario.rawValue) { session.store.leakChecks.loadFixture(scenario) }
                }
            }
            CommandMenu("环境保护场景") {
                ForEach(SwitcherReviewScenario.allCases, id: \.rawValue) { scenario in
                    Button(scenario.title) { session.applyEnvironmentScenario(scenario) }
                }
            }
            CommandMenu("AI 页面验收") {
                ForEach(AIProbeFixtureScenario.allCases, id: \.rawValue) { scenario in
                    Button(scenario.rawValue) { session.store.aiChecks.loadFixture(scenario) }
                }
            }
            CommandMenu("GPT 设计预览") {
                ForEach(GPTDiagnosticLayout.allCases, id: \.self) { layout in
                    Button(layout.rawValue) { session.gptLayout = layout; session.store.page = .gptAI }
                }
                Divider()
                Button("结果已过期") {
                    session.store.aiChecks.now = Date().addingTimeInterval(301)
                    session.store.page = .gptAI
                }
            }
        }
    }
}

private struct UIReviewRoot: View {
    @ObservedObject var session: UIReviewSession

    var body: some View {
        MonitorView(store: session.store, startMonitoring: false, restoresNavigation: false, refreshAction: session.refresh)
            .environment(\.gptDiagnosticLayout, session.gptLayout)
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Text("模拟数据 · 界面验收")
                        .font(.system(size: 13, weight: .semibold))
                        .accessibilityLabel("模拟数据，界面验收")
                }
            }
    }
}

@MainActor
private final class UIReviewSession: ObservableObject {
    let store = MonitorStore()
    @Published var gptLayout: GPTDiagnosticLayout = .inspector
    private var currentScenario: UIReviewScenario = .loading
    private var graphClock = UIReviewFixtures.epoch + 100

    init() {
        UserDefaults.standard.set(false, forKey: "darkAppearance")
        store.leakChecks.fixtureDelayNanoseconds = 2_000_000_000
        apply(.namedServices)
        store.aiChecks.loadFixture(.ready)
        store.leakChecks.loadFixture(.matched)
        store.leakChecks.loadRecordedCoffeeFixture()
        store.netCoffee.fetchAI("8.8.8.8")
        store.networkSelection.product = .openAI
        applyEnvironmentScenario(.normal)
    }

    func apply(_ scenario: UIReviewScenario) {
        currentScenario = scenario
        store.error = scenario.error
        store.snapshot = scenario.snapshot
        store.now = Date(timeIntervalSince1970: scenario.snapshot?.capturedAt ?? UIReviewFixtures.epoch)
        // Explicit fixture references only; the review app never starts query workers.
        for flow in scenario.snapshot?.proxy?.flows ?? [] {
            guard let request = ServerReferenceRequest(flow: flow) else { continue }
            let address = request.observedIP ?? "104.18.32.7"
            store.acceptServerReference(ServerReference(host: request.host,
                basis: request.observedIP == nil ? "dns_reference" : "observed_ip", address: address, addresses: [address],
                countryCode: "US", country: "美国", region: "加利福尼亚州", city: "",
                status: "ready", message: "模拟数据，仅供界面验收。", queriedAt: UIReviewFixtures.epoch,
                expiresAt: UIReviewFixtures.epoch + 600, dnsSource: "Cloudflare DoH（模拟）", geoSource: "IPinfo（模拟）"),
                for: request, at: store.now)
        }
        store.synchronizeNetworkSelection()
    }

    func refresh() { apply(currentScenario) }

    func applyGraphScenario(_ scenario: GraphReviewScenario) {
        graphClock += 10
        store.error = scenario == .failed ? "隔离模拟：本轮读取失败，没有进行真实采集。" : nil
        store.now = Date(timeIntervalSince1970: graphClock)
        store.snapshot = UIReviewFixtures.continuitySnapshot(scenario, at: graphClock)
        store.automatic = scenario != .paused
        store.page = .network
        store.synchronizeNetworkSelection()
    }

    func applyEnvironmentScenario(_ scenario: SwitcherReviewScenario) {
        guard let bundle = ReviewReceiptBundle.load(scenario) else { return }
        store.switcher.loadReviewReceipts(bundle.environment, background: bundle.background)
        if let webrtc = bundle.webrtc { store.leakChecks.loadReviewWebRTC(webrtc) }
        store.page = .environment
    }

    func resize(width: CGFloat, height: CGFloat) {
        guard let window = NSApp.keyWindow ?? NSApp.windows.first(where: { $0.isVisible }) else { return }
        window.setContentSize(NSSize(width: width, height: height))
    }
}

private enum GraphReviewScenario: String, CaseIterable, Identifiable {
    case live = "1 实时完整路径"
    case quiet = "2 本轮暂无新连接"
    case failed = "3 读取失败"
    case partial = "4 采样不完整"
    case expired = "5 样本过期"
    case changed = "6 网络上下文变化"
    case recovered = "7 恢复新的完整路径"
    case stopped = "8 应用进程退出"
    case paused = "9 暂停界面刷新"
    var id: String { rawValue }
}

private struct ReviewReceiptBundle: Decodable {
    let environment: CurrentEnvironmentReceipt
    let background: BackgroundServiceReceipt
    let webrtc: LeakProbeResult?

    static func load(_ scenario: SwitcherReviewScenario) -> ReviewReceiptBundle? {
        guard let url = Bundle.main.url(forResource: scenario.rawValue, withExtension: "json", subdirectory: "review"),
              let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(ReviewReceiptBundle.self, from: data)
    }
}

private enum UIReviewScenario: String, CaseIterable, Identifiable {
    case loading, idle, activeMatch, mismatchTun, failure, longText, refreshedConnections, nodeSwitched, namedServices, renewedNamedServices

    var id: String { rawValue }
    var title: String {
        switch self {
        case .loading: return "读取中"
        case .idle: return "空闲"
        case .activeMatch: return "活动匹配"
        case .mismatchTun: return "路径差异与 TUN"
        case .failure: return "读取失败"
        case .longText: return "长文本"
        case .refreshedConnections: return "同名应用更换 PID 与连接"
        case .nodeSwitched: return "旧09与新11连接共存"
        case .namedServices: return "名称聚合 · MCP 与 Chromium"
        case .renewedNamedServices: return "同名组件更换 PID 与端口"
        }
    }

    var error: String? { self == .failure ? "模拟读取失败：未向后台、采集器或网络发送请求。" : nil }

    var snapshot: MonitorSnapshot? {
        switch self {
        case .loading, .failure: return nil
        case .idle: return UIReviewFixtures.snapshot()
        case .activeMatch: return UIReviewFixtures.snapshot(
            processes: UIReviewFixtures.processes,
            events: UIReviewFixtures.events,
            proxy: UIReviewFixtures.matchingProxy
        )
        case .mismatchTun: return UIReviewFixtures.snapshot(
            processes: UIReviewFixtures.processes,
            events: UIReviewFixtures.mismatchEvents,
            proxy: UIReviewFixtures.tunMismatchProxy
        )
        case .longText: return UIReviewFixtures.snapshot(
            processes: UIReviewFixtures.processes,
            events: UIReviewFixtures.longEvents,
            proxy: UIReviewFixtures.matchingProxy
        )
        case .refreshedConnections: return UIReviewFixtures.snapshot(
            processes: UIReviewFixtures.refreshedProcesses,
            proxy: UIReviewFixtures.refreshedProxy
        )
        case .nodeSwitched: return UIReviewFixtures.snapshot(
            processes: UIReviewFixtures.refreshedProcesses,
            proxy: UIReviewFixtures.switchedNodeProxy
        )
        case .namedServices: return UIReviewFixtures.namedSnapshot(shift: 0)
        case .renewedNamedServices: return UIReviewFixtures.namedSnapshot(shift: 1000)
        }
    }
}

private enum UIReviewFixtures {
    static let epoch: Double = 1_792_224_000

    static func namedSnapshot(shift: Int) -> MonitorSnapshot {
        let records = [
            WatchedProcess(id: "main-\(shift)", pid: 500 + shift, started: "mock", kind: "openai-desktop-main", authorized: true),
            WatchedProcess(id: "network-\(shift)", pid: 501 + shift, started: "mock", kind: "openai-desktop-helper", authorized: true,
                runtimeRole: "chromium_network", serviceName: "Chromium 网络服务", roleEvidence: "runtime_component"),
            WatchedProcess(id: "mcp-\(shift)", pid: 502 + shift, started: "mock", kind: "openai-child", authorized: true,
                runtimeRole: "mcp", serviceName: "REA", roleEvidence: "configured_mcp_entry")
        ]
        func sample(_ name: String, owner: Int, host: String, peer: String = "127.0.0.1:7890", association: String = "correlated", policy: String = "match", port: Int) -> Flow {
            Flow(id: "\(name)-\(shift)", pid: owner + shift, host: host, peer: peer,
                local: "127.0.0.1:\(port + shift)", transport: "TCP", association: association, policy: policy,
                reason: "隔离模拟数据，不代表当前系统连接。", chains: association == "correlated" ? ["海外 AI", "东京节点"] : [],
                routePath: association == "correlated" ? "local_proxy" : nil, interfaceName: nil)
        }
        let samples = [
            sample("chat-1", owner: 500, host: "chatgpt.com", port: 50001),
            sample("chat-2", owner: 501, host: "chatgpt.com", port: 50002),
            sample("api", owner: 501, host: "api.openai.com", port: 50003),
            sample("mcp", owner: 502, host: "tools.example.org", port: 50004),
            sample("local-1", owner: 500, host: "127.0.0.1:9876", peer: "127.0.0.1:9876", association: "local_service", policy: "not_applicable", port: 50005),
            sample("local-2", owner: 501, host: "127.0.0.1:9876", peer: "127.0.0.1:9876", association: "local_service", policy: "not_applicable", port: 50006),
            sample("tun-1", owner: 501, host: "198.18.0.6:5228", peer: "198.18.0.6:5228", association: "unconfirmed", policy: "unconfirmed", port: 50007),
            sample("tun-2", owner: 501, host: "198.18.0.6:443", peer: "198.18.0.6:443", association: "unconfirmed", policy: "unconfirmed", port: 50008)
        ]
        return snapshot(processes: records, proxy: proxy(flows: samples, selectedNode: "东京节点"))
    }

    static let processes = [
        WatchedProcess(id: "desktop", pid: 4217, started: "2026-10-19 10:31:14", kind: "desktop-main", authorized: true),
        WatchedProcess(id: "code", pid: 4262, started: "2026-10-19 10:33:02", kind: "code", authorized: nil),
        WatchedProcess(id: "helper", pid: 4270, started: "", kind: "desktop-helper", authorized: false),
        WatchedProcess(id: "codex", pid: 4311, started: "2026-10-19 10:35:01", kind: "codex-cli", authorized: true),
        WatchedProcess(id: "chatgpt", pid: 4364, started: "2026-10-19 10:36:22", kind: "chatgpt-desktop-main", authorized: true),
        WatchedProcess(id: "shared", pid: 4370, started: "2026-10-19 10:36:26", kind: "openai-desktop-helper", authorized: nil)
    ]

    static let events = [
        Event(id: "match", timestamp: "10:44:00", epoch: epoch, severity: "info", category: "network",
              title: "连接样本与预期路径匹配", detail: "PID 4262 通过 127.0.0.1:7890 访问 api.anthropic.com:443。"),
        Event(id: "process", timestamp: "10:42:18", epoch: epoch - 102, severity: "notice", category: "process",
              title: "检测到 Claude Code 会话", detail: "该会话的授权状态尚待后续采样确认。")
    ]

    static let mismatchEvents = [
        Event(id: "tun", timestamp: "10:45:12", epoch: epoch, severity: "warning", category: "network",
              title: "TUN 路径与预期节点存在差异", detail: "路径由 utun4 观测到；该记录仅用于界面验收，不表示真实网络状态。")
    ]

    static let longEvents = [
        Event(id: "long", timestamp: "10:46:39", epoch: epoch, severity: "error", category: "network",
              title: "包含长原始记录的示例事件",
              detail: "原始记录：connection=8F61A7A3 pid=4262 local=10.0.0.7:53821 peer=203.0.113.9:443 route=Tun interface=utun4 policy=mismatch。此段文本用于检查折叠、展开、复制、换行与窄窗口下的布局；它是静态 fixture，不来自采集器，也不应被解释为实际异常。")
    ]

    static let matchingProxy = proxy(
        flows: [
        Flow(id: "matching", pid: 4262, host: "api.anthropic.com:443", peer: "127.0.0.1:7890",
                   local: "127.0.0.1:53821", transport: "TCP", association: "correlated", policy: "match",
                   reason: "模拟的本机代理关联", chains: ["海外 AI", "东京节点"], routePath: "local_proxy", interfaceName: nil),
        Flow(id: "codex-matching", pid: 4311, host: "api.openai.com:443", peer: "127.0.0.1:7890",
                   local: "127.0.0.1:53827", transport: "TCP", association: "correlated", policy: "match",
                   reason: "Codex 与 Claude 使用同一主机名时仍由 PID 分离", chains: ["海外 AI", "东京节点"], routePath: "local_proxy", interfaceName: nil),
        Flow(id: "chatgpt-matching", pid: 4364, host: "api.openai.com:443", peer: "127.0.0.1:7890",
                   local: "127.0.0.1:53829", transport: "TCP", association: "correlated", policy: "match",
                   reason: "ChatGPT 样本，仅用于界面验收", chains: ["海外 AI", "东京节点"], routePath: "local_proxy", interfaceName: nil)
        ],
        selectedNode: "东京节点"
    )

    static let tunMismatchProxy = proxy(
        flows: [Flow(id: "tun-mismatch", pid: 4262, host: "api.anthropic.com:443", peer: "203.0.113.9:443",
                   local: "10.0.0.7:53822", transport: "TCP", association: "correlated", policy: "mismatch",
                   reason: "模拟的 TUN 路径差异", chains: ["海外 AI", "东京节点"], routePath: "Tun", interfaceName: "utun4")],
        selectedNode: "其他节点"
    )

    static let refreshedProcesses = processes.filter { $0.pid != 4364 && $0.pid != 4370 } + [
        WatchedProcess(id: "chatgpt-new", pid: 4980, started: "2026-10-19 11:00:00", kind: "chatgpt-desktop-main", authorized: true)
    ]
    static let refreshedProxy = proxy(flows: [
        Flow(id: "local-service", pid: 4980, host: "127.0.0.1:9876", peer: "127.0.0.1:9876",
             local: "127.0.0.1:60001", transport: "TCP", association: "local_service", policy: "not_applicable",
             reason: "模拟本机服务，不应自动覆盖代理路径", chains: [], routePath: nil, interfaceName: nil),
        Flow(id: "chatgpt-refreshed", pid: 4980, host: "api.openai.com:443", peer: "127.0.0.1:7890",
             local: "127.0.0.1:60002", transport: "TCP", association: "correlated", policy: "match",
             reason: "同名应用的新 PID、新端口及新连接实例", chains: ["海外 AI", "东京节点"], routePath: "local_proxy", interfaceName: nil)
    ], selectedNode: "东京节点")
    static let switchedNodeProxy = proxy(flows: [
        Flow(id: "old-node-09", pid: 4980, host: "api.openai.com:443", peer: "127.0.0.1:7890",
             local: "127.0.0.1:60002", transport: "TCP", association: "correlated", policy: "mismatch",
             reason: "旧长连接仍经日本09", chains: ["海外 AI", "日本09"], routePath: "local_proxy", interfaceName: nil),
        Flow(id: "new-node-11", pid: 4980, host: "api.openai.com:443", peer: "127.0.0.1:7890",
             local: "127.0.0.1:60003", transport: "TCP", association: "correlated", policy: "match",
             reason: "新连接实际经日本11", chains: ["海外 AI", "日本11"], routePath: "local_proxy", interfaceName: nil)
    ], selectedNode: "日本11", expectedNode: "日本11", globalNode: "日本11")

    static func snapshot(processes: [WatchedProcess] = [], events: [Event] = [], proxy: ProxySnapshot? = nil,
                         at time: Double = epoch, collector: String? = nil) -> MonitorSnapshot {
        var proxy = proxy
        if var value = proxy {
            value.listenerStarted = "fixture-tag-start"
            value.connectionObservation = ConnectionObservation(schema: 1, roundID: "fixture-\(value.observedAt)",
                observedAt: value.observedAt, collectorState: collector ?? (processes.isEmpty ? "no_targets" : value.flows.isEmpty ? "empty" : "ok"),
                targetCount: processes.count, parsedCount: value.flows.count, acceptedCount: value.flows.count,
                correlatedCount: value.flows.filter { $0.association == "correlated" }.count,
                unconfirmedCount: value.flows.filter { $0.association == "unconfirmed" }.count,
                dropped: [:], detail: "隔离模拟连接回执", uiFilteredCount: 0, uiDropped: [:])
            proxy = value
        }
        return MonitorSnapshot(capturedAt: time,
                        health: Health(state: "running", mode: "ACTIVE", pid: 4100, heartbeatAge: 0,
                                       started: "2026-10-19 10:00:00", detail: "模拟监控状态，仅供界面验收。", alerts: "无"),
                        installed: true, autoStart: true, keepAlive: true, hasBaseline: true, stderrBytes: 0,
                        processes: processes, events: events, proxy: proxy, proxyError: nil,
                        logPath: "/tmp/claude-watch-ui-review.log", backendVersion: "2.2.0-fixture",
                        monitoredApps: ["claude", "codex", "chatgpt"])
    }

    private static func proxy(flows: [Flow], selectedNode: String, expectedNode: String = "东京节点", globalNode: String = "", at time: Double = epoch) -> ProxySnapshot {
        ProxySnapshot(observedAt: time, entryState: "verified", entryReason: "模拟监听者证据", entrySource: "UI fixture",
                      endpoint: "127.0.0.1:7890", listenerPID: 4101, listenerPath: "/mock/mihomo", apiState: "available",
                      apiReason: "", mode: "rule", coversProxy: true, expectedGroup: "海外 AI", expectedNode: expectedNode,
                      selectedNode: selectedNode, globalNode: globalNode, pinned: true, selectionChanged: selectedNode != expectedNode, flows: flows)
    }

    static func continuitySnapshot(_ scenario: GraphReviewScenario, at time: Double) -> MonitorSnapshot {
        let newNetwork = scenario == .changed || scenario == .recovered || scenario == .stopped
        let node = newNetwork ? "新的日本节点" : "东京节点"
        let active = scenario == .live || scenario == .recovered || scenario == .paused
        let flows: [Flow] = active ? [
            Flow(id: "claude-\(time)", pid: 4262, host: "api.anthropic.com", peer: "198.18.0.89:443",
                 local: "198.18.0.1:53001", transport: "UDP", association: "correlated", policy: "match", reason: "隔离模拟：同核映射与链路已核对",
                 chains: ["海外 AI", node], routePath: "Tun", interfaceName: "utun4", destinationIP: "160.79.104.10", destinationPort: 443, destinationIPState: "public"),
            Flow(id: "openai-\(time)", pid: 4364, host: "chatgpt.com", peer: "198.18.0.90:443",
                 local: "198.18.0.1:53002", transport: "UDP", association: "correlated", policy: "match", reason: "隔离模拟：同核映射与链路已核对",
                 chains: ["海外 AI", node], routePath: "Tun", interfaceName: "utun4")
        ] : []
        return snapshot(processes: scenario == .stopped ? [] : processes,
            proxy: proxy(flows: flows, selectedNode: node, expectedNode: node,
                         at: scenario == .expired ? time - 40 : time), at: time,
            collector: scenario == .partial ? "partial" : nil)
    }
}
