import Foundation

enum ConnectionPurpose: String, CaseIterable, Identifiable, Hashable {
    case platform, mcp, local, component, unidentified
    var id: String { rawValue }
    var title: String {
        switch self {
        case .platform: return "AI 平台服务"
        case .mcp: return "MCP 工具通信"
        case .local: return "本地通信"
        case .component: return "Chromium 与应用组件"
        case .unidentified: return "其他应用流量"
        }
    }
    var symbol: String {
        switch self {
        case .platform: return "globe"
        case .mcp: return "puzzlepiece.extension"
        case .local: return "desktopcomputer"
        case .component: return "square.stack.3d.up"
        case .unidentified: return "network"
        }
    }
}

struct ConnectionServiceGroup: Identifiable {
    let id, name: String
    let purpose: ConnectionPurpose
    let flows: [Flow]
    var representative: Flow { flows.sorted {
        let left = $0.association == "correlated" ? ($0.policy == "match" ? 0 : 1) : 2
        let right = $1.association == "correlated" ? ($1.policy == "match" ? 0 : 1) : 2
        return left == right ? $0.id < $1.id : left < right
    }[0] }
    var routes: [String] { Array(Set(flows.filter { !$0.chains.isEmpty }.map { $0.chains.joined(separator: " → ") })).sorted() }
    var endpoints: [String] { Array(Set(flows.map(\.host))).sorted() }
    var status: String {
        if purpose == .local { return "本机通信" }
        if flows.contains(where: { $0.policy == "mismatch" }) { return "路径差异" }
        if flows.allSatisfy({ $0.association == "correlated" && $0.policy == "match" }) { return "样本匹配" }
        if purpose == .platform { return "代理链未关联" }
        if purpose == .component { return "组件已识别" }
        if purpose == .mcp { return "工具已识别" }
        return "用途未识别"
    }
    var note: String {
        switch purpose {
        case .platform: return "已识别平台域名；路由结论只适用于当前连接样本。"
        case .mcp: return "来自已匹配 MCP 配置入口的工具进程；保留网络证据，不混入平台连接统计。"
        case .local: return "本机回环通信，不参与外网代理链判定；不因此认定为可信 MCP。"
        case .component: return "已识别应用组件；TUN 地址或其他未关联目标不会被当成已验证的平台出口。"
        case .unidentified: return "当前证据不足以识别用途，保留地址和原始记录，不显示安全结论。"
        }
    }
}

enum ConnectionInventory {
    static func host(_ value: String) -> String {
        let source = value.contains("://") ? value : "https://" + value
        return (URLComponents(string: source)?.host ?? value).lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "[]."))
    }
    static func loopback(_ endpoint: String) -> Bool {
        let value = host(endpoint)
        let bytes = value.split(separator: ".").compactMap { Int($0) }
        return value == "::1" || value == "localhost"
            || (bytes.count == 4 && bytes[0] == 127 && bytes.allSatisfy { (0...255).contains($0) })
    }
    static func purpose(_ flow: Flow, process: WatchedProcess?, proxyEndpoint: String = "127.0.0.1:7890") -> ConnectionPurpose {
        if process?.runtimeRole == "mcp", ["configured_mcp_entry", "configured_mcp_descendant"].contains(process?.roleEvidence ?? "") { return .mcp }
        let gateway = host(flow.peer) == host(proxyEndpoint)
            && URLComponents(string: "http://" + flow.peer)?.port == URLComponents(string: proxyEndpoint.contains("://") ? proxyEndpoint : "http://" + proxyEndpoint)?.port
        if flow.association == "local_service" || (loopback(flow.peer) && !gateway) { return .local }
        let domain = host(flow.host)
        let domains = process?.product == .claude ? ["anthropic.com", "claude.ai"] : ["openai.com", "chatgpt.com", "oaiusercontent.com"]
        if domains.contains(where: { domain == $0 || domain.hasSuffix("." + $0) }) { return .platform }
        // The helper process name establishes ownership, not request purpose.
        // A missing host or a raw socket IP remains unidentified.
        let addressLike = domain.isEmpty || domain.contains(":") || domain.split(separator: ".").allSatisfy { Int($0) != nil }
        if !addressLike && (process?.runtimeRole?.hasPrefix("chromium_") == true || process?.kind.contains("desktop-helper") == true) { return .component }
        return .unidentified
    }
    static func groups(product: MonitoredProduct, processes: [WatchedProcess], flows: [Flow], proxyEndpoint: String = "127.0.0.1:7890") -> [ConnectionServiceGroup] {
        let owned = processes.filter { $0.product == product }
        let byPID = Dictionary(owned.map { ($0.pid, $0) }, uniquingKeysWith: { first, _ in first })
        var buckets: [String: [Flow]] = [:]
        var labels: [String: (ConnectionPurpose, String)] = [:]
        for flow in flows {
            guard let process = byPID[flow.pid] else { continue }
            let purpose = purpose(flow, process: process, proxyEndpoint: proxyEndpoint)
            let name: String
            switch purpose {
            case .platform: name = host(flow.host)
            case .mcp: name = process.serviceName ?? "MCP 工具"
            case .local: name = "本地服务与 IPC"
            case .component: name = process.componentName
            case .unidentified: name = "用途未识别的应用连接"
            }
            // No PID, temporary source port, socket ID or ordering in this key.
            let key = [product.rawValue, purpose.rawValue, name].joined(separator: "|")
            buckets[key, default: []].append(flow); labels[key] = (purpose, name)
        }
        return buckets.map { key, members in
            ConnectionServiceGroup(id: key, name: labels[key]!.1, purpose: labels[key]!.0, flows: members)
        }.sorted {
            let order = ConnectionPurpose.allCases
            let left = order.firstIndex(of: $0.purpose)!, right = order.firstIndex(of: $1.purpose)!
            return left == right ? $0.name.localizedStandardCompare($1.name) == .orderedAscending : left < right
        }
    }
}

extension WatchedProcess {
    var componentName: String {
        if runtimeRole == "mcp" { return "MCP · " + (serviceName ?? "工具服务") }
        switch runtimeRole {
        case "chromium_network": return "Chromium 网络服务"
        case "chromium_renderer": return "Chromium 渲染器"
        case "chromium_gpu": return "Chromium GPU 组件"
        case "chromium_crashpad": return "Chromium 崩溃报告"
        default: return name
        }
    }
    var componentKey: String { [product.rawValue, sourceDisplay, runtimeRole ?? kind, runtimeRole == "mcp" ? serviceName ?? "" : ""].joined(separator: "|") }
}

extension ConnectionGraphScope {
    var platformFlows: [Flow] {
        let owners = Dictionary(processes.map { ($0.pid, $0) }, uniquingKeysWith: { first, _ in first })
        return flows.filter { ConnectionInventory.purpose($0, process: owners[$0.pid]) == .platform }
    }
}
