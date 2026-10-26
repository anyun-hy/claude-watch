import Foundation

/// Evidence deliberately separates observed traffic from TAG's saved selection.
enum GraphEvidence: String, Sendable, Equatable {
    case confirmed
    case pending
    case mismatch
    case configuration
}

/// One application family owns each PID once; a common hostname never merges
/// different sources or copies the same desktop flow into multiple products.
struct ConnectionGraphScope {
    let processes: [WatchedProcess]
    let flows: [Flow]

    init(product: MonitoredProduct, processes: [WatchedProcess], flows: [Flow]) {
        self.processes = processes.filter { $0.product == product }
        let pids = Set(self.processes.map(\.pid))
        self.flows = flows.filter { pids.contains($0.pid) }
    }
}

/// Keep each product's current sample across navigation. Automatic selection
/// uses an evidenced route; an unrelated loopback service is never its fallback.
struct NetworkGraphSelection: Equatable {
    var product: MonitoredProduct = .claude
    private var selectedIDs: [MonitoredProduct: String] = [:]
    private var manualProducts: Set<MonitoredProduct> = []
    /// This deliberately excludes PID, local port, and controller connection ID.
    /// It is a display-continuity key, not a claim that two TCP connections are one.
    private var recentPathKeys: [MonitoredProduct: String] = [:]

    func selectedFlowID(for product: MonitoredProduct) -> String? { selectedIDs[product] }

    mutating func select(flowID: String, product: MonitoredProduct) {
        self.product = product
        selectedIDs[product] = flowID
        manualProducts.insert(product)
    }

    mutating func reconcile(proxy: ProxySnapshot?, processes: [WatchedProcess], fresh: Bool) {
        // Temporary collection failures must not erase a still-useful selection.
        // The view's existing freshness gate separately prevents stale animation.
        guard fresh, let proxy else { return }
        for product in MonitoredProduct.allCases {
            let owned = ConnectionGraphScope(product: product, processes: processes, flows: proxy.flows)
            let scope = ConnectionGraphScope(product: product, processes: owned.processes, flows: owned.platformFlows)
            let existing = scope.flows.first { $0.id == selectedIDs[product] }
            if let existing, manualProducts.contains(product) {
                recentPathKeys[product] = Self.pathKey(for: existing, in: scope.processes)
                continue
            }
            let candidates = scope.flows.compactMap { flow -> Candidate? in
                let graph = ConnectionGraphProjection(proxy: proxy, processes: scope.processes,
                                                      selectedFlowID: flow.id, fresh: true,
                                                      showConfigurationReference: false)
                let observed: Set<GraphEvidence> = [.confirmed, .mismatch]
                guard ["proxy", "tun"].contains(graph.routePresentation),
                      observed.contains(graph.sourceEdgeState),
                      observed.contains(graph.gatewayEdgeState),
                      observed.contains(graph.nodeEdgeState) else { return nil }
                return Candidate(flow: flow,
                                 rank: graph.nodeEdgeState == .confirmed ? 0 : 1,
                                 pathKey: Self.pathKey(for: flow, in: scope.processes))
            }

            if let existingCandidate = candidates.first(where: { $0.flow.id == existing?.id }) {
                // Keep an equally good live route through list reordering, but move
                // from a stale mismatch to any available confirmed path.
                let bestRank = candidates.map(\.rank).min() ?? existingCandidate.rank
                if existingCandidate.rank == bestRank {
                    recentPathKeys[product] = existingCandidate.pathKey
                    continue
                }
            }
            manualProducts.remove(product)
            let priorPathKey = recentPathKeys[product]
            let next = candidates.sorted {
                if $0.rank != $1.rank { return $0.rank < $1.rank }
                let leftMatches = $0.pathKey == priorPathKey
                let rightMatches = $1.pathKey == priorPathKey
                if leftMatches != rightMatches { return leftMatches }
                return $0.flow.id < $1.flow.id
            }.first
            selectedIDs[product] = next?.flow.id
            if let next { recentPathKeys[product] = next.pathKey }
        }
    }

    private struct Candidate {
        let flow: Flow
        let rank: Int
        let pathKey: String
    }

    private static func pathKey(for flow: Flow, in processes: [WatchedProcess]) -> String {
        let role = processes.first(where: { $0.pid == flow.pid })?.sourceRole
        let roleText: String
        switch role {
        case .cli?: roleText = "cli"
        case .desktop?: roleText = "desktop"
        case .child?: roleText = "child"
        case nil: roleText = "unknown"
        }
        let route = flow.routePath?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
        return [roleText, flow.host, flow.transport.uppercased(), route, flow.chains.joined(separator: "\\u{1F}")]
            .joined(separator: "\\u{1E}")
    }
}

struct ConnectionGraphProjection: Sendable {
    let flow: Flow?
    let sourceKind: String
    let sourcePID: Int?
    let sourceLocal: String
    let gatewayTitle: String
    let gatewayEndpoint: String
    let gatewayDetail: String
    let gatewayState: GraphEvidence
    let groupTitle: String
    let groupState: GraphEvidence
    let nodeTitle: String
    let nodeState: GraphEvidence
    let serviceTitle: String
    let serviceEndpoint: String
    let sourceEdgeState: GraphEvidence
    let gatewayEdgeState: GraphEvidence
    let nodeEdgeState: GraphEvidence
    let targetEdgeState: GraphEvidence
    let routePresentation: String
    let summary: String

    init(proxy: ProxySnapshot?, processes: [WatchedProcess], selectedFlowID: String?, fresh: Bool,
         showConfigurationReference: Bool = true) {
        let selected: Flow?
        if let selectedFlowID, let match = proxy?.flows.first(where: { $0.id == selectedFlowID }) {
            selected = match
        } else {
            selected = nil
        }
        self.flow = selected

        let process = selected.flatMap { flow in
            processes.first(where: { $0.pid == flow.pid })
        }
        let hasCurrentProcess = selected != nil && process != nil
        let sourceUnresolved = process?.sourceRole == .child
        sourcePID = selected?.pid
        sourceLocal = selected?.local.nonEmpty ?? "等待连接"
        switch process?.sourceRole {
        case .cli: sourceKind = "code"
        case .desktop: sourceKind = "desktop"
        case .child: sourceKind = "other"
        case .none: sourceKind = selected == nil ? "none" : "other"
        }

        let endpoint = proxy?.endpoint.nonEmpty ?? "127.0.0.1:7890"
        let entryVerified = proxy?.entryState == "verified"
        let entryAvailable = fresh && entryVerified && (proxy?.coversProxy == true)
        let normalizedRoute = selected?.routePath?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let explicitLocalProxy = normalizedRoute == "local_proxy"
        let peerIsGateway = selected.map { Self.isGatewayPeer($0.peer, endpoint: endpoint) } ?? false
        // The backend emits either the exact local_proxy path or TAG metadata.type Tun.
        // A route label resembling "tun" and a loopback proxy peer are not TUN evidence.
        let explicitTun = normalizedRoute == "tun" && selected.map { !Self.isLoopbackPeer($0.peer) } == true
        let validLocalProxy = explicitLocalProxy && peerIsGateway
        let isLocalService = selected?.association == "local_service"
        if selected == nil {
            routePresentation = "idle"
        } else if isLocalService {
            routePresentation = "localService"
        } else if explicitTun {
            routePresentation = "tun"
        } else if validLocalProxy || peerIsGateway {
            routePresentation = "proxy"
        } else {
            routePresentation = "unresolved"
        }
        let correlatedMatch = selected?.association == "correlated" && selected?.policy == "match"
        let correlatedMismatch = selected?.association == "correlated" && selected?.policy == "mismatch"
        let observedFlowState: GraphEvidence = fresh && hasCurrentProcess && correlatedMismatch ? .mismatch : (fresh && hasCurrentProcess && correlatedMatch ? .confirmed : .pending)
        let pathState: GraphEvidence
        if explicitTun {
            pathState = observedFlowState
            gatewayTitle = "TUN 通道"
            gatewayEndpoint = selected?.interfaceName?.nonEmpty ?? "接口待确认"
            gatewayState = observedFlowState == .mismatch ? .confirmed : observedFlowState
            gatewayDetail = "TUN 接入按连接身份核对；分组和末端节点另行显示核对结果。"
        } else if isLocalService {
            gatewayTitle = "本机服务"
            gatewayEndpoint = selected?.peer.nonEmpty ?? "本机端点待确认"
            gatewayState = .pending
            gatewayDetail = selected?.reason.nonEmpty ?? "此连接由本机服务处理，未作为代理链。"
            pathState = .pending
        } else if selected == nil && !showConfigurationReference {
            gatewayTitle = "接入方式待确认"
            gatewayEndpoint = "—"
            gatewayState = .pending
            gatewayDetail = "尚无当前关联路径；没有从配置中推断 HTTP 代理或 TUN 接入。"
            pathState = .pending
        } else if selected == nil || peerIsGateway {
            gatewayTitle = "7890 本机入口"
            gatewayEndpoint = endpoint
            gatewayState = fresh && entryVerified ? .confirmed : .pending
            gatewayDetail = entryAvailable
                ? "监听身份与代理覆盖已确认"
                : (proxy?.entryReason.nonEmpty ?? "等待本机入口采样")
            // A local_proxy label alone is insufficient: it must actually point at
            // the verified loopback listener and be covered by the proxy policy.
            pathState = validLocalProxy && entryAvailable ? observedFlowState : .pending
        } else {
            gatewayTitle = "路径待关联"
            gatewayEndpoint = selected?.interfaceName?.nonEmpty.map { "\($0)（仅参考）" } ?? "入口待确认"
            gatewayState = .pending
            gatewayDetail = "未获得可关联的代理或 TUN 路径证据"
            pathState = .pending
        }

        let actualGroup = selected.flatMap { flow in
            flow.chains.dropLast().first?.nonEmpty
        }
        groupTitle = actualGroup ?? (showConfigurationReference ? proxy?.expectedGroup.nonEmpty : nil)
            ?? (showConfigurationReference ? "TAG 分组" : "分组待确认")
        groupState = actualGroup == nil ? (showConfigurationReference ? .configuration : .pending) : pathState

        let actualNode = selected?.chains.last?.nonEmpty
        nodeTitle = actualNode ?? (showConfigurationReference ? proxy?.currentNode.nonEmpty ?? proxy?.expectedNode.nonEmpty : nil)
            ?? (showConfigurationReference ? "代理节点" : "节点待确认")
        nodeState = actualNode == nil ? (showConfigurationReference ? .configuration : .pending) : pathState

        let host = selected?.host.nonEmpty
        let hostIsGateway = host.map { Self.isGatewayPeer($0, endpoint: endpoint) } ?? false
        let hasTarget = host != nil && !hostIsGateway
        serviceTitle = hasTarget ? host! : "目标服务待确认"
        serviceEndpoint = hasTarget && !peerIsGateway
            ? (selected?.peer.nonEmpty ?? "目标 IP 待确认")
            : "目标 IP 待确认"

        sourceEdgeState = selected == nil || sourceUnresolved ? .pending : pathState
        if explicitTun {
            gatewayEdgeState = pathState
        } else if validLocalProxy {
            gatewayEdgeState = pathState
        } else {
            gatewayEdgeState = .pending
        }
        nodeEdgeState = (actualNode != nil && (explicitTun || validLocalProxy)) ? pathState : .pending
        targetEdgeState = hasTarget && (explicitTun || validLocalProxy) ? pathState : .pending

        if !fresh {
            summary = proxy == nil ? "尚无有效网络快照，等待后台更新。" : "路径来自保存的完整样本，仅供回看，不表示连接仍存在。"
        } else if selected != nil && !hasCurrentProcess {
            summary = "该进程样本已结束或不在当前监控列表中，等待下一次刷新。"
        } else if sourceUnresolved {
            summary = "此 PID 的桌面应用或独立 CLI 来源待确认。代理链证据单独核对。"
        } else if selected == nil {
            if !showConfigurationReference && proxy?.flows.isEmpty == false {
                summary = "当前没有可确认的代理路径；本机服务和待确认连接可在明细中查看。"
            } else {
                summary = proxy?.flows.isEmpty == false
                    ? "存在多个连接样本，请选择一条连接以查看路径。"
                    : "暂无受监控应用的连接样本；7890 监听状态可独立显示。"
            }
        } else if correlatedMismatch && pathState == .mismatch {
            summary = "该连接与预期路径不一致，需要核对实际代理链。"
        } else if validLocalProxy && correlatedMatch && entryAvailable {
            summary = "已确认此样本经 7890 入口；节点和目标以本次采样为准。"
        } else if explicitTun {
            summary = correlatedMatch ? "已核对这条连接的 TUN 接入与代理链；目标地址按本轮证据展示。" :
                "存在 TUN 记录，但连接关联证据尚不完整。"
        } else {
            summary = "连接证据尚不完整；TAG 当前选择仅作为配置参考。"
        }
    }

    /// Moving particles are reserved for a currently selected, platform-owned
    /// route with every displayed hop evidenced by this sample. Configuration,
    /// components, and incomplete paths remain visible but static.
    var supportsPathAnimation: Bool {
        guard flow != nil else { return false }
        let observed: Set<GraphEvidence> = [.confirmed, .mismatch]
        return observed.contains(sourceEdgeState)
            && observed.contains(gatewayEdgeState)
            && observed.contains(nodeEdgeState)
            && observed.contains(targetEdgeState)
    }

    private static func isGatewayPeer(_ peer: String, endpoint: String) -> Bool {
        let endpointPort = endpoint.split(separator: ":").last.map(String.init)
        guard let endpointPort, !endpointPort.isEmpty else { return false }
        return peer.hasSuffix(":" + endpointPort) &&
            (peer.hasPrefix("127.0.0.1:") || peer.hasPrefix("[::1]:") || peer.hasPrefix("localhost:"))
    }

    private static func isLoopbackPeer(_ peer: String) -> Bool {
        let host: String
        if peer.hasPrefix("[") {
            host = peer.split(separator: "]", maxSplits: 1).first.map { String($0.dropFirst()) } ?? ""
        } else {
            host = peer.split(separator: ":", maxSplits: 1).first.map(String.init) ?? peer
        }
        let normalized = host.lowercased()
        return normalized == "localhost" || normalized == "::1" || normalized.hasPrefix("127.")
    }
}

private extension String {
    var nonEmpty: String? {
        let trimmed = trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
