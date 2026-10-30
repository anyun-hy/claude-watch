import Foundation

enum GraphDisplayPhase: String, Sendable {
    case waiting, live, noSample, unassociated, partial, failed, expired, stopped, contextChanged, paused
}

/// A single immutable route observation. Never fed back into a current snapshot
/// or any launch/protection evaluator.
struct GraphPathSample: Sendable {
    let proxy: ProxySnapshot
    let processes: [WatchedProcess]
    let flowID: String
    let product: MonitoredProduct
    let observedAt: Double
    let roundID: String
    let networkKey: String
    let sourceStarted: String
    let egressIP: String?
    var egressObservedAt: Double? = nil
    var reference: ServerReference? = nil
    var referenceCapturedAt: Double? = nil
    var flow: Flow? { proxy.flows.first { $0.id == flowID } }
}

struct GraphDisplayState: Sendable {
    let phase: GraphDisplayPhase
    let title, detail: String
    let currentProxy: ProxySnapshot?
    let currentProcesses: [WatchedProcess]
    let currentFlows: [Flow]
    let sample: GraphPathSample?
    let archivedSample: GraphPathSample?
    let isHistorical: Bool
    let countsAvailable: Bool
    var safetyBlocked = false
    var sampledAt: Double? { sample?.observedAt ?? currentProxy?.observedAt }
    var projection: ConnectionGraphProjection {
        if let sample {
            return ConnectionGraphProjection(proxy: sample.proxy, processes: sample.processes,
                selectedFlowID: sample.flowID, fresh: !isHistorical && phase == .live,
                showConfigurationReference: false)
        }
        return ConnectionGraphProjection(proxy: nil, processes: currentProcesses,
            selectedFlowID: nil, fresh: false, showConfigurationReference: false)
    }
    var canAnimate: Bool {
        phase == .live && !isHistorical && !safetyBlocked && projection.supportsPathAnimation
    }
    /// Resolve each source against its own flow in the same complete round.
    /// The common downstream canvas still describes the selected flow, so an
    /// additional source may join it only when the evidenced route is the same.
    func sourceProjection(_ role: ProcessSourceRole) -> ConnectionGraphProjection? {
        let selected = projection
        let expectedKind = role == .cli ? "code" : role == .desktop ? "desktop" : "other"
        if selected.sourceKind == expectedKind, selected.flow != nil { return selected }
        guard role != .child, phase == .live, !isHistorical, !safetyBlocked,
              let sample, let proxy = currentProxy,
              proxy.observedAt == sample.observedAt,
              proxy.connectionObservationIsComplete,
              proxy.connectionObservation?.roundID == sample.roundID,
              let selectedFlow = selected.flow else { return nil }
        let scope = ConnectionGraphScope(product: sample.product, processes: currentProcesses, flows: currentFlows)
        for candidate in scope.platformFlows.sorted(by: { $0.id < $1.id }) {
            guard scope.processes.first(where: { $0.pid == candidate.pid })?.sourceRole == role,
                  candidate.chains == selectedFlow.chains else { continue }
            let route = ConnectionGraphProjection(proxy: proxy, processes: scope.processes,
                selectedFlowID: candidate.id, fresh: true, showConfigurationReference: false)
            guard route.supportsPathAnimation,
                  route.routePresentation == selected.routePresentation,
                  route.gatewayEndpoint == selected.gatewayEndpoint,
                  route.sourceEdgeState == selected.sourceEdgeState else { continue }
            return route
        }
        return nil
    }
    var platformFlowCount: Int? {
        guard countsAvailable else { return nil }
        return ConnectionGraphScope(product: sample?.product ?? currentProcesses.first?.product ?? .claude,
            processes: currentProcesses, flows: currentFlows).platformFlows.count
    }
}

/// At most one recent and one retired route per product. Historical observations
/// have no expiry extension: their original time and source identity never change.
struct GraphContinuityStore {
    private var recent: [MonitoredProduct: GraphPathSample] = [:]
    private var retired: [MonitoredProduct: GraphPathSample] = [:]
    private var minimumObservation: [MonitoredProduct: Double] = [:]

    private static func networkKey(_ proxy: ProxySnapshot) -> String? {
        guard proxy.entryState == "verified", proxy.apiState == "available",
              let pid = proxy.listenerPID, let started = proxy.listenerStarted, !started.isEmpty,
              !proxy.endpoint.isEmpty, !proxy.mode.isEmpty, !proxy.currentNode.isEmpty else { return nil }
        return [proxy.endpoint, String(pid), started, proxy.listenerPath, proxy.mode,
                proxy.currentNode, proxy.expectedGroup, proxy.expectedNode].joined(separator: "\u{1F}")
    }

    private static func snapshotCurrent(_ snapshot: MonitorSnapshot, now: Double) -> Bool {
        let elapsed = now - snapshot.capturedAt
        return MonitorSnapshotTiming.isCurrent(capturedAt: snapshot.capturedAt, now: now)
            && snapshot.health.state == "running" && (snapshot.health.heartbeatAge ?? 99) + elapsed <= 30
    }
    private static func proxyCurrent(_ proxy: ProxySnapshot, now: Double) -> Bool {
        let age = now - proxy.observedAt
        return age >= 0 && age <= 30
    }
    private static func covers(_ snapshot: MonitorSnapshot, product: MonitoredProduct) -> Bool {
        product.covered(by: snapshot.monitoredApps ?? [])
    }

    private func contextChanged(_ old: GraphPathSample, snapshot: MonitorSnapshot, product: MonitoredProduct,
                                now: Double, egressIP: String?, egressObservedAt: Double? = nil) -> Bool {
        // Missing observations are not proof that the network changed.
        if let newIP = egressIP, let oldIP = old.egressIP, newIP != oldIP,
           let at = egressObservedAt, at > (old.egressObservedAt ?? -.infinity), at <= now { return true }
        if let proxy = snapshot.proxy, proxy.observedAt >= old.observedAt, Self.proxyCurrent(proxy, now: now),
           let key = Self.networkKey(proxy), key != old.networkKey {
            return true
        }
        guard Self.snapshotCurrent(snapshot, now: now), snapshot.proxy?.connectionObservationIsComplete == true,
              (snapshot.proxy?.observedAt ?? 0) >= old.observedAt else { return false }
        guard let flow = old.flow else { return true }
        return !snapshot.processes.contains { $0.product == product && $0.pid == flow.pid && $0.started == old.sourceStarted }
    }

    mutating func observe(snapshot: MonitorSnapshot?, selection: NetworkGraphSelection, now: Double,
                          error: String?, automatic: Bool, claudeEgressIP: String? = nil,
                          egressObservedAt: Double? = nil, safetyBlocked: Bool = false,
                          references: [String: ServerReference] = [:]) {
        // A positively observed context change is latched. A later missing
        // snapshot must not bring the old network back into the main canvas.
        if let snapshot {
            for product in MonitoredProduct.allCases {
                guard let old = recent[product] else { continue }
                let ip = product == .claude ? claudeEgressIP : nil
                if contextChanged(old, snapshot: snapshot, product: product, now: now, egressIP: ip,
                                  egressObservedAt: product == .claude ? egressObservedAt : nil)
                    || (product == .claude && safetyBlocked) {
                    retired[product] = old
                    recent.removeValue(forKey: product)
                    if let ip, let oldIP = old.egressIP, ip != oldIP {
                        minimumObservation[product] = egressObservedAt ?? now
                    }
                }
            }
        }
        guard automatic, error == nil, let snapshot, Self.snapshotCurrent(snapshot, now: now),
              snapshot.proxyError == nil, let proxy = snapshot.proxy, Self.proxyCurrent(proxy, now: now),
              let observation = proxy.connectionObservation, proxy.connectionObservationIsComplete,
              let key = Self.networkKey(proxy) else { return }
        for product in MonitoredProduct.allCases where Self.covers(snapshot, product: product) {
            if let minimum = minimumObservation[product], proxy.observedAt < minimum { continue }
            let ip = product == .claude ? claudeEgressIP : nil
            let scope = ConnectionGraphScope(product: product, processes: snapshot.processes, flows: proxy.flows)
            guard let id = selection.selectedFlowID(for: product),
                  let flow = scope.platformFlows.first(where: { $0.id == id }),
                  let owner = scope.processes.first(where: { $0.pid == flow.pid }), !owner.started.isEmpty else { continue }
            let scopedProxy = proxy.retainingFlows([flow])
            let projection = ConnectionGraphProjection(proxy: scopedProxy, processes: scope.processes,
                selectedFlowID: id, fresh: true, showConfigurationReference: false)
            guard projection.supportsPathAnimation else { continue }
            if product == .claude && safetyBlocked { continue }
            if let old = recent[product] {
                guard proxy.observedAt >= old.observedAt else { continue }
                if let ip, let oldIP = old.egressIP, ip != oldIP,
                   let changedAt = egressObservedAt, proxy.observedAt < changedAt { continue }
                if contextChanged(old, snapshot: snapshot, product: product, now: now, egressIP: ip,
                                  egressObservedAt: product == .claude ? egressObservedAt : nil) {
                    retired[product] = old
                }
            }
            let reference = ServerReferenceRequest(flow: flow).flatMap { request in
                references[request.key].flatMap { $0.applies(to: request, now: now) ? $0 : nil }
            }
            recent[product] = GraphPathSample(proxy: scopedProxy, processes: scope.processes, flowID: id,
                product: product, observedAt: proxy.observedAt, roundID: observation.roundID,
                networkKey: key, sourceStarted: owner.started, egressIP: ip,
                egressObservedAt: product == .claude ? egressObservedAt : nil,
                reference: reference, referenceCapturedAt: reference == nil ? nil : now)
        }
    }

    func display(product: MonitoredProduct, snapshot: MonitorSnapshot?, selection: NetworkGraphSelection,
                 now: Double, error: String?, automatic: Bool, claudeEgressIP: String? = nil,
                 egressObservedAt: Double? = nil, safetyBlocked: Bool = false) -> GraphDisplayState {
        let old = recent[product]
        let processes = (snapshot?.processes ?? []).filter { $0.product == product }
        let changed: Bool
        if let old, let snapshot {
            changed = contextChanged(old, snapshot: snapshot, product: product, now: now,
                egressIP: product == .claude ? claudeEgressIP : nil,
                egressObservedAt: product == .claude ? egressObservedAt : nil)
        } else { changed = false }
        let contextRetired = (old != nil && changed) || (old == nil && retired[product] != nil)
        let blocked = product == .claude && safetyBlocked
        let history = contextRetired || blocked ? nil : old
        let archive = contextRetired || blocked ? old ?? retired[product] : retired[product]
        func result(_ phase: GraphDisplayPhase, _ title: String, _ detail: String,
                    proxy: ProxySnapshot? = nil, flows: [Flow] = [], count: Bool = false,
                    liveSample: GraphPathSample? = nil, stop: Bool = false) -> GraphDisplayState {
            let historical = liveSample == nil && !stop ? history : nil
            return GraphDisplayState(phase: phase, title: title, detail: detail, currentProxy: proxy,
                currentProcesses: processes, currentFlows: flows, sample: liveSample ?? historical,
                archivedSample: stop ? old ?? archive : archive, isHistorical: historical != nil,
                countsAvailable: count, safetyBlocked: blocked)
        }
        guard automatic else { return result(.paused, "自动刷新已暂停", "最近路径仅供回看；后台保护独立继续运行。") }
        if let error { return result(.failed, "采样失败", error) }
        guard let snapshot else { return result(.waiting, "等待首次采样", "尚无当前连接证据。") }
        guard MonitorSnapshotTiming.isCurrent(capturedAt: snapshot.capturedAt, now: now) else {
            return result(.expired, "界面样本已过期", "未能取得新鲜读取结果；当前计数不可确认。")
        }
        guard snapshot.health.state == "running" else {
            return result(.failed, "后台采样未就绪", snapshot.health.detail)
        }
        guard (snapshot.health.heartbeatAge ?? 99) + now - snapshot.capturedAt <= 30 else {
            return result(.expired, "后台心跳已过期", "当前采集状态不可确认，最近路径仅供回看。")
        }
        guard Self.covers(snapshot, product: product) else {
            return result(.waiting, "采集范围未确认", "当前后台尚未明确覆盖所选应用。")
        }
        if let message = snapshot.proxyError { return result(.failed, "连接采样不可用", message) }
        guard let proxy = snapshot.proxy else { return result(.waiting, "等待连接采样", "尚未取得可用的代理连接回执。") }
        guard Self.proxyCurrent(proxy, now: now) else { return result(.expired, "连接样本已过期", "显示最近记录，不代表当前连接仍存在。") }
        if let old, proxy.observedAt < old.observedAt {
            return result(.partial, "收到较旧的连接样本", "保留最近一次完整记录；较旧结果不会覆盖它。")
        }
        guard let observation = proxy.connectionObservation else {
            return result(.partial, "采集状态未提供", "后台没有提供采集完整性回执，不能把空数组解释为 0 条连接。")
        }
        guard proxy.connectionObservationIsComplete else {
            let failed = observation.collectorState == "failed"
            return result(failed ? .failed : .partial, failed ? "连接采样失败" : "连接采样不完整",
                observation.detail.isEmpty ? "当前证据不完整，计数不可确认。" : observation.detail)
        }
        if processes.isEmpty { return result(.stopped, "应用未运行", "本轮完整进程采样未发现所选应用；旧路径仅在历史中保留。", proxy: proxy, count: true, stop: true) }
        let scope = ConnectionGraphScope(product: product, processes: processes, flows: proxy.flows)
        let selected = selection.selectedFlowID(for: product)
        if let id = selected, let flow = scope.platformFlows.first(where: { $0.id == id }),
           let owner = processes.first(where: { $0.pid == flow.pid }), let key = Self.networkKey(proxy) {
            let scopedProxy = proxy.retainingFlows([flow])
            let projection = ConnectionGraphProjection(proxy: scopedProxy, processes: processes, selectedFlowID: id,
                fresh: true, showConfigurationReference: false)
            if projection.supportsPathAnimation && !contextRetired && !blocked {
                let sample = GraphPathSample(proxy: scopedProxy, processes: processes, flowID: id, product: product,
                    observedAt: proxy.observedAt, roundID: observation.roundID, networkKey: key,
                    sourceStarted: owner.started, egressIP: product == .claude ? claudeEgressIP : nil,
                    egressObservedAt: product == .claude ? egressObservedAt : nil)
                return result(.live, "本轮路径已关联", "线条表示本轮已观测路径，不代表持续传输或安全检查全部通过。",
                              proxy: proxy, flows: scope.flows, count: true, liveSample: sample)
            }
        }
        if contextRetired || blocked {
            return result(.contextChanged, blocked ? "会话保护已触发" : "路径上下文已变化",
                "旧路径已移入历史；等待属于当前应用与网络的新证据。", proxy: proxy, flows: scope.flows, count: true, stop: true)
        }
        let unconfirmed = scope.flows.contains { $0.association == "unconfirmed" }
        if unconfirmed || !scope.platformFlows.isEmpty {
            return result(.unassociated, "连接路径待关联", "已观测到连接，但尚无完整平台路径；最近路径仅为历史。",
                          proxy: proxy, flows: scope.flows, count: true)
        }
        return result(.noSample, "本轮未观测到平台连接", "保留最近路径并停止动画；这不表示应用断线或退出登录。",
                      proxy: proxy, flows: scope.flows, count: true)
    }

}
