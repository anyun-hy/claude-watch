import AppKit
import SwiftUI

private enum GraphNodeID: String {
    case code, desktop, managed, gateway, tag, node, service
}

/// The illustration is a native projection of one existing sample.
struct ConnectionGraphView: View {
    @ObservedObject var store: MonitorStore
    let p: Palette
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var selectedNode: GraphNodeID = .gateway
    @State private var expandedNode: GraphNodeID?

    private var selectedProduct: MonitoredProduct { store.networkSelection.product }
    private var display: GraphDisplayState { store.graphDisplay(for: selectedProduct) }
    /// The canvas is always built from one sample.  A historical canvas never
    /// borrows the current proxy, processes, or configuration.
    private var sample: GraphPathSample? { display.sample }
    private var processes: [WatchedProcess] { sample?.processes ?? display.currentProcesses }
    private var currentScope: ConnectionGraphScope {
        ConnectionGraphScope(product: selectedProduct, processes: display.currentProcesses, flows: display.currentFlows)
    }
    private var flows: [Flow] { currentScope.platformFlows }
    private var serviceGroups: [ConnectionServiceGroup] {
        ConnectionInventory.groups(product: selectedProduct, processes: display.currentProcesses,
                                   flows: display.currentFlows, proxyEndpoint: display.currentProxy?.endpoint ?? "127.0.0.1:7890")
    }
    private var backendCoversSelectedProduct: Bool {
        guard let apps = store.snapshot?.monitoredApps else { return false }
        return selectedProduct.covered(by: apps)
    }
    private var backendCoverageKnown: Bool { store.snapshot?.monitoredApps?.isEmpty == false }
    private var proxy: ProxySnapshot? { sample?.proxy }
    private var graph: ConnectionGraphProjection { display.projection }
    private var codeGraph: ConnectionGraphProjection? { display.sourceProjection(.cli) }
    private var desktopGraph: ConnectionGraphProjection? { display.sourceProjection(.desktop) }
    private var managedGraph: ConnectionGraphProjection? { display.sourceProjection(.managed) }
    private var codeSelected: Bool { codeGraph != nil }
    private var desktopSelected: Bool { desktopGraph != nil }
    private var managedProcess: WatchedProcess? { processes.first(where: { $0.sourceRole == .managed }) }
    private var hasManaged: Bool { selectedProduct == .openAI && managedProcess != nil }
    private var codeProcess: WatchedProcess? {
        processes.first(where: { $0.sourceRole == .cli })
    }
    private var desktopProcess: WatchedProcess? {
        if selectedProduct == .openAI {
            return processes.first(where: { $0.kind.hasSuffix("desktop-main") })
                ?? processes.first(where: { $0.sourceRole == .desktop })
        }
        return processes.first(where: { $0.sourceRole == .desktop })
            ?? processes.first(where: { $0.sourceRole == .child })
    }
    private var codeTitle: String { selectedProduct.graphCLITitle }
    private var gatewayIsTun: Bool { graph.gatewayTitle.localizedCaseInsensitiveContains("TUN") }
    private var gatewayIsProxy: Bool { graph.routePresentation == "proxy" }
    private var shouldAnimate: Bool {
        display.canAnimate && !reduceMotion
    }
    private var serverTarget: ServerTargetPresentation {
        ServerTargetPresentation(product: selectedProduct, flow: graph.flow,
            reference: display.isHistorical ? sample?.reference : store.reference(for: graph.flow),
            now: display.isHistorical ? (sample?.referenceCapturedAt ?? sample?.observedAt ?? 0) : store.now.timeIntervalSince1970,
            historical: display.isHistorical)
    }
    private var countText: String {
        guard display.countsAvailable, let count = display.platformFlowCount else { return "平台连接 —" }
        return "\(count) 条平台连接"
    }
    private var statusColor: Color {
        switch display.phase {
        case .failed, .partial, .expired: return p.amber
        case .live: return p.mint
        case _ where display.isHistorical: return p.blue
        default: return p.secondary
        }
    }
    private var needsAttention: Bool { [.failed, .partial, .expired].contains(display.phase) }
    private var sampleText: String {
        guard let sampledAt = display.sampledAt else { return display.detail }
        return (display.isHistorical ? "上次记录 " : "采样 ") + timeText(sampledAt)
    }
    private func historicalTitle(_ current: String) -> String { display.isHistorical ? "上次 " + current : current }

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 8) {
                HStack(alignment: .center, spacing: 12) {
                    HStack(spacing: 9) {
                        Image(systemName: "point.3.connected.trianglepath.dotted")
                            .font(.system(size: 17)).foregroundStyle(p.mint)
                        Text("连接全景").font(WatchTypography.section)
                    }
                    Spacer()
                    Badge(text: display.title, color: statusColor)
                }
                HStack(spacing: 12) {
                    Picker("应用", selection: $store.networkSelection.product) {
                        ForEach(MonitoredProduct.allCases) { product in Text(product.title).tag(product) }
                    }.labelsHidden().pickerStyle(.segmented).frame(width: 252)
                        .onChange(of: selectedProduct) {
                            store.synchronizeNetworkSelection(); expandedNode = nil
                            if selectedNode == .managed && selectedProduct != .openAI { selectedNode = .gateway }
                        }
                    let platform = serviceGroups.filter { $0.purpose == .platform }
                    if display.countsAvailable, !platform.isEmpty {
                        Menu {
                            ForEach(platform) { group in
                                Button(group.name) { store.selectNetworkFlow(group.representative, product: selectedProduct) }
                            }
                        } label: {
                            Text("平台服务 \(platform.count) 项").font(WatchTypography.caption)
                        }.menuStyle(.borderlessButton).frame(maxWidth: 148)
                    }
                    Spacer(minLength: 0)
                    HStack(spacing: 8) {
                        GraphLaunchButton(product: selectedProduct, monitor: store, switcher: store.switcher,
                                          processControl: store.processControl, p: p)
                        AIProcessCloseButton(product: selectedProduct, store: store, control: store.processControl,
                                             switcher: store.switcher, p: p)
                            .id(selectedProduct)
                    }
                }
                HStack(spacing: 10) {
                    Text(display.detail)
                        .foregroundStyle(needsAttention ? p.amber : p.secondary)
                        .lineLimit(2).fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 8)
                    if !backendCoversSelectedProduct && backendCoverageKnown {
                        Text("采集器暂未覆盖此应用").foregroundStyle(p.amber)
                    }
                    VStack(alignment: .trailing, spacing: 3) {
                        Text(sampleText).lineLimit(1)
                        Text(countText).lineLimit(1)
                    }.foregroundStyle(p.secondary)
                }.font(WatchTypography.small).frame(height: 34)
            }.padding(.horizontal, 23).padding(.top, 17).padding(.bottom, 7)

            protectionSummary

            ViewThatFits(in: .horizontal) {
                wideScene.frame(minWidth: 900)
                compactScene
            }

            HStack(spacing: 22) {
                legend(.confirmed, "已确认")
                legend(.pending, "路径未关联 / 参考路径")
                legend(.mismatch, "路径差异")
                legend(.configuration, "配置参考")
                Spacer(minLength: 12)
                Text("点击节点查看证据").font(WatchTypography.small).foregroundStyle(p.secondary)
            }.padding(.horizontal, 24).padding(.top, 2).padding(.bottom, 12)

            if expandedNode != nil {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: "info.circle").font(.system(size: 15)).foregroundStyle(p.blue).padding(.top, 2)
                    VStack(alignment: .leading, spacing: 6) {
                        Text(detailTitle).font(WatchTypography.bodyStrong)
                        Text(detailText).font(WatchTypography.caption).foregroundStyle(p.secondary)
                            .lineSpacing(4).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                    }
                    Spacer(minLength: 0)
                    Button { expandedNode = nil } label: {
                        Image(systemName: "xmark.circle.fill").font(.system(size: 14)).foregroundStyle(p.secondary)
                    }.buttonStyle(.plain).help("收起详情")
                }.padding(.horizontal, 19).padding(.vertical, 11)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(p.elevated.opacity(0.65))
            }
            if let archived = display.archivedSample {
                archivedPath(archived)
            }
        }
        .background {
            ZStack {
                p.graphBackground
                RadialGradient(colors: [p.blue.opacity(p.dark ? 0.09 : 0.04), .clear],
                               center: .init(x: 0.55, y: 0.47), startRadius: 10, endRadius: 370)
            }
        }
        .clipShape(RoundedRectangle(cornerRadius: 20))
        .overlay(RoundedRectangle(cornerRadius: 20).strokeBorder(p.border, lineWidth: 1))
        .onAppear { store.synchronizeNetworkSelection() }
    }

    private var protectionSummary: some View {
        let text: String
        let symbol: String
        let tint: Color
        if let channelState = store.channelState(for: selectedProduct) {
            let disposition = channelState.process_preserved ? "断流保进程" : "传统退出"
            text = "通道状态：\(channelState.display_label_zh)（\(disposition)） · \(channelState.policy_sync_label_zh) · 活动连接 \(channelState.active_flows_count) / 已断开 \(channelState.terminated_flows_count) / 拒新连接 \(channelState.blocked_new_connections)"
            switch channelState.display_state {
            case .forwarding:
                symbol = "checkmark.shield.fill"; tint = p.mint
            case .disconnecting:
                symbol = "arrow.triangle.2.circlepath.circle.fill"; tint = p.amber
            case .blocked:
                symbol = "nosign"; tint = p.red
            case .failed:
                symbol = "exclamationmark.triangle.fill"; tint = p.red
            case .pendingVerification:
                symbol = "clock.badge.questionmark"; tint = p.secondary
            }
        } else if selectedProduct == .openAI {
            text = "ChatGPT / Codex 通道状态待同步；当前连接图保持独立判断。"
            symbol = "network"; tint = p.secondary
        } else if let evidence = store.switcher.sessionDisplayEvidence {
            let value = evidence.presentation(at: store.now.timeIntervalSince1970)
            text = value.detail + " 回执 \(timeText(evidence.observedAt))。"
            symbol = value.symbol
            tint = value.tone == "danger" ? p.red : value.tone == "warning" ? p.amber : value.tone == "success" ? p.mint : p.secondary
        } else {
            text = "Claude 会话保护状态尚未读取；当前连接图保持独立判断。"
            symbol = "shield"; tint = p.secondary
        }
        return VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: symbol).foregroundStyle(tint)
                Text(text).font(WatchTypography.small).foregroundStyle(p.secondary).lineLimit(2)
                Spacer(minLength: 0)
            }
            if let vpnSummary = vpnSupervisionSummaryText {
                Text(vpnSummary)
                    .font(WatchTypography.small)
                    .foregroundStyle(vpnSupervisionSummaryTint)
                    .lineLimit(2)
            }
        }.padding(.horizontal, 23).padding(.vertical, 6).background(p.elevated.opacity(0.35))
    }

    private var vpnSupervisionSummaryText: String? {
        var parts: [String] = []
        if store.switcher.policySyncPendingApply {
            parts.append("策略已保存 · 待执行器应用")
        }
        if let sup = store.vpnSupervision {
            let state = sup.vpn_match?.state ?? "unknown"
            parts.append("VPN 监督：\(state)")
            if sup.requires_migration == true {
                parts.append("配置待迁移确认")
            }
            if let channelState = store.channelState(for: selectedProduct), channelState.sandbox_ready == false {
                let reason = sup.unavailable_reason ?? "I03_server_identity_unverified"
                parts.append("沙箱生产门禁未就绪（\(reason)）")
            }
            if !sup.differences.isEmpty {
                let diffText = sup.differences.map { "\($0.field): 预期 \($0.expected) ≠ 实际 \($0.observed)" }.joined(separator: "；")
                parts.append("偏差：\(diffText)")
            }
            let reasons = store.vpnUnknownOrStaleReasons
            if !reasons.isEmpty {
                parts.append("未知/过期：\(reasons.joined(separator: ", "))")
            }
        }
        let unmanaged = store.unmanagedPids(for: selectedProduct)
        if !unmanaged.isEmpty {
            parts.append("发现实例（未受控）：PID \(unmanaged.map(String.init).joined(separator: ", "))")
        }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private var vpnSupervisionSummaryTint: Color {
        if let sup = store.vpnSupervision {
            let state = sup.vpn_match?.state ?? "unknown"
            if state == "mismatch" || !sup.differences.isEmpty { return p.red }
            if state == "unknown" || state == "stale" || sup.requires_migration == true { return p.amber }
        }
        if store.channelState(for: selectedProduct)?.sandbox_ready == false ||
           !store.unmanagedPids(for: selectedProduct).isEmpty ||
           store.switcher.policySyncPendingApply {
            return p.amber
        }
        return p.secondary
    }

    private func archivedPath(_ sample: GraphPathSample) -> some View {
        DisclosureGroup("查看已归档的上次路径") {
            VStack(alignment: .leading, spacing: 5) {
                let flow = sample.flow
                let source = flow.flatMap { item in sample.processes.first(where: { $0.pid == item.pid }) }
                Text("采样 \(timeText(sample.observedAt)) · \(source?.sourceDisplay ?? "来源待确认") · PID \(flow?.pid.description ?? "—")")
                Text("接入：\(flow?.transport ?? "—") · \(flow?.local ?? "—") → \(flow?.peer ?? "—")")
                Text("路径：\(flow?.routePath ?? "待确认")")
                Text("TAG：\(flow?.chains.isEmpty == false ? flow!.chains.joined(separator: " → ") : "未提供")")
                Text("目标：\(flow?.host ?? "目标待确认")")
                Text("原始说明：\(flow?.reason ?? "未提供")")
                Text("此记录来自已退出进程或已变化的网络上下文；不会参与当前计数、动画或保护判断。")
                    .foregroundStyle(p.secondary)
            }.font(WatchTypography.small).padding(.top, 5)
        }.font(WatchTypography.caption).padding(.horizontal, 23).padding(.vertical, 9)
    }

    private var wideScene: some View {
        GeometryReader { geometry in
            let width = max(900, geometry.size.width)
            let sourceX: CGFloat = 108
            let gatewayX = width * 0.35
            let tagX = width * 0.56
            let exitX = width * 0.84
            let sceneHeight: CGFloat = hasManaged ? 382 : 278
            let desktopY: CGFloat = hasManaged ? 303 : 210
            graphCanvas(width: width, height: sceneHeight, localWidth: width * 0.68)
            if graph.flow != nil {
                sourceRibbons(sourceX: sourceX, gatewayX: gatewayX, sourceWidth: 178, gatewayWidth: 174, sourceTop: 91, sourceBottom: desktopY, gatewayY: 150)
                pathRibbons(gatewayX: gatewayX, tagX: tagX, exitX: exitX, gatewayWidth: 174, tagWidth: 164, exitWidth: 220, gatewayY: 150, tagY: 150, exitTop: 91, exitBottom: 210, unresolvedY: 239)
            } else {
                referenceRibbons(sourceX: sourceX, gatewayX: gatewayX, tagX: tagX, exitX: exitX, sourceWidth: 178, gatewayWidth: 174, tagWidth: 164, exitWidth: 220, sourceTop: 91, sourceBottom: desktopY, gatewayY: 150, tagY: 150, exitTop: 91, exitBottom: 210)
            }
            if hasManaged {
                managedRibbon(sourceX: sourceX, gatewayX: gatewayX, sourceWidth: 178, gatewayWidth: 174, sourceY: 197, gatewayY: 150)
                sourceNode(.managed, title: "Codex 托管后台", symbol: "server", process: managedProcess, active: managedGraph != nil, width: 178)
                    .position(x: sourceX, y: 197)
            }
            sourceNode(.code, title: codeTitle, symbol: "square-terminal", process: codeProcess, active: codeSelected, width: 178)
                .position(x: sourceX, y: 91)
            sourceNode(.desktop, title: selectedProduct.graphDesktopTitle, symbol: "monitor", process: desktopProcess, active: desktopSelected, width: 178)
                .position(x: sourceX, y: desktopY)
            gateway(width: 174).position(x: gatewayX, y: 150)
            tagHub(width: 164).position(x: tagX, y: 150)
            exitNode(width: 220).position(x: exitX, y: 91)
            targetNode(width: 220).position(x: exitX, y: 210)
        }.frame(height: hasManaged ? 382 : 278)
    }

    private var compactScene: some View {
        GeometryReader { geometry in
            let width = max(740, geometry.size.width)
            let sourceX: CGFloat = 103
            let middleX = width * 0.49
            let exitX = width * 0.82
            let sceneHeight: CGFloat = hasManaged ? 400 : 356
            let desktopY: CGFloat = hasManaged ? 302 : 246
            graphCanvas(width: width, height: sceneHeight, localWidth: width * 0.65)
            if graph.flow != nil {
                sourceRibbons(sourceX: sourceX, gatewayX: middleX, sourceWidth: 170, gatewayWidth: 160, sourceTop: 92, sourceBottom: desktopY, gatewayY: 92)
                compactPathRibbons(middleX: middleX, exitX: exitX, gatewayWidth: 160, tagWidth: 160, exitWidth: 176, gatewayY: 92, tagY: 246, exitTop: 92, exitBottom: 246, unresolvedY: 330)
            } else {
                compactReferenceRibbons(sourceX: sourceX, middleX: middleX, exitX: exitX, sourceWidth: 170, gatewayWidth: 160, tagWidth: 160, exitWidth: 176, sourceTop: 92, sourceBottom: desktopY, gatewayY: 92, tagY: 246, exitTop: 92, exitBottom: 246)
            }
            if hasManaged {
                managedRibbon(sourceX: sourceX, gatewayX: middleX, sourceWidth: 170, gatewayWidth: 160, sourceY: 197, gatewayY: 92)
                sourceNode(.managed, title: "Codex 托管后台", symbol: "server", process: managedProcess, active: managedGraph != nil, width: 170)
                    .position(x: sourceX, y: 197)
            }
            sourceNode(.code, title: codeTitle, symbol: "square-terminal", process: codeProcess, active: codeSelected, width: 170)
                .position(x: sourceX, y: 92)
            sourceNode(.desktop, title: selectedProduct.graphDesktopTitle, symbol: "monitor", process: desktopProcess, active: desktopSelected, width: 170)
                .position(x: sourceX, y: desktopY)
            gateway(width: 160).position(x: middleX, y: 92)
            tagHub(width: 160).position(x: middleX, y: 246)
            exitNode(width: 176).position(x: exitX, y: 92)
            targetNode(width: 176).position(x: exitX, y: 246)
        }.frame(height: hasManaged ? 400 : 356)
    }

    @ViewBuilder private func graphCanvas(width: CGFloat, height: CGFloat, localWidth: CGFloat) -> some View {
        RoundedRectangle(cornerRadius: 18)
            .fill(p.blue.opacity(p.dark ? 0.028 : 0.02))
            .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(p.border.opacity(0.8), lineWidth: 1))
            .frame(width: localWidth - 24, height: height - 48).offset(x: 12, y: 36)
        RoundedRectangle(cornerRadius: 18)
            .fill(p.surface.opacity(0.27))
            .overlay(RoundedRectangle(cornerRadius: 18).strokeBorder(p.border.opacity(0.65), lineWidth: 1))
            .frame(width: width - localWidth - 16, height: height - 48).offset(x: localWidth + 4, y: 36)
        HStack(spacing: 6) {
            LucideGraphIcon(name: "laptop").frame(width: 14, height: 14)
            Text("本机 Mac").font(WatchTypography.small)
            Text("进程与代理").font(WatchTypography.small).foregroundStyle(p.secondary)
        }.foregroundStyle(p.secondary).offset(x: 24, y: 13)
        HStack(spacing: 6) {
            LucideGraphIcon(name: "globe").frame(width: 13, height: 13)
            Text("节点与连接目标").font(WatchTypography.small)
        }.foregroundStyle(p.secondary).offset(x: localWidth + 18, y: 13)
    }

    @ViewBuilder private func sourceRibbons(sourceX: CGFloat, gatewayX: CGFloat, sourceWidth: CGFloat, gatewayWidth: CGFloat, sourceTop: CGFloat, sourceBottom: CGFloat, gatewayY: CGFloat) -> some View {
        let sourceRight = sourceX + sourceWidth / 2
        let gatewayLeft = gatewayX - gatewayWidth / 2
        ribbon(from: CGPoint(x: sourceRight, y: sourceTop), to: CGPoint(x: gatewayLeft, y: gatewayY), c1: CGPoint(x: sourceRight + 28, y: sourceTop), c2: CGPoint(x: gatewayLeft - 28, y: gatewayY), state: codeGraph?.sourceEdgeState ?? .pending, animated: codeGraph != nil && shouldAnimate, showsArrow: codeGraph != nil)
        ribbon(from: CGPoint(x: sourceRight, y: sourceBottom), to: CGPoint(x: gatewayLeft, y: gatewayY), c1: CGPoint(x: sourceRight + 28, y: sourceBottom), c2: CGPoint(x: gatewayLeft - 28, y: gatewayY), state: desktopGraph?.sourceEdgeState ?? .pending, animated: desktopGraph != nil && shouldAnimate, showsArrow: desktopGraph != nil)
    }

    private func managedRibbon(sourceX: CGFloat, gatewayX: CGFloat, sourceWidth: CGFloat, gatewayWidth: CGFloat, sourceY: CGFloat, gatewayY: CGFloat) -> some View {
        let start = sourceX + sourceWidth / 2
        let end = gatewayX - gatewayWidth / 2
        return ribbon(from: CGPoint(x: start, y: sourceY), to: CGPoint(x: end, y: gatewayY),
                      c1: CGPoint(x: start + 28, y: sourceY), c2: CGPoint(x: end - 28, y: gatewayY),
                      state: managedGraph?.sourceEdgeState ?? .pending, animated: managedGraph != nil && shouldAnimate,
                      showsArrow: managedGraph != nil)
    }

    @ViewBuilder private func pathRibbons(gatewayX: CGFloat, tagX: CGFloat, exitX: CGFloat, gatewayWidth: CGFloat, tagWidth: CGFloat, exitWidth: CGFloat, gatewayY: CGFloat, tagY: CGFloat, exitTop: CGFloat, exitBottom: CGFloat, unresolvedY: CGFloat) -> some View {
        let gatewayRight = gatewayX + gatewayWidth / 2
        let tagLeft = tagX - tagWidth / 2
        let tagRight = tagX + tagWidth / 2
        let exitLeft = exitX - exitWidth / 2
        if ["proxy", "tun"].contains(graph.routePresentation) {
            ribbon(from: CGPoint(x: gatewayRight, y: gatewayY), to: CGPoint(x: tagLeft, y: tagY), c1: CGPoint(x: gatewayRight + 20, y: gatewayY), c2: CGPoint(x: tagLeft - 20, y: tagY), state: graph.gatewayEdgeState, animated: shouldAnimate)
            ribbon(from: CGPoint(x: tagRight, y: tagY), to: CGPoint(x: exitLeft, y: exitTop), c1: CGPoint(x: tagRight + 24, y: tagY), c2: CGPoint(x: exitLeft - 24, y: exitTop), state: graph.nodeEdgeState, animated: shouldAnimate)
            ribbon(from: CGPoint(x: exitX, y: exitTop + 42), to: CGPoint(x: exitX, y: exitBottom - 42), c1: CGPoint(x: exitX, y: exitTop + 58), c2: CGPoint(x: exitX, y: exitBottom - 58), state: graph.targetEdgeState, animated: shouldAnimate)
        } else if graph.routePresentation == "unresolved" {
            ribbon(from: CGPoint(x: gatewayRight, y: gatewayY + 26), to: CGPoint(x: exitLeft, y: exitBottom), c1: CGPoint(x: gatewayRight + 36, y: unresolvedY), c2: CGPoint(x: exitLeft - 36, y: unresolvedY), state: .pending)
            Text("路径待关联").font(WatchTypography.small).foregroundStyle(p.secondary).position(x: (gatewayX + exitX) / 2, y: unresolvedY)
        }
    }

    @ViewBuilder private func compactPathRibbons(middleX: CGFloat, exitX: CGFloat, gatewayWidth: CGFloat, tagWidth: CGFloat, exitWidth: CGFloat, gatewayY: CGFloat, tagY: CGFloat, exitTop: CGFloat, exitBottom: CGFloat, unresolvedY: CGFloat) -> some View {
        let gatewayBottom = gatewayY + 42
        let tagTop = tagY - 42
        let tagRight = middleX + tagWidth / 2
        let exitLeft = exitX - exitWidth / 2
        if ["proxy", "tun"].contains(graph.routePresentation) {
            ribbon(from: CGPoint(x: middleX, y: gatewayBottom), to: CGPoint(x: middleX, y: tagTop), c1: CGPoint(x: middleX, y: gatewayBottom + 20), c2: CGPoint(x: middleX, y: tagTop - 20), state: graph.gatewayEdgeState, animated: shouldAnimate)
            ribbon(from: CGPoint(x: tagRight, y: tagY), to: CGPoint(x: exitLeft, y: exitTop), c1: CGPoint(x: tagRight + 20, y: tagY), c2: CGPoint(x: exitLeft - 20, y: exitTop), state: graph.nodeEdgeState, animated: shouldAnimate)
            ribbon(from: CGPoint(x: exitX, y: exitTop + 42), to: CGPoint(x: exitX, y: exitBottom - 42), c1: CGPoint(x: exitX, y: exitTop + 58), c2: CGPoint(x: exitX, y: exitBottom - 58), state: graph.targetEdgeState, animated: shouldAnimate)
        } else if graph.routePresentation == "unresolved" {
            ribbon(from: CGPoint(x: middleX + gatewayWidth / 2, y: gatewayY + 24), to: CGPoint(x: exitLeft, y: exitBottom), c1: CGPoint(x: middleX + gatewayWidth / 2 + 28, y: unresolvedY), c2: CGPoint(x: exitLeft - 28, y: unresolvedY), state: .pending)
            Text("路径待关联").font(WatchTypography.small).foregroundStyle(p.secondary).position(x: (middleX + exitX) / 2, y: unresolvedY)
        }
    }

    @ViewBuilder private func referenceRibbons(sourceX: CGFloat, gatewayX: CGFloat, tagX: CGFloat, exitX: CGFloat, sourceWidth: CGFloat, gatewayWidth: CGFloat, tagWidth: CGFloat, exitWidth: CGFloat, sourceTop: CGFloat, sourceBottom: CGFloat, gatewayY: CGFloat, tagY: CGFloat, exitTop: CGFloat, exitBottom: CGFloat) -> some View {
        let sourceRight = sourceX + sourceWidth / 2
        let gatewayLeft = gatewayX - gatewayWidth / 2
        let gatewayRight = gatewayX + gatewayWidth / 2
        let tagLeft = tagX - tagWidth / 2
        let tagRight = tagX + tagWidth / 2
        let exitLeft = exitX - exitWidth / 2
        ribbon(from: CGPoint(x: sourceRight, y: sourceTop), to: CGPoint(x: gatewayLeft, y: gatewayY), c1: CGPoint(x: sourceRight + 28, y: sourceTop), c2: CGPoint(x: gatewayLeft - 28, y: gatewayY), state: .pending, showsArrow: false)
        ribbon(from: CGPoint(x: sourceRight, y: sourceBottom), to: CGPoint(x: gatewayLeft, y: gatewayY), c1: CGPoint(x: sourceRight + 28, y: sourceBottom), c2: CGPoint(x: gatewayLeft - 28, y: gatewayY), state: .pending, showsArrow: false)
        ribbon(from: CGPoint(x: gatewayRight, y: gatewayY), to: CGPoint(x: tagLeft, y: tagY), c1: CGPoint(x: gatewayRight + 20, y: gatewayY), c2: CGPoint(x: tagLeft - 20, y: tagY), state: .pending, showsArrow: false)
        ribbon(from: CGPoint(x: tagRight, y: tagY), to: CGPoint(x: exitLeft, y: exitTop), c1: CGPoint(x: tagRight + 24, y: tagY), c2: CGPoint(x: exitLeft - 24, y: exitTop), state: .pending, showsArrow: false)
        ribbon(from: CGPoint(x: exitX, y: exitTop + 42), to: CGPoint(x: exitX, y: exitBottom - 42), c1: CGPoint(x: exitX, y: exitTop + 58), c2: CGPoint(x: exitX, y: exitBottom - 58), state: .pending, showsArrow: false)
    }

    @ViewBuilder private func compactReferenceRibbons(sourceX: CGFloat, middleX: CGFloat, exitX: CGFloat, sourceWidth: CGFloat, gatewayWidth: CGFloat, tagWidth: CGFloat, exitWidth: CGFloat, sourceTop: CGFloat, sourceBottom: CGFloat, gatewayY: CGFloat, tagY: CGFloat, exitTop: CGFloat, exitBottom: CGFloat) -> some View {
        let sourceRight = sourceX + sourceWidth / 2
        let gatewayLeft = middleX - gatewayWidth / 2
        let tagRight = middleX + tagWidth / 2
        let exitLeft = exitX - exitWidth / 2
        ribbon(from: CGPoint(x: sourceRight, y: sourceTop), to: CGPoint(x: gatewayLeft, y: gatewayY), c1: CGPoint(x: sourceRight + 28, y: sourceTop), c2: CGPoint(x: gatewayLeft - 28, y: gatewayY), state: .pending, showsArrow: false)
        ribbon(from: CGPoint(x: sourceRight, y: sourceBottom), to: CGPoint(x: gatewayLeft, y: gatewayY), c1: CGPoint(x: sourceRight + 28, y: sourceBottom), c2: CGPoint(x: gatewayLeft - 28, y: gatewayY), state: .pending, showsArrow: false)
        ribbon(from: CGPoint(x: middleX, y: gatewayY + 42), to: CGPoint(x: middleX, y: tagY - 42), c1: CGPoint(x: middleX, y: gatewayY + 62), c2: CGPoint(x: middleX, y: tagY - 62), state: .pending, showsArrow: false)
        ribbon(from: CGPoint(x: tagRight, y: tagY), to: CGPoint(x: exitLeft, y: exitTop), c1: CGPoint(x: tagRight + 20, y: tagY), c2: CGPoint(x: exitLeft - 20, y: exitTop), state: .pending, showsArrow: false)
        ribbon(from: CGPoint(x: exitX, y: exitTop + 42), to: CGPoint(x: exitX, y: exitBottom - 42), c1: CGPoint(x: exitX, y: exitTop + 58), c2: CGPoint(x: exitX, y: exitBottom - 58), state: .pending, showsArrow: false)
    }

    private func sourceNode(_ id: GraphNodeID, title: String, symbol: String,
                            process: WatchedProcess?, active: Bool, width: CGFloat) -> some View {
        let sourceGraph = id == .code ? codeGraph : id == .managed ? managedGraph : desktopGraph
        let state: GraphEvidence = sourceGraph?.sourceEdgeState ?? .pending
        let idleText = store.snapshot == nil ? (store.error == nil ? "读取中…" : "读取失败") : "未检测到进程"
        let role: ProcessSourceRole = id == .code ? .cli : id == .managed ? .managed : .desktop
        let connectionCount = flows.filter { flow in processes.contains { $0.pid == flow.pid && $0.sourceRole == role } }.count
        let sourceStatus: String
        if display.isHistorical { sourceStatus = active ? "上次观测来源" : "此路径未经过此来源" }
        else if !display.countsAvailable { sourceStatus = "当前计数不可确认" }
        else if !store.live { sourceStatus = "等待最新采样" }
        else if process == nil { sourceStatus = idleText }
        else { sourceStatus = "\(connectionCount) 条平台连接" }
        return Button { selectNode(id) } label: {
            HStack(alignment: .center, spacing: 9) {
                Group {
                    if id == .desktop { BrandLogo(brand:selectedProduct == .claude ? .claude : .chatgpt,size:20).frame(width:28,height:28) }
                    else { glyph(symbol,state:state) }
                }
                VStack(alignment: .leading, spacing: 4) {
                    Text(title).font(WatchTypography.bodyStrong).foregroundStyle(p.text).lineLimit(1)
                    Text(verbatim: sourceStatus)
                        .font(WatchTypography.small).foregroundStyle(p.secondary).lineLimit(1)
                    Text(sourceGraph?.sourceLocal ?? (connectionCount > 0 ? "未归入当前路径" : "等待连接样本"))
                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                        .lineLimit(2).truncationMode(.middle).fixedSize(horizontal: false, vertical: true)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.padding(.horizontal, 10).frame(width: width, height: 84)
                .background(tileBackground(id, state: state))
                .contentShape(RoundedRectangle(cornerRadius: 12))
        }.buttonStyle(.plain)
            .help(sourceGraph.map { $0.sourceLocal + "\n" + $0.summary } ?? (connectionCount > 0 ? "存在平台连接，但尚未归入当前显示的路径。" : (store.snapshot == nil ? "正在读取进程状态" : "当前没有关联到此设备的连接样本")))
            .accessibilityLabel("\(title)，\(sourceStatus)，\(evidenceLabel(state))")
    }

    private func gateway(width: CGFloat) -> some View {
        Button { selectNode(.gateway) } label: {
            HStack(spacing: 9) {
                glyph(gatewayIsProxy ? "router" : graph.routePresentation == "localService" ? "server" : "network",
                      state: graph.gatewayState)
                VStack(alignment: .leading, spacing: 5) {
                    Text(historicalTitle(gatewayIsProxy ? "本机代理" : graph.gatewayTitle))
                        .font(WatchTypography.bodyStrong).foregroundStyle(p.text).lineLimit(1)
                    Text(graph.gatewayEndpoint.replacingOccurrences(of: "http://", with: ""))
                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                        .lineLimit(2).truncationMode(.middle).fixedSize(horizontal: false, vertical: true)
                    Text(verbatim: !gatewayIsProxy ? evidenceLabel(graph.gatewayState) :
                            "TAG · " + evidenceLabel(graph.gatewayState))
                        .font(WatchTypography.small).foregroundStyle(color(graph.gatewayState)).lineLimit(1)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.padding(.horizontal, 10).frame(width: width, height: 84)
                .background(tileBackground(.gateway, state: graph.gatewayState))
                .contentShape(RoundedRectangle(cornerRadius: 12))
        }.buttonStyle(.plain).help(graph.gatewayDetail)
            .accessibilityLabel("\(historicalTitle(gatewayIsProxy ? "本机代理" : graph.gatewayTitle))，\(evidenceLabel(graph.gatewayState))，点击查看证据")
    }

    private func tagHub(width: CGFloat) -> some View {
        Button { selectNode(.tag) } label: {
            HStack(spacing: 9) {
                glyph("network", state: graph.groupState)
                VStack(alignment: .leading, spacing: 5) {
                    Text(historicalTitle("TAG 分流")).font(WatchTypography.bodyStrong).foregroundStyle(p.text).lineLimit(1)
                    Text(graph.groupTitle).font(WatchTypography.caption).foregroundStyle(p.secondary)
                        .lineLimit(2).truncationMode(.tail).fixedSize(horizontal: false, vertical: true)
                    Text(evidenceLabel(graph.groupState)).font(WatchTypography.small).foregroundStyle(color(graph.groupState)).lineLimit(1)
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.padding(.horizontal, 10).frame(width: width, height: 84)
                .background(tileBackground(.tag, state: graph.groupState))
                .contentShape(RoundedRectangle(cornerRadius: 12))
        }.buttonStyle(.plain).help("TAG 分组：\(graph.groupTitle)\n查看 TAG 分组与本次样本的关联证据")
            .accessibilityLabel("TAG 分流，\(graph.groupTitle)，\(evidenceLabel(graph.groupState))，点击查看证据")
    }

    private func exitNode(width: CGFloat) -> some View {
        Button { selectNode(.node) } label: {
            HStack(spacing: 10) {
                glyph("server", state: graph.nodeState)
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text(historicalTitle("代理节点"))
                            .font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                        Text(evidenceLabel(graph.nodeState)).font(WatchTypography.small).foregroundStyle(color(graph.nodeState)).lineLimit(1)
                    }
                    Text(graph.nodeTitle).font(WatchTypography.caption).foregroundStyle(p.secondary)
                        .lineLimit(2).truncationMode(.tail).fixedSize(horizontal: false, vertical: true)
                    if graph.nodeState == .confirmed || graph.nodeState == .mismatch,
                       let global = proxy?.globalNode, !global.isEmpty, global != graph.nodeTitle {
                        Text("GLOBAL 配置：" + global).font(WatchTypography.small).foregroundStyle(p.secondary)
                            .lineLimit(2).fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text("节点出口未单独测定").font(WatchTypography.small).foregroundStyle(p.secondary).lineLimit(1)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.padding(.horizontal, 10).frame(width: width, height: 84)
                .background(tileBackground(.node, state: graph.nodeState))
                .contentShape(RoundedRectangle(cornerRadius: 12))
        }.buttonStyle(.plain).help(graph.nodeTitle + "；当前检测未提供此节点的公网出口 IP")
            .accessibilityLabel("代理节点，\(graph.nodeTitle)，\(evidenceLabel(graph.nodeState))，点击查看证据")
    }

    private func targetNode(width: CGFloat) -> some View {
        Button { selectNode(.service) } label: {
            HStack(spacing: 10) {
                BrandLogo(brand:selectedProduct == .claude ? .claude : .chatgpt,size:20).frame(width:28,height:28)
                VStack(alignment: .leading, spacing: 4) {
                    Text(historicalTitle(serverTarget.title)).font(WatchTypography.bodyStrong).foregroundStyle(p.text).lineLimit(1)
                    Text(serverTarget.addressLine).font(WatchTypography.caption).foregroundStyle(p.secondary)
                        .lineLimit(2).truncationMode(.middle)
                    HStack(spacing:6) {
                        CountryFlag(code:serverTarget.regionCountryCode,width:16)
                        Text(serverTarget.regionLine).font(WatchTypography.small).foregroundStyle(p.secondary)
                            .lineLimit(1).truncationMode(.tail)
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.padding(.horizontal, 10).frame(width: width, height: 84)
                .background(tileBackground(.service, state: graph.targetEdgeState))
                .contentShape(RoundedRectangle(cornerRadius: 12))
        }.buttonStyle(.plain).help(serverTarget.detail)
            .accessibilityLabel("\(serverTarget.title)，\(serverTarget.addressLine)，\(serverTarget.regionLine)，点击查看证据")
    }

    private func selectNode(_ node: GraphNodeID) {
        if selectedNode == node, expandedNode == node {
            expandedNode = nil
        } else {
            selectedNode = node
            expandedNode = node
        }
    }

    private func tileBackground(_ id: GraphNodeID, state: GraphEvidence) -> some View {
        RoundedRectangle(cornerRadius: 12)
            .fill(LinearGradient(colors: [p.surface, p.surface.opacity(0.82)], startPoint: .top, endPoint: .bottom))
            .overlay(RoundedRectangle(cornerRadius: 12)
                .strokeBorder(selectedNode == id ? color(state).opacity(0.7) : p.border.opacity(0.9), lineWidth: 1))
    }

    private func glyph(_ symbol: String, state: GraphEvidence) -> some View {
        LucideGraphIcon(name: symbol).frame(width: 28, height: 28)
            .foregroundStyle(state == .pending ? p.secondary.opacity(0.9) : color(state))
            .frame(width: 36, height: 42)
    }

    private func ribbon(from start: CGPoint, to end: CGPoint, c1: CGPoint, c2: CGPoint,
                        state: GraphEvidence, animated: Bool = false, showsArrow: Bool = true) -> some View {
        let path = Path { path in
            path.move(to: start); path.addCurve(to: end, control1: c1, control2: c2)
        }
        return FlowRibbon(path: path, end: end, control: c2, state: state, tint: color(state), secondary: p.secondary,
                          dark: p.dark, animate: animated, showsArrow: showsArrow)
            .allowsHitTesting(false)
    }

    private func legend(_ state: GraphEvidence, _ title: String) -> some View {
        HStack(spacing: 6) {
            if state == .pending {
                Capsule().fill(color(state).opacity(0.6)).frame(width: 4, height: 2)
                Capsule().fill(color(state).opacity(0.6)).frame(width: 4, height: 2).padding(.leading, -4)
            } else {
                Circle().fill(color(state)).frame(width: 5, height: 5)
            }
            Text(title).font(WatchTypography.small).foregroundStyle(p.secondary)
        }
    }
    private func color(_ state: GraphEvidence) -> Color {
        switch state {
        case .confirmed: return p.mint
        case .pending: return p.secondary
        case .mismatch: return p.amber
        case .configuration: return p.blue
        }
    }
    private func evidenceLabel(_ state: GraphEvidence) -> String {
        if display.isHistorical { return graph.flow?.policy == "mismatch" ? "历史差异" : "历史记录" }
        switch state {
        case .confirmed: return "已确认"
        case .pending: return "未关联"
        case .mismatch: return "路径差异"
        case .configuration: return store.proxyFresh ? "配置参考" : "等待采样"
        }
    }
    private var detailTitle: String {
        let title: String
        switch selectedNode {
        case .code: title = codeTitle
        case .desktop: title = selectedProduct == .openAI ? "ChatGPT / Codex 桌面应用" : selectedProduct.graphDesktopTitle
        case .managed: title = "Codex 托管后台"
        case .gateway: title = graph.gatewayTitle
        case .tag: title = "TAG · " + graph.groupTitle
        case .node: title = "代理节点 · " + graph.nodeTitle
        case .service: title = serverTarget.title
        }
        return historicalTitle(title)
    }
    private var detailText: String {
        let text: String
        switch selectedNode {
        case .code, .desktop, .managed:
            let sourceProcess = selectedNode == .code ? codeProcess : selectedNode == .managed ? managedProcess : desktopProcess
            let evidenceDetail = sourceProcess.map { store.processEvidenceText($0) + "\n" } ?? ""
            let sourceGraph = selectedNode == .code ? codeGraph : selectedNode == .managed ? managedGraph : desktopGraph
            let sourceDetail = selectedProduct == .openAI
                ? (selectedNode == .desktop ? "桌面应用来源；Chromium 组件与 MCP 工具独立分组。\n" : selectedNode == .managed ? "按托管服务身份显示；客户端归属待确认。\n" : "仅展示后台识别为独立 Codex CLI 的进程；桌面内置服务不重复计入。\n")
                : ""
            if let sourceGraph, let flow = sourceGraph.flow {
                text = evidenceDetail + sourceDetail + "PID \(flow.pid) · \(flow.transport) · 本地端点 \(flow.local)\n" + sourceGraph.summary
            } else {
                let role: ProcessSourceRole = selectedNode == .code ? .cli : selectedNode == .managed ? .managed : .desktop
                let hasOtherPath = flows.contains { flow in processes.contains { $0.pid == flow.pid && $0.sourceRole == role } }
                text = evidenceDetail + sourceDetail + (hasOtherPath ? "存在平台连接，但未归入当前显示的路径；可在连接列表中选择查看。" : "尚无与此进程关联的连接样本。出现连接后，图中才会显示对应路径。")
            }
        case .gateway:
            let unmanaged = store.unmanagedPids(for: selectedProduct)
            let unmanagedNotice = unmanaged.isEmpty
                ? ""
                : "\n注意：发现未受控实例 PID \(unmanaged.map(String.init).joined(separator: ", "))（running_unprotected，未经过受控入口启动，不享受沙箱与通道保护）"
            text = graph.gatewayDetail + (gatewayIsProxy ? "\n" + (proxy?.listenerPath ?? "监听者路径未取得") : "") + unmanagedNotice
        case .tag:
            text = graph.flow?.chains.isEmpty == false
                ? (graph.flow?.chains.joined(separator: " → ") ?? "") + "\n" + graph.summary
                : "尚未获得该应用的实际路由规则记录；配置参考可在代理详情中查看。"
        case .node:
            let configuration = selectedProduct == .openAI ? "\n海外AI 分组配置：\(proxy?.selectedNode ?? "未取得")\nGLOBAL 配置：\(proxy?.globalNode ?? "未取得")\n采样控制器模式：\(modeName(proxy?.mode ?? ""))" : ""
            text = "当前连接记录的节点：\(graph.nodeTitle)\n" + graph.summary + configuration
                + "\n最终公网出口 IP 未取得。配置选项与这条连接实际使用的节点分开核对。"
        case .service:
            text = serverTarget.detail + "\n" + graph.summary
        }
        return display.isHistorical ? "以下为上次记录，不代表当前路径。\n" + text + "\n原始说明：" + (graph.flow?.reason ?? "") : text
    }
}

private struct FlowRibbon: View {
    let path: Path
    let end: CGPoint
    let control: CGPoint
    let state: GraphEvidence
    let tint: Color
    let secondary: Color
    let dark: Bool
    let animate: Bool
    let showsArrow: Bool

    private var observed: Bool { state == .confirmed || state == .mismatch }

    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 24.0, paused: !animate || !observed)) { context in
            let progress = animate && observed
                ? CGFloat((context.date.timeIntervalSinceReferenceDate * 0.22).truncatingRemainder(dividingBy: 1))
                : 0
            ZStack(alignment: .topLeading) {
                if observed {
                    path.stroke(tint.opacity(dark ? 0.16 : 0.12), style: StrokeStyle(lineWidth: 12, lineCap: .round)).blur(radius: 7)
                    path.stroke(tint.opacity(dark ? 0.26 : 0.22), style: StrokeStyle(lineWidth: 8, lineCap: .round))
                    path.stroke(tint.opacity(animate ? (dark ? 0.32 : 0.34) : (dark ? 0.72 : 0.82)),
                                style: StrokeStyle(lineWidth: 2.1, lineCap: .round))
                    if animate {
                        movingMarks(progress: progress)
                    }
                } else {
                    path.stroke(secondary.opacity(dark ? 0.32 : 0.38), style: StrokeStyle(lineWidth: 1.5, lineCap: .round, dash: [5, 7]))
                }
                if showsArrow {
                    let angle = atan2(end.y - control.y, end.x - control.x) * 180 / .pi
                    Image(systemName: "chevron.right").font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(observed ? tint : secondary.opacity(0.55))
                        .rotationEffect(.degrees(angle)).position(end)
                }
            }
        }
    }

    @ViewBuilder private func movingMarks(progress: CGFloat) -> some View {
        // The marks indicate an evidenced sampled path, never measured throughput.
        ForEach(Array([progress, (progress + 0.48).truncatingRemainder(dividingBy: 1)].enumerated()), id: \.offset) { item in
            let start = item.element
            let length: CGFloat = 0.105
            let end = start + length
            mark(path.trimmedPath(from: start, to: min(end, 1)))
            if end > 1 {
                mark(path.trimmedPath(from: 0, to: end - 1))
            }
        }
    }

    private func mark(_ segment: Path) -> some View {
        segment.stroke(tint.opacity(dark ? 0.50 : 0.42), style: StrokeStyle(lineWidth: 8, lineCap: .round))
            .blur(radius: 3)
            .overlay {
                segment.stroke(tint, style: StrokeStyle(lineWidth: 3.2, lineCap: .round))
            }
    }
}

private struct LucideGraphIcon: View {
    let name: String
    private static let images: [String: NSImage] = {
        var result: [String: NSImage] = [:]
        for name in ["square-terminal", "monitor", "router", "network", "server", "cloud", "laptop", "globe"] {
            if let resource = Bundle.main.resourceURL?.appendingPathComponent("Icons/graph-" + name + ".png"),
               let image = NSImage(contentsOf: resource) {
                image.isTemplate = true
                result[name] = image
            }
        }
        return result
    }()
    var body: some View {
        if let image = Self.images[name] {
            Image(nsImage: image).renderingMode(.template).resizable().scaledToFit()
        } else {
            Image(systemName: "questionmark.square.dashed").resizable().scaledToFit()
        }
    }
}
