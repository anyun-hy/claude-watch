import SwiftUI

private extension String {
    var aiNonEmpty: String? {
        let value = trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }
}

/// A manual, local diagnostic for one AI service. It intentionally keeps probe
/// output separate from sampled application flows: a successful request through
/// 7890 does not establish the egress used by an existing Claude/Codex process.
struct AIServiceCheckPage: View {
    let service: AIService
    @ObservedObject var store: MonitorStore
    @ObservedObject var probes: AIProbeStore
    let p: Palette

    private var state: AIProbeState { probes.state(service) }
    private var result: AIProbeResult? { state.result }
    private var scope: ConnectionGraphScope {
        ConnectionGraphScope(product: service.product,
                             processes: store.snapshot?.processes ?? [],
                             flows: store.proxy?.flows ?? [])
    }
    private var sampledNodes: [String] {
        Array(Set(scope.flows
            .filter { $0.association == "correlated" }
            .compactMap { $0.chains.last?.aiNonEmpty }))
            .sorted()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Surface(p, padding: 16) {
                header
                Text("本页检查经 7890 发出的网络诊断请求。\(service == .claude ? "Claude" : "ChatGPT / Codex") 应用当前使用的路径，请查看连接图中的关联证据。")
                    .font(WatchTypography.caption).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 12)
            }

            ViewThatFits(in: .horizontal) {
                HStack(spacing: 12) { metricCards }
                VStack(spacing: 12) { metricCards }
            }

            if let result {
                resultCard(result)
            } else {
                Surface(p) {
                    EmptyState(symbol: "network.badge.shield.half.filled", title: "尚未执行服务检测",
                               detail: "开始后会记录本机 7890 诊断请求的出口与端点响应；未采样时不显示安全结论。", p: p)
                }
            }

            SharedLeakResults(store: store.leakChecks, p: p) {
                store.page = .dns
            } openWebRTC: {
                store.page = .webrtc
            }

            HStack(spacing: 7) {
                Image(systemName: "info.circle").font(.system(size: 13))
                Text("网站风险评分算法/数据库未接入，暂不提供分数。")
            }
            .font(WatchTypography.caption).foregroundStyle(p.secondary).padding(.horizontal, 3)
        }
        .frame(maxWidth: 1240, alignment: .leading)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: service == .claude ? "sparkles" : "terminal")
                .font(.system(size: 17, weight: .regular)).foregroundStyle(statusTint)
                .frame(width: 28, height: 28).background(statusTint.opacity(0.08), in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 4) {
                Text("服务网络诊断").font(WatchTypography.title).foregroundStyle(p.text)
                Text(state.verdict.detail).font(WatchTypography.caption).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 10)
            VStack(alignment: .trailing, spacing: 8) {
                Badge(text: state.verdict.title, color: statusTint)
                HStack(spacing: 7) {
                    Button {
                        store.networkSelection.product = service.product
                        store.page = .network
                    } label: {
                        Label("连接图", systemImage: "point.3.connected.trianglepath.dotted")
                    }
                    .buttonStyle(.bordered).controlSize(.small)
                    .accessibilityLabel("查看\(service.title)连接图")
                    Button {
                        state.running ? probes.cancel(service) : probes.start(service)
                    } label: {
                        Label(state.running ? "取消" : "开始检测", systemImage: state.running ? "xmark" : "play.fill")
                    }
                    .buttonStyle(.bordered).controlSize(.small).tint(state.running ? p.amber : p.blue)
                    .accessibilityLabel(state.running ? "取消\(service.title)服务检测" : "开始\(service.title)服务检测")
                }
            }
        }
    }

    @ViewBuilder private var metricCards: some View {
        AIServiceMetric(title: "对应服务出口参考 IP", value: metricIP(result?.exitIP),
                        detail: result.map { sourceDescription($0.exitSource) } ?? "来自本次本机诊断请求", symbol: "arrow.up.right.circle", tint: p.blue, p: p)
        AIServiceMetric(title: "Cloudflare 参考 IP", value: metricIP(result?.referenceIP),
                        detail: (result?.referenceIP.isEmpty ?? true) ? "等待本次检测返回" : "同轮 HTTP 参考", symbol: "cloud", tint: p.blue, p: p)
        AIServiceMetric(title: "当前实际节点", value: sampledNodes.isEmpty ? "未采样" : sampledNodes.joined(separator: "、"),
                        detail: sampledNodes.isEmpty ? "尚无对应服务的关联连接样本" : "\(scope.flows.count) 条连接样本，\(scope.processes.count) 个关联进程", symbol: "point.3.connected.trianglepath.dotted", tint: p.amber, p: p)
    }

    private func resultCard(_ result: AIProbeResult) -> some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 13) {
                SectionHeading(title: "本轮服务响应", caption: "端点响应反映本次请求可达性；HTTP 401 是认证响应，并不表示断网。", p: p)
                VStack(alignment: .leading, spacing: 0) {
                    DetailRow(title: "开始 / 完成", value: "\(timeText(result.startedAt, date: true))  /  \(result.finishedAt > 0 ? timeText(result.finishedAt, date: true) : "进行中")", p: p, monospaced: true)
                    DetailRow(title: "出口归属", value: location(result), p: p)
                    DetailRow(title: "ASN / 组织", value: result.organization.aiNonEmpty ?? "未返回", p: p)
                    DetailRow(title: "时区", value: "出口：\(result.ipTimezone.aiNonEmpty ?? "未返回")；本机：\(TimeZone.current.identifier)", p: p)
                    DetailRow(title: "检测状态", value: probeStatus(result.status), p: p, tint: statusTint)
                }
                .padding(.vertical, 3).overlay(alignment: .top) { Rectangle().fill(p.border.opacity(0.62)).frame(height: 1) }

                endpointSection(result.endpoints)
                if !result.errors.isEmpty { errorSection(result.errors) }
                if !result.details.isEmpty { detailsSection(result.details) }
            }
        }
    }

    private func endpointSection(_ endpoints: [AIEndpointResult]) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("端点 HTTP 响应").font(WatchTypography.section)
            if endpoints.isEmpty {
                Text("本轮没有端点响应；请查看错误记录。")
                    .font(WatchTypography.caption).foregroundStyle(p.secondary)
            } else {
                ForEach(endpoints) { endpoint in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack(spacing: 8) {
                            Text(endpoint.status == "responded" ? "HTTP \(endpoint.httpStatus ?? 0)" : endpoint.status == "timeout" ? "超时" : "未完成")
                                .font(WatchTypography.bodyStrong).foregroundStyle(endpointTint(endpoint))
                            Text(endpoint.url).font(WatchTypography.mono).foregroundStyle(p.text).lineLimit(1).textSelection(.enabled)
                            Spacer(minLength: 4)
                            if let elapsed = endpoint.elapsedMs { Text("\(Int(elapsed)) ms").font(WatchTypography.small).foregroundStyle(p.secondary) }
                        }
                        Text(endpointMessage(endpoint)).font(WatchTypography.caption).foregroundStyle(p.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(10).background(p.elevated.opacity(0.55), in: RoundedRectangle(cornerRadius: 8))
                }
            }
        }
    }

    private func errorSection(_ errors: [LeakProbeError]) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text("检测错误（\(errors.count)）").font(WatchTypography.section).foregroundStyle(p.amber)
            ForEach(errors) { error in
                Text("\(error.stage) · \(error.code)：\(error.message)")
                    .font(WatchTypography.caption).foregroundStyle(p.secondary).textSelection(.enabled)
            }
        }
    }

    private func detailsSection(_ details: [String]) -> some View {
        DisclosureGroup("诊断详情（\(details.count)）") {
            VStack(alignment: .leading, spacing: 5) {
                ForEach(Array(details.enumerated()), id: \.offset) { _, detail in
                    Text(detail).font(WatchTypography.mono).foregroundStyle(p.secondary).textSelection(.enabled)
                }
            }.padding(.top, 7)
        }
        .font(WatchTypography.bodyStrong).foregroundStyle(p.text)
        .disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
    }

    private var statusTint: Color {
        if state.running { return p.blue }
        if result?.errors.isEmpty == false { return p.amber }
        switch state.verdict.state {
        case .difference, .incomplete, .cancelled: return p.amber
        case .idle, .unconfigured: return p.secondary
        case .running, .matched: return p.blue
        }
    }
    private func endpointTint(_ endpoint: AIEndpointResult) -> Color {
        guard let code = endpoint.httpStatus else { return p.amber }
        return (200..<400).contains(code) ? p.blue : p.amber
    }
    private func probeStatus(_ status: String) -> String {
        switch status {
        case "complete": return "本轮请求已完成"
        case "partial": return "仍有未完成项目"
        case "timeout": return "本轮请求超时"
        default: return "本轮未完成"
        }
    }
    private func endpointMessage(_ endpoint: AIEndpointResult) -> String {
        if endpoint.httpStatus == 401 { return "认证响应（401）：端点可达；该响应不表示断网或账号状态。\(endpoint.message.isEmpty ? "" : " \(endpoint.message)")" }
        if let code = endpoint.httpStatus, code == 403 || code == 429 || code >= 500 {
            return "服务限制或服务端响应（HTTP \(code)）；不据此判断账号状态。\(endpoint.message.isEmpty ? "" : " \(endpoint.message)")"
        }
        return endpoint.message.isEmpty ? "未提供附加信息" : endpoint.message
    }
    private func sourceDescription(_ source: String) -> String { source.aiNonEmpty ?? "未返回出口来源" }
    private func metricIP(_ value: String?) -> String {
        result == nil ? "未检测" : (value?.aiNonEmpty ?? "未取得")
    }
    private func location(_ result: AIProbeResult) -> String {
        let country = localizedCountry(result.countryCode, fallback: result.country)
        return [country, result.region, result.city].filter { !$0.isEmpty }.joined(separator: " · ").aiNonEmpty ?? "未返回"
    }
    private func localizedCountry(_ code: String, fallback: String) -> String {
        guard !code.isEmpty else { return fallback }
        return Locale(identifier: "zh_Hans").localizedString(forRegionCode: code.uppercased()) ?? fallback
    }
}

private struct AIServiceMetric: View {
    let title, value, detail, symbol: String
    let tint: Color
    let p: Palette
    var body: some View {
        Surface(p, padding: 14) {
            VStack(alignment: .leading, spacing: 8) {
                HStack { Text(title).font(WatchTypography.caption).foregroundStyle(p.secondary); Spacer(); Image(systemName: symbol).font(.system(size: 15)).foregroundStyle(tint) }
                Text(value).font(.system(size: 18, weight: .semibold, design: .rounded)).foregroundStyle(p.text).lineLimit(2).minimumScaleFactor(0.8)
                Text(detail).font(WatchTypography.caption).foregroundStyle(p.secondary).lineLimit(2)
            }.frame(maxWidth: .infinity, minHeight: 78, alignment: .topLeading)
        }
    }
}

/// This child owns the observed object so DNS/WebRTC state updates while this
/// page remains visible, without tying either shared diagnostic to an AI process.
private struct SharedLeakResults: View {
    @ObservedObject var store: LeakCheckStore
    let p: Palette
    let openDNS: () -> Void
    let openWebRTC: () -> Void
    var body: some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 11) {
                SectionHeading(title: "共享 DNS / WebRTC 最近结果", caption: "这两项是本机共用诊断；AI 应用的实际路径请以连接图中的关联连接样本为准。", p: p)
                HStack(spacing: 10) {
                    sharedRow("DNS", state: store.dns, symbol: "network", action: openDNS)
                    sharedRow("WebRTC", state: store.rtc, symbol: "antenna.radiowaves.left.and.right", action: openWebRTC)
                }
            }
        }
    }
    private func sharedRow(_ title: String, state: LeakCheckState, symbol: String, action: @escaping () -> Void) -> some View {
        HStack(spacing: 8) {
            Image(systemName: symbol).font(.system(size: 14)).foregroundStyle(p.blue)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(WatchTypography.bodyStrong)
                Text(state.verdict.title).font(WatchTypography.caption).foregroundStyle(p.secondary)
            }
            Spacer(minLength: 4)
            Button("查看", action: action).buttonStyle(.bordered).controlSize(.small)
        }
        .padding(10).background(p.elevated.opacity(0.55), in: RoundedRectangle(cornerRadius: 8))
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
