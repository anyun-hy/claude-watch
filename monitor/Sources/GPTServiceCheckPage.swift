import SwiftUI

// The default is a compact native inspector. The report alternative is exposed
// only by the isolated review app; both layouts read the same existing stores.
enum GPTDiagnosticLayout: String, CaseIterable {
    case inspector = "原生检查器", report = "检测报告"
}
private struct GPTDiagnosticLayoutKey: EnvironmentKey {
    static let defaultValue: GPTDiagnosticLayout = .inspector
}
extension EnvironmentValues {
    var gptDiagnosticLayout: GPTDiagnosticLayout {
        get { self[GPTDiagnosticLayoutKey.self] }
        set { self[GPTDiagnosticLayoutKey.self] = newValue }
    }
}

/// Presentation only. Probe start/cancel, verdicts, expiry and process/flow
/// correlation remain owned by the existing collectors and policy objects.
struct AIInspectorPage: View {
    let service: AIService
    @ObservedObject var store: MonitorStore
    @ObservedObject var probes: AIProbeStore
    let p: Palette
    @Environment(\.gptDiagnosticLayout) private var layout
    @State private var detailsExpanded = false

    private var state: AIProbeState { probes.state(service) }
    private var result: AIProbeResult? { state.result }
    private var style: InspectorStyle { InspectorStyle(p: p) }
    private var accent: Color { style.action }
    private var line: Color { p.border.opacity(p.dark ? 0.55 : 0.65) }
    private var scope: ConnectionGraphScope {
        ConnectionGraphScope(product: service.product, processes: store.snapshot?.processes ?? [],
                             flows: store.proxy?.flows ?? [])
    }
    private var nodes: [String] {
        Array(Set(scope.platformFlows.filter { $0.association == "correlated" }
            .compactMap { clean($0.chains.last) })).sorted()
    }
    private var statusTint: Color {
        if state.running { return accent }
        switch state.verdict.state {
        case .difference, .incomplete: return p.amber
        case .idle, .cancelled: return p.secondary
        case .running: return accent
        case .matched, .unconfigured: return p.blue
        }
    }
    private var statusSymbol: String {
        switch state.verdict.state {
        case .idle: return "circle.dotted"
        case .running: return "arrow.triangle.2.circlepath"
        case .difference: return "exclamationmark.circle"
        case .incomplete: return "clock.badge.exclamationmark"
        case .cancelled: return "xmark.circle"
        case .matched, .unconfigured: return "waveform.path"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading
            statusSummary
            if layout == .inspector || service == .claude {
                inspector
            } else {
                report
            }
            endpointSection
            CoffeeAIReport(ip: result?.exitIP ?? "", store: store.netCoffee, p: p) { store.page = .ipScore }
            GPTSharedChecks(store: store.leakChecks, p: p,
                openDNS: { store.page = .dns }, openRTC: { store.page = .webrtc })
            evidenceDetails
        }
        .font(.body).foregroundStyle(p.text)
        .frame(maxWidth: 1120, alignment: .leading)
        .padding(.top, 24)
    }

    private var heading: some View {
        InspectorHeading(title: service.title,
            subtitle: service == .claude ? "Claude 与 Anthropic · 网络诊断" : "ChatGPT 与 OpenAI API · 网络诊断",
            symbol: service == .claude ? "sparkles" : "bubble.left.and.bubble.right",
            color: service == .claude ? style.service : style.proxy, p: p, brand:service == .claude ? .claude : .chatgpt) {
            Button {
                state.running ? probes.cancel(service) : probes.start(service)
            } label: {
                Label(state.running ? "取消检测" : "开始检测",
                      systemImage: state.running ? "stop.fill" : "play.fill")
                    .font(.body.weight(.medium)).padding(.horizontal, 4).frame(minHeight: 28)
            }
            .buttonStyle(.borderedProminent).controlSize(.large)
            .tint(state.running ? p.secondary : accent)
            .accessibilityLabel(state.running ? "取消 \(service.title)" : "开始 \(service.title)")
        }
    }

    private var statusSummary: some View {
        HStack(alignment: .top, spacing: 12) {
            if state.running {
                ProgressView().controlSize(.small).frame(width: 20, height: 20)
            } else {
                symbol(statusSymbol, tint: statusTint).frame(width: 20, height: 20)
            }
            VStack(alignment: .leading, spacing: 5) {
                Text(state.verdict.title).font(.headline).foregroundStyle(statusTint)
                Text(state.verdict.detail).font(.callout).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 12)
            if let result, result.finishedAt > 0 {
                Label(timeText(result.finishedAt), systemImage: "clock")
                    .font(.caption).foregroundStyle(p.secondary).monospacedDigit()
                    .help("本轮完成：" + timeText(result.finishedAt, date: true))
            } else {
                Text("手动检测").font(.caption).foregroundStyle(p.secondary)
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading)
        .background(statusTint.opacity(p.dark ? 0.09 : 0.045), in: RoundedRectangle(cornerRadius: 10))
    }

    private var inspector: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: 0) {
                exitSummary.padding(20).frame(minWidth: 360, maxWidth: .infinity, alignment: .leading)
                Rectangle().fill(line).frame(width: 1).padding(.vertical, 20)
                connectionSummary.padding(20).frame(width: 284, alignment: .leading)
            }.fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 0) {
                exitSummary.padding(20)
                Divider().overlay(line).padding(.horizontal, 20)
                connectionSummary.padding(20)
            }
        }
        .background(p.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).strokeBorder(line, lineWidth: 0.7))
        .shadow(color: .black.opacity(p.dark ? 0 : 0.025), radius: 12, y: 3)
    }

    private var exitSummary: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionLabel("诊断请求出口", symbol: "globe", tint: style.network)
            VStack(alignment: .leading, spacing: 8) {
                Text(address(result?.exitIP))
                    .font(.system(size: 24, weight: .semibold, design: .monospaced))
                    .tracking(-0.5).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing:8) {
                    CountryFlag(code:CountryIdentity.code(result?.countryCode,country:result?.country))
                    Text(location).font(.callout).foregroundStyle(p.secondary)
                }
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(alignment: .top, spacing: 10) {
                symbol("building.2", tint: style.location)
                Text(clean(result?.organization) ?? (result == nil ? "网络组织 · 等待诊断结果" : "网络组织 · 未取得"))
                    .font(.callout).foregroundStyle(p.secondary).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Divider().overlay(line)
            HStack(alignment: .firstTextBaseline, spacing: 12) {
                HStack(spacing: 8) {
                    BrandLogo(brand:.cloudflare,size:16)
                    Text("HTTP 对照出口").font(.callout).foregroundStyle(p.secondary)
                }
                Spacer(minLength: 8)
                Text(address(result?.referenceIP)).font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            }
            Text("服务与对照出口来自本轮诊断请求，经 127.0.0.1:7890。")
                .font(.caption).foregroundStyle(p.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var connectionSummary: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionLabel("应用连接证据", symbol: "desktopcomputer", tint: style.proxy)
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    symbol("server.rack", tint: style.proxy)
                    Text("实际代理节点").font(.caption).foregroundStyle(p.secondary)
                }
                Text(nodes.isEmpty ? "等待连接采样" : nodes.joined(separator: "、"))
                    .font(.headline).fixedSize(horizontal: false, vertical: true)
                Text(nodes.isEmpty ? "尚无可关联的实际代理链" : "由已关联的连接链确认")
                    .font(.caption).foregroundStyle(p.secondary)
            }
            HStack(spacing: 16) {
                Label("\(scope.platformFlows.count) 条平台连接", systemImage: "point.3.connected.trianglepath.dotted")
                Label("\(Set(scope.processes.map(\.componentKey)).count) 类组件", systemImage: "square.stack.3d.up")
            }.font(.caption).foregroundStyle(p.secondary).fixedSize()
            Text("当前应用采样，与左侧诊断请求分开取证。")
                .font(.caption).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
            Button(action: openConnections) {
                HStack(spacing: 8) {
                    Text("查看连接图").font(.callout.weight(.medium))
                    Spacer(minLength: 8)
                    Image(systemName: "arrow.up.right").font(.system(size: 11, weight: .medium))
                }.padding(.vertical, 8).contentShape(Rectangle())
            }
            .buttonStyle(.plain).foregroundStyle(accent)
            .accessibilityLabel("查看 \(service.product.title) 连接图")
        }
    }

    // A second, document-style direction for visual comparison in UI_REVIEW.
    // It changes presentation alone, never collection or verdict policy.
    private var report: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text("出口与连接").font(.title3.weight(.semibold))
                Spacer()
                Button("查看连接图", action: openConnections).buttonStyle(.link).tint(accent)
            }.padding(.bottom, 16)
            reportRow("globe", "诊断请求出口", address(result?.exitIP), prominent: true)
            reportRow("mappin.and.ellipse", "归属区域", location)
            reportRow("building.2", "网络组织", clean(result?.organization) ?? "未取得")
            reportRow("cloud", "HTTP 对照出口", address(result?.referenceIP))
            reportRow("server.rack", "应用实际节点", nodes.isEmpty ? "等待连接采样" : nodes.joined(separator: "、"))
            Text("诊断请求经 7890；应用节点独立取自已关联的连接链。")
                .font(.caption).foregroundStyle(p.secondary).padding(.top, 12)
        }.padding(20)
        .background(p.surface, in: RoundedRectangle(cornerRadius: 10))
    }

    private func reportRow(_ icon: String, _ label: String, _ value: String, prominent: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            symbol(icon, tint: p.secondary).frame(width: 18)
            Text(label).font(.callout).foregroundStyle(p.secondary).frame(width: 112, alignment: .leading)
            Text(value).font(prominent ? .system(.title2, design: .monospaced).weight(.semibold) : .body)
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }.padding(.vertical, 12)
            .overlay(alignment: .bottom) { Rectangle().fill(line.opacity(0.65)).frame(height: 0.5) }
    }

    private var endpointSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                sectionLabel("服务响应", symbol: "arrow.up.arrow.down", tint: style.transport)
                Spacer()
                Text(result.map { "\($0.endpoints.count) 个端点" } ?? "等待检测")
                    .font(.caption).foregroundStyle(p.secondary)
            }
            VStack(spacing: 0) {
                if let result, !result.endpoints.isEmpty {
                    ForEach(Array(result.endpoints.enumerated()), id: \.element.id) { index, endpoint in
                        if index > 0 { Divider().overlay(line).padding(.leading, 56) }
                        endpointRow(endpoint)
                    }
                } else {
                    HStack(spacing: 12) {
                        symbol(state.running ? "antenna.radiowaves.left.and.right" : "tray", tint: p.secondary)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(state.running ? "正在等待服务响应" : result == nil ? "尚未执行服务检测" : "本轮没有端点响应")
                                .font(.body.weight(.medium))
                            Text(state.running ? "当前请求完成前不显示检测结论。" : result == nil
                                 ? (service == .claude ? "检测将核对 Claude 与 Anthropic 的公开入口。" : "检测将核对 ChatGPT 与 OpenAI API 的公开入口。")
                                 : "本轮未取得服务响应，请查看检测状态与原始证据。")
                                .font(.callout).foregroundStyle(p.secondary)
                        }
                        Spacer(minLength: 0)
                    }.padding(20)
                }
            }
            .background(p.surface, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(line, lineWidth: 0.7))
        }
    }

    private func endpointRow(_ endpoint: AIEndpointResult) -> some View {
        let response = GPTEndpointPresentation(endpoint)
        let tint = response.needsAttention ? p.amber : p.blue
        return HStack(alignment: .center, spacing: 12) {
            Group {
                if let brand = ServiceBrand.endpoint(endpoint.url) { BrandLogo(brand:brand,size:20) }
                else { symbol(response.symbol,tint:tint) }
            }.frame(width:28,height:32)
            VStack(alignment: .leading, spacing: 5) {
                Text(response.name).font(.body.weight(.medium))
                Text(endpoint.url).font(.system(.caption, design: .monospaced))
                    .foregroundStyle(p.secondary).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }.frame(maxWidth: .infinity, alignment: .leading)
            VStack(alignment: .trailing, spacing: 5) {
                Text(response.status).font(.system(.callout, design: .monospaced).weight(.medium))
                Text(response.detail).font(.caption)
            }.foregroundStyle(tint).frame(minWidth: 90, alignment: .trailing)
            Text(endpoint.elapsedMs.flatMap { value in
                value.isFinite && value >= 0 && value < Double(Int.max) ? "\(Int(value)) ms" : nil
            } ?? "—")
                .font(.system(.callout, design: .monospaced)).foregroundStyle(p.secondary)
                .frame(width: 64, alignment: .trailing)
        }.padding(.horizontal, 16).padding(.vertical, 16)
    }

    private var evidenceDetails: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let result, !result.errors.isEmpty {
                HStack(alignment: .top, spacing: 10) {
                    symbol("exclamationmark.triangle", tint: p.amber)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("\(result.errors.count) 项未完成信息").font(.body.weight(.medium)).foregroundStyle(p.amber)
                        Text(result.errors[0].message).font(.callout).foregroundStyle(p.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            DisclosureGroup(isExpanded: $detailsExpanded) {
                VStack(alignment: .leading, spacing: 12) {
                    if let result {
                        DetailRow(title: "开始 / 完成", value: "\(timeText(result.startedAt, date: true)) / \(timeText(result.finishedAt, date: true))", p: p, monospaced: true)
                        DetailRow(title: "出口来源", value: clean(result.exitSource) ?? "未取得", p: p)
                        DetailRow(title: "对照来源", value: clean(result.referenceIP) == nil ? "未取得" : "Cloudflare · 同轮 HTTP 请求", p: p)
                        DetailRow(title: "出口时区", value: clean(result.ipTimezone) ?? "未取得", p: p)
                        DetailRow(title: "本机时区", value: TimeZone.current.identifier, p: p)
                        ForEach(result.endpoints) { endpoint in
                            Text(endpoint.url + "\n" + endpoint.message).font(.callout).textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        ForEach(result.errors) { error in
                            Text("\(error.stage) · \(error.code)：\(error.message)").font(.callout).foregroundStyle(p.amber)
                                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        }
                        ForEach(Array(result.details.enumerated()), id: \.offset) { _, detail in
                            Text(detail).font(.callout).foregroundStyle(p.secondary)
                                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Text("服务诊断不代表 AI 应用的实际出口或账号可用性。HTTP 401 表示端点要求认证，不表示断网。网站风险评分未接入，不提供分数。")
                        .font(.callout).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
                }.padding(.top, 16)
            } label: {
                Label("检测范围与原始证据", systemImage: "doc.text.magnifyingglass")
                    .font(.callout.weight(.medium)).foregroundStyle(p.secondary)
            }
            .disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            Text("诊断结果仅反映本轮网络请求，不用于判断账号安全。")
                .font(.caption).foregroundStyle(p.secondary)
        }.padding(.horizontal, 4)
    }

    private func sectionLabel(_ text: String, symbol name: String, tint: Color? = nil) -> some View {
        HStack(spacing: 8) {
            symbol(name, tint: tint ?? style.network)
            Text(text).font(.headline)
        }
    }
    private func symbol(_ name: String, tint: Color) -> some View {
        Image(systemName: name).font(.system(size: 15, weight: .regular))
            .symbolRenderingMode(.hierarchical).foregroundStyle(tint).accessibilityHidden(true)
    }
    private func openConnections() {
        store.networkSelection.product = service.product
        store.page = .network
    }
    private func clean(_ value: String?) -> String? {
        guard let value else { return nil }
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? nil : text
    }
    private func address(_ value: String?) -> String {
        clean(value) ?? (result == nil ? "未检测" : "未取得")
    }
    private var location: String {
        guard let result else { return "归属区域 · 等待诊断结果" }
        let country = Locale(identifier: "zh_Hans").localizedString(forRegionCode: result.countryCode) ?? result.country
        var values: [String] = []
        for value in [country, result.region, result.city] where clean(value) != nil {
            if !values.contains(value) { values.append(value) }
        }
        return values.isEmpty ? "归属区域未取得" : values.joined(separator: " · ")
    }
}

/// HTTP status presentation only. In particular, 401 is a received authentication
/// response, while absent statuses and timeouts never become a positive result.
struct GPTEndpointPresentation {
    let name, status, detail, symbol: String
    let needsAttention: Bool
    init(_ endpoint: AIEndpointResult) {
        let host = URL(string: endpoint.url)?.host ?? endpoint.url
        name = host == "chatgpt.com" ? "ChatGPT" : host == "api.openai.com" ? "OpenAI API"
            : host == "claude.ai" ? "Claude" : host == "www.anthropic.com" ? "Anthropic" : host
        guard endpoint.status == "responded", let code = endpoint.httpStatus else {
            status = endpoint.status == "timeout" ? "超时" : "未完成"
            detail = "未取得有效响应"; symbol = "clock"; needsAttention = true; return
        }
        status = "HTTP \(code)"
        if code == 401 {
            detail = "需要认证"; symbol = "lock.circle"; needsAttention = false
        } else if (200..<400).contains(code) {
            detail = "已响应"; symbol = "checkmark.circle"; needsAttention = false
        } else {
            detail = code == 403 || code == 429 ? "入口限制" : "查看响应"
            symbol = "exclamationmark.circle"; needsAttention = true
        }
    }
}

private struct GPTSharedChecks: View {
    @ObservedObject var store: LeakCheckStore
    let p: Palette
    let openDNS, openRTC: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                HStack(spacing: 8) {
                    InspectorIcon(name: "network", color: InspectorStyle(p: p).network)
                    Text("本机网络检查").font(.headline)
                }
                Spacer()
                Text("独立检测 · 最近结果").font(.caption).foregroundStyle(p.secondary)
            }
            HStack(spacing: 16) {
                row("DNS 泄漏检测", state: store.dns, symbol: "network", action: openDNS)
                row("WebRTC 泄漏检测", state: store.rtc, symbol: "antenna.radiowaves.left.and.right", action: openRTC)
            }
            Text("DNS / WebRTC 是本机诊断，结果不代表 AI 应用的实际流量。")
                .font(.caption).foregroundStyle(p.secondary)
        }
    }
    private func row(_ title: String, state: LeakCheckState, symbol: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: symbol).font(.system(size: 16, weight: .regular))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(title.hasPrefix("DNS") ? InspectorStyle(p: p).network : InspectorStyle(p: p).location)
                    .frame(width: 24)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 5) {
                    Text(title).font(.body.weight(.medium)).foregroundStyle(p.text)
                    Label(state.verdict.title, systemImage: stateIcon(state.verdict.state))
                        .font(.caption).foregroundStyle(stateTint(state.verdict.state))
                }
                Spacer(minLength: 8)
                Image(systemName: "chevron.right").font(.system(size: 10, weight: .medium))
                    .foregroundStyle(p.secondary).accessibilityHidden(true)
            }.padding(16).frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
                .background(p.surface, in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(p.border.opacity(0.65), lineWidth: 0.7))
        }.buttonStyle(.plain).accessibilityLabel("查看\(title)，\(state.verdict.title)")
    }
    private func stateIcon(_ state: LeakVerdictState) -> String {
        switch state {
        case .matched: return "checkmark.circle"
        case .difference: return "exclamationmark.triangle"
        case .incomplete: return "clock"
        case .running: return "arrow.triangle.2.circlepath"
        case .cancelled: return "xmark.circle"
        case .idle, .unconfigured: return "circle.dotted"
        }
    }
    private func stateTint(_ state: LeakVerdictState) -> Color {
        switch state {
        case .matched: return p.mint
        case .difference, .incomplete: return p.amber
        case .running: return p.blue
        case .idle, .unconfigured, .cancelled: return p.secondary
        }
    }
}
