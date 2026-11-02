import SwiftUI
import WebKit

struct DNSLeakPage: View {
    @ObservedObject var store: LeakCheckStore
    let p: Palette
    var body: some View { LeakInspectorPage(kind: .dns, store: store, p: p) }
}
struct WebRTCLeakPage: View {
    @ObservedObject var store: LeakCheckStore
    let p: Palette
    var body: some View { LeakInspectorPage(kind: .webrtc, store: store, p: p) }
}

/// The existing store still owns validation, probe execution, cancellation,
/// comparison, expiry and context checks. This view only arranges their output.
private struct LeakInspectorPage: View {
    let kind: LeakKind
    @ObservedObject var store: LeakCheckStore
    let p: Palette
    @ObservedObject private var diagnosticLog = DiagnosticLogStatus.shared
    @State private var detailsExpanded = false
    @State private var localExpanded = false
    private var isDNS: Bool { kind == .dns }
    private var isIPLeak: Bool { isDNS }
    private var state: LeakCheckState { isDNS ? store.dns : store.rtc }
    private var currentProgress: String? { store.progress[kind] }
    private var currentBrowser: WKWebView? { store.browserViews[kind] }
    // The latest result remains authoritative for the verdict and backend record.
    // The display result may be the previous good sample after a collector failure.
    private var latestResult: LeakProbeResult? { state.result }
    private var result: LeakProbeResult? { state.displayResult }
    private var showingPreviousSuccessfulResult: Bool { state.displaysPreviousSuccessfulResult }
    private var style: InspectorStyle { .init(p: p) }
    private var title: String { isDNS ? "DNS 泄漏检测" : "WebRTC 泄漏检测" }
    private var expected: Binding<String> { Binding(get: { store.rtcExpected }, set: { store.rtcExpected = $0 }) }
    private var countryCodes: [String:String] { CountryIdentity.geoCodes(result?.externalJSON) }
    private var observations: [LeakObservation] { result?.observations ?? [] }
    private var reference: [LeakObservation] { observations.filter { $0.kind.lowercased() == "http" } }
    private var detected: [LeakObservation] { observations.filter { $0.kind.lowercased() != "http" } }
    private var local: [LeakObservation] { detected.filter(isLocal) }
    private var principal: [LeakObservation] { detected.filter { !isLocal($0) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            InspectorHeading(title: title,
                subtitle: isDNS ? "递归解析出口 · 与同轮公网出口国家核对" : "当前检测 WebView · ICE / STUN 与 HTTP 出口核对",
                symbol: isDNS ? "network" : "antenna.radiowaves.left.and.right",
                color: isDNS ? style.network : style.location, p: p) {
                    Button {
                        state.running ? store.cancel(kind) : store.start(kind)
                    } label: {
                        Label(state.running ? "取消检测" : "开始检测", systemImage: state.running ? "stop.fill" : "play.fill")
                            .font(.body.weight(.medium)).padding(.horizontal, 4).frame(minHeight: 28)
                    }.buttonStyle(.borderedProminent).controlSize(.large).tint(style.action)
                        .accessibilityLabel(state.running ? "取消\(title)" : "开始\(title)")
                }
            HStack(spacing:16) {
                if !isDNS {
                    Picker("检测来源",selection:Binding(get:{store.source},set:{store.changeSource($0)})) {
                        ForEach(LeakProbeSource.allCases,id: \.self) { Text($0.rawValue).tag($0) }
                    }.pickerStyle(.segmented).frame(width:280).disabled(store.dns.running || store.rtc.running)
                }
                if isDNS {
                    Picker("查询轮次",selection:$store.deepDNS) { Text("标准 · 5 轮").tag(false); Text("深度 · 8 轮").tag(true) }
                        .frame(width:180).disabled(state.running)
                }
                Spacer(minLength:0)
            }
            if state.running, let progress = currentProgress { Label(progress,systemImage:"arrow.triangle.2.circlepath").font(.callout).foregroundStyle(style.network) }
            if let browser = currentBrowser {
                CoffeeCollectorView(browser: browser, onDetach: { store.reattachBrowser($0, kind: kind) })
                    .frame(height:72).clipShape(RoundedRectangle(cornerRadius:10))
            }
            InspectorStatus(verdict: state.verdict, running: state.running, finishedAt: latestResult?.finishedAt, p: p)
            if let error = diagnosticLog.error ?? LeakDiagnosticTrace.shared.error {
                Label(error, systemImage: "exclamationmark.triangle").font(WatchTypography.caption).foregroundStyle(p.amber)
            }
            if showingPreviousSuccessfulResult, let previous = result {
                Label("本轮查询未完成；下方保留上次有效样本（" + probeTime(previous.finishedAt) + "）供核对。当前判词与启动预检仍按本轮失败结果执行。", systemImage: "clock.arrow.circlepath")
                    .font(.callout).foregroundStyle(p.amber).fixedSize(horizontal: false, vertical: true)
            }
            if latestResult?.contextChanged == true {
                Label("检测期间网络环境发生变化，本轮结果需重新核对。", systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(p.amber)
            }
            referenceAndSettings
            addresses
            if !local.isEmpty {
                DisclosureGroup(isExpanded: $localExpanded) {
                    addressList(local).padding(.top, 12)
                } label: {
                    Label("本地与 mDNS 候选（\(local.count)）", systemImage: "desktopcomputer")
                        .font(.callout.weight(.medium)).foregroundStyle(style.location)
                }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
            details
            if isDNS || store.source == .netCoffee {
                Text("检测结果在环境状态、DNS 与 WebRTC 页面共享；离开本页不会取消正在进行的采样。").font(.caption).foregroundStyle(p.secondary)
            }
            Label(isDNS ? "本机 WebView 发起查询，IPLeak 返回 DNS 观测；不代表所有 AI 应用。"
                  : "仅代表当前检测 WebView，不代表 AI 应用或其他浏览器。", systemImage: "info.circle")
                .font(.caption).foregroundStyle(p.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }.font(.body).foregroundStyle(p.text)
            .frame(maxWidth: 1120, alignment: .leading).padding(.top, 24)
    }

    private var referenceAndSettings: some View {
        InspectorPanel(p: p) {
            ViewThatFits(in: .horizontal) {
                HStack(alignment: .top, spacing: 0) {
                    referenceSummary.padding(20).frame(minWidth: 320, maxWidth: .infinity, alignment: .leading)
                    Rectangle().fill(style.border).frame(width: 1).padding(.vertical, 20)
                    settings.padding(20).frame(width: 312, alignment: .leading)
                }.fixedSize(horizontal: false, vertical: true)
                VStack(alignment: .leading, spacing: 0) {
                    referenceSummary.padding(20)
                    Divider().padding(.horizontal, 20)
                    settings.padding(20)
                }
            }
        }
    }
    private var referenceSummary: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing:8) {
                if isIPLeak { InspectorIcon(name:"globe",color:style.transport) }
                else { BrandLogo(brand:.cloudflare,size:18) }
                Text("HTTP 出口参考").font(.headline)
            }
            if reference.isEmpty {
                Text(result == nil ? "未检测" : "未取得")
                    .font(.system(size: 24, weight: .semibold, design: .monospaced))
                Text(state.running ? "等待本轮 HTTP 出口参考" : result == nil ? "开始检测后展示同轮出口地址" : "本轮没有有效的 HTTP 出口参考")
                    .font(.callout).foregroundStyle(p.secondary)
            } else {
                ForEach(reference) { item in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(item.address).font(.system(size: 24, weight: .semibold, design: .monospaced))
                            .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        if item.country != nil {
                            CountryLine(code:countryCodes[item.address],country:item.country,region:item.region,city:item.city,organization:item.isp,p:p)
                        }
                        Label(item.family.map { "IPv\($0) · HTTP 参考" } ?? "HTTP 参考", systemImage: "cloud")
                            .font(.callout).foregroundStyle(style.network)
                        Text(item.source).font(.caption).foregroundStyle(p.secondary)
                            .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            Divider().overlay(style.border)
            Label(isDNS ? "用于对照网络出口，不视为 DNS 解析器地址。"
                  : "与同轮 ICE / STUN 公网候选比较。", systemImage: "arrow.left.arrow.right")
                .font(.callout).foregroundStyle(p.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
    private var settings: some View {
        VStack(alignment: .leading, spacing: 12) {
            sectionHeading("本次诊断对照值", icon: "slider.horizontal.3", color: style.location)
            if isDNS {
                Text("自动比较同一轮 DNS 递归出口与 HTTP 公网出口的国家：同国通过；异国显示泄漏风险；任一国家缺失则本轮未完成。无需填写或确认 DNS IP 名单。")
                    .font(.caption).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
            } else {
                Text("预期出口 IP（可选）").font(.callout.weight(.medium))
                TextField("IPv4 / IPv6，以逗号分隔", text: expected)
                    .textFieldStyle(.roundedBorder).font(.system(.callout, design: .monospaced))
                    .disabled(state.running).controlSize(.large)
                    .accessibilityLabel("预期出口 IP（可选）")
                Text("留空时，与本轮 HTTP 出口参考比较。")
                    .font(.caption).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if let error = state.inputError, !error.isEmpty {
                Label(error, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(p.amber)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Divider().overlay(style.border)
            Label(isDNS ? "IPLeak DNS · IPLeak HTTP · 本机采样" : store.source == .netCoffee ? "Net.Coffee 归属 · Cloudflare HTTP · 本机采样" : "Google / Cloudflare STUN", systemImage: "server.rack")
                .font(.caption).foregroundStyle(style.transport)
            Text(isDNS ? "DNS 与 HTTP 参考均通过当前检测 WebView。" : "按当前系统路由检测，不强制 UDP 走 7890。")
                .font(.caption).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
    private var addresses: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                sectionHeading(isDNS ? "DNS 递归出口" : "出口与中继候选",
                               icon: isDNS ? "network" : "point.3.connected.trianglepath.dotted",
                               color: isDNS ? style.network : style.transport)
                Spacer()
                Text("\(principal.count) 项").font(.caption).foregroundStyle(p.secondary)
            }
            if principal.isEmpty {
                InspectorPanel(p: p) {
                    HStack(spacing: 12) {
                        InspectorIcon(name: state.running ? "arrow.triangle.2.circlepath" : "tray", color: p.secondary)
                        VStack(alignment: .leading, spacing: 5) {
                            Text(state.running ? "正在收集地址" : result == nil ? "等待首次检测" : "本轮未取得可用于对照的地址")
                                .font(.body.weight(.medium))
                            Text(result == nil ? "点击开始检测，结果会显示在这里。" : "缺少结果不能判定安全，请查看检测状态与原始证据。")
                                .font(.callout).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                        Spacer(minLength: 0)
                    }.padding(20)
                }
            } else { addressList(principal) }
        }
    }
    private func addressList(_ rows: [LeakObservation]) -> some View {
        InspectorPanel(p: p) {
            VStack(spacing: 0) {
                ForEach(Array(rows.enumerated()), id: \.offset) { index, observation in
                    if index > 0 { Divider().padding(.leading, 56) }
                    HStack(alignment: .top, spacing: 12) {
                        Group {
                            if let brand = ServiceBrand.provider(observation.isp) ?? ServiceBrand.endpoint(observation.source) { BrandLogo(brand:brand,size:18) }
                            else { InspectorIcon(name:observationIcon(observation),color:observationColor(observation)) }
                        }.frame(width:24,height:22)
                        VStack(alignment: .leading, spacing: 7) {
                            Text(observation.address).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                            if observation.country != nil || observation.isp != nil {
                                CountryLine(code:countryCodes[observation.address],country:observation.country,region:observation.region,city:observation.city,organization:observation.isp,p:p)
                            }
                            Text(observation.source).font(.caption).foregroundStyle(p.secondary).textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }.frame(maxWidth: .infinity, alignment: .leading)
                        VStack(alignment: .trailing, spacing: 6) {
                            Text(observationKind(observation.kind)).font(.callout).foregroundStyle(observationColor(observation))
                            if let family = observation.family { Text("IPv\(family)").font(.caption).foregroundStyle(p.secondary) }
                        }.frame(minWidth: 88, alignment: .trailing)
                    }.padding(16)
                }
            }
        }
    }
    private var details: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let latestResult, !latestResult.errors.isEmpty {
                Label("本轮查询失败：\(latestResult.errors[0].message)", systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(p.amber).fixedSize(horizontal: false, vertical: true)
            }
            DisclosureGroup(isExpanded: $detailsExpanded) {
                VStack(alignment: .leading, spacing: 12) {
                    if let result {
                        if showingPreviousSuccessfulResult {
                            DetailRow(title: "展示样本", value: "上次有效结果；当前判词见页面顶部", p: p)
                        }
                        DetailRow(title: "检测范围", value: result.scope, p: p)
                        DetailRow(title: "开始时间", value: probeTime(result.startedAt), p: p, monospaced: true)
                        DetailRow(title: "完成时间", value: probeTime(result.finishedAt), p: p, monospaced: true)
                        ForEach(Array(result.errors.enumerated()), id: \.offset) { _, error in
                            Text("\(error.stage) · \(error.code)：\(error.message)").font(.callout)
                                .foregroundStyle(p.amber).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        }
                        if let raw = result.externalJSON {
                            Text(isIPLeak ? "IPLeak 回执（DNS 地址、计数与归属摘要）" : "Net.Coffee 原始 API 回执（含来源、时间、HTTP 状态与未裁剪 JSON）").font(.callout.weight(.medium))
                            Text(raw).font(.system(.caption,design:.monospaced)).textSelection(.enabled).fixedSize(horizontal:false,vertical:true)
                        }
                        ForEach(Array(result.details.enumerated()), id: \.offset) { _, detail in
                            Text(detail).font(.callout).foregroundStyle(p.secondary).textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Text(isDNS ? "结果仅覆盖所选检测来源；DNS 与 HTTP 地址不要求相同，比较的是同轮实测国家。"
                         : "仅在当前检测 WebView 内采集候选；未访问摄像头或麦克风，不覆盖其他应用的 WebRTC 行为。")
                        .font(.callout).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
                }.padding(.top, 16)
            } label: {
                Label("检测范围与原始证据", systemImage: "doc.text.magnifyingglass")
                    .font(.callout.weight(.medium)).foregroundStyle(p.secondary)
            }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
        }.padding(.horizontal, 4)
    }
    private func sectionHeading(_ title: String, icon: String, color: Color) -> some View {
        HStack(spacing: 8) { InspectorIcon(name: icon, color: color); Text(title).font(.headline) }
    }
    private func isLocal(_ observation: LeakObservation) -> Bool {
        guard !isDNS else { return false }
        return observation.kind == "mdns" || (observation.kind == "host" && LeakIPAddress(observation.address)?.isPublic != true)
    }
    private func observationColor(_ observation: LeakObservation) -> Color {
        switch observation.kind {
        case "resolver": return style.network
        case "relay": return style.proxy
        case "mdns", "host": return style.location
        default: return style.transport
        }
    }
    private func observationIcon(_ observation: LeakObservation) -> String {
        switch observation.kind {
        case "resolver": return "network"
        case "relay": return "server.rack"
        case "mdns": return "lock.shield"
        case "host": return "desktopcomputer"
        default: return "antenna.radiowaves.left.and.right"
        }
    }
    private func observationKind(_ value: String) -> String {
        switch value {
        case "resolver": return "递归解析器"
        case "srflx": return "STUN 候选"
        case "prflx": return "对端反射候选"
        case "relay": return "TURN 中继"
        case "host": return "主机候选"
        case "mdns": return "mDNS"
        default: return value
        }
    }
    private func probeTime(_ epoch: Double) -> String {
        epoch.isFinite && epoch > 0 ? timeText(epoch, date: true) : "未取得"
    }
}

struct CoffeeCollectorView: NSViewRepresentable {
    let browser: WKWebView
    var onDetach: ((WKWebView) -> Void)? = nil
    final class Coordinator {
        let onDetach: ((WKWebView) -> Void)?
        init(_ onDetach: ((WKWebView) -> Void)?) { self.onDetach = onDetach }
    }
    func makeCoordinator() -> Coordinator { Coordinator(onDetach) }
    func makeNSView(context: Context) -> WKWebView { browser }
    func updateNSView(_ nsView: WKWebView, context: Context) {}
    static func dismantleNSView(_ nsView: WKWebView, coordinator: Coordinator) { coordinator.onDetach?(nsView) }
}
