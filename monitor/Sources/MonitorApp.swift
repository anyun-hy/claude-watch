import AppKit
import SwiftUI
import UserNotifications

struct MonitorView: View {
    @ObservedObject var store: MonitorStore
    let startMonitoring: Bool
    let restoresNavigation: Bool
    let refreshAction: (() -> Void)?
    @AppStorage("darkAppearance") private var dark = true
    @AppStorage("selectedPage") private var savedPage = Page.environment.rawValue
    @Environment(\.controlActiveState) private var controlActiveState
    @State private var sidebarVisibility: NavigationSplitViewVisibility = .all
    @State private var showProxyDetails = false

    init(store: MonitorStore, startMonitoring: Bool = true, restoresNavigation: Bool = true, refreshAction: (() -> Void)? = nil) {
        self.store = store
        self.startMonitoring = startMonitoring
        self.restoresNavigation = restoresNavigation
        self.refreshAction = refreshAction
    }

    private var p: Palette { Palette(dark: dark) }
    private var sidebarIconTint: Color { Color(red: 0, green: 149.0 / 255, blue: 1) }
    private func sidebarForeground(selected: Bool, icon: Bool = false) -> Color {
        if selected && controlActiveState == .key { return .white }
        return icon ? sidebarIconTint : p.text
    }
    private var selection: Binding<Page?> {
        Binding(get: { store.page }, set: { if let page = $0 { store.page = page } })
    }
    private var statusTint: Color { store.error != nil ? p.amber : !store.automatic ? p.secondary : store.live ? p.mint : p.amber }
    private var statusTitle: String {
        if store.error != nil { return "本次同步未完成" }
        return !store.automatic && store.snapshot != nil ? "界面同步已暂停" : store.heroTitle
    }
    private var statusDetail: String {
        if store.error != nil { return "当前状态未能确认，可手动刷新重试。已有记录保留为上次采样。" }
        if !store.automatic { return "后台监控独立运行。手动刷新可更新当前显示。" }
        guard let snapshot = store.snapshot else { return "正在读取后台状态与网络快照。" }
        if !store.live { return snapshot.health.detail }
        return snapshot.health.mode == "ACTIVE"
            ? "正在观察当前会话及关联进程的活动。"
            : "正在观察 AI 应用进程、后台活动与代理入口。"
    }

    var body: some View {
        NavigationSplitView(columnVisibility: $sidebarVisibility) {
            sidebar.navigationSplitViewColumnWidth(min: 172, ideal: 188, max: 228)
        } detail: {
            VStack(spacing: 0) {
                if !store.page.isManualCheck { pageHeader }
                if let error = store.error {
                    InlineNotice(title: "暂时无法同步检测数据", detail: error,
                                 symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                        .padding(.horizontal, 20).padding(.bottom, 12)
                }
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        switch store.page {
                        case .overview: overview
                        case .network: network
                        case .processes: ProcessActivityPage(store: store, p: p)
                        case .events: EventTimelinePage(store: store, p: p)
                        case .dns: DNSLeakPage(store: store.leakChecks, p: p, managePolicy: { store.page = .protection })
                        case .webrtc: WebRTCLeakPage(store: store.leakChecks, p: p)
                        case .claudeAI: AIInspectorPage(service: .claude, store: store, probes: store.aiChecks, p: p)
                        case .ipScore: NetCoffeeScorePage(store: store.netCoffee, p: p)
                        case .gptAI: AIInspectorPage(service: .gpt, store: store, probes: store.aiChecks, p: p)
                        case .environment: taskPage(.environment)
                        case .switcher: taskPage(.accounts)
                        case .protection: taskPage(.protection)
                        }
                    }.frame(maxWidth: 1280).frame(maxWidth: .infinity)
                        .padding(.horizontal, 20).padding(.bottom, 20)
                }
                if store.page.isPrimary { SwitcherFeedbackRegion(store: store.switcher, p: p) }
                footer
            }.background(p.background)
        }
        .navigationSplitViewStyle(.balanced)
        .navigationTitle("Claude Watch")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                HStack(spacing: 8) {
                    Text("自动检测与刷新").font(WatchTypography.caption).foregroundStyle(p.secondary)
                    Toggle("自动检测环境并刷新后台数据", isOn: $store.automatic).labelsHidden().toggleStyle(.switch)
                        .controlSize(.mini)
                }.fixedSize().help("自动更新环境、DNS、WebRTC 与后台数据；关闭后保镖仍继续运行。")
                Button {
                    if let refreshAction { refreshAction() }
                    else { store.refresh(full: true, manual: true) }
                } label: {
                    HStack(spacing: 6) {
                        ZStack {
                            Image(systemName: "arrow.clockwise").opacity(store.refreshing ? 0 : 1)
                            if store.refreshing { ProgressView().controlSize(.mini).scaleEffect(0.7) }
                        }.frame(width: 14, height: 14)
                        Text("刷新后台数据")
                    }.font(WatchTypography.caption).frame(width: 104, height: 22)
                }.disabled(store.refreshing).keyboardShortcut("r", modifiers: .command)
                    .help("读取最新后台数据，自动同步不会改变按钮状态")
            }
        }
        .foregroundStyle(p.text)
        .preferredColorScheme(dark ? .dark : .light)
        .frame(minWidth: 1000, minHeight: 680)
        .onAppear {
            if restoresNavigation { store.page = Page.restored(savedPage) }
            if startMonitoring { store.start() }
        }
        .onChange(of: store.page) { _, page in if restoresNavigation { savedPage = page.rawValue } }
    }

    private func taskPage(_ section: SwitcherSection) -> some View {
        SwitcherPage(store: store.switcher, p: p, section: section, navigate: { target in
            store.page = target == .environment ? .environment : target == .accounts ? .switcher : .protection
        }, openLeakCheck: { kind in store.page = kind == .dns ? .dns : .webrtc }, leakChecks: store.leakChecks, netCoffee: store.netCoffee, finished: { store.page = .environment })
    }

    private func navRow(_ page: Page) -> some View {
        let selected = store.page == page
        return HStack(spacing: 8) {
            Image(systemName: page.symbol)
                .font(.system(size: 14, weight: .regular))
                .foregroundStyle(sidebarForeground(selected: selected, icon: true))
                .frame(width: 18, height: 18)
            Text(page.rawValue)
        }
        .font(WatchTypography.body)
        .fontWeight(selected ? .semibold : .regular)
        .foregroundStyle(sidebarForeground(selected: selected))
        .padding(.vertical, 4)
        .tag(page)
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 8) {
                    Image(systemName: "shield.lefthalf.filled").font(.system(size: 19)).foregroundStyle(p.mint)
                    Text("Claude Watch").font(.system(size: 14, weight: .semibold)).lineLimit(1)
                    Spacer(minLength: 0)
                }
                Text("Claude · ChatGPT / Codex").font(WatchTypography.small).foregroundStyle(p.secondary).lineLimit(1)
            }.padding(.horizontal, 15).padding(.top, 16).padding(.bottom, 15)
            List(selection: selection) {
                Section {
                    ForEach(Page.primaryPages, id: \.self) { page in navRow(page) }
                } header: {
                    Text("日常使用").foregroundStyle(p.secondary)
                }
                Section {
                    ForEach(Page.monitorPages, id: \.self) { page in navRow(page) }
                } header: {
                    Text("监控与记录").foregroundStyle(p.secondary)
                }
                Section {
                    ForEach(Page.diagnosticPages, id: \.self) { page in
                        let selected = store.page == page
                        HStack(spacing: 8) {
                            Group {
                                if page == .claudeAI || page == .gptAI { BrandLogo(brand:page == .claudeAI ? .claude : .chatgpt,size:14) }
                                else { InspectorIcon(name:page.symbol,color: sidebarForeground(selected: selected, icon: true)) }
                            }.frame(width:18,height:18)
                            Text(page.rawValue)
                        }
                        .font(WatchTypography.body)
                        .fontWeight(selected ? .semibold : .regular)
                        .foregroundStyle(sidebarForeground(selected: selected))
                        .padding(.vertical, 4).tag(page)
                    }
                } header: {
                    Text("网络检测").foregroundStyle(p.secondary)
                }
            }.listStyle(.sidebar).scrollContentBackground(.hidden)
            VStack(alignment: .leading, spacing: 12) {
                Divider()
                HStack(spacing: 7) {
                    Circle().fill(statusTint).frame(width: 6, height: 6)
                    Text(store.error != nil ? "后台数据读取未完成" : !store.automatic ? "界面刷新已暂停" : store.live ? "采集后台心跳正常" : "等待后台数据")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                }
                HStack {
                    Text(dark ? "深色外观" : "浅色外观").font(WatchTypography.caption).foregroundStyle(p.secondary)
                    Spacer()
                    Button { dark.toggle() } label: {
                        Image(systemName: dark ? "sun.max" : "moon").font(.system(size: 14)).frame(width: 25, height: 24)
                    }.buttonStyle(.borderless).help("切换浅色与深色外观")
                        .accessibilityLabel("切换外观")
                }
            }.padding(.horizontal, 15).padding(.bottom, 15)
        }
        .background(p.sidebar)
    }

    private var pageHeader: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Text(store.page.rawValue).font(WatchTypography.pageTitle)
                Text(pageCaption).font(WatchTypography.body).foregroundStyle(p.secondary)
            }
            Spacer(minLength: 12)
            Text(store.page.isManualCheck ? "手动检测" : store.page == .network ? "连接管理" : "只读监控").font(WatchTypography.small).foregroundStyle(p.secondary)
                .padding(.horizontal, 9).padding(.vertical, 5)
                .background(p.elevated, in: Capsule())
        }.padding(.horizontal, 22).padding(.top, 20).padding(.bottom, 18)
    }
    private var pageCaption: String {
        switch store.page {
        case .overview: return "后台状态、当前检测结果与需要关注的事项"
        case .network: return "查看已观测的连接路径，区分实际证据与配置参考"
        case .processes: return "最近采样到的 AI 应用及关联进程"
        case .events: return "检索最近的监控事件与原始记录"
        case .dns: return "采集递归出口，按预期解析器核对；无结果保持未完成"
        case .webrtc: return "比较当前检测 WebView 的 ICE/STUN 候选与 HTTP 出口"
        case .claudeAI: return "核对 Claude 域名的代理诊断、入口响应与现有连接"
        case .ipScore: return "读取 Net.Coffee 评分与原始 IP 资料"
        case .gptAI: return "核对 ChatGPT 与 API 入口响应，并查看现有连接证据"
        case .switcher: return Page.switcher.caption
        case .environment: return Page.environment.caption
        case .protection: return Page.protection.caption
        }
    }
    private var footer: some View {
        HStack(spacing: 7) {
            Circle().fill(statusTint).frame(width: 5, height: 5)
            Text(store.error != nil ? "本次同步未完成" : !store.automatic ? "已暂停界面同步" : store.live ? "后台数据自动同步" : "等待有效状态")
            Spacer()
            Text(pageSampleTime)
                .monospacedDigit()
        }.font(WatchTypography.small).foregroundStyle(p.secondary)
            .padding(.horizontal, 20).frame(height: 31)
            .background(p.surface.opacity(0.5))
            .overlay(alignment: .top) { Rectangle().fill(p.border.opacity(0.55)).frame(height: 1) }
    }
    private var pageSampleTime: String {
        if store.page == .environment { return store.switcher.currentEnvironment.map { "环境采样于 " + timeText($0.observed_at) } ?? "环境尚未采样" }
        if store.page == .switcher { return store.switcher.currentPolicyEvaluation.map { "同轮检测于 " + timeText($0.observed_at) } ?? "等待当前启动要求检测" }
        if store.page == .protection { return store.switcher.background.map { "状态读取于 " + timeText($0.observed_at) } ?? "后台状态尚未读取" }
        return store.snapshot.map { "后台数据采样于 " + timeText($0.capturedAt) } ?? "等待首次读取"
    }

    private var overview: some View {
        Group {
            Surface(p, padding: 18) {
                HStack(spacing: 15) {
                    Image(systemName: "gearshape.2")
                        .font(.system(size: 26, weight: .regular)).foregroundStyle(statusTint)
                        .frame(width: 48, height: 48).background(statusTint.opacity(0.08), in: RoundedRectangle(cornerRadius: 13))
                    VStack(alignment: .leading, spacing: 6) {
                        Text("采集后台 · " + statusTitle).font(WatchTypography.title)
                        Text(statusDetail).font(WatchTypography.body).foregroundStyle(p.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 16)
                    VStack(alignment: .trailing, spacing: 7) {
                        Badge(text: store.error != nil ? "读取失败" : !store.automatic ? "界面刷新暂停" : store.live ? "心跳正常" : "待核对", color: statusTint)
                        Text(verbatim: store.snapshot?.health.pid.map { "服务 PID \($0)" } ?? "读取服务信息")
                            .font(WatchTypography.mono).foregroundStyle(p.secondary)
                    }
                }
            }
            HStack(spacing: 12) {
                metric("AI 应用进程", value: store.snapshot.map { String($0.processes.count) } ?? "—",
                       detail: store.snapshot == nil ? "等待首次采样" : "最近采样的进程数量", symbol: "waveform.path", tint: p.blue)
                metric("本机代理入口", value: store.entryTitle,
                       detail: store.proxy?.endpoint.replacingOccurrences(of: "http://", with: "") ?? "等待代理快照",
                       symbol: "cable.connector", tint: store.proxy?.entryState == "verified" ? p.mint : p.amber)
                metric("实际代理链", value: store.chainTitle,
                       detail: store.proxy?.flows.isEmpty == false ? "以选中连接的证据为准" : "使用受监控应用后产生连接样本",
                       symbol: "point.3.connected.trianglepath.dotted", tint: store.chainTitle == "样本匹配" ? p.mint : p.blue)
            }
            HStack(alignment: .top, spacing: 16) {
                Surface(p) {
                    SectionHeading(title: "检测提示", p: p).padding(.bottom, 13)
                    VStack(spacing: 9) {
                        if let error = store.error {
                            InlineNotice(title: "本次同步未完成", detail: error, symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                        } else if !store.automatic {
                            InlineNotice(title: "界面同步已暂停", detail: "可点击刷新读取最新结果。", symbol: "pause.circle", tint: p.secondary, p: p)
                        } else if store.proxy == nil {
                            InlineNotice(title: "代理快照尚未就绪", detail: store.proxyError ?? "等待后台提供有效采样。",
                                         symbol: "clock", tint: p.amber, p: p)
                        } else if store.proxy?.selectionDiffers == true {
                            InlineNotice(title: "当前选择与参照节点不同", detail: "请在代理与连接页核对实际路径。",
                                         symbol: "arrow.triangle.branch", tint: p.amber, p: p)
                        } else if store.proxy?.coversProxy != true {
                            InlineNotice(title: "入口与控制器尚未关联", detail: "当前控制器数据不能证明该入口的流量路径。",
                                         symbol: "link", tint: p.amber, p: p)
                        }
                        let baseline = SessionBaselinePresentation.make(evidence: store.switcher.sessionDisplayEvidence,
                                                                       now: store.now.timeIntervalSince1970)
                        InlineNotice(title: baseline.title, detail: baseline.detail, symbol: baseline.symbol,
                                     tint: baseline.tone == "danger" ? p.red : baseline.tone == "warning" ? p.amber : baseline.tone == "success" ? p.mint : p.blue, p: p)
                        if store.snapshot?.monitoredApps?.isEmpty == false && !multiProductCoverageDeclared {
                            InlineNotice(title: "Codex 与 ChatGPT 需要更新后台", detail: "当前后台没有声明 Codex 与 ChatGPT 的采集能力；界面不会把未采样到的 0 个进程显示为已覆盖。",
                                         symbol: "arrow.down.app", tint: p.amber, p: p)
                        }
                    }
                    Button { store.page = .network } label: { Label("查看连接证据", systemImage: "arrow.right") }
                        .buttonStyle(.borderless).font(WatchTypography.caption).foregroundStyle(p.blue).padding(.top, 13)
                }
                Surface(p) {
                    SectionHeading(title: "服务信息", p: p).padding(.bottom, 10)
                    DetailRow(title: "最近心跳", value: heartbeatValue, p: p, monospaced: true)
                    DetailRow(title: "登录自启", value: store.snapshot.map { $0.autoStart ? "已配置" : "未配置" } ?? "读取中", p: p)
                    DetailRow(title: "异常退出恢复", value: store.snapshot.map { $0.keepAlive ? "已配置" : "未配置" } ?? "读取中", p: p)
                    DetailRow(title: "系统提醒", value: store.snapshot?.health.alerts ?? "读取中", p: p)
                    Text("关闭窗口后，已安装的后台服务继续运行。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary).lineSpacing(3).padding(.top, 11)
                    Button("查看保镖与任务实际状态") { store.page = .protection }.buttonStyle(.borderless).font(WatchTypography.caption).padding(.top, 8)
                }
            }
            Surface(p) {
                HStack {
                    SectionHeading(title: "最近事件", p: p)
                    Spacer()
                    Button("查看全部") { store.page = .events }.buttonStyle(.borderless)
                        .font(WatchTypography.caption).foregroundStyle(p.blue)
                }.padding(.bottom, 8)
                if let events = store.snapshot?.events, !events.isEmpty {
                    ForEach(Array(events.prefix(4))) { EventTimelineRow(event: $0, p: p, compact: true) }
                } else if let error = store.snapshot?.eventError {
                    Text(error).font(WatchTypography.body).foregroundStyle(p.amber).padding(.vertical, 16)
                } else {
                    Text(store.snapshot == nil ? "正在读取事件记录…" : "暂无可显示的事件记录。")
                        .font(WatchTypography.body).foregroundStyle(p.secondary).padding(.vertical, 16)
                }
            }
        }
    }

    private var heartbeatValue: String {
        guard let snapshot = store.snapshot, let age = snapshot.health.heartbeatAge else { return "待确认" }
        return "\(Int(max(0, age + store.now.timeIntervalSince1970 - snapshot.capturedAt))) 秒前"
    }
    private var multiProductCoverageDeclared: Bool {
        let apps = Set(store.snapshot?.monitoredApps ?? [])
        return apps.contains("codex") && apps.contains("chatgpt")
    }
    private func metric(_ title: String, value: String, detail: String, symbol: String, tint: Color) -> some View {
        Surface(p, padding: 15) {
            VStack(alignment: .leading, spacing: 9) {
                HStack {
                    Text(title).font(WatchTypography.caption).foregroundStyle(p.secondary)
                    Spacer()
                    Image(systemName: symbol).font(.system(size: 15)).foregroundStyle(tint)
                }
                Text(value).font(.system(size: 21, weight: .semibold, design: .rounded)).monospacedDigit()
                Text(detail).font(WatchTypography.caption).foregroundStyle(p.secondary).lineLimit(2)
            }.frame(minHeight: 83, alignment: .topLeading)
        }
    }

    private var network: some View {
        Group {
            ConnectionGraphView(store: store, p: p)
            ConnectionInventoryView(store: store, p: p)
            Surface(p) {
                DisclosureGroup(isExpanded: $showProxyDetails) {
                    VStack(alignment: .leading, spacing: 0) {
                        if let proxy = store.proxy {
                            DetailRow(title: "本机入口", value: proxy.endpoint, p: p, monospaced: true)
                            DetailRow(title: "监听进程", value: proxy.listenerPID.map { "PID \($0)" } ?? "待确认", p: p, monospaced: true)
                            DetailRow(title: "程序路径", value: proxy.listenerPath, p: p, monospaced: true)
                            DetailRow(title: "核对结果", value: proxy.entryReason, p: p)
                            Divider().padding(.vertical, 8)
                            DetailRow(title: "采样控制器模式", value: modeName(proxy.mode), p: p)
                            DetailRow(title: "海外AI 分组配置", value: proxy.selectedNode, p: p)
                            DetailRow(title: "GLOBAL 配置", value: proxy.globalNode, p: p)
                            DetailRow(title: "参照节点", value: proxy.expectedNode, p: p)
                            DetailRow(title: "参照方式", value: proxy.pinned ? "已保存到环境基线" : "随 TAG 分组选择，尚未固定", p: p)
                            DetailRow(title: "入口覆盖", value: proxy.coversProxy ? "控制器已关联此入口" : "尚未确认", p: p)
                            DetailRow(title: "网络采样", value: timeText(proxy.observedAt, date: true), p: p, monospaced: true)
                        } else {
                            Text(store.proxyError ?? "等待有效的后台代理快照。").font(WatchTypography.body)
                                .foregroundStyle(p.secondary).padding(.vertical, 12)
                        }
                    }.padding(.top, 12)
                } label: {
                    SectionHeading(title: "代理详情", caption: "查看监听者、控制器和配置参考", p: p)
                }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
            Label("入口验证和节点配置不能单独证明 DNS 出口；未采集的信息保持待确认。", systemImage: "info.circle")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
                .fixedSize(horizontal: false, vertical: true).padding(.horizontal, 3)
        }
    }

}

func modeName(_ mode: String) -> String {
    switch mode {
    case "global": return "全局模式"
    case "rule": return "规则模式"
    case "direct": return "直连模式"
    default: return "待确认"
    }
}

func timeText(_ epoch: Double, date: Bool = false) -> String {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "zh_CN")
    formatter.dateFormat = date ? "MM-dd HH:mm:ss" : "HH:mm:ss"
    return formatter.string(from: Date(timeIntervalSince1970: epoch))
}

final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate, ObservableObject {
    @Published var notificationTarget: String?
    static func notificationPage(_ target: String?) -> Page? {
        let pages: [String: Page] = ["events": .events, "environment": .environment, "protection": .protection]
        guard let target else { return nil }
        return pages[target]
    }
    func applicationWillFinishLaunching(_ notification: Notification) {
        UNUserNotificationCenter.current().delegate = self
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        if let url = Bundle.main.url(forResource: "AppIcon", withExtension: "icns"),
           let icon = NSImage(contentsOf: url) {
            NSApp.applicationIconImage = icon
        }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            if settings.authorizationStatus == .notDetermined {
                center.requestAuthorization(options: [.alert, .sound]) { _, _ in }
            }
        }
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .list, .sound])
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                withCompletionHandler completionHandler: @escaping () -> Void) {
        guard response.actionIdentifier == UNNotificationDefaultActionIdentifier,
              let target = response.notification.request.content.userInfo["destination"] as? String,
              Self.notificationPage(target) != nil else {
            completionHandler(); return
        }
        DispatchQueue.main.async {
            self.notificationTarget = target
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first(where: { $0.canBecomeKey })?.makeKeyAndOrderFront(nil)
            completionHandler()
        }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

#if !UI_REVIEW
struct ClaudeWatchApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var store: MonitorStore
    @StateObject private var initialization: FirstRunInitialization
    @MainActor init() {
        let store = MonitorStore()
        let storage = InitializationStorage()
        _store = StateObject(wrappedValue: store)
        _initialization = StateObject(wrappedValue: FirstRunInitialization(checks: FirstRunChecks(store: store),
            completed: storage.isComplete(), saveCompletion: { try storage.complete() }))
    }
    var body: some Scene {
        WindowGroup("Claude Watch") {
            MonitorEntryView(store: store, initialization: initialization)
                .onReceive(delegate.$notificationTarget) { target in
                    guard let page = AppDelegate.notificationPage(target) else { return }
                    UserDefaults.standard.set(page.rawValue, forKey: "selectedPage")
                    store.page = page
                }
        }
            .defaultSize(width: 1240, height: 820)
            .windowStyle(.titleBar)
            .windowToolbarStyle(.unifiedCompact)
            .commands {
                CommandGroup(replacing: .newItem) {}
                CommandMenu("页面") {
                    ForEach(Array(Page.orderedPages.enumerated()), id: \.element) { index, page in
                        if index < 10 {
                            Button(page.rawValue) { store.page = page }
                                .keyboardShortcut(KeyEquivalent(Character(index == 9 ? "0" : String(index + 1))), modifiers: .command)
                        } else { Button(page.rawValue) { store.page = page } }
                    }.disabled(!initialization.entered)
                }
            }
    }
}

@main
enum ClaudeWatchMain {
    @MainActor static func main() {
        if CommandLine.arguments.dropFirst().first == "--notification-deliver" {
            WatchNotificationWorker.run(arguments: CommandLine.arguments)
        }
        ClaudeWatchApp.main()
    }
}
#endif
