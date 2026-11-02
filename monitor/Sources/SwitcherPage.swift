import AppKit
import SwiftUI

enum SwitcherSection: String, CaseIterable {
    case environment = "环境状态", accounts = "启动与账号", protection = "后台保护"
    var caption: String {
        switch self {
        case .environment: return "自动识别代理，按本轮实测出口核对地区、日期与时区；英文语言独立保持。"
        case .accounts: return "查看 Claude 启动条件，启动应用或切换本地资料槽位。"
        case .protection: return "分别核对两套保镖、时区守护和更新任务的实际状态。"
        }
    }
}

struct SwitcherPage: View {
    @ObservedObject var store: SwitcherStore
    let p: Palette
    var section: SwitcherSection = .environment
    var navigate: (SwitcherSection) -> Void = { _ in }
    var openLeakCheck: (LeakKind) -> Void = { _ in }
    var leakChecks: LeakCheckStore? = nil
    var netCoffee: NetCoffeeStore? = nil
    let finished: () -> Void
    @State private var showEnvironmentAdjustment = false
    @State private var showSettings = false
    @State private var showSource = false
    @State private var showMigration = false
    @State private var showDiagnostics = false
    @State private var showAuditHistory = false
    @State private var showLoginInfo = false
    @State private var showProxyAddress = false
    @State private var showReview = false
    @State private var showLogs = false
    @State private var confirmation = false
    @State private var pendingTitle = ""
    @State private var pendingMessage = ""
    @State private var pendingAction = "确认"
    @State private var pendingDestructive = false
    @State private var pendingArguments: [String] = []
    @State private var applyingSetup = false

    private func confirm(_ title: String, _ message: String, _ args: [String], action: String, destructive: Bool = false) {
        pendingTitle = title; pendingMessage = message; pendingArguments = args
        pendingAction = action; pendingDestructive = destructive; applyingSetup = false; confirmation = true
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            header
            if store.hasUnsavedSettings {
                InlineNotice(title: "有未保存的工具设置", detail: "先保存或撤销草稿，再进行启动、切换或应用变更。实际后台状态仍按已保存设置展示。", symbol: "pencil.circle", tint: p.amber, p: p)
            }
            switch section {
            case .environment: environmentContent
            case .accounts: accountsContent
            case .protection: protectionContent
            }
        }.padding(.top, 24)
            .task(id: section) {
                if !store.loaded { await store.load() }
                await store.refreshBackground()
                if section == .accounts { await store.refreshCurrentLogin(force: true) }
                if section == .protection {
                    while !Task.isCancelled {
                        do { try await Task.sleep(nanoseconds: 10_000_000_000) } catch { break }
                        await store.refreshBackground()
                    }
                }
            }
            .alert(pendingTitle, isPresented: $confirmation) {
                Button("取消", role: .cancel) {}
                Button(pendingAction, role: pendingDestructive ? .destructive : nil) {
                    Task {
                        if applyingSetup { await store.applyEnvironment() }
                        else { await store.perform(pendingArguments) }
                        await store.refreshBackground()
                        if !store.failure && pendingArguments.contains("switch") &&
                            store.isOn(Setting.returnToOverview) { finished() }
                    }
                }
            } message: { Text(pendingMessage) }
            .sheet(isPresented: $showReview) { changeReview }
            .sheet(isPresented: $showLogs) { logSheet }
    }
    private var header: some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 7) {
                Text(section.rawValue).font(WatchTypography.pageTitle)
                Text(section.caption).font(WatchTypography.body).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
                if section != .environment && store.busy {
                    Label(store.activity.isEmpty ? "正在读取…" : store.activity, systemImage: "hourglass")
                        .font(WatchTypography.caption).foregroundStyle(p.blue)
                }
            }
            Spacer(minLength: 8)
            if section == .environment {
                EnvironmentDetectionControl(reading: store.readingEnvironment, disabled: store.busy && !store.readingEnvironment) {
                    if store.readingEnvironment { store.cancelCurrentDetection() }
                    else { Task { await store.detectCurrentEnvironment() } }
                }
                .help(store.readingEnvironment
                      ? (store.activity.isEmpty ? "正在检测环境；点击取消本轮检测。" : store.activity + "；点击取消本轮检测。")
                      : "重新读取系统、检测出口并核对环境。")
            } else if section == .protection {
                Button { Task { await store.refreshBackground() } } label: { Label("刷新状态", systemImage: "arrow.clockwise") }.disabled(store.busy)
            }
        }
    }
    private var environmentContent: some View {
        Group {
            auditPanel
            Surface(p) {
                DisclosureGroup("需要调整环境时：核对候选与具体变更", isExpanded: $showEnvironmentAdjustment) {
                    environmentAdjustment.padding(.top, 14)
                }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
            Surface(p) {
                DisclosureGroup("独立代理诊断", isExpanded: $showDiagnostics) { diagnosticPanel.padding(.top, 14) }
                    .disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
        }
    }
    private var auditPanel: some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 12) {
                SectionHeading(title: "本轮环境检测", caption: "以下为实测状态。启动条件按已接受策略单独检查，不使用这里的结果直接放行。", p: p)
                if !store.detectionError.isEmpty {
                    InlineNotice(title: "本轮检测未完成", detail: store.detectionError, symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                }
                if !store.sourceNotices.isEmpty {
                    InlineNotice(title: "数据源状态", detail: store.sourceNotices.map { $0.title + "：" + $0.detail }.joined(separator: "\n"),
                                 symbol: "antenna.radiowaves.left.and.right", tint: sourceNoticeTint(store.sourceNotices), p: p)
                }
                if let result = store.currentEnvironment {
                    if let recommendation = EnvironmentModeRecommendation.evaluate(result.display_facts?.local?.rules) {
                        InlineNotice(title: recommendation.title, detail: recommendation.detail,
                                     symbol: "lightbulb", tint: p.blue, p: p)
                    }
                    SessionProtectionStatusView(value: store.sessionDisplay, p: p)
                    if let facts = result.facts, facts.state == "fail" {
                        InlineNotice(title: "当前环境风险", detail: facts.risks?.compactMap { $0.reason ?? $0.id }.joined(separator: "\n") ?? "本轮环境检测发现风险。",
                                     symbol: "exclamationmark.shield", tint: p.red, p: p)
                    }
                    if let transition = result.context_transition, transition.state != "stable" {
                        InlineNotice(title: transition.state == "changed" ? "检测期间环境已变化" : "环境采样暂不可用",
                                     detail: contextTransitionDetail(transition),
                                     symbol: "arrow.triangle.2.circlepath", tint: p.amber, p: p)
                    }
                    if result.candidates.count > 1 {
                        InlineNotice(title: "检测到多个运行中的代理候选", detail: result.candidates.joined(separator: "、") + "。请核对实际监听入口与路由后重新检测；当前保持未确认。", symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                    }
                    EnvironmentSummaryStrip(result: result, p: p,
                        stale: result.expires_at < Date().timeIntervalSince1970 || store.currentEnvironmentIsHistorical,
                        previousObserved: store.previousEnvironment?.observed_at)
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let expired = result.expires_at < context.date.timeIntervalSince1970
                        let historical = expired || store.currentEnvironmentIsHistorical
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(spacing: 12) {
                                stateCount(result.count("ok"), "核对", "checkmark.circle.fill", historical ? p.secondary : p.mint)
                                stateCount(result.count("fail"), "需处理", "xmark.octagon.fill", historical ? p.secondary : p.red)
                                stateCount(result.count("unknown"), "未取得", "questionmark.circle.fill", historical ? p.secondary : p.amber)
                                stateCount(result.count("warn"), "提示", "exclamationmark.triangle.fill", historical ? p.secondary : p.amber)
                                stateCount(result.count("info"), "已读取", "info.circle.fill", p.secondary)
                                stateCount(result.count("cached"), "上次有效", "clock.arrow.circlepath", p.secondary)
                            }
                            HStack {
                                Label("采样于 " + timeLabel(result.observed_at), systemImage: "clock")
                                Spacer()
                                if historical {
                                    Label(expired ? "历史样本 · 请重新检测" :
                                          store.detectionError.isEmpty ? "上下文已变化 · 上次样本仅供参考" : "本轮检测未完成 · 上次样本仅供参考",
                                          systemImage: "clock.badge.exclamationmark").foregroundStyle(p.amber)
                                }
                            }.font(WatchTypography.small).foregroundStyle(p.secondary)
                            let previousRows = Dictionary(store.previousEnvironment.map { $0.rows.map { ($0.id, $0) } } ?? [],
                                                          uniquingKeysWith: { first, _ in first })
                            LazyVGrid(columns: [GridItem(.adaptive(minimum: 310), spacing: 10, alignment: .top)], spacing: 10) {
                                ForEach(result.rows) { row in
                                    EnvironmentCheckTile(row: row, p: p, stale: historical, previous: previousRows[row.id],
                                                         flags: row.id == "dns" ? dnsRecursiveFlags(leakChecks) : nil)
                                }
                                if let local = result.display_facts?.local { EnvironmentModeTile(local: local, p: p, stale: historical) }
                                if let leakChecks { EnvironmentWebRTCTile(state: leakChecks.rtc, p: p, stale: historical, open: { openLeakCheck(.webrtc) }) }
                            }
                        }
                    }
                    if !store.webRTCReceiptError.isEmpty {
                        InlineNotice(title: "WebRTC 保护判定未提交", detail: store.webRTCReceiptError,
                                     symbol: "exclamationmark.shield", tint: p.amber, p: p)
                    }
                    Label("悬停查看完整依据 · 点击固定 · Esc 关闭", systemImage: "cursorarrow").font(WatchTypography.small).foregroundStyle(p.secondary)
                    Button { navigate(.accounts) } label: { Label("查看启动条件与账号", systemImage: "arrow.right") }.buttonStyle(.borderless)
                    DisclosureGroup("检测范围与数据来源") {
                        Text(result.message).padding(.top, 6)
                        Text("本次检测会请求出口、DNS、STUN 与服务响应，不携带账号凭据，也不保存候选为目标。受控启动的联网预检有独立开关。")
                        Text("DNS 与 UDP/STUN 为受控启动必检；国家相同不能替代实际出口与代理路径校验。WebRTC 检测只覆盖应用内 WebView，不能用来替其他应用作出无泄漏保证。")
                    }.font(WatchTypography.caption).foregroundStyle(p.secondary)
                    if !store.dnsReceiptError.isEmpty {
                        InlineNotice(title: "DNS 结果尚未同步到启动预检", detail: store.dnsReceiptError, symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                    }
                    if let netCoffee { EnvironmentIPQualitySummary(store: netCoffee, environment: result, p: p) }
                } else {
                    Label(store.busy ? "正在读取系统与检测出口…" : "尚无本轮样本。点击重新检测。", systemImage: "network").font(WatchTypography.body).foregroundStyle(p.secondary)
                }
            }
        }
    }
    private func stateCount(_ count: Int, _ title: String, _ symbol: String, _ tint: Color) -> some View {
        Label("\(count) \(title)", systemImage: symbol)
            .font(WatchTypography.caption)
            .foregroundStyle(count > 0 ? tint : p.secondary)
            .padding(.horizontal, 9).padding(.vertical, 4)
            .background((count > 0 ? tint : p.secondary).opacity(count > 0 ? 0.12 : 0.07), in: Capsule())
            .overlay(Capsule().strokeBorder((count > 0 ? tint : p.secondary).opacity(0.30), lineWidth: 1))
            .accessibilityLabel("\(title) \(count) 项")
    }
    /// Recursive-resolver countries from the latest DNS probe, de-duplicated
    /// in observation order; nil when nothing is on record.
    private func dnsRecursiveFlags(_ leakChecks: LeakCheckStore?) -> [String]? {
        guard let observations = leakChecks?.dns.result?.observations else { return nil }
        var seen = Set<String>()
        var order: [String] = []
        for item in observations where item.kind == "resolver" {
            if let country = item.country, !country.isEmpty, seen.insert(country).inserted { order.append(country) }
        }
        return order.isEmpty ? nil : order
    }
    private func sourceNoticeTint(_ notices: [EnvironmentSourceNotice]) -> Color {
        notices.contains { $0.severity == "fail" || $0.severity == "error" } ? p.red : notices.contains { $0.severity == "warn" } ? p.amber : p.secondary
    }
    private func contextTransitionDetail(_ value: EnvironmentContextTransition) -> String {
        if value.state == "changed" {
            let fields = value.changed_fields?.joined(separator: "、") ?? "代理或网络上下文"
            return "本轮开始后 \(fields) 已变化；结果不会作为当前启动许可。"
        }
        let unavailable = value.unavailable?.joined(separator: "、") ?? "代理上下文"
        return "\(unavailable) 暂未稳定；自动刷新会等待有效上下文后重试。"
    }
    private var environmentAdjustment: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("出口地区、时区和日期格式按实测自动识别；代理客户端可自动识别或手动指定。这里只在确有系统修复时展示具体变更与回滚范围。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
            Picker("代理客户端", selection: $store.detectMode) {
                Text("自动识别").tag("auto")
                Text("TAG / mihomo").tag("tag")
                Text("Clash Verge").tag("clash-verge")
                Text("Shadowrocket").tag("shadowrocket")
                Text("sing-box").tag("sing-box")
                Text("ClashX").tag("clashx")
                Text("Surge").tag("surge")
            }
            .pickerStyle(.menu).disabled(store.busy)
            Text("节点钉死基线仅对带控制接口的 TAG/mihomo 类客户端生效；其余客户端按出口 IP 基线保护。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
            HStack {
                Button { Task { await store.detectEnvironment() } } label: { Label("自动检测并生成调整建议", systemImage: "wand.and.stars") }
                    .disabled(store.busy || store.hasUnsavedSettings || store.setupRecoveryRequired)
                Button { Task { await store.inspectEnvironment() } } label: { Label("读取本机与已接受参考", systemImage: "desktopcomputer") }.disabled(store.busy)
            }
            if let observation = store.environment {
                environmentValues(store.candidate?.rows ?? observation.rows)
            }
            if let candidate = store.candidate {
                Text("候选采样于 \(timeLabel(candidate.observed_at)) · 有效至 \(timeLabel(candidate.expires_at))").font(WatchTypography.caption).foregroundStyle(p.blue)
                Toggle("应用候选的地区、日期、时区及所需 IPv6 设置；Claude 保持英文", isOn: $store.setupApplyEnvironment).disabled(store.busy)
                Text("此入口不停止原版保镖。每项实际系统变更会在下方列出；日常保护按实测环境自动运行。")
                    .font(WatchTypography.caption).foregroundStyle(p.secondary)
                Button("预览具体变更") { Task { await store.previewEnvironment() } }.disabled(store.busy || store.hasUnsavedSettings || store.setupRecoveryRequired)
                if let plan = store.setupPlan {
                    ForEach(plan.actions) { action in changeRow(action) }
                    Text("确认后仅应用所列系统变更，并更新对应基线。当前后台意愿：Claude Watch 保镖 \(store.setupGuard ? "开启" : "关闭")；时区守护 \(store.setupWatchdog ? "开启" : "关闭")；自动更新 \(store.setupUpdater ? "开启" : "关闭")。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                    Button("应用所列系统变更") {
                        pendingTitle = "应用环境修复"
                        pendingMessage = plan.rows.filter { !$0.proposed.isEmpty }.map { $0.title + "：" + $0.target + " → " + $0.proposed }.joined(separator: "\n")
                            + "\n\n" + plan.actions.map { $0.title + "：" + ($0.detail ?? "请核对权限范围") }.joined(separator: "\n")
                        pendingAction = "应用所列变更"; pendingDestructive = false; pendingArguments = []; applyingSetup = true; confirmation = true
                    }.buttonStyle(.borderedProminent).disabled(!store.setupCanConfirm)
                }
            }
            Divider()
            Button("按已接受参考生成修复预览") {
                Task { await store.preview("repair"); showReview = store.plan != nil }
            }.disabled(store.busy || store.hasUnsavedSettings)
            recoveryPanel
        }
    }
    private func environmentValues(_ rows: [EnvironmentValueRow]) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            ForEach(rows) { row in
                VStack(alignment: .leading, spacing: 7) {
                    Text(row.title).font(WatchTypography.bodyStrong)
                    Text("实测：" + row.current).foregroundStyle(p.text)
                    Text("已接受参考：" + row.target).foregroundStyle(p.secondary)
                    if !row.proposed.isEmpty { Text("本次候选：" + row.proposed).foregroundStyle(p.blue) }
                    DisclosureGroup("来源与确认记录") {
                        Text("实测来源：" + row.source)
                        Text("参考来源：" + row.target_source)
                        if !row.proposed_source.isEmpty { Text("候选来源：" + row.proposed_source) }
                    }.font(WatchTypography.small).foregroundStyle(p.secondary)
                }.font(WatchTypography.caption).textSelection(.enabled).padding(.vertical, 10)
                Divider()
            }
        }
    }
    private var accountsContent: some View {
        Group {
            launchConditions
            Surface(p) {
                VStack(alignment: .leading, spacing: 14) {
                    HStack {
                        SectionHeading(title: "Claude 账号切换", caption: "选择 A/B，自动保存当前资料并载入目标账号 · Claude \(store.claudeVersion.isEmpty ? "版本未确认" : store.claudeVersion)", p: p)
                        Spacer()
                        Button {
                            confirm("启动 Claude", "将重新运行启动前检查，通过后启动 Claude。检测到的缺项不会被自动忽略。", ["launch", "--apply"], action: "检查并启动 Claude")
                        } label: { Label("检查并启动 Claude", systemImage: "play.fill") }.disabled(store.busy || store.hasUnsavedSettings)
                    }
                    HStack(spacing: 12) {
                        ForEach(store.accounts?.accounts ?? []) { account in
                            if account.current {
                                accountCard(account)
                            } else {
                            Button {
                                let slot = SwitcherStore.accountSlotPresentation(account, current: store.accounts?.current)
                                confirm(slot.confirmationTitle, slot.confirmationDetail,
                                        ["account", "switch", account.id, "--apply", "--ack-unverified-version"],
                                        action: slot.actionTitle, destructive: true)
                            } label: {
                                accountCard(account)
                            }.buttonStyle(.plain).disabled(store.busy || store.hasUnsavedSettings || store.accounts?.recovery_required == true)
                                .accessibilityLabel("切换到账号 \(account.id)，当前账号是 \(store.accounts?.current ?? "未知")，切换会自动保存与恢复资料")
                            }
                        }
                    }
                    Text("首次使用 A 会保存当前资料；切换时自动保存与恢复，登录状态以 Claude 中显示的账号为准。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                    DisclosureGroup("只读登录信息", isExpanded: $showLoginInfo) {
                        Button(store.loginProbeRunning ? "读取中" : "刷新登录状态") { Task { await store.refreshCurrentLogin(force: true) } }
                            .buttonStyle(.borderless).disabled(store.loginProbeRunning)
                        claudeLoginStatus.padding(.top, 8)
                    }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
                    Toggle("切换完成后返回环境状态", isOn: store.flag(Setting.returnToOverview)).disabled(store.busy)
                    if store.hasUnsavedSettings { draftActions }
                    if store.accounts?.recovery_required == true {
                        Button("恢复未完成账号切换") { confirm("恢复账号资料", "将按事务记录找回原目录，保留可能产生的新资料供核对。", ["account", "recover", "--apply"], action: "恢复账号资料") }.disabled(store.busy)
                    }
                }
            }
            Surface(p) {
                DisclosureGroup("原版资料迁移与操作记录", isExpanded: $showMigration) {
                    VStack(alignment: .leading, spacing: 12) {
                        Text("迁移是独立维护操作；原版保镖继续并行。")
                        HStack {
                            Button("查看原版可导入资料") { Task { await store.perform(["account", "import"], refresh: false) } }
                            Button("导入原版资料…") {
                                confirm("导入原版资料", "将导入原版 A/B 存档与工具设置，原版资料及原版保镖保留。请先核对预览。", ["account", "import", "--apply"], action: "导入资料")
                            }
                            Button("查看操作记录") { Task { await store.perform(["logs"], refresh: false); showLogs = true } }
                        }.disabled(store.busy || store.hasUnsavedSettings)
                    }.font(WatchTypography.caption).padding(.top, 12)
                }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
            recoveryPanel
        }
    }
    private func accountCard(_ account: SwitcherAccountSlot) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                Label("账号 \(account.id)", systemImage: "person.crop.circle").font(WatchTypography.title)
                Spacer()
                if account.current { Badge(text: "当前", color: p.blue) }
            }
            Text(SwitcherStore.accountSlotPresentation(account, current: store.accounts?.current).summary)
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
        }.frame(maxWidth: .infinity, alignment: .leading).padding(14)
            .background(account.current ? p.blue.opacity(0.13) : p.elevated, in: RoundedRectangle(cornerRadius: 9))
    }
    private var claudeLoginStatus: some View {
        Surface(p, padding: 12) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Label("当前 Claude 登录", systemImage: "person.text.rectangle").font(WatchTypography.bodyStrong)
                    Spacer()
                    Text(loginLabel).font(WatchTypography.caption).foregroundStyle(loginTint)
                }
                if let login = store.currentLogin {
                    if let account = store.currentLoginAccount {
                        let identity = [account.displayName, account.menuLabel, account.email]
                            .compactMap { $0?.trimmingCharacters(in: .whitespacesAndNewlines) }
                            .filter { !$0.isEmpty }.joined(separator: " · ")
                        if !identity.isEmpty { Text(identity).font(WatchTypography.caption).textSelection(.enabled) }
                    }
                    Text(login.detail).font(WatchTypography.small).foregroundStyle(p.secondary)
                    if login.state == "access_required" {
                        Text("新版首次打开时会请求辅助功能授权。请在系统提示中允许 Claude Watch；授权后自动重新读取登录状态。")
                            .font(WatchTypography.small).foregroundStyle(p.amber)
                        Button("重新请求授权并打开系统设置") { store.openClaudeWatchAccessibilitySettings() }
                            .buttonStyle(.borderless).font(WatchTypography.small)
                    }
                    HStack(spacing: 10) {
                        Text((store.currentLoginIsHistorical ? "上次验证于 " : "核对于 ") + timeLabel(login.observedAt))
                        Text("来源：" + login.source)
                        if let version = login.appVersion, !version.isEmpty { Text("Claude " + version) }
                    }.font(WatchTypography.small).foregroundStyle(p.secondary)
                } else {
                    Text("未验证。未读取 Cookie、资料槽或钥匙串来推断登录。").font(WatchTypography.small).foregroundStyle(p.secondary)
                }
            }
        }
    }
    private var loginLabel: String {
        switch store.currentLogin?.state {
        case "logged_in": return store.currentLoginIsHistorical ? "上次验证已登录" : "已登录"
        case "logged_out": return "未登录"
        case "app_closed": return "应用未运行"
        case "access_required": return "需要访问权限"
        case "error": return "读取失败"
        default: return "未验证"
        }
    }
    private var loginTint: Color {
        switch store.currentLogin?.state {
        case "logged_in": return store.currentLoginIsHistorical ? p.secondary : p.mint
        case "logged_out", "app_closed": return p.secondary
        case "access_required", "error": return p.amber
        default: return p.secondary
        }
    }
    private var launchConditions: some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    SectionHeading(title: "启动条件", caption: "环境实测、后台健康与启动预检分别取证。启动和切换仍独立复核原有全部要求。", p: p)
                    Spacer()
                    Button { Task { await store.checkLaunchConditions() } } label: { Label("检查启动条件", systemImage: "checklist") }.disabled(store.busy || store.hasUnsavedSettings)
                }
                if let result = store.currentPolicyEvaluation {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let expired = result.expires_at < context.date.timeIntervalSince1970
                        VStack(alignment: .leading, spacing: 9) {
                            Label(expired ? "同轮启动要求预览已过期" : result.ready ? "同轮启动要求已满足" : "同轮启动要求尚未满足",
                                  systemImage: expired ? "clock" : result.ready ? "checkmark.circle.fill" : "exclamationmark.triangle")
                                .foregroundStyle(expired ? p.secondary : result.ready ? p.mint : p.amber)
                            Text("与环境页同轮 · 采样于 " + timeLabel(result.observed_at) + " · 仅展示，不授予启动许可")
                                .font(WatchTypography.small).foregroundStyle(p.secondary)
                            ForEach(result.rows.filter { result.blocked.contains($0.id) }) { row in
                                VStack(alignment: .leading, spacing: 4) {
                                    Label(row.name + " · " + row.statusLabel, systemImage: row.statusSymbol).font(WatchTypography.bodyStrong)
                                    Text(row.detail).font(WatchTypography.caption)
                                }.foregroundStyle(expired ? p.secondary : p.amber)
                            }
                        }
                    }
                    if let facts = result.facts, facts.state == "fail" {
                        InlineNotice(title: "同轮阻断原因", detail: facts.risks?.compactMap { $0.reason ?? $0.id }.joined(separator: "\n") ?? "当前保护事实未满足。",
                                     symbol: "exclamationmark.shield", tint: p.red, p: p)
                    }
                    SessionProtectionStatusView(value: store.sessionDisplay, p: p)
                } else {
                    Text("尚未取得与当前环境同轮的启动要求预览。启动时仍会独立重新检查。").font(WatchTypography.body).foregroundStyle(p.secondary)
                    if !store.detectionError.isEmpty {
                        Text("本轮采样未完成：" + store.detectionError).font(WatchTypography.caption).foregroundStyle(p.amber)
                    }
                }
                if !store.webRTCReceiptError.isEmpty {
                    InlineNotice(title: "WebRTC 当前保护判定未提交", detail: store.webRTCReceiptError,
                                 symbol: "exclamationmark.shield", tint: p.amber, p: p)
                }
                DisclosureGroup("上次实际启动预检（历史）", isExpanded: $showAuditHistory) {
                    VStack(alignment: .leading, spacing: 8) {
                        if let result = store.audit {
                            TimelineView(.periodic(from: .now, by: 1)) { context in
                                let expired = result.expires_at < context.date.timeIntervalSince1970
                                VStack(alignment: .leading, spacing: 6) {
                                    Label(expired ? "历史预检已过期，不代表当前环境" : "历史预检记录", systemImage: expired ? "clock.badge.exclamationmark" : "clock")
                                        .foregroundStyle(expired ? p.secondary : p.amber)
                                    Text("采样于 " + timeLabel(result.observed_at)).font(WatchTypography.small).foregroundStyle(p.secondary)
                                    Text(result.message).font(WatchTypography.caption).foregroundStyle(p.secondary)
                                }
                            }
                        } else {
                            Text("暂无实际启动预检记录。").font(WatchTypography.caption).foregroundStyle(p.secondary)
                        }
                        if !store.auditOperationMessage.isEmpty {
                            Text("本次启动预检结果：" + store.auditOperationMessage)
                                .font(WatchTypography.caption).foregroundStyle(store.failure ? p.amber : p.secondary)
                        }
                    }.padding(.top, 8)
                }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
                ForEach(store.background?.policy_issues ?? []) { issue in
                    VStack(alignment: .leading, spacing: 4) {
                        Label(issue.title, systemImage: "info.circle").font(WatchTypography.bodyStrong)
                        Text(issue.detail).font(WatchTypography.caption)
                    }.foregroundStyle(p.amber)
                }
            }
        }
    }
    /// Per-criterion actions for a running Claude session. The backend
    /// records a baseline at session start (HTTP exit, DNS recursive exit
    /// countries, WebRTC public candidates) and compares each round; a drift
    /// triggers the configured action, a missing or stale sample only warns.
    /// Each AI service declares its own policy, so the panel renders the
    /// catalog instead of one shape copied per service.
    private var protectionPolicyPanel: some View {
        VStack(alignment: .leading, spacing: 14) {
            ForEach(AIPolicyCatalog.services) { policy in policyCard(policy) }
        }
    }
    private func policyCard(_ policy: AIServicePolicy) -> some View {
        Surface(p) {
            VStack(alignment: .leading, spacing: 12) {
                Label(policy.title, systemImage: "shield.lefthalf.filled.badge.checkmark")
                    .font(WatchTypography.section)
                Text(policy.subtitle)
                    .font(WatchTypography.caption).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
                ForEach(policy.criteria) { criterion in
                    policyRow(criterion, in: policy)
                }
                if let note = policy.note {
                    InlineNotice(title: "可配置动作少于 Claude", detail: note,
                                 symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                }
            }
        }
    }
    private func policyRow(_ criterion: PolicyCriterion, in policy: AIServicePolicy) -> some View {
        HStack {
            Text(criterion.title).font(WatchTypography.body)
            Spacer()
            Picker(criterion.title, selection: store.choice(policy.setting(criterion))) {
                ForEach(policy.actions) { Text($0.title).tag($0.id) }
            }
            .labelsHidden()
            .frame(width: 128)
            .disabled(policy.actions.count < 2)
            .help(policy.actions.count < 2 ? "该服务当前只能配置为提示" : "选择偏离时的处置动作")
        }
    }
    private var protectionContent: some View {
        Group {
            if !store.backgroundError.isEmpty { InlineNotice(title: "后台状态读取未完成", detail: store.backgroundError, symbol: "exclamationmark.triangle", tint: p.amber, p: p) }
            if store.failure, store.plan == nil, !store.message.isEmpty {
                InlineNotice(title: "后台操作未完成", detail: store.message, symbol: "exclamationmark.triangle", tint: p.amber, p: p)
            }
            if let result = store.background {
                Label("保护后台：\((result.guard_backend_healthy ?? result.backend_healthy) ? "身份与心跳已确认" : "尚未确认") · 监控采样：\(result.backend_healthy ? "完整" : "待复核") · 状态读取于 \(timeLabel(result.observed_at))", systemImage: "clock")
                    .font(WatchTypography.caption).foregroundStyle(p.secondary)
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    LazyVGrid(columns: [GridItem(.flexible(minimum: 310), spacing: 14, alignment: .top),
                                        GridItem(.flexible(minimum: 310), spacing: 14, alignment: .top)], spacing: 14) {
                        ForEach(result.services) { service in serviceCard(service, stale: !store.backgroundError.isEmpty || context.date.timeIntervalSince1970 - result.observed_at > 35) }
                    }
                }
                if let evidence = store.sessionDisplayEvidence { sessionGuardCard(evidence) }
                if let facts = result.facts, facts.state == "fail" {
                    InlineNotice(title: "当前保护风险", detail: facts.risks?.compactMap { $0.reason ?? $0.id }.joined(separator: "\n") ?? "后端已报告当前风险。",
                                 symbol: "exclamationmark.shield", tint: p.red, p: p)
                }
            } else { Text(store.busy ? "正在读取后台…" : "尚无后台状态，请刷新。").foregroundStyle(p.secondary) }
            Text("会话保护在明确 IP 变化、中国出口、DNS/WebRTC 风险或会话缺失时请求退出 Claude；它是进程级策略，存在采样窗口，不是防火墙，也不保证账号状态。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
            protectionPolicyPanel
            recoveryPanel
            Surface(p) {
                DisclosureGroup("启动要求与高级维护", isExpanded: $showSettings) { settingsPanel.padding(.top, 14) }
                    .disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            }
        }
    }
    private func serviceCard(_ service: BackgroundServiceRow, stale: Bool) -> some View {
        let descriptor = BackgroundServiceCatalog.descriptor(service.id)
        return Surface(p) {
            VStack(alignment: .leading, spacing: 11) {
                HStack {
                    Label(service.title, systemImage: descriptor.symbol).font(WatchTypography.section)
                    Spacer()
                    Label(stale ? "上次状态 · 请刷新" : service.statusLabel, systemImage: stale ? "clock" : service.healthy ? "checkmark.circle.fill" : service.state == "inactive" ? "pause.circle" : "exclamationmark.circle")
                        .font(WatchTypography.caption).foregroundStyle(stale ? p.secondary : service.healthy ? p.mint : service.state == "inactive" ? p.secondary : p.amber)
                }
                Text(service.detail).font(WatchTypography.body).fixedSize(horizontal: false, vertical: true)
                if let desired = service.desired { Text("保存设置：" + (desired ? "开启" : "关闭") + " · 实际状态见回读结果").font(WatchTypography.small).foregroundStyle(p.secondary) }
                if let checked = service.last_checked { Text("最近检查：" + timeLabel(checked)).font(WatchTypography.small).foregroundStyle(p.secondary) }
                HStack {
                    serviceControls(service, descriptor)
                }.disabled(store.busy || store.hasUnsavedSettings)
                Text("来源：" + service.source).font(WatchTypography.small).foregroundStyle(p.secondary)
            }
        }
    }
    /// What a service offers is read from its descriptor — which setting its
    /// switch owns, how the action reads and what it requires first — instead
    /// of comparing the service id against a list of known names.
    @ViewBuilder
    private func serviceControls(_ service: BackgroundServiceRow,
                                 _ descriptor: BackgroundServiceCatalog.Descriptor) -> some View {
        if let toggle = descriptor.toggle {
            if descriptor.requiresSource && !store.updateSourceReady {
                Button("配置本项目发布源…") { showSettings = true; showSource = true }
                if service.desired == true { serviceButton("预览关闭更新设置", toggle, enable: false) }
            } else {
                let outOfSync = service.state == "mismatch"
                    || (descriptor.requiresEnabled && service.desired == true && !store.isOn(Setting.enabled))
                if outOfSync { serviceButton(descriptor.syncTitle, toggle, enable: service.desired ?? true) }
                serviceButton(service.desired == true ? descriptor.disableTitle : descriptor.enableTitle,
                              toggle, enable: service.desired != true)
            }
        } else {
            Label(descriptor.note ?? "此服务由本工具单独管理。", systemImage: "link")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
        }
    }
    private func serviceButton(_ title: String, _ setting: FlagSetting, enable: Bool) -> some View {
        Button(title) { Task { await store.previewProtection(setting.key, enable: enable); showReview = store.plan != nil } }
    }
    private func sessionGuardCard(_ evidence: SessionProtectionEvidence) -> some View {
        let session = evidence.session
        let value = evidence.presentation(at: store.loginClock.timeIntervalSince1970)
        return VStack(alignment: .leading, spacing: 10) {
            SessionProtectionStatusView(value: value, p: p)
            if session.baseline != nil || session.current != nil || (session.reason != nil && session.state != "idle") || session.locked_at != nil {
                Surface(p) {
                    VStack(alignment: .leading, spacing: 9) {
                        if let baseline = session.baseline {
                            Text("会话基准：" + egressText(baseline)).font(WatchTypography.caption)
                        }
                        if let current = session.current {
                            Text((session.state == "locked" ? "退出时出口：" : "最近核验出口：") + egressText(current)).font(WatchTypography.caption)
                        }
                        if let reason = session.reason, session.state != "idle" {
                            Text((session.state == "locked" ? "停止原因：" : "检测情况：") + reason.detail).font(WatchTypography.caption).foregroundStyle(sessionGuardTint(value))
                            if let observed = reason.observed_at {
                                Text("原因时间：" + timeLabel(observed)).font(WatchTypography.small).foregroundStyle(p.secondary)
                            }
                        }
                        if let locked = session.locked_at {
                            Text("锁存时间：" + timeLabel(locked)).font(WatchTypography.small).foregroundStyle(p.secondary)
                        }
                        Text("明确风险时退出 Claude；未知状态不会宣称已完成检测。").font(WatchTypography.small).foregroundStyle(p.secondary)
                    }
                }
            }
        }
    }
    private func egressText(_ value: EgressReference) -> String {
        [value.ip, value.country].compactMap { $0?.isEmpty == false ? $0 : nil }.joined(separator: " / ")
    }
    private func sessionGuardTint(_ value: SessionProtectionPresentation) -> Color {
        value.tone == "danger" ? p.red : value.tone == "warning" ? p.amber : value.tone == "success" ? p.mint : p.secondary
    }
    private var settingsPanel: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("代理客户端、地区、时区和网络服务使用自动识别与已确认的参考，不提供手工软件选择。以下要求继续参与启动预检。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
            Text("受控启动按当前实测环境独立检查；无需填写国家、时区、DNS 或出口 IP。")
                .font(WatchTypography.small).foregroundStyle(p.secondary)
            Toggle("启动前要求 IPv6 已关闭", isOn: store.flag(Setting.requireIPv6Off))
            Toggle("启动前要求 Claude 使用英文", isOn: store.flag(Setting.requireEnglish))
            Label("DNS 与 UDP/STUN 探针", systemImage: "lock.shield")
                .font(WatchTypography.bodyStrong).foregroundStyle(p.text)
            Text("两项检测始终运行并在面板显示结果。它们测量的是探针自身的 UDP/DNS 路径，不代表 Claude 的实际连接；默认只提示、不阻止受控启动。勾选后对应探针失败将阻止受控启动。运行中的会话由「Claude 会话处置策略」按出口变化处置，与这里的开关无关。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary).fixedSize(horizontal: false, vertical: true)
            Toggle("启动前要求 DNS 递归出口无泄漏", isOn: store.flag(Setting.requireDNS))
            Toggle("启动前要求 UDP/STUN 出口一致", isOn: store.flag(Setting.requireStun))
            ForEach(store.policyWarnings, id: \.self) { Text($0).font(WatchTypography.caption).foregroundStyle(p.amber) }
            Toggle("启动前要求代理规则覆盖通过", isOn: store.flag(Setting.requirePinnedRules))
            DisclosureGroup("发布源与工具维护", isExpanded: $showSource) {
                VStack(alignment: .leading, spacing: 12) {
                    Text("此处供本项目发布维护使用。缺少发布源或固定公钥时，自动更新显示尚不可用。")
                    TextField("本项目 HTTPS 发布清单", text: store.text(Setting.updateURL)).textFieldStyle(.roundedBorder)
                    Text("固定 RSA 公钥（PEM）").font(WatchTypography.caption)
                    TextEditor(text: store.text(Setting.updatePublicKey)).font(WatchTypography.mono).frame(height: 100)
                    HStack {
                        Button("检查本项目更新") { Task { await store.perform(["update"], refresh: false) } }.disabled(!store.updateSourceReady || store.hasUnsavedSettings)
                        Button("更新系统辅助组件…") {
                            confirm("更新系统辅助组件", "需要管理员认证，更新本工具固定辅助程序；不会切换时区、语言或原版保镖。", ["services", "refresh-admin", "--apply"], action: "更新辅助组件")
                        }.disabled(store.hasUnsavedSettings)
                        Button("查看操作记录") { Task { await store.perform(["logs"], refresh: false); showLogs = true } }
                    }
                }.font(WatchTypography.caption).padding(.top, 12)
            }.disclosureGroupStyle(FullWidthDisclosureStyle(p: p))
            draftActions
        }.disabled(store.busy || !store.loaded)
    }
    private var draftActions: some View {
        HStack {
            Button("保存设置") { Task { await store.save(); await store.refreshBackground() } }
                .buttonStyle(.borderedProminent).disabled(!store.hasUnsavedSettings || store.busy)
            Button("撤销未保存修改") { store.discardChanges() }.disabled(!store.hasUnsavedSettings || store.busy)
            if store.hasUnsavedSettings { Text("未保存").font(WatchTypography.caption).foregroundStyle(p.amber) }
        }
    }
    @ViewBuilder private var recoveryPanel: some View {
        if store.setupRecoveryRequired {
            Surface(p) {
                VStack(alignment: .leading, spacing: 10) {
                    InlineNotice(title: "环境或后台变更待恢复", detail: "新的写操作已暂停。恢复会核对记录，保留外部修改。", symbol: "exclamationmark.triangle", tint: p.amber, p: p)
                    Button("恢复未完成变更") { confirm("恢复未完成变更", "按现有事务记录恢复仍匹配的设置、原配置与基线。", ["setup", "recover", "--apply"], action: "恢复记录中的变更") }.disabled(store.busy)
                }
            }
        }
        if store.updateRecoveryRequired {
            Button("恢复未完成升级") { confirm("恢复整包更新", "依据升级事务记录恢复应用与后台组件。", ["update", "--recover", "--apply"], action: "恢复整包更新") }.disabled(store.busy)
        }
    }
    private var changeReview: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("确认具体变更").font(WatchTypography.pageTitle)
            Text("每项列出修改前后的值和权限范围。Claude Watch 与原版保镖独立管理。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(store.plan?.actions ?? []) { action in changeRow(action) }
                    if store.plan?.actions.isEmpty == true { Text("没有待应用的变更。").foregroundStyle(p.secondary) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(maxHeight: 330)
            if !store.message.isEmpty { Text(store.message).font(WatchTypography.caption).foregroundStyle(store.failure ? p.amber : p.secondary).textSelection(.enabled) }
            HStack {
                Button("取消") { showReview = false }.disabled(store.busy)
                Spacer()
                Button("应用 \(store.plan?.actions.count ?? 0) 项变更") {
                    Task { await store.applyPreview(); if !store.failure { showReview = false } }
                }.buttonStyle(.borderedProminent).disabled(store.busy || store.hasUnsavedSettings || store.plan?.actions.isEmpty != false)
            }
        }.padding(24).frame(width: 590).foregroundStyle(p.text).background(p.surface).interactiveDismissDisabled(store.busy)
    }
    private func changeRow(_ action: SwitcherRepairAction) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                Text(action.title).font(WatchTypography.bodyStrong)
                Spacer()
                Badge(text: action.scope == "administrator" ? "管理员" : action.scope == "preferences" ? "系统偏好" : action.scope == "application" ? "应用" : "本工具", color: action.scope == "administrator" ? p.amber : p.blue)
            }
            Text(action.detail ?? "具体值未返回，请重新生成预览。").font(WatchTypography.caption).foregroundStyle(p.secondary).textSelection(.enabled)
        }.padding(12).frame(maxWidth: .infinity, alignment: .leading).background(p.elevated, in: RoundedRectangle(cornerRadius: 9))
    }
    private var logSheet: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack { Text("工具操作记录").font(WatchTypography.pageTitle); Spacer(); Button("关闭") { showLogs = false } }
            Text("环境确认、账号切换和后台操作的最近记录；监控事件另见事件记录页。").font(WatchTypography.caption).foregroundStyle(p.secondary)
            ScrollView { Text(store.operationLog.isEmpty ? "暂无操作记录" : store.operationLog).font(WatchTypography.mono).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }.frame(height: 360)
        }.padding(24).frame(width: 720).foregroundStyle(p.text).background(p.surface)
    }
    private var diagnosticPanel: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("手动测试指定代理到 Claude 网页/API 的传输；支持 HTTP / SOCKS，不保存地址或凭据，也不生成启动许可。")
                .font(WatchTypography.caption).foregroundStyle(p.secondary)
            HStack {
                Group {
                    if showProxyAddress { TextField("临时诊断代理地址", text: $store.diagnosticProxy) }
                    else { SecureField("临时诊断代理地址", text: $store.diagnosticProxy) }
                }.textFieldStyle(.roundedBorder)
                Button(showProxyAddress ? "隐藏" : "显示") { showProxyAddress.toggle() }
                Button("诊断传输") { Task { await store.diagnoseProxy() } }.disabled(store.diagnosticProxy.isEmpty)
            }.disabled(store.busy)
            if store.diagnosticRunning {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("正在诊断代理传输，通常需要数十秒；期间不会保存地址或凭据。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                }
            }
            if !store.diagnosticError.isEmpty { Text(store.diagnosticError).foregroundStyle(p.amber) }
            if let result = store.diagnostic {
                Text(result.message).font(WatchTypography.caption)
                ForEach(result.checks) { row in
                    HStack { Text(row.title); Spacer(); Text(row.accessLabel); if let code = row.http_status { Badge(text: "HTTP \(code)", color: code < 400 ? p.blue : p.amber) } }
                }.font(WatchTypography.caption)
            }
        }
    }
    private func timeLabel(_ epoch: Double) -> String { Date(timeIntervalSince1970: epoch).formatted(date: .numeric, time: .shortened) }
}

struct SwitcherFeedbackBar: View {
    @ObservedObject var store: SwitcherStore
    let p: Palette
    @State private var showDetails = false
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: store.failure ? "exclamationmark.triangle" : "info.circle").foregroundStyle(store.failure ? p.amber : p.blue)
            Text(store.message).font(WatchTypography.caption).lineLimit(2)
            Spacer(minLength: 8)
            Button("查看完整结果") { showDetails = true }.buttonStyle(.borderless)
            Button { store.dismissMessage() } label: { Image(systemName: "xmark") }.buttonStyle(.plain).accessibilityLabel("关闭操作结果")
        }.padding(12).background(p.surface).overlay(alignment: .top) { p.border.frame(height: 1) }
            .sheet(isPresented: $showDetails) {
                VStack(alignment: .leading, spacing: 16) {
                    HStack { Text("操作结果").font(WatchTypography.title); Spacer(); Button("关闭") { showDetails = false } }
                    ScrollView { Text(store.message).font(WatchTypography.body).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }.frame(height: 280)
                }.padding(24).frame(width: 640).foregroundStyle(p.text).background(p.surface)
            }
    }
}

struct SwitcherFeedbackRegion: View {
    @ObservedObject var store: SwitcherStore
    let p: Palette
    var body: some View { if !store.message.isEmpty { SwitcherFeedbackBar(store: store, p: p) } }
}

struct EnvironmentCheckTile: View {
    let row: EnvironmentCheckRow
    let p: Palette
    var stale = false
    /// Same row from the previous detection receipt; when its value or state
    /// differs, the tile shows what this refresh actually changed.
    var previous: EnvironmentCheckRow?
    /// Recursive-resolver country codes for the DNS row; displayed as small
    /// flag chips under the value.
    var flags: [String]? = nil
    @State private var presentation = EnvironmentDetailPresentation()
    @State private var previewTask: Task<Void, Never>?
    @State private var closeTask: Task<Void, Never>?
    private var tint: Color {
        if stale || row.state == "info" || row.state == "cached" { return p.secondary }
        return row.state == "ok" ? p.mint : row.state == "fail" ? p.red : p.amber
    }
    private var value: String {
        guard let current = row.current, !current.isEmpty else { return row.detail }
        return current == "unknown" ? "尚未取得验证依据" : current
    }
    /// Only live, current samples carry the diff; a historical badge already
    /// tells the whole "not current" story without mixing in a change marker.
    private var changeNote: String? {
        guard !stale, let previous, previous.current != row.current || previous.state != row.state else { return nil }
        if let old = previous.current, !old.isEmpty, old != row.current { return "上一轮：" + old }
        return "上一轮：" + previous.statusLabel
    }
    private var showReference: Bool { row.id == "timezone" || row.id == "locale" || row.state == "fail" || row.state == "cached" }

    var body: some View {
        card
            .accessibilityLabel(row.name + "，" + row.statusLabel + "，" + value)
            .accessibilityHint("按空格键固定检测依据与来源，再次激活或按 Esc 关闭")
            .accessibilityValue(presentation.isPinned ? "详情已固定" : "")
            .onHover { inside in
                presentation.hoverCard(inside)
                updateHover()
            }
            .popover(isPresented: popoverBinding, arrowEdge: .trailing) { popoverDetails }
            .onExitCommand(perform: dismiss)
            .onDisappear(perform: dismiss)
    }
    private var popoverBinding: Binding<Bool> {
        Binding(get: { presentation.isPresented }, set: { if !$0 { dismiss() } })
    }
    private var popoverDetails: some View {
        EnvironmentCheckDetails(row: row, p: p, pinned: presentation.isPinned,
            togglePin: { presentation.togglePin(); updateHover() }, close: dismiss, stale: stale)
            .onHover { inside in
                presentation.hoverDetails(inside)
                updateHover()
            }
            .onExitCommand(perform: dismiss)
    }
    private var card: some View {
        Button {
            cancelTasks()
            presentation.activate()
        } label: {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: row.categorySymbol).font(.system(size: 16, weight: .medium))
                        .foregroundStyle(tint).frame(width: 30, height: 30)
                        .background(tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
                    VStack(alignment: .leading, spacing: 5) {
                        HStack(spacing: 6) {
                            Text(row.name).font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                            Spacer(minLength: 0)
                            Label(stale ? "历史样本" : row.statusLabel, systemImage: stale ? "clock" : row.statusSymbol)
                                .font(WatchTypography.small).foregroundStyle(tint)
                                .padding(.horizontal, 6).padding(.vertical, 3)
                                .background(tint.opacity(0.10), in: Capsule())
                            Image(systemName: presentation.isPinned ? "pin.fill" : "info.circle")
                                .font(.system(size: 11, weight: .medium)).foregroundStyle(p.secondary)
                                .accessibilityHidden(true)
                        }
                        Text(value).font(WatchTypography.caption).foregroundStyle(p.text)
                            .lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                        if let note = changeNote {
                            Label(note, systemImage: "arrow.triangle.2.circlepath")
                                .font(WatchTypography.small).foregroundStyle(p.blue)
                                .lineLimit(1)
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(p.blue.opacity(0.10), in: Capsule())
                                .accessibilityLabel("与上一轮相比有变化，" + note)
                        }
                        if !stale, let flags, !flags.isEmpty {
                            HStack(spacing: 6) {
                                Text("递归出口").font(WatchTypography.small).foregroundStyle(p.secondary)
                                ForEach(flags, id: \.self) { code in
                                    Text(countryFlag(code) + " " + code)
                                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                                        .monospacedDigit()
                                }
                            }.accessibilityElement(children: .combine)
                                .accessibilityLabel("DNS 递归出口国家：" + flags.joined(separator: "、"))
                        }
                        if showReference, let reference = row.reference {
                            Text("要求：" + reference).font(WatchTypography.small).foregroundStyle(p.secondary).lineLimit(2)
                        }
                        if let sampled = row.sampled_at {
                            Text((row.state == "cached" ? "上次有效采样：" : (row.sample_reused == true ? "复用采样：" : "采样时间：")) + environmentSummaryTime(sampled))
                                .font(WatchTypography.small).foregroundStyle(p.secondary)
                        }
                    }
                }.frame(maxWidth: .infinity, minHeight: 48, alignment: .topLeading)
            .padding(10)
            .background(p.elevated.opacity(0.65), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(
                !stale && row.state == "fail" ? p.red.opacity(0.4) : p.border.opacity(0.65), lineWidth: 1))
            .contentShape(Rectangle())
        }.buttonStyle(.plain)
    }

    private func dismiss() { cancelTasks(); presentation.dismiss() }
    private func cancelTasks() {
        previewTask?.cancel(); previewTask = nil
        closeTask?.cancel(); closeTask = nil
    }
    private func updateHover() {
        cancelTasks()
        if presentation.shouldPreview {
            previewTask = Task { @MainActor in
                try? await Task.sleep(nanoseconds: 350_000_000)
                guard !Task.isCancelled else { return }
                presentation.previewIfNeeded()
            }
        } else if presentation.shouldClose {
            closeTask = Task { @MainActor in
                try? await Task.sleep(nanoseconds: 200_000_000)
                guard !Task.isCancelled else { return }
                presentation.closeIfNeeded()
            }
        }
    }
}

/// Synthetic grid card (same pattern as the WebRTC tile): names the proxy
/// routing mode the audit actually observed — 全局 or 规则 — plus the exit
/// node and rule-table coverage. Evidence-only display; never gates.
private struct EnvironmentModeTile: View {
    let local: EnvironmentLocalFacts
    let p: Palette
    let stale: Bool
    private var api: EnvironmentTagAPI? { local.tag?.api }
    private var rules: EnvironmentRulesEvidence? { local.rules }
    private var mode: String { api?.mode ?? rules?.actual_mode ?? "" }
    private var status: (label: String, symbol: String, tint: Color, value: String) {
        if stale { return ("历史样本", "clock", p.secondary, "环境采样已过期；重新检测后显示当前模式。") }
        if mode.isEmpty {
            let reason = api?.reason ?? rules?.detail ?? ""
            return ("未取得", "questionmark.circle.fill", p.amber,
                    "未能读取代理路由模式" + (reason.isEmpty ? "；请确认代理客户端控制接口可用。" : "；" + reason))
        }
        if mode == "global" {
            let node = api?.global_node ?? api?.selected_node ?? ""
            return ("全局模式", "arrow.triangle.branch", p.mint,
                    "全部流量统一走单一出口节点，规则表不参与匹配。" + (node.isEmpty ? "" : "出口节点：" + node))
        }
        if mode == "rule" {
            let missing = rules?.missing_domains?.count ?? 0
            let covered = rules?.covered_domains?.count ?? 0
            let coverage = missing > 0 ? "规则表缺失 \(missing) 项域名覆盖。" : (covered > 0 ? "规则表覆盖 \(covered) 项域名。" : "")
            return ("规则模式", "list.bullet.rectangle", p.blue,
                    "流量按规则表逐条匹配，未覆盖的域名可能绕过代理直连。" + coverage)
        }
        return ("未识别模式", "questionmark.circle.fill", p.amber, "代理运行在 \(mode) 模式；实际流量走向见连接页。")
    }
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: status.symbol)
                .font(.system(size: 16, weight: .medium))
                .foregroundStyle(status.tint).frame(width: 30, height: 30)
                .background(status.tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 6) {
                    Text("代理模式").font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                    Spacer(minLength: 0)
                    Label(status.label, systemImage: status.symbol).font(WatchTypography.small).foregroundStyle(status.tint)
                        .padding(.horizontal, 6).padding(.vertical, 3).background(status.tint.opacity(0.10), in: Capsule())
                }
                Text(status.value).font(WatchTypography.caption).foregroundStyle(p.text)
                    .lineLimit(3).frame(maxWidth: .infinity, alignment: .leading)
                if let detail = rules?.detail, !detail.isEmpty, !stale, !mode.isEmpty {
                    Text(detail).font(WatchTypography.small).foregroundStyle(p.secondary).lineLimit(2)
                }
            }
        }.frame(maxWidth: .infinity, minHeight: 48, alignment: .topLeading).padding(10)
            .background(p.elevated.opacity(0.65), in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(
                !stale && mode == "rule" && (rules?.missing_domains?.count ?? 0) > 0 ? p.amber.opacity(0.4) : p.border.opacity(0.65), lineWidth: 1))
            .accessibilityElement(children: .combine)
            .accessibilityLabel("代理模式，" + status.label + "，" + status.value)
    }
}

/// One-glance context bar above the tile grid: exit country/IP, routing mode
/// with the live node, and the exit-local clock. Everything shown already
/// exists in the captured sample; the strip only removes the need to scan the
/// whole grid to answer "我现在在哪、走的什么线".
private struct EnvironmentSummaryStrip: View {
    let result: CurrentEnvironmentReceipt
    let p: Palette
    var stale = false
    /// When the previous detection ran, so the strip anchors 刷新前后对比
    /// in time as well as in per-row change markers.
    var previousObserved: Double? = nil

    private var egressCurrent: String { result.rows.first { $0.id == "egress" }?.current ?? "" }
    private var mode: String {
        result.display_facts?.local?.tag?.api?.mode ?? result.display_facts?.local?.rules?.actual_mode ?? ""
    }
    private var node: String {
        let api = result.display_facts?.local?.tag?.api
        if mode == "global" { return api?.global_node ?? api?.selected_node ?? "" }
        return api?.selected_node ?? ""
    }
    private var exitTimezone: TimeZone? {
        result.display_facts?.online?.geo?.timezone.flatMap(TimeZone.init(identifier:))
    }

    var body: some View {
        HStack(spacing: 8) {
            if !egressCurrent.isEmpty {
                pill(symbol: "globe", text: egressCurrent, tint: stale ? p.secondary : p.mint)
            }
            if !mode.isEmpty {
                let label = (mode == "global" ? "全局模式" : mode == "rule" ? "规则模式" : mode)
                    + (node.isEmpty ? "" : " · \(node)")
                pill(symbol: mode == "global" ? "arrow.triangle.branch" : "list.bullet.rectangle",
                     text: label, tint: stale ? p.secondary : mode == "global" ? p.mint : p.blue)
            }
            if let tz = exitTimezone {
                TimelineView(.periodic(from: .now, by: 30)) { context in
                    pill(symbol: "clock", text: exitClock(tz, context.date), tint: p.secondary)
                }
            }
            if let previousObserved, previousObserved > 0 {
                pill(symbol: "clock.arrow.circlepath", text: "上一轮 " + environmentSummaryTime(previousObserved), tint: p.secondary)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }

    private func pill(symbol: String, text: String, tint: Color) -> some View {
        Label(text, systemImage: symbol)
            .font(WatchTypography.caption)
            .foregroundStyle(stale ? p.secondary : p.text)
            .lineLimit(1)
            // Long node names must survive truncation: hover shows the full text.
            .help(text)
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(p.elevated.opacity(0.8), in: Capsule())
            .overlay(Capsule().strokeBorder(tint.opacity(0.35), lineWidth: 1))
    }

    /// Live exit-local time plus the offset against this Mac, e.g.
    /// "出口 18:52 · 与本机差 +1h" or "+30m" for half-hour zones.
    private func exitClock(_ tz: TimeZone, _ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.timeZone = tz
        formatter.dateFormat = "HH:mm"
        let offset = (tz.secondsFromGMT(for: date) - TimeZone.current.secondsFromGMT(for: date)) / 60
        let diff: String
        if offset == 0 {
            diff = "与本机同"
        } else {
            var text = offset > 0 ? "+" : "-"
            let hours = abs(offset) / 60, minutes = abs(offset) % 60
            if hours > 0 { text += "\(hours)h" }
            if minutes > 0 { text += "\(minutes)m" }
            diff = "与本机差 \(text)"
        }
        return "出口 \(formatter.string(from: date)) · \(diff)"
    }
}

private struct EnvironmentWebRTCTile: View {
    let state: LeakCheckState
    let p: Palette
    let stale: Bool
    let open: () -> Void
    private var status: (label: String, symbol: String, tint: Color, value: String) {
        if stale { return ("历史样本", "clock", p.secondary, "环境采样已过期；WebRTC 最近结果见详情") }
        if state.running { return ("更新中", "arrow.triangle.2.circlepath", p.blue, state.result == nil ? "正在采集当前 WebView 的 ICE/STUN 候选" : "正在更新；保留上次检测结果") }
        switch state.verdict.state {
        case .matched: return ("已核对", "checkmark.circle.fill", p.mint, state.verdict.title)
        case .difference: return ("出口差异", "exclamationmark.triangle", p.amber, state.verdict.title)
        case .incomplete, .unconfigured: return ("检测未完成", "exclamationmark.triangle.fill", p.amber, state.verdict.detail)
        case .cancelled: return ("已取消", "stop.circle", p.amber, state.verdict.detail)
        case .idle: return ("尚未检测", "clock", p.secondary, "等待自动检测或打开详情立即检测")
        case .running: return ("更新中", "arrow.triangle.2.circlepath", p.blue, "正在采集当前 WebView 的 ICE/STUN 候选")
        }
    }
    var body: some View {
        Button(action: open) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "antenna.radiowaves.left.and.right").font(.system(size: 16, weight: .medium))
                    .foregroundStyle(status.tint).frame(width: 30, height: 30)
                    .background(status.tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 6) {
                        Text("WebRTC 泄漏检测").font(WatchTypography.bodyStrong).foregroundStyle(p.text)
                        Spacer(minLength: 0)
                        Label(status.label, systemImage: status.symbol).font(WatchTypography.small).foregroundStyle(status.tint)
                            .padding(.horizontal, 6).padding(.vertical, 3).background(status.tint.opacity(0.10), in: Capsule())
                    }
                    Text(status.value).font(WatchTypography.caption).foregroundStyle(p.text).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                    if let result = state.result { Text("采样于 " + environmentSummaryTime(result.finishedAt)).font(WatchTypography.small).foregroundStyle(p.secondary) }
                }
            }.frame(maxWidth: .infinity, minHeight: 48, alignment: .topLeading).padding(10)
                .background(p.elevated.opacity(0.65), in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(status.tint.opacity(0.35), lineWidth: 1))
        }.buttonStyle(.plain).accessibilityLabel("WebRTC 泄漏检测，" + status.label)
    }
}

private struct EnvironmentIPQualitySummary: View {
    @ObservedObject var store: NetCoffeeStore
    let environment: CurrentEnvironmentReceipt
    let p: Palette
    private var ip: String? {
        guard let raw = environment.rows.first(where: { $0.id == "egress" })?.current else { return nil }
        return raw.components(separatedBy: " / ").first.flatMap { LeakIPAddress($0.trimmingCharacters(in: .whitespacesAndNewlines))?.canonical }
    }
    var body: some View {
        guard let ip else { return AnyView(EmptyView()) }
        let receipt = store.report(ip)
        let fresh = store.isFreshLookup(ip)
        return AnyView(Surface(p, padding: 12) {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Label("IP 质量概要", systemImage: "gauge.with.dots.needle.50percent").font(WatchTypography.bodyStrong)
                    Spacer()
                    Text(store.running.contains(ip) ? "更新中" : receipt == nil ? "未取得" : fresh && receipt?.cache_state != "last_good" ? "本轮 IP" : "历史资料").font(WatchTypography.small).foregroundStyle(p.secondary)
                }
                if let receipt {
                    HStack(alignment: .top, spacing: 18) {
                        VStack(alignment: .leading, spacing: 3) {
                            Text(receipt.score.map(String.init) ?? "—").font(.system(size: 22, weight: .semibold, design: .rounded)).monospacedDigit()
                            Text("Net.Coffee 信任分 / 100").font(WatchTypography.small).foregroundStyle(p.secondary)
                        }
                        VStack(alignment: .leading, spacing: 3) {
                            Text("AS\(receipt.field("asn")) · \(receipt.field("asOrganization"))").font(WatchTypography.caption).lineLimit(1)
                            Text("出口地理国家：\(receipt.field("country"))；IP 注册地（Net.Coffee）：\(receipt.field("registered_country"))").font(WatchTypography.small).foregroundStyle(p.secondary).lineLimit(2)
                        }
                    }
                    Text((fresh && receipt.cache_state != "last_good" ? "资料时间：" : "历史资料时间：") + environmentSummaryTime(receipt.queriedAt) + " · 数据来自 Net.Coffee")
                        .font(WatchTypography.small).foregroundStyle(p.secondary)
                } else {
                    Text("正在按本轮公网出口 IP 读取 Net.Coffee 网络资料；未返回时保持未取得。")
                        .font(WatchTypography.caption).foregroundStyle(p.secondary)
                }
            }
        })
    }
}

private func environmentSummaryTime(_ epoch: Double) -> String {
    Date(timeIntervalSince1970: epoch).formatted(date: .numeric, time: .shortened)
}

/// Any ISO 3166-1 alpha-2 code renders as its regional flag via Unicode
/// regional indicators (same mechanism the backend uses for egress cards).
/// Non-2-letter input degrades to the plain text instead of garbage.
func countryFlag(_ code: String) -> String {
    let upper = code.uppercased()
    guard upper.count == 2, upper.unicodeScalars.allSatisfy({ ("A"..."Z").contains(String($0)) }) else { return code }
    let scalars = upper.unicodeScalars.map { Unicode.Scalar(0x1F1E6 + ($0.value - 65)) }.compactMap { $0 }
    return scalars.count == 2 ? String(String.UnicodeScalarView(scalars)) : code
}


struct EnvironmentCheckDetails: View {
    let row: EnvironmentCheckRow
    let p: Palette
    let pinned: Bool
    let togglePin: () -> Void
    let close: () -> Void
    var stale = false
    @State private var contentHeight: CGFloat = 240

    private var tint: Color {
        if stale || row.state == "info" || row.state == "cached" { return p.secondary }
        return row.state == "ok" ? p.mint : row.state == "fail" ? p.red : p.amber
    }
    private var value: String {
        guard let current = row.current, !current.isEmpty, current != "unknown" else { return "尚未取得验证依据" }
        return current
    }
    private var copyText: String {
        let stamp = row.state == "cached" ? "上次有效采样：" : (row.sample_reused == true ? "复用采样：" : "采样时间：")
        return [row.name + " · " + (stale ? "历史样本" : row.statusLabel), "实测：" + value,
         "判定依据：" + (row.reference ?? "无独立参考值"), "说明：" + row.detail,
         "来源：" + (row.source ?? row.scope),
         row.sampled_at.map { stamp + environmentSummaryTime($0) } ?? "",
         row.query_error.map { "本次查询失败：" + $0 } ?? ""].filter { !$0.isEmpty }.joined(separator: "\n")
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 9) {
                Image(systemName: row.categorySymbol).foregroundStyle(tint)
                Text(row.name).font(WatchTypography.bodyStrong)
                Spacer(minLength: 4)
                Button(action: togglePin) {
                    Image(systemName: pinned ? "pin.fill" : "pin")
                }.help(pinned ? "取消固定" : "固定详情，移开鼠标后保留")
                    .accessibilityLabel(pinned ? "取消固定详情" : "固定详情")
                Button(action: close) { Image(systemName: "xmark") }
                    .help("关闭详情（Esc）").accessibilityLabel("关闭详情")
            }.buttonStyle(.plain)
            Label(stale ? "历史样本 · 请重新检测" : row.statusLabel, systemImage: stale ? "clock" : row.statusSymbol)
                .font(WatchTypography.caption).foregroundStyle(tint)
            ScrollView {
                details.background(GeometryReader { geometry in
                    Color.clear.preference(key: EnvironmentDetailHeight.self, value: geometry.size.height)
                })
            }.frame(height: min(320, max(60, contentHeight)))
                .onPreferenceChange(EnvironmentDetailHeight.self) { height in
                    if height > 0 { contentHeight = height }
                }
            Divider().overlay(p.border)
            HStack {
                Text(pinned ? "已固定 · 可选择并复制文字" : "点击卡片或图钉可固定")
                    .font(WatchTypography.small).foregroundStyle(p.secondary)
                Spacer()
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(copyText, forType: .string)
                } label: { Label("复制", systemImage: "doc.on.doc") }
                    .buttonStyle(.borderless).font(WatchTypography.caption)
                    .accessibilityLabel("复制本项完整检测依据")
            }
        }.padding(16).frame(width: 390, alignment: .leading)
            .foregroundStyle(p.text).background(p.surface)
            .environment(\.colorScheme, p.dark ? .dark : .light)
    }
    private var details: some View {
        VStack(alignment: .leading, spacing: 12) {
            detail("实测", value)
            if let reference = row.reference { detail("判定依据", reference) }
            detail("说明", row.detail)
            detail("来源", row.source ?? row.scope)
            if let sampled = row.sampled_at {
                detail(row.state == "cached" ? "上次有效采样" : (row.sample_reused == true ? "复用采样" : "采样时间"), environmentSummaryTime(sampled))
            }
            if let error = row.query_error, !error.isEmpty { detail("本次查询失败", error) }
        }.frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
    }
    private func detail(_ title: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(WatchTypography.small).foregroundStyle(p.secondary)
            Text(text).font(WatchTypography.caption).fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct EnvironmentDetailHeight: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = nextValue() }
}
