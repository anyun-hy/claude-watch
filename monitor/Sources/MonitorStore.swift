import Foundation
import Combine

enum ReadOutcome: Sendable {
    case success(MonitorSnapshot)
    case failure(String)
}

enum SnapshotRunner {
    static func run(full: Bool) -> ReadOutcome {
        guard let url = Bundle.main.url(forResource: "snapshot", withExtension: "sh") else {
            return .failure("找不到数据读取组件，请重新构建界面。")
        }
        let task = Process()
        let output = Pipe()
        let errors = Pipe()
        task.executableURL = URL(fileURLWithPath: "/bin/bash")
        task.arguments = [url.path] + (full ? ["--full"] : [])
        task.standardOutput = output
        task.standardError = errors
        do {
            try task.run()
        } catch {
            return .failure("数据读取组件未能启动。")
        }
        let timeout = DispatchWorkItem { if task.isRunning { task.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 20, execute: timeout)
        let data = output.fileHandleForReading.readDataToEndOfFile()
        _ = errors.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        timeout.cancel()
        guard task.terminationStatus == 0 else {
            return .failure("本次读取未完成，将在下次刷新时重试。")
        }
        do { return .success(try JSONDecoder().decode(MonitorSnapshot.self, from: data)) }
        catch { return .failure("检测数据暂时无法解析，将在下次刷新时重试。") }
    }
}

enum Page: String, CaseIterable {
    case overview = "监控概览", network = "代理与连接", processes = "进程活动", events = "事件记录"
    case dns = "DNS 泄漏检测", webrtc = "WebRTC 泄漏检测"
    case ipScore = "IP 评分"
    case claudeAI = "Claude AI 检测", gptAI = "GPT / Codex 检测"
    case switcher = "启动与账号", environment = "环境状态", protection = "后台保护"
    static let primaryPages: [Page] = [.environment, .switcher, .protection]
    static let monitorPages: [Page] = [.overview, .network, .processes, .events]
    static var orderedPages: [Page] { primaryPages + monitorPages + diagnosticPages }
    static func restored(_ value: String) -> Page { value == "安全启动与账号" ? .environment : Page(rawValue: value) ?? .environment }
    var isPrimary: Bool { Self.primaryPages.contains(self) }
    var isLeakCheck: Bool { self == .dns || self == .webrtc }
    var isManualCheck: Bool { isLeakCheck || self == .ipScore || self == .claudeAI || self == .gptAI || isPrimary }
    static let diagnosticPages: [Page] = [.claudeAI, .gptAI, .ipScore, .dns, .webrtc]
    var symbol: String {
        switch self {
        case .overview: return "square.grid.2x2"
        case .network: return "point.3.connected.trianglepath.dotted"
        case .processes: return "waveform.path"
        case .events: return "clock.arrow.circlepath"
        case .dns: return "network"
        case .webrtc: return "antenna.radiowaves.left.and.right"
        case .switcher: return "person.crop.circle.badge.checkmark"
        case .environment: return "globe.asia.australia"
        case .protection: return "shield.lefthalf.filled"
        case .claudeAI: return "sparkles"
        case .ipScore: return "gauge.with.dots.needle.50percent"
        case .gptAI: return "terminal"
        }
    }
    var caption: String {
        switch self {
        case .overview: return "后台状态、入口与当前检测结果"
        case .network: return "区分代理设置与实际连接证据"
        case .processes: return "Claude 及关联进程的最近一次采样"
        case .events: return "查看已有监控日志中的最近 100 条记录"
        case .dns: return "手动检查 DNS 递归出口与预期解析器"
        case .webrtc: return "手动检查当前 WebView 的公网候选和 HTTP 出口"
        case .switcher: return "启动条件、Claude 启动与本地资料槽位"
        case .environment: return "自动识别代理，核对本轮实测环境"
        case .protection: return "两套保镖、时区守护与更新任务的实际状态"
        case .claudeAI: return "Claude 域名的代理诊断与现有连接证据"
        case .ipScore: return "Net.Coffee 原始评分、IP 属性与情报"
        case .gptAI: return "ChatGPT / API 入口的代理诊断与现有连接证据"
        }
    }
}

@MainActor
final class MonitorStore: ObservableObject {
    let leakChecks: LeakCheckStore
    let aiChecks: AIProbeStore
    let netCoffee = NetCoffeeStore()
    let processControl = AIProcessControl()
    let switcher = SwitcherStore()
    @Published var snapshot: MonitorSnapshot?
    @Published var error: String?
    @Published var refreshing = false
    @Published var automatic = true
    @Published var page: Page = .environment
    @Published var now = Date()
    @Published var networkSelection = NetworkGraphSelection()
    @Published private(set) var graphContinuity = GraphContinuityStore()
    @Published private(set) var serverReferences: [String: ServerReference] = [:]
    private var referenceQueryRunning = false
    private var referenceQueriesEnabled = false
    private var timer: Timer?
    private var lastFull: Date = .distantPast
    private var lastBackgroundRead: Date = .distantPast
    private var backgroundReadRunning = false
    private var environmentRefreshScheduler = EnvironmentRefreshScheduler()
    private var lastValidSnapshotContext: String?
    private var refreshGate = MonitorRefreshGate()
    init(leakChecks: LeakCheckStore? = nil, aiChecks: AIProbeStore? = nil) {
        self.leakChecks = leakChecks ?? LeakCheckStore()
        self.aiChecks = aiChecks ?? AIProbeStore()
        let context: () -> String? = { [weak self] in
            guard let proxy = self?.proxy, proxy.entryState == "verified",
                  proxy.apiState == "available", proxy.coversProxy else { return nil }
            return [proxy.endpoint, proxy.mode, proxy.selectedNode, proxy.globalNode].joined(separator: "|")
        }
        self.leakChecks.contextProvider = context
        self.switcher.diagnosticContextProvider = context
        self.leakChecks.onDNSComplete = { [weak self] result in
            guard let self else { return false }
            return await self.switcher.recordDNSLeak(result)
        }
        self.leakChecks.onWebRTCComplete = { [weak self] result in
            guard let self else { return false }
            return await self.switcher.recordWebRTCRisk(result)
        }
        self.switcher.awaitFreshDNSReceipt = { [weak self] in
            guard let self else { return false }
            return await self.leakChecks.ensureFreshDNSReceipt()
        }
        self.switcher.onDNSReceiptRecorded = { [weak self] in
            self?.requestEnvironmentRefreshAfterDNS()
        }
        self.switcher.onWebRTCRiskRecorded = { [weak self] in
            Task { await self?.switcher.refreshBackground() }
        }
        self.aiChecks.contextProvider = context
        self.aiChecks.onResult = { [weak self] result in
            let ip = result.exitIP
            guard !ip.isEmpty else { return }
            self?.netCoffee.fetchAI(ip)
        }
        self.switcher.onCurrentEnvironment = { [weak self] result in
            self?.refreshEnvironmentQuality(result)
        }
    }
    func start() {
        guard timer == nil else { return }
        AccessibilityPermission.checkInstalledBuild()
        refreshBackgroundIfNeeded(at: Date())
        referenceQueriesEnabled = true
        refresh(full: true)
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.monitorTick(at: Date())
            }
        }
    }
    func monitorTick(at date: Date) {
        now = date
        leakChecks.now = date
        aiChecks.now = date
        // Login freshness is a display fact and must age even while automatic
        // network/environment detection is paused.
        switcher.advanceLoginClock(date)
        guard automatic else { return }
        refreshBackgroundIfNeeded(at: date)
        // AX reading is independent and must not delay the snapshot scheduler.
        Task { @MainActor [weak switcher] in
            await switcher?.refreshCurrentLogin()
        }
        refresh(full: date.timeIntervalSince(lastFull) >= 15)
    }
    func refresh(full: Bool, manual: Bool = false) {
        if manual { refreshBackgroundIfNeeded(at: Date(), force: true) }
        let shouldRead = refreshGate.request(manual: manual)
        if refreshing != refreshGate.manualVisible { refreshing = refreshGate.manualVisible }
        guard shouldRead else { return }
        if full { lastFull = Date() }
        Task {
            let result = await Task.detached(priority: .utility) {
                SnapshotRunner.run(full: full)
            }.value
            // A newly captured snapshot may be newer than the previous timer
            // tick. Advance the display clock before deriving `live` through
            // `proxy` or starting any context-bound diagnostic.
            let completedAt = Date()
            now = completedAt
            leakChecks.now = completedAt
            aiChecks.now = completedAt
            switch result {
            case .success(let value):
                snapshot = value
                error = nil
                if automatic {
                    invalidateEnvironmentRequestForRealContextChange()
                    leakChecks.refreshWebRTCIfNeeded()
                    refreshEnvironmentIfNeeded()
                }
            case .failure(let message):
                error = message
            }
            synchronizeNetworkSelection()
            let repeatManual = refreshGate.complete()
            if refreshing != refreshGate.manualVisible { refreshing = refreshGate.manualVisible }
            if repeatManual { refresh(full: true, manual: true) }
        }
    }
    private func refreshBackgroundIfNeeded(at date: Date, force: Bool = false) {
        guard !backgroundReadRunning, force || date.timeIntervalSince(lastBackgroundRead) >= 15 else { return }
        backgroundReadRunning = true
        lastBackgroundRead = date
        Task { @MainActor in
            await switcher.refreshBackground()
            backgroundReadRunning = false
        }
    }
    private func refreshEnvironmentIfNeeded() {
        let usableContext = snapshotContext()
        guard environmentRefreshScheduler.claim(context: usableContext, now: Date(),
                                                switcherBusy: switcher.readingEnvironment || switcher.busy) != nil else { return }
        Task { @MainActor [weak self] in
            guard let self else { return }
            let dnsRecorded = await self.leakChecks.ensureFreshDNSReceipt()
            guard self.snapshotContext() == usableContext else {
                self.environmentRefreshScheduler.complete(context: usableContext, accepted: false, now: Date())
                return
            }
            let accepted = await self.switcher.detectCurrentEnvironment()
            self.environmentRefreshScheduler.complete(context: usableContext, accepted: dnsRecorded && accepted, now: Date())
        }
    }
    private func snapshotContext() -> String? {
        guard let value = proxy, value.entryState == "verified", value.apiState == "available",
              value.coversProxy, !value.endpoint.isEmpty, !value.mode.isEmpty, !value.currentNode.isEmpty else { return nil }
        return [value.endpoint, value.mode, value.currentNode].joined(separator: "|")
    }
    private func invalidateEnvironmentRequestForRealContextChange() {
        guard let context = snapshotContext() else { return }
        defer { lastValidSnapshotContext = context }
        guard let previous = lastValidSnapshotContext, previous != context else { return }
        switcher.invalidateCurrentEnvironmentRequest()
    }
    private func requestEnvironmentRefreshAfterDNS() {
        // Do not merge a DNS-only receipt into a prior observation.  The next
        // stable full observation atomically refreshes both environment and
        // display-only launch-preview rows.
        guard automatic else { return }
        guard !environmentRefreshScheduler.isInFlight else { return }
        environmentRefreshScheduler.requestRefresh()
        refreshEnvironmentIfNeeded()
    }
    private func refreshEnvironmentQuality(_ result: CurrentEnvironmentReceipt) {
        if let receipt = result.netcoffee_lookup { netCoffee.ingest(receipt) }
    }
    func synchronizeNetworkSelection() {
        var selection = networkSelection
        selection.reconcile(proxy: proxy, processes: snapshot?.processes ?? [],
                            fresh: proxyFresh && proxy?.connectionObservationIsComplete == true)
        if selection != networkSelection { networkSelection = selection }
        rememberGraphPath()
        refreshServerReference()
    }
    func selectNetworkFlow(_ flow: Flow, product: MonitoredProduct) {
        networkSelection.select(flowID: flow.id, product: product)
        rememberGraphPath()
        refreshServerReference()
    }
    private var graphEgress: (ip: String?, time: Double?) {
        guard let background = switcher.background,
              0 <= now.timeIntervalSince1970 - background.observed_at,
              now.timeIntervalSince1970 - background.observed_at <= 30,
              let reference = background.session_guard?.current,
              let at = reference.observed_at ?? reference.checked_at,
              0 <= now.timeIntervalSince1970 - at, now.timeIntervalSince1970 - at <= 30,
              let ip = reference.ip, !ip.isEmpty else { return (nil, nil) }
        return (ip, at)
    }
    private var graphSafetyBlocked: Bool {
        let value = switcher.background?.session_guard
        return value?.state == "locked" || value?.phase == "locked"
    }
    private func rememberGraphPath() {
        graphContinuity.observe(snapshot: snapshot, selection: networkSelection, now: now.timeIntervalSince1970,
            error: error, automatic: automatic, claudeEgressIP: graphEgress.ip,
            egressObservedAt: graphEgress.time, safetyBlocked: graphSafetyBlocked,
            references: serverReferences)
    }
    func graphDisplay(for product: MonitoredProduct) -> GraphDisplayState {
        graphContinuity.display(product: product, snapshot: snapshot, selection: networkSelection,
            now: now.timeIntervalSince1970, error: error, automatic: automatic,
            claudeEgressIP: graphEgress.ip, egressObservedAt: graphEgress.time, safetyBlocked: graphSafetyBlocked)
    }
    func reference(for flow: Flow?) -> ServerReference? {
        guard let request = ServerReferenceRequest(flow: flow), let value = serverReferences[request.key],
              value.applies(to: request, now: now.timeIntervalSince1970) else { return nil }
        return value
    }
    func acceptServerReference(_ result: ServerReference?, for request: ServerReferenceRequest, at date: Date) {
        let epoch = date.timeIntervalSince1970
        let value = result.flatMap { $0.applies(to: request, now: epoch) ? $0 : nil }
            ?? ServerReference.unavailable(for: request, now: epoch)
        if serverReferences[request.key] == nil, serverReferences.count >= 64,
           let oldest = serverReferences.min(by: { $0.value.queriedAt < $1.value.queriedAt })?.key {
            serverReferences.removeValue(forKey: oldest)
        }
        serverReferences[request.key] = value
        // Only a still-current selected connection may capture this reference.
        // Late answers never mutate a historical path from an ended connection.
        rememberGraphPath()
    }
    private func refreshServerReference() {
        guard referenceQueriesEnabled, automatic, page == .network, !referenceQueryRunning,
              graphDisplay(for: networkSelection.product).phase == .live,
              let selectedID = networkSelection.selectedFlowID(for: networkSelection.product),
              let flow = proxy?.flows.first(where: { $0.id == selectedID }),
              let request = ServerReferenceRequest(flow: flow), reference(for: flow) == nil else { return }
        referenceQueryRunning = true
        Task {
            let result = await Task.detached(priority: .utility) { ServerReferenceRunner.run(request) }.value
            referenceQueryRunning = false
            acceptServerReference(result, for: request, at: Date())
        }
    }
    var proxy: ProxySnapshot? {
        guard live, snapshot?.proxyError == nil, let value = snapshot?.proxy else { return nil }
        let age = now.timeIntervalSince1970 - value.observedAt
        return age >= 0 && age <= 30 ? value : nil
    }
    var proxyError: String? {
        if let error { return error }
        if let message = snapshot?.proxyError { return message }
        if let value = snapshot?.proxy, now.timeIntervalSince1970 - value.observedAt > 30 {
            return "网络样本已过期，等待后台更新"
        }
        return nil
    }
    var live: Bool {
        guard let s = snapshot else { return false }
        let elapsed = now.timeIntervalSince1970 - s.capturedAt
        return error == nil && s.health.state == "running" && MonitorSnapshotTiming.isCurrent(capturedAt: s.capturedAt, now: now.timeIntervalSince1970)
            && (s.health.heartbeatAge ?? 99) + elapsed <= 30
    }
    var proxyFresh: Bool {
        proxy != nil
    }
    var heroTitle: String {
        guard snapshot != nil else { return error == nil ? "正在连接监控" : "暂时无法读取" }
        guard live else { return "监控状态待检查" }
        switch snapshot?.health.mode {
        case "ACTIVE": return "授权会话监控中"
        case "GUARD": return "后台警戒中"
        default: return "运行模式待确认"
        }
    }
    var entryTitle: String {
        guard let p = proxy else { return "等待采样" }
        guard proxyFresh else { return "待刷新" }
        switch p.entryState {
        case "verified": return "已确认"
        case "mismatch": return "身份不符"
        case "unavailable": return "不可用"
        default: return "待确认"
        }
    }
    var chainTitle: String {
        guard let p = proxy else { return "等待采样" }
        guard !p.flows.isEmpty else { return "暂无样本" }
        guard proxyFresh else { return "待刷新" }
        if p.flows.contains(where: { $0.policy == "mismatch" }) { return "发现差异" }
        if p.flows.allSatisfy({ $0.association == "correlated" && $0.policy == "match" }) { return "样本匹配" }
        return "部分待确认"
    }
}

