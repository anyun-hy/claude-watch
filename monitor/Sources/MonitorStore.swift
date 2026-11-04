import Foundation
import Combine
import UserNotifications
import AppKit

@MainActor
final class MonitorStore: ObservableObject {
    let leakChecks: LeakCheckStore
    let aiChecks: AIProbeStore
    let netCoffee = NetCoffeeStore()
    let processControl = AIProcessControl()
    let switcher: SwitcherStore
    /// First-run owns diagnostic/mutation sequencing; the timer only reads snapshots.
    @Published private(set) var initializing = false
    @Published var snapshot: MonitorSnapshot?
    @Published var error: String?
    @Published var refreshing = false
    @Published var automatic = true
    @Published private(set) var notificationAccess = WatchNotificationAccess.unknown
    /// Live desktop-app presence, read every fast tick straight from AppKit
    /// (`NSRunningApplication`) with no backend round-trip. This is the cheap
    /// "fast lane" that keeps the launch/quit buttons accurate within ~2s even
    /// though the full backend snapshot (CLI/daemon/connections) still arrives
    /// on the relaxed ~20s cadence.
    @Published private(set) var desktopRunning: [MonitoredProduct: Bool] = [:]
    @Published var page: Page = .environment
    @Published var now = Date()
    @Published var networkSelection = NetworkGraphSelection()
    @Published private(set) var graphContinuity = GraphContinuityStore()
    @Published private(set) var serverReferences: [String: ServerReference] = [:]
    private var referenceQueryRunning = false
    private var referenceQueriesEnabled = false
    private var timer: Timer?
    private var workspaceObserver: WorkspaceAppObserver?
    private var lastFull: Date = .distantPast
    private var lastBackgroundRead: Date = .distantPast
    private var backgroundReadRunning = false
    private var environmentRefreshScheduler = EnvironmentRefreshScheduler()
    private var diagnosticContext = DiagnosticContextTracker()
    private var refreshGate = MonitorRefreshGate()
    private var notificationRequestGeneration = 0
    init(leakChecks: LeakCheckStore? = nil, aiChecks: AIProbeStore? = nil, switcher: SwitcherStore? = nil) {
        self.leakChecks = leakChecks ?? LeakCheckStore()
        self.aiChecks = aiChecks ?? AIProbeStore()
        self.switcher = switcher ?? SwitcherStore()
        let bindingContext: () -> String? = { [weak self] in self?.retainedDiagnosticContext() }
        let currentContext: () -> String? = { [weak self] in self?.currentDiagnosticContext() }
        self.leakChecks.contextProvider = bindingContext
        self.leakChecks.automaticContextProvider = currentContext
        self.switcher.diagnosticContextProvider = bindingContext
        self.leakChecks.onDNSComplete = { [weak self] result, runID in
            guard let self else { return false }
            return await self.switcher.recordDNSLeak(result, runID: runID)
        }
        self.leakChecks.onWebRTCComplete = { [weak self] result, runID in
            guard let self else { return false }
            return await self.switcher.recordWebRTCRisk(result, runID: runID)
        }
        self.switcher.awaitFreshDNSReceipt = { [weak self] maximumAge in
            guard let self else { return false }
            return await self.leakChecks.ensureFreshDNSReceipt(maximumAge: maximumAge)
        }
        self.switcher.onDNSReceiptRecorded = { [weak self] in
            self?.requestEnvironmentRefreshAfterDNS()
        }
        self.switcher.onWebRTCRiskRecorded = { [weak self] in
            guard let self, !self.initializing else { return }
            Task { await self.switcher.refreshBackground() }
        }
        self.switcher.onReceiptDiagnostic = { kind, event, runID, code in
            guard case .rustCandidate? = BundledBackendVariant.current(), let runID else { return }
            if event != "receipt_accepted" { LeakDiagnosticTrace.shared.record(kind: kind.rawValue, event: event, run: runID) }
            let input = ReceiptDiagnosticInput(kind: kind.rawValue, outcome: event == "receipt_accepted" ? "accepted" : "rejected", code: code ?? "none", run_id: runID.uuidString)
            if let data = try? JSONEncoder().encode(input) { DiagnosticLogRunner.submit(data, command: "receipt-diagnostic") }
        }
        self.aiChecks.contextProvider = bindingContext
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
        if !initializing { refreshBackgroundIfNeeded(at: Date()) }
        referenceQueriesEnabled = !initializing
        refresh(full: true)
        // Desktop app launches/terminations are now event-driven: the moment
        // macOS posts a launch/quit notification for a supervised app, the
        // snapshot re-reads immediately (no polling lag). The timer below is
        // only the coarse fallback for CLI processes and health freshness.
        if workspaceObserver == nil {
            workspaceObserver = WorkspaceAppObserver { [weak self] in
                guard let self else { return }
                self.refresh(full: true, manual: true)
            }
            workspaceObserver?.start()
        }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.monitorTick(at: Date())
            }
        }
    }
    func refreshNotificationAccess() async {
        guard !switcher.isFixture else { return }
        await readNotificationAccess {
            let settings = await UNUserNotificationCenter.current().notificationSettings()
            return .classify(settings.authorizationStatus, alert: settings.alertSetting, style: settings.alertStyle)
        }
    }
    private func readNotificationAccess(_ reader: () async -> WatchNotificationAccess) async {
        notificationRequestGeneration += 1
        let generation = notificationRequestGeneration
        let value = await reader()
        guard generation == notificationRequestGeneration else { return }
        notificationAccess = value
    }
    #if UI_REVIEW
    func refreshNotificationAccessForFixture(_ reader: () async -> WatchNotificationAccess) async {
        guard switcher.isFixture else { return }
        await readNotificationAccess(reader)
    }
    #endif
    func monitorTick(at date: Date) {
        now = date
        leakChecks.now = date
        aiChecks.now = date
        // The cheap desktop-presence fast lane runs every tick regardless of
        // automatic detection state, so launch/quit buttons stay accurate even
        // when background network detection is paused.
        refreshDesktopState()
        // Login freshness is a display fact and must age even while automatic
        // network/environment detection is paused.
        switcher.advanceLoginClock(date)
        guard automatic else {
            if case .rustCandidate? = BundledBackendVariant.current() { LeakDiagnosticTrace.shared.schedule(kind: "all", event: "schedule_disabled") }
            return
        }
        if initializing {
            if case .rustCandidate? = BundledBackendVariant.current() { LeakDiagnosticTrace.shared.schedule(kind: "all", event: "schedule_initializing") }
            // Initialization also validates the service receipt while waiting
            // for the user. Keep it fresh using the same read-only scheduler as
            // the main view; otherwise a healthy service always appears stale
            // 30 seconds after the final check.
            refreshBackgroundIfNeeded(at: date)
            refresh(full: date.timeIntervalSince(lastFull) >= 20)
            return
        }
        refreshBackgroundIfNeeded(at: date)
        // AX reading is independent and must not delay the snapshot scheduler.
        Task { @MainActor [weak switcher] in
            await switcher?.refreshCurrentLogin()
        }
        // Desktop app changes arrive via WorkspaceAppObserver; this interval is
        // the coarse fallback for CLI processes (no .app launch event) and for
        // general health freshness, so it can stay relaxed.
        refresh(full: date.timeIntervalSince(lastFull) >= 20)
    }
    /// Reads the supervised desktop apps' presence straight from AppKit. This is
    /// the fast lane: `NSRunningApplication` answers in microseconds and never
    /// touches the Rust backend, so it can run on the 2s tick while the full
    /// snapshot (which also resolves CLI/daemon/connections) stays at ~20s.
    /// The bundle-id → product mapping mirrors `WorkspaceAppObserver` and the
    /// desktop attribution in `AIProcessInventory.read()`.
    private func refreshDesktopState() {
        let claudeBundles = Set(["com.anthropic.claudefordesktop"])
        let openAIBundles = Set(["com.openai.codex", "com.openai.chat"])
        let running = NSWorkspace.shared.runningApplications
        let claudeRunning = running.contains { app in
            app.bundleIdentifier.map(claudeBundles.contains) ?? false
        }
        let openAIRunning = running.contains { app in
            app.bundleIdentifier.map(openAIBundles.contains) ?? false
        }
        let next: [MonitoredProduct: Bool] = [
            .claude: claudeRunning,
            .openAI: openAIRunning,
        ]
        if next != desktopRunning { desktopRunning = next }
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
            switch result {
            case .success(let value):
                acceptSnapshot(value, receivedAt: completedAt)
            case .failure(let message):
                if case .rustCandidate? = BundledBackendVariant.current() { LeakDiagnosticTrace.shared.schedule(kind: "all", event: "snapshot_failed") }
                error = message
                now = completedAt
                leakChecks.now = completedAt
                aiChecks.now = completedAt
            }
            synchronizeNetworkSelection()
            let repeatManual = refreshGate.complete()
            if refreshing != refreshGate.manualVisible { refreshing = refreshGate.manualVisible }
            if repeatManual { refresh(full: true, manual: true) }
        }
    }
    func acceptSnapshot(_ value: MonitorSnapshot, receivedAt: Date) {
        // A single publication path is shared by first-run and normal polling.
        // Backend capture time remains authoritative; rereads cannot renew it.
        now = max(receivedAt, Date(timeIntervalSince1970: value.capturedAt))
        error = nil
        let transition = observeDiagnosticContext(from: value, at: receivedAt)
        snapshot = value
        // Re-evaluate only after both the tracker and snapshot describe this
        // observation. Otherwise a recovered sampler can leave a fresh
        // receipt marked incomplete until an unrelated later clock tick.
        leakChecks.now = now; aiChecks.now = now
        if automatic && transition == .changed { switcher.invalidateCurrentEnvironmentRequest() }
        if automatic && !initializing {
            leakChecks.refreshWebRTCIfNeeded()
            refreshEnvironmentIfNeeded()
        }
    }
    private func refreshBackgroundIfNeeded(at date: Date, force: Bool = false) {
        guard !backgroundReadRunning, !switcher.busy,
              force || date.timeIntervalSince(lastBackgroundRead) >= 5 else { return }
        backgroundReadRunning = true
        lastBackgroundRead = date
        Task { @MainActor in
            await switcher.refreshBackground()
            backgroundReadRunning = false
        }
    }
    private func refreshEnvironmentIfNeeded() {
        guard !initializing else { return }
        let usableContext = currentDiagnosticContext()
        let busy = switcher.readingEnvironment || switcher.busy
        guard environmentRefreshScheduler.claim(context: usableContext, now: Date(), switcherBusy: busy) != nil else {
            if case .rustCandidate? = BundledBackendVariant.current() {
                LeakDiagnosticTrace.shared.schedule(kind: "dns", event: usableContext == nil ? "schedule_context_missing" : busy ? "schedule_busy" : "schedule_deferred")
            }
            return
        }
        Task { @MainActor [weak self] in
            guard let self else { return }
            let dnsRecorded = await self.leakChecks.ensureFreshDNSReceipt()
            guard self.currentDiagnosticContext() == usableContext else {
                self.environmentRefreshScheduler.complete(context: usableContext, accepted: false, now: Date())
                return
            }
            let accepted = await self.switcher.detectCurrentEnvironment()
            // Do not let a read begun on an older proxy identity publish a
            // complete environment/launch-preview pair after a new identity
            // was confirmed while it was running.
            guard self.currentDiagnosticContext() == usableContext else {
                self.environmentRefreshScheduler.complete(context: usableContext, accepted: false, now: Date())
                return
            }
            self.environmentRefreshScheduler.complete(context: usableContext, accepted: dnsRecorded && accepted, now: Date())
        }
    }
    private func context(from value: ProxySnapshot?) -> String? {
        guard let value, value.entryState == "verified", value.apiState == "available",
              value.coversProxy else { return nil }
        // Must exactly match receipts::tag_signature: DNS/WebRTC receipts bind
        // themselves to both selected and global node values, not a collapsed
        // mode-dependent display node.
        return tagReceiptContext(endpoint: value.endpoint, mode: value.mode,
                                 selectedNode: value.selectedNode, globalNode: value.globalNode)
    }
    private func observeDiagnosticContext(from value: MonitorSnapshot, at date: Date) -> DiagnosticContextTracker.Transition {
        let proxy = freshProxy(in: value, at: date)
        let sourceTime = proxy.map { Date(timeIntervalSince1970: $0.observedAt) } ?? date
        return diagnosticContext.observe(context(from: proxy), observedAt: sourceTime)
    }
    /// Only a directly verified identity can start a new environment round.
    /// A short sampler gap can retain its predecessor for an in-flight probe,
    /// but cannot create a new green environment receipt.
    private func currentDiagnosticContext() -> String? {
        context(from: freshProxy(in: snapshot, at: now))
    }
    var initializationContext: String? { currentDiagnosticContext() }
    func beginInitialization(startSnapshotPolling: Bool = true) {
        initializing = true
        if startSnapshotPolling { start() }
    }
    func finishInitialization() {
        // Preserve the exact receipts just checked; normal polling adopts them
        // instead of clearing or immediately recollecting all page data.
        environmentRefreshScheduler.complete(context: currentDiagnosticContext(), accepted: true, now: Date())
        leakChecks.adoptInitializationReceipts()
        initializing = false
        referenceQueriesEnabled = true
    }
    private func retainedDiagnosticContext() -> String? {
        guard !hasExplicitProxyFailure else { return nil }
        // A directly verified, still-current snapshot is stronger than the
        // short grace used only when an observation is unavailable. Do not
        // discard its identity merely because the producer's next sample has
        // not arrived within that grace window.
        return currentDiagnosticContext() ?? diagnosticContext.retained(at: now)
    }
    private var hasExplicitProxyFailure: Bool {
        guard let value = freshRawProxy(in: snapshot, at: now) else { return false }
        return value.entryState == "mismatch" || value.apiState == "mismatch" || value.selectionChanged
    }
    private func freshRawProxy(in snapshot: MonitorSnapshot?, at date: Date) -> ProxySnapshot? {
        guard error == nil, let snapshot,
              MonitorSnapshotTiming.isCurrent(capturedAt: snapshot.capturedAt, now: date.timeIntervalSince1970),
              let value = snapshot.proxy else { return nil }
        let age = date.timeIntervalSince1970 - value.observedAt
        return (0...MonitorSnapshotTiming.proxyMaximumAge).contains(age) ? value : nil
    }
    private func freshProxy(in snapshot: MonitorSnapshot?, at date: Date) -> ProxySnapshot? {
        guard snapshot?.proxyError == nil else { return nil }
        return freshRawProxy(in: snapshot, at: date)
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
        guard live else { return nil }
        return freshProxy(in: snapshot, at: now)
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

