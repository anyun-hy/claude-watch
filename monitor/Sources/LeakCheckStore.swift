import Foundation
import Combine
import WebKit

final class DNSProbeRunner: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false
    func cancel() {
        lock.lock(); cancelled = true; let task = process; lock.unlock()
        if task?.isRunning == true { task?.terminate() }
    }
    func run() -> LeakProbeResult {
        let executable: URL
        let arguments: [String]
        if case .rustCandidate? = BundledBackendVariant.current() {
            guard let engine = Bundle.main.url(forResource: "watch-engine", withExtension: nil),
                  FileManager.default.isExecutableFile(atPath: engine.path) else {
                return .failure(.dns, code: "component_missing", message: "Rust DNS 采集组件不可用。")
            }
            executable = engine; arguments = ["dns-probe"]
        } else {
            guard let script = Bundle.main.url(forResource: "dns_probe", withExtension: "py"),
                  let python = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"].first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
                return .failure(.dns, code: "component_missing", message: "DNS 采集组件或 Python 3 不可用。")
            }
            executable = URL(fileURLWithPath: python); arguments = [script.path]
        }
        let task = Process(), output = Pipe()
        task.executableURL = executable; task.arguments = arguments
        task.standardOutput = output; task.standardError = FileHandle.nullDevice
        lock.lock()
        if cancelled { lock.unlock(); return .failure(.dns, code: "cancelled", message: "本轮检测已取消。") }
        process = task
        do { try task.run() } catch {
            process = nil; lock.unlock()
            return .failure(.dns, code: "launch_failed", message: "DNS 采集组件未能启动。")
        }
        lock.unlock()
        let timeout = DispatchWorkItem { [weak self] in self?.cancel() }
        DispatchQueue.global().asyncAfter(deadline: .now() + 30, execute: timeout)
        let data = output.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit(); timeout.cancel()
        lock.lock(); process = nil; let wasCancelled = cancelled; lock.unlock()
        guard !wasCancelled else { return .failure(.dns, code: "timeout", message: "DNS 检测超过本轮时限或已取消。") }
        guard task.terminationStatus == 0, data.count <= 65_536,
              let result = try? JSONDecoder().decode(LeakProbeResult.self, from: data) else {
            return .failure(.dns, code: "invalid_result", message: "DNS 采集结果无效或执行失败，不能判断出口。")
        }
        return result
    }
}

@MainActor
final class WebRTCProbeRunner: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
    #if LEAK_BRIDGE_TEST
    var testBootstrap: String?
    #endif
    private var webView: WKWebView?
    private var completion: ((LeakProbeResult) -> Void)?
    private var runID: String?
    private var documentURL: URL?
    private var watchdog: DispatchWorkItem?

    func start(id: UUID, completion: @escaping (LeakProbeResult) -> Void) {
        self.runID = id.uuidString; self.completion = completion
        guard let file = Bundle.main.url(forResource: "webrtc_probe", withExtension: "html") else {
            finish(.failure(.webrtc, code: "component_missing", message: "WebRTC 检测页面不可用。")); return
        }
        documentURL = file
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
        #if LEAK_BRIDGE_TEST
        if let testBootstrap {
            configuration.userContentController.addUserScript(WKUserScript(source: testBootstrap, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        }
        #endif
        configuration.userContentController.add(self, name: "leakProbe")
        let view = WKWebView(frame: .zero, configuration: configuration)
        view.navigationDelegate = self; webView = view
        let work = DispatchWorkItem { [weak self] in
            self?.finish(.failure(.webrtc, code: "timeout", message: "WebRTC 页面未在时限内完成；没有结果不代表无泄漏。"))
        }
        watchdog = work; DispatchQueue.main.asyncAfter(deadline: .now() + 22, execute: work)
        view.loadFileURL(file, allowingReadAccessTo: file.deletingLastPathComponent())
    }
    func cancel() {
        if let runID {
            webView?.evaluateJavaScript("window.ClaudeWatchProbe && window.ClaudeWatchProbe.cancel('\(runID)')", completionHandler: nil)
        }
        cleanup()
    }
    private func cleanup() {
        watchdog?.cancel(); watchdog = nil
        webView?.configuration.userContentController.removeScriptMessageHandler(forName: "leakProbe")
        webView?.stopLoading(); webView?.navigationDelegate = nil
        webView = nil; completion = nil; runID = nil
    }
    private func finish(_ result: LeakProbeResult) {
        let done = completion
        cancel()
        done?(result)
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard webView === self.webView, let runID else { return }
        // Return a plain scalar to WebKit; the probe sends its async receipt via
        // the native handler instead of asking evaluateJavaScript to bridge a Promise.
        let script = "if (!window.ClaudeWatchProbe) { throw new Error('probe missing'); } window.ClaudeWatchProbe.run({runID:'\(runID)', timeoutMs:8000}); true;"
        webView.evaluateJavaScript(script) { [weak self] _, error in
            guard let self, self.runID == runID, error != nil else { return }
            self.finish(.failure(.webrtc, code: "javascript_unavailable", message: "WebRTC 检测脚本不可用，未完成采样。"))
        }
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        finish(.failure(.webrtc, code: "page_failed", message: "本地 WebRTC 检测页加载失败。"))
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        finish(.failure(.webrtc, code: "page_failed", message: "本地 WebRTC 检测页未能打开。"))
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        decisionHandler(navigationAction.request.url == documentURL ? .allow : .cancel)
    }
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let view = webView, let expectedID = runID,
              message.frameInfo.isMainFrame, message.webView === view,
              let body = message.body as? [String: Any], body["runID"] as? String == expectedID,
              let payload = body["payload"], JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload), data.count <= 65_536,
              let result = try? JSONDecoder().decode(LeakProbeResult.self, from: data) else { return }
        finish(result)
    }
}

enum LeakProbeSource: String, CaseIterable { case netCoffee = "Net.Coffee", original = "原有检测" }
enum DNSProbeSource: String, CaseIterable { case netCoffee = "Net.Coffee", ipLeak = "IPLeak.net" }

enum LeakFixtureScenario: String, CaseIterable {
    case matched = "样本一致", difference = "出口差异", timeout = "检测超时", empty = "没有结果"
    case partial = "部分失败", missingReference = "缺少 HTTP 参考", ipv6 = "缺少 IPv6 参考", stale = "结果过期", noPolicy = "DNS 未设预期"
}

@MainActor
final class LeakCheckStore: ObservableObject {
    @Published var source: LeakProbeSource = .netCoffee
    @Published var deepDNS = false
    @Published private(set) var dnsSource: DNSProbeSource = .netCoffee
    @Published var ipLeakDeepDNS = false
    @Published private(set) var ipLeakDNS = LeakCheckState()
    @Published private(set) var ipLeakProgress: String?
    @Published private(set) var ipLeakBrowserView: WKWebView?
    @Published private(set) var progress: [LeakKind: String] = [:]
    @Published private(set) var browserViews: [LeakKind: WKWebView] = [:]
    private var coffeeRunners: [LeakKind: NetCoffeeLeakRunner] = [:]
    @Published var rtcExpected = "" { didSet { reevaluate(.webrtc) } }
    @Published private(set) var dns = LeakCheckState()
    @Published private(set) var rtc = LeakCheckState()
    @Published var now = Date() { didSet { reevaluate(.dns); reevaluate(.webrtc); reevaluateIPLeak(at: now) } }
    let isFixture: Bool
    var fixtureDelayNanoseconds: UInt64 = 350_000_000
    var fixtureScenario: LeakFixtureScenario = .matched
    var contextProvider: (() -> String?)?
    /// New automatic probes require a directly current identity. The ordinary
    /// context provider may retain a short value only to finish an in-flight
    /// probe without inventing a network change.
    var automaticContextProvider: (() -> String?)?
    /// The owner persists a complete DNS receipt through the backend.  This is
    /// deliberately a callback: the UI never writes the policy receipt itself.
    var onDNSComplete: ((LeakProbeResult) async -> Bool)?
    var onWebRTCComplete: ((LeakProbeResult) async -> Bool)?
    private var runs: [LeakKind: UUID] = [:]
    private var runLogSources: [LeakKind: String] = [:]
    private struct ContextSnapshot { let required: Bool; let value: String? }
    private var contexts: [LeakKind: ContextSnapshot] = [:]
    private var lastAutomaticDNSAt: Date?
    private var lastAutomaticDNSContext: String?
    private var lastAutomaticProbeAt: Date?
    private var lastAutomaticProbeContext: String?
    private var lastAutomaticWebRTCAt: Date?
    private var lastAutomaticWebRTCContext: String?
    private var dnsRunner: DNSProbeRunner?
    private var rtcRunner: WebRTCProbeRunner?
    private var fixtureTasks: [LeakKind: Task<Void, Never>] = [:]
    private var dnsReceiptSubmitting = false
    private var lastRecordedDNSAt: Date?
    private var lastRecordedDNSContext: String?
    private var webRTCReceiptSubmitting = false
    private var lastRecordedWebRTCAt: Date?
    private var lastRecordedWebRTCContext: String?
    private var ipLeakRunner: IPLeakDNSRunner?
    private var ipLeakRun: UUID?
    private var ipLeakContext: ContextSnapshot?
    private var ipLeakFixtureTask: Task<Void, Never>?

    init(isFixture: Bool = false) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
    }
    private func state(_ kind: LeakKind) -> LeakCheckState { kind == .dns ? dns : rtc }
    private func expected(_ kind: LeakKind) -> String { kind == .dns ? "" : rtcExpected }
    private func set(_ state: LeakCheckState, for kind: LeakKind) { if kind == .dns { dns = state } else { rtc = state } }
    private func automaticContext() -> String? {
        if let automaticContextProvider { return automaticContextProvider() }
        return contextProvider?()
    }
    private func discardHistoricalResultIfContextChanged(_ kind: LeakKind) {
        var value = state(kind)
        guard value.lastSuccessfulContextRequired else { return }
        // A missing context is an observer gap, not a confirmed replacement.
        // Keep the historical receipt for explanation, but the active result
        // remains incomplete until a current context is available.
        guard let current = contextProvider?(), current != value.lastSuccessfulContext else { return }
        value.lastSuccessfulResult = nil
        value.lastSuccessfulContext = nil
        value.lastSuccessfulContextRequired = false
        set(value, for: kind)
    }
    func changeSource(_ value: LeakProbeSource) {
        guard source != value else { return }
        cancel(.webrtc); set(LeakCheckState(), for: .webrtc)
        source = value
    }
    func changeDNSSource(_ value: DNSProbeSource) {
        dnsSource = value
    }
    func startIPLeakDNS() {
        guard !ipLeakDNS.running else { return }
        let id = UUID(); ipLeakRun = id
        ipLeakContext = ContextSnapshot(required: contextProvider != nil, value: contextProvider?())
        ipLeakDNS = .init(running: true, verdict: .running)
        if isFixture {
            ipLeakFixtureTask = Task { [weak self] in
                guard let delay = self?.fixtureDelayNanoseconds else { return }
                do { try await Task.sleep(nanoseconds: delay) } catch { return }
                guard let self else { return }
                let sample = Self.fixture(.dns, scenario: self.fixtureScenario, at: Date())
                let observations = sample.observations.map { item in
                    LeakObservation(address: item.address, kind: item.kind,
                                    source: item.kind == "resolver" ? "IPLeak DNS（模拟）" : "IPLeak HTTP（模拟）",
                                    family: item.family, country: item.country)
                }
                let comparison = LeakProbeResult(kind: sample.kind, status: sample.status,
                    startedAt: sample.startedAt, finishedAt: sample.finishedAt, scope: "IPLeak.net · 本机 WebView DNS 对照（模拟）",
                    observations: observations, errors: sample.errors, contextChanged: sample.contextChanged, details: sample.details)
                self.completeIPLeakDNS(id: id, result: comparison)
            }
            return
        }
        let runner = IPLeakDNSRunner(); ipLeakRunner = runner
        ipLeakProgress = "准备 IPLeak 备用检测"
        runner.start(rounds: ipLeakDeepDNS ? 8 : 5, id: id, progress: { [weak self] text in
            guard self?.ipLeakRun == id else { return }; self?.ipLeakProgress = text
        }) { [weak self] result in self?.completeIPLeakDNS(id: id, result: result) }
        ipLeakBrowserView = runner.browserView
    }
    func cancelIPLeakDNS() {
        guard ipLeakDNS.running else { return }
        ipLeakRun = nil; ipLeakFixtureTask?.cancel(); ipLeakFixtureTask = nil
        ipLeakRunner?.cancel(); ipLeakRunner = nil; ipLeakBrowserView = nil; ipLeakProgress = nil
        ipLeakContext = nil; ipLeakDNS = .init(verdict: .cancelled)
    }
    private func completeIPLeakDNS(id: UUID, result: LeakProbeResult) {
        guard ipLeakRun == id else { return }
        ipLeakRun = nil; ipLeakFixtureTask = nil; ipLeakRunner = nil; ipLeakBrowserView = nil; ipLeakProgress = nil
        var sample = result
        if let context = ipLeakContext, context.required {
            if let original = context.value, let current = contextProvider?() {
                if original != current { sample.contextChanged = true }
            } else { sample.contextChanged = true }
        }
        ipLeakDNS = .init(result: sample)
        reevaluateIPLeak(at: Date())
        if !isFixture, let event = EventDiagnosticInput.make(kind: .dns, source: "ipleak", result: ipLeakDNS.result ?? sample,
                                                              verdict: ipLeakDNS.verdict.state) {
            EventDiagnosticLogger.submit(event)
        }
    }
    private func reevaluateIPLeak(at date: Date) {
        guard !ipLeakDNS.running, var sample = ipLeakDNS.result else { return }
        if let context = ipLeakContext, context.required {
            guard let original = context.value, let current = contextProvider?() else {
                ipLeakDNS.verdict = .init(state: .incomplete, title: "检测未完成", detail: "本轮代理上下文暂不可确认。")
                return
            }
            if original != current { sample.contextChanged = true }
        }
        ipLeakDNS.result = sample
        ipLeakDNS.verdict = LeakPolicy.evaluate(sample, kind: .dns, expected: "", now: date.timeIntervalSince1970)
    }
    func start(_ kind: LeakKind) {
        guard !state(kind).running else { return }
        discardHistoricalResultIfContextChanged(kind)
        guard kind == .dns || (try? LeakPolicy.expectedAddresses(expected(kind))) != nil else {
            var value = state(kind); value.inputError = LeakPolicy.invalidInput
            value.verdict = .init(state: .incomplete, title: "预期地址无效", detail: LeakPolicy.invalidInput)
            set(value, for: kind); return
        }
        now = Date()
        let id = UUID(); runs[kind] = id
        runLogSources[kind] = kind == .dns || source == .netCoffee ? "netcoffee" : "local"
        contexts[kind] = ContextSnapshot(required: contextProvider != nil, value: contextProvider?())
        // Keep the last receipt visible while a periodic refresh is in flight.
        // A running verdict still makes clear that the previous receipt cannot
        // authorize a new launch.
        var updating = state(kind)
        updating.running = true; updating.verdict = .running; updating.inputError = nil
        set(updating, for: kind)
        if isFixture {
            fixtureTasks[kind]?.cancel()
            fixtureTasks[kind] = Task { [weak self] in
                guard let delay = self?.fixtureDelayNanoseconds else { return }
                do { try await Task.sleep(nanoseconds: delay) } catch { return }
                guard let self else { return }
                self.complete(kind, id: id, result: Self.fixture(kind, scenario: self.fixtureScenario, at: Date()))
            }
        } else if kind == .dns || source == .netCoffee {
            let runner = NetCoffeeLeakRunner(); coffeeRunners[kind] = runner
            progress[kind] = "准备 Net.Coffee 采集"
            runner.start(kind: kind, rounds: deepDNS ? 8 : 5, id: id, progress: { [weak self] text in
                guard self?.runs[kind] == id else { return }; self?.progress[kind] = text
            }) { [weak self] result in self?.complete(kind, id: id, result: result) }
            browserViews[kind] = runner.browserView
        } else {
            let runner = WebRTCProbeRunner(); rtcRunner = runner
            runner.start(id: id) { [weak self] result in self?.complete(kind, id: id, result: result) }
        }
    }
    /// Runs the same DNS/WebView collector used by the dedicated page.  It is
    /// rate-limited and retains the previous receipt while updating.
    func refreshLeakChecksIfNeeded(interval: TimeInterval = 60, networkChanged: Bool = false) {
        let context = automaticContext()
        guard (automaticContextProvider == nil && contextProvider == nil) || (context?.isEmpty == false) else { return }
        let dnsChanged = context != lastAutomaticDNSContext
        let dnsElapsed = lastAutomaticDNSAt.map { Date().timeIntervalSince($0) } ?? .infinity
        if networkChanged || dnsChanged || dnsElapsed >= interval {
            lastAutomaticDNSAt = Date(); lastAutomaticDNSContext = context
            if !dns.running { start(.dns) }
        }
        guard source == .netCoffee else { return }
        let contextChanged = context != lastAutomaticProbeContext
        let elapsed = lastAutomaticProbeAt.map { Date().timeIntervalSince($0) } ?? .infinity
        guard networkChanged || contextChanged || elapsed >= interval else { return }
        lastAutomaticProbeAt = Date(); lastAutomaticProbeContext = context
        if !rtc.running { start(.webrtc) }
    }
    func refreshWebRTCIfNeeded(interval: TimeInterval = 60) {
        guard source == .netCoffee, !state(.webrtc).running else { return }
        let context = automaticContext()
        guard (automaticContextProvider == nil && contextProvider == nil) || (context?.isEmpty == false) else { return }
        let changed = context != lastAutomaticWebRTCContext
        let elapsed = lastAutomaticWebRTCAt.map { Date().timeIntervalSince($0) } ?? .infinity
        guard changed || elapsed >= interval else { return }
        lastAutomaticWebRTCAt = Date(); lastAutomaticWebRTCContext = context
        start(.webrtc)
    }
    func ensureFreshDNSReceipt(maximumWait: TimeInterval = 80) async -> Bool {
        let context = automaticContext()
        guard (automaticContextProvider == nil && contextProvider == nil) || (context?.isEmpty == false) else { return false }
        let age = lastRecordedDNSAt.map { Date().timeIntervalSince($0) } ?? .infinity
        if age <= 10, context == lastRecordedDNSContext, !dnsReceiptSubmitting { return true }
        if !state(.dns).running { start(.dns) }
        let deadline = Date().addingTimeInterval(maximumWait)
        while Date() < deadline {
            if !state(.dns).running && !dnsReceiptSubmitting {
                let recordedAge = lastRecordedDNSAt.map { Date().timeIntervalSince($0) } ?? .infinity
                return recordedAge <= 10 && contextProvider?() == lastRecordedDNSContext
            }
            try? await Task.sleep(nanoseconds: 150_000_000)
        }
        return false
    }
    /// First-run requires both a real passing result and its accepted backend
    /// receipt. A completed WebView alone is not enough to open the main UI.
    func initializationReceiptIsCurrent(_ kind: LeakKind, at date: Date = Date()) -> Bool {
        let value = state(kind)
        guard !value.running, value.verdict.state == .matched,
              let result = value.result, !result.contextChanged,
              let context = automaticContext(), contexts[kind]?.value == context else { return false }
        let submitted = kind == .dns ? lastRecordedDNSAt : lastRecordedWebRTCAt
        let submittedContext = kind == .dns ? lastRecordedDNSContext : lastRecordedWebRTCContext
        let submitting = kind == .dns ? dnsReceiptSubmitting : webRTCReceiptSubmitting
        guard !submitting, let submitted, submittedContext == context,
              submitted.timeIntervalSince1970 == result.finishedAt else { return false }
        return (0..<300).contains(date.timeIntervalSince1970 - result.finishedAt)
    }
    func ensureInitializationReceipt(_ kind: LeakKind, maximumWait: TimeInterval = 85) async -> Bool {
        now = Date()
        if initializationReceiptIsCurrent(kind) { return true }
        guard automaticContext()?.isEmpty == false else { return false }
        if !state(kind).running { start(kind) }
        let deadline = Date().addingTimeInterval(maximumWait)
        while Date() < deadline && !Task.isCancelled {
            let submitting = kind == .dns ? dnsReceiptSubmitting : webRTCReceiptSubmitting
            if !state(kind).running && !submitting {
                now = Date()
                return initializationReceiptIsCurrent(kind)
            }
            try? await Task.sleep(nanoseconds: 150_000_000)
        }
        return false
    }
    func adoptInitializationReceipts() {
        lastAutomaticDNSAt = lastRecordedDNSAt; lastAutomaticDNSContext = lastRecordedDNSContext
        lastAutomaticWebRTCAt = lastRecordedWebRTCAt; lastAutomaticWebRTCContext = lastRecordedWebRTCContext
    }
    func cancel(_ kind: LeakKind) {
        guard state(kind).running else { return }
        browserViews[kind] = nil; coffeeRunners[kind]?.cancel(); coffeeRunners[kind] = nil; progress[kind] = nil
        runs[kind] = nil; fixtureTasks[kind]?.cancel(); fixtureTasks[kind] = nil
        runLogSources[kind] = nil
        if kind == .dns { dnsRunner?.cancel(); dnsRunner = nil }
        else { rtcRunner?.cancel(); rtcRunner = nil }
        var cancelled = state(kind)
        cancelled.running = false; cancelled.result = nil; cancelled.verdict = .cancelled; cancelled.inputError = nil
        set(cancelled, for: kind)
    }
    private func complete(_ kind: LeakKind, id: UUID, result: LeakProbeResult) {
        guard runs[kind] == id else { return }
        let logSource = runLogSources.removeValue(forKey: kind)
        browserViews[kind] = nil; runs[kind] = nil; fixtureTasks[kind] = nil; coffeeRunners[kind] = nil; progress[kind] = nil
        if kind == .dns { dnsRunner = nil } else { rtcRunner = nil }
        now = Date()
        var completed = result
        if let context = contexts[kind], context.required {
            if let original = context.value, let current = contextProvider?() {
                if current != original { completed.contextChanged = true }
            } else { completed.contextChanged = true }
        }
        let previous = state(kind)
        set(LeakCheckState(running: false, result: completed, lastSuccessfulResult: previous.lastSuccessfulResult,
                           lastSuccessfulContext: previous.lastSuccessfulContext,
                           lastSuccessfulContextRequired: previous.lastSuccessfulContextRequired,
                           verdict: .idle, inputError: nil), for: kind)
        reevaluate(kind)
        rememberSuccessfulResult(kind)
        if !isFixture, let logSource,
           let event = EventDiagnosticInput.make(kind: kind, source: logSource, result: state(kind).result ?? completed,
                                                 verdict: state(kind).verdict.state) {
            EventDiagnosticLogger.submit(event)
        }
        if kind == .dns, let onDNSComplete {
            dnsReceiptSubmitting = true
            let boundContext = contextProvider?()
            Task { [weak self] in
                let stored = await onDNSComplete(completed)
                guard let self else { return }
                self.dnsReceiptSubmitting = false
                if stored {
                    self.lastRecordedDNSAt = Date(timeIntervalSince1970: completed.finishedAt)
                    self.lastRecordedDNSContext = boundContext
                } else {
                    self.lastRecordedDNSAt = nil; self.lastRecordedDNSContext = nil
                }
            }
        }
        if kind == .webrtc, let onWebRTCComplete {
            webRTCReceiptSubmitting = true
            let boundContext = contextProvider?()
            Task { [weak self] in
                let stored = await onWebRTCComplete(completed)
                guard let self else { return }
                self.webRTCReceiptSubmitting = false
                self.lastRecordedWebRTCAt = stored ? Date(timeIntervalSince1970: completed.finishedAt) : nil
                self.lastRecordedWebRTCContext = stored ? boundContext : nil
            }
        }
    }
    private func reevaluate(_ kind: LeakKind) {
        discardHistoricalResultIfContextChanged(kind)
        var value = state(kind)
        guard !value.running else { return }
        value.inputError = kind == .dns ? nil : ((try? LeakPolicy.expectedAddresses(expected(kind))) == nil ? LeakPolicy.invalidInput : nil)
        if var result = value.result {
            if let context = contexts[kind], context.required {
                guard let original = context.value, let current = contextProvider?() else {
                    value.verdict = .init(state: .incomplete, title: "检测未完成", detail: "本轮代理上下文暂不可确认，保留地址观测，请在后台采样就绪后重新检测。")
                    set(value, for: kind); return
                }
                if current != original { result.contextChanged = true }
            }
            value.result = result
            value.verdict = LeakPolicy.evaluate(result, kind: kind, expected: expected(kind), now: now.timeIntervalSince1970)
        }
        set(value, for: kind)
    }
    private func rememberSuccessfulResult(_ kind: LeakKind) {
        var value = state(kind)
        if case .matched = value.verdict.state {
            value.lastSuccessfulResult = value.result
            value.lastSuccessfulContextRequired = contexts[kind]?.required ?? false
            value.lastSuccessfulContext = contexts[kind]?.value
        }
        set(value, for: kind)
    }
    func loadRecordedCoffeeFixture() {
        guard isFixture, let url = Bundle.main.url(forResource:"coffee-live-leak-results",withExtension:"json"),
              let bytes = try? Data(contentsOf:url), let results = try? JSONDecoder().decode([LeakProbeResult].self,from:bytes) else { return }
        rtcExpected = ""; source = .netCoffee; now = Date()
        for result in results {
            guard let kind = LeakKind(rawValue:result.kind) else { continue }
            cancel(kind); contexts[kind] = nil
            var sample = result
            sample = LeakProbeResult(kind:sample.kind,status:sample.status,startedAt:sample.startedAt,finishedAt:sample.finishedAt,scope:sample.scope+"（实测回放）",observations:sample.observations,errors:sample.errors,contextChanged:sample.contextChanged,details:sample.details+["隔离预览展示已录制的本机实测，不自动发起新检测。"],externalJSON:sample.externalJSON)
            set(.init(result:sample),for:kind); reevaluate(kind); rememberSuccessfulResult(kind)
        }
    }
    func loadReviewWebRTC(_ result: LeakProbeResult) {
        guard isFixture, result.kind == LeakKind.webrtc.rawValue else { return }
        contexts[.webrtc] = nil
        set(.init(result: result), for: .webrtc)
        now = Date()
        reevaluate(.webrtc)
        rememberSuccessfulResult(.webrtc)
    }
    func loadFixture(_ scenario: LeakFixtureScenario) {
        guard isFixture else { return }
        for kind in LeakKind.allCases { cancel(kind) }
        fixtureScenario = scenario; rtcExpected = ""
        now = Date()
        for kind in LeakKind.allCases {
            contexts[kind] = nil
            set(.init(result: Self.fixture(kind, scenario: scenario, at: now)), for: kind)
            reevaluate(kind); rememberSuccessfulResult(kind)
        }
    }
    static func fixture(_ kind: LeakKind, scenario: LeakFixtureScenario, at date: Date) -> LeakProbeResult {
        let epoch = date.timeIntervalSince1970 - (scenario == .stale ? 400 : 0)
        var observations: [LeakObservation] = [.init(address: "1.1.1.1", kind: "http", source: "HTTP 参考（模拟）", family: 4, country: "JP")]
        if kind == .dns {
            observations.append(.init(address: scenario == .difference ? "8.8.4.4" : "8.8.8.8", kind: "resolver", source: "Akamai NS（模拟）", family: 4, country: scenario == .difference ? "CN" : "JP"))
        } else {
            observations += ["Google STUN（模拟）", "Cloudflare STUN（模拟）"].map {
                LeakObservation(address: scenario == .difference ? "8.8.4.4" : "1.1.1.1", kind: "srflx", source: $0, family: 4, country: scenario == .difference ? "CN" : "JP")
            }
        }
        var errors: [LeakProbeError] = []; var status = "complete"
        if scenario == .timeout { status = "timeout"; errors = [.init(stage: "probe", code: "timeout", message: "模拟超时；已有地址不能构成完整检测。") ] }
        if scenario == .partial { status = "partial"; errors = [.init(stage: "probe", code: "service_failed", message: "一个诊断服务未完成，保留其他有效观测。") ] }
        if scenario == .empty { observations = [] }
        if scenario == .missingReference { observations.removeAll { $0.kind == "http" } }
        if scenario == .ipv6 { observations.append(.init(address: "2606:4700:4700::1111", kind: kind == .dns ? "resolver" : "srflx", source: "IPv6（模拟）", family: 6)) }
        return LeakProbeResult(kind: kind.rawValue, status: status, startedAt: epoch - 2, finishedAt: epoch,
            scope: kind == .dns ? "dig/resolv.conf DNS 路径（模拟）" : "当前检测 WebView（模拟）",
            observations: observations, errors: errors, contextChanged: false,
            details: ["此结果为隔离模拟数据；未调用网络、DNS、STUN 或真实 WebView。"])
    }
}
