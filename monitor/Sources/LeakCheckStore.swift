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
    var onDiagnostic: ((String, Bool) -> Void)?
    private func trace(_ event: String) { onDiagnostic?(event, webView?.window != nil) }

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
            self?.trace("watchdog_timeout")
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
        trace("navigation_finished")
        // Return a plain scalar to WebKit; the probe sends its async receipt via
        // the native handler instead of asking evaluateJavaScript to bridge a Promise.
        let script = "if (!window.ClaudeWatchProbe) { throw new Error('probe missing'); } window.ClaudeWatchProbe.run({runID:'\(runID)', timeoutMs:8000}); true;"
        webView.evaluateJavaScript(script) { [weak self] _, error in
            guard let self, self.runID == runID else { return }
            if error == nil { self.trace("script_started"); return }
            self.trace("script_failed")
            self.finish(.failure(.webrtc, code: "javascript_unavailable", message: "WebRTC 检测脚本不可用，未完成采样。"))
        }
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        trace("navigation_failed")
        finish(.failure(.webrtc, code: "page_failed", message: "本地 WebRTC 检测页加载失败。"))
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        trace("navigation_failed")
        finish(.failure(.webrtc, code: "page_failed", message: "本地 WebRTC 检测页未能打开。"))
    }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        guard webView === self.webView else { return }
        trace("webcontent_terminated")
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        decisionHandler(navigationAction.request.url == documentURL ? .allow : .cancel)
    }
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let view = webView, let expectedID = runID,
              message.frameInfo.isMainFrame, message.webView === view,
              let body = message.body as? [String: Any], body["runID"] as? String == expectedID else { trace("message_rejected"); return }
        guard let payload = body["payload"], JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload), data.count <= 65_536,
              let result = try? JSONDecoder().decode(LeakProbeResult.self, from: data) else { trace("payload_invalid"); return }
        trace("payload_received")
        finish(result)
    }
}

enum LeakProbeSource: String, CaseIterable { case netCoffee = "Net.Coffee", original = "原有检测" }

enum LeakFixtureScenario: String, CaseIterable {
    case matched = "样本一致", difference = "出口差异", timeout = "检测超时", empty = "没有结果"
    case partial = "部分失败", missingReference = "缺少 HTTP 参考", ipv6 = "缺少 IPv6 参考", stale = "结果过期", noPolicy = "DNS 未设预期"
}

@MainActor
final class LeakCheckStore: ObservableObject {
    @Published var source: LeakProbeSource = .netCoffee
    @Published var deepDNS = false
    @Published private(set) var progress: [LeakKind: String] = [:]
    @Published private(set) var browserViews: [LeakKind: WKWebView] = [:]
    private var coffeeRunners: [LeakKind: NetCoffeeLeakRunner] = [:]
    @Published var rtcExpected = "" { didSet { reevaluate(.webrtc) } }
    @Published private(set) var dns = LeakCheckState()
    @Published private(set) var rtc = LeakCheckState()
    @Published var now = Date() { didSet { reevaluate(.dns); reevaluate(.webrtc) } }
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
    private var ipLeakRunner: IPLeakDNSRetryRunner?

    init(isFixture: Bool = false) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
    }
    private func state(_ kind: LeakKind) -> LeakCheckState { kind == .dns ? dns : rtc }
    private func trace(_ kind: LeakKind, _ event: String, run: UUID? = nil, attached: Bool? = nil) {
        guard !isFixture, case .rustCandidate? = BundledBackendVariant.current() else { return }
        LeakDiagnosticTrace.shared.record(kind: kind.rawValue, event: event, run: run, attached: attached)
    }
    private func traceSchedule(_ kind: LeakKind, _ event: String) {
        guard !isFixture, case .rustCandidate? = BundledBackendVariant.current() else { return }
        LeakDiagnosticTrace.shared.schedule(kind: kind.rawValue, event: event)
    }
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
        runLogSources[kind] = kind == .dns ? "ipleak" : source == .netCoffee ? "netcoffee" : "local"
        trace(kind, "start", run: id)
        trace(kind, "source_" + (runLogSources[kind] ?? "local"), run: id)
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
        } else if kind == .dns {
            let runner = IPLeakDNSRetryRunner(); ipLeakRunner = runner
            runner.onDiagnostic = { [weak self] event, attached in self?.trace(kind, event, run: id, attached: attached) }
            runner.onViewChanged = { [weak self] browser in
                guard self?.runs[kind] == id else { return }; self?.browserViews[kind] = browser
            }
            progress[kind] = "准备 IPLeak DNS 采集"
            runner.start(rounds: deepDNS ? 8 : 5, id: id, progress: { [weak self] text in
                guard self?.runs[kind] == id else { return }; self?.progress[kind] = text
            }) { [weak self] result in self?.complete(kind, id: id, result: result) }
        } else if source == .netCoffee {
            let runner = NetCoffeeLeakRunner(); coffeeRunners[kind] = runner
            runner.onDiagnostic = { [weak self] event, attached in self?.trace(kind, event, run: id, attached: attached) }
            progress[kind] = "准备 Net.Coffee 采集"
            runner.start(kind: kind, rounds: deepDNS ? 8 : 5, id: id, progress: { [weak self] text in
                guard self?.runs[kind] == id else { return }; self?.progress[kind] = text
            }) { [weak self] result in self?.complete(kind, id: id, result: result) }
            browserViews[kind] = runner.browserView
            trace(kind, runner.browserView?.window == nil ? "host_detached" : "host_attached", run: id,
                  attached: runner.browserView?.window != nil)
        } else {
            let runner = WebRTCProbeRunner(); rtcRunner = runner
            runner.onDiagnostic = { [weak self] event, attached in self?.trace(kind, event, run: id, attached: attached) }
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
        guard source == .netCoffee else { traceSchedule(.webrtc, "schedule_source_manual"); return }
        guard !state(.webrtc).running else { traceSchedule(.webrtc, "schedule_running"); return }
        let context = automaticContext()
        guard (automaticContextProvider == nil && contextProvider == nil) || (context?.isEmpty == false) else { traceSchedule(.webrtc, "schedule_context_missing"); return }
        let changed = context != lastAutomaticWebRTCContext
        let elapsed = lastAutomaticWebRTCAt.map { Date().timeIntervalSince($0) } ?? .infinity
        guard changed || elapsed >= interval else { traceSchedule(.webrtc, "schedule_wait_interval"); return }
        traceSchedule(.webrtc, "schedule_ready")
        lastAutomaticWebRTCAt = Date(); lastAutomaticWebRTCContext = context
        start(.webrtc)
    }
    func ensureFreshDNSReceipt(maximumWait: TimeInterval = 80) async -> Bool {
        let context = automaticContext()
        guard (automaticContextProvider == nil && contextProvider == nil) || (context?.isEmpty == false) else { traceSchedule(.dns, "schedule_context_missing"); return false }
        let age = lastRecordedDNSAt.map { Date().timeIntervalSince($0) } ?? .infinity
        if age <= 10, context == lastRecordedDNSContext, !dnsReceiptSubmitting { return true }
        if !state(.dns).running { traceSchedule(.dns, "schedule_ready"); start(.dns) }
        else { traceSchedule(.dns, "schedule_running") }
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
        initializationReceiptProblem(kind, at: date) == nil
    }
    func invalidateInitializationReceipt(_ kind: LeakKind) {
        if kind == .dns { lastRecordedDNSAt = nil; lastRecordedDNSContext = nil }
        else { lastRecordedWebRTCAt = nil; lastRecordedWebRTCContext = nil }
    }
    func initializationReceiptProblem(_ kind: LeakKind, at date: Date = Date()) -> (code: String, detail: String)? {
        let label = kind == .dns ? "DNS" : "WebRTC"
        func problem(_ code: String, _ detail: String) -> (code: String, detail: String) {
            (kind.rawValue + "_" + code, label + "：" + detail)
        }
        let value = state(kind)
        guard !value.running else { return problem("running", "检测仍在进行。") }
        guard let result = value.result else { return problem("missing", "没有本轮检测结果。") }
        guard let context = automaticContext(), !context.isEmpty else {
            return problem("context_unavailable", "当前代理上下文暂不可确认。")
        }
        guard contexts[kind]?.value == context, !result.contextChanged else {
            return problem("context_changed", "检测结果与当前代理上下文不一致。")
        }
        let age = date.timeIntervalSince1970 - result.finishedAt
        guard age >= 0 && age < 300 else { return problem("expired", "检测结果已过期或时间无效。") }
        guard value.verdict.state == .matched else {
            return problem("not_passed", value.verdict.detail.isEmpty ? "当前检测结果未通过。" : value.verdict.detail)
        }
        let submitted = kind == .dns ? lastRecordedDNSAt : lastRecordedWebRTCAt
        let submittedContext = kind == .dns ? lastRecordedDNSContext : lastRecordedWebRTCContext
        let submitting = kind == .dns ? dnsReceiptSubmitting : webRTCReceiptSubmitting
        guard !submitting else { return problem("submitting", "检测结果正在提交后台。") }
        guard let submitted, submittedContext == context,
              submitted.timeIntervalSince1970 == result.finishedAt else {
            return problem("not_recorded", "当前检测结果尚未被后台确认。")
        }
        return nil
    }
    func ensureInitializationReceipt(_ kind: LeakKind, maximumWait: TimeInterval = 85, forceNew: Bool = false) async -> Bool {
        now = Date()
        if !forceNew && initializationReceiptIsCurrent(kind) { return true }
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
        trace(kind, "cancelled", run: runs[kind])
        browserViews[kind] = nil; coffeeRunners[kind]?.cancel(); coffeeRunners[kind] = nil; progress[kind] = nil
        runs[kind] = nil; fixtureTasks[kind]?.cancel(); fixtureTasks[kind] = nil
        runLogSources[kind] = nil
        if kind == .dns { dnsRunner?.cancel(); dnsRunner = nil; ipLeakRunner?.cancel(); ipLeakRunner = nil }
        else { rtcRunner?.cancel(); rtcRunner = nil }
        var cancelled = state(kind)
        cancelled.running = false; cancelled.result = nil; cancelled.verdict = .cancelled; cancelled.inputError = nil
        set(cancelled, for: kind)
    }
    func reattachDNSBrowser(_ browser: WKWebView) { ipLeakRunner?.reattachIfNeeded(browser) }
    private func complete(_ kind: LeakKind, id: UUID, result: LeakProbeResult) {
        guard runs[kind] == id else { return }
        let logSource = runLogSources.removeValue(forKey: kind)
        browserViews[kind] = nil; runs[kind] = nil; fixtureTasks[kind] = nil; coffeeRunners[kind] = nil; progress[kind] = nil
        if kind == .dns { dnsRunner = nil; ipLeakRunner = nil } else { rtcRunner = nil }
        now = Date()
        var completed = result
        if let context = contexts[kind], context.required {
            if let original = context.value, let current = contextProvider?() {
                if current != original { completed.contextChanged = true; trace(kind, "context_changed", run: id) }
            } else {
                trace(kind, "context_missing", run: id)
                // Missing evidence is not proof that the proxy changed. The
                // error keeps the receipt incomplete even if sampling resumes.
                if completed.errors.count >= 32 { completed.errors.removeLast() }
                completed.errors.append(.init(stage: "context", code: "context_unavailable",
                                              message: "检测期间代理上下文未能持续确认。"))
            }
        }
        let previous = state(kind)
        set(LeakCheckState(running: false, result: completed, lastSuccessfulResult: previous.lastSuccessfulResult,
                           lastSuccessfulContext: previous.lastSuccessfulContext,
                           lastSuccessfulContextRequired: previous.lastSuccessfulContextRequired,
                           verdict: .idle, inputError: nil), for: kind)
        reevaluate(kind)
        rememberSuccessfulResult(kind)
        let verdict = state(kind).verdict.state
        trace(kind, verdict == .matched ? "result_matched" : verdict == .difference ? "result_difference" : verdict == .incomplete || verdict == .unconfigured ? "result_incomplete" : "result_other", run: id)
        if !isFixture, let logSource,
           let event = EventDiagnosticInput.make(kind: kind, source: logSource, result: state(kind).result ?? completed,
                                                 verdict: state(kind).verdict.state) {
            EventDiagnosticLogger.submit(event)
        }
        if kind == .dns, let onDNSComplete {
            trace(kind, "receipt_submitting", run: id)
            dnsReceiptSubmitting = true
            let boundContext = contextProvider?()
            Task { [weak self] in
                let stored = await onDNSComplete(completed)
                guard let self else { return }
                self.trace(kind, stored ? "receipt_accepted" : "receipt_rejected", run: id)
                if !stored {
                    if self.contextProvider?() == nil { self.trace(kind, "context_missing", run: id) }
                    else if self.contextProvider?() != boundContext { self.trace(kind, "context_changed", run: id) }
                }
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
            trace(kind, "receipt_submitting", run: id)
            webRTCReceiptSubmitting = true
            let boundContext = contextProvider?()
            Task { [weak self] in
                let stored = await onWebRTCComplete(completed)
                guard let self else { return }
                self.trace(kind, stored ? "receipt_accepted" : "receipt_rejected", run: id)
                if !stored {
                    if self.contextProvider?() == nil { self.trace(kind, "context_missing", run: id) }
                    else if self.contextProvider?() != boundContext { self.trace(kind, "context_changed", run: id) }
                }
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
                    let timedOut = result.status == "timeout" || result.errors.contains { $0.code == "timeout" }
                    let detail = timedOut
                        ? "本轮检测超时；代理上下文也暂不可确认。请在后台采样就绪后重新检测。"
                        : "本轮代理上下文暂不可确认，保留地址观测，请在后台采样就绪后重新检测。"
                    value.verdict = .init(state: .incomplete, title: "检测未完成", detail: detail)
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
