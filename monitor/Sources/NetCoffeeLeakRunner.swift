import Foundation
import WebKit

private final class CoffeeScriptHandler: NSObject, WKScriptMessageHandler {
    weak var target: WKScriptMessageHandler?
    init(_ target: WKScriptMessageHandler) { self.target = target }
    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        target?.userContentController(controller, didReceive: message)
    }
}

@MainActor
final class NetCoffeeLeakRunner: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
    #if COFFEE_BRIDGE_TEST
    var testBootstrap: String?
    var testWatchdogInterval: TimeInterval?
    #endif
    private var view: WKWebView?
    var browserView: WKWebView? { view }
    private var document: URL?
    private var id: UUID?
    private var kind: LeakKind = .dns
    private var rounds = 5
    private var completion: ((LeakProbeResult) -> Void)?
    private var progress: ((String) -> Void)?
    private var watchdog: DispatchWorkItem?
    private var deadline: TimeInterval = 0
    private var startedAt: Double = 0
    private var phase = "collector"
    private var pageReady = false
    private var hiddenHost: NSWindow?
    /// Only fixed phase names and relative timings; never addresses or tokens.
    var onPhase: ((String, Double) -> Void)?
    var onDiagnostic: ((String, Bool) -> Void)?
    private func trace(_ event: String) {
        guard id != nil else { return }
        onDiagnostic?(event, view?.window != nil)
    }
    private var requests: [String: CoffeeRequest] = [:]
    private var usedIDs = Set<String>()
    private let resourceDirectory: URL?
    private let backendVariant: BundledBackendVariant?

    init(resourceDirectory: URL? = nil, backendVariant: BundledBackendVariant? = nil) {
        self.resourceDirectory = resourceDirectory
        self.backendVariant = backendVariant
        super.init()
    }

    func start(kind: LeakKind, rounds: Int = 5, id: UUID, progress: @escaping (String) -> Void = { _ in }, completion: @escaping (LeakProbeResult) -> Void) {
        _ = cancel()
        self.kind = kind; self.rounds = rounds == 8 ? 8 : 5; self.id = id; self.completion = completion; self.progress = progress
        startedAt = Date().timeIntervalSince1970
        deadline = ProcessInfo.processInfo.systemUptime + 70
        phase = "collector"
        let timer = DispatchWorkItem { [weak self] in
            guard let self, self.id == id else { return }
            self.trace("watchdog_timeout")
            self.finish(.init(kind: kind.rawValue, status: "timeout", startedAt: self.startedAt,
                              finishedAt: Date().timeIntervalSince1970, scope: "Net.Coffee · 本机 WebView",
                              observations: [], errors: [.init(stage: self.phase, code: "timeout", message: "本轮检测超过总时限；未完成不代表安全")],
                              contextChanged: false, details: []))
        }
        #if COFFEE_BRIDGE_TEST
        let watchdogInterval = testWatchdogInterval ?? 75
        #else
        let watchdogInterval: TimeInterval = 75
        #endif
        watchdog = timer; DispatchQueue.main.asyncAfter(deadline: .now()+watchdogInterval, execute: timer)
        if let view {
            reattachIfNeeded(view)
            if pageReady { trace("view_reused"); runScript(view, id: id) }
            return
        }
        let directory = resourceDirectory ?? Bundle.main.resourceURL
        let file = directory?.appendingPathComponent("netcoffee_probe.html", isDirectory: false)
        guard let file, FileManager.default.isReadableFile(atPath: file.path) else { finish(.failure(kind, code: "component_missing", message: "Net.Coffee 采集页面不可用")); return }
        document = file.resolvingSymlinksInPath().standardizedFileURL
        let c = WKWebViewConfiguration(); c.websiteDataStore = .nonPersistent(); c.preferences.javaScriptCanOpenWindowsAutomatically = false
        c.preferences.inactiveSchedulingPolicy = .none
        c.userContentController.add(CoffeeScriptHandler(self), name: "coffeeProbe")
        let w = WKWebView(frame: NSRect(x:0,y:0,width:640,height:100), configuration: c); view = w; w.navigationDelegate = self
        let host = NSWindow(contentRect: NSRect(x: -10000, y: -10000, width: 1, height: 1),
                            styleMask: .borderless, backing: .buffered, defer: false)
        host.isReleasedWhenClosed = false
        // The hidden host must never surface in the Dock, the Window menu,
        // state restoration or spaces cycling: a miniaturized or restored
        // copy shows up as a blank phantom thumbnail on unrelated screens.
        host.isRestorable = false
        host.excludedFromWindowsMenu = true
        host.ignoresMouseEvents = true
        host.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle]
        host.contentView = w; hiddenHost = host; host.orderFront(nil)
        trace("host_attached")
        w.loadFileURL(document!, allowingReadAccessTo: document!.deletingLastPathComponent())
    }
    @discardableResult
    func cancel() -> Bool {
        let oldID = id
        id = nil; watchdog?.cancel(); watchdog = nil
        if let oldID {
            view?.evaluateJavaScript("window.NetCoffeeProbe && window.NetCoffeeProbe.cancel('\(oldID.uuidString)')", completionHandler: nil)
        }
        let deadline = DispatchTime.now() + .seconds(3)
        var requestsExited = true
        for request in requests.values {
            if !request.cancelAndWait(until: deadline) { requestsExited = false }
        }
        requests.removeAll(); usedIDs.removeAll(); completion = nil; progress = nil
        return requestsExited
    }
    @discardableResult
    func invalidate() -> Bool {
        let stopped = cancel()
        pageReady = false
        view?.configuration.userContentController.removeScriptMessageHandler(forName: "coffeeProbe")
        view?.stopLoading(); view?.navigationDelegate = nil; view = nil
        hiddenHost?.close(); hiddenHost = nil
        return stopped
    }
    func reattachIfNeeded(_ browser: WKWebView) {
        DispatchQueue.main.async { [weak self, weak browser] in
            guard let self, let browser, self.view === browser, browser.window == nil,
                  let host = self.hiddenHost else { return }
            host.contentView = browser; host.orderFront(nil); self.trace("host_attached")
        }
    }
    private func finish(_ result: LeakProbeResult) {
        let done = completion
        var receipt = result
        if receipt.scope == "本机 dig DNS 路径" || receipt.scope == "当前检测 WebView" {
            receipt = .init(kind:result.kind,status:result.status,startedAt:result.startedAt,finishedAt:result.finishedAt,
                scope:kind == .dns ? "Net.Coffee · 本机 WebView DNS 查询" : "Net.Coffee · 当前检测 WebView ICE",observations:result.observations,errors:result.errors,contextChanged:result.contextChanged,details:result.details,externalJSON:result.externalJSON)
        }
        if receipt.status == "complete" && receipt.errors.isEmpty { _ = cancel() }
        else { _ = invalidate() }
        done?(receipt)
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard webView === view else { return }
        pageReady = true
        trace("navigation_finished")
        if let id { runScript(webView, id: id) }
    }
    private func runScript(_ webView: WKWebView, id: UUID) {
        #if COFFEE_BRIDGE_TEST
        let bootstrap = testBootstrap ?? ""
        #else
        let bootstrap = ""
        #endif
        let budgetMs = max(1, min(70_000, Int((deadline - ProcessInfo.processInfo.systemUptime) * 1000)))
        webView.evaluateJavaScript("\(bootstrap) window.NetCoffeeProbe.run({runID:'\(id.uuidString)',kind:'\(kind.rawValue)',rounds:\(rounds),budgetMs:\(budgetMs)});true;") { [weak self] _, error in
            #if COFFEE_BRIDGE_TEST
            if let error { print("NetCoffee bridge evaluate error: \(error.localizedDescription)") }
            #endif
            guard let self, self.id == id else { return }
            if error == nil { self.trace("script_started"); return }
            self.trace("script_failed")
            self.finish(.failure(self.kind, code: "script_failed", message: "检测脚本未能执行"))
        }
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard webView === view else { decisionHandler(.cancel); return }
        let requested = navigationAction.request.url?.resolvingSymlinksInPath().standardizedFileURL
        let allowed = requested == document
        #if COFFEE_BRIDGE_TEST
        print("NetCoffee bridge navigation \(allowed ? "allow" : "cancel"): \(navigationAction.request.url?.absoluteString ?? "nil")")
        #endif
        decisionHandler(allowed ? .allow : .cancel)
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        guard webView === view else { return }
        trace("navigation_failed")
        #if COFFEE_BRIDGE_TEST
        print("NetCoffee bridge navigation failed: \(error.localizedDescription)")
        #endif
        finish(.failure(kind, code: "page_failed", message: "本地采集页加载失败"))
    }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        guard webView === view else { return }
        trace("webcontent_terminated")
        if id != nil { finish(.failure(kind, code: "page_failed", message: "WebRTC 检测页面进程已退出。")) }
        else { _ = invalidate() }
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        guard webView === view else { return }
        trace("navigation_failed")
        #if COFFEE_BRIDGE_TEST
        print("NetCoffee bridge provisional failure: \(error.localizedDescription)")
        #endif
        finish(.failure(kind, code: "page_failed", message: "本地采集页加载失败"))
    }
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let id, message.webView === view, message.frameInfo.isMainFrame, let body = message.body as? [String:Any], body["runID"] as? String == id.uuidString else { trace("message_rejected"); return }
        if let phase = body["phase"] as? String,
           ["collector", "http", "dns_images", "dns_records", "geoip", "ice"].contains(phase),
           let elapsed = body["elapsedMs"] as? Double, elapsed.isFinite, (0...75_000).contains(elapsed) {
            self.phase = phase
            trace("phase_" + phase)
            onPhase?(phase, elapsed)
        }
        if body["diagnostic"] as? String == "http_retry" { trace("http_retry") }
        if let cancel = body["cancelRequest"] as? [String: String], let key = cancel["id"] {
            requests.removeValue(forKey: key)?.cancel()
            return
        }
        if let payload = body["payload"] {
            guard JSONSerialization.isValidJSONObject(payload), let data = try? JSONSerialization.data(withJSONObject: payload), data.count < 1_048_576,
                  let r = try? JSONDecoder().decode(LeakProbeResult.self, from: data), r.kind == kind.rawValue else {
                trace("payload_invalid")
                finish(.failure(kind, code: "invalid_result", message: "WebRTC 返回结果无效。"))
                return
            }
            trace("payload_received"); finish(r); return
        }
        if let text = body["progress"] as? String, text.utf8.count < 256 { progress?(text) }
        guard let request = body["request"] as? [String:String], let key = request["id"], key.count < 16, !key.isEmpty, key.allSatisfy({ $0.isASCII && $0.isNumber }), !usedIDs.contains(key), usedIDs.count < 32,
              let type = request["kind"], ["trace","geoip","dns"].contains(type), let query = request["query"], query.count < 80 else { return }
        usedIDs.insert(key)
        let requested = request["timeoutMs"].flatMap(Double.init) ?? 20_000
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        // Return a native timeout before the JS timer expires, freeing the
        // bridge slot instead of leaving a stale child behind the next retry.
        let timeout = min(20, min(max(0.1, (requested - 1000) / 1000), remaining))
        guard requested.isFinite, requested > 0, timeout > 0, requests.count < 4 else {
            let receipt = CoffeeReceipt.failure(type, query: query, "本轮接口请求没有剩余预算或并发名额")
            deliver(receipt, key: key)
            return
        }
        progress?("读取 " + type + " 接口")
        let client = CoffeeRequest(resourceDirectory: resourceDirectory, backendVariant: backendVariant); requests[key] = client
        Task { [weak self] in
            let r = await Task.detached(priority: .utility) { client.run(kind: type, query: query, timeout: timeout) }.value
            guard let self, self.id == id else { return }; self.requests[key] = nil
            self.deliver(r, key: key)
        }
    }
    private func deliver(_ receipt: CoffeeReceipt, key: String) {
        guard let bytes = try? JSONEncoder().encode(receipt), let json = String(data: bytes, encoding: .utf8) else { return }
        view?.evaluateJavaScript("window.NetCoffeeProbe.receive('\(key)',\(json));true;", completionHandler: nil)
    }
}
