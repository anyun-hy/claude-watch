import Foundation
import WebKit

@MainActor
final class NetCoffeeLeakRunner: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
    #if COFFEE_BRIDGE_TEST
    var testBootstrap: String?
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
    /// Only fixed phase names and relative timings; never addresses or tokens.
    var onPhase: ((String, Double) -> Void)?
    var onDiagnostic: ((String, Bool) -> Void)?
    private func trace(_ event: String) { onDiagnostic?(event, view?.window != nil) }
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
        self.kind = kind; self.rounds = rounds == 8 ? 8 : 5; self.id = id; self.completion = completion; self.progress = progress
        startedAt = Date().timeIntervalSince1970
        deadline = ProcessInfo.processInfo.systemUptime + 70
        phase = "collector"
        let directory = resourceDirectory ?? Bundle.main.resourceURL
        let file = directory?.appendingPathComponent("netcoffee_probe.html", isDirectory: false)
        guard let file, FileManager.default.isReadableFile(atPath: file.path) else { finish(.failure(kind, code: "component_missing", message: "Net.Coffee 采集页面不可用")); return }
        document = file.resolvingSymlinksInPath().standardizedFileURL
        let c = WKWebViewConfiguration(); c.websiteDataStore = .nonPersistent(); c.preferences.javaScriptCanOpenWindowsAutomatically = false
        c.userContentController.add(self, name: "coffeeProbe")
        let w = WKWebView(frame: NSRect(x:0,y:0,width:640,height:100), configuration: c); view = w; w.navigationDelegate = self
        let timer = DispatchWorkItem { [weak self] in
            guard let self, self.id == id else { return }
            self.trace("watchdog_timeout")
            self.finish(.init(kind: kind.rawValue, status: "timeout", startedAt: self.startedAt,
                              finishedAt: Date().timeIntervalSince1970, scope: "Net.Coffee · 本机 WebView",
                              observations: [], errors: [.init(stage: self.phase, code: "timeout", message: "本轮检测超过总时限；未完成不代表安全")],
                              contextChanged: false, details: []))
        }
        watchdog = timer; DispatchQueue.main.asyncAfter(deadline: .now()+75, execute: timer)
        w.loadFileURL(document!, allowingReadAccessTo: document!.deletingLastPathComponent())
    }
    @discardableResult
    func cancel() -> Bool {
        id = nil; watchdog?.cancel(); watchdog = nil
        view?.evaluateJavaScript("window.NetCoffeeProbe && window.NetCoffeeProbe.cancel()", completionHandler: nil)
        view?.configuration.userContentController.removeScriptMessageHandler(forName: "coffeeProbe")
        view?.stopLoading(); view?.navigationDelegate = nil; view = nil
        let deadline = DispatchTime.now() + .seconds(3)
        var requestsExited = true
        for request in requests.values {
            if !request.cancelAndWait(until: deadline) { requestsExited = false }
        }
        requests.removeAll(); usedIDs.removeAll(); completion = nil; progress = nil
        return requestsExited
    }
    private func finish(_ result: LeakProbeResult) {
        let done = completion
        var receipt = result
        if receipt.scope == "本机 dig DNS 路径" || receipt.scope == "当前检测 WebView" {
            receipt = .init(kind:result.kind,status:result.status,startedAt:result.startedAt,finishedAt:result.finishedAt,
                scope:kind == .dns ? "Net.Coffee · 本机 WebView DNS 查询" : "Net.Coffee · 当前检测 WebView ICE",observations:result.observations,errors:result.errors,contextChanged:result.contextChanged,details:result.details,externalJSON:result.externalJSON)
        }
        _ = cancel(); done?(receipt)
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard webView === view, let id else { return }
        trace("navigation_finished")
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
        let requested = navigationAction.request.url?.resolvingSymlinksInPath().standardizedFileURL
        let allowed = requested == document
        #if COFFEE_BRIDGE_TEST
        print("NetCoffee bridge navigation \(allowed ? "allow" : "cancel"): \(navigationAction.request.url?.absoluteString ?? "nil")")
        #endif
        decisionHandler(allowed ? .allow : .cancel)
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        trace("navigation_failed")
        #if COFFEE_BRIDGE_TEST
        print("NetCoffee bridge navigation failed: \(error.localizedDescription)")
        #endif
        finish(.failure(kind, code: "page_failed", message: "本地采集页加载失败"))
    }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        guard webView === view else { return }
        trace("webcontent_terminated")
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
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
                  let r = try? JSONDecoder().decode(LeakProbeResult.self, from: data), r.kind == kind.rawValue else { trace("payload_invalid"); return }
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
