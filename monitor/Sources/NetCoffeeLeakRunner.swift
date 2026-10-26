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
    private var requests: [String: CoffeeRequest] = [:]
    private var usedIDs = Set<String>()
    func start(kind: LeakKind, rounds: Int = 5, id: UUID, progress: @escaping (String) -> Void = { _ in }, completion: @escaping (LeakProbeResult) -> Void) {
        self.kind = kind; self.rounds = rounds == 8 ? 8 : 5; self.id = id; self.completion = completion; self.progress = progress
        guard let file = Bundle.main.url(forResource: "netcoffee_probe", withExtension: "html") else { finish(.failure(kind, code: "component_missing", message: "Net.Coffee 采集页面不可用")); return }
        document = file
        let c = WKWebViewConfiguration(); c.websiteDataStore = .nonPersistent(); c.preferences.javaScriptCanOpenWindowsAutomatically = false
        #if COFFEE_BRIDGE_TEST
        if let testBootstrap { c.userContentController.addUserScript(.init(source: testBootstrap, injectionTime: .atDocumentStart, forMainFrameOnly: true)) }
        #endif
        c.userContentController.add(self, name: "coffeeProbe")
        let w = WKWebView(frame: NSRect(x:0,y:0,width:640,height:100), configuration: c); view = w; w.navigationDelegate = self
        let timer = DispatchWorkItem { [weak self] in guard let self else { return }; self.finish(.failure(kind, code: "timeout", message: "Net.Coffee 检测超时；未完成不代表安全")) }
        watchdog = timer; DispatchQueue.main.asyncAfter(deadline: .now()+75, execute: timer)
        w.loadFileURL(file, allowingReadAccessTo: file.deletingLastPathComponent())
    }
    func cancel() {
        id = nil; watchdog?.cancel(); watchdog = nil
        view?.evaluateJavaScript("window.NetCoffeeProbe && window.NetCoffeeProbe.cancel()", completionHandler: nil)
        view?.configuration.userContentController.removeScriptMessageHandler(forName: "coffeeProbe")
        view?.stopLoading(); view?.navigationDelegate = nil; view = nil
        requests.values.forEach { $0.cancel() }; requests.removeAll(); usedIDs.removeAll(); completion = nil; progress = nil
    }
    private func finish(_ result: LeakProbeResult) {
        let done = completion
        var receipt = result
        if receipt.scope == "本机 dig DNS 路径" || receipt.scope == "当前检测 WebView" {
            receipt = .init(kind:result.kind,status:result.status,startedAt:result.startedAt,finishedAt:result.finishedAt,
                scope:kind == .dns ? "Net.Coffee · 本机 WebView DNS 查询" : "Net.Coffee · 当前检测 WebView ICE",observations:result.observations,errors:result.errors,contextChanged:result.contextChanged,details:result.details,externalJSON:result.externalJSON)
        }
        cancel(); done?(receipt)
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard webView === view, let id else { return }
        webView.evaluateJavaScript("window.NetCoffeeProbe.run({runID:'\(id.uuidString)',kind:'\(kind.rawValue)',rounds:\(rounds)});true;") { [weak self] _, error in
            guard let self, self.id == id, error != nil else { return }
            self.finish(.failure(self.kind, code: "script_failed", message: "检测脚本未能执行"))
        }
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) { decisionHandler(navigationAction.request.url == document ? .allow : .cancel) }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { finish(.failure(kind, code: "page_failed", message: "本地采集页加载失败")) }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { finish(.failure(kind, code: "page_failed", message: "本地采集页加载失败")) }
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let id, message.webView === view, message.frameInfo.isMainFrame, let body = message.body as? [String:Any], body["runID"] as? String == id.uuidString else { return }
        if let payload = body["payload"], JSONSerialization.isValidJSONObject(payload), let data = try? JSONSerialization.data(withJSONObject: payload), data.count < 1_048_576,
           let r = try? JSONDecoder().decode(LeakProbeResult.self, from: data), r.kind == kind.rawValue { finish(r); return }
        if let text = body["progress"] as? String, text.utf8.count < 256 { progress?(text) }
        guard let request = body["request"] as? [String:String], let key = request["id"], key.count < 16, !key.isEmpty, key.allSatisfy({ $0.isASCII && $0.isNumber }), !usedIDs.contains(key), usedIDs.count < 32, requests.count < 4,
              let type = request["kind"], ["trace","geoip","dns"].contains(type), let query = request["query"], query.count < 80 else { return }
        progress?("读取 " + type + " 接口")
        let client = CoffeeRequest(); requests[key] = client; usedIDs.insert(key)
        Task { [weak self] in
            let r = await Task.detached(priority: .utility) { client.run(kind: type, query: query) }.value
            guard let self, self.id == id else { return }; self.requests[key] = nil
            guard let bytes = try? JSONEncoder().encode(r), let json = String(data: bytes, encoding: .utf8) else { return }
            _ = try? await self.view?.evaluateJavaScript("window.NetCoffeeProbe.receive('\(key)',\(json));true;")
        }
    }
}
