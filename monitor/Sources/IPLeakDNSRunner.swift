import Foundation
import WebKit

/// A diagnostic-only WebView. Its result never enters the protection receipt.
@MainActor
final class IPLeakDNSRunner: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
    #if IPLEAK_BRIDGE_TEST
    var testBootstrap: String?
    #endif
    private var view: WKWebView?
    var browserView: WKWebView? { view }
    private var document: URL?
    private var id: UUID?
    private var completion: ((LeakProbeResult) -> Void)?
    private var progress: ((String) -> Void)?
    private var watchdog: DispatchWorkItem?
    private var rounds = 5

    private static func failure(code: String, message: String) -> LeakProbeResult {
        let now = Date().timeIntervalSince1970
        return .init(kind: LeakKind.dns.rawValue, status: code == "timeout" ? "timeout" : "error",
                     startedAt: now, finishedAt: now, scope: "IPLeak.net · 本机 WebView DNS 对照",
                     observations: [], errors: [.init(stage: "collector", code: code, message: message)],
                     contextChanged: false, details: [])
    }

    func start(rounds: Int, id: UUID, progress: @escaping (String) -> Void = { _ in },
               completion: @escaping (LeakProbeResult) -> Void) {
        self.id = id; self.completion = completion; self.progress = progress
        self.rounds = rounds == 8 ? 8 : 5
        guard let file = Bundle.main.url(forResource: "ipleak_probe", withExtension: "html") else {
            finish(Self.failure(code: "component_missing", message: "IPLeak 检测页面不可用。")); return
        }
        document = file
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
        #if IPLEAK_BRIDGE_TEST
        if let testBootstrap {
            configuration.userContentController.addUserScript(.init(source: testBootstrap, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        }
        #endif
        configuration.userContentController.add(self, name: "ipLeakProbe")
        let webView = WKWebView(frame: NSRect(x: 0, y: 0, width: 640, height: 100), configuration: configuration)
        webView.navigationDelegate = self; view = webView
        let timer = DispatchWorkItem { [weak self] in
            self?.finish(Self.failure(code: "timeout", message: "IPLeak 检测超时；未完成不代表安全。"))
        }
        watchdog = timer; DispatchQueue.main.asyncAfter(deadline: .now() + 90, execute: timer)
        webView.loadFileURL(file, allowingReadAccessTo: file.deletingLastPathComponent())
    }

    func cancel() {
        id = nil; watchdog?.cancel(); watchdog = nil
        view?.evaluateJavaScript("window.IPLeakProbe && window.IPLeakProbe.cancel()", completionHandler: nil)
        view?.configuration.userContentController.removeScriptMessageHandler(forName: "ipLeakProbe")
        view?.stopLoading(); view?.navigationDelegate = nil; view = nil
        completion = nil; progress = nil
    }
    private func finish(_ result: LeakProbeResult) {
        let done = completion
        cancel(); done?(result)
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard webView === view, let id else { return }
        webView.evaluateJavaScript("window.IPLeakProbe.run({runID:'\(id.uuidString)',rounds:\(rounds)});true;") { [weak self] _, error in
            guard let self, self.id == id, error != nil else { return }
            self.finish(Self.failure(code: "script_failed", message: "IPLeak 检测脚本未能执行。"))
        }
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        finish(Self.failure(code: "page_failed", message: "IPLeak 检测页面加载失败。"))
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        finish(Self.failure(code: "page_failed", message: "IPLeak 检测页面未能打开。"))
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        decisionHandler(navigationAction.request.url == document ? .allow : .cancel)
    }
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard let id, message.webView === view, message.frameInfo.isMainFrame,
              let body = message.body as? [String: Any], body["runID"] as? String == id.uuidString else { return }
        if let text = body["progress"] as? String, text.utf8.count < 256 { progress?(text) }
        guard let payload = body["payload"], JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload), data.count <= 1_048_576,
              let result = try? JSONDecoder().decode(LeakProbeResult.self, from: data), result.kind == LeakKind.dns.rawValue else { return }
        finish(result)
    }
}
