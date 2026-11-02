import AppKit
import Foundation
import WebKit

private final class IPLeakScriptHandler: NSObject, WKScriptMessageHandler {
    weak var target: WKScriptMessageHandler?
    init(_ target: WKScriptMessageHandler) { self.target = target }
    func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
        target?.userContentController(controller, didReceive: message)
    }
}

/// IPLeak DNS collection shared by the UI and the background evidence worker.
@MainActor
final class IPLeakDNSRunner: NSObject, WKScriptMessageHandler, WKNavigationDelegate {
    #if IPLEAK_BRIDGE_TEST
    var testBootstrap: String?
    var testWatchdogInterval: TimeInterval?
    #endif
    private var view: WKWebView?
    private var hiddenHost: NSWindow?
    var browserView: WKWebView? { view }
    private var document: URL?
    private var id: UUID?
    private var completion: ((LeakProbeResult) -> Void)?
    private var progress: ((String) -> Void)?
    var onDiagnostic: ((String, Bool) -> Void)?
    private func trace(_ event: String) {
        guard id != nil else { return }
        onDiagnostic?(event, view?.window != nil)
    }
    private var watchdog: DispatchWorkItem?
    private var rounds = 5
    private var startedAt: Double = 0
    private let resourceDirectory: URL?
    private var pageReady = false

    init(resourceDirectory: URL? = nil) {
        self.resourceDirectory = resourceDirectory
        super.init()
    }

    private func failure(code: String, message: String) -> LeakProbeResult {
        let now = Date().timeIntervalSince1970
        return .init(kind: LeakKind.dns.rawValue, status: code == "timeout" ? "timeout" : "error",
                     startedAt: startedAt > 0 ? startedAt : now, finishedAt: now, scope: "IPLeak.net · 本机 WebView DNS 检测",
                     observations: [], errors: [.init(stage: "collector", code: code, message: message)],
                     contextChanged: false, details: [])
    }

    func start(rounds: Int, id: UUID, progress: @escaping (String) -> Void = { _ in },
               completion: @escaping (LeakProbeResult) -> Void) {
        cancel()
        self.id = id; self.completion = completion; self.progress = progress
        self.startedAt = Date().timeIntervalSince1970
        self.rounds = rounds == 8 ? 8 : 5
        let timer = DispatchWorkItem { [weak self] in
            guard let self, self.id == id else { return }
            self.trace("watchdog_timeout")
            self.finish(self.failure(code: "timeout", message: "IPLeak 检测超时；未完成不代表安全。"))
        }
        #if IPLEAK_BRIDGE_TEST
        let timeout: Double = testWatchdogInterval ?? (testBootstrap == nil ? 75 : 15)
        #else
        let timeout: Double = 75
        #endif
        watchdog = timer; DispatchQueue.main.asyncAfter(deadline: .now() + timeout, execute: timer)
        if let view {
            reattachIfNeeded(view)
            if pageReady { trace("view_reused"); runScript(view, id: id) }
            return
        }
        let directory = resourceDirectory ?? Bundle.main.resourceURL
        guard let file = directory?.appendingPathComponent("ipleak_probe.html"), FileManager.default.isReadableFile(atPath: file.path) else {
            finish(failure(code: "component_missing", message: "IPLeak 检测页面不可用。")); return
        }
        document = file.resolvingSymlinksInPath().standardizedFileURL
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
        // The collector may be detached while its page is not selected. Keep
        // this retained WebView runnable rather than suspending its timers.
        configuration.preferences.inactiveSchedulingPolicy = .none
        #if IPLEAK_BRIDGE_TEST
        if let testBootstrap {
            configuration.userContentController.addUserScript(.init(source: testBootstrap, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        }
        #endif
        configuration.userContentController.add(IPLeakScriptHandler(self), name: "ipLeakProbe")
        let webView = WKWebView(frame: NSRect(x: 0, y: 0, width: 640, height: 100), configuration: configuration)
        webView.navigationDelegate = self; view = webView
        // Automatic DNS checks must keep a WebKit view attached even when the
        // DNS page is not open. The host never activates or appears on screen.
        let host = NSWindow(contentRect: NSRect(x: -10_000, y: -10_000, width: 1, height: 1),
                            styleMask: .borderless, backing: .buffered, defer: false)
        host.isReleasedWhenClosed = false
        // The hidden host must never surface in the Dock, the Window menu,
        // state restoration or spaces cycling: a miniaturized or restored
        // copy shows up as a blank phantom thumbnail on unrelated screens.
        host.isRestorable = false
        host.excludedFromWindowsMenu = true
        host.ignoresMouseEvents = true
        host.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle]
        host.contentView = webView; hiddenHost = host; host.orderFront(nil)
        trace("host_attached")
        guard let document else { finish(failure(code: "component_missing", message: "IPLeak 检测页面不可用。")); return }
        webView.loadFileURL(document, allowingReadAccessTo: document.deletingLastPathComponent())
    }

    func cancel() {
        let oldID = id
        id = nil; watchdog?.cancel(); watchdog = nil
        if let oldID {
            view?.evaluateJavaScript("window.IPLeakProbe && window.IPLeakProbe.cancel('\(oldID.uuidString)')", completionHandler: nil)
        }
        completion = nil; progress = nil
    }
    func invalidate() {
        cancel()
        pageReady = false
        view?.configuration.userContentController.removeScriptMessageHandler(forName: "ipLeakProbe")
        view?.stopLoading(); view?.navigationDelegate = nil; view = nil
        hiddenHost?.close(); hiddenHost = nil
    }
    func reattachIfNeeded(_ browser: WKWebView) {
        DispatchQueue.main.async { [weak self, weak browser] in
            guard let self, let browser, self.view === browser, browser.window == nil,
                  let host = self.hiddenHost else { return }
            host.contentView = browser
            host.orderFront(nil)
            self.trace("host_attached")
        }
    }
    private func finish(_ result: LeakProbeResult) {
        let done = completion
        if result.status == "complete" && result.errors.isEmpty { cancel() }
        else { invalidate() }
        done?(result)
    }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        guard webView === view else { return }
        pageReady = true
        trace("navigation_finished")
        if let id { runScript(webView, id: id) }
    }
    private func runScript(_ webView: WKWebView, id: UUID) {
        #if IPLEAK_BRIDGE_TEST || BACKGROUND_LEAK_WORKER_TEST
        FileHandle.standardError.write(Data("IPLeak bridge: didFinish\n".utf8))
        #endif
        webView.evaluateJavaScript("window.IPLeakProbe.run({runID:'\(id.uuidString)',rounds:\(rounds)});true;") { [weak self] _, error in
            #if IPLEAK_BRIDGE_TEST || BACKGROUND_LEAK_WORKER_TEST
            if let error { FileHandle.standardError.write(Data("IPLeak bridge: script error \(error.localizedDescription)\n".utf8)) }
            #endif
            guard let self, self.id == id else { return }
            if error == nil { self.trace("script_started"); return }
            self.trace("script_failed")
            self.finish(self.failure(code: "script_failed", message: "IPLeak 检测脚本未能执行。"))
        }
    }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        guard webView === view else { return }
        trace("webcontent_terminated")
        if id != nil { finish(failure(code: "page_failed", message: "IPLeak 检测页面进程已退出。")) }
        else { invalidate() }
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        guard webView === view else { return }
        trace("navigation_failed")
        #if IPLEAK_BRIDGE_TEST || BACKGROUND_LEAK_WORKER_TEST
        FileHandle.standardError.write(Data("IPLeak bridge: navigation failed\n".utf8))
        #endif
        finish(failure(code: "page_failed", message: "IPLeak 检测页面加载失败。"))
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        guard webView === view else { return }
        trace("navigation_failed")
        #if IPLEAK_BRIDGE_TEST || BACKGROUND_LEAK_WORKER_TEST
        FileHandle.standardError.write(Data("IPLeak bridge: provisional navigation failed\n".utf8))
        #endif
        finish(failure(code: "page_failed", message: "IPLeak 检测页面未能打开。"))
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard webView === view else { decisionHandler(.cancel); return }
        let requested = navigationAction.request.url?.resolvingSymlinksInPath().standardizedFileURL
        let allowed = requested == document
        #if IPLEAK_BRIDGE_TEST || BACKGROUND_LEAK_WORKER_TEST
        FileHandle.standardError.write(Data("IPLeak bridge: navigation \(allowed ? "allow" : "reject")\n".utf8))
        #endif
        decisionHandler(allowed ? .allow : .cancel)
        if !allowed, navigationAction.targetFrame?.isMainFrame == true {
            finish(failure(code: "page_failed", message: "IPLeak 检测页面地址不匹配，已停止本轮检测。"))
        }
    }
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        #if IPLEAK_BRIDGE_TEST || BACKGROUND_LEAK_WORKER_TEST
        FileHandle.standardError.write(Data("IPLeak bridge: received message\n".utf8))
        #endif
        guard let id, message.webView === view, message.frameInfo.isMainFrame,
              let body = message.body as? [String: Any], body["runID"] as? String == id.uuidString else { trace("message_rejected"); return }
        if let event = body["diagnostic"] as? String,
           ["dns", "http", "geoip"].contains(where: { prefix in
               ["timeout", "network", "http_status", "invalid_response"].contains { event == prefix + "_request_" + $0 }
           }) { trace(event) }
        if let text = body["progress"] as? String, text.utf8.count < 256 {
            if text.hasPrefix("IPLeak DNS") { trace("phase_dns") }
            else if text.hasPrefix("读取 IPLeak HTTP") || text.hasPrefix("IPLeak HTTP") { trace("phase_http") }
            else if text.hasPrefix("读取 IPLeak DNS 归属") { trace("phase_geoip") }
            progress?(text)
        }
        guard body["payload"] != nil else { return }
        guard let payload = body["payload"], JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload), data.count <= 1_048_576,
              let result = try? JSONDecoder().decode(LeakProbeResult.self, from: data), result.kind == LeakKind.dns.rawValue else {
            trace("payload_invalid")
            finish(failure(code: "invalid_result", message: "IPLeak 返回结果无效。"))
            return
        }
        trace("payload_received")
        finish(result)
    }
}
