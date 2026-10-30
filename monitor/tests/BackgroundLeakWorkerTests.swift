import AppKit
import WebKit

@MainActor
private final class WebKitDiagnosticProbe: NSObject, WKNavigationDelegate {
    private let complete: (Bool) -> Void
    init(complete: @escaping (Bool) -> Void) { self.complete = complete }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        print("Background WebKit diagnostic: inline HTML didFinish")
        complete(true)
    }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        print("Background WebKit diagnostic: inline HTML didFail \(error.localizedDescription)")
        complete(false)
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        print("Background WebKit diagnostic: inline HTML provisional failure \(error.localizedDescription)")
        complete(false)
    }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        print("Background WebKit diagnostic: web content process terminated")
        complete(false)
    }
}

@main
struct BackgroundLeakWorkerTests {
    @MainActor static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        let resources = Bundle.main.resourceURL!
        guard BackgroundLeakWorker.kind(arguments: ["watch-leak-worker", "--dns"]) == .dns,
              BackgroundLeakWorker.kind(arguments: ["watch-leak-worker", "--webrtc"]) == .webrtc,
              BackgroundLeakWorker.kind(arguments: ["watch-leak-worker", "--bad"]) == nil,
              BackgroundLeakWorker.resources(executable: resources.appendingPathComponent("watch-leak-worker")) == resources,
              BackgroundLeakWorker.verifiedResources(executable: resources.appendingPathComponent("watch-leak-worker")) == resources,
              BundledBackendVariant.backgroundEvidenceSchema(from: resources) == 1 else {
            fputs("FAIL: background helper fixed arguments/resources\n", stderr)
            exit(1)
        }
        let host = NSWindow(contentRect: NSRect(x: -10_000, y: -10_000, width: 1, height: 1),
                            styleMask: .borderless, backing: .buffered, defer: false)
        host.isReleasedWhenClosed = false
        let watchdog = DispatchWorkItem {
            fputs("FAIL: background helper WebKit bridge timed out\n", stderr)
            exit(1)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 30, execute: watchdog)
        let runner = NetCoffeeLeakRunner(resourceDirectory: resources, backendVariant: .rustCandidate)
        runner.testBootstrap = #"""
        window.NetCoffeeProbe.run = function(options) {
          window.webkit.messageHandlers.coffeeProbe.postMessage({runID:options.runID,payload:{
            kind:options.kind,status:'complete',startedAt:1,finishedAt:2,
            scope:'test',observations:[{address:'8.8.4.4',kind:'http',source:'test',family:4}],
            errors:[],contextChanged:false,details:['mocked']
          }});
        };
        """#
        func check(_ result: LeakProbeResult, kind: LeakKind) -> Bool {
            result.kind == kind.rawValue && result.status == "complete" && result.errors.isEmpty &&
                result.observations.count == 1 && result.observations[0].address == "8.8.4.4"
        }
        func startRunner() {
            runner.start(kind: .dns, id: UUID(), progress: { _ in }) { dns in
                guard check(dns, kind: .dns) else {
                    fputs("FAIL: background helper WebKit bridge\n", stderr)
                    exit(1)
                }
                runner.start(kind: .webrtc, id: UUID(), progress: { _ in }) { webrtc in
                    guard check(webrtc, kind: .webrtc) else {
                        fputs("FAIL: background helper WebKit WebRTC bridge\n", stderr)
                        exit(1)
                    }
                    watchdog.cancel()
                    print("BackgroundLeakWorkerTests: fixed resource selection and injected DNS/WebRTC receipts passed")
                    exit(0)
                }
                host.contentView = runner.browserView
                host.orderFront(nil)
            }
            host.contentView = runner.browserView
            host.orderFront(nil)
        }
        let inline = WKWebView(frame: .zero)
        let diagnostic = WebKitDiagnosticProbe { success in
            guard success else {
                fputs("FAIL: background helper inline WebKit diagnostic\n", stderr)
                exit(1)
            }
            startRunner()
        }
        inline.navigationDelegate = diagnostic
        host.contentView = inline
        host.orderFront(nil)
        inline.loadHTMLString("<html><body>ok</body></html>", baseURL: nil)
        app.run()
        _ = (runner, diagnostic)
    }
}
