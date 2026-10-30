import AppKit
import Foundation
import WebKit

@main
struct IPLeakBridgeTests {
    @MainActor static func main() {
        let live = CommandLine.arguments.contains("--live")
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)
        let window = NSWindow(contentRect: NSRect(x: 120, y: 120, width: 640, height: 120),
                              styleMask: [.titled], backing: .buffered, defer: false)
        window.title = live ? "IPLeak DNS · 临时实测" : "IPLeak DNS · 隔离测试"

        if !live {
            let runner = IPLeakDNSRunner()
            var diagnostics: [(String, Bool)] = []
            runner.onDiagnostic = { diagnostics.append(($0, $1)) }
            runner.testBootstrap = #"""
            window.fetch = async function(raw) {
              const u = new URL(raw); let data;
              if (u.pathname === '/dnsdetection/') {
                const m = u.hostname.match(/^([0-9a-f]{40})-[0-7]\.ipleak\.net$/);
                if (!m) throw new Error('invalid DNS request');
                data = {session:m[1], ip:{'8.8.8.8':1}};
              } else if (u.hostname === 'ipleak.net' && u.pathname === '/json/') {
                data = {ip:'1.1.1.1',country_code:'JP'};
              } else if (u.hostname === 'ipleak.net' && u.pathname === '/json/8.8.8.8') {
                data = {ip:'8.8.8.8',country_code:'JP'};
              } else { throw new Error('unexpected endpoint'); }
              return new Response(JSON.stringify(data), {status:200,headers:{'Content-Type':'application/json'}});
            };
            """#
            runner.start(rounds: 5, id: UUID()) { result in
                let verdict = LeakPolicy.evaluate(result, kind: .dns, expected: "", now: Date().timeIntervalSince1970)
                guard result.status == "complete", result.errors.isEmpty, verdict.state == .matched,
                      result.observations.contains(where: { $0.kind == "resolver" && $0.address == "8.8.8.8" }),
                      result.observations.contains(where: { $0.kind == "http" && $0.address == "1.1.1.1" }) else {
                    fputs("FAIL: IPLeak isolated WebKit bridge: \(result.status) \(result.errors) \(verdict.detail)\n", stderr)
                    exit(1)
                }
                guard diagnostics.contains(where: { $0.0 == "host_attached" && $0.1 }),
                      diagnostics.contains(where: { $0.0 == "navigation_finished" }),
                      diagnostics.contains(where: { $0.0 == "phase_dns" }),
                      diagnostics.contains(where: { $0.0 == "payload_received" }) else {
                    fputs("FAIL: IPLeak bridge lifecycle diagnostics missing\n", stderr); exit(1)
                }
                print("IPLeakBridgeTests: local page, WebKit, JS and native result passed with mocked network")
                exit(0)
            }
            app.run()
            _ = runner
            return
        }

        let store = LeakCheckStore()
        var dnsCallbacks = 0, rtcCallbacks = 0
        store.contextProvider = {
            let path = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/ClaudeWatch/state/proxy-snapshot.json")
            guard let data = try? Data(contentsOf: path),
                  let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let captured = value["observed_epoch"] as? Double,
                  abs(Date().timeIntervalSince1970 - captured) <= 30,
                  let entry = value["entry"] as? [String: Any], entry["state"] as? String == "verified",
                  let endpoint = entry["endpoint"] as? String,
                  let api = value["api"] as? [String: Any], api["state"] as? String == "available",
                  api["covers_7890"] as? Bool == true,
                  let mode = api["mode"] as? String,
                  let selected = api["selected_node"] as? String,
                  let global = api["global_node"] as? String else { return nil }
            return [endpoint, mode, selected, global].joined(separator: "|")
        }
        store.onDNSComplete = { _, _ in dnsCallbacks += 1; return false }
        store.onWebRTCComplete = { _, _ in rtcCallbacks += 1; return false }
        store.start(.dns)
        window.contentView = store.browserViews[.dns]
        window.orderFront(nil)
        Timer.scheduledTimer(withTimeInterval: 0.15, repeats: true) { timer in
            Task { @MainActor in
                if let browser = store.browserViews[.dns], window.contentView !== browser {
                    window.contentView = browser; window.orderFront(nil)
                }
                guard !store.dns.running, dnsCallbacks > 0 else { return }
                timer.invalidate()
                guard let result = store.dns.result else { fputs("FAIL: IPLeak produced no result\n", stderr); exit(1) }
                let resolvers = result.observations.filter { $0.kind == "resolver" }
                let http = result.observations.filter { $0.kind == "http" }
                print("IPLeakLive: status=\(result.status), verdict=\(store.dns.verdict.state), DNS=\(resolvers.count), HTTP=\(http.count)")
                print("DNS countries=\(Array(Set(resolvers.compactMap(\.country))).sorted()); HTTP countries=\(Array(Set(http.compactMap(\.country))).sorted())")
                if !result.errors.isEmpty { print("Errors: \(result.errors.map(\.message))") }
                guard dnsCallbacks == 1, rtcCallbacks == 0, store.source == .netCoffee,
                      store.rtc.result == nil else {
                    fputs("FAIL: primary DNS callback or WebRTC isolation\n", stderr); exit(1)
                }
                guard result.status == "complete", !resolvers.isEmpty, !http.isEmpty,
                      store.dns.verdict.state == .matched || store.dns.verdict.state == .difference else {
                    fputs("FAIL: live IPLeak observation was incomplete or context was unavailable\n", stderr); exit(4)
                }
                print("IPLeakLive: actual WebView result observed; simulated DNS callback only")
                exit(0)
            }
        }
        app.run()
        _ = store
    }
}
