import AppKit
import Foundation
import WebKit

@main
struct ResidentWebViewTests {
    @MainActor static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        Task { @MainActor in
            func expect(_ value: Bool, _ message: String) {
                if !value { fputs("FAIL: \(message)\n", stderr); exit(1) }
            }
            let dns = IPLeakDNSRunner()
            let dnsFixture = #"""
            window.fetch = async function(raw) {
              const u=new URL(raw);let body;
              if(u.pathname==='/dnsdetection/') { const m=u.hostname.match(/^([0-9a-f]{40})-[0-7]r?\.ipleak\.net$/); body={session:m[1],ip:{'8.8.8.8':1}}; }
              else if(u.pathname==='/json/') body={ip:'8.8.4.4',country_code:'US'};
              else body={ip:'8.8.8.8',country_code:'US'};
              return new Response(JSON.stringify(body),{status:200});
            };
            """#
            dns.testBootstrap = dnsFixture
            var dnsEvents: [String] = []
            dns.onDiagnostic = { event, _ in dnsEvents.append(event) }
            @MainActor func collectDNS(stale: WKWebView? = nil) async -> LeakProbeResult {
                await withCheckedContinuation { continuation in
                    dns.start(rounds: 5, id: UUID()) { continuation.resume(returning: $0) }
                    if let stale { dns.webView(stale, didFinish: nil) }
                }
            }
            let first = await collectDNS()
            let firstView = dns.browserView
            expect(first.status == "complete" && firstView != nil, "DNS retains its completed view")
            let second = await collectDNS()
            expect(second.status == "complete" && dns.browserView === firstView, "DNS reuses one loaded page")
            func session(_ result: LeakProbeResult) -> String? {
                guard let raw = result.externalJSON, let data = raw.data(using: .utf8),
                      let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
                return value["session"] as? String
            }
            expect(session(first) != nil && session(first) != session(second), "reused DNS page creates a fresh sampling session")
            expect(dnsEvents.filter { $0 == "navigation_finished" }.count == 1 && dnsEvents.contains("view_reused"),
                   "a reused DNS round does not navigate again")
            var cancelledDNS = 0
            dns.start(rounds: 5, id: UUID()) { _ in cancelledDNS += 1 }
            dns.cancel()
            let afterCancel = await collectDNS()
            expect(afterCancel.status == "complete" && cancelledDNS == 0, "late DNS cancellation cannot cancel or publish into the next run")
            if let old = dns.browserView {
                dns.webViewWebContentProcessDidTerminate(old)
                expect(dns.browserView == nil, "idle DNS content termination invalidates the view")
                expect(await collectDNS(stale: old).status == "complete" && dns.browserView !== old,
                       "DNS rebuilds after content termination and ignores old navigation callbacks")
            }
            dns.invalidate()
            dns.testBootstrap = "window.fetch = function(){return new Promise(function(){});};"
            dns.testWatchdogInterval = 0.15
            expect(await collectDNS().status == "timeout" && dns.browserView == nil, "DNS native timeout tears down the stuck page")
            dns.testBootstrap = dnsFixture; dns.testWatchdogInterval = 5
            expect(await collectDNS().status == "complete", "DNS automatically creates a healthy page on the next round")
            dns.invalidate()
            dns.testBootstrap = "document.addEventListener('DOMContentLoaded',function(){window.IPLeakProbe.run=function(o){window.webkit.messageHandlers.ipLeakProbe.postMessage({runID:o.runID,payload:{}});};});"
            expect(await collectDNS().status == "error" && dns.browserView == nil, "invalid DNS payload is rejected and rebuilds without waiting for a timeout")
            dns.testBootstrap = dnsFixture
            expect(await collectDNS().status == "complete", "DNS recovers after an invalid payload")
            dns.invalidate()

            let rtc = NetCoffeeLeakRunner()
            let rtcFixture = #"""
            window.RTCPeerConnection = class {
              constructor(){this.iceGatheringState='new';} createDataChannel(){}
              createOffer(){return Promise.resolve({type:'offer',sdp:''});}
              setLocalDescription(){queueMicrotask(()=>{
                this.onicecandidate({candidate:{address:'8.8.4.4',type:'srflx',candidate:'candidate:1 1 udp 1 8.8.4.4 3478 typ srflx'}});
                this.onicecandidate({candidate:null});
              });return Promise.resolve();} close(){}
            };
            """#
            rtc.testBootstrap = rtcFixture
            var rtcEvents: [String] = []
            rtc.onDiagnostic = { event, _ in rtcEvents.append(event) }
            @MainActor func collectRTC(stale: WKWebView? = nil) async -> LeakProbeResult {
                await withCheckedContinuation { continuation in
                    rtc.start(kind: .webrtc, id: UUID()) { continuation.resume(returning: $0) }
                    if let stale { rtc.webView(stale, didFinish: nil) }
                }
            }
            let rtcFirst = await collectRTC()
            let rtcView = rtc.browserView
            let rtcSecond = await collectRTC()
            expect(rtcFirst.status == "complete" && rtcSecond.status == "complete" && rtc.browserView === rtcView,
                   "WebRTC retains and reuses its loaded page")
            expect(rtcEvents.filter { $0 == "navigation_finished" }.count == 1 && rtcEvents.contains("view_reused"),
                   "WebRTC does not reload on each sample")
            expect(LeakPolicy.evaluate(rtcSecond, kind: .webrtc, expected: "", now: Date().timeIntervalSince1970).state == .matched,
                   "reused WebRTC still passes the normal comparison policy")
            var cancelledRTC = 0
            rtc.start(kind: .webrtc, id: UUID()) { _ in cancelledRTC += 1 }
            _ = rtc.cancel()
            expect(await collectRTC().status == "complete" && cancelledRTC == 0, "late WebRTC callbacks cannot publish into the next round")
            if let old = rtc.browserView {
                rtc.webViewWebContentProcessDidTerminate(old)
                expect(rtc.browserView == nil, "idle WebRTC content termination invalidates the view")
                expect(await collectRTC(stale: old).status == "complete" && rtc.browserView !== old, "WebRTC recreates after abnormal termination")
            }
            _ = rtc.invalidate()
            rtc.testBootstrap = "window.NetCoffeeProbe.run=function(){};"
            rtc.testWatchdogInterval = 0.15
            expect(await collectRTC().status == "timeout" && rtc.browserView == nil, "WebRTC timeout tears down its page")
            rtc.testBootstrap = rtcFixture; rtc.testWatchdogInterval = 5
            expect(await collectRTC().status == "complete", "WebRTC automatically rebuilds on its next round")
            rtc.testBootstrap = "window.NetCoffeeProbe.run=function(o){window.webkit.messageHandlers.coffeeProbe.postMessage({runID:o.runID,payload:{}});};"
            expect(await collectRTC().status == "error" && rtc.browserView == nil, "invalid WebRTC payload is rejected and forces a new page")
            rtc.testBootstrap = rtcFixture
            expect(await collectRTC().status == "complete", "WebRTC recovers after an invalid payload")
            _ = rtc.invalidate()
            print("ResidentWebViewTests passed: page reuse, new DNS session, cancellation, timeout and abnormal-process recovery; all network mocked")
            exit(0)
        }
        app.run()
    }
}
