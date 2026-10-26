import AppKit
import WebKit

@main
struct LeakBridgeTests {
    @MainActor static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        let runner = WebRTCProbeRunner()
        // Run the real bundled page/collector/Swift message boundary, replacing
        // both outbound primitives before the page script can execute.
        runner.testBootstrap = #"""
        window.fetch = function () {
          return Promise.resolve({ok:true,text:function(){return Promise.resolve('ip=8.8.4.4\n');}});
        };
        window.RTCPeerConnection = class {
          constructor() { this.iceGatheringState = 'new'; }
          createDataChannel() {}
          createOffer() { return Promise.resolve({type:'offer',sdp:''}); }
          setLocalDescription() {
            queueMicrotask(() => {
              this.onicecandidate({candidate:{address:'8.8.4.4',type:'srflx',protocol:'udp'}});
              this.onicecandidate({candidate:null});
              this.iceGatheringState = 'complete';
              this.onicegatheringstatechange();
            });
            return Promise.resolve();
          }
          close() {}
        };
        """#
        runner.start(id: UUID()) { result in
            let verdict = LeakPolicy.evaluate(result, kind: .webrtc, expected: "", now: Date().timeIntervalSince1970)
            guard result.status == "complete", result.errors.isEmpty,
                  result.observations.filter({ $0.kind == "srflx" }).count == 2,
                  result.observations.contains(where: { $0.kind == "http" && $0.address == "8.8.4.4" }),
                  verdict.state == .matched else {
                fputs("FAIL: isolated WebKit bridge: \(result.status) \(result.errors) \(verdict.detail)\n", stderr)
                exit(1)
            }
            print("LeakBridgeTests: local resource + CSP + JavaScript collector + native receipt passed; fetch and RTC mocked")
            exit(0)
        }
        app.run()
        _ = runner
    }
}
