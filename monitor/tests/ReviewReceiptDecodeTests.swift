import Foundation

private struct ReviewWrapper: Decodable {
    let environment: CurrentEnvironmentReceipt
    let background: BackgroundServiceReceipt
    let webrtc: LeakProbeResult?
}

@main
struct ReviewReceiptDecodeTests {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("review fixture directory required") }
        let root = URL(fileURLWithPath: CommandLine.arguments[1])
        for name in ["normal", "ipChanged", "cnRisk", "transientFailure", "evidenceExpired", "recovered"] {
            let bytes = try Data(contentsOf: root.appendingPathComponent(name + ".json"))
            let value = try JSONDecoder().decode(ReviewWrapper.self, from: bytes)
            guard let preview = value.environment.policy_evaluation,
                  SwitcherStore.acceptsDisplayPolicy(preview, for: value.environment, hasUnsavedSettings: false) else {
                fatalError("same-observation preview rejected for \\(name)")
            }
            guard value.environment.facts?.state.isEmpty == false,
                  value.background.session_guard?.state.isEmpty == false else {
                fatalError("missing flattened facts/session guard for \\(name)")
            }
            if ["ipChanged", "cnRisk", "evidenceExpired", "recovered"].contains(name) {
                guard value.background.session_guard?.state == "locked",
                      value.background.session_guard?.reason?.detail.isEmpty == false else {
                    fatalError("locked session evidence missing for \\(name)")
                }
            }
            if name == "normal" {
                let service = value.environment.rows.first { $0.id == "reachability" }
                let asn = value.environment.rows.first { $0.id == "asn" }
                guard service?.state == "ok",
                      service?.detail.contains("需要浏览器验证") == true,
                      service?.detail.contains("未提供密钥") == true,
                      asn?.current?.contains("AS2516") == true,
                      asn?.reference?.contains("JP") == true,
                      let rtc = value.webrtc else {
                    fatalError("normal service/ASN/WebRTC contract missing")
                }
                let http = rtc.observations.first { $0.kind == "http" }?.address
                let srflx = rtc.observations.first { $0.kind == "srflx" }?.address
                guard rtc.status == "complete", http == srflx else {
                    fatalError("normal WebRTC receipt does not match same-round HTTP exit")
                }
            }
        }
        print("ReviewReceiptDecodeTests: six production-schema wrappers decoded")
    }
}
