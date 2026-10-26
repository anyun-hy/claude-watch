import Foundation

@main
struct ServiceStatusDecodeTests {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("service-status JSON path required") }
        let bytes = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let receipt = try JSONDecoder().decode(BackgroundServiceReceipt.self, from: bytes)
        guard let session = receipt.session_guard else { fatalError("missing session_guard") }
        guard ["safe", "active", "unknown", "pending", "risk", "locked", "missing"].contains(session.state) else {
            fatalError("unknown session state")
        }
        if ["risk", "locked"].contains(session.state) {
            guard session.reason?.code.isEmpty == false, session.reason?.detail.isEmpty == false else {
                fatalError("risk/locked receipt must explain its reason")
            }
        }
        if let baseline = session.baseline, baseline.ip?.isEmpty != false {
            fatalError("baseline must contain an IP when present")
        }
        print("ServiceStatusDecodeTests: production service-status decoded")
    }
}
