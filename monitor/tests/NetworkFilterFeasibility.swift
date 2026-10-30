import Foundation
import NetworkExtension

/// Compile-time contract only. This type is never instantiated, packaged as a
/// system extension, or registered with NEFilterManager by this test.
@available(macOS 10.15, *)
final class NetworkFilterFeasibility: NEFilterDataProvider {
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        // The source fields are optional in the API. A production filter must
        // measure Claude and helper-process attribution before relying on them.
        let appToken: Data? = flow.sourceAppAuditToken
        let processToken: Data? = flow.sourceProcessAuditToken
        // `sourceAppIdentifier` is explicitly unavailable in the macOS SDK.
        // Production attribution must therefore validate these optional audit
        // tokens rather than assume a bundle identifier is available.
        _ = (appToken, processToken)

        // A real provider may pause a new flow while a bounded policy decision
        // is pending. This test never receives a flow or returns this verdict.
        return .pause()
    }

    func verifyExistingSocketFlowCanBeDropped(_ flow: NEFilterSocketFlow) {
        // A real provider can update an existing socket flow on a confirmed
        // risk. This function is intentionally never called by the test.
        update(flow, using: .drop(), for: .any)
    }
}

@main
struct NetworkFilterFeasibilityTest {
    static func main() {
        print("NetworkFilterFeasibility: compiled API contract only; no provider was instantiated or activated")
        print("Referenced: NEFilterDataProvider new-flow pause, existing socket-flow drop, source app/process audit tokens")
        print("macOS SDK check: sourceAppIdentifier is unavailable; no bundle-ID attribution is assumed")
    }
}
