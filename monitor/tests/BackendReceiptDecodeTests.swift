import Foundation

@main
struct BackendReceiptDecodeTests {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("receipt path required") }
        let data = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let receipt = try JSONDecoder().decode(CurrentEnvironmentReceipt.self, from: data)
        guard let preview = receipt.policy_evaluation else { fatalError("missing policy preview") }
        guard receipt.context_transition?.state == "stable" else { fatalError("expected stable fixture") }
        guard SwitcherStore.acceptsDisplayPolicy(preview, for: receipt, hasUnsavedSettings: false) else {
            fatalError("same-observation preview rejected")
        }
        guard !preview.grants_launch_permission else { fatalError("preview must never authorize launch") }
        print("BackendReceiptDecodeTests: production receipt decoded and preview bound")
    }
}
