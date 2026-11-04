import Foundation

/// Keeps the last directly verified proxy identity through a short observer
/// gap. A missing sampler result is not evidence that the proxy changed; a
/// newly verified identity is. The retained value is only for binding an
/// in-flight diagnostic to its existing network context, never for presenting
/// the network as currently healthy or authorizing a launch.
struct DiagnosticContextTracker: Equatable {
    enum Transition: Equatable { case initial, stable, changed, unavailable }
    private(set) var context: String?
    private(set) var lastVerifiedAt: Date?
    static let grace: TimeInterval = 10

    mutating func observe(_ candidate: String?, observedAt: Date) -> Transition {
        guard let candidate, !candidate.isEmpty else { return .unavailable }
        guard let context else {
            self.context = candidate
            lastVerifiedAt = observedAt
            return .initial
        }
        guard context != candidate else {
            // Re-reading the same snapshot must not extend the retained
            // binding window. Only a genuinely newer backend observation does.
            if lastVerifiedAt.map({ observedAt > $0 }) ?? true { lastVerifiedAt = observedAt }
            return .stable
        }
        self.context = candidate
        lastVerifiedAt = observedAt
        return .changed
    }

    func retained(at now: Date) -> String? {
        guard let context, let lastVerifiedAt,
              now.timeIntervalSince(lastVerifiedAt) >= 0,
              now.timeIntervalSince(lastVerifiedAt) <= Self.grace else { return nil }
        return context
    }
}

/// Wire-compatible with Rust `receipts::tag_signature`. A missing node value is
/// emitted as an empty segment — exactly like `receipts.rs` joins `a|b|c|d` with
/// `unwrap_or("")` — instead of collapsing the whole signature. `endpoint` and
/// `mode` still must be present: without them there is no verified proxy to bind
/// a receipt to, so the context stays unavailable.
func tagReceiptContext(endpoint: String, mode: String, selectedNode: String, globalNode: String) -> String? {
    guard !endpoint.isEmpty, !mode.isEmpty else { return nil }
    return [endpoint, mode, selectedNode, globalNode].joined(separator: "|")
}
