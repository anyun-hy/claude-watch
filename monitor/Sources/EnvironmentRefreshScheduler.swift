import Foundation

/// Debounces snapshot-derived proxy context before starting a costly
/// environment observation. Empty/transient contexts never count as a change.
struct EnvironmentRefreshScheduler {
    enum Trigger: Equatable { case initial, changed, interval, retry }
    private(set) var stableContext: String?
    private var candidateContext: String?
    private var consecutiveCandidateCount = 0
    private var lastSuccess: Date?
    private var retryAfter: Date?
    private var failures = 0
    private(set) var inFlight = false
    var isInFlight: Bool { inFlight }

    mutating func requestRefresh() {
        lastSuccess = nil
    }

    mutating func claim(context: String?, now: Date, switcherBusy: Bool) -> Trigger? {
        guard !inFlight, !switcherBusy else { return nil }
        guard let context, !context.isEmpty else {
            candidateContext = nil; consecutiveCandidateCount = 0
            return nil
        }
        if context == candidateContext { consecutiveCandidateCount += 1 }
        else { candidateContext = context; consecutiveCandidateCount = 1 }
        guard consecutiveCandidateCount >= 2 else { return nil }
        let trigger: Trigger
        if let retryAfter {
            guard now >= retryAfter else { return nil }
            trigger = .retry
        } else if stableContext == nil { trigger = .initial }
        else if stableContext != context { trigger = .changed }
        else if lastSuccess.map({ now.timeIntervalSince($0) >= 60 }) ?? true { trigger = .interval }
        else { return nil }
        inFlight = true
        return trigger
    }

    mutating func complete(context: String?, accepted: Bool, now: Date) {
        inFlight = false
        guard accepted, let context, !context.isEmpty else {
            failures += 1
            retryAfter = now.addingTimeInterval(min(30, Double(5 * (1 << min(failures - 1, 2)))))
            return
        }
        stableContext = context
        candidateContext = context
        consecutiveCandidateCount = max(consecutiveCandidateCount, 2)
        lastSuccess = now
        retryAfter = nil
        failures = 0
    }
}
