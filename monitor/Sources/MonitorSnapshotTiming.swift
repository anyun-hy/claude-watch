import Foundation

/// Keeps freshness checks explicit when a new snapshot arrives between timer
/// ticks. A clock older than the capture time is never a valid context.
enum MonitorSnapshotTiming {
    static let proxyMaximumAge: TimeInterval = 30
    static func isCurrent(capturedAt: Double, now: Double, maximumAge: Double = 8) -> Bool {
        let elapsed = now - capturedAt
        return elapsed >= 0 && elapsed < maximumAge
    }
}
