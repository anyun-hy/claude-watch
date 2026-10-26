import Foundation

@main
struct MonitorSnapshotTimingTests {
    static func main() {
        func expect(_ value: Bool, _ message: String) {
            guard value else { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }
        // Regression: the old timer value can precede a just-captured snapshot.
        expect(!MonitorSnapshotTiming.isCurrent(capturedAt: 101, now: 100), "old clock must not create a live context")
        // MonitorStore now advances its clock before deriving the proxy context.
        expect(MonitorSnapshotTiming.isCurrent(capturedAt: 101, now: 101.001), "fresh snapshot creates a usable context")
        expect(!MonitorSnapshotTiming.isCurrent(capturedAt: 101, now: 116.1), "expired snapshot remains unusable")
        print("MonitorSnapshotTimingTests: 3 assertions passed")
    }
}
