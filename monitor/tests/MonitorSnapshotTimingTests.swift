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
        var context = DiagnosticContextTracker()
        let now = Date(timeIntervalSince1970: 100)
        expect(context.observe("tag|global|JP-1", observedAt: now) == .initial,
               "first verified proxy identity establishes a diagnostic context")
        expect(context.retained(at: now.addingTimeInterval(5)) == "tag|global|JP-1",
               "a short sampler gap retains identity only for an in-flight diagnostic")
        expect(context.observe(nil, observedAt: now.addingTimeInterval(6)) == .unavailable,
               "missing sampler data is not promoted to a context change")
        expect(context.retained(at: now.addingTimeInterval(11)) == nil,
               "retained diagnostic context expires instead of becoming stale proof")
        expect(context.observe("tag|global|JP-2", observedAt: now.addingTimeInterval(12)) == .changed,
               "a newly verified node is an immediate real context change")
        expect(context.retained(at: now.addingTimeInterval(13)) == "tag|global|JP-2",
               "new identity replaces the previous diagnostic binding")
        let endpoint = "http://127.0.0.1:7890"
        expect(tagReceiptContext(endpoint: endpoint, mode: "global", selectedNode: "JP-a", globalNode: "JP-b") ==
               "\(endpoint)|global|JP-a|JP-b",
               "diagnostic binding matches the four-field Rust TAG receipt signature")
        expect(tagReceiptContext(endpoint: endpoint, mode: "global", selectedNode: "", globalNode: "JP-b") == nil,
               "partial TAG identity cannot start a new probe")
        var sourceTime = DiagnosticContextTracker()
        expect(sourceTime.observe("tag|rule|JP-a", observedAt: now) == .initial,
               "source timestamp fixture initializes")
        expect(sourceTime.observe("tag|rule|JP-a", observedAt: now) == .stable &&
               sourceTime.retained(at: now.addingTimeInterval(11)) == nil,
               "re-reading one backend snapshot never extends cached context lifetime")
        print("MonitorSnapshotTimingTests: 13 assertions passed")
    }
}
