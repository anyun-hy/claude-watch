import Foundation

@main
struct RustBackendTransportTests {
    static func main() {
        var count = 0
        func expect(_ value: Bool, _ message: String) {
            guard value else { fputs("FAIL: \(message)\n", stderr); exit(1) }
            count += 1
        }
        // A future receipt must never authorize a context merely because the
        // UI's timer is behind the engine capture time.
        expect(!MonitorSnapshotTiming.isCurrent(capturedAt: 200, now: 199), "future engine receipt is not current")
        expect(MonitorSnapshotTiming.isCurrent(capturedAt: 200, now: 200.01), "same-round engine receipt is current")

        var gate = MonitorRefreshGate()
        expect(gate.request(manual: false), "first background read starts")
        expect(!gate.request(manual: true), "manual request joins active read")
        expect(gate.manualVisible, "joined manual request stays visible")
        expect(gate.complete(), "one queued manual read follows")
        expect(gate.request(manual: true), "queued manual read starts once")
        _ = gate.complete()
        print("RustBackendTransportTests: \(count) assertions passed")
    }
}
