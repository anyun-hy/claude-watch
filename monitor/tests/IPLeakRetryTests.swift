import Foundation

@MainActor
private final class FakeDNSRunner: IPLeakDNSRunning {
    var onDiagnostic: ((String, Bool) -> Void)?
    var callback: ((LeakProbeResult) -> Void)?
    var cancelled = false
    func start(rounds: Int, id: UUID, progress: @escaping (String) -> Void,
               completion: @escaping (LeakProbeResult) -> Void) { callback = completion; progress("检测中") }
    func cancel() { cancelled = true }
}

@main
struct IPLeakRetryTests {
    @MainActor static func main() async {
        func expect(_ value: Bool, _ message: String) { if !value { fputs("FAIL: \(message)\n", stderr); exit(1) } }
        var attempts: [FakeDNSRunner] = [], received: [LeakProbeResult] = []
        let wrapper = IPLeakDNSRetryRunner(stallTimeout: 0.2, totalTimeout: 2, makeRunner: {
            let runner = FakeDNSRunner(); attempts.append(runner); return runner
        })
        var diagnostics: [String] = []
        wrapper.onDiagnostic = { event, _ in diagnostics.append(event) }
        wrapper.start(rounds: 5, id: UUID()) { received.append($0) }
        for _ in 0..<100 where attempts.count < 2 { try? await Task.sleep(nanoseconds: 10_000_000) }
        expect(attempts.count == 2 && attempts[0].cancelled, "stalled round is cancelled and retried exactly once")
        expect(diagnostics.contains("dns_retry"), "retry is visible in bounded diagnostics")
        let result = LeakProbeResult(kind: "dns", status: "complete", startedAt: 1, finishedAt: 2,
                                     scope: "fixture", observations: [], errors: [], contextChanged: false, details: [])
        attempts[0].callback?(result)
        expect(received.isEmpty, "late result from cancelled round is discarded")
        attempts[1].callback?(result)
        expect(received.count == 1 && received[0].status == "complete", "only the new round is delivered")
        attempts[0].callback?(result)
        expect(received.count == 1, "a stale callback cannot replace completed evidence")

        wrapper.start(rounds: 5, id: UUID()) { received.append($0) }
        expect(attempts.count == 2, "a successful collector is retained for the next round")
        attempts[1].callback?(result)
        expect(received.count == 2, "reused collector publishes the new round")
        wrapper.invalidate()
        attempts.removeAll(); received.removeAll()
        wrapper.start(rounds: 5, id: UUID()) { received.append($0) }
        for _ in 0..<100 where received.isEmpty { try? await Task.sleep(nanoseconds: 10_000_000) }
        expect(attempts.count == 2 && received.count == 1 && received[0].status == "timeout",
               "two stalled rounds produce a bounded timeout, never a pass")
        expect(received[0].errors.first?.code == "timeout", "timeout remains identifiable in diagnostics")
        expect(diagnostics.contains("watchdog_timeout"), "an exhausted retry emits a timeout diagnostic")

        wrapper.invalidate()
        attempts.removeAll(); received.removeAll()
        wrapper.start(rounds: 5, id: UUID()) { received.append($0) }
        wrapper.cancel(); attempts[0].callback?(result)
        try? await Task.sleep(nanoseconds: 60_000_000)
        expect(received.isEmpty && attempts.count == 1, "cancelled runs neither retry nor publish late results")
        print("IPLeak native retry: bounded recovery, timeout and cancellation passed")
    }
}
