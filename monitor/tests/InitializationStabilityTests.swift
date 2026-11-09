import Foundation

@MainActor
private final class StabilityChecks: InitializationChecking {
    var current: InitializationResult = .passed("current", validUntil: Date().timeIntervalSince1970 + 120)
    var failures: [InitializationStep: InitializationResult] = [:]
    func begin() {}
    func check(_ step: InitializationStep) async -> InitializationResult { .passed("passed", validUntil: Date().timeIntervalSince1970 + 120) }
    func approve(_ request: InitializationApproval, progress: @escaping SetupProgressObserver) async -> InitializationResult { .failed(code: "unexpected", detail: "") }
    func validateCurrentEvidence() -> InitializationResult { current }
    func currentEvidenceFailures() -> [InitializationStep: InitializationResult] { failures }
    func finish() {}
}

@main
struct InitializationStabilityTests {
    @MainActor static func main() async {
        func expect(_ condition: Bool, _ message: String) {
            guard condition else { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }
        let backend = SwitcherStore(isFixture: true)
        let store = MonitorStore(leakChecks: LeakCheckStore(isFixture: true),
                                 aiChecks: AIProbeStore(isFixture: true), switcher: backend)
        store.beginInitialization(startSnapshotPolling: false)
        let start = Date()
        store.monitorTick(at: start)
        try? await Task.sleep(nanoseconds: 100_000_000)
        guard let first = backend.background?.observed_at else {
            expect(false, "initialization must read service status on the normal timer"); return
        }
        store.monitorTick(at: start.addingTimeInterval(4))
        try? await Task.sleep(nanoseconds: 100_000_000)
        expect(backend.background?.observed_at == first, "status reads remain rate-limited")
        store.monitorTick(at: start.addingTimeInterval(5))
        try? await Task.sleep(nanoseconds: 100_000_000)
        guard let second = backend.background?.observed_at else {
            expect(false, "the next service status must be available"); return
        }
        expect(second > first, "initialization refreshes actual service evidence before it expires")
        expect(!store.leakChecks.dns.running && !store.leakChecks.rtc.running,
               "service status polling does not start independent network probes")

        func receipt(_ sampled: Double) -> BackgroundServiceReceipt {
            .init(observed_at: sampled, backend_healthy: true, update_source_ready: false,
                  guard_backend_healthy: true, backend_sampling_state: "complete", services: [], policy_issues: [])
        }
        expect(!FirstRunChecks.backendEvidenceIsCurrent(receipt(100), now: 131),
               "the original evidence really expires after thirty seconds")
        expect(FirstRunChecks.backendEvidenceIsCurrent(receipt(116), now: 131),
               "a real subsequent observation keeps the gate current without extending the old timestamp")
        expect(!FirstRunChecks.backendEvidenceIsCurrent(receipt(116), error: "read failed", now: 131),
               "a failed service read cannot be presented as healthy")
        expect(FirstRunChecks.backgroundFailureDetail(receipt(100), error: "", settingsEnabled: true, now: 131).contains("已过期"),
               "expired status is identified rather than asserting that the service stopped")
        expect(FirstRunChecks.backgroundFailureDetail(receipt(116), error: "failed", settingsEnabled: true, now: 131).contains("读取失败"),
               "failed reads are distinguished from a confirmed service failure")
        let checks = StabilityChecks()
        let initialization = FirstRunInitialization(checks: checks, completed: false, saveCompletion: {})
        await initialization.start()
        checks.current = .failed(code: "protection_not_ready", detail: "backend unavailable")
        initialization.refreshReadiness()
        expect(initialization.rows[7].status == .failed && !initialization.canEnter(at: Date().timeIntervalSince1970),
               "unavailable backend immediately removes entry readiness")
        initialization.refreshReadiness()
        expect(initialization.rows[7].status == .failed, "a persistent backend failure cannot recover without real evidence")
        checks.current = .passed("current", validUntil: Date().timeIntervalSince1970 + 120)
        initialization.refreshReadiness()
        expect(initialization.allPassed && initialization.canEnter(at: Date().timeIntervalSince1970),
               "fresh complete evidence automatically recovers a transient backend failure")
        checks.current = .failed(code: "protection_not_ready", detail: "backend unavailable")
        initialization.refreshReadiness()
        checks.current = .passed("current", validUntil: Date().timeIntervalSince1970 + 120)
        checks.failures[.dns] = .failed(code: "dns_expired", detail: "DNS expired")
        initialization.refreshReadiness()
        expect(!initialization.allPassed && !initialization.canEnter(at: Date().timeIntervalSince1970),
               "backend recovery never bypasses an expired prerequisite")
        let changedChecks = StabilityChecks()
        let changed = FirstRunInitialization(checks: changedChecks, completed: false, saveCompletion: {})
        await changed.start()
        changedChecks.failures[.connection] = .failed(code: "context_changed", detail: "different proxy")
        changed.refreshReadiness()
        changedChecks.failures = [:]
        changed.refreshReadiness(at: Date().addingTimeInterval(120))
        expect(!changed.running && changed.rows[1].code == "context_changed" && !changed.allPassed,
               "a confirmed proxy change cannot automatically reuse the earlier environment approval")
        print("Initialization stability: scheduler and freshness contracts passed; fixture only")
    }
}
