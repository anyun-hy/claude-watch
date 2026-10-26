import Foundation

@main
struct AIProbeTests {
    @MainActor static func main() async throws {
        var passed = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            guard value() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
            passed += 1
        }
        let now = Date().timeIntervalSince1970
        for service in AIService.allCases {
            let ready = AIProbeStore.fixture(service, scenario: .ready)
            expect(AIProbePolicy.evaluate(ready, service: service, now: now).state == .unconfigured, "valid AI observation is informational, not account safety")
            expect(AIProbePolicy.evaluate(ready, service: service, now: now + 301).state == .incomplete, "old observation expires")
            for scenario in [AIProbeFixtureScenario.timeout, .empty] {
                let result = AIProbeStore.fixture(service, scenario: scenario)
                expect(AIProbePolicy.evaluate(result, service: service, now: now).state == .incomplete, "\(scenario) cannot pass")
            }
            let limited = AIProbeStore.fixture(service, scenario: .limited)
            expect(limited.exitIP.isEmpty && !limited.referenceIP.isEmpty, "limited main endpoint does not inherit reference IP")
            expect(limited.countryCode.isEmpty && limited.ipTimezone.isEmpty, "missing service exit cannot inherit unrelated geography")
            expect(AIProbePolicy.evaluate(limited, service: service, now: now).state == .difference, "HTTP restriction is distinct from success")
            let decoded = try JSONDecoder().decode(AIProbeResult.self, from: JSONEncoder().encode(limited))
            expect(decoded.exitIP.isEmpty && decoded.endpoints.first?.httpStatus == 403, "partial receipt retains required wire fields")
        }
        let r = AIProbeStore.fixture(.gpt, scenario: .ready)
        let needsAuth = AIProbeResult(service: r.service, status: r.status, startedAt: r.startedAt, finishedAt: r.finishedAt,
            exitIP: r.exitIP, referenceIP: r.referenceIP, exitSource: r.exitSource, countryCode: r.countryCode, country: r.country,
            region: r.region, city: r.city, organization: r.organization, ipTimezone: r.ipTimezone,
            endpoints: r.endpoints, errors: [], details: [])
        expect(AIProbePolicy.evaluate(needsAuth, service: .gpt, now: now).state == .unconfigured, "401 is a response, not a network outage")
        expect(AIProbePolicy.evaluate(needsAuth, service: .claude, now: now).state == .incomplete, "cross-service receipt rejected")
        let store = AIProbeStore(isFixture: true)
        store.loadFixture(.ready)
        expect(store.state(.claude).result != nil && store.state(.gpt).result != nil, "independent service pages have fixture data")
        store.start(.gpt)
        expect(store.gpt.running && store.gpt.result == nil, "start clears prior receipt")
        store.cancel(.gpt)
        try await Task.sleep(nanoseconds: 650_000_000)
        expect(store.gpt.verdict.state == .cancelled && store.gpt.result == nil, "late callback after cancellation is ignored")
        store.fixtureScenario = .timeout; store.start(.gpt)
        try await Task.sleep(nanoseconds: 650_000_000)
        expect(store.gpt.verdict.state == .incomplete, "subsequent timeout cannot resurrect prior result")
        print("AIProbeTests: \(passed) assertions passed; no network")
    }
}
