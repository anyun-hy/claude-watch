import Foundation

@main
struct LeakCheckTests {
    @MainActor static func main() async throws {
        var passed = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            guard value() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
            passed += 1
        }
        let epoch = 1000.0
        func observation(_ address: String, _ kind: String, source: String = "fixture", country: String? = nil) -> LeakObservation {
            .init(address: address, kind: kind, source: source, country: country)
        }
        let http = observation("1.1.1.1", "http", country: "JP")
        let resolver = observation("8.8.8.8", "resolver", country: "JP")
        let candidate = observation("1.1.1.1", "srflx")
        func receipt(_ kind: LeakKind, _ rows: [LeakObservation], status: String = "complete", errors: [LeakProbeError] = [], at: Double = 999, changed: Bool = false) -> LeakProbeResult {
            .init(kind: kind.rawValue, status: status, startedAt: at - 2, finishedAt: at, scope: "fixture",
                  observations: rows, errors: errors, contextChanged: changed, details: [])
        }
        func verdict(_ result: LeakProbeResult, _ kind: LeakKind, expected: String = "") -> LeakVerdictState {
            LeakPolicy.evaluate(result, kind: kind, expected: expected, now: epoch).state
        }
        expect(verdict(receipt(.dns, [http, resolver]), .dns) == .matched, "same-country DNS and HTTP egress passes without an IP list")
        let unavailableError = LeakProbeError(stage: "context", code: "context_unavailable", message: "fixture")
        expect(verdict(receipt(.dns, [http, observation("8.8.8.8", "resolver", country: "CN")], errors: [unavailableError]), .dns) == .incomplete,
               "a foreign resolver with unconfirmed context is unknown, not an attributed risk")
        expect(verdict(receipt(.dns, [http, resolver]), .dns, expected: "9.9.9.9") == .matched, "DNS ignores an obsolete manual resolver list")
        expect(verdict(receipt(.dns, []), .dns) == .incomplete, "empty DNS receipt is never safe")
        expect(verdict(receipt(.dns, [http]), .dns) == .incomplete, "HTTP success is not DNS evidence")
        expect(verdict(receipt(.dns, [resolver]), .dns) == .incomplete, "missing HTTP context stays incomplete")
        for kind in LeakKind.allCases {
            let rows = kind == .dns ? [http, resolver] : [http, candidate]
            for status in ["timeout", "partial", "error", "unknown"] {
            expect(verdict(receipt(kind, rows, status: status), kind) == .incomplete,
                       "\(kind) \(status) cannot become a pass from partial good addresses")
            }
            expect(verdict(receipt(kind, rows, errors: [.init(stage: "probe", code: "failed", message: "fixture")]), kind) == .incomplete,
                   "complete flag cannot hide an error")
            expect(verdict(receipt(kind, rows, changed: true), kind) == .incomplete, "network context change invalidates either probe")
            expect(verdict(receipt(kind, rows, at: 600), kind) == .incomplete, "stale sample cannot remain green")
            expect(verdict(receipt(kind, rows, at: 1100), kind) == .incomplete, "future sample rejected")
        }
        expect(verdict(receipt(.webrtc, [http, candidate]), .webrtc) == .matched, "complete HTTP and STUN sample equal")
        expect(verdict(receipt(.webrtc, [http, observation("8.8.8.8", "srflx")]), .webrtc) == .difference, "single differing STUN address is not a green pass")
        expect(verdict(receipt(.webrtc, [http, candidate, observation("8.8.8.8", "srflx")]), .webrtc) == .difference, "all public candidates are compared")
        expect(verdict(receipt(.webrtc, [http, candidate, observation("8.8.8.8", "srflx")]), .webrtc, expected: "1.1.1.1,8.8.8.8") == .matched, "intentional multiple exits can match explicit policy")
        expect(verdict(receipt(.webrtc, [http, observation("relay.local", "mdns")]), .webrtc) == .incomplete, "mDNS-only is not a public-egress pass")
        expect(verdict(receipt(.webrtc, [http, observation("8.8.8.8", "relay")]), .webrtc) == .incomplete, "TURN-only address is not the client egress")
        expect(verdict(receipt(.webrtc, [http, observation("192.168.1.3", "host")]), .webrtc) == .incomplete, "local-only candidates not safe")
        expect(verdict(receipt(.webrtc, [http, candidate, observation("10.0.0.2", "srflx")]), .webrtc) == .incomplete, "nonpublic STUN response cannot be silently discarded into a pass")
        expect(verdict(receipt(.webrtc, [http, observation("2606:4700:4700::1111", "srflx")]), .webrtc) == .incomplete, "IPv6 candidate requires IPv6 reference or explicit policy")
        let http6 = observation("2606:4700:4700:0000:0000:0000:0000:1111", "http")
        expect(verdict(receipt(.webrtc, [http6, observation("2606:4700:4700::1111", "srflx")]), .webrtc) == .matched, "IPv6 canonical forms compare equal")
        expect(verdict(receipt(.webrtc, [http, observation("::ffff:1.1.1.1", "srflx")]), .webrtc) == .matched, "IPv4-mapped IPv6 compares with IPv4")
        let japanHTTP = http
        let japanResolver = observation("9.9.9.9", "resolver", country: "JP")
        var japanCandidate = observation("8.8.8.8", "srflx"); japanCandidate.country = "JP"
        expect(verdict(receipt(.dns, [japanHTTP, japanResolver]), .dns) == .matched, "different DNS IP in same country passes")
        expect(verdict(receipt(.webrtc, [japanHTTP, japanCandidate]), .webrtc) == .difference, "same country cannot hide a different public WebRTC candidate")
        var foreignResolver = resolver; foreignResolver.country = "CN"
        expect(verdict(receipt(.dns, [japanHTTP, foreignResolver]), .dns) == .difference, "foreign DNS country is leak risk")
        let noCountryResolver = observation("9.9.9.9", "resolver")
        expect(verdict(receipt(.dns, [japanHTTP, noCountryResolver]), .dns) == .incomplete, "missing DNS country cannot pass")
        let secondCountryResolver = observation("4.4.4.4", "resolver", country: "US")
        expect(verdict(receipt(.dns, [japanHTTP, japanResolver, secondCountryResolver]), .dns) == .difference, "multiple DNS countries including foreign is leak risk")
        expect(verdict(receipt(.dns, [japanHTTP, japanResolver], at: 600), .dns) == .incomplete, "expired DNS sample cannot pass")
        var foreignCandidate = candidate; foreignCandidate.country = "CN"
        expect(verdict(receipt(.webrtc, [japanHTTP, foreignCandidate]), .webrtc) == .difference, "contradictory country metadata cannot earn a match")
        for address in ["172.64.155.209", "172.15.1.1", "172.32.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            expect(LeakIPAddress(address)?.isPublic == true, "valid public address \(address)")
        }
        for address in ["172.16.1.1", "172.31.1.1", "198.18.0.1", "198.19.255.255", "100.64.0.2", "127.0.0.1", "0.0.0.0", "224.0.0.1", "192.0.2.1", "2001:db8::1", "3fff::1", "fc00::1", "fe80::1", "::1"] {
            expect(LeakIPAddress(address)?.isPublic == false, "nonpublic or reserved address \(address)")
        }
        for input in ["host.local", "8.8.8.8:53", "8.8.8.999", "1.1.1.1,garbage", "fe80::1%en0", "[2606:4700::1]", "127.0.0.1"] {
            expect((try? LeakPolicy.expectedAddresses(input)) == nil, "reject invalid expected policy \(input)")
        }
        expect((try? LeakPolicy.expectedAddresses(" 8.8.8.8，8.8.8.8\n1.1.1.1 ").count) == 2, "expected list deduplicates and accepts common separators")

        let store = LeakCheckStore(isFixture: true)
        store.loadFixture(.matched)
        expect(store.dns.verdict.state == .matched && store.rtc.verdict.state == .matched, "offline matching fixtures")
        store.now = Date().addingTimeInterval(301)
        expect(store.rtc.verdict.state == .incomplete, "display clock expires old sample")
        store.loadFixture(.matched)
        store.start(.webrtc)
        expect(store.rtc.running && store.rtc.result != nil && store.rtc.verdict.state == .running, "new run retains the prior receipt while updating")
        store.cancel(.webrtc)
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(store.rtc.verdict.state == .cancelled && store.rtc.result == nil, "cancelled fixture cannot publish a late pass")
        store.fixtureScenario = .difference; store.start(.webrtc)
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(store.rtc.verdict.state == .difference, "new run after cancellation publishes independently")
        var networkContext = "A"
        store.contextProvider = { networkContext }
        store.fixtureScenario = .matched; store.start(.webrtc)
        networkContext = "B"
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(store.rtc.verdict.state == .incomplete, "context change during a run cannot retain pass")
        expect(store.rtc.result?.contextChanged == true, "a verified different context remains a real change")
        let missingDuringDNS = LeakCheckStore(isFixture: true)
        var dnsContext: String? = "A"
        var unknownSubmissions = 0
        missingDuringDNS.contextProvider = { dnsContext }
        missingDuringDNS.onDNSComplete = { _, _ in unknownSubmissions += 1; return true }
        missingDuringDNS.start(.dns); dnsContext = nil
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(missingDuringDNS.dns.verdict.state == .incomplete, "missing context never passes")
        expect(missingDuringDNS.dns.result?.contextChanged == false, "missing context is not a confirmed change")
        expect(missingDuringDNS.dns.result?.errors.contains(where: { $0.code == "context_unavailable" }) == true,
               "missing context is recorded as unavailable")
        expect(unknownSubmissions == 1 && !missingDuringDNS.initializationReceiptIsCurrent(.dns),
               "the incomplete result can be recorded but cannot authorize initialization")
        var optionalContext: String? = nil
        store.contextProvider = { optionalContext }
        store.start(.webrtc); optionalContext = "ready"
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(store.rtc.verdict.state == .incomplete, "initially unknown context cannot turn into a green pass")
        store.start(.dns)
        expect(store.dns.running, "DNS does not require a manually entered policy")
        let retention = LeakCheckStore(isFixture: true)
        retention.loadFixture(.matched)
        retention.fixtureScenario = .partial; retention.start(.dns)
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(retention.dns.verdict.state == .incomplete && retention.dns.result?.status == "partial", "latest partial DNS result remains authoritative")
        expect(retention.dns.displaysPreviousSuccessfulResult && retention.dns.displayResult?.status == "complete", "partial refresh retains the prior success only for display")
        var changedContext = "A"
        retention.contextProvider = { changedContext }
        retention.loadFixture(.matched); retention.start(.dns); changedContext = "B"
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(retention.dns.result?.contextChanged == true && !retention.dns.displaysPreviousSuccessfulResult, "context change never displays the previous pass as current evidence")
        let historicalContext = LeakCheckStore(isFixture: true)
        var historicalNode = "node-A"
        historicalContext.contextProvider = { historicalNode }
        historicalContext.fixtureScenario = .matched; historicalContext.start(.dns)
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(historicalContext.dns.lastSuccessfulResult != nil, "successful sample records its proxy context")
        historicalNode = "node-B"
        historicalContext.fixtureScenario = .partial; historicalContext.start(.dns)
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(historicalContext.dns.lastSuccessfulResult == nil && !historicalContext.dns.displaysPreviousSuccessfulResult,
               "a new proxy context never displays a previous node's successful sample")
        let samplerGap = LeakCheckStore(isFixture: true)
        var samplerContext: String? = "node-A"
        samplerGap.contextProvider = { samplerContext }
        samplerGap.fixtureScenario = .matched; samplerGap.start(.dns)
        try await Task.sleep(nanoseconds: 450_000_000)
        samplerContext = nil
        samplerGap.fixtureScenario = .partial; samplerGap.start(.dns)
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(samplerGap.dns.lastSuccessfulResult != nil,
               "an unavailable sampler does not delete the previous context-bound receipt")
        expect(samplerGap.dns.verdict.state == .incomplete && !samplerGap.dns.displaysPreviousSuccessfulResult,
               "a sampler gap never displays cached evidence as a current pass")
        let unavailableAutomatic = LeakCheckStore(isFixture: true)
        unavailableAutomatic.contextProvider = { nil }
        unavailableAutomatic.refreshWebRTCIfNeeded(interval: 0)
        expect(!unavailableAutomatic.dns.running && !unavailableAutomatic.rtc.running,
               "automatic probes wait for a verified context instead of manufacturing a context change")
        let retainedOnly = LeakCheckStore(isFixture: true)
        retainedOnly.contextProvider = { "old-but-bound" }
        retainedOnly.automaticContextProvider = { nil }
        retainedOnly.refreshWebRTCIfNeeded(interval: 0)
        let freshDuringGap = await retainedOnly.ensureFreshDNSReceipt(maximumWait: 1)
        expect(!retainedOnly.dns.running && !retainedOnly.rtc.running && !freshDuringGap,
               "retained context only binds an in-flight probe and never starts or refreshes a new one")

        let primary = LeakCheckStore(isFixture: true)
        primary.contextProvider = { "current" }
        var dnsWrites = 0, rtcWrites = 0
        primary.onDNSComplete = { _, _ in dnsWrites += 1; return true }
        primary.onWebRTCComplete = { _, _ in rtcWrites += 1; return true }
        let ready = await primary.ensureFreshDNSReceipt(maximumWait: 2)
        expect(ready && dnsWrites == 1 && primary.dns.verdict.state == .matched,
               "primary DNS completes through the shared backend receipt callback")
        primary.start(.webrtc); primary.start(.dns); primary.cancel(.dns)
        expect(primary.rtc.running, "cancelling DNS never cancels WebRTC")
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(rtcWrites == 1 && dnsWrites == 1, "cancelled DNS cannot submit a late receipt")
        // Stale-submit epoch guard: a slow submission of round A returning
        // after round B was accepted must not overwrite the recorded receipt.
        let epochGuard = LeakCheckStore(isFixture: true)
        epochGuard.contextProvider = { "epoch-ctx" }
        epochGuard.fixtureDelayNanoseconds = 1_000_000
        var submitCalls = 0
        var releaseFirstSubmit = false
        epochGuard.onDNSComplete = { _, _ in
            submitCalls += 1
            if submitCalls == 1 {
                while !releaseFirstSubmit { try? await Task.sleep(nanoseconds: 10_000_000) }
            }
            return true
        }
        epochGuard.start(.dns)
        try await Task.sleep(nanoseconds: 450_000_000)
        let staleFinishedAt = epochGuard.dns.result!.finishedAt
        epochGuard.start(.dns)
        try await Task.sleep(nanoseconds: 450_000_000)
        let freshFinishedAt = epochGuard.dns.result!.finishedAt
        expect(freshFinishedAt > staleFinishedAt && submitCalls == 2, "a second round completes while the first submission is still in flight")
        expect(epochGuard.initializationReceiptIsCurrent(.dns), "the newer accepted receipt is the recorded one while the older submit is pending")
        releaseFirstSubmit = true
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(epochGuard.dns.result!.finishedAt == freshFinishedAt && epochGuard.initializationReceiptIsCurrent(.dns),
               "a stale in-flight submission cannot overwrite the newer recorded receipt")
        // Receipt-driven WebRTC cadence: while the backend still accepts the
        // recorded receipt (display TTL), the schedule must not reopen a
        // WebView for duplicate evidence; a context change always re-probes.
        let cadence = LeakCheckStore(isFixture: true)
        var cadenceContext = "rtc-ctx"
        cadence.contextProvider = { cadenceContext }
        cadence.automaticContextProvider = { cadenceContext }
        cadence.fixtureDelayNanoseconds = 1_000_000
        cadence.onWebRTCComplete = { _, _ in true }
        cadence.refreshWebRTCIfNeeded(interval: 0)
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(!cadence.rtc.running && cadence.initializationReceiptIsCurrent(.webrtc), "the automatic webrtc probe completes and records its receipt")
        cadence.refreshWebRTCIfNeeded(interval: 0)
        expect(!cadence.rtc.running, "a recorded receipt the backend still accepts suppresses duplicate webrtc re-probing")
        cadenceContext = "rtc-ctx-2"
        cadence.refreshWebRTCIfNeeded(interval: 0)
        expect(cadence.rtc.running, "a proxy context change always re-probes webrtc")
        let receiptProbe = LeakCheckStore(isFixture: true)
        let receiptStore = SwitcherStore(isFixture: true)
        receiptProbe.contextProvider = { "ctx" }
        receiptStore.diagnosticContextProvider = { "ctx" }
        var injectedCode = "dns_context_changed"
        var submittedRun: UUID?
        var diagnostic: (LeakKind, String, UUID?, String?)?
        receiptStore.receiptCommandFixture = { _, _ in
            try JSONSerialization.data(withJSONObject: ["status":"error", "code":injectedCode, "message":"private-token 203.0.113.9"])
        }
        receiptStore.onReceiptDiagnostic = { kind, event, id, code in diagnostic = (kind,event,id,code) }
        receiptProbe.onDNSComplete = { result, id in submittedRun = id; return await receiptStore.recordDNSLeak(result, runID: id) }
        receiptProbe.onWebRTCComplete = { result, id in submittedRun = id; return await receiptStore.recordWebRTCRisk(result, runID: id) }
        for code in ["dns_context_changed", "busy", "invalid_dns_receipt"] {
            injectedCode = code; diagnostic = nil; submittedRun = nil
            receiptProbe.start(.dns)
            try await Task.sleep(nanoseconds: 450_000_000)
            expect(receiptProbe.dns.verdict.state == .matched, "a rejected receipt does not rewrite the matched detection")
            expect(diagnostic?.2 == submittedRun && diagnostic?.3 == code && diagnostic?.1 == "receipt_backend_error", "DNS rejection retains this run and bounded backend code")
        }
        injectedCode = "webrtc_context_unavailable"; diagnostic = nil; submittedRun = nil
        receiptProbe.start(.webrtc)
        try await Task.sleep(nanoseconds: 450_000_000)
        expect(diagnostic?.0 == .webrtc && diagnostic?.2 == submittedRun && diagnostic?.3 == "webrtc_context_unavailable", "WebRTC rejection retains its own run and code")
        expect(SwitcherStore.safeReceiptCode("private-token-203.0.113.9") == "other", "unrecognized backend strings never enter receipt diagnostics")

        if CommandLine.arguments.count == 2 {
            let bytes = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
            let live = try JSONDecoder().decode([LeakProbeResult].self, from: bytes)
            for sample in live {
                guard let kind = LeakKind(rawValue: sample.kind) else { continue }
                let verdict = LeakPolicy.evaluate(sample, kind: kind, expected: "", now: sample.finishedAt + 1)
                expect(verdict.state == .matched, "recorded \(kind) receipt matches under its original sampling time")
            }
        }
        print("LeakCheckTests: \(passed) assertions passed; fixture mode only")
    }
}
