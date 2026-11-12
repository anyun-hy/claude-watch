import Foundation

/// Submits original production-worker probes through the real Swift receiver
/// and the explicitly selected candidate engine. Never generates probe input.
@main
struct LeakReceiptRoundTripTests {
    @MainActor static func main() async throws {
        guard CommandLine.arguments.count == 6,
              CommandLine.arguments[4] == "--observed-probes",
              CommandLine.arguments[5] == "--production-home" else {
            fputs("usage: LeakReceiptRoundTripTests <absolute-engine> <production-home> <context-json> --observed-probes --production-home\n", stderr)
            exit(2)
        }
        let engine = CommandLine.arguments[1]
        let watchHome = CommandLine.arguments[2]
        let contextPath = CommandLine.arguments[3]
        let homeURL = URL(fileURLWithPath: watchHome).standardizedFileURL.resolvingSymlinksInPath()
        guard [engine, watchHome, contextPath].allSatisfy({ $0.hasPrefix("/") }),
              FileManager.default.isExecutableFile(atPath: engine),
              homeURL == FileManager.default.homeDirectoryForCurrentUser.resolvingSymlinksInPath() else {
            fputs("explicit candidate engine and current user's production home are required\n", stderr); exit(2)
        }
        let contextURL = URL(fileURLWithPath: contextPath)
        let input = try JSONSerialization.jsonObject(with: Data(contentsOf: contextURL)) as? [String: Any]
        guard let signature = input?["signature"] as? String, !signature.isEmpty,
              let rawProbes = input?["probes"] as? [[String: Any]] else {
            fputs("context JSON requires the original binding signature and original observed probes\n", stderr); exit(2)
        }
        let probes = try JSONDecoder().decode([LeakProbeResult].self,
            from: JSONSerialization.data(withJSONObject: rawProbes))
        guard (1...2).contains(probes.count), Set(probes.map(\.kind)).count == probes.count,
              probes.allSatisfy({ LeakKind(rawValue: $0.kind) != nil }) else {
            fputs("one or two distinct original DNS/WebRTC probes are required\n", stderr); exit(2)
        }
        let snapshotURL = homeURL.appendingPathComponent("Library/Application Support/ClaudeWatch/state/runtime-snapshot.json")
        func currentSignature() -> String? {
            guard let size = try? snapshotURL.resourceValues(forKeys: [.fileSizeKey]).fileSize,
                  size > 0 && size <= 8 * 1024 * 1024,
                  let bytes = try? Data(contentsOf: snapshotURL),
                  let root = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
                  let snapshot = root["snapshot"] as? [String: Any],
                  let capturedAt = snapshot["capturedAt"] as? Double,
                  snapshot["proxyError"] == nil || snapshot["proxyError"] is NSNull,
                  let rawProxy = snapshot["proxy"] as? [String: Any],
                  let proxyBytes = try? JSONSerialization.data(withJSONObject: rawProxy),
                  let proxy = try? JSONDecoder().decode(ProxySnapshot.self, from: proxyBytes) else { return nil }
            let now = Date().timeIntervalSince1970
            guard MonitorSnapshotTiming.isCurrent(capturedAt: capturedAt, now: now),
                  (0...MonitorSnapshotTiming.proxyMaximumAge).contains(now - proxy.observedAt),
                  proxy.entryState == "verified", proxy.apiState == "available", proxy.coversProxy,
                  !proxy.selectionChanged else { return nil }
            return tagReceiptContext(endpoint: proxy.endpoint, mode: proxy.mode,
                                     selectedNode: proxy.selectedNode, globalNode: proxy.globalNode)
        }
        var outcomes: [[String: Any]] = []
        var commandCount = 0
        var allAccepted = true, allPassed = true
        for value in probes {
            let kind = LeakKind(rawValue: value.kind)!
            let store = SwitcherStore(isFixture: true)
            store.diagnosticContextProvider = currentSignature
            var response: [String: Any] = [:]
            var receiptCode = "none"
            store.onReceiptDiagnostic = { _, _, _, code in receiptCode = code ?? "none" }
            store.receiptCommandFixture = { command, payload in
                guard ["dns-leak-record", "webrtc-risk-record"].contains(command) else { throw CocoaError(.featureUnsupported) }
                commandCount += 1
                let data = try await Task.detached {
                    let task = Process()
                    task.executableURL = URL(fileURLWithPath: engine)
                    task.arguments = [command, "--apply", "--home", watchHome]
                    task.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": watchHome, "LC_ALL": "C"]
                    return try SwitcherCommandRunner.execute(task, input: payload)
                }.value
                response = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
                return data
            }
            let began = ContinuousClock.now
            let bindingBefore = currentSignature()
            let submitted = bindingBefore == signature
            let accepted: Bool
            if submitted {
                if kind == .dns { accepted = await store.recordDNSLeak(value, runID: UUID()) }
                else { accepted = await store.recordWebRTCRisk(value, runID: UUID()) }
            } else {
                accepted = false
                receiptCode = bindingBefore == nil ? "context_unavailable" : "context_changed"
            }
            let bindingAfter = currentSignature()
            let elapsed = began.duration(to: .now).components
            let metadata = kind == .dns ? store.initializationDNSReceipt : store.initializationWebRTCReceipt
            let rawReceipt = response["receipt"] as? [String: Any] ?? [:]
            let rawVerdict = rawReceipt[kind == .dns ? "comparison" : "risk"] as? [String: Any] ?? [:]
            let backendState = rawVerdict["state"] as? String ?? "missing"
            let bound = accepted && metadata?.sampled == value.finishedAt && metadata?.context == rawReceipt["context_id"] as? String &&
                metadata?.state == backendState && metadata?.context != signature && metadata?.context.count == 64
            let passed = bound && bindingAfter == signature && backendState == "ok" && value.status == "complete" &&
                value.errors.isEmpty && !value.contextChanged
            allAccepted = allAccepted && bound; allPassed = allPassed && passed
            outcomes.append(["kind": kind.rawValue, "status": submitted ? (accepted ? "accepted" : "rejected") : "not_submitted",
                "accepted": accepted, "metadata_matches": bound, "passed": passed,
                "binding_before_matches": submitted, "binding_after_matches": bindingAfter == signature,
                "probe_status": ["complete", "partial", "error", "timeout"].contains(value.status) ? value.status : "other",
                "probe_error_count": value.errors.count, "context_changed": value.contextChanged,
                "sampled_at": value.finishedAt, "sample_age_seconds": Date().timeIntervalSince1970 - value.finishedAt,
                "backend_state": ["ok", "fail", "unknown"].contains(backendState) ? backendState : "missing",
                "receipt_code": receiptCode,
                "duration_seconds": Double(elapsed.seconds) + Double(elapsed.attoseconds) / 1e18])
        }
        let report: [String: Any] = ["schema": 1, "mode": "observed_probes", "engine": engine,
            "home_scope": "production Watch diagnostic receipts only", "engine_commands": commandCount,
            "network_observations": "caller-supplied original production worker probes; content and timestamps preserved",
            "all_accepted": allAccepted, "all_passed": allPassed, "results": outcomes]
        try JSONSerialization.data(withJSONObject: report, options: [.prettyPrinted, .sortedKeys])
            .write(to: contextURL.deletingLastPathComponent().appendingPathComponent("leak-receipt-observed.json"))
        print("LeakReceiptRoundTripTests: observed probes; accepted=\(allAccepted), passed=\(allPassed); original sample timestamps preserved")
        exit(allPassed ? 0 : 1)
    }
}
