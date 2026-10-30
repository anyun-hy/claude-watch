import Foundation

private final class RecordedPhases: @unchecked Sendable {
    private let lock = NSLock()
    private var values: [SetupProgressPhase] = []
    func append(_ value: SetupProgressPhase) { lock.lock(); values.append(value); lock.unlock() }
    var snapshot: [SetupProgressPhase] { lock.lock(); defer { lock.unlock() }; return values }
}

@MainActor
private final class ScriptedInitializationChecks: InitializationChecking {
    var calls: [InitializationStep] = []
    var overrides: [InitializationStep: InitializationResult] = [:]
    var validation = InitializationResult.passed("current", validUntil: Date().timeIntervalSince1970 + 120)
    var evidenceFailures: [InitializationStep: InitializationResult] = [:]
    var approvalResult = InitializationResult.passed("authorized")
    var begins = 0, approvals = 0, finishes = 0
    var automaticRefreshes = 0
    var automaticRefreshDelay: UInt64 = 0
    var delayStep: InitializationStep?
    var previousProgress: SetupProgressObserver?
    func begin() { begins += 1 }
    func check(_ step: InitializationStep) async -> InitializationResult {
        calls.append(step)
        if delayStep == step { try? await Task.sleep(nanoseconds: 100_000_000) }
        return overrides[step] ?? .passed("checked", validUntil: step == .verification ? Date().timeIntervalSince1970 + 120 : nil)
    }
    func approve(_ request: InitializationApproval, progress: @escaping SetupProgressObserver) async -> InitializationResult {
        approvals += 1; previousProgress = progress; progress(.verifyEgress); return approvalResult
    }
    func validateCurrentEvidence() -> InitializationResult { validation }
    func currentEvidenceFailures() -> [InitializationStep: InitializationResult] { evidenceFailures }
    func refreshWaitingEvidence() async -> InitializationRefreshOutcome {
        automaticRefreshes += 1
        if automaticRefreshDelay > 0 { try? await Task.sleep(nanoseconds: automaticRefreshDelay) }
        return .passed(validUntil: Date().timeIntervalSince1970 + 120)
    }
    func finish() { finishes += 1 }
}

@main
struct InitializationTests {
    @MainActor
    static func main() async throws {
        var assertions = 0
        func expect(_ condition: Bool, _ message: String) {
            assertions += 1
            guard condition else { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }
        func passed(_ result: InitializationResult) -> Bool {
            if case .passed = result { return true }; return false
        }
        expect(AppDelegate.notificationPage("events") == .events &&
               AppDelegate.notificationPage("environment") == .environment &&
               AppDelegate.notificationPage("protection") == .protection,
               "notification destinations resolve to the corresponding Watch pages")
        expect(AppDelegate.notificationPage("unexpected") == nil && AppDelegate.notificationPage(nil) == nil,
               "unknown notification destinations cannot navigate")
        for (kind, timestamp, verdict) in [(LeakKind.dns, "finished_at", "comparison"), (.webrtc, "sampled_at", "risk")] {
            let valid: [String: Any] = ["status": "ok", "receipt": ["context_id": "context", timestamp: 123.5, verdict: ["state": "ok"]]]
            expect(SwitcherStore.initializationReceiptMetadata(valid, kind: kind, sampledAt: 123.5)?.context == "context",
                   "real backend response binds its context and verdict to the exact probe time")
            expect(SwitcherStore.initializationReceiptMetadata(valid, kind: kind, sampledAt: 124) == nil,
                   "backend response for a different probe cannot be accepted")
            expect(SwitcherStore.initializationReceiptMetadata(["status": "ok", "receipt": [:]], kind: kind, sampledAt: 123.5) == nil,
                   "a missing backend context or verdict cannot be accepted")
        }
        if case .failed(let code, let detail) = FirstRunChecks.networkContextFailure(bound: "A", current: nil, timeoutStage: "dns_images") {
            expect(code == "context_unavailable" && detail.contains("超时") && !detail.contains("已变化"),
                   "a sampling gap does not hide the DNS timeout or claim a confirmed change")
        } else { expect(false, "missing context blocks initialization") }
        if case .failed(let code, _) = FirstRunChecks.networkContextFailure(bound: "A", current: "B", timeoutStage: nil) {
            expect(code == "context_changed", "a confirmed different context remains blocked")
        } else { expect(false, "changed context blocks initialization") }
        let parserEvents = RecordedPhases()
        let parser = SetupProgressReader { phase, _ in parserEvents.append(phase) }
        parser.consume(Data("CW_SETUP_PRO".utf8))
        parser.consume(Data("GRESS:verify_egress\nCW_SETUP_PROGRESS:unknown-private-token\n".utf8))
        parser.consume(Data((String(repeating: "x", count: 500) + "\nCW_SETUP_PROGRESS:request_administrator\n").utf8))
        expect(parserEvents.snapshot == [.verifyEgress, .requestAdministrator], "only complete allowlisted progress frames reach the UI")
        parser.finish()
        parser.consume(Data("CW_SETUP_PROGRESS:apply_settings\n".utf8))
        expect(parserEvents.snapshot.count == 2, "finished operations reject late progress")
        let pipeEvents = RecordedPhases()
        let pipe = SetupProgressReader { phase, _ in pipeEvents.append(phase) }
        let child = Process(); child.executableURL = URL(fileURLWithPath: "/bin/sh")
        child.arguments = ["-c", "printf 'CW_SETUP_PROGRESS:verify_egress\\n' >&2; /bin/sleep 0.2; printf 'CW_SETUP_PROGRESS:request_administrator\\n' >&2; /bin/sleep 0.2; printf '{\"status\":\"ok\"}'"]
        let childData = try await Task.detached { try SwitcherCommandRunner.execute(child, setupProgress: pipe) }.value
        let childResult = try JSONSerialization.jsonObject(with: childData) as? [String: String]
        expect(childResult?["status"] == "ok" && pipeEvents.snapshot == [.verifyEgress, .requestAdministrator], "real child stderr progress streams independently from the JSON result")
        let approval = InitializationApproval(id: "plan-1", action: .environment, title: "setup", detail: "review", changes: ["Watch only"])
        let fake = ScriptedInitializationChecks()
        fake.overrides[.environment] = .approval(approval)
        var writes = 0
        let coordinator = FirstRunInitialization(checks: fake, completed: false, saveCompletion: { writes += 1 })
        expect(!coordinator.entered && !coordinator.canEnter(at: Date().timeIntervalSince1970), "fresh install has no route into the main view")
        await coordinator.start()
        expect(fake.calls == [.components, .connection, .environment] && fake.begins == 1, "sequential checks stop before the first required authorization")
        expect(coordinator.approval == approval && writes == 0 && coordinator.passedCount == 2, "waiting for approval cannot create green state or completion")
        await coordinator.enter()
        expect(!coordinator.entered && writes == 0, "enter action itself cannot bypass a pending check")
        let staleApproval = InitializationApproval(id: "old-plan", action: .environment, title: "old", detail: "", changes: [])
        await coordinator.authorize(staleApproval)
        expect(fake.approvals == 0, "obsolete or unrelated approval is rejected")
        fake.approvalResult = .failed(code: "authorization_denied", detail: "denied")
        await coordinator.authorize(approval)
        expect(!coordinator.allPassed && !coordinator.entered && writes == 0 && coordinator.approval == nil, "denied authorization leaves the gate closed")
        let failedDetail = coordinator.rows[2].detail
        fake.previousProgress?(.requestAdministrator)
        expect(coordinator.rows[2].status == .failed && coordinator.rows[2].detail == failedDetail,
               "late progress cannot overwrite a completed failure or reopen the gate")
        fake.overrides = [:]
        await coordinator.retry()
        expect(coordinator.allPassed && !coordinator.entered && writes == 0, "all required checks must finish before entry becomes available")
        expect(Array(fake.calls.suffix(InitializationStep.allCases.count)) == InitializationStep.allCases, "retry rechecks dependencies instead of merging pre-change greens")
        expect(coordinator.canEnter(at: Date().timeIntervalSince1970), "all current checks enable the entry control")
        fake.validation = .failed(code: "context_changed", detail: "actual network changed")
        coordinator.refreshReadiness()
        expect(!coordinator.allPassed && !coordinator.canEnter(at: Date().timeIntervalSince1970), "network changes revoke ready state before entry")
        fake.validation = .passed("current", validUntil: Date().timeIntervalSince1970 + 120)
        await coordinator.retry()
        fake.overrides[.verification] = .failed(code: "real_risk", detail: "DNS risk")
        await coordinator.enter()
        expect(!coordinator.entered && writes == 0 && fake.finishes == 0, "last-moment risk during entry cannot save completion or open main view")
        fake.overrides = [:]
        await coordinator.retry()
        await coordinator.enter()
        expect(coordinator.entered && writes == 1 && fake.finishes == 1, "completion is saved only after final recheck")
        await coordinator.enter()
        expect(writes == 1, "repeated entry cannot repeat completion side effects")
        let reopenedChecks = ScriptedInitializationChecks()
        let reopened = FirstRunInitialization(checks: reopenedChecks, completed: true, saveCompletion: { writes += 100 })
        await reopened.start()
        expect(reopened.entered && reopenedChecks.begins == 0 && reopenedChecks.calls.isEmpty, "reopen or reboot restores normal operation after one completed initialization")
        let stagedChecks = ScriptedInitializationChecks()
        let protectionApproval = InitializationApproval(id: "protection-plan", action: .protection, title: "guard", detail: "review", changes: [])
        stagedChecks.overrides[.environment] = .approval(approval)
        stagedChecks.overrides[.protection] = .approval(protectionApproval)
        let staged = FirstRunInitialization(checks: stagedChecks, completed: false, saveCompletion: {})
        await staged.start(); await staged.authorize(approval)
        expect(staged.approval == protectionApproval && stagedChecks.calls.suffix(3) == [.dns, .webrtc, .protection],
               "new protection requires a separate confirmation after DNS and WebRTC have passed")
        expect(!staged.allPassed && !staged.entered && !stagedChecks.calls.contains(.verification), "pending guard approval cannot reach the final gate")
        let beforeGuardPoll = stagedChecks.calls.count
        await staged.pollAccessibility(at: Date().addingTimeInterval(600))
        expect(stagedChecks.calls.count == beforeGuardPoll, "other authorization stages never poll accessibility")
        staged.refreshReadiness(at: Date().addingTimeInterval(600))
        expect(staged.approval == protectionApproval && stagedChecks.automaticRefreshes == 0,
               "waiting for authorization never starts automatic collection or bypasses confirmation")
        await staged.authorize(protectionApproval)
        expect(staged.allPassed && !staged.entered, "authorized guard step still requires final joint verification")

        let axApproval = InitializationApproval(id: "ax", action: .accessibility, title: "access", detail: "waiting", changes: [])
        let axChecks = ScriptedInitializationChecks()
        axChecks.overrides[.accessibility] = .approval(axApproval)
        axChecks.approvalResult = .approval(axApproval)
        let axCoordinator = FirstRunInitialization(checks: axChecks, completed: false, saveCompletion: {})
        await axCoordinator.start()
        let initialAXChecks = axChecks.calls.filter { $0 == .accessibility }.count
        await axCoordinator.pollAccessibility(at: Date().addingTimeInterval(100))
        expect(axChecks.calls.filter { $0 == .accessibility }.count == initialAXChecks, "no polling before user opens settings")
        await axCoordinator.authorize(axApproval)
        let tick = Date().addingTimeInterval(10)
        await axCoordinator.pollAccessibility(at: tick)
        expect(axChecks.calls.filter { $0 == .accessibility }.count == initialAXChecks + 1 && axChecks.approvals == 1, "waiting poll reads trust without reopening settings")
        await axCoordinator.pollAccessibility(at: tick.addingTimeInterval(1))
        expect(axChecks.calls.filter { $0 == .accessibility }.count == initialAXChecks + 1, "poll is rate limited")
        axChecks.overrides[.accessibility] = .passed("trusted")
        await axCoordinator.pollAccessibility(at: tick.addingTimeInterval(3))
        expect(axCoordinator.allPassed && axChecks.calls.filter { $0 == .dns }.count == 1, "real trust confirmation continues once")
        await axCoordinator.pollAccessibility(at: tick.addingTimeInterval(30))
        expect(axChecks.calls.filter { $0 == .dns }.count == 1 && axChecks.approvals == 1, "completed authorization never polls or continues twice")
        let axRetryChecks = ScriptedInitializationChecks()
        axRetryChecks.overrides[.accessibility] = .approval(axApproval)
        axRetryChecks.approvalResult = .approval(axApproval)
        let axRetry = FirstRunInitialization(checks: axRetryChecks, completed: false, saveCompletion: {})
        await axRetry.start(); await axRetry.authorize(axApproval); await axRetry.retry()
        let retryCount = axRetryChecks.calls.count
        await axRetry.pollAccessibility(at: Date().addingTimeInterval(100))
        expect(axRetryChecks.calls.count == retryCount, "retry requires a new explicit settings opening before polling")
        await axRetry.authorize(axApproval)
        axRetry.stopAccessibilityPolling()
        let stoppedCount = axRetryChecks.calls.count
        await axRetry.pollAccessibility(at: Date().addingTimeInterval(100))
        expect(axRetryChecks.calls.count == stoppedCount, "declining again stops background trust polling")
        await axRetry.authorize(axApproval)
        axRetryChecks.overrides[.accessibility] = .passed("trusted")
        axRetryChecks.delayStep = .accessibility
        let latePoll = Task { await axRetry.pollAccessibility(at: Date().addingTimeInterval(100)) }
        try? await Task.sleep(nanoseconds: 20_000_000)
        axRetry.stopAccessibilityPolling()
        await latePoll.value
        expect(axRetry.approval == axApproval && !axRetryChecks.calls.contains(.dns), "declining cancels a late trust result before continuation")

        let concurrentChecks = ScriptedInitializationChecks()
        concurrentChecks.automaticRefreshDelay = 100_000_000
        let concurrentInit = FirstRunInitialization(checks: concurrentChecks, completed: false, saveCompletion: {})
        await concurrentInit.start()
        concurrentInit.refreshReadiness(at: Date().addingTimeInterval(61))
        concurrentInit.refreshReadiness(at: Date().addingTimeInterval(61))
        await concurrentInit.enter()
        try await Task.sleep(nanoseconds: 20_000_000)
        expect(concurrentChecks.automaticRefreshes == 1 && concurrentInit.running && !concurrentInit.entered,
               "overlapping timer ticks and entry cannot start duplicate refreshes or bypass an in-flight round")
        for _ in 0..<100 where concurrentInit.running { try await Task.sleep(nanoseconds: 10_000_000) }
        expect(concurrentInit.allPassed && !concurrentInit.running, "one completed automatic refresh restores readiness")

        let changingChecks = ScriptedInitializationChecks()
        changingChecks.overrides[.protection] = .approval(protectionApproval)
        let changing = FirstRunInitialization(checks: changingChecks, completed: false, saveCompletion: {})
        await changing.start()
        changingChecks.evidenceFailures[.dns] = .failed(code: "dns_expired", detail: "DNS expired")
        changing.refreshReadiness()
        expect(changing.rows[4].status == .failed && changing.rows[4].code == "dns_expired" && changing.rows[5].status == .passed,
               "a revoked DNS receipt updates its own previously green row without mislabelling WebRTC")
        expect(changing.approval == nil && changing.rows[6].status == .pending,
               "invalidated prerequisite withdraws pending protection approval")
        await changing.authorize(protectionApproval)
        expect(changingChecks.approvals == 0 && !changing.canEnter(at: Date().timeIntervalSince1970),
               "a withdrawn approval cannot enable protection or enter")

        let persistenceChecks = ScriptedInitializationChecks()
        let unwritable = FirstRunInitialization(checks: persistenceChecks, completed: false, saveCompletion: { throw CocoaError(.fileWriteNoPermission) })
        await unwritable.start(); await unwritable.enter()
        expect(!unwritable.entered && persistenceChecks.finishes == 0, "completion storage failure keeps initialization visible")
        let cancelledChecks = ScriptedInitializationChecks()
        cancelledChecks.delayStep = .components
        let cancelled = FirstRunInitialization(checks: cancelledChecks, completed: false, saveCompletion: { writes += 100 })
        let cancelledRun = Task { await cancelled.start() }
        try await Task.sleep(nanoseconds: 10_000_000)
        cancelledRun.cancel(); await cancelledRun.value
        expect(!cancelled.allPassed && !cancelled.entered && cancelledChecks.calls == [.components], "a late result from a cancelled initialization cannot advance the gate")
        let expiredChecks = ScriptedInitializationChecks()
        expiredChecks.overrides[.verification] = .passed("old", validUntil: Date().timeIntervalSince1970 - 1)
        let expired = FirstRunInitialization(checks: expiredChecks, completed: false, saveCompletion: { writes += 100 })
        await expired.start()
        expect(!expired.canEnter(at: Date().timeIntervalSince1970), "expired results cannot enable entry")
        expired.refreshReadiness()
        expect(!expired.allPassed, "expired green indicators are revoked")
        for status in ["unknown", "timeout", "cached", "partial", "permission_denied"] {
            let checks = ScriptedInitializationChecks()
            checks.overrides[.dns] = .failed(code: status, detail: "sensitive 203.0.113.123 token=secret account@example.test")
            let value = FirstRunInitialization(checks: checks, completed: false, saveCompletion: { writes += 100 })
            await value.start(); await value.enter()
            expect(!value.entered && !value.allPassed, "\(status) cannot pass the gate")
            expect(!value.diagnosticReport.contains("203.0.113") && !value.diagnosticReport.contains("secret") && !value.diagnosticReport.contains("example.test"), "diagnostic reports exclude raw details and private values")
        }

        // Use the actual leak store and its asynchronous backend callbacks.
        // A passing fixture probe must still wait for successful persistence.
        let leaks = LeakCheckStore(isFixture: true)
        leaks.fixtureDelayNanoseconds = 1_000_000
        var context = "fixture-A"
        leaks.contextProvider = { context }; leaks.automaticContextProvider = { context }
        leaks.onDNSComplete = { _ in true }
        leaks.onWebRTCComplete = { _ in false }
        let dnsAccepted = await leaks.ensureInitializationReceipt(.dns, maximumWait: 1)
        expect(dnsAccepted && leaks.initializationReceiptIsCurrent(.dns), "DNS page and onboarding use the actual same recorded result")
        let unrecordedRTC = await leaks.ensureInitializationReceipt(.webrtc, maximumWait: 1)
        expect(!unrecordedRTC && leaks.rtc.verdict.state == .matched, "a locally green WebRTC probe cannot pass without an accepted backend receipt")
        leaks.onWebRTCComplete = { _ in true }
        let recordedRTC = await leaks.ensureInitializationReceipt(.webrtc, maximumWait: 1)
        expect(recordedRTC && leaks.initializationReceiptIsCurrent(.webrtc), "accepted WebRTC receipt completes its mandatory check")
        let dnsSampleTime = leaks.dns.result!.finishedAt
        leaks.adoptInitializationReceipts()
        leaks.refreshWebRTCIfNeeded()
        expect(!leaks.rtc.running && leaks.dns.result!.finishedAt == dnsSampleTime, "handoff reuses checked data without immediately starting duplicate probes or renewing timestamps")
        context = "fixture-B"
        expect(!leaks.initializationReceiptIsCurrent(.dns) && !leaks.initializationReceiptIsCurrent(.webrtc), "changed proxy context invalidates both receipts")
        context = "fixture-A"
        expect(!leaks.initializationReceiptIsCurrent(.dns, at: Date(timeIntervalSince1970: dnsSampleTime + 301)), "cache use never extends evidence lifetime")
        expect(leaks.initializationReceiptProblem(.dns, at: Date(timeIntervalSince1970: dnsSampleTime + 301))?.code == "dns_expired",
               "expired evidence identifies the specific failing prerequisite")
        leaks.fixtureScenario = .difference
        let realRisk = await leaks.ensureInitializationReceipt(.dns, maximumWait: 1)
        // Force a new round rather than reusing the recent passing receipt.
        leaks.start(.dns)
        try await Task.sleep(nanoseconds: 200_000_000)
        expect(realRisk && leaks.dns.verdict.state == .difference && !leaks.initializationReceiptIsCurrent(.dns), "new explicit DNS difference revokes the previous passing result")

        let shared = MonitorStore(leakChecks: leaks, aiChecks: AIProbeStore(isFixture: true), switcher: SwitcherStore(isFixture: true))
        var access = false, prompts = 0, components = 0
        let liveAdapter = FirstRunChecks(store: shared, componentCheck: { components += 1 },
            accessibilityTrusted: { access }, requestAccessibility: { prompts += 1 })
        let componentResult = await liveAdapter.check(.components)
        expect(passed(componentResult) && components == 1 && liveAdapter.store === shared && liveAdapter.store.leakChecks === leaks,
               "live adapter shares the exact main-view stores and supports isolated component checks")
        let accessResult = await liveAdapter.check(.accessibility)
        if case .approval(let request) = accessResult {
            let pending = await liveAdapter.approve(request)
            expect(!passed(pending) && prompts == 1, "opening system settings alone never grants permission")
        } else { expect(false, "missing AX access must request explicit authorization") }
        access = true
        let granted = await liveAdapter.check(.accessibility)
        expect(passed(granted), "actual trusted state advances authorization step")
        for step in [InitializationStep.protection, .verification] {
            let uninitialized = await liveAdapter.check(step)
            expect(!passed(uninitialized), "\(step.rawValue) cannot run ahead of required initialization evidence")
        }
        let unreviewed = await liveAdapter.approve(protectionApproval)
        expect(!passed(unreviewed) && shared.switcher.settings["guard_enabled"] as? Bool != true,
               "an unreviewed protection request cannot enable a service")
        expect(FirstRunChecks.allowed([.init(id: "watchdog", title: "Watch timezone", scope: "administrator")]), "Watch-owned timezone action is supported")
        for id in ["rules", "reload_proxy", "enable_tun", "start_proxy", "legacy_stop", "original"] {
            expect(!FirstRunChecks.allowed([.init(id: id, title: id, scope: "proxy")]), "\(id) cannot enter the setup apply path")
        }
        func backendEvidence(at time: Double, sampling: Bool, native: Bool?) -> BackgroundServiceReceipt {
            .init(observed_at: time, backend_healthy: sampling, update_source_ready: false,
                  guard_backend_healthy: native, backend_sampling_state: sampling ? "complete" : "incomplete",
                  services: [.init(id: "guard", title: "Watch", state: "inactive", detail: "", source: "fixture", desired: false, last_checked: time)],
                  policy_issues: [], facts: .init(state: "ok", risks: []))
        }
        expect(FirstRunChecks.backendEvidenceIsCurrent(backendEvidence(at: 100, sampling: false, native: true), now: 101),
               "partial monitoring cannot veto verified native daemon identity and heartbeat")
        for native in [false, nil] as [Bool?] {
            expect(!FirstRunChecks.backendEvidenceIsCurrent(backendEvidence(at: 100, sampling: true, native: native), now: 101),
                   "complete sampling cannot substitute for missing or false native liveness")
        }
        for time in [69.0, 101.0, .nan, .infinity] {
            expect(!FirstRunChecks.backendEvidenceIsCurrent(backendEvidence(at: time, sampling: true, native: true), now: 100),
                   "stale, future or invalid service evidence cannot pass initialization")
        }
        expect(!FirstRunChecks.backendEvidenceIsCurrent(backendEvidence(at: 100, sampling: true, native: true), error: "read failed", now: 101),
               "failed status refresh cannot reuse an older green liveness result")
        expect(!FirstRunChecks.backendEvidenceIsCurrent(nil, now: 101), "missing service evidence cannot pass initialization")
        let published = MonitorStore(leakChecks: LeakCheckStore(isFixture: true), aiChecks: AIProbeStore(isFixture: true), switcher: SwitcherStore(isFixture: true))
        published.beginInitialization(startSnapshotPolling: false)
        published.switcher.loadReviewScenario(.normal)
        func snapshot(node: String, at time: Double) -> MonitorSnapshot {
            let proxy = ProxySnapshot(observedAt: time, entryState: "verified", entryReason: "fixture", entrySource: "fixture",
                endpoint: "127.0.0.1:7890", listenerPID: 99, listenerPath: "/fixture/tag", apiState: "available", apiReason: "",
                mode: "global", coversProxy: true, expectedGroup: "GLOBAL", expectedNode: node, selectedNode: node,
                globalNode: node, pinned: true, selectionChanged: false, flows: [])
            return MonitorSnapshot(capturedAt: time, health: .init(state: "running", mode: "IDLE", pid: 7, heartbeatAge: 0,
                started: "fixture-start", detail: "fixture", alerts: "on"), installed: true, autoStart: true, keepAlive: true,
                hasBaseline: false, stderrBytes: 0, processes: [], events: [], proxy: proxy, proxyError: nil,
                logPath: "/fixture/log", backendVersion: "fixture", monitoredApps: ["claude"])
        }
        // A clean installation has no UI snapshot to seed the first check.
        // Replay publication latency (4s) and the observed 14s proxy cadence:
        // first sample at t=5, next at t=19. Timer rereads keep returning the
        // first source timestamp; they must not count as new observations.
        let cold = MonitorStore(leakChecks: LeakCheckStore(isFixture: true), aiChecks: AIProbeStore(isFixture: true), switcher: SwitcherStore(isFixture: true))
        cold.beginInitialization(startSnapshotPolling: false)
        cold.switcher.loadReviewScenario(.normal)
        let coldEnvironment = cold.switcher.currentEnvironment!
        let epoch = Date().timeIntervalSince1970
        var coldTime = epoch
        var publications: [(at: Double, sampled: Double, node: String)] = [(5, 1, "A"), (19, 15, "A")]
        var nativeAvailable = true
        func publishColdRound() {
            let elapsed = coldTime - epoch
            cold.switcher.loadReviewReceipts(coldEnvironment, background: backendEvidence(at: coldTime, sampling: true, native: nativeAvailable && elapsed >= 5))
            guard let publication = publications.last(where: { $0.at <= elapsed }) else { cold.snapshot = nil; return }
            let sample = snapshot(node: publication.node, at: epoch + publication.sampled)
            let reread = MonitorSnapshot(capturedAt: coldTime, health: sample.health,
                installed: true, autoStart: true, keepAlive: true, hasBaseline: false,
                stderrBytes: 0, processes: [], events: [], proxy: sample.proxy, proxyError: nil,
                logPath: "/fixture/log", backendVersion: "fixture", monitoredApps: ["claude"])
            cold.acceptSnapshot(reread, receivedAt: Date(timeIntervalSince1970: coldTime))
        }
        publishColdRound()
        expect(cold.snapshot == nil, "clean startup has no cached snapshot or proxy evidence")
        let coldChecks = FirstRunChecks(store: cold, componentCheck: {}, connectionNow: { coldTime },
            waitForConnectionPoll: { coldTime += 1; publishColdRound() })
        let coldResult = await coldChecks.check(.connection)
        if !passed(coldResult) {
            let retryResult = await coldChecks.check(.connection)
            print("Cold-start regression: first=\(coldResult), immediate retry=\(retryResult)")
        }
        expect(passed(coldResult), "clean startup must wait for the second actual proxy publication without requiring Retry")
        expect(coldTime >= epoch + 19 && coldTime < epoch + 30,
               "repeated reads of the first snapshot never count as two samples")
        func replay(_ values: [(Double, Double, String)], native: Bool = true) async -> InitializationResult {
            coldTime = epoch; publications = values; nativeAvailable = native
            cold.snapshot = nil; publishColdRound()
            return await coldChecks.check(.connection)
        }
        func failureCode(_ result: InitializationResult) -> String? {
            if case .failed(let code, _) = result { return code }; return nil
        }
        let delayedStartup = await replay([(29, 25, "A"), (43, 39, "A")])
        expect(passed(delayedStartup) && coldTime == epoch + 43,
               "startup and confirmation have separate bounds; a late first sample does not consume the next round's window")
        let frozenSource = await replay([(5, 1, "A")])
        expect(failureCode(frozenSource) == "proxy_next_sample_timeout" && coldTime == epoch + 31,
               "a stalled producer fails at the first source's expiry even as snapshot and service read times advance")
        let missingSource = await replay([])
        expect(failureCode(missingSource) == "snapshot_unavailable" && coldTime == epoch + 30,
               "absence of a first snapshot has a bounded, specific failure")
        let missingBackend = await replay([(5, 1, "A"), (19, 15, "A")], native: false)
        expect(failureCode(missingBackend) == "backend_unverified",
               "two proxy samples cannot substitute for an unverified native backend")
        let changedSource = await replay([(5, 1, "A"), (19, 15, "B")])
        expect(!passed(changedSource) && coldTime == epoch + 31,
               "different proxy contexts cannot combine into a pass or renew the confirmation deadline")
        for invalidTime in [-100.0, 100.0] {
            let invalidSource = await replay([(5, invalidTime, "A")])
            expect(failureCode(invalidSource) == "proxy_sample_stale",
                   "stale and future proxy source times remain blocking during cold startup")
        }
        expect(cold.switcher.settings["guard_enabled"] as? Bool != true && !cold.leakChecks.dns.running && !cold.leakChecks.rtc.running,
               "cold-start readiness never enables protection or starts independent network probes")
        let firstSnapshot = snapshot(node: "A", at: Date().timeIntervalSince1970)
        published.acceptSnapshot(firstSnapshot, receivedAt: Date())
        expect(published.initializationContext != nil && published.initializing && !published.leakChecks.dns.running && !published.leakChecks.rtc.running,
               "first-run snapshot polling updates shared context without starting independent diagnostic jobs")
        let recovery = MonitorStore(leakChecks: LeakCheckStore(isFixture: true), aiChecks: AIProbeStore(isFixture: true), switcher: SwitcherStore(isFixture: true))
        recovery.beginInitialization(startSnapshotPolling: false)
        recovery.automatic = false
        recovery.leakChecks.fixtureDelayNanoseconds = 1_000_000
        recovery.leakChecks.onDNSComplete = { _ in true }
        let base = Date()
        recovery.acceptSnapshot(snapshot(node: "A", at: base.timeIntervalSince1970 - 9), receivedAt: base)
        let acceptedBeforeGap = await recovery.leakChecks.ensureInitializationReceipt(.dns, maximumWait: 1)
        expect(acceptedBeforeGap, "fresh receipt starts in the verified proxy context")
        let afterGap = base.addingTimeInterval(2)
        recovery.monitorTick(at: afterGap)
        expect(recovery.initializationContext != nil && recovery.leakChecks.dns.verdict.state == .matched &&
               recovery.leakChecks.initializationReceiptIsCurrent(.dns),
               "a directly verified current proxy remains usable after the separate ten-second gap grace")
        let noProxy = MonitorSnapshot(capturedAt: afterGap.timeIntervalSince1970, health: firstSnapshot.health,
            installed: true, autoStart: true, keepAlive: true, hasBaseline: false,
            stderrBytes: 0, processes: [], events: [], proxy: nil, proxyError: nil,
            logPath: "/fixture/log", backendVersion: "fixture", monitoredApps: ["claude"])
        recovery.acceptSnapshot(noProxy, receivedAt: afterGap)
        expect(recovery.leakChecks.dns.verdict.state == .incomplete && !recovery.leakChecks.initializationReceiptIsCurrent(.dns),
               "a genuinely unavailable proxy beyond the grace window cannot keep a green verdict")
        recovery.acceptSnapshot(snapshot(node: "A", at: afterGap.timeIntervalSince1970), receivedAt: afterGap)
        expect(recovery.leakChecks.dns.verdict.state == .matched && recovery.leakChecks.initializationReceiptIsCurrent(.dns),
               "same-context recovery re-evaluates the receipt against the newly published snapshot immediately")

        // Exercise the real coordinator, checks and shared stores end-to-end;
        // all external inputs, authorizations and writes stay in fixtures.
        let fullSwitcher = SwitcherStore(isFixture: true)
        fullSwitcher.fullInitializationFixture = true
        let fullLeaks = LeakCheckStore(isFixture: true)
        fullLeaks.fixtureDelayNanoseconds = 1_000_000
        let fullStore = MonitorStore(leakChecks: fullLeaks, aiChecks: AIProbeStore(isFixture: true), switcher: fullSwitcher)
        var fullNode = "A"
        fullStore.acceptSnapshot(snapshot(node: "A", at: Date().timeIntervalSince1970), receivedAt: Date())
        let fullChecks = FirstRunChecks(store: fullStore, componentCheck: {}, accessibilityTrusted: { true },
            requestAccessibility: {}, waitForConnectionPoll: {
                try? await Task.sleep(nanoseconds: 5_000_000)
                fullStore.acceptSnapshot(snapshot(node: fullNode, at: Date().timeIntervalSince1970), receivedAt: Date())
            }, startSnapshotPolling: false)
        var fullWrites = 0
        let full = FirstRunInitialization(checks: fullChecks, completed: false, saveCompletion: { fullWrites += 1 })
        await full.start()
        expect(full.approval?.action == .environment && full.passedCount == 2,
               "full flow stops at the real environment confirmation before any DNS or guard changes")
        if let request = full.approval { await full.authorize(request) }
        expect(full.approval?.action == .protection && full.passedCount == 6 &&
               fullLeaks.initializationReceiptIsCurrent(.dns) && fullLeaks.initializationReceiptIsCurrent(.webrtc),
               "full flow carries the actual two accepted fixture receipts into guard confirmation")
        let mismatchedApproval = full.approval!
        fullSwitcher.setInitializationReceiptForFixture(.webrtc, context: "different-backend-network", state: "ok")
        full.refreshReadiness()
        expect(full.rows[4].status == .passed && full.rows[5].code == "webrtc_backend_context_changed" && full.approval == nil,
               "backend network change revokes the affected receipt even when the visible proxy signature is unchanged")
        await full.authorize(mismatchedApproval)
        expect(fullSwitcher.settings["guard_enabled"] as? Bool != true, "a backend context mismatch cannot use the old approval")
        await full.retry()
        if full.approval?.action == .environment, let request = full.approval { await full.authorize(request) }
        expect(full.approval?.action == .protection, "new matching backend receipts permit a fresh guard confirmation")
        fullSwitcher.setInitializationReadbackForFixture(.dns, sampled: 1)
        full.refreshReadiness()
        expect(full.rows[4].code == "dns_backend_receipt_changed" && full.approval == nil,
               "a replaced persisted DNS receipt revokes the old green and guard confirmation")
        await full.retry()
        if full.approval?.action == .environment, let request = full.approval { await full.authorize(request) }
        expect(full.approval?.action == .protection, "retry obtains a new persisted receipt after the backend readback changes")
        let oldGuardApproval = full.approval!
        fullNode = "B"
        fullStore.acceptSnapshot(snapshot(node: fullNode, at: Date().timeIntervalSince1970), receivedAt: Date())
        full.refreshReadiness()
        expect(full.approval == nil && full.rows[1].status == .failed && full.rows[4].status == .failed &&
               full.rows[5].status == .failed && full.rows[6].status == .pending,
               "changing the real shared context revokes both receipt greens and the pending guard approval")
        await full.authorize(oldGuardApproval)
        expect(fullSwitcher.settings["guard_enabled"] as? Bool != true, "old approval cannot enable guard after a context change")
        await full.retry()
        expect(full.approval?.action == .environment, "new context requires a new environment confirmation")
        if let request = full.approval { await full.authorize(request) }
        expect(full.approval?.action == .protection && fullLeaks.initializationReceiptIsCurrent(.dns) &&
               fullLeaks.initializationReceiptIsCurrent(.webrtc),
               "retry obtains new-context receipts before presenting a new guard confirmation")
        if let request = full.approval { await full.authorize(request) }
        expect(full.allPassed && !full.entered && fullStore.switcher.settings["guard_enabled"] as? Bool == true,
               "confirmed fixture guard still runs the real final verification before entry")
        // Advance six scheduled intervals without waiting six real minutes;
        // the real shared stores and fixture collectors produce new receipts.
        for _ in 0..<6 {
            let oldDNS = fullLeaks.dns.result!.finishedAt, oldRTC = fullLeaks.rtc.result!.finishedAt
            full.refreshReadiness(at: Date().addingTimeInterval(61))
            expect(full.running && !full.canEnter(at: Date().timeIntervalSince1970), "automatic refresh cannot grant entry while evidence is in flight")
            for _ in 0..<300 where full.running { try await Task.sleep(nanoseconds: 10_000_000) }
            expect(!full.running && full.allPassed && fullLeaks.dns.result!.finishedAt > oldDNS && fullLeaks.rtc.result!.finishedAt > oldRTC,
                   "each scheduled cycle refreshes DNS and WebRTC before restoring ready state")
            let readback = fullSwitcher.currentEnvironment?.initialization_receipts
            expect(readback?.dns?.sampled_at == fullLeaks.dns.result?.finishedAt && readback?.webrtc?.sampled_at == fullLeaks.rtc.result?.finishedAt,
                   "the environment page uses the exact newly submitted receipts")
        }
        fullLeaks.fixtureScenario = .timeout
        full.refreshReadiness(at: Date().addingTimeInterval(61))
        for _ in 0..<300 where full.running { try await Task.sleep(nanoseconds: 10_000_000) }
        expect(full.rows[4].status == .failed && !full.canEnter(at: Date().timeIntervalSince1970),
               "an automatic DNS failure is visible and cannot reuse the previous green")
        fullLeaks.fixtureScenario = .matched
        full.refreshReadiness(at: Date().addingTimeInterval(31))
        for _ in 0..<300 where full.running { try await Task.sleep(nanoseconds: 10_000_000) }
        expect(full.allPassed && full.canEnter(at: Date().timeIntervalSince1970),
               "automatic retry restores readiness only after new checks and joint verification")
        let gapAt = Date().timeIntervalSince1970
        let gap = MonitorSnapshot(capturedAt: gapAt, health: firstSnapshot.health,
            installed: true, autoStart: true, keepAlive: true, hasBaseline: false,
            stderrBytes: 0, processes: [], events: [], proxy: nil, proxyError: nil,
            logPath: "/fixture/log", backendVersion: "fixture", monitoredApps: ["claude"])
        fullStore.acceptSnapshot(gap, receivedAt: Date())
        full.refreshReadiness()
        expect(full.rows[1].code == "context_unavailable" && full.rows[2].status == .pending && !full.allPassed,
               "a temporary proxy sampling gap revokes dependent green states")
        fullStore.acceptSnapshot(snapshot(node: fullNode, at: Date().timeIntervalSince1970), receivedAt: Date())
        full.refreshReadiness(at: Date().addingTimeInterval(31))
        for _ in 0..<300 where full.running { try await Task.sleep(nanoseconds: 10_000_000) }
        expect(full.allPassed && full.canEnter(at: Date().timeIntervalSince1970),
               "the same recovered context automatically rechecks both receipts and environment")
        await full.enter()
        expect(full.entered && fullWrites == 1 && !fullStore.initializing,
               "full flow revalidates, saves once and hands the same stores to the main view")
        let partialBackend = backendEvidence(at: Date().timeIntervalSince1970, sampling: false, native: true)
        published.switcher.loadReviewReceipts(published.switcher.currentEnvironment!, background: partialBackend)
        let connectionChecks = FirstRunChecks(store: published, componentCheck: {}, accessibilityTrusted: { true }, requestAccessibility: {})
        let connectionRead = Task { await connectionChecks.check(.connection) }
        try await Task.sleep(nanoseconds: 50_000_000)
        published.acceptSnapshot(snapshot(node: "A", at: Date().timeIntervalSince1970), receivedAt: Date())
        let connectionResult = await connectionRead.value
        expect(passed(connectionResult) && published.switcher.background?.backend_healthy == false,
               "actual step 2 uses native liveness during the installed-315 partial-sampling case")
        expect(published.switcher.settings["guard_enabled"] as? Bool != true && !published.leakChecks.dns.running,
               "passing local readiness never enables protection or starts a network probe")
        published.switcher.fixtureEnvironmentReadDelayNanoseconds = 100_000_000
        let oldRead = Task { await published.switcher.detectCurrentEnvironment() }
        try await Task.sleep(nanoseconds: 10_000_000)
        let changedSnapshot = snapshot(node: "B", at: Date().timeIntervalSince1970)
        published.acceptSnapshot(changedSnapshot, receivedAt: Date())
        let acceptedOldRead = await oldRead.value
        expect(!acceptedOldRead && published.switcher.currentEnvironmentIsHistorical && published.switcher.currentPolicyEvaluation == nil,
               "network change during initialization rejects a late environment result and its green policy preview")
        let retainedTime = published.snapshot!.capturedAt
        published.finishInitialization()
        expect(!published.initializing && published.snapshot!.capturedAt == retainedTime,
               "handoff preserves the shared snapshot rather than resetting or renewing its sample time")

        var data = try JSONSerialization.jsonObject(with: SwitcherStore.fixtureCurrentEnvironment()) as! [String: Any]
        let now = Date().timeIntervalSince1970
        var rows = data["rows"] as! [[String: Any]]
        let mandatory: Set<String> = ["proxy", "tun", "egress", "timezone", "locale", "dns", "stun", "guard", "reachability", "ipv6", "language"]
        for i in rows.indices { rows[i]["state"] = "ok"; rows[i]["required"] = mandatory.contains(rows[i]["id"] as! String) }
        data["rows"] = rows; data["observed_at"] = now; data["expires_at"] = now + 120
        data["context_transition"] = ["state": "stable"]
        data["facts"] = ["state": "ok", "risks": []]
        var policy = data["policy_evaluation"] as! [String: Any]
        policy["rows"] = rows; policy["observed_at"] = now; policy["expires_at"] = now + 120
        policy["ready"] = true; policy["blocked"] = []; policy["policy"] = "fixture-policy"
        policy["facts"] = ["state": "ok", "risks": []]
        data["policy_evaluation"] = policy
        func evaluate(_ value: [String: Any], historical: Bool = false, clock: Double? = nil) throws -> InitializationResult {
            let environment = try JSONDecoder().decode(CurrentEnvironmentReceipt.self, from: JSONSerialization.data(withJSONObject: value))
            return InitializationEnvironmentGate.evaluate(environment, policy: environment.policy_evaluation,
                settings: ["require_ipv6_off": true, "require_english": true], historical: historical,
                unsavedSettings: false, now: clock ?? now)
        }
        expect(try passed(evaluate(data)), "all complete same-observation required rows pass the environment gate")
        for state in ["fail", "unknown", "warn", "info", "cached"] {
            var value = data, changedPolicy = policy, changedRows = rows
            changedRows[0]["state"] = state
            changedPolicy["rows"] = changedRows; value["policy_evaluation"] = changedPolicy
            expect(try !passed(evaluate(value)), "required \(state) cannot masquerade as a green row")
        }
        var truncated = data, truncatedPolicy = policy
        truncatedPolicy["rows"] = Array(rows.dropLast()); truncated["policy_evaluation"] = truncatedPolicy
        expect(try !passed(evaluate(truncated)), "missing required evidence cannot vacuously pass")
        var mismatched = data, mismatchedPolicy = policy
        mismatchedPolicy["observation_id"] = "other-round"; mismatched["policy_evaluation"] = mismatchedPolicy
        expect(try !passed(evaluate(mismatched)), "policy and environment from different rounds cannot combine")
        expect(try !passed(evaluate(data, historical: true)) && !passed(evaluate(data, clock: now + 121)), "historical and expired environment results cannot pass")
        var beforeGuard = data, beforeGuardPolicy = policy, beforeGuardRows = rows
        let guardIndex = beforeGuardRows.firstIndex { $0["id"] as? String == "guard" }!
        beforeGuardRows[guardIndex]["state"] = "fail"
        beforeGuardPolicy["rows"] = beforeGuardRows; beforeGuardPolicy["ready"] = false; beforeGuardPolicy["blocked"] = ["guard"]
        beforeGuard["policy_evaluation"] = beforeGuardPolicy
        let preEnvironment = try JSONDecoder().decode(CurrentEnvironmentReceipt.self, from: JSONSerialization.data(withJSONObject: beforeGuard))
        let precheck = InitializationEnvironmentGate.evaluate(preEnvironment, policy: preEnvironment.policy_evaluation,
            settings: ["require_ipv6_off": true, "require_english": true], historical: false, unsavedSettings: false,
            now: now, checkingBeforeGuardEnable: true)
        let stillRequiresGuard = try evaluate(beforeGuard)
        expect(passed(precheck) && !passed(stillRequiresGuard), "pre-enable environment check cannot substitute for the final guard-required gate")
        beforeGuardRows[beforeGuardRows.firstIndex { $0["id"] as? String == "dns" }!]["state"] = "fail"
        beforeGuardPolicy["rows"] = beforeGuardRows; beforeGuardPolicy["blocked"] = ["guard", "dns"]
        beforeGuard["policy_evaluation"] = beforeGuardPolicy
        let unsafeEnvironment = try JSONDecoder().decode(CurrentEnvironmentReceipt.self, from: JSONSerialization.data(withJSONObject: beforeGuard))
        expect(!passed(InitializationEnvironmentGate.evaluate(unsafeEnvironment, policy: unsafeEnvironment.policy_evaluation,
            settings: ["require_ipv6_off": true, "require_english": true], historical: false, unsavedSettings: false,
            now: now, checkingBeforeGuardEnable: true)), "real DNS failure blocks even the pre-enable environment check")

        let temporary = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("cw-initialization-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: temporary, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: temporary) }
        let storage = InitializationStorage(directory: temporary)
        expect(!storage.isComplete(), "no marker means first run")
        try FileManager.default.createDirectory(at: temporary.appendingPathComponent("switcher"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        FileManager.default.createFile(atPath: temporary.appendingPathComponent("switcher/config.json").path, contents: Data("{}".utf8), attributes: [.posixPermissions: 0o600])
        try storage.complete(at: now)
        expect(storage.isComplete(at: now + 1), "private valid completion survives reopen")
        expect(!storage.isComplete(at: now - 1), "future-dated marker is rejected")
        let marker = temporary.appendingPathComponent("initialization.json")
        let bytes = try Data(contentsOf: marker)
        expect(!String(decoding: bytes, as: UTF8.self).contains("fixture-policy"), "completion marker stores no network or launch policy")
        let attributes = try FileManager.default.attributesOfItem(atPath: marker.path)
        expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600, "completion marker is private before handoff")
        try Data("{}".utf8).write(to: marker)
        expect(!storage.isComplete(), "corrupt completion record does not skip initialization")
        try FileManager.default.removeItem(at: marker)
        let target = temporary.appendingPathComponent("target")
        try bytes.write(to: target)
        try FileManager.default.createSymbolicLink(at: marker, withDestinationURL: target)
        expect(!storage.isComplete(), "symlink completion marker is rejected")
        do { try storage.complete(); expect(false, "symlink write must be refused") }
        catch { expect(try Data(contentsOf: target) == bytes, "refusing marker write preserves the symlink target") }
        print("InitializationTests: \(assertions) assertions passed; no network, system authorization, TAG, original guard or installed application actions")
    }
}
