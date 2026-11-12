import AppKit
import Foundation

/// The adapter has no separate detection cache: it owns the exact stores that
/// MonitorView receives when onboarding completes. Existing backend previews,
/// transactions, receipt writers and policy checks remain authoritative.
@MainActor
final class FirstRunChecks: InitializationChecking {
    let store: MonitorStore
    private var boundContext: String?
    private var acceptedSettings: Data?
    private var setupWasApproved = false
    private var approvedContext: String?
    private var requireBackendContextMatch = false
    private let componentCheck: () async throws -> Void
    private let accessibilityTrusted: () -> Bool
    private let requestAccessibility: () -> Void
    private let connectionNow: () -> Double
    private let waitForConnectionPoll: () async -> Void
    private let startSnapshotPolling: Bool
    private let connectionLog: InitializationConnectionLog

    init(store: MonitorStore,
         componentCheck: (() async throws -> Void)? = nil,
         accessibilityTrusted: (() -> Bool)? = nil,
         requestAccessibility: (() -> Void)? = nil,
         connectionNow: @escaping () -> Double = { Date().timeIntervalSince1970 },
         waitForConnectionPoll: @escaping () async -> Void = { try? await Task.sleep(nanoseconds: 1_000_000_000) },
         startSnapshotPolling: Bool = true,
         connectionLog: InitializationConnectionLog? = nil) {
        self.store = store
        self.connectionNow = connectionNow
        self.waitForConnectionPoll = waitForConnectionPoll
        self.startSnapshotPolling = startSnapshotPolling
        self.connectionLog = connectionLog ?? (store.switcher.isFixture
            ? InitializationConnectionLog(directory: nil) : InitializationConnectionLog())
        self.componentCheck = componentCheck ?? {
            let data = try await Task.detached { try SwitcherCommandRunner.run(["self-check"]) }.value
            let value = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            guard value?["status"] as? String == "ok", value?["component_integrity"] as? Bool == true,
                  value?["grants_launch_permission"] as? Bool == false else {
                throw CocoaError(.fileReadCorruptFile)
            }
        }
        self.accessibilityTrusted = accessibilityTrusted ?? { AccessibilityPermission.trusted }
        self.requestAccessibility = requestAccessibility ?? { store.switcher.requestAccessibilityConsent() }
    }
    func begin() { store.beginInitialization(startSnapshotPolling: startSnapshotPolling) }
    func check(_ step: InitializationStep) async -> InitializationResult {
        switch step {
        case .components:
            do { try await componentCheck(); return .passed("运行组件完整性及 Watch 数据读取已核对。") }
            catch { return .failed(code: "components_unavailable", detail: "运行组件或 Watch 数据读取未通过，请检查安装完整性与数据目录权限。") }
        case .connection:
            connectionLog.begin()
            var phase = "status_read"
            func finish(_ result: InitializationResult) -> InitializationResult {
                let event: String, code: String
                switch result {
                case .passed: event = "passed"; code = "passed"
                case .failed(let reason, _): event = reason == "cancelled" ? "cancelled" : "failed"; code = reason
                case .approval: event = "failed"; code = "unexpected_approval"
                }
                traceConnection(event: event, phase: phase, code: code)
                return result
            }
            traceConnection(event: "start", phase: phase, code: "started")
            boundContext = nil; acceptedSettings = nil; requireBackendContextMatch = false
            guard await store.switcher.refreshInitializationStatus() else {
                return finish(.failed(code: "status_unavailable", detail: "后台状态读取未完成，请重试。"))
            }
            traceConnection(event: "status", phase: phase, code: "status_read")
            guard !recoveryRequired else { return finish(recoveryFailure) }
            // A fresh install only waits for launchd's running state before
            // opening the UI. No proxy sample need exist yet. The producer
            // waits 10s AFTER collection before starting another network
            // round; a single 12s budget can expire before two samples arrive.
            let startupDeadline = connectionNow() + MonitorSnapshotTiming.proxyMaximumAge
            var confirmationDeadline: Double?
            var candidate: String?
            var candidateSample: Double?
            var lastFailure = InitializationResult.failed(code: "snapshot_unavailable", detail: "采集后台尚未发布首份可读取的快照。")
            // Once the first valid sample arrives, wait for a second source
            // observation only while that first sample is still current.
            // Rereads, gaps and context changes cannot renew this deadline.
            while !Task.isCancelled {
                phase = confirmationDeadline == nil ? "waiting_first_sample" : "waiting_next_sample"
                let deadline = confirmationDeadline ?? startupDeadline
                guard connectionNow() < deadline else { return finish(lastFailure) }
                traceConnection(event: "poll_begin", phase: phase, code: "reading_backend", deadline: deadline,
                                candidate: candidate, sampled: candidateSample)
                await store.switcher.refreshBackground(maximumAge: 5)
                let now = connectionNow()
                let failure = connectionEvidenceFailure(at: now)
                let observedCode: String
                if case .failed(let code, _)? = failure { observedCode = code } else { observedCode = "evidence_current" }
                traceConnection(event: "poll_end", phase: phase, code: observedCode, deadline: deadline,
                                candidate: candidate, sampled: candidateSample)
                guard now < deadline else { return finish(failure ?? lastFailure) }
                if let failure {
                    lastFailure = failure
                    candidate = nil; candidateSample = nil
                } else if let context = store.initializationContext, let sampled = store.snapshot?.proxy?.observedAt {
                    if candidate == context, let previous = candidateSample, sampled > previous {
                        boundContext = context
                        let detail = store.switcher.background?.backend_healthy == false
                            ? "原生采集后台身份、心跳及代理入口已确认。连接监控采样存在缺口，单独记录其完整性。"
                            : "原生采集后台身份、心跳及代理入口已确认；持续读取同一网络上下文。"
                        return finish(.passed(detail))
                    }
                    if candidate != context { candidate = context; candidateSample = sampled }
                    if confirmationDeadline == nil {
                        confirmationDeadline = sampled + MonitorSnapshotTiming.proxyMaximumAge
                    }
                    lastFailure = .failed(code: "proxy_next_sample_timeout", detail: "已取得首轮有效代理采样，但未在其有效期内收到同一代理的后续采样。")
                }
                await waitForConnectionPoll()
            }
            return finish(.failed(code: "cancelled", detail: "本轮检查已取消，请重新检查。"))
        case .environment:
            return await prepareEnvironment()
        case .accessibility:
            return accessResult
        case .dns, .webrtc:
            return await checkNetwork(step, forceNew: false)
        case .protection:
            guard contextMatches, acceptedSettings != nil, acceptedSettings == settingsData else { return changedFailure }
            // The leak checks may already have read back both receipts in a
            // fresh environment audit. Only acquire a new audit when needed.
            if !hasCurrentProtectionReadback, !(await store.switcher.detectCurrentEnvironment()) {
                return .failed(code: "environment_unstable", detail: "启用守护前的环境预检未完成，请重试。")
            }
            requireBackendContextMatch = true
            let precheck = preProtectionEvidence()
            if case .failed = precheck { return precheck }
            guard let id = store.switcher.currentEnvironment?.observation_id, !id.isEmpty else {
                return .failed(code: "environment_not_ready", detail: "环境回执缺少本轮观测编号。")
            }
            return await previewSetup(candidateID: "confirmed-protection:\(id)", enableProtection: true)
        case .verification:
            guard contextMatches else { return changedFailure }
            guard !recoveryRequired else { return recoveryFailure }
            guard acceptedSettings == settingsData else { return changedFailure }
            // Watch's newly enabled guard needs time to publish its first real
            // heartbeat. Bound this wait; never manufacture readiness from intent.
            let deadline = Date().addingTimeInterval(20)
            repeat {
                await store.switcher.refreshBackground(maximumAge: 5)
                if backgroundIsCurrent { break }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            } while Date() < deadline && !Task.isCancelled
            guard backgroundIsCurrent else { return backgroundFailure }
            if !hasCurrentProtectionReadback, !(await store.switcher.detectCurrentEnvironment()) {
                return .failed(code: "environment_unstable", detail: "最终环境检测未完成或上下文不稳定，请重新检查。")
            }
            requireBackendContextMatch = true
            // Re-read configuration as well as service facts after the long
            // audit, so an external change cannot reuse the earlier UI config.
            guard await store.switcher.refreshInitializationStatus() else {
                return .failed(code: "status_unavailable", detail: "最终配置与后台状态回读未完成，请重试。")
            }
            return validateCurrentEvidence()
        }
    }
    private func checkNetwork(_ step: InitializationStep, forceNew: Bool) async -> InitializationResult {
        guard contextMatches else {
            return Self.networkContextFailure(bound: boundContext, current: store.initializationContext, timeoutStage: nil)
        }
        let kind: LeakKind = step == .dns ? .dns : .webrtc
        let accepted = await store.leakChecks.ensureInitializationReceipt(kind, forceNew: forceNew)
        let value = kind == .dns ? store.leakChecks.dns : store.leakChecks.rtc
        let timeoutStage = value.result?.errors.first(where: { $0.code == "timeout" })?.stage
        guard contextMatches else {
            return Self.networkContextFailure(bound: boundContext, current: store.initializationContext, timeoutStage: timeoutStage)
        }
        guard accepted else {
            let error = kind == .dns ? store.switcher.dnsReceiptError : store.switcher.webRTCReceiptError
            let timeoutDetail = timeoutStage.map { Self.timeoutDescription($0) + value.verdict.detail }
            return .failed(code: kind == .dns ? "dns_not_passed" : "webrtc_not_passed",
                           detail: timeoutDetail ?? (error.isEmpty ? value.verdict.detail : error))
        }
        if let failure = backendReceiptFailure(kind) {
            store.leakChecks.invalidateInitializationReceipt(kind)
            return failure
        }
        markEnvironmentReadbackPending(kind)
        return .passed("检测通过，结果已提交后台；主界面与保护检查共用本次回执。")
    }
    /// Let both leak checks finish before reading them back together. A new
    /// receipt from the same backend context cannot be judged against the
    /// previous audit. Protection and final verification still require an
    /// audit that references both exact receipts.
    private func markEnvironmentReadbackPending(_ kind: LeakKind) {
        guard requireBackendContextMatch,
              let environment = store.switcher.currentEnvironment,
              let receipt = kind == .dns ? store.switcher.initializationDNSReceipt : store.switcher.initializationWebRTCReceipt,
              environment.context_id == receipt.context else { return }
        let observed = kind == .dns ? environment.initialization_receipts?.dns
                                    : environment.initialization_receipts?.webrtc
        if observed?.sampled_at != receipt.sampled { requireBackendContextMatch = false }
    }
    func refreshWaitingEvidence() async -> InitializationRefreshOutcome {
        // One predicate defines "still current" for every rerun path: these
        // are the same revocation rules the coordinator applies to kept
        // greens, so a waiting-period refresh and a failed-round resume can
        // never disagree about what counts as current evidence.
        let blocking = currentEvidenceFailures()
        for step in [InitializationStep.connection, .environment, .accessibility] {
            if case .failed(let code, let detail)? = blocking[step] {
                return .failed(step: step, code: code, detail: detail)
            }
        }
        for step in [InitializationStep.dns, .webrtc] {
            // A receipt that is still current (fresh result, same context,
            // already accepted by the backend) must not be re-collected: a
            // waiting-period refresh only re-runs the kind that actually
            // expired. Forcing both probes every cycle turned each refresh
            // into a full multi-minute restart of the network checks.
            let kind: LeakKind = step == .dns ? .dns : .webrtc
            if store.leakChecks.initializationReceiptIsCurrent(kind) { continue }
            let result = await checkNetwork(step, forceNew: true)
            guard !Task.isCancelled else { return .failed(step: step, code: "cancelled", detail: "自动刷新已取消，请重新检查。") }
            if case .failed(let code, let detail) = result {
                let failingStep: InitializationStep = ["context_unavailable", "context_changed"].contains(code) ? .connection : step
                return .failed(step: failingStep, code: code, detail: detail)
            }
        }
        let result = await check(.verification)
        switch result {
        case .passed(_, let expiry):
            guard let expiry else { return .failed(step: .verification, code: "evidence_expired", detail: "自动刷新未取得有效期，请重新检查。") }
            return .passed(validUntil: expiry)
        case .failed(let code, let detail): return .failed(step: .verification, code: code, detail: detail)
        case .approval: return .failed(step: .verification, code: "unexpected_approval", detail: "自动刷新需要重新确认，请重新检查。")
        }
    }
    func approve(_ request: InitializationApproval, progress: @escaping SetupProgressObserver) async -> InitializationResult {
        switch request.action {
        case .accessibility:
            requestAccessibility()
            // OS consent can outlive this call. Only a later actual trust check
            // may advance; opening Settings is never treated as permission.
            return accessResult
        case .environment, .protection:
            guard contextMatches, let plan = store.switcher.setupPlan, plan.id == request.id,
                  store.switcher.setupCanConfirm, Self.allowed(plan.actions) else {
                return .failed(code: "setup_preview_expired", detail: "授权预览已过期或环境改变，请重新检查并确认。")
            }
            if request.action == .protection {
                // Consent may have taken minutes. Recheck the original source
                // times immediately before enabling protection, not just the
                // more recently generated preview's expiry.
                let precheck = preProtectionEvidence()
                if case .failed = precheck { return precheck }
            }
            await store.switcher.applyEnvironment(refreshDetection: false, progress: progress)
            guard !store.switcher.failure, !recoveryRequired,
                  store.switcher.environment?.initialized == true,
                  request.action != .protection || protectionSettingsEnabled else {
                return .failed(code: "setup_not_applied", detail: store.switcher.message.isEmpty ? "环境或守护未能应用并确认，请查看检查记录。" : store.switcher.message)
            }
            guard contextMatches else { return changedFailure }
            setupWasApproved = true
            approvedContext = boundContext
            acceptedSettings = settingsData
            return .passed(request.action == .protection ? "守护设置已应用；实际运行心跳将在最后复核。" : "实测环境已保存并回读，继续核对权限及网络。")
        }
    }
    private var hasCurrentProtectionReadback: Bool {
        let now = Date().timeIntervalSince1970
        guard let audit = store.switcher.currentEnvironment, !store.switcher.currentEnvironmentIsHistorical,
              audit.observed_at <= now, now < audit.expires_at else { return false }
        return [LeakKind.dns, .webrtc].allSatisfy {
            backendReceiptFailure($0, environmentContext: audit.context_id, requireEnvironment: true) == nil
        }
    }
    private func prepareEnvironment() async -> InitializationResult {
        guard contextMatches else { return changedFailure }
        guard !recoveryRequired else { return recoveryFailure }
        await store.switcher.detectEnvironment()
        guard let candidate = store.switcher.candidate, !store.switcher.failure else {
            return .failed(code: "environment_unavailable", detail: store.switcher.message)
        }
        return await previewSetup(candidateID: candidate.id, enableProtection: false)
    }
    private func previewSetup(candidateID: String, enableProtection: Bool) async -> InitializationResult {
        store.switcher.setupApplyEnvironment = !enableProtection
        store.switcher.setupEnablePolicy = true
        // First collect/verify the environment. Enabling new protection is a
        // separate, explicit step only after DNS, WebRTC and precheck passed.
        store.switcher.setupGuard = enableProtection || store.switcher.isOn(Setting.guardEnabled)
        store.switcher.setupWatchdog = enableProtection || store.switcher.isOn(Setting.timezoneWatchdog)
        store.switcher.setupUpdater = store.switcher.isOn(Setting.autoUpdate)
        await store.switcher.previewEnvironment(candidateID: candidateID)
        guard let plan = store.switcher.setupPlan else {
            return .failed(code: "setup_preview_unavailable", detail: store.switcher.message)
        }
        guard plan.candidate_id == candidateID,
              plan.expires_at > Date().timeIntervalSince1970, Self.allowed(plan.actions), contextMatches,
              !enableProtection || plan.actions.allSatisfy({ $0.id == "watchdog" }) else {
            return .failed(code: "setup_preview_invalid", detail: "环境预览不可用、已变化或包含范围外操作；未执行变更。请重新检查。")
        }
        if setupWasApproved && approvedContext == boundContext && plan.actions.isEmpty
            && (plan.confirmation_lines ?? []).isEmpty && (!enableProtection || protectionSettingsEnabled) {
            acceptedSettings = settingsData
            return .passed(enableProtection ? "已保存的两项守护开启设置保持一致，继续复核实际心跳。" : "已确认的环境设置保持一致。")
        }
        let needsAdministrator = plan.actions.contains { ["timezone", "ipv6", "watchdog"].contains($0.id) }
        let description = needsAdministrator
            ? "确认后先复核出口，再请求 macOS 管理员权限以执行所列系统操作，完成后回读。"
            : "确认后先复核出口，再保存 Watch 设置；本次列出的操作不需要管理员权限。"
        return .approval(.init(id: plan.id, action: enableProtection ? .protection : .environment,
            title: enableProtection ? "启用 Watch 自有守护" : "确认初始化环境",
            detail: description,
            changes: Self.confirmationChanges(plan, enableProtection: enableProtection)))
    }
    static func confirmationChanges(_ plan: EnvironmentSetupPlan, enableProtection: Bool) -> [String] {
        (enableProtection ? ["开启 Watch 保镖与时区守护，保存重启后的自动恢复设置"] : ["保存本次实测环境及 Watch 启动策略"])
            + (plan.confirmation_lines ?? [])
            + plan.actions.map { $0.title + "：" + ($0.detail ?? $0.scope) }
    }
    private func preProtectionEvidence() -> InitializationResult {
        guard contextMatches, snapshotIsCurrent, acceptedSettings != nil, acceptedSettings == settingsData else { return changedFailure }
        guard store.switcher.isOn(Setting.enabled) else {
            return .failed(code: "policy_not_enabled", detail: "环境设置与启动策略尚未确认，请重新检查。")
        }
        guard accessibilityTrusted() else { return .failed(code: "permission_missing", detail: "辅助功能权限未确认，请重新授权。") }
        guard let environment = store.switcher.currentEnvironment else {
            return .failed(code: "environment_not_ready", detail: "尚未取得启用守护前的环境预检结果。")
        }
        if let failure = receiptFailure(environmentContext: environment.context_id) { return failure }
        return InitializationEnvironmentGate.evaluate(environment,
            policy: store.switcher.currentPolicyEvaluation, settings: store.switcher.settings,
            historical: store.switcher.currentEnvironmentIsHistorical, unsavedSettings: store.switcher.hasUnsavedSettings,
            now: Date().timeIntervalSince1970,
            checkingBeforeGuardEnable: !store.switcher.isOn(Setting.guardEnabled))
    }
    func validateCurrentEvidence() -> InitializationResult {
        let now = Date().timeIntervalSince1970
        guard contextMatches, snapshotIsCurrent, acceptedSettings != nil, acceptedSettings == settingsData else { return changedFailure }
        guard accessibilityTrusted() else { return .failed(code: "permission_missing", detail: "辅助功能授权尚未确认或已被撤销。") }
        guard !recoveryRequired else { return recoveryFailure }
        guard protectionSettingsEnabled, backgroundIsCurrent else { return backgroundFailure }
        guard let environment = store.switcher.currentEnvironment else {
            return .failed(code: "environment_not_ready", detail: "尚未取得本轮环境回执。")
        }
        if let failure = receiptFailure(environmentContext: environment.context_id) { return failure }
        let environmentResult = InitializationEnvironmentGate.evaluate(environment,
            policy: store.switcher.currentPolicyEvaluation, settings: store.switcher.settings,
            historical: store.switcher.currentEnvironmentIsHistorical,
            unsavedSettings: store.switcher.hasUnsavedSettings, now: now)
        if case .failed = environmentResult { return environmentResult }
        let expiry = [environment.expires_at,
                      (store.leakChecks.dns.result?.finishedAt ?? 0) + 300,
                      (store.leakChecks.rtc.result?.finishedAt ?? 0) + 300].min()!
        return .passed("所有检查均已通过，网络、配置及证据时效一致。进入后继续使用这些检测结果。", validUntil: expiry)
    }
    private func backendReceiptFailure(_ kind: LeakKind, environmentContext: String? = nil,
                                       requireEnvironment: Bool = false) -> InitializationResult? {
        let label = kind == .dns ? "DNS" : "WebRTC"
        let receipt = kind == .dns ? store.switcher.initializationDNSReceipt : store.switcher.initializationWebRTCReceipt
        guard let receipt else {
            return .failed(code: kind.rawValue + "_backend_missing", detail: label + "：没有本轮后台回执，请重新检查。")
        }
        guard receipt.state == "ok" else {
            return .failed(code: kind.rawValue + "_backend_not_passed", detail: label + "：后台对本轮回执的判定未通过，请重新检查。")
        }
        if requireEnvironment {
            guard let environmentContext, !environmentContext.isEmpty else {
                return .failed(code: "environment_context_unavailable", detail: "环境回执缺少网络上下文，无法核对检测结果。")
            }
            guard receipt.context == environmentContext else {
                return .failed(code: kind.rawValue + "_backend_context_changed", detail: label + "：后台回执与本轮环境的网络上下文不一致，请重新检查。")
            }
            let observed = kind == .dns ? store.switcher.currentEnvironment?.initialization_receipts?.dns
                                        : store.switcher.currentEnvironment?.initialization_receipts?.webrtc
            guard let observed, observed.state == "ok", observed.context_id == environmentContext,
                  observed.sampled_at == receipt.sampled else {
                return .failed(code: kind.rawValue + "_backend_receipt_changed", detail: label + "：本轮环境回读的后台回执已变化、未通过或不可用，请重新检查。")
            }
        }
        return nil
    }
    private func receiptFailure(environmentContext: String?) -> InitializationResult? {
        let problems = [LeakKind.dns, .webrtc].compactMap { store.leakChecks.initializationReceiptProblem($0) }
        if let first = problems.first {
            return .failed(code: first.code, detail: problems.map(\.detail).joined(separator: "\n") + " 请重新检查。")
        }
        for kind in [LeakKind.dns, .webrtc] {
            if let failure = backendReceiptFailure(kind, environmentContext: environmentContext, requireEnvironment: true) {
                store.leakChecks.invalidateInitializationReceipt(kind)
                return failure
            }
        }
        return nil
    }
    func currentEvidenceFailures() -> [InitializationStep: InitializationResult] {
        var failures: [InitializationStep: InitializationResult] = [:]
        if boundContext != nil && !contextMatches {
            failures[.connection] = Self.networkContextFailure(bound: boundContext, current: store.initializationContext, timeoutStage: nil)
        } else if boundContext != nil && !snapshotIsCurrent {
            failures[.connection] = .failed(code: "snapshot_unavailable", detail: "后台或代理采样状态暂不可确认，请重新检查。")
        }
        if let acceptedSettings, acceptedSettings != settingsData {
            failures[.environment] = .failed(code: "settings_changed", detail: "已确认的 Watch 设置发生变化，请重新检查。")
        }
        if !accessibilityTrusted() {
            failures[.accessibility] = .failed(code: "permission_missing", detail: "辅助功能权限当前未确认，请重新检查。")
        }
        for (kind, step) in [(LeakKind.dns, InitializationStep.dns), (.webrtc, .webrtc)] {
            if let failure = backendReceiptFailure(kind, environmentContext: store.switcher.currentEnvironment?.context_id,
                                                    requireEnvironment: requireBackendContextMatch) {
                store.leakChecks.invalidateInitializationReceipt(kind)
                failures[step] = failure
            } else if let problem = store.leakChecks.initializationReceiptProblem(kind) {
                failures[step] = .failed(code: problem.code, detail: problem.detail + " 请重新检查。")
            }
        }
        return failures
    }
    func finish() { store.finishInitialization() }
    static func allowed(_ actions: [SwitcherRepairAction]) -> Bool {
        let allowed: Set<String> = ["timezone", "locale", "language", "ipv6", "watchdog", "updater"]
        return actions.allSatisfy { allowed.contains($0.id) }
    }
    private var accessResult: InitializationResult {
        if accessibilityTrusted() { return .passed("macOS 已确认 Claude Watch 的辅助功能授权。") }
        return .approval(.init(id: "accessibility", action: .accessibility, title: "授权辅助功能",
            detail: "用于读取 Claude 界面的登录状态。macOS 只承认在「系统设置 › 隐私与安全性 › 辅助功能」中开启的授权，因此这一步会直接打开该面板；开启后自动核对并继续。",
            changes: ["在系统设置 › 隐私与安全性 › 辅助功能 中打开 Claude Watch 的开关", "授权状态以 macOS 实际回读为准；密码仅在系统窗口输入"]))
    }
    private var contextMatches: Bool { boundContext != nil && boundContext == store.initializationContext }
    static func timeoutDescription(_ stage: String) -> String {
        let label = ["dns_images": "DNS 查询", "dns_records": "DNS 记录读取",
                     "geoip": "地址归属查询", "http": "HTTP 出口查询", "ice": "WebRTC 采样"][stage] ?? "检测"
        return "\(label)超时。"
    }
    static func networkContextFailure(bound: String?, current: String?, timeoutStage: String?) -> InitializationResult {
        let unavailable = bound == nil || current == nil
        let detail = unavailable ? "代理上下文暂不可确认，不能使用本次检测结果。请重新检查。"
                                 : "检测期间代理上下文已变化，不能使用本次检测结果。请重新检查。"
        return .failed(code: unavailable ? "context_unavailable" : "context_changed",
                       detail: timeoutStage.map(timeoutDescription).map { $0 + detail } ?? detail)
    }
    private var settingsData: Data? { try? JSONSerialization.data(withJSONObject: store.switcher.settings, options: .sortedKeys) }
    private var protectionSettingsEnabled: Bool {
        [Setting.enabled, Setting.guardEnabled, Setting.timezoneWatchdog].allSatisfy { store.switcher.isOn($0) }
    }
    private var recoveryRequired: Bool {
        store.switcher.setupRecoveryRequired || store.switcher.updateRecoveryRequired || store.switcher.accounts?.recovery_required == true
    }
    private var snapshotIsCurrent: Bool {
        snapshotIsCurrent(at: Date().timeIntervalSince1970)
    }
    var connectionDiagnosticReport: String { connectionLog.report }
    func diagnosticReason(for step: InitializationStep) -> String? {
        guard step == .protection || step == .verification else { return nil }
        guard protectionSettingsEnabled else { return "protection_settings_disabled" }
        guard store.switcher.backgroundError.isEmpty else { return "background_read_failed" }
        guard let value = store.switcher.background else { return "background_missing" }
        let now = Date().timeIntervalSince1970
        guard value.observed_at.isFinite, (0..<30).contains(now - value.observed_at) else { return "background_stale" }
        guard let service = value.services.first(where: { $0.id == "guard" }) else { return "guard_receipt_missing" }
        if !service.healthy || service.desired != true { return service.reason_code ?? "guard_receipt_unverified" }
        guard value.guard_backend_healthy == true else { return value.backend_diagnostics?.reason ?? "backend_unverified" }
        guard let watchdog = value.services.first(where: { $0.id == "watchdog" }), watchdog.healthy, watchdog.desired == true else {
            return "watchdog_unverified"
        }
        return "protection_evidence_unverified"
    }
    private func traceConnection(event: String, phase: String, code: String, deadline: Double? = nil,
                                 candidate: String? = nil, sampled: Double? = nil) {
        let now = connectionNow(), background = store.switcher.background, snapshot = store.snapshot
        let proxy = snapshot?.proxy
        func finite(_ number: Double?) -> Double? { number.flatMap { $0.isFinite ? $0 : nil } }
        connectionLog.append(.init(event: event, phase: phase, code: code, time: now,
            app_version: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
            app_build: Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
            backend_read_error: store.switcher.backgroundReadFailureCode,
            backend_healthy: background?.backend_healthy, native_backend_healthy: background?.guard_backend_healthy,
            backend_receipt_age_seconds: finite(background.map { now - $0.observed_at }),
            backend: background?.backend_diagnostics?.sanitized,
            snapshot_read_failed: store.error != nil, snapshot_present: snapshot != nil,
            snapshot_age_seconds: finite(snapshot.map { now - $0.capturedAt }),
            installed: snapshot?.installed, auto_start: snapshot?.autoStart, keep_alive: snapshot?.keepAlive,
            proxy_present: proxy != nil, proxy_read_failed: snapshot?.proxyError != nil,
            proxy_age_seconds: finite(proxy.map { now - $0.observedAt }),
            proxy_entry_verified: proxy.map { $0.entryState == "verified" },
            proxy_api_available: proxy.map { $0.apiState == "available" }, proxy_port_covered: proxy?.coversProxy,
            context_available: store.initializationContext != nil,
            same_candidate_context: candidate.map { $0 == store.initializationContext },
            source_sample_advanced: sampled.flatMap { previous in proxy.map { $0.observedAt > previous } },
            deadline_remaining_seconds: finite(deadline.map { $0 - now })))
    }
    /// The gate and its diagnostic code use the same facts. Never infer a
    /// proxy outage merely because a cold daemon has not published two rounds.
    private func connectionEvidenceFailure(at now: Double) -> InitializationResult? {
        guard Self.backendEvidenceIsCurrent(store.switcher.background, error: store.switcher.backgroundError, now: now) else {
            let detail: String
            if !store.switcher.backgroundError.isEmpty {
                detail = "后台状态读取失败（\(store.switcher.backgroundReadFailureCode ?? "read_failed")）。具体记录见“检查记录”。"
            } else if let diagnosis = store.switcher.background?.backend_diagnostics,
                      store.switcher.background?.guard_backend_healthy != true {
                detail = diagnosis.failureDescription
            } else {
                detail = "后台状态回执缺失、过期或未提供具体诊断。具体记录见“检查记录”。"
            }
            return .failed(code: "backend_unverified", detail: detail)
        }
        guard store.error == nil, let snapshot = store.snapshot else {
            return .failed(code: "snapshot_unavailable", detail: "采集后台快照尚未就绪或读取失败。")
        }
        guard snapshot.installed, snapshot.autoStart, snapshot.keepAlive else {
            return .failed(code: "collector_registration_unverified", detail: "采集后台的安装、自启或异常恢复注册尚未确认。")
        }
        guard MonitorSnapshotTiming.isCurrent(capturedAt: snapshot.capturedAt, now: now) else {
            return .failed(code: "snapshot_stale", detail: "采集后台快照已过期或时间异常。")
        }
        guard snapshot.proxyError == nil, let proxy = snapshot.proxy else {
            return .failed(code: "proxy_snapshot_unavailable", detail: "后台尚未发布可用的代理采样。")
        }
        guard (0...MonitorSnapshotTiming.proxyMaximumAge).contains(now - proxy.observedAt) else {
            return .failed(code: "proxy_sample_stale", detail: "代理采样已过期或时间异常。")
        }
        guard proxy.entryState == "verified" else {
            return .failed(code: "proxy_entry_unverified", detail: "本机代理入口及监听进程身份尚未确认。")
        }
        guard proxy.apiState == "available", proxy.coversProxy else {
            return .failed(code: "proxy_api_unverified", detail: "代理控制接口或本机代理端口覆盖尚未确认。")
        }
        guard store.initializationContext != nil else {
            return .failed(code: "proxy_context_unavailable", detail: "当前代理上下文尚不完整，无法比较连续采样。")
        }
        return nil
    }
    private func snapshotIsCurrent(at now: Double) -> Bool {
        guard store.error == nil, let snapshot = store.snapshot, snapshot.installed,
              snapshot.autoStart, snapshot.keepAlive, store.initializationContext != nil else { return false }
        return MonitorSnapshotTiming.isCurrent(capturedAt: snapshot.capturedAt, now: now)
    }
    private var backgroundIsCurrent: Bool {
        guard let value = store.switcher.background,
              Self.backendEvidenceIsCurrent(value, error: store.switcher.backgroundError),
              value.services.first(where: { $0.id == "guard" })?.healthy == true,
              value.services.first(where: { $0.id == "guard" })?.desired == true,
              value.services.first(where: { $0.id == "watchdog" })?.healthy == true,
              value.services.first(where: { $0.id == "watchdog" })?.desired == true,
              value.facts?.state != "fail" else { return false }
        return true
    }
    /// `guard_backend_healthy` already binds native runtime identity, launchd
    /// registration and a <=30s heartbeat. This is the exact backend predicate
    /// used by onboarding::require_transport, independent of monitoring quality
    /// and of whether the guard policy has been enabled yet.
    static func backendEvidenceIsCurrent(_ value: BackgroundServiceReceipt?, error: String = "",
                                         now: Double = Date().timeIntervalSince1970) -> Bool {
        guard let value, error.isEmpty, now.isFinite, value.observed_at.isFinite,
              value.guard_backend_healthy == true else { return false }
        return (0..<30).contains(now - value.observed_at)
    }
    private var changedFailure: InitializationResult {
        .failed(code: "context_changed", detail: "检查期间网络、代理、设置或采样状态变化。此前的通过结果不能合并放行，请重新检查。")
    }
    private var backgroundFailure: InitializationResult {
        .failed(code: "protection_not_ready", detail: Self.backgroundFailureDetail(
            store.switcher.background, error: store.switcher.backgroundError, settingsEnabled: protectionSettingsEnabled))
    }
    static func backgroundFailureDetail(_ value: BackgroundServiceReceipt?, error: String, settingsEnabled: Bool,
                                        now: Double = Date().timeIntervalSince1970) -> String {
        guard settingsEnabled else { return "Watch 保护设置尚未全部开启，请重新检查。" }
        guard error.isEmpty else { return "后台状态读取失败，暂时无法确认保护是否运行；正在等待重新读取。" }
        guard let value else { return "尚未取得后台状态，暂时无法确认保护是否运行；正在等待读取。" }
        guard now.isFinite, value.observed_at.isFinite, (0..<30).contains(now - value.observed_at) else {
            return "后台状态已过期或时间异常，暂时无法确认保护是否运行；正在等待重新读取。"
        }
        guard let guardService = value.services.first(where: { $0.id == "guard" }) else {
            return "Watch 保镖的运行状态当前未确认。"
        }
        if !guardService.healthy || guardService.desired != true {
            return guardService.detail.isEmpty ? "Watch 保镖的运行状态当前未确认。" : guardService.detail
        }
        guard value.guard_backend_healthy == true else { return "采集后台身份或心跳当前未确认，无法确认保护状态。" }
        guard let watchdog = value.services.first(where: { $0.id == "watchdog" }), watchdog.healthy, watchdog.desired == true else {
            return "时区守护的运行状态当前未确认。"
        }
        return "后台保护证据存在风险或未通过核对，请重新检查。"
    }
    private var recoveryFailure: InitializationResult {
        .failed(code: "recovery_required", detail: "Watch 存在未完成事务，需要先按操作记录恢复。本次未覆盖事务或扩大修复范围。")
    }
}

@MainActor
enum InitializationEnvironmentGate {
    static func evaluate(_ environment: CurrentEnvironmentReceipt, policy: EnvironmentPolicyEvaluation?,
                         settings: [String: Any], historical: Bool, unsavedSettings: Bool,
                         now: Double, checkingBeforeGuardEnable: Bool = false) -> InitializationResult {
        guard let policy, !historical, now.isFinite,
              SwitcherStore.acceptsDisplayPolicy(policy, for: environment, hasUnsavedSettings: unsavedSettings),
              policy.policy?.isEmpty == false, environment.context_transition?.state == "stable",
              environment.observed_at.isFinite, environment.expires_at.isFinite,
              environment.observed_at <= now, now < environment.expires_at,
              environment.facts?.state == "ok", policy.facts?.state == "ok" else {
            return .failed(code: "environment_not_ready", detail: "本轮环境、策略或保护证据没有全部通过，请重新检查。")
        }
        // Never accept an empty, truncated, duplicate or downgraded check list.
        // The ChatGPT service card is measured only by display rounds, so a
        // receipt either carries every base check plus that card, or the base
        // checks alone — never a partial or unknown set.
        let required: Set<String> = ["proxy", "tun", "egress", "ip_history", "timezone", "locale", "ipv6",
                                     "dns", "stun", "guard", "routing", "language", "asn", "reachability"]
        var expected = required
        expected.insert("chatgpt_reachability")
        var mandatory: Set<String> = ["proxy", "tun", "egress", "timezone", "locale", "guard", "reachability"]
        // DNS and STUN rows are required only when their probes are explicitly
        // requested (require_dns / require_stun). Backend audit marks them
        // `required=false` otherwise; hardcoding them here would reject a valid
        // receipt for "缺少必检项目".
        for (key, id) in [("require_ipv6_off", "ipv6"), ("require_english", "language"),
                          ("require_pinned_rules", "routing"), ("require_dns", "dns"), ("require_stun", "stun")] {
            if settings[key] as? Bool == true { mandatory.insert(id) }
        }
        let ids = policy.rows.map(\.id)
        let found = Set(ids)
        guard ids.count == found.count,
              found == required || found == expected,
              mandatory.allSatisfy({ id in policy.rows.contains { $0.id == id && $0.required } }) else {
            return .failed(code: "required_checks_missing", detail: "最终回执缺少必检项目或项目要求不符，未允许进入主界面。")
        }
        let unresolved = policy.rows.filter { $0.required && $0.state != "ok" && !(checkingBeforeGuardEnable && $0.id == "guard") }
        let ready = checkingBeforeGuardEnable ? policy.blocked.allSatisfy({ $0 == "guard" }) : policy.ready && policy.blocked.isEmpty
        guard unresolved.isEmpty, ready else {
            return .failed(code: "required_checks_not_passed", detail: unresolved.isEmpty ? "本轮必检项目尚未全部通过。" : unresolved.map { $0.name + "：" + $0.detail }.joined(separator: "\n"))
        }
        return .passed("同轮环境必检项目全部通过。", validUntil: environment.expires_at)
    }
}
