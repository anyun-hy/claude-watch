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
    private let componentCheck: () async throws -> Void
    private let accessibilityTrusted: () -> Bool
    private let requestAccessibility: () -> Void

    init(store: MonitorStore,
         componentCheck: (() async throws -> Void)? = nil,
         accessibilityTrusted: (() -> Bool)? = nil,
         requestAccessibility: (() -> Void)? = nil) {
        self.store = store
        self.componentCheck = componentCheck ?? {
            let data = try await Task.detached { try SwitcherCommandRunner.run(["self-check"]) }.value
            let value = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            guard value?["status"] as? String == "ok", value?["component_integrity"] as? Bool == true,
                  value?["grants_launch_permission"] as? Bool == false else {
                throw CocoaError(.fileReadCorruptFile)
            }
        }
        self.accessibilityTrusted = accessibilityTrusted ?? { AccessibilityPermission.trusted }
        self.requestAccessibility = requestAccessibility ?? { store.switcher.openClaudeWatchAccessibilitySettings() }
    }
    func begin() { store.beginInitialization() }
    func check(_ step: InitializationStep) async -> InitializationResult {
        switch step {
        case .components:
            do { try await componentCheck(); return .passed("运行组件完整性及 Watch 数据读取已核对。") }
            catch { return .failed(code: "components_unavailable", detail: "运行组件或 Watch 数据读取未通过，请检查安装完整性与数据目录权限。") }
        case .connection:
            boundContext = nil; acceptedSettings = nil
            guard await store.switcher.refreshInitializationStatus() else {
                return .failed(code: "status_unavailable", detail: "后台状态读取未完成，请重试。")
            }
            guard !recoveryRequired else { return recoveryFailure }
            let deadline = Date().addingTimeInterval(12)
            var candidate: String?
            var candidateSample: Double?
            // Two separate reads of verified current context, while the normal
            // snapshot-only timer keeps long DNS checks bound to fresh evidence.
            while Date() < deadline && !Task.isCancelled {
                await store.switcher.refreshBackground()
                if let context = store.initializationContext, snapshotIsCurrent,
                   Self.backendEvidenceIsCurrent(store.switcher.background, error: store.switcher.backgroundError) {
                    let sampled = store.snapshot?.proxy?.observedAt ?? 0
                    if candidate == context, let previous = candidateSample, sampled > previous {
                        boundContext = context
                        let detail = store.switcher.background?.backend_healthy == false
                            ? "原生采集后台身份、心跳及代理入口已确认。连接监控采样存在缺口，单独记录其完整性。"
                            : "原生采集后台身份、心跳及代理入口已确认；持续读取同一网络上下文。"
                        return .passed(detail)
                    }
                    if candidate != context { candidate = context; candidateSample = sampled }
                } else { candidate = nil; candidateSample = nil }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
            return .failed(code: "connection_unverified", detail: "原生采集后台身份、有效心跳或代理入口尚未持续确认。请查看检查记录后重试。")
        case .environment:
            return await prepareEnvironment(enableProtection: false)
        case .accessibility:
            return accessResult
        case .dns, .webrtc:
            guard contextMatches else { return changedFailure }
            let kind: LeakKind = step == .dns ? .dns : .webrtc
            let accepted = await store.leakChecks.ensureInitializationReceipt(kind)
            guard contextMatches else { return changedFailure }
            guard accepted else {
                let value = kind == .dns ? store.leakChecks.dns : store.leakChecks.rtc
                let error = kind == .dns ? store.switcher.dnsReceiptError : store.switcher.webRTCReceiptError
                return .failed(code: kind == .dns ? "dns_not_passed" : "webrtc_not_passed",
                               detail: error.isEmpty ? value.verdict.detail : error)
            }
            return .passed("检测通过，结果已提交后台；主界面与保护检查共用本次回执。")
        case .protection:
            guard contextMatches, acceptedSettings != nil, acceptedSettings == settingsData else { return changedFailure }
            guard await store.switcher.detectCurrentEnvironment() else {
                return .failed(code: "environment_unstable", detail: "启用守护前的环境预检未完成，请重试。")
            }
            let precheck = preProtectionEvidence()
            if case .failed = precheck { return precheck }
            return await prepareEnvironment(enableProtection: true)
        case .verification:
            guard contextMatches else { return changedFailure }
            guard await store.switcher.refreshInitializationStatus(), !recoveryRequired else {
                return .failed(code: "status_unavailable", detail: "最终后台状态读取未完成或存在待恢复事务。")
            }
            guard acceptedSettings == settingsData else { return changedFailure }
            // Watch's newly enabled guard needs time to publish its first real
            // heartbeat. Bound this wait; never manufacture readiness from intent.
            let deadline = Date().addingTimeInterval(12)
            repeat {
                await store.switcher.refreshBackground()
                if backgroundIsCurrent { break }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            } while Date() < deadline && !Task.isCancelled
            guard backgroundIsCurrent else { return backgroundFailure }
            guard await store.switcher.detectCurrentEnvironment() else {
                return .failed(code: "environment_unstable", detail: "最终环境检测未完成或上下文不稳定，请重新检查。")
            }
            // Re-read configuration as well as service facts after the long
            // audit, so an external change cannot reuse the earlier UI config.
            guard await store.switcher.refreshInitializationStatus() else {
                return .failed(code: "status_unavailable", detail: "最终配置与后台状态回读未完成，请重试。")
            }
            return validateCurrentEvidence()
        }
    }
    func approve(_ request: InitializationApproval) async -> InitializationResult {
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
            await store.switcher.applyEnvironment(refreshDetection: false)
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
    private func prepareEnvironment(enableProtection: Bool) async -> InitializationResult {
        guard contextMatches else { return changedFailure }
        await store.switcher.inspectEnvironment()
        guard !recoveryRequired else { return recoveryFailure }
        await store.switcher.detectEnvironment()
        guard let candidate = store.switcher.candidate, !store.switcher.failure else {
            return .failed(code: "environment_unavailable", detail: store.switcher.message)
        }
        store.switcher.setupApplyEnvironment = !enableProtection
        store.switcher.setupEnablePolicy = true
        // First collect/verify the environment. Enabling new protection is a
        // separate, explicit step only after DNS, WebRTC and precheck passed.
        store.switcher.setupGuard = enableProtection || store.switcher.settings["guard_enabled"] as? Bool == true
        store.switcher.setupWatchdog = enableProtection || store.switcher.settings["timezone_watchdog"] as? Bool == true
        store.switcher.setupUpdater = store.switcher.settings["auto_update"] as? Bool ?? false
        await store.switcher.previewEnvironment()
        guard let plan = store.switcher.setupPlan, plan.candidate_id == candidate.id,
              plan.expires_at > Date().timeIntervalSince1970, Self.allowed(plan.actions), contextMatches,
              !enableProtection || plan.actions.allSatisfy({ ["watchdog", "updater"].contains($0.id) }) else {
            return .failed(code: "setup_preview_invalid", detail: "环境预览不可用、已变化或包含范围外操作；未执行变更。请重新检查。")
        }
        if setupWasApproved && approvedContext == boundContext && plan.actions.isEmpty && (!enableProtection || protectionSettingsEnabled) {
            acceptedSettings = settingsData
            return .passed(enableProtection ? "已保存的两项守护开启设置保持一致，继续复核实际心跳。" : "已确认的环境设置保持一致。")
        }
        return .approval(.init(id: plan.id, action: enableProtection ? .protection : .environment,
            title: enableProtection ? "启用 Watch 自有守护" : "确认初始化环境",
            detail: "确认后应用下列变更。需要管理员权限时，macOS 会弹出密码窗口；完成后重新读取实际状态。",
            changes: (enableProtection ? ["开启 Watch 保镖与时区守护，保存重启后的自动恢复设置"] : ["保存本次实测环境及 Watch 启动策略"])
                + plan.actions.map { $0.title + "：" + ($0.detail ?? $0.scope) }))
    }
    private func preProtectionEvidence() -> InitializationResult {
        guard contextMatches, snapshotIsCurrent, acceptedSettings != nil, acceptedSettings == settingsData else { return changedFailure }
        guard store.switcher.settings["enabled"] as? Bool == true else {
            return .failed(code: "policy_not_enabled", detail: "环境设置与启动策略尚未确认，请重新检查。")
        }
        guard accessibilityTrusted() else { return .failed(code: "permission_missing", detail: "辅助功能权限未确认，请重新授权。") }
        guard store.leakChecks.initializationReceiptIsCurrent(.dns), store.leakChecks.initializationReceiptIsCurrent(.webrtc) else {
            return .failed(code: "receipt_not_current", detail: "启用守护前，DNS 与 WebRTC 必须都已通过、提交后台且仍有效。请重新检查。")
        }
        guard let environment = store.switcher.currentEnvironment else {
            return .failed(code: "environment_not_ready", detail: "尚未取得启用守护前的环境预检结果。")
        }
        return InitializationEnvironmentGate.evaluate(environment,
            policy: store.switcher.currentPolicyEvaluation, settings: store.switcher.settings,
            historical: store.switcher.currentEnvironmentIsHistorical, unsavedSettings: store.switcher.hasUnsavedSettings,
            now: Date().timeIntervalSince1970,
            checkingBeforeGuardEnable: store.switcher.settings["guard_enabled"] as? Bool != true)
    }
    func validateCurrentEvidence() -> InitializationResult {
        let now = Date().timeIntervalSince1970
        guard contextMatches, snapshotIsCurrent, acceptedSettings != nil, acceptedSettings == settingsData else { return changedFailure }
        guard accessibilityTrusted() else { return .failed(code: "permission_missing", detail: "辅助功能授权尚未确认或已被撤销。") }
        guard !recoveryRequired else { return recoveryFailure }
        guard protectionSettingsEnabled, backgroundIsCurrent else { return backgroundFailure }
        guard store.leakChecks.initializationReceiptIsCurrent(.dns),
              store.leakChecks.initializationReceiptIsCurrent(.webrtc) else {
            return .failed(code: "receipt_not_current", detail: "DNS 或 WebRTC 结果未通过、已过期或未被后台接受，请重新检查。")
        }
        guard let environment = store.switcher.currentEnvironment else {
            return .failed(code: "environment_not_ready", detail: "尚未取得本轮环境回执。")
        }
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
    func finish() { store.finishInitialization() }
    static func allowed(_ actions: [SwitcherRepairAction]) -> Bool {
        let allowed: Set<String> = ["timezone", "locale", "language", "ipv6", "watchdog", "updater"]
        return actions.allSatisfy { allowed.contains($0.id) }
    }
    private var accessResult: InitializationResult {
        if accessibilityTrusted() { return .passed("macOS 已确认 Claude Watch 的辅助功能授权。") }
        return .approval(.init(id: "accessibility", action: .accessibility, title: "授权辅助功能",
            detail: "用于读取 Claude 界面的登录状态。请在 macOS 系统设置中允许 Claude Watch，返回后重新核对。",
            changes: ["在系统设置中开启 Claude Watch 的辅助功能权限", "授权状态以 macOS 实际回读为准；密码仅在系统窗口输入"]))
    }
    private var contextMatches: Bool { boundContext != nil && boundContext == store.initializationContext }
    private var settingsData: Data? { try? JSONSerialization.data(withJSONObject: store.switcher.settings, options: .sortedKeys) }
    private var protectionSettingsEnabled: Bool {
        ["enabled", "guard_enabled", "timezone_watchdog"].allSatisfy { store.switcher.settings[$0] as? Bool == true }
    }
    private var recoveryRequired: Bool {
        store.switcher.setupRecoveryRequired || store.switcher.updateRecoveryRequired || store.switcher.accounts?.recovery_required == true
    }
    private var snapshotIsCurrent: Bool {
        guard store.error == nil, let snapshot = store.snapshot, snapshot.installed,
              snapshot.autoStart, snapshot.keepAlive, store.initializationContext != nil else { return false }
        return MonitorSnapshotTiming.isCurrent(capturedAt: snapshot.capturedAt, now: Date().timeIntervalSince1970)
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
        .failed(code: "protection_not_ready", detail: "Watch 保镖或时区守护的实际运行状态尚未通过核对；设置为开启不等于后台就绪。请重试。")
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
        let expected: Set<String> = ["proxy", "tun", "egress", "ip_history", "timezone", "locale", "ipv6",
                                     "dns", "stun", "guard", "routing", "language", "asn", "reachability"]
        var mandatory: Set<String> = ["proxy", "tun", "egress", "timezone", "locale", "dns", "stun", "guard", "reachability"]
        for (key, id) in [("require_ipv6_off", "ipv6"), ("require_english", "language"), ("require_pinned_rules", "routing")] {
            if settings[key] as? Bool == true { mandatory.insert(id) }
        }
        let ids = policy.rows.map(\.id)
        guard ids.count == expected.count, Set(ids) == expected,
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
