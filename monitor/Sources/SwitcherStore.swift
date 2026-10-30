import AppKit
import Combine
import Foundation
import SwiftUI

struct EnvironmentCheckRow: Decodable, Identifiable {
    let id, name, state, detail, scope: String
    let required: Bool
    var current: String? = nil
    var reference: String? = nil
    var source: String? = nil
    var sampled_at: Double? = nil
    /// True when this passing row's evidence is a reused observation (a receipt
    /// hit or a cached query) rather than a probe from the current round.
    var sample_reused: Bool? = nil
    var query_error: String? = nil
    var statusLabel: String {
        switch state {
        case "ok": return id == "reachability" ? "网络可达" : "已核对"
        case "fail": return "需处理"
        case "warn": return "提示"
        case "info": return "已读取"
        case "cached": return "上次有效"
        default: return "未取得"
        }
    }
    var statusSymbol: String {
        switch state { case "ok": return "checkmark.circle.fill"; case "fail": return "xmark.octagon.fill";
        case "warn": return "exclamationmark.triangle.fill"; case "info": return "info.circle.fill";
        case "cached": return "clock.arrow.circlepath"; default: return "questionmark.circle.fill" }
    }
    var categorySymbol: String {
        switch id {
        case "proxy": return "cpu"
        case "tun": return "network"
        case "egress": return "globe.asia.australia"
        case "ip_history": return "arrow.triangle.2.circlepath"
        case "timezone": return "clock"
        case "locale": return "calendar"
        case "ipv6": return "6.circle"
        case "dns": return "server.rack"
        case "stun": return "antenna.radiowaves.left.and.right"
        case "guard": return "shield.lefthalf.filled"
        case "routing": return "list.bullet.rectangle"
        case "language": return "character.bubble"
        case "asn": return "building.2"
        case "reachability": return "link"
        default: return "checklist"
        }
    }
}
struct EnvironmentSourceNotice: Decodable, Identifiable {
    let id, title, detail, severity: String
}
struct EgressReference: Decodable {
    let ip, country, timezone, context_id: String?
    let checked_at: Double?
    var observed_at: Double? = nil
}
struct GuardRisk: Decodable, Identifiable {
    let id: String
    var source: String?
    var value: String?
    var reason: String?
    var required: Bool?
}
struct ProtectionFacts: Decodable {
    let state: String
    var risks: [GuardRisk]?
    var evidence: CoffeeJSON?
}
struct SessionGuardStatus: Decodable {
    let state: String
    var phase: String?
    var baseline: EgressReference?
    var current: EgressReference?
    var reason: SessionGuardReason?
    var risk_evidence: CoffeeJSON?
    var locked_at: Double?
}
struct SessionGuardReason: Decodable {
    let code, detail: String
    var source: String?
    var observed_at: Double?
}
enum SwitcherReviewScenario: String, CaseIterable {
    case normal, ipChanged, cnRisk, transientFailure, evidenceExpired, recovered
    var title: String {
        switch self {
        case .normal: return "正常 JP"
        case .ipChanged: return "同国 IP 变化"
        case .cnRisk: return "中国出口风险"
        case .transientFailure: return "单次采样失败"
        case .evidenceExpired: return "证据过期"
        case .recovered: return "恢复待手动启动"
        }
    }
}
struct EnvironmentAuditReceipt: Decodable {
    var observed_at, expires_at: Double
    let ready: Bool
    let rows: [EnvironmentCheckRow]
    let blocked: [String]
    let message: String
    var egress_reference: EgressReference?
    var facts: ProtectionFacts?
}
struct CurrentEnvironmentReceipt: Decodable {
    let purpose: String
    let grants_launch_permission: Bool
    var observed_at, expires_at: Double
    var rows: [EnvironmentCheckRow]
    let candidates: [String]
    let message: String
    var source_notices: [EnvironmentSourceNotice]?
    var netcoffee_lookup: CoffeeReceipt?
    var observation_id: String?
    var context_id: String?
    var context_transition: EnvironmentContextTransition?
    var policy_evaluation: EnvironmentPolicyEvaluation?
    var egress_reference: EgressReference?
    var facts: ProtectionFacts?
    var session_guard: SessionGuardStatus?
    var display_facts: EnvironmentDisplayFacts?
    func count(_ state: String) -> Int { rows.filter { $0.state == state }.count }
    mutating func replaceDNSRow(_ row: EnvironmentCheckRow) {
        if let index = rows.firstIndex(where: { $0.id == "dns" }) { rows[index] = row }
        else { rows.append(row) }
    }
}
/// Engine-side evidence for the routing row.  The audit row itself only carries
/// state and detail; the missing/bypass lists live here so the UI can name the
/// exact domains instead of showing a bare count.
struct EnvironmentDisplayFacts: Decodable {
    var local: EnvironmentLocalFacts?
}
struct EnvironmentLocalFacts: Decodable {
    var rules: EnvironmentRulesEvidence?
    var tag: EnvironmentTagEvidence?
}
struct EnvironmentRulesEvidence: Decodable {
    var state: String?
    var actual_mode: String?
    var missing_domains: [String]?
    var bypass_domains: [String]?
    /// Rules the user switched off in the proxy client: present in the table,
    /// matching nothing.  Named so the gap between written and effective stays
    /// visible instead of reading as coverage.
    var disabled_domains: [String]?
    var covered_domains: [String]?
    var detail: String?
}
struct EnvironmentTagEvidence: Decodable {
    var pinned: Bool?
    var expected_group: String?
    var expected_node: String?
    var api: EnvironmentTagAPI?
}
struct EnvironmentTagAPI: Decodable {
    var mode: String?
    var global_node: String?
    var selected_node: String?
}
/// A neutral recommendation, deliberately not a gate.  When the proxy runs in
/// rule mode the product suggests global mode, where one node handles every
/// flow and leaks have no rule-table gap to slip through.  This never touches
/// the routing audit row, the launch gate, or any required check: it is advice
/// the user may ignore, not a verdict about their configuration.
struct EnvironmentModeRecommendation {
    let title: String
    let detail: String
    static func evaluate(_ evidence: EnvironmentRulesEvidence?) -> EnvironmentModeRecommendation? {
        guard let evidence, let mode = evidence.actual_mode, !mode.isEmpty, mode != "global" else { return nil }
        return EnvironmentModeRecommendation(
            title: "推荐：切换到全局模式",
            detail: "当前代理为 \(mode) 模式。规则模式下流量按规则表逐条匹配，任何未覆盖的域名都可能绕过代理暴露本机 IP；全局模式下全部流量统一走单一节点出口，更能避免 IP 等信息泄漏。请在代理客户端（如 TAG）的模式选择中切换为 Global/全局；本产品只作建议，不代改代理配置。")
    }
}
struct EnvironmentContextTransition: Decodable {
    let state: String
    var changed_fields: [String]? = nil
    var unavailable: [String]? = nil
}
struct EnvironmentPolicyEvaluation: Decodable {
    let purpose: String
    let grants_launch_permission: Bool
    let observed_at, expires_at: Double
    let observation_id, context_id: String?
    let policy: String?
    let rows: [EnvironmentCheckRow]
    let blocked: [String]
    let ready: Bool
    let message: String?
    var egress_reference: EgressReference?
    var facts: ProtectionFacts?
    var session_guard: SessionGuardStatus?
}
struct SwitcherRepairAction: Decodable, Identifiable {
    let id, title, scope: String
    var detail: String? = nil
    init(id: String, title: String, scope: String, detail: String? = nil) {
        self.id = id; self.title = title; self.scope = scope; self.detail = detail
    }
    private enum CodingKeys: String, CodingKey { case id, title, scope, detail, before, after }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id); title = try c.decode(String.self, forKey: .title)
        scope = try c.decode(String.self, forKey: .scope)
        detail = try c.decodeIfPresent(String.self, forKey: .detail)
        if detail == nil, c.contains(.before), c.contains(.after) {
            detail = try c.decode(PlanValue.self, forKey: .before).text + " → " + c.decode(PlanValue.self, forKey: .after).text
        }
    }
}
private indirect enum PlanValue: Decodable {
    case text(String)
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .text("未设置") }
        else if let v = try? c.decode(Bool.self) { self = .text(v ? "开启" : "关闭") }
        else if let v = try? c.decode(String.self) { self = .text(v) }
        else if let v = try? c.decode(Double.self) { self = .text(String(v)) }
        else { self = .text(try c.decode([PlanValue].self).map(\.text).joined(separator: ", ")) }
    }
    var text: String { switch self { case .text(let value): return value } }
}
struct BackgroundServiceRow: Decodable, Identifiable {
    let id, title, state, detail, source: String
    let desired: Bool?
    let last_checked: Double?
    var statusLabel: String {
        switch state {
        case "running": return "断线保护就绪"
        case "scheduled": return "已加载"
        case "inactive": return "已停用"
        case "unavailable": return "尚不可用"
        case "mismatch": return "待同步"
        case "error": return "需处理"
        default: return "未确认"
        }
    }
    var healthy: Bool { state == "running" || state == "scheduled" }
}
struct PolicyIssue: Decodable, Identifiable { let id, title, detail: String }
struct BackgroundServiceReceipt: Decodable {
    let observed_at: Double
    let backend_healthy, update_source_ready: Bool
    let guard_backend_healthy: Bool?
    let backend_sampling_state: String?
    let services: [BackgroundServiceRow]
    let policy_issues: [PolicyIssue]
    var egress_reference: EgressReference?
    var facts: ProtectionFacts?
    var session_guard: SessionGuardStatus?
}
struct SwitcherRepairPlan: Decodable {
    let id: String
    let actions: [SwitcherRepairAction]
}
struct SwitcherAccountSlot: Decodable, Identifiable {
    let id: String
    let stored, current: Bool
}
struct SwitcherAccountState: Decodable {
    let current: String?
    let recovery_required: Bool
    let accounts: [SwitcherAccountSlot]
    let detail: String
}
struct AccountSlotPresentation {
    let summary, confirmationTitle, confirmationDetail, actionTitle: String
}

struct EnvironmentValueRow: Decodable, Identifiable {
    let id, title, current, target, proposed, source, target_source, proposed_source: String
}
struct EnvironmentObservation: Decodable {
    let observed_at: Double
    let initialized: Bool
    let rows: [EnvironmentValueRow]
    let candidates: [String]
    let message: String
    let recovery_required: Bool
    let confirmed_at: Double?
}
struct EnvironmentCandidate: Decodable {
    let id: String
    let observed_at, expires_at: Double
    let rows: [EnvironmentValueRow]
    let message: String
}
struct EnvironmentSetupPlan: Decodable {
    let id, candidate_id: String
    let actions: [SwitcherRepairAction]
    let rows: [EnvironmentValueRow]
    let expires_at: Double
}

struct ProxyDiagnosticCheck: Decodable, Identifiable {
    let name: String
    let transport_reached: Bool
    let access: String
    let http_status: Int?
    let elapsed_seconds: Double?
    let error: String?
    var id: String { name }
    var title: String { name == "anthropic_api" ? "Anthropic API" : "Claude 网页" }
    var accessLabel: String {
        switch access {
        case "unauthenticated": return "需要账号认证"
        case "access_restricted": return "访问受限"
        case "server_error": return "服务端错误"
        case "http_response": return "已收到 HTTP 响应"
        default: return error == "probe_timeout" ? "请求超时" : "传输未确认"
        }
    }
}
struct ProxyDiagnosticReceipt: Decodable {
    let state, message: String
    let checks: [ProxyDiagnosticCheck]
    var reached: Bool { state == "transport_reached" }
}

enum SwitcherCommandRunner {
    static func run(_ args: [String], input: Data? = nil, cancellation: SwitcherReadCancellation? = nil,
                    dnsRefreshToken: String? = nil) throws -> Data {
        let task = Process(), output = Pipe()
        guard let variant = BundledBackendVariant.current() else {
            throw NSError(domain: "Switcher", code: 1, userInfo: [NSLocalizedDescriptionKey: "构建包未声明后台类型，请重新构建界面。"])
        }
        switch variant {
        case .rustCandidate:
            guard let engine = Bundle.main.url(forResource: "watch-engine", withExtension: nil) else {
                throw NSError(domain: "Switcher", code: 1, userInfo: [NSLocalizedDescriptionKey: "缺少 Rust 账号与环境组件，请重新构建候选包。"])
            }
            task.executableURL = engine
            task.arguments = args
        case .stable:
            guard let script = Bundle.main.url(forResource: "switcher", withExtension: "py") else {
                throw NSError(domain: "Switcher", code: 1, userInfo: [NSLocalizedDescriptionKey: "缺少稳定版账号与环境组件，请重新构建界面。"])
            }
            task.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            task.arguments = ["python3", script.path] + args
        }
        var env = ProcessInfo.processInfo.environment
        env["PATH"] = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"
        if case .stable = variant { env["PYTHONDONTWRITEBYTECODE"] = "1" }
        env.removeValue(forKey: "BASH_ENV")
        env.removeValue(forKey: "CLAUDE_WATCH_DNS_REFRESH_TOKEN")
        if let dnsRefreshToken { env["CLAUDE_WATCH_DNS_REFRESH_TOKEN"] = dnsRefreshToken }
        task.environment = env
        task.standardOutput = output
        task.standardError = output
        let incoming = Pipe()
        task.standardInput = incoming
        if let cancellation { try cancellation.start(task) } else { try task.run() }
        if let input { incoming.fileHandleForWriting.write(input) }
        try? incoming.fileHandleForWriting.close()
        // Mutating transactions have their own recovery journal. Never kill one
        // because a GUI timer expired between two directory renames.
        let data = output.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        if cancellation?.isCancelled == true { throw CancellationError() }
        guard data.count <= 4_000_000,
              (try? JSONSerialization.jsonObject(with: data)) is [String: Any] else {
            throw NSError(domain: "Switcher", code: 2, userInfo: [NSLocalizedDescriptionKey: "运行组件未返回完整结果；没有将此状态视为成功。"])
        }
        return data
    }
}

final class SwitcherReadCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false
    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
    func start(_ task: Process) throws {
        lock.lock(); defer { lock.unlock() }
        if cancelled { throw CancellationError() }
        try task.run(); process = task
    }
    func cancel() {
        lock.lock(); cancelled = true; let task = process; lock.unlock()
        if task?.isRunning == true { task?.terminate() }
    }
}

@MainActor
final class SwitcherStore: ObservableObject {
    @Published var settings: [String: Any] = [:]
    @Published private(set) var audit: EnvironmentAuditReceipt?
    @Published private(set) var currentPolicyEvaluation: EnvironmentPolicyEvaluation?
    @Published private(set) var auditOperationMessage = ""
    @Published private(set) var currentEnvironment: CurrentEnvironmentReceipt?
    @Published private(set) var currentEnvironmentIsHistorical = false
    @Published private(set) var detectionError = ""
    @Published private(set) var dnsReceiptError = ""
    @Published private(set) var webRTCReceiptError = ""
    @Published private(set) var sourceNotices: [EnvironmentSourceNotice] = []
    @Published private(set) var accounts: SwitcherAccountState?
    @Published private(set) var currentLogin: ClaudeLoginProbeResult?
    @Published private(set) var loginProbeRunning = false
    @Published private(set) var loginClock = Date()
    @Published private(set) var plan: SwitcherRepairPlan?
    @Published private(set) var planCommand = "repair"
    @Published private(set) var busy = false
    @Published private(set) var waitingForEnvironmentRead = false
    @Published private(set) var message = ""
    @Published private(set) var failure = false
    @Published private(set) var claudeVersion = ""
    @Published private(set) var loaded = false
    @Published private(set) var hasUnsavedSettings = false
    @Published private(set) var proxyGroups: [String] = []
    @Published private(set) var updateRecoveryRequired = false
    @Published private(set) var environment: EnvironmentObservation?
    @Published private(set) var candidate: EnvironmentCandidate?
    @Published private(set) var setupPlan: EnvironmentSetupPlan?
    @Published private(set) var setupRecoveryRequired = false
    @Published private(set) var background: BackgroundServiceReceipt?
    @Published private(set) var backgroundError = ""
    @Published private(set) var readingEnvironment = false
    /// MonitorStore consumes a new observation to refresh the matching IP
    /// quality summary.  No policy/configuration is changed by this callback.
    var onCurrentEnvironment: ((CurrentEnvironmentReceipt) -> Void)?
    var awaitFreshDNSReceipt: (() async -> Bool)?
    var onDNSReceiptRecorded: (() -> Void)?
    var onWebRTCRiskRecorded: (() -> Void)?
    var diagnosticContextProvider: (() -> String?)?
    @Published private(set) var activity = ""
    @Published private(set) var operationLog = ""
    @Published var setupApplyEnvironment = true { didSet { setupPlan = nil } }
    @Published var setupEnablePolicy = true { didSet { setupPlan = nil } }
    @Published var setupGuard = false { didSet { setupPlan = nil } }
    @Published var setupWatchdog = false { didSet { setupPlan = nil } }
    @Published var setupUpdater = false { didSet { setupPlan = nil } }
    @Published var diagnosticProxy = "http://127.0.0.1:7890"
    @Published private(set) var diagnostic: ProxyDiagnosticReceipt?
    @Published private(set) var diagnosticError = ""
    let isFixture: Bool
    private var savedSettings: [String: Any] = [:]
    private var protectionChanges: [String: Bool]?
    private var detectionCancellation: SwitcherReadCancellation?
    private var environmentGeneration = 0
    private var backgroundGeneration = 0
    private var webRTCReceiptGeneration = 0
    private var reviewScenario: SwitcherReviewScenario?
    private var reviewBackground: BackgroundServiceReceipt?
    private var lastLoginProbeAt: Date = .distantPast
    private var loginProbeGeneration = 0
    var dnsRefreshRoot = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/ClaudeWatch/switcher", isDirectory: true)
    private var activityGeneration = 0
    var fixtureEnvironmentReadDelayNanoseconds: UInt64 = 0
    var environmentReadWaitTimeout: TimeInterval = 4

    init(isFixture: Bool = false) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
    }
    func loadReviewScenario(_ scenario: SwitcherReviewScenario) {
        guard isFixture else { return }
        reviewScenario = scenario
        try? consumeStatus(Self.fixtureStatus())
        let now = Date().timeIntervalSince1970
        settings = ["schema": 1, "enabled": true, "online_enabled": true, "guard_enabled": true,
                    "proxy_mode": "auto", "country": "", "timezone": "", "locale": ""]
        savedSettings = settings; hasUnsavedSettings = false; loaded = true
        var environment = try! JSONDecoder().decode(CurrentEnvironmentReceipt.self, from: Self.fixtureCurrentEnvironment(settings: settings))
        var rows = normalizeReviewRows(environment.rows)
        let jp = EgressReference(ip: "8.8.8.8", country: "JP", timezone: "Asia/Tokyo",
                                 context_id: environment.context_id, checked_at: now)
        var facts = ProtectionFacts(state: "ok", risks: [], evidence: nil)
        var blocked: [String] = []
        var previewReady = true
        var transition = EnvironmentContextTransition(state: "stable", changed_fields: [], unavailable: [])
        var guardState = "safe"
        var guardReason: SessionGuardReason?
        switch scenario {
        case .normal:
            break
        case .ipChanged:
            rows = mutate(rows, id: "ip_history", state: "fail", current: "8.8.4.4",
                          detail: "会话建立后出口 IP 已变化；保护已请求退出 Claude。")
            facts = ProtectionFacts(state: "fail", risks: [.init(id: "egress_ip_changed", source: "会话基准", value: "8.8.4.4", reason: "会话出口 IP 与基准不一致。", required: true)], evidence: nil)
            blocked = ["ip_history"]; previewReady = false; guardState = "locked"
            guardReason = .init(code: "egress_ip_changed", detail: "会话出口 IP 已变化，已请求退出 Claude。", source: "会话基准", observed_at: now)
        case .cnRisk:
            rows = mutate(rows, id: "egress", state: "fail", current: "203.0.113.8 / CN",
                          detail: "实测出口位于中国；保护已请求退出 Claude。")
            facts = ProtectionFacts(state: "fail", risks: [.init(id: "egress_country_cn", source: "本轮出口", value: "CN", reason: "检测到中国出口。", required: true)], evidence: nil)
            blocked = ["egress"]; previewReady = false; guardState = "locked"
            guardReason = .init(code: "egress_country_cn", detail: "检测到中国出口，已请求退出 Claude。", source: "本轮出口", observed_at: now)
        case .transientFailure:
            transition = .init(state: "sampling_unavailable", changed_fields: [], unavailable: ["代理控制接口"])
            rows = mutate(rows, id: "proxy", state: "unknown", current: "未取得",
                          detail: "本轮采样未完成；上次有效会话基准仍保留，但不授予启动许可。")
            facts = ProtectionFacts(state: "ok", risks: [], evidence: nil)
            blocked = ["proxy"]; previewReady = false; guardState = "unknown"
        case .evidenceExpired:
            environment.expires_at = now - 1
            rows = mutate(rows, id: "dns", state: "unknown", current: "历史样本",
                          detail: "保护证据已过期，需要重新检测。")
            facts = ProtectionFacts(state: "fail", risks: [.init(id: "evidence_expired", source: "会话保护", value: "", reason: "保护证据已过期。", required: true)], evidence: nil)
            blocked = ["dns"]; guardState = "unknown"
        case .recovered:
            rows = mutate(rows, id: "guard", state: "ok", current: "保护心跳已确认",
                          detail: "风险已恢复；不会自动重新启动 Claude。")
            facts = ProtectionFacts(state: "ok", risks: [], evidence: nil)
            blocked = []; previewReady = true; guardState = "safe"
            auditOperationMessage = "网络已恢复。Claude 保持退出，需由用户手动检查并启动。"
        }
        environment.rows = rows
        environment.context_transition = transition
        environment.facts = facts
        currentEnvironment = environment
        currentEnvironmentIsHistorical = scenario == .evidenceExpired
        let preview = EnvironmentPolicyEvaluation(purpose: "launch_requirements_preview", grants_launch_permission: false,
            observed_at: environment.observed_at, expires_at: environment.expires_at, observation_id: environment.observation_id,
            context_id: environment.context_id, policy: "fixture", rows: rows, blocked: blocked, ready: previewReady,
            message: "隔离同轮启动要求预览。", egress_reference: jp, facts: facts)
        currentPolicyEvaluation = Self.acceptsDisplayPolicy(preview, for: environment, hasUnsavedSettings: false) ? preview : nil
        let base = try! JSONDecoder().decode(BackgroundServiceReceipt.self, from: Self.fixtureBackground(settings: settings))
        background = .init(observed_at: now, backend_healthy: true, update_source_ready: base.update_source_ready,
                           guard_backend_healthy: true, backend_sampling_state: "complete",
                           services: base.services, policy_issues: base.policy_issues, egress_reference: jp, facts: facts,
                           session_guard: .init(state: guardState, baseline: jp,
                                                current: scenario == .ipChanged ? .init(ip: "8.8.4.4", country: "JP", timezone: "Asia/Tokyo", context_id: environment.context_id, checked_at: now) : jp,
                                                reason: guardReason, risk_evidence: nil))
        sourceNotices = []
    }
    func loadReviewReceipts(_ environment: CurrentEnvironmentReceipt, background: BackgroundServiceReceipt) {
        guard isFixture else { return }
        reviewBackground = background
        currentEnvironment = environment
        currentEnvironmentIsHistorical = environment.context_transition?.state == "changed"
        sourceNotices = environment.source_notices ?? []
        currentPolicyEvaluation = environment.policy_evaluation.flatMap {
            Self.acceptsDisplayPolicy($0, for: environment, hasUnsavedSettings: false) ? $0 : nil
        }
        self.background = background
        loaded = true
    }
    func refreshCurrentLogin(force: Bool = false) async {
        advanceLoginClock(Date())
        guard !isFixture else { currentLogin = nil; return }
        guard !loginProbeRunning else { return }
        let now = Date()
        guard force || now.timeIntervalSince(lastLoginProbeAt) >= 10 else { return }
        lastLoginProbeAt = now
        loginProbeGeneration += 1
        let generation = loginProbeGeneration
        loginProbeRunning = true
        defer {
            if generation == loginProbeGeneration { loginProbeRunning = false }
        }
        let result = await Task.detached(priority: .utility) {
            ClaudeLoginProbe.probe(prompt: false)
        }.value
        guard generation == loginProbeGeneration else { return }
        currentLogin = result
    }
    func advanceLoginClock(_ date: Date) {
        loginClock = date
    }
    var currentLoginIsHistorical: Bool {
        guard let login = currentLogin else { return false }
        return Self.isLoginHistorical(observedAt: login.observedAt, now: loginClock.timeIntervalSince1970)
    }
    static func isLoginHistorical(observedAt: Double, now: Double) -> Bool {
        now - observedAt > 90
    }
    static func accountSlotPresentation(_ slot: SwitcherAccountSlot, current: String?) -> AccountSlotPresentation {
        if slot.current {
            return .init(summary: "当前使用", confirmationTitle: "", confirmationDetail: "", actionTitle: "")
        }
        if slot.stored {
            return .init(summary: "已保存 · 点击切换", confirmationTitle: "切换到账号 \(slot.id)",
                         confirmationDetail: "将先保存当前资料，再载入 \(slot.id) 并通过完整检查启动。失败时恢复原资料，登录状态以 Claude 中显示的账号为准。",
                         actionTitle: "切换到 \(slot.id)")
        }
        if slot.id == "A", current == nil {
            return .init(summary: "未保存", confirmationTitle: "将当前资料保存为 A",
                         confirmationDetail: "将当前资料保存为 A 并重新打开 Claude，保持当前登录。无需另行设置账号或网络参数。",
                         actionTitle: "保存当前资料为 A 并打开")
        }
        let source = current ?? "A"
        return .init(summary: "未保存", confirmationTitle: "首次使用账号 \(slot.id)",
                     confirmationDetail: "将先保存当前 \(source) 资料，再打开空的 \(slot.id) 资料。届时在 Claude 中登录所需账号；失败时恢复原资料。",
                     actionTitle: "保存当前并打开 \(slot.id)")
    }
    var currentLoginAccount: ClaudeLoginAccount? {
        guard currentLogin?.state != "app_closed" else { return nil }
        return currentLogin?.account
    }
    var sessionDisplayEvidence: SessionProtectionEvidence? {
        var candidates: [SessionProtectionEvidence] = []
        if let value = background, let session = value.session_guard {
            candidates.append(.init(session: session, observedAt: value.observed_at,
                                    backendReady: value.backend_healthy && value.services.first(where: { $0.id == "guard" })?.healthy == true,
                                    readError: backgroundError))
        }
        if let value = currentEnvironment, let session = value.session_guard {
            candidates.append(.init(session: session, observedAt: value.observed_at,
                                    backendReady: value.rows.first(where: { $0.id == "guard" })?.state == "ok"))
        }
        return SessionProtectionEvidence.latest(candidates)
    }
    var sessionDisplay: SessionProtectionPresentation {
        sessionDisplayEvidence?.presentation(at: loginClock.timeIntervalSince1970) ?? .loading
    }
    func openClaudeWatchAccessibilitySettings() {
        guard !isFixture else { return }
        AccessibilityPermission.request()
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") else { return }
        NSWorkspace.shared.open(url)
    }
    private func mutate(_ rows: [EnvironmentCheckRow], id: String, state: String, current: String, detail: String) -> [EnvironmentCheckRow] {
        rows.map { row in
            guard row.id == id else { return row }
            return .init(id: row.id, name: row.name, state: state, detail: detail, scope: row.scope, required: row.required,
                         current: current, reference: row.reference, source: row.source, sampled_at: row.sampled_at,
                         sample_reused: row.sample_reused, query_error: row.query_error)
        }
    }
    private func normalizeReviewRows(_ rows: [EnvironmentCheckRow]) -> [EnvironmentCheckRow] {
        rows.map { row in
            switch row.id {
            case "stun":
                return .init(id: row.id, name: row.name, state: "ok", detail: "原生 UDP/STUN 完整采样与本轮出口一致。",
                             scope: row.scope, required: row.required, current: "8.8.8.8", reference: "8.8.8.8", source: "隔离 fixture")
            case "routing":
                return .init(id: row.id, name: row.name, state: "ok", detail: "运行规则覆盖已确认。",
                             scope: row.scope, required: row.required, current: "13/13 已覆盖", reference: row.reference, source: "隔离 fixture")
            case "asn":
                return .init(id: row.id, name: row.name, state: "warn", detail: "ASN 注册资料仅供参考。",
                             scope: row.scope, required: row.required, current: "AS2516 · JP", reference: row.reference, source: "隔离 fixture")
            case "reachability":
                return .init(id: row.id, name: row.name, state: "warn", detail: "网页 403 需要浏览器验证；API 401 未提供密钥。",
                             scope: row.scope, required: row.required, current: "网络响应提示 · 网页：HTTP 403 / API：HTTP 401", reference: row.reference, source: "隔离 fixture")
            default: return row
            }
        }
    }
    func text(_ key: String) -> Binding<String> {
        Binding(get: { self.settings[key] as? String ?? "" }, set: { self.settings[key] = $0; self.markDraft() })
    }
    func flag(_ key: String) -> Binding<Bool> {
        Binding(get: { self.settings[key] as? Bool ?? false }, set: { self.settings[key] = $0; self.markDraft() })
    }
    func addresses(_ key: String) -> Binding<String> {
        Binding(get: { (self.settings[key] as? [String] ?? []).joined(separator: ", ") }, set: {
            self.settings[key] = $0.components(separatedBy: CharacterSet(charactersIn: ",，;； \n"))
                .filter { !$0.isEmpty }
            self.markDraft()
        })
    }
    private func markDraft() {
        hasUnsavedSettings = true; plan = nil; setupPlan = nil; audit = nil
        currentPolicyEvaluation = nil
    }
    func discardChanges() { settings = savedSettings; hasUnsavedSettings = false; setupPlan = nil; plan = nil }
    func dismissMessage() { message = "" }
    var policyWarnings: [String] {
        var items: [String] = []
        if settings["auto_update"] as? Bool == true && !updateSourceReady { items.append("保存的自动更新意愿为开启，但发布源与公钥尚未配置。实际状态见后台保护。") }
        return items
    }
    func load(automaticCheck: Bool = false) async {
        guard !busy else { return }
        busy = true
        do {
            let data = isFixture ? Self.fixtureStatus() : try await Task.detached {
                try SwitcherCommandRunner.run(["status"])
            }.value
            try consumeStatus(data)
            loaded = true
        } catch { message = error.localizedDescription; failure = true }
        busy = false
        if loaded { await inspectEnvironment() }
        if automaticCheck { _ = await detectCurrentEnvironment() }
    }
    func save() async {
        guard let data = try? JSONSerialization.data(withJSONObject: settings, options: [.sortedKeys]) else { return }
        await perform(["config", "set", "--apply"], input: data)
    }
    func detectCurrentEnvironment() async -> Bool {
        guard !busy && !readingEnvironment else { return false }
        readingEnvironment = true; detectionError = ""
        let activityToken = beginActivity("读取系统、检测出口并核对环境…")
        environmentGeneration += 1
        let generation = environmentGeneration
        let cancellation = SwitcherReadCancellation(); detectionCancellation = cancellation
        defer { readingEnvironment = false; detectionCancellation = nil; endActivity(activityToken) }
        do {
            if isFixture, fixtureEnvironmentReadDelayNanoseconds > 0 {
                try await Task.sleep(nanoseconds: fixtureEnvironmentReadDelayNanoseconds)
            }
            let data = isFixture ? Self.fixtureCurrentEnvironment(settings: savedSettings) : try await Task.detached {
                try SwitcherCommandRunner.run(["environment", "--online", "--record", "--mode", "auto"], cancellation: cancellation)
            }.value
            try checkedSetupResult(data)
            let result = try JSONDecoder().decode(CurrentEnvironmentReceipt.self, from: data)
            guard result.purpose == "environment_detection", !result.grants_launch_permission else {
                throw NSError(domain: "Switcher", code: 6, userInfo: [NSLocalizedDescriptionKey: "检测结果类型不符，请重新检测。"])
            }
            if !isFixture { GuardDiagnosticLogger.submit(from: data) }
            guard generation == environmentGeneration else { return false }
            currentEnvironment = result
            // A newly received failed/unavailable observation is still current;
            // only an older receipt retained after a later context change is historical.
            currentEnvironmentIsHistorical = false
            sourceNotices = result.source_notices ?? []
            if let preview = result.policy_evaluation,
               Self.acceptsDisplayPolicy(preview, for: result, hasUnsavedSettings: hasUnsavedSettings) {
                currentPolicyEvaluation = preview
            } else {
                currentPolicyEvaluation = nil
            }
            onCurrentEnvironment?(result)
            return result.context_transition?.state == "stable"
        } catch is CancellationError { recordDetectionFailure("本轮检测已取消；下方若有结果，为此前样本。") }
        catch { recordDetectionFailure(error.localizedDescription) }
        return false
    }
    func recordDetectionFailure(_ reason: String) {
        invalidateCurrentEnvironmentRequest()
        detectionError = reason
    }
    func cancelCurrentDetection() {
        environmentGeneration += 1
        detectionCancellation?.cancel()
    }
    private func yieldEnvironmentReadForUserAction() async -> Bool {
        guard readingEnvironment else { return true }
        waitingForEnvironmentRead = true
        cancelCurrentDetection()
        let deadline = Date().addingTimeInterval(environmentReadWaitTimeout)
        while readingEnvironment && Date() < deadline {
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        waitingForEnvironmentRead = false
        return !readingEnvironment
    }
    private func beginActivity(_ text: String) -> Int {
        activityGeneration += 1
        activity = text
        return activityGeneration
    }
    private func updateActivity(_ text: String, token: Int) {
        if token == activityGeneration { activity = text }
    }
    private func endActivity(_ token: Int) {
        if token == activityGeneration { activity = "" }
    }
    static func acceptsDisplayPolicy(_ preview: EnvironmentPolicyEvaluation, for environment: CurrentEnvironmentReceipt,
                                     hasUnsavedSettings: Bool) -> Bool {
        guard let observationID = environment.observation_id, !observationID.isEmpty,
              let contextID = environment.context_id, !contextID.isEmpty else { return false }
        return preview.purpose == "launch_requirements_preview" && !preview.grants_launch_permission &&
            preview.observation_id == observationID && preview.context_id == contextID &&
            !preview.observation_id!.isEmpty && !preview.context_id!.isEmpty &&
            preview.observed_at == environment.observed_at &&
            preview.expires_at == environment.expires_at &&
            !hasUnsavedSettings &&
            (environment.context_transition?.state == "stable" || !preview.ready)
    }
    func invalidateCurrentEnvironmentRequest() {
        environmentGeneration += 1
        detectionCancellation?.cancel()
        currentPolicyEvaluation = nil
        if currentEnvironment != nil { currentEnvironmentIsHistorical = true }
    }
    func recordDNSLeak(_ probe: LeakProbeResult) async -> Bool {
        guard !isFixture else { return true }
        guard let expectedContext = diagnosticContextProvider?(), !expectedContext.isEmpty else {
            dnsReceiptError = "DNS 检测时代理上下文未稳定，未记录为当前网络结果。"
            return false
        }
        do {
            let payload = try JSONEncoder().encode(DNSLeakRecordInput(probe: probe, expected_context: expectedContext))
            let data = try await Task.detached {
                try SwitcherCommandRunner.run(["dns-leak-record", "--apply"], input: payload)
            }.value
            let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
            guard raw["status"] as? String != "error" else {
                throw NSError(domain: "Switcher", code: 7, userInfo: [NSLocalizedDescriptionKey: raw["message"] as? String ?? "DNS 泄漏回执未保存"])
            }
            dnsReceiptError = ""
            guard diagnosticContextProvider?() == expectedContext else {
                dnsReceiptError = "DNS 检测完成后代理上下文已变化，未接受该回执。"
                return false
            }
            // A DNS receipt cannot update only the environment card: the
            // same observation's display-only launch preview would retain its
            // previous DNS row. Keep both views atomic and request a fresh
            // complete environment receipt instead.
            onDNSReceiptRecorded?()
            return true
        } catch {
            dnsReceiptError = "DNS 泄漏结果未能提交给启动预检：" + error.localizedDescription
            return false
        }
    }
    func recordWebRTCRisk(_ probe: LeakProbeResult) async -> Bool {
        webRTCReceiptGeneration += 1
        let generation = webRTCReceiptGeneration
        if isFixture {
            webRTCReceiptError = ""
            return true
        }
        guard let expectedContext = diagnosticContextProvider?(), !expectedContext.isEmpty else {
            if generation == webRTCReceiptGeneration {
                webRTCReceiptError = Self.webRTCSubmissionError(backendMessage: nil, hasContext: false, contextStillMatches: false)
            }
            return false
        }
        do {
            let payload = try JSONEncoder().encode(WebRTCRiskRecordInput(probe: probe, expected_context: expectedContext))
            let data = try await Task.detached {
                try SwitcherCommandRunner.run(["webrtc-risk-record", "--apply"], input: payload)
            }.value
            let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
            let backendMessage = raw["message"] as? String
            guard raw["status"] as? String != "error" else {
                if generation == webRTCReceiptGeneration {
                    webRTCReceiptError = Self.webRTCSubmissionError(backendMessage: backendMessage, hasContext: true, contextStillMatches: true)
                }
                return false
            }
            guard diagnosticContextProvider?() == expectedContext else {
                if generation == webRTCReceiptGeneration {
                    webRTCReceiptError = Self.webRTCSubmissionError(backendMessage: nil, hasContext: true, contextStillMatches: false)
                }
                return false
            }
            guard generation == webRTCReceiptGeneration else { return false }
            webRTCReceiptError = ""
            onWebRTCRiskRecorded?()
            return true
        } catch {
            if generation == webRTCReceiptGeneration {
                webRTCReceiptError = Self.webRTCSubmissionError(backendMessage: error.localizedDescription, hasContext: true, contextStillMatches: true)
            }
            return false
        }
    }
    static func webRTCSubmissionError(backendMessage: String?, hasContext: Bool, contextStillMatches: Bool) -> String {
        if !hasContext { return "本地检测已完成，但当前代理上下文未稳定，未提交当前保护判定。" }
        if !contextStillMatches { return "本地检测完成后代理上下文已变化，未接受该保护判定。" }
        let detail = backendMessage?.trimmingCharacters(in: .whitespacesAndNewlines)
        return "本地检测已完成，但未提交当前保护判定" + ((detail?.isEmpty == false) ? "：" + detail! : "。")
    }
    func setWebRTCReceiptErrorForFixture(_ value: String) {
        guard isFixture else { return }
        webRTCReceiptError = value
    }
    func refreshBackground() async {
        guard !busy else { return }
        backgroundGeneration += 1
        let generation = backgroundGeneration
        do {
            let value: BackgroundServiceReceipt
            if isFixture, let reviewBackground {
                value = reviewBackground
            } else if isFixture {
                value = try JSONDecoder().decode(BackgroundServiceReceipt.self, from: Self.fixtureBackground(settings: savedSettings, scenario: reviewScenario))
            } else {
                let data = try await Task.detached { try SwitcherCommandRunner.run(["service-status"]) }.value
                value = try JSONDecoder().decode(BackgroundServiceReceipt.self, from: data)
            }
            guard generation == backgroundGeneration else { return }
            background = value; backgroundError = ""
        } catch { backgroundError = error.localizedDescription }
    }
    /// First-run reads the same status consumed by the regular pages, with a
    /// success result so an old `loaded` value cannot conceal a failed read.
    func refreshInitializationStatus() async -> Bool {
        guard !busy else { return false }
        busy = true
        defer { busy = false }
        do {
            let data = isFixture ? Self.fixtureStatus() : try await Task.detached {
                try SwitcherCommandRunner.run(["status"])
            }.value
            try consumeStatus(data)
            loaded = true
            return true
        } catch {
            message = error.localizedDescription; failure = true
            return false
        }
    }
    func previewProtection(_ key: String, enable: Bool) async {
        guard !busy, !hasUnsavedSettings else { return }
        protectionChanges = [key: enable]; planCommand = "protection"; plan = nil
        let input = try? JSONSerialization.data(withJSONObject: [key: enable])
        await perform(["protection", "preview"], input: input, refresh: false)
    }
    func checkLaunchConditions() async { await perform(["checkdetail", "--online"]) }
    var setupOptions: [String: Bool] {
        ["apply_environment": setupApplyEnvironment, "enable_policy": setupEnablePolicy,
         "guard_enabled": setupGuard, "timezone_watchdog": setupWatchdog, "auto_update": setupUpdater]
    }
    var updateSourceReady: Bool {
        !(settings["update_url"] as? String ?? "").isEmpty && !(settings["update_public_key"] as? String ?? "").isEmpty
    }
    var setupCanConfirm: Bool {
        guard let setupPlan else { return false }
        return !busy && !hasUnsavedSettings && !setupRecoveryRequired && setupPlan.expires_at > Date().timeIntervalSince1970
    }
    private func checkedSetupResult(_ data: Data) throws {
        let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        if ["error", "partial"].contains(raw["status"] as? String ?? "") {
            if raw["recovery_required"] as? Bool == true { setupRecoveryRequired = true }
            throw NSError(domain: "Switcher", code: 5, userInfo: [NSLocalizedDescriptionKey: raw["message"] as? String ?? "初始化未完成"])
        }
    }
    func inspectEnvironment() async {
        guard !busy else { return }
        busy = true; candidate = nil; setupPlan = nil
        defer { busy = false }
        do {
            let data = isFixture ? Self.fixtureEnvironment(settings: savedSettings) : try await Task.detached {
                try SwitcherCommandRunner.run(["setup", "inspect", "--mode", "auto"])
            }.value
            try checkedSetupResult(data)
            environment = try JSONDecoder().decode(EnvironmentObservation.self, from: data)
            setupRecoveryRequired = environment?.recovery_required ?? false
        } catch { message = error.localizedDescription; failure = true }
    }
    func detectEnvironment() async {
        guard !busy, !hasUnsavedSettings else { return }
        busy = true; candidate = nil; setupPlan = nil
        defer { busy = false }
        do {
            let data = isFixture ? Self.fixtureCandidate(settings: savedSettings) : try await Task.detached {
                try SwitcherCommandRunner.run(["setup", "detect", "--online", "--mode", "auto"])
            }.value
            try checkedSetupResult(data)
            candidate = try JSONDecoder().decode(EnvironmentCandidate.self, from: data)
            message = candidate?.message ?? ""; failure = false
        } catch { message = error.localizedDescription; failure = true }
    }
    func previewEnvironment() async {
        guard !busy, !hasUnsavedSettings, let candidate else { return }
        busy = true; setupPlan = nil
        defer { busy = false }
        do {
            if isFixture {
                setupPlan = .init(id: "fixture-setup", candidate_id: candidate.id, actions: [], rows: candidate.rows, expires_at: candidate.expires_at)
            } else {
                let input = try JSONSerialization.data(withJSONObject: setupOptions)
                let data = try await Task.detached {
                    try SwitcherCommandRunner.run(["setup", "preview", "--candidate-id", candidate.id], input: input)
                }.value
                try checkedSetupResult(data)
                setupPlan = try JSONDecoder().decode(EnvironmentSetupPlan.self, from: data)
            }
            message = "请核对候选目标、选项与系统变更。确认后才会保存基线。"; failure = false
        } catch { message = error.localizedDescription; failure = true }
    }
    func applyEnvironment(refreshDetection: Bool = true) async {
        guard setupCanConfirm, let setupPlan else { return }
        let input = try? JSONSerialization.data(withJSONObject: setupOptions)
        await perform(["setup", "apply", "--candidate-id", setupPlan.candidate_id, "--plan-id", setupPlan.id, "--apply"], input: input)
        self.setupPlan = nil; candidate = nil
        await inspectEnvironment()
        if refreshDetection { _ = await detectCurrentEnvironment() }
    }
    func diagnoseProxy() async {
        guard !busy else { return }
        busy = true
        diagnostic = nil; diagnosticError = ""
        defer { busy = false }
        do {
            // Credentials never enter process arguments, saved settings or status refreshes.
            let input = try JSONSerialization.data(withJSONObject: ["proxy_url": diagnosticProxy])
            let data = isFixture ? Self.fixtureDiagnostic() : try await Task.detached {
                try SwitcherCommandRunner.run(["diagnose-proxy", "--stdin-config"], input: input)
            }.value
            diagnostic = try JSONDecoder().decode(ProxyDiagnosticReceipt.self, from: data)
        } catch { diagnosticError = error.localizedDescription }
    }
    func preview(_ command: String) async {
        plan = nil; planCommand = command; protectionChanges = nil
        await perform([command], refresh: false)
    }
    func applyPreview() async {
        guard let plan else { return }
        if planCommand == "protection", let protectionChanges {
            let input = try? JSONSerialization.data(withJSONObject: protectionChanges)
            await perform(["protection", "apply", "--apply", "--plan-id", plan.id], input: input)
        } else { await perform([planCommand, "--apply", "--plan-id", plan.id]) }
        self.plan = nil
        await refreshBackground()
    }
    private func pollDNSRefreshRequests(_ bridge: DNSRefreshBridge) async {
        var answered = Set<String>()
        while !Task.isCancelled {
            if let id = bridge.pendingRequestID(), !answered.contains(id) {
                answered.insert(id)
                let ready = await awaitFreshDNSReceipt?() ?? false
                guard !Task.isCancelled else { return }
                try? bridge.writeReply(id: id, ready: ready)
            }
            try? await Task.sleep(nanoseconds: 150_000_000)
        }
    }
    private func runAccountSwitchWithDNSRefresh(_ args: [String], input: Data?) async throws -> Data {
        let bridge = try DNSRefreshBridge(root: dnsRefreshRoot)
        let poller = Task { @MainActor [weak self] in
            guard let self else { return }
            await self.pollDNSRefreshRequests(bridge)
        }
        defer {
            poller.cancel()
            bridge.cleanup()
        }
        let token = bridge.token
        return try await Task.detached {
            try SwitcherCommandRunner.run(args, input: input, dnsRefreshToken: token)
        }.value
    }
    func perform(_ args: [String], input: Data? = nil, refresh: Bool = true) async {
        guard !busy else { return }
        busy = true
        let activityToken = beginActivity("等待环境读取结束…")
        defer {
            busy = false
            waitingForEnvironmentRead = false
            endActivity(activityToken)
        }
        guard await yieldEnvironmentReadForUserAction() else {
            failure = true
            let text = "环境读取未在限定时间内结束，未执行此操作。请稍后重试。"
            if args.first == "checkdetail" {
                auditOperationMessage = text; message = ""
            } else {
                message = text
            }
            return
        }
        let requiresFreshDNS = args.first == "checkdetail" || args.first == "launch" ||
            (args.starts(with: ["account", "switch"]) && args.contains("--apply"))
        if requiresFreshDNS, let awaitFreshDNSReceipt {
            updateActivity("正在完成 DNS 泄漏检测并同步启动预检…", token: activityToken)
            let ready = await awaitFreshDNSReceipt()
            guard ready else {
                failure = true
                let failureText = "DNS 泄漏检测未在当前网络上下文内完成，未执行启动预检或启动 Claude。"
                if args.first == "checkdetail" { auditOperationMessage = failureText; message = "" }
                else { message = failureText }
                return
            }
        }
        updateActivity(args.first == "checkdetail" ? "按已接受策略检查启动条件…" : "正在核对并完成操作…", token: activityToken)
        do {
            if isFixture {
                if args.first == "checkdetail" {
                    audit = Self.fixtureAudit()
                    auditOperationMessage = audit?.message ?? ""
                    message = ""
                }
                else if args == ["protection", "preview"], let change = protectionChanges?.first {
                    plan = .init(id: "fixture-protection", actions: [.init(id: "guard", title: "修改后台开关（模拟）", scope: "watch", detail: "\(settings[change.key] as? Bool == true ? "开启" : "关闭") → \(change.value ? "开启" : "关闭")；原版保镖保留")])
                }
                else if args == ["repair"] || args == ["set-region"] {
                    plan = .init(id: "fixture-plan", actions: [.init(id: "timezone", title: "设置时区（模拟）", scope: "administrator", detail: "Asia/Tokyo → Asia/Tokyo")])
                }
                else if args.starts(with: ["config", "set"]) { savedSettings = settings; hasUnsavedSettings = false }
                else if args.starts(with: ["protection", "apply"]), let protectionChanges {
                    for (key, value) in protectionChanges { settings[key] = value }
                    if protectionChanges["guard_enabled"] == true { settings["enabled"] = true }
                    savedSettings = settings
                }
                else if args.first == "logs" { operationLog = "隔离记录：没有访问真实操作日志。" }
                else if args.starts(with: ["account", "switch"]), args.count > 2 {
                    accounts = .init(current: args[2], recovery_required: false, accounts: ["A", "B"].map {
                        .init(id: $0, stored: true, current: $0 == args[2])
                    }, detail: "隔离模拟账号")
                }
                if args.first != "checkdetail" { message = "隔离预览：未访问真实账号、未联网、未执行系统或进程操作。" }
                failure = false
            } else {
                let data: Data
                if args.starts(with: ["account", "switch"]) && args.contains("--apply") {
                    data = try await runAccountSwitchWithDNSRefresh(args, input: input)
                } else {
                    data = try await Task.detached { try SwitcherCommandRunner.run(args, input: input) }.value
                }
                let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
                let status = raw["status"] as? String ?? ""
                failure = ["error", "partial"].contains(status)
                if let value = try? JSONDecoder().decode(EnvironmentAuditReceipt.self, from: data) {
                    audit = value
                    auditOperationMessage = value.message
                    message = ""
                    failure = !value.ready
                } else if let value = try? JSONDecoder().decode(SwitcherRepairPlan.self, from: data), !args.contains("--apply") {
                    plan = value; message = value.actions.isEmpty ? "没有需要应用的修复项。" : "请核对变更列表后再应用。"
                } else {
                    message = raw["message"] as? String ?? (failure ? "操作部分完成，请查看变更记录。" :
                        status == "available" ? "发现新版本；完整应用更新应在退出界面后执行。" : "操作已完成。")
                    if args.first == "launch", status == "ok" {
                        message = "上次操作：启动检查通过并打开 Claude。当前运行状态以上方会话状态为准。"
                    }
                    if args == ["account", "import"] {
                        let found = (raw["accounts"] as? [String] ?? []).joined(separator: "、")
                        let config = raw["settings"] as? [String: String] ?? [:]
                        message = "旧版存档：" + (found.isEmpty ? "无" : found) + "\n"
                            + ["proxy_mode", "country", "timezone", "locale"].compactMap { key in config[key].map { key + " = " + $0 } }.joined(separator: "\n")
                            + "\n仅预览，尚未导入或停用旧后台。"
                    }
                    // A preview that cannot be read as a plan must not report
                    // success with an empty action list: the review sheet would
                    // never open and the button would look unresponsive.
                    if args.count >= 2, args[0] == "protection", args[1] == "preview", !failure {
                        failure = true
                        message = "预览回执未能识别为变更计划，未生成变更列表。请重新预览；若仍然如此，请查看操作记录。"
                    }
                }
                if args.first == "logs" { operationLog = raw["message"] as? String ?? "暂无操作记录" }
                if let result = raw["config"] as? [String: Any], args.first == "config", !failure {
                    settings = result; savedSettings = result; hasUnsavedSettings = false; audit = nil
                }
                if refresh && !(args.first == "config" && failure) {
                    let state = try await Task.detached { try SwitcherCommandRunner.run(["status"]) }.value
                    try consumeStatus(state)
                }
            }
        } catch {
            if args.first == "checkdetail" {
                auditOperationMessage = error.localizedDescription
                message = ""
            } else {
                message = error.localizedDescription
            }
            failure = true
        }
    }
    private func consumeStatus(_ data: Data) throws {
        let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        if raw["status"] as? String == "error" {
            throw NSError(domain: "Switcher", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: raw["message"] as? String ?? "读取未完成"])
        }
        let incoming = raw["config"] as? [String: Any] ?? [:]
        savedSettings = incoming
        if !hasUnsavedSettings { settings = incoming }
        claudeVersion = raw["claude_version"] as? String ?? ""
        proxyGroups = raw["proxy_groups"] as? [String] ?? []
        updateRecoveryRequired = raw["update_recovery_required"] as? Bool ?? false
        setupRecoveryRequired = raw["setup_recovery_required"] as? Bool ?? false
        setupGuard = settings["guard_enabled"] as? Bool ?? false
        setupWatchdog = settings["timezone_watchdog"] as? Bool ?? false
        setupUpdater = settings["auto_update"] as? Bool ?? false
        setupEnablePolicy = settings["enabled"] as? Bool ?? false
        if let object = raw["service_status"] {
            background = try JSONDecoder().decode(BackgroundServiceReceipt.self, from: JSONSerialization.data(withJSONObject: object))
        }
        if let object = raw["accounts"], !(object is NSNull) {
            accounts = try JSONDecoder().decode(SwitcherAccountState.self, from: JSONSerialization.data(withJSONObject: object))
        }
        if let object = raw["audit"], !(object is NSNull) {
            audit = try JSONDecoder().decode(EnvironmentAuditReceipt.self, from: JSONSerialization.data(withJSONObject: object))
        }
    }
    static func fixtureAudit() -> EnvironmentAuditReceipt {
        let names = ["代理内核", "TUN 网卡", "出口国家", "IP 一致性", "时区", "地区与日期格式", "IPv6 策略",
                     "DNS", "UDP/STUN 出口", "保护后台", "代理规则覆盖", "Claude 语言", "ASN 属性", "Claude 服务"]
        let ids = ["proxy", "tun", "egress", "ip_history", "timezone", "locale", "ipv6", "dns", "stun", "guard", "routing", "language", "asn", "reachability"]
        return .init(observed_at: Date().timeIntervalSince1970, expires_at: Date().timeIntervalSince1970 + 30,
                     ready: false, rows: names.enumerated().map {
            .init(id: ids[$0.offset], name: $0.element, state: $0.offset == 8 ? "unknown" : "ok",
                  detail: $0.offset == 8 ? "未取得完整样本；不会显示为通过" : "隔离模拟结果",
                  scope: "模拟", required: true)
        }, blocked: ["stun"], message: "模拟环境存在未知项，未启动真实应用")
    }
    static func fixtureEnvironment(settings: [String: Any] = [:]) -> Data {
        let value: [String: Any] = ["observed_at": Date().timeIntervalSince1970, "initialized": false,
            "candidates": ["tag"], "message": "隔离本机检测；没有联网或修改设置", "recovery_required": false,
            "rows": fixtureEnvironmentRows(settings: settings)]
        return try! JSONSerialization.data(withJSONObject: value)
    }
    static func fixtureCurrentEnvironment(settings: [String: Any] = [:]) -> Data {
        let audit = fixtureAudit()
        let now = Date().timeIntervalSince1970
        let guardOn = settings["guard_enabled"] as? Bool == true && settings["enabled"] as? Bool == true
        let values = ["tag · http://127.0.0.1:7890", "utun4", "8.8.8.8 / JP", "8.8.8.8", "Asia/Tokyo", "ja_JP · 示例 2026/10/23",
                      "已关闭", "8.8.8.8 / JP", "未知", guardOn ? "保护心跳有效" : "保护未启用", "未知", "en-JP", "fixture ISP", "Claude HTTP 403 / API HTTP 401"]
        let references = ["运行进程与监听者身份", "实际 TUN 路由", "本轮两个来源一致", "48 小时检测历史", "Asia/Tokyo（本轮出口）",
                          "ja_JP · 示例 2026/10/23", "实际 IPv6 状态", "本轮 HTTP 出口国家 JP", "8.8.8.8（本轮 HTTP 出口）", "当前心跳", "实际规则证据", "英文偏好", "仅供参考", "响应不代表账号可用"]
        let sources = ["进程清单 / 后台新鲜样本", "ifconfig / route", "Cloudflare + IPinfo", "独立检测历史", "/etc/localtime / IPinfo",
                       "Foundation 日期模板 / AppleLocale / 本轮 GeoIP", "networksetup Ethernet", "dig / Akamai", "原生 UDP/STUN", "保护心跳", "规则 / 连接证据", "系统 AppleLanguages", "IPinfo", "本轮 HTTPS"]
        let states = ["ok", "ok", "ok", "ok", "ok", "ok", "ok", "ok", "unknown", guardOn ? "ok" : "fail", "unknown", "ok", "warn", "warn"]
        let rows: [[String: Any]] = audit.rows.enumerated().map { index, row in
            ["id": row.id, "name": row.name, "state": states[index], "detail": "隔离检测样本；未读取目标配置",
             "scope": row.scope, "required": false, "current": values[index], "reference": references[index], "source": sources[index]]
        }
        return try! JSONSerialization.data(withJSONObject: [
            "status": "ok", "purpose": "environment_detection", "grants_launch_permission": false,
            "observation_id": "fixture-observation-0001", "context_id": "fixture-context-0001",
            // before/after are objects in the backend contract; Swift only
            // renders its stable/changed summary fields and safely ignores
            // opaque diagnostic objects.
            "context_transition": ["state": "stable",
                                   "before": ["proxy": "tag", "network": "en0"],
                                   "after": ["proxy": "tag", "network": "en0"]],
            "observed_at": now, "expires_at": now + 300, "rows": rows, "candidates": ["tag"],
            "egress_reference": ["ip": "8.8.8.8", "country": "JP", "timezone": "Asia/Tokyo", "checked_at": now, "context_id": "fixture-context-0001"],
            "facts": ["state": "ok", "risks": []],
            "policy_evaluation": ["purpose": "launch_requirements_preview", "grants_launch_permission": false,
                                  "observation_id": "fixture-observation-0001", "context_id": "fixture-context-0001",
                                  "observed_at": now, "expires_at": now + 300, "policy": "fixture",
                                  "rows": rows, "blocked": ["stun"], "ready": false,
                                  "egress_reference": ["ip": "8.8.8.8", "country": "JP", "timezone": "Asia/Tokyo", "checked_at": now, "context_id": "fixture-context-0001"],
                                  "facts": ["state": "ok", "risks": []],
                                  "message": "隔离同轮启动要求预览；不生成启动许可。"],
            "message": "模拟本轮实测结果；不会生成启动许可或保存目标。"])
    }
    static func fixtureEnvironmentRows(proposed: Bool = false, settings: [String: Any] = [:]) -> [[String: String]] {
        [("proxy_mode", "代理客户端", "tag", "运行进程身份"),
         ("proxy_url", "HTTP 入口", "http://127.0.0.1:7890", "后台监听者身份样本"),
         ("proxy_group", "代理组", "海外 AI", "TAG 控制接口"),
         ("node", "当前节点", "Japan 1", "TAG 控制接口"),
         ("network_service", "活动网络服务", "Ethernet", "scutil PrimaryService"),
         ("country", "出口国家", proposed ? "JP" : "未知", proposed ? "Cloudflare + IPinfo" : "未联网检测"),
         ("ip", "出口 IP", proposed ? "8.8.8.8" : "未知", proposed ? "Cloudflare + IPinfo" : "未联网检测"),
         ("timezone", "系统时区", "Asia/Tokyo", "/etc/localtime"),
         ("locale", "地区与日期格式", "ja_JP", "Foundation / AppleLocale"),
         ("language", "Claude 语言", "en-JP", "系统 AppleLanguages（Claude 未单独设置）")].map { key, title, current, source in
            ["id": key, "title": title, "current": current, "target": (settings[key] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "未配置",
             "proposed": proposed ? current : "", "source": source, "target_source": "尚未确认",
             "proposed_source": proposed ? source : ""]
        }
    }
    static func fixtureCandidate(settings: [String: Any] = [:]) -> Data {
        let value: [String: Any] = ["id": "fixture-candidate", "observed_at": Date().timeIntervalSince1970,
            "expires_at": Date().timeIntervalSince1970 + 300, "rows": fixtureEnvironmentRows(proposed: true, settings: settings),
            "message": "隔离候选；尚未保存目标或修改系统"]
        return try! JSONSerialization.data(withJSONObject: value)
    }
    static func fixtureStatus() -> Data {
        let raw: [String: Any] = [
            "status": "ok", "config": ["schema": 1, "enabled": false, "proxy_mode": "auto",
                                       "country": "", "timezone": "", "locale": "",
                                       "network_service": "Wi-Fi", "proxy_group": ""],
            "accounts": ["current": NSNull(), "recovery_required": false,
                         "accounts": [["id": "A", "stored": false, "current": false],
                                      ["id": "B", "stored": false, "current": false]],
                         "detail": "隔离账号槽位；没有真实登录信息"],
            "claude_version": "fixture"
        ]
        return try! JSONSerialization.data(withJSONObject: raw)
    }
    static func fixtureDiagnostic() -> Data {
        let raw: [String: Any] = [
            "state": "transport_reached", "message": "隔离模拟：已收到 HTTP 响应，账号状态未验证。",
            "checks": [
                ["name": "anthropic_api", "transport_reached": true, "http_status": 401,
                 "access": "unauthenticated", "elapsed_seconds": 0.1],
                ["name": "claude_web", "transport_reached": true, "http_status": 403,
                 "access": "access_restricted", "elapsed_seconds": 0.2]]]
        return try! JSONSerialization.data(withJSONObject: raw)
    }
    static func fixtureBackground(settings: [String: Any] = [:], scenario: SwitcherReviewScenario? = nil) -> Data {
        let guardOn = settings["guard_enabled"] as? Bool == true && settings["enabled"] as? Bool == true
        let clockOn = settings["timezone_watchdog"] as? Bool == true
        var issues: [[String: String]] = []
        if settings["enabled"] as? Bool != true { issues.append(["id":"policy", "title":"启动策略尚未启用", "detail":"先确认自动检测的环境，再预览启用保护。"] ) }
        let now = Date().timeIntervalSince1970
        let session: [String: Any]
        switch scenario {
        case .ipChanged:
            session = ["state": "locked",
                       "baseline": ["ip": "8.8.8.8", "country": "JP", "observed_at": now, "source": "fixture"],
                       "current": ["ip": "8.8.4.4", "country": "JP", "observed_at": now, "source": "fixture"],
                       "reason": ["code": "egress_ip_changed", "detail": "会话出口 IP 已变化，已请求退出 Claude。", "source": "fixture", "observed_at": now],
                       "locked_at": now]
        case .cnRisk:
            session = ["state": "locked",
                       "baseline": ["ip": "8.8.8.8", "country": "JP", "observed_at": now, "source": "fixture"],
                       "current": ["ip": "203.0.113.8", "country": "CN", "observed_at": now, "source": "fixture"],
                       "reason": ["code": "egress_country_cn", "detail": "检测到中国出口，已请求退出 Claude。", "source": "fixture", "observed_at": now],
                       "locked_at": now]
        case .transientFailure, .evidenceExpired:
            session = ["state": "unknown",
                       "baseline": ["ip": "8.8.8.8", "country": "JP", "observed_at": now, "source": "fixture"],
                       "reason": ["code": "egress_unconfirmed", "detail": "当前风险证据未确认。", "source": "fixture", "observed_at": now]]
        case .recovered:
            session = ["state": "safe",
                       "baseline": ["ip": "8.8.8.8", "country": "JP", "observed_at": now, "source": "fixture"],
                       "current": ["ip": "8.8.8.8", "country": "JP", "observed_at": now, "source": "fixture"]]
        default:
            session = ["state": guardOn ? "safe" : "missing",
                       "baseline": ["ip": "8.8.8.8", "country": "JP", "observed_at": now, "source": "fixture"],
                       "current": ["ip": "8.8.8.8", "country": "JP", "observed_at": now, "source": "fixture"]]
        }
        let raw: [String: Any] = ["observed_at": now, "backend_healthy": true,
            "guard_backend_healthy": true, "backend_sampling_state": "complete",
            "update_source_ready": false, "policy_issues": issues,
            "egress_reference": ["ip": "8.8.8.8", "country": "JP", "timezone": "Asia/Tokyo", "checked_at": now, "context_id": "fixture-context-0001"],
            "facts": ["state": "ok", "risks": []],
            "session_guard": session,
            "services": [
                ["id":"guard", "title":"Claude Watch 保镖", "state":guardOn ? "running" : "inactive", "detail":guardOn ? "后台及保护心跳均有效。" : "保护已停用；后台采集继续运行。", "source":"本工具保护心跳 / 采集后台", "desired":settings["guard_enabled"] as? Bool ?? false],
                ["id":"original", "title":"原版 Claude切换器保镖", "state":"scheduled", "detail":"已加载，每 10 秒检查；最近退出码：0。", "source":"原版系统任务；独立管理"],
                ["id":"watchdog", "title":"时区守护", "state":clockOn ? "scheduled" : "inactive", "detail":clockOn ? "实际目标：Asia/Tokyo；已接受目标：Asia/Tokyo。任务按计划运行。" : "实际目标：未设置；已接受目标：未配置。", "source":"系统任务 / 目标文件", "desired":clockOn],
                ["id":"updater", "title":"自动更新", "state":"unavailable", "detail":"尚未配置本项目发布源与固定公钥。", "source":"发布配置 / 用户任务", "desired":settings["auto_update"] as? Bool ?? false]]]
        return try! JSONSerialization.data(withJSONObject: raw)
    }
}
