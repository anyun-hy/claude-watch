import Foundation
import CryptoKit

struct Health: Decodable, Sendable {
    let state, mode: String
    let pid: Int?
    let heartbeatAge: Double?
    let started, detail, alerts: String
}

struct WatchedProcess: Decodable, Identifiable, Sendable {
    let id: String
    let pid: Int
    let started, kind: String
    let authorized: Bool?
    var runtimeRole: String? = nil
    var serviceName: String? = nil
    var roleEvidence: String? = nil
    var uid: UInt32? = nil
    var startSeconds: UInt64? = nil
    var startMicroseconds: UInt64? = nil
    var matchReason: String? = nil
    var matchRootReason: String? = nil
    var matchParent: ProcessIdentityRefModel? = nil
    var matchRoot: ProcessIdentityRefModel? = nil
    var protection: ProcessProtectionModel? = nil

    var discoveryExplanation: String {
        let label: String
        switch matchReason {
        case "installation_pending": label = "已发现，安装证据待确认"
        case "supported_cli_alias": label = "受支持的 CLI 别名"
        case "known_cli_layout": label = "已知 CLI 安装布局"
        case "verified_bundle": label = "应用包身份"
        case "verified_bundle_component": label = "桌面应用内置组件"
        case "script_entry": label = "实际脚本入口"
        case "managed_app_server": label = "托管 app-server 入口"
        case "launcher_seed": label = "受控启动记录"
        case "retained_lifetime": label = "同一进程生命期跟踪（当前执行程序未直接识别）"
        case "verified_descendant": label = "已确认来源的后代进程"
        default: label = "发现依据未取得"
        }
        return label + (matchParent.map { " · 来源 PID \($0.pid)" } ?? "")
            + (matchRootReason == "launcher_seed" && matchReason != "launcher_seed" ? " · 来自受控启动记录" : "")
    }

    func protectionExplanation(state: FamilyChannelMonitorState?, executorBootId: String?, now: Double, live: Bool) -> String {
        guard live, let proof = protection, now.isFinite, proof.observed_at.isFinite,
              now >= proof.observed_at - 1, now - proof.observed_at < 10 else {
            return "保护未知：未取得当前实例的新鲜证据"
        }
        guard proof.state == "protected" else { return proof.explanation }
        let pending = "待验证：当前身份、策略或执行回执尚未对齐"
        guard let state, state.matchesProcess(self), state.producer_boot_id == proof.producer_boot_id,
              let executorBootId, !executorBootId.isEmpty, executorBootId == proof.executor_boot_id,
              proof.policy_version == state.saved_policy_version, state.applied_policy_version == state.saved_policy_version,
              proof.command_seq == state.command_seq, proof.permit_generation == state.permit_generation,
              proof.vpn_epoch == state.vpn_epoch,
              state.policy_sync_state == .applied,
              let until = proof.valid_until, until.isFinite, until > now,
              state.coverage_scope?.hasRequiredFacts == true, state.coverage_scope?.hasVerifiedEndpoint == true,
              state.backend == "seatbelt", state.coverage_scope?.backend == state.backend,
              state.coverage_scope?.protected_pids.contains(UInt32(max(0, pid))) == true else {
            return pending
        }
        switch state.display_state {
        case .forwarding:
            // Forwarding needs a current permit as well as the Rust proof's
            // receipt/registry/VPN deadline. A newer family state can expire it.
            guard proof.reason_code == "forwarding_verified", state.isPermitted,
                  let permitUntil = state.valid_until, permitUntil.isFinite, permitUntil > now else { return pending }
        case .blocked:
            // Rust bounds this proof by the fresh cutoff receipt and registry,
            // not by the old revoke command's lease. Keep that evidence expiry.
            guard proof.reason_code == "blocked_verified", state.isConfirmedFlowBlocked else { return pending }
        default:
            return pending
        }
        return proof.explanation
    }

    /// Product ownership is derived solely from the stable backend kind contract.
    /// The three-field process records themselves remain unchanged.
    var product: MonitoredProduct {
        if kind.hasPrefix("codex-") || kind.hasPrefix("chatgpt-") || kind.hasPrefix("openai-") {
            return .openAI
        }
        return .claude
    }

    var sourceRole: ProcessSourceRole {
        // The Codex app-server daemon (codex_managed) is OpenAI's self-started
        // background server, not an independently supervised source. It is folded
        // into the desktop source instead of surfacing as a separate "托管后台"
        // node, so closing Codex/ChatGPT leaves no orphan backend card behind.
        if runtimeRole == "codex_managed" && roleEvidence == "managed_app_server" { return .desktop }
        if runtimeRole == "codex_managed_unconfirmed" && roleEvidence == "managed_path_only" { return .child }
        if kind == "code" || kind == "codex-cli" { return .cli }
        if kind.contains("desktop-") { return .desktop }
        // These providers have no standalone CLI kind. The backend has already
        // attributed their descendants to a verified desktop process tree.
        if kind == "openai-child" || kind == "chatgpt-child" { return .desktop }
        // A legacy codex-child may descend from desktop or CLI, or be reparented.
        // Its three-field record does not establish which source owns it.
        return .child
    }

    var productDisplay: String { product.title }
    var sourceDisplay: String {
        switch sourceRole {
        case .cli: return product == .openAI ? "独立 CLI" : "Claude Code"
        case .desktop: return "桌面应用"
        case .managed: return "Codex 托管后台"
        case .child: return "来源待确认"
        }
    }

    var name: String {
        if sourceRole == .managed { return "Codex 托管后台" }
        if runtimeRole == "codex_managed_unconfirmed" && roleEvidence == "managed_path_only" { return "Codex 后台（身份待确认）" }
        switch kind {
        case "desktop-main": return "Claude Desktop"
        case "desktop-helper": return "Desktop 辅助进程"
        case "code": return "Claude Code"
        case "child": return "Claude 关联子进程"
        case "codex-desktop-main": return "Codex Desktop"
        case "codex-desktop-helper": return "Codex Desktop 辅助进程"
        case "codex-cli": return "Codex CLI"
        case "codex-child": return "Codex 关联子进程"
        case "chatgpt-desktop-main": return "ChatGPT Desktop"
        case "chatgpt-desktop-helper": return "ChatGPT Desktop 辅助进程"
        case "chatgpt-child": return "ChatGPT 关联子进程"
        case "openai-desktop-main": return "ChatGPT 桌面应用"
        case "openai-desktop-helper": return "ChatGPT 桌面辅助进程"
        case "openai-child": return "ChatGPT 桌面关联子进程"
        default: return "关联子进程"
        }
    }
}

struct ProcessIdentityRefModel: Codable, Equatable, Sendable {
    let pid, uid: UInt32
    let start_seconds, start_microseconds: UInt64
}

struct ProcessProtectionModel: Codable, Equatable, Sendable {
    let state, reason_code: String
    let observed_at: Double
    let producer_boot_id: String?
    let executor_boot_id: String?
    let policy_version: ChannelPolicyVersionModel?
    let valid_until: Double?
    let audit_identity_digest: String?
    let command_seq: UInt64?
    let permit_generation: UInt64?
    let vpn_epoch: VpnEpochModel?

    var explanation: String {
        switch reason_code {
        case "external_unmanaged_process": return "发现但未保护：未经过受控入口"
        case "target_approval_changed", "retained_policy_changed", "unexpected_exec_image_change", "executable_evidence_changed", "member_identity_or_file_evidence_changed": return "未保护：入口、身份、文件或批准证据已变化"
        case "exec_audit_token_changed", "instance_birth_time_mismatch": return "未保护：执行身份已变化"
        case "gateway_endpoint_proof_missing": return "待验证：网关端点证明缺失"
        case "pending_apply": return "待验证：等待执行器应用"
        case "current_vpn_path_evidence_unverified": return "待验证：当前 VPN 路径或周期证据未确认"
        case "coverage_evidence_unverified": return "保护未知：当前覆盖范围证据未确认"
        case "current_process_identity_unverified": return "保护未知：当前进程身份未确认"
        case "authority_stale_or_mismatched": return "保护未知：监督器证据已过期或不匹配"
        case "registry_evidence_unavailable": return "保护未知：未取得受控实例证据"
        case "current_member_token_unverified": return "待验证：当前成员身份未确认"
        case "current_permit_identity_or_epoch_unverified": return "待验证：当前许可或 VPN 周期未确认"
        case "execution_receipt_missing", "execution_pending": return "待验证：执行回执尚未确认"
        case "execution_failed": return "未保护：执行失败"
        case "forwarding_verified": return "已保护：当前身份获准转发"
        case "blocked_verified": return "已保护：已确认断流，进程保留"
        case "sandbox_identity_pending_or_stale": return "待验证：沙箱或执行身份尚未确认"
        default: return state == "unprotected" ? "未保护：\(reason_code)" : "保护未知：\(reason_code)"
        }
    }
}

enum ProcessSourceRole: Sendable, Equatable {
    case cli, desktop, managed, child
}

enum MonitoredProduct: String, CaseIterable, Identifiable, Sendable, Hashable {
    case claude
    case openAI

    var id: String { rawValue }
    var title: String {
        switch self {
        case .claude: return "Claude"
        case .openAI: return "ChatGPT / Codex"
        }
    }
    var graphDesktopTitle: String {
        switch self {
        case .claude: return "Claude Desktop"
        case .openAI: return "ChatGPT"
        }
    }
    var graphCLITitle: String {
        switch self {
        case .claude: return "Claude Code"
        case .openAI: return "Codex CLI"
        }
    }
    func covered(by apps: [String]) -> Bool {
        switch self {
        case .claude: return apps.contains("claude")
        case .openAI: return apps.contains("codex") && apps.contains("chatgpt")
        }
    }
}

struct Event: Decodable, Identifiable, Sendable {
    let id, timestamp: String
    let epoch: Double?
    let severity, category, title, detail: String
    var rawDetail: String? = nil
    var explanation: String? = nil
}

struct Flow: Decodable, Identifiable, Sendable {
    let id: String
    let pid: Int
    let host, peer, local, transport, association, policy, reason: String
    let chains: [String]
    let routePath: String?
    let interfaceName: String?
    var destinationIP: String? = nil
    var destinationPort: Int? = nil
    var destinationIPState: String? = nil
    var destinationCountry: String? = nil
    enum CodingKeys: String, CodingKey {
        case id, pid, host, peer, local, association, policy, reason, chains
        case transport = "protocol"
        case routePath = "path"
        case interfaceName = "interface"
        case destinationIP, destinationPort, destinationIPState, destinationCountry
    }
}

struct ProxySnapshot: Decodable, Sendable {
    let observedAt: Double
    let entryState, entryReason, entrySource, endpoint: String
    let listenerPID: Int?
    let listenerPath, apiState, apiReason, mode: String
    let coversProxy: Bool
    let expectedGroup, expectedNode, selectedNode, globalNode: String
    let pinned, selectionChanged: Bool
    var flows: [Flow]
    var listenerStarted: String? = nil
    var connectionObservation: ConnectionObservation? = nil
    var connectionObservationIsComplete: Bool {
        guard let observation = connectionObservation else { return false }
        return observedAt.isFinite && observation.complete && abs(observation.observedAt - observedAt) <= 5
    }
    var currentNode: String { mode == "global" ? globalNode : selectedNode }
    var selectionDiffers: Bool {
        !currentNode.isEmpty && !expectedNode.isEmpty && currentNode != expectedNode
    }
    func retainingFlows(_ values: [Flow]) -> ProxySnapshot {
        var result = self
        result.flows = values
        return result
    }
}

/// Coverage of one connection collection round, independent of route safety.
struct ConnectionObservation: Decodable, Sendable {
    let schema: Int
    let roundID: String
    let observedAt: Double
    let collectorState: String
    let targetCount, parsedCount, acceptedCount, correlatedCount, unconfirmedCount: Int
    let dropped: [String: Int]
    let detail: String
    let uiFilteredCount: Int
    let uiDropped: [String: Int]

    var complete: Bool {
        schema == 1 && !roundID.isEmpty && observedAt.isFinite
            && ["ok", "empty", "no_targets"].contains(collectorState)
            && [targetCount, parsedCount, acceptedCount, correlatedCount, unconfirmedCount].allSatisfy { $0 >= 0 }
            && acceptedCount <= parsedCount && correlatedCount + unconfirmedCount <= acceptedCount
            && dropped.values.allSatisfy { $0 == 0 } && uiFilteredCount == 0 && uiDropped.values.allSatisfy { $0 == 0 }
            && (collectorState != "no_targets" || (targetCount == 0 && acceptedCount == 0))
            && (collectorState != "empty" || (targetCount > 0 && parsedCount == 0 && acceptedCount == 0))
            && (collectorState != "ok" || acceptedCount > 0)
    }
}

struct ChannelPolicyVersionModel: Codable, Equatable, Sendable {
    let policy_digest: String
    let guard_policy_digest: String
}

enum ChannelMonitorDisplayState: String, Codable, Equatable, Sendable {
    case pendingVerification = "pending_verification"
    case forwarding = "forwarding"
    case disconnecting = "disconnecting"
    case blocked = "blocked"
    case failed = "failed"

    var labelZh: String {
        switch self {
        case .pendingVerification: return "待验证"
        case .forwarding: return "获准转发"
        case .disconnecting: return "正在断开"
        case .blocked: return "已阻断"
        case .failed: return "执行失败"
        }
    }
}

enum PolicySyncState: String, Codable, Equatable, Sendable {
    case applied = "applied"
    case pendingApply = "pending_apply"
    case applyFailed = "apply_failed"

    var labelZh: String {
        switch self {
        case .applied: return "执行器已应用"
        case .pendingApply: return "配置已保存（待执行器应用）"
        case .applyFailed: return "配置已保存（执行器应用失败）"
        }
    }
}

struct BoundProcessTokenModel: Codable, Equatable, Sendable {
    let pid: UInt32
    let uid: UInt32
    let start_seconds: UInt64
    let start_microseconds: UInt64
    let role: String
    let audit_token: [UInt32]?

    var auditIdentityDigest: String? {
        guard let audit_token, audit_token.count == 8 else { return nil }
        let data = Data(audit_token.map(String.init).joined(separator: ":").utf8)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

struct VpnEpochModel: Codable, Equatable, Sendable {
    let observer_boot_id: String
    let change_generation: UInt64
}

struct BackendCoverageScopeModel: Codable, Equatable, Sendable {
    let backend: String
    let configured_entries: [String]
    let protected_pids: [UInt32]
    let unprotected_pids: [UInt32]
    let uncovered_boundaries: [String]
    let server_identity_verified: Bool
    let gateway_endpoint_protection_verified: Bool
    let gateway_endpoint_protection_method: String?
    private(set) var hasRequiredFacts: Bool = true

    enum CodingKeys: String, CodingKey {
        case backend, configured_entries, protected_pids, unprotected_pids, uncovered_boundaries
        case server_identity_verified, gateway_endpoint_protection_verified, gateway_endpoint_protection_method
    }

    init(backend: String, configured_entries: [String], protected_pids: [UInt32],
         unprotected_pids: [UInt32], uncovered_boundaries: [String], server_identity_verified: Bool,
         gateway_endpoint_protection_verified: Bool, gateway_endpoint_protection_method: String?) {
        self.backend = backend
        self.configured_entries = configured_entries
        self.protected_pids = protected_pids
        self.unprotected_pids = unprotected_pids
        self.uncovered_boundaries = uncovered_boundaries
        self.server_identity_verified = server_identity_verified
        self.gateway_endpoint_protection_verified = gateway_endpoint_protection_verified
        self.gateway_endpoint_protection_method = gateway_endpoint_protection_method
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        backend = try values.decodeIfPresent(String.self, forKey: .backend) ?? "unknown"
        configured_entries = try values.decodeIfPresent([String].self, forKey: .configured_entries) ?? []
        protected_pids = try values.decodeIfPresent([UInt32].self, forKey: .protected_pids) ?? []
        unprotected_pids = try values.decodeIfPresent([UInt32].self, forKey: .unprotected_pids) ?? []
        uncovered_boundaries = try values.decodeIfPresent([String].self, forKey: .uncovered_boundaries) ?? []
        server_identity_verified = try values.decodeIfPresent(Bool.self, forKey: .server_identity_verified) ?? false
        gateway_endpoint_protection_verified = try values.decodeIfPresent(Bool.self, forKey: .gateway_endpoint_protection_verified) ?? false
        gateway_endpoint_protection_method = try values.decodeIfPresent(String.self, forKey: .gateway_endpoint_protection_method)
        var complete = true
        for key in [CodingKeys.backend, .configured_entries, .protected_pids, .unprotected_pids,
                    .uncovered_boundaries, .server_identity_verified] {
            if !values.contains(key) { complete = false; continue }
            if try values.decodeNil(forKey: key) { complete = false }
        }
        hasRequiredFacts = complete
    }

    var hasVerifiedEndpoint: Bool {
        server_identity_verified || (gateway_endpoint_protection_verified
            && gateway_endpoint_protection_method?.isEmpty == false)
    }

    /// Coverage is an observed set, separate from backend capabilities and permits.
    var allDiscoveredProtected: Bool {
        hasRequiredFacts && ["seatbelt", "network_extension"].contains(backend)
            && hasVerifiedEndpoint && !configured_entries.isEmpty && !protected_pids.isEmpty && unprotected_pids.isEmpty
    }
}

struct FamilyChannelMonitorState: Codable, Equatable, Sendable {
    var producer_boot_id: String = ""
    let family: String
    let session_id: String?
    let saved_policy_version: ChannelPolicyVersionModel
    let applied_policy_version: ChannelPolicyVersionModel?
    let policy_sync_state: PolicySyncState
    let policy_sync_label_zh: String
    let permit_generation: UInt64
    let command_seq: UInt64
    let permit_state: String
    let display_state: ChannelMonitorDisplayState
    let display_label_zh: String
    let reason_code: String
    let process_preserved: Bool
    let active_member_pids: [UInt32]
    var active_members: [BoundProcessTokenModel] = []
    var local_proxy_ready: Bool = false
    var system_extension_active: Bool = false
    let active_flows_count: UInt32
    let terminated_flows_count: UInt32
    let blocked_new_connections: UInt32
    var local_proxy_port: UInt16? = nil
    var valid_until: Double? = nil
    let updated_at: Double
    var backend: String? = nil
    var vpn_epoch: VpnEpochModel? = nil
    var coverage_scope: BackendCoverageScopeModel? = nil
    var unmanaged_member_pids: [UInt32]? = nil
    var sandbox_ready: Bool? = nil

    var isPermitted: Bool {
        permit_state == "permitted"
    }

    var hasUnmanagedMembers: Bool {
        !(unmanaged_member_pids ?? []).isEmpty
    }

    /// True only when a real executor flow-termination receipt has been applied
    /// (`display_state == .blocked` and `policy_sync_state == .applied`).
    /// Never true while `pending_apply` or `disconnecting`.
    var isConfirmedFlowBlocked: Bool {
        display_state == .blocked && policy_sync_state == .applied && active_flows_count == 0
    }

    /// Binds network flows and process rows to the same supervised session and
    /// policy version so stale flows or another session's processes are never
    /// mixed with the current channel disposition.
    func matchesProcess(_ process: WatchedProcess) -> Bool {
        guard let uid = process.uid, let seconds = process.startSeconds, let microseconds = process.startMicroseconds,
              let digest = process.protection?.audit_identity_digest else { return false }
        return active_members.contains { token in
            token.pid == UInt32(max(0, process.pid)) && token.uid == uid && token.start_seconds == seconds
                && token.start_microseconds == microseconds && token.auditIdentityDigest == digest
        }
    }

    func isUnmanagedProcess(_ process: WatchedProcess) -> Bool {
        let pid = UInt32(max(0, process.pid))
        if unmanaged_member_pids?.contains(pid) == true {
            return true
        }
        return !matchesProcess(process)
    }
}

struct ChannelMonitorSnapshot: Codable, Equatable, Sendable {
    var producer_boot_id: String = ""
    let snapshot_seq: UInt64
    let captured_at: Double
    let saved_policy_version: ChannelPolicyVersionModel
    let families: [String: FamilyChannelMonitorState]
    var executor_boot_id: String? = nil
}

struct ChannelMonitorEvent: Codable, Equatable, Sendable {
    var producer_boot_id: String = ""
    let event_seq: UInt64
    let family_state: FamilyChannelMonitorState
}

enum ChannelSubscriptionApplyOutcome: Equatable, Sendable {
    case applied
    case ignoredStaleEvent
    case gapDetectedResyncRequired(expectedSeq: UInt64, receivedSeq: UInt64)
}

struct ChannelMonitorSubscriptionStore: Sendable {
    private(set) var producerBootId: String? = nil
    private(set) var lastEventSeq: UInt64 = 0
    private(set) var needsResync: Bool = true
    private(set) var savedPolicyVersion: ChannelPolicyVersionModel? = nil
    private(set) var families: [String: FamilyChannelMonitorState] = [:]

    mutating func markReconnected() {
        needsResync = true
    }

    @discardableResult
    mutating func applySnapshot(_ snapshot: ChannelMonitorSnapshot) -> Bool {
        let bootIdChanged = !snapshot.producer_boot_id.isEmpty
            && producerBootId != nil
            && !producerBootId!.isEmpty
            && producerBootId != snapshot.producer_boot_id
        if snapshot.snapshot_seq < lastEventSeq && !needsResync && !bootIdChanged {
            return false
        }
        if !snapshot.producer_boot_id.isEmpty {
            producerBootId = snapshot.producer_boot_id
        }
        lastEventSeq = snapshot.snapshot_seq
        savedPolicyVersion = snapshot.saved_policy_version
        families = snapshot.families
        needsResync = false
        return true
    }

    mutating func applyEvent(_ event: ChannelMonitorEvent) -> ChannelSubscriptionApplyOutcome {
        let eventBootId = !event.producer_boot_id.isEmpty
            ? event.producer_boot_id
            : event.family_state.producer_boot_id
        if !eventBootId.isEmpty
            && producerBootId != nil
            && !producerBootId!.isEmpty
            && producerBootId != eventBootId
        {
            needsResync = true
            return .gapDetectedResyncRequired(
                expectedSeq: lastEventSeq + 1,
                receivedSeq: event.event_seq
            )
        }
        if needsResync {
            return .gapDetectedResyncRequired(
                expectedSeq: lastEventSeq + 1,
                receivedSeq: event.event_seq
            )
        }
        if event.event_seq <= lastEventSeq {
            return .ignoredStaleEvent
        }
        if event.event_seq > lastEventSeq + 1 {
            needsResync = true
            return .gapDetectedResyncRequired(
                expectedSeq: lastEventSeq + 1,
                receivedSeq: event.event_seq
            )
        }
        if let existing = families[event.family_state.family] {
            if event.family_state.permit_generation < existing.permit_generation
                || (event.family_state.permit_generation == existing.permit_generation
                    && event.family_state.command_seq < existing.command_seq)
            {
                return .ignoredStaleEvent
            }
        }
        lastEventSeq = event.event_seq
        savedPolicyVersion = event.family_state.saved_policy_version
        families[event.family_state.family] = event.family_state
        return .applied
    }

    /// Returns the effective display state for `family`, degrading to
    /// `.pendingVerification` if the subscriber is disconnected (`!live`),
    /// requires resync (`needsResync`), or the state is older than `maxAge`.
    func effectiveState(
        for family: String,
        now: Double,
        live: Bool,
        maxAge: Double = 30.0
    ) -> FamilyChannelMonitorState? {
        guard let state = families[family] else {
            return nil
        }
        let expired = !now.isFinite || !state.updated_at.isFinite || now < state.updated_at - 1 || (now - state.updated_at) > maxAge
        if !live || needsResync || expired {
            return FamilyChannelMonitorState(
                family: state.family,
                session_id: state.session_id,
                saved_policy_version: state.saved_policy_version,
                applied_policy_version: state.applied_policy_version,
                policy_sync_state: state.policy_sync_state,
                policy_sync_label_zh: state.policy_sync_label_zh,
                permit_generation: state.permit_generation,
                command_seq: state.command_seq,
                permit_state: state.permit_state,
                display_state: .pendingVerification,
                display_label_zh: "待验证（订阅失联或状态已过期）",
                reason_code: "subscription_stale_or_disconnected",
                process_preserved: state.process_preserved,
                active_member_pids: state.active_member_pids,
                active_flows_count: state.active_flows_count,
                terminated_flows_count: state.terminated_flows_count,
                blocked_new_connections: state.blocked_new_connections,
                updated_at: state.updated_at,
                backend: state.backend,
                vpn_epoch: state.vpn_epoch,
                coverage_scope: state.coverage_scope,
                unmanaged_member_pids: state.unmanaged_member_pids,
                sandbox_ready: state.sandbox_ready
            )
        }
        return state
    }
}

struct VpnFieldDiffModel: Codable, Equatable, Sendable {
    let field: String
    let expected: String
    let observed: String
}

struct VpnExpectationModel: Codable, Equatable, Sendable {
    var configured: Bool = false
    var proxy_mode: String = "auto"
    var proxy_url: String = ""
    var proxy_group: String = ""
    var running_mode: String? = nil
    var require_tun: Bool? = nil
    var require_system_proxy: Bool? = nil
    var expected_node: String? = nil
    var expected_chain: [String] = []
    var expected_rules_digest: String? = nil

    init(
        configured: Bool = false,
        proxy_mode: String = "auto",
        proxy_url: String = "",
        proxy_group: String = "",
        running_mode: String? = nil,
        require_tun: Bool? = nil,
        require_system_proxy: Bool? = nil,
        expected_node: String? = nil,
        expected_chain: [String] = [],
        expected_rules_digest: String? = nil
    ) {
        self.configured = configured
        self.proxy_mode = proxy_mode
        self.proxy_url = proxy_url
        self.proxy_group = proxy_group
        self.running_mode = running_mode
        self.require_tun = require_tun
        self.require_system_proxy = require_system_proxy
        self.expected_node = expected_node
        self.expected_chain = expected_chain
        self.expected_rules_digest = expected_rules_digest
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        configured = try container.decodeIfPresent(Bool.self, forKey: .configured) ?? false
        proxy_mode = try container.decodeIfPresent(String.self, forKey: .proxy_mode) ?? "auto"
        proxy_url = try container.decodeIfPresent(String.self, forKey: .proxy_url) ?? ""
        proxy_group = try container.decodeIfPresent(String.self, forKey: .proxy_group) ?? ""
        running_mode = try container.decodeIfPresent(String.self, forKey: .running_mode)
        require_tun = try container.decodeIfPresent(Bool.self, forKey: .require_tun)
        require_system_proxy = try container.decodeIfPresent(Bool.self, forKey: .require_system_proxy)
        expected_node = try container.decodeIfPresent(String.self, forKey: .expected_node)
        expected_chain = try container.decodeIfPresent([String].self, forKey: .expected_chain) ?? []
        expected_rules_digest = try container.decodeIfPresent(String.self, forKey: .expected_rules_digest)
    }
}

struct VpnMatchModel: Codable, Equatable, Sendable {
    let state: String
    var differences: [VpnFieldDiffModel]? = nil
    var reasons: [String]? = nil

    enum CodingKeys: String, CodingKey { case verdict, state, differences, reasons }

    init(state: String, differences: [VpnFieldDiffModel]? = nil, reasons: [String]? = nil) {
        self.state = state; self.differences = differences; self.reasons = reasons
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        let verdict = try values.decodeIfPresent(String.self, forKey: .verdict)
        let legacy = try values.decodeIfPresent(String.self, forKey: .state)
        differences = try values.decodeIfPresent([VpnFieldDiffModel].self, forKey: .differences)
        reasons = try values.decodeIfPresent([String].self, forKey: .reasons)
        if let verdict, let legacy, verdict != legacy {
            state = "unknown"; reasons = (reasons ?? []) + ["vpn_match_wire_conflict"]
        } else if let value = verdict ?? legacy, ["matched", "mismatched", "unknown", "stale"].contains(value) {
            state = value
        } else {
            state = "unknown"; reasons = (reasons ?? []) + ["vpn_match_verdict_missing_or_unsupported"]
        }
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(state, forKey: .verdict)
        try values.encodeIfPresent(differences, forKey: .differences)
        try values.encodeIfPresent(reasons, forKey: .reasons)
    }
}

struct VpnSupervisionSnapshotModel: Codable, Equatable, Sendable {
    let captured_at: Double
    var network_backend: String? = nil
    var requires_migration: Bool? = nil
    var expectation: VpnExpectationModel? = nil
    var unavailable_reason: String? = nil
    var vpn_match: VpnMatchModel? = nil

    var differences: [VpnFieldDiffModel] {
        vpn_match?.differences ?? []
    }

    var unknownOrStaleReasons: [String] {
        var out: [String] = []
        if let reason = unavailable_reason, !reason.isEmpty {
            out.append(reason)
        }
        if vpn_match?.state == "stale" {
            out.append("vpn_observation_stale")
        }
        if let reasons = vpn_match?.reasons {
            for r in reasons where !out.contains(r) {
                out.append(r)
            }
        }
        return out
    }
}

/// Discovery completeness describes installation evidence, never protection.
struct TargetDiscoveryStatusModel: Decodable, Equatable, Sendable {
    let revision: String
    let complete: Bool
    let issues: [String]
}

struct MonitorSnapshot: Decodable, Sendable {
    let capturedAt: Double
    let health: Health
    let installed, autoStart, keepAlive, hasBaseline: Bool
    let stderrBytes: Int
    let processes: [WatchedProcess]
    let events: [Event]
    let proxy: ProxySnapshot?
    let proxyError: String?
    var channelSupervision: ChannelMonitorSnapshot? = nil
    var channelEvents: [ChannelMonitorEvent]? = nil
    var vpnSupervision: VpnSupervisionSnapshotModel? = nil
    var targetDiscovery: TargetDiscoveryStatusModel? = nil
    let logPath: String
    /// Absent when an older installed script has not yet published multi-product capability.
    let backendVersion: String?
    let monitoredApps: [String]?
    var eventError: String? = nil
}

