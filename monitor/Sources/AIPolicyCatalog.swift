import Foundation

/// One selectable disposition for a drift criterion.
struct PolicyAction: Identifiable, Hashable {
    let id: String
    let title: String
    static let force = PolicyAction(id: "force", title: "强制退出 (终止应用)")
    static let close = PolicyAction(id: "close", title: "断流保护 (保留应用)")
    static let warn = PolicyAction(id: "warn", title: "仅提示 (不阻断，VPN节点异常硬门禁除外)")
}

/// One criterion of a service's disposition policy. Its config key is derived
/// from the family that owns it, so a family cannot name a key the backend
/// does not declare.
struct PolicyCriterion: Identifiable {
    let id: String
    let title: String
    /// Assumed value when this criterion's key is absent. A criterion whose
    /// backend default differs from its family's keeps that value here, so the
    /// UI can never show a title the backend would not resolve to.
    var fallback: String? = nil
}

/// Disposition policy for one AI service.
///
/// Rust declares the criterion set, policy defaults, keys and allowed
/// actions. GeneratedPolicyCatalog.swift is produced from that Rust source;
/// this Swift type contains only localized presentation details.
struct AIServicePolicy: Identifiable {
    let id: String
    let title: String
    let subtitle: String
    /// Prefix of this family's configuration keys, matching the backend
    /// catalog. A key is always `{keyPrefix}_close_{criterion.id}`.
    let keyPrefix: String
    let criteria: [PolicyCriterion]
    let actions: [PolicyAction]
    /// Assumed when a key of this family is absent.
    let defaultAction: String
    /// Shown only when this service's options differ from the full set.
    let note: String?
    func setting(_ criterion: PolicyCriterion) -> ChoiceSetting {
        .init(key: "\(keyPrefix)_close_\(criterion.id)", fallback: criterion.fallback ?? defaultAction)
    }
    func actionTitle(_ id: String) -> String {
        actions.first { $0.id == id }?.title ?? actions.last?.title ?? id
    }
}

enum AIPolicyCatalog {
    // Criteria, configuration keys, defaults and selectable actions come
    // exclusively from Rust policy.rs via GeneratedPolicyCatalog.swift.
    // Only localized presentation strings live in this file.
    static let services: [AIServicePolicy] = GeneratedPolicyCatalog.families.map { family in
        let isClaude = family.id == "claude"
        let criteria = family.criteria.map { item in
            PolicyCriterion(id: item.id, title: criterionTitle(item.id, isClaude: isClaude),
                            fallback: item.fallback)
        }
        let actions: [PolicyAction] = family.actions.compactMap { action in
            switch action {
            case "force": return .force
            case "close": return .close
            case "warn": return .warn
            default: return nil  // Generator refuses an unsupported action.
            }
        }
        return AIServicePolicy(
            id: family.id,
            title: isClaude ? "Claude 会话处置策略" : "ChatGPT / Codex 会话处置策略",
            subtitle: isClaude
                ? "会话建立时记录当时的出口 IP、DNS 递归出口与 WebRTC 公网候选作为基线；运行中任一项偏离基线即按下表处置。探针采样缺失或过期只提示、不处置。"
                : "与 Claude 分开保存，改动互不影响。判据沿用同一台机器本轮的出口、DNS 递归出口与 WebRTC 公网候选。",
            keyPrefix: family.keyPrefix,
            criteria: criteria,
            actions: actions,
            defaultAction: family.defaultAction,
            note: nil
        )
    }

    private static func criterionTitle(_ id: String, isClaude: Bool) -> String {
        switch id {
        case "ip": return "出口 IP 变化"
        case "cn": return "出口国家为中国大陆"
        case "dns": return isClaude ? "DNS 递归出口偏离会话基线" : "DNS 递归出口偏离"
        case "webrtc": return isClaude ? "WebRTC 公网候选偏离会话基线" : "WebRTC 公网候选偏离"
        case "session": return "未能建立受管会话"
        default: return "未识别判据（" + id + "）"
        }
    }

    /// The policy a monitored product maps to. Claude and ChatGPT / Codex
    /// are separate families; key ownership comes from the generated rows.
    static func service(for product: MonitoredProduct) -> AIServicePolicy {
        let wanted = product == .claude ? "claude" : "openai"
        return services.first { $0.id == wanted } ?? services[0]
    }

    /// One-line, read-only display of the same criteria as the policy panel.
    static func summary(for product: MonitoredProduct, settings: [String: Any]) -> String {
        let policy = service(for: product)
        let parts = policy.criteria.map { criterion in
            let key = policy.setting(criterion).key
            let stored = settings[key] as? String
            let actionID = stored ?? criterion.fallback ?? policy.defaultAction
            return "\(criterion.title)→\(policy.actionTitle(actionID))"
        }
        return parts.joined(separator: " · ")
    }
}
