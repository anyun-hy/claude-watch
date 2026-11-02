import Foundation

/// One selectable disposition for a drift criterion.
struct PolicyAction: Identifiable, Hashable {
    let id: String
    let title: String
    static let force = PolicyAction(id: "force", title: "强制关闭")
    static let close = PolicyAction(id: "close", title: "正常关闭")
    static let warn = PolicyAction(id: "warn", title: "仅提示")
}

/// One criterion of a service's disposition policy. Its config key is derived
/// from the family that owns it, so a family cannot name a key the backend
/// does not declare.
struct PolicyCriterion: Identifiable {
    let id: String
    let title: String
}

/// Disposition policy for one AI service.
///
/// The services are deliberately not the same shape. Claude's session is
/// supervised end to end, so it can be asked to exit; ChatGPT / Codex has no
/// automatic exit path, so the only action it can be configured to take is a
/// notice. That difference lives here as data: what the UI offers, what it
/// writes and what the backend accepts all read the same declaration, so no
/// caller can offer an action the service cannot perform.
///
/// Adding a criterion or widening a service's capability is one edit in this
/// catalog plus the matching backend family — never a second copy of the rows.
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
        .init(key: "\(keyPrefix)_close_\(criterion.id)", fallback: defaultAction)
    }
    func actionTitle(_ id: String) -> String {
        actions.first { $0.id == id }?.title ?? actions.last?.title ?? id
    }
}

enum AIPolicyCatalog {
    static let services: [AIServicePolicy] = [claude, openAI]
    private static let claude = AIServicePolicy(
        id: "claude",
        title: "Claude 会话处置策略",
        subtitle: "会话建立时记录当时的出口 IP、DNS 递归出口与 WebRTC 公网候选作为基线；运行中任一项偏离基线即按下表处置。探针采样缺失或过期只提示、不处置。",
        keyPrefix: "claude",
        criteria: [
            .init(id: "ip", title: "出口 IP 变化"),
            .init(id: "cn", title: "出口国家为中国大陆"),
            .init(id: "dns", title: "DNS 递归出口偏离会话基线"),
            .init(id: "webrtc", title: "WebRTC 公网候选偏离会话基线"),
        ],
        actions: [.force, .close, .warn],
        defaultAction: "force",
        note: nil
    )
    private static let openAI = AIServicePolicy(
        id: "openai",
        title: "ChatGPT / Codex 会话处置策略",
        subtitle: "与 Claude 分开保存，改动互不影响。判据沿用同一台机器本轮的出口、DNS 递归出口与 WebRTC 公网候选。",
        keyPrefix: "gpt",
        criteria: [
            .init(id: "ip", title: "出口 IP 变化"),
            .init(id: "cn", title: "出口国家为中国大陆"),
            .init(id: "dns", title: "DNS 递归出口偏离"),
            .init(id: "webrtc", title: "WebRTC 公网候选偏离"),
        ],
        actions: [.warn],
        defaultAction: "warn",
        note: "该服务当前没有自动退出通路，因此只提供提示：检测到偏离时记录并提示，不会结束 ChatGPT / Codex 的进程。等退出动作接入后，在这里补上动作即可，Claude 的配置不受影响。"
    )
}
