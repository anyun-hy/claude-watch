import Foundation

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

struct MonitorSnapshot: Decodable, Sendable {
    let capturedAt: Double
    let health: Health
    let installed, autoStart, keepAlive, hasBaseline: Bool
    let stderrBytes: Int
    let processes: [WatchedProcess]
    let events: [Event]
    let proxy: ProxySnapshot?
    let proxyError: String?
    let logPath: String
    /// Absent when an older installed script has not yet published multi-product capability.
    let backendVersion: String?
    let monitoredApps: [String]?
    var eventError: String? = nil
}

