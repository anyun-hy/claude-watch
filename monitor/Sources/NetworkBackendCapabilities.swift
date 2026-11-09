import Foundation

/// Capabilities and coverage scope of the packaged network supervision backend
/// (`seatbelt` vs `network-extension`).
enum NetworkBackendCapabilities {
    static func currentBackend() -> String {
        if let env = ProcessInfo.processInfo.environment["CW_NETWORK_BACKEND"], !env.isEmpty {
            return env
        }
        if let url = Bundle.main.url(forResource: "BuildInfo", withExtension: "plist"),
           let values = NSDictionary(contentsOf: url),
           let raw = values["NetworkBackend"] as? String, !raw.isEmpty {
            return raw
        }
        return "seatbelt"
    }

    static func runtimeBackend(from settings: [String: Any]) -> String {
        if let explicit = settings["network_backend"] as? String, !explicit.isEmpty {
            return explicit == "nono" ? "seatbelt" : explicit
        }
        let schema = settings["schema"] as? Int ?? 1
        return schema >= 2 ? "seatbelt" : "network-extension"
    }

    static func requiresLegacyMigration(from settings: [String: Any]) -> Bool {
        guard !settings.isEmpty else { return false }
        let schema = settings["schema"] as? Int ?? 1
        let explicit = settings["network_backend"] as? String
        return isSeatbeltBackend() && schema < 2 && (explicit == nil || explicit?.isEmpty == true)
    }

    static func isBackendAligned(with settings: [String: Any]) -> Bool {
        if settings.isEmpty { return true }
        if requiresLegacyMigration(from: settings) { return false }
        let pkg = isSeatbeltBackend() ? "seatbelt" : "network-extension"
        return runtimeBackend(from: settings) == pkg
    }

    static func isSeatbeltBackend() -> Bool {
        let backend = currentBackend()
        return backend == "seatbelt" || backend == "nono"
    }

    static func requiresSystemExtensionActivation() -> Bool {
        !isSeatbeltBackend()
    }

    static func coverageScopeSummaryZh() -> String {
        if isSeatbeltBackend() {
            return "受控入口启动的 AI 进程树受 nono/Seatbelt 沙箱与本地网关监管；绕过受控入口直接启动的未受控实例将显示为未受保护 (running_unprotected)"
        }
        return "系统透明网络扩展按进程身份拦截受管 AI 流量"
    }
}

