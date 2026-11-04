import Foundation

enum Page: String, CaseIterable {
    case overview = "监控概览", network = "代理与连接", processes = "进程活动", events = "事件记录"
    case dns = "DNS 泄漏检测", webrtc = "WebRTC 泄漏检测"
    case ipScore = "IP 评分"
    case claudeAI = "Claude AI 检测", gptAI = "GPT / Codex 检测"
    case switcher = "启动与账号", environment = "环境状态", protection = "后台保护"
    static let primaryPages: [Page] = [.environment, .switcher, .protection]
    static let monitorPages: [Page] = [.overview, .network, .processes, .events]
    static var orderedPages: [Page] { primaryPages + monitorPages + diagnosticPages }
    static func restored(_ value: String) -> Page { value == "安全启动与账号" ? .environment : Page(rawValue: value) ?? .environment }
    var isPrimary: Bool { Self.primaryPages.contains(self) }
    var isLeakCheck: Bool { self == .dns || self == .webrtc }
    var isManualCheck: Bool { isLeakCheck || self == .ipScore || self == .claudeAI || self == .gptAI || isPrimary }
    static let diagnosticPages: [Page] = [.claudeAI, .gptAI, .ipScore, .dns, .webrtc]
    var symbol: String {
        switch self {
        case .overview: return "square.grid.2x2"
        case .network: return "point.3.connected.trianglepath.dotted"
        case .processes: return "waveform.path"
        case .events: return "clock.arrow.circlepath"
        case .dns: return "network"
        case .webrtc: return "antenna.radiowaves.left.and.right"
        case .switcher: return "person.crop.circle.badge.checkmark"
        case .environment: return "globe.asia.australia"
        case .protection: return "shield.lefthalf.filled"
        case .claudeAI: return "sparkles"
        case .ipScore: return "gauge.with.dots.needle.50percent"
        case .gptAI: return "terminal"
        }
    }
    var caption: String {
        switch self {
        case .overview: return "后台状态、入口与当前检测结果"
        case .network: return "区分代理设置与实际连接证据"
        case .processes: return "Claude 及关联进程的最近一次采样"
        case .events: return "查看和筛选本地保留的事件与检测记录"
        case .dns: return "手动检查 DNS 递归出口与预期解析器"
        case .webrtc: return "手动检查当前 WebView 的公网候选和 HTTP 出口"
        case .switcher: return "启动条件、Claude 启动与本地资料槽位"
        case .environment: return "自动识别代理，核对本轮实测环境"
        case .protection: return "两套保镖、时区守护与更新任务的实际状态"
        case .claudeAI: return "Claude 域名的代理诊断与现有连接证据"
        case .ipScore: return "Net.Coffee 原始评分、IP 属性与情报"
        case .gptAI: return "ChatGPT / API 入口的代理诊断与现有连接证据"
        }
    }
}
