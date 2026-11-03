import Foundation

enum SetupProgressPhase: String, CaseIterable, Sendable {
    case verifyEgress = "verify_egress"
    case requestAdministrator = "request_administrator"
    case applySettings = "apply_settings"
    case verifySettings = "verify_settings"
    case saveBaseline = "save_baseline"
    case restoreSettings = "restore_settings"
    case collectEvidence = "collect_evidence"
    case verifyLaunchConditions = "verify_launch_conditions"
    case bindSession = "bind_session"
    case openApplication = "open_application"
    var detail: String {
        switch self {
        case .verifyEgress: return "正在复核出口 IP、国家与时区…"
        case .requestAdministrator: return "正在请求管理员权限，请留意 macOS 系统授权窗口并完成已确认操作…"
        case .applySettings: return "正在应用已确认的设置…"
        case .verifySettings: return "正在回读系统设置与后台状态…"
        case .saveBaseline: return "正在核对并保存本次环境基线…"
        case .restoreSettings: return "操作未完成，正在按事务记录恢复…"
        case .collectEvidence: return "正在实测出口、DNS、WebRTC 与服务响应…"
        case .verifyLaunchConditions: return "正在按已接受策略核对启动条件…"
        case .bindSession: return "正在登记受管会话…"
        case .openApplication: return "正在打开应用并确认主进程…"
        }
    }
    /// Which stage of the pre-launch check this is, for the progress row next to
    /// the launch button. The setup phases do not belong to a launch.
    var launchStage: Int? {
        switch self {
        case .collectEvidence: return 1
        case .verifyLaunchConditions: return 2
        case .bindSession, .openApplication: return 3
        default: return nil
        }
    }
    static let launchStageCount = 3
}
typealias SetupProgressObserver = @MainActor @Sendable (SetupProgressPhase) -> Void

/// One bounded status-only stderr stream, scoped to one owned setup child.
/// Neither arbitrary stderr nor a completed child's late event reaches the UI.
final class SetupProgressReader: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = Data()
    private var dropping = false
    private var active = true
    private let receive: @Sendable (SetupProgressPhase, SetupProgressReader) -> Void
    init(receive: @escaping @Sendable (SetupProgressPhase, SetupProgressReader) -> Void) { self.receive = receive }
    var isActive: Bool { lock.lock(); defer { lock.unlock() }; return active }
    func consume(_ data: Data) {
        lock.lock()
        guard active else { lock.unlock(); return }
        var phases: [SetupProgressPhase] = []
        for byte in data {
            if byte == 10 {
                if !dropping, let line = String(data: buffer, encoding: .utf8),
                   line.hasPrefix("CW_SETUP_PROGRESS:"),
                   let phase = SetupProgressPhase(rawValue: String(line.dropFirst(18))), phases.count < 64 { phases.append(phase) }
                buffer.removeAll(keepingCapacity: true); dropping = false
            } else if buffer.count < 128 && !dropping { buffer.append(byte) }
            else { buffer.removeAll(keepingCapacity: true); dropping = true }
        }
        lock.unlock()
        for phase in phases { receive(phase, self) }
    }
    func finish() {
        lock.lock(); defer { lock.unlock() }
        active = false; buffer.removeAll(); dropping = false
    }
}
