import AppKit
import Foundation
import UserNotifications

extension Notification.Name {
    static let watchNotificationPermissionChanged = Notification.Name("watchNotificationPermissionChanged")
}

/// System permission is separate from the Watch notification-mode setting.
enum WatchNotificationAccess: Equatable {
    case unknown, notDetermined, denied, allowed, quiet, noBanner

    static func classify(_ authorization: UNAuthorizationStatus, alert: UNNotificationSetting,
                         style: UNAlertStyle) -> Self {
        switch authorization {
        case .notDetermined: return .notDetermined
        case .denied: return .denied
        case .provisional: return .quiet
        case .authorized: return alert == .disabled || style == .none ? .noBanner : .allowed
        @unknown default: return .unknown
        }
    }

    var label: String {
        switch self {
        case .unknown: return "系统权限待核对"
        case .notDetermined: return "系统授权待确认"
        case .denied: return "系统未授权"
        case .allowed: return "系统已授权"
        case .quiet: return "系统仅允许静默通知"
        case .noBanner: return "系统横幅未启用"
        }
    }
    var notice: String? {
        switch self {
        case .denied: return "系统通知当前未获授权，提醒无法送达；保护判断不依赖通知。"
        case .notDetermined: return "系统通知尚未完成授权；保护判断不依赖通知。"
        case .quiet: return "系统当前只允许静默通知；保护判断不依赖通知。"
        case .noBanner: return "系统通知横幅未启用；保护判断不依赖通知。"
        case .unknown, .allowed: return nil
        }
    }
    static func summary(mode: String?, access: Self) -> String {
        let modeText = mode.map { "软件：" + $0 } ?? "软件状态待读取"
        return modeText + " · " + access.label
    }
}

/// A separate invocation of the app's own executable, used by the persistent
/// Rust agent even when the application window is closed. It never prompts for
/// permission: the normal app is responsible for requesting authorization.
enum WatchNotificationWorker {
    @MainActor static func run(arguments: [String]) -> Never {
        guard arguments.count == 6, arguments[1] == "--notification-deliver",
              ["critical", "warning", "info"].contains(arguments[2]),
              ["events", "environment", "protection"].contains(arguments[3]),
              !arguments[4].isEmpty, !arguments[5].isEmpty,
              Bundle.main.bundleIdentifier == "io.local.watchpanel" else { exit(2) }
        let app = NSApplication.shared
        app.setActivationPolicy(.prohibited)
        let center = UNUserNotificationCenter.current()
        let severity = arguments[2], destination = arguments[3], title = arguments[4], message = arguments[5]
        func finish(_ status: Int32) {
            if status != 0 { fputs("notification_unavailable\n", stderr) }
            exit(status)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { finish(1) }
        center.getNotificationSettings { settings in
            guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else {
                DispatchQueue.main.async { finish(3) }
                return
            }
            let content = UNMutableNotificationContent()
            content.title = title
            content.body = message
            content.userInfo = ["destination": destination]
            if severity == "critical" { content.sound = .default }
            let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
            UNUserNotificationCenter.current().add(request) { error in DispatchQueue.main.async { finish(error == nil ? 0 : 1) } }
        }
        app.run()
        exit(1)
    }
}
