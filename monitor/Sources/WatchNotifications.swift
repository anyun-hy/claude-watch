import AppKit
import Foundation
import UserNotifications

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
