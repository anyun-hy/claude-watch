import Foundation
import UserNotifications

@main
struct MonitorLoginClockTests {
    @MainActor
    static func main() async {
        func expect(_ value: Bool, _ message: String) {
            guard value else { fputs("FAIL: \\(message)\\n", stderr); exit(1) }
        }
        let monitor = MonitorStore()
        monitor.automatic = false
        let tick = Date(timeIntervalSince1970: 1_792_900_000)
        monitor.monitorTick(at: tick)
        expect(monitor.switcher.loginClock == tick, "disabled automatic refresh still advances login freshness clock")
        monitor.monitorTick(at: tick.addingTimeInterval(2))
        expect(monitor.switcher.loginClock == tick.addingTimeInterval(2), "each timer tick advances login clock without AX work")
        let denied = WatchNotificationAccess.classify(.denied, alert: .disabled, style: .none)
        expect(denied == .denied && WatchNotificationAccess.summary(mode: "开启", access: denied).contains("系统未授权"),
               "enabled Watch alerts do not imply system notification permission")
        expect(WatchNotificationAccess.classify(.authorized, alert: .enabled, style: .banner) == .allowed,
               "granted notification permission is shown separately")
        expect(WatchNotificationAccess.classify(.authorized, alert: .disabled, style: .none) == .noBanner,
               "disabled notification banners are visible")
        expect(WatchNotificationAccess.classify(.provisional, alert: .enabled, style: .banner) == .quiet,
               "provisional permission does not promise visible banners")
        expect(WatchNotificationAccess.summary(mode: "静默", access: .allowed).contains("静默"),
               "Watch mute remains visible even when macOS allows notifications")
        await monitor.refreshNotificationAccess()
        expect(monitor.notificationAccess == .unknown, "fixture does not query or change macOS permissions")
        var delayed: CheckedContinuation<Void, Never>?
        let earlier = Task {
            await monitor.refreshNotificationAccessForFixture {
                await withCheckedContinuation { delayed = $0 }
                return .denied
            }
        }
        for _ in 0..<1000 {
            if delayed != nil { break }
            await Task.yield()
        }
        guard let delayed else { fatalError("earlier permission read did not start") }
        await monitor.refreshNotificationAccessForFixture { .allowed }
        delayed.resume()
        await earlier.value
        expect(monitor.notificationAccess == .allowed, "a late old permission read cannot overwrite a newer one")
        print("MonitorLoginClockTests: clock and notification-state checks passed")
    }
}
