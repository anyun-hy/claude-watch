import Foundation

@main
struct MonitorLoginClockTests {
    @MainActor
    static func main() {
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
        print("MonitorLoginClockTests: 2 assertions passed")
    }
}
