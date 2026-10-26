import Foundation

@main
struct RefreshGateTests {
    static func main() {
        var checks = 0
        func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
            guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
            checks += 1
        }
        var gate = MonitorRefreshGate()
        expect(gate.request(manual: false), "automatic read starts")
        expect(!gate.manualVisible, "automatic read never activates manual indicator")
        expect(!gate.request(manual: false), "automatic ticks cannot overlap")
        expect(!gate.request(manual: true), "manual request waits for active read")
        expect(gate.manualVisible, "explicit request gets feedback")
        expect(!gate.request(manual: true), "repeated requests coalesce")
        expect(gate.complete(), "queued manual read must execute")
        expect(gate.manualVisible, "feedback persists across queued read")
        expect(gate.request(manual: true), "queued read starts")
        expect(!gate.request(manual: false), "background cannot interrupt manual read")
        expect(!gate.complete(), "only one manual read was queued")
        expect(!gate.manualVisible && !gate.reading, "manual state clears after completion")
        expect(gate.request(manual: false), "automatic synchronization resumes")
        expect(!gate.manualVisible, "resumed polling stays silent")
        expect(!gate.complete(), "ordinary completion has no extra work")
        print("RefreshGateTests: \(checks) assertions passed")
    }
}
