import Foundation

@main
struct EnvironmentRefreshSchedulerTests {
    static func main() {
        var count = 0
        func expect(_ value: Bool, _ message: String) {
            guard value else { fputs("FAIL: \(message)\n", stderr); exit(1) }
            count += 1
        }
        var scheduler = EnvironmentRefreshScheduler()
        let base = Date(timeIntervalSince1970: 1_792_713_600)

        expect(scheduler.claim(context: "A", now: base, switcherBusy: false) == nil,
               "first valid snapshot only establishes a candidate")
        expect(scheduler.claim(context: "A", now: base.addingTimeInterval(2), switcherBusy: false) == .initial,
               "second stable snapshot starts the initial observation")
        scheduler.complete(context: "A", accepted: true, now: base.addingTimeInterval(3))

        for offset in [64.0, 125.0, 186.0] {
            expect(scheduler.claim(context: "A", now: base.addingTimeInterval(offset), switcherBusy: false) == .interval,
                   "stable context refreshes every 60 seconds")
            scheduler.complete(context: "A", accepted: true, now: base.addingTimeInterval(offset + 1))
        }

        expect(scheduler.claim(context: nil, now: base.addingTimeInterval(190), switcherBusy: false) == nil,
               "transient empty context never triggers a new observation")
        expect(scheduler.claim(context: "B", now: base.addingTimeInterval(192), switcherBusy: false) == nil,
               "first new context snapshot is debounced")
        expect(scheduler.claim(context: "B", now: base.addingTimeInterval(194), switcherBusy: false) == .changed,
               "two stable new-context snapshots trigger one changed observation")
        scheduler.complete(context: "B", accepted: false, now: base.addingTimeInterval(195))
        expect(scheduler.claim(context: "B", now: base.addingTimeInterval(199), switcherBusy: false) == nil,
               "failed observation uses bounded retry instead of immediate looping")
        expect(scheduler.claim(context: "B", now: base.addingTimeInterval(200), switcherBusy: false) == .retry,
               "failed observation retries after its bounded delay")
        scheduler.complete(context: "B", accepted: true, now: base.addingTimeInterval(201))
        expect(scheduler.stableContext == "B", "recovered observation commits the stable context")
        print("EnvironmentRefreshSchedulerTests: \(count) assertions passed")
    }
}
