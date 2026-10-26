import Foundation

@main
struct NetCoffeeStoreTests {
    @MainActor
    static func main() {
        func expect(_ value: Bool, _ message: String) {
            guard value else { fputs("FAIL: \(message)\n", stderr); exit(1) }
        }
        let store = NetCoffeeStore()
        let now = Date().timeIntervalSince1970
        let good = CoffeeReceipt(kind: "lookup", query: "1.1.1.1", sourceURL: "fixture",
                                 queriedAt: now - 1, finishedAt: now - 1, status: "complete",
                                 httpStatus: 200, raw: "{}", data: .object(["ip": .string("1.1.1.1")]), error: nil)
        store.ingest(good)
        expect(store.report("1.1.1.1")?.status == "complete" && store.isFreshLookup("1.1.1.1"),
               "complete lookup enters the shared fresh cache")
        store.ingest(.failure("lookup", query: "1.1.1.1", "timeout"))
        expect(store.report("1.1.1.1")?.status == "complete", "failed lookup never overwrites last good data")
        let stale = CoffeeReceipt(kind: "lookup", query: "8.8.8.8", sourceURL: "fixture",
                                  queriedAt: now - 301, finishedAt: now - 301, status: "complete",
                                  httpStatus: 200, raw: "{}", data: .object(["ip": .string("8.8.8.8")]), error: nil)
        store.ingest(stale)
        expect(!store.isFreshLookup("8.8.8.8"), "original query time controls TTL without renewal")
        let historicalData = try! JSONEncoder().encode(stale)
        let historical = try! JSONDecoder().decode(CoffeeJSON.self, from: historicalData)
        var backoff = CoffeeReceipt.failure("lookup", query: "8.8.8.8", "upstream cooldown")
        backoff.last_good = historical
        let restarted = NetCoffeeStore()
        restarted.ingest(backoff)
        expect(restarted.report("8.8.8.8")?.queriedAt == stale.queriedAt && !restarted.isFreshLookup("8.8.8.8"),
               "a restarted store restores same-IP last good data without renewing TTL")
        var wrongBackoff = CoffeeReceipt.failure("lookup", query: "1.1.1.1", "upstream cooldown")
        wrongBackoff.last_good = historical
        let rejected = NetCoffeeStore()
        rejected.ingest(wrongBackoff)
        expect(rejected.report("1.1.1.1") == nil, "last good data for a different IP is rejected")
        print("NetCoffeeStoreTests: 5 assertions passed")
    }
}
