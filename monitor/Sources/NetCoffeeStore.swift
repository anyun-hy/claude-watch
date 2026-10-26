import Foundation
import Combine

@MainActor
final class NetCoffeeStore: ObservableObject {
    @Published var query = ""
    @Published private(set) var reports: [String: CoffeeReceipt] = [:]
    @Published private(set) var riskReports: [String: CoffeeReceipt] = [:]
    @Published private(set) var running = Set<String>()
    @Published private(set) var message: String?
    @Published private(set) var selectedIP = ""
    private var requests: [String: CoffeeRequest] = [:]
    private var generations: [String: UUID] = [:]
    private let lookupTTL: TimeInterval = 300
    let isFixture: Bool
    init(isFixture: Bool = false) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
        if self.isFixture { loadFixture() }
    }
    func report(_ ip: String) -> CoffeeReceipt? { LeakIPAddress(ip).flatMap { reports[$0.canonical] } }
    func isFreshLookup(_ ip: String, now: Date = Date()) -> Bool {
        guard let receipt = report(ip) else { return false }
        return now.timeIntervalSince1970 - receipt.queriedAt >= 0 && now.timeIntervalSince1970 - receipt.queriedAt < lookupTTL
    }
    private func isFreshRisk(_ ip: String, now: Date = Date()) -> Bool {
        guard let receipt = LeakIPAddress(ip).flatMap({ riskReports[$0.canonical] }) else { return false }
        return now.timeIntervalSince1970 - receipt.queriedAt >= 0 && now.timeIntervalSince1970 - receipt.queriedAt < lookupTTL
    }
    private func validLookup(_ receipt: CoffeeReceipt, for ip: String) -> Bool {
        receipt.kind == "lookup" && receipt.status == "complete" && receipt.httpStatus == 200 &&
            receipt.data != nil && LeakIPAddress(receipt.query)?.canonical == ip &&
            receipt.data?["ip"]?.text.flatMap(LeakIPAddress.init)?.canonical == ip
    }
    private func decodeLastGood(_ value: CoffeeJSON?) -> CoffeeReceipt? {
        guard let value, let bytes = try? JSONEncoder().encode(value) else { return nil }
        return try? JSONDecoder().decode(CoffeeReceipt.self, from: bytes)
    }
    /// Environment observations and the score page share this one cache.
    /// Failed refreshes leave the last complete receipt intact and never renew it.
    func ingest(_ receipt: CoffeeReceipt) {
        guard let ip = LeakIPAddress(receipt.query), ip.isPublic else { return }
        if validLookup(receipt, for: ip.canonical) {
            reports[ip.canonical] = receipt
            if message?.hasPrefix("Net.Coffee") == true { message = nil }
        } else {
            if let historical = decodeLastGood(receipt.last_good), validLookup(historical, for: ip.canonical) {
                // Keep historical queriedAt unchanged: this is display evidence,
                // never a renewed current-environment lookup.
                reports[ip.canonical] = historical
            }
            message = "Net.Coffee 查询未完成：" + (receipt.error ?? receipt.status)
        }
    }
    func selectedForPage(_ ip: String) { selectedIP = LeakIPAddress(ip)?.canonical ?? "" }
    var isQuerying: Bool { running.contains(selectedIP) || running.contains("_current") }
    func cancelQuery() { cancel(running.contains("_current") ? "_current" : selectedIP) }
    private func currentExit() {
        guard !running.contains("_current") else { return }
        if isFixture { message = "隔离预览只使用已录制的指定 IP 样本。"; return }
        let key = "_current", id = UUID(), request = CoffeeRequest()
        requests[key] = request; generations[key] = id; running.insert(key); message = "正在读取 7890 诊断路径的 HTTP 出口"
        Task { [weak self] in
            let r = await Task.detached(priority: .utility) { request.run(kind: "trace", query: "") }.value
            guard let self, self.generations[key] == id else { return }
            self.requests[key] = nil; self.generations[key] = nil; self.running.remove(key)
            guard r.status == "complete", let line = r.raw.split(separator:"\n").first(where:{$0.hasPrefix("ip=")}) else { self.message = r.error ?? "未取得代理 HTTP 出口"; return }
            self.start(String(line.dropFirst(3)))
        }
    }
    func fetchAI(_ input: String) {
        guard let ip = LeakIPAddress(input), ip.isPublic else { return }
        fetch(ip.canonical)
        let key = "risk:"+ip.canonical
        guard !running.contains(key) else { return }
        if isFreshRisk(ip.canonical) { return }
        if isFixture {
            if let url = Bundle.main.url(forResource:"coffee-risk-"+ip.canonical,withExtension:"json"), let data = try? Data(contentsOf:url), let r = try? JSONDecoder().decode(CoffeeReceipt.self,from:data) { riskReports[ip.canonical] = r }
            return
        }
        let id = UUID(), request = CoffeeRequest(); requests[key] = request; generations[key] = id; running.insert(key)
        Task { [weak self] in
            let r = await Task.detached(priority:.utility) { request.run(kind:"risk",query:ip.canonical) }.value
            guard let self, self.generations[key] == id else { return }
            self.requests[key] = nil; self.generations[key] = nil; self.running.remove(key)
            if r.status == "complete" { self.riskReports[ip.canonical] = r }
            else { self.message = "Net.Coffee 风险查询未完成：" + (r.error ?? r.status) }
        }
    }
    func start(_ input: String? = nil) {
        let candidate = (input ?? query).trimmingCharacters(in: .whitespacesAndNewlines)
        if candidate.isEmpty { currentExit(); return }
        guard let ip = LeakIPAddress(candidate), ip.isPublic else { message = "请输入有效的公网 IPv4 或 IPv6；本机、虚拟和保留地址不提交查询。"; return }
        if isQuerying { cancelQuery() }
        query = ip.canonical; selectedIP = ip.canonical; fetch(ip.canonical)
    }
    func fetch(_ ip: String) {
        guard let parsed = LeakIPAddress(ip), parsed.isPublic else { return }
        let key = parsed.canonical
        guard !running.contains(key) else { return }
        if isFreshLookup(key) { return }
        message = nil
        if isFixture {
            loadFixture()
            if reports[key] == nil { message = "隔离预览没有该 IP 的录制样本，未访问网络。" }
            return
        }
        let id = UUID(), request = CoffeeRequest(); requests[key] = request; generations[key] = id
        running.insert(key)
        Task { [weak self] in
            let receipt = await Task.detached(priority: .utility) { request.run(kind: "lookup", query: key) }.value
            guard let self, self.generations[key] == id else { return }
            self.requests[key] = nil; self.generations[key] = nil; self.running.remove(key)
            self.ingest(receipt)
        }
    }
    func cancel(_ ip: String) { generations[ip] = nil; requests[ip]?.cancel(); requests[ip] = nil; running.remove(ip) }
    func loadFixture() {
        guard isFixture else { return }
        for ip in ["1.1.1.1","8.8.8.8"] {
            if let url = Bundle.main.url(forResource: "coffee-lookup-\(ip)", withExtension: "json"), let bytes = try? Data(contentsOf: url), let r = try? JSONDecoder().decode(CoffeeReceipt.self, from: bytes) { reports[ip] = r }
        }
        if let url = Bundle.main.url(forResource:"coffee-lookup-current",withExtension:"json"), let bytes = try? Data(contentsOf:url), let r = try? JSONDecoder().decode(CoffeeReceipt.self,from:bytes) {
            reports[r.query] = r
            if selectedIP.isEmpty { selectedIP = r.query; query = selectedIP }
        }
        if selectedIP.isEmpty { selectedIP = "1.1.1.1"; query = selectedIP }
    }
}
