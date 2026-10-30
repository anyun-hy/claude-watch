import Foundation

// Preserve unknown fields and nested source data across API changes.
indirect enum CoffeeJSON: Codable, Sendable {
    case object([String: CoffeeJSON]), array([CoffeeJSON]), string(String), number(Double), bool(Bool), null
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([String: CoffeeJSON].self) { self = .object(v) }
        else { self = .array(try c.decode([CoffeeJSON].self)) }
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .object(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .bool(let v): try c.encode(v)
        case .null: try c.encodeNil()
        }
    }
    subscript(_ key: String) -> CoffeeJSON? { if case .object(let v) = self { return v[key] }; return nil }
    var text: String? {
        switch self { case .string(let v): return v; case .number(let v): return v.rounded() == v ? String(format: "%.0f", v) : String(v); case .bool(let v): return v ? "是" : "否"; default: return nil }
    }
    var number: Double? { if case .number(let v) = self { return v }; return nil }
    var flag: Bool? { if case .bool(let v) = self { return v }; return nil }
    var pretty: String { guard let d = try? JSONEncoder.pretty.encode(self) else { return "null" }; return String(decoding: d, as: UTF8.self) }
}
private extension JSONEncoder {
    static var pretty: JSONEncoder { let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted,.sortedKeys,.withoutEscapingSlashes]; return e }
}
struct CoffeeReceipt: Codable, Sendable {
    let kind, query, sourceURL: String
    let queriedAt, finishedAt: Double
    let status: String
    let httpStatus: Int?
    let raw: String
    let data: CoffeeJSON?
    let error: String?
    var sha256: String? = nil
    var transport: String? = nil
    var cache_state: String? = nil
    /// Backoff responses may carry a persisted complete lookup.  It is decoded
    /// only by NetCoffeeStore after the requested-IP checks succeed.
    var last_good: CoffeeJSON? = nil
    var score: Int? {
        guard status == "complete", httpStatus == 200, (data?["ip"]?.text.flatMap(LeakIPAddress.init)?.canonical == LeakIPAddress(query)?.canonical
                || (kind == "risk" && data?["ip"] == nil && sourceURL == "https://ip.net.coffee/api/iprisk/"+query)),
              let n = data?["trust_score"]?.number, n.isFinite, n >= 0, n <= 100, n.rounded() == n else { return nil }
        return Int(n)
    }
    func field(_ key: String) -> String { let value = data?[key]?.text?.trimmingCharacters(in: .whitespacesAndNewlines); return value?.isEmpty == false ? value! : "未提供" }
    static func failure(_ kind: String, query: String, _ error: String) -> CoffeeReceipt {
        let t = Date().timeIntervalSince1970
        return .init(kind: kind, query: query, sourceURL: "", queriedAt: t, finishedAt: t, status: "error", httpStatus: nil, raw: "", data: nil, error: error)
    }
    static func timeout(_ kind: String, query: String, startedAt: Double) -> CoffeeReceipt {
        .init(kind: kind, query: query, sourceURL: "", queriedAt: startedAt,
              finishedAt: Date().timeIntervalSince1970, status: "timeout", httpStatus: nil,
              raw: "", data: nil, error: "本轮接口请求超过剩余时限")
    }
}
final class CoffeeRequest: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false
    private var active = false
    private var timedOut = false
    private let exitSignal = DispatchSemaphore(value: 0)
    private let resourceDirectory: URL?
    private let backendVariant: BundledBackendVariant?

    init(resourceDirectory: URL? = nil, backendVariant: BundledBackendVariant? = nil) {
        self.resourceDirectory = resourceDirectory
        self.backendVariant = backendVariant
    }

    func cancel() {
        lock.lock(); cancelled = true; let p = process; lock.unlock()
        if p?.isRunning == true { p?.terminate() }
    }

    /// Wait only for this request's own child after asking it to terminate.
    /// The caller supplies one shared deadline when cancelling several API
    /// requests, so a damaged service cannot keep the helper alive forever.
    func cancelAndWait(until deadline: DispatchTime) -> Bool {
        cancel()
        lock.lock(); let running = active; lock.unlock()
        return !running || exitSignal.wait(timeout: deadline) == .success
    }

    private func expire() {
        lock.lock()
        guard !cancelled && active else { lock.unlock(); return }
        timedOut = true; cancelled = true
        let child = process
        lock.unlock()
        if child?.isRunning == true { child?.terminate() }
    }

    func run(kind: String, query: String, timeout: TimeInterval? = nil) -> CoffeeReceipt {
        let startedAt = Date().timeIntervalSince1970
        if let timeout, !timeout.isFinite || timeout <= 0 {
            return .timeout(kind, query: query, startedAt: startedAt)
        }
        let p = Process(), output = Pipe()
        guard let resources = resourceDirectory ?? Bundle.main.resourceURL,
              let variant = backendVariant ?? BundledBackendVariant.read(from: resources) else {
            return .failure(kind, query: query, "构建包未声明后台类型，请重新构建界面。")
        }
        switch variant {
        case .stable:
            let script = resources.appendingPathComponent("netcoffee_client.py", isDirectory: false)
            guard FileManager.default.isReadableFile(atPath: script.path),
                  let python = ["/opt/homebrew/bin/python3","/usr/local/bin/python3","/usr/bin/python3"].first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
                return .failure(kind, query: query, "Net.Coffee 采集组件不可用")
            }
            p.executableURL = URL(fileURLWithPath: python)
            p.arguments = [script.path, kind, query]
        case .rustCandidate:
            let engine = resources.appendingPathComponent("watch-engine", isDirectory: false)
            guard FileManager.default.isExecutableFile(atPath: engine.path) else {
                return .failure(kind, query: query, "找不到 Rust Net.Coffee 采集组件，请重新构建候选包。")
            }
            p.executableURL = engine
            p.arguments = ["coffee", kind, query]
        }
        p.standardOutput = output; p.standardError = FileHandle.nullDevice
        lock.lock(); if cancelled { lock.unlock(); return .failure(kind, query: query, "已取消") }; process = p
        do { try p.run() } catch { process = nil; lock.unlock(); return .failure(kind, query: query, "采集组件启动失败") }
        active = true; lock.unlock()
        let timer = DispatchWorkItem { [weak self] in self?.expire() }
        if let timeout {
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + min(timeout, 20), execute: timer)
        }
        defer {
            timer.cancel()
            lock.lock(); process = nil; active = false; lock.unlock()
            exitSignal.signal()
        }
        let bytes = output.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        lock.lock(); let stopped = cancelled; let expired = timedOut; lock.unlock()
        if expired { return .timeout(kind, query: query, startedAt: startedAt) }
        guard !stopped, p.terminationStatus == 0, bytes.count <= 1_048_576,
              let r = try? JSONDecoder().decode(CoffeeReceipt.self, from: bytes) else { return .failure(kind, query: query, "请求取消或返回数据无效") }
        return r
    }
}
