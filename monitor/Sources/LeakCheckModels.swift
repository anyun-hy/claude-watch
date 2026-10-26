import Foundation
import Darwin

enum LeakKind: String, CaseIterable, Sendable { case dns, webrtc }
enum LeakVerdictState: String, Sendable { case idle, running, matched, difference, incomplete, unconfigured, cancelled }

struct LeakVerdict: Equatable, Sendable {
    let state: LeakVerdictState
    let title, detail: String
    static let idle = LeakVerdict(state: .idle, title: "未检测", detail: "点击开始后进行一次检测，页面刷新不会自动发起探测。")
    static let running = LeakVerdict(state: .running, title: "正在检测", detail: "等待本轮完整结果；上轮结论不参与本次判断。")
    static let cancelled = LeakVerdict(state: .cancelled, title: "已取消", detail: "本轮未完成，不能作出出口是否符合预期的结论。")
}

struct LeakObservation: Codable, Identifiable, Equatable, Sendable {
    let address, kind, source: String
    var family: Int? = nil
    var country: String? = nil
    var region: String? = nil
    var city: String? = nil
    var isp: String? = nil
    var geoSource: String? = nil
    var geoQueriedAt: Double? = nil
    var id: String { [kind, address, source].joined(separator: "|") }
}
struct LeakProbeError: Codable, Identifiable, Equatable, Sendable {
    let stage, code, message: String
    var id: String { [stage, code, message].joined(separator: "|") }
}
struct LeakProbeResult: Codable, Sendable {
    let kind, status: String
    let startedAt, finishedAt: Double
    let scope: String
    let observations: [LeakObservation]
    let errors: [LeakProbeError]
    var contextChanged: Bool
    let details: [String]
    var externalJSON: String? = nil

    init(kind: String, status: String, startedAt: Double, finishedAt: Double, scope: String,
         observations: [LeakObservation], errors: [LeakProbeError], contextChanged: Bool,
         details: [String], externalJSON: String? = nil) {
        self.kind = kind; self.status = status; self.startedAt = startedAt; self.finishedAt = finishedAt
        self.scope = scope; self.observations = observations; self.errors = errors
        self.contextChanged = contextChanged; self.details = details; self.externalJSON = externalJSON
    }

    private enum CodingKeys: String, CodingKey {
        case kind, status, startedAt, finishedAt, scope, observations, errors, contextChanged, details, externalJSON
    }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        kind = try c.decode(String.self, forKey: .kind)
        status = try c.decode(String.self, forKey: .status)
        startedAt = try c.decode(Double.self, forKey: .startedAt)
        finishedAt = try c.decode(Double.self, forKey: .finishedAt)
        scope = try c.decode(String.self, forKey: .scope)
        observations = try c.decode([LeakObservation].self, forKey: .observations)
        errors = try c.decode([LeakProbeError].self, forKey: .errors)
        contextChanged = try c.decodeIfPresent(Bool.self, forKey: .contextChanged) ?? false
        details = try c.decodeIfPresent([String].self, forKey: .details) ?? []
        externalJSON = try c.decodeIfPresent(String.self, forKey: .externalJSON)
    }

    static func failure(_ kind: LeakKind, code: String, message: String, at now: Date = Date()) -> LeakProbeResult {
        LeakProbeResult(kind: kind.rawValue, status: code == "timeout" ? "timeout" : "error",
            startedAt: now.timeIntervalSince1970, finishedAt: now.timeIntervalSince1970,
            scope: kind == .dns ? "本机 dig DNS 路径" : "当前检测 WebView",
            observations: [], errors: [.init(stage: "collector", code: code, message: message)],
            contextChanged: false, details: [])
    }
}
struct LeakCheckState {
    var running = false
    /// Always the latest collection result.  Policy and backend persistence use
    /// this value, never the previous successful display sample.
    var result: LeakProbeResult? = nil
    /// Kept only to explain a transient collector failure to the user.
    var lastSuccessfulResult: LeakProbeResult? = nil
    var lastSuccessfulContext: String? = nil
    var lastSuccessfulContextRequired = false
    var verdict: LeakVerdict = .idle
    var inputError: String? = nil

    var displaysPreviousSuccessfulResult: Bool {
        guard let result, lastSuccessfulResult != nil, !result.contextChanged else { return false }
        if case .difference = verdict.state { return false }
        return result.status != "complete" || !result.errors.isEmpty
    }
    var displayResult: LeakProbeResult? {
        displaysPreviousSuccessfulResult ? lastSuccessfulResult : result
    }
}

/// Canonical address comparison; local, synthetic and documentation addresses
/// are retained as observations but cannot establish a public egress match.
struct LeakIPAddress: Hashable, Sendable {
    let canonical: String
    let family: Int
    let isPublic: Bool

    init?(_ input: String) {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.utf8.count <= 64, !value.contains("%") else { return nil }
        var v4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            let bytes = withUnsafeBytes(of: &v4) { Array($0) }
            canonical = bytes.map(String.init).joined(separator: ".")
            family = 4
            isPublic = Self.publicV4(bytes)
            return
        }
        var v6 = in6_addr()
        guard value.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 else { return nil }
        let bytes = withUnsafeBytes(of: &v6) { Array($0) }
        if bytes.prefix(10).allSatisfy({ $0 == 0 }), bytes[10] == 255, bytes[11] == 255 {
            let mapped = Array(bytes.suffix(4))
            canonical = mapped.map(String.init).joined(separator: ".")
            family = 4; isPublic = Self.publicV4(mapped)
            return
        }
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &v6, &buffer, socklen_t(buffer.count)) != nil else { return nil }
        canonical = String(cString: buffer).lowercased(); family = 6
        let documentation = bytes[0...3].elementsEqual([0x20, 0x01, 0x0d, 0xb8])
        // Conservatively exclude the IETF protocol-assignment block here;
        // supported egress comparisons need ordinary global unicast addresses.
        let special2001 = bytes[0] == 0x20 && bytes[1] == 0x01 && (bytes[2] & 0xfe) == 0
        let documentation3fff = bytes[0] == 0x3f && bytes[1] == 0xff && (bytes[2] & 0xf0) == 0
        let sixToFourPrivate = bytes[0] == 0x20 && bytes[1] == 0x02 && !Self.publicV4(Array(bytes[2...5]))
        isPublic = (bytes[0] & 0xe0) == 0x20 && !documentation && !documentation3fff && !special2001 && !sixToFourPrivate
    }

    private static func publicV4(_ b: [UInt8]) -> Bool {
        let a = Int(b[0]), c = Int(b[1]), d = Int(b[2])
        if a == 0 || a == 10 || a == 127 || a >= 224 { return false }
        if a == 100 && (64...127).contains(c) { return false }
        if a == 169 && c == 254 { return false }
        if a == 172 && (16...31).contains(c) { return false }
        if a == 192 && c == 168 { return false }
        if a == 192 && c == 0 && d == 0 { return b[3] == 9 || b[3] == 10 }
        if a == 192 && ((c == 0 && d == 2) || (c == 88 && d == 99)) { return false }
        if a == 198 && (c == 18 || c == 19 || (c == 51 && d == 100)) { return false }
        if a == 203 && c == 0 && d == 113 { return false }
        return true
    }
}

enum LeakPolicy {
    static func expectedAddresses(_ text: String) throws -> Set<String> {
        guard text.utf8.count <= 4096 else { throw PolicyError.invalid }
        let tokens = text.components(separatedBy: CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: ",，;；"))).filter { !$0.isEmpty }
        guard tokens.count <= 32 else { throw PolicyError.invalid }
        var result = Set<String>()
        for token in tokens {
            guard let address = LeakIPAddress(token), address.isPublic else { throw PolicyError.invalid }
            result.insert(address.canonical)
        }
        return result
    }
    enum PolicyError: Error { case invalid }
    static let invalidInput = "请输入公网 IP（IPv4 或 IPv6），以逗号分隔；不接受域名、端口或本地代理地址。"

    static func evaluate(_ result: LeakProbeResult, kind: LeakKind, expected: String, now: Double) -> LeakVerdict {
        func incomplete(_ detail: String) -> LeakVerdict { .init(state: .incomplete, title: "检测未完成", detail: detail) }
        // DNS leak detection has no user-maintained IP allow-list.  Its reference
        // is the HTTP egress observed in the same run.  WebRTC keeps its optional
        // explicit address reference because ICE candidates are compared by address.
        let allowed: Set<String>
        if kind == .dns {
            allowed = []
        } else {
            guard let value = try? expectedAddresses(expected) else { return incomplete(invalidInput) }
            allowed = value
        }
        guard result.kind == kind.rawValue, result.startedAt.isFinite, result.finishedAt.isFinite,
              result.startedAt <= result.finishedAt, result.finishedAt <= now + 5,
              result.finishedAt - result.startedAt <= 120, result.observations.count <= 128,
              result.errors.count <= 32 else { return incomplete("采集结果无效，不能用于当前判断。") }
        guard now - result.finishedAt <= 300 else { return .init(state: .incomplete, title: "结果已过期", detail: "这次采样已超过 5 分钟，请重新检测。") }
        guard !result.contextChanged else { return incomplete("检测期间或之后网络/代理上下文发生变化，请在网络稳定后重新检测。") }
        // A partial WebRTC result can contain useful addresses, but never earns a pass.
        // DNS is handled below: a valid foreign resolver remains a leak-risk
        // finding even if another DNS round or enrichment request failed.
        if kind != .dns && (result.status != "complete" || !result.errors.isEmpty) {
            let message = result.errors.first?.message ?? "本轮结果不完整，请查看检测详情后重试。"
            return incomplete(result.status == "timeout" ? "检测超时。" + message : message)
        }
        var normalized: [(LeakObservation, LeakIPAddress)] = []
        for row in result.observations {
            if row.kind == "mdns" { continue }
            guard let ip = LeakIPAddress(row.address), row.family == nil || row.family == ip.family
                    || (row.family == 6 && ip.family == 4 && row.address.contains(":")) else {
                return incomplete("采集中包含无效地址或地址族信息，已保留原始记录供核对。")
            }
            guard ["resolver", "http", "srflx", "prflx", "relay", "host"].contains(row.kind) else { return incomplete("采集结果包含未知候选类型。") }
            if ["resolver", "http", "srflx", "prflx"].contains(row.kind), !ip.isPublic {
                return incomplete("诊断返回了不可用于公网出口比较的地址，不能据此判断匹配。")
            }
            normalized.append((row, ip))
        }
        let http = Set(normalized.filter { $0.0.kind == "http" && $0.1.isPublic }.map { $0.1.canonical })
        guard !http.isEmpty else { return incomplete("未取得本轮 HTTP 出口参考，不能把空参考当成匹配。") }
        // Geography can reveal an additional inconsistency. It never grants a
        // pass: address references, completeness and route context still apply.
        let httpCountries = Set(normalized.filter { $0.0.kind == "http" }.compactMap { CountryIdentity.code($0.0.country, country: $0.0.country) })
        if httpCountries.count > 1 { return incomplete("同轮 HTTP 出口归属来源不一致，请重新检测。") }
        let comparedKinds = kind == .dns ? ["resolver"] : ["srflx", "prflx", "host"]
        let observedCountries = Set(normalized.filter { comparedKinds.contains($0.0.kind) && $0.1.isPublic }
            .compactMap { CountryIdentity.code($0.0.country, country: $0.0.country) })
        if kind != .dns, let referenceCountry = httpCountries.first, observedCountries.contains(where: { $0 != referenceCountry }) {
            return .init(state: .difference, title: "发现出口归属差异", detail: "检测出口与本轮 HTTP 出口的已知国家归属不一致，需核对代理路径。国家相同也不会替代实际出口校验。")
        }
        if kind == .dns {
            let resolvers = Set(normalized.filter { $0.0.kind == "resolver" && $0.1.isPublic }.map { $0.1.canonical })
            guard !resolvers.isEmpty else { return incomplete("没有取得有效 DNS 递归出口；空结果不能证明 DNS 已加密或没有泄漏。") }
            guard let httpCountry = httpCountries.first, httpCountries.count == 1 else {
                return incomplete("未取得唯一的本轮公网出口国家，不能判断 DNS 是否随出口代理。")
            }
            if observedCountries.contains(where: { $0 != httpCountry }) {
                return .init(state: .difference, title: "发现 DNS 出口地区差异", detail: "至少一个 DNS 递归出口国家与本轮公网出口 \(httpCountry) 不一致，存在 DNS 泄漏风险。")
            }
            guard observedCountries.count == 1, let dnsCountry = observedCountries.first else {
                return incomplete("未取得唯一的 DNS 递归出口国家，不能判断是否存在 DNS 泄漏。")
            }
            guard dnsCountry == httpCountry else {
                return .init(state: .difference, title: "发现 DNS 出口地区差异", detail: "DNS 递归出口为 \(dnsCountry)，本轮公网出口为 \(httpCountry)。DNS 未随当前出口路径，存在泄漏风险。")
            }
            guard result.status == "complete", result.errors.isEmpty else {
                let message = result.errors.first?.message ?? "本轮 DNS 查询未完整结束。"
                return incomplete("DNS 出口国家一致，但本轮检测未完整结束：" + message)
            }
            return .init(state: .matched, title: "DNS 出口与公网出口一致", detail: "本轮 DNS 递归出口和 HTTP 公网出口均为 \(httpCountry)。范围仅限本轮检测路径。")
        }
        let candidates = Set(normalized.filter { ["srflx", "prflx", "host"].contains($0.0.kind) && $0.1.isPublic }.map { $0.1.canonical })
        guard !candidates.isEmpty else { return incomplete("没有取得可比较的公网 ICE/STUN 候选；仅有本地、mDNS 或 TURN 中继候选也不能判定无泄漏。") }
        let reference = allowed.isEmpty ? http : allowed
        let referenceFamilies = Set(reference.compactMap { LeakIPAddress($0)?.family })
        if allowed.isEmpty && candidates.contains(where: { !referenceFamilies.contains(LeakIPAddress($0)!.family) }) {
            return incomplete("已取得候选，但缺少对应 IPv4/IPv6 的 HTTP 出口参考；可填写完整的预期出口后重新核对。")
        }
        let unexpected = candidates.subtracting(reference)
        if !unexpected.isEmpty {
            return .init(state: .difference, title: "发现出口差异", detail: "公网候选与" + (allowed.isEmpty ? "本轮 HTTP 参考" : "预期列表") + "不一致：" + unexpected.sorted().joined(separator: "、") + "。可能涉及 UDP 分流，需核对实际网络策略。")
        }
        return .init(state: .matched, title: "本轮出口样本一致", detail: "已观测的公网候选与" + (allowed.isEmpty ? "同轮 HTTP 出口" : "预期出口") + "一致；范围仅限当前检测 WebView，不代表 AI 应用或其他浏览器。")
    }
}
