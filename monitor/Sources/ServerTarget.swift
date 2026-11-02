import Foundation

enum AITargetService: Equatable {
    case claude, chatGPT

    var title: String { self == .claude ? "Claude 服务器" : "ChatGPT 服务器" }

    static func normalizedHost(_ value: String) -> String? {
        let parts = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            .split(separator: ":", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count) else { return nil }
        if parts.count == 2 {
            guard let port = Int(parts[1]), (1...65535).contains(port) else { return nil }
        }
        var host = String(parts[0])
        if host.hasSuffix(".") { host.removeLast() }
        guard host.count <= 253,
              host.range(of: #"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"#,
                         options: .regularExpression) != nil else { return nil }
        return host
    }

    static func identify(_ value: String) -> AITargetService? {
        guard let host = normalizedHost(value) else { return nil }
        func belongs(to root: String) -> Bool { host == root || host.hasSuffix("." + root) }
        if ["claude.ai", "anthropic.com"].contains(where: belongs) { return .claude }
        if ["chatgpt.com", "openai.com", "oaiusercontent.com"].contains(where: belongs) { return .chatGPT }
        return nil
    }
}

struct ServerReferenceRequest: Equatable, Sendable {
    let host: String
    let observedIP: String?
    var key: String { host + "|" + (observedIP ?? "dns") }

    init?(flow: Flow?) {
        guard let flow, flow.association == "correlated", AITargetService.identify(flow.host) != nil,
              let host = AITargetService.normalizedHost(flow.host) else { return nil }
        self.host = host
        observedIP = flow.destinationIPState == "public" && flow.destinationIP?.isEmpty == false
            ? flow.destinationIP : nil
    }
}

struct ServerReference: Decodable, Sendable {
    let host, basis, address: String
    let addresses: [String]
    let countryCode, country, region, city, status, message: String
    let queriedAt, expiresAt: Double
    let dnsSource, geoSource: String

    static func unavailable(for request: ServerReferenceRequest, now: Double) -> ServerReference {
        ServerReference(host: request.host, basis: request.observedIP == nil ? "dns_reference" : "observed_ip",
                        address: request.observedIP ?? "", addresses: request.observedIP.map { [$0] } ?? [],
                        countryCode: "", country: "", region: "", city: "", status: "unavailable",
                        message: "参考查询暂不可用，稍后重试。", queriedAt: now, expiresAt: now + 300,
                        dnsSource: "", geoSource: "")
    }

    func applies(to request: ServerReferenceRequest, now: Double) -> Bool {
        host == request.host && queriedAt.isFinite && expiresAt.isFinite
            && queriedAt <= now + 5 && queriedAt < expiresAt && now < expiresAt
            && (request.observedIP.map { basis == "observed_ip" && address == $0 } ?? (basis == "dns_reference"))
    }
}

struct ServerTargetPresentation {
    let title, addressLine, regionLine, detail: String
    let regionCountryCode: String?

    init(product: MonitoredProduct, flow: Flow?, reference: ServerReference?, now: Double, historical: Bool = false) {
        let service = flow.flatMap { AITargetService.identify($0.host) }
        title = service?.title ?? (flow == nil ? (product == .claude ? "Claude 服务器" : "ChatGPT 服务器") : "连接目标")
        let request = ServerReferenceRequest(flow: flow)
        let validReference = request.flatMap { request in reference.flatMap { $0.applies(to: request, now: now) ? $0 : nil } }
        let actualIP = flow?.association == "correlated" && flow?.destinationIPState == "public" ? flow?.destinationIP : nil
        let observed = actualIP?.isEmpty == false
        let referenceIP = validReference?.address.isEmpty == false ? validReference?.address : nil
        let address = observed ? actualIP : referenceIP

        if let address {
            let endpoint: String
            if observed, let port = flow?.destinationPort {
                endpoint = address.contains(":") ? "[\(address)]:\(port)" : "\(address):\(port)"
            } else { endpoint = address }
            addressLine = (observed ? "实测 IP：" : "DNS 参考：") + endpoint
        } else if flow == nil {
            addressLine = "等待连接样本"
        } else if request != nil {
            addressLine = historical ? "当时未保存目标 IP 参考" : validReference == nil ? "DNS 参考待查询" : "目标 IP 暂不可用"
        } else {
            addressLine = "实际目标 IP 未提供"
        }

        let code = validReference?.countryCode.isEmpty == false
            ? validReference?.countryCode : (observed ? flow?.destinationCountry : nil)
        regionCountryCode = code
        let localizedCountry = code.flatMap { Locale(identifier: "zh_CN").localizedString(forRegionCode: $0) }
        let country = localizedCountry ?? validReference?.country ?? ""
        let region = validReference?.region ?? ""
        let place = [country, region == country ? "" : region].filter { !$0.isEmpty }.joined(separator: " · ")
        regionLine = place.isEmpty ? "IP 归属地区未取得" : "IP 归属：" + place

        var details = ["服务域名：\(flow?.host ?? "待采样")", addressLine, regionLine]
        if historical { details.insert("上次保存的目标信息，非当前查询。", at: 0) }
        if !observed, address != nil {
            details.append("DNS 解析参考，未证实为这条连接实际使用的 IP。")
        } else if !observed {
            details.append("当前连接未提供真实目标 IP；代理传输端点与 TUN 虚拟地址不作为服务器 IP。")
        }
        if let validReference {
            if !validReference.addresses.isEmpty { details.append("查询地址：" + validReference.addresses.joined(separator: "、")) }
            if !validReference.city.isEmpty { details.append("城市参考：" + validReference.city) }
            if !validReference.dnsSource.isEmpty { details.append("DNS 来源：" + validReference.dnsSource) }
            if !validReference.geoSource.isEmpty { details.append("IP 归属来源：" + validReference.geoSource) }
            let formatter = DateFormatter(); formatter.dateFormat = "MM-dd HH:mm:ss"
            details.append("参考查询时间：" + formatter.string(from: Date(timeIntervalSince1970: validReference.queriedAt)))
            if !validReference.message.isEmpty { details.append(validReference.message) }
        }
        details.append("IP 归属是数据库估计；CDN/Anycast 地址不代表模型机房或实际处理地区。")
        detail = details.joined(separator: "\n")
    }
}

enum ServerReferenceRunner {
    static func run(_ request: ServerReferenceRequest) -> ServerReference? {
        guard let variant=BundledBackendVariant.current() else { return nil }
        let process = Process(); let output = Pipe(); let errors = Pipe()
        switch variant {
        case .rustCandidate:
            guard let runtime=Bundle.main.url(forResource:"watch-engine",withExtension:nil),FileManager.default.isExecutableFile(atPath:runtime.path) else{return nil}
            process.executableURL=runtime
            process.arguments=["server-reference","--host",request.host]+(request.observedIP.map{["--ip",$0]} ?? [])
        }
        process.standardOutput = output; process.standardError = errors
        do { try process.run() } catch { return nil }
        let timeout = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 32, execute: timeout)
        let data = output.fileHandleForReading.readDataToEndOfFile()
        _ = errors.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit(); timeout.cancel()
        guard process.terminationStatus == 0, data.count <= 65_536 else { return nil }
        return try? JSONDecoder().decode(ServerReference.self, from: data)
    }
}
