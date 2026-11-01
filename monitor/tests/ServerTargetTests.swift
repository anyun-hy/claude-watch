import Foundation

@main
struct ServerTargetTests {
    @MainActor static func main() throws {
        var passed = 0
        func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
            guard condition() else { fputs("FAIL: \(message)\n", stderr); exit(1) }
            passed += 1
        }
        func flow(host: String = "chatgpt.com", association: String = "correlated") -> Flow {
            Flow(id: "fixture", pid: 23, host: host, peer: "127.0.0.1:7890", local: "127.0.0.1:50001",
                 transport: "TCP", association: association, policy: "match", reason: "fixture",
                 chains: ["海外AI", "日本11"], routePath: "local_proxy", interfaceName: nil)
        }
        func reference(_ request: ServerReferenceRequest, basis: String = "dns_reference", address: String = "104.18.32.7", city: String = "") -> ServerReference {
            ServerReference(host: request.host, basis: basis, address: address, addresses: [address],
                            countryCode: "US", country: "United States", region: "California", city: city,
                            status: "ready", message: "fixture", queriedAt: 100, expiresAt: 700,
                            dnsSource: basis == "dns_reference" ? "Cloudflare DoH" : "", geoSource: "IPinfo")
        }
        expect(AITargetService.identify("API.Anthropic.com.:443") == .claude, "Claude exact domain family")
        expect(AITargetService.identify("ws.chatgpt.com") == .chatGPT, "ChatGPT service subdomain")
        let rustWire = #"{"host":"api.chatgpt.com","basis":"dns_reference","address":"1.1.1.1","addresses":["1.1.1.1"],"countryCode":"AU","country":"","region":"Queensland","city":"South Brisbane","status":"ready","message":"DNS 解析与 IP 归属仅作参考，非这条连接的实测目标 IP。","queriedAt":100,"expiresAt":700,"dnsSource":"Cloudflare DoH","geoSource":"IPinfo"}"#
        let decoded = try JSONDecoder().decode(ServerReference.self, from: Data(rustWire.utf8))
        expect(decoded.host == "api.chatgpt.com" && decoded.queriedAt == 100 && decoded.expiresAt == 700,
               "Rust server-reference wire fields decode in Swift")
        for host in ["chatgpt.com.evil.test", "fakechatgpt.com", "chatgpt.com@evil.test", "https://openai.com", "127.0.0.1", "openai.com:0"] {
            expect(AITargetService.identify(host) == nil, "reject spoof or invalid host \(host)")
        }
        let sample = flow()
        let request = ServerReferenceRequest(flow: sample)!
        let dns = reference(request)
        let card = ServerTargetPresentation(product: .openAI, flow: sample, reference: dns, now: 101)
        expect(card.title == "ChatGPT 服务器", "service title uses observed domain")
        expect(card.addressLine == "DNS 参考：104.18.32.7", "DNS address remains explicitly reference")
        expect(card.regionLine.contains("美国"), "country is localized")
        expect(card.detail.contains("未证实") && card.detail.contains("CDN/Anycast"), "reference and geography boundaries remain visible in detail")
        let claude = flow(host: "claude.ai")
        let claudeRequest = ServerReferenceRequest(flow: claude)!
        let claudeCard = ServerTargetPresentation(product: .claude, flow: claude,
            reference: reference(claudeRequest, city: "San Francisco"), now: 101)
        expect(claudeCard.title == "Claude 服务器" && claudeCard.regionLine.contains("美国") &&
               claudeCard.detail.contains("城市参考：San Francisco"),
               "Claude uses the same reference lookup and displays an available city in the detail")
        expect(dns.applies(to: request, now: 699) && !dns.applies(to: request, now: 700), "expired cache cannot display as current")
        expect(!dns.applies(to: ServerReferenceRequest(flow: flow(host: "claude.ai"))!, now: 101), "no cache reuse for a different host")

        var actual = sample
        actual.destinationIP = "8.8.8.8"; actual.destinationIPState = "public"
        actual.destinationPort = 443; actual.destinationCountry = "JP"
        let actualRequest = ServerReferenceRequest(flow: actual)!
        expect(!dns.applies(to: actualRequest, now: 101), "DNS cache never substitutes for observed IP geography")
        let actualCard = ServerTargetPresentation(product: .openAI, flow: actual, reference: dns, now: 101)
        expect(actualCard.addressLine == "实测 IP：8.8.8.8:443" && actualCard.regionLine.contains("日本"), "observed IP wins; unmatched DNS geography ignored")
        let geo = reference(actualRequest, basis: "observed_ip", address: "8.8.8.8")
        expect(geo.applies(to: actualRequest, now: 101), "geography query matches exact observed IP")
        actual.destinationIP = "2606:4700:4700::1111"
        let ipv6 = ServerTargetPresentation(product: .openAI, flow: actual, reference: geo, now: 101)
        expect(ipv6.addressLine == "实测 IP：[2606:4700:4700::1111]:443", "IPv6 port uses brackets, old IP cache discarded")
        actual.destinationIP = "198.18.0.8"; actual.destinationIPState = "synthetic"
        expect(!ServerTargetPresentation(product: .openAI, flow: actual, reference: nil, now: 101).addressLine.contains("198.18"), "fake IP never displayed as service address")
        var uncorrelated = flow(association: "pending")
        uncorrelated.destinationIP = "8.8.8.8"; uncorrelated.destinationIPState = "public"
        expect(ServerReferenceRequest(flow: uncorrelated) == nil, "uncorrelated host triggers no query")
        expect(!ServerTargetPresentation(product: .openAI, flow: uncorrelated, reference: nil, now: 101).addressLine.contains("实测"), "uncorrelated address is not promoted to evidence")
        expect(ServerTargetPresentation(product: .claude, flow: nil, reference: dns, now: 101).addressLine == "等待连接样本", "idle product does not invent a server IP")

        let store = MonitorStore()
        store.now = Date(timeIntervalSince1970: 101)
        store.acceptServerReference(nil, for: request, at: store.now)
        let failure = store.reference(for: sample)
        expect(failure?.status == "unavailable", "runner failure is negative-cached")
        expect(failure?.dnsSource.isEmpty == true && failure?.geoSource.isEmpty == true,
               "a missing runner result does not pretend either external service was queried")
        expect(ServerTargetPresentation(product: .openAI, flow: sample, reference: failure, now: 101).addressLine == "目标 IP 暂不可用", "failure does not stay in loading state")
        store.now = Date(timeIntervalSince1970: 402)
        expect(store.reference(for: sample) == nil, "failure cache expires for retry")
        store.now = Date(timeIntervalSince1970: 101)
        store.acceptServerReference(dns, for: request, at: store.now)
        var replacement = flow(); replacement = Flow(id: "replacement", pid: 99, host: sample.host, peer: sample.peer,
            local: "127.0.0.1:62000", transport: sample.transport, association: sample.association, policy: sample.policy,
            reason: "fixture", chains: sample.chains, routePath: sample.routePath, interfaceName: nil)
        expect(store.reference(for: replacement)?.address == dns.address, "PID and local-port refresh preserve host reference cache")

        let oldJSON = #"{"id":"old","pid":1,"host":"chatgpt.com","peer":"127.0.0.1:7890","local":"127.0.0.1:50000","protocol":"TCP","association":"correlated","policy":"match","reason":"fixture","chains":[]}"#
        let oldFlow = try JSONDecoder().decode(Flow.self, from: Data(oldJSON.utf8))
        expect(oldFlow.destinationIP == nil && ServerReferenceRequest(flow: oldFlow) != nil, "old backend snapshots remain readable and can use DNS reference")
        print("ServerTargetTests: \(passed) assertions passed")
    }
}
