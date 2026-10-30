import Foundation

/// Presentation-only identity. No IP geolocation or service routing is inferred.
enum ServiceBrand: String, CaseIterable {
    case claude, chatgpt, cloudflare
    var title: String { switch self { case .claude: return "Claude"; case .chatgpt: return "ChatGPT"; case .cloudflare: return "Cloudflare" } }
    static func endpoint(_ value: String) -> ServiceBrand? {
        let host = URL(string:value)?.host ?? URL(string:"https://"+value)?.host
        guard let host = host?.lowercased() else { return nil }
        func belongs(_ root: String) -> Bool { host == root || host.hasSuffix("."+root) }
        if ["claude.ai","claude.com","anthropic.com"].contains(where:belongs) { return .claude }
        if ["chatgpt.com","openai.com","oaiusercontent.com"].contains(where:belongs) { return .chatgpt }
        if host == "1.1.1.1" || belongs("cloudflare.com") { return .cloudflare }
        return nil
    }
    static func provider(_ name: String?) -> ServiceBrand? {
        guard let name else { return nil }
        let normalized = name.lowercased().filter { $0.isLetter || $0.isNumber }
        return ["cloudflare","cloudflareinc","cloudflareincorporated"].contains(normalized) ? .cloudflare : nil
    }
}

enum CountryIdentity {
    private static let regions = Set(Locale.Region.isoRegions.map(\.identifier).filter { $0.count == 2 } + ["XK"])
    private static let names: [String:String] = {
        var result: [String:String] = [:]
        for identifier in ["en_US","zh_Hans","zh_Hant"] {
            let locale = Locale(identifier:identifier)
            for code in regions {
                if let name = locale.localizedString(forRegionCode:code) { result[name.lowercased()] = code }
            }
        }
        return result
    }()
    static func code(_ value: String?, country: String? = nil) -> String? {
        let candidate = value?.trimmingCharacters(in:.whitespacesAndNewlines).uppercased() ?? ""
        if regions.contains(candidate) { return candidate }
        guard let name = country?.trimmingCharacters(in:.whitespacesAndNewlines), !name.isEmpty else { return nil }
        if regions.contains(name.uppercased()) { return name.uppercased() }
        return names[name.lowercased()]
    }
    static func place(_ values: [String?]) -> String {
        var used = Set<String>()
        return values.compactMap{$0?.trimmingCharacters(in:.whitespacesAndNewlines)}
            .filter{!$0.isEmpty && $0 != "未提供" && used.insert($0.lowercased()).inserted}.joined(separator:" · ")
    }
    /// Country codes already present in the retained GeoIP receipts. Read only.
    static func geoCodes(_ raw: String?) -> [String:String] {
        guard let raw, let bytes = raw.data(using:.utf8),
              let object = try? JSONSerialization.jsonObject(with:bytes) else { return [:] }
        if let evidence = object as? [String: Any], let values = evidence["geoip"] as? [[String: Any]] {
            var result: [String: String] = [:]
            for row in values {
                if let ip = row["ip"] as? String, let country = code(row["country_code"] as? String, country: nil) { result[ip] = country }
            }
            if let http = evidence["http"] as? [String: Any], let ip = http["address"] as? String,
               let country = code(http["country"] as? String, country: nil) { result[ip] = country }
            return result
        }
        guard let receipts = object as? [[String:Any]] else { return [:] }
        var result: [String:String] = [:]
        for r in receipts where r["kind"] as? String == "geoip" && r["status"] as? String == "complete" {
            guard let ip = r["query"] as? String, let data = r["data"] as? [String:Any],
                  let country = code(data["country_code"] as? String, country:data["country"] as? String) else { continue }
            result[ip] = country
        }
        return result
    }
}
