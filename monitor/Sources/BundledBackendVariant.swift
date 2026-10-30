import Foundation

enum BundledBackendVariant {
    case stable
    case rustCandidate

    static func current() -> BundledBackendVariant? {
        guard let url = Bundle.main.url(forResource: "BuildInfo", withExtension: "plist") else { return nil }
        return read(from: url.deletingLastPathComponent())
    }

    static func read(from resourceDirectory: URL) -> BundledBackendVariant? {
        let manifest = resourceDirectory.appendingPathComponent("BuildInfo.plist", isDirectory: false)
        guard let values = NSDictionary(contentsOf: manifest),
              let raw = values["BackendVariant"] as? String else { return nil }
        switch raw {
        case "stable": return .stable
        case "rust-candidate": return .rustCandidate
        default: return nil
        }
    }

    static func backgroundEvidenceSchema(from resourceDirectory: URL) -> Int? {
        let manifest = resourceDirectory.appendingPathComponent("BuildInfo.plist", isDirectory: false)
        return (NSDictionary(contentsOf: manifest)?["BackgroundEvidenceSchema"] as? NSNumber)?.intValue
    }
}
