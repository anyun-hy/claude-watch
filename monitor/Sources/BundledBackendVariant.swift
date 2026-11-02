import Foundation

/// The backend a packaged app ships. There is one: the Rust engine. The
/// manifest still declares it, so a bundle built before the Python backend was
/// retired is rejected instead of silently running against missing components.
enum BundledBackendVariant {
    case rustCandidate

    static func current() -> BundledBackendVariant? {
        guard let url = Bundle.main.url(forResource: "BuildInfo", withExtension: "plist") else { return nil }
        return read(from: url.deletingLastPathComponent())
    }

    static func read(from resourceDirectory: URL) -> BundledBackendVariant? {
        let manifest = resourceDirectory.appendingPathComponent("BuildInfo.plist", isDirectory: false)
        guard let values = NSDictionary(contentsOf: manifest),
              let raw = values["BackendVariant"] as? String else { return nil }
        return raw == "rust-candidate" ? .rustCandidate : nil
    }

    static func backgroundEvidenceSchema(from resourceDirectory: URL) -> Int? {
        let manifest = resourceDirectory.appendingPathComponent("BuildInfo.plist", isDirectory: false)
        return (NSDictionary(contentsOf: manifest)?["BackgroundEvidenceSchema"] as? NSNumber)?.intValue
    }
}
