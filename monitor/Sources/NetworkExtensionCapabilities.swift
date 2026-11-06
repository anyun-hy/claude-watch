import Foundation

enum NetworkExtensionCapabilities {
    static func allowsActivation(installation: Any?, providers: Any?) -> Bool {
        guard installation as? Bool == true, let providers = providers as? [String] else { return false }
        return providers.contains("app-proxy-provider-systemextension")
    }
}
