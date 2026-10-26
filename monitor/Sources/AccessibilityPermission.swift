import AppKit
import ApplicationServices

enum AccessibilityPermission {
    static let bundleID = "io.local.watchpanel"
    static let installedPath = "/Applications/Claude Watch Monitor.app"

    static func shouldPrompt(trusted: Bool, build: String, previous: String?, bundle: String?, path: String) -> Bool {
        !trusted && !build.isEmpty && previous != build && bundle == bundleID && path == installedPath
    }

    @MainActor static func checkInstalledBuild() {
        #if !UI_REVIEW
        let bundle = Bundle.main
        let build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? ""
        let key = "accessibilityPromptedBuild"
        guard shouldPrompt(trusted: AXIsProcessTrusted(), build: build,
                           previous: UserDefaults.standard.string(forKey: key),
                           bundle: bundle.bundleIdentifier, path: bundle.bundleURL.standardizedFileURL.path) else { return }
        UserDefaults.standard.set(build, forKey: key)
        request()
        #endif
    }

    @MainActor static func request() {
        #if !UI_REVIEW
        // macOS adds this running app to its permission list; approval remains a system action.
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(options)
        #endif
    }
}
