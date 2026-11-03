import AppKit
import ApplicationServices

enum AccessibilityPermission {
    static let bundleID = "io.local.watchpanel"
    static let installedPath = "/Applications/Claude Watch Monitor.app"
    /// Privacy & Security > Accessibility, newest pane identifier first. The
    /// older alias is kept because the renamed pane is not addressable on
    /// every macOS release, and a failed deep link must not be silent.
    static let settingsPanes = [
        "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility",
        "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility",
    ]

    @MainActor static var trusted: Bool {
        #if UI_REVIEW
        return false
        #else
        return AXIsProcessTrusted()
        #endif
    }

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

    /// Only triggers the system consent prompt. It never opens System
    /// Settings: that would cover the prompt the user is meant to answer, so
    /// the "Device Control and Data Access" sheet would be skipped and the
    /// Settings window would appear to jump in front of it. The prompt itself
    /// carries an "Open System Settings" button, so opening the pane is the
    /// user's action, not ours.
    @MainActor static func request() {
        #if !UI_REVIEW
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(options)
        #endif
    }

    /// Explicitly opens the Accessibility pane, for the cases where the user
    /// has already dismissed the prompt and needs to reach the switch again.
    /// This is the "重新请求授权" path only; it must not run on the same turn
    /// as `request()` or it would hide the consent prompt.
    @MainActor @discardableResult static func openSettings() -> Bool {
        #if UI_REVIEW
        return true
        #else
        for pane in settingsPanes {
            if let url = URL(string: pane), NSWorkspace.shared.open(url) { return true }
        }
        return false
        #endif
    }
}
