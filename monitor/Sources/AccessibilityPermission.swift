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

    @MainActor static func request() {
        #if !UI_REVIEW
        // macOS adds this running app to its permission list; approval remains a system action.
        let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: true] as CFDictionary
        _ = AXIsProcessTrustedWithOptions(options)
        #endif
    }

    /// Registers this build in Privacy & Security and opens that pane.
    ///
    /// Only the switch in System Settings can grant the permission, so this
    /// step is never skipped: without the pane the user has nowhere to act and
    /// the round can only end in "not authorized". Returns whether the pane
    /// was handed to the system, so the caller can say so when it was not.
    @MainActor @discardableResult static func requestAndOpenSettings() -> Bool {
        #if UI_REVIEW
        return true
        #else
        request()
        if openPane() { return true }
        // The system prompt is presented by macOS in the same run loop turn
        // and can swallow the first open attempt; retry once after it settles.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { _ = openPane() }
        return false
        #endif
    }

    @MainActor private static func openPane() -> Bool {
        for pane in settingsPanes {
            if let url = URL(string: pane), NSWorkspace.shared.open(url) { return true }
        }
        return false
    }
}
