import AppKit
import Foundation

/// Event-driven observation of the desktop apps Watch supervises.
///
/// Instead of polling the whole process table on a fixed interval, this
/// observer listens to `NSWorkspace` launch/terminate notifications. macOS
/// posts these the moment a `.app` starts or quits, so the launch/quit button
/// state can update within milliseconds at zero background cost. The periodic
/// snapshot loop remains only as a coarse fallback for CLI processes (e.g.
/// `codex` run from a terminal), which are not `.app` bundles and therefore
/// never fire these notifications.
final class WorkspaceAppObserver {
    /// Bundle identifiers whose launch/terminate should trigger a refresh.
    /// Matches the product attribution in `AIProcessControl`: Claude desktop
    /// plus the OpenAI ChatGPT/Codex desktop apps.
    static let supervisedBundleIDs: Set<String> = [
        "com.anthropic.claudefordesktop",
        "com.openai.codex",
        "com.openai.chat",
    ]

    private var launchToken: NSObjectProtocol?
    private var terminateToken: NSObjectProtocol?
    /// Coalesces the burst of launch/terminate notifications macOS posts for a
    /// single app transition (launch fires several events as the process and
    /// its helpers spin up). Pending work is merged into one `onChange` call so
    /// the monitor re-snapshots exactly once instead of once per notification.
    private var pendingWork: DispatchWorkItem?
    /// Debounce window for the notification burst. Short enough to keep button
    /// state effectively instant, long enough to swallow the multi-event burst.
    private let debounce: TimeInterval

    /// Called on the main thread whenever a supervised desktop app launches or
    /// terminates. The monitor uses it to re-snapshot immediately.
    private let onChange: () -> Void

    init(onChange: @escaping () -> Void, debounce: TimeInterval = 0.3) {
        self.onChange = onChange
        self.debounce = debounce
    }

    func start() {
        guard launchToken == nil else { return }
        let center = NSWorkspace.shared.notificationCenter
        launchToken = center.addObserver(
            forName: NSWorkspace.didLaunchApplicationNotification,
            object: nil, queue: .main
        ) { [weak self] note in
            self?.handle(note, event: "launch")
        }
        terminateToken = center.addObserver(
            forName: NSWorkspace.didTerminateApplicationNotification,
            object: nil, queue: .main
        ) { [weak self] note in
            self?.handle(note, event: "terminate")
        }
    }

    func stop() {
        pendingWork?.cancel()
        pendingWork = nil
        if let token = launchToken {
            NSWorkspace.shared.notificationCenter.removeObserver(token)
            launchToken = nil
        }
        if let token = terminateToken {
            NSWorkspace.shared.notificationCenter.removeObserver(token)
            terminateToken = nil
        }
    }

    deinit { stop() }

    private func handle(_ note: Notification, event: String) {
        guard let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
              let bundleID = app.bundleIdentifier,
              Self.supervisedBundleIDs.contains(bundleID) else { return }
        // Debounce: cancel any in-flight work and schedule a single snapshot
        // after the burst settles. The observation loop is main-threaded, so
        // mutating `pendingWork` here is race-free.
        pendingWork?.cancel()
        let work = DispatchWorkItem { [weak self] in
            self?.pendingWork = nil
            self?.onChange()
        }
        pendingWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + debounce, execute: work)
    }
}
