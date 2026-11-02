import AppKit

/// Menu-bar presence for the monitor. The app keeps running with no visible
/// window; the status item toggles the main window and close collapses into
/// the menu bar instead of quitting. Minimize keeps the native macOS Dock
/// thumbnail (a real window snapshot), like other Dock+menu-bar apps
/// (Docker Desktop, 1Password). Windows that state restoration resurrects
/// already miniaturized (the phantom blank Dock thumbnails attached to
/// unrelated screens) are collapsed on adoption.
final class StatusBarController: NSObject, NSWindowDelegate {
    private let item: NSStatusItem
    private var quitting = false

    override init() {
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        super.init()
        if let button = item.button {
            let symbol = NSImage(systemSymbolName: "shield.lefthalf.filled",
                                  accessibilityDescription: "Claude Watch")
                ?? NSImage(systemSymbolName: "shield.fill",
                           accessibilityDescription: "Claude Watch")
            symbol?.isTemplate = true
            button.image = symbol
            button.toolTip = "Claude Watch 正在后台守护（左键开合主窗口，右键菜单）"
            button.target = self
            button.action = #selector(statusItemClicked)
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }
        NotificationCenter.default.addObserver(
            self, selector: #selector(handleWindowKey(_:)),
            name: NSWindow.didBecomeKeyNotification, object: nil)
        adoptWindows()
    }

    deinit { NotificationCenter.default.removeObserver(self) }

    // MARK: window adoption

    /// The main SwiftUI window is titled and far larger than the 1x1
    /// offscreen sampling hosts created by the leak runners.
    static func isMainWindow(_ window: NSWindow) -> Bool {
        window.canBecomeMain && window.frame.width > 100
    }

    static func mainWindowVisible() -> Bool {
        NSApp.windows.contains { Self.isMainWindow($0) && $0.isVisible && !$0.isMiniaturized }
    }

    @objc private func handleWindowKey(_ note: Notification) {
        guard let window = note.object as? NSWindow else { return }
        adopt(window)
    }

    private func adoptWindows() {
        for window in NSApp.windows { adopt(window) }
    }

    /// Take over the window delegate so close can be folded into the menu
    /// bar. The yellow minimize button keeps its native behavior (a real
    /// Dock thumbnail); the tray can always deminiaturize and recall it.
    /// SwiftUI assigns its delegate once at window creation, so
    /// re-asserting on each did-become-key is safe.
    private func adopt(_ window: NSWindow) {
        guard Self.isMainWindow(window) else { return }
        window.delegate = self
        if window.isMiniaturized {
            // A window restored in miniaturized state shows up as a blank
            // phantom thumbnail on whatever screen owns the Dock. Collapse
            // it into the menu bar so only real windows are ever visible.
            window.deminiaturize(nil)
            window.orderOut(nil)
        }
    }

    // MARK: status item

    @objc private func statusItemClicked() {
        guard let event = NSApp.currentEvent else { return }
        if event.type == .rightMouseUp {
            buildMenu().popUp(positioning: nil, at: .zero, in: item.button)
        } else {
            if Self.mainWindowVisible() { hideMainWindow() } else { showMainWindow() }
        }
    }

    private func buildMenu() -> NSMenu {
        let menu = NSMenu()
        let status = NSMenuItem(title: "Claude Watch 正在后台守护", action: nil, keyEquivalent: "")
        status.isEnabled = false
        menu.addItem(status)
        menu.addItem(.separator())
        let show = NSMenuItem(title: "打开主窗口", action: #selector(showMainWindow), keyEquivalent: "")
        show.target = self
        menu.addItem(show)
        let hide = NSMenuItem(title: "隐藏主窗口", action: #selector(hideMainWindow), keyEquivalent: "")
        hide.target = self
        menu.addItem(hide)
        menu.addItem(.separator())
        let quit = NSMenuItem(title: "退出 Claude Watch", action: #selector(quitFromMenu), keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)
        return menu
    }

    @objc func showMainWindow() {
        guard let window = NSApp.windows.first(where: { Self.isMainWindow($0) }) else { return }
        NSApp.activate(ignoringOtherApps: true)
        if window.isMiniaturized { window.deminiaturize(nil) }
        window.makeKeyAndOrderFront(nil)
    }

    @objc func hideMainWindow() {
        for window in NSApp.windows where Self.isMainWindow(window) && !window.isMiniaturized {
            window.orderOut(nil)
        }
    }

    @objc private func quitFromMenu() {
        prepareToQuit()
        NSApp.terminate(nil)
    }

    func prepareToQuit() {
        quitting = true
    }

    // MARK: NSWindowDelegate — close collapses to the menu bar

    func windowShouldClose(_ window: NSWindow) -> Bool {
        guard Self.isMainWindow(window), !quitting else { return true }
        window.orderOut(nil)
        return false
    }
}
