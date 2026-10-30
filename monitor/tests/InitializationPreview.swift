import AppKit
import SwiftUI

@MainActor
private final class PreviewInitializationChecks: InitializationChecking {
    let fails: Bool
    init(fails: Bool) { self.fails = fails }
    func begin() {}
    func check(_ step: InitializationStep) async -> InitializationResult {
        if fails && step == .dns { return .failed(code: "timeout", detail: "本轮 DNS 查询未完整结束。请确认网络稳定后重新检查；已有结果保留用于核对。") }
        return .passed("隔离模拟：此项已核对，未读取实际网络或执行系统操作。", validUntil: Date().timeIntervalSince1970 + 120)
    }
    func approve(_ request: InitializationApproval, progress: @escaping SetupProgressObserver) async -> InitializationResult { .failed(code: "preview", detail: "界面验收不执行授权。") }
    func validateCurrentEvidence() -> InitializationResult { .passed("fixture", validUntil: Date().timeIntervalSince1970 + 120) }
    func finish() {}
}

@main
struct InitializationPreview {
    @MainActor static func main() async throws {
        guard CommandLine.arguments.count == 2 else { fatalError("Expected an output directory") }
        let output = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        NSApplication.shared.setActivationPolicy(.prohibited)
        for dark in [false, true] {
            for failed in [true, false] {
                UserDefaults.standard.setVolatileDomain(["darkAppearance": dark], forName: UserDefaults.argumentDomain)
                let store = MonitorStore(leakChecks: LeakCheckStore(isFixture: true), aiChecks: AIProbeStore(isFixture: true), switcher: SwitcherStore(isFixture: true))
                let checks = PreviewInitializationChecks(fails: failed)
                let initialization = FirstRunInitialization(checks: checks, completed: false, saveCompletion: {})
                await initialization.start()
                let view = NSHostingView(rootView: FirstRunView(store: store, initialization: initialization))
                let size = NSSize(width: 1120, height: 900)
                let window = NSWindow(contentRect: NSRect(origin: .zero, size: size), styleMask: [.borderless], backing: .buffered, defer: false)
                window.isReleasedWhenClosed = false
                window.contentView = view
                view.frame = NSRect(origin: .zero, size: size)
                view.layoutSubtreeIfNeeded()
                window.displayIfNeeded()
                try await Task.sleep(nanoseconds: 200_000_000)
                guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { fatalError("No bitmap") }
                view.cacheDisplay(in: view.bounds, to: bitmap)
                guard let png = bitmap.representation(using: .png, properties: [:]) else { fatalError("No PNG") }
                let name = "initialization-\(dark ? "dark" : "light")-\(failed ? "failed" : "ready").png"
                try png.write(to: output.appendingPathComponent(name))
                window.close()
                print("Rendered \(name); fixtures only")
            }
        }
    }
}
