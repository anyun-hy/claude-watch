import SwiftUI

enum GraphLaunchTarget: Equatable {
    case claude, chatgpt

    init(product: MonitoredProduct) {
        self = product == .claude ? .claude : .chatgpt
    }
    var title: String { self == .claude ? "Claude" : "ChatGPT" }
    var arguments: [String] {
        self == .claude ? ["launch", "--apply"] : ["launch", "--target", "chatgpt-desktop", "--apply"]
    }
    func hasRunningDesktop(in processes: [WatchedProcess]) -> Bool {
        processes.contains { process in
            self == .claude ? process.kind == "desktop-main"
                : ["chatgpt-desktop-main", "openai-desktop-main"].contains(process.kind)
        }
    }
    /// A launch is only impossible when the backend cannot represent the target
    /// at all. This never depends on the (per-page) environment check, so it can
    /// gate the button without making it look stuck.
    @MainActor func capabilityBlockReason(store: SwitcherStore) -> String? {
        if self == .chatgpt && !store.isFixture {
            guard case .rustCandidate? = BundledBackendVariant.current() else {
                return "当前后台不支持从此处启动 ChatGPT。"
            }
        }
        return nil
    }
    /// The full pre-launch verification. This runs when the user actually taps
    /// launch (and is re-checked inside `launch`), so the environment/session
    /// prerequisites never gray out the button on a page that cannot satisfy
    /// them — they only surface as a clear result on the launch attempt.
    @MainActor func blockReason(store: SwitcherStore, at now: Date) -> String? {
        if let reason = capabilityBlockReason(store: store) { return reason }
        if let reason = store.graphLaunchBlockReason(for: self == .claude ? .claude : .openAI, at: now) { return reason }
        if self == .claude {
            guard let evidence = store.sessionDisplayEvidence,
                  evidence.backendReady, !evidence.isStale(at: now.timeIntervalSince1970) else {
                return "后台保护状态尚未确认，请查看后台保护。"
            }
            guard ["idle", "missing"].contains(evidence.session.state), evidence.session.phase != "locked" else {
                return "Claude 会话状态尚未就绪，请查看后台保护。"
            }
        }
        return nil
    }
}

struct GraphLaunchButton: View {
    let product: MonitoredProduct
    @ObservedObject var monitor: MonitorStore
    @ObservedObject var switcher: SwitcherStore
    @ObservedObject var processControl: AIProcessControl
    let p: Palette
    @State private var pending: GraphLaunchTarget?
    @State private var confirming = false
    @State private var resultTitle = ""
    @State private var resultMessage = ""
    @State private var showingResult = false

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let target = GraphLaunchTarget(product: product)
            let reason = buttonBlockReason(for: target, at: context.date)
            Button {
                pending = target
                confirming = true
            } label: {
                Label(switcher.busy ? "正在检查" : "启动 \(target.title)", systemImage: "play.fill")
                    .font(WatchTypography.caption.weight(.medium)).padding(.horizontal, 12).frame(height: 32)
                    .foregroundStyle(reason == nil ? (p.dark ? Color.black : Color.white) : p.secondary)
                    .background(reason == nil ? p.mint : p.elevated, in: RoundedRectangle(cornerRadius: 8))
            }
            .buttonStyle(.plain)
            .disabled(reason != nil)
            .help(reason ?? "环境预览已通过；启动时会重新执行完整检查。")
            .accessibilityHint(reason ?? "启动前将重新检查当前环境。")
            if switcher.busy {
                launchProgress
            }
        }
        .confirmationDialog("检查并启动 \(pending?.title ?? "应用")？", isPresented: $confirming, titleVisibility: .visible) {
            if let target = pending {
                Button("检查并启动 \(target.title)") { Task { await launch(target) } }
            }
            Button("取消", role: .cancel) { pending = nil }
        } message: {
            Text(pending == .chatgpt
                 ? "将重新执行 ChatGPT 桌面应用的启动检查。Claude 会话出口保护不覆盖 ChatGPT。"
                 : "将重新执行 Claude 的完整启动检查，通过后建立受控会话。")
        }
        .alert(resultTitle, isPresented: $showingResult) {
            Button("知道了", role: .cancel) {}
        } message: { Text(resultMessage) }
    }

    /// The live pre-launch check row. The backend announces which stage is
    /// running; before the first announcement (and for commands with no
    /// stages) this still shows an indeterminate spinner with the generic
    /// activity text, so the button never looks frozen.
    private var launchProgress: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text(switcher.activity.isEmpty ? "正在检查启动条件…" : switcher.activity)
                    .font(WatchTypography.caption).foregroundStyle(p.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if let stage = switcher.activityStage {
                ProgressView(value: Double(stage), total: Double(SetupProgressPhase.launchStageCount))
                    .controlSize(.small)
                Text("第 \(stage) / \(SetupProgressPhase.launchStageCount) 步：实测取样 → 核对策略 → 建立会话")
                    .font(WatchTypography.small).foregroundStyle(p.secondary)
            }
        }
        .padding(.top, 8)
        .accessibilityLabel("启动检查进度")
    }

    @MainActor
    private func buttonBlockReason(for target: GraphLaunchTarget, at now: Date) -> String? {        if processControl.busy { return "正在核对或关闭进程，请稍后再启动。" }
        if let reason = target.capabilityBlockReason(store: switcher) { return reason }
        // Fast lane first: the 2s desktop-presence poll answers immediately for
        // the common "already running" case without waiting for a full backend
        // snapshot. When the backend is absent or stale (e.g. during first-run),
        // fall back to the snapshot's desktop-main processes.
        let product: MonitoredProduct = target == .claude ? .claude : .openAI
        let unmanaged = monitor.unmanagedPids(for: product)
        if monitor.desktopRunning[product] == true {
            if !unmanaged.isEmpty {
                return "\(target.title) 已在运行（检测到未受控实例 running_unprotected，未受保护）。"
            }
            return "\(target.title) 已在运行。"
        }
        let sampleTime = switcher.isFixture ? monitor.now.timeIntervalSince1970 : now.timeIntervalSince1970
        if monitor.error == nil, let snapshot = monitor.snapshot,
           snapshot.health.state == "running",
           MonitorSnapshotTiming.isCurrent(capturedAt: snapshot.capturedAt, now: sampleTime),
           target.hasRunningDesktop(in: snapshot.processes) {
            if !unmanaged.isEmpty {
                return "\(target.title) 已在运行（检测到未受控实例 running_unprotected，未受保护）。"
            }
            return "\(target.title) 已在运行。"
        }
        return nil
    }

    @MainActor
    private func blockReason(for target: GraphLaunchTarget, at now: Date) -> String? {
        if let reason = buttonBlockReason(for: target, at: now) { return reason }
        // The environment/session prerequisites are only evaluated on the actual
        // launch attempt, never to gray out the button.
        if let reason = target.blockReason(store: switcher, at: now) { return reason }
        return nil
    }

    @MainActor
    private func launch(_ target: GraphLaunchTarget) async {
        pending = nil
        if let reason = blockReason(for: target, at: Date()) {
            resultTitle = "未启动 \(target.title)"
            resultMessage = reason
            showingResult = true
            return
        }
        switcher.dismissMessage()
        await switcher.perform(target.arguments)
        resultTitle = switcher.failure ? "启动未完成" : "启动结果"
        resultMessage = switcher.message.isEmpty ? switcher.auditOperationMessage : switcher.message
        if resultMessage.isEmpty { resultMessage = "未取得启动结果，请查看环境状态。" }
        showingResult = true
        if !switcher.isFixture { monitor.refresh(full: true, manual: true) }
    }
}
