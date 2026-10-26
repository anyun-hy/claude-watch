import SwiftUI

struct AIProcessCloseButton: View {
    let product: MonitoredProduct
    @ObservedObject var store: MonitorStore
    @ObservedObject var control: AIProcessControl
    let p: Palette
    @State private var pending: AIProcessClosePlan?
    @State private var confirming = false
    @State private var message = ""
    @State private var showingMessage = false
    var body: some View {
        Button {
            Task {
                do {
                    let plan = try await control.prepare(product, sampled: store.snapshot?.processes ?? [],
                                                         backendPID: store.snapshot?.health.pid)
                    if plan.targets.isEmpty {
                        message = "当前未发现可核实的 \(product.title) 进程。"; showingMessage = true
                    } else { pending = plan; confirming = true }
                } catch { message = error.localizedDescription; showingMessage = true }
            }
        } label: {
            Label(control.busy ? "正在核对" : "退出 \(product.title)", systemImage: "power")
                .font(.body.weight(.medium)).padding(.horizontal, 2).frame(minHeight: 28)
        }
        .buttonStyle(.bordered).controlSize(.large).tint(p.red).disabled(control.busy)
        .help("核对身份后关闭 \(product.title) 桌面应用、CLI 与关联子进程")
        .accessibilityLabel("退出 \(product.title)")
        .confirmationDialog("退出 \(product.title)？", isPresented: $confirming, titleVisibility: .visible) {
            if let plan = pending {
                Button("关闭 \(plan.targets.count) 个已核实进程", role: .destructive) {
                    Task {
                        message = await control.execute(plan); pending = nil; showingMessage = true
                        if !control.isFixture { store.refresh(full: true, manual: true) }
                    }
                }
            }
            Button("取消", role: .cancel) { pending = nil }
        } message: {
            Text(control.isFixture ? "当前为隔离预览，只模拟关闭，不影响实际应用。"
                 : product == .openAI ? "将结束 ChatGPT / Codex 桌面应用与独立 CLI，当前 Codex 对话和运行任务可能中断。"
                 : "将结束 Claude Desktop、Claude Code 及已核实的关联进程，正在运行的会话可能中断。")
        }
        .alert(control.isFixture ? "进程关闭 · 模拟结果" : "进程关闭结果", isPresented: $showingMessage) {
            Button("知道了", role: .cancel) {}
        } message: { Text(message) }
    }
}
