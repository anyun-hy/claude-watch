import SwiftUI

/// Shared display evidence. This never changes a session, a gate or a protection decision.
struct SessionProtectionEvidence {
    let session: SessionGuardStatus
    let observedAt: Double
    let backendReady: Bool
    var readError: String = ""

    static func fromBackground(_ receipt: BackgroundServiceReceipt, error: String = "") -> Self? {
        guard let session = receipt.session_guard else { return nil }
        let backendReady = (receipt.guard_backend_healthy ?? receipt.backend_healthy) &&
            receipt.services.first(where: { $0.id == "guard" })?.healthy == true
        return .init(session: session, observedAt: (session.state == "idle" || session.state == "missing" || session.state == "pending") ? receipt.observed_at : (session.sampled_at ?? 0), backendReady: backendReady, readError: error)
    }

    func isStale(at now: Double) -> Bool {
        let age = now - observedAt
        let activeExpired = session.state == "safe" && (session.valid_until.map { !$0.isFinite || now > $0 } ?? true)
        return !readError.isEmpty || !age.isFinite || age < 0 || age > 35 || activeExpired
    }
    func presentation(at now: Double) -> SessionProtectionPresentation {
        if !readError.isEmpty && session.state != "risk" && session.state != "locked" && session.phase != "locked" {
            return .init(title: "保护状态读取失败", detail: "保留上次记录：" + readError, symbol: "exclamationmark.triangle", tone: "warning")
        }
        return .make(session, stale: isStale(at: now), backendReady: backendReady)
    }
}

struct SessionProtectionPresentation {
    let title, detail, symbol, tone: String
    static let idleTitle = "后台保护待命"
    static let idleDetail = "后台保护待命，无需操作。Claude 已关闭；下次使用时通过“检查并启动 Claude”执行完整校验。"
    static let loading = Self(title: "正在读取保护状态", detail: "正在读取后台检测结果。", symbol: "clock", tone: "info")

    static func make(_ session: SessionGuardStatus, stale: Bool = false, backendReady: Bool = true) -> Self {
        if session.state == "risk" || session.state == "locked" || session.phase == "locked" {
            let stop = session.stop_state == "confirmed" ? "Claude 已确认退出。" : (session.stop_state == "failed" ? "退出失败（\(session.stop_error ?? "未知错误")），待后台重试。" : "正在等待退出确认。")
            return .init(title: "会话保护已触发",
                         detail: (session.reason?.detail ?? "保护检测命中阻断条件。") + " " + stop,
                         symbol: "pause.circle", tone: "danger")
        }
        if stale {
            return .init(title: "正在更新保护状态", detail: "显示的是上次记录，正在等待新的后台检测结果。",
                         symbol: "clock", tone: "info")
        }
        if !backendReady {
            return .init(title: "保护后台不可用", detail: "尚未取得有效保护心跳或保护未启用；具体原因见“后台保护”。",
                         symbol: "exclamationmark.shield", tone: "warning")
        }
        switch session.state {
        case "idle":
            return .init(title: idleTitle, detail: idleDetail, symbol: "shield", tone: "info")
        case "safe":
            if ["egress_unconfirmed", "risk_evidence_missing", "risk_evidence_unavailable"].contains(session.reason?.code ?? "") {
                return .init(title: "本轮保护检测未完成", detail: session.reason?.detail ?? "正在重试采样。",
                             symbol: "clock", tone: "info")
            }
            return .init(title: "保护运行中", detail: "会话基准与当前出口已核对。", symbol: "checkmark.shield", tone: "success")
        case "pending":
            if session.phase == "rechecking" {
                return .init(title: "正在复核新进程", detail: "旧会话已结束，正在重新核验 Claude 身份和网络；出口保护继续运行。", symbol: "clock", tone: "info")
            }
            return .init(title: "正在建立受控会话", detail: "正在绑定 Claude 启动进程，完成后自动更新。", symbol: "clock", tone: "info")
        case "missing":
            return .init(title: "等待受控启动", detail: "使用“检查并启动 Claude”时自动建立会话，无需手动配置。", symbol: "shield", tone: "info")
        default:
            return .init(title: "本轮保护检测未完成", detail: session.reason?.detail ?? "尚未取得有效的本轮保护检测结果，正在等待下一轮采样。",
                         symbol: "clock", tone: "info")
        }
    }
}

/// The same read-only status presentation is used wherever the session appears.
struct SessionProtectionStatusView: View {
    let value: SessionProtectionPresentation
    let p: Palette
    private var tint: Color {
        value.tone == "danger" ? p.red : value.tone == "warning" ? p.amber :
            (value.tone == "success" || value.title == SessionProtectionPresentation.idleTitle) ? p.color(0x4ADE80, 0x087D36) : p.secondary
    }
    var body: some View {
        InlineNotice(title: value.title, detail: value.detail, symbol: value.symbol,
                     tint: tint, p: p, iconSize: 24, iconWidth: 32, iconWeight: .medium)
    }
}
