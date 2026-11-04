import Foundation

/// Presentation of the same read-only service receipt used by Background Protection.
/// It cannot establish a session or grant launch permission.
struct SessionBaselinePresentation {
    let title, detail, symbol: String
    let tone: String

    static func make(_ receipt: BackgroundServiceReceipt?, error: String = "", now: Double) -> Self {
        guard let receipt, let evidence = SessionProtectionEvidence.fromBackground(receipt, error: error) else {
            if !error.isEmpty {
                let display = SessionProtectionPresentation.unavailable(error: error)
                return .init(title: display.title, detail: display.detail,
                             symbol: display.symbol, tone: display.tone)
            }
            return .init(title: "正在读取会话基准", detail: "正在读取自动保护的会话记录。",
                         symbol: "clock", tone: "info")
        }
        return make(evidence: evidence, now: now)
    }
    static func make(evidence: SessionProtectionEvidence?, now: Double) -> Self {
        guard let evidence else {
            return .init(title: "正在读取会话基准", detail: "正在读取自动保护的会话记录。", symbol: "clock", tone: "info")
        }
        let session = evidence.session
        let reference = session.baseline
        let baseline = [reference?.ip, reference?.country].compactMap { $0 }.joined(separator: " / ")
        let date = reference?.observed_at.map { Date(timeIntervalSince1970: $0).formatted(date: .numeric, time: .shortened) }
        let saved = baseline.isEmpty ? "" : "基准：\(baseline)" + (date.map { " · 建立于 \($0)" } ?? "")
        if session.state == "locked" || session.phase == "locked" {
            let display = evidence.presentation(at: now)
            return .init(title: display.title, detail: [saved, display.detail].filter { !$0.isEmpty }.joined(separator: "。"),
                         symbol: "shield.slash", tone: "danger")
        }
        // A failed current read is a warning even when an older baseline
        // remains visible. Keep locked risk above this branch: a failed read
        // must not downgrade a previously latched danger.
        if !evidence.readError.isEmpty {
            let display = evidence.presentation(at: now)
            return .init(title: display.title,
                         detail: [saved, display.detail].filter { !$0.isEmpty }.joined(separator: "。"),
                         symbol: display.symbol, tone: display.tone)
        }
        guard !evidence.isStale(at: now) else {
            return .init(title: baseline.isEmpty ? "会话基准读取未完成" : "上次会话基准",
                         detail: [saved, evidence.readError.isEmpty ? "当前保护状态等待更新；历史记录不用于启动放行。" : evidence.readError].filter { !$0.isEmpty }.joined(separator: "。"),
                         symbol: "clock", tone: "info")
        }
        let display = evidence.presentation(at: now)
        if session.state == "idle" || !evidence.backendReady {
            return .init(title: display.title, detail: display.detail + (saved.isEmpty ? "" : " 上次会话" + saved),
                         symbol: display.symbol, tone: display.tone)
        }
        guard !baseline.isEmpty else {
            return .init(title: "等待受控启动建立会话基准", detail: "点击“检查并启动 Claude”时，完整校验通过后自动建立，无需手动配置。",
                         symbol: "info.circle", tone: "info")
        }
        if display.tone == "success", reference?.ip == session.current?.ip,
           reference?.country == session.current?.country {
            return .init(title: "会话基准已自动建立", detail: saved + "。当前出口已核对。",
                         symbol: "checkmark.shield", tone: "success")
        }
        return .init(title: "会话基准已建立，当前状态待核对",
                     detail: saved + "。" + (session.reason?.detail ?? "等待本轮保护检测；不会使用历史基准直接放行。"),
                     symbol: "clock", tone: "warning")
    }
}
