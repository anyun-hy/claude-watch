import Foundation
import WebKit

@MainActor
protocol IPLeakDNSRunning: AnyObject {
    var onDiagnostic: ((String, Bool) -> Void)? { get set }
    func start(rounds: Int, id: UUID, progress: @escaping (String) -> Void,
               completion: @escaping (LeakProbeResult) -> Void)
    func cancel()
    func invalidate()
}
extension IPLeakDNSRunning { func invalidate() { cancel() } }
extension IPLeakDNSRunner: IPLeakDNSRunning {}

/// A native progress deadline protects against a suspended WebKit timer. A
/// retry starts an entirely new session; results from different rounds never
/// get combined, and a late callback from a cancelled round is ignored.
@MainActor
final class IPLeakDNSRetryRunner {
    private let makeRunner: () -> IPLeakDNSRunning
    private let stallTimeout, totalTimeout: TimeInterval
    private var active: IPLeakDNSRunning?
    private var stall: DispatchWorkItem?
    private var total: DispatchWorkItem?
    private var runID: UUID?
    private var attemptID: UUID?
    private var attempts = 0
    private var startedAt: Double = 0
    private var completion: ((LeakProbeResult) -> Void)?
    private var progress: ((String) -> Void)?
    private var rounds = 5
    var onDiagnostic: ((String, Bool) -> Void)?
    var onViewChanged: ((WKWebView?) -> Void)?
    var browserView: WKWebView? { (active as? IPLeakDNSRunner)?.browserView }
    func reattachIfNeeded(_ browser: WKWebView) { (active as? IPLeakDNSRunner)?.reattachIfNeeded(browser) }

    init(resourceDirectory: URL? = nil, stallTimeout: TimeInterval = 12, totalTimeout: TimeInterval = 75,
         makeRunner: (() -> IPLeakDNSRunning)? = nil) {
        self.makeRunner = makeRunner ?? { IPLeakDNSRunner(resourceDirectory: resourceDirectory) }
        self.stallTimeout = stallTimeout; self.totalTimeout = totalTimeout
    }
    func start(rounds: Int, id: UUID, progress: @escaping (String) -> Void = { _ in },
               completion: @escaping (LeakProbeResult) -> Void) {
        cancel()
        runID = id; self.rounds = rounds; self.progress = progress; self.completion = completion
        startedAt = Date().timeIntervalSince1970; attempts = 0
        let timer = DispatchWorkItem { [weak self] in self?.timedOut(id) }
        total = timer; DispatchQueue.main.asyncAfter(deadline: .now() + totalTimeout, execute: timer)
        beginAttempt(id)
    }
    private func beginAttempt(_ id: UUID) {
        guard runID == id else { return }
        attempts += 1
        let attempt = UUID(); attemptID = attempt
        let runner = active ?? makeRunner(); active = runner
        runner.onDiagnostic = { [weak self] event, attached in
            guard let self, self.runID == id, self.attemptID == attempt else { return }
            self.onDiagnostic?(event, attached)
        }
        armStall(id, attempt: attempt)
        runner.start(rounds: rounds, id: attempt, progress: { [weak self] label in
            guard let self, self.runID == id, self.attemptID == attempt else { return }
            self.armStall(id, attempt: attempt); self.progress?(label)
        }) { [weak self] result in
            guard let self, self.runID == id, self.attemptID == attempt else { return }
            self.finish(result)
        }
        if runID == id && attemptID == attempt { onViewChanged?(browserView) }
    }
    private func armStall(_ id: UUID, attempt: UUID) {
        stall?.cancel()
        let timer = DispatchWorkItem { [weak self] in
            guard let self, self.runID == id, self.attemptID == attempt else { return }
            if self.attempts < 2 {
                self.onDiagnostic?("dns_retry", self.browserView?.window != nil)
                self.attemptID = nil
                self.active?.invalidate(); self.active = nil
                self.progress?("IPLeak 请求无进展，正在重新检测。")
                self.beginAttempt(id)
            } else { self.timedOut(id) }
        }
        stall = timer; DispatchQueue.main.asyncAfter(deadline: .now() + stallTimeout, execute: timer)
    }
    private func timedOut(_ id: UUID) {
        guard runID == id else { return }
        onDiagnostic?("watchdog_timeout", browserView?.window != nil)
        active?.invalidate(); active = nil
        finish(.init(kind: "dns", status: "timeout", startedAt: startedAt,
                     finishedAt: Date().timeIntervalSince1970, scope: "IPLeak.net · 本机 WebView DNS 检测",
                     observations: [], errors: [.init(stage: "dns", code: "timeout", message: "IPLeak 检测在时限内没有完成。")],
                     contextChanged: false, details: []))
    }
    private func finish(_ result: LeakProbeResult) {
        let callback = completion
        if result.status != "complete" || !result.errors.isEmpty {
            active?.invalidate(); active = nil
        }
        cancel(); callback?(result)
    }
    func cancel() {
        runID = nil; attemptID = nil
        stall?.cancel(); stall = nil; total?.cancel(); total = nil
        active?.cancel(); onViewChanged?(nil); completion = nil; progress = nil
    }
    func invalidate() {
        cancel()
        active?.invalidate(); active = nil
    }
}
