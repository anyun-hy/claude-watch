import Combine
import Darwin
import Foundation

enum InitializationStep: String, CaseIterable, Codable, Identifiable {
    case components, connection, environment, accessibility, dns, webrtc, protection, verification
    var id: String { rawValue }
    var title: String {
        switch self {
        case .components: return "运行组件与数据目录"
        case .connection: return "采集后台与本机代理"
        case .environment: return "实测环境与设置"
        case .accessibility: return "辅助功能授权"
        case .dns: return "DNS 主检测"
        case .webrtc: return "WebRTC 泄漏检测"
        case .protection: return "启用 Watch 自有守护"
        case .verification: return "环境与保护状态联合复核"
        }
    }
}
enum InitializationStatus: String, Codable {
    case pending, running, authorization, passed, failed
    var title: String {
        switch self {
        case .pending: return "等待检查"
        case .running: return "正在检查"
        case .authorization: return "等待授权"
        case .passed: return "已通过"
        case .failed: return "未通过"
        }
    }
}
struct InitializationRow: Identifiable {
    let step: InitializationStep
    var status: InitializationStatus = .pending
    var detail = ""
    var code = "pending"
    var checkedAt: Double?
    var id: String { step.rawValue }
}
struct InitializationApproval: Identifiable, Equatable {
    enum Action { case environment, accessibility, protection }
    let id: String
    let action: Action
    let title, detail: String
    let changes: [String]
}
enum InitializationResult {
    case passed(String, validUntil: Double? = nil)
    case approval(InitializationApproval)
    case failed(code: String, detail: String)
}

@MainActor
protocol InitializationChecking: AnyObject {
    func begin()
    func check(_ step: InitializationStep) async -> InitializationResult
    func approve(_ request: InitializationApproval, progress: @escaping SetupProgressObserver) async -> InitializationResult
    func validateCurrentEvidence() -> InitializationResult
    func finish()
}
extension InitializationChecking {
    func approve(_ request: InitializationApproval) async -> InitializationResult {
        await approve(request, progress: { _ in })
    }
}

/// This marker remembers onboarding only. It contains no address, account,
/// policy, token or launch permission, and is never consulted by the guard.
struct InitializationMarker: Codable {
    let schema: Int
    let completedAt: Double
    let checks: [InitializationStep]
}
struct InitializationStorage {
    let directory: URL
    init(directory: URL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/ClaudeWatch", isDirectory: true)) {
        self.directory = directory.standardizedFileURL
    }
    private var marker: URL { directory.appendingPathComponent("initialization.json") }
    private func privateItem(_ path: URL, type: FileAttributeType) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path.path),
              attributes[.type] as? FileAttributeType == type,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              let mode = attributes[.posixPermissions] as? NSNumber else { return false }
        return mode.intValue & 0o077 == 0
    }
    func isComplete(at now: Double = Date().timeIntervalSince1970) -> Bool {
        guard privateItem(directory, type: .typeDirectory), privateItem(marker, type: .typeRegular),
              FileManager.default.fileExists(atPath: directory.appendingPathComponent("switcher/config.json").path),
              let size = try? marker.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 4096,
              let data = try? Data(contentsOf: marker),
              let value = try? JSONDecoder().decode(InitializationMarker.self, from: data) else { return false }
        return value.schema == 1 && value.completedAt.isFinite && value.completedAt > 0 && value.completedAt <= now
            && value.checks == InitializationStep.allCases
    }
    func complete(at now: Double = Date().timeIntervalSince1970) throws {
        // The backend must already have created this private app-owned root.
        guard privateItem(directory, type: .typeDirectory),
              FileManager.default.fileExists(atPath: directory.appendingPathComponent("switcher/config.json").path),
              now.isFinite, now > 0 else { throw CocoaError(.fileWriteNoPermission) }
        if FileManager.default.fileExists(atPath: marker.path), !privateItem(marker, type: .typeRegular) {
            throw CocoaError(.fileWriteNoPermission)
        }
        let temporary = directory.appendingPathComponent(".initialization-" + UUID().uuidString)
        guard FileManager.default.createFile(atPath: temporary.path, contents: nil,
                                             attributes: [.posixPermissions: 0o600]) else {
            throw CocoaError(.fileWriteUnknown)
        }
        defer { try? FileManager.default.removeItem(at: temporary) }
        let data = try JSONEncoder().encode(InitializationMarker(schema: 1, completedAt: now,
                                                               checks: InitializationStep.allCases))
        let handle = try FileHandle(forWritingTo: temporary)
        defer { try? handle.close() }
        try handle.write(contentsOf: data)
        try handle.synchronize()
        guard rename(temporary.path, marker.path) == 0 else { throw CocoaError(.fileWriteUnknown) }
    }
}

/// A single sequential owner. Pending, unavailable, expired and refused
/// authorization states have no path to the application's main interface.
@MainActor
final class FirstRunInitialization: ObservableObject {
    @Published private(set) var rows = InitializationStep.allCases.map { InitializationRow(step: $0) }
    @Published private(set) var approval: InitializationApproval?
    @Published private(set) var running = false
    @Published private(set) var entered: Bool
    @Published private(set) var validUntil: Double?
    private let checks: InitializationChecking
    private let saveCompletion: () throws -> Void
    private var started = false
    private var approvalOperation: UUID?

    init(checks: InitializationChecking, completed: Bool, saveCompletion: @escaping () throws -> Void) {
        self.checks = checks; self.entered = completed; self.saveCompletion = saveCompletion
    }
    var passedCount: Int { rows.filter { $0.status == .passed }.count }
    var allPassed: Bool { rows.allSatisfy { $0.status == .passed } }
    func canEnter(at now: Double) -> Bool {
        !entered && !running && allPassed && approval == nil && validUntil.map { now < $0 } == true
    }
    func start() async {
        guard !started, !entered else { return }
        started = true
        checks.begin()
        await run(from: 0)
    }
    func retry() async {
        guard !running, !entered else { return }
        // Rechecking all dependencies prevents combining greens from before
        // a network/permission change with results obtained after it.
        rows = InitializationStep.allCases.map { InitializationRow(step: $0) }
        approval = nil; validUntil = nil
        await run(from: 0)
    }
    private func run(from index: Int) async {
        guard !running else { return }
        running = true
        defer { running = false }
        for offset in index..<rows.count {
            rows[offset].status = .running
            rows[offset].detail = "正在读取实际状态…"
            let result = await checks.check(rows[offset].step)
            guard !Task.isCancelled else {
                accept(.failed(code: "cancelled", detail: "本轮检查已取消，请重新检查。"), at: offset)
                return
            }
            guard accept(result, at: offset) else { return }
        }
    }
    @discardableResult
    private func accept(_ result: InitializationResult, at index: Int) -> Bool {
        rows[index].checkedAt = Date().timeIntervalSince1970
        switch result {
        case .passed(let detail, let expiry):
            rows[index].status = .passed; rows[index].detail = detail; rows[index].code = "passed"
            if let expiry { validUntil = expiry }
            approval = nil
            return true
        case .approval(let request):
            rows[index].status = .authorization; rows[index].detail = request.detail
            rows[index].code = request.action == .accessibility ? "authorization_required" : "confirmation_required"
            approval = request
        case .failed(let code, let detail):
            rows[index].status = .failed; rows[index].detail = detail; rows[index].code = code
            approval = nil
        }
        validUntil = nil
        return false
    }
    func authorize(_ request: InitializationApproval) async {
        guard !running, !entered, request == approval,
              let index = rows.firstIndex(where: { $0.status == .authorization }) else { return }
        running = true
        rows[index].status = .running
        rows[index].detail = request.action == .accessibility
            ? "正在请求辅助功能授权，请在系统设置中确认…" : SetupProgressPhase.verifyEgress.detail
        let operation = UUID(); approvalOperation = operation
        let result = await checks.approve(request, progress: { [weak self] phase in
            guard let self, self.approvalOperation == operation, self.running,
                  self.rows[index].status == .running else { return }
            self.rows[index].detail = phase.detail
            self.rows[index].code = "progress_" + phase.rawValue
        })
        approvalOperation = nil
        let accepted = accept(result, at: index)
        running = false
        if accepted { await run(from: index + 1) }
    }
    func recheckAuthorization() async {
        guard !running, approval?.action == .accessibility,
              let index = rows.firstIndex(where: { $0.step == .accessibility }) else { return }
        running = true
        let accepted = accept(await checks.check(.accessibility), at: index)
        running = false
        if accepted { await run(from: index + 1) }
    }
    func refreshReadiness() {
        guard !entered, !running, allPassed else { return }
        let index = rows.count - 1
        if let expiry = validUntil, Date().timeIntervalSince1970 >= expiry {
            accept(.failed(code: "evidence_expired", detail: "检查结果已过期，请重新检查。"), at: index)
        } else {
            let result = checks.validateCurrentEvidence()
            if case .failed = result { accept(result, at: index) }
        }
    }
    func enter() async {
        guard canEnter(at: Date().timeIntervalSince1970) else { refreshReadiness(); return }
        running = true
        let index = rows.count - 1
        rows[index].status = .running
        let result = await checks.check(.verification)
        guard !Task.isCancelled else {
            accept(.failed(code: "cancelled", detail: "本轮检查已取消，请重新检查。"), at: index)
            running = false
            return
        }
        guard accept(result, at: index),
              accept(checks.validateCurrentEvidence(), at: index), allPassed else { running = false; return }
        do {
            try saveCompletion()
            checks.finish()
            entered = true
        } catch {
            accept(.failed(code: "completion_write_failed", detail: "初始化记录未能保存，请检查 Watch 数据目录权限后重试。"), at: index)
        }
        running = false
    }
    /// Diagnostic export is deliberately status-only. UI details can contain
    /// detected addresses, so they are never interpolated into this report.
    var diagnosticReport: String {
        let values = rows.map { row in
            let safe = row.code.utf8.count <= 64 && row.code.unicodeScalars.allSatisfy {
                CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789_").contains($0)
            }
            return "\(row.step.rawValue)\t\(row.status.rawValue)\t\(safe ? row.code : "unknown")\t\(row.checkedAt.map { String(Int($0)) } ?? "-")"
        }
        return (["Claude Watch 首次初始化检查", "仅含检查步骤、状态、原因代码及时间；不含 IP、节点、账号或凭据。"] + values).joined(separator: "\n")
    }
}
