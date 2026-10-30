import Darwin
import Foundation

/// Same-observation facts from service-status. No paths, arguments, addresses,
/// node names or account data are part of this diagnostic contract.
struct BackendInitializationDiagnostics: Codable {
    var reason: String
    var observed_at: Double?
    var heartbeat_present: Bool?
    var heartbeat_pid: Int?
    var heartbeat_status: String?
    var heartbeat_age_seconds: Double?
    var process_found: Bool?
    var start_identity_matches: Bool?
    var native_path_matches: Bool?
    var launchd_registered: Bool?
    var launchd_state: String?
    var launchd_pid: Int?
    var worker_verified: Bool?
    var worker_error_code: String?
    var source_error_code: String?

    static func code(_ text: String) -> String {
        guard !text.isEmpty, text.utf8.count <= 96,
              text.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }) else { return "unknown" }
        return text
    }
    var sanitized: Self {
        var value = self
        value.reason = Self.code(reason)
        value.heartbeat_status = heartbeat_status.map { ["ok", "error"].contains($0) ? $0 : "unknown" }
        value.launchd_state = launchd_state.map { ["running", "waiting", "not running", "absent", "unknown"].contains($0) ? $0 : "unknown" }
        value.worker_error_code = worker_error_code.map(Self.code)
        value.source_error_code = source_error_code.map(Self.code)
        return value
    }
    var failureDescription: String {
        let text: String
        switch reason {
        case "heartbeat_missing": text = "后台心跳文件尚未生成"
        case "heartbeat_unreadable": text = "后台心跳文件读取失败"
        case "heartbeat_encoding", "heartbeat_format": text = "后台心跳格式无效"
        case "pid_invalid": text = "心跳中的 PID 无效"
        case "time_invalid": text = "心跳时间无效"
        case "heartbeat_stale": text = "后台心跳已过期或时间异常"
        case "process_sample_failed": text = "系统进程信息读取失败"
        case "pid_unconfirmed": text = "心跳对应的进程不存在或无法确认"
        case "uid_invalid": text = "采集后台所属用户无效"
        case "identity_mismatch": text = "心跳与进程启动身份不匹配"
        case "job_unconfirmed": text = "launchd 任务或采集 worker 身份核对失败"
        case "native_path_mismatch": text = "后台进程的运行路径不匹配"
        case "status_read_failed": text = "后台健康状态读取失败"
        default: text = "后台未提供可确认的身份或心跳原因"
        }
        let underlying = worker_error_code ?? source_error_code
        return text + (underlying.map { "（\(Self.code($0))）" } ?? "") + "。具体记录见“检查记录”。"
    }
}

struct InitializationConnectionRecord: Encodable {
    let event, phase, code: String
    let time: Double
    var app_version: String?
    var app_build: String?
    var backend_read_error: String?
    var backend_healthy: Bool?
    var native_backend_healthy: Bool?
    var backend_receipt_age_seconds: Double?
    var backend: BackendInitializationDiagnostics?
    var snapshot_read_failed: Bool?
    var snapshot_present: Bool?
    var snapshot_age_seconds: Double?
    var installed: Bool?
    var auto_start: Bool?
    var keep_alive: Bool?
    var proxy_present: Bool?
    var proxy_read_failed: Bool?
    var proxy_age_seconds: Double?
    var proxy_entry_verified: Bool?
    var proxy_api_available: Bool?
    var proxy_port_covered: Bool?
    var context_available: Bool?
    var same_candidate_context: Bool?
    var source_sample_advanced: Bool?
    var deadline_remaining_seconds: Double?
}

/// One private file per attempt: a successful retry cannot erase the first
/// failure. Writes happen before returning the result, not in a detached task.
@MainActor
final class InitializationConnectionLog {
    private let directory: URL?
    private var file: FileHandle?
    private var attempt = ""
    private var records: [String] = []
    private var paths: [String] = []
    private(set) var writeError = ""
    private var count = 0

    init(directory: URL? = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/ClaudeWatch/logs", isDirectory: true)) {
        self.directory = directory
    }
    private func privateDirectory(_ url: URL) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              attributes[.type] as? FileAttributeType == .typeDirectory,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              let mode = attributes[.posixPermissions] as? NSNumber else { return false }
        return mode.intValue & 0o077 == 0
    }
    func begin() {
        try? file?.close(); file = nil
        attempt = UUID().uuidString; count = 0; writeError = ""
        guard let directory else { return }
        do {
            guard privateDirectory(directory.deletingLastPathComponent()) else { throw CocoaError(.fileWriteNoPermission) }
            if !FileManager.default.fileExists(atPath: directory.path) {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o700])
            }
            guard privateDirectory(directory) else { throw CocoaError(.fileWriteNoPermission) }
            let dirFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            guard dirFD >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            defer { close(dirFD) }
            let name = "initialization-\(attempt).jsonl"
            let fd = openat(dirFD, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
            guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            paths.append(directory.appendingPathComponent(name).path)
        } catch { writeError = "初始化日志写入失败（错误码 \((error as NSError).code)）；以下记录仅保留在当前窗口。" }
    }
    func append(_ value: InitializationConnectionRecord) {
        guard count < 256 else { return }
        count += 1
        do {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            var object = try JSONSerialization.jsonObject(with: encoder.encode(value)) as! [String: Any]
            object["schema"] = 1; object["attempt_id"] = attempt
            let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) + Data([10])
            guard data.count <= 8192 else { throw CocoaError(.fileWriteUnknown) }
            records.append(String(decoding: data, as: UTF8.self).trimmingCharacters(in: .newlines))
            if records.count > 512 { records.removeFirst() }
            try file?.write(contentsOf: data)
            if ["passed", "failed", "cancelled"].contains(value.event) {
                try file?.synchronize(); try file?.close(); file = nil
            }
        } catch { writeError = "初始化日志写入失败（错误码 \((error as NSError).code)）；以下记录仅保留在当前窗口。" }
    }
    var report: String {
        guard !records.isEmpty else { return "" }
        return (["第 2 步逐轮诊断（含本次窗口的首次检查与重试）："] + paths.map { "日志文件：" + $0 }
                + (writeError.isEmpty ? [] : [writeError]) + records).joined(separator: "\n")
    }
}
