import Darwin
import Foundation

/// Private JSONL diagnostics. Each component owns a bounded namespace; a new
/// attempt preserves recent failures without allowing logs to grow indefinitely.
/// Callers provide fixed schemas, never arbitrary error descriptions or payloads.
final class BoundedDiagnosticLog {
    static let defaultDirectory = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/ClaudeWatch/logs", isDirectory: true)
    let component: String
    private let directory: URL
    private let prefix: String
    private let overrideFile: URL?
    private let maxBytes: Int
    private let maxFiles: Int
    private let identity: [String: Any]
    private var fileURL: URL?
    private var recent: [String] = []
    private(set) var runID = UUID().uuidString
    private(set) var writeError = ""
    private(set) var paths: [String] = []

    init(component: String, directory: URL = defaultDirectory, overrideFile: URL? = nil,
         maxBytes: Int = 256 * 1024, maxFiles: Int = 16,
         identity: [String: Any]? = nil, runtimeDirectory: URL? = nil) {
        self.component = Self.code(component)
        self.prefix = Self.code(component).replacingOccurrences(of: "_", with: "-") + "-"
        self.overrideFile = overrideFile
        self.directory = overrideFile?.deletingLastPathComponent() ?? directory
        self.maxBytes = max(4096, maxBytes); self.maxFiles = max(1, min(32, maxFiles))
        self.identity = Self.sanitizedIdentity(identity ?? Self.readIdentity(runtimeDirectory: runtimeDirectory))
    }
    static func code(_ value: String) -> String {
        guard !value.isEmpty, value.utf8.count <= 96,
              value.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }) else { return "unknown" }
        return value
    }
    private static func readIdentity(runtimeDirectory: URL?) -> [String: Any] {
        var value = Bundle.main.infoDictionary ?? [:]
        let candidates = [Bundle.main.url(forResource: "BuildInfo", withExtension: "plist"),
                          runtimeDirectory?.appendingPathComponent("BuildInfo.plist")]
        for url in candidates.compactMap({ $0 }) {
            if let data = try? Data(contentsOf: url), data.count <= 64 * 1024,
               let build = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] {
                value.merge(build) { _, new in new }; break
            }
        }
        if let url = runtimeDirectory?.appendingPathComponent("BuildIdentity.json"),
           let data = try? Data(contentsOf: url), data.count <= 64 * 1024,
           let build = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            for (source, target) in [("source_revision", "SourceRevision"), ("source_dirty", "SourceDirty"),
                                      ("source_tree_digest", "SourceTreeDigest"), ("app_build", "AppBuild"),
                                      ("app_version", "ProductVersion")] {
                if let item = build[source] { value[target] = item }
            }
        }
        return value
    }
    static func sanitizedIdentity(_ value: [String: Any]) -> [String: Any] {
        func version(_ key: String, fallback: String? = nil) -> String {
            let raw = (value[key] as? String) ?? fallback.flatMap { value[$0] as? String } ?? "unknown"
            return raw.utf8.count <= 32 && !raw.isEmpty && raw.utf8.allSatisfy({ (48...57).contains($0) || $0 == 46 }) ? raw : "unknown"
        }
        func digest(_ key: String, lengths: [Int]) -> String {
            let raw = value[key] as? String ?? ""
            return lengths.contains(raw.utf8.count) && raw.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) ? raw : "unknown"
        }
        return ["app_version": version("CFBundleShortVersionString", fallback: "ProductVersion"),
                "app_build": version("AppBuild", fallback: "CFBundleVersion"),
                "source_revision": digest("SourceRevision", lengths: [40, 64]),
                "source_tree_digest": digest("SourceTreeDigest", lengths: [64]),
                "source_dirty": (value["SourceDirty"] as? Bool).map { $0 as Any } ?? NSNull()]
    }
    func begin() { runID = UUID().uuidString; fileURL = nil; writeError = "" }
    private func checkedDirectory() throws -> Int32 {
        if !FileManager.default.fileExists(atPath: directory.path) {
            let parent = directory.deletingLastPathComponent()
            var info = stat()
            guard lstat(parent.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                  info.st_uid == getuid(), info.st_mode & 0o022 == 0 else { throw POSIXError(.EACCES) }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                   attributes: [.posixPermissions: 0o700])
        }
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var info = stat()
        let forbidden: mode_t = overrideFile == nil ? 0o077 : 0o022
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & forbidden == 0 else {
            close(fd); throw POSIXError(.EACCES)
        }
        return fd
    }
    private func retainRecentFiles(directoryFD: Int32) throws {
        // Only this logger's generated UUID names, private regular files and
        // current owner are eligible. Never follow or remove a symlink.
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .compactMap { url -> (URL, timespec, Int64)? in
                let name = url.lastPathComponent
                guard name.hasPrefix(prefix), name.hasSuffix(".jsonl"),
                      UUID(uuidString: String(name.dropFirst(prefix.count).dropLast(6))) != nil else { return nil }
                var info = stat()
                guard fstatat(directoryFD, name, &info, AT_SYMLINK_NOFOLLOW) == 0,
                      info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { return nil }
                return (url, info.st_mtimespec, info.st_size)
            }.sorted { a, b in a.1.tv_sec == b.1.tv_sec ? a.1.tv_nsec > b.1.tv_nsec : a.1.tv_sec > b.1.tv_sec }
        var retained = 0, bytes: Int64 = 0
        let budget = Int64(maxBytes) * Int64(maxFiles - 1)
        for (url, _, size) in files {
            if retained < maxFiles - 1, size >= 0, size <= budget - bytes {
                retained += 1; bytes += size
            } else {
                guard unlinkat(directoryFD, url.lastPathComponent, 0) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            }
        }
    }
    func append(_ fields: [String: Any]) {
        do {
            var row = identity
            row.merge(fields) { _, new in new }
            row["schema"] = 1; row["component"] = component; row["run_id"] = runID
            let now = Date().timeIntervalSince1970
            row["time"] = (fields["time"] as? Double).flatMap { $0.isFinite ? $0 : nil } ?? now
            row["recorded_at"] = now; row["producer_pid"] = getpid()
            let data = try JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]) + Data([10])
            guard data.count <= 8192 else { throw POSIXError(.EFBIG) }
            recent.append(String(decoding: data, as: UTF8.self)); if recent.count > 256 { recent.removeFirst() }
            let dirFD = try checkedDirectory(); defer { close(dirFD) }
            for _ in 0..<2 {
                if fileURL == nil {
                    if overrideFile == nil { try retainRecentFiles(directoryFD: dirFD) }
                    fileURL = overrideFile ?? directory.appendingPathComponent(prefix + UUID().uuidString + ".jsonl")
                    paths.append(fileURL!.path); if paths.count > maxFiles { paths.removeFirst() }
                }
                let fd = openat(dirFD, fileURL!.lastPathComponent, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, mode_t(0o600))
                guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
                defer { close(fd) }
                // Logging must not stall initialization or an AppleEvent reply
                // behind another writer. A busy file is a visible log failure.
                guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
                defer { flock(fd, LOCK_UN) }
                var info = stat()
                guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(),
                      info.st_mode & 0o077 == 0, info.st_nlink == 1 else { throw POSIXError(.EACCES) }
                if info.st_size + Int64(data.count) > Int64(maxBytes) {
                    guard overrideFile == nil else { throw POSIXError(.EFBIG) }
                    fileURL = nil; continue
                }
                try data.withUnsafeBytes { bytes in
                    var offset = 0
                    while offset < bytes.count {
                        let written = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                        if written < 0 && errno == EINTR { continue }
                        guard written > 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
                        offset += written
                    }
                }
                guard fsync(fd) == 0 else { throw POSIXError(.EIO) }
                return
            }
            throw POSIXError(.EFBIG)
        } catch {
            let failure = "diagnostic_write_failed_\((error as NSError).code)"
            if writeError != failure {
                // Never interpolate the original NSError: it can contain paths.
                fputs("ClaudeWatch \(component): \(failure)\n", stderr)
            }
            writeError = failure
        }
    }
    var report: String {
        (["日志组件：\(component)", "记录文件："] + paths + (writeError.isEmpty ? [] : ["日志写入失败：\(writeError)"])
         + recent).joined(separator: "\n")
    }
}

/// The desktop entry only records transport outcomes, never URL/file contents
/// or exception messages. The same policy applies to fixture log overrides.
enum ControlledEntryDiagnosticFields {
    static func logger(stateDirectory: String, overridePath: String? = nil) -> BoundedDiagnosticLog {
        let root = URL(fileURLWithPath: stateDirectory).deletingLastPathComponent()
        let override = overridePath.flatMap { $0.isEmpty ? nil : URL(fileURLWithPath: $0) }
        return BoundedDiagnosticLog(component: "controlled_entry", directory: root.appendingPathComponent("logs"),
                                    overrideFile: override, runtimeDirectory: root.appendingPathComponent("runtime"))
    }
    static func sanitize(_ payload: [String: Any]) -> [String: Any] {
        var row: [String: Any] = ["source": "ControlledEntryApp", "event": "entry_event"]
        for key in ["event", "status", "code", "error", "reason", "trigger", "outcome", "state"] {
            if let value = payload[key] as? String { row[key] = BoundedDiagnosticLog.code(value) }
        }
        if let target = payload["target"] as? String {
            row["target"] = ["claude-desktop", "codex-desktop", "chatgpt-desktop"].contains(target) ? target : "other"
        }
        for key in ["pid", "verified_pid", "return_id", "os_status", "exit_code"] {
            if let value = payload[key] as? NSNumber, value.doubleValue.isFinite,
               value.doubleValue == Double(value.int64Value),
               value.int64Value >= Int64(Int32.min), value.int64Value <= Int64(UInt32.max) { row[key] = value.int64Value }
        }
        for key in ["activated", "appkit_activated", "apple_event_reply_confirmed"] {
            if let value = payload[key] as? Bool { row[key] = value }
        }
        if let value = payload["instance_id"] as? String {
            if let id = UUID(uuidString: value) { row["instance_id"] = id.uuidString }
            else if value.hasPrefix("sandbox-inst-"), let id = UUID(uuidString: String(value.dropFirst(13))) {
                row["instance_id"] = "sandbox-inst-" + id.uuidString.lowercased()
            }
        }
        if let value = payload["files"] as? [String] { row["file_count"] = value.count }
        if let value = payload["urls"] as? [String] { row["url_count"] = value.count }
        if let value = payload["unmanaged_pids"] as? [Int32] { row["unmanaged_process_count"] = value.count }
        return row
    }
}
