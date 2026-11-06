import Foundation
import Darwin
import Security

/// Ownership is independent of the current permission to use the gateway.
enum ChannelOwnership: Equatable { case managed, unmanaged, uncertain }

struct ChannelProcessIdentity: Codable, Hashable {
    let pid: UInt32
    let uid: UInt32
    let start_seconds: UInt64
    let start_microseconds: UInt32
    let audit_token: [UInt32]?

    func matches(_ other: Self) -> Bool {
        sameLifetime(other)
            && audit_token != nil && audit_token == other.audit_token
    }
    func sameLifetime(_ other: Self) -> Bool {
        pid == other.pid && uid == other.uid && start_seconds == other.start_seconds
            && start_microseconds == other.start_microseconds
    }
    var valid: Bool {
        pid > 1 && pid <= UInt32(Int32.max) && uid > 0 && start_seconds > 0 && start_microseconds < 1_000_000
            && (audit_token == nil || (audit_token?.count == 8 && audit_token?[5] == pid && audit_token?[1] == uid))
    }
}

enum ChannelCodeIdentity {
    static let engineID = "io.local.watchpanel.engine"
    static func words(_ data: Data?) -> [UInt32]? {
        guard let data, data.count == 32 else { return nil }
        return data.withUnsafeBytes { bytes in (0..<8).map { bytes.loadUnaligned(fromByteOffset: $0 * 4, as: UInt32.self) } }
    }
    static func code(_ token: Data) -> SecCode? {
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: token] as CFDictionary, [], &code) == errSecSuccess else { return nil }
        return code
    }
    static func satisfies(_ code: SecCode, _ text: String) -> Bool {
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement else { return false }
        return SecCodeCheckValidity(code, [], requirement) == errSecSuccess
    }
    static func signingInfo(_ code: SecCode) -> [String: Any]? {
        var staticCode: SecStaticCode?
        var info: CFDictionary?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess else { return nil }
        return info as? [String: Any]
    }
    static let ownTeam: String? = {
        var own: SecCode?
        guard SecCodeCopySelf([], &own) == errSecSuccess, let own,
              satisfies(own, "anchor apple generic"),
              let team = signingInfo(own)?[kSecCodeInfoTeamIdentifier as String] as? String,
              team.count == 10, team.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) }) else { return nil }
        return team
    }()
    static func engineRequirement(team: String) -> String {
        "anchor apple generic and identifier \"\(engineID)\" and certificate leaf[subject.OU] = \"\(team)\""
    }
    static func peerAuditWords(fd: Int32, uid: uid_t) -> [UInt32]? {
        var token = [UInt32](repeating: 0, count: 8)
        var size = socklen_t(32)
        guard getsockopt(fd, 0, LOCAL_PEERTOKEN, &token, &size) == 0, size == 32,
              token[1] == uid, token[5] > 1 else { return nil }
        return token
    }
    static func authenticatedGateway(fd: Int32, uid: uid_t) -> Bool {
        guard let token = peerAuditWords(fd: fd, uid: uid), let team = ownTeam,
              let code = token.withUnsafeBytes({ code(Data($0)) }) else { return false }
        return satisfies(code, engineRequirement(team: team))
    }
    static func auditToken(pid: UInt32) -> Data? {
        guard pid > 1, pid <= UInt32(Int32.max) else { return nil }
        var task: mach_port_name_t = 0
        guard task_name_for_pid(mach_task_self_, Int32(pid), &task) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, task) }
        var token = audit_token_t()
        var count = mach_msg_type_number_t(8)
        let status = withUnsafeMutablePointer(to: &token) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: 8) { task_info(task, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count) }
        }
        guard status == KERN_SUCCESS, count == 8 else { return nil }
        return withUnsafeBytes(of: token) { Data($0) }
    }
    struct Process {
        let identity: ChannelProcessIdentity
        let parent: UInt32
        let executable: String
        let token: Data
    }
    static func process(pid: UInt32, token: Data? = nil) -> Process? {
        guard pid > 1, pid <= UInt32(Int32.max), let before = token ?? auditToken(pid: pid),
              let words = words(before), words[5] == pid else { return nil }
        var info = proc_bsdinfo()
        var confirm = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        var path = [CChar](repeating: 0, count: 4096)
        var raw = before.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
        guard proc_pidinfo(Int32(pid), PROC_PIDTBSDINFO, 0, &info, size) == size,
              words[1] == info.pbi_uid,
              proc_pidpath_audittoken(&raw, &path, UInt32(path.count)) > 0,
              proc_pidinfo(Int32(pid), PROC_PIDTBSDINFO, 0, &confirm, size) == size,
              info.pbi_uid == confirm.pbi_uid, info.pbi_start_tvsec == confirm.pbi_start_tvsec,
              info.pbi_start_tvusec == confirm.pbi_start_tvusec, info.pbi_ppid == confirm.pbi_ppid,
              auditToken(pid: pid) == before else { return nil }
        return Process(identity: .init(pid: pid, uid: info.pbi_uid, start_seconds: info.pbi_start_tvsec,
            start_microseconds: UInt32(info.pbi_start_tvusec), audit_token: words), parent: info.pbi_ppid,
            executable: String(cString: path), token: before)
    }

    /// Read only argv (not the following environment) and cwd for known
    /// interpreters. Fence both reads by the same kernel exec identity.
    static func invocation(_ process: Process) -> (arguments: [String], cwd: String?)? {
        guard auditToken(pid: process.identity.pid) == process.token else { return nil }
        var mib = [CTL_KERN, KERN_PROCARGS2, Int32(process.identity.pid)]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4, size <= 1_048_576 else { return nil }
        var data = Data(count: size)
        let status = data.withUnsafeMutableBytes { sysctl(&mib, 3, $0.baseAddress, &size, nil, 0) }
        guard status == 0 else { return nil }
        data.count = size
        guard let arguments = channelProcessArguments(data) else { return nil }
        var paths = proc_vnodepathinfo()
        let pathSize = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        var cwd: String?
        if proc_pidinfo(Int32(process.identity.pid), PROC_PIDVNODEPATHINFO, 0, &paths, pathSize) == pathSize {
            cwd = withUnsafeBytes(of: paths.pvi_cdir.vip_path) { bytes in
                String(bytes: bytes.prefix { $0 != 0 }, encoding: .utf8)
            }
        }
        guard auditToken(pid: process.identity.pid) == process.token else { return nil }
        return (arguments, cwd)
    }
}

/// Retain observed managed children after reparenting, but never across a
/// PID/start identity change. Exec does not remove ownership, but does invalidate
/// an audit-bound permission. No permit revocation clears this registry.
struct ChannelOwnershipRegistry {
    private var retained: [UInt32: ChannelProcessIdentity] = [:]
    mutating func remember(_ identity: ChannelProcessIdentity) { retained[identity.pid] = identity }
    mutating func prune(current: (UInt32) -> ChannelProcessIdentity?, exited: (UInt32) -> Bool) {
        retained = retained.filter { pid, old in
            if let identity = current(pid) { return old.sameLifetime(identity) }
            return !exited(pid) // Unreadable is not evidence of exit.
        }
    }
    func contains(_ identity: ChannelProcessIdentity) -> Bool {
        retained[identity.pid].map { $0.sameLifetime(identity) } == true
    }
    func contains(token: [UInt32]) -> Bool {
        token.count == 8 && retained[token[5]]?.audit_token == token
    }
}

func channelOwnership(targetEvidence: Bool, identityConfirmed: Bool) -> ChannelOwnership {
    guard targetEvidence else { return .unmanaged }
    return identityConfirmed ? .managed : .uncertain
}

func channelProcessArguments(_ data: Data) -> [String]? {
    guard data.count > 4 else { return nil }
    let count = data.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
    guard count > 0, count <= 4096 else { return nil }
    let bytes = Array(data)
    var offset = 4
    // Executable path precedes argv, separated by one or more NULs.
    while offset < bytes.count && bytes[offset] != 0 { offset += 1 }
    while offset < bytes.count && bytes[offset] == 0 { offset += 1 }
    var arguments: [String] = []
    for _ in 0..<count {
        let start = offset
        while offset < bytes.count && bytes[offset] != 0 { offset += 1 }
        guard offset < bytes.count, let value = String(bytes: bytes[start..<offset], encoding: .utf8) else { return nil }
        arguments.append(value); offset += 1
    }
    return arguments
}

/// Early capture of the same official Node entrypoints as process_roots.rs.
/// This only withholds a first flow until Rust grants a bound permission.
func channelIsManagedInvocation(executable: String, arguments: [String], cwd: String?, home: String? = nil) -> Bool {
    if channelIsManagedAppServerPath(executable, home: home) {
        guard arguments.count >= 3, let first = arguments.first,
              URL(fileURLWithPath: first).lastPathComponent == "codex", arguments[1] == "app-server" else { return false }
        return arguments[2] == "daemon" || (arguments[2] == "--listen" && arguments.count >= 4
            && !arguments[3].isEmpty && !arguments[3].hasPrefix("-"))
    }
    guard ["node", "nodejs", "bun"].contains(URL(fileURLWithPath: executable).lastPathComponent),
          let first = arguments.first,
          ["node", "nodejs", "bun"].contains(URL(fileURLWithPath: first).lastPathComponent) else { return false }
    var index = 1
    while index < arguments.count {
        let value = arguments[index]; index += 1
        if ["--no-warnings", "--enable-source-maps", "--watch-preserve-output"].contains(value)
            || ["--experimental-", "--trace-", "--disable-warning=", "--require=", "--import=", "--conditions=", "--loader="].contains(where: { value.hasPrefix($0) }) { continue }
        if ["--require", "--import", "--conditions", "--loader"].contains(value) {
            guard index < arguments.count else { return false }; index += 1; continue
        }
        let entry: String
        if value == "--" {
            guard index < arguments.count else { return false }; entry = arguments[index]
        } else {
            guard !value.hasPrefix("-") else { return false }; entry = value
        }
        let path: String
        if entry.hasPrefix("/") { path = entry }
        else if let cwd, cwd.hasPrefix("/") { path = cwd + "/" + entry }
        else { return false }
        let resolved = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath().path
        return resolved.hasSuffix("/node_modules/@anthropic-ai/claude-code/cli.js")
            || resolved.hasSuffix("/node_modules/@openai/codex/bin/codex.js")
    }
    return false
}
