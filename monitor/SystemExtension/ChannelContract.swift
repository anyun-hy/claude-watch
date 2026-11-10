import Foundation

struct ChannelPolicy: Codable, Equatable {
    let policy_digest: String
    let guard_policy_digest: String
    var dictionary: [String: Any] { ["policy_digest": policy_digest, "guard_policy_digest": guard_policy_digest] }
}
struct ChannelCommand: Codable {
    let family: String
    let policy_version: ChannelPolicy
    let command_seq: UInt64
    let permit_generation: UInt64
    let issued_at: Double
    let valid_until: Double
    let permit_state: String
    let allowed_pids: [UInt32]
    let allowed_processes: [ChannelProcessIdentity]
    let session_id: String?
    let command_binding: String
    let reason: String?

    func canGrant(providerStartedAt: Double, now: Double) -> Bool {
        permit_state == "permitted" && issued_at >= providerStartedAt
            && issued_at <= now + 0.05 && valid_until > now
    }
}
struct ChannelCommandEnvelope: Codable {
    let executor_boot_id: String
    let extension_boot_id: String?
    let gateway_socket: String
    let commands: [ChannelCommand]
    static func decode(_ data: Data) throws -> Self {
        let envelope = try JSONDecoder().decode(Self.self, from: data)
        guard !envelope.executor_boot_id.isEmpty, envelope.gateway_socket.hasPrefix("/tmp/cw-channel-"),
              envelope.commands.count <= 2, Set(envelope.commands.map { $0.family }).count == envelope.commands.count else {
            throw ExtensionStateDirectory.error("Invalid command envelope")
        }
        for command in envelope.commands {
            guard ["claude", "openai"].contains(command.family), command.command_seq > 0,
                  command.permit_generation > 0, !command.policy_version.policy_digest.isEmpty,
                  command.command_binding.count == 64, command.command_binding.allSatisfy({ $0.isHexDigit }),
                  !command.policy_version.guard_policy_digest.isEmpty,
                  ["permitted", "revoked", "pending_verification"].contains(command.permit_state),
                  command.issued_at.isFinite, command.valid_until.isFinite,
                  command.valid_until >= command.issued_at, command.valid_until - command.issued_at <= 10.05,
                  command.allowed_processes.count <= 2048,
                  command.allowed_processes.allSatisfy({ $0.valid }),
                  Set(command.allowed_processes.map { $0.pid }).count == command.allowed_processes.count,
                  Set(command.allowed_pids) == Set(command.allowed_processes.map { $0.pid }) else {
                throw ExtensionStateDirectory.error("Invalid family command")
            }
        }
        return envelope
    }
}

/// Each wake invalidates outstanding RPCs and requires an explicit, current-
/// epoch revocation before that family's normal audited recovery can grant.
struct ChannelExecutionEpoch {
    private(set) var bootID: String
    private(set) var minimumIssuedAt: Double
    private var sleeping = false
    private var requiresRevocation = false
    private var revokedFamilies: Set<String> = []

    init(startedAt: Double, bootID: String = UUID().uuidString) {
        self.bootID = bootID
        minimumIssuedAt = startedAt
    }

    mutating func suspend() {
        sleeping = true
        requiresRevocation = true
        revokedFamilies.removeAll()
    }

    mutating func wake(at now: Double, bootID: String = UUID().uuidString) {
        self.bootID = bootID
        minimumIssuedAt = max(minimumIssuedAt, now)
        sleeping = false
        requiresRevocation = true
        revokedFamilies.removeAll()
    }

    mutating func permits(_ command: ChannelCommand, acknowledgedBoot: String?, now: Double) -> Bool {
        guard !sleeping, acknowledgedBoot == bootID,
              command.issued_at >= minimumIssuedAt, command.issued_at <= now + 0.05 else { return false }
        if command.permit_state == "revoked" { revokedFamilies.insert(command.family) }
        return (!requiresRevocation || revokedFamilies.contains(command.family))
            && command.canGrant(providerStartedAt: minimumIssuedAt, now: now)
    }
}

/// A drain deadline describes failure; it never removes an unclosed flow.
func channelDrainStatus(remaining: Int, started: Double, now: Double) -> String {
    if remaining == 0 { return "revoked" }
    return now - started >= 1.5 ? "failed" : "disconnecting"
}

/// A repeated omission retries closing without extending the original drain
/// deadline. Only confirmed closure clears that deadline and reports revoked.
struct ChannelDrainUpdate {
    let status: String
    let closingSince: Double?
    let appliedAt: Double

    init(remaining: Int, previouslyStarted: Double?, closeFailed: Bool, now: Double) {
        let started = previouslyStarted ?? now
        status = closeFailed ? "failed" : channelDrainStatus(remaining: remaining, started: started, now: now)
        closingSince = status == "revoked" ? nil : started
        appliedAt = now
    }
}

// Both counters are monotonic within one executor boot. An identical command
// may be replayed idempotently only after its entire payload is compared.
func channelCommandAdvances(generation: UInt64, sequence: UInt64,
                            previousGeneration: UInt64, previousSequence: UInt64) -> Bool {
    generation >= previousGeneration && sequence > previousSequence
}

func channelPermitIsLive(permitted: Bool, issuedAt: Double, deadline: Double,
                         monotonicDeadline: Double, now: Double, uptime: Double) -> Bool {
    permitted && issuedAt <= now + 0.05 && deadline > now && monotonicDeadline > uptime
}

/// Membership updates close removed/execed members only. Actual authority
/// changes and recovery still drain the whole family.
struct ChannelFlowUpdate {
    let closeAll: Bool
    let processes: [ChannelProcessIdentity]
    init(command: ChannelCommand, allowed: Bool, changedBoot: Bool,
         previousGeneration: UInt64?, previousPolicy: ChannelPolicy?,
         previousSession: String?, wasClosing: Bool) {
        closeAll = !allowed || changedBoot || wasClosing
            || previousGeneration.map { $0 != command.permit_generation } == true
            || previousPolicy.map { $0 != command.policy_version } == true
            || (previousGeneration != nil && previousSession != command.session_id)
        processes = command.allowed_processes
    }
    func keeps(_ identity: ChannelProcessIdentity) -> Bool {
        !closeAll && processes.contains { $0.matches(identity) }
    }
}

// Identity uncertainty blocks a positively identified target only. Ordinary
// interpreters and unsigned software do not enter the managed AI scope.
func channelMayBypass(ownership: ChannelOwnership) -> Bool {
    ownership == .unmanaged
}

// These fallbacks claim new application flows for denial until Rust publishes
// their verified identity. Substring matches would also capture our own
// ClaudeWatchMonitor parent and prevent its gateway from reaching TAG.
func channelIsManagedSigningID(_ value: String) -> Bool {
    let value = value.lowercased()
    return ["com.anthropic.claudefordesktop", "com.openai.codex", "com.openai.chat"].contains {
        value == $0 || value.hasPrefix($0 + ".")
    }
}

func channelIsManagedProcessName(_ value: String) -> Bool {
    let value = value.lowercased()
    return ["claude", "codex", "chatgpt"].contains {
        value == $0 || value == $0 + " helper" || value.hasPrefix($0 + " helper (")
    }
}

func channelCLIAliases(home: String?) -> [String] {
    var paths = ["/opt/homebrew/bin/claude", "/usr/local/bin/claude", "/opt/homebrew/bin/codex", "/usr/local/bin/codex"]
    if let home { paths += [home + "/.local/bin/claude", home + "/.claude/local/claude", home + "/.local/bin/codex"] }
    return paths
}
func channelResolvedCLIAliases(home: String?) -> Set<String> {
    Set(channelCLIAliases(home: home).compactMap { path in
        FileManager.default.fileExists(atPath: path) ? URL(fileURLWithPath: path).resolvingSymlinksInPath().path : nil
    })
}
func channelIsManagedAppServerPath(_ path: String, home: String?) -> Bool {
    guard let home else { return false }
    let prefix = home + "/.codex/packages/app-server-daemon/releases/"
    let normalized = URL(fileURLWithPath: path).standardizedFileURL.path
    guard normalized.hasPrefix(prefix) else { return false }
    let components = normalized.dropFirst(prefix.count).split(separator: "/")
    return components.count == 3 && components[1] == "bin" && components[2] == "codex"
}
func channelBundlePath(_ executable: String) -> String? {
    executable.range(of: ".app/Contents/").map { String(executable[..<$0.lowerBound]) + ".app" }
}
func channelDesktopBundleID(_ executable: String) -> String? {
    channelBundlePath(executable).flatMap { Bundle(path: $0)?.bundleIdentifier }
}
func channelIsManagedExecutable(_ path: String, home: String?, aliases: Set<String>? = nil, bundleID: String? = nil) -> Bool {
    // The managed daemon path requires its constrained argv, even if an alias
    // happens to point at it. Match the Rust classifier's precedence.
    if channelIsManagedAppServerPath(path, home: home) { return false }
    if (aliases ?? channelResolvedCLIAliases(home: home)).contains(path) { return true }
    if let bundle = channelBundlePath(path), let identifier = bundleID ?? channelDesktopBundleID(path) {
        let name = URL(fileURLWithPath: bundle).lastPathComponent
        if identifier == "com.anthropic.claudefordesktop"
            || (identifier == "com.openai.codex" && ["Codex.app", "ChatGPT.app"].contains(name))
            || (identifier == "com.openai.chat" && name == "ChatGPT.app") { return true }
    }
    if let home, path.hasPrefix(home + "/.local/share/claude/versions/") { return true }
    return (path.contains("/Caskroom/codex/") && path.hasSuffix("/bin/codex"))
        || (path.contains("/node_modules/@openai/codex/") && path.hasSuffix("/codex"))
}
