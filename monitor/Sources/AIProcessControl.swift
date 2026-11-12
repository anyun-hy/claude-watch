import Foundation
#if !PROCESS_POLICY_TESTS
import AppKit
import Combine
import Darwin
#endif

struct AIProcessIdentity: Equatable, Sendable {
    let pid, parent: Int32
    let uid: UInt32
    let startSeconds, startMicroseconds: UInt64
    let executable: String
    /// Kernel audit token words (including monotonically increasing pidversion)
    /// when obtainable via the public Mach task-name port API. Distinguishes
    /// in-place exec replacements that keep the same PID, start timestamp, and
    /// executable path on XNU.
    var auditToken: [UInt32]? = nil
    var rootProduct: MonitoredProduct? = nil
    var desktopMain = false
    func sameProcess(as other: Self) -> Bool {
        pid == other.pid && uid == other.uid && startSeconds == other.startSeconds
            && startMicroseconds == other.startMicroseconds && executable == other.executable
            && auditToken == other.auditToken
    }
}
struct AIProcessClosePlan: Sendable {
    let product: MonitoredProduct
    let uid: UInt32
    let targets: [AIProcessIdentity]
    let protected: Set<Int32>
}
/// A failed identity read is not proof that a process exited.
enum AIProcessPresence {
    case live(AIProcessIdentity)
    case gone
    case unavailable
}
struct AIProcessExitEvidence {
    let remaining: [AIProcessIdentity]
    let unconfirmed: Int
    var complete: Bool { remaining.isEmpty && unconfirmed == 0 }
}
enum AIProcessInventoryFailure: Error {
    case malformed, incomplete, stale, identityChanged, engineUnavailable
    case timeout, outputTooLarge, readFailed, commandFailed
}
/// Wire decoding and identity binding only. Product classification belongs to Rust's sampler.
struct AIProcessClassificationBatch: Decodable {
    struct Identity: Decodable {
        let pid, parent: Int32
        let uid: UInt32
        let executable: String
        let start_seconds, start_microseconds: UInt64
        func matches(_ value: AIProcessIdentity) -> Bool {
            pid == value.pid && uid == value.uid && executable == value.executable
                && start_seconds == value.startSeconds && start_microseconds == value.startMicroseconds
        }
    }
    struct Target: Decodable {
        let identity: Identity
        let product: String
        let desktop_main: Bool
    }
    let schema: Int
    let status, mode, state: String
    let uid: UInt32
    let observed_at: TimeInterval
    let grants_launch_permission, grants_close_permission: Bool
    let targets: [Target]

    static func apply(_ data: Data, to before: [AIProcessIdentity], uid: UInt32, now: TimeInterval,
                      lookup: (Int32) -> AIProcessPresence) throws -> [AIProcessIdentity] {
        let batch = try JSONDecoder().decode(Self.self, from: data)
        guard batch.schema == 1, batch.status == "ok", batch.mode == "read_only", batch.uid == uid,
              !batch.grants_launch_permission, !batch.grants_close_permission,
              batch.targets.count <= 65_536 else { throw AIProcessInventoryFailure.malformed }
        guard batch.state == "ok" else { throw AIProcessInventoryFailure.incomplete }
        guard batch.observed_at.isFinite, batch.observed_at > 0,
              batch.observed_at <= now + 2, now - batch.observed_at <= 20 else {
            throw AIProcessInventoryFailure.stale
        }
        var inventory = before
        var indices: [Int32: Int] = [:]
        for index in inventory.indices {
            guard indices.updateValue(index, forKey: inventory[index].pid) == nil else {
                throw AIProcessInventoryFailure.malformed
            }
            inventory[index].rootProduct = nil; inventory[index].desktopMain = false
        }
        var seen = Set<Int32>()
        for target in batch.targets {
            let expected = target.identity
            guard expected.pid > 1, expected.uid == uid, expected.start_seconds > 0,
                  expected.start_microseconds < 1_000_000, expected.executable.hasPrefix("/"),
                  seen.insert(expected.pid).inserted else { throw AIProcessInventoryFailure.malformed }
            let product: MonitoredProduct
            switch target.product {
            case "claude": product = .claude
            case "openai": product = .openAI
            default: throw AIProcessInventoryFailure.malformed
            }
            guard let index = indices[expected.pid],
                  expected.matches(before[index]) else { throw AIProcessInventoryFailure.identityChanged }
            switch lookup(expected.pid) {
            case .gone: continue
            case .unavailable: throw AIProcessInventoryFailure.identityChanged
            case .live(let current):
                // The native audit token brackets the entire Rust classification batch.
                guard before[index].sameProcess(as: current) else { throw AIProcessInventoryFailure.identityChanged }
                inventory[index] = current
                inventory[index].rootProduct = product
                inventory[index].desktopMain = target.desktop_main
            }
        }
        return inventory
    }
}
enum AIProcessCloseScope: Equatable, Sendable {
    case desktopBundleOnly
    case allProductProcesses
}
enum AIProcessClosePolicy {
    static func automaticDesktopScope(for product: MonitoredProduct) -> AIProcessCloseScope {
        switch product {
        // A bare binary named like Claude is not a Claude desktop install;
        // automatic desktop supervision scopes Claude to its .app bundle tree.
        case .claude: return .desktopBundleOnly
        // ChatGPT / Codex also runs as an independent CLI or daemon without an
        // .app bundle, so automatic OpenAI family supervision covers all
        // attributed OpenAI processes.
        case .openAI: return .allProductProcesses
        }
    }
    static func manualCloseScope(for product: MonitoredProduct) -> AIProcessCloseScope {
        .allProductProcesses
    }
    static func scopedInventory(_ inventory: [AIProcessIdentity], for product: MonitoredProduct,
                                scope: AIProcessCloseScope) -> [AIProcessIdentity] {
        guard scope == .desktopBundleOnly else { return inventory }
        var scoped = inventory
        for index in scoped.indices {
            if scoped[index].rootProduct == product && !scoped[index].executable.contains(".app/Contents/") {
                scoped[index].rootProduct = nil
                scoped[index].desktopMain = false
            }
        }
        return scoped
    }
    static func plan(_ product: MonitoredProduct, inventory: [AIProcessIdentity], uid: UInt32,
                     protected: Set<Int32>) -> AIProcessClosePlan {
        let owned = inventory.filter { $0.uid == uid && $0.pid > 1 && !protected.contains($0.pid) }
        var ids = Set(owned.filter { $0.rootProduct == product }.map(\.pid))
        while true {
            let next = ids.union(owned.filter { ids.contains($0.parent) && ($0.rootProduct == nil || $0.rootProduct == product) }.map(\.pid))
            if next == ids { break }; ids = next
        }
        return .init(product: product, uid: uid,
                     targets: owned.filter { ids.contains($0.pid) }.sorted { $0.pid < $1.pid }, protected: protected)
    }
    /// Read-only completion evidence; this never creates new signal authority.
    /// Retain the original identities even after reparenting, and include newly
    /// observed family members only in the report, not in forceRemaining().
    static func exitEvidence(_ original: AIProcessClosePlan, inventory: [AIProcessIdentity],
                             lookup: (Int32) -> AIProcessPresence) -> AIProcessExitEvidence {
        let fresh = plan(original.product, inventory: inventory, uid: original.uid,
                         protected: original.protected)
        var samples: [Int32: AIProcessPresence] = [:]
        var live: [Int32: AIProcessIdentity] = [:]
        var unknown = Set<Int32>()
        for expected in original.targets + fresh.targets {
            guard expected.pid > 1, expected.uid == original.uid,
                  !original.protected.contains(expected.pid) else { continue }
            let sample: AIProcessPresence
            if let cached = samples[expected.pid] { sample = cached }
            else { sample = lookup(expected.pid); samples[expected.pid] = sample }
            switch sample {
            case .live(let actual):
                if expected.sameProcess(as: actual) { live[actual.pid] = actual }
            case .gone: break
            case .unavailable: unknown.insert(expected.pid)
            }
        }
        return .init(remaining: live.values.sorted { $0.pid < $1.pid }, unconfirmed: unknown.count)
    }
    static func execute(_ plan: AIProcessClosePlan, lookup: (Int32) -> AIProcessIdentity?,
                        quitApplication: (AIProcessIdentity) -> Bool, terminate: (AIProcessIdentity) -> Bool) -> (requested: Int, skipped: Int, failed: Int) {
        var requested = 0, skipped = 0, failed = 0
        // Roots are asked to quit normally. No SIGKILL or privileged helper is used.
        for target in plan.targets.sorted(by: { $0.desktopMain && !$1.desktopMain }) {
            guard target.uid == plan.uid, !plan.protected.contains(target.pid), target.pid > 1,
                  let live = lookup(target.pid), target.sameProcess(as: live),
                  // A second immediate read narrows the PID-reuse interval
                  // between plan validation and the side effect. It cannot
                  // make a PID-only Darwin signal an atomic identity operation.
                  let latest = lookup(target.pid), target.sameProcess(as: latest) else { skipped += 1; continue }
            let accepted = target.desktopMain ? quitApplication(target) : terminate(target)
            if accepted { requested += 1 } else { failed += 1 }
        }
        return (requested, skipped, failed)
    }
    /// The effect adapter is given the originally authorised identity, not
    /// only its PID. Recheck at the actual side-effect boundary so a changed
    /// process is never accepted merely because it passed an earlier poll.
    /// No macOS PID-based signal is an atomic identity-conditional syscall.
    static func applyToMatchingIdentity(_ expected: AIProcessIdentity,
                                        lookup: (Int32) -> AIProcessIdentity?,
                                        effect: (Int32) -> Bool) -> Bool {
        guard expected.pid > 1, let current = lookup(expected.pid),
              expected.sameProcess(as: current) else { return false }
        return effect(expected.pid)
    }

    /// Only the exact identities from the original, verified plan are eligible.
    /// Observed PID reuse and new processes are skipped; the final identity
    /// read narrows but cannot eliminate the non-atomic Darwin signal window.
    /// Whether force is allowed at all is decided upstream by the policy
    /// table; this routine only verifies identity, for any product.
    static func forceRemaining(_ plan: AIProcessClosePlan, lookup: (Int32) -> AIProcessIdentity?,
                               force: (AIProcessIdentity) -> Bool) -> (requested: Int, skipped: Int, failed: Int) {
        var requested = 0, skipped = 0, failed = 0
        for target in plan.targets {
            guard target.uid == plan.uid, !plan.protected.contains(target.pid), target.pid > 1,
                  let live = lookup(target.pid), target.sameProcess(as: live),
                  let latest = lookup(target.pid), target.sameProcess(as: latest) else { skipped += 1; continue }
            if force(target) { requested += 1 } else { failed += 1 }
        }
        return (requested, skipped, failed)
    }
}

#if !PROCESS_POLICY_TESTS
enum AIProcessInventory {
    private static func rawAuditToken(_ pid: Int32) -> audit_token_t? {
        guard pid > 1 else { return nil }
        var name: mach_port_name_t = 0
        guard task_name_for_pid(mach_task_self_, pid, &name) == KERN_SUCCESS else { return nil }
        defer { mach_port_deallocate(mach_task_self_, name) }
        var token = audit_token_t()
        var count = mach_msg_type_number_t(MemoryLayout<audit_token_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &token) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(name, task_flavor_t(TASK_AUDIT_TOKEN), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return nil }
        return token
    }
    private static func tokenWords(_ token: audit_token_t) -> [UInt32] {
        let v = token.val
        return [v.0, v.1, v.2, v.3, v.4, v.5, v.6, v.7]
    }
    static func identity(_ pid: Int32) -> AIProcessIdentity? {
        guard pid > 1 else { return nil }
        var info = proc_bsdinfo()
        let expected = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, expected) == expected else { return nil }
        let beforeToken = rawAuditToken(pid)
        // PROC_PIDPATHINFO_MAXSIZE is a C expression macro unavailable in Swift.
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        if var token = beforeToken {
            guard proc_pidpath_audittoken(&token, &path, UInt32(path.count)) > 0 else { return nil }
        } else {
            guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
        }
        var confirm = proc_bsdinfo()
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &confirm, expected) == expected,
              info.pbi_uid == confirm.pbi_uid,
              info.pbi_start_tvsec == confirm.pbi_start_tvsec,
              info.pbi_start_tvusec == confirm.pbi_start_tvusec else { return nil }
        let beforeWords = beforeToken.map(tokenWords)
        let afterWords = rawAuditToken(pid).map(tokenWords)
        guard beforeWords == afterWords else { return nil }
        return .init(pid: pid, parent: Int32(confirm.pbi_ppid), uid: confirm.pbi_uid,
                     startSeconds: confirm.pbi_start_tvsec, startMicroseconds: confirm.pbi_start_tvusec,
                     executable: String(cString: path), auditToken: beforeWords)
    }
    static func presence(_ pid: Int32) -> AIProcessPresence {
        if let live = identity(pid) { return .live(live) }
        // Signal 0 checks existence only; no signal is delivered. Permission
        // and metadata failures stay unknown rather than becoming a false exit.
        if pid > 1, Darwin.kill(pid, 0) == -1, errno == ESRCH { return .gone }
        return .unavailable
    }
    static let maximumReadSeconds: TimeInterval = 8
    static func read(engine explicitEngine: URL? = nil, timeout: TimeInterval = maximumReadSeconds) throws -> [AIProcessIdentity] {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let listing = try command(URL(fileURLWithPath: "/bin/ps"), arguments: ["-axo", "pid="], deadline: deadline)
        let before = String(decoding: listing, as: UTF8.self).split(whereSeparator: \.isWhitespace)
            .compactMap { Int32($0) }.compactMap(identity)
        let engine = try classificationEngine(explicitEngine)
        let data = try command(engine, arguments: ["observe", "--processes-only", "--home",
            FileManager.default.homeDirectoryForCurrentUser.path], deadline: deadline)
        return try AIProcessClassificationBatch.apply(data, to: before, uid: getuid(),
                                                      now: Date().timeIntervalSince1970, lookup: presence)
    }
    private static func classificationEngine(_ explicit: URL?) throws -> URL {
        #if PROCESS_HELPER
        guard let own = Bundle.main.executableURL else { throw AIProcessInventoryFailure.engineUnavailable }
        let packaged = own.deletingLastPathComponent().appendingPathComponent("watch-engine").standardizedFileURL
        let candidate = explicit?.standardizedFileURL ?? packaged
        if let explicit {
            guard explicit.path.hasPrefix("/"),
                  let parent = identity(getppid()), parent.uid == getuid(),
                  parent.executable == candidate.path,
                  let latest = identity(parent.pid), parent.sameProcess(as: latest) else {
                throw AIProcessInventoryFailure.engineUnavailable
            }
        }
        if candidate != packaged {
            #if PROCESS_HELPER_DEVELOPMENT
            guard explicit != nil, candidate.path == ProcessHelperDevelopment.enginePath else {
                throw AIProcessInventoryFailure.engineUnavailable
            }
            #else
            throw AIProcessInventoryFailure.engineUnavailable
            #endif
        }
        #else
        guard explicit == nil, let candidate = Bundle.main.url(forResource: "watch-engine", withExtension: nil) else {
            throw AIProcessInventoryFailure.engineUnavailable
        }
        #endif
        guard FileManager.default.isExecutableFile(atPath: candidate.path) else {
            throw AIProcessInventoryFailure.engineUnavailable
        }
        return candidate
    }
    static func protectedIDs(in inventory: [AIProcessIdentity], backendPID: Int?) -> Set<Int32> {
        var result: Set<Int32> = [1, getpid()]
        var current = getpid()
        for _ in 0..<64 {
            guard let parent = inventory.first(where: { $0.pid == current })?.parent, parent > 0,
                  result.insert(parent).inserted else { break }; current = parent
        }
        if let pid = backendPID, pid > 1, pid <= Int(Int32.max) { result.insert(Int32(pid)) }
        return result
    }
    /// One bounded synchronous boundary for both inventory commands. No reader or timer thread survives it.
    static func command(_ executable: URL, arguments: [String], deadline: TimeInterval,
                        maxBytes: Int = 4_000_000) throws -> Data {
        let task = Process(), pipe = Pipe()
        task.executableURL = executable; task.arguments = arguments
        task.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        task.standardInput = FileHandle.nullDevice
        task.standardOutput = pipe; task.standardError = FileHandle.nullDevice
        let handle = pipe.fileHandleForReading
        let descriptor = handle.fileDescriptor
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            throw AIProcessInventoryFailure.readFailed
        }
        try task.run()
        try? pipe.fileHandleForWriting.close()
        defer {
            // This is only the Process instance created above, never a monitored target.
            if task.isRunning { _ = Darwin.kill(task.processIdentifier, SIGKILL) }
            task.waitUntilExit()
            try? handle.close()
        }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 65_536)
        var eof = false
        while !eof || task.isRunning {
            guard ProcessInfo.processInfo.systemUptime < deadline else {
                throw AIProcessInventoryFailure.timeout
            }
            if !eof {
                let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
                if count > 0 {
                    guard data.count + count <= maxBytes else { throw AIProcessInventoryFailure.outputTooLarge }
                    data.append(contentsOf: buffer.prefix(count))
                    continue
                }
                if count == 0 { eof = true }
                else if errno != EAGAIN && errno != EINTR { throw AIProcessInventoryFailure.readFailed }
            }
            if eof && !task.isRunning { break }
            var pollfd = pollfd(fd: eof ? -1 : descriptor, events: Int16(POLLIN), revents: 0)
            let remaining = max(1, min(100, Int((deadline - ProcessInfo.processInfo.systemUptime) * 1_000)))
            if poll(&pollfd, 1, Int32(remaining)) < 0 && errno != EINTR {
                throw AIProcessInventoryFailure.readFailed
            }
        }
        task.waitUntilExit()
        guard task.terminationStatus == 0 else { throw AIProcessInventoryFailure.commandFailed }
        return data
    }

}

#if !PROCESS_HELPER
@MainActor
final class AIProcessControl: ObservableObject {
    @Published private(set) var busy = false
    let isFixture: Bool
    init(isFixture: Bool = false) {
        #if UI_REVIEW
        self.isFixture = true
        #else
        self.isFixture = isFixture
        #endif
    }
    func prepare(_ product: MonitoredProduct, sampled: [WatchedProcess], backendPID: Int?) async throws -> AIProcessClosePlan {
        guard !busy else { throw CancellationError() }
        busy = true; defer { busy = false }
        if isFixture {
            return .init(product: product, uid: getuid(), targets: sampled.filter { $0.product == product }.map {
                .init(pid: Int32($0.pid), parent: 1, uid: getuid(), startSeconds: 1, startMicroseconds: 0, executable: "/mock/" + $0.name)
            }, protected: [])
        }
        return try await Task.detached(priority: .userInitiated) {
            let inventory = AIProcessClosePolicy.scopedInventory(
                try AIProcessInventory.read(),
                for: product,
                scope: AIProcessClosePolicy.manualCloseScope(for: product)
            )
            return AIProcessClosePolicy.plan(product, inventory: inventory, uid: getuid(),
                protected: AIProcessInventory.protectedIDs(in: inventory, backendPID: backendPID))
        }.value
    }
    func execute(_ plan: AIProcessClosePlan) async -> String {
        guard !busy else { return "已有关闭操作正在进行。" }
        busy = true; defer { busy = false }
        if isFixture { return "模拟关闭 \(plan.targets.count) 个 \(plan.product.title) 进程；未向任何系统进程发送退出请求。" }
        let outcome = await Task.detached(priority: .userInitiated) {
            AIProcessClosePolicy.execute(plan, lookup: AIProcessInventory.identity,
                quitApplication: { expected in
                    AIProcessClosePolicy.applyToMatchingIdentity(expected, lookup: AIProcessInventory.identity) {
                        NSRunningApplication(processIdentifier: $0)?.terminate() ?? false
                    }
                },
                terminate: { expected in
                    AIProcessClosePolicy.applyToMatchingIdentity(expected, lookup: AIProcessInventory.identity) {
                        Darwin.kill($0, SIGTERM) == 0
                    }
                })
        }.value
        try? await Task.sleep(nanoseconds: 1_200_000_000)
        do {
            let evidence = try await Task.detached {
                let inventory = AIProcessClosePolicy.scopedInventory(
                    try AIProcessInventory.read(),
                    for: plan.product,
                    scope: AIProcessClosePolicy.manualCloseScope(for: plan.product)
                )
                return AIProcessClosePolicy.exitEvidence(plan, inventory: inventory,
                                                         lookup: AIProcessInventory.presence)
            }.value
            return evidence.complete
                ? "当前未检测到 \(plan.product.title) 相关进程。退出请求 \(outcome.requested) 项，身份变化跳过 \(outcome.skipped) 项。"
                : "仍有 \(evidence.remaining.count) 个 \(plan.product.title) 进程，另有 \(evidence.unconfirmed) 项身份无法复核。退出请求 \(outcome.requested) 项，失败 \(outcome.failed) 项；未确认全部退出。"
        } catch { return "已发送 \(outcome.requested) 项退出请求，但无法复核是否全部退出。" }
    }
}
#endif

#endif // !PROCESS_POLICY_TESTS
