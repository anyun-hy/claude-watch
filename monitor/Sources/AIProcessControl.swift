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
    var rootProduct: MonitoredProduct? = nil
    var desktopMain = false
    func sameProcess(as other: Self) -> Bool {
        pid == other.pid && uid == other.uid && startSeconds == other.startSeconds
            && startMicroseconds == other.startMicroseconds && executable == other.executable
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
enum AIProcessClosePolicy {
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
                        quitApplication: (Int32) -> Bool, terminate: (Int32) -> Bool) -> (requested: Int, skipped: Int, failed: Int) {
        var requested = 0, skipped = 0, failed = 0
        // Roots are asked to quit normally. No SIGKILL or privileged helper is used.
        for target in plan.targets.sorted(by: { $0.desktopMain && !$1.desktopMain }) {
            guard target.uid == plan.uid, !plan.protected.contains(target.pid), target.pid > 1,
                  let live = lookup(target.pid), target.sameProcess(as: live),
                  // A second immediate read narrows the PID-reuse interval
                  // between plan validation and the side effect. It cannot
                  // make a PID-only Darwin signal an atomic identity operation.
                  let latest = lookup(target.pid), target.sameProcess(as: latest) else { skipped += 1; continue }
            let accepted = target.desktopMain ? quitApplication(target.pid) : terminate(target.pid)
            if accepted { requested += 1 } else { failed += 1 }
        }
        return (requested, skipped, failed)
    }
    /// Only the exact identities from the original, verified plan are eligible.
    /// Observed PID reuse and new processes are skipped; the final identity
    /// read narrows but cannot eliminate the non-atomic Darwin signal window.
    /// Whether force is allowed at all is decided upstream by the policy
    /// table; this routine only verifies identity, for any product.
    static func forceRemaining(_ plan: AIProcessClosePlan, lookup: (Int32) -> AIProcessIdentity?,
                               force: (Int32) -> Bool) -> (requested: Int, skipped: Int, failed: Int) {
        var requested = 0, skipped = 0, failed = 0
        for target in plan.targets {
            guard target.uid == plan.uid, !plan.protected.contains(target.pid), target.pid > 1,
                  let live = lookup(target.pid), target.sameProcess(as: live),
                  let latest = lookup(target.pid), target.sameProcess(as: latest) else { skipped += 1; continue }
            if force(target.pid) { requested += 1 } else { failed += 1 }
        }
        return (requested, skipped, failed)
    }
}

#if !PROCESS_POLICY_TESTS
enum AIProcessInventory {
    static func identity(_ pid: Int32) -> AIProcessIdentity? {
        guard pid > 1 else { return nil }
        var info = proc_bsdinfo()
        let expected = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, expected) == expected else { return nil }
        // PROC_PIDPATHINFO_MAXSIZE is a C expression macro unavailable in Swift.
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
        return .init(pid: pid, parent: Int32(info.pbi_ppid), uid: info.pbi_uid,
                     startSeconds: info.pbi_start_tvsec, startMicroseconds: info.pbi_start_tvusec,
                     executable: String(cString: path))
    }
    static func presence(_ pid: Int32) -> AIProcessPresence {
        if let live = identity(pid) { return .live(live) }
        // Signal 0 checks existence only; no signal is delivered. Permission
        // and metadata failures stay unknown rather than becoming a false exit.
        if pid > 1, Darwin.kill(pid, 0) == -1, errno == ESRCH { return .gone }
        return .unavailable
    }
    static func read() throws -> [AIProcessIdentity] {
        let output = try command(["-axo", "pid="])
        var identities = output.split(whereSeparator: \.isWhitespace).compactMap { Int32($0) }.compactMap(identity)
        for index in identities.indices where identities[index].uid == getuid() {
            let path = identities[index].executable
            if let bundleRange = path.range(of: ".app/Contents/") {
                let bundlePath = String(path[..<bundleRange.lowerBound]) + ".app"
                let id = Bundle(path: bundlePath)?.bundleIdentifier ?? ""
                let product: MonitoredProduct? = id == "com.anthropic.claudefordesktop" ? .claude
                    : ["com.openai.codex", "com.openai.chat"].contains(id) ? .openAI : nil
                identities[index].rootProduct = product
                identities[index].desktopMain = product != nil && path.hasPrefix(bundlePath + "/Contents/MacOS/")
            } else if let product = nativeCLI(path) { identities[index].rootProduct = product }
            else if ["node", "nodejs", "bun"].contains(URL(fileURLWithPath: path).lastPathComponent),
                    let args = try? command(["-ww", "-p", String(identities[index].pid), "-o", "args="]),
                    let script = nodeEntry(args) {
                if script.hasSuffix("/node_modules/@anthropic-ai/claude-code/cli.js") { identities[index].rootProduct = .claude }
                if script.hasSuffix("/node_modules/@openai/codex/bin/codex.js") { identities[index].rootProduct = .openAI }
            }
        }
        return identities
    }
    static func nativeCLI(_ path: String) -> MonitoredProduct? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let known: [(String, MonitoredProduct)] = [
            (home + "/.local/bin/claude", .claude), (home + "/.claude/local/claude", .claude),
            ("/opt/homebrew/bin/claude", .claude), ("/usr/local/bin/claude", .claude),
            ("/opt/homebrew/bin/codex", .openAI), ("/usr/local/bin/codex", .openAI)
        ]
        for (entry, product) in known where FileManager.default.fileExists(atPath: entry) {
            if URL(fileURLWithPath: entry).resolvingSymlinksInPath().path == path { return product }
        }
        if path.hasPrefix(home + "/.local/share/claude/versions/") { return .claude }
        if path.contains("/Caskroom/codex/"), path.hasSuffix("/bin/codex") { return .openAI }
        if path.contains("/node_modules/@openai/codex/"), path.hasSuffix("/codex") { return .openAI }
        // The self-started app-server daemon OpenAI ships (see process_roots::
        // managed_codex_app_server) lives under ~/.codex/packages/app-server-daemon/.
        // It is launched by launchd (parent PID 1), so it is not a descendant of
        // any desktop/CLI root and would otherwise survive "退出 ChatGPT / Codex".
        // Attribute it to OpenAI so the close plan collects it too.
        if path.hasPrefix(home + "/.codex/packages/app-server-daemon/"), path.hasSuffix("/bin/codex") { return .openAI }
        return nil
    }
    static func nodeEntry(_ command: String) -> String? {
        // Reject ambiguous shell quoting and executing flags such as -e. A path
        // merely present in another argument never establishes process ownership.
        guard !command.contains("\""), !command.contains("'") else { return nil }
        let tokens = command.split(whereSeparator: \.isWhitespace).map(String.init)
        guard let first = tokens.first, ["node", "nodejs", "bun"].contains(URL(fileURLWithPath: first).lastPathComponent) else { return nil }
        for token in tokens.dropFirst() {
            if ["--no-warnings", "--enable-source-maps", "--"].contains(token) { continue }
            guard !token.hasPrefix("-"), token.hasPrefix("/") else { return nil }
            return token
        }
        return nil
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
    private static func command(_ arguments: [String]) throws -> String {
        let task = Process(), pipe = Pipe()
        task.executableURL = URL(fileURLWithPath: "/bin/ps"); task.arguments = arguments
        task.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        task.standardOutput = pipe; task.standardError = FileHandle.nullDevice
        try task.run()
        let deadline = DispatchWorkItem { if task.isRunning { task.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: deadline)
        defer { deadline.cancel() }
        let data = pipe.fileHandleForReading.readDataToEndOfFile(); task.waitUntilExit()
        guard task.terminationStatus == 0, let text = String(data: data, encoding: .utf8) else {
            throw NSError(domain: "ClaudeWatch.ProcessControl", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "无法读取当前进程身份，未关闭任何进程。"])
        }
        return text
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
            let inventory = try AIProcessInventory.read()
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
                quitApplication: { NSRunningApplication(processIdentifier: $0)?.terminate() ?? false },
                terminate: { Darwin.kill($0, SIGTERM) == 0 })
        }.value
        try? await Task.sleep(nanoseconds: 1_200_000_000)
        do {
            let evidence = try await Task.detached {
                AIProcessClosePolicy.exitEvidence(plan, inventory: try AIProcessInventory.read(),
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
