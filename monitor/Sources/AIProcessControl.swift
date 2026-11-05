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
    static func resolveLexicalPath(_ value: String, cwd: String? = nil) -> String? {
        guard !value.isEmpty else { return nil }
        let combined: String
        if value.hasPrefix("/") {
            combined = value
        } else if let cwd, cwd.hasPrefix("/") {
            combined = cwd + "/" + value
        } else {
            return nil
        }
        var stack: [String] = []
        for part in combined.split(separator: "/", omittingEmptySubsequences: true) {
            if part == "." { continue }
            if part == ".." {
                guard !stack.isEmpty else { return nil }
                stack.removeLast()
                continue
            }
            stack.append(String(part))
        }
        return "/" + stack.joined(separator: "/")
    }
    static func nodeEntryTokens(_ tokens: [String], cwd: String? = nil) -> String? {
        guard let first = tokens.first,
              ["node", "nodejs", "bun"].contains(URL(fileURLWithPath: first).lastPathComponent) else { return nil }
        var index = 1
        while index < tokens.count {
            let token = tokens[index]
            index += 1
            if token == "--" {
                guard index < tokens.count else { return nil }
                return resolveLexicalPath(tokens[index], cwd: cwd)
            }
            if ["--no-warnings", "--enable-source-maps", "--watch-preserve-output"].contains(token)
                || token.hasPrefix("--experimental-")
                || token.hasPrefix("--trace-")
                || token.hasPrefix("--disable-warning=")
                || token.hasPrefix("--require=")
                || token.hasPrefix("--import=")
                || token.hasPrefix("--conditions=")
                || token.hasPrefix("--loader=") {
                continue
            }
            if ["--require", "--import", "--conditions", "--loader"].contains(token) {
                guard index < tokens.count else { return nil }
                index += 1
                continue
            }
            guard !token.hasPrefix("-") else { return nil }
            return resolveLexicalPath(token, cwd: cwd)
        }
        return nil
    }
    static func nodeEntry(_ command: String, cwd: String? = nil) -> String? {
        // Fallback for string command lines: reject ambiguous shell quoting.
        // Production inventory reads NUL-delimited KERN_PROCARGS2 tokens via
        // nodeEntryTokens(_:cwd:) so script paths with spaces are preserved.
        guard !command.contains("\""), !command.contains("'") else { return nil }
        let tokens = command.split(whereSeparator: \.isWhitespace).map(String.init)
        return nodeEntryTokens(tokens, cwd: cwd)
    }
    static func managedCodexAppServerPath(_ path: String, home: String) -> Bool {
        guard let normalizedPath = resolveLexicalPath(path),
              let normalizedHome = resolveLexicalPath(home) else { return false }
        let prefix = (normalizedHome == "/" ? "" : normalizedHome) + "/.codex/packages/app-server-daemon/releases/"
        guard normalizedPath.hasPrefix(prefix) else { return false }
        let parts = normalizedPath.dropFirst(prefix.count)
            .split(separator: "/", omittingEmptySubsequences: false)
            .map(String.init)
        return parts.count == 3 && !parts[0].isEmpty && parts[1] == "bin" && parts[2] == "codex"
    }
    static func managedCodexAppServerTokens(path: String, home: String, tokens: [String]?) -> Bool {
        guard managedCodexAppServerPath(path, home: home),
              let tokens, tokens.count >= 3,
              URL(fileURLWithPath: tokens[0]).lastPathComponent == "codex",
              tokens[1] == "app-server" else { return false }
        if tokens[2] == "daemon" { return true }
        if tokens[2] == "--listen", tokens.count >= 4, !tokens[3].isEmpty, !tokens[3].hasPrefix("-") {
            return true
        }
        return false
    }
    static func managedCodexAppServer(path: String, home: String, arguments: String?) -> Bool {
        guard let arguments, !arguments.contains("\""), !arguments.contains("'") else { return false }
        let tokens = arguments.split(whereSeparator: \.isWhitespace).map(String.init)
        return managedCodexAppServerTokens(path: path, home: home, tokens: tokens)
    }
    static func classifyRoot(
        executable: String,
        bundleIdentifier: String? = nil,
        argumentTokens: [String]? = nil,
        arguments: String? = nil,
        cwd: String? = nil,
        home: String,
        trustedClaudePaths: Set<String> = [],
        trustedCodexPaths: Set<String> = [],
        resolveScript: (String) -> String? = { $0 }
    ) -> (product: MonitoredProduct?, desktopMain: Bool) {
        if managedCodexAppServerPath(executable, home: home) {
            let matched = argumentTokens != nil
                ? managedCodexAppServerTokens(path: executable, home: home, tokens: argumentTokens)
                : managedCodexAppServer(path: executable, home: home, arguments: arguments)
            return matched ? (.openAI, false) : (nil, false)
        }
        if trustedClaudePaths.contains(executable)
            || executable.hasPrefix(home + "/.local/share/claude/versions/")
            || executable.hasSuffix("/node_modules/@anthropic-ai/claude-code/cli.js") {
            return (.claude, false)
        }
        if trustedCodexPaths.contains(executable)
            || (executable.contains("/Caskroom/codex/") && executable.hasSuffix("/bin/codex"))
            || executable.hasSuffix("/node_modules/@openai/codex/bin/codex.js")
            || (executable.contains("/node_modules/@openai/codex/") && executable.hasSuffix("/codex")) {
            return (.openAI, false)
        }
        if let bundleRange = executable.range(of: ".app/Contents/") {
            let bundlePath = String(executable[..<bundleRange.lowerBound]) + ".app"
            let bundleName = URL(fileURLWithPath: bundlePath).lastPathComponent
            let id = bundleIdentifier ?? ""
            if ["com.openai.codex", "com.openai.chat"].contains(id)
                && (executable.hasSuffix("/Resources/codex")
                    || executable.contains("/Resources/codex-cli/")
                    || executable.hasSuffix("/CodexCLI.app/Contents/MacOS/codex")) {
                return (.openAI, false)
            }
            let main = executable.hasPrefix(bundlePath + "/Contents/MacOS/")
            switch (id, bundleName) {
            case ("com.anthropic.claudefordesktop", _):
                return (.claude, main)
            case ("com.openai.codex", "Codex.app"),
                 ("com.openai.chat", "ChatGPT.app"),
                 ("com.openai.codex", "ChatGPT.app"):
                return (.openAI, main)
            default:
                break
            }
        }
        if ["node", "nodejs", "bun"].contains(URL(fileURLWithPath: executable).lastPathComponent) {
            let entry: String?
            if let argumentTokens {
                entry = nodeEntryTokens(argumentTokens, cwd: cwd)
            } else if let arguments {
                entry = nodeEntry(arguments, cwd: cwd)
            } else {
                entry = nil
            }
            if let script = entry {
                let resolved = resolveScript(script) ?? script
                if resolved.hasSuffix("/node_modules/@anthropic-ai/claude-code/cli.js") {
                    return (.claude, false)
                }
                if resolved.hasSuffix("/node_modules/@openai/codex/bin/codex.js") {
                    return (.openAI, false)
                }
            }
        }
        return (nil, false)
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
    static func currentDirectory(_ pid: Int32) -> String? {
        guard pid > 1 else { return nil }
        var info = proc_vnodepathinfo()
        let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, size) == size else { return nil }
        let value = withUnsafePointer(to: &info.pvi_cdir.vip_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
        }
        return value.hasPrefix("/") ? value : nil
    }
    static func arguments(_ pid: Int32) -> [String]? {
        guard pid > 1 else { return nil }
        var mib = [Int32(CTL_KERN), Int32(KERN_PROCARGS2), pid]
        var size = 0
        guard sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0,
              size >= 4, size <= 1_048_576 else { return nil }
        var bytes = [UInt8](repeating: 0, count: size)
        let result = bytes.withUnsafeMutableBytes { pointer in
            sysctl(&mib, UInt32(mib.count), pointer.baseAddress, &size, nil, 0)
        }
        guard result == 0, size >= 4 else { return nil }
        let argc = bytes.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) }
        guard argc >= 0, argc <= 131_072 else { return nil }
        var offset = 4
        // KERN_PROCARGS2 has argc, executable path, NUL padding, then exactly argc argv strings.
        while offset < size && bytes[offset] != 0 { offset += 1 }
        while offset < size && bytes[offset] == 0 { offset += 1 }
        var args: [String] = []
        var total = 0
        for _ in 0..<min(Int(argc), 256) {
            guard offset < size else { return nil }
            let start = offset
            while offset < size && bytes[offset] != 0 { offset += 1 }
            guard offset < size, offset - start <= 16_384 else { return nil }
            total += offset - start
            guard total <= 65_536,
                  let text = String(bytes: bytes[start..<offset], encoding: .utf8) else { return nil }
            args.append(text)
            offset += 1
        }
        return args
    }
    static func read() throws -> [AIProcessIdentity] {
        let output = try command(["-axo", "pid="])
        var identities = output.split(whereSeparator: \.isWhitespace).compactMap { Int32($0) }.compactMap(identity)
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let trusted = trustedCLIPaths(home: home)
        for index in identities.indices where identities[index].uid == getuid() {
            let path = identities[index].executable
            let bundleId: String?
            if let bundleRange = path.range(of: ".app/Contents/") {
                let bundlePath = String(path[..<bundleRange.lowerBound]) + ".app"
                bundleId = Bundle(path: bundlePath)?.bundleIdentifier ?? ""
            } else {
                bundleId = nil
            }
            let needsArgs = AIProcessClosePolicy.managedCodexAppServerPath(path, home: home)
                || ["node", "nodejs", "bun"].contains(URL(fileURLWithPath: path).lastPathComponent)
            var verifiedArgTokens: [String]? = nil
            var verifiedArgs: String? = nil
            var verifiedCwd: String? = nil
            if needsArgs {
                let pid = identities[index].pid
                let tokens = arguments(pid)
                let fallbackArgs = tokens == nil ? (try? command(["-ww", "-p", String(pid), "-o", "args="])) : nil
                let cwd = currentDirectory(pid)
                if let verified = identity(pid),
                   identities[index].sameProcess(as: verified) {
                    verifiedArgTokens = tokens
                    verifiedArgs = fallbackArgs
                    verifiedCwd = cwd
                }
            }
            let classified = AIProcessClosePolicy.classifyRoot(
                executable: path,
                bundleIdentifier: bundleId,
                argumentTokens: verifiedArgTokens,
                arguments: verifiedArgs,
                cwd: verifiedCwd,
                home: home,
                trustedClaudePaths: trusted.claude,
                trustedCodexPaths: trusted.codex,
                resolveScript: { script in
                    FileManager.default.fileExists(atPath: script)
                        ? URL(fileURLWithPath: script).resolvingSymlinksInPath().path
                        : script
                }
            )
            identities[index].rootProduct = classified.product
            identities[index].desktopMain = classified.desktopMain
        }
        return identities
    }
    static func trustedCLIPaths(home: String) -> (claude: Set<String>, codex: Set<String>) {
        let known: [(String, MonitoredProduct)] = [
            (home + "/.local/bin/claude", .claude), (home + "/.claude/local/claude", .claude),
            ("/opt/homebrew/bin/claude", .claude), ("/usr/local/bin/claude", .claude),
            ("/opt/homebrew/bin/codex", .openAI), ("/usr/local/bin/codex", .openAI)
        ]
        var claude = Set<String>()
        var codex = Set<String>()
        for (entry, product) in known where FileManager.default.fileExists(atPath: entry) {
            let resolved = URL(fileURLWithPath: entry).resolvingSymlinksInPath().path
            if product == .claude { claude.insert(resolved) } else { codex.insert(resolved) }
        }
        return (claude, codex)
    }
    static func nativeCLI(_ path: String) -> MonitoredProduct? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let trusted = trustedCLIPaths(home: home)
        return AIProcessClosePolicy.classifyRoot(
            executable: path,
            home: home,
            trustedClaudePaths: trusted.claude,
            trustedCodexPaths: trusted.codex
        ).product
    }
    static func nodeEntry(_ command: String, cwd: String? = nil) -> String? {
        AIProcessClosePolicy.nodeEntry(command, cwd: cwd)
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
