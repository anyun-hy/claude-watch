import Foundation
import Darwin

@main
struct AIProcessControlTests {
    @MainActor static func main() async throws {
        if CommandLine.arguments.contains("--owned-force-child") {
            let child = Process()
            child.executableURL = URL(fileURLWithPath: "/bin/sh")
            child.arguments = ["-c", "trap '' TERM; exec /bin/sleep 30"]
            try child.run()
            let pid = child.processIdentifier
            defer { if child.isRunning { _ = Darwin.kill(pid, SIGKILL); child.waitUntilExit() } }
            var identity: AIProcessIdentity?
            for _ in 0..<50 {
                if let current = AIProcessInventory.identity(pid), current.executable == "/bin/sleep" {
                    identity = current; break
                }
                try await Task.sleep(nanoseconds: 20_000_000)
            }
            guard let identity, identity.uid == getuid() else { fatalError("owned child identity unavailable") }
            let plan = AIProcessClosePlan(product: .claude, uid: getuid(), targets: [identity], protected: [getpid()])
            guard Darwin.kill(pid, SIGTERM) == 0 else { fatalError("normal exit request failed") }
            try await Task.sleep(nanoseconds: 200_000_000)
            guard child.isRunning else { fatalError("fixture did not ignore normal exit") }
            let forced = AIProcessClosePolicy.forceRemaining(plan, lookup: AIProcessInventory.identity,
                force: { target in target.pid == pid &&
                    AIProcessClosePolicy.applyToMatchingIdentity(target, lookup: AIProcessInventory.identity) {
                        Darwin.kill($0, SIGKILL) == 0
                    } })
            guard forced.requested == 1 else { fatalError("verified child was not force-signalled") }
            child.waitUntilExit()
            guard !child.isRunning else { fatalError("owned child still running") }
            print("Owned-child force fallback passed: only the verified test child was force-stopped")
            return
        }
        if CommandLine.arguments.contains("--owned-child") {
            let child = Process()
            child.executableURL = URL(fileURLWithPath: "/bin/sleep"); child.arguments = ["30"]
            try child.run()
            defer { if child.isRunning { child.terminate() } }
            let pid = child.processIdentifier
            guard let identity = AIProcessInventory.identity(pid), identity.uid == getuid(),
                  identity.executable == "/bin/sleep" else { fatalError("owned child identity unavailable") }
            let plan = AIProcessClosePlan(product: .claude, uid: getuid(), targets: [identity], protected: [getpid()])
            let outcome = AIProcessClosePolicy.execute(plan, lookup: AIProcessInventory.identity,
                quitApplication: { _ in fatalError("not an application") },
                terminate: { target in target.pid == pid &&
                    AIProcessClosePolicy.applyToMatchingIdentity(target, lookup: AIProcessInventory.identity) {
                        Darwin.kill($0, SIGTERM) == 0
                    } })
            guard outcome.requested == 1 else { fatalError("owned child was not signalled") }
            child.waitUntilExit()
            guard !child.isRunning else { fatalError("owned child still running") }
            print("Owned-child integration passed: verified and terminated only the sleep process created by this test")
            return
        }
        if CommandLine.arguments.contains("--inspect") {
            let rows = try AIProcessInventory.read()
            let protection = AIProcessInventory.protectedIDs(in: rows, backendPID: nil)
            let counts = Dictionary(uniqueKeysWithValues: MonitoredProduct.allCases.map {
                ($0.rawValue, AIProcessClosePolicy.plan($0, inventory: rows, uid: getuid(), protected: protection).targets.count)
            })
            print(String(data: try JSONEncoder().encode(counts), encoding: .utf8)!)
            return
        }
        var passed = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            guard value() else { fputs("FAIL: \(message)\n", stderr); exit(1) }; passed += 1
        }
        func row(_ pid: Int32, parent: Int32 = 1, product: MonitoredProduct? = nil,
                 uid: UInt32 = 501, seconds: UInt64 = 100, micros: UInt64 = 1, path: String = "/mock/app", main: Bool = false) -> AIProcessIdentity {
            .init(pid: pid, parent: parent, uid: uid, startSeconds: seconds, startMicroseconds: micros,
                  executable: path, rootProduct: product, desktopMain: main)
        }
        let rows = [row(10, product: .claude, main: true), row(11, parent: 10), row(12, parent: 11),
                    row(20, product: .openAI, main: true), row(21, parent: 20),
                    row(30, parent: 10, uid: 502), row(40), row(50, product: .claude),
                    row(60, parent: 10, product: .openAI), row(61, parent: 60)]
        let plan = AIProcessClosePolicy.plan(.claude, inventory: rows, uid: 501, protected: [50])
        expect(Set(plan.targets.map(\.pid)) == [10, 11, 12], "only requested product and same-user descendants")
        expect(!plan.targets.contains { $0.pid == 30 }, "different owner excluded")
        expect(!plan.targets.contains { $0.pid == 40 }, "unrelated process excluded")
        expect(!plan.targets.contains { $0.pid == 50 }, "monitor/backend protection honored")
        expect(!plan.targets.contains { [20, 21, 60, 61].contains($0.pid) }, "other product subtree excluded")
        let empty = AIProcessClosePolicy.plan(.claude, inventory: [row(20, product: .openAI)], uid: 501, protected: [])
        expect(empty.targets.isEmpty, "missing product never falls back to another product")
        var quit: [Int32] = [], signals: [Int32] = []
        let ok = AIProcessClosePolicy.execute(plan, lookup: { pid in rows.first { $0.pid == pid } },
            quitApplication: { quit.append($0.pid); return true }, terminate: { signals.append($0.pid); return true })
        expect(quit == [10] && Set(signals) == [11, 12], "desktop gets normal quit; descendants get TERM")
        expect(ok.requested == 3 && ok.failed == 0 && ok.skipped == 0, "request accounting")
        for changed in [row(10, product: .claude, seconds: 101), row(10, product: .claude, micros: 2),
                        row(10, product: .claude, path: "/unrelated/app"), row(10, product: .claude, uid: 502)] {
            let one = AIProcessClosePlan(product: .claude, uid: 501, targets: [rows[0]], protected: [])
            var called = false
            let result = AIProcessClosePolicy.execute(one, lookup: { _ in changed },
                quitApplication: { _ in called = true; return true }, terminate: { _ in called = true; return true })
            expect(!called && result.skipped == 1, "reused PID, changed identity or UID must not receive request")
        }
        let gone = AIProcessClosePolicy.execute(plan, lookup: { _ in nil }, quitApplication: { _ in fatalError() }, terminate: { _ in fatalError() })
        expect(gone.skipped == 3 && gone.requested == 0, "already-exited targets skipped")
        let failed = AIProcessClosePolicy.execute(plan, lookup: { pid in rows.first { $0.pid == pid } },
            quitApplication: { _ in false }, terminate: { _ in false })
        expect(failed.failed == 3 && failed.requested == 0, "failed requests are not reported as accepted")
        var forced: [Int32] = []
        let onlySame = AIProcessClosePolicy.forceRemaining(plan, lookup: { pid in
            if pid == 10 { return row(10, product: .claude, seconds: 101, main: true) }
            if pid == 11 { return rows.first { $0.pid == pid } }
            return nil
        }, force: { forced.append($0.pid); return true })
        expect(forced == [11] && onlySame.requested == 1 && onlySame.skipped == 2,
               "force fallback skips recycled or exited identities")
        for changed in [row(10, product: .claude, seconds: 101), row(10, product: .claude, micros: 2),
                        row(10, product: .claude, path: "/unrelated/app"), row(10, product: .claude, uid: 502)] {
            let one = AIProcessClosePlan(product: .claude, uid: 501, targets: [rows[0]], protected: [])
            var called = false
            let result = AIProcessClosePolicy.forceRemaining(one, lookup: { _ in changed }, force: { _ in called = true; return true })
            expect(!called && result.skipped == 1, "force fallback rechecks PID start, path and owner")
        }
        // Force eligibility is decided by the policy table upstream; the
        // helper verifies identity alone, whatever product the plan carries.
        let otherPlan = AIProcessClosePlan(product: .openAI, uid: 501, targets: [rows[3]], protected: [])
        var otherForced: [Int32] = []
        let other = AIProcessClosePolicy.forceRemaining(otherPlan, lookup: { pid in
            pid == 20 ? rows.first { $0.pid == pid } : nil
        }, force: { otherForced.append($0.pid); return true })
        expect(otherForced == [20] && other.requested == 1 && other.skipped == 0,
               "force follows the upstream policy decision and identity verification alone")
        // The effect adapter independently checks the original full identity;
        // a PID check alone cannot authorise an action after process reuse.
        var effects = 0
        let original = rows[0]
        let fakeReused = row(original.pid, seconds: original.startSeconds + 1)
        let effectSkipped = AIProcessClosePolicy.applyToMatchingIdentity(original,
            lookup: { _ in fakeReused }, effect: { _ in effects += 1; return true })
        expect(!effectSkipped && effects == 0, "effect-boundary identity change blocks a signal")
        let effectAccepted = AIProcessClosePolicy.applyToMatchingIdentity(original,
            lookup: { _ in original }, effect: { pid in
                effects += 1
                return pid == original.pid
            })
        expect(effectAccepted && effects == 1, "effect adapter receives the verified original PID")
        let forceFailed = AIProcessClosePolicy.forceRemaining(plan, lookup: { pid in rows.first { $0.pid == pid } }, force: { _ in false })
        expect(forceFailed.requested == 0 && forceFailed.failed == 3, "failed force requests are never reported as successful")
        expect(AIProcessInventory.nodeEntry("/usr/bin/node /x/node_modules/@anthropic-ai/claude-code/cli.js")?.hasSuffix("cli.js") == true, "executed node script recognized")
        expect(AIProcessInventory.nodeEntry("/usr/bin/node -e /x/node_modules/@anthropic-ai/claude-code/cli.js") == nil, "inline code cannot impersonate script entry")
        expect(AIProcessInventory.nodeEntry("/usr/bin/node /unrelated.js /x/node_modules/@anthropic-ai/claude-code/cli.js") == "/unrelated.js", "later data argument is not an entry")
        let fixture = AIProcessControl(isFixture: true)
        let mock = [WatchedProcess(id: "p", pid: 999999, started: "mock", kind: "code", authorized: true)]
        let prepared = try await fixture.prepare(.claude, sampled: mock, backendPID: nil)
        let message = await fixture.execute(prepared)
        expect(message.contains("模拟关闭") && message.contains("未向任何系统进程"), "preview executes no OS termination calls")
        expect(!fixture.busy, "operation state resets")
        print("AIProcessControlTests: \(passed) assertions passed; all exit requests mocked")
    }
}
