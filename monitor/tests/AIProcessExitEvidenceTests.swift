// Compile with -D PROCESS_POLICY_TESTS and Sources/AIProcessControl.swift.
// This binary uses mock identities only: no inventory, signal or AppKit calls.
import Foundation

enum MonitoredProduct: Equatable, Sendable { case claude, openAI }

@main
struct AIProcessExitEvidenceTests {
    static func main() {
        var checks = 0
        func expect(_ value: @autoclosure () -> Bool, _ message: String) {
            precondition(value(), message)
            checks += 1
            print("PASS: \(message)")
        }
        func row(_ pid: Int32, parent: Int32 = 1, uid: UInt32 = 501,
                 start: UInt64 = 100, product: MonitoredProduct? = nil,
                 path: String = "/mock/process",
                 token: [UInt32]? = [501, 501, 20, 501, 20, 10, 1000, 1]) -> AIProcessIdentity {
            .init(pid: pid, parent: parent, uid: uid, startSeconds: start,
                  startMicroseconds: 1, executable: path, auditToken: token, rootProduct: product)
        }
        let root = row(10, product: .openAI)
        let child = row(11, parent: 10)
        let original = AIProcessClosePolicy.plan(.openAI, inventory: [root, child], uid: 501, protected: [])
        expect(original.targets.count == 2, "fixture contains root and descendant")
        let orphan = row(11)
        let orphaned = AIProcessClosePolicy.exitEvidence(original, inventory: [orphan]) { pid in
            pid == 11 ? .live(orphan) : .gone
        }
        expect(orphaned.remaining.map(\.pid) == [11], "original child survives reparenting in exit evidence")
        expect(!orphaned.complete, "empty new tree is not proof that original child exited")
        let gone = AIProcessClosePolicy.exitEvidence(original, inventory: []) { _ in .gone }
        expect(gone.complete, "confirmed absence permits completion")
        let unknown = AIProcessClosePolicy.exitEvidence(original, inventory: []) { pid in
            pid == 11 ? .unavailable : .gone
        }
        expect(unknown.unconfirmed == 1 && !unknown.complete, "metadata failure is unknown rather than exited")
        let replacement = row(10, start: 200)
        let reused = AIProcessClosePolicy.exitEvidence(original, inventory: [replacement]) { pid in
            pid == 10 ? .live(replacement) : .gone
        }
        expect(reused.complete, "unrelated reused PID is not the original process")
        let foreign = row(10, uid: 502, product: .openAI)
        let otherOwner = AIProcessClosePolicy.exitEvidence(original, inventory: [foreign]) { pid in
            pid == 10 ? .live(foreign) : .gone
        }
        expect(otherOwner.complete, "another user's PID is not included")
        let newRoot = row(20, start: 200, product: .openAI)
        let restarted = AIProcessClosePolicy.exitEvidence(original, inventory: [newRoot]) { pid in
            pid == 20 ? .live(newRoot) : .gone
        }
        expect(restarted.remaining.map(\.pid) == [20], "new family root prevents a false completion")
        var forceCalls: [Int32] = []
        let force = AIProcessClosePolicy.forceRemaining(original, lookup: { pid in
            pid == 20 ? newRoot : nil
        }, force: { forceCalls.append($0.pid); return true })
        expect(forceCalls.isEmpty && force.requested == 0, "new report member never inherits force authority")
        let still = [root, child]
        var calls: [Int32: Int] = [:]
        let duplicated = AIProcessClosePolicy.exitEvidence(original, inventory: still) { pid in
            calls[pid, default: 0] += 1
            return .live(still.first { $0.pid == pid }!)
        }
        expect(duplicated.remaining.count == 2, "original and fresh plans are deduplicated")
        expect(calls[10] == 1 && calls[11] == 1, "each identity sampled once per verification round")
        let unknownTwice = AIProcessClosePolicy.exitEvidence(original, inventory: still) { _ in .unavailable }
        expect(unknownTwice.unconfirmed == 2, "unknown identities are deduplicated")
        let protected = AIProcessClosePlan(product: .openAI, uid: 501, targets: [root], protected: [10])
        let excluded = AIProcessClosePolicy.exitEvidence(protected, inventory: [root]) { _ in
            preconditionFailure("protected process must not be queried")
        }
        expect(excluded.complete, "protected identities stay outside exit scope")
        let changedPath = row(10, path: "/different/program")
        let changed = AIProcessClosePolicy.exitEvidence(original, inventory: [changedPath]) { pid in
            pid == 10 ? .live(changedPath) : .gone
        }
        expect(changed.complete, "changed executable does not preserve original ownership")
        let newChild = row(12, parent: 10)
        let expanded = AIProcessClosePolicy.exitEvidence(original, inventory: [root, newChild]) { pid in
            if pid == 10 { return .live(root) }
            if pid == 12 { return .live(newChild) }
            return .gone
        }
        expect(expanded.remaining.map(\.pid) == [10, 12], "new descendant is visible in completion evidence")
        forceCalls.removeAll()
        _ = AIProcessClosePolicy.forceRemaining(original, lookup: { pid in
            if pid == 10 { return root }; if pid == 12 { return newChild }; return nil
        }, force: { forceCalls.append($0.pid); return true })
        expect(forceCalls == [10], "new descendant is never forced by the old plan")
        // A PID may be recycled after the first observation but before the
        // side effect. A second identity read must then skip the signal.
        // This narrows the race; PID-only signalling is not atomic.
        let single = AIProcessClosePlan(product: .openAI, uid: 501, targets: [root], protected: [])
        var signalReads = 0
        var signals = 0
        let recycledBeforeTerm = AIProcessClosePolicy.execute(single, lookup: { _ in
            signalReads += 1
            return signalReads == 1 ? root : replacement
        }, quitApplication: { _ in signals += 1; return true },
           terminate: { _ in signals += 1; return true })
        expect(signalReads == 2 && signals == 0 && recycledBeforeTerm.skipped == 1,
               "a PID recycled between identity reads never receives TERM")

        var forceReads = 0
        let recycledBeforeForce = AIProcessClosePolicy.forceRemaining(single, lookup: { _ in
            forceReads += 1
            return forceReads == 1 ? root : replacement
        }, force: { _ in signals += 1; return true })
        expect(forceReads == 2 && signals == 0 && recycledBeforeForce.skipped == 1,
               "a PID recycled between identity reads never receives Force")

        var stableReads = 0
        let stable = AIProcessClosePolicy.execute(single, lookup: { _ in
            stableReads += 1
            return root
        }, quitApplication: { _ in signals += 1; return true },
           terminate: { _ in signals += 1; return true })
        expect(stableReads == 2 && stable.requested == 1 && signals == 1,
               "stable matching identity still permits one explicit normal-exit request")
        var unavailableReads = 0
        let vanishedBeforeForce = AIProcessClosePolicy.forceRemaining(single, lookup: { _ in
            unavailableReads += 1
            return unavailableReads == 1 ? root : nil
        }, force: { _ in signals += 1; return true })
        expect(vanishedBeforeForce.skipped == 1 && signals == 1,
               "missing second identity check never authorizes Force")

        var effectSignals = 0
        let effectReuse = AIProcessClosePolicy.applyToMatchingIdentity(root,
            lookup: { _ in replacement }, effect: { _ in effectSignals += 1; return true })
        expect(!effectReuse && effectSignals == 0, "effect adapter refuses a recycled PID")
        let effectUnavailable = AIProcessClosePolicy.applyToMatchingIdentity(root,
            lookup: { _ in nil }, effect: { _ in effectSignals += 1; return true })
        expect(!effectUnavailable && effectSignals == 0, "effect adapter refuses a missing identity")
        let effectValid = AIProcessClosePolicy.applyToMatchingIdentity(root,
            lookup: { _ in root }, effect: { pid in effectSignals += 1; return pid == root.pid })
        expect(effectValid && effectSignals == 1, "effect adapter receives only the verified PID")
        // On XNU, execve preserves pbi_start_tvsec/usec; an updated audit token
        // (pidversion) with identical PID, UID, start time and path must still
        // be rejected at every decision and effect boundary.
        let samePathExec = row(10, product: .openAI, token: [501, 501, 20, 501, 20, 10, 1000, 2])
        expect(!root.sameProcess(as: samePathExec),
               "in-place exec with identical start time and path is not the same process")
        var execEffects = 0
        let execBlocked = AIProcessClosePolicy.applyToMatchingIdentity(root,
            lookup: { _ in samePathExec }, effect: { _ in execEffects += 1; return true })
        expect(!execBlocked && execEffects == 0,
               "effect adapter refuses an in-place exec with changed audit token")
        let execForce = AIProcessClosePolicy.forceRemaining(single,
            lookup: { _ in samePathExec }, force: { _ in execEffects += 1; return true })
        expect(execForce.skipped == 1 && execEffects == 0,
               "forceRemaining refuses an in-place exec with changed audit token")
        let anotherProduct = row(30, product: .claude)
        let unrelated = AIProcessClosePolicy.exitEvidence(original, inventory: [anotherProduct]) { _ in .gone }
        expect(unrelated.complete, "another family is not silently added to close scope")
        let claudeDesktop = row(40, product: .claude, path: "/Applications/Claude.app/Contents/MacOS/Claude")
        let claudeDesktopChild = row(41, parent: 40, path: "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper")
        let claudeCLI = row(42, product: .claude, path: "/Users/test/.local/share/claude/versions/1.0.0/claude")
        let claudeCLIChild = row(43, parent: 42, path: "/usr/bin/git")
        let mixedClaude = [claudeDesktop, claudeDesktopChild, claudeCLI, claudeCLIChild]
        expect(AIProcessClosePolicy.automaticDesktopScope(for: .claude) == .desktopBundleOnly,
               "automatic Claude desktop scope excludes standalone CLI roots")
        expect(AIProcessClosePolicy.automaticDesktopScope(for: .openAI) == .allProductProcesses,
               "automatic OpenAI scope includes attributed family processes")
        expect(AIProcessClosePolicy.manualCloseScope(for: .claude) == .allProductProcesses &&
               AIProcessClosePolicy.manualCloseScope(for: .openAI) == .allProductProcesses,
               "manual UI close scope includes both desktop and CLI trees")
        let autoClaudeScoped = AIProcessClosePolicy.scopedInventory(
            mixedClaude, for: .claude, scope: AIProcessClosePolicy.automaticDesktopScope(for: .claude))
        let autoClaudePlan = AIProcessClosePolicy.plan(.claude, inventory: autoClaudeScoped, uid: 501, protected: [])
        expect(autoClaudePlan.targets.map(\.pid) == [40, 41],
               "automatic Claude desktop close plan excludes standalone Claude CLI and its children")
        let manualClaudeScoped = AIProcessClosePolicy.scopedInventory(
            mixedClaude, for: .claude, scope: AIProcessClosePolicy.manualCloseScope(for: .claude))
        let manualClaudePlan = AIProcessClosePolicy.plan(.claude, inventory: manualClaudeScoped, uid: 501, protected: [])
        expect(manualClaudePlan.targets.map(\.pid) == [40, 41, 42, 43],
               "manual Claude close plan includes both desktop and standalone CLI trees")
        let classified = row(70, path: "/fixture/Renamed.app/Contents/MacOS/App")
        func batch(_ change: (inout [String: Any]) -> Void = { _ in }) -> Data {
            var value: [String: Any] = [
                "schema": 1, "status": "ok", "mode": "read_only", "state": "ok", "uid": 501,
                "observed_at": 100.0, "grants_launch_permission": false, "grants_close_permission": false,
                "targets": [["identity": ["pid": 70, "parent": 1, "uid": 501,
                    "executable": classified.executable, "start_seconds": 100, "start_microseconds": 1],
                    "product": "openai", "desktop_main": true]]
            ]
            change(&value)
            return try! JSONSerialization.data(withJSONObject: value)
        }
        let mapped = try! AIProcessClassificationBatch.apply(batch(), to: [classified], uid: 501, now: 101,
            lookup: { _ in .live(classified) })
        expect(mapped.first?.rootProduct == .openAI && mapped.first?.desktopMain == true,
               "Swift accepts the Rust product projection without matching application names")
        let completed = try! AIProcessClassificationBatch.apply(batch(), to: [classified], uid: 501, now: 101,
            lookup: { _ in .gone })
        expect(completed.first?.rootProduct == nil, "confirmed exit creates no new close target")
        func rejects(_ data: Data, before: [AIProcessIdentity] = [classified],
                     lookup: (Int32) -> AIProcessPresence = { _ in .live(classified) }) -> Bool {
            do { _ = try AIProcessClassificationBatch.apply(data, to: before, uid: 501, now: 101, lookup: lookup); return false }
            catch { return true }
        }
        expect(rejects(batch { $0["state"] = "partial" }), "partial classification cannot claim an empty complete inventory")
        expect(rejects(batch { $0["observed_at"] = 1 }), "expired classification is rejected")
        expect(rejects(batch { $0["observed_at"] = 104 }), "future classification is rejected")
        expect(rejects(batch { $0["uid"] = 502 }), "foreign owner classification is rejected")
        expect(rejects(batch { $0["grants_close_permission"] = true }), "read-only classification cannot grant close authority")
        expect(rejects(batch { value in
            let targets = value["targets"] as! [[String: Any]]
            value["targets"] = targets + targets
        }), "duplicate classified PID is rejected")
        expect(rejects(batch(), before: []), "new root absent from the original identity capture is rejected")
        expect(rejects(batch(), lookup: { _ in .unavailable }), "unknown native identity blocks classification")
        expect(rejects(batch(), lookup: { _ in .live(row(70, start: 101, path: classified.executable)) }),
               "PID reuse during batch classification is rejected")
        expect(rejects(batch(), lookup: { _ in .live(row(70, path: "/fixture/replacement")) }),
               "executable replacement during batch classification is rejected")
        var reexecuted = classified; reexecuted.auditToken = [501, 501, 20, 501, 20, 70, 1000, 2]
        expect(rejects(batch(), lookup: { _ in .live(reexecuted) }),
               "in-place exec with unchanged PID/start/path is rejected by the audit token")
        print("AIProcessExitEvidenceTests: \(checks) assertions passed; all identities and actions mocked")
    }
}
