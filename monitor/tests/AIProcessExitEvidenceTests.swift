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
                 path: String = "/mock/process") -> AIProcessIdentity {
            .init(pid: pid, parent: parent, uid: uid, startSeconds: start,
                  startMicroseconds: 1, executable: path, rootProduct: product)
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
        }, force: { forceCalls.append($0); return true })
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
        }, force: { forceCalls.append($0); return true })
        expect(forceCalls == [10], "new descendant is never forced by the old plan")
        let anotherProduct = row(30, product: .claude)
        let unrelated = AIProcessClosePolicy.exitEvidence(original, inventory: [anotherProduct]) { _ in .gone }
        expect(unrelated.complete, "another family is not silently added to close scope")
        print("AIProcessExitEvidenceTests: \(checks) assertions passed; all identities and actions mocked")
    }
}
