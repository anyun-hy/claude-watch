import Foundation

// Synthetic owned subprocesses only; no real applications, network or
// installed monitor service are used. The transport only signals the direct
// synthetic child it spawned; lingering descendants created by these
// fixtures exit on their own after a short sleep and are never signalled.
@main
struct SnapshotProcessTransportTests {
    static func main() {
        var count = 0
        func expect(_ condition: @autoclosure () -> Bool, _ description: String) {
            guard condition() else { fatalError(description) }
            count += 1
            print("PASS: " + description)
        }
        func timed(_ body: () -> SnapshotProcessResult) -> (SnapshotProcessResult, TimeInterval) {
            let started = Date()
            let result = body()
            return (result, Date().timeIntervalSince(started))
        }
        func isTimedOut(_ result: SnapshotProcessResult) -> Bool {
            if case .timedOut = result { return true }
            return false
        }
        let sh = URL(fileURLWithPath: "/bin/sh")

        // 100 KB of stderr exceeds normal pipe capacity; stdout must not block.
        let verbose = "i=0; while [ \"$i\" -lt 512 ]; do printf '%0200d' 0 >&2; i=$((i+1)); done; printf 'ok'"
        let (result, verboseElapsed) = timed {
            SnapshotProcessTransport.run(executable: sh, arguments: ["-c", verbose], timeoutSeconds: 5)
        }
        if case .success(let bytes) = result {
            expect(String(data: bytes, encoding: .utf8) == "ok", "stderr flooding cannot block stdout")
        } else { fatalError("verbose child failed") }
        expect(verboseElapsed < 5, "the command finishes before its deadline")

        let bad = SnapshotProcessTransport.run(executable: sh, arguments: ["-c", "exit 17"], timeoutSeconds: 5)
        if case .executionFailed = bad { count += 1; print("PASS: failed exit is not a success") }
        else { fatalError("bad exit misclassified") }

        let missing = SnapshotProcessTransport.run(
            executable: URL(fileURLWithPath: "/no/such/cw-fixture-binary"), arguments: [], timeoutSeconds: 5)
        if case .launchFailed = missing { count += 1; print("PASS: missing binary reports launch failure") }
        else { fatalError("missing binary misclassified") }

        // 17 MiB of synthetic stdout verifies bounded memory consumption.
        let overflow = SnapshotProcessTransport.run(
            executable: sh, arguments: ["-c", "head -c 17825792 /dev/zero"], timeoutSeconds: 10)
        if case .outputTooLarge = overflow { count += 1; print("PASS: excessive stdout is rejected") }
        else { fatalError("oversized stdout accepted") }

        // A child that ignores TERM and keeps stdout open must be bounded by
        // timeout + TERM grace + KILL grace, then classified as timedOut.
        let (stubborn, stubbornElapsed) = timed {
            SnapshotProcessTransport.run(
                executable: sh, arguments: ["-c", "trap '' TERM; printf partial; exec sleep 30"],
                timeoutSeconds: 1, terminationGraceSeconds: 0.5)
        }
        expect(isTimedOut(stubborn), "TERM-ignoring child with open stdout reports timedOut")
        expect(stubbornElapsed < 1 + 0.5 + 0.5 + 1.0, "TERM-ignoring child returns within the bounded deadline")

        // The direct child exits at once, but a descendant inherits stdout.
        // The transport must not wait for that descendant's EOF, and this test
        // waits for its own synthetic descendant before exiting so no test
        // child outlives the test process.
        let pidFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("cw-orphan-\(ProcessInfo.processInfo.processIdentifier)-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: pidFile) }
        let (orphan, orphanElapsed) = timed {
            SnapshotProcessTransport.run(
                executable: sh,
                arguments: ["-c", "sleep 1.8 & echo $! > '\(pidFile.path)'; printf '{}'; exit 0"],
                timeoutSeconds: 0.4, terminationGraceSeconds: 0.2)
        }
        let orphanPID = (try? String(contentsOf: pidFile, encoding: .utf8))
            .flatMap { Int32($0.trimmingCharacters(in: .whitespacesAndNewlines)) }
        expect(isTimedOut(orphan), "descendant holding stdout yields timedOut, not success")
        expect(orphanElapsed < 1.2, "descendant holding stdout cannot block until its EOF")
        if let pid = orphanPID, pid > 1 {
            let cleanDeadline = Date().addingTimeInterval(3)
            while kill(pid, 0) == 0 && Date() < cleanDeadline {
                usleep(20_000)
            }
            if kill(pid, 0) == 0 {
                _ = kill(pid, SIGKILL)
            }
        }

        // Infinite stdout must stop as soon as the byte limit is crossed,
        // well before the time limit.
        let (endless, endlessElapsed) = timed {
            SnapshotProcessTransport.run(
                executable: sh, arguments: ["-c", "exec cat /dev/zero"],
                timeoutSeconds: 20, terminationGraceSeconds: 0.5)
        }
        if case .outputTooLarge = endless { count += 1; print("PASS: infinite stdout is rejected as outputTooLarge") }
        else { fatalError("infinite stdout misclassified") }
        expect(endlessElapsed < 10, "infinite stdout stops at the byte limit, not at EOF")

        // stdout is complete and the child exits 0, but only after the
        // deadline (TERM is trapped into a late clean exit). Still a timeout.
        let (late, lateElapsed) = timed {
            SnapshotProcessTransport.run(
                executable: sh,
                arguments: ["-c", "trap 'exit 0' TERM; printf '{}'; exec 1>&-; sleep 1; exit 0"],
                timeoutSeconds: 0.3, terminationGraceSeconds: 3)
        }
        expect(isTimedOut(late), "exit 0 after the deadline is still timedOut")
        expect(lateElapsed < 0.3 + 3 + 3 + 1.0, "late clean exit returns within the bounded deadline")

        // A timeout must not poison later reads.
        let after = SnapshotProcessTransport.run(executable: sh, arguments: ["-c", "printf ok"], timeoutSeconds: 5)
        if case .success(let bytes) = after, String(data: bytes, encoding: .utf8) == "ok" {
            count += 1; print("PASS: a later read succeeds after timeouts")
        } else { fatalError("later read failed after timeouts") }

        print("SnapshotProcessTransportTests: \(count) assertions passed")
    }
}
