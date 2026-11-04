import Foundation

// Synthetic owned subprocesses only; no real applications, network or
// installed monitor service are used.
@main
struct SnapshotProcessTransportTests {
    static func main() {
        var count = 0
        func expect(_ condition: @autoclosure () -> Bool, _ description: String) {
            guard condition() else { fatalError(description) }
            count += 1
            print("PASS: " + description)
        }
        let sh = URL(fileURLWithPath: "/bin/sh")
        // 100 KB of stderr exceeds normal pipe capacity; stdout must not block.
        let verbose = "i=0; while [ \"$i\" -lt 512 ]; do printf '%0200d' 0 >&2; i=$((i+1)); done; printf 'ok'"
        let started = Date()
        let result = SnapshotProcessTransport.run(executable: sh, arguments: ["-c", verbose], timeoutSeconds: 5)
        if case .success(let bytes) = result {
            expect(String(data: bytes, encoding: .utf8) == "ok", "stderr flooding cannot block stdout")
        } else { fatalError("verbose child failed") }
        expect(Date().timeIntervalSince(started) < 5, "the command finishes before its deadline")
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
        print("SnapshotProcessTransportTests: \(count) assertions passed")
    }
}
