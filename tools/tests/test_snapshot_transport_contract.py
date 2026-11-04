"""Source contract for read-only snapshot subprocess isolation."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = (ROOT / "monitor/Sources/MonitorSnapshotReader.swift").read_text(encoding="utf-8")
TRANSPORT = (ROOT / "monitor/Sources/SnapshotProcessTransport.swift").read_text(encoding="utf-8")
SWIFT_TEST = (ROOT / "monitor/tests/SnapshotProcessTransportTests.swift").read_text(encoding="utf-8")
FINAL = (ROOT / "tools/test-final-no-signal.sh").read_text(encoding="utf-8")


class SnapshotTransportContract(unittest.TestCase):
    def test_stderr_is_never_a_sequentially_drained_pipe(self):
        self.assertIn('posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0)', TRANSPORT)
        self.assertNotIn("let errors = Pipe()", TRANSPORT)
        self.assertNotIn("readDataToEndOfFile()", TRANSPORT)
        self.assertNotIn("let errors = Pipe()", RUNNER)

    def test_stdout_is_read_with_a_bounded_buffer(self):
        self.assertIn("static let maximumOutputBytes = 16 * 1024 * 1024", TRANSPORT)
        self.assertIn("count > maximumOutputBytes - data.count", TRANSPORT)
        self.assertIn("return .outputTooLarge", TRANSPORT)

    def test_deadline_does_not_rely_on_blocking_waits(self):
        # Blocking read()/waitUntilExit() after terminate() is what BUG-01
        # removed; the deadline must be enforced by poll + WNOHANG reaping.
        self.assertNotIn("waitUntilExit()", TRANSPORT)
        self.assertNotIn("read(upToCount:", TRANSPORT)
        self.assertNotIn("asyncAfter", TRANSPORT)
        self.assertIn("O_NONBLOCK", TRANSPORT)
        self.assertIn("poll(&pfd, 1,", TRANSPORT)
        self.assertIn("waitpid(pid, &status, WNOHANG)", TRANSPORT)
        self.assertIn("case timedOut", TRANSPORT)

    def test_only_the_unreaped_direct_child_is_signalled(self):
        self.assertIn("guard case .running = reap(pid, until: 0) else { return }", TRANSPORT)
        self.assertNotIn("killpg", TRANSPORT)
        self.assertNotIn("kill(-", TRANSPORT)
        self.assertNotIn("kill(0", TRANSPORT)

    def test_failures_cannot_publish_a_successful_snapshot(self):
        self.assertIn("return status == 0 ? .success(data) : .executionFailed", TRANSPORT)
        self.assertIn("case .launchFailed:", RUNNER)
        self.assertIn("case .executionFailed:", RUNNER)
        self.assertIn("case .outputTooLarge:", RUNNER)
        self.assertIn("case .timedOut:", RUNNER)
        self.assertIn("case .success(let data):", RUNNER)
        self.assertIn("JSONDecoder().decode(MonitorSnapshot.self, from: data)", RUNNER)

    def test_behavioral_fixture_covers_noisy_child_and_oversized_output(self):
        self.assertIn("stderr flooding cannot block stdout", SWIFT_TEST)
        self.assertIn("excessive stdout is rejected", SWIFT_TEST)
        self.assertIn("failed exit is not a success", SWIFT_TEST)

    def test_behavioral_fixture_covers_strict_timeout_paths(self):
        self.assertIn("TERM-ignoring child with open stdout reports timedOut", SWIFT_TEST)
        self.assertIn("descendant holding stdout cannot block until its EOF", SWIFT_TEST)
        self.assertIn("infinite stdout is rejected as outputTooLarge", SWIFT_TEST)
        self.assertIn("exit 0 after the deadline is still timedOut", SWIFT_TEST)
        # The behavioural fixture must actually be compiled and executed.
        self.assertIn('"$BUILD/snapshot-transport-tests"', FINAL)


if __name__ == "__main__":
    unittest.main()
