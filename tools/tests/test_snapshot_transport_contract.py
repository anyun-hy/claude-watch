"""Source contract for read-only snapshot subprocess isolation."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = (ROOT / "monitor/Sources/MonitorSnapshotReader.swift").read_text(encoding="utf-8")
TRANSPORT = (ROOT / "monitor/Sources/SnapshotProcessTransport.swift").read_text(encoding="utf-8")
SWIFT_TEST = (ROOT / "monitor/tests/SnapshotProcessTransportTests.swift").read_text(encoding="utf-8")


class SnapshotTransportContract(unittest.TestCase):
    def test_stderr_is_never_a_sequentially_drained_pipe(self):
        self.assertIn("task.standardError = FileHandle.nullDevice", TRANSPORT)
        self.assertNotIn("let errors = Pipe()", TRANSPORT)
        self.assertNotIn("readDataToEndOfFile()", TRANSPORT)
        self.assertNotIn("let errors = Pipe()", RUNNER)

    def test_stdout_is_read_with_a_bounded_buffer(self):
        self.assertIn("static let maximumOutputBytes = 16 * 1024 * 1024", TRANSPORT)
        self.assertIn("read(upToCount: 65_536)", TRANSPORT)
        self.assertIn("chunk.count > Self.maximumOutputBytes - data.count", TRANSPORT)
        self.assertIn("if oversized { return .outputTooLarge }", TRANSPORT)

    def test_failures_cannot_publish_a_successful_snapshot(self):
        self.assertIn("if readFailed || task.terminationStatus != 0", TRANSPORT)
        self.assertIn("case .launchFailed:", RUNNER)
        self.assertIn("case .executionFailed:", RUNNER)
        self.assertIn("case .outputTooLarge:", RUNNER)
        self.assertIn("case .success(let data):", RUNNER)
        self.assertIn("JSONDecoder().decode(MonitorSnapshot.self, from: data)", RUNNER)

    def test_behavioral_fixture_covers_noisy_child_and_oversized_output(self):
        self.assertIn("stderr flooding cannot block stdout", SWIFT_TEST)
        self.assertIn("excessive stdout is rejected", SWIFT_TEST)
        self.assertIn("failed exit is not a success", SWIFT_TEST)


if __name__ == "__main__":
    unittest.main()
