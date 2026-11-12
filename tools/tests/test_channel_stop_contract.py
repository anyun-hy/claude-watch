"""Only validates request-versus-confirmation status in the Rust guard.

No real processes, network or system extension are exercised here.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DISPOSITION = (ROOT / "crates/watch-runtime/src/controlled/disposition.rs").read_text()


def rust_block(marker, start=0):
    """Select one branch, independent of the order of its sibling branches."""
    opening = DISPOSITION.index("{", DISPOSITION.index(marker, start))
    depth = 0
    for match in re.finditer(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[{}]',
                             DISPOSITION[opening:], re.S):
        token = match.group()
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth == 0:
                end = opening + match.end()
                return DISPOSITION[opening:end], end
    raise AssertionError(f"Unterminated Rust branch: {marker}")


class ChannelStopContract(unittest.TestCase):
    def test_channel_request_is_not_a_confirmed_stop(self):
        branch, _ = rust_block("} else if system.channel_mode() {")
        self.assertIn('receipt["stop_state"] = json!("disconnecting")', branch)
        self.assertIn('receipt["action"] = json!("disconnect-channel")', branch)
        self.assertIn('receipt["process_preserved"] = json!(true)', branch)
        self.assertIn("StopOutcome::SkippedWarn", branch)
        self.assertNotIn("StopOutcome::Confirmed", branch)
        self.assertNotIn("system.quit_", branch)

    def test_confirmed_stop_still_requires_real_exit_or_executor_evidence(self):
        force, _ = rust_block('} else if action == "force" && family.is_some_and')
        _, end = rust_block("} else if system.channel_mode() {")
        close, _ = rust_block("} else {", end - 1)
        for branch, operation in ((force, "system.quit_for_confirmed_ip_risk(&mut forced)"),
                                  (close, "system.quit_desktop()")):
            self.assertIn(f"let result = {operation};", branch)
            self.assertIn("result.map(|()| StopOutcome::Confirmed)", branch)
            self.assertIn('receipt["process_execution_state"] = json!("failed")', branch)
            self.assertNotIn("Ok(StopOutcome::Confirmed)", branch)


if __name__ == "__main__":
    unittest.main()
