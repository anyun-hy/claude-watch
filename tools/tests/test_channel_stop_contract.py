"""Only validates request-versus-confirmation status in the Rust guard.

No real processes, network or system extension are exercised here.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DISPOSITION = (ROOT / "crates/watch-runtime/src/controlled/disposition.rs").read_text()


class ChannelStopContract(unittest.TestCase):
    def test_channel_request_is_not_a_confirmed_stop(self):
        start = DISPOSITION.index("} else if system.channel_mode() {")
        end = DISPOSITION.index('} else if action == "force"', start)
        branch = DISPOSITION[start:end]
        self.assertIn('receipt["stop_state"] = json!("disconnecting")', branch)
        self.assertIn('receipt["action"] = json!("disconnect-channel")', branch)
        self.assertIn("StopOutcome::SkippedWarn", branch)
        self.assertNotIn("StopOutcome::Confirmed", branch)

    def test_confirmed_stop_still_requires_real_exit_or_executor_evidence(self):
        self.assertIn("system.quit_desktop().map(|()| StopOutcome::Confirmed)", DISPOSITION)
        self.assertIn("result.map(|()| StopOutcome::Confirmed)", DISPOSITION)


if __name__ == "__main__":
    unittest.main()
