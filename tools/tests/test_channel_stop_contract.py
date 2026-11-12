"""Static ownership checks; actual EOF/expiry and process receipts are Rust tests."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROJECTION = (ROOT / "crates/watch-runtime/src/channel_policy_status.rs").read_text()
SUPERVISOR = (ROOT / "crates/watch-runtime/src/channel_supervisor.rs").read_text()

class ChannelStopContract(unittest.TestCase):
    def test_projection_distinguishes_request_in_progress_and_confirmed_isolation(self):
        self.assertIn('ChannelSupervisionVerdict::PendingIsolation { .. } => ("pending", "pending_verification", "disconnecting")', PROJECTION)
        self.assertIn('ChannelSupervisionVerdict::IsolatedKeepProcess => ("protection_triggered", "locked", "blocked")', PROJECTION)
        self.assertNotIn("quit_desktop", PROJECTION)
        self.assertNotIn("signal_bound_process", PROJECTION)

    def test_supervisor_keeps_process_authority_separate_from_network_authority(self):
        self.assertIn('self.config.close_action(risk, provider) != "force"', SUPERVISOR)
        self.assertIn("dispatcher.submit(job)", SUPERVISOR)
        self.assertIn("authority.target_identities", SUPERVISOR)
        self.assertIn("now >= evidence_deadline", SUPERVISOR)

if __name__ == "__main__":
    unittest.main()
