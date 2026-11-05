"""Static binding checks for truthful execution acknowledgement (no processes launched)."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DAEMON = (ROOT / "crates/watch-engine/src/daemon_run.rs").read_text()
CORE = (ROOT / "crates/watch-core/src/channel.rs").read_text()
EXT = (ROOT / "monitor/SystemExtension/WatchChannelExtension.swift").read_text()


class ExecutionReceiptAuthority(unittest.TestCase):
    def test_liveness_is_not_execution_confirmation(self):
        self.assertIn("let extension_confirmed = heartbeat_active && receipt_confirmed", DAEMON)
        self.assertIn("receipt.is_fresh(now, 8.0)", DAEMON)
        self.assertIn("receipt.policy_version == policy.policy_digest", DAEMON)
        self.assertNotIn('Some("扩展独立心跳在线")', DAEMON)
        self.assertIn("system_extension_command_superseded", DAEMON)
        self.assertIn("record_activation_failure", DAEMON)

    def test_revoke_requires_final_receipt_and_exact_identity(self):
        method = CORE.split("pub fn is_confirmed_revoked", 1)[1].split(
            "pub fn matches_supervision", 1
        )[0]
        self.assertIn('self.status == "revoked"', method)
        self.assertIn('self.permit_state == "revoked"', method)
        self.assertIn("self.command_seq == min_command_seq", method)
        self.assertIn("self.permit_generation == min_generation", method)
        self.assertNotIn("self.command_seq >= min_command_seq", method)
        self.assertIn('status: "drain_timeout_unconfirmed"', EXT)

    def test_failed_start_cannot_report_interception_active(self):
        self.assertIn('status: "activation_failed"', EXT)
        self.assertIn('self.isInterceptionActive = false', EXT)


if __name__ == "__main__":
    unittest.main()
