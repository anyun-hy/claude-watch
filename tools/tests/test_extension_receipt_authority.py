"""Static binding checks for truthful execution acknowledgement (no processes launched)."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
DAEMON = (ROOT / "crates/watch-engine/src/daemon_run.rs").read_text()
CORE = (ROOT / "crates/watch-core/src/channel.rs").read_text()
EXT = (ROOT / "monitor/SystemExtension/WatchChannelExtension.swift").read_text()
ENFORCER = (ROOT / "crates/watch-runtime/src/channel_enforcer.rs").read_text()


class ExecutionReceiptAuthority(unittest.TestCase):
    def test_liveness_is_not_execution_confirmation(self):
        self.assertIn('h.is_live(&guard.boot_id, now)', ENFORCER)
        self.assertIn('r.matches_supervision(&cmd.policy_version, cmd.command_seq', ENFORCER)
        self.assertIn('self.executor_boot_id == expected_boot', CORE)
        self.assertIn('self.extension_boot_id == extension_boot', CORE)
        self.assertIn('"executor_boot_id": executorBoot, "extension_boot_id": executionEpoch.bootID', EXT)
        self.assertNotIn('Some("扩展独立心跳在线")', DAEMON)
        self.assertIn('extension_receipt_pending_or_invalid', ENFORCER)
        self.assertIn("record_activation_failure", DAEMON)

    def test_revoke_requires_final_receipt_and_exact_identity(self):
        method = CORE.split("pub fn is_confirmed_revoked", 1)[1].split(
            "pub fn matches_supervision", 1
        )[0]
        self.assertIn('self.status == "revoked"', method)
        self.assertIn('self.permit_state == "revoked"', method)
        self.assertIn('self.new_connections_blocked', method)
        self.assertIn("self.command_seq == expected_command_seq", CORE)
        self.assertIn("self.permit_generation == expected_generation", CORE)
        self.assertIn('families[family]?.status = "failed"', EXT)

    def test_failed_start_cannot_report_interception_active(self):
        start = EXT.split('open override func startProxy', 1)[1].split('private func startControlTimers', 1)[0]
        self.assertLess(start.index('if let error = error { completionHandler(error); return }'),
                        start.index('self.isInterceptionActive = true'))


if __name__ == "__main__":
    unittest.main()
