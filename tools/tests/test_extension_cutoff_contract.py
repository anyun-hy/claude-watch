"""Guard against false positive channel cut-off and stale command acceptance.

Static contract tests only; not evidence of actual NetworkExtension interception.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "monitor/SystemExtension/WatchChannelExtension.swift").read_text()


class ChannelCutoffContracts(unittest.TestCase):
    def test_drain_timeout_is_not_confirmed(self):
        self.assertIn('status: "drain_timeout_unconfirmed"', SOURCE)
        self.assertNotIn('drain_timeout_forced', SOURCE)
        self.assertNotIn('|| checks >= 30 {', SOURCE)
        self.assertIn('record.connection.state == .cancelled', SOURCE)
        self.assertIn('record.connection.state == .disconnected', SOURCE)

    def test_extension_stop_and_sleep_do_not_claim_revocation(self):
        self.assertIn('status: "stopped_unverified"', SOURCE)
        self.assertIn('status: "suspended_unverified"', SOURCE)
        self.assertIn('status: "wake_unverified"', SOURCE)
        self.assertNotIn('activeFlows.removeAll()', SOURCE)

    def test_command_sequence_and_generation_cannot_move_backwards(self):
        self.assertIn(
            'cmdSeq > currentCommandSeq && permitGen >= currentPermitGeneration',
            SOURCE,
        )
        self.assertGreaterEqual(
            SOURCE.count('isCommandNewerLocked(permitGen: incomingGen, cmdSeq: incomingSeq)'),
            2,
        )


if __name__ == "__main__":
    unittest.main()
