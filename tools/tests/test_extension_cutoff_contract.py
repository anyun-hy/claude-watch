"""Guard against false positive channel cut-off and stale command acceptance.

Static contract tests only; not evidence of actual NetworkExtension interception.
"""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "monitor/SystemExtension/WatchChannelExtension.swift").read_text()
CONTRACT = (ROOT / "monitor/SystemExtension/ChannelContract.swift").read_text()
TRANSPORT = (ROOT / "monitor/SystemExtension/ChannelTransport.swift").read_text()


class ChannelCutoffContracts(unittest.TestCase):
    def test_drain_timeout_is_not_confirmed(self):
        self.assertIn('families[family]?.status = "failed"', SOURCE)
        self.assertIn('channelDrainStatus(remaining: remaining', SOURCE)
        self.assertNotIn('drain_timeout_forced', SOURCE)
        self.assertNotIn('|| checks >= 30 {', SOURCE)
        self.assertIn('if record.connection.cancel() { activeFlows.removeValue(forKey: id) }', SOURCE)
        self.assertIn('shutdown(descriptor, SHUT_RDWR)', TRANSPORT)
        self.assertIn('stopped && closed ? .cancelled : .failed', TRANSPORT)

    def test_extension_stop_and_sleep_do_not_claim_revocation(self):
        stopped = SOURCE.split('open override func stopProxy', 1)[1].split('private func revokeAllLocked', 1)[0]
        self.assertIn('isInterceptionActive = false', stopped)
        self.assertIn('emitHeartbeat()', stopped)
        self.assertIn('revokeAllLocked(reason: "system_sleep")', SOURCE)
        self.assertIn('terminateFlowsLocked(family: nil)', SOURCE)
        self.assertNotIn('activeFlows.removeAll()', SOURCE)

    def test_command_sequence_and_generation_cannot_move_backwards(self):
        self.assertIn(
            'generation >= previousGeneration && sequence > previousSequence',
            CONTRACT,
        )
        self.assertIn('channelCommandAdvances(generation: command.permit_generation', SOURCE)
        self.assertIn('Conflicting command sequence', SOURCE)


if __name__ == "__main__":
    unittest.main()
