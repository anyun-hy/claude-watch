"""Check the provider's removal path uses actual per-family close results before publication."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "monitor/SystemExtension/WatchChannelExtension.swift").read_text()


class RemovedFamilyReceiptContract(unittest.TestCase):
    def test_removed_family_updates_execution_state_before_publishing(self):
        application = SOURCE.split("private func applyCommands(", 1)[1].split("private func writeReceiptsLocked", 1)[0]
        removal = application.split("for family in families.keys.filter({ !present.contains($0) })", 1)[1]
        self.assertLess(removal.index("permitted = false"), removal.index("terminateFlowsLocked(family: family)"))
        self.assertLess(removal.index("terminateFlowsLocked(family: family)"), removal.index("let remaining = activeFlows.values.filter"))
        self.assertIn("$0.family == family", removal)
        self.assertIn("$0.connection.state == .failed", removal)
        self.assertIn("previouslyStarted: families[family]?.closingSince", removal)
        self.assertNotIn("closingSince = now", removal)
        for assignment in ["status = update.status", "closingSince = update.closingSince", "appliedAt = update.appliedAt"]:
            self.assertLess(removal.index(assignment), removal.index("writeReceiptsLocked()"))
        self.assertIn('"flow_close_failed"', removal)
        self.assertIn('"drain_timeout"', removal)
        self.assertNotIn("activeFlows.removeAll()", removal)


if __name__ == "__main__":
    unittest.main()
