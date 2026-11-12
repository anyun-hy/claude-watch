"""Structural no-signal guard/UI consistency checks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTROLLED = (ROOT / "crates/watch-runtime/src/controlled.rs").read_text(encoding="utf-8")
SUPERVISOR = (ROOT / "crates/watch-runtime/src/channel_supervisor.rs").read_text(encoding="utf-8")
DISPOSITION = (ROOT / "crates/watch-runtime/src/process_disposition.rs").read_text(encoding="utf-8")
PROJECTION = (ROOT / "crates/watch-runtime/src/channel_policy_status.rs").read_text(encoding="utf-8")
PROTECTION = (ROOT / "monitor/Sources/SessionProtectionPresentation.swift").read_text(encoding="utf-8")
BASELINE = (ROOT / "monitor/Sources/SessionBaselinePresentation.swift").read_text(encoding="utf-8")
STORE = (ROOT / "monitor/Sources/SwitcherStore.swift").read_text(encoding="utf-8")


class GuardStopConsolidation(unittest.TestCase):
    def test_controller_cannot_issue_process_or_channel_effects(self):
        for retired in ["finish_current_stop", "quit_desktop", "terminate_supervised_processes", "enforce_channel"]:
            self.assertNotIn(retired, CONTROLLED)
        self.assertIn("fn update_process_intent(", SUPERVISOR)
        self.assertIn("dispatcher.submit(job)", SUPERVISOR)

    def test_actual_results_have_a_single_dispatcher_and_ingestion_path(self):
        self.assertIn("ProcessReceiptArrived", SUPERVISOR)
        self.assertIn("pub fn ingest_process_receipt(", SUPERVISOR)
        self.assertIn("claude_watch_system::bound_lifetime_exited", DISPOSITION)
        self.assertIn('"partially_terminated"', DISPOSITION)
        self.assertIn('"already_exited"', DISPOSITION)

    def test_network_isolation_does_not_manufacture_a_process_exit(self):
        self.assertIn('state["process_execution_state"]', PROJECTION)
        self.assertIn('state["process_preserved"] == false', PROJECTION)
        self.assertIn('Some("confirmed" | "already_exited")', PROJECTION)
        self.assertIn('ChannelSupervisionVerdict::PendingIsolation', PROJECTION)
        self.assertNotIn('last-guard-stop.json', CONTROLLED)

    def test_ui_missing_receipt_and_read_failure_have_same_verdict(self):
        self.assertIn("static func unavailable(error: String)", PROTECTION)
        self.assertIn('SessionProtectionPresentation.unavailable(error: error)', BASELINE)
        self.assertIn('?? .unavailable(error: backgroundError)', STORE)
        self.assertIn('symbol: "exclamationmark.triangle", tone: "warning"', PROTECTION)


if __name__ == "__main__":
    unittest.main()
