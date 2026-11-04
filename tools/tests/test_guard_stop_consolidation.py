"""Structural no-signal guard/UI consistency checks."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTROLLED = (ROOT / "crates/watch-runtime/src/controlled.rs").read_text(encoding="utf-8")
DISPOSITION = (ROOT / "crates/watch-runtime/src/controlled/disposition.rs").read_text(encoding="utf-8")
PROTECTION = (ROOT / "monitor/Sources/SessionProtectionPresentation.swift").read_text(encoding="utf-8")
BASELINE = (ROOT / "monitor/Sources/SessionBaselinePresentation.swift").read_text(encoding="utf-8")
STORE = (ROOT / "monitor/Sources/SwitcherStore.swift").read_text(encoding="utf-8")


class GuardStopConsolidation(unittest.TestCase):
    def test_stop_result_is_handled_in_one_place(self):
        self.assertNotIn("match sessions.close_if_current(", CONTROLLED)
        self.assertEqual(DISPOSITION.count("pub(super) fn finish_current_stop"), 1)
        self.assertEqual(CONTROLLED.count("self.finish_current_stop("), 8)

    def test_last_guard_stop_is_persisted_only_on_confirmed_result(self):
        self.assertNotIn('last-guard-stop.json', CONTROLLED)
        self.assertEqual(DISPOSITION.count('last-guard-stop.json'), 1)
        confirmed = DISPOSITION.index("Ok(Some(StopOutcome::Confirmed))")
        persisted = DISPOSITION.index('last-guard-stop.json')
        self.assertLess(confirmed, persisted)
        self.assertIn('Ok(None) => receipt["stop_state"] = json!("session_changed")', DISPOSITION)
        self.assertIn('receipt["stop_error"] = json!(error.code)', DISPOSITION)

    def test_a_skipped_warning_cannot_be_mislabeled_as_success(self):
        self.assertIn('Ok(Some(StopOutcome::SkippedWarn)) => {}', DISPOSITION)
        self.assertIn('receipt["stop_state"] = json!("skipped_warn_only")', DISPOSITION)
        self.assertIn('receipt["action"] = json!("observe")', DISPOSITION)

    def test_ui_missing_receipt_and_read_failure_have_same_verdict(self):
        self.assertIn("static func unavailable(error: String)", PROTECTION)
        self.assertIn('SessionProtectionPresentation.unavailable(error: error)', BASELINE)
        self.assertIn('?? .unavailable(error: backgroundError)', STORE)
        self.assertIn('symbol: "exclamationmark.triangle", tone: "warning"', PROTECTION)


if __name__ == "__main__":
    unittest.main()
