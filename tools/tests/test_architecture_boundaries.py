"""No-execution architecture contracts for the bounded R04/C05 refactor."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONTROLLED = (ROOT / "crates/watch-runtime/src/controlled.rs").read_text(encoding="utf-8")
LAUNCH = (ROOT / "crates/watch-runtime/src/controlled/launch.rs").read_text(encoding="utf-8")
FAILURE = (ROOT / "crates/watch-runtime/src/controlled/sampling_failure.rs").read_text(encoding="utf-8")
MONITOR = (ROOT / "monitor/Sources/MonitorStore.swift").read_text(encoding="utf-8")
SNAPSHOT = (ROOT / "monitor/Sources/MonitorSnapshotReader.swift").read_text(encoding="utf-8")
CONTEXT = (ROOT / "monitor/Sources/DiagnosticContextTracker.swift").read_text(encoding="utf-8")
PAGE = (ROOT / "monitor/Sources/MonitorPage.swift").read_text(encoding="utf-8")
PROCESS = (ROOT / "monitor/Sources/AIProcessControl.swift").read_text(encoding="utf-8")
HELPER = (ROOT / "monitor/tools/ProcessHelper.swift").read_text(encoding="utf-8")


class ArchitectureBoundaries(unittest.TestCase):
    def test_guard_controller_keeps_family_coordination_not_launch_effects(self):
        self.assertIn("mod launch;", CONTROLLED)
        self.assertIn("mod sampling_failure;", CONTROLLED)
        self.assertIn("pub fn guard_tick<S: DesktopSystem>", CONTROLLED)
        self.assertNotIn("fn record_launch(", CONTROLLED)
        self.assertNotIn("pub fn launch_cli", CONTROLLED)
        self.assertNotIn("fn sampling_failure", CONTROLLED)

    def test_launch_lifecycle_has_a_single_authoritative_implementation(self):
        for key in ["pub fn launch<", "pub fn launch_cli", "fn observation_audit<",
                    "pub(crate) fn lease("]:
            self.assertIn(key, LAUNCH)
        self.assertIn('self.finish_current_stop(', CONTROLLED)
        self.assertIn("pub(super) fn sampling_failure<", FAILURE)

    def test_monitor_presentation_is_not_its_snapshot_reader(self):
        self.assertIn("final class MonitorStore: ObservableObject", MONITOR)
        self.assertNotIn("enum SnapshotRunner", MONITOR)
        self.assertNotIn("enum Page:", MONITOR)
        self.assertNotIn("struct DiagnosticContextTracker", MONITOR)
        self.assertIn("enum SnapshotRunner", SNAPSHOT)
        self.assertIn("struct DiagnosticContextTracker", CONTEXT)
        self.assertIn("func tagReceiptContext(", CONTEXT)
        self.assertIn("enum Page: String, CaseIterable", PAGE)

    def test_process_policy_passes_bound_identity_not_bare_pid_to_effect(self):
        self.assertIn("quitApplication: (AIProcessIdentity) -> Bool", PROCESS)
        self.assertIn("force: (AIProcessIdentity) -> Bool", PROCESS)
        self.assertIn("if force(target)", PROCESS)
        self.assertIn("quitApplication(target) : terminate(target)", PROCESS)
        self.assertIn("static func applyToMatchingIdentity(", PROCESS)

    def test_all_production_signal_callbacks_revalidate_at_effect_boundary(self):
        self.assertEqual(HELPER.count("AIProcessClosePolicy.applyToMatchingIdentity("), 3)
        self.assertEqual(PROCESS.count("AIProcessClosePolicy.applyToMatchingIdentity("), 2)
        self.assertIn("Darwin.kill($0, SIGTERM)", PROCESS)
        self.assertIn("Darwin.kill($0, SIGTERM)", HELPER)
        self.assertIn("Darwin.kill($0, SIGKILL)", HELPER)
        self.assertIn("No macOS PID-based signal is an atomic", PROCESS)


if __name__ == "__main__":
    unittest.main()
