"""Behavioral tests of the coordinator; never invokes the actual project suite."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("cw_unified_runner", ROOT / "tools/run_all_tests.py")
runner_module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner_module
SPEC.loader.exec_module(runner_module)
Step, Runner = runner_module.Step, runner_module.Runner


class UnifiedRunnerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="cw-runner-selftest-")
        self.root = Path(self.directory.name)
        self.output = self.root / 'results "with quotes"'

    def tearDown(self):
        self.directory.cleanup()

    def runner(self, steps):
        env = runner_module.clean_environment(dict(os.environ), ROOT, self.output)
        return Runner(ROOT, self.output, steps, env)

    def run_quiet(self, runner):
        with contextlib.redirect_stdout(io.StringIO()):
            return runner.run()

    def test_failure_is_preserved_independent_steps_continue_and_dependencies_block(self):
        runner = self.runner([
            Step("bad", "test", [[sys.executable, "-c", "print('actual failure');print('test host ... ignored, needs host');raise SystemExit(7)"]]),
            Step("dependent", "test", [["must-not-execute"]], dependencies=["bad"]),
            Step("independent", "test", [[sys.executable, "-c", "print('completed')"]]),
            Step("live", "excluded", [["must-not-execute"]], excluded_reason="real network excluded"),
        ])
        self.assertEqual(self.run_quiet(runner), 1)
        report = json.loads((self.output / "results.json").read_text())
        self.assertEqual([r["status"] for r in report["steps"]], ["failed", "blocked", "passed", "excluded"])
        self.assertEqual(report["steps"][0]["exit_code"], 7)
        self.assertEqual(report["outcome"], "failed")
        self.assertEqual(report["steps"][0]["coverage_notes"], ["test host ... ignored, needs host"])
        self.assertIn("actual failure", (self.output / "logs/bad.log").read_text())
        self.assertIn("independent", (self.output / "SUMMARY.md").read_text())

    def test_zero_exit_cannot_hide_failure_or_missing_native_completion(self):
        runner = self.runner([
            Step("fake_green", "test", [[sys.executable, "-c", "import sys;print('FAIL: assertion',file=sys.stderr)"]],
                 failure_patterns=[r"(?m)^FAIL:"]),
            Step("only_launched", "test", [[sys.executable, "-c", "print('app launch succeeded')"]],
                 success_markers=["all assertions passed"]),
        ])
        self.assertEqual(self.run_quiet(runner), 1)
        self.assertTrue(all(r["status"] == "failed" for r in runner.results))

    def test_timeout_cleans_owned_group_even_after_leader_exits(self):
        marker = self.root / "must-not-be-written"
        child = f"import time;from pathlib import Path;time.sleep(1);Path({str(marker)!r}).write_text('leaked')"
        parent = f"import subprocess,sys;subprocess.Popen([sys.executable,'-c',{child!r}]);print('owned child ready',flush=True)"
        runner = self.runner([Step("timeout", "test", [[sys.executable, "-c", parent]], timeout_seconds=0.2)])
        self.assertEqual(self.run_quiet(runner), 1)
        self.assertEqual(runner.results[0]["reason"], "command timed out")
        time.sleep(1.1)
        self.assertFalse(marker.exists(), "owned descendant survived cancellation and wrote after its deadline")

    def test_interruption_saves_summary_and_never_starts_later_steps(self):
        marker = self.root / "later"
        runner = self.runner([
            Step("active", "test", [[sys.executable, "-c", "import time;time.sleep(10)"]]),
            Step("later", "test", [[sys.executable, "-c", f"from pathlib import Path;Path({str(marker)!r}).touch()"]]),
        ])
        timer = threading.Timer(0.15, lambda: setattr(runner, "cancelled", True))
        timer.start()
        try:
            self.assertEqual(self.run_quiet(runner), 130)
        finally:
            timer.join()
        self.assertEqual([r["status"] for r in runner.results], ["interrupted", "not_run"])
        self.assertFalse(marker.exists())
        self.assertEqual(json.loads((self.output / "results.json").read_text())["outcome"], "interrupted")

    def test_missing_fixture_blocks_only_the_dependent_step(self):
        runner = self.runner([
            Step("fixture", "prerequisite", prepare=[{"kind": "require_file", "path": str(self.root / "absent")}]),
            Step("other", "test", [[sys.executable, "-c", "pass"]]),
        ])
        self.assertEqual(self.run_quiet(runner), 1)
        self.assertEqual([r["status"] for r in runner.results], ["blocked", "passed"])

    def test_new_run_never_overwrites_existing_results(self):
        self.output.mkdir()
        marker = self.output / "prior.json"
        marker.write_text("preserve")
        with self.assertRaises(FileExistsError):
            self.runner([])
        self.assertEqual(marker.read_text(), "preserve")

    def test_child_mode_environment_is_removed_without_replacing_home(self):
        original = {"HOME": "/original-user", "PATH": "/bin", "CW_FAULT_ROLE": "child",
                    "CW_TEST_RESIDENT_LIVE": "1", "WATCH_NETWORK_SINGLEFLIGHT_CHILD": "1",
                    "LEAK_BRIDGE_APP": "/Applications/not-a-fixture.app"}
        env = runner_module.clean_environment(original, ROOT, self.output)
        self.assertEqual(env["HOME"], original["HOME"])
        for key in ("CW_FAULT_ROLE", "CW_TEST_RESIDENT_LIVE", "WATCH_NETWORK_SINGLEFLIGHT_CHILD", "LEAK_BRIDGE_APP"):
            self.assertNotIn(key, env)
        self.assertEqual(env["CARGO_TARGET_DIR"], str(ROOT / "target"))

    def test_inventory_covers_every_swift_test_and_keeps_live_entries_excluded(self):
        steps, coverage = runner_module.build_plan(self.output)
        self.assertFalse(coverage["missing"])
        self.assertFalse(coverage["duplicates"])
        self.assertEqual(coverage["swift_test_count"], coverage["swift_mapped_count"])
        self.assertTrue(next(s for s in steps if s.id == "swift.NetCoffeeLiveCheck").excluded_reason)
        fixture = next(s for s in steps if s.id == "swift.BackendReceiptDecodeTests")
        self.assertIn('results "with quotes"', fixture.prepare[0]["destination"])
        self.assertEqual(next(s for s in steps if s.id == "webkit.resident_runtime").commands[0][-1], "--fixture")
        self.assertIn("macos.gui_session", next(s for s in steps if s.id == "webkit.resident_runtime").dependencies)

    def test_long_output_path_does_not_lengthen_fixture_socket_paths(self):
        output = self.root / ("long-output-" * 15)
        short_tmp = self.root / "tmp"
        short_tmp.mkdir()
        runner = Runner(ROOT, output, [], dict(os.environ), fixture_tmp=short_tmp)
        self.assertEqual(runner.environment["TMPDIR"], str(short_tmp) + "/")
        self.assertEqual((output / "tmp").resolve(), short_tmp.resolve())
        # Exercise the actual local Unix socket length constraint.
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(short_tmp / "peer.sock"))


if __name__ == "__main__":
    unittest.main()
