"""Behavioral tests of the coordinator; never invokes the actual project suite."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

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

    def isolated_repo(self):
        repo = self.root / "source"
        (repo / "crates").mkdir(parents=True)
        (repo / "crates/input.rs").write_text("original source")
        (repo / "target").mkdir()
        return repo

    def isolated_runner(self, repo, steps):
        return Runner(repo, self.output, steps, runner_module.clean_environment(dict(os.environ), repo, self.output))

    def test_source_receipt_reuses_build_algorithm_and_marks_mid_run_change(self):
        repo = self.isolated_repo()
        expected = runner_module._IDENTITY.snapshot(repo, None, None)
        runner = self.isolated_runner(repo, [Step("mutate", "test", [[sys.executable, "-c",
            "from pathlib import Path;Path('crates/input.rs').write_text('changed source')"]])])
        self.assertEqual(self.run_quiet(runner), 0)
        report = json.loads((self.output / "results.json").read_text())
        for key in runner_module.SOURCE_KEYS:
            self.assertEqual(report["source_identity"]["before"][key], expected[key])
        self.assertIsNone(report["source_identity"]["before"]["app_build"])
        self.assertIsNone(report["source_identity"]["before"]["source_revision"])
        self.assertTrue(report["source_identity"]["changed_during_run"])
        self.assertEqual(report["evidence_binding"], "unstable")
        self.assertEqual(report["outcome"], "passed", "source changes must not rewrite actual test results")

    def test_declared_component_changes_are_unstable_for_tests_but_expected_for_builds(self):
        for category, binding in (("test", "unstable"), ("build", "before_after_match")):
            with self.subTest(category=category), tempfile.TemporaryDirectory(dir=self.root) as temp:
                repo = Path(temp)
                (repo / "crates").mkdir()
                component = repo / "component"
                component.write_text("before")
                output = repo / "results"
                runner = Runner(repo, output, [Step("change", category, [[sys.executable, "-c",
                    "from pathlib import Path;Path('component').write_text('after')"]], artifacts=[str(component)])], dict(os.environ))
                self.assertEqual(self.run_quiet(runner), 0)
                report = json.loads((output / "results.json").read_text())
                self.assertFalse(report["source_identity"]["changed_during_run"])
                self.assertEqual(report["evidence_binding"], binding)

    def test_executed_file_replacement_is_detected_even_when_source_is_unchanged(self):
        repo = self.isolated_repo()
        executable = repo / "target/self-replacing"
        executable.write_text(f"#!{sys.executable}\nfrom pathlib import Path\nPath(__file__).write_text('replaced')\n")
        executable.chmod(0o700)
        runner = self.isolated_runner(repo, [Step("execute", "test", [[str(executable)]])])
        self.assertEqual(self.run_quiet(runner), 0)
        report = json.loads((self.output / "results.json").read_text())
        evidence = report["steps"][0]["command_results"][0]
        self.assertTrue(evidence["program_changed_during_command"])
        self.assertNotEqual(evidence["program_before"]["sha256"], evidence["program_after"]["sha256"])
        self.assertFalse(report["source_identity"]["changed_during_run"])
        self.assertEqual(report["evidence_binding"], "unstable")

    def test_old_product_receipt_and_runtime_hashes_are_not_rebound_to_run_source(self):
        repo = self.isolated_repo()
        runtime = repo / "target/runtime"
        runtime.mkdir()
        engine = runtime / "watch-engine"
        engine.write_bytes(b"old candidate bytes")
        (runtime / "BuildIdentity.json").write_text(json.dumps({"schema": 1, "app_build": "404",
            "app_version": "4.0.0", "source_revision": "old", "source_dirty": True, "source_tree_digest": "0" * 64}))
        (runtime / "BuildInfo.plist").write_bytes(plistlib.dumps({"RuntimeHashes": {
            "watch-engine": hashlib.sha256(engine.read_bytes()).hexdigest(), "../outside": "0" * 64}}))
        runner = self.isolated_runner(repo, [Step("fixture", "test", [[sys.executable, "-c", "pass"]], artifacts=[str(engine)])])
        self.assertEqual(self.run_quiet(runner), 0)
        artifact = runner.results[0]["declared_artifacts_after"][0]
        self.assertEqual(artifact["product_build_identity"]["identity"]["app_build"], "404")
        self.assertFalse(artifact["product_build_identity"]["matches_run_source"])
        checks = {Path(item["path"]).name: item for item in artifact["runtime_hashes"]["files"]}
        self.assertTrue(checks["watch-engine"]["matches_manifest"])
        self.assertEqual(checks["outside"]["state"], "outside_manifest_directory")

    def test_typecheck_has_no_product_or_compiler_output_and_source_errors_are_explicit(self):
        repo = self.isolated_repo()
        runner = self.isolated_runner(repo, [Step("typecheck", "build", [[sys.executable, "-c", "pass", "swiftc", "-typecheck"]])])
        with mock.patch.object(runner_module, "source_identity", return_value={"error": "source unavailable"}):
            self.assertEqual(self.run_quiet(runner), 0)
        report = json.loads((self.output / "results.json").read_text())
        self.assertEqual(report["evidence_binding"], "unavailable")
        self.assertIsNone(report["source_identity"]["changed_during_run"])
        self.assertEqual(report["steps"][0]["command_results"][0]["artifacts"], [])
        self.assertEqual(report["steps"][0]["declared_artifacts_after"], [])

    def test_cargo_reports_known_test_executable_and_native_component_paths(self):
        repo = self.isolated_repo()
        test_binary, helper = repo / "target/test executable", repo / "target/watch-process-control"
        test_binary.write_bytes(b"fixture test program")
        helper.write_bytes(b"fixture native component")
        records = [json.dumps({"reason": "compiler-artifact", "executable": str(test_binary),
                              "target": {"name": "fixture"}, "profile": {"test": True}, "fresh": False}),
                   json.dumps({"reason": "build-script-executed", "env": [["CW_PROCESS_CONTROL_BUILD_PATH", str(helper)]]}),
                   f"     Running tests/fixture.rs ({test_binary})"]
        cargo = repo / "target/cargo"
        cargo.write_text(f"#!{sys.executable}\nprint({chr(10).join(records)!r})\n")
        cargo.chmod(0o700)
        runner = self.isolated_runner(repo, [Step("cargo-fixture", "test", [[str(cargo), "test", "--message-format=json"]])])
        self.assertEqual(self.run_quiet(runner), 0)
        artifacts = runner.results[0]["command_results"][0]["artifacts"]
        self.assertEqual(len(artifacts), 2)
        self.assertTrue(artifacts[0]["invocation_observed"])
        self.assertEqual(artifacts[0]["sha256"], hashlib.sha256(test_binary.read_bytes()).hexdigest())
        self.assertEqual(artifacts[1]["component_key"], "CW_PROCESS_CONTROL_BUILD_PATH")
        self.assertEqual(artifacts[1]["sha256"], hashlib.sha256(helper.read_bytes()).hexdigest())
        self.assertTrue(all(item["product_build_identity"] is None for item in artifacts))

    def test_fixture_log_cannot_claim_cargo_binary_provenance(self):
        repo = self.isolated_repo()
        target = repo / "target/pretend-test"
        target.write_bytes(b"not executed")
        record = json.dumps({"reason": "compiler-artifact", "executable": str(target),
                             "target": {"name": "fake"}, "profile": {"test": True}})
        runner = self.isolated_runner(repo, [Step("fixture-log", "test", [[sys.executable, "-c", f"print({record!r})"]])])
        self.assertEqual(self.run_quiet(runner), 0)
        self.assertEqual(runner.results[0]["command_results"][0]["artifacts"], [])

    def test_explicit_candidate_component_query_records_only_returned_component_paths(self):
        repo = self.isolated_repo()
        helper = repo / "target/watch-process-control"
        helper.write_bytes(b"actual candidate helper")
        engine = repo / "target/claude-watch-engine"
        engine.write_text(f"#!{sys.executable}\nprint({json.dumps({'process_control': str(helper)})!r})\n")
        engine.chmod(0o700)
        runner = self.isolated_runner(repo, [Step("components", "prerequisite", [[str(engine), "--component-paths"]])])
        self.assertEqual(self.run_quiet(runner), 0)
        artifacts = runner.results[0]["command_results"][0]["artifacts"]
        self.assertEqual([(item["component_key"], item["path"]) for item in artifacts], [("process_control", str(helper))])
        self.assertEqual(artifacts[0]["sha256"], hashlib.sha256(helper.read_bytes()).hexdigest())

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

    def mechanism_runner(self, missing_last=False):
        steps, _ = runner_module.build_plan(self.output)
        fixture = next(s for s in steps if s.id == "rust.mechanism_review_fixtures")
        marker = self.root / "decoder-ran"
        runner = self.runner([
            Step("rust.workspace", "test", [[sys.executable, "-c", "raise SystemExit(9)"]]),
            fixture,
            Step("decoder", "test", [[sys.executable, "-c", f"from pathlib import Path;Path({str(marker)!r}).touch()"]],
                 dependencies=[fixture.id]),
        ])
        # Simulate receipts emitted by successful cases before an unrelated
        # workspace target failed. The decoder still validates their content.
        actions = fixture.prepare[:-1] if missing_last else fixture.prepare
        for action in actions:
            path = Path(action["path"])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}")
        return runner, marker

    def test_complete_mechanism_receipts_run_decoder_without_hiding_workspace_failure(self):
        runner, marker = self.mechanism_runner()
        self.assertEqual(self.run_quiet(runner), 1)
        self.assertEqual([r["status"] for r in runner.results], ["failed", "passed", "passed"])
        self.assertEqual(runner.results[0]["exit_code"], 9)
        self.assertTrue(marker.is_file())
        self.assertEqual(json.loads((self.output / "results.json").read_text())["outcome"], "failed")

    def test_incomplete_mechanism_receipts_still_block_decoder_after_workspace_failure(self):
        runner, marker = self.mechanism_runner(missing_last=True)
        self.assertEqual(self.run_quiet(runner), 1)
        self.assertEqual([r["status"] for r in runner.results], ["failed", "blocked", "blocked"])
        self.assertFalse(marker.exists())

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
