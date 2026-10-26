"""Adversarial contract tests for the vendored upstream account staging adapter."""
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Resources"))

from watch_switcher.common import DEFAULT_CONFIG, Paths, SwitcherError, atomic_json, read_json
from watch_switcher.accounts import AccountStore, tree_manifest, write_account_manifest
from watch_switcher.upstream_accounts import PINNED_SHA256, UpstreamAccountAdapter


VENDOR = Path(__file__).resolve().parents[1] / "ThirdParty/ClaudeSwitcher/upstream/core/claude-switch.sh"


class UpstreamAccountContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cw-upstream-")
        self.addCleanup(self.temp.cleanup)
        home = Path(self.temp.name) / "home"; home.mkdir()
        self.paths = Paths(home); self.paths.initialize()
        self.paths.active.mkdir(parents=True)
        (self.paths.active / "Cookie-fixture.txt").write_text("real-active")
        atomic_json(self.paths.state, {"schema": 1, "current": "A"})
        stored = self.paths.accounts / "A/profile"; stored.mkdir(parents=True)
        (stored / "Cookie-fixture.txt").write_text("old-A")
        write_account_manifest(stored.parent / "manifest.json", {"schema": 1, "files": tree_manifest(stored)})

    def adapter(self):
        self.assertEqual(hashlib.sha256(VENDOR.read_bytes()).hexdigest(), PINNED_SHA256)
        return UpstreamAccountAdapter(self.paths, VENDOR)

    def assert_real_untouched(self):
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "real-active")
        self.assertEqual((self.paths.accounts / "A/profile/Cookie-fixture.txt").read_text(), "old-A")
        self.assertEqual(self.paths.state.read_text(), '{"current": "A", "schema": 1}\n')

    def test_vendor_runs_only_in_private_stage_without_real_open_or_quit(self):
        result = self.adapter().run("A")
        self.assertTrue(result.workspace.is_dir())
        self.assertTrue(result.data.is_dir())
        self.assertTrue(result.launch_requested)
        self.assertEqual((result.data / "Cookie-fixture.txt").read_text(), "real-active")
        self.assert_real_untouched()

    def test_extracted_source_is_account_only_before_any_vendor_execution(self):
        observed = {}
        def fake_run(argv, **_kwargs):
            source = Path(argv[2]).read_text()
            observed["source"] = source
            return subprocess.CompletedProcess(argv, 1, "fixture stop")
        with patch("watch_switcher.upstream_accounts.subprocess.run", side_effect=fake_run):
            with self.assertRaises(SwitcherError):
                self.adapter().run("A")
        source = observed["source"]
        self.assertTrue(source.lstrip().startswith("status()"))
        self.assertIn("switch_to()", source)
        self.assertNotIn('BASE="$HOME/.claude-switcher"', source)
        self.assertNotIn('mkdir -p "$BASE/accounts"', source)
        self.assertNotIn('case "${1:-}"', source)
        self.assert_real_untouched()

    def test_tampered_vendor_is_rejected_before_stage_or_real_data_mutation(self):
        tampered = (Path(self.temp.name) / "tampered.sh").resolve()
        tampered.write_bytes(VENDOR.read_bytes() + b"\n# changed\n")
        with self.assertRaises(SwitcherError) as raised:
            UpstreamAccountAdapter(self.paths, tampered).run("A")
        self.assertEqual(raised.exception.code, "upstream_hash_invalid")
        self.assert_real_untouched()
        self.assertEqual(list(self.paths.base.glob("claude-upstream-*")), [])

    def test_stage_copy_failure_is_normalized_and_does_not_touch_real_data(self):
        with patch("watch_switcher.upstream_accounts.shutil.copytree", side_effect=OSError("fixture copy failed")):
            with self.assertRaises(SwitcherError) as raised:
                self.adapter().run("A")
        self.assertEqual(raised.exception.code, "upstream_run_failed")
        self.assert_real_untouched()

    def test_missing_or_empty_stage_output_is_rejected(self):
        completed = subprocess.CompletedProcess(["/bin/bash"], 0, "")
        with patch("watch_switcher.upstream_accounts.subprocess.run", return_value=completed):
            with self.assertRaises(SwitcherError) as raised:
                self.adapter().run("B")
        self.assertEqual(raised.exception.code, "upstream_output_invalid")
        self.assert_real_untouched()

    def test_vendor_timeout_or_interrupted_stage_never_publishes_to_active(self):
        with patch("watch_switcher.upstream_accounts.subprocess.run", side_effect=subprocess.TimeoutExpired("bash", 30)):
            with self.assertRaises(SwitcherError) as raised:
                self.adapter().run("B")
        self.assertEqual(raised.exception.code, "upstream_run_failed")
        self.assert_real_untouched()

    def test_empty_a_is_reported_as_not_saved_not_as_a_real_profile(self):
        shutil.rmtree(self.paths.accounts / "A")
        shutil.rmtree(self.paths.active)
        self.paths.active.mkdir()
        result = self.adapter().run("A")
        self.assertFalse(any(result.accounts.glob("A/**/Cookie-fixture.txt")))
        self.assertFalse((self.paths.accounts / "A").exists())
        self.assertFalse((self.paths.active / "Cookie-fixture.txt").exists())

    def store(self, checkpoint=None):
        class System:
            def __init__(self): self.quit_calls = 0; self.launch_calls = 0
            def claude_running(self): return False
            def claude_version(self): return "fixture"
            def quit_claude(self): self.quit_calls += 1
            def launch_claude(self): self.launch_calls += 1
        return AccountStore(self.paths, System(), lambda: None, checkpoint=checkpoint)

    def switch_config(self): return dict(DEFAULT_CONFIG, verified_claude_versions=["fixture"])

    def test_publish_interruption_recovers_original_active_and_slot(self):
        class Crash(BaseException): pass
        store = self.store(checkpoint=lambda stage: (_ for _ in ()).throw(Crash()) if stage == "old_moved" else None)
        with self.assertRaises(Crash): store.switch("B", self.switch_config())
        self.assertTrue(self.paths.journal.exists())
        self.assertEqual(store.recover()["status"], "ok")
        self.assert_real_untouched()
        self.assertFalse(self.paths.journal.exists())

    def test_recovery_never_overwrites_an_external_post_interrupt_change(self):
        class Crash(BaseException): pass
        store = self.store(checkpoint=lambda stage: (_ for _ in ()).throw(Crash()) if stage == "old_moved" else None)
        with self.assertRaises(Crash): store.switch("B", self.switch_config())
        active = self.paths.active; active.mkdir(parents=True, exist_ok=True)
        (active / "external.txt").write_text("do-not-overwrite")
        with self.assertRaises(SwitcherError) as raised: store.recover()
        self.assertEqual(raised.exception.code, "recovery_conflict")
        self.assertEqual((active / "external.txt").read_text(), "do-not-overwrite")


if __name__ == "__main__":
    unittest.main()
