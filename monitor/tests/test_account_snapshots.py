"""Synthetic profiles only; exercise COW fallback and every move-journal boundary."""
import ctypes
import errno
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch

from test_switcher import Fixture
from watch_switcher.accounts import AccountStore, tree_manifest, verified_copy
from watch_switcher.common import SwitcherError, atomic_json, read_json


class CloneTests(Fixture):
    def copy_profile(self, **kwargs):
        self.active("original data")
        target = self.paths.home / "copy"
        metrics = {}
        value = verified_copy(self.paths.active, target, metrics=metrics, **kwargs)
        return target, metrics, value

    def test_forced_regular_copy_keeps_private_permissions_and_hashes(self):
        with patch.dict(os.environ, {"CLAUDE_WATCH_NO_CLONE": "1"}):
            target, metrics, value = self.copy_profile()
        self.assertEqual(metrics["strategy"], "copy")
        self.assertEqual(value, tree_manifest(target))
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertEqual((target / "Cookie-fixture.txt").stat().st_mode & 0o777, 0o600)
        self.assertNotEqual((target / "Cookie-fixture.txt").stat().st_ino,
                            (self.paths.active / "Cookie-fixture.txt").stat().st_ino)

    def test_unsupported_clone_discards_partial_file_and_falls_back(self):
        def unsupported(source, target, flags):
            Path(os.fsdecode(target)).write_text("incomplete")
            ctypes.set_errno(errno.ENOTSUP)
            return -1
        with patch("watch_switcher.accounts.clone_function", return_value=unsupported):
            target, metrics, _ = self.copy_profile()
        self.assertEqual((target / "Cookie-fixture.txt").read_text(), "original data")
        self.assertEqual(metrics["copied_files"], 1)

    def test_clone_disk_error_does_not_fall_back_or_touch_original(self):
        def failed(source, target, flags): ctypes.set_errno(errno.ENOSPC); return -1
        with patch("watch_switcher.accounts.clone_function", return_value=failed), \
                patch("watch_switcher.accounts.shutil.copy2", side_effect=AssertionError("must not retry disk-full copy")):
            with self.assertRaises(shutil.Error): self.copy_profile()
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "original data")

    def test_source_changes_during_clone_are_detected(self):
        def changed(source, target, flags):
            shutil.copyfile(source, target)
            Path(os.fsdecode(source)).write_text("source changed")
            return 0
        with patch("watch_switcher.accounts.clone_function", return_value=changed):
            with self.assertRaises(SwitcherError): self.copy_profile()

    @unittest.skipUnless(sys.platform == "darwin", "native APFS clone is macOS-only")
    def test_real_clone_is_independent_after_writes(self):
        with patch.dict(os.environ, {"CLAUDE_WATCH_NO_CLONE": "0", "CLAUDE_SWITCHER_NO_CLONE": "0"}):
            target, metrics, _ = self.copy_profile()
        if metrics["cloned_files"] == 0: self.skipTest("fixture volume does not support clonefile")
        (target / "Cookie-fixture.txt").write_text("clone changed")
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "original data")
        (self.paths.active / "Cookie-fixture.txt").write_text("source changed")
        self.assertEqual((target / "Cookie-fixture.txt").read_text(), "clone changed")


class MoveArchiveTests(Fixture):
    def seed(self):
        self.paths.initialize()
        self.active("live A")
        for account, contents in (("A", "old stored A"), ("B", "stored B")):
            profile = self.paths.accounts / account / "profile"
            profile.mkdir(parents=True)
            (profile / "Cookie-fixture.txt").write_text(contents)
            atomic_json(profile.parent / "manifest.json", {"schema": 1, "files": tree_manifest(profile)})
        atomic_json(self.paths.state, {"schema": 1, "current": "A"})

    def test_upstream_stage_publishes_independent_live_and_stored_profiles(self):
        self.seed()
        result = self.store().switch("B", self.config)
        self.assertEqual(result["archive_method"], "upstream-stage")
        self.assertGreaterEqual(result["elapsed_seconds"], 0)
        (self.paths.active / "Cookie-fixture.txt").write_text("changed B")
        self.assertEqual((self.paths.accounts / "B/profile/Cookie-fixture.txt").read_text(), "stored B")
        self.assertEqual((self.paths.accounts / "A/profile/Cookie-fixture.txt").read_text(), "live A")
        self.assertFalse(list(self.paths.accounts.glob(".A.*")))

    def test_prior_snapshot_is_preserved_until_schema3_publish_commit(self):
        self.seed()
        observed = []
        def checkpoint(stage):
            if stage == "committed":
                journal = read_json(self.paths.journal)
                previous = next(r for r in journal["records"] if r["key"] == "A")
                observed.append((Path(previous["old"]) / "profile/Cookie-fixture.txt").read_text())
        self.store(checkpoint=checkpoint).switch("B", self.config)
        self.assertEqual(observed, ["old stored A"])

    def test_crash_before_or_after_each_rename_restores_live_and_stored_data(self):
        class Crash(BaseException): pass
        for point in ("prepared", "previous_snapshot_moved", "snapshot_committed", "old_moved", "installed", "committed"):
            with self.subTest(point=point):
                shutil.rmtree(self.paths.home); self.paths.home.mkdir(); self.system.running = False
                self.seed()
                def checkpoint(stage):
                    if stage == point: raise Crash()
                with self.assertRaises(Crash): self.store(checkpoint=checkpoint).switch("B", self.config)
                self.system.running = False
                self.store().recover()
                self.assertFalse(self.paths.journal.exists())
                self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(),
                                 "stored B" if point == "committed" else "live A")
                self.assertEqual((self.paths.accounts / "A/profile/Cookie-fixture.txt").read_text(),
                                 "live A" if point == "committed" else "old stored A")
                self.assertEqual(self.store().state()["current"], "B" if point == "committed" else "A")

    def test_recovery_itself_can_resume_after_original_directory_is_restored(self):
        class Crash(BaseException): pass
        self.seed()
        def interrupted_switch(stage):
            if stage == "installed": raise Crash()
        with self.assertRaises(Crash): self.store(checkpoint=interrupted_switch).switch("B", self.config)
        def interrupted_recovery(stage):
            if stage == "original_restored": raise Crash()
        with self.assertRaises(Crash): self.store(checkpoint=interrupted_recovery).recover()
        self.store().recover()
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "live A")
        self.assertEqual((self.paths.accounts / "A/profile/Cookie-fixture.txt").read_text(), "old stored A")
        self.assertFalse(self.paths.journal.exists())

    def test_failed_launch_preserves_new_writes_and_restores_previous_snapshot(self):
        self.seed()
        def launch():
            (self.paths.active / "Cookie-fixture.txt").write_text("post-launch B data")
            raise SwitcherError("launch_failed", "fixture")
        self.system.launch_claude = launch
        with self.assertRaises(SwitcherError): self.store().switch("B", self.config)
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "live A")
        saved = list(self.paths.accounts.glob("recovered-*/Cookie-fixture.txt"))
        self.assertEqual([p.read_text() for p in saved], ["post-launch B data"])
        self.assertEqual((self.paths.accounts / "A/profile/Cookie-fixture.txt").read_text(), "old stored A")

    def test_cross_volume_strategy_uses_verified_copy_and_legacy_recovery(self):
        class Crash(BaseException): pass
        self.seed()
        def checkpoint(stage):
            if stage == "installed": raise Crash()
        with self.assertRaises(Crash): self.store(checkpoint=checkpoint).switch("B", self.config)
        self.assertEqual(read_json(self.paths.journal)["schema"], 3)
        self.store().recover()
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "live A")

    def test_publish_replace_failure_restores_original_and_keeps_previous_snapshot(self):
        self.seed()
        original_replace = os.replace
        def fail_archive(source, target):
            if Path(source) == self.paths.active and Path(target).parent.name == "old":
                raise OSError(errno.EXDEV, "fixture device changed")
            return original_replace(source, target)
        with patch("watch_switcher.accounts.os.replace", side_effect=fail_archive):
            with self.assertRaises(OSError): self.store().switch("B", self.config)
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "live A")
        self.assertEqual((self.paths.accounts / "A/profile/Cookie-fixture.txt").read_text(), "old stored A")

    def test_claude_restart_during_hashing_aborts_before_any_directory_move(self):
        self.seed()
        samples = iter((False, True))
        self.system.claude_running = lambda: next(samples)
        with self.assertRaises(SwitcherError): self.store().switch("B", self.config)
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "live A")
        self.assertEqual((self.paths.accounts / "A/profile/Cookie-fixture.txt").read_text(), "old stored A")
        self.assertFalse(self.paths.journal.exists())
        self.assertNotIn("launch", self.system.calls)

    def test_oversize_manifest_is_rejected_before_moving_the_live_profile(self):
        self.seed()
        with patch("watch_switcher.accounts.ACCOUNT_MANIFEST_LIMIT", 64):
            with self.assertRaises(SwitcherError) as raised:
                self.store().switch("B", self.config)
        self.assertEqual(raised.exception.code, "oversize_account_manifest")
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "live A")
        self.assertEqual((self.paths.accounts / "A/profile/Cookie-fixture.txt").read_text(), "old stored A")
        self.assertFalse(self.paths.journal.exists())
        self.assertFalse(list(self.paths.accounts.glob(".A.*")))

    def test_damaged_previous_manifest_does_not_prevent_original_profile_recovery(self):
        class Crash(BaseException): pass
        self.seed()
        (self.paths.accounts / "A/manifest.json").write_text("damaged older manifest")
        def checkpoint(stage):
            if stage == "snapshot_committed": raise Crash()
        with self.assertRaises(Crash): self.store(checkpoint=checkpoint).switch("B", self.config)
        self.store().recover()
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "live A")
        self.assertEqual((self.paths.accounts / "A/manifest.json").read_text(), "damaged older manifest")
        self.assertEqual((self.paths.accounts / "A/profile/Cookie-fixture.txt").read_text(), "old stored A")
        self.assertFalse(self.paths.journal.exists())

    def test_recovery_rejects_redirected_archive_paths_without_touching_data(self):
        class Crash(BaseException): pass
        self.seed()
        def checkpoint(stage):
            if stage == "prepared": raise Crash()
        with self.assertRaises(Crash): self.store(checkpoint=checkpoint).switch("B", self.config)
        journal = read_json(self.paths.journal); journal["records"][0]["old"] = str(self.paths.home / "unrelated")
        atomic_json(self.paths.journal, journal)
        with self.assertRaises(SwitcherError): self.store().recover()
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "live A")


if __name__ == "__main__": unittest.main()
