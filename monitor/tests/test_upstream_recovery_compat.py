"""Compatibility and post-commit contracts; profiles are temporary fixtures."""
from pathlib import Path
import os
import shutil
from unittest.mock import patch

from test_switcher import Fixture
from watch_switcher.accounts import tree_manifest, verified_copy
from watch_switcher.common import atomic_json, read_json


class UpstreamRecoveryCompatibilityTests(Fixture):
    def test_owner_executable_permission_survives_private_copy(self):
        self.active()
        executable = self.paths.active / "tool"
        executable.write_text("#!/bin/sh\nexit 0\n"); executable.chmod(0o755)
        target = self.paths.home / "copied"
        verified_copy(self.paths.active, target)
        self.assertEqual((target / "tool").stat().st_mode & 0o777, 0o700)
        self.assertEqual((target / "Cookie-fixture.txt").stat().st_mode & 0o777, 0o600)

    def test_schema1_completed_swap_can_still_be_recovered(self):
        self.paths.initialize(); self.active("new B")
        token = "a" * 32
        old = self.paths.active.parent / (".claude-watch-old-" + token)
        old.mkdir(); (old / "Cookie-fixture.txt").write_text("old A")
        stage = self.paths.active.parent / (".claude-watch-stage-" + token)
        atomic_json(self.paths.journal, dict(schema=1, token=token, target="B", phase="installed",
            previous={"schema":1,"current":"A"}, had_active=True, old=str(old), stage=str(stage)))
        self.store().recover()
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "old A")
        self.assertEqual((self.paths.accounts / ("recovered-"+token) / "Cookie-fixture.txt").read_text(), "new B")

    def test_schema2_move_archive_can_still_be_recovered(self):
        self.paths.initialize(); self.active("new B")
        token = "b" * 32
        store = self.store(); archive = store._archive_paths("A", token)
        for key, text in (("slot", "live A"), ("backup", "old stored A")):
            profile = archive[key] / "profile"; profile.mkdir(parents=True)
            (profile / "Cookie-fixture.txt").write_text(text)
            atomic_json(archive[key] / "manifest.json", dict(schema=1, files=tree_manifest(profile), archive_transaction=token if key=="slot" else "older"))
        atomic_json(self.paths.journal, dict(schema=2, token=token, target="B", phase="installed",
            previous={"schema":1,"current":"A"}, had_active=True,
            old=str(self.paths.active.parent / (".claude-watch-old-"+token)),
            stage=str(self.paths.active.parent / (".claude-watch-stage-"+token)),
            archive=dict(account="A", had_snapshot=True, **{k:str(v) for k,v in archive.items()})))
        store.recover()
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "live A")
        self.assertEqual((self.paths.accounts / "A/profile/Cookie-fixture.txt").read_text(), "old stored A")

    def test_cleanup_failure_does_not_quit_committed_account(self):
        self.active("A")
        real_remove = shutil.rmtree
        def fail_after_commit(path, *args, **kwargs):
            journal = read_json(self.paths.journal, {})
            if journal.get("phase") == "committed" and str(path) == journal.get("workspace"):
                raise OSError("fixture cleanup failed")
            return real_remove(path, *args, **kwargs)
        with patch("watch_switcher.upstream_accounts.shutil.rmtree", side_effect=fail_after_commit):
            result = self.store().switch("B", self.config)
        self.assertEqual(result["status"], "partial")
        self.assertTrue(self.system.running)
        self.assertEqual(self.store().state()["current"], "B")
        self.system.running = False
        self.store().recover()
        self.assertFalse(self.paths.journal.exists())
        self.assertEqual(self.store().state()["current"], "B")
