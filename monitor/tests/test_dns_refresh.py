import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Resources"))
from watch_switcher.common import Paths, SwitcherError, atomic_json, read_json
from watch_switcher.audit import dns_receipt_path, _dns_receipt_state
from watch_switcher.dns_refresh import refresh_for_launch


class DNSRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.paths = Paths(Path(self.temp.name)); self.paths.initialize()
        self.token = "a" * 32
        self.channel = self.paths.base / (".dns-refresh-" + self.token)
        self.channel.mkdir(mode=0o700)
        self.env = patch.dict(os.environ, {"CLAUDE_WATCH_DNS_REFRESH_TOKEN": self.token})
        self.env.start(); self.addCleanup(self.env.stop)

    def test_fresh_receipt_does_not_duplicate_probe(self):
        atomic_json(dns_receipt_path(self.paths), {"provider": "ipleak", "finished_at": time.time()})
        refresh_for_launch(self.paths)
        self.assertFalse((self.channel / "request.json").exists())

    def test_old_reply_cannot_acknowledge_new_request(self):
        atomic_json(self.channel / "reply.json", {"schema": 1, "id": "b" * 32, "ready": True})
        ticks = iter([0, 0, 90])
        with self.assertRaises(SwitcherError) as caught:
            refresh_for_launch(self.paths, clock=lambda: next(ticks), sleep=lambda _: None)
        self.assertEqual(caught.exception.code, "dns_refresh_timeout")

    def test_success_still_requires_real_launch_receipt(self):
        def reply(_):
            request = read_json(self.channel / "request.json")
            atomic_json(self.channel / "reply.json", dict(request, ready=True))
        refresh_for_launch(self.paths, sleep=reply)
        self.assertEqual(_dns_receipt_state({}, "same", launch=True)[0], "unknown")

    def test_failed_probe_aborts(self):
        def reply(_):
            request = read_json(self.channel / "request.json")
            atomic_json(self.channel / "reply.json", dict(request, ready=False))
        with self.assertRaises(SwitcherError) as caught:
            refresh_for_launch(self.paths, sleep=reply)
        self.assertEqual(caught.exception.code, "dns_refresh_failed")

    def test_cli_keeps_existing_gate_without_ui_wait(self):
        with patch.dict(os.environ, {"CLAUDE_WATCH_DNS_REFRESH_TOKEN": ""}):
            refresh_for_launch(self.paths)
        self.assertFalse((self.channel / "request.json").exists())

    def test_path_traversal_rejected(self):
        with patch.dict(os.environ, {"CLAUDE_WATCH_DNS_REFRESH_TOKEN": "../../elsewhere"}):
            with self.assertRaises(SwitcherError): refresh_for_launch(self.paths)


if __name__ == "__main__": unittest.main()
