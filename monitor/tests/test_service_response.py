"""Offline service-response classification and safe final-header parsing."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RESOURCES = Path(__file__).resolve().parents[1] / "Resources"
sys.path.insert(0, str(RESOURCES))
from watch_switcher.common import DEFAULT_CONFIG, Paths, SwitcherError
from watch_switcher.system import System


class ServiceResponseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        home = Path(self.tmp.name) / "home"; home.mkdir()
        self.system = System(Paths(home)); self.config = dict(DEFAULT_CONFIG, proxy_mode="tag")

    def native(self, status, headers=""):
        def run(argv, *args, **kwargs):
            path = argv[argv.index("--dump-header") + 1]
            Path(path).write_text(headers)
            return subprocess.CompletedProcess(argv, 0, str(status), "")
        self.system.run = run

    def test_final_cloudflare_challenge_excludes_connect_interim_headers(self):
        self.native(403, "HTTP/1.1 200 Connection established\r\nCF-Mitigated: challenge\r\n\r\nHTTP/2 403\r\nCF-Mitigated: challenge\r\n\r\n")
        row = self.system.service_response("claude", "https://claude.ai/", self.config)
        self.assertEqual((row["status"], row["access"]), ("ok", "challenge"))
        self.assertEqual(row["challenge"]["mitigated"], "challenge")

    def test_interim_challenge_header_does_not_green_a_plain_final_403(self):
        self.native(403, "HTTP/1.1 200 Connection established\r\nCF-Mitigated: challenge\r\n\r\nHTTP/2 403\r\n\r\n")
        row = self.system.service_response("claude", "https://claude.ai/", self.config)
        self.assertEqual((row["status"], row["access"]), ("warn", "access_restricted"))

    def test_plain_403_429_and_500_remain_warnings(self):
        for status in (403, 429, 500):
            with self.subTest(status=status):
                self.native(status, "HTTP/2 %d\r\n\r\n" % status)
                row = self.system.service_response("claude", "https://claude.ai/", self.config)
                self.assertEqual(row["status"], "warn")
                self.assertNotIn("challenge", row)

    def test_api_401_is_uncredentialed_access_not_account_success(self):
        self.native(401, "HTTP/2 401\r\n\r\n")
        row = self.system.service_response("api", "https://api.anthropic.com/v1/models", self.config)
        self.assertEqual((row["status"], row["access"], row["transport_reached"]), ("ok", "authentication_required", True))

    def test_api_challenge_and_other_service_401_do_not_receive_special_cases(self):
        self.native(403, "HTTP/2 403\r\nCF-Mitigated: challenge\r\n\r\n")
        api = self.system.service_response("api", "https://api.anthropic.com/v1/models", self.config)
        self.assertEqual((api["status"], api["access"]), ("warn", "access_restricted"))
        self.native(401, "HTTP/2 401\r\n\r\n")
        other = self.system.service_response("other", "https://example.invalid/", self.config)
        self.assertEqual((other["status"], other["access"]), ("warn", "http_response"))

    def test_redirects_remain_normal_http_responses(self):
        self.native(302, "HTTP/2 302\r\nLocation: /next\r\n\r\n")
        row = self.system.service_response("claude", "https://claude.ai/", self.config)
        self.assertEqual((row["status"], row["access"]), ("ok", "http_response"))

    def test_tls_timeout_remains_unknown(self):
        def run(_argv, *args, **kwargs):
            raise SwitcherError("tls_failed", "TLS 证书校验失败")
        self.system.run = run
        row = self.system.service_response("claude", "https://claude.ai/", self.config)
        self.assertEqual((row["status"], row["access"], row["error_code"]), ("unknown", "network_error", "tls_failed"))

    def test_run_timeout_cause_is_preserved(self):
        def run(_argv, *args, **kwargs):
            raise SwitcherError("command_unavailable", "系统操作不可用或超时") from subprocess.TimeoutExpired("curl", 8)
        self.system.run = run
        row = self.system.service_response("claude", "https://claude.ai/", self.config)
        self.assertEqual(row["error_code"], "timeout")

    def test_header_tmpfile_is_removed(self):
        seen = []
        def run(argv, *args, **kwargs):
            path = argv[argv.index("--dump-header") + 1]; seen.append(path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            Path(path).write_text("HTTP/2 403\r\nCF-Mitigated: challenge\r\n\r\n")
            return subprocess.CompletedProcess(argv, 0, "403", "")
        self.system.run = run
        self.system.service_response("claude", "https://claude.ai/", self.config)
        self.assertFalse(Path(seen[0]).exists())


if __name__ == "__main__": unittest.main()
