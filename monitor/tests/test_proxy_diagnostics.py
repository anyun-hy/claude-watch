"""No real requests: explicit proxy selection, redaction and no state side effects."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

RESOURCES = Path(__file__).resolve().parents[1] / "Resources"
sys.path.insert(0, str(RESOURCES))
from watch_switcher.diagnostics import diagnose


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cw-diagnostics-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.calls = []
        self.env = {"HOME": str(self.home), "PATH": os.defpath, "HTTP_PROXY": "http://ignored:9999",
                    "NO_PROXY": "*", "ANTHROPIC_AUTH_TOKEN": "account-token", "CURL_HOME": "/private/secret"}

    def runner(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        status = 401 if "api.anthropic.com" in argv[-1] else 403
        return subprocess.CompletedProcess(argv, 0, f"{status}\t200\t0\t0.01\t0.05", "not part of report")

    def run_check(self, args, **kwargs):
        return diagnose(args, environ=self.env, runner=kwargs.pop("runner", self.runner), **kwargs)

    def test_explicit_transport_success_does_not_grant_launch_or_login(self):
        result, code = self.run_check(["--proxy", "http://127.0.0.1:7890"])
        self.assertEqual(code, 0)
        self.assertEqual(result["state"], "transport_reached")
        self.assertEqual([c["access"] for c in result["checks"]], ["unauthenticated", "access_restricted"])
        self.assertIsNone(result["launch_allowed"])
        self.assertEqual(result["account_status"], "not_evaluated")
        self.assertEqual(result["leak_protection"], "not_evaluated")
        self.assertFalse(result["application_started"] or result["system_modified"])
        self.assertEqual(list(self.home.iterdir()), [])

    def test_private_proxy_never_enters_report_or_curl_arguments(self):
        config = self.home / "private-proxy-config.json"
        proxy = 'socks5h://name:secret-password@proxy.private.example:1080'
        config.write_text(json.dumps({"proxy_url": proxy}))
        result, code = self.run_check(["--config", str(config)])
        self.assertEqual(code, 0)
        self.assertTrue(result["proxy"]["authentication_configured"])
        for argv, options in self.calls:
            self.assertEqual(argv[:2], ["/usr/bin/curl", "--disable"])
            self.assertNotIn(proxy, " ".join(argv))
            self.assertIn(proxy, options["input"])
            for key in ("HTTP_PROXY", "NO_PROXY", "ANTHROPIC_AUTH_TOKEN", "CURL_HOME"):
                self.assertNotIn(key, options["env"])
        for sensitive in ("secret-password", "proxy.private.example", str(config), "account-token"):
            self.assertNotIn(sensitive, json.dumps(result))

    def test_stdin_entry_avoids_credential_arguments_and_creates_no_files(self):
        result, code = self.run_check(["--stdin-config"], input_stream=io.StringIO(
            '{"proxy_url":"https://name:password@127.0.0.1:7890"}'))
        self.assertEqual(code, 0)
        self.assertEqual(result["proxy"]["source"], "stdin")
        self.assertEqual(list(self.home.iterdir()), [])

    def test_does_not_inherit_generic_proxy_or_fall_back_to_direct(self):
        result, code = self.run_check([])
        self.assertEqual(code, 2)
        self.assertEqual(result["state"], "configuration_error")
        self.assertEqual(self.calls, [])

    def test_explicit_environment_and_argument_precedence(self):
        self.env.update(CLAUDE_WATCH_PROXY_URL="socks5://[::1]:1080", CLAUDE_SWITCHER_PROXY_URL="http://ignored:9")
        result, code = self.run_check([])
        self.assertEqual((code, result["proxy"]["scheme"], result["proxy"]["port"]), (0, "socks5", 1080))
        result, _ = self.run_check(["--proxy", "https://127.0.0.1:7890"])
        self.assertEqual(result["proxy"]["source"], "argument")
        self.assertEqual(result["proxy"]["port"], 7890)

    def test_invalid_arguments_are_redacted_without_probing(self):
        for args in (["--proxy", "http://secret-password@host:bad"],
                     ["--proxy", "file:///secret-password"],
                     ["--proxy", "http://host:80/path"],
                     ["--proxy", "http://host:80", "--unknown", "secret-password"],
                     ["--proxy", "http://host:80", "--config", "secret-password"],
                     ["--proxy", "http://host:80\nsecret-password"],
                     ["--proxy", "http://secret-password\ud800:80"],
                     ["--config", str(self.home / "secret-password")]):
            with self.subTest(args=args):
                result, code = self.run_check(args)
                self.assertEqual(code, 2)
                self.assertNotIn("secret-password", json.dumps(result))
        self.assertEqual(self.calls, [])

    def test_oversize_or_invalid_configuration_never_probes(self):
        for raw in ('[]', '{bad', 'x' * 65537, '{"proxy_url":null}'):
            result, code = self.run_check(["--stdin-config"], input_stream=io.StringIO(raw))
            self.assertEqual(code, 2)
        self.assertEqual(self.calls, [])

    def test_tls_or_metrics_failure_never_passes(self):
        for stdout, returncode in (("403 200 60 0.1 0.2", 60), ("401 200 0 0 0.2", 0),
                                   ("401 200 0 nan 0.2", 0), ("401 200 0 .1 inf", 0),
                                   ("invalid", 0), ("401 200 0 .1 .2 extra", 0),
                                   ("0 0 0 .1 .2", 0)):
            with self.subTest(stdout=stdout):
                def fake(argv, **kwargs): return subprocess.CompletedProcess(argv, returncode, stdout, "secret-password")
                result, code = self.run_check(["--proxy", "http://127.0.0.1:7890"], runner=fake)
                self.assertEqual(code, 1)
                self.assertTrue(all(not c["transport_reached"] for c in result["checks"]))
                self.assertNotIn("secret-password", json.dumps(result))

    def test_one_failed_destination_is_partial_without_retry_or_direct_fallback(self):
        def fake(argv, **kwargs):
            self.calls.append((argv, kwargs))
            if "api.anthropic.com" in argv[-1]: raise subprocess.TimeoutExpired(argv, 15, stderr="secret-password")
            return subprocess.CompletedProcess(argv, 0, "403 200 0 .1 .2", "")
        result, code = self.run_check(["--proxy", "http://127.0.0.1:7890"], runner=fake)
        self.assertEqual(code, 1)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(result["checks"][0]["error"], "probe_timeout")
        self.assertTrue(result["checks"][1]["transport_reached"])

    def test_socks_success_does_not_require_http_connect_code(self):
        def fake(argv, **kwargs): return subprocess.CompletedProcess(argv, 0, "401 0 0 .1 .2", "")
        result, code = self.run_check(["--proxy", "socks5h://[::1]:1080"], runner=fake)
        self.assertEqual(code, 0)
        self.assertEqual(result["proxy"]["host_scope"], "loopback")

    def test_runtime_entry_never_loads_account_or_environment_state(self):
        spec = importlib.util.spec_from_file_location("switcher_diagnostic_test", RESOURCES / "switcher.py")
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        output = io.StringIO()
        with patch.object(module, "load_config", side_effect=AssertionError("policy read")), \
                patch.object(module, "Paths", side_effect=AssertionError("account paths")), \
                patch("watch_switcher.diagnostics.subprocess.run", side_effect=self.runner), \
                contextlib.redirect_stdout(output):
            code = module.main(["diagnose-proxy", "--proxy", "http://127.0.0.1:7890"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["mode"], "proxy_diagnostics")

    def test_shell_entry_rejects_missing_proxy_without_creating_user_state(self):
        script = RESOURCES.parents[1] / "claude-watch.sh"
        env = dict(os.environ, HOME=str(self.home), PYTHONDONTWRITEBYTECODE="1")
        env.pop("CLAUDE_WATCH_PROXY_URL", None); env.pop("CLAUDE_SWITCHER_PROXY_URL", None)
        run = subprocess.run(["/bin/bash", str(script), "diagnose-proxy"], env=env,
                             capture_output=True, text=True, timeout=10)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertEqual(json.loads(run.stdout)["state"], "configuration_error")
        self.assertEqual(list(self.home.iterdir()), [])


if __name__ == "__main__": unittest.main()
