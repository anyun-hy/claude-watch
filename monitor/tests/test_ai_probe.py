import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("ai_probe", Path(__file__).parents[1] / "Resources/ai_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class AIProbeTests(unittest.TestCase):
    class Process:
        def __init__(self, command, stdout="", returncode=0):
            self.command, self.stdout, self.returncode = command, stdout, returncode
            self.terminated = False

        def communicate(self, timeout=None):
            return self.stdout, ""

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.terminated = True
            self.returncode = -9

    @staticmethod
    def body(body, status):
        return body + "\n" + probe.STATUS_MARKER + str(status)

    def responder(self, overrides=None):
        overrides = overrides or {}
        defaults = {
            "https://claude.ai/cdn-cgi/trace": ("ip=8.8.8.8\n", 200),
            "https://www.anthropic.com/cdn-cgi/trace": ("ip=8.8.4.4\n", 200),
            "https://chatgpt.com/cdn-cgi/trace": ("ip=9.9.9.9\n", 200),
            "https://api.openai.com/v1/models": ("{\\\"error\\\":{}}", 401),
            probe.REFERENCE_URL: ("ip=1.1.1.1\n", 200),
            "https://ipinfo.io/8.8.8.8/json": ('{"ip":"8.8.8.8","country":"US","country_name":"United States","region":"California","city":"Mountain View","org":"Google","timezone":"America/Los_Angeles"}', 200),
            "https://ipinfo.io/9.9.9.9/json": ('{"ip":"9.9.9.9","country":"US"}', 200),
        }
        defaults.update(overrides)
        def popen(command, **kwargs):
            url = command[-1]
            value = defaults[url]
            if isinstance(value, Exception):
                raise value
            body, status = value
            return self.Process(command, self.body(body, status))
        return popen

    def test_normal_claude_collects_primary_exit_and_geo(self):
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responder()):
            result = probe.collect("claude")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["exitIP"], "8.8.8.8")
        self.assertEqual(result["referenceIP"], "1.1.1.1")
        self.assertEqual(result["organization"], "Google")
        self.assertEqual(result["countryCode"], "US")

    def test_primary_trace_403_does_not_fallback_to_anthropic_trace(self):
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responder({"https://claude.ai/cdn-cgi/trace": ("ip=8.8.8.8", 403)})):
            result = probe.collect("claude")
        self.assertEqual(result["exitIP"], "")
        self.assertEqual(result["referenceIP"], "1.1.1.1")
        self.assertEqual(result["status"], "partial")
        self.assertIn("http_status", [row["code"] for row in result["errors"]])
        self.assert_schema_strings(result)

    def test_gpt_401_is_a_response_not_network_failure(self):
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responder()):
            result = probe.collect("gpt")
        model_endpoint = next(row for row in result["endpoints"] if row["url"].endswith("/v1/models"))
        self.assertEqual(result["status"], "complete")
        self.assertEqual(model_endpoint["status"], "responded")
        self.assertEqual(model_endpoint["httpStatus"], 401)

    def test_geo_identity_mismatch_is_partial_and_discards_geo(self):
        bad_geo = ('{"ip":"1.1.1.1","country":"US"}', 200)
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responder({"https://ipinfo.io/8.8.8.8/json": bad_geo})):
            result = probe.collect("claude")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["countryCode"], "")
        self.assertIn("identity_mismatch", [row["code"] for row in result["errors"]])

    def test_geo_failure_is_partial(self):
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responder({"https://ipinfo.io/8.8.8.8/json": ("", 503)})):
            result = probe.collect("claude")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["countryCode"], "")
        self.assertIn("lookup_failed", [row["code"] for row in result["errors"]])
        self.assert_schema_strings(result)

    def test_geo_missing_optional_fields_preserves_string_schema(self):
        bare_geo = ('{"ip":"8.8.8.8","country":"US"}', 200)
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responder({"https://ipinfo.io/8.8.8.8/json": bare_geo})):
            result = probe.collect("claude")
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["region"], "")
        self.assert_schema_strings(result)

    def test_invalid_http_status_is_explicit_error(self):
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responder({"https://claude.ai/cdn-cgi/trace": ("ip=8.8.8.8", 999)})):
            result = probe.collect("claude")
        self.assertEqual(result["status"], "partial")
        self.assertIn("invalid_http_status", [row["code"] for row in result["errors"]])
        self.assert_schema_strings(result)

    def test_curl_28_with_http_000_is_timeout_not_invalid_http_status(self):
        def popen(command, **kwargs):
            url = command[-1]
            if url == "https://claude.ai/cdn-cgi/trace":
                return self.Process(command, self.body("", 0), returncode=28)
            return self.responder()(command, **kwargs)
        with mock.patch.object(probe.subprocess, "Popen", side_effect=popen):
            result = probe.collect("claude")
        codes = [row["code"] for row in result["errors"]]
        self.assertIn("timeout", codes)
        self.assertNotIn("invalid_http_status", codes)

    def test_curl_35_with_http_000_is_request_failure_not_invalid_http_status(self):
        def popen(command, **kwargs):
            url = command[-1]
            if url == "https://claude.ai/cdn-cgi/trace":
                return self.Process(command, self.body("", 0), returncode=35)
            return self.responder()(command, **kwargs)
        with mock.patch.object(probe.subprocess, "Popen", side_effect=popen):
            result = probe.collect("claude")
        codes = [row["code"] for row in result["errors"]]
        self.assertIn("request_failed", codes)
        self.assertNotIn("invalid_http_status", codes)

    def assert_schema_strings(self, result):
        for key in ("service", "status", "exitIP", "referenceIP", "exitSource", "countryCode",
                    "country", "region", "city", "organization", "ipTimezone"):
            self.assertIsInstance(result[key], str, key)

    def test_timeout_is_reported(self):
        def popen(command, **kwargs):
            child = self.Process(command)
            def timeout(timeout=None):
                raise subprocess.TimeoutExpired(command, timeout)
            child.communicate = timeout
            return child
        with mock.patch.object(probe.subprocess, "Popen", side_effect=popen):
            result = probe.collect("gpt")
        self.assertEqual(result["status"], "timeout")
        self.assertTrue(all(row["status"] == "timeout" for row in result["endpoints"]))

    def test_every_curl_forces_7890_without_redirect_or_tls_bypass(self):
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responder()) as popen:
            probe.collect("claude")
        for call in popen.call_args_list:
            command = call.args[0]
            self.assertEqual(command[0], "/usr/bin/curl")
            self.assertEqual(command[command.index("--proxy") + 1], "http://127.0.0.1:7890")
            self.assertEqual(command[command.index("--noproxy") + 1], "")
            self.assertNotIn("-L", command)
            self.assertNotIn("-k", command)

    def test_cancellation_reaps_only_active_child(self):
        child = self.Process(["/usr/bin/curl"])
        child.returncode = None
        probe.ACTIVE_CHILD = child
        with self.assertRaises(SystemExit) as raised:
            probe.cancellation_handler(15, None)
        self.assertEqual(raised.exception.code, 143)
        self.assertTrue(child.terminated)
        self.assertIsNone(probe.ACTIVE_CHILD)


if __name__ == "__main__":
    unittest.main()
