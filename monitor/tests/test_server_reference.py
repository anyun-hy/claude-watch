#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import subprocess
import unittest
from unittest.mock import patch


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "Resources" / "server_reference.py"
SPEC = importlib.util.spec_from_file_location("server_reference", MODULE_PATH)
reference = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(reference)


def completed(payload, code=0):
    raw = json.dumps(payload).encode("utf-8") if isinstance(payload, dict) else payload
    return subprocess.CompletedProcess([], code, stdout=raw)


class ServerReferenceTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

    def fake_curl(self, responses):
        def run(command, **kwargs):
            self.calls.append(command)
            return responses.pop(0)
        return run

    def test_normalizes_whitelist_and_forces_proxy(self):
        responses = [
            completed({"Answer": [{"type": 1, "data": "1.1.1.1"}]}),
            completed({"ip": "1.1.1.1", "country": "AU", "region": "Queensland", "city": "South Brisbane", "anycast": True}),
        ]
        with patch.object(reference.subprocess, "run", self.fake_curl(responses)):
            result = reference.query("API.ChatGPT.COM.:443", now=100)
        self.assertEqual(result["host"], "api.chatgpt.com")
        self.assertEqual(result["basis"], "dns_reference")
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["countryCode"], "AU")
        self.assertEqual(result["country"], "")
        self.assertEqual(result["geoSource"], "IPinfo")
        self.assertEqual(result["expiresAt"], 700)
        self.assertEqual(len(self.calls), 2)
        for command in self.calls:
            self.assertIn("-q", command)
            self.assertIn("--proxy", command)
            self.assertEqual(command[command.index("--proxy") + 1], "http://127.0.0.1:7890")
            self.assertEqual(command[command.index("--noproxy") + 1], "")
            self.assertIn("--proto", command)
            self.assertNotIn("-L", command)
        self.assertEqual(self.calls[-1][-1], "https://ipinfo.io/1.1.1.1/json")

    def test_rejects_attack_hosts_and_ip_hosts_without_curl(self):
        bad = ["https://chatgpt.com/x", "chatgpt.com@evil.test", "chatgpt.com.evil.test", "127.0.0.1", "[::1]", "openai.com:0"]
        for host in bad:
            with self.subTest(host=host), patch.object(reference.subprocess, "run") as run:
                result = reference.query(host, now=100)
                self.assertEqual(result["status"], "unavailable")
                run.assert_not_called()

    def test_observed_ip_skips_dns_and_checks_response_identity(self):
        responses = [completed({"ip": "8.8.4.4", "country": "US", "region": "CA", "city": "Mountain View"})]
        with patch.object(reference.subprocess, "run", self.fake_curl(responses)):
            result = reference.query("openai.com", "8.8.8.8", now=100)
        self.assertEqual(result["basis"], "observed_ip")
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["address"], "8.8.8.8")
        self.assertEqual(result["expiresAt"], 400)
        self.assertEqual(len(self.calls), 1)

    def test_rejects_private_benchmark_and_multicast_supplied_addresses(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.1.1", "0.0.0.0", "198.18.0.1", "224.0.0.1", "::1"):
            with self.subTest(address=address), patch.object(reference.subprocess, "run") as run:
                result = reference.query("claude.ai", address, now=100)
                self.assertEqual(result["status"], "unavailable")
                self.assertEqual(result["expiresAt"], 400)
                run.assert_not_called()

    def test_dns_falls_back_to_aaaa_and_preserves_address_when_geo_fails(self):
        responses = [
            completed({"Answer": []}),
            completed({"Answer": [{"type": 28, "data": "2606:4700:4700::1111"}]}),
            completed(b"not json"),
        ]
        with patch.object(reference.subprocess, "run", self.fake_curl(responses)):
            result = reference.query("sub.anthropic.com", now=100)
        self.assertEqual(result["address"], "2606:4700:4700::1111")
        self.assertEqual(result["addresses"], ["2606:4700:4700::1111"])
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["country"], "")
        self.assertIn("未完成", result["message"])

    def test_dns_rejects_private_answers_and_fails_closed_on_429(self):
        responses = [
            completed({"Answer": [{"type": 1, "data": "198.18.0.1"}]}),
            completed({"Answer": [{"type": 28, "data": "fd00::1"}]}),
        ]
        with patch.object(reference.subprocess, "run", self.fake_curl(responses)):
            result = reference.query("oaiusercontent.com", now=100)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["addresses"], [])

        with patch.object(reference.subprocess, "run", return_value=completed(b"", code=22)):
            rate_limited = reference.query("oaiusercontent.com", now=100)
        self.assertEqual(rate_limited["status"], "unavailable")
        self.assertEqual(rate_limited["expiresAt"], 400)

    def test_dns_rejects_nonzero_doh_status_but_allows_missing_status_for_compatibility(self):
        responses = [
            completed({"Status": 2, "Answer": [{"type": 1, "data": "1.1.1.1"}]}),
            completed({"Status": 3, "Answer": []}),
        ]
        with patch.object(reference.subprocess, "run", self.fake_curl(responses)):
            unavailable = reference.query("openai.com", now=100)
        self.assertEqual(unavailable["status"], "unavailable")

        compatible = [
            completed({"Answer": [{"type": 1, "data": "1.1.1.1"}]}),
            completed({"ip": "1.1.1.1", "country": "AU", "region": "Queensland", "city": "South Brisbane"}),
        ]
        with patch.object(reference.subprocess, "run", self.fake_curl(compatible)):
            ready = reference.query("openai.com", now=100)
        self.assertEqual(ready["status"], "ready")
        self.assertIn("非这条连接的实测目标 IP", ready["message"])

    def test_ipinfo_rejects_error_or_invalid_country(self):
        for response in (
            {"ip": "1.1.1.1", "country": "US", "error": {"title": "Rate Limited"}},
            {"ip": "1.1.1.1", "country": "USA", "region": "", "city": ""},
        ):
            with self.subTest(response=response), patch.object(reference.subprocess, "run", return_value=completed(response)):
                result = reference.query("openai.com", "1.1.1.1", now=100)
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["countryCode"], "")


if __name__ == "__main__":
    unittest.main()
