"""Online query receipts preserve causes without performing real network I/O."""
import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

RESOURCES = Path(__file__).resolve().parents[1] / "Resources"
sys.path.insert(0, str(RESOURCES))

from watch_switcher.common import DEFAULT_CONFIG, Paths, SwitcherError
from watch_switcher.system import System


class QueryFailureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cw-query-")
        self.addCleanup(self.temp.cleanup)
        home = Path(self.temp.name) / "home"; home.mkdir()
        self.system = System(Paths(home))
        self.config = dict(DEFAULT_CONFIG, proxy_mode="tag")

    @staticmethod
    def reply(body, status=200, code=0, stderr="private-token"):
        return subprocess.CompletedProcess(["curl"], code, body + "\n" + str(status), stderr)

    def test_curl_failures_have_specific_redacted_codes(self):
        expected = {6: "dns_resolution_failed", 7: "connection_failed", 28: "timeout", 35: "tls_failed", 60: "tls_failed"}
        for exit_code, code in expected.items():
            with self.subTest(exit_code=exit_code):
                self.system.run = lambda *args, exit_code=exit_code, **kwargs: self.reply("", 0, exit_code)
                with self.assertRaises(SwitcherError) as raised:
                    self.system.fetch("https://example.invalid", self.config)
                self.assertEqual(raised.exception.code, code)
                self.assertNotIn("private-token", str(raised.exception))

    def test_guard_egress_uses_system_tun_route_not_fixed_http_proxy(self):
        calls = []
        def runner(argv, *_args, **_kwargs):
            calls.append(argv)
            return self.reply("ip=1.1.1.1\nloc=JP")
        self.system.run = runner
        value = self.system.guard_egress(self.config, attempts=1)
        self.assertEqual((value["state"], value["ip"], value["country"]), ("ok", "1.1.1.1", "JP"))
        args = calls[0]
        self.assertEqual(args[args.index("--proxy") + 1], "")
        self.assertNotIn("http://127.0.0.1:7890", args)

    def test_trace_failure_is_reported_once_without_inventing_a_geo_result(self):
        responses = iter([self.reply("blocked", 429)])
        self.system.run = lambda *args, **kwargs: next(responses)
        value = self.system.egress_reference(self.config)
        self.assertEqual(value["errors"], ["trace"])
        self.assertEqual(value["query_errors"]["trace"]["code"], "http_429")
        self.assertEqual(value["query_errors"]["trace"]["http_status"], 429)
        self.assertEqual(value["source_times"], {})
        self.assertNotIn("private-token", repr(value))

    def test_cloudflare_and_netcoffee_country_conflict_is_explicit(self):
        responses = iter([self.reply("ip=1.1.1.1\nloc=JP")])
        self.system.run = lambda *args, **kwargs: next(responses)
        lookup = {"status":"complete","httpStatus":200,"query":"1.1.1.1","queriedAt":1.0,"finishedAt":1.0,
                  "data":{"ip":"1.1.1.1","countryCode":"US","asn":13335,"asOrganization":"Cloudflare"}}
        with patch("netcoffee_client.request", return_value=lookup):
            value = self.system.egress_reference(self.config)
        self.assertEqual(value["geo"]["country"], "US")
        self.assertEqual(value["query_errors"]["egress_consistency"]["code"], "country_mismatch")

    def test_lookup_ip_mismatch_is_an_explicit_conflict_not_a_fallback(self):
        self.system.run = lambda *args, **kwargs: self.reply("ip=1.1.1.1\nloc=JP")
        lookup = {"status":"complete","httpStatus":200,"query":"1.1.1.1","queriedAt":1.0,"finishedAt":1.0,
                  "data":{"ip":"8.8.8.8","countryCode":"JP"}}
        with patch("netcoffee_client.request", return_value=lookup):
            value = self.system.egress_reference(self.config)
        self.assertEqual(value["query_errors"]["egress_consistency"]["code"], "ip_mismatch")
        self.assertNotIn("geo", value)

    def test_wrong_lookup_ip_never_becomes_an_asn_card(self):
        self.system.egress_reference = lambda _config: {
            "trace":{"ip":"1.1.1.1","loc":"JP"}, "errors":["egress_consistency"],
            "query_errors":{"egress_consistency":{"code":"ip_mismatch","message":"mismatch","source":"fixture"}},
            "source_times":{}, "netcoffee_lookup":{"status":"complete","httpStatus":200,"query":"1.1.1.1",
            "data":{"ip":"8.8.8.8","asn":13335,"asOrganization":"Cloudflare"}}}
        self.system.fetch = lambda url, *_args, **_kwargs: ("", 403 if "claude.ai" in url else 401)
        with patch("watch_switcher.stun.probe", return_value={"complete":True,"observations":[]}):
            value = self.system.online(self.config)
        self.assertNotIn("asn", value)
        self.assertEqual(value["query_errors"]["egress_consistency"]["code"], "ip_mismatch")

    def test_ipinfo_backoff_preserves_http_code_and_cooldown(self):
        self.system.run = lambda *args, **kwargs: self.reply("ip=1.1.1.1\nloc=US")
        lookup = {"status":"complete","httpStatus":200,"query":"1.1.1.1","queriedAt":1.0,"finishedAt":1.0,
                  "data":{"ip":"1.1.1.1","countryCode":"US"}}
        failed = {"status":"error","httpStatus":429,"error":"HTTP 429","retry_after":900,
                  "queriedAt":2.0,"finishedAt":2.0,"cache_state":"backoff"}
        with patch("netcoffee_client.request", return_value=lookup):
            self.system.metadata_query = lambda *_args, **_kwargs: failed
            value = self.system.egress_reference(self.config)
        error = value["query_errors"]["geo"]
        self.assertEqual(error["code"], "http_429")
        self.assertEqual(error["http_status"], 429)
        self.assertIn("冷却剩余", error["message"])

    def test_known_ipinfo_fallback_conflict_is_not_reported_as_a_query_failure(self):
        self.system.run = lambda *args, **kwargs: self.reply("ip=1.1.1.1\nloc=US")
        lookup = {"status":"complete","httpStatus":200,"query":"1.1.1.1","queriedAt":1.0,"finishedAt":1.0,
                  "data":{"ip":"1.1.1.1","countryCode":"US"}}
        fallback = {"status":"complete","httpStatus":200,"data":{"ip":"8.8.8.8","country":"US"},"finishedAt":2.0}
        with patch("netcoffee_client.request", return_value=lookup):
            self.system.metadata_query = lambda *_args, **_kwargs: fallback
            value = self.system.egress_reference(self.config)
        self.assertEqual(value["query_errors"]["egress_consistency"]["code"], "fallback_mismatch")
        self.assertNotIn("geo", value["query_errors"])

    def test_real_ipinfo_loader_preserves_valid_wrong_ip_for_downstream_conflict(self):
        responses = iter([self.reply("ip=1.1.1.1\nloc=US"), self.reply('{"ip":"8.8.8.8","country":"US"}')])
        self.system.run = lambda *args, **kwargs: next(responses)
        lookup = {"status":"complete","httpStatus":200,"query":"1.1.1.1","queriedAt":1.0,"finishedAt":1.0,
                  "data":{"ip":"1.1.1.1","countryCode":"US"}}
        with patch("netcoffee_client.request", return_value=lookup):
            value = self.system.egress_reference(self.config)
        self.assertEqual(value["query_errors"]["egress_consistency"]["code"], "fallback_mismatch")

    def test_online_keeps_http_auth_status_without_network_query_errors(self):
        def reference(_config):
            return {"trace": {"ip": "1.1.1.1", "loc": "JP"},
                    "geo": {"ip": "1.1.1.1", "country": "JP", "timezone": "Asia/Tokyo", "org": "AS13335 Cloudflare"},
                    "errors": [], "query_errors": {}, "source_times": {"trace": 1.0, "geo": 1.0}}
        reference_value = reference(self.config)
        reference_value["netcoffee_lookup"] = {"status":"complete","httpStatus":200,"query":"1.1.1.1","finishedAt":1.0,
            "data":{"ip":"1.1.1.1","asn":13335,"asOrganization":"Cloudflare"}}
        self.system.egress_reference = lambda _config: copy.deepcopy(reference_value)
        responses = iter([("", 403), ("", 401), ('{"data":{"located_resources":[{"resource":"13335","location":"US"}]}}', 200)])
        self.system.fetch = lambda *args, **kwargs: next(responses)
        with patch("watch_switcher.stun.probe", return_value={"complete": True, "observations": []}):
            value = self.system.online(self.config)
        self.assertEqual((value["claude"], value["api"]), (403, 401))
        self.assertNotIn("claude", value["query_errors"])
        self.assertNotIn("api", value["query_errors"])
        self.assertEqual(value["service_responses"]["claude"]["status"], "warn")
        self.assertEqual(value["service_responses"]["api"]["access"], "authentication_required")
        self.assertIn("asn", value["source_times"])

    def test_ripe_empty_200_is_not_cached_as_a_registration_success(self):
        self.system.fetch = lambda url, *_args, **_kwargs: ('{"data":{"located_resources":[]}}', 200)
        value = self.system.ripe_asn_lookup(2516, self.config)
        self.assertNotEqual(value["status"], "complete")

    def test_asn_reports_netcoffee_upstream_failure_without_claiming_ripe_failure(self):
        self.system.egress_reference = lambda _config: {"errors": ["netcoffee"],
            "query_errors": {"netcoffee": {"code": "timeout", "message": "请求超时", "source": "Net.Coffee lookup", "queried_at": 1.0}},
            "source_times": {}}
        def fetch(url, *_args, **_kwargs):
            if "stat.ripe.net" in url:
                raise AssertionError("RIPE must not run")
            return "", 403 if "claude.ai" in url else 401
        self.system.fetch = fetch
        with patch("watch_switcher.stun.probe", return_value={"complete": True, "observations": []}):
            value = self.system.online(self.config)
        error = value["query_errors"]["asn"]
        self.assertEqual(error["code"], "asn_upstream_lookup_unavailable")
        self.assertIn("Net.Coffee", error["message"])
        self.assertNotIn("RIPE", error["message"])

    def test_missing_netcoffee_timezone_keeps_valid_ip_and_country(self):
        responses = iter([self.reply('ip=8.8.8.8\nloc=JP')])
        self.system.run = lambda *args, **kwargs: next(responses)
        lookup = {"status":"complete","httpStatus":200,"query":"8.8.8.8","queriedAt":1.0,"finishedAt":1.0,
                  "data":{"ip":"8.8.8.8","countryCode":"jp"}}
        with patch("netcoffee_client.request", return_value=lookup) as request:
            value = self.system.egress_reference(self.config)
        self.assertEqual(value['geo']['country'], 'JP')
        self.assertNotIn('geo', value['query_errors'])
        self.assertEqual(request.call_args.kwargs['cache_dir'], self.system.paths.watch / 'observations')

    def test_process_deadline_is_reported_as_query_timeout(self):
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('curl', 10)):
            with self.assertRaises(SwitcherError) as raised:
                self.system.fetch('https://example.invalid', self.config)
        self.assertEqual(raised.exception.code, 'timeout')

    def test_malformed_netcoffee_country_uses_ipinfo_only_as_a_fallback(self):
        responses = iter([self.reply('ip=8.8.8.8\nloc=jp'), self.reply('{"ip":"8.8.8.8","country":"JP","timezone":"Asia/Tokyo"}')])
        self.system.run = lambda *args, **kwargs: next(responses)
        lookup = {"status":"complete","httpStatus":200,"query":"8.8.8.8","queriedAt":1.0,"finishedAt":1.0,
                  "data":{"ip":"8.8.8.8","countryCode":"Japan"}}
        with patch("netcoffee_client.request", return_value=lookup):
            value = self.system.egress_reference(self.config)
        self.assertEqual(value['trace']['loc'], 'JP')
        self.assertEqual(value['geo']['country'], 'JP')


if __name__ == "__main__":
    unittest.main()
