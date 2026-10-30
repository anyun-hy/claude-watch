"""Offline contracts for the shared IPLeak DNS-leak receipt."""
import copy
import json
import io
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from watch_switcher.audit import (dns_receipt_status, evaluate, record_dns_leak)
from watch_switcher.common import DEFAULT_CONFIG, Paths
from watch_switcher.system import asn_organization, asn_number, parse_ripe_asn_country
import switcher as runtime


class ReceiptSystem:
    def __init__(self, address="222.10.87.169", country="JP"):
        self.address, self.country = address, country
        self.local_value = {"context": "stable", "proxy": "ok", "mode": "tag", "tun": "ok",
                            "timezone": "Asia/Tokyo", "locale": "ja_JP", "ipv6": "ok",
                            "language": '("en-JP")', "guard": True,
                            "date_format": {"state": "available", "configured_locale": "ja_JP",
                            "patterns": {"short": "y/MM/dd", "medium": "y/MM/dd", "long": "y年M月d日"},
                            "reference_patterns": {"ja_JP": {"short": "y/MM/dd", "medium": "y/MM/dd", "long": "y年M月d日"}},
                            "short_sample": "2026/10/23", "reference_samples": {"ja_JP": "2026/10/23"}}}

    def local(self, _config):
        return copy.deepcopy(self.local_value)

    def egress_reference(self, _config):
        return {"trace": {"ip": self.address, "loc": self.country},
                "geo": {"ip": self.address, "country": self.country, "timezone": "Asia/Tokyo"}}


def probe(now, dns_country="jp", *, status="complete", errors=None, changed=False):
    observations = [
        {"address": "222.10.87.169", "kind": "http", "source": "fixture", "family": 4},
        {"address": "8.8.8.8", "kind": "resolver", "source": "fixture", "family": 4},
    ]
    records = {"session": "a" * 40, "dns_servers": {"8.8.8.8": 5},
               "http": {"address": "222.10.87.169", "country": "jp"},
               "geoip": [{"ip": "8.8.8.8", "country_code": dns_country}]}
    return {"kind": "dns", "status": status, "startedAt": now - 2, "finishedAt": now,
            "scope": "fixture", "observations": observations, "errors": errors or [],
            "contextChanged": changed, "externalJSON": json.dumps(records)}


class DNSReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dns-receipt-")
        self.addCleanup(self.temp.cleanup)
        home = Path(self.temp.name) / "home"; home.mkdir()
        self.paths = Paths(home); self.system = ReceiptSystem()
        self.config = dict(DEFAULT_CONFIG, enabled=True, country="JP", timezone="Asia/Tokyo",
                           locale="ja_JP", online_enabled=True, guard_enabled=True)

    def test_lowercase_ipleak_country_codes_make_one_shared_passing_receipt(self):
        now = time.time()
        receipt = record_dns_leak(self.paths, self.system, probe(now), now=now + 1)
        self.assertEqual(receipt["comparison"]["state"], "ok")
        display = dns_receipt_status(self.paths, "stable", now=now + 2)
        launch = dns_receipt_status(self.paths, "stable", launch=True, now=now + 2)
        self.assertEqual((display["state"], launch["state"]), ("ok", "ok"))
        online = {"trace": {"ip": "222.10.87.169", "loc": "JP"},
                  "geo": {"ip": "222.10.87.169", "country": "JP", "timezone": "Asia/Tokyo"},
                  "dns": launch, "stun": {"complete": True, "observations": [{"status": "ok", "address": "222.10.87.169"}]},
                  "claude": 403, "api": 401}
        rows = {row["id"]: row for row in evaluate(self.config, self.system.local(self.config), online, now=now + 2)["rows"]}
        self.assertEqual(rows["dns"]["state"], "ok")

    def test_foreign_country_stays_a_failure_even_when_same_sample_is_partial(self):
        now = time.time()
        result = record_dns_leak(self.paths, self.system, probe(now, "us", status="partial", errors=[{"stage": "geoip", "code": "timeout"}]), now=now + 1)
        self.assertEqual(result["comparison"]["state"], "fail")
        self.assertEqual(dns_receipt_status(self.paths, "stable", launch=True, now=now + 2)["state"], "fail")

    def test_incomplete_new_sample_replaces_old_pass_and_blocks_launch(self):
        now = time.time()
        previous = record_dns_leak(self.paths, self.system, probe(now), now=now + 1)
        record_dns_leak(self.paths, self.system, probe(now + 3, status="partial", errors=[{"stage": "dns", "code": "timeout"}]), now=now + 4)
        launch = dns_receipt_status(self.paths, "stable", launch=True, now=now + 5)
        display = dns_receipt_status(self.paths, "stable", now=now + 5)
        self.assertEqual(launch["state"], "unknown")
        self.assertEqual(display["receipt"]["comparison"]["state"], "unknown")
        self.assertEqual(display["display_receipt"]["finished_at"], previous["finished_at"])
        self.assertIn("dns / timeout", launch["detail"])

    def test_context_change_replaces_old_pass_and_blocks_launch(self):
        now = time.time()
        record_dns_leak(self.paths, self.system, probe(now), now=now + 1)
        record_dns_leak(self.paths, self.system, probe(now + 3, changed=True), now=now + 4)
        status = dns_receipt_status(self.paths, "stable", launch=True, now=now + 5)
        self.assertEqual(status["state"], "unknown")
        self.assertEqual(status["display_receipt"]["comparison"]["reason"], "context_changed")

    def test_empty_new_sample_replaces_old_pass_and_blocks_launch(self):
        now = time.time()
        record_dns_leak(self.paths, self.system, probe(now), now=now + 1)
        failed = probe(now + 3, status="error", errors=[{"stage": "dns", "code": "empty"}])
        failed["observations"] = []
        record_dns_leak(self.paths, self.system, failed, now=now + 4)
        self.assertEqual(dns_receipt_status(self.paths, "stable", launch=True, now=now + 5)["state"], "unknown")

    def test_foreign_latest_receipt_never_falls_back_to_last_valid_for_display(self):
        now = time.time()
        previous = record_dns_leak(self.paths, self.system, probe(now), now=now + 1)
        foreign = record_dns_leak(self.paths, self.system, probe(now + 3, "us"), now=now + 4)
        status = dns_receipt_status(self.paths, "stable", now=now + 5)
        self.assertEqual(status["state"], "fail")
        self.assertEqual(status["receipt"]["finished_at"], foreign["finished_at"])
        self.assertNotEqual(status["display_receipt"]["finished_at"], previous["finished_at"])

    def test_dns_pass_does_not_depend_on_a_separate_ipinfo_round(self):
        now = time.time()
        record_dns_leak(self.paths, self.system, probe(now), now=now + 1)
        dns = dns_receipt_status(self.paths, "stable", launch=True, now=now + 2)
        online = {"trace": {}, "geo": {}, "dns": dns,
                  "stun": {"complete": True, "observations": [{"status": "ok", "address": "222.10.87.169"}]},
                  "claude": 403, "api": 401}
        rows = {row["id"]: row for row in evaluate(self.config, self.system.local(self.config), online, now=now + 2)["rows"]}
        self.assertEqual(rows["dns"]["state"], "ok")
        self.assertEqual(rows["egress"]["state"], "unknown")

    def test_timeout_receipt_is_a_successful_record_command_but_blocks_launch(self):
        now = time.time()
        failed = probe(now, status="timeout", errors=[{"stage": "dns", "code": "timeout"}])
        args = runtime.parser().parse_args(["dns-leak-record", "--apply"])
        with patch.object(runtime.sys, "stdin", io.StringIO(json.dumps({"probe": failed}))):
            result = runtime.dispatch(args, self.paths, self.system)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["receipt"]["status"], "timeout")
        self.assertEqual(result["dns_row"]["id"], "dns")
        self.assertEqual(result["dns_row"]["state"], "unknown")
        self.assertEqual(dns_receipt_status(self.paths, "stable", launch=True, now=now + 1)["state"], "unknown")

    def test_receipt_cannot_be_renewed_by_re_recording_old_probe(self):
        now = time.time()
        record_dns_leak(self.paths, self.system, probe(now), now=now + 1)
        self.assertEqual(dns_receipt_status(self.paths, "stable", launch=True, now=now + 31)["state"], "unknown")
        self.assertEqual(dns_receipt_status(self.paths, "stable", now=now + 31)["state"], "ok")

    def test_expired_last_valid_remains_display_only_after_a_query_failure(self):
        now = 1_792_739_000.0
        record_dns_leak(self.paths, self.system, probe(now), now=now + 1)
        record_dns_leak(self.paths, self.system,
                        probe(now + 3, status="timeout", errors=[{"stage": "dns", "code": "timeout"}]), now=now + 4)
        status = dns_receipt_status(self.paths, "stable", launch=True, now=now + 305)
        self.assertEqual(status["state"], "unknown")
        self.assertTrue(status["display_cached"])
        self.assertTrue(status["last_valid"]["expired"])
        self.assertEqual(status["display_receipt"]["comparison"]["state"], "ok")

    def test_ripe_country_requires_exact_asn_and_does_not_use_ip_geo_country(self):
        body = json.dumps({"data": {"result_time": "2026-10-21T00:00:00", "located_resources": [
            {"resource": "2516", "location": "JP"}, {"resource": "AS999", "location": "US"}]}})
        self.assertEqual(parse_ripe_asn_country(body, 2516), {"registered_country": "JP", "result_time": "2026-10-21T00:00:00"})
        self.assertEqual(parse_ripe_asn_country(body, 999), {"registered_country": "US", "result_time": "2026-10-21T00:00:00"})
        self.assertEqual(parse_ripe_asn_country(body, 13335), {})

    def test_asn_organization_does_not_repeat_the_rendered_asn(self):
        geo = {"org": "AS2516 KDDI CORPORATION"}
        self.assertEqual(asn_number(geo), 2516)
        self.assertEqual(asn_organization(geo, 2516), "KDDI CORPORATION")
        self.assertEqual(asn_organization({"org": "KDDI CORPORATION"}, 2516), "KDDI CORPORATION")


if __name__ == "__main__":
    unittest.main()
