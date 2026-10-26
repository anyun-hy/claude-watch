"""Independent observation-to-launch contracts for sampling and preview boundaries."""
import copy
import json
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Resources"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_switcher import Fixture, FakeSystem
from test_onboarding import SetupSystem
from watch_switcher import onboarding
from watch_switcher.audit import audit, dns_receipt_path, policy_digest, record_dns_leak, record_webrtc_risk, require_ready
from watch_switcher.automatic_policy import session_risk, extract_risks
from watch_switcher.common import SwitcherError, atomic_json, digest, load_config, read_json, save_config
from watch_switcher.system import System


class SequenceSystem(FakeSystem):
    def __init__(self, before, after):
        super().__init__()
        self.samples = [copy.deepcopy(before), copy.deepcopy(after)]
        self.local_value = copy.deepcopy(after)

    def local(self, _config, **_kwargs):
        return copy.deepcopy(self.samples.pop(0) if self.samples else self.local_value)


class ObservationContractTests(Fixture):
    def setUp(self):
        super().setUp()
        self.config["expected_resolvers"] = []
        self.write_dns("stable")

    def write_dns(self, context):
        now = time.time()
        atomic_json(dns_receipt_path(self.paths), {
            "schema": 1, "status": "complete", "context": context,
            "finished_at": now, "recorded_at": now,
            "display_expires_at": now + 300, "launch_expires_at": now + 30,
            "comparison": {"state": "ok", "detail": "fixture"},
        })

    def local(self):
        value = copy.deepcopy(self.system.local_value)
        value["network_identity"] = {"mode": "tag", "entry": "127.0.0.1:7890", "tun": "utun4"}
        value["context_id"] = "stable"
        return value

    def test_native_process_order_is_stable_but_pid_reuse_changes_identity(self):
        system = System(self.paths)
        processes = [{"pid": n, "uid": 501, "executable": "/Applications/Surge.app/Contents/MacOS/Surge",
                      "start_seconds": 100, "start_microseconds": 20} for n in (901, 902)]
        system.proxy_processes = lambda: copy.deepcopy(processes)
        system.guard_status = lambda _: True
        system.regional_status = lambda: copy.deepcopy(self.system.local_value["date_format"])
        def optional(argv):
            if argv[0] == "/sbin/ifconfig": return "utun4: flags\n    inet 198.18.0.1\n"
            if argv[0] == "/sbin/route": return "interface: utun4"
            if argv[0] == "/usr/sbin/networksetup": return "IPv6: Off"
            if argv[0] == "/usr/bin/readlink": return "/var/db/timezone/zoneinfo/Asia/Tokyo"
            if argv[-1] == "AppleLocale": return "ja_JP"
            if argv[-1] == "AppleLanguages": return '("en-JP")'
            return ""
        system.optional = optional
        config = dict(self.config, proxy_mode="surge")
        initial = system.local(config)["context_id"]
        processes.reverse()
        self.assertEqual(system.local(config)["context_id"], initial)
        processes[0]["start_seconds"] += 1
        self.assertNotEqual(system.local(config)["context_id"], initial)

    def test_sampling_unavailable_after_same_identity_blocks_and_persists_transition(self):
        before = self.local()
        after = self.local(); after["observation_unavailable"] = ["proxy_sampling"]
        self.system = SequenceSystem(before, after)
        save_config(self.paths, self.config)
        result = audit(self.paths, self.system, self.config, online=True, persist=True)
        self.assertEqual(result["context_transition"]["state"], "sampling_unavailable")
        self.assertFalse(result["ready"])
        self.assertTrue(result["blocked"])
        saved = read_json(self.paths.base / "last-audit.json")
        self.assertEqual(saved["context_transition"], result["context_transition"])

    def test_sampling_failure_recovers_without_clearing_timezone(self):
        healthy_before = self.local()
        self.system = SequenceSystem(healthy_before, copy.deepcopy(healthy_before))
        save_config(self.paths, self.config)
        first = audit(self.paths, self.system, self.config, online=True, persist=False)
        self.assertTrue(first["ready"])

        before = copy.deepcopy(healthy_before)
        after = self.local(); after["observation_unavailable"] = ["proxy_sampling"]
        self.system = SequenceSystem(before, after)
        failed = audit(self.paths, self.system, self.config, online=True, persist=False)
        failed_rows = {row["id"]: row for row in failed["rows"]}
        self.assertFalse(failed["ready"])
        self.assertNotEqual(failed_rows["timezone"]["state"], "unknown")

        recovered_before = copy.deepcopy(healthy_before)
        self.system = SequenceSystem(recovered_before, copy.deepcopy(recovered_before))
        recovered = audit(self.paths, self.system, self.config, online=True, persist=False)
        self.assertEqual(recovered["context_transition"]["state"], "stable")
        self.assertTrue(recovered["ready"])

    def test_after_guard_failure_blocks_without_erasing_known_local_rows(self):
        before = self.local()
        after = self.local(); after["guard"] = False
        self.system = SequenceSystem(before, after)
        save_config(self.paths, self.config)
        result = audit(self.paths, self.system, self.config, online=True, persist=False)
        rows = {row["id"]: row for row in result["rows"]}
        self.assertFalse(result["ready"])
        self.assertIn("guard", result["blocked"])
        self.assertNotEqual(rows["timezone"]["state"], "unknown")
        self.assertNotEqual(rows["locale"]["state"], "unknown")

    def test_known_timezone_locale_and_date_format_change_remains_blocked(self):
        before = self.local()
        after = self.local(); after.update(timezone="Europe/London", locale="en_GB")
        after["date_format"] = copy.deepcopy(after["date_format"])
        after["date_format"]["configured_locale"] = "en_GB"
        self.system = SequenceSystem(before, after)
        save_config(self.paths, self.config)
        result = audit(self.paths, self.system, self.config, online=True, persist=False)
        self.assertEqual(result["context_transition"]["state"], "changed")
        self.assertTrue({"timezone", "locale", "date_format"} <= set(result["context_transition"]["changed_fields"]))
        self.assertFalse(result["ready"])
        self.assertTrue(set(result["blocked"]))

    def test_actual_tag_node_change_is_a_transition_and_blocks(self):
        before = self.local()
        before["network_identity"]["selection"] = {"mode": "rule", "selected_node": "Japan 1", "global_node": None}
        after = copy.deepcopy(before)
        after["network_identity"]["selection"]["selected_node"] = "Japan 2"
        self.system = SequenceSystem(before, after)
        save_config(self.paths, self.config)
        result = audit(self.paths, self.system, self.config, online=True, persist=False)
        self.assertEqual(result["context_transition"]["state"], "changed")
        self.assertIn("selection", result["context_transition"]["changed_fields"])
        self.assertFalse(result["ready"])

    def test_environment_policy_evaluation_binds_to_same_observation(self):
        self.system = SetupSystem()
        save_config(self.paths, self.config)
        receipt = onboarding.observe(self.paths, self.system, online=True, persist=True)
        policy = receipt["policy_evaluation"]
        self.assertIsInstance(policy, dict)
        for key in ("observation_id", "context_id", "observed_at", "expires_at"):
            self.assertEqual(policy.get(key), receipt.get(key), key)
        self.assertEqual(self.system.calls.count("online"), 1)

    def test_auto_probe_parameters_do_not_change_actual_guard_policy_hash(self):
        self.system = SetupSystem()
        save_config(self.paths, self.config)
        self.system.guard_status = lambda cfg: digest(cfg) == digest(self.config)
        original_local = self.system.local
        seen = []
        def local(cfg, **kwargs):
            seen.append(copy.deepcopy(cfg))
            result = original_local(cfg, **kwargs)
            result["guard"] = self.system.guard_status(cfg)
            return result
        self.system.local = local
        receipt = audit(self.paths, self.system, self.config, online=True, persist=False)
        self.assertEqual(next(row for row in receipt["rows"] if row["id"] == "guard")["state"], "ok")
        self.assertTrue(receipt["ready"])
        self.assertTrue(all(cfg["proxy_mode"] == "auto" and cfg["network_service"] == "Ethernet" for cfg in seen))

    def test_launch_audit_rejects_actual_active_service_change(self):
        self.system = SetupSystem()
        save_config(self.paths, self.config)
        original_online = self.system.online
        def change(cfg):
            result = original_online(cfg)
            self.system.network["service"] = "Wi-Fi"
            self.system.network["interface"] = "en1"
            return result
        self.system.online = change
        receipt = audit(self.paths, self.system, self.config, online=True, persist=False)
        self.assertFalse(receipt["ready"])
        self.assertEqual(receipt["context_transition"]["state"], "changed")
        self.assertIn("network_service", receipt["context_transition"]["changed_fields"])

    def test_environment_policy_preview_auto_detects_client_without_a_second_probe(self):
        self.system = SetupSystem()
        saved = dict(self.config, proxy_mode="clash-verge")
        save_config(self.paths, saved)
        receipt = onboarding.observe(self.paths, self.system, online=True, persist=False)
        policy = receipt["policy_evaluation"]
        rows = {row["id"]: row for row in policy["rows"]}
        self.assertEqual(policy["policy"], policy_digest(load_config(self.paths)))
        self.assertEqual(rows["proxy"]["state"], "ok")
        self.assertTrue(policy["ready"])
        self.assertFalse(policy["grants_launch_permission"])
        self.assertEqual(self.system.calls.count("online"), 1)

    def test_preview_cannot_license_require_ready_after_current_state_changes(self):
        self.system = SetupSystem()
        save_config(self.paths, self.config)
        candidate = onboarding.detect(self.paths, self.system, online=True)
        options = dict(apply_environment=True, enable_policy=True, guard_enabled=False,
                       timezone_watchdog=False, auto_update=False)
        onboarding.preview(self.paths, self.system, candidate["id"], options)
        self.system.local_value["tun"] = "fail"
        with self.assertRaises(SwitcherError) as raised:
            require_ready(self.paths, self.system, self.config)
        self.assertEqual(raised.exception.code, "preflight_blocked")

    def test_late_dns_context_mismatch_is_rejected_without_replacing_existing_receipt(self):
        self.system.local_value["tag"] = {
            "entry": {"endpoint": "http://127.0.0.1:7890"},
            "api": {"mode": "rule", "selected_node": "Japan 1", "global_node": ""},
        }
        before = read_json(dns_receipt_path(self.paths))
        now = time.time()
        probe = {
            "kind": "dns", "status": "complete", "contextChanged": False,
            "startedAt": now - 1, "finishedAt": now, "errors": [],
            "observations": [{"kind": "resolver", "address": "8.8.8.8"},
                             {"kind": "http", "address": "8.8.8.8"}],
            "externalJSON": json.dumps([
                {"kind": "geoip", "status": "complete", "query": "8.8.8.8", "data": {"country_code": "jp"}},
            ]),
        }
        with self.assertRaises(SwitcherError) as raised:
            record_dns_leak(self.paths, self.system, probe, now=now + 1,
                            expected_context="http://127.0.0.1:7890|rule|Japan 2|")
        self.assertEqual(raised.exception.code, "dns_context_changed")
        self.assertEqual(read_json(dns_receipt_path(self.paths)), before)

    def webrtc_probe(self, now, country="JP"):
        return {"kind":"webrtc","status":"complete","contextChanged":False,"startedAt":now-2,"finishedAt":now,
                "errors":[],"observations":[{"kind":"srflx","address":"8.8.8.8","country":country}]}

    def test_webrtc_producer_consumer_cn_and_context_bound(self):
        now=time.time(); receipt=record_webrtc_risk(self.paths,self.system,self.webrtc_probe(now,"CN"),now=now+1)
        self.assertEqual(receipt["risk"]["state"],"fail")
        self.assertEqual(session_risk(self.paths,"stable")["state"],"risk")
        self.system.local_value["context"]="new"
        self.assertEqual(session_risk(self.paths,"new")["state"],"unknown")

    def test_webrtc_rejects_future_delayed_nan_and_context_changed(self):
        now=time.time()
        for mutate in (lambda p:p.update(finishedAt=now+10),lambda p:p.update(finishedAt=float("nan")),lambda p:p.update(finishedAt=now-100),lambda p:p.update(contextChanged=True)):
            probe=self.webrtc_probe(now); mutate(probe)
            with self.assertRaises(SwitcherError): record_webrtc_risk(self.paths,self.system,probe,now=now)

    def test_extract_risks_uses_real_dns_receipt_schema_and_old_asn_is_ignored(self):
        now=time.time(); probe={"kind":"dns","status":"complete","contextChanged":False,"startedAt":now-2,"finishedAt":now,"errors":[],
          "observations":[{"kind":"resolver","address":"8.8.8.8"},{"kind":"http","address":"8.8.8.8"}],
          "externalJSON":json.dumps([{"kind":"geoip","status":"complete","query":"8.8.8.8","data":{"country_code":"cn"}}])}
        record_dns_leak(self.paths,self.system,probe,now=now+1)
        online=copy.deepcopy(self.system.online_value); online["dns"]={"receipt":read_json(dns_receipt_path(self.paths))}; online["asn"]={"registered_country":"CN"}; online["netcoffee_lookup"]={"data":{"ip":"1.1.1.1"}}
        ids=[x["id"] for x in extract_risks(online)["risks"]]
        self.assertIn("cn_dns",ids); self.assertNotIn("cn_asn_registration",ids)


if __name__ == "__main__":
    unittest.main()
