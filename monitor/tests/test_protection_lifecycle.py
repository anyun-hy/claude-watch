"""Real entry/gate/session/receipt lifecycle with a fake OS and temporary HOME.

No network, application launch, user settings, or live account files are used.
"""
import copy
import io
import json
import os
import subprocess
import time
from unittest.mock import patch

from test_switcher import Fixture
from test_onboarding import SetupSystem
from test_dns_receipt import probe as dns_probe
import switcher as runtime
from watch_switcher.audit import record_dns_leak, record_webrtc_risk, require_ready
from watch_switcher.accounts import AccountStore
from watch_switcher.onboarding import observe
from watch_switcher.common import SwitcherError, load_config, read_json, save_config
from watch_switcher.services import guard_tick, service_status, protection_preview
from watch_switcher.system import System


class LifecycleSystem(SetupSystem, System):
    launch_claude = System.launch_claude
    _launch_claude = System._launch_claude
    _write_claude_session = System._write_claude_session
    _process_start_stamp = System._process_start_stamp

    def __init__(self):
        super().__init__()
        self.address = "222.10.87.169"
        self.country = "JP"
        self.failed_sample = False
        self.desktop = dict(pid=901, desktop_main=True, start_seconds=1234, start_microseconds=5)
        self.local_value["context_id"] = "stable"
        self.set_online(self.address)

    def set_online(self, address):
        self.online_value["trace"] = dict(ip=address, loc="JP")
        self.online_value["geo"].update(ip=address, country="JP")
        self.online_value["stun"] = dict(complete=True, observations=[dict(status="ok", address=address)])

    def guard_egress(self, config):
        self.calls.append("fast-egress")
        if self.failed_sample: return dict(state="unknown", error="timeout", observed_at=time.time())
        return dict(ip=self.address, country=self.country, observed_at=time.time(), source="isolated HTTP")

    def session_desktop_matches(self, identity):
        return self.running and all(identity.get(k) == self.desktop[k] for k in ("pid", "start_seconds", "start_microseconds"))

    def process_helper(self, action, *args):
        if action == "desktop-status": return dict(status="ok", processes=[copy.deepcopy(self.desktop)] if self.running else [])
        raise AssertionError("Unexpected native operation: " + action)

    def run(self, argv, *args, **kwargs):
        self.calls.append(argv)
        if argv[:3] == ["/usr/bin/open", "-a", "Claude"]:
            self.running = True
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:2] == ["/bin/ps", "-p"]:
            return subprocess.CompletedProcess(argv, 0, "Sun Oct 25 12:00:00 2026\n", "")
        raise AssertionError("Unexpected OS operation: " + repr(argv))

    def service_job(self, name):
        return dict(registered=name == "original", trusted=True, last_exit=0, interval=10)


class ProtectionLifecycleTests(Fixture):
    def setUp(self):
        super().setUp()
        self.system = LifecycleSystem()
        self.system.paths = self.paths
        self.evidence()

    def evidence(self, *, country="jp", at=None):
        now = time.time() if at is None else at
        value = dns_probe(now, country)
        value["observations"][0]["address"] = self.system.address
        records = json.loads(value["externalJSON"])
        records[0]["query"] = self.system.address
        value["externalJSON"] = json.dumps(records)
        record_dns_leak(self.paths, self.system, value, now=now)
        record_webrtc_risk(self.paths, self.system, dict(kind="webrtc", status="complete", startedAt=now-1,
            finishedAt=now, contextChanged=False, errors=[], observations=[
                dict(kind="http", address=self.system.address, country="JP"),
                dict(kind="srflx", address=self.system.address, country="JP")]), now=now)

    def launch(self):
        # These lifecycle contracts explicitly opt in to protection. Fresh
        # product defaults intentionally keep the setting disabled.
        save_config(self.paths, dict(self.config, enabled=True, online_enabled=True, guard_enabled=True))
        return runtime.dispatch(runtime.parser().parse_args(["launch", "--apply"]), self.paths, self.system)

    def state(self): return read_json(self.paths.base / "session-guard.json", {})

    def tick(self): return guard_tick(self.paths, self.system)

    def test_clean_install_launch_uses_one_full_gate_without_target_configuration(self):
        self.assertFalse(self.paths.config.exists())
        self.launch()
        self.assertEqual(self.state()["state"], "active")
        self.assertEqual(self.state()["baseline"]["ip"], self.system.address)
        self.assertEqual(self.system.calls.count("online"), 1)
        self.assertEqual(len(list((self.paths.watch / "state/sessions").glob("*.session"))), 1)
        self.assertTrue(self.paths.config.exists())

    def test_same_country_change_latches_until_explicit_fresh_launch(self):
        self.launch()
        session = self.state()["session_id"]
        baseline = copy.deepcopy(self.state()["baseline"])
        for _ in range(5):
            self.assertEqual(self.tick()["session_guard"]["state"], "safe")
            self.assertEqual(self.state()["baseline"], baseline)
        self.system.address = "8.8.4.4"
        stopped = self.tick()
        self.assertEqual(stopped["action"], "close-desktop")
        self.assertEqual(stopped["session_guard"]["reason"]["code"], "egress_ip_changed")
        self.assertFalse(self.system.running)
        self.system.set_online(self.system.address)
        display = observe(self.paths, self.system, online=True, persist=True)
        self.assertEqual(next(row for row in display["rows"] if row["id"] == "ip_history")["state"], "fail")
        self.assertIn("ip_history", display["policy_evaluation"]["blocked"])
        self.assertEqual(self.state()["baseline"], baseline)
        for _ in range(3):
            self.tick()
            self.assertEqual(self.state()["state"], "locked")
            self.assertEqual(service_status(self.paths, self.system, load_config(self.paths))["session_guard"]["state"], "locked")
        self.system.set_online(self.system.address)
        self.evidence()
        self.launch()
        self.assertNotEqual(self.state()["session_id"], session)
        self.assertEqual(self.state()["baseline"]["ip"], self.system.address)

    def test_cn_country_and_cn_dns_each_stop_a_running_session(self):
        for source in ("http", "dns"):
            with self.subTest(source=source):
                self.system.country = "JP"
                self.evidence()
                self.launch()
                if source == "http": self.system.country = "CN"
                else: self.evidence(country="cn")
                self.assertEqual(self.tick()["action"], "close-desktop")
                self.assertEqual(self.state()["state"], "locked")
                self.assertFalse(self.system.running)

    def test_query_failure_is_bounded_and_never_called_ip_change(self):
        self.launch()
        self.tick()
        self.system.failed_sample = True
        first = self.tick()
        self.assertEqual(first["action"], "observe")
        self.assertEqual(first["session_guard"]["state"], "unknown")
        second = self.tick()
        self.assertEqual(second["action"], "observe")
        with patch("watch_switcher.session_guard.time.time", return_value=time.time() + 16):
            third = self.tick()
        self.assertEqual(third["action"], "close-desktop")
        self.assertEqual(self.state()["reason"]["code"], "egress_unconfirmed")

    def test_transient_failure_and_recovery_agree_across_production_receipts(self):
        self.launch()
        self.tick()
        self.system.failed_sample = True
        self.tick()
        self.assertEqual(service_status(self.paths, self.system, load_config(self.paths))["session_guard"]["state"], "unknown")
        display = observe(self.paths, self.system, online=True, persist=True)
        self.assertEqual(display["session_guard"]["state"], "unknown")
        self.assertIn("guard", display["policy_evaluation"]["blocked"])
        self.system.failed_sample = False
        self.assertEqual(self.tick()["session_guard"]["state"], "safe")
        background = service_status(self.paths, self.system, load_config(self.paths))
        self.assertEqual(background["session_guard"]["state"], "safe")
        self.assertIsNone(background["session_guard"]["reason"])

    def test_clock_preview_uses_auto_detection_without_saved_target_or_prior_launch(self):
        observe(self.paths, self.system, online=True, persist=True)
        self.assertFalse((self.paths.base / "last-audit.json").exists())
        plan = protection_preview(self.paths, self.system, {"timezone_watchdog": True})
        self.assertEqual(plan["desired_config"]["timezone"], "Asia/Tokyo")
        self.assertEqual(plan["desired_config"]["country"], "JP")
        self.assertFalse(self.paths.config.exists())
        self.assertFalse(any(isinstance(call, tuple) and call[:1] == ("admin",) for call in self.system.calls))

    def test_stale_evidence_is_not_refreshed_by_fast_http_success(self):
        self.launch()
        self.tick()
        stale = time.time() + 301
        with patch("time.time", return_value=stale):
            self.assertEqual(self.tick()["action"], "close-desktop")
        self.assertEqual(self.state()["reason"]["code"], "evidence_expired")

    def test_change_between_full_gate_and_open_never_launches(self):
        self.system.address = "8.8.4.4"
        with self.assertRaises(SwitcherError) as error: self.launch()
        self.assertEqual(error.exception.code, "egress_changed")
        self.assertFalse(self.system.running)
        self.assertFalse(any(isinstance(x, list) and x[:1] == ["/usr/bin/open"] for x in self.system.calls))

    def test_fast_probe_preserves_rate_limit_reason_and_uses_system_route(self):
        native = System(self.paths)
        requests = []
        def limited(url, config, timeout=8):
            requests.append((url, config, timeout))
            return "rate limited", 429
        native.fetch = limited
        result = native.guard_egress(dict(load_config(self.paths), proxy_mode="tag", proxy_url="http://127.0.0.1:7890"))
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(len(requests), 2)
        self.assertIn("HTTP 429", result["error"])
        self.assertTrue(all(item[1]["proxy_url"] == "" and item[1]["proxy_mode"] == "auto" for item in requests))
        self.assertTrue(all(item["code"] == "http_429" for item in result["attempts"]))

    def test_whole_sampler_failure_is_bounded_without_inventing_ip_change(self):
        self.launch()
        with patch.object(self.system, "local", side_effect=SwitcherError("sample_unavailable", "进程采样超时")):
            self.assertEqual(self.tick()["action"], "observe")
            self.assertEqual(self.tick()["action"], "observe")
            with patch("watch_switcher.session_guard.time.time", return_value=time.time() + 16):
                self.assertEqual(self.tick()["action"], "close-desktop")
        self.assertEqual(self.state()["reason"]["code"], "guard_sampling_failed")
        self.assertIn("进程采样超时", self.state()["reason"]["detail"])

    def test_reused_process_identity_never_inherits_permission(self):
        self.launch()
        self.system.desktop["start_microseconds"] += 1
        self.assertEqual(self.tick()["action"], "close-desktop")
        self.assertEqual(self.state()["reason"]["code"], "session_identity_changed")

    def test_partial_dns_keeps_only_unexpired_previous_evidence(self):
        self.launch()
        self.tick()
        original_time = self.state()["risk_evidence"]["observed_at"]
        value = dns_probe(time.time(), status="partial", errors=[dict(stage="dns", code="timeout")])
        record_dns_leak(self.paths, self.system, value)
        for _ in range(3):
            self.assertEqual(self.tick()["action"], "observe")
            self.assertEqual(self.state()["risk_evidence"]["observed_at"], original_time)
        with patch("time.time", return_value=original_time + 301):
            self.assertEqual(self.tick()["action"], "close-desktop")
        self.assertEqual(self.state()["reason"]["code"], "evidence_expired")

    def test_webrtc_china_and_same_country_ip_mismatch_both_stop(self):
        for address, country in ((self.system.address, "CN"), ("8.8.4.4", "JP")):
            self.evidence()
            self.launch()
            now = time.time()
            record_webrtc_risk(self.paths, self.system, dict(kind="webrtc", status="complete", startedAt=now-1,
                finishedAt=now, contextChanged=False, errors=[], observations=[
                    dict(kind="http", address=self.system.address, country="JP"),
                    dict(kind="srflx", address=address, country=country)]))
            self.assertEqual(self.tick()["action"], "close-desktop")
            self.assertEqual(self.state()["state"], "locked")

    def test_shared_current_asn_risk_reaches_running_guard(self):
        self.launch()
        self.system.online_value["asn"] = dict(number=123, registered_country="CN", organization="fixture")
        self.system.online_value["netcoffee_lookup"] = dict(data=dict(ip=self.system.address))
        observation = observe(self.paths, self.system, online=True, persist=True)
        asn = next(row for row in observation["rows"] if row["id"] == "asn")
        self.assertEqual(asn["state"], "fail")
        self.assertEqual(self.tick()["action"], "close-desktop")
        self.assertEqual(self.state()["reason"]["code"], "cn_asn_registration")

    def test_account_data_rolls_back_if_final_launch_exit_changes(self):
        self.active("original")
        original = (self.paths.active / "Cookie-fixture.txt").read_text()
        def checkpoint(phase):
            if phase == "installed": self.system.address = "8.8.4.4"
        accounts = AccountStore(self.paths, self.system,
            lambda: require_ready(self.paths, self.system, load_config(self.paths)), checkpoint=checkpoint)
        with self.assertRaises(SwitcherError):
            accounts.switch("B", dict(load_config(self.paths), verified_claude_versions=["1.0.0"]))
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), original)
        self.assertFalse(self.system.running)

