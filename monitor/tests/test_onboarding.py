"""Setup acceptance and recovery using temporary homes and a simulated macOS."""
import copy
import json
import subprocess
import time
from unittest.mock import patch

from test_switcher import Fixture, FakeSystem
import switcher as runtime
from watch_switcher import onboarding as setup
from watch_switcher.common import SwitcherError, atomic_json, load_config, operation_lock, read_json, save_config
from watch_switcher.system import System


class SetupSystem(FakeSystem):
    def __init__(self):
        super().__init__()
        owner = dict(pid=42, uid=0, executable="/Applications/TAG.app/Contents/Resources/bin/mihomo",
                     stamp="Fri Oct 23 09:00:00 2026")
        self.local_value.update(app_language=None, system_language='("en-JP")', candidates=["tag"],
            processes=[dict(owner, start_stamp=owner["stamp"])],
            tag=dict(expected_group="AI", entry=dict(state="verified", owners=[owner], public_listener=False),
                     api=dict(state="available", covers_7890=True, mode="rule", selected_node="Japan 1")))
        self.network = dict(service="Ethernet", interface="en0", services=["Ethernet", "Wi-Fi"], source="scutil PrimaryService")
        self.watchdog = None
        self.fail_baseline = False
        self.conflict_on_failure = False
        self.ipv6 = "Off"

    def network_environment(self): return copy.deepcopy(self.network)
    def egress_reference(self, config):
        self.calls.append(("egress_reference", copy.deepcopy(config)))
        geo=copy.deepcopy(self.online_value["geo"]); geo.setdefault("timezone_source", "Net.Coffee lookup"); geo.setdefault("country_source", "Net.Coffee lookup")
        return dict(trace=copy.deepcopy(self.online_value["trace"]), geo=geo,
                    errors=[], query_errors={}, source_times={"trace": 1.0, "geo": 1.0},
                    netcoffee_lookup={"status":"complete","sourceURL":"https://ip.net.coffee/api/ip/lookup/8.8.8.8"})
    def guard_status(self, config): return bool(config["guard_enabled"] and self.local_value.get("guard"))
    def watchdog_state(self): return dict(target=self.watchdog, registered=bool(self.watchdog), last_success=None)
    def fetch(self, url, config):
        self.calls.append(("fetch", url, copy.deepcopy(config)))
        if "ipinfo" in url: return json.dumps(self.online_value["geo"]), 200
        trace = self.online_value["trace"]
        return "ip=" + trace["ip"] + "\nloc=" + trace["loc"] + "\n", 200
    def optional(self, argv):
        if "-getinfo" in argv: return "IPv6: " + self.ipv6
        return self.local_value["locale"]
    def admin(self, verb, *args):
        self.calls.append(("admin", verb, *args))
        if verb == "timezone": self.local_value["timezone"] = args[0]
        elif verb == "watchdog": self.watchdog = None if args[0] == "off" else args[0]
        elif verb == "ipv6":
            self.ipv6 = "Off" if args[1] == "off" else "Automatic"
            self.local_value["ipv6"] = "ok" if self.ipv6 == "Off" else "fail"
    def run(self, argv, *args, **kwargs):
        self.calls.append(argv)
        if argv[:3] == ["/usr/bin/defaults", "write", "-g"]:
            self.local_value["locale"] = argv[-1]
            self.local_value["date_format"]["configured_locale"] = argv[-1]
            patterns = self.local_value["date_format"]["reference_patterns"].get(argv[-1])
            if patterns: self.local_value["date_format"]["patterns"] = copy.deepcopy(patterns)
        elif "AppleLanguages" in argv:
            self.local_value["app_language"] = None if argv[1] == "delete" else "(" + ", ".join(argv[5:]) + ")"
            self.local_value["language"] = self.local_value["app_language"] or self.local_value["system_language"]
        return subprocess.CompletedProcess(argv, 0, "", "")
    def baseline_data(self):
        if self.fail_baseline:
            if self.conflict_on_failure: self.local_value["timezone"] = "Europe/London"
            raise SwitcherError("baseline_incomplete", "fixture baseline failed")
        return "format=2\nonline=no\ntimezone=" + self.local_value["timezone"] + "\nipv4_route=en0\n"


class OnboardingTests(Fixture):
    def setUp(self):
        super().setUp()
        self.system = SetupSystem()
        self.options = dict(apply_environment=True, enable_policy=True, guard_enabled=False,
                            timezone_watchdog=False, auto_update=False)
    def detect(self): return setup.detect(self.paths, self.system, online=True)
    def plan(self, candidate=None): return setup.preview(self.paths, self.system, (candidate or self.detect())["id"], self.options)
    def apply(self, plan): return setup.apply(self.paths, self.system, plan["candidate_id"], self.options, plan["id"])

    def test_first_local_discovery_has_no_writes_network_or_default_service(self):
        result = setup.inspect(self.paths, self.system)
        rows = {r["id"]: r for r in result["rows"]}
        self.assertFalse(self.paths.watch.exists())
        self.assertFalse(result["initialized"])
        self.assertEqual(rows["network_service"]["current"], "Ethernet")
        self.assertEqual(rows["network_service"]["target"], "未配置")
        self.assertEqual(rows["country"]["current"], "未知")
        self.assertFalse(self.system.calls)

    def test_first_online_probe_does_not_require_saved_online_policy(self):
        result = self.detect()
        self.assertEqual(result["values"]["country"], "JP")
        self.assertEqual(result["values"]["locale"], "ja_JP")
        self.assertFalse(self.paths.config.exists())
        self.assertFalse((self.paths.watch / "state/baseline.conf").exists())
        cache = self.paths.base / "environment-candidate.json"
        self.assertEqual(cache.stat().st_mode & 0o777, 0o600)
        self.assertEqual([x[0] for x in self.system.calls], ["egress_reference"])
        self.assertEqual(self.system.calls[0][1]["proxy_url"], "")
        self.assertEqual(result["sources"]["country"], "Cloudflare trace + Net.Coffee lookup")
        self.assertNotIn("IPinfo", result["sources"]["timezone"])
        with self.assertRaises(SwitcherError): setup.detect(self.paths, self.system)

    def test_candidate_crosschecks_country_ip_and_timezone_without_fallback(self):
        for change in ({"ip": "1.1.1.1"}, {"country": "US"}, {"timezone": "Invalid/Nowhere"}):
            with self.subTest(change=change):
                self.system.online_value["geo"] = dict(ip="8.8.8.8", country="JP", timezone="Asia/Tokyo", **{})
                self.system.online_value["geo"].update(change)
                with self.assertRaises(SwitcherError): self.detect()
                self.assertFalse(self.paths.config.exists())
                self.assertFalse((self.paths.base / "environment-candidate.json").exists())

    def test_japanese_formats_do_not_force_japanese_interface_language(self):
        self.system.local_value.update(locale="en_US", language='("en-US")')
        self.assertEqual(self.detect()["values"]["locale"], "ja_JP")
        self.assertEqual(self.system.local_value["language"], '("en-US")')

    def test_global_tag_uses_actual_global_selector(self):
        self.system.local_value["tag"]["api"].update(mode="global", global_node="Global Japan")
        values = self.detect()["values"]
        self.assertEqual((values["proxy_group"], values["node"]), ("GLOBAL", "Global Japan"))

    def test_explicit_adaptation_can_accept_new_node_but_keeps_saved_target_until_confirm(self):
        save_config(self.paths, self.config)
        self.system.local_value["proxy"] = "fail"
        self.system.local_value["tag"]["selection_changed"] = True
        self.system.local_value["tag"]["api"]["selected_node"] = "Japan 2"
        self.assertEqual(self.detect()["values"]["node"], "Japan 2")
        self.assertEqual(load_config(self.paths), self.config)

    def test_unknown_service_tun_listener_or_api_never_issues_http(self):
        mutations = [lambda: self.system.network.update(service=None),
                     lambda: self.system.local_value.update(tun="unknown"),
                     lambda: self.system.local_value["tag"]["entry"].update(state="unconfirmed"),
                     lambda: self.system.local_value["tag"]["api"].update(covers_7890=False),
                     lambda: self.system.local_value["processes"].clear(),
                     lambda: self.system.local_value["tag"]["entry"].update(public_listener=True)]
        for mutate in mutations:
            self.system = SetupSystem(); mutate()
            with self.assertRaises(SwitcherError): self.detect()
            self.assertFalse(self.system.calls)

    def test_network_change_during_probe_rejects_candidate(self):
        original = self.system.egress_reference
        def change(*args):
            value = original(*args)
            self.system.local_value["context"] = "different"
            return value
        self.system.egress_reference = change
        with self.assertRaises(SwitcherError): self.detect()
        self.assertFalse((self.paths.base / "environment-candidate.json").exists())

    def test_expired_tampered_and_changed_candidates_are_rejected(self):
        candidate = self.detect()
        with patch.object(setup.time, "time", return_value=candidate["expires_at"] + 1):
            with self.assertRaises(SwitcherError): self.plan(candidate)
        self.system.local_value["timezone"] = "Europe/London"
        with self.assertRaises(SwitcherError): self.plan(candidate)
        self.system.local_value["timezone"] = "Asia/Tokyo"
        cache = read_json(self.paths.base / "environment-candidate.json")
        cache["values"]["country"] = "US"
        atomic_json(self.paths.base / "environment-candidate.json", cache)
        with self.assertRaises(SwitcherError): self.plan(candidate)

    def test_saved_policy_changes_require_new_detection(self):
        candidate = self.detect()
        save_config(self.paths, self.config)
        with self.assertRaises(SwitcherError): self.plan(candidate)

    def test_changed_choices_and_egress_require_new_preview(self):
        plan = self.plan()
        self.options["apply_environment"] = False
        with self.assertRaises(SwitcherError): self.apply(plan)
        self.options["apply_environment"] = True
        self.system.online_value["trace"]["ip"] = "1.1.1.1"
        self.system.online_value["geo"]["ip"] = "1.1.1.1"
        with self.assertRaises(SwitcherError): self.apply(plan)
        self.assertFalse(self.paths.config.exists())

    def test_success_commits_fixed_target_sources_and_core_baseline(self):
        plan = self.plan()
        self.assertEqual(plan["actions"], [])
        result = self.apply(plan)
        self.assertEqual(result["status"], "ok")
        config = load_config(self.paths)
        self.assertEqual((config["country"], config["locale"], config["network_service"]), ("JP", "ja_JP", "Ethernet"))
        self.assertTrue(config["enabled"] and config["online_enabled"])
        self.assertFalse(config["guard_enabled"] or config["auto_update"] or config["timezone_watchdog"])
        baseline = (self.paths.watch / "state/baseline.conf").read_text()
        self.assertIn("tag_group=AI\ntag_node=Japan 1", baseline)
        self.assertIn("online=no", baseline)  # GeoIP consent does not claim DNS/STUN sampling.
        self.assertFalse((self.paths.base / "setup-transaction.json").exists())
        rows = {r["id"]: r for r in setup.inspect(self.paths, self.system)["rows"]}
        self.assertEqual(rows["country"]["target"], "JP")
        self.assertEqual(rows["country"]["current"], "未知")
        self.assertIn("Net.Coffee", rows["country"]["target_source"])
        self.assertEqual(rows["node"]["target"], "Japan 1")
        self.system.online_value["trace"]["loc"] = "GB"
        self.system.online_value["geo"].update(country="GB", timezone="Europe/London")
        self.detect()
        self.assertEqual(load_config(self.paths)["country"], "JP")

    def test_protection_options_are_explicit_and_updater_requires_source(self):
        candidate = self.detect()
        self.options["auto_update"] = True
        with self.assertRaises(SwitcherError): self.plan(candidate)
        self.options["auto_update"] = False
        self.options["guard_enabled"] = True
        plan = self.plan(candidate)
        with self.assertRaises(SwitcherError): self.apply(plan)
        runtime = self.paths.watch / "runtime/switcher.py"
        runtime.parent.mkdir(); runtime.write_text("# fixture")
        self.apply(plan)
        self.assertTrue(load_config(self.paths)["guard_enabled"])

    def test_unchecked_system_changes_only_save_target(self):
        self.system.local_value.update(timezone="America/New_York", locale="en_US")
        self.options["apply_environment"] = False
        self.apply(self.plan())
        self.assertEqual(self.system.local_value["timezone"], "America/New_York")
        self.assertEqual(load_config(self.paths)["timezone"], "Asia/Tokyo")
        self.assertFalse(any(x[0] == "admin" for x in self.system.calls))

    def test_partial_failure_rolls_back_timezone_locale_language_and_ipv6(self):
        self.system.local_value.update(timezone="America/New_York", locale="zh_CN", language='("zh-Hans")',
                                       system_language='("zh-Hans")', ipv6="fail")
        self.system.ipv6 = "Automatic"
        self.system.fail_baseline = True
        with self.assertRaisesRegex(SwitcherError, "已恢复原设置"): self.apply(self.plan())
        self.assertEqual(self.system.local_value["timezone"], "America/New_York")
        self.assertEqual(self.system.local_value["locale"], "zh_CN")
        self.assertIsNone(self.system.local_value["app_language"])
        self.assertEqual(self.system.ipv6, "Automatic")
        self.assertFalse(self.paths.config.exists())
        self.assertFalse((self.paths.base / "setup-transaction.json").exists())

    def test_conflicting_external_change_is_preserved_and_blocks_new_writes(self):
        self.system.local_value.update(timezone="America/New_York")
        self.system.fail_baseline = True; self.system.conflict_on_failure = True
        result = self.apply(self.plan())
        self.assertEqual(result["status"], "partial")
        self.assertEqual(self.system.local_value["timezone"], "Europe/London")
        with self.assertRaises(SwitcherError): save_config(self.paths, self.config)
        self.system.local_value["timezone"] = "Asia/Tokyo"
        self.assertEqual(setup.recover(self.paths, self.system)["status"], "ok")
        self.assertEqual(self.system.local_value["timezone"], "America/New_York")

    def test_interruption_after_system_write_has_recoverable_pending_action(self):
        self.system.local_value["timezone"] = "America/New_York"
        plan = self.plan()
        original = self.system.admin
        def interrupted(*args):
            original(*args)
            raise KeyboardInterrupt()
        self.system.admin = interrupted
        with self.assertRaises(KeyboardInterrupt): self.apply(plan)
        self.assertTrue((self.paths.base / "setup-transaction.json").exists())
        with self.assertRaises(SwitcherError):
            with operation_lock(self.paths): pass
        self.system.admin = original
        setup.recover(self.paths, self.system)
        self.assertEqual(self.system.local_value["timezone"], "America/New_York")

    def test_unknown_transaction_is_not_executed(self):
        self.paths.initialize()
        atomic_json(self.paths.base / "setup-transaction.json", {"schema": 99})
        with self.assertRaises(SwitcherError): setup.recover(self.paths, self.system)
        self.assertFalse(self.system.calls)

    def test_commit_failure_restores_existing_config_baseline_and_provenance(self):
        save_config(self.paths, self.config)
        baseline = self.paths.watch / "state/baseline.conf"
        baseline.parent.mkdir(parents=True); baseline.write_text("old baseline\n")
        metadata = self.paths.base / "confirmed-environment.json"
        atomic_json(metadata, {"schema": 1, "note": "original provenance"})
        originals = {p: p.read_bytes() for p in (self.paths.config, baseline, metadata)}
        plan = self.plan()
        original = setup.atomic_text
        failed = False
        def fail_config(path, text, home):
            nonlocal failed
            if path == self.paths.config and not failed:
                failed = True
                raise OSError("isolated commit failure")
            return original(path, text, home)
        with patch.object(setup, "atomic_text", side_effect=fail_config):
            with self.assertRaises(SwitcherError): self.apply(plan)
        self.assertEqual({p: p.read_bytes() for p in originals}, originals)
        self.assertFalse((self.paths.base / "setup-transaction.json").exists())

    def test_app_language_array_and_watchdog_restore_after_failure(self):
        self.system.local_value.update(language='("ja-JP", "en-US")', app_language='("ja-JP", "en-US")')
        self.system.watchdog = "Europe/London"
        self.options["timezone_watchdog"] = True
        self.system.fail_baseline = True
        with self.assertRaises(SwitcherError): self.apply(self.plan())
        self.assertEqual(setup.language_array(self.system.local_value["app_language"]), ["ja-JP", "en-US"])
        self.assertEqual(self.system.watchdog, "Europe/London")

    def test_multiple_clients_require_an_explicit_selection(self):
        self.system.local_value.update(mode="", proxy="unknown", candidates=["tag", "surge"], tag={})
        result = setup.inspect(self.paths, self.system)
        self.assertEqual(result["candidates"], ["tag", "surge"])
        with self.assertRaises(SwitcherError): self.detect()
        self.assertFalse(self.system.calls)

    def test_old_manual_target_does_not_claim_detected_provenance(self):
        save_config(self.paths, self.config)
        result = setup.inspect(self.paths, self.system)
        self.assertIsNone(result["confirmed_at"])
        row = next(r for r in result["rows"] if r["id"] == "country")
        self.assertEqual(row["target"], "JP")
        self.assertIn("手动或旧版", row["target_source"])


class NetworkDiscoveryTests(Fixture):
    def test_dynamic_store_service_uuid_resolves_name_instead_of_wifi_default(self):
        system = System(self.paths)
        service = "11111111-1111-1111-1111-111111111111"
        system.optional = lambda argv: "An asterisk denotes disabled services.\nEthernet\nWi-Fi\n"
        def run(argv, **kwargs):
            text = "PrimaryService : " + service + "\nPrimaryInterface : en7" if "State:" in kwargs["input"] else "UserDefinedName : Ethernet"
            return subprocess.CompletedProcess(argv, 0, text, "")
        system.run = run
        self.assertEqual(system.network_environment()["service"], "Ethernet")
        system.run = lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "No such key", "")
        self.assertIsNone(system.network_environment()["service"])


class CurrentEnvironmentTests(Fixture):
    def setUp(self):
        super().setUp()
        self.system = SetupSystem()
    def observe(self, **kwargs): return setup.observe(self.paths, self.system, online=True, **kwargs)
    def row(self, receipt, key): return next(r for r in receipt["rows"] if r["id"] == key)

    def test_initialization_readback_uses_current_receipts_not_display_cache(self):
        dns = {"state": "unknown", "receipt": {"context_id": "new", "finished_at": 101.0},
               "display_receipt": {"context_id": "old", "finished_at": 90.0}}
        webrtc = {"state": "ok", "receipt": {"context_id": "new", "sampled_at": 102.0}}
        with patch.object(setup, "dns_receipt_status", return_value=dns), \
             patch("watch_switcher.audit.webrtc_receipt_status", return_value=webrtc):
            receipts = self.observe()["initialization_receipts"]
        self.assertEqual(receipts["dns"], {"state": "unknown", "context_id": "new", "sampled_at": 101.0})
        self.assertEqual(receipts["webrtc"], {"state": "ok", "context_id": "new", "sampled_at": 102.0})

    def test_unconfigured_machine_can_run_all_fourteen_live_checks(self):
        result = self.observe()
        self.assertEqual(len(result["rows"]), 14)
        self.assertFalse(result["grants_launch_permission"])
        self.assertNotIn("ready", result)
        self.assertNotIn("blocked", result)
        self.assertEqual(self.row(result, "egress")["current"], "8.8.8.8 / JP")
        self.assertEqual(self.row(result, "timezone")["reference"], "Asia/Tokyo")
        self.assertEqual(self.row(result, "timezone")["state"], "ok")
        self.assertEqual(self.system.calls, ["online"])
        self.assertFalse(self.paths.watch.exists())

    def test_wrong_saved_targets_and_disabled_online_policy_do_not_define_live_results(self):
        saved = dict(self.config, country="US", timezone="America/New_York", locale="en_US",
                     proxy_mode="surge", online_enabled=False, enabled=False)
        save_config(self.paths, saved)
        result = self.observe()
        self.assertEqual(self.row(result, "egress")["state"], "ok")
        self.assertEqual(self.row(result, "timezone")["state"], "ok")
        self.assertTrue(self.row(result, "locale")["reference"].startswith("ja_JP"))
        self.assertEqual(load_config(self.paths), saved)
        self.assertIn("online", self.system.calls)

    def test_broken_settings_or_account_state_cannot_prevent_live_detection(self):
        self.paths.initialize()
        self.paths.config.write_text("{broken-config")
        self.paths.state.write_text("{broken-account-state")
        args = runtime.parser().parse_args(["environment", "--online"])
        with patch.object(runtime, "AccountStore", side_effect=AssertionError("account state must not be consulted")):
            result = runtime.dispatch(args, self.paths, self.system)
        self.assertEqual(len(result["rows"]), 14)
        self.assertEqual(self.row(result, "timezone")["state"], "ok")
        self.assertEqual(self.row(result, "guard")["state"], "unknown")
        self.assertEqual(self.paths.config.read_text(), "{broken-config")

    def test_current_timezone_mismatch_is_detected_against_this_rounds_geoip(self):
        self.system.local_value["timezone"] = "America/New_York"
        result = self.observe()
        self.assertEqual(self.row(result, "timezone")["current"], "America/New_York")
        self.assertEqual(self.row(result, "timezone")["reference"], "Asia/Tokyo")
        self.assertEqual(self.row(result, "timezone")["state"], "fail")
        self.assertFalse(any(x[0] == "admin" for x in self.system.calls))

    def test_disagreeing_sources_do_not_create_a_default_country_or_timezone(self):
        self.system.online_value["geo"]["country"] = "US"
        result = self.observe()
        self.assertEqual(self.row(result, "egress")["state"], "fail")
        for key in ("timezone", "locale"):
            self.assertEqual(self.row(result, key)["state"], "info")
        self.assertEqual(self.row(result, "stun")["state"], "ok")
        self.assertNotIn("America/New_York", self.row(result, "timezone")["reference"])

    def test_failed_tun_does_not_trigger_online_probes_or_invent_egress(self):
        self.system.local_value["tun"] = "fail"
        result = self.observe()
        self.assertNotIn("online", self.system.calls)
        self.assertEqual(self.row(result, "tun")["state"], "fail")
        self.assertEqual(self.row(result, "egress")["state"], "unknown")

    def test_changed_network_after_probe_invalidates_all_current_results(self):
        original = self.system.online
        def changed(config):
            values = original(config)
            self.system.local_value["context"] = "changed"
            return values
        self.system.online = changed
        result = self.observe()
        self.assertTrue(all(r["state"] == "unknown" for r in result["rows"]))

    def test_detection_history_cannot_replace_controlled_launch_history(self):
        self.paths.initialize()
        audit_history = [{"time": time.time(), "ip": "1.1.1.1"}]
        atomic_json(self.paths.base / "ip-history.json", audit_history)
        self.observe(persist=True)
        self.assertEqual(read_json(self.paths.base / "ip-history.json"), audit_history)
        self.assertEqual(read_json(self.paths.base / "environment-history.json")[-1]["ip"], "8.8.8.8")
        self.assertFalse(self.paths.config.exists())
        self.assertFalse((self.paths.base / "confirmed-environment.json").exists())

    def test_missing_shared_dns_receipt_and_partial_stun_are_independent(self):
        self.system.online_value["stun"]["complete"] = False
        result = self.observe()
        self.assertEqual(self.row(result, "dns")["current"], "未知")
        self.assertEqual(self.row(result, "dns")["state"], "unknown")
        self.assertEqual(self.row(result, "stun")["state"], "ok")  # One accepted matching response remains usable.

    def test_stun_requires_accepted_public_response(self):
        for observations in ([], [{"status": "timeout"}],
                             [{"status": "ok", "address": "10.0.0.1"}],
                             [{"status": "ok", "address": "8.8.8.8", "accepted": False}],
                             [{"status": "ok", "address": "8.8.8.8", "deadline_exceeded": True}]):
            with self.subTest(observations=observations):
                self.system.online_value["stun"] = {"complete": False, "observations": observations}
                row = self.row(self.observe(), "stun")
                self.assertEqual(row["state"], "unknown")
                self.assertIn("无法确认 UDP 出口", row["detail"])
        self.system.online_value["stun"]["observations"] = [
            {"status": "ok", "address": "8.8.8.8"},
            {"status": "ok", "address": "1.1.1.1", "accepted": False, "deadline_exceeded": True},
        ]
        self.assertEqual(self.row(self.observe(), "stun")["state"], "fail")

    def test_verified_web_challenge_and_keyless_api_are_shown_as_reachable(self):
        now = time.time()
        self.system.online_value["service_responses"] = {
            "claude": {"status": "ok", "transport_reached": True, "access": "challenge", "http_status": 403,
                       "source": "https://claude.ai/", "queried_at": now,
                       "challenge": {"provider": "cloudflare", "mitigated": "challenge"}},
            "api": {"status": "ok", "transport_reached": True, "access": "authentication_required",
                    "http_status": 401, "source": "https://api.anthropic.com/v1/models", "queried_at": now}}
        result = self.observe(persist=True)
        row = self.row(result, "reachability")
        self.assertEqual(row["state"], "ok")
        self.assertEqual(row["current"], "网络可达 · 网页：需要浏览器验证 / API：未提供密钥")
        self.assertNotIn("query_error", row)
        self.assertIn("需要浏览器验证", row["detail"])
        self.assertIn("未提供密钥", row["detail"])
        saved = read_json(self.paths.base / "last-environment-detection.json")
        stored = self.row(saved, "reachability")
        self.assertEqual(stored["service_responses"]["api"]["access"], "authentication_required")

    def test_stun_server_attempts_preserve_latest_failure_and_wall_clock_trace(self):
        started, finished = 1792713600.0, 1792713604.0  # 2026-10-23 UTC
        self.system.online_value["stun"] = {
            "complete": False, "missing": 1, "started_at": started, "finished_at": finished,
            "observations": [
                {"server": "stun.miwifi.com", "port": 3478, "status": "ok", "address": "8.8.8.8",
                 "started_at": started, "finished_at": started + 2, "attempts": [
                     {"attempt": 1, "started_at": started, "finished_at": started + 1, "status": "timeout",
                      "error_code": "timeout", "error": "等待响应超时", "stage": "receive"},
                     {"attempt": 2, "started_at": started + 1, "finished_at": started + 2, "status": "ok",
                      "error_code": "", "error": "", "stage": "receive"}]},
                {"server": "stun.cloudflare.com", "port": 3478, "status": "timeout",
                 "started_at": started, "finished_at": finished, "attempts": [
                     {"attempt": 1, "started_at": started + 2, "finished_at": finished, "status": "timeout",
                      "error_code": "timeout", "error": "未收到 UDP 回包", "stage": "receive"}]},
                {"server": "stun.l.google.com", "port": 19302, "status": "network_error",
                 "started_at": started, "finished_at": started + 1, "attempts": [
                     {"attempt": 1, "started_at": started, "finished_at": started + 1, "status": "network_error",
                      "error_code": "dns_error", "errno": -2, "error": "名称未解析", "stage": "resolve"}]},
                {"server": "stun.delayed.example", "port": 3478, "status": "budget_exhausted",
                 "accepted": False, "deadline_exceeded": True, "started_at": started, "finished_at": finished,
                 "attempts": [{"attempt": 1, "started_at": started + 2, "finished_at": finished,
                               "status": "ok", "error_code": "", "error": "", "stage": "receive"}]}]}
        result = self.observe(persist=True)
        row = self.row(result, "stun")
        self.assertEqual(row["state"], "ok")  # One accepted matching response remains usable.
        self.assertEqual(row["sampled_at"], finished)
        self.assertEqual(row["stun_probe"]["finished_at"], finished)
        self.assertIn("第1次", row["detail"])
        self.assertIn("第2次", row["detail"])
        self.assertIn("等待 UDP 回包超时", row["detail"])
        self.assertIn("域名解析：名称未解析；错误代码 dns_error；系统错误 -2", row["detail"])
        self.assertIn("错误代码 timeout", row["detail"])
        self.assertIn("已收到回包，但超出整轮时限，未采纳", row["detail"])
        self.assertIn("最终状态：总预算耗尽（超出整轮时限，未采纳）", row["detail"])
        self.assertIn("2026-", row["detail"])
        persisted = read_json(self.paths.base / "last-environment-detection.json")
        saved = next(item for item in persisted["rows"] if item["id"] == "stun")
        self.assertEqual(saved["sampled_at"], finished)
        self.assertEqual(saved["stun_probe"]["observations"][1]["status"], "timeout")

    def test_dns_card_prioritizes_country_and_count_over_a_long_address_list(self):
        now = time.time()
        entries = ["203.0.113." + str(index) for index in range(1, 11)]
        # Documentation addresses are adequate here because this test covers
        # only receipt presentation; the validator is tested separately.
        atomic_json(self.paths.base / "dns-leak-receipt.json", {
            "schema": 1, "finished_at": now, "recorded_at": now,
            "display_expires_at": now + 300, "launch_expires_at": now + 30,
            "context": self.system.local_value["context"],
            "comparison": {"state": "ok", "reason": "same_country"},
            "dns": {"egress_ips": entries, "countries": ["JP"]},
            "http": {"egress_ips": ["8.8.8.8"], "countries": ["JP"]},
        })
        row = self.row(self.observe(), "dns")
        self.assertEqual(row["current"], "JP · 10 个 DNS 出口")
        self.assertEqual(row["reference"], "同轮 HTTP 出口国家 JP")
        self.assertIn("203.0.113.1", row["detail"])

    def test_asn_card_distinguishes_registered_country_from_egress_geography(self):
        self.system.online_value["asn"] = {"number": 2516, "organization": "KDDI CORPORATION",
                                           "registered_country": "JP", "result_time": "2026-10-21",
                                           "queried_at": 1792739000.0}
        row = self.row(self.observe(), "asn")
        self.assertEqual(row["current"], "AS2516 KDDI CORPORATION · 当前 IP JP")
        self.assertIn("ASN 注册国家 JP", row["reference"])
        self.assertIn("出口地理国家 JP", row["reference"])
        self.assertIn("RIPEstat RIR", row["source"])
