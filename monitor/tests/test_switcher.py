"""Offline integration and failure-injection tests. No real account/system actions."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

RESOURCES = Path(__file__).resolve().parents[1] / "Resources"
sys.path.insert(0, str(RESOURCES))
from watch_switcher.common import (CHECKS, DEFAULT_CONFIG, Paths, SwitcherError, atomic_json,
                                   load_config, operation_lock, read_json, save_config, validate_config)
from watch_switcher.audit import evaluate, audit
from watch_switcher.accounts import AccountStore, tree_manifest, verified_copy
from watch_switcher.rules import BEGIN, DOMAINS, discover_groups, format_detail, inspect_rules, render_rules, remove_block
from watch_switcher.repair import apply_plan, make_plan, region_plan
from watch_switcher.services import guard_tick, user_update_plist
from watch_switcher.stun import COOKIE, decode, probe
from watch_switcher.update import APP_NAME, Updater, extract_verified, verify_envelope
from watch_switcher.system import System


class FakeSystem:
    def __init__(self):
        self.calls = []
        self.running = False
        self.fail_launch = False
        self.fail_admin = False
        self.local_value = dict(proxy="ok", mode="tag", tun="ok", interface="utun4",
                                ipv6="ok", timezone="Asia/Tokyo", locale="ja_JP",
                                language='(\n "en-JP"\n)', guard=True, dns={}, tag={},
                                processes=[], context="stable")
        formats = {"ja_JP": {"short":"y/MM/dd", "medium":"y/MM/dd", "long":"y年M月d日"},
                   "en_US": {"short":"M/d/yy", "medium":"MMM d, y", "long":"MMMM d, y"},
                   "en_GB": {"short":"dd/MM/y", "medium":"d MMM y", "long":"d MMMM y"}}
        self.local_value["date_format"] = dict(state="available", configured_locale="ja_JP",
            patterns=copy.deepcopy(formats["ja_JP"]), short_sample="2026/10/23", reference_patterns=formats,
            reference_samples={"ja_JP":"2026/10/23", "en_US":"10/23/26", "en_GB":"23/10/2026"}, has_custom_formats=False)
        self.online_value = dict(trace={"ip": "8.8.8.8", "loc": "JP"},
                                 geo={"ip": "8.8.8.8", "country": "JP", "timezone": "Asia/Tokyo", "org": "fixture"},
                                 stun={"complete": True, "observations": [{"status": "ok", "address": "8.8.8.8"}]},
                                 dns={"state": "ok", "detail": "fixture DNS receipt"}, claude=403, api=401)
    def local(self, config, **kwargs): return copy.deepcopy(self.local_value)
    def online(self, config): self.calls.append("online"); return copy.deepcopy(self.online_value)
    def egress_reference(self, config):
        return dict(trace=copy.deepcopy(self.online_value["trace"]), geo=copy.deepcopy(self.online_value["geo"]),
                    errors=[], query_errors={}, source_times={"trace": 1.0, "geo": 1.0})
    def backend_healthy(self): return True
    def watchdog_state(self): return {"target": None, "registered": False, "last_success": None}
    def claude_version(self): return "1.0.0"
    def claude_running(self): return self.running
    def quit_claude(self): self.calls.append("quit"); self.running = False
    def launch_claude(self):
        self.calls.append("launch")
        if self.fail_launch: raise SwitcherError("launch_failed", "fixture")
        self.running = True
    def processes(self): return []
    def run(self, argv, *args, **kwargs):
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, '{"status":"ok"}', "")
    def optional(self, argv):
        return self.local_value["locale"]
    def admin(self, *args):
        self.calls.append(("admin", *args))
        if self.fail_admin: raise SwitcherError("authorization_cancelled", "fixture")
    def fetch(self, url, config):
        if "ipinfo" in url: return json.dumps(self.online_value["geo"]), 200
        return "ip=8.8.8.8\nloc=JP\n", 200


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="watch-switcher-")
        self.addCleanup(self.temp.cleanup)
        self.paths = Paths(Path(self.temp.name) / "home")
        self.paths.home.mkdir()
        self.system = FakeSystem()
        self.config = dict(copy.deepcopy(DEFAULT_CONFIG), enabled=True, online_enabled=True,
                           country="JP", timezone="Asia/Tokyo", locale="ja_JP", proxy_mode="tag",
                           guard_enabled=True, expected_resolvers=["1.1.1.1"],
                           verified_claude_versions=["1.0.0"])
    def active(self, data="original"):
        self.paths.active.mkdir(parents=True, exist_ok=True)
        (self.paths.active / "Cookie-fixture.txt").write_text(data)
    def store(self, **kwargs):
        def preflight(): self.system.calls.append("preflight")
        return AccountStore(self.paths, self.system, preflight, **kwargs)


class ConfigurationTests(Fixture):
    def test_read_defaults_has_no_write_side_effect(self):
        config = load_config(self.paths)
        self.assertTrue(config["enabled"])
        self.assertTrue(config["online_enabled"])
        self.assertTrue(config["guard_enabled"])
        self.assertEqual(config["country"], "")
        self.assertEqual(config["timezone"], "")
        self.assertFalse(self.paths.watch.exists())
    def test_unknown_keys_and_shell_input_rejected(self):
        for data in ({"arbitrary": True}, {"country": "$(id)"}, {"timezone": "../../tmp"},
                     {"proxy_url": "http://example.com:7890"}, {"enabled": "true"},
                     {"expected_egress": ["127.0.0.1"]}):
            with self.assertRaises(SwitcherError): validate_config(data)
    def test_locale_language_can_differ_from_region(self):
        self.assertEqual(validate_config({"locale": "en_JP"})["locale"], "en_JP")
    def test_private_config_and_lock_exclusion(self):
        save_config(self.paths, self.config)
        self.assertEqual(self.paths.config.stat().st_mode & 0o777, 0o600)
        with operation_lock(self.paths):
            with self.assertRaises(SwitcherError): save_config(self.paths, self.config)

    def test_pending_update_blocks_new_account_and_configuration_writes(self):
        self.paths.initialize()
        atomic_json(self.paths.base / "update-transaction.json", {"schema": 1})
        with self.assertRaises(SwitcherError): save_config(self.paths, self.config)
        with self.assertRaises(SwitcherError):
            with operation_lock(self.paths): pass
        with operation_lock(self.paths, recovery="update"): pass
    def test_state_symlink_rejected(self):
        self.paths.initialize()
        destination = self.paths.home / "unrelated"
        destination.write_text("{}")
        self.paths.config.symlink_to(destination)
        with self.assertRaises(SwitcherError): load_config(self.paths)
        self.assertEqual(destination.read_text(), "{}")


class AuditTests(Fixture):
    def test_failed_proxy_prevents_all_online_probes(self):
        self.system.local_value["proxy"] = "fail"
        result = audit(self.paths, self.system, self.config, online=True, persist=False)
        self.assertNotIn("online", self.system.calls)
        self.assertFalse(result["ready"])

    def test_policy_change_during_probe_invalidates_receipt(self):
        save_config(self.paths, self.config)
        def change(config):
            save_config(self.paths, dict(self.config, country="GB"))
            return self.system.online_value
        self.system.online = change
        result = audit(self.paths, self.system, self.config, online=True, persist=False)
        self.assertFalse(result["ready"])
        self.assertEqual(result["rows"][0]["state"], "unknown")

    def test_probe_disables_user_curlrc_and_uses_explicit_tag_proxy(self):
        system = System(self.paths)
        calls = []
        def record(argv, *args, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "fixture\n200", "")
        system.run = record
        _, status = system.fetch("https://www.cloudflare.com/cdn-cgi/trace", self.config)
        self.assertEqual(status, 200)
        self.assertEqual(calls[0][:2], ["/usr/bin/curl", "--disable"])
        self.assertIn("http://127.0.0.1:7890", calls[0])

    def test_local_observations_never_issue_dns_or_http_queries(self):
        system = System(self.paths)
        commands = []
        system.proxy_processes = lambda: [{"pid":1,"executable":"/Applications/TAG.app/Contents/Resources/bin/mihomo",
                                     "uid":501,"start_seconds":1}]
        def local_only(argv, *args, **kwargs):
            commands.append(argv)
            if argv[0].endswith("/ifconfig"): return "utun4: flags\n    inet 198.18.0.1\n"
            if argv[0].endswith("/route"): return "interface: utun4"
            if argv[0].endswith("/networksetup"): return "IPv6: Off"
            if argv[0].endswith("/readlink"): return "/var/db/timezone/zoneinfo/Asia/Tokyo"
            if "AppleLocale" in argv: return "en_JP"
            return ""
        system.optional = local_only
        result = system.local(self.config)
        self.assertEqual(result["mode"], "tag")
        self.assertFalse(any(argv[0].endswith(("/dig","/curl")) for argv in commands))

    def receipt(self, **kwargs):
        return evaluate(self.config, self.system.local_value, self.system.online_value, **kwargs)
    def test_exact_fourteen_keys_and_http_auth_not_account_success(self):
        result = self.receipt()
        self.assertEqual([r["id"] for r in result["rows"]], [k for k, _ in CHECKS])
        self.assertNotIn("reachability", result["blocked"])
        self.assertEqual(result["rows"][-1]["state"], "warn")
    def test_none_stun_and_partial_results_never_pass(self):
        for value in ({}, {"complete": True, "observations": []},
                      {"complete": False, "observations": [{"status": "ok", "address": "8.8.8.8"}]}):
            self.system.online_value["stun"] = value
            self.assertFalse(self.receipt()["ready"])
            self.assertEqual(self.receipt()["rows"][8]["state"], "unknown")
            self.assertIn("UDP/STUN 出口", self.receipt()["message"])
            self.assertNotIn("或功能未启用", self.receipt()["message"])

    def test_last_audit_keeps_structured_stun_failure_evidence(self):
        started, finished = 1792713600.0, 1792713603.0
        self.system.online_value["stun"] = {
            "complete": False, "missing": 1, "started_at": started, "finished_at": finished,
            "observations": [{"server": "stun.cloudflare.com", "port": 3478, "status": "invalid_response",
                               "started_at": started, "finished_at": finished, "attempts": [
                                   {"attempt": 1, "started_at": started, "finished_at": finished,
                                    "status": "invalid_response", "error_code": "invalid_length",
                                    "error": "响应长度无效", "stage": "validation"}]}]}
        save_config(self.paths, self.config)
        result = audit(self.paths, self.system, self.config, online=True, persist=True)
        row = next(item for item in result["rows"] if item["id"] == "stun")
        self.assertEqual(row["state"], "unknown")
        self.assertEqual(row["sampled_at"], finished)
        self.assertIn("报文校验：响应长度无效；错误代码 invalid_length", row["detail"])
        saved = read_json(self.paths.base / "last-audit.json")
        stored = next(item for item in saved["rows"] if item["id"] == "stun")
        self.assertEqual(stored["stun_probe"]["observations"][0]["attempts"][0]["error_code"], "invalid_length")
    def test_http_response_meanings_are_explicit(self):
        from watch_switcher.audit import http_result
        for code, state, text in [(401, 'ok', '认证'), (403, 'warn', '访问被拒绝'),
                                  (429, 'warn', '限流'), (503, 'warn', '服务端错误'),
                                  (0, 'unknown', '未收到')]:
            actual, detail = http_result(code)
            self.assertEqual(actual, state)
            self.assertIn(text, detail)
    def test_verified_challenge_and_keyless_api_are_reachable_without_query_error(self):
        now = time.time()
        self.system.online_value["service_responses"] = {
            "claude": {"status": "ok", "transport_reached": True, "access": "challenge", "http_status": 403,
                       "source": "https://claude.ai/", "queried_at": now,
                       "challenge": {"provider": "cloudflare", "mitigated": "challenge"}},
            "api": {"status": "ok", "transport_reached": True, "access": "authentication_required",
                    "http_status": 401, "source": "https://api.anthropic.com/v1/models", "queried_at": now}}
        save_config(self.paths, self.config)
        result = audit(self.paths, self.system, self.config, online=True, persist=True)
        row = next(item for item in result["rows"] if item["id"] == "reachability")
        self.assertEqual(row["state"], "ok")
        self.assertNotIn("query_error", row)
        self.assertIn("需要浏览器验证", row["detail"])
        self.assertIn("未提供密钥", row["detail"])
        self.assertNotIn("reachability", result["blocked"])
        saved = read_json(self.paths.base / "last-audit.json")
        stored = next(item for item in saved["rows"] if item["id"] == "reachability")
        self.assertEqual(stored["service_responses"]["claude"]["access"], "challenge")

    def test_unverified_403_or_request_failure_remain_non_green(self):
        self.system.online_value["service_responses"] = {
            "claude": {"status": "ok", "transport_reached": True, "access": "http_response",
                       "http_status": 200, "source": "https://wrong.example/", "queried_at": time.time()},
            "api": {"status": "ok", "transport_reached": True, "access": "authentication_required",
                    "http_status": 401, "source": "https://api.anthropic.com/v1/models", "queried_at": time.time()}}
        self.assertEqual(next(row for row in self.receipt()["rows"] if row["id"] == "reachability")["state"], "warn")
        self.system.online_value["service_responses"]["claude"] = {
            "status": "ok", "transport_reached": True, "access": "challenge", "http_status": 403,
            "queried_at": time.time(), "challenge": {"provider": "cloudflare", "mitigated": "challenge"}}
        self.assertEqual(next(row for row in self.receipt()["rows"] if row["id"] == "reachability")["state"], "warn")
        self.system.online_value["service_responses"]["claude"] = {
            "status": "unknown", "transport_reached": False, "access": "network_error",
            "http_status": None, "source": "https://claude.ai/", "queried_at": time.time(),
            "error_code": "timeout", "error": "连接超时"}
        self.system.online_value["claude"] = 0
        result = self.receipt()
        row = next(item for item in result["rows"] if item["id"] == "reachability")
        self.assertEqual(row["state"], "unknown")
        self.assertIn("reachability", result["blocked"])
    def test_exit_reference_mismatch_blocks(self):
        self.system.online_value["geo"]["ip"] = "9.9.9.9"
        self.assertIn("egress", self.receipt()["blocked"])
    def test_network_change_invalidates_critical_rows(self):
        self.system.local_value["context_changed"] = True
        result = self.receipt()
        self.assertFalse(result["ready"])
        self.assertTrue(all(r["state"] == "unknown" for r in result["rows"] if r["required"]))
    def test_history_warning_and_expiration(self):
        now = time.time()
        history = [{"time": now - 5, "ip": "1.1.1.1"}, {"time": now - 3, "ip": "9.9.9.9"}]
        self.assertEqual(self.receipt(history=history, now=now)["rows"][3]["state"], "warn")
        self.assertTrue(self.receipt(history=history, now=now)["ready"])
        self.config["allow_ip_change"] = False
        # A legacy preference cannot make old sessions a permanent startup
        # target. Running sessions have a separate immutable-IP guard.
        self.assertNotIn("ip_history", self.receipt(history=history, now=now)["blocked"])
    def test_offline_check_does_not_initiate_network(self):
        result = audit(self.paths, self.system, self.config, online=False, persist=False)
        self.assertNotIn("online", self.system.calls)
        self.assertFalse(result["ready"])
        self.assertFalse(self.paths.base.exists())
    def test_legacy_stun_skip_flag_cannot_remove_a_required_leak_check(self):
        self.config["require_stun"] = False
        self.system.online_value["stun"] = {}
        result = self.receipt()
        self.assertEqual(result["rows"][8]["state"], "unknown")
        self.assertTrue(result["rows"][8]["required"])
        self.assertIn("stun", result["blocked"])
    def test_language_region_pair_is_accepted(self):
        result = self.receipt()
        self.assertEqual(result["rows"][5]["state"], "ok")
        self.assertEqual(result["rows"][11]["state"], "ok")

    def test_english_fallback_is_not_preferred_english(self):
        self.system.local_value["language"] = '("zh-Hans-JP", "en-JP")'
        self.assertEqual(self.receipt()["rows"][11]["state"], "fail")


class RootProxyTests(Fixture):
    tag_path = "/Applications/TAG.app/Contents/Resources/bin/mihomo-universal-tag-darwin"

    def live_fixture(self, output, returncode=0):
        system = System(self.paths)
        native = []
        system.processes = lambda: native
        system.run = lambda argv, **kwargs: subprocess.CompletedProcess(argv, returncode, output, "")
        def optional(argv, **kwargs):
            if argv[0] == "/sbin/ifconfig": return "utun4: flags\n    inet 198.18.0.1\n"
            if argv[0] == "/sbin/route": return "interface: utun4"
            return ""
        system.optional = optional
        system.backend_healthy = lambda: True
        system.claude_running = lambda: True
        closed = []
        system.quit_claude = lambda: closed.append("quit")
        save_config(self.paths, self.config)
        return system, native, closed

    def test_root_tag_identity_is_recognized_independently_of_missing_session(self):
        system, native, closed = self.live_fixture("1180 1 0 Wed Oct 21 11:36:21 2026 " + self.tag_path + "\n")
        local = system.local(self.config, guard_only=True)
        self.assertEqual((local["proxy"], local["mode"], local["tun"]), ("ok", "tag", "ok"))
        result = guard_tick(self.paths, system)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["session_guard"]["reason"]["code"], "session_missing")
        self.assertEqual(closed, ["quit"])
        self.assertEqual(native, [], "read-only supplement must not enter native close inventory")

    def test_confirmed_missing_proxy_still_requests_normal_claude_exit(self):
        system, _, closed = self.live_fixture("10 1 0 Wed Oct 21 11:36:21 2026 /usr/libexec/unrelated\n")
        self.assertEqual(guard_tick(self.paths, system)["action"], "close-desktop")
        self.assertEqual(closed, ["quit"])

    def test_failed_snapshot_stays_unknown_and_unbound_app_is_stopped(self):
        for output, code in (("", 0), ("", 1)):
            with self.subTest(returncode=code):
                system, _, closed = self.live_fixture(output, code)
                result = guard_tick(self.paths, system)
                self.assertEqual(result["status"], "unknown")
                self.assertEqual(result["session_guard"]["reason"]["code"], "session_missing")
                self.assertEqual(closed, ["quit"])

    def test_incomplete_proxy_identity_is_not_reported_as_ip_change(self):
        system, _, closed = self.live_fixture("1180 1 0 " + self.tag_path + "\n")
        result = guard_tick(self.paths, system)
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["session_guard"]["reason"]["code"], "session_missing")
        self.assertEqual(closed, ["quit"])

    def test_supplement_accepts_only_root_processes_in_known_proxy_locations(self):
        output = ("1180 1 501 Wed Oct 21 11:36:21 2026 " + self.tag_path + "\n"
                  "1181 1 0 Wed Oct 21 11:36:21 2026 /tmp/TAG.app/Contents/mihomo\n")
        system, _, _ = self.live_fixture(output)
        self.assertEqual(system.proxy_processes(), [])


class AccountTests(Fixture):
    def test_legacy_invalid_config_rejected_before_any_copy(self):
        root = self.paths.legacy / "accounts/A"
        root.mkdir(parents=True)
        (root / "fixture").write_text("account")
        script = self.paths.home / ".local/bin/claude-switch.sh"
        script.parent.mkdir(parents=True)
        script.write_text('COUNTRY_TARGET="invalid"\n')
        with self.assertRaises(SwitcherError): self.store().import_legacy(apply=True)
        self.assertEqual(list(self.paths.accounts.iterdir()), [])

    def test_invalid_account_never_creates_storage(self):
        with self.assertRaises(SwitcherError): self.store().switch("../../Other", self.config)
        self.assertFalse(self.paths.base.exists())
    def test_unverified_version_requires_explicit_acknowledgement(self):
        self.active()
        self.config["verified_claude_versions"] = []
        with self.assertRaises(SwitcherError): self.store().switch("B", self.config)
        self.assertNotIn("quit", self.system.calls)
    def test_first_b_and_back_a_preserves_both_profiles(self):
        self.active("account A")
        result = self.store().switch("B", self.config)
        self.assertFalse(result["login_verified"])
        self.assertEqual(self.store().state()["current"], "B")
        (self.paths.active / "Cookie-fixture.txt").write_text("account B")
        self.store().switch("A", self.config)
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "account A")
        self.assertEqual((self.paths.accounts / "B/profile/Cookie-fixture.txt").read_text(), "account B")
        self.assertFalse(self.paths.journal.exists())
    def test_copy_failure_keeps_original_and_does_not_launch(self):
        self.active()
        stored = self.paths.accounts / "B/profile"
        stored.mkdir(parents=True)
        (stored / "Cookie-fixture.txt").write_text("saved B")
        atomic_json(stored.parent / "manifest.json", {"schema": 1, "files": tree_manifest(stored)})
        def broken(source, target): raise OSError("disk full")
        with self.assertRaises(SwitcherError) as error: self.store(copier=broken).switch("B", self.config)
        self.assertEqual(error.exception.code, "upstream_run_failed")
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "original")
        self.assertNotIn("launch", self.system.calls)
    def test_failed_launch_rolls_back_original(self):
        self.active()
        self.system.fail_launch = True
        with self.assertRaises(SwitcherError): self.store().switch("B", self.config)
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "original")
        self.assertFalse(self.paths.journal.exists())
    def test_crash_at_each_durable_phase_is_recoverable(self):
        class Crash(BaseException): pass
        for stage in ("prepared", "old_moved", "installed"):
            with self.subTest(stage=stage):
                if self.paths.base.exists(): shutil.rmtree(self.paths.base)
                self.active("original " + stage)
                def checkpoint(value):
                    if value == stage: raise Crash()
                with self.assertRaises(Crash): self.store(checkpoint=checkpoint).switch("B", self.config)
                self.store().recover()
                self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "original " + stage)
    def test_same_account_is_a_noop_and_keeps_running_session(self):
        self.active()
        self.store().switch("A", self.config)
        self.system.calls.clear()
        result = self.store().switch("A", self.config)
        self.assertEqual(self.system.calls, [])
        self.assertTrue(self.system.running)
        self.assertEqual((self.paths.active / "Cookie-fixture.txt").read_text(), "original")
        self.assertEqual(result["current"], "A")
    def test_preflight_block_stops_before_quit(self):
        self.active()
        def blocked(): raise SwitcherError("blocked", "fixture")
        with self.assertRaises(SwitcherError): AccountStore(self.paths, self.system, blocked).switch("B", self.config)
        self.assertEqual(self.system.calls, [])
    def test_journal_cannot_redirect_recovery(self):
        self.paths.initialize()
        atomic_json(self.paths.journal, {"schema": 1, "token": "a"*32, "target": "A",
                                        "stage": "/private/tmp/unrelated", "old": "/private/tmp/unrelated"})
        with self.assertRaises(SwitcherError): self.store().recover()
    def test_data_symlink_rejected_without_following_it(self):
        self.active()
        outside = self.paths.home / "private"
        outside.write_text("do not copy")
        (self.paths.active / "escape").symlink_to(outside)
        with self.assertRaises(SwitcherError): self.store().switch("B", self.config)
        self.assertEqual(outside.read_text(), "do not copy")
    def test_snapshot_tampering_blocks_restoration(self):
        self.active()
        self.store().switch("B", self.config)
        (self.paths.accounts / "A/profile/Cookie-fixture.txt").write_text("modified")
        with self.assertRaises(SwitcherError): self.store().switch("A", self.config)
        self.assertEqual(self.store().state()["current"], "B")
    def test_import_preview_does_not_copy_or_execute_legacy_script(self):
        root = self.paths.legacy / "accounts/A"
        root.mkdir(parents=True)
        (root / "fixture").write_text("account")
        script = self.paths.home / ".local/bin/claude-switch.sh"
        script.parent.mkdir(parents=True)
        script.write_text('PROXY_MODE="tag"\nCOUNTRY_TARGET="JP"\ntouch /tmp/MUST_NOT_EXECUTE\n')
        preview = self.store().import_legacy()
        self.assertEqual(preview["accounts"], ["A"])
        self.assertFalse(self.paths.base.exists())
        self.store().import_legacy(apply=True)
        self.assertEqual((self.paths.accounts / "A/profile/fixture").read_text(), "account")
        self.assertTrue(root.exists())


class RulesAndRepairTests(Fixture):
    def tag_runtime(self, text):
        path = self.paths.home / "Library/Application Support/com.tag.lab/mihomo/runtime.yaml"
        path.parent.mkdir(parents=True)
        path.write_text(text)

    def test_group_discovery_lists_only_select_group_names(self):
        path = self.paths.home / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml"
        path.parent.mkdir(parents=True)
        path.write_text('secret: do-not-emit\nproxy-groups:\n  - name: "AI 日本"\n    type: select\n  - name: auto\n    type: url-test\nrules:\n  - MATCH,AI\n')
        self.assertEqual(discover_groups(self.paths), ["AI 日本"])

    def test_rule_merge_preserves_user_values_and_is_idempotent(self):
        original = "# keep comment\nprofile:\n  store-selected: true\nprepend-rules:\n  - DOMAIN,example.com,DIRECT\n"
        once = render_rules(original, 'AI "group"')
        self.assertEqual(render_rules(once, 'AI "group"'), once)
        self.assertEqual(remove_block(once), original)
        self.assertIn("DOMAIN,example.com,DIRECT", once)
        self.assertEqual(once.count("DOMAIN-SUFFIX,"), 13)
    def test_complex_or_duplicate_keys_refuse_without_change(self):
        for original in ("prepend-rules: [a,b]\n", "prepend-rules:\nprepend-rules:\n",
                         "prepend-rules:\n  " + BEGIN + "\n"):
            with self.assertRaises(SwitcherError): render_rules(original, "AI")

    def test_tag_global_uses_verified_non_bypass_global_node(self):
        self.tag_runtime("mode: global\nrules:\n")
        result = inspect_rules(self.paths, self.config, "tag", {
            "api": {"state": "available", "mode": "global", "global_node": "Japan 1"},
            "rules": {"state": "available", "entries": []},
        })
        self.assertEqual(result["state"], "ok")
        self.assertEqual(result["covered_domains"], list(DOMAINS))
        self.assertEqual(result["tag_saved_container"], "encrypted_unreadable")

    def test_tag_global_never_falls_back_to_an_unrelated_selected_group(self):
        self.tag_runtime("mode: global\nrules:\n")
        result = inspect_rules(self.paths, self.config, "tag", {
            "api": {"state": "available", "mode": "global", "selected_node": "Japan AI", "global_node": None},
            "rules": {"state": "available", "entries": [], "total": 4109},
        })
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["covered_domains"], [])
        self.assertEqual((result["controller_rule_total"], result["controller_rule_published"]), (4109, 0))
        self.assertEqual(result["mode_consistency"], "一致")

    def test_tag_rule_comparison_uses_active_controller_rules_not_stale_runtime(self):
        runtime = "mode: rule\nrules:\n" + "".join(
            "  - DOMAIN-SUFFIX," + domain + ",GLOBAL\n" for domain in DOMAINS)
        self.tag_runtime(runtime)
        active = ["DOMAIN-SUFFIX," + domain + ",GLOBAL" for domain in DOMAINS]
        active[0] = "DOMAIN-SUFFIX,claude.ai,DIRECT"
        result = inspect_rules(self.paths, self.config, "tag", {
            "api": {"state": "available", "mode": "rule"},
            "rules": {"state": "available", "entries": active},
        })
        self.assertEqual(result["state"], "fail")
        self.assertEqual(result["bypass_domains"], ["claude.ai"])
        self.assertEqual(result["runtime_domains"], list(DOMAINS))
        self.assertEqual(result["controller_domains"], list(DOMAINS))

    def test_tag_rule_absence_is_unknown_not_a_bypass_warning(self):
        self.tag_runtime("mode: rule\nrules:\n  - MATCH,GLOBAL\n")
        result = inspect_rules(self.paths, self.config, "tag", {
            "api": {"state": "available", "mode": "rule"},
            "rules": {"state": "available", "entries": ["MATCH,GLOBAL"]},
        })
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["bypass_domains"], [])
        self.assertEqual(result["missing_domains"], list(DOMAINS))
        self.assertEqual(result["uncertain_domains"]["claude.ai"], "match")

    def test_tag_broad_rule_before_suffix_keeps_coverage_unknown(self):
        runtime = "mode: rule\nrules:\n  - DOMAIN-KEYWORD,claude,DIRECT\n" + "".join(
            "  - DOMAIN-SUFFIX," + domain + ",GLOBAL\n" for domain in DOMAINS)
        self.tag_runtime(runtime)
        entries = ["DOMAIN-KEYWORD,claude,DIRECT"] + [
            "DOMAIN-SUFFIX," + domain + ",GLOBAL" for domain in DOMAINS]
        result = inspect_rules(self.paths, self.config, "tag", {
            "api": {"state": "available", "mode": "rule"},
            "rules": {"state": "available", "entries": entries},
        })
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["covered_domains"], [])
        self.assertEqual(result["uncertain_domains"]["claude.ai"], "DOMAIN-KEYWORD")

    def test_tag_domain_rule_is_not_counted_as_suffix_family_coverage(self):
        self.tag_runtime("mode: rule\nrules:\n  - DOMAIN,claude.ai,GLOBAL\n")
        result = inspect_rules(self.paths, self.config, "tag", {
            "api": {"state": "available", "mode": "rule"},
            "rules": {"state": "available", "entries": ["DOMAIN,claude.ai,GLOBAL"]},
        })
        self.assertEqual(result["state"], "unknown")
        self.assertNotIn("claude.ai", result["covered_domains"])
        self.assertEqual(result["uncertain_domains"]["claude.ai"], "exact")

    def test_rule_detail_explains_encrypted_saved_config_and_evidence_counts(self):
        self.tag_runtime("mode: global\nrules:\n")
        result = inspect_rules(self.paths, self.config, "tag", {
            "api": {"state": "available", "mode": "global", "global_node": "Japan 1"},
            "rules": {"state": "available", "entries": [], "total": 4109},
        })
        detail = format_detail(result)
        self.assertIn("4109", detail)
        self.assertIn("加密容器，不能逐条比较", detail)
    def test_plan_is_read_only_and_stale_plan_cannot_apply(self):
        self.system.local_value["timezone"] = "Europe/London"
        plan = make_plan(self.paths, self.system, self.config)
        self.assertFalse(self.paths.base.exists())
        self.system.local_value["timezone"] = "Europe/Paris"
        with self.assertRaises(SwitcherError): apply_plan(self.paths, self.system, self.config, plan["id"])
        self.assertEqual(self.system.calls, [])
    def test_cancelled_admin_reports_partial_not_success(self):
        self.system.local_value["timezone"] = "Europe/London"
        plan = make_plan(self.paths, self.system, self.config)
        self.system.fail_admin = True
        result = apply_plan(self.paths, self.system, self.config, plan["id"])
        self.assertEqual(result["status"], "partial")
        self.assertFalse(self.paths.config.exists())
    def test_region_detection_separates_japanese_formats_from_english(self):
        plan = region_plan(self.paths, self.system, self.config)
        self.assertEqual(plan["desired_config"]["locale"], "ja_JP")
        self.assertEqual(self.system.local_value["language"], '(\n "en-JP"\n)')
        self.assertFalse(self.paths.base.exists())
    def test_region_source_disagreement_aborts(self):
        self.system.online_value["geo"]["ip"] = "1.1.1.1"
        with self.assertRaises(SwitcherError): region_plan(self.paths, self.system, self.config)


class ProtectionTests(Fixture):
    def admin_fixture(self):
        resources = self.paths.home / "resources"; resources.mkdir()
        source = resources / "watch-admin.sh"; source.write_text("# fixed helper\n")
        target = self.paths.home / "admin/claude-watch-admin.sh"
        target.parent.mkdir(); target.write_text(source.read_text())
        system = System(self.paths, resources=resources)
        calls = []
        system.run = lambda args, **kwargs: calls.append(args)
        return system, target, calls

    def test_regular_admin_action_never_overwrites_installed_helper(self):
        system, target, calls = self.admin_fixture()
        with patch("watch_switcher.system.ADMIN_TARGET", target), patch("watch_switcher.system.validate_admin_target"):
            system.admin("timezone", "Asia/Tokyo")
        self.assertEqual(len(calls), 1)
        self.assertNotIn("/usr/bin/install", calls[0][-1])
        self.assertIn(str(target), calls[0][-1])

    def test_changed_user_helper_requires_explicit_upgrade(self):
        system, target, calls = self.admin_fixture()
        target.write_text("# older fixed helper\n")
        with patch("watch_switcher.system.ADMIN_TARGET", target), patch("watch_switcher.system.validate_admin_target"):
            with self.assertRaises(SwitcherError): system.admin("timezone", "Asia/Tokyo")
        self.assertEqual(calls, [])

    def test_explicit_upgrade_verifies_root_copy_before_execution(self):
        system, target, calls = self.admin_fixture()
        with patch("watch_switcher.system.ADMIN_TARGET", target), patch("watch_switcher.system.validate_admin_target"):
            system.admin("status")
        self.assertIn("/usr/bin/install", calls[0][-1])
        self.assertIn("/usr/bin/shasum -a 256", calls[0][-1])

    def test_admin_prompt_compiles_without_executing_any_operation(self):
        system, target, calls = self.admin_fixture()
        with patch("watch_switcher.system.ADMIN_TARGET", target), patch("watch_switcher.system.validate_admin_target"):
            system.admin("status")
        output = self.paths.home / "compile-only.scpt"
        result = subprocess.run(["/usr/bin/osacompile", "-o", str(output), "-"],
                                input=calls[0][-1], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.is_file())
        self.assertEqual(target.read_text(), "# fixed helper\n")

    def test_user_owned_admin_target_is_rejected_without_prompt(self):
        system, target, calls = self.admin_fixture()
        with patch("watch_switcher.system.ADMIN_TARGET", target):
            with self.assertRaises(SwitcherError): system.admin("timezone", "Asia/Tokyo")
        self.assertEqual(calls, [])

    def test_disabled_guard_does_not_create_state_or_scan(self):
        save_config(self.paths, dict(self.config, enabled=False, guard_enabled=False))
        self.assertEqual(guard_tick(self.paths, self.system)["status"], "disabled")
        self.assertFalse((self.paths.base / "guard-heartbeat.json").exists())
        self.assertEqual(self.system.calls, [])
    def test_known_failure_closes_only_via_shared_component(self):
        save_config(self.paths, self.config)
        self.system.local_value["tun"] = "fail"
        self.system.running = True
        self.assertEqual(guard_tick(self.paths, self.system)["action"], "close-desktop")
        self.assertIn("quit", self.system.calls)
    def test_unknown_proxy_is_not_reported_as_an_ip_change_for_unbound_app(self):
        save_config(self.paths, self.config)
        self.system.local_value["proxy"] = "unknown"
        self.system.running = True
        result = guard_tick(self.paths, self.system)
        self.assertNotEqual(result["status"], "ok")
        self.assertEqual(result["session_guard"]["reason"]["code"], "session_missing")
        self.assertIn("quit", self.system.calls)
    def test_account_transaction_does_not_delay_confirmed_risk_exit(self):
        save_config(self.paths, self.config)
        self.system.local_value["tun"] = "fail"
        self.system.running = True
        with operation_lock(self.paths):
            result = guard_tick(self.paths, self.system)
            self.assertEqual(result["action"], "close-desktop")
        self.assertFalse(self.system.running)
    def test_auto_update_is_user_agent_and_not_run_at_load(self):
        value = user_update_plist(self.paths, "/usr/bin/python3")
        self.assertEqual(value["StartInterval"], 43200)
        self.assertFalse(value["RunAtLoad"])
        self.assertNotIn("UserName", value)


class STUNTests(unittest.TestCase):
    def packet(self, transaction=b"a"*12):
        raw = bytes([8,8,8,8])
        value = b"\0\1" + b"\0\0" + bytes(a ^ b for a, b in zip(raw, COOKIE))
        attr = struct.pack("!HH", 0x20, len(value)) + value
        return b"\1\1" + struct.pack("!H", len(attr)) + COOKIE + transaction + attr
    def test_transaction_and_length_validation(self):
        self.assertEqual(decode(self.packet(), b"a"*12), "8.8.8.8")
        for data, txn in ((self.packet(), b"b"*12), (self.packet()[:-1], b"a"*12),
                          (self.packet()+b"junk", b"a"*12)):
            with self.assertRaises(ValueError): decode(data, txn)
    def test_timeout_is_explicit_not_none_success(self):
        def timeout(*args): raise TimeoutError()
        result = probe((("fixture",3478),), requester=timeout, budget=0.2)
        self.assertFalse(result["complete"])
        self.assertEqual(result["observations"][0]["status"], "timeout")


class UpdateTests(Fixture):
    def test_real_rsa_signature_and_tampering_offline(self):
        import base64, platform
        self.paths.initialize()
        key, public = self.paths.base/"fixture-key.pem", self.paths.base/"fixture-public.pem"
        subprocess.run(["/usr/bin/openssl", "genrsa", "-out", str(key), "2048"], check=True, capture_output=True)
        subprocess.run(["/usr/bin/openssl", "rsa", "-in", str(key), "-pubout", "-out", str(public)], check=True, capture_output=True)
        payload = json.dumps({"schema":1,"runtime_schema":1,"admin_abi":1,"architecture":platform.machine(),
                              "version":"2.4.0","files":{"runtime/switcher.py":"fixture"}}).encode()
        data, signature = self.paths.base/"to-sign.json", self.paths.base/"signature.bin"
        data.write_bytes(payload)
        subprocess.run(["/usr/bin/openssl","dgst","-sha256","-sign",str(key),"-out",str(signature),str(data)],
                       check=True,capture_output=True)
        envelope = {"manifest":base64.b64encode(payload).decode(),"signature":base64.b64encode(signature.read_bytes()).decode()}
        class CryptoOnly:
            def run(self, argv, **kwargs):
                if argv[:3] != ["/usr/bin/openssl","dgst","-sha256"]: raise AssertionError("unexpected tool")
                p = subprocess.run(argv, capture_output=True, timeout=10)
                if p.returncode: raise SwitcherError("signature", "fixture")
                return p
        destination = self.paths.base/"verify"; destination.mkdir()
        self.assertEqual(verify_envelope(envelope,public.read_text(),CryptoOnly(),destination)["version"],"2.4.0")
        envelope["manifest"] = base64.b64encode(payload.replace(b"2.4.0",b"9.9.9")).decode()
        with self.assertRaises(SwitcherError): verify_envelope(envelope,public.read_text(),CryptoOnly(),destination)

    def payload(self):
        source = self.paths.home / "payload"
        contents = {
            "claude-watch.sh": "new backend",
            "runtime/switcher.py": "new runtime",
            "runtime/watch-admin.sh": "new admin",
            "runtime/watch-process-control": "new process component",
            "app/" + APP_NAME + "/Contents/Info.plist": "new app",
        }
        for name, content in contents.items():
            p = source / name; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(content)
        return source, dict(schema=1, version="2.4.0", files={k:hashlib.sha256(v.encode()).hexdigest() for k,v in contents.items()})
    def test_archive_requires_complete_manifest_and_no_traversal(self):
        source, manifest = self.payload()
        archive = self.paths.home / "bundle.zip"
        with zipfile.ZipFile(archive,"w") as z:
            for p in source.rglob("*"):
                if p.is_file(): z.write(p,p.relative_to(source))
        extracted = self.paths.home / "extracted"
        extract_verified(archive, extracted, manifest)
        self.assertTrue((extracted/"runtime/switcher.py").exists())
        with zipfile.ZipFile(archive,"a") as z: z.writestr("../escape", "bad")
        with self.assertRaises(SwitcherError): extract_verified(archive, self.paths.home/"bad", manifest)
        self.assertFalse((self.paths.home/"escape").exists())
    def test_partial_update_rolls_back_every_component(self):
        source, manifest = self.payload()
        self.paths.initialize()
        app = self.paths.home / "Applications" / APP_NAME
        (app/"Contents").mkdir(parents=True)
        (app/"Contents/Info.plist").write_text("old app")
        (self.paths.watch/"runtime").mkdir()
        (self.paths.watch/"runtime/switcher.py").write_text("old runtime")
        self.paths.backend.write_text("old backend")
        def fail(): raise SwitcherError("self_check", "fixture")
        updater = Updater(self.paths, self.system, app_path=app, health=fail)
        with self.assertRaises(SwitcherError):
            with operation_lock(self.paths): updater.apply_payload(source,manifest)
        self.assertEqual((app/"Contents/Info.plist").read_text(),"old app")
        self.assertEqual((self.paths.watch/"runtime/switcher.py").read_text(),"old runtime")
        self.assertEqual(self.paths.backend.read_text(),"old backend")
        self.assertFalse((self.paths.base/"update-transaction.json").exists())
    def test_no_release_channel_is_explicitly_unconfigured(self):
        self.assertEqual(Updater(self.paths,self.system).check(self.config)["status"],"unconfigured")
        self.assertFalse(self.paths.base.exists())
    def test_update_permission_reset_targets_only_installed_watch(self):
        self.system.calls.clear()
        Updater(self.paths,self.system,app_path=self.paths.home/'isolated.app').reset_replaced_app_accessibility()
        self.assertEqual(self.system.calls,[])
        Updater(self.paths,self.system).reset_replaced_app_accessibility()
        self.assertEqual(self.system.calls,[['/usr/bin/tccutil','reset','Accessibility','io.local.watchpanel'],
                                          ['/usr/bin/defaults','delete','io.local.watchpanel','accessibilityPromptedBuild']])
    def test_signature_failure_does_not_trust_same_origin_hash(self):
        self.paths.initialize()
        envelope={"manifest":"e30=","signature":"YQ=="}
        self.system.run=lambda *a,**kw: (_ for _ in ()).throw(SwitcherError("failed","fixture"))
        with self.assertRaises(SwitcherError):
            verify_envelope(envelope,"-----BEGIN PUBLIC KEY-----\nfixture",self.system,self.paths.base)


if __name__ == "__main__":
    unittest.main()
