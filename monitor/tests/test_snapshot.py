import importlib.util
import datetime as dt
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock
import shlex
import subprocess
import time

spec = importlib.util.spec_from_file_location("snapshot", Path(__file__).parents[1] / "Resources/snapshot.py")
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "state").mkdir()
        (self.root / "state/mode").write_text("armed\n")
        self.stamp = "Fri Oct 16 15:06:15 2026"
        self.service = "state = running\npid = 67166\n"

    def health(self, heartbeat, service=None, stamp=None, now=1000, rc=0):
        (self.root / "state/heartbeat").write_text(heartbeat)
        return adapter.health_snapshot(self.root, service or self.service, stamp or self.stamp, now, rc)

    def test_valid_identity_and_fresh_heartbeat_are_required(self):
        result = self.health(f"67166|{self.stamp}|995|ok|GUARD")
        self.assertEqual(result["state"], "running")
        self.assertEqual(result["heartbeatAge"], 5)
        self.assertEqual(result["mode"], "GUARD")

    def test_stale_and_future_heartbeats_are_not_healthy(self):
        for epoch in (900, 1001):
            with self.subTest(epoch=epoch):
                self.assertEqual(self.health(f"67166|{self.stamp}|{epoch}|ok|GUARD")["state"], "degraded")

    def test_reused_pid_is_not_healthy(self):
        self.assertEqual(self.health(f"67166|{self.stamp}|995|ok|GUARD", stamp="Fri Oct 16 17:00:00 2026")["state"], "degraded")

    def test_scan_failure_is_not_healthy(self):
        self.assertEqual(self.health(f"67166|{self.stamp}|995|error|GUARD")["state"], "degraded")

    def test_service_unavailable_cannot_be_overridden_by_heartbeat(self):
        result = self.health(f"67166|{self.stamp}|995|ok|GUARD", service="Not permitted", rc=1)
        self.assertEqual(result["state"], "unavailable")

    def test_blank_and_malformed_process_rows_do_not_become_processes(self):
        self.assertEqual(adapter.process_records("\n||\n1||code\nx|time|code\n1|time|unknown\n"), [])
        result = adapter.process_records("3|stamp|code\n", active={3})
        self.assertEqual(result[0]["pid"], 3)
        self.assertTrue(result[0]["authorized"])
        self.assertIsNone(adapter.process_records("3|stamp|code\n")[0]["authorized"])

    def test_malformed_proxy_does_not_crash_or_claim_verified(self):
        path = self.root / "proxy.json"
        for raw in ("", "null", "[]", '{"schema":1}', '{"schema":1,"entry":{},"api":{},"flows":null}'):
            with self.subTest(raw=raw):
                path.write_text(raw)
                self.assertIsNone(adapter.proxy_snapshot(path))

    def test_multiapp_processes_keep_product_and_authorization_identity(self):
        raw = ("11|stamp|code\n12|stamp|codex-cli\n13|stamp|codex-child\n"
               "14|stamp|chatgpt-desktop-main\n15|stamp|openai-desktop-helper\n"
               "16|stamp|chatgpt-cli\n17|stamp|unrelated\n")
        records = adapter.process_records(raw, {12})
        self.assertEqual([r["pid"] for r in records], [11, 12, 13, 14, 15])
        self.assertEqual([r["kind"] for r in records], ["code", "codex-cli", "codex-child", "chatgpt-desktop-main", "openai-desktop-helper"])
        self.assertEqual([r["pid"] for r in records if r["authorized"]], [12])

    def test_legacy_backend_never_claims_openai_coverage(self):
        proxy, error = self.read_daemon_report(self.daemon_report())
        self.assertIsNone(error)
        self.assertIsNone(proxy["backendVersion"])
        self.assertEqual(proxy["monitoredApps"], ["claude"])

    def test_multiapp_capabilities_require_valid_metadata(self):
        report = self.daemon_report()
        report.update(monitor_version="2.2.1", monitored_apps=["claude", "codex", "chatgpt"])
        proxy, error = self.read_daemon_report(report)
        self.assertIsNone(error)
        self.assertEqual(proxy["backendVersion"], "2.2.1")
        self.assertEqual(set(proxy["monitoredApps"]), {"claude", "codex", "chatgpt"})
        for apps in ("codex", ["browser"], [None], [], {"codex": True}):
            with self.subTest(apps=apps):
                report["monitored_apps"] = apps
                proxy, _ = self.read_daemon_report(report)
                self.assertEqual(proxy["monitoredApps"], [])

    def test_mixed_product_flows_correlate_by_pid_not_host(self):
        report = self.daemon_report()
        report["connection_observation"] = self.connection_observation()
        report["flows"] = [dict(pid=pid, host="shared.example", local=["127.0.0.1", 5000+pid],
                                 peer=["127.0.0.1", 7890], protocol="tcp", chains=[])
                           for pid in (11, 12, 13)]
        proxy = adapter.proxy_snapshot(None, report)
        records = adapter.process_records("11|stamp|code\n12|stamp|codex-cli\n")
        filtered = adapter.active_proxy_flows(proxy, records)
        self.assertEqual([f["pid"] for f in filtered["flows"]], [11, 12])
        self.assertNotEqual(filtered["flows"][0]["id"], filtered["flows"][1]["id"])
        observation = filtered["connectionObservation"]
        self.assertEqual(observation["collectorState"], "partial")
        self.assertEqual(observation["uiFilteredCount"], 1)
        self.assertEqual(observation["uiDropped"], {"process_missing": 1})

    def connection_observation(self, **changes):
        value = {
            "schema": 1, "round_id": "round-1", "observed_at": 995,
            "collector_state": "ok", "target_count": 3, "parsed_count": 3,
            "accepted_count": 3, "correlated_count": 2, "unconfirmed_count": 1,
            "dropped": {"malformed": 0}, "detail": "采集完成",
        }
        value.update(changes)
        return value

    def test_missing_connection_receipt_is_unknown_not_an_empty_round(self):
        proxy = adapter.proxy_snapshot(None, self.daemon_report())
        receipt = proxy["connectionObservation"]
        self.assertEqual(receipt["collectorState"], "unknown")
        self.assertEqual(receipt["detail"], "后台未提供连接采集回执")
        self.assertEqual(receipt["targetCount"], 0)
        self.assertEqual(receipt["uiFilteredCount"], 0)

    def test_backend_unknown_preserves_the_specific_missing_receipt_reason(self):
        raw = self.connection_observation(collector_state="unknown", round_id="", detail="连接采样回执缺失")
        value = adapter.connection_observation(raw, 995)
        self.assertEqual(value["collectorState"], "unknown")
        self.assertEqual(value["detail"], "连接采样回执缺失")

    def test_new_process_after_empty_round_is_not_reported_as_zero_connections(self):
        at = 1000
        stamp = dt.datetime.fromtimestamp(at + 1).strftime("%a %b %d %H:%M:%S %Y")
        proxy = {"observedAt": at, "flows": [], "connectionObservation": adapter.connection_observation(
            self.connection_observation(observed_at=at, collector_state="no_targets", target_count=0,
                parsed_count=0, accepted_count=0, correlated_count=0, unconfirmed_count=0), at)}
        value = adapter.active_proxy_flows(proxy, [{"pid": 9, "started": stamp, "kind": "desktop-main"}])
        self.assertEqual(value["connectionObservation"]["collectorState"], "partial")
        self.assertEqual(value["connectionObservation"]["uiDropped"]["new_process_not_sampled"], 1)

    def test_connection_receipt_projects_camel_case_and_preserves_collection_state(self):
        report = self.daemon_report()
        report["connection_observation"] = self.connection_observation(
            collector_state="empty", target_count=2, parsed_count=0, accepted_count=0,
            correlated_count=0, unconfirmed_count=0, dropped={}, detail="无可关联连接")
        receipt = adapter.proxy_snapshot(None, report)["connectionObservation"]
        self.assertEqual(receipt, {
            "schema": 1, "roundID": "round-1", "observedAt": 995.0,
            "collectorState": "empty", "targetCount": 2, "parsedCount": 0,
            "acceptedCount": 0, "correlatedCount": 0, "unconfirmedCount": 0,
            "dropped": {}, "detail": "无可关联连接",
            "uiFilteredCount": 0, "uiDropped": {},
        })

    def test_connection_receipt_bad_format_or_wrong_round_is_unknown(self):
        bad_receipts = (
            self.connection_observation(observed_at=1001),
            self.connection_observation(schema=2),
            self.connection_observation(schema=True),
            self.connection_observation(collector_state="empty"),
            self.connection_observation(collector_state="no_targets"),
            self.connection_observation(accepted_count=True),
            self.connection_observation(correlated_count=3, unconfirmed_count=1),
            self.connection_observation(dropped={"bad": -1}),
        )
        for receipt in bad_receipts:
            with self.subTest(receipt=receipt):
                report = self.daemon_report()
                report["connection_observation"] = receipt
                result = adapter.proxy_snapshot(None, report)["connectionObservation"]
                self.assertEqual(result["collectorState"], "unknown")
                self.assertEqual(result["uiFilteredCount"], 0)

        report = self.daemon_report()
        report["connection_observation"] = self.connection_observation(observed_at=1000)
        self.assertEqual(adapter.proxy_snapshot(None, report)["connectionObservation"]["collectorState"], "ok")

    def test_connection_receipt_allows_many_sockets_for_one_target_process(self):
        report = self.daemon_report()
        report["connection_observation"] = self.connection_observation(
            target_count=1, parsed_count=20, accepted_count=20,
            correlated_count=17, unconfirmed_count=3)
        self.assertEqual(adapter.proxy_snapshot(None, report)["connectionObservation"]["collectorState"], "ok")

        report["connection_observation"] = self.connection_observation(
            target_count=0, parsed_count=1, accepted_count=1,
            correlated_count=1, unconfirmed_count=0)
        self.assertEqual(adapter.proxy_snapshot(None, report)["connectionObservation"]["collectorState"], "unknown")

    def test_ui_pid_reuse_filter_makes_clean_collector_round_partial(self):
        report = self.daemon_report()
        report["connection_observation"] = self.connection_observation(target_count=1, parsed_count=1,
                                                                          accepted_count=1, correlated_count=1,
                                                                          unconfirmed_count=0)
        report["flows"] = [{"pid": 11, "local": ["127.0.0.1", 5000], "peer": ["198.18.0.1", 443]}]
        proxy = adapter.proxy_snapshot(None, report)
        filtered = adapter.active_proxy_flows(proxy, adapter.process_records("11|Fri Oct 16 15:06:16 2026|code\n"))
        self.assertEqual(filtered["flows"], [])
        self.assertEqual(filtered["connectionObservation"]["collectorState"], "partial")
        self.assertEqual(filtered["connectionObservation"]["uiDropped"], {"process_restarted": 1})

    def test_proxy_keeps_selection_separate_from_observed_chain(self):
        path = self.root / "proxy.json"
        raw = {"schema": 1, "observed_epoch": 995,
               "entry": {"state": "verified", "owners": [{"pid": 50, "executable": "/example/mihomo",
                                                                  "stamp": "Fri Oct 16 15:06:15 2026"}]},
               "api": {"state": "available", "mode": "global", "global_node": "JP09", "selected_node": "JP11", "covers_7890": False},
               "expected_node": "JP11", "flows": []}
        path.write_text(json.dumps(raw))
        result = adapter.proxy_snapshot(path)
        self.assertEqual(result["globalNode"], "JP09")
        self.assertEqual(result["expectedNode"], "JP11")
        self.assertEqual(result["flows"], [])
        self.assertFalse(result["coversProxy"])
        self.assertEqual(result["listenerStarted"], "Fri Oct 16 15:06:15 2026")
        raw["flows"] = [{"pid": 3, "peer": ["2001:db8::1", 443], "local": ["127.0.0.1", 5000],
                         "chains": ["JP11", "海外AI"], "policy": "match", "association": "correlated",
                         "path": "Tun", "interface": "utun4"}]
        path.write_text(json.dumps(raw))
        flow = adapter.proxy_snapshot(path)["flows"][0]
        self.assertEqual(flow["peer"], "[2001:db8::1]:443")
        self.assertEqual(flow["chains"], ["海外AI", "JP11"])
        self.assertEqual(flow["path"], "Tun")
        self.assertEqual(flow["interface"], "utun4")

    def test_listener_started_is_omitted_when_owner_is_not_verified_or_has_no_stamp(self):
        report = self.daemon_report()
        self.assertIsNone(adapter.proxy_snapshot(None, report)["listenerStarted"])
        report["entry"] = {"state": "unconfirmed", "owners": [{"pid": 1, "stamp": "unverified"}]}
        self.assertIsNone(adapter.proxy_snapshot(None, report)["listenerStarted"])

    def test_target_evidence_is_optional_and_revalidated(self):
        path = self.root / "proxy.json"
        raw = self.daemon_report()
        raw["flows"] = [
            {"pid": 3, "protocol": "tcp", "local": ["127.0.0.1", 5000], "peer": ["127.0.0.1", 7890],
             "destination_ip": "8.8.8.8", "destination_port": "443", "destination_ip_state": "public", "destination_country": "jp"},
            {"pid": 4, "protocol": "tcp", "local": ["127.0.0.1", 5001], "peer": ["127.0.0.1", 7890]},
            {"pid": 5, "protocol": "tcp", "local": ["127.0.0.1", 5002], "peer": ["127.0.0.1", 7890],
             "destination_ip": "198.19.1.1", "destination_ip_state": "public", "destination_country": "JP"},
            {"pid": 6, "protocol": "tcp", "local": ["127.0.0.1", 5003], "peer": ["127.0.0.1", 7890],
             "destination_ip": "2001:4860:4860::8888", "destination_port": 443, "destination_ip_state": "public", "destination_country": "US"},
            {"pid": 7, "protocol": "tcp", "local": ["127.0.0.1", 5004], "peer": ["127.0.0.1", 7890],
             "destination_ip": "198.18.1.1", "destination_port": 443, "destination_ip_state": "synthetic", "destination_country": "JP"},
        ]
        path.write_text(json.dumps(raw))
        flows = {flow["pid"]: flow for flow in adapter.proxy_snapshot(path)["flows"]}
        self.assertEqual((flows[3]["destinationIP"], flows[3]["destinationPort"], flows[3]["destinationIPState"], flows[3]["destinationCountry"]),
                         ("8.8.8.8", 443, "public", "JP"))
        self.assertEqual((flows[4]["destinationIP"], flows[4]["destinationIPState"]), ("", "missing"))
        self.assertEqual((flows[5]["destinationIP"], flows[5]["destinationIPState"], flows[5]["destinationCountry"]), ("", "invalid", ""))
        self.assertEqual((flows[6]["destinationIP"], flows[6]["destinationIPState"], flows[6]["destinationCountry"]),
                         ("2001:4860:4860::8888", "public", "US"))
        self.assertEqual((flows[7]["destinationIP"], flows[7]["destinationPort"], flows[7]["destinationIPState"], flows[7]["destinationCountry"]),
                         ("", 443, "synthetic", ""))

    def test_events_preserve_evidence_and_order(self):
        path = self.root / "events.log"
        raw = "2026-10-16T15:06:15+0900\tdaemon-start version=2.1.0\n2026-10-16T15:06:16+0900\ttag-proxy [配置差异] GLOBAL JP09\n"
        path.write_text(raw)
        result = adapter.tail_events(path)
        self.assertEqual(result[0]["severity"], "warning")
        self.assertEqual(result[0]["category"], "network")
        self.assertEqual(result[0]["detail"], "[配置差异] GLOBAL JP09")
        self.assertEqual(path.read_text(), raw)

    def test_absent_installation_does_not_fabricate_data(self):
        scratch = self.root / "scratch"
        scratch.mkdir()
        result = adapter.snapshot(self.root, scratch, full=True)
        self.assertFalse(result["installed"])
        self.assertEqual(result["processes"], [])
        self.assertEqual(result["events"], [])
        self.assertIsNone(result["proxy"])
        self.assertIsNotNone(result["proxyError"])

    def daemon_report(self):
        return {
            "schema": 1, "observed_epoch": 995,
            "producer": {"pid": 67166, "started": self.stamp},
            "entry": {"state": "verified", "owners": [{"pid": 53009, "executable": "/example/mihomo"}]},
            "api": {"state": "available", "covers_7890": True}, "flows": [],
        }

    def read_daemon_report(self, report, **health_changes):
        (self.root / "state/proxy-snapshot.json").write_text(json.dumps(report))
        health = self.health(f"67166|{self.stamp}|995|ok|GUARD")
        health.update(health_changes)
        return adapter.daemon_proxy_snapshot(self.root, health, 1000)

    def test_daemon_evidence_does_not_require_ui_socket_enumeration(self):
        proxy, error = self.read_daemon_report(self.daemon_report())
        self.assertIsNone(error)
        self.assertEqual(proxy["entryState"], "verified")
        self.assertEqual(proxy["listenerPID"], 53009)
        self.assertEqual(proxy["flows"], [])

    def test_daemon_restart_or_reused_pid_rejects_old_snapshot(self):
        for changed in ({"pid": 67167}, {"started": "Fri Oct 16 16:00:00 2026"}):
            with self.subTest(changed=changed):
                proxy, error = self.read_daemon_report(self.daemon_report(), **changed)
                self.assertIsNone(proxy)
                self.assertIn("身份", error)

    def test_stale_future_and_failed_daemon_never_show_current_success(self):
        for epoch in (900, 1001, float("nan")):
            raw = self.daemon_report()
            raw["observed_epoch"] = epoch
            with self.subTest(epoch=epoch):
                proxy, error = self.read_daemon_report(raw)
                self.assertIsNone(proxy)
                self.assertIn("过期", error)
        proxy, error = self.read_daemon_report(self.daemon_report(), state="degraded")
        self.assertIsNone(proxy)
        self.assertIn("心跳", error)

    def test_failed_collection_tombstone_and_symlink_are_rejected(self):
        proxy, error = self.read_daemon_report({})
        self.assertIsNone(proxy)
        path = self.root / "state/proxy-snapshot.json"
        path.unlink()
        target = self.root / "elsewhere.json"
        target.write_text(json.dumps(self.daemon_report()))
        path.symlink_to(target)
        health = self.health(f"67166|{self.stamp}|995|ok|GUARD")
        proxy, error = adapter.daemon_proxy_snapshot(self.root, health, 1000)
        self.assertIsNone(proxy)
        self.assertIn("路径", error)

    def test_real_publisher_and_reader_contract_without_network_or_service(self):
        source = Path(__file__).parents[2] / "claude-watch.sh"
        report_path = self.root / "input.json"
        raw = self.daemon_report()
        del raw["producer"]
        report_path.write_text(json.dumps(raw))
        command = (
            f"source {shlex.quote(str(source))}\n"
            f"STATE_DIR={shlex.quote(str(self.root / 'state'))}\n"
            f"DAEMON_STAMP={shlex.quote(self.stamp)}\n"
            f"publish_proxy_snapshot {shlex.quote(str(report_path))}\n"
            "printf '%s' \"$$\"\n"
        )
        result = subprocess.run(["/bin/bash", "-c", command], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        health = {"state": "running", "pid": int(result.stdout), "started": self.stamp}
        proxy, error = adapter.daemon_proxy_snapshot(self.root, health, 1000)
        self.assertIsNone(error)
        self.assertEqual(proxy["listenerPID"], 53009)
        self.assertEqual((self.root / "state/proxy-snapshot.json").stat().st_mode & 0o777, 0o600)

        failed = command[:command.index("publish_proxy_snapshot")] + "publish_proxy_snapshot -\n"
        result = subprocess.run(["/bin/bash", "-c", failed], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.root / "state/proxy-snapshot.json").read_text()), {})
        self.assertIsNone(adapter.daemon_proxy_snapshot(self.root, health, 1000)[0])

    def snapshot_home(self, now):
        home = self.root / "home"
        state = home / "Library/Application Support/ClaudeWatch/state"
        state.mkdir(parents=True)
        (home / "Library/Application Support/ClaudeWatch/claude-watch.sh").write_text("#!/bin/bash\n")
        agents = home / "Library/LaunchAgents"
        agents.mkdir(parents=True)
        (agents / "io.local.claudewatch.agent.plist").write_bytes(plistlib.dumps({"RunAtLoad": True, "KeepAlive": True}))
        scratch = self.root / "snapshot-scratch"
        scratch.mkdir()
        (scratch / "service-rc").write_text("0\n")
        (scratch / "service").write_text(self.service)
        (scratch / "process-stamp").write_text(self.stamp)
        (state / "mode").write_text("armed\n")
        (state / "heartbeat").write_text(f"67166|{self.stamp}|{int(now) - 1}|ok|GUARD\n")
        return home, state, scratch

    def test_quick_snapshot_reads_latest_proxy_and_configuration(self):
        now = time.time()
        home, state, scratch = self.snapshot_home(now)
        report = self.daemon_report()
        report["observed_epoch"] = now
        report["api"].update({"selected_node": "JP09", "global_node": "JP09"})
        (state / "tracked").write_text("3|not-a-date|code\n")
        report["flows"] = [{"pid": 3, "protocol": "tcp", "local": ["127.0.0.1", 5000],
                            "peer": ["203.0.113.1", 443], "connection_id": "first"}]
        (state / "proxy-snapshot.json").write_text(json.dumps(report))
        first = adapter.snapshot(home, scratch, full=False)
        self.assertEqual(first["proxy"]["selectedNode"], "JP09")
        self.assertEqual(len(first["proxy"]["flows"]), 1)
        report["api"]["selected_node"] = "JP11"
        report["flows"] = [{"pid": 3, "protocol": "tcp", "local": ["127.0.0.1", 5001],
                            "peer": ["203.0.113.2", 443], "connection_id": "second"}]
        (state / "proxy-snapshot.json").write_text(json.dumps(report))
        second = adapter.snapshot(home, scratch, full=False)
        self.assertEqual(second["proxy"]["selectedNode"], "JP11")
        self.assertEqual(second["proxy"]["flows"][0]["peer"], "203.0.113.2:443")

    def test_snapshot_drops_cached_flows_for_ended_or_newer_processes(self):
        now = time.time()
        home, state, scratch = self.snapshot_home(now)
        report = self.daemon_report()
        report["observed_epoch"] = now - 2
        report["flows"] = [{"pid": 3, "protocol": "tcp", "local": ["127.0.0.1", 5000],
                            "peer": ["203.0.113.1", 443], "connection_id": "first"}]
        (state / "proxy-snapshot.json").write_text(json.dumps(report))
        (state / "tracked").write_text("")
        self.assertEqual(adapter.snapshot(home, scratch)["proxy"]["flows"], [])
        (state / "tracked").write_text("3|Fri Oct 16 15:06:15 2026|code\n")
        report["observed_epoch"] = 2000
        (state / "heartbeat").write_text(f"67166|{self.stamp}|2001|ok|GUARD\n")
        (state / "proxy-snapshot.json").write_text(json.dumps(report))
        with mock.patch.object(adapter.time, "time", return_value=2001):
            self.assertEqual(adapter.snapshot(home, scratch)["proxy"]["flows"], [])

    def test_old_proxy_is_rejected_on_quick_snapshot(self):
        now = time.time()
        home, state, scratch = self.snapshot_home(now)
        report = self.daemon_report()
        report["observed_epoch"] = now - 31
        (state / "proxy-snapshot.json").write_text(json.dumps(report))
        result = adapter.snapshot(home, scratch)
        self.assertIsNone(result["proxy"])
        self.assertIn("过期", result["proxyError"])

    def test_flow_ids_stay_stable_when_source_order_changes(self):
        path = self.root / "proxy.json"
        base = {"schema": 1, "observed_epoch": 995, "entry": {}, "api": {}}
        first = dict(base, flows=[
            {"pid": 3, "protocol": "tcp", "local": ["127.0.0.1", 5000], "peer": ["203.0.113.1", 443], "connection_id": "a"},
            {"pid": 4, "protocol": "udp", "local": ["127.0.0.1", 5001], "peer": ["203.0.113.2", 53], "connection_id": "b"},
        ])
        path.write_text(json.dumps(first))
        ids = {flow["pid"]: flow["id"] for flow in adapter.proxy_snapshot(path)["flows"]}
        first["flows"].reverse()
        path.write_text(json.dumps(first))
        reordered = {flow["pid"]: flow["id"] for flow in adapter.proxy_snapshot(path)["flows"]}
        self.assertEqual(ids, reordered)
        first["flows"][0]["connection_id"] = "changed"
        path.write_text(json.dumps(first))
        changed = {flow["pid"]: flow["id"] for flow in adapter.proxy_snapshot(path)["flows"]}
        self.assertNotEqual(reordered[4], changed[4])


if __name__ == "__main__":
    unittest.main()
