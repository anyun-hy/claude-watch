"""TAG adapter tests: all process inspection, sockets and HTTP are isolated."""
import contextlib
import copy
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock
import urllib.error

SCRIPT = Path(__file__).resolve().parents[1] / "claude-watch.sh"
SOURCE = SCRIPT.read_text().split("<<'PY_TAG'\n", 1)[1].split("\nPY_TAG\n", 1)[0]
tag = types.ModuleType("isolated_tag_adapter")
exec(compile(SOURCE, str(SCRIPT) + ":TAG", "exec"), tag.__dict__)


class TagTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(tag, "run_readonly", side_effect=AssertionError("real process command forbidden")))
        self.stack.enter_context(mock.patch.object(tag.socket, "create_connection", side_effect=AssertionError("real socket forbidden")))
        self.stack.enter_context(mock.patch.object(tag.urllib.request.OpenerDirector, "open", side_effect=AssertionError("real HTTP forbidden")))
        self.stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
        self.stamp = (datetime.datetime.now() - datetime.timedelta(seconds=30)).strftime("%a %b %d %H:%M:%S %Y")
        self.now = time.time()
        self.group = "🧲 海外AI"
        self.owner = {"uid": os.getuid(), "stamp": self.stamp,
                      "executable": tag.TAG_BINARY_DIR + "mihomo-universal-tag-darwin"}
        self.api = {"state": "available", "mode": "rule", "covers_7890": True,
                    "selected_node": "JP11", "global_node": "JP09", "reason": "",
                    "route_chains": {self.group: ["JP11", self.group], "GLOBAL": ["JP09", "GLOBAL"]}}
        self.flow = {"pid": 77, "protocol": "tcp", "local": ["127.0.0.1", 50000], "peer": ["127.0.0.1", 7890]}
        self.record = {
            "id": "conn-1",
            "start": datetime.datetime.fromtimestamp(self.now - 5, datetime.timezone.utc).isoformat(),
            "metadata": {"sourceIP": "127.0.0.1", "sourcePort": "50000", "network": "tcp",
                         "inboundIP": "127.0.0.1", "inboundPort": "7890",
                         "destinationIP": "203.0.113.9", "destinationPort": "443",
                         "type": "HTTP", "host": "api.anthropic.com"},
            "chains": ["JP11", self.group], "rule": "DomainSuffix", "rulePayload": "anthropic.com",
        }

    def entry(self, owner=None, second=None, output="p100\nn127.0.0.1:7890\n", reachable=True, error=""):
        first = {100: owner if owner is not None else self.owner}
        after = first if second is None else {100: second}
        return tag.inspect_entry(first, after, subprocess.CompletedProcess([], 0, output, error), reachable)

    def correlate(self, records=None, flow=None, api=None):
        return tag.correlate_flow(flow or self.flow, self.stamp, api or self.api,
                                  records if records is not None else [self.record], self.group, "JP11", self.now)

    def base_report(self):
        return {"entry": self.entry(), "api": self.api, "expected_group": self.group,
                "expected_node": "JP11", "pinned": True, "selection_changed": False, "flows": []}

    def test_tag_listener_with_stable_identity(self):
        self.assertEqual(self.entry()["state"], "verified")

    def test_empty_lsof_recovers_root_listener_pid_from_kernel_table(self):
        kernel = "tcp4 0 0 127.0.0.1.7890 *.* LISTEN 0 0 131072 131072 mihomo-universal:53009 00180 00000006\n"
        results = [subprocess.CompletedProcess([], 1, "", ""), subprocess.CompletedProcess([], 0, kernel, "")]
        with mock.patch.object(tag, "run_readonly", side_effect=results) as reader:
            evidence = tag.listener_query()
        root = {53009: {**self.owner, "uid": 0}}
        report = tag.inspect_entry(root, root, evidence, True)
        self.assertEqual(report["state"], "verified")
        self.assertEqual(report["source"], "netstat")
        self.assertEqual(report["owners"][0]["pid"], 53009)
        self.assertEqual(reader.call_args_list[1].args[0], ["/usr/sbin/netstat", "-anv", "-p", "tcp"])

    def test_kernel_fallback_does_not_relax_process_identity(self):
        kernel = "tcp4 0 0 127.0.0.1.7890 *.* LISTEN 0 0 1 1 python:53009\n"
        results = [subprocess.CompletedProcess([], 1, "", ""), subprocess.CompletedProcess([], 0, kernel, "")]
        with mock.patch.object(tag, "run_readonly", side_effect=results):
            evidence = tag.listener_query()
        wrong = {53009: {**self.owner, "uid": 0, "executable": "/usr/bin/python3"}}
        self.assertEqual(tag.inspect_entry(wrong, wrong, evidence, True)["state"], "mismatch")
        self.assertEqual(tag.inspect_entry({53009: self.owner}, wrong, evidence, True)["state"], "unconfirmed")

    def test_kernel_fallback_requires_a_readable_pid(self):
        kernel = "tcp4 0 0 127.0.0.1.7890 *.* LISTEN 0 0 1 1 unknown:0\n"
        results = [subprocess.CompletedProcess([], 1, "", ""), subprocess.CompletedProcess([], 0, kernel, "")]
        with mock.patch.object(tag, "run_readonly", side_effect=results):
            evidence = tag.listener_query()
        self.assertEqual(tag.inspect_entry({}, {}, evidence, True)["state"], "unconfirmed")

    def test_explicit_lsof_errors_are_not_hidden_by_fallback(self):
        error = subprocess.CompletedProcess([], 1, "", "permission denied")
        with mock.patch.object(tag, "run_readonly", return_value=error) as reader:
            self.assertIs(tag.listener_query(), error)
            self.assertEqual(reader.call_count, 1)

    def test_shell_snapshot_works_when_python_netstat_is_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot, errors = Path(directory) / "listeners", Path(directory) / "errors"
            snapshot.write_text("tcp4 0 0 127.0.0.1.7890 *.* LISTEN 0 0 1 1 mihomo:53009\n")
            errors.write_text("")
            with mock.patch.object(tag, "process_table", return_value={53009: {**self.owner, "uid": 0}}), \
                 mock.patch.object(tag, "run_readonly", return_value=subprocess.CompletedProcess([], 1, "", "")) as reader, \
                 mock.patch.object(tag, "tcp_reachable", return_value=True), \
                 mock.patch.object(tag, "api_snapshot", return_value=(self.api, [])):
                report = tag.collect_report("-", "-", "-", str(snapshot), str(errors), "0")
            self.assertEqual(report["entry"]["state"], "verified")
            self.assertEqual(reader.call_count, 1)
            self.assertEqual(reader.call_args.args[0][0], "/usr/sbin/lsof")

    def test_closed_port_is_unavailable(self):
        self.assertEqual(self.entry(reachable=False)["state"], "unavailable")

    def test_hidden_listener_is_unknown_not_absent(self):
        self.assertEqual(self.entry(output="")["state"], "unconfirmed")

    def test_other_program_or_same_named_binary_is_rejected(self):
        for exe in ("/usr/bin/python3", "/tmp/TAG.app/Contents/Resources/bin/mihomo",
                    "/Applications/TAG.app/Contents/Resources/bin/../other/mihomo"):
            with self.subTest(exe=exe):
                self.assertEqual(self.entry(owner={**self.owner, "executable": exe})["state"], "mismatch")

    def test_listener_pid_reuse_is_not_verified(self):
        self.assertEqual(self.entry(second={**self.owner, "stamp": "different"})["state"], "unconfirmed")

    def test_listener_read_error_does_not_pass(self):
        self.assertEqual(self.entry(error="permission denied")["state"], "unconfirmed")

    def test_lan_listener_is_reported_without_configuration_change(self):
        report = self.base_report()
        report["entry"] = self.entry(output="p100\nn*:7890\n")
        self.assertTrue(report["entry"]["public_listener"])
        self.assertEqual(tag.report_exit(report), 3)

    def test_exact_http_proxy_flow_matches_node_and_group(self):
        result = self.correlate()
        self.assertEqual((result["association"], result["policy"]), ("correlated", "match"))
        self.assertEqual(result["host"], "api.anthropic.com")

    def test_public_destination_evidence_includes_valid_country_only(self):
        record = copy.deepcopy(self.record)
        record["metadata"].update(destinationIP="8.8.8.8", destinationPort="443", destinationGeoIP="jp")
        result = self.correlate([record])
        self.assertEqual((result["destination_ip"], result["destination_port"],
                          result["destination_ip_state"], result["destination_country"]),
                         ("8.8.8.8", 443, "public", "JP"))

    def test_empty_destination_never_uses_proxy_transport_endpoint(self):
        record = copy.deepcopy(self.record)
        record["metadata"].update(destinationIP="", destinationPort="443", remoteDestination="58.247.187.44:443")
        result = self.correlate([record])
        self.assertEqual((result["destination_ip"], result["destination_port"], result["destination_ip_state"]),
                         ("", 443, "missing"))
        self.assertNotIn("58.247.187.44", result.values())

    def test_fake_and_nonpublic_destination_addresses_are_not_exposed_as_targets(self):
        for address, state in (("198.18.1.10", "synthetic"), ("198.19.255.1", "synthetic"),
                               ("127.0.0.1", "nonpublic"), ("10.0.0.1", "nonpublic"),
                               ("::1", "nonpublic"), ("ff02::1", "nonpublic")):
            record = copy.deepcopy(self.record)
            record["metadata"].update(destinationIP=address, destinationGeoIP="JP")
            with self.subTest(address=address):
                result = self.correlate([record])
                self.assertEqual((result["destination_ip"], result["destination_ip_state"], result["destination_country"]),
                                 ("", state, ""))

    def test_malformed_destination_and_country_are_not_presented_as_evidence(self):
        record = copy.deepcopy(self.record)
        record["metadata"].update(destinationIP="not-an-ip", destinationGeoIP="Japan")
        result = self.correlate([record])
        self.assertEqual((result["destination_ip"], result["destination_ip_state"], result["destination_country"]),
                         ("", "invalid", ""))

    def test_same_hostname_different_source_is_not_claude(self):
        record = copy.deepcopy(self.record)
        record["metadata"]["sourcePort"] = "50001"
        self.assertEqual(self.correlate([record])["association"], "unconfirmed")

    def test_same_port_different_source_address_or_protocol_does_not_match(self):
        for key, value in (("sourceIP", "::1"), ("network", "udp"), ("processID", 88), ("inboundPort", 7891)):
            record = copy.deepcopy(self.record)
            record["metadata"][key] = value
            with self.subTest(key=key):
                self.assertEqual(self.correlate([record])["association"], "unconfirmed")

    def test_double_core_does_not_guess_chain_from_matching_hostname(self):
        result = self.correlate(api={**self.api, "covers_7890": False})
        self.assertEqual(result["association"], "unconfirmed")
        self.assertIn("另一内核", result["reason"])

    def test_tun_record_is_not_matched_to_local_http_entry(self):
        record = copy.deepcopy(self.record)
        record["metadata"]["type"] = "Tun"
        self.assertEqual(self.correlate([record])["association"], "unconfirmed")

    def test_ambiguous_connections_do_not_pick_first(self):
        second = copy.deepcopy(self.record)
        second["id"] = "conn-2"
        self.assertEqual(self.correlate([self.record, second])["association"], "unconfirmed")

    def test_old_missing_or_future_connection_start_is_not_trusted(self):
        for stamp in ("2000-01-01T00:00:00Z", None, "2999-01-01T00:00:00Z"):
            record = copy.deepcopy(self.record)
            record["start"] = stamp
            self.assertEqual(self.correlate([record])["association"], "unconfirmed")

    def test_nanosecond_api_timestamp_is_accepted(self):
        self.assertAlmostEqual(tag.epoch_from_start("2026-10-16T03:00:00.123456789Z"),
                               tag.epoch_from_start("2026-10-16T03:00:00.123456Z"))

    def test_global_route_to_wrong_node_is_a_policy_mismatch(self):
        record = copy.deepcopy(self.record)
        record["chains"] = ["JP09", "GLOBAL"]
        result = self.correlate([record])
        self.assertEqual(result["association"], "correlated")
        self.assertEqual(result["policy"], "mismatch")

    def test_right_node_without_expected_group_does_not_claim_group_matched(self):
        record = copy.deepcopy(self.record)
        record["chains"] = ["JP11", "GLOBAL"]
        self.assertEqual(self.correlate([record])["policy"], "mismatch")

    def test_global_automatically_compares_actual_global_selection(self):
        api = {**self.api, "mode": "global"}
        record = {**self.record, "chains": ["JP09", "GLOBAL"], "rule": ""}
        self.assertEqual(tag.connection_policy(record["chains"], "GLOBAL", "JP09", api, record)[0], "match")
        self.assertEqual(tag.connection_policy(record["chains"], "GLOBAL", "JP11", api, record)[0], "mismatch")
        self.assertEqual(tag.connection_policy(["JP11", "GLOBAL"], "GLOBAL", "JP11", api, record)[0], "mismatch")
        self.assertEqual(tag.connection_policy(record["chains"], self.group, "JP09", api, record)[0], "mismatch")

    def test_rule_mode_automatically_uses_independently_resolved_chain(self):
        self.assertEqual(tag.connection_policy(self.record["chains"], "", "", self.api, self.record)[0], "match")
        self.assertEqual(tag.connection_policy(["JP09", self.group], "", "", self.api, self.record)[0], "mismatch")
        self.assertEqual(tag.connection_policy(self.record["chains"], "", "", self.api, {**self.record, "rule": ""})[0], "unconfirmed")
        self.assertEqual(tag.connection_policy(self.record["chains"], "", "", {**self.api, "route_chains": {}}, self.record)[0], "unconfirmed")

    def test_direct_unknown_and_intermediate_chain_change_do_not_pass(self):
        for api, chain in (({**self.api, "mode": "direct"}, self.record["chains"]),
                           (self.api, ["DIRECT"]), (self.api, ["JP11", "Unexpected", self.group])):
            self.assertEqual(tag.connection_policy(chain, "", "", api, self.record)[0], "mismatch")
        self.assertEqual(tag.connection_policy(self.record["chains"], "", "", {**self.api, "mode": "unknown"}, self.record)[0], "unconfirmed")

    def test_api_global_selection_does_not_require_default_ai_group(self):
        configs = {"mode": "global", "mixed-port": 7890}
        proxies = {"proxies": {"GLOBAL": {"type": "Selector", "now": "JP09"}, "JP09": {"type": "Shadowsocks"}}}
        with mock.patch.object(tag, "controller_credentials", return_value=("http://127.0.0.1:9090", "")), \
             mock.patch.object(tag, "api_get", side_effect=[configs, proxies, {"connections": []}, {"rules": []}]):
            report, _ = tag.api_snapshot("fixture", "")
        self.assertEqual(report["selected_node"], "JP09")
        self.assertEqual(report["route_chains"]["GLOBAL"], ["JP09", "GLOBAL"])

    def test_exact_tun_tuple_can_be_correlated_without_7890(self):
        flow = {**self.flow, "local": ["198.18.0.1", 50000], "peer": ["203.0.113.9", 443]}
        record = copy.deepcopy(self.record)
        record["metadata"].update(sourceIP="198.18.0.1", type="Tun")
        with mock.patch.object(tag, "route_interface", return_value="utun4"):
            result = self.correlate([record], flow)
        self.assertEqual((result["association"], result["policy"], result["path"]), ("correlated", "match", "Tun"))

    def test_incomplete_fake_ip_tuple_remains_unknown_not_direct_leak(self):
        flow = {**self.flow, "local": ["198.18.0.1", 50000], "peer": ["198.18.1.10", 443]}
        record = copy.deepcopy(self.record)
        record["metadata"].update(sourceIP="198.18.0.1", type="Tun", destinationIP="", dnsMode="fake-ip")
        with mock.patch.object(tag, "route_interface", return_value="utun4"):
            result = self.correlate([record], flow)
        self.assertEqual(result["association"], "unconfirmed")
        self.assertEqual(result["interface"], "utun4")
        self.assertIn("不能认定直连泄漏", result["reason"])

    def test_other_loopback_service_is_not_a_proxy_bypass_alert(self):
        result = self.correlate(flow={**self.flow, "peer": ["127.0.0.1", 9001]})
        self.assertEqual(result["policy"], "not_applicable")

    def test_malformed_api_records_are_not_correlated(self):
        self.assertEqual(self.correlate([{"metadata": None}, {"id": []}, "invalid"])["association"], "unconfirmed")

    def test_controller_credentials_accept_only_loopback(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "config.yaml"
            filename.write_text('external-controller: "127.0.0.1:9090"\nsecret: "private-token"\n')
            self.assertEqual(tag.controller_credentials(filename), ("http://127.0.0.1:9090", "private-token"))
            for address in ("evil.example:9090", "127.0.0.1:9090/path", "user@127.0.0.1:9090"):
                filename.write_text("external-controller: " + address + "\nsecret: private-token\n")
                with self.assertRaises(ValueError):
                    tag.controller_credentials(filename)

    def test_local_api_uses_get_no_proxy_and_no_redirect(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"mode":"rule"}'
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(tag.urllib.request, "build_opener", return_value=opener) as builder:
            self.assertEqual(tag.api_get("http://127.0.0.1:9090", "private-token", "/configs"), {"mode": "rule"})
            request = opener.open.call_args.args[0]
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.full_url, "http://127.0.0.1:9090/configs")
            self.assertIsNone(request.data)
            self.assertEqual(builder.call_args.args[0].proxies, {})
            self.assertIsInstance(builder.call_args.args[1], tag.NoRedirect)
        self.assertIsNone(tag.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.example"))
        for endpoint in ("/restart", "/cache/dns/flush", "/configs?force=true"):
            with self.assertRaises(ValueError):
                tag.api_get("http://127.0.0.1:9090", "private-token", endpoint)

    def test_rules_endpoint_is_read_only_and_publish_is_domain_bounded(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"rules":["DOMAIN-SUFFIX,claude.ai,GLOBAL","DOMAIN,example.com,DIRECT","MATCH,GLOBAL"]}'
        opener = mock.Mock(); opener.open.return_value = response
        with mock.patch.object(tag.urllib.request, "build_opener", return_value=opener):
            payload = tag.api_get("http://127.0.0.1:9090", "private-token", "/rules")
        published = tag.published_rules(payload)
        self.assertEqual(published["entries"], ["DOMAIN-SUFFIX,claude.ai,GLOBAL", "MATCH,GLOBAL"])
        self.assertEqual((published["total"], published["relevant"]), (3, 1))
        request = opener.open.call_args.args[0]
        self.assertEqual((request.get_method(), request.full_url, request.data), ("GET", "http://127.0.0.1:9090/rules", None))

    def test_actual_mihomo_rule_objects_are_canonicalized_without_payload_leak(self):
        published = tag.published_rules({"rules": [
            {"type": "DomainSuffix", "payload": "claude.ai", "proxy": "GLOBAL", "extra": "ignored"},
            {"type": "DomainKeyword", "payload": "private-rule-set://token", "proxy": "GLOBAL"},
            {"type": "IPCIDR", "payload": "10.0.0.0/8", "proxy": "DIRECT"},
            {"type": "Domain", "payload": "user@private.invalid", "proxy": "GLOBAL"},
        ]})
        self.assertEqual(published["entries"], ["DOMAIN-SUFFIX,claude.ai,GLOBAL", "DOMAIN-KEYWORD,*,GLOBAL", "IP-CIDR,*,DIRECT"])
        self.assertNotIn("private-rule-set", repr(published))
        self.assertNotIn("10.0.0.0", repr(published))

    def test_rule_table_failure_does_not_erase_verified_api_state(self):
        configs = {"mode": "rule", "mixed-port": 7890}
        proxies = {"proxies": {self.group: {"type": "Selector", "now": "JP11"},
                                "GLOBAL": {"type": "Selector", "now": "JP09"},
                                "JP11": {"type": "Shadowsocks"}, "JP09": {"type": "Shadowsocks"}}}
        failure = urllib.error.HTTPError("http://127.0.0.1:9090/rules", 404, "not found", {}, None)
        with mock.patch.object(tag, "controller_credentials", return_value=("http://127.0.0.1:9090", "private-token")), \
             mock.patch.object(tag, "api_get", side_effect=[configs, proxies, {"connections": []}, failure]):
            report, records = tag.api_snapshot("fixture", self.group)
        self.assertEqual((report["state"], report["mode"], records), ("available", "rule", []))
        self.assertEqual(report["rules"]["state"], "unavailable")
        self.assertNotIn("private-token", repr(report))

    def test_invalid_or_oversized_rule_table_is_not_published(self):
        for value in ({"rules": "not-a-list"}, {"rules": ["MATCH,GLOBAL"] * (tag.MAX_RULE_ENTRIES + 1)}):
            with self.subTest(value=type(value["rules"]).__name__):
                with self.assertRaises(ValueError):
                    tag.published_rules(value)

    def test_api_auth_failure_never_prints_token(self):
        error = urllib.error.HTTPError("http://127.0.0.1:9090", 401, "private-token", {}, None)
        with mock.patch.object(tag, "controller_credentials", return_value=("http://127.0.0.1:9090", "private-token")), \
             mock.patch.object(tag, "api_get", side_effect=error):
            report, records = tag.api_snapshot("fixture", self.group)
        self.assertEqual(report["state"], "unavailable")
        self.assertEqual(records, [])
        self.assertNotIn("private-token", repr(report))

    def test_wrong_listener_skips_credential_and_api_access(self):
        processes = {100: {**self.owner, "executable": "/tmp/mihomo"}}
        with mock.patch.object(tag, "process_table", return_value=processes), \
             mock.patch.object(tag, "run_readonly", return_value=subprocess.CompletedProcess([], 0, "p100\nn127.0.0.1:7890\n", "")), \
             mock.patch.object(tag, "tcp_reachable", return_value=True), \
             mock.patch.object(tag, "api_snapshot", side_effect=AssertionError("credentials must not be touched")):
            report = tag.collect_report("-", "-", "-")
        self.assertEqual(tag.report_exit(report), 4)

    def test_collect_report_moves_rule_snapshot_out_of_api_object(self):
        rules = {"state": "available", "reason": "", "entries": ["MATCH,GLOBAL"], "total": 1, "relevant": 0, "broad": 1}
        with mock.patch.object(tag, "process_table", return_value={100: self.owner}), \
             mock.patch.object(tag, "run_readonly", return_value=subprocess.CompletedProcess([], 0, "p100\nn127.0.0.1:7890\n", "")), \
             mock.patch.object(tag, "tcp_reachable", return_value=True), \
             mock.patch.object(tag, "api_snapshot", return_value=({**self.api, "rules": rules}, [])):
            report = tag.collect_report("-", "-", "-")
        self.assertEqual(report["rules"], rules)
        self.assertNotIn("rules", report["api"])

    def test_pinned_node_is_not_silently_replaced_by_new_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline"
            baseline.write_text("tag_group=" + self.group + "\ntag_node=JP11\n")
            with mock.patch.object(tag, "process_table", return_value={100: self.owner}), \
                 mock.patch.object(tag, "run_readonly", return_value=subprocess.CompletedProcess([], 0, "p100\nn127.0.0.1:7890\n", "")), \
                 mock.patch.object(tag, "tcp_reachable", return_value=True), \
                 mock.patch.object(tag, "api_snapshot", return_value=({**self.api, "selected_node": "JP12"}, [])):
                report = tag.collect_report("-", "-", str(baseline))
        self.assertEqual(report["expected_node"], "JP11")
        self.assertTrue(report["selection_changed"])
        self.assertEqual(tag.report_exit(report), 3)

    def test_selection_resolver_handles_nested_group_and_rejects_cycle_or_direct(self):
        proxies = {"AI": {"type": "Selector", "now": "Auto"}, "Auto": {"type": "URLTest", "now": "JP11"}, "JP11": {"type": "Shadowsocks"}}
        self.assertEqual(tag.resolve_selection(proxies, "AI"), "JP11")
        proxies["Auto"]["now"] = "AI"
        self.assertIsNone(tag.resolve_selection(proxies, "AI"))
        self.assertIsNone(tag.resolve_selection({"DIRECT": {"type": "Direct"}}, "DIRECT"))

    def test_new_baseline_accepts_current_selection_not_stale_pin(self):
        report = self.base_report()
        report["api"] = {**self.api, "selected_node": "JP12"}
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "report.json"
            filename.write_text(json.dumps(report))
            output = io.StringIO()
            with mock.patch.object(tag.sys, "argv", ["adapter", "baseline", str(filename)]), contextlib.redirect_stdout(output):
                self.assertEqual(tag.main(), 0)
            self.assertIn("tag_node=JP12", output.getvalue())

    def test_baseline_refuses_unknown_api_even_with_old_pin(self):
        report = self.base_report()
        report["api"] = {"state": "unavailable"}
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "report.json"
            filename.write_text(json.dumps(report))
            with mock.patch.object(tag.sys, "argv", ["adapter", "baseline", str(filename)]):
                self.assertEqual(tag.main(), 4)

    def test_cli_proxy_configuration_and_bypass_are_separate(self):
        with mock.patch.dict(os.environ, {"https_proxy": "http://127.0.0.1:7890", "NO_PROXY": "localhost,127.0.0.1,::1"}):
            self.assertEqual(tag.cli_proxy_state(), {"matches_7890": True, "other_bypass_rules": False, "bypass_all": False})
        with mock.patch.dict(os.environ, {"https_proxy": "http://127.0.0.1:7891", "HTTPS_PROXY": "http://127.0.0.1:7890", "NO_PROXY": "*"}):
            state = tag.cli_proxy_state()
            self.assertFalse(state["matches_7890"])
            self.assertTrue(state["bypass_all"])
        with mock.patch.dict(os.environ, {"all_proxy": "socks5h://127.0.0.1:7890"}):
            self.assertFalse(tag.cli_proxy_state()["matches_7890"])

    def test_stale_socket_or_reused_pid_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            targets, connections = Path(directory) / "targets", Path(directory) / "connections"
            targets.write_text("77|" + self.stamp + "|code\n")
            connections.write_text("77|TCP|127.0.0.1:50000->127.0.0.1:7890\n")
            processes = {77: {"uid": os.getuid(), "stamp": "reused"}}
            self.assertFalse(tag.read_flows(str(targets), str(connections), processes)[0][2])
            processes[77]["stamp"] = self.stamp
            os.utime(connections, (self.now - 60, self.now - 60))
            self.assertFalse(tag.read_flows(str(targets), str(connections), processes)[0][2])

    def test_one_no_proxy_casing_cannot_hide_global_bypass_in_other(self):
        with mock.patch.dict(os.environ, {"https_proxy": "http://127.0.0.1:7890", "no_proxy": "localhost", "NO_PROXY": "*"}):
            self.assertTrue(tag.cli_proxy_state()["bypass_all"])

    def test_no_claude_sample_does_not_claim_actual_route_verified(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = tag.render(self.base_report())
        self.assertEqual(rc, 0)
        self.assertIn("没有可关联的受监控应用连接样本", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)

