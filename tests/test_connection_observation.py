"""Isolated connection-observation contract tests; no real process or network access."""
import datetime
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "claude-watch.sh"
SOURCE = SCRIPT.read_text().split("<<'PY_TAG'\n", 1)[1].split("\nPY_TAG\n", 1)[0]
tag = types.ModuleType("isolated_connection_observation")
exec(compile(SOURCE, str(SCRIPT) + ":TAG", "exec"), tag.__dict__)


class ConnectionObservationTests(unittest.TestCase):
    def receipt(self, **changes):
        value = {"schema": 1, "round_id": "round-1", "observed_at": time.time(), "collector_state": "ok",
                 "target_count": 0, "parsed_count": 0, "accepted_count": 0, "correlated_count": 0,
                 "unconfirmed_count": 0, "dropped": {}, "detail": "fixture"}
        value.update(changes)
        return value

    def test_missing_receipt_is_unknown_not_empty(self):
        value = tag.read_connection_observation("-")
        self.assertEqual(value["collector_state"], "unknown")
        self.assertIn("缺失", value["detail"])

    def test_invalid_receipt_fields_are_rejected_whole(self):
        for changes in ({"round_id": ""}, {"observed_at": float("nan")}, {"observed_at": time.time() - 60},
                        {"accepted_count": True}, {"dropped": {"bad": True}}, {"dropped": {"": 1}}):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as directory:
                filename = Path(directory) / "receipt.json"
                filename.write_text(json.dumps(self.receipt(**changes)))
                self.assertEqual(tag.read_connection_observation(str(filename))["collector_state"], "unknown")

    def test_read_flows_records_malformed_filtered_and_stale_identity(self):
        stamp = "Fri Oct 16 10:00:00 2026"
        with tempfile.TemporaryDirectory() as directory:
            targets = Path(directory) / "targets"
            connections = Path(directory) / "connections"
            targets.write_text("77|" + stamp + "|code\ninvalid\n")
            connections.write_text("bad\n78|TCP|127.0.0.1:1->127.0.0.1:7890\n"
                                   "77|TCP|not-an-endpoint->127.0.0.1:7890\n"
                                   "77|TCP|127.0.0.1:4->127.0.0.1:7890\n")
            observation = tag._observation_default()
            observation["collector_state"] = "ok"
            flows = tag.read_flows(str(targets), str(connections),
                                   {77: {"uid": os.getuid(), "stamp": "reused"}}, observation)
        self.assertEqual(len(flows), 1)
        self.assertFalse(flows[0][2])
        self.assertEqual(observation["dropped"], {"malformed_target": 1, "malformed_connection": 1,
                                                     "filtered_pid": 1, "malformed_endpoint": 1,
                                                     "identity_stale": 1})
        self.assertEqual((observation["target_count"], observation["parsed_count"], observation["accepted_count"]),
                         (1, 2, 0))

    def test_listener_and_unconnected_rows_are_benignly_excluded(self):
        stamp = "Fri Oct 16 10:00:00 2026"
        with tempfile.TemporaryDirectory() as directory:
            targets, connections = Path(directory) / "targets", Path(directory) / "connections"
            targets.write_text("77|" + stamp + "|code\n")
            connections.write_text("77|TCP|*:7890\n77|TCP|127.0.0.1:50000\n")
            observation = self.receipt()
            self.assertEqual(tag.read_flows(str(targets), str(connections),
                                             {77: {"uid": os.getuid(), "stamp": stamp}}, observation), [])
        self.assertEqual(observation["dropped"], {})
        self.assertEqual((observation["parsed_count"], observation["accepted_count"]), (0, 0))

    def test_stale_empty_files_downgrade_receipt_to_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            targets, connections = Path(directory) / "targets", Path(directory) / "connections"
            targets.write_text("")
            connections.write_text("")
            old = time.time() - 60
            os.utime(targets, (old, old))
            os.utime(connections, (old, old))
            observation = self.receipt(collector_state="empty")
            self.assertFalse(tag.observation_file_receipt_current(observation, str(targets), str(connections)))
        self.assertEqual(observation["collector_state"], "unknown")
        self.assertIn("stale_target_file", observation["dropped"])

    def test_collect_report_recalculates_multi_socket_observation(self):
        stamp = "Fri Oct 16 10:00:00 2026"
        owner = {"uid": os.getuid(), "stamp": stamp,
                 "executable": tag.TAG_BINARY_DIR + "mihomo-universal-tag-darwin"}
        target = {"uid": os.getuid(), "stamp": stamp, "executable": "/usr/bin/claude"}
        api = {"state": "available", "mode": "rule", "covers_7890": True,
               "selected_node": "JP11", "global_node": "", "reason": ""}
        def record(index, port):
            return {"id": "conn-" + str(index), "start": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "metadata": {"sourceIP": "127.0.0.1", "sourcePort": str(port), "network": "tcp",
                                 "inboundIP": "127.0.0.1", "inboundPort": "7890",
                                 "destinationIP": "203.0.113.9", "destinationPort": "443",
                                 "type": "HTTP", "host": "api.anthropic.com"},
                    "chains": ["JP11", "AI"], "rule": "DomainSuffix", "rulePayload": "anthropic.com"}
        with tempfile.TemporaryDirectory() as directory:
            targets, connections, receipt = (Path(directory) / "targets", Path(directory) / "connections",
                                              Path(directory) / "receipt.json")
            targets.write_text("77|" + stamp + "|code\n")
            connections.write_text("77|TCP|127.0.0.1:50000->127.0.0.1:7890\n"
                                   "77|TCP|127.0.0.1:50001->127.0.0.1:7890\n")
            receipt.write_text(json.dumps(self.receipt(target_count=1, parsed_count=99, accepted_count=99)))
            listener = subprocess.CompletedProcess([], 0, "p100\nn127.0.0.1:7890\n", "")
            with mock.patch.object(tag, "process_table", side_effect=[{100: owner, 77: target}, {100: owner, 77: target}]), \
                 mock.patch.object(tag, "listener_query", return_value=listener), \
                 mock.patch.object(tag, "tcp_reachable", return_value=True), \
                 mock.patch.object(tag, "api_snapshot", return_value=(api, [record(1, 50000), record(2, 50001)])), \
                 mock.patch.object(tag, "collect_fakeip_evidence", return_value={}):
                report = tag.collect_report(str(targets), str(connections), "-", collector_file=str(receipt))
        observed = report["connection_observation"]
        self.assertEqual((observed["target_count"], observed["parsed_count"], observed["accepted_count"],
                          observed["correlated_count"], observed["unconfirmed_count"]), (1, 2, 2, 2, 0))

    def run_collector(self, lsof_body, csv="77"):
        with tempfile.TemporaryDirectory() as directory:
            command = f'''source {SCRIPT!s}
set +e
TMP_SCAN={directory!s}/scan; mkdir -p "$TMP_SCAN"
CSV={shlex.quote(csv)}
lsof() {{ {lsof_body}; }}
connection_sample "$CSV" "$TMP_SCAN/status.json" > "$TMP_SCAN/connections"
rc=$?
python3 - "$TMP_SCAN/status.json" "$TMP_SCAN/connections" "$rc" <<'PY'
import json, pathlib, sys
value = json.load(open(sys.argv[1]))
print(json.dumps({{"status": value, "connections": pathlib.Path(sys.argv[2]).read_text(), "rc": int(sys.argv[3])}}))
PY
'''
            return json.loads(subprocess.run(["/bin/bash", "-c", command], check=True, text=True,
                                             capture_output=True).stdout)

    def test_lsof_failure_writes_failed_receipt(self):
        result = self.run_collector("printf denied >&2; return 1")
        self.assertEqual((result["rc"], result["status"]["collector_state"], result["connections"]),
                         (1, "failed", ""))

    def test_exit_one_without_output_is_empty_not_no_network_proof(self):
        result = self.run_collector("return 1")
        self.assertEqual((result["rc"], result["status"]["collector_state"]), (0, "empty"))
        self.assertIn("不能证明没有网络活动", result["status"]["detail"])

    def test_no_targets_receipt_is_distinct(self):
        result = self.run_collector("return 99", csv="")
        self.assertEqual((result["rc"], result["status"]["collector_state"], result["status"]["target_count"]),
                         (0, "no_targets", 0))

    def test_parse_pipeline_failure_is_not_empty_success(self):
        result = self.run_collector("printf 'p77\\nPTCP\\nn127.0.0.1:1->127.0.0.1:7890\\n'; awk() { return 55; }; return 0")
        self.assertEqual((result["rc"], result["status"]["collector_state"]), (1, "failed"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
