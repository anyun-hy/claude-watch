import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("dns_probe", Path(__file__).parents[1] / "Resources/dns_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def is_geoip_command(command):
    return (isinstance(command, list) and bool(command) and command[0] == "/usr/bin/curl"
            and isinstance(command[-1], str) and command[-1].startswith(probe.GEOIP_URL_PREFIX))


class DNSProbeTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "requires macOS system tools")
    def test_default_route_context_command_is_executable(self):
        command = next(command for name, command in probe.CONTEXT_COMMANDS if name == "route4")
        self.assertTrue(Path(command[0]).is_file())
        self.assertTrue(os.access(command[0], os.X_OK))

    class Process:
        def __init__(self, command, returncode=0, stdout=""):
            self.command = command
            self.returncode = returncode
            self.stdout = stdout
            self.terminated = False

        def communicate(self, timeout=None):
            return self.stdout, ""

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.terminated = True
            self.returncode = -9

    def responses(self, dig='"ns" "8.8.8.8"\n"ns" "2606:4700:4700::1111"\n', curl='ip=1.1.1.1\n', geo='{"country_code":"US"}'):
        def popen(command, **kwargs):
            if command == probe.DNS_COMMAND:
                return self.Process(command, 0, dig)
            if command == probe.HTTP_COMMAND:
                return self.Process(command, 0, curl)
            if is_geoip_command(command):
                return self.Process(command, 0, geo)
            if command == probe.CONTEXT_COMMANDS[-1][1]:
                return self.Process(command, 0, "Internet6:\nDestination Gateway Flags Netif\n")
            return self.Process(command, 0, "context\n")
        return popen

    def test_normal_multiple_ns_and_forced_proxy_contract(self):
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responses()) as popen:
            result = probe.collect()
        self.assertEqual(result["status"], "complete")
        self.assertEqual([row["address"] for row in result["observations"]], ["8.8.8.8", "2606:4700:4700::1111", "1.1.1.1"])
        self.assertEqual(result["scope"], "dig/resolv.conf DNS 路径；HTTP 经 7890 参考")
        curl_call = next(call.args[0] for call in popen.call_args_list if call.args[0] == probe.HTTP_COMMAND)
        self.assertEqual(curl_call, probe.HTTP_COMMAND)
        self.assertIn("--proxy", curl_call)
        self.assertEqual(curl_call[curl_call.index("--proxy") + 1], "http://127.0.0.1:7890")
        self.assertEqual(curl_call[curl_call.index("--noproxy") + 1], "")
        self.assertNotIn("-k", curl_call)
        self.assertNotIn("-L", curl_call)

    def test_no_ns_is_explicitly_incomplete(self):
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responses(dig='"ecs" "1.2.3.0/24"\n')):
            result = probe.collect()
        self.assertEqual(result["status"], "error")
        self.assertIn("no_ns", [row["code"] for row in result["errors"]])

    def test_dns_timeout_is_timeout(self):
        def popen(command, **kwargs):
            if command == probe.DNS_COMMAND:
                child = self.Process(command)
                def timeout(timeout=None):
                    raise subprocess.TimeoutExpired(command, timeout)
                child.communicate = timeout
                return child
            return self.Process(command, 0, "ip=1.1.1.1\n" if command == probe.HTTP_COMMAND else "context\n")
        with mock.patch.object(probe.subprocess, "Popen", side_effect=popen):
            result = probe.collect()
        self.assertEqual(result["status"], "timeout")
        self.assertIn("timeout", [row["code"] for row in result["errors"]])

    def test_dns_success_http_failure_is_partial(self):
        def popen(command, **kwargs):
            if command == probe.HTTP_COMMAND:
                return self.Process(command, 22, "")
            return self.responses()(command, **kwargs)
        with mock.patch.object(probe.subprocess, "Popen", side_effect=popen):
            result = probe.collect()
        self.assertEqual(result["status"], "partial")
        self.assertEqual([row["kind"] for row in result["observations"]], ["resolver", "resolver"])

    def test_ipv6_and_fake_private_answers_are_filtered(self):
        dig = '\n'.join(['"ns" "2606:4700:4700::1111"', '"ns" "127.0.0.1"', '"ns" "198.18.1.2"', '"ns" "10.0.0.1"', '"ns" "bad"'])
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responses(dig=dig, curl='ip=2001:4860:4860::8888\n')):
            result = probe.collect()
        self.assertEqual([row["address"] for row in result["observations"]], ["2606:4700:4700::1111", "2001:4860:4860::8888"])
        self.assertEqual(result["status"], "partial")
        self.assertIn("invalid_ns", [row["code"] for row in result["errors"]])

    def test_multicast_scope_zone_and_v4_mapped_are_handled_strictly(self):
        self.assertIsNone(probe.public_address("224.0.0.1"))
        self.assertIsNone(probe.public_address("fe80::1%en0"))
        self.assertEqual(probe.public_address("::ffff:8.8.8.8"), "8.8.8.8")

    def test_absent_ipv6_default_is_valid_context(self):
        contexts = iter(["dns", "proxy", "route4", "Internet6:\nDestination Gateway Flags Netif\n", "dns", "proxy", "route4", "Internet6:\nDestination Gateway Flags Netif\n"])
        def popen(command, **kwargs):
            if command in (probe.DNS_COMMAND, probe.HTTP_COMMAND):
                return self.responses()(command, **kwargs)
            if is_geoip_command(command):
                return self.Process(command, 0, '{"error":"not enriched"}')
            return self.Process(command, 0, next(contexts))
        with mock.patch.object(probe.subprocess, "Popen", side_effect=popen):
            result = probe.collect()
        self.assertEqual(result["status"], "complete")
        self.assertEqual(probe.stable_inet6_defaults("Internet6:\nDestination Gateway Flags Netif\n"), "absent")

    def test_blank_or_malformed_context_is_unknown_not_absent(self):
        def blank_popen(command, **kwargs):
            if command in (probe.DNS_COMMAND, probe.HTTP_COMMAND):
                return self.responses()(command, **kwargs)
            return self.Process(command, 0, "   \n")
        with mock.patch.object(probe.subprocess, "Popen", side_effect=blank_popen):
            result = probe.collect()
        self.assertEqual(result["status"], "partial")
        self.assertIn("context_unknown", [row["code"] for row in result["errors"]])
        self.assertIsNone(probe.stable_inet6_defaults("Internet6:\ndefault fe80::1\n"))

    def test_oversize_stdout_is_explicit_error(self):
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responses(dig='x' * 32769)):
            result = probe.collect()
        self.assertEqual(result["status"], "error")
        self.assertIn("output_limit", [row["code"] for row in result["errors"]])

    def test_context_change_is_partial(self):
        contexts = iter(["one", "one", "one", "Internet6:\nDestination Gateway Flags Netif\n", "two", "one", "one", "Internet6:\nDestination Gateway Flags Netif\n"])
        def popen(command, **kwargs):
            if command in (probe.DNS_COMMAND, probe.HTTP_COMMAND):
                return self.responses()(command, **kwargs)
            if is_geoip_command(command):
                return self.Process(command, 0, '{"error":"not enriched"}')
            return self.Process(command, 0, next(contexts))
        with mock.patch.object(probe.subprocess, "Popen", side_effect=popen):
            result = probe.collect()
        self.assertTrue(result["contextChanged"])
        self.assertEqual(result["status"], "partial")

    def test_resolver_attribution_enriches_without_downgrading_the_round(self):
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responses(geo='{"country_code":"US"}')) as popen:
            result = probe.collect()
        resolvers = [row for row in result["observations"] if row["kind"] == "resolver"]
        self.assertEqual([row["country"] for row in resolvers], ["US", "US"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["errors"], [])
        geo_calls = [call.args[0] for call in popen.call_args_list if call.args[0][-1].startswith(probe.GEOIP_URL_PREFIX)]
        self.assertEqual(len(geo_calls), 2)
        self.assertIn("--proxy", geo_calls[0])
        self.assertEqual(geo_calls[0][geo_calls[0].index("--proxy") + 1], "http://127.0.0.1:7890")

    def test_failed_resolver_attribution_stays_silent_and_keeps_the_round_complete(self):
        # A broken side channel must not write into `errors`: the geography
        # verdict keeps failing closed on the missing attribution instead.
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.responses(geo='{"error":"rate limited"}')):
            result = probe.collect()
        resolvers = [row for row in result["observations"] if row["kind"] == "resolver"]
        self.assertTrue(resolvers)
        self.assertTrue(all("country" not in row for row in resolvers))
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["errors"], [])

    def test_cancellation_terminates_only_active_child(self):
        child = self.Process(["/usr/bin/dig"])
        child.returncode = None
        probe.ACTIVE_CHILD = child
        with self.assertRaises(SystemExit) as raised:
            probe.cancellation_handler(15, None)
        self.assertEqual(raised.exception.code, 143)
        self.assertTrue(child.terminated)
        self.assertIsNone(probe.ACTIVE_CHILD)

    def test_cancellation_kills_unresponsive_created_child_then_reaps(self):
        child = self.Process(["/usr/bin/dig"])
        child.returncode = None
        calls = []
        def communicate(timeout=None):
            calls.append(timeout)
            if len(calls) == 1:
                raise subprocess.TimeoutExpired(child.command, timeout)
            return "", ""
        child.communicate = communicate
        child.kill = mock.Mock()
        probe.ACTIVE_CHILD = child
        with self.assertRaises(SystemExit):
            probe.cancellation_handler(15, None)
        child.kill.assert_called_once_with()
        self.assertEqual(calls, [1, 1])


if __name__ == "__main__":
    unittest.main()
