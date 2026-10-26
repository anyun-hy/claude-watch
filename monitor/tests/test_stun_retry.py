"""Offline retry/deadline contracts for the native UDP/STUN collector."""
import threading
import time
import unittest
from unittest.mock import patch

from watch_switcher import stun


ONE = (("fixture.stun", 3478),)
FOUR = (("a", 1), ("b", 2), ("c", 3), ("d", 4))


class StunRetryTests(unittest.TestCase):
    def test_timeout_then_success_records_both_attempts(self):
        calls = []
        def requester(host, port):
            calls.append((host, port))
            if len(calls) == 1: raise TimeoutError()
            return "8.8.8.8"
        result = stun.probe(ONE, requester=requester, budget=1, sleeper=lambda _value: None)
        row = result["observations"][0]
        self.assertTrue(result["complete"])
        self.assertEqual([x["status"] for x in row["attempts"]], ["timeout", "ok"])
        self.assertEqual(row["address"], "8.8.8.8")

    def test_invalid_sender_never_retries(self):
        calls = []
        def requester(host, port):
            calls.append(1); raise ValueError("unexpected_sender")
        result = stun.probe(ONE, requester=requester, budget=1)
        row = result["observations"][0]
        self.assertFalse(result["complete"])
        self.assertEqual(row["status"], "unexpected_sender")
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(row["attempts"]), 1)

    def test_budget_zero_records_every_server_without_sending(self):
        calls = []
        result = stun.probe(FOUR, requester=lambda h, p: calls.append((h, p)) or "8.8.8.8", budget=0)
        self.assertEqual(calls, [])
        self.assertEqual(len(result["observations"]), 4)
        self.assertEqual(result["missing"], 4)
        self.assertTrue(all(x["status"] == "budget_exhausted" for x in result["observations"]))

    def test_late_worker_never_starts_a_retry_after_deadline(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def requester(host, port):
            calls.append(1); entered.set(); release.wait(1); raise TimeoutError()
        result = stun.probe(ONE, requester=requester, budget=0.02)
        self.assertTrue(entered.is_set())
        self.assertEqual(result["observations"][0]["status"], "budget_exhausted")
        release.set(); time.sleep(0.04)
        self.assertEqual(len(calls), 1)

    def test_budget_snapshot_keeps_first_failure_while_second_attempt_is_late(self):
        entered, release = threading.Event(), threading.Event()
        calls = []
        def requester(host, port):
            calls.append(1)
            if len(calls) == 1: raise TimeoutError()
            entered.set(); release.wait(1); return "8.8.8.8"
        result = stun.probe(ONE, requester=requester, budget=0.3, sleeper=lambda _value: None)
        self.assertTrue(entered.is_set())
        row = result["observations"][0]
        self.assertEqual([x["status"] for x in row["attempts"]], ["timeout", "budget_exhausted"])
        self.assertLessEqual(len(row["attempts"]), stun.ATTEMPTS)
        self.assertFalse(result["complete"])
        release.set(); time.sleep(0.04)
        self.assertEqual(row["status"], "budget_exhausted")
        self.assertLessEqual(len(row["attempts"]), stun.ATTEMPTS)

    def test_default_request_does_not_send_after_late_dns_resolution(self):
        class FakeSocket:
            sent = False
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def settimeout(self, _): pass
            def sendto(self, *_): self.sent = True
        clock_values = iter([2.0])
        fake = FakeSocket()
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("8.8.8.8", 3478))]), \
             patch("socket.socket", return_value=fake):
            with self.assertRaises(stun.ProbeError) as raised:
                stun.request("fixture", 3478, deadline=1.0, clock=lambda: next(clock_values))
        self.assertEqual(raised.exception.code, "budget_exhausted")
        self.assertFalse(fake.sent)

    def test_network_failure_retries_once_then_remains_explicit(self):
        calls = []
        def requester(host, port):
            calls.append(1); raise OSError("network down")
        result = stun.probe(ONE, requester=requester, budget=1, sleeper=lambda _value: None)
        row = result["observations"][0]
        self.assertEqual(len(calls), 2)
        self.assertEqual(row["status"], "network_error")
        self.assertEqual([x["attempt"] for x in row["attempts"]], [1, 2])


if __name__ == "__main__":
    unittest.main()
