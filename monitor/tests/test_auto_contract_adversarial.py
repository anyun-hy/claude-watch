"""Adversarial producer/consumer contracts; these must fail on unsafe shortcuts."""
import time
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Resources"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_switcher import Fixture
from watch_switcher.audit import record_webrtc_risk
from watch_switcher.automatic_policy import session_risk


class AutomaticContractAdversarialTests(Fixture):
    def payload(self, now, observations):
        return {"kind":"webrtc","status":"complete","contextChanged":False,
                "startedAt":now-2,"finishedAt":now,"errors":[],"observations":observations}

    def test_absent_receipts_are_unknown_not_safe(self):
        result = session_risk(self.paths, "stable")
        self.assertEqual(result["state"], "unknown")

    def test_web_rtc_legacy_provider_signature_is_accepted(self):
        self.system.local_value["tag"] = {"entry":{"endpoint":"http://127.0.0.1:7890"},
                                          "api":{"mode":"rule","selected_node":"Japan 1","global_node":""}}
        now=time.time()
        receipt = record_webrtc_risk(self.paths, self.system,
            self.payload(now,[{"kind":"http","address":"8.8.8.8","country":"JP"},{"kind":"srflx","address":"8.8.8.8","country":"JP"}]),
            expected_context="http://127.0.0.1:7890|rule|Japan 1|", now=now+1)
        self.assertEqual(receipt["risk"]["state"], "ok")

    def test_complete_zero_candidates_is_unknown_not_safe(self):
        now=time.time()
        receipt = record_webrtc_risk(self.paths, self.system, self.payload(now,[]), now=now+1)
        self.assertEqual(receipt["risk"]["state"], "unknown")


if __name__ == "__main__": unittest.main()
