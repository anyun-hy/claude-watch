"""Generate UI contracts through production functions with an isolated fake OS."""
import json
import sys
import time
from pathlib import Path
from unittest.mock import patch

sys.path[:0] = [str(Path(__file__).parent), str(Path(__file__).resolve().parents[1] / "Resources")]
from test_protection_lifecycle import ProtectionLifecycleTests
from watch_switcher.onboarding import observe
from watch_switcher.services import service_status
from watch_switcher.system import System
from watch_switcher.common import load_config, read_json


def generate(destination):
    destination.mkdir(parents=True, exist_ok=True)
    for scenario in ("normal", "ipChanged", "cnRisk", "transientFailure", "evidenceExpired", "recovered"):
        fixture = ProtectionLifecycleTests()
        fixture.setUp()
        try:
            system, paths = fixture.system, fixture.paths
            system.local_value["tag"]["api"].update(mode="global", global_node="Japan fixture")
            service = System(paths)
            service._service_fetch = lambda url, config: ("", 403, {"cf-mitigated": "challenge"}) if url == "https://claude.ai/" else ("", 401, {})
            system.online_value["service_responses"] = {
                key: service.service_response(key, url, load_config(paths)) for key, url in
                (("claude", "https://claude.ai/"), ("api", "https://api.anthropic.com/v1/models"))}
            system.online_value["asn"] = dict(number=2516, organization="KDDI CORPORATION (isolated fixture)", registered_country="JP")
            if scenario == "evidenceExpired":
                old = time.time() - 301
                with patch("time.time", return_value=old):
                    fixture.evidence(at=old)
                    fixture.launch()
                    fixture.tick()
            else:
                fixture.launch()
                fixture.tick()
            if scenario in ("ipChanged", "recovered"):
                system.address = "8.8.4.4"
                system.set_online(system.address)
                fixture.evidence()
                fixture.tick()
                if scenario == "recovered":
                    system.address = "222.10.87.169"
                    system.set_online(system.address)
                    fixture.evidence()
            elif scenario == "cnRisk":
                system.country = "CN"
                system.online_value["trace"]["loc"] = "CN"
                system.online_value["geo"].update(country="CN", timezone="Asia/Shanghai")
                fixture.tick()
            elif scenario == "transientFailure":
                system.failed_sample = True
                fixture.tick()
            elif scenario == "evidenceExpired":
                fixture.tick()
            environment = observe(paths, system, online=True, persist=True)
            background = service_status(paths, system, load_config(paths))
            rtc = read_json(paths.base / "webrtc-risk-receipt.json")
            result = dict(scenario=scenario, simulated=True, environment=environment, background=background,
                webrtc=dict(kind="webrtc", status=rtc["status"], startedAt=rtc["sampled_at"] - 1,
                            finishedAt=rtc["sampled_at"], contextChanged=False, scope="隔离场景 · 生产回执链",
                            observations=rtc["observations"], errors=rtc["errors"]))
            (destination / (scenario + ".json")).write_text(json.dumps(result, ensure_ascii=False, indent=2))
        finally: fixture.doCleanups()


if __name__ == "__main__":
    generate(Path(__file__).parent / "fixtures/review")
