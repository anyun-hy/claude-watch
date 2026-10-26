"""Offline contracts for controlled Claude session egress protection."""
import copy
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Resources"))

from watch_switcher.common import DEFAULT_CONFIG, Paths, SwitcherError, save_config
from watch_switcher import session_guard
from watch_switcher.services import service_status, session_status


class FakeSystem:
    def __init__(self, egress):
        self.egress = egress
        self.match = True
    def guard_egress(self, _config): return copy.deepcopy(self.egress)
    def session_desktop_matches(self, _desktop): return self.match


class StatusSystem:
    def backend_healthy(self): return True
    def guard_status(self, _config): return True
    def watchdog_state(self): return {"registered": False, "target": None, "last_success": None}
    def service_job(self, _name): return {"registered": False, "trusted": False, "last_exit": None, "interval": None}
    def claude_running(self): return False


class SessionGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cw-session-")
        self.addCleanup(self.temp.cleanup)
        home = Path(self.temp.name) / "home"; home.mkdir()
        self.paths = Paths(home)
        self.config = dict(DEFAULT_CONFIG, enabled=True, online_enabled=True, guard_enabled=True, country="JP", timezone="Asia/Tokyo")
        save_config(self.paths, self.config)
        now = time.time()
        self.system = FakeSystem({"state": "ok", "ip": "1.1.1.1", "country": "JP", "observed_at": now, "source": "fixture"})
        self.audit = {"ready": True, "context_id": "ctx", "observation_id": "obs", "observed_at": now,
                      "expires_at": now + 30, "context_transition": {"state": "stable"},
                      "egress_reference": {"ip": "1.1.1.1", "country": "JP", "checked_at": now,
                                           "context": "ctx", "source": "fixture"}}
        self.risk = patch("watch_switcher.automatic_policy.session_risk", return_value={"state": "safe", "observed_at": now})
        self.risk.start(); self.addCleanup(self.risk.stop)

    def active(self):
        session = session_guard.begin_launch_session(self.paths, self.system, self.audit)
        return session_guard.bind_launch_process(self.paths, session["session_id"],
                                                  {"pid": 77, "start_seconds": 10, "start_microseconds": 20})

    def test_baseline_is_created_only_from_ready_audit_and_never_rolls(self):
        with self.assertRaises(SwitcherError):
            session_guard.begin_launch_session(self.paths, self.system, {"ready": False})
        state = self.active()
        now = time.time()
        self.system.egress = {"state": "ok", "ip": "8.8.8.8", "country": "JP", "observed_at": now, "source": "fixture"}
        result = session_guard.check_session(self.paths, self.system, self.config, risk_reader=lambda *_: {"state": "safe", "observed_at": now})
        self.assertEqual((result["state"], result["reason"]["code"]), ("risk", "egress_ip_changed"))
        self.assertEqual(result["baseline"]["ip"], state["baseline"]["ip"])
        self.assertEqual(session_guard.read_session(self.paths)["state"], "locked")

    def test_cn_and_identity_change_lock_without_claiming_firewall(self):
        self.active()
        self.system.egress = {"state": "ok", "ip": "1.1.1.1", "country": "CN", "observed_at": time.time(), "source": "fixture"}
        result = session_guard.check_session(self.paths, self.system, self.config)
        self.assertEqual(result["reason"]["code"], "egress_country_cn")
        self.system.egress = {"state": "ok", "ip": "1.1.1.1", "country": "JP", "observed_at": time.time(), "source": "fixture"}
        self.active()
        self.system.match = False
        result = session_guard.check_session(self.paths, self.system, self.config)
        self.assertEqual(result["reason"]["code"], "session_identity_changed")

    def test_short_egress_failure_is_unknown_then_fail_closed(self):
        self.active()
        self.system.egress = {"state": "unknown", "observed_at": 101.0, "source": "fixture"}
        first = session_guard.check_session(self.paths, self.system, self.config)
        second = session_guard.check_session(self.paths, self.system, self.config)
        self.assertEqual(first["state"], "unknown")
        self.assertEqual((second["state"], second["reason"]["code"]), ("risk", "egress_unconfirmed"))

    def test_same_ip_multiple_safe_rounds_keep_the_original_baseline(self):
        state = self.active()
        first = session_guard.check_session(self.paths, self.system, self.config,
                                            risk_reader=lambda *_: {"state": "safe", "observed_at": time.time()})
        second = session_guard.check_session(self.paths, self.system, self.config,
                                             risk_reader=lambda *_: {"state": "safe", "observed_at": time.time()})
        self.assertEqual((first["state"], second["state"]), ("safe", "safe"))
        self.assertEqual(session_guard.read_session(self.paths)["baseline"], state["baseline"])

    def test_missing_initial_risk_evidence_and_prelaunch_ip_change_are_rejected(self):
        with patch("watch_switcher.automatic_policy.session_risk", return_value={"state": "unknown"}):
            with self.assertRaises(SwitcherError) as raised:
                session_guard.begin_launch_session(self.paths, self.system, self.audit)
        self.assertEqual(raised.exception.code, "risk_evidence_unavailable")
        self.system.egress = {"state": "ok", "ip": "8.8.8.8", "country": "JP", "observed_at": time.time(), "source": "fixture"}
        with self.assertRaises(SwitcherError) as raised:
            session_guard.begin_launch_session(self.paths, self.system, self.audit)
        self.assertEqual(raised.exception.code, "egress_changed")

    def test_unknown_risk_does_not_refresh_old_safe_evidence(self):
        self.active()
        state = session_guard.read_session(self.paths)
        old = copy.deepcopy(state["risk_evidence"])
        result = session_guard.check_session(self.paths, self.system, self.config,
                                             risk_reader=lambda *_: {"state": "unknown", "observed_at": time.time()})
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(session_guard.read_session(self.paths)["risk_evidence"], old)

    def test_service_projection_never_marks_active_session_safe_without_fresh_check(self):
        self.active()
        pending = service_status(self.paths, StatusSystem(), self.config)["session_guard"]
        self.assertEqual((pending["phase"], pending["state"]), ("active", "idle"))
        self.system.egress["observed_at"] = time.time()
        session_guard.check_session(self.paths, self.system, self.config,
                                    risk_reader=lambda *_: {"state": "safe", "observed_at": time.time()})
        safe = session_status(self.paths)
        self.assertEqual((safe["phase"], safe["state"]), ("active", "safe"))
        idle = service_status(self.paths, StatusSystem(), self.config)["session_guard"]
        self.assertEqual((idle["phase"], idle["state"]), ("active", "idle"))
        session_guard.lock_session(self.paths, "fixture", "locked")
        locked = service_status(self.paths, StatusSystem(), self.config)["session_guard"]
        self.assertEqual((locked["phase"], locked["state"], locked["reason"]["code"]), ("locked", "locked", "fixture"))

    def test_compare_and_save_cannot_overwrite_a_new_launch_session(self):
        old = self.active()
        new = session_guard.begin_launch_session(self.paths, self.system, self.audit)
        old["unknown_count"] = 99
        self.assertFalse(session_guard._save(self.paths, old, old["session_id"]))
        self.assertEqual(session_guard.read_session(self.paths)["session_id"], new["session_id"])

    def test_locked_status_persists_triggering_current_egress(self):
        self.active()
        self.system.egress = {"state": "ok", "ip": "8.8.8.8", "country": "JP", "observed_at": time.time(), "source": "fixture"}
        result = session_guard.check_session(self.paths, self.system, self.config,
                                             risk_reader=lambda *_: {"state": "safe", "observed_at": time.time()})
        self.assertEqual(result["state"], "risk")
        for _ in range(3):
            status = service_status(self.paths, StatusSystem(), self.config)["session_guard"]
            self.assertEqual((status["state"], status["baseline"]["ip"], status["current"]["ip"]),
                             ("locked", "1.1.1.1", "8.8.8.8"))

    def test_old_guard_cannot_close_a_newly_established_session(self):
        old = self.active()
        self.system.egress = {"state": "ok", "ip": "8.8.8.8", "country": "JP", "observed_at": time.time(), "source": "fixture"}
        verdict = session_guard.check_session(self.paths, self.system, self.config,
                                              risk_reader=lambda *_: {"state": "safe", "observed_at": time.time()})
        self.assertEqual(verdict["state"], "risk")
        self.system.egress = {"state": "ok", "ip": "1.1.1.1", "country": "JP", "observed_at": time.time(), "source": "fixture"}
        newer = session_guard.begin_launch_session(self.paths, self.system, self.audit)
        closed = []
        self.assertFalse(session_guard.close_if_current(self.paths, old["session_id"], lambda: closed.append(True)))
        self.assertEqual(closed, [])
        self.assertEqual(session_guard.read_session(self.paths)["session_id"], newer["session_id"])

    def test_expired_risk_evidence_locks_without_misattributing_ip_or_country(self):
        self.active()
        self.system.egress = {"state": "ok", "ip": "1.1.1.1", "country": "JP", "observed_at": time.time(), "source": "fixture"}
        session = session_guard.read_session(self.paths)
        session["risk_evidence"] = {"state": "safe", "observed_at": 1.0}
        session_guard._save(self.paths, session)
        result = session_guard.check_session(self.paths, self.system, self.config,
                                             risk_reader=lambda *_: {"state": "unknown"})
        self.assertEqual((result["state"], result["reason"]["code"]), ("risk", "evidence_expired"))


if __name__ == "__main__": unittest.main()
