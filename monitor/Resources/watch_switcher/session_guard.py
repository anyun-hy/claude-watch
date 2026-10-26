"""Per-session egress baseline. It never changes the system network."""
from __future__ import annotations

import copy
import ipaddress
import math
import time
import uuid

from .common import SwitcherError, atomic_json, load_config, operation_lock, read_json

SCHEMA = 1
UNKNOWN_LIMIT = 2
RISK_EVIDENCE_TTL = 300
AUDIT_EGRESS_TTL = 30
GUARD_EGRESS_TTL = 10


def state_path(paths): return paths.base / "session-guard.json"


def _reason(code, detail, source="session guard", observed_at=None):
    return {"code": str(code)[:80], "detail": str(detail)[:240], "source": str(source)[:160],
            "observed_at": float(time.time() if observed_at is None else observed_at)}


def _egress(value):
    if not isinstance(value, dict): return None
    try: ip = ipaddress.ip_address(value.get("ip", ""))
    except ValueError: return None
    country, observed = value.get("country"), value.get("observed_at")
    if (not ip.is_global or not isinstance(country, str) or not country.isupper() or len(country) != 2 or
            type(observed) not in (int, float) or not math.isfinite(float(observed)) or
            float(observed) <= 0 or float(observed) > time.time() + 5):
        return None
    return {"ip": str(ip), "country": country.upper(), "observed_at": float(observed),
            "source": str(value.get("source") or "HTTP egress")[:160]}


def _fresh_egress(value, ttl=GUARD_EGRESS_TTL):
    value = _egress(value)
    if not value or time.time() - value["observed_at"] > ttl:
        return None
    return value


def _state(paths):
    try: value = read_json(state_path(paths), {})
    except SwitcherError: return None
    if not isinstance(value, dict) or value.get("schema") != SCHEMA or value.get("state") not in ("pending", "active", "locked"):
        return None
    if not isinstance(value.get("session_id"), str) or not _egress(value.get("baseline")): return None
    value["baseline"] = _egress(value["baseline"])
    return value


def read_session(paths):
    """Read-only status for UI/service reporting."""
    return _state(paths)


def _save(paths, value, expected_session_id=None):
    with operation_lock(paths, "session-guard"):
        if expected_session_id is not None:
            current = _state(paths)
            if not current or current.get("session_id") != expected_session_id:
                return False
        atomic_json(state_path(paths), value)
    return True


def begin_launch_session(paths, system, audit_receipt):
    # Hold the same short lock used by guard-triggered termination, so an old
    # guard cannot observe A and then terminate a freshly created B session.
    with operation_lock(paths, "session-guard"):
        if not isinstance(audit_receipt, dict) or audit_receipt.get("ready") is not True:
            raise SwitcherError("preflight_blocked", "完整启动校验未通过，未建立运行会话")
        transition = audit_receipt.get("context_transition", {})
        now = time.time()
        try:
            observed, expires = float(audit_receipt["observed_at"]), float(audit_receipt["expires_at"])
        except (KeyError, TypeError, ValueError):
            raise SwitcherError("egress_unconfirmed", "完整启动校验缺少有效时间范围")
        raw = audit_receipt.get("egress_reference", {})
        if isinstance(raw, dict):
            raw = dict(raw, observed_at=raw.get("checked_at"), source=raw.get("source") or "完整启动校验出口")
        audited = _egress(raw)
        context_id = str(audit_receipt.get("context_id") or "")
        if (not audited or now - audited["observed_at"] > AUDIT_EGRESS_TTL or observed > now + 5 or
                now > expires or not isinstance(transition, dict) or transition.get("state") != "stable" or
                not context_id or raw.get("context") != context_id):
            raise SwitcherError("egress_unconfirmed", "完整启动校验缺少新鲜的实测出口证据")
        current = _fresh_egress(system.guard_egress(load_config(paths)))
        if not current: raise SwitcherError("egress_unconfirmed", "启动时实际 HTTP 出口未能确认")
        if current["ip"] != audited["ip"] or current["country"] != audited["country"]:
            raise SwitcherError("egress_changed", "完整校验与启动前快速出口不一致，未建立会话")
        initial_risk = _risk(None, paths, context_id, current["ip"])
        if initial_risk.get("state") != "safe":
            raise SwitcherError("risk_evidence_unavailable", "启动前 DNS/WebRTC 风险证据未完整通过")
        if current["country"] == "CN": raise SwitcherError("egress_country_cn", "启动时检测到 CN 出口")
        created = time.time()
        value = {"schema": SCHEMA, "state": "pending", "session_id": str(uuid.uuid4()), "created_at": created,
                 "context_id": context_id[:160], "audit_observation_id": str(audit_receipt.get("observation_id") or "")[:80],
                 "baseline": current, "unknown_count": 0, "risk_evidence": copy.deepcopy(initial_risk), "reason": None,
                 "pending_deadline": created + 15, "launcher": None}
        atomic_json(state_path(paths), value)
        return value


def close_if_current(paths, expected_session_id, closer):
    """Run the actual Claude exit only if its checked session is still current."""
    with operation_lock(paths, "session-guard"):
        current = _state(paths)
        matches = (current is None) if expected_session_id is None else (
            current is not None and current.get("session_id") == expected_session_id)
        if not matches:
            return False
        closer()
        return True


def bind_pending_launcher(paths, session_id, launcher):
    if not isinstance(launcher, dict) or not isinstance(launcher.get("pid"), int) or not isinstance(launcher.get("start"), str):
        raise SwitcherError("launcher_identity_unavailable", "启动器身份未能确认")
    with operation_lock(paths, "session-guard"):
        value = _state(paths)
        if not value or value.get("state") != "pending" or value.get("session_id") != session_id:
            raise SwitcherError("session_changed", "启动会话已变化，未登记启动器")
        value["launcher"] = {"pid": launcher["pid"], "start": launcher["start"][:80]}
        atomic_json(state_path(paths), value)
    return value


def bind_launch_process(paths, session_id, process):
    if not isinstance(process, dict) or not isinstance(process.get("pid"), int):
        raise SwitcherError("desktop_identity_unavailable", "Claude 主进程身份未能确认")
    if not all(isinstance(process.get(key), int) for key in ("start_seconds", "start_microseconds")):
        raise SwitcherError("desktop_identity_unavailable", "Claude 主进程启动身份不完整")
    with operation_lock(paths, "session-guard"):
        value = _state(paths)
        if not value or value["state"] != "pending" or value["session_id"] != session_id:
            raise SwitcherError("session_changed", "启动会话已变化，未绑定 Claude 进程")
        value.update(state="active", bound_at=time.time(), desktop={key: process[key] for key in ("pid", "start_seconds", "start_microseconds")})
        atomic_json(state_path(paths), value)
    return value


def lock_session(paths, code, detail, expected_session_id=None, current=None, risk_evidence=None):
    with operation_lock(paths, "session-guard"):
        value = _state(paths)
        if not value or (expected_session_id is not None and value.get("session_id") != expected_session_id): return None
        value.update(state="locked", locked_at=time.time(), reason=_reason(code, detail))
        if _egress(current): value["last_check"] = _egress(current)
        if isinstance(risk_evidence, dict): value["risk_evidence"] = copy.deepcopy(risk_evidence)
        atomic_json(state_path(paths), value)
    return value


def record_uncertain(paths, code, detail):
    """Bound a transient local-observation failure without inventing a risk."""
    value = _state(paths)
    if value and value.get("state") == "locked":
        return {"state": "locked", "reason": value.get("reason"), "session": value}
    if not value or value.get("state") not in ("active", "pending"):
        return {"state": "risk", "reason": _reason("session_missing", "Claude 未绑定受控启动会话")}
    value["unknown_count"] = int(value.get("unknown_count", 0)) + 1
    value["last_reason"] = _reason(code, detail)
    value["last_risk_state"] = "unknown"
    if not _save(paths, value, value["session_id"]):
        return {"state": "unknown", "reason": _reason("session_changed", "会话已由新的受控启动替换")}
    if value["unknown_count"] < UNKNOWN_LIMIT:
        return {"state": "unknown", "reason": value["last_reason"], "session": value}
    locked = lock_session(paths, code, detail, value["session_id"])
    if not locked: return {"state": "unknown", "reason": _reason("session_changed", "会话已由新的受控启动替换")}
    return {"state": "risk", "reason": locked["reason"], "session": locked}


def _risk(reader, paths, context_id, current_ip):
    if reader is None:
        try:
            from .automatic_policy import session_risk
            reader = session_risk
        except (ImportError, AttributeError):
            return {"state": "unknown", "reason": _reason("risk_evidence_missing", "DNS/WebRTC 风险证据尚未提供")}
    try: value = reader(paths, context_id, current_ip)
    except Exception: return {"state": "unknown", "reason": _reason("risk_evidence_unavailable", "DNS/WebRTC 风险证据不可读取")}
    if not isinstance(value, dict) or value.get("state") not in ("safe", "risk", "unknown"):
        return {"state": "unknown", "reason": _reason("risk_evidence_invalid", "DNS/WebRTC 风险证据格式无效")}
    return value


def check_session(paths, system, config, *, risk_reader=None):
    value = _state(paths)
    if not value: return {"state": "risk", "reason": _reason("session_missing", "Claude 未绑定受控启动会话")}
    if value["state"] == "locked": return {"state": "locked", "reason": value.get("reason"), "session": value}
    if value["state"] == "pending":
        try: launcher_live = system.launcher_matches(value.get("launcher"))
        except Exception: launcher_live = False
        if time.time() <= float(value.get("pending_deadline", 0)) and launcher_live:
            return {"state": "unknown", "reason": _reason("session_pending", "Claude 启动身份正在确认"), "session": value}
        locked = lock_session(paths, "session_pending", "Claude 启动身份未在宽限期内完成绑定")
        return {"state": "risk", "reason": locked["reason"], "session": locked}
    try:
        identity_matches = system.session_desktop_matches(value.get("desktop"))
    except Exception:
        value["unknown_count"] = int(value.get("unknown_count", 0)) + 1
        value["last_reason"] = _reason("session_identity_unconfirmed", "Claude 主进程身份暂未能复核")
        value["last_risk_state"] = "unknown"
        if not _save(paths, value, value["session_id"]):
            return {"state": "unknown", "reason": _reason("session_changed", "会话已由新的受控启动替换")}
        if value["unknown_count"] < UNKNOWN_LIMIT:
            return {"state": "unknown", "reason": value["last_reason"], "session": value}
        locked = lock_session(paths, "session_identity_unconfirmed", "Claude 主进程身份连续未能复核", value["session_id"])
        if not locked: return {"state": "unknown", "reason": _reason("session_changed", "会话已由新的受控启动替换")}
        return {"state": "risk", "reason": locked["reason"], "session": locked}
    if not identity_matches:
        locked = lock_session(paths, "session_identity_changed", "运行中的 Claude 主进程不再匹配受控启动身份", value["session_id"])
        if not locked: return {"state": "unknown", "reason": _reason("session_changed", "会话已由新的受控启动替换")}
        return {"state": "risk", "reason": locked["reason"], "session": locked}
    baseline, sample = value["baseline"], system.guard_egress(config)
    current = _fresh_egress(sample)
    if not current:
        error = str(sample.get("error") or "未收到有效公网 IP 与国家")[:200] if isinstance(sample, dict) else "出口回执格式无效"
        return record_uncertain(paths, "egress_unconfirmed", "运行中出口查询失败：" + error)
    if current["country"] == "CN":
        locked = lock_session(paths, "egress_country_cn", "运行中实测 HTTP 出口为 CN", value["session_id"], current=current)
        if not locked: return {"state": "unknown", "reason": _reason("session_changed", "会话已由新的受控启动替换")}
        return {"state": "risk", "baseline": baseline, "current": current, "reason": locked["reason"], "session": locked}
    if current["ip"] != baseline["ip"]:
        locked = lock_session(paths, "egress_ip_changed", "运行中实测 HTTP 出口 IP 已变化", value["session_id"], current=current)
        if not locked: return {"state": "unknown", "reason": _reason("session_changed", "会话已由新的受控启动替换")}
        return {"state": "risk", "baseline": baseline, "current": current, "reason": locked["reason"], "session": locked}
    risk = _risk(risk_reader, paths, value.get("context_id", ""), current["ip"]); now = time.time()
    if risk.get("state") == "risk":
        reason = risk.get("reason") if isinstance(risk.get("reason"), dict) else _reason("network_leak_risk", "DNS 或 WebRTC 风险证据触发")
        locked = lock_session(paths, reason.get("code", "network_leak_risk"), reason.get("detail", "网络风险证据触发"), value["session_id"], current=current, risk_evidence=risk)
        if not locked: return {"state": "unknown", "reason": _reason("session_changed", "会话已由新的受控启动替换")}
        return {"state": "risk", "baseline": baseline, "current": current, "reason": locked["reason"], "risk_evidence": risk, "session": locked}
    if risk.get("state") == "safe": value["risk_evidence"] = copy.deepcopy(risk)
    evidence = value.get("risk_evidence")
    try: age = now - float((evidence or {}).get("observed_at"))
    except (TypeError, ValueError): age = RISK_EVIDENCE_TTL + 1
    if age > RISK_EVIDENCE_TTL:
        locked = lock_session(paths, "evidence_expired", "DNS/WebRTC 有效风险证据已超过 300 秒", value["session_id"], current=current, risk_evidence=risk)
        if not locked: return {"state": "unknown", "reason": _reason("session_changed", "会话已由新的受控启动替换")}
        return {"state": "risk", "baseline": baseline, "current": current, "reason": locked["reason"], "risk_evidence": risk, "session": locked}
    value.update(unknown_count=0, last_check=current, last_risk_state=risk.get("state"),
                 last_reason=None if risk.get("state") == "safe" else risk.get("reason"))
    if not _save(paths, value, value["session_id"]):
        return {"state": "unknown", "reason": _reason("session_changed", "会话已由新的受控启动替换")}
    return {"state": "safe" if risk.get("state") == "safe" else "unknown", "baseline": baseline, "current": current,
            "risk_evidence": risk, "session": value}
