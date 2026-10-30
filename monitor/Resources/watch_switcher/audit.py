"""One 14-check contract for the GUI, CLI and controlled launches."""
from __future__ import annotations

import ipaddress
import math
import re
import time
import uuid

from .common import CHECKS, DEFAULT_CONFIG, SwitcherError, atomic_json, digest, load_config, operation_lock, read_json
from .region import reference as region_reference, locale_check, date_summary, expected_date_summary
from .automatic_policy import facts as automatic_facts


DNS_RECEIPT_SCHEMA = 1
DNS_DISPLAY_TTL = 300
DNS_LAUNCH_TTL = 30


def public_ip(value):
    try:
        address = ipaddress.ip_address(value)
        return str(address) if address.is_global else ""
    except (ValueError, TypeError):
        return ""


def context_transition(before, after):
    def view(value):
        value = value if isinstance(value, dict) else {}
        identity = value.get("network_identity") or {"context": value.get("context", "")}
        return {"context_id": value.get("context_id", value.get("context", "")),
                "identity": identity,
                "unavailable": list(value.get("observation_unavailable", []))}
    left, right = view(before), view(after)
    unavailable = sorted(set(left["unavailable"] + right["unavailable"]))
    if unavailable: return {"state":"sampling_unavailable","before":left,"after":right,"changed_fields":[],"unavailable":unavailable}
    fields = sorted(key for key in set(left["identity"]) | set(right["identity"]) if left["identity"].get(key) != right["identity"].get(key))
    return {"state":"changed" if fields else "stable","before":left,"after":right,"changed_fields":fields,"unavailable":[]}


def reconcile_observations(before, after):
    """Keep later failures authoritative without calling missing data a network move."""
    transition = context_transition(before, after)
    unavailable = set(transition["unavailable"])
    changed = set(transition["changed_fields"])
    for key in ("timezone", "locale", "date_format", "ipv6", "language", "app_language"):
        left, right = before.get(key), after.get(key)
        if left == right:
            continue
        def missing(value):
            return value is None or value == "unknown" or (key == "date_format" and
                isinstance(value, dict) and value.get("state") != "available")
        # An absent application-specific language is a valid system fallback.
        if key == "app_language":
            changed.add(key)
        elif missing(left) or missing(right):
            unavailable.add(key)
            if missing(right): before[key] = right
        else:
            changed.add(key)
    for key in ("proxy", "tun"):
        previous, next_value = before.get(key), after.get(key)
        # A confirmed failure is sticky within this observation. A later
        # missing sample cannot erase it; likewise one later OK sample cannot
        # convert a prior unknown into a complete pass.
        if next_value == "fail" or previous == "fail":
            before[key] = "fail"
            if key == "proxy" and next_value == "fail":
                before["proxy_detail"] = after.get("proxy_detail", "代理已确认失效")
        elif next_value == "unknown" or previous == "unknown":
            before[key] = "unknown"
            unavailable.add(key + "_sampling")
            if key == "proxy" and next_value == "unknown":
                before["proxy_detail"] = after.get("proxy_detail", "代理采样未确认")
    if not before.get("guard") or not after.get("guard"):
        before["guard"] = False
        disabled = before.get("guard_state") == "disabled" or after.get("guard_state") == "disabled"
        before["guard_state"] = "disabled" if disabled else "unknown"
        before["guard_detail"] = "保护策略已禁用" if disabled else "本轮保护心跳或后台身份未能持续确认"
    transition.update(state="changed" if changed else "sampling_unavailable" if unavailable else "stable",
                      changed_fields=sorted(changed), unavailable=sorted(unavailable))
    before["context_transition"] = transition
    before["context_changed"] = transition["state"] == "changed"
    return transition


def preferred_language(value):
    if not isinstance(value, str): return None
    value = value.strip()
    if value.startswith("(") and value.endswith(")"): value = value[1:-1]
    items = [x.strip().strip('"') for x in value.split(",") if x.strip()]
    if not items or any(not re.fullmatch(r"[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{1,8})*", x) for x in items):
        return None
    return items[0]


def dns_receipt_path(paths):
    return paths.base / "dns-leak-receipt.json"


def dns_last_valid_path(paths):
    return paths.base / "dns-leak-last-valid.json"

def webrtc_receipt_path(paths):
    return paths.base / "webrtc-risk-receipt.json"

def record_webrtc_risk(paths, system, probe, *, expected_context=None, now=None):
    now = time.time() if now is None else now
    if not isinstance(probe, dict) or probe.get("kind") != "webrtc":
        raise SwitcherError("invalid_webrtc_receipt", "WebRTC 检测回执无效")
    local = system.local(dict(load_config(paths), proxy_mode="auto", proxy_url="", proxy_group=""))
    context = local.get("context_id", local.get("context", ""))
    tag = local.get("tag") or {}
    entry, api = tag.get("entry") or {}, tag.get("api") or {}
    signature = "|".join(str(value or "") for value in
                         (entry.get("endpoint"), api.get("mode"), api.get("selected_node"), api.get("global_node")))
    if (not context or local.get("proxy") != "ok" or local.get("tun") != "ok" or local.get("observation_unavailable") or
            (expected_context is not None and expected_context not in (context, signature))):
        raise SwitcherError("webrtc_context_changed", "WebRTC 检测后的网络上下文已变化")
    if probe.get("contextChanged") is not False: raise SwitcherError("webrtc_context_changed", "WebRTC 检测期间网络上下文变化")
    try: started, finished = float(probe["startedAt"]), float(probe["finishedAt"])
    except (KeyError, TypeError, ValueError): raise SwitcherError("invalid_webrtc_receipt", "WebRTC 检测时间无效")
    if not all(math.isfinite(x) for x in (started, finished)) or started > finished or finished-started > 120 or finished > now+5 or now-finished > 90: raise SwitcherError("webrtc_stale", "WebRTC 检测结果不在可接受时间范围内")
    observations, errors = probe.get("observations", []), probe.get("errors", [])
    if not isinstance(observations, list) or len(observations) > 128 or not isinstance(errors, list) or len(errors) > 32:
        raise SwitcherError("invalid_webrtc_receipt", "WebRTC 候选列表无效")
    countries = _netcoffee_country_codes(probe.get("externalJSON"))
    clean, references, candidates, cn = [], set(), set(), []
    names = {"CHINA": "CN", "中国": "CN", "JAPAN": "JP", "日本": "JP"}
    for item in observations:
        if not isinstance(item, dict): raise SwitcherError("invalid_webrtc_receipt", "WebRTC 地址记录无效")
        address = public_ip(item.get("address"))
        # Local/mDNS and TURN relays are not public client-egress evidence.
        if not address: continue
        kind = item.get("kind")
        if kind not in ("http", "host", "srflx", "prflx"): continue
        raw_country = item.get("country")
        country = countries.get(address) or _country_code(raw_country) or names.get(str(raw_country).upper(), "")
        clean.append(dict(address=address, kind=kind, country=country, source=str(item.get("source", ""))[:160]))
        if kind == "http": references.add(address)
        else: candidates.add(address)
        if country == "CN": cn.append(address)
    mismatch = bool(references and candidates and not candidates <= references)
    state = ("fail" if cn or mismatch else "ok" if len(references) == 1 and candidates and
             probe.get("status") == "complete" and not errors else "unknown")
    detail = ("WebRTC 本轮公网出口或候选含中国归属" if cn else
              "WebRTC 公网候选与同轮 HTTP 出口不一致" if mismatch else
              "WebRTC 公网候选与同轮 HTTP 出口一致" if state == "ok" else
              "WebRTC 未取得完整的同轮 HTTP 出口与公网候选")
    receipt = {"schema":1,"kind":"webrtc","status":probe.get("status"),"sampled_at":finished,
               "recorded_at":now,"context_id":context,"risk":{"state":state,"detail":detail,"cn_candidates":cn},
               "observations":clean,"errors":errors}
    with operation_lock(paths,"observations"): atomic_json(webrtc_receipt_path(paths),receipt)
    return receipt


def webrtc_receipt_status(paths, context, *, now=None):
    now = time.time() if now is None else now
    try: receipt = read_json(webrtc_receipt_path(paths), {})
    except SwitcherError: return {"state": "unknown", "detail": "WebRTC 回执不可读取"}
    if not isinstance(receipt, dict) or receipt.get("schema") != 1 or receipt.get("context_id") != context:
        return {"state": "unknown", "detail": "WebRTC 尚无当前网络的检测回执"}
    try: sampled, recorded = float(receipt["sampled_at"]), float(receipt["recorded_at"])
    except (KeyError, ValueError, TypeError): return {"state": "unknown", "detail": "WebRTC 时间记录无效"}
    if not all(math.isfinite(v) for v in (sampled, recorded)) or not 0 <= now - sampled <= 300 or not -5 <= recorded - sampled <= 90:
        return {"state": "unknown", "detail": "WebRTC 检测回执已过期"}
    risk = receipt.get("risk", {})
    if not isinstance(risk, dict) or risk.get("state") not in ("ok", "fail", "unknown"):
        return {"state": "unknown", "detail": "WebRTC 比较结果无效"}
    return dict(state=risk["state"], detail=risk.get("detail", "WebRTC 本轮检测"), sampled_at=sampled,
                observations=receipt.get("observations", []), receipt=receipt)


def policy_digest(config):
    """DNS resolver allow-lists are legacy display data, never launch policy."""
    return digest({key: value for key, value in config.items() if key != "expected_resolvers"})


def _country_code(value):
    value = value.strip().upper() if isinstance(value, str) else ""
    return value if re.fullmatch(r"[A-Z]{2}", value) else ""


def _time_text(value):
    try:
        value = float(value)
        if math.isfinite(value) and value > 0:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))
    except (TypeError, ValueError, OverflowError):
        pass
    return "未提供"


def _dns_receipt_state(receipt, context, *, launch=False, now=None):
    """Return one bounded DNS-leak receipt state for display or launch.

    The receipt is derived by ``record_dns_leak`` from the current IPLeak
    WebView result.  It is deliberately not reconstructed from resolv.conf,
    a hand-entered resolver list, or a fresh unrelated GeoIP request.
    """
    now = time.time() if now is None else now
    if not isinstance(receipt, dict) or receipt.get("schema") != DNS_RECEIPT_SCHEMA:
        return "unknown", "DNS 泄漏检测尚未完成"
    if receipt.get("provider") != "ipleak":
        return "unknown", "请使用 IPLeak 重新检测 DNS 出口"
    try:
        finished = float(receipt["finished_at"])
        recorded = float(receipt["recorded_at"])
        expires = float(receipt["launch_expires_at" if launch else "display_expires_at"])
    except (KeyError, TypeError, ValueError):
        return "unknown", "DNS 检测回执格式不完整"
    if (not math.isfinite(finished) or not math.isfinite(recorded) or not math.isfinite(expires) or
            recorded < finished or recorded - finished > 90 or finished > now + 5 or now > expires):
        return "unknown", "DNS 检测结果已过期，请重新检测"
    if not isinstance(context, str) or not context or receipt.get("context") != context:
        return "unknown", "DNS 检测后的网络或代理上下文已变化，请重新检测"
    comparison = receipt.get("comparison")
    if not isinstance(comparison, dict):
        return "unknown", "DNS 检测比较结果缺失"
    state = comparison.get("state")
    sampled = _time_text(receipt.get("finished_at"))
    if state == "ok":
        return "ok", "本轮 DNS 递归出口与同轮公网出口国家一致；采样 " + sampled
    if state == "fail":
        return "fail", "DNS 递归出口与同轮公网出口国家不一致，存在泄漏风险；采样 " + sampled
    error = receipt.get("query_error")
    suffix = "；查询失败：" + error if isinstance(error, str) and error else ""
    return "unknown", str(comparison.get("detail") or "DNS 检测未取得完整国家归属") + suffix + "；采样 " + sampled


def _valid_cached_dns_receipt(receipt, context, *, now=None):
    """Validate retained evidence without treating its age as launch evidence."""
    now = time.time() if now is None else now
    if not isinstance(receipt, dict) or receipt.get("schema") != DNS_RECEIPT_SCHEMA:
        return False
    if receipt.get("provider") != "ipleak": return False
    try:
        finished, recorded = float(receipt["finished_at"]), float(receipt["recorded_at"])
    except (KeyError, TypeError, ValueError):
        return False
    if (not math.isfinite(finished) or not math.isfinite(recorded) or finished > now + 5 or
            recorded < finished or recorded - finished > 90):
        return False
    comparison = receipt.get("comparison")
    return (isinstance(context, str) and bool(context) and receipt.get("context") == context and
            receipt.get("status") == "complete" and not receipt.get("errors") and
            isinstance(comparison, dict) and comparison.get("state") == "ok")


def dns_receipt_status(paths, context, *, launch=False, now=None):
    """Load latest DNS evidence; a valid history is display-only metadata."""
    now = time.time() if now is None else now
    try:
        receipt = read_json(dns_receipt_path(paths), {})
    except SwitcherError:
        receipt = {}
    state, detail = _dns_receipt_state(receipt, context, launch=launch, now=now)
    try:
        last_valid = read_json(dns_last_valid_path(paths), {})
    except SwitcherError:
        last_valid = {}
    comparison = receipt.get("comparison", {}) if isinstance(receipt, dict) else {}
    reason = comparison.get("reason") if isinstance(comparison, dict) else ""
    # An older pass may help explain a temporary collector failure only.  It
    # must never mask an observed country mismatch, HTTP-reference change, or
    # context change in the latest receipt.
    latest_status = receipt.get("status") if isinstance(receipt, dict) else ""
    cacheable = state == "unknown" and (latest_status in {"partial", "error", "timeout"} or
                                         reason in {"country_missing", "dns_http_reference_missing", "dns_resolver_missing"})
    valid_cached = _valid_cached_dns_receipt(last_valid, context, now=now)
    valid_state, _ = _dns_receipt_state(last_valid, context, launch=False, now=now)
    display_receipt = last_valid if cacheable and valid_cached else receipt
    return {"state": state, "detail": detail, "receipt": receipt if isinstance(receipt, dict) else {},
            "display_receipt": display_receipt if isinstance(display_receipt, dict) else {},
            "display_cached": bool(cacheable and valid_cached),
            "last_valid": {"available": valid_cached, "fresh": valid_state == "ok", "expired": valid_cached and valid_state != "ok",
                           "sampled_at": last_valid.get("finished_at") if isinstance(last_valid, dict) else None,
                           "context_matches": isinstance(last_valid, dict) and last_valid.get("context") == context}}


def dns_row(status):
    """One UI row derived from the backend's DNS decision, never rejudged by Swift."""
    status = status if isinstance(status, dict) else {}
    receipt = status.get("display_receipt") or status.get("receipt") or {}
    dns = receipt.get("dns", {}) if isinstance(receipt, dict) else {}
    http = receipt.get("http", {}) if isinstance(receipt, dict) else {}
    ips = dns.get("egress_ips", []) if isinstance(dns, dict) else []
    countries = dns.get("countries", []) if isinstance(dns, dict) else []
    http_countries = http.get("countries", []) if isinstance(http, dict) else []
    if len(ips) == 1: current = str(ips[0]) + " / " + ("、".join(countries) or "国家未确认")
    elif ips: current = ("、".join(countries) or "国家未确认") + " · %d 个 DNS 出口" % len(ips)
    else: current = "未知"
    cached = bool(status.get("display_cached"))
    detail = str(status.get("detail") or "DNS 泄漏检测尚未完成")
    if ips: detail += "；DNS 出口 " + "、".join(str(x) for x in ips[:128])
    if cached: detail += "；此为历史显示，最新失败仍阻止受控启动"
    return {"id": "dns", "name": "DNS", "state": "cached" if cached else status.get("state", "unknown"),
            "detail": detail, "scope": "IPLeak.net DNS 泄漏采样；不代表所有应用或浏览器 DoH", "required": True,
            "current": current, "reference": "同轮 HTTP 出口国家 " + ("、".join(http_countries) or "未确认"),
            "source": "IPLeak.net 权威 DNS 记录 + 同轮 HTTP 参考", "sampled_at": receipt.get("finished_at"),
            "query_error": status.get("detail") if status.get("state") == "unknown" else "",
            "display_cached": cached, "last_valid": bool(status.get("last_valid", {}).get("available"))}


def source_notices(values):
    """Condense source failures once; individual cards retain only their own state."""
    errors = values.get("query_errors", {}) if isinstance(values, dict) else {}
    if not isinstance(errors, dict): return []
    grouped = {}
    for key, error in errors.items():
        if not isinstance(error, dict): continue
        if key in ("claude", "api"):
            continue
        source = str(error.get("source") or key)[:120]
        detail = str(error.get("message") or "查询未完成")[:240]
        severity = "fail" if key == "egress_consistency" else "warn"
        previous = grouped.get(source)
        if previous is None or (severity == "fail" and previous["severity"] != "fail"):
            grouped[source] = {"id": str(key)[:80], "title": source, "detail": detail, "severity": severity}
    return list(grouped.values())


def _dns_record_error(code, message):
    raise SwitcherError(code, message)


def _public_observation(value):
    if not isinstance(value, dict):
        return None
    address = public_ip(value.get("address"))
    if not address:
        return None
    return address


def _netcoffee_country_codes(raw):
    """Use country codes already returned by Net.Coffee, without a new lookup."""
    if not isinstance(raw, str) or len(raw.encode("utf-8", "replace")) > 512_000:
        return {}
    try:
        rows = __import__("json").loads(raw)
    except (ValueError, TypeError):
        return {}
    if not isinstance(rows, list) or len(rows) > 32:
        return {}
    codes = {}
    for row in rows:
        if not isinstance(row, dict) or row.get("kind") != "geoip" or row.get("status") != "complete":
            continue
        address = public_ip(row.get("query"))
        data = row.get("data")
        code = _country_code(data.get("country_code")) if isinstance(data, dict) else ""
        if address and code:
            codes[address] = code
    return codes


def _probe_error(errors):
    """Keep one bounded failure explanation without exposing raw API bodies."""
    if not isinstance(errors, list):
        return ""
    for value in errors:
        if not isinstance(value, dict):
            continue
        stage = str(value.get("stage", "检测"))[:80]
        code = str(value.get("code", "失败"))[:80]
        message = str(value.get("message", ""))[:240]
        return " / ".join(item for item in (stage, code, message) if item)
    return ""


def _ipleak_evidence(raw):
    try:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 512000: return None
        value = __import__("json").loads(raw)
        if not isinstance(value, dict) or not re.fullmatch(r"[0-9a-f]{40}", value.get("session", "")): return None
        servers, rows, http = value.get("dns_servers"), value.get("geoip"), value.get("http")
        if not isinstance(servers, dict) or len(servers) > 127 or not isinstance(rows, list) or len(rows) > 32 or not isinstance(http, dict): return None
        resolvers = set()
        for address, count in servers.items():
            ip = public_ip(address)
            if not ip or type(count) is not int or count <= 0: return None
            resolvers.add(ip)
        reference, code = public_ip(http.get("address")), _country_code(http.get("country"))
        if not reference or not code: return None
        countries = {reference: code}
        for row in rows:
            if not isinstance(row, dict): return None
            address, code = public_ip(row.get("ip")), _country_code(row.get("country_code"))
            if not address or address not in resolvers or not code or (address in countries and countries[address] != code): return None
            countries[address] = code
        return countries, resolvers, reference
    except (ValueError, TypeError, AttributeError): return None


def record_dns_leak(paths, system, probe, *, now=None, expected_context=None):
    """Validate and persist one IPLeak DNS receipt under the backend lock."""
    now = time.time() if now is None else now
    if not isinstance(probe, dict):
        _dns_record_error("invalid_dns_receipt", "DNS 检测回执不是对象")
    try:
        encoded = __import__("json").dumps(probe, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        _dns_record_error("invalid_dns_receipt", "DNS 检测回执无法读取")
    if len(encoded) > 768_000:
        _dns_record_error("oversize_dns_receipt", "DNS 检测回执过大")
    if probe.get("kind") != "dns" or type(probe.get("contextChanged")) is not bool:
        _dns_record_error("invalid_dns_receipt", "DNS 检测上下文字段无效")
    if probe.get("status") not in ("complete", "partial", "error", "timeout") or not isinstance(probe.get("errors"), list):
        _dns_record_error("invalid_dns_receipt", "DNS 检测状态无效")
    try:
        started, finished = float(probe["startedAt"]), float(probe["finishedAt"])
    except (KeyError, TypeError, ValueError):
        _dns_record_error("invalid_dns_receipt", "DNS 检测时间无效")
    if (not math.isfinite(started) or not math.isfinite(finished) or started > finished or
            finished - started > 120 or finished > now + 5 or now - finished > 90):
        _dns_record_error("dns_stale", "DNS 检测结果不在可接受时间范围内")
    observations = probe.get("observations")
    if not isinstance(observations, list) or len(observations) > 128:
        _dns_record_error("invalid_dns_receipt", "DNS 检测地址列表无效")
    evidence = _ipleak_evidence(probe.get("externalJSON"))
    countries = evidence[0] if evidence else {}
    buckets = {"resolver": set(), "http": set()}
    seen = {"resolver": False, "http": False}
    missing_country = False
    for value in observations:
        if not isinstance(value, dict) or value.get("kind") not in buckets:
            missing_country = True
            continue
        seen[value["kind"]] = True
        address = _public_observation(value)
        if not address:
            missing_country = True
            continue
        belongs = bool(evidence and (address == evidence[2] if value["kind"] == "http" else address in evidence[1]))
        country = countries.get(address) if belongs else None
        if not country:
            missing_country = True
            continue
        buckets[value["kind"]].add((address, country))
    if not evidence or any(not any(ip == address for ip, _ in buckets["resolver"]) for address in evidence[1]) or not any(ip == evidence[2] for ip, _ in buckets["http"]):
        missing_country = True
    dns_countries = sorted({country for _, country in buckets["resolver"]})
    http_countries = sorted({country for _, country in buckets["http"]})
    if len(http_countries) == 1 and any(country != http_countries[0] for country in dns_countries):
        # A concrete mismatch stays visible even if another endpoint timed out
        # or could not be geolocated during the same sample.
        comparison = {"state": "fail", "reason": "country_mismatch",
                      "detail": "DNS 递归出口与同轮公网出口国家不一致，存在泄漏风险"}
    elif (probe.get("status") == "complete" and not probe["errors"] and not missing_country and
          len(dns_countries) == 1 and len(http_countries) == 1 and dns_countries[0] == http_countries[0]):
        comparison = {"state": "ok", "reason": "same_country",
                      "detail": "DNS 递归出口与同轮公网出口国家一致；范围仅限本次采样路径"}
    elif not seen["http"]:
        comparison = {"state": "unknown", "reason": "dns_http_reference_missing",
                      "detail": "DNS 检测未取得同轮 HTTP 出口参考，不能给出通过结论"}
    elif not seen["resolver"]:
        comparison = {"state": "unknown", "reason": "dns_resolver_missing",
                      "detail": "DNS 检测未取得递归出口，不能给出通过结论"}
    elif missing_country:
        comparison = {"state": "unknown", "reason": "country_missing",
                      "detail": "DNS 或同轮公网出口缺少国家归属，不能给出通过结论"}
    elif len(dns_countries) != 1 or len(http_countries) != 1:
        comparison = {"state": "unknown", "reason": "country_ambiguous",
                      "detail": "DNS 或同轮公网出口存在多个国家归属，不能给出通过结论"}
    else:
        comparison = {"state": "unknown", "reason": "incomplete",
                      "detail": "DNS 检测未完整完成，不能给出通过结论"}
    if probe["contextChanged"]:
        comparison = {"state": "unknown", "reason": "context_changed",
                      "detail": "DNS 检测期间网络或代理上下文变化，不能给出通过结论"}
    config = dict(DEFAULT_CONFIG)
    try:
        from .common import load_config
        config = load_config(paths)
    except SwitcherError:
        pass
    local = system.local(dict(config, proxy_mode="auto", proxy_url="", proxy_group=""))
    context = local.get("context")
    if expected_context is not None:
        tag = local.get("tag") or {}
        entry, api = tag.get("entry") or {}, tag.get("api") or {}
        actual = "|".join(str(value or "") for value in (entry.get("endpoint"), api.get("mode"), api.get("selected_node"), api.get("global_node")))
        if (not isinstance(expected_context, str) or not expected_context or actual != expected_context or
                local.get("proxy") != "ok" or local.get("tun") != "ok" or local.get("observation_unavailable")):
            _dns_record_error("dns_context_changed", "DNS 采样所属网络与当前验证网络不一致或未能确认，未覆盖检测记录")
    if not isinstance(context, str) or not context:
        _dns_record_error("dns_context_unknown", "当前代理或网络上下文未能确认")
    query_error = _probe_error(probe["errors"])
    receipt = {
        "schema": DNS_RECEIPT_SCHEMA, "status": str(probe.get("status")), "observed_at": now, "recorded_at": now,
        "started_at": started, "finished_at": finished, "sampled_at": finished,
        "display_expires_at": finished + DNS_DISPLAY_TTL,
        "launch_expires_at": finished + DNS_LAUNCH_TTL,
        "context": context, "context_id": context, "provider": "ipleak",
        "dns": {"egress_ips": sorted(address for address, _ in buckets["resolver"]),
                "countries": dns_countries, "source": "IPLeak.net WebView authoritative DNS"},
        "http": {"egress_ips": sorted(address for address, _ in buckets["http"]),
                 "countries": http_countries, "source": "IPLeak.net WebView HTTP reference"},
        "comparison": comparison,
        "errors": [dict(stage=str(x.get("stage", ""))[:80], code=str(x.get("code", ""))[:80], message=str(x.get("message", ""))[:240]) for x in probe["errors"] if isinstance(x, dict)][:32],
        "query_error": query_error,
        "scope": probe.get("scope") if isinstance(probe.get("scope"), str) else "IPLeak.net DNS 泄漏检测",
    }
    with operation_lock(paths, "observations"):
        atomic_json(dns_receipt_path(paths), receipt)
        if (comparison["state"] == "ok" and probe.get("status") == "complete" and
                not probe["errors"] and not probe["contextChanged"]):
            atomic_json(dns_last_valid_path(paths), receipt)
    return receipt


def http_result(status):
    if type(status) is not int or status <= 0:
        return "unknown", "未收到有效 HTTP 响应"
    if status == 401:
        return "ok", "HTTP 401，需要账号认证（本轮未携带凭据）"
    if status == 403:
        return "warn", "HTTP 403，访问被拒绝；不能仅据此判断是地区或账号问题"
    if status == 429:
        return "warn", "HTTP 429，请求受到限流"
    if status >= 500:
        return "warn", "HTTP %s，服务端错误" % status
    if status >= 400:
        return "warn", "HTTP %s，请求未被接受" % status
    return "ok", "HTTP %s，已收到响应" % status


def service_response_result(service, response, legacy_status):
    """Classify only explicitly verified service-response metadata.

    Old integer-only receipts intentionally retain http_result() behaviour:
    a bare 403 is never inferred to be a browser verification page.
    """
    if not isinstance(response, dict):
        return (*http_result(legacy_status), None)
    status, access = response.get("status"), response.get("access")
    transport = response.get("transport_reached") is True
    http_status = response.get("http_status")
    expected_source = "https://claude.ai/" if service == "claude" else "https://api.anthropic.com/v1/models"
    raw_source = response.get("source")
    source = str(raw_source)[:160] if isinstance(raw_source, str) else ""
    metadata_matches = source == expected_source and isinstance(http_status, int) and http_status == legacy_status
    if not metadata_matches:
        # A mismatched metadata object is not evidence for this request.  Do
        # not let it change the legacy response classification.
        return (*http_result(legacy_status), expected_source)
    challenge = response.get("challenge")
    verified_challenge = (isinstance(challenge, dict) and challenge.get("provider") == "cloudflare" and
                          challenge.get("mitigated") == "challenge")
    if (service == "api" and status == "ok" and transport and access == "authentication_required" and
            http_status == 401 and legacy_status == 401):
        return "ok", "网络可达；API HTTP 401，未提供密钥，需要认证。", source
    if (service == "claude" and status == "ok" and transport and access == "challenge" and
            http_status == 403 and legacy_status == 403 and verified_challenge):
        return "ok", "网络可达；网页 HTTP 403，需要浏览器验证（Cloudflare challenge）。", source
    if status == "unknown" or access == "network_error" or not transport:
        error = str(response.get("error") or response.get("error_code") or "请求未完成")[:240]
        return "unknown", "网络未确认：" + error, source
    # Generic HTTP responses remain conservatively classified by the status
    # code; status=ok alone must not turn an unverified 403 green.
    state, detail = http_result(legacy_status)
    return state, detail, source


def service_responses_presentation(online):
    values = online.get("service_responses", {}) if isinstance(online, dict) else {}
    values = values if isinstance(values, dict) else {}
    web = service_response_result("claude", values.get("claude"), online.get("claude") if isinstance(online, dict) else None)
    api = service_response_result("api", values.get("api"), online.get("api") if isinstance(online, dict) else None)
    states = [web[0], api[0]]
    state = "unknown" if "unknown" in states else "warn" if "warn" in states else "ok"
    detail = "网页：%s\nAPI：%s\n范围：网络可达不代表已登录、账号可用或订阅状态。" % (
        web[1].rstrip("。；"), api[1].rstrip("。；"))
    sampled = []
    for item in values.values():
        if not isinstance(item, dict): continue
        try:
            value = float(item.get("queried_at"))
            if math.isfinite(value) and value > 0: sampled.append(value)
        except (TypeError, ValueError): pass
    return state, detail, {"claude": values.get("claude"), "api": values.get("api")}, max(sampled) if sampled else None


def service_access_label(service, response, legacy_status):
    """Compact card label; full HTTP/source evidence stays in row detail."""
    state, detail, _ = service_response_result(service, response, legacy_status)
    access = response.get("access") if isinstance(response, dict) else None
    if state == "ok" and service == "claude" and access == "challenge":
        return "需要浏览器验证"
    if state == "ok" and service == "api" and access == "authentication_required":
        return "未提供密钥"
    if state == "unknown": return "网络未确认"
    status = response.get("http_status") if isinstance(response, dict) else legacy_status
    return "HTTP %s" % status if isinstance(status, int) else detail


def query_error_detail(values, *sources):
    failures = values.get("query_errors", {})
    if not isinstance(failures, dict): return ""
    return "；".join((str(failures[key].get("source", key)) + "：" + str(failures[key].get("message", "查询未完成")))[:400]
                    for key in sources if isinstance(failures.get(key), dict))


def stun_presentation(stun, candidates, reference):
    """Return bounded human detail and trace metadata without changing policy."""
    stun = stun if isinstance(stun, dict) else {}
    observations = stun.get("observations", [])
    observations = observations if isinstance(observations, list) else []
    probe_started, probe_finished = stun.get("started_at"), stun.get("finished_at")
    try:
        probe_started, probe_finished = float(probe_started), float(probe_finished)
        if not math.isfinite(probe_started) or not math.isfinite(probe_finished) or probe_finished < probe_started:
            probe_started = probe_finished = None
    except (TypeError, ValueError): probe_started = probe_finished = None
    status_text = {
        "ok": "成功",
        "timeout": "等待 UDP 回包超时",
        "network_error": "网络失败",
        "unexpected_sender": "收到非目标服务器响应",
        "invalid_response": "报文校验失败",
        "budget_exhausted": "总预算耗尽",
    }
    stage_text = {"resolve": "域名解析", "send": "发送请求", "receive": "等待 UDP 回包",
                  "validation": "报文校验", "budget": "预算"}
    # 失败项优先：没应答的服务器不能压在折页下面，只看见一屏"成功"。
    # False 排在前面，所以键取"是否已应答"本身。
    rows = [o for o in observations if isinstance(o, dict)]
    def _answered(o):
        return o.get("status") == "ok" and o.get("accepted") is not False and o.get("deadline_exceeded") is not True
    rows.sort(key=_answered)
    answered = sum(1 for o in rows if _answered(o))
    lines = ["汇总：%d 个公网候选；参考：%s；%s" % (
        len(candidates), ", ".join(sorted(reference)) or "无",
        "未取得可用的公网 STUN 回包，无法确认 UDP 出口" if not candidates
        else "%d / %d 台服务器应答" % (answered, len(rows)))]
    for index, observation in enumerate(rows[:16], 1):
        if not isinstance(observation, dict): continue
        server = str(observation.get("server") or "未知服务器")[:160]
        port = observation.get("port")
        endpoint = server + (":" + str(port) if isinstance(port, int) and 0 < port < 65536 else "")
        attempts = observation.get("attempts")
        attempts = attempts if isinstance(attempts, list) else []
        status = str(observation.get("status") or "unknown")[:40]
        display_status = status_text.get(status, "未完成")
        address = public_ip(observation.get("address"))
        late_unaccepted = observation.get("deadline_exceeded") is True or observation.get("accepted") is False
        final = "；最终状态：" + display_status
        if late_unaccepted:
            final += "（超出整轮时限，未采纳）"
        if attempts:
            attempt_parts = []
            for attempt in attempts[:8]:
                if not isinstance(attempt, dict): continue
                number = attempt.get("attempt")
                label = "第%s次" % number if isinstance(number, int) and number > 0 else "一次尝试"
                started, finished = _time_text(attempt.get("started_at")), _time_text(attempt.get("finished_at"))
                raw_status = str(attempt.get("status") or "unknown")[:40]
                attempt_status = status_text.get(raw_status, "未完成")
                if raw_status == "ok" and late_unaccepted:
                    attempt_parts.append("%s %s–%s 已收到回包，但超出整轮时限，未采纳" % (
                        label, started, finished))
                elif raw_status == "ok":
                    attempt_parts.append("%s %s–%s 成功%s" % (
                        label, started, finished, ("，出口 " + address) if address else ""))
                else:
                    stage = stage_text.get(str(attempt.get("stage") or ""), "")
                    reason = str(attempt.get("error") or "")[:160]
                    if stage: reason = stage + ("：" + reason if reason else "")
                    error_code = str(attempt.get("error_code") or "")[:80]
                    if error_code: reason += ("；错误代码 " + error_code) if reason else ("错误代码 " + error_code)
                    errno = attempt.get("errno")
                    if isinstance(errno, int): reason += ("；系统错误 " + str(errno)) if reason else ("系统错误 " + str(errno))
                    attempt_parts.append("%s %s–%s %s%s" % (
                        label, started, finished, attempt_status, ("：" + reason) if reason else ""))
            lines.append("%s：%s%s%s" % (endpoint, "；".join(attempt_parts) or display_status,
                ("；最终出口 " + address) if address else "", final))
        else:
            lines.append("%s：%s%s；未提供逐次尝试记录%s" % (
                endpoint, display_status, ("；出口 " + address) if address else "", final))
    if len(observations) > 16: lines.append("其余 %d 台服务器结果已省略。" % (len(observations) - 16))
    return "\n".join(lines), probe_finished, observations


def apply_risk_rows(rows, automatic):
    """Apply explicit risk evidence after presentation enrichment as well."""
    by_id = {row["id"]: row for row in rows}
    for risk in automatic.get("risks", []):
        key = {"dns": "dns", "asn": "asn", "webrtc": "guard"}.get(risk.get("source"), "egress")
        if key in by_id:
            by_id[key].update(state="fail", required=True, detail=risk["reason"])


def evaluate(config, local, online, history=(), now=None):
    now = time.time() if now is None else now
    rows = []
    names = dict(CHECKS)
    def add(key, state, detail, required=True, scope="本机环境"):
        rows.append(dict(id=key, name=names[key], state=state, detail=detail,
                         required=required, scope=scope))
    add("proxy", local.get("proxy", "unknown"),
        local.get("proxy_detail") or ("已识别 " + local["mode"] if local.get("mode") else "代理未运行、身份不完整或多个候选需明确选择"))
    add("tun", local.get("tun", "unknown"), "接口与代理状态核对；不构成逐包出站保证")
    trace, geo = online.get("trace", {}), online.get("geo", {})
    automatic = automatic_facts(online)
    measured = automatic["measured"]
    address = public_ip(trace.get("ip"))
    country = measured.get("country", "")
    geo_matches = bool(measured)
    risk_items = automatic["risks"]
    egress_risks = [item for item in risk_items if item["id"] in ("cn_egress", "egress_conflict")]
    if egress_risks:
        add("egress", "fail", (address or "未取得 IP") + "；" + "；".join(x["reason"] for x in egress_risks), scope="诊断请求")
    elif not geo_matches:
        add("egress", "unknown", "本轮出口/国家未能交叉确认", scope="诊断请求")
    else:
        add("egress", "ok", address + " / " + country, scope="诊断请求")
    history = [x for x in history if isinstance(x, dict) and 0 <= now - x.get("time", 0) <= 172800]
    addresses = {x["ip"] for x in history if public_ip(x.get("ip"))}
    previous = history[-1]["ip"] if history else ""
    if address: addresses.add(address)
    changed = bool(address and previous and previous != address)
    state = "unknown" if not address else ("warn" if changed or len(addresses) >= 3 else "ok")
    add("ip_history", state, "48 小时内观测到 %d 个出口；变化不等同泄漏" % len(addresses),
        required=False, scope="检测历史；运行中 IP 变化由不可滚动的会话基准阻断")
    expected_tz, actual_tz = measured.get("timezone"), local.get("timezone")
    tz_state = "unknown" if not expected_tz or actual_tz is None else ("ok" if expected_tz == actual_tz else "fail")
    add("timezone", tz_state, "当前 %s；本轮实测出口所属时区 %s" % (
        actual_tz or "未知", expected_tz or "未确认"))
    expected_locale = measured.get("locale")
    locale_state = locale_check(local, expected_locale)
    add("locale", locale_state, "当前 %s；本轮出口要求 %s；短、中、长日期模板%s，界面语言独立" % (
        date_summary(local), expected_date_summary(local, expected_locale),
        "已核对" if locale_state == "ok" else "不匹配或未确认"))
    add("ipv6", local.get("ipv6", "unknown"), "关闭策略已启用" if config["require_ipv6_off"] else
        "未要求关闭；此项不能证明 IPv6 无泄漏", required=config["require_ipv6_off"])
    dns = online.get("dns", {})
    dns_state = dns.get("state") if isinstance(dns, dict) else "unknown"
    if dns_state not in ("ok", "fail", "unknown"):
        dns_state = "unknown"
    # DNS remains mandatory for controlled launches.  The state comes solely
    # from the stored IPLeak DNS-leak receipt, not from a resolver allow
    # list or a new dig request made by this preflight.
    add("dns", dns_state, (dns.get("detail") if isinstance(dns, dict) else "") or "DNS 泄漏检测尚未完成",
        required=True, scope="IPLeak.net DNS 泄漏采样；不代表所有应用或浏览器 DoH")
    stun = online.get("stun", {})
    observations = stun.get("observations", []) if isinstance(stun, dict) else []
    observations = observations if isinstance(observations, list) else []
    observed_candidates = {public_ip(x.get("address")) for x in observations if isinstance(x, dict) and x.get("status") == "ok"} - {""}
    candidates = {public_ip(x.get("address")) for x in observations if isinstance(x, dict) and x.get("status") == "ok"
                  and x.get("accepted") is not False and x.get("deadline_exceeded") is not True} - {""}
    reference = {address} if address else set()
    # 无回包不能证明 UDP 不出网；至少一个已采纳公网回包才可通过。
    # 未采纳的迟到结果不能放行，但与出口不一致时仍保留为风险证据。
    stun_state = ("unknown" if not reference else
                  ("fail" if not observed_candidates <= reference else "unknown" if not candidates else "ok"))
    stun_detail, stun_sampled_at, stun_observations = stun_presentation(stun, candidates, reference)
    add("stun", stun_state, stun_detail, required=True,
        scope="原生 UDP/STUN 探针，用于 AI 受控启动网络检查；不等于 Claude 实际 socket 或 WebRTC")
    rows[-1]["sampled_at"] = stun_sampled_at
    rows[-1]["stun_finished_at"] = stun_sampled_at
    rows[-1]["stun_observations"] = stun_observations
    rows[-1]["stun_probe"] = stun
    guard_state = local.get("guard_state")
    add("guard", "ok" if local.get("guard") else "fail" if guard_state == "disabled" else "unknown",
        local.get("guard_detail") or "要求保护已启用且收到新鲜心跳")
    rules = local.get("rules", {})
    add("routing", rules.get("state", "unknown"), rules.get("detail", "规则未确认；请配置或查看代理实际连接"),
        required=config["require_pinned_rules"], scope="规则配置；实际流量另见连接页")
    language = local.get("language")
    first_language = preferred_language(language)
    english = bool(first_language and first_language.split("-")[0].split("_")[0] == "en")
    add("language", "unknown" if first_language is None else ("ok" if english else "fail"),
        "Claude 应用语言或系统首选语言", required=config["require_english"])
    asn = online.get("asn", {})
    asn_number = asn.get("number") if isinstance(asn, dict) else None
    asn_country = _country_code(asn.get("registered_country")) if isinstance(asn, dict) else ""
    asn_org = asn.get("organization") if isinstance(asn, dict) else ""
    if isinstance(asn_number, int) and asn_number > 0:
        registration = ("ASN 注册国家 %s（RIPEstat RIR；统计日期 %s，本次查询 %s）" % (
            asn_country, asn.get("result_time") or "未提供", _time_text(asn.get("registered_queried_at"))) if asn_country
            else "ASN 注册国家暂未取得（RIPEstat 查询失败不会否定已读取的 ASN）")
        detail = "AS%d%s；%s。当前 IP 出口归属国家 %s（Net.Coffee）。" % (
            asn_number, " · " + asn_org if isinstance(asn_org, str) and asn_org else "", registration, country or "未确认")
        asn_state = "ok"
    else:
        detail = "未取得与本轮出口 ASN 严格匹配的注册国家；出口地理国家 %s（Net.Coffee）不替代 ASN 注册国家。" % (country or "未确认")
        asn_state = "unknown"
    add("asn", asn_state, detail, required=False, scope="Net.Coffee 出口归属 / RIPEstat RIR")
    state, service_detail, service_responses, service_sampled_at = service_responses_presentation(online)
    add("reachability", state, service_detail, scope="无账号凭据的诊断请求")
    rows[-1]["service_responses"] = service_responses
    rows[-1]["sampled_at"] = service_sampled_at
    dependencies = {"egress": ("trace", "geo"), "timezone": ("trace", "geo"),
                    "locale": ("trace", "geo"), "asn": ("geo", "asn"), "reachability": ("claude", "api")}
    for row in rows:
        if row["state"] == "unknown" and row["id"] in dependencies:
            error = query_error_detail(online, *dependencies[row["id"]])
            if error:
                row["query_error"] = error
                row["detail"] += "；查询原因：" + error
    transition = local.get("context_transition", {})
    if transition.get("state") == "sampling_unavailable":
        reasons = transition.get("unavailable", [])
        network_missing = any(key not in ("timezone", "locale", "date_format", "ipv6", "language", "app_language") for key in reasons)
        if network_missing:
            for row in rows:
                if row["id"] in ("proxy", "routing", "egress", "dns", "stun", "reachability") and row["state"] != "fail":
                    row.update(state="unknown", detail="本轮代理或网络采样未能持续确认；未判定为网络切换。原因：" + "、".join(reasons))
    if local.get("context_changed"):
        for row in rows:
            if row["required"]:
                row.update(state="unknown", detail="检测期间网络上下文变化，请重新检测")
    if not local.get("context_changed"): apply_risk_rows(rows, automatic)
    blocked = [x["id"] for x in rows if x["required"] and x["state"] in ("fail", "unknown")]
    message = ("启动预检未通过：" + "；".join(x["name"] + "：" + x["detail"] for x in rows if x["id"] in blocked)
               if blocked else "启动策略尚未启用；检测已完成，但尚未允许受控启动" if not config["enabled"] else
               "预检通过，仅限当前策略和采样范围")
    return dict(schema=1, observed_at=now, expires_at=now + 30, context=local.get("context", ""),
                policy=policy_digest(config), rows=rows, ready=not blocked and config["enabled"], blocked=blocked,
                message=message, netcoffee_lookup=online.get("netcoffee_lookup"), source_notices=source_notices(online),
                egress_reference={"ip":address, "country":country, "timezone":measured.get("timezone"), "checked_at":now, "context":local.get("context", "")}, facts=automatic)


def audit(paths, system, config, *, online=False, persist=True, dns_launch=False):
    from .rules import inspect_rules
    policy_before = policy_digest(load_config(paths))
    probe_config = dict(config, proxy_mode="auto", proxy_url="", proxy_group="")
    network = system.network_environment() if hasattr(system, "network_environment") else None
    if isinstance(network, dict): probe_config["network_service"] = network.get("service") or ""
    local = system.local(probe_config)
    if hasattr(system, "guard_status"):
        local["guard"] = system.guard_status(config)
        local["guard_state"] = "ok" if local["guard"] else "unknown" if config["guard_enabled"] else "disabled"
        local["guard_detail"] = "保护心跳已确认" if local["guard"] else "保护未启用或保护心跳未能确认"
    local["rules"] = inspect_rules(paths, config, local.get("mode", ""), tag=local.get("tag") or {})
    effective = dict(probe_config, proxy_mode=local["mode"]) if local.get("mode") else probe_config
    may_probe = online and config["online_enabled"] and local.get("proxy") == "ok" and local.get("tun") == "ok"
    values = system.online(effective) if may_probe else {}
    if dns_launch:
        from .dns_refresh import refresh_for_launch
        refresh_for_launch(paths)
    values["dns"] = dns_receipt_status(paths, local.get("context", ""), launch=dns_launch)
    values["webrtc"] = webrtc_receipt_status(paths, local.get("context", ""))
    transition = {"state":"sampling_unavailable","before":{},"after":{},"changed_fields":[],"unavailable":["online_not_run"]}
    if may_probe:
        after = system.local(probe_config)
        if hasattr(system, "guard_status"):
            after["guard"] = system.guard_status(config)
            after["guard_state"] = "ok" if after["guard"] else "unknown" if config["guard_enabled"] else "disabled"
        transition = reconcile_observations(local, after)
        after_network = system.network_environment() if isinstance(network, dict) else None
        if isinstance(after_network, dict):
            for field in ("service", "interface"):
                if network.get(field) == after_network.get(field): continue
                if network.get(field) and after_network.get(field):
                    transition["state"] = "changed"
                    transition["changed_fields"].append("network_" + field)
                else:
                    transition["unavailable"].append("network_" + field)
                    if transition["state"] != "changed": transition["state"] = "sampling_unavailable"
        if policy_before != policy_digest(load_config(paths)):
            transition["state"] = "changed"; transition["changed_fields"].append("policy")
        local["context_transition"] = transition
        local["context_changed"] = transition["state"] == "changed"
    history = read_json(paths.base / "ip-history.json", [])
    result = evaluate(config, local, values, history)
    result.update(observation_id=str(uuid.uuid4()), context_id=local.get("context_id", local.get("context", "")), context_transition=transition)
    if persist:
        with operation_lock(paths, "observations"):
            address = public_ip(values.get("trace", {}).get("ip"))
            now = result["observed_at"]
            current = read_json(paths.base / "ip-history.json", [])
            current = [x for x in current if isinstance(x, dict) and 0 <= now - x.get("time", 0) <= 172800]
            if address and not local.get("context_changed"):
                current.append({"time": now, "ip": address})
            atomic_json(paths.base / "ip-history.json", current[-2048:])
            atomic_json(paths.base / "last-audit.json", result)
    return result


def require_ready(paths, system, config):
    result = audit(paths, system, config, online=True, dns_launch=True)
    if not result["ready"]:
        names = dict(CHECKS)
        raise SwitcherError("preflight_blocked", "启动条件未满足：" + "、".join(names.get(key, key) for key in result["blocked"]))
    return result
