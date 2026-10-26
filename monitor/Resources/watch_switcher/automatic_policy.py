"""Pure same-round fact/risk extraction shared by display and launch policy."""
import re
import time
import ipaddress
import math

from .region import reference as region_reference
from .common import read_json

def _public(value):
    try:
        address = ipaddress.ip_address(value)
        return str(address) if address.is_global and not address.is_multicast else None
    except (ValueError, TypeError): return None


def extract_risks(online, measured=None):
    online = online if isinstance(online, dict) else {}
    measured = measured if isinstance(measured, dict) else region_reference(online.get("trace", {}), online.get("geo", {}))
    risks = []
    country = measured.get("country") if isinstance(measured, dict) else ""
    trace, geo = online.get("trace", {}), online.get("geo", {})
    trace_cn = isinstance(trace, dict) and trace.get("loc") == "CN" and _public(trace.get("ip"))
    geo_cn = isinstance(geo, dict) and geo.get("country") == "CN" and _public(geo.get("ip"))
    if trace_cn or geo_cn:
        source = "trace" if trace_cn and not geo_cn else "geo" if geo_cn and not trace_cn else "trace/geo"
        risks.append({"id":"cn_egress", "source":source, "value":"CN", "reason":"本轮出口来源显示中国归属", "required":True})
    errors = online.get("query_errors", {})
    disagree = (isinstance(trace, dict) and isinstance(geo, dict) and _public(trace.get("ip")) and
                _public(geo.get("ip")) and (trace["ip"] != geo["ip"] or
                (trace.get("loc") and geo.get("country") and trace["loc"] != geo["country"])))
    if disagree or (isinstance(errors, dict) and "egress_consistency" in errors):
        risks.append({"id":"egress_conflict", "source":"egress_consistency", "value":"conflict", "reason":"出口来源返回不一致", "required":True})
    dns = online.get("dns", {})
    receipt = dns.get("receipt", {}) if isinstance(dns, dict) else {}
    countries = receipt.get("dns", {}).get("countries", []) if isinstance(receipt, dict) else []
    if isinstance(countries, list) and "CN" in countries:
        risks.append({"id":"cn_dns", "source":"dns", "value":"CN", "reason":"同轮 DNS 递归出口含中国归属", "required":True})
    webrtc = online.get("webrtc", {})
    observations = webrtc.get("observations", []) if isinstance(webrtc, dict) else []
    if isinstance(observations, list) and any(isinstance(x, dict) and x.get("country") == "CN" for x in observations):
        risks.append({"id":"cn_webrtc", "source":"webrtc", "value":"CN", "reason":"同轮 WebRTC 公网候选含中国归属", "required":True})
    elif isinstance(webrtc, dict) and webrtc.get("state") == "fail":
        risks.append({"id":"webrtc_mismatch", "source":"webrtc", "value":"mismatch", "reason":webrtc.get("detail") or "WebRTC 公网候选与同轮出口不一致", "required":True})
    asn = online.get("asn", {})
    lookup = online.get("netcoffee_lookup", {})
    lookup_ip = lookup.get("data", {}).get("ip") if isinstance(lookup, dict) and isinstance(lookup.get("data"), dict) else ""
    trace_ip = trace.get("ip") if isinstance(trace, dict) else ""
    if isinstance(asn, dict) and asn.get("registered_country") == "CN" and lookup_ip and lookup_ip == trace_ip:
        risks.append({"id":"cn_asn_registration", "source":"asn", "value":"CN", "reason":"当前 IP 的 ASN 注册归属为中国；这是归属风险，不等同已证实泄漏", "required":True})
    return {"state":"fail" if risks else "ok", "risks":risks, "evidence":{"country":country}}


def facts(online):
    online = online if isinstance(online, dict) else {}
    measured = region_reference(online.get("trace", {}), online.get("geo", {}))
    return dict(extract_risks(online, measured), measured=measured)


def session_risk(paths, context_id, current_ip=None):
    """Consume actual dated receipts. Missing/expired evidence is never safe."""
    from .audit import dns_receipt_status, webrtc_receipt_status
    now = time.time()
    dns = dns_receipt_status(paths, context_id, now=now)
    rtc = webrtc_receipt_status(paths, context_id, now=now)
    reasons, sources, times = [], {}, []
    for key, value in (("dns", dns), ("webrtc", rtc)):
        receipt = value.get("receipt", {})
        sampled = receipt.get("finished_at" if key == "dns" else "sampled_at", 0)
        try: fresh = math.isfinite(float(sampled)) and 0 <= now - float(sampled) <= 300
        except (TypeError, ValueError): fresh = False
        addresses = (receipt.get("http", {}).get("egress_ips", []) if key == "dns" else
                     [item.get("address") for item in receipt.get("observations", []) if item.get("kind") == "http"])
        bound = not current_ip or addresses == [current_ip]
        state = value.get("state", "unknown") if fresh and bound else "unknown"
        detail = value.get("detail", "检测证据缺失") if bound else "检测参考 IP 与当前会话出口不同"
        sources[key] = dict(state=state, observed_at=sampled if fresh else None, detail=detail)
        if state == "fail":
            reasons.append(dict(code=key + "_risk", detail=detail, source=key, observed_at=sampled))
        if state == "ok": times.append(float(sampled))
    # CN in otherwise internally consistent DNS/WebRTC results is still a risk.
    risks = extract_risks({"dns": dns if sources["dns"]["state"] != "unknown" else {},
                           "webrtc": rtc if sources["webrtc"]["state"] != "unknown" else {}})["risks"]
    for risk in risks:
        key = "dns" if risk["source"] == "dns" else "webrtc"
        reasons.append(dict(code=risk["id"], detail=risk["reason"], source=risk["source"],
                            observed_at=sources[key]["observed_at"]))
    # Same-IP ASN/country evidence from the shared environment/audit pipeline.
    for name in ("last-environment-detection.json", "last-audit.json"):
        try: value = read_json(paths.base / name, {})
        except Exception: continue
        if not isinstance(value, dict) or value.get("context_id") != context_id: continue
        evidence = value.get("policy_evaluation") or value
        if not isinstance(evidence, dict): continue
        facts_value = evidence.get("facts") or {}
        measured = facts_value.get("measured") or {}
        try: fresh = 0 <= now - float(value.get("observed_at", 0)) <= 300
        except (TypeError, ValueError): fresh = False
        if not fresh or not current_ip or measured.get("ip") != current_ip: continue
        for risk in facts_value.get("risks", []):
            if isinstance(risk, dict):
                reasons.append(dict(code=risk["id"], detail=risk["reason"], source=risk["source"], observed_at=value["observed_at"]))
    if reasons: return dict(state="risk", observed_at=min(float(r["observed_at"]) for r in reasons), reason=reasons[0], reasons=reasons, sources=sources)
    if len(times) == 2: return dict(state="safe", observed_at=min(times), sources=sources)
    return dict(state="unknown", observed_at=min(times) if times else None, sources=sources,
                reason=dict(code="risk_evidence_unavailable", detail="DNS/WebRTC 当前有效证据尚未齐全", source="自动检测", observed_at=now))
