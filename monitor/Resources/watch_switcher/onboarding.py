"""Read-only discovery, expiring suggestions and explicitly confirmed setup.

Detection never changes a target. Only apply() writes the baseline, through a
private recovery journal shared with the existing operation lock.
"""
from __future__ import annotations

import json
import copy
import math
import re
import time
import uuid

from .audit import (evaluate, preferred_language, public_ip, dns_receipt_status, query_error_detail, source_notices, context_transition, reconcile_observations, policy_digest,
                    service_access_label, service_responses_presentation, stun_presentation, _time_text)
from .common import (DEFAULT_CONFIG, DOMAINS, LOCALES, MODES, SwitcherError, atomic_json, digest, event, load_config,
                     operation_lock, read_json, reject_symlink, sync_directory, validate_config)
from .repair import atomic_text, execute_action, file_text, make_plan
from .services import configure_update_task
from .region import reference as region_reference, date_summary, expected_date_summary, date_check

TTL = 300
OPTIONS = ("apply_environment", "enable_policy", "guard_enabled", "timezone_watchdog", "auto_update")
LABELS = {"proxy_mode": "代理客户端", "proxy_url": "HTTP 入口", "proxy_group": "代理组",
          "node": "当前节点", "network_service": "活动网络服务", "country": "出口国家",
          "ip": "出口 IP", "timezone": "系统时区", "locale": "地区格式", "language": "Claude 语言"}


def _query_failure(values, *sources):
    return query_error_detail(values, *sources)


def _display_source_failures(paths, rows, local, values, address, matched, conflict, now, persist):
    """Historical display data is separate from all controlled-launch evidence."""
    target = paths.base / "environment-valid-samples.json"
    try: previous = read_json(target, {})
    except SwitcherError: previous = {}
    previous = previous.get("rows", {}) if isinstance(previous, dict) else {}
    if not isinstance(previous, dict): previous = {}
    saved = {key: value for key, value in previous.items() if key in ("egress", "timezone", "locale", "asn")}
    by_id = {row["id"]: row for row in rows}
    reference_error = _query_failure(values, "trace", "geo") or "本轮出口来源资料不完整，未完成交叉核对"
    eligible = (not local.get("context_changed") and local.get("proxy") == "ok"
                and local.get("tun") == "ok" and not conflict)
    source_times = values.get("source_times", {})
    if not isinstance(source_times, dict): source_times = {}
    reference_data = region_reference(values.get("trace", {}), values.get("geo", {}))
    for key in ("egress", "timezone", "locale", "asn"):
        row = by_id[key]
        failure = (_query_failure(values, "geo", "asn") or "ASN 注册资料未返回完整结果") if key == "asn" else reference_error
        missing = row["state"] == "unknown" and (key == "asn" or not matched or
            (key == "timezone" and not reference_data.get("timezone")))
        if key == "timezone" and matched and not reference_data.get("timezone") and not _query_failure(values, "geo"):
            failure = "IPinfo：时区字段缺失、无效或不属于本轮出口国家"
        if row["state"] == "ok" and eligible and address:
            sampled = source_times.get("asn" if key == "asn" else "geo", now)
            if type(sampled) not in (float, int) or not math.isfinite(sampled): sampled = now
            row["sampled_at"] = sampled
            saved[key] = {"row": copy.deepcopy(row), "sampled_at": sampled,
                          "context": local.get("context"), "egress_ip": address,
                          "country": values.get("trace", {}).get("loc", ""),
                          "local_value": copy.deepcopy({name: local.get(name) for name in
                              (("timezone",) if key == "timezone" else ("locale", "date_format") if key == "locale" else ())})}
            continue
        if not missing: continue
        row["query_error"] = failure
        if failure not in row["detail"]: row["detail"] += "；查询原因：" + failure
        # Successfully read local values remain local observations, even when
        # an independent external reference could not be queried.
        if key == "timezone" and local.get("timezone"):
            row["state"] = "info"
            row["reference"] = "本机时区已读取；出口时区核对暂未完成"
            row["detail"] = "已读取当前系统时区 " + str(local["timezone"]) + "；出口时区查询未完成：" + failure
        elif key == "locale" and local.get("locale"):
            row["state"] = "info"
            row["reference"] = "本机地区与日期已读取；出口地区核对暂未完成"
            row["detail"] = "已读取本机地区与日期格式；本轮未完成出口地区核对：" + failure
        elif key == "egress" and address:
            row["state"] = "info"
            loc = values.get("trace", {}).get("loc")
            if isinstance(loc, str) and re.fullmatch(r"[A-Z]{2}", loc): row["current"] = address + " / " + loc
            row["reference"] = "Cloudflare 已返回出口；IPinfo 交叉核对暂未完成"
        old = previous.get(key)
        if not eligible or not isinstance(old, dict) or old.get("context") != local.get("context"): continue
        # Never reuse another IP/network's registration or locale reference.
        if not address or old.get("egress_ip") != address: continue
        loc = values.get("trace", {}).get("loc")
        if loc and old.get("country") and loc != old["country"]: continue
        old_row, sampled = old.get("row"), old.get("sampled_at")
        if not isinstance(old_row, dict) or type(sampled) not in (float, int) or not math.isfinite(sampled) or sampled > now: continue
        old_local = old.get("local_value", {})
        if not isinstance(old_local, dict) or any(local.get(name) != value for name, value in old_local.items()):
            row["detail"] += "；本机值已变化，未套用历史判定"
            continue
        row.update(current=old_row.get("current", row["current"]), state="cached", sampled_at=sampled,
                   reference="上次有效结果 · " + time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(sampled)),
                   source=old_row.get("source", row.get("source", "")),
                   detail="本轮查询失败：" + failure + "。保留上次有效数据，仅供显示，不用于启动放行。\n" + old_row.get("detail", ""))
    if persist and eligible:
        with operation_lock(paths, "observations"):
            atomic_json(target, {"schema": 1, "rows": saved})


def observe(paths, system, *, online=False, mode="auto", persist=False):
    """Measure the current environment without saved target/permission prerequisites.

    The reference for region/timezone/STUN comes from this round's measured
    egress. This receipt is intentionally not a launch-authorization receipt.
    """
    if mode not in MODES: raise SwitcherError("invalid_mode", "请选择已识别的代理类型")
    network = system.network_environment()
    probe = dict(DEFAULT_CONFIG, proxy_mode=mode, network_service=network.get("service") or "")
    local = system.local(probe)
    before_context = context(network, local)
    guard_known = True
    policy_before = None
    try:
        # Only the guard's actual enabled/heartbeat state uses its saved policy;
        # country, timezone, proxy selection and online permission do not.
        policy = load_config(paths)
        policy_before = policy_digest(policy)
        local["guard"] = system.guard_status(policy)
        local["guard_state"] = "ok" if local["guard"] else "unknown" if policy.get("guard_enabled") else "disabled"
        local["guard_detail"] = "保护心跳已确认" if local["guard"] else "保护心跳或后台身份未确认" if policy.get("guard_enabled") else "保护策略已禁用"
    except SwitcherError:
        local["guard"] = False; guard_known = False
    values, reason = {}, "尚未执行在线检测"
    after = None
    if online:
        try:
            require_transport(system, local)
            effective = dict(probe, proxy_mode=local["mode"], proxy_url="")
            values = system.online(effective)
            after_network = system.network_environment()
            after = system.local(probe)
            policy_after = load_config(paths)
            after["guard"] = system.guard_status(policy_after)
            after["guard_state"] = "ok" if after["guard"] else "unknown" if policy_after.get("guard_enabled") else "disabled"
            transition = reconcile_observations(local, after)
            changed_settings = []
            for key in ("service", "interface"):
                if network.get(key) == after_network.get(key): continue
                if network.get(key) and after_network.get(key): changed_settings.append("network_" + key)
                else:
                    transition["unavailable"].append("network_" + key)
                    if transition["state"] != "changed": transition["state"] = "sampling_unavailable"
            if policy_before != policy_digest(policy_after): changed_settings.append("policy")
            if changed_settings:
                transition["state"] = "changed"
                transition["changed_fields"] = sorted(set(transition["changed_fields"] + changed_settings))
            local["context_transition"] = transition
            local["context_changed"] = transition["state"] == "changed"
            require_transport(system, after)
            reason = ""
        except SwitcherError as exc:
            reason = str(exc)
            if values:
                if local.get("context_transition", {}).get("state") != "changed":
                    transition = local.get("context_transition") or {"before":{}, "after":{}, "changed_fields":[]}
                    transition.update(state="sampling_unavailable", unavailable=sorted(set(transition.get("unavailable", []) + [exc.code])))
                    local["context_transition"] = transition
                    local["context_changed"] = False
    # DNS is intentionally read from the same IPLeak receipt used by the
    # controlled launch path.  ``system.online`` must not create a second,
    # different resolver observation here.
    values["dns"] = dns_receipt_status(paths, local.get("context", ""))
    from .audit import webrtc_receipt_status
    values["webrtc"] = webrtc_receipt_status(paths, local.get("context_id", local.get("context", "")))
    if guard_known:
        try:
            policy = load_config(paths); local["guard"] = bool(local.get("guard") and system.guard_status(policy))
            if local["guard"]:
                local["guard_state"] = "ok"; local["guard_detail"] = "保护心跳已确认"
            elif policy.get("guard_enabled"):
                local["guard_state"] = "unknown"; local["guard_detail"] = "保护心跳或后台身份未能确认"
        except SwitcherError: local["guard"] = False; guard_known = False
    # A saved node mismatch is a separate drift warning. Verified physical
    # entry/TUN evidence remains usable for an explicit current-state diagnosis.
    if local.get("mode") == "tag":
        try:
            require_transport(system, local)
            local["proxy"] = "ok"
            local["proxy_detail"] = "TAG 运行进程、回环监听者和控制接口已核对"
        except SwitcherError: pass
    trace, geo = values.get("trace", {}), values.get("geo", {})
    address = public_ip(trace.get("ip"))
    measured = region_reference(trace, geo)
    country, timezone = measured.get("country"), measured.get("timezone")
    matched = bool(measured)
    geo_ip = public_ip(geo.get("ip"))
    trace_country, geo_country = trace.get("loc"), geo.get("country")
    reference_conflict = bool(address and geo_ip and (address != geo_ip or
        (isinstance(trace_country, str) and re.fullmatch(r"[A-Z]{2}", trace_country) and
         isinstance(geo_country, str) and re.fullmatch(r"[A-Z]{2}", geo_country) and trace_country != geo_country)))
    reference = dict(probe, enabled=True, country=country if matched else "", timezone=timezone or "",
                     locale=measured.get("locale") or "",
                     online_enabled=True, expected_egress=[address] if matched else [])
    try: history = read_json(paths.base / "environment-history.json", [])
    except SwitcherError: history = []
    if not isinstance(history, list): history = []
    result = evaluate(reference, local, values, history)
    rows_by_id = {row["id"]: row for row in result["rows"]}
    def detail(key, current, reference_text, source):
        row = rows_by_id[key]
        row.update(current=str(current or "未知"), reference=reference_text, source=source, required=False)
    tag = local.get("tag", {})
    entry = tag.get("entry", {})
    api = tag.get("api", {})
    node = api.get("global_node") if api.get("mode") == "global" else api.get("selected_node")
    detail("proxy", (local.get("mode") or "未识别") + (" · " + entry["endpoint"] if entry.get("state") == "verified" and entry.get("endpoint") else ""),
           "运行进程与监听者身份", "进程清单 / 后台新鲜样本 / 控制接口")
    if node: rows_by_id["proxy"]["detail"] += "；当前选择 " + node
    detail("tun", local.get("interface"), "代理与 TUN 路由同时存在", "ifconfig / route")
    detail("egress", (address + " / " + country) if matched else address or "未知",
           "Cloudflare 与 Net.Coffee 本轮出口一致", "Cloudflare trace + Net.Coffee lookup")
    rows_by_id["egress"]["detail"] = "本轮出口 IP 与国家交叉确认" if matched else "本轮出口/国家未能交叉确认"
    if reference_conflict:
        rows_by_id["egress"].update(state="fail", detail="Cloudflare 与 IPinfo 已返回的数据确实不一致：%s / %s 对 %s / %s" % (address, trace_country, geo_ip, geo_country))
    if matched: rows_by_id["egress"]["state"] = "fail" if country == "CN" else "ok"
    detail("ip_history", address, "48 小时检测历史，仅提示变化", "本轮出口 / 独立检测历史")
    detail("timezone", local.get("timezone"), timezone or "本轮出口时区未确认", "/etc/localtime / " + measured.get("timezone_source", "出口时区未确认"))
    rows_by_id["timezone"]["detail"] = "比较当前系统时区与本轮检测出口的时区；不读取已保存目标"
    detail("locale", date_summary(local), expected_date_summary(local, measured.get("locale")),
           "Foundation 日期模板 / AppleLocale / 本轮出口国家")
    detail("ipv6", "已关闭" if local.get("ipv6") == "ok" else "未关闭" if local.get("ipv6") == "fail" else "未知",
           "实际 IPv6 状态；不证明无泄漏", "networksetup -getinfo " + (network.get("service") or "（活动服务未知）"))
    dns_status = values.get("dns", {}) if isinstance(values.get("dns"), dict) else {}
    dns_receipt = dns_status.get("display_receipt") or dns_status.get("receipt", {})
    dns_data = dns_receipt.get("dns", {}) if isinstance(dns_receipt, dict) else {}
    resolvers = dns_data.get("egress_ips", []) if isinstance(dns_data, dict) else []
    countries = dns_data.get("countries", []) if isinstance(dns_data, dict) else []
    http_data = dns_receipt.get("http", {}) if isinstance(dns_receipt, dict) else {}
    http_countries = http_data.get("countries", []) if isinstance(http_data, dict) else []
    try:
        sampled_at = float(dns_receipt.get("finished_at"))
        sampled_text = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(sampled_at))
    except (TypeError, ValueError, OverflowError):
        sampled_text = "未取得"
    if len(resolvers) == 1:
        dns_current = resolvers[0] + " / " + (", ".join(countries) or "国家未确认")
    elif resolvers:
        dns_current = (", ".join(countries) or "国家未确认") + " · %d 个 DNS 出口" % len(resolvers)
    else:
        dns_current = "未知"
    detail("dns", dns_current, "同轮 HTTP 出口国家 " + (", ".join(http_countries) or "未确认"),
           "IPLeak.net 权威 DNS 记录 + 同轮 HTTP 参考；DNS 采样 " + sampled_text)
    rows_by_id["dns"]["detail"] = values["dns"].get("detail", "DNS 泄漏检测尚未完成")
    if countries:
        rows_by_id["dns"]["detail"] += "；DNS 国家 " + ", ".join(countries)
    if resolvers:
        rows_by_id["dns"]["detail"] += "；DNS 出口 " + "、".join(resolvers)
    rows_by_id["dns"]["sampled_at"] = dns_receipt.get("finished_at")
    if dns_status.get("display_receipt") and dns_status.get("display_receipt") != dns_status.get("receipt"):
        rows_by_id["dns"].update(state="cached", query_error=dns_status.get("detail", "本轮 DNS 查询未完成"))
        rows_by_id["dns"]["reference"] = "上次有效 DNS · " + sampled_text
        rows_by_id["dns"]["detail"] += "；此为历史显示，最新失败仍阻止受控启动"
    stun = values.get("stun", {}) if isinstance(values.get("stun"), dict) else {}
    stun_candidates = {public_ip(x.get("address")) for x in stun.get("observations", [])
                       if isinstance(x, dict) and x.get("status") == "ok"
                       and x.get("accepted") is not False and x.get("deadline_exceeded") is not True} - {""}
    stun_detail, stun_sampled_at, stun_observations = stun_presentation(stun, stun_candidates, {address} if matched else set())
    detail("stun", ", ".join(sorted(stun_candidates)),
           address if matched else "本轮 HTTP 出口未确认",
           "原生 UDP/STUN 逐台探针；用于 AI 受控启动网络检查，不等于 Claude 实际 socket 或 WebRTC")
    rows_by_id["stun"].update(detail=stun_detail, sampled_at=stun_sampled_at,
                              stun_finished_at=stun_sampled_at, stun_observations=stun_observations,
                              stun_probe=stun)
    # STUN compares against the independently observed HTTP address, not the
    # availability of IPinfo's country/timezone metadata.
    rows_by_id["stun"]["reference"] = address or "本轮 HTTP 出口未取得"
    detail("guard", "心跳已确认" if local.get("guard") else "保护未启用" if local.get("guard_state") == "disabled" else "保护心跳暂未确认", "当前后台真实状态", "保护心跳 / 已启用状态 / 后台身份")
    if not guard_known: rows_by_id["guard"]["state"] = "unknown"
    from .rules import format_detail, inspect_rules
    routing = inspect_rules(paths, dict(probe, proxy_group=tag.get("expected_group") or ""), local.get("mode", ""), tag=tag)
    rows_by_id["routing"].update(state=routing.get("state", "unknown"), detail=format_detail(routing))
    covered = routing.get("covered_domains", []) if isinstance(routing.get("covered_domains"), list) else []
    missing = routing.get("missing_domains", []) if isinstance(routing.get("missing_domains"), list) else []
    runtime = routing.get("runtime_domains", []) if isinstance(routing.get("runtime_domains"), list) else []
    controller = routing.get("controller_domains", []) if isinstance(routing.get("controller_domains"), list) else []
    current_rules = "%d/%d 已覆盖" % (len(covered), len(DOMAINS))
    if missing: current_rules += "；%d 项未确认" % len(missing)
    routing_reference = ("全局模式按全局代理节点转发，不使用逐域名规则表分流" if routing.get("actual_mode") == "global" else
        "规则模式：运行配置 %d/%d；控制器规则 %d/%d" % (len(runtime), len(DOMAINS), len(controller), len(DOMAINS)))
    detail("routing", current_rules, routing_reference, routing.get("source", "当前代理规则"))
    detail("language", preferred_language(local.get("language")), "英文偏好；与国家分开判断", "Claude AppleLanguages" if local.get("app_language") else "系统 AppleLanguages（Claude 未单独设置）")
    asn = values.get("asn", {}) if isinstance(values.get("asn"), dict) else {}
    number = asn.get("number")
    organization = asn.get("organization") if isinstance(asn.get("organization"), str) else ""
    registered_country = asn.get("registered_country") if isinstance(asn.get("registered_country"), str) else ""
    if isinstance(number, int) and number > 0:
        current_asn = "AS%d%s · 当前 IP %s" % (number, " " + organization if organization else "", country or "归属未确认")
        asn_reference = ("ASN 注册国家 %s；本轮出口地理国家 %s" % (registered_country, country or "未确认") if registered_country
                         else "ASN 注册国家暂未取得；本轮出口地理国家 %s" % (country or "未确认"))
        try:
            asn_queried = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(asn.get("registered_queried_at"))))
        except (TypeError, ValueError, OverflowError):
            asn_queried = "未提供"
        source_asn = "Net.Coffee lookup（采样 %s）/ RIPEstat RIR（统计日期 %s；查询 %s）" % (
            _time_text(values.get("netcoffee_lookup", {}).get("finishedAt")),
            asn.get("result_time") or "未提供", asn_queried)
    else:
        current_asn, asn_reference = "未取得", "ASN 注册国家未确认；出口地理国家 %s" % (country or "未确认")
        source_asn = "Net.Coffee lookup 未返回 ASN；IPinfo 仅在主源缺失时作为备用"
    detail("asn", current_asn, asn_reference, source_asn)
    service_state, service_detail, service_responses, service_sampled_at = service_responses_presentation(values)
    web = service_responses.get("claude") if isinstance(service_responses, dict) else None
    api_response = service_responses.get("api") if isinstance(service_responses, dict) else None
    web_label = service_access_label("claude", web, values.get("claude"))
    api_label = service_access_label("api", api_response, values.get("api"))
    service_sources = "网页：" + str(web.get("source") or "未提供")[:120] if isinstance(web, dict) else "网页：未提供"
    service_sources += "；API：" + (str(api_response.get("source") or "未提供")[:120] if isinstance(api_response, dict) else "未提供")
    network_prefix = "网络可达" if service_state == "ok" else "网络响应提示" if service_state == "warn" else "网络未确认"
    detail("reachability", network_prefix + " · 网页：" + web_label + " / API：" + api_label,
           "网页/API 分别展示网络与访问状态；不证明登录或账号可用", "本轮无账号凭据的 HTTPS 请求")
    rows_by_id["reachability"].update(state=service_state, detail=service_detail,
                                      service_responses=service_responses, sampled_at=service_sampled_at,
                                      source=service_sources)
    # Only real request failures become a row query_error.  Expected API 401
    # and a verified browser challenge remain green evidence, not failures.
    if service_state == "unknown":
        service_error = _query_failure(values, "claude", "api")
        if service_error:
            rows_by_id["reachability"]["query_error"] = service_error
    _display_source_failures(paths, result["rows"], local, values, address, matched,
                             reference_conflict, result["observed_at"], persist)
    from .audit import apply_risk_rows
    apply_risk_rows(result["rows"], result["facts"])
    if local.get("context_changed"):
        for row in result["rows"]:
            row.update(state="unknown", detail="检测期间网络或系统环境变化，请重新检测")
    now = result["observed_at"]
    try: saved_policy = load_config(paths)
    except SwitcherError: saved_policy = None
    policy_local = copy.deepcopy(local)
    if isinstance(saved_policy, dict):
        policy_local["rules"] = inspect_rules(paths, saved_policy, local.get("mode", ""), tag=local.get("tag") or {})
        if policy_before != policy_digest(saved_policy):
            policy_local["context_changed"] = True
    # Preview is descriptive evidence from this already-completed observation;
    # saved online permission controls a future launch audit, never erases facts.
    policy_values = values
    policy_preview = evaluate(saved_policy, policy_local, policy_values, history) if isinstance(saved_policy, dict) else None
    if policy_preview:
        policy_preview.update(purpose="launch_requirements_preview", grants_launch_permission=False,
                              observed_at=now, expires_at=now + 300)
    from .services import session_status
    session = session_status(paths)
    if session.get("phase") == "active":
        try:
            if system.claude_running() is False: session = dict(session, state="idle")
        except (SwitcherError, AttributeError): pass
    if policy_preview: policy_preview["session_guard"] = session
    if session.get("state") in ("locked", "unknown", "pending"):
        state = "fail" if session["state"] == "locked" else "unknown"
        explanation = (session.get("reason") or {}).get("detail") or "受控会话尚在核验"
        for view_rows in (result["rows"], policy_preview["rows"] if policy_preview else []):
            for row in view_rows:
                if row["id"] == "guard":
                    row.update(state=state, name="会话保护", current="已停止" if state == "fail" else "正在核验",
                               detail=explanation + "；后台心跳与会话安全分别核对。", required=True,
                               reference="再次启动仍执行完整校验", source="持久会话保护状态")
        if policy_preview:
            policy_preview["ready"] = False
            if "guard" not in policy_preview["blocked"]: policy_preview["blocked"].append("guard")
            policy_preview["message"] = explanation
    baseline_ip = (session.get("baseline") or {}).get("ip") if session.get("state") not in ("idle", "missing") else None
    if baseline_ip:
        locked_change = session.get("state") == "locked" and (session.get("reason") or {}).get("code") == "egress_ip_changed"
        different = bool(address and address != baseline_ip)
        session_state = "fail" if different or locked_change else "ok" if address else "unknown"
        session_detail = ("会话已因 IP 变化停止；再次启动必须完整核验并建立新基准。" if locked_change else
                          "当前出口 IP 与本次会话基准不同，保护正在处理。" if different else
                          "当前出口 IP 与本次受控会话基准一致。" if address else "本轮公网 IP 尚未取得，保留会话基准。")
        for view_rows in (result["rows"], policy_preview["rows"] if policy_preview else []):
            for row in view_rows:
                if row["id"] == "ip_history":
                    row.update(state=session_state, current=address or "未取得", reference="会话基准 " + baseline_ip,
                               detail=session_detail, source="本轮实测出口 / 受控启动会话基准", required=True)
        if policy_preview and session_state in ("fail", "unknown"):
            policy_preview["ready"] = False
            if "ip_history" not in policy_preview["blocked"]: policy_preview["blocked"].append("ip_history")
            policy_preview["message"] = session_detail
    receipt = dict(status="ok", purpose="environment_detection", grants_launch_permission=False,
                   observed_at=now, expires_at=now + 300, rows=result["rows"],
                   facts=result["facts"], egress_reference=result["egress_reference"],
                   session_guard=session,
                   candidates=local.get("candidates", []), regional_reference=measured,
                   netcoffee_lookup=values.get("netcoffee_lookup"), source_notices=source_notices(values),
                   observation_id=str(uuid.uuid4()), context_id=local.get("context_id", local.get("context", "")),
                   context_transition=local.get("context_transition", {"state":"sampling_unavailable","before":{},"after":{},"changed_fields":[],"unavailable":["online_not_run"]}),
                   policy_evaluation=policy_preview,
                   message="本轮实测结果；未知项保留未知。受控启动仍需独立预检。" + ("\n" + reason if reason else ""))
    if policy_preview:
        policy_preview.update(observation_id=receipt["observation_id"], context_id=receipt["context_id"])
    receipt["initialization_receipts"] = {}
    for kind, timestamp in (("dns", "finished_at"), ("webrtc", "sampled_at")):
        status = values.get(kind) if isinstance(values.get(kind), dict) else {}
        recorded = status.get("receipt") if isinstance(status.get("receipt"), dict) else {}
        receipt["initialization_receipts"][kind] = {
            "state": status.get("state"), "context_id": recorded.get("context_id"),
            "sampled_at": recorded.get(timestamp),
        }
    if persist:
        with operation_lock(paths, "observations"):
            current = read_json(paths.base / "environment-history.json", [])
            current = [x for x in current if isinstance(x, dict) and 0 <= now - x.get("time", 0) <= 172800] if isinstance(current, list) else []
            if matched and not local.get("context_changed"): current.append(dict(time=now, ip=address))
            atomic_json(paths.base / "environment-history.json", current[-2048:])
            atomic_json(paths.base / "last-environment-detection.json", receipt)
    return receipt


def language_array(value):
    if value is None: return None
    if preferred_language(value) is None:
        raise SwitcherError("language_unreadable", "原应用语言无法完整解析；未覆盖设置")
    return [x.strip().strip('"') for x in value.strip().strip("()").split(",") if x.strip()]


def snapshot(paths, system, mode="auto"):
    if mode not in MODES: raise SwitcherError("invalid_mode", "请选择已识别的代理类型")
    config = load_config(paths)
    network = system.network_environment()
    probe = dict(config, proxy_mode=mode, network_service=network.get("service") or "")
    local = system.local(probe)
    return config, network, local


def context(network, local):
    return digest({"network": network.get("service"), "interface": network.get("interface"),
                   **{key: local.get(key) for key in
                      ("context", "timezone", "locale", "date_format", "language", "app_language", "ipv6")}})


def current_values(network, local):
    tag = local.get("tag") or {}
    api = tag.get("api") or {}
    verified = (local.get("mode") == "tag" and tag.get("entry", {}).get("state") == "verified"
                and api.get("state") == "available" and api.get("covers_7890") is True)
    global_mode = api.get("mode") == "global"
    return {"proxy_mode": local.get("mode"), "proxy_url": "http://127.0.0.1:7890" if verified else None,
            "proxy_group": ("GLOBAL" if global_mode else tag.get("expected_group")) if verified else None,
            "node": (api.get("global_node") if global_mode else api.get("selected_node")) if verified else None,
            "network_service": network.get("service"), "country": None, "ip": None,
            "timezone": local.get("timezone"), "locale": local.get("locale"),
            "language": preferred_language(local.get("language"))}


def rows(paths, config, network, local, candidate=None):
    current = current_values(network, local)
    metadata = read_json(paths.base / "confirmed-environment.json", {})
    matches = metadata.get("policy") == digest(config)
    proposed = candidate.get("values", {}) if candidate else {}
    source = {"proxy_mode": "运行进程身份 / scutil", "proxy_url": "后台监听者身份样本（非默认端口猜测）",
              "proxy_group": "TAG 控制接口", "node": "TAG 控制接口",
              "network_service": network.get("source", "scutil / networksetup"),
              "country": "未联网检测", "ip": "未联网检测", "timezone": "/etc/localtime",
              "locale": "defaults AppleLocale", "language": "Claude AppleLanguages" if local.get("app_language")
              else "系统 AppleLanguages（Claude 未单独设置）"}
    if candidate:
        current.update({k: proposed.get(k) for k in ("country", "ip")})
        source.update(country="Cloudflare + IPinfo 交叉确认", ip="Cloudflare + IPinfo 交叉确认")
    result = []
    for key, title in LABELS.items():
        target = config.get(key)
        if key == "language": target = "English" if config["require_english"] else "未限定"
        if key == "node": target = metadata.get("values", {}).get(key) if matches else None
        if key == "ip": target = ", ".join(config["expected_egress"]) or ("允许变化（保留历史提示）" if config["allow_ip_change"] else "按历史检测变化")
        if not paths.config.exists(): target = None
        target_source = (metadata.get("sources", {}).get(key) if matches else None) or (
            "已保存设置（手动或旧版，检测来源未记录）" if paths.config.exists() else "尚未确认")
        if key == "ip" and paths.config.exists(): target_source = "已保存的出口 IP 策略；候选 IP 只作本次观测"
        result.append(dict(id=key, title=title, current=str(current.get(key) or "未知"),
                           target=str(target or "未配置"), proposed=str(proposed.get(key) or ""),
                           source=source[key], target_source=target_source,
                           proposed_source=candidate.get("sources", {}).get(key, "") if candidate else ""))
    return result


def inspect(paths, system, mode="auto"):
    config, network, local = snapshot(paths, system, mode)
    metadata = read_json(paths.base / "confirmed-environment.json", {})
    return dict(status="ok", observed_at=time.time(), initialized=bool(paths.config.exists() and config["country"] and config["timezone"]),
                rows=rows(paths, config, network, local), candidates=local.get("candidates", []),
                message=local.get("proxy_detail", "本机读取完成；尚未联网检测"),
                confirmed_at=metadata.get("confirmed_at") if metadata.get("policy") == digest(config) else None,
                recovery_required=(paths.base / "setup-transaction.json").exists())


def require_transport(system, local):
    tag = local.get("tag") or {}
    # Explicit adaptation may accept a new selection, but never an unverified
    # listener or an API belonging to a different kernel.
    if local.get("mode") == "tag":
        entry, api = tag.get("entry", {}), tag.get("api", {})
        if (entry.get("state") != "verified" or entry.get("public_listener") or
                api.get("state") != "available" or api.get("covers_7890") is not True or
                api.get("mode") not in ("rule", "global")):
            raise SwitcherError("proxy_unverified", "TAG 回环入口、控制接口或覆盖范围未确认；未联网")
        processes = local.get("processes", [])
        owners = entry.get("owners", [])
        if not owners or any(not any(p.get("pid") == owner.get("pid") and
                p.get("executable") == owner.get("executable") and p.get("uid") == owner.get("uid") and
                (not p.get("start_stamp") or p["start_stamp"] == owner.get("stamp"))
                for p in processes) for owner in owners):
            raise SwitcherError("proxy_unverified", "监听者与当前运行进程身份不一致；未联网")
    elif local.get("proxy") != "ok":
        raise SwitcherError("proxy_unverified", "代理身份不完整或有多个候选，请先明确选择客户端")
    if local.get("tun") != "ok" or not system.backend_healthy():
        raise SwitcherError("proxy_unverified", "TUN 或保护后台健康未确认；未联网")


def region(system, config, local, *, include_sources=False):
    probe = dict(config, proxy_mode=local["mode"], proxy_url="")
    try:
        values = system.egress_reference(probe)
        measured = region_reference(values.get("trace", {}), values.get("geo", {}))
        if (not measured or
                not measured.get("timezone") or not measured.get("locale")):
            raise ValueError()
    except (SwitcherError, ValueError, TypeError, KeyError):
        raise SwitcherError("region_inconsistent", "出口 IP、国家、对应时区或地区格式未能确认；未生成候选")
    if measured["country"] == "CN":
        raise SwitcherError("region_confirmation_required", "检测到 CN 出口，自动初始化不接受此地区；请检查代理")
    result = {key: measured[key] for key in ("ip", "country", "timezone")}
    return (result, values, measured) if include_sources else result


def detect(paths, system, mode="auto", *, online=False):
    if not online: raise SwitcherError("online_consent_required", "生成候选需要本次明确允许 Cloudflare 与 Net.Coffee 联网检测")
    config, network, local = snapshot(paths, system, mode)
    require_transport(system, local)
    if not network.get("service"):
        raise SwitcherError("network_unknown", "活动网络服务未确认，请先检查网络或使用高级手动设置")
    values = current_values(network, local)
    measured_values, egress_values, measured_reference = region(system, config, local, include_sources=True)
    values.update(measured_values)
    # Date/region conventions follow the exit country; English is independent.
    values["locale"] = LOCALES[values["country"]]
    values["language"] = "English" if config["require_english"] else (preferred_language(local.get("language")) or "未限定")
    if local["mode"] == "tag" and (not values["proxy_group"] or not values["node"]):
        raise SwitcherError("selection_unknown", "当前代理组或节点未确认；未生成候选")
    after_config, after_network, after = snapshot(paths, system, mode)
    require_transport(system, after)
    if digest(config) != digest(after_config) or context(network, local) != context(after_network, after):
        raise SwitcherError("context_changed", "检测期间环境或目标配置变化，请重新检测")
    now = time.time()
    geo_source = egress_values.get("geo", {}) if isinstance(egress_values, dict) else {}
    country_source = "Cloudflare trace + " + ((geo_source.get("country_source") if isinstance(geo_source, dict) else "") or "当前出口归属来源")
    timezone_source = measured_reference.get("timezone_source") or "出口时区来源未确认"
    candidate = dict(schema=1, observed_at=now, expires_at=now + TTL, mode=mode,
                     policy=digest(config), context=context(network, local), values=values,
                     sources={key: (country_source if key in ("country", "ip") else
                              timezone_source if key == "timezone" else
                              "出口国家对应的地区与日期格式" if key == "locale" else
                              "独立的英文语言偏好（不随地区改变）" if key == "language" else
                              "scutil PrimaryService" if key == "network_service" else
                              "TAG 验证入口 / 控制接口" if local["mode"] == "tag" else "运行进程 / TUN") for key in LABELS})
    candidate["id"] = digest(candidate)
    with operation_lock(paths):
        if digest(load_config(paths)) != candidate["policy"]:
            raise SwitcherError("context_changed", "目标设置变化，请重新检测")
        atomic_json(paths.base / "environment-candidate.json", candidate)
    return dict(status="ok", **candidate, rows=rows(paths, config, network, local, candidate),
                message="候选尚未保存。当前出口仅代表诊断请求；不证明 Claude 账号或全部流量可用。")


def checked_candidate(paths, system, candidate_id):
    candidate = read_json(paths.base / "environment-candidate.json", {})
    if candidate.get("id") != candidate_id or not 0 <= time.time() - candidate.get("observed_at", 0) <= TTL:
        raise SwitcherError("candidate_expired", "候选不存在或已超过 5 分钟，请重新检测")
    body = {k: v for k, v in candidate.items() if k != "id"}
    if digest(body) != candidate_id: raise SwitcherError("invalid_candidate", "候选校验失败，请重新检测")
    config, network, local = snapshot(paths, system, candidate["mode"])
    require_transport(system, local)
    if digest(config) != candidate["policy"] or context(network, local) != candidate["context"]:
        raise SwitcherError("stale_candidate", "当前值、代理或已保存目标变化，请重新检测")
    return candidate, config, network, local


def preview(paths, system, candidate_id, options):
    if not isinstance(options, dict) or set(options) != set(OPTIONS) or any(type(x) is not bool for x in options.values()):
        raise SwitcherError("invalid_options", "请明确选择环境与后台选项")
    candidate, config, network, local = checked_candidate(paths, system, candidate_id)
    values = candidate["values"]
    desired = dict(config, **{k: values.get(k) or "" for k in
                             ("country", "timezone", "locale", "proxy_mode", "proxy_url", "proxy_group", "network_service")})
    desired.update(enabled=options["enable_policy"], online_enabled=options["enable_policy"] or config["online_enabled"],
                   guard_enabled=options["guard_enabled"], timezone_watchdog=options["timezone_watchdog"], auto_update=options["auto_update"])
    desired = validate_config(desired)
    if desired["guard_enabled"] and not desired["enabled"]:
        raise SwitcherError("policy_required", "启用断线保护时也需启用受控环境策略")
    if desired["auto_update"] and not config["auto_update"] and (not desired["update_url"] or not desired["update_public_key"]):
        raise SwitcherError("update_source_missing", "尚未配置自有发布清单及公钥，不能启用实际自动更新")
    # Reuse the fixed executors, applying only the selected environment changes
    # and preserving the explicitly supplied background intentions.
    plan = make_plan(paths, system, desired)
    actions = [x for x in plan["actions"] if x["id"] in ("watchdog", "updater") or
               (options["apply_environment"] and x["id"] in ("timezone", "locale", "language", "ipv6"))]
    if options["apply_environment"] and desired["require_ipv6_off"] and local.get("ipv6") == "unknown":
        raise SwitcherError("ipv6_unknown", "选定网络服务的 IPv6 状态未知；未预览自动修改")
    for action in actions:
        if action["id"] == "language": action["before"] = language_array(local.get("app_language"))
        if action["id"] == "ipv6":
            info = system.optional(["/usr/sbin/networksetup", "-getinfo", desired["network_service"]]) or ""
            match = re.search(r"^IPv6:\s*(.+)$", info, re.M)
            if not match or match[1].strip().lower() != "automatic":
                raise SwitcherError("ipv6_not_reversible", "IPv6 不是可恢复的自动模式，请在高级设置中手动处理")
            action["before"] = "automatic"
        def display(value):
            if value is None: return "未设置"
            if isinstance(value, bool): return "启用" if value else "停用"
            if isinstance(value, list): return ", ".join(value)
            return str(value)
        action["detail"] = display(action["before"]) + " → " + display(action["after"])
    plan = dict(schema=1, candidate_id=candidate_id, options=options, actions=actions,
                desired_config=desired, policy=digest(config), context=candidate["context"],
                values=values, rows=rows(paths, config, network, local, candidate),
                observed_at=candidate["observed_at"], expires_at=candidate["expires_at"])
    plan["id"] = digest(plan)
    return dict(status="ok", **plan)


def managed_files(paths):
    return {"config": paths.config, "baseline": paths.watch / "state/baseline.conf",
            "confirmation": paths.base / "confirmed-environment.json"}


def restore_action(paths, system, desired, action):
    kind, before, after = action["id"], action["before"], action["after"]
    local = system.local(desired)
    if kind in ("timezone", "locale"):
        current = local.get(kind)
        if current == before: return
        if current != after: raise SwitcherError("rollback_conflict", "设置已被其他操作更改，保留当前值")
        if not before: raise SwitcherError("rollback_unknown", "原设置未知，未猜测恢复值")
        if kind == "timezone": system.admin("timezone", before)
        else: system.run(["/usr/bin/defaults", "write", "-g", "AppleLocale", before])
    elif kind == "language":
        current = language_array(local.get("app_language"))
        if current == before: return
        if current != ["en-US"]: raise SwitcherError("rollback_conflict", "Claude 语言已被其他操作更改")
        args = ["/usr/bin/defaults"]
        if before is None: args += ["delete", "com.anthropic.claudefordesktop", "AppleLanguages"]
        else: args += ["write", "com.anthropic.claudefordesktop", "AppleLanguages", "-array", *before]
        system.run(args)
    elif kind == "ipv6":
        info = system.optional(["/usr/sbin/networksetup", "-getinfo", desired["network_service"]]) or ""
        if re.search(r"^IPv6:\s*Automatic\s*$", info, re.M | re.I): return
        if local.get("ipv6") == "ok": system.admin("ipv6", desired["network_service"], before)
        else: raise SwitcherError("rollback_conflict", "IPv6 状态已变化，请核对后恢复")
    elif kind == "watchdog":
        current = system.watchdog_state()["target"]
        if current == before: return
        if current != after: raise SwitcherError("rollback_conflict", "时区守护目标已被其他操作更改")
        system.admin("watchdog", before or "off")
    elif kind == "updater":
        path = paths.home / "Library/LaunchAgents/io.local.claudewatch.update.plist"
        if path.exists() != before: configure_update_task(paths, system, before)


def rollback(paths, system, journal):
    failed = []
    for action in reversed(journal["actions"]):
        if action.get("state") == "restored": continue
        try:
            restore_action(paths, system, journal["desired_config"], action)
            action["state"] = "restored"
            atomic_json(paths.base / "setup-transaction.json", journal)
        except Exception: failed.append(action["id"])
    for key, path in managed_files(paths).items():
        saved = journal["files"][key]
        try:
            current = file_text(path, paths.home) if path.exists() else None
            if current != saved["before"]:
                if current != saved["after"]: raise SwitcherError("rollback_conflict", "文件已被其他操作更改")
                if saved["before"] is None:
                    path.unlink(); sync_directory(path.parent)
                else:
                    atomic_text(path, saved["before"], paths.home); sync_directory(path.parent)
        except Exception: failed.append(key)
    if failed:
        return {"status": "partial", "recovery_required": True,
                "message": "初始化未完成；部分恢复需要处理：" + "、".join(failed)}
    (paths.base / "setup-transaction.json").unlink()
    sync_directory(paths.base)
    return {"status": "ok", "recovery_required": False, "message": "已恢复初始化前的设置与基线。"}


def recover(paths, system):
    with operation_lock(paths, recovery="setup"):
        journal = read_json(paths.base / "setup-transaction.json")
        if not journal: return {"status": "ok", "message": "没有待恢复的初始化事务"}
        if journal.get("schema") != 1 or set(journal.get("files", {})) != set(managed_files(paths)):
            raise SwitcherError("invalid_transaction", "初始化事务格式不完整，未猜测恢复内容")
        validate_config(journal["desired_config"])
        if (not isinstance(journal.get("actions"), list) or len(journal["actions"]) > 8 or
                any(not isinstance(saved, dict) or set(saved) != {"before", "after"} or
                    any(v is not None and (not isinstance(v, str) or len(v) > 2_000_000) for v in saved.values())
                    for saved in journal["files"].values())):
            raise SwitcherError("invalid_transaction", "初始化事务字段无效，未执行恢复")
        for action in journal["actions"]:
            if (not isinstance(action, dict) or action.get("id") not in
                    ("timezone", "locale", "language", "ipv6", "watchdog", "updater") or
                    action.get("state") not in ("pending", "applied", "restored") or
                    "before" not in action or "after" not in action):
                raise SwitcherError("invalid_transaction", "初始化动作记录无效，未执行恢复")
            kind, before, after = action["id"], action["before"], action["after"]
            if kind in ("timezone", "locale", "watchdog"):
                key = "timezone" if kind == "watchdog" else kind
                for value in (before, after):
                    if value is not None: validate_config({key: value})
            if kind == "language" and (after != "en-US" or (before is not None and
                    (not isinstance(before, list) or not before or any(not isinstance(x, str) or
                     not re.fullmatch(r"[A-Za-z]{2,3}(?:[-_][A-Za-z0-9]{1,8})*", x) for x in before)))):
                raise SwitcherError("invalid_transaction", "原语言记录无效")
            if kind == "ipv6" and (before != "automatic" or after != journal["desired_config"]["network_service"]):
                raise SwitcherError("invalid_transaction", "原 IPv6 记录无效")
            if kind == "updater" and (type(before) is not bool or type(after) is not bool):
                raise SwitcherError("invalid_transaction", "更新任务记录无效")
        return rollback(paths, system, journal)


def apply(paths, system, candidate_id, options, plan_id):
    with operation_lock(paths):
        plan = preview(paths, system, candidate_id, options)
        if plan["id"] != plan_id: raise SwitcherError("stale_plan", "预览选项或环境变化，请重新预览")
        candidate, config, network, local = checked_candidate(paths, system, candidate_id)
        if region(system, config, local) != {k: candidate["values"][k] for k in ("ip", "country", "timezone")}:
            raise SwitcherError("egress_changed", "确认时出口发生变化，请重新检测")
        checked_candidate(paths, system, candidate_id)
        desired = plan["desired_config"]
        if desired["guard_enabled"] and not (paths.watch / "runtime/switcher.py").is_file():
            raise SwitcherError("backend_update_required", "先安装完整后台，再启用保护")
        journal = dict(schema=1, id=plan_id, desired_config=desired, actions=[], files={
            k: {"before": file_text(p, paths.home) if p.exists() else None, "after": None}
            for k, p in managed_files(paths).items()})
        atomic_json(paths.base / "setup-transaction.json", journal)
        try:
            for action in plan["actions"]:
                journal["actions"].append(dict(action, state="pending"))
                atomic_json(paths.base / "setup-transaction.json", journal)
                execute_action(paths, system, desired, action)
                journal["actions"][-1]["state"] = "applied"
                atomic_json(paths.base / "setup-transaction.json", journal)
            # Changes to time/locale are expected now; network identity must stay fixed.
            _, final_network, final = snapshot(paths, system, candidate["mode"])
            require_transport(system, final)
            if (local.get("context") != final.get("context") or network != final_network or
                    digest(load_config(paths)) != candidate["policy"]):
                raise SwitcherError("context_changed", "应用期间网络或目标设置变化")
            for action in plan["actions"]:
                kind = action["id"]
                if kind in ("timezone", "locale") and final.get(kind) != action["after"]:
                    raise SwitcherError("setting_unconfirmed", "系统设置应用后未能确认：" + kind)
                if kind == "language" and preferred_language(final.get("app_language")) != "en-US":
                    raise SwitcherError("setting_unconfirmed", "Claude 英文语言应用后未能确认")
                if kind == "ipv6" and final.get("ipv6") != "ok":
                    raise SwitcherError("setting_unconfirmed", "IPv6 关闭状态未能确认")
                if kind == "watchdog":
                    state = system.watchdog_state()
                    if state["target"] != action["after"] or (action["after"] and not state["registered"]):
                        raise SwitcherError("setting_unconfirmed", "时区守护注册未能确认")
            if options["apply_environment"] and date_check(final, desired["locale"]) != "ok":
                raise SwitcherError("setting_unconfirmed", "应用后的实际日期格式未能与出口地区模板核对，已取消保存")
            baseline = system.baseline_data()
            _, end_network, end = snapshot(paths, system, candidate["mode"])
            require_transport(system, end)
            if (context(final_network, final) != context(end_network, end) or final_network != end_network):
                raise SwitcherError("context_changed", "基线读取期间代理或网络变化")
            baseline_values = dict(line.split("=", 1) for line in baseline.splitlines() if "=" in line)
            if baseline_values.get("format") != "2" or baseline_values.get("timezone") != end.get("timezone"):
                raise SwitcherError("baseline_incomplete", "基线与最终本机时区未能核对")
            if local["mode"] == "tag":
                for key in ("proxy_group", "node"):
                    if any(c in candidate["values"][key] for c in "\n\r\x00"):
                        raise SwitcherError("selection_invalid", "代理选择格式无效")
                baseline += "tag_group=" + candidate["values"]["proxy_group"] + "\ntag_node=" + candidate["values"]["node"] + "\n"
            metadata = dict(schema=1, confirmed_at=time.time(), observed_at=candidate["observed_at"],
                            policy=digest(desired), values=candidate["values"], sources=candidate["sources"])
            texts = {"baseline": baseline, "confirmation": json.dumps(metadata, ensure_ascii=False, sort_keys=True) + "\n",
                     "config": json.dumps(desired, ensure_ascii=False, sort_keys=True) + "\n"}
            for key in ("baseline", "confirmation", "config"):
                path = managed_files(paths)[key]
                current = file_text(path, paths.home) if path.exists() else None
                if current != journal["files"][key]["before"]:
                    raise SwitcherError("external_change", "保存期间文件被其他操作更改；未覆盖：" + key)
                journal["files"][key]["after"] = texts[key]
                atomic_json(paths.base / "setup-transaction.json", journal)
                atomic_text(path, texts[key], paths.home)
                sync_directory(path.parent)
            (paths.base / "setup-transaction.json").unlink(); sync_directory(paths.base)
        except Exception as exc:
            result = rollback(paths, system, journal)
            if result["recovery_required"]: return result
            raise SwitcherError("setup_rolled_back", "初始化未完成，已恢复原设置。" +
                                (str(exc) if isinstance(exc, SwitcherError) else "请重新检测后重试")) from exc
        event(paths, "setup", status="ok", count=len(plan["actions"]))
        return {"status": "ok", "config": desired,
                "message": "已确认并保存目标与本地基线。首次受控启动仍需通过现有 14 项预检；后台状态将在下一轮采样更新。"}
