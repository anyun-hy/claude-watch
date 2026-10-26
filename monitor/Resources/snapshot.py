"""Read-only presentation adapter for the existing multi-application Watch service."""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import plistlib
import re
import time
import ipaddress

KINDS = {"desktop-main", "desktop-helper", "code", "child", "codex-cli"}
KINDS.update(f"{product}-{role}" for product in ("codex", "chatgpt", "openai")
             for role in ("desktop-main", "desktop-helper", "child"))
LABEL = "io.local.claudewatch.agent"
FAKE_IP_NETWORK = ipaddress.ip_network("198.18.0.0/15")
DESTINATION_IP_STATES = {"public", "missing", "synthetic", "nonpublic", "invalid"}
CONNECTION_COLLECTOR_STATES = {"ok", "empty", "partial", "failed", "no_targets", "unknown"}
CONNECTION_OBSERVATION_SKEW_SECONDS = 5


def monitor_capabilities(raw):
    """Capabilities come from the validated running producer, not the GUI version."""
    version = raw.get("monitor_version")
    apps = raw.get("monitored_apps")
    if version is None and apps is None:
        return None, ["claude"]  # Legacy 2.1 producer only collected Claude.
    if (not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version)
            or not isinstance(apps, list) or not apps
            or any(not isinstance(app, str) or app not in {"claude", "codex", "chatgpt"} for app in apps)):
        return None, []
    return version, sorted(set(apps))

def text(path):
    try:
        return Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ""

def destination_evidence(flow):
    """Revalidate optional backend target evidence before it reaches the GUI."""
    raw_ip = flow.get("destination_ip", "")
    raw_port = flow.get("destination_port")
    port = None
    try:
        if isinstance(raw_port, bool):
            raise ValueError("boolean_port")
        candidate = int(raw_port)
        if 0 < candidate < 65536:
            port = candidate
    except (TypeError, ValueError):
        pass
    reported_state = flow.get("destination_ip_state")
    if raw_ip in (None, ""):
        return "", port, "missing", ""
    try:
        address = ipaddress.ip_address(str(raw_ip))
    except ValueError:
        return "", port, "invalid", ""
    if address in FAKE_IP_NETWORK:
        derived_state = "synthetic"
    elif (not address.is_global or address.is_loopback or address.is_private or address.is_link_local
          or address.is_multicast or address.is_reserved or address.is_unspecified):
        derived_state = "nonpublic"
    else:
        derived_state = "public"
    if reported_state is not None and reported_state not in DESTINATION_IP_STATES:
        return "", port, "invalid", ""
    if reported_state is not None and reported_state != derived_state:
        return "", port, "invalid", ""
    if derived_state != "public":
        return "", port, derived_state, ""
    country = flow.get("destination_country", "")
    if not isinstance(country, str) or not re.fullmatch(r"[A-Za-z]{2}", country):
        country = ""
    return str(address), port, "public", country.upper()

def process_records(raw, active=None):
    records = []
    for line in raw.splitlines():
        parts = line.split("|")
        if len(parts) != 3 or not parts[0].isdigit() or not parts[1] or parts[2] not in KINDS:
            continue
        pid = int(parts[0])
        records.append({"id": parts[0] + "|" + parts[1], "pid": pid, "started": parts[1],
                        "kind": parts[2], "authorized": None if active is None else pid in active})
    return sorted(records, key=lambda row: row["pid"])

def process_started_after_observation(started, observed_at):
    """Return true only when the C-locale lstart stamp proves a newer PID."""
    if not isinstance(observed_at, (int, float)) or not math.isfinite(observed_at):
        return False
    match = re.fullmatch(
        r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) "
        r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})",
        started.strip(),
    )
    if not match:
        return False
    months = {name: index for index, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )}
    try:
        month, day, hour, minute, second, year = match.groups()
        stamp = dt.datetime(int(year), months[month], int(day), int(hour), int(minute), int(second))
        return time.mktime(stamp.timetuple()) > observed_at
    except (KeyError, ValueError, OverflowError, OSError):
        return False

def active_proxy_flows(proxy, records):
    """Keep only flows whose source process exists in this exact UI read."""
    if proxy is None:
        return None
    valid = {record["pid"]: record for record in records}
    observed_at = proxy.get("observedAt")
    kept = []
    dropped = {}
    sampled_pids = {flow["pid"] for flow in proxy["flows"]}
    for flow in proxy["flows"]:
        record = valid.get(flow["pid"])
        if record is None:
            reason = "process_missing"
        elif process_started_after_observation(record["started"], observed_at):
            reason = "process_restarted"
        else:
            kept.append(flow)
            continue
        dropped[reason] = dropped.get(reason, 0) + 1
    proxy["flows"] = kept
    observation = proxy.get("connectionObservation")
    if isinstance(observation, dict):
        observation["uiFilteredCount"] = sum(dropped.values())
        uncovered = sum(record["pid"] not in sampled_pids and
                        process_started_after_observation(record["started"], observed_at)
                        for record in records)
        observation["uiDropped"] = dict(dropped)
        if uncovered:
            observation["uiDropped"]["new_process_not_sampled"] = uncovered
        # A UI-side PID/reuse guard is evidence that the visible list is not a
        # complete empty collection.  Do not let this look like a clean empty
        # collector round merely because every cached flow was filtered here.
        if (dropped or uncovered) and observation.get("collectorState") in {"ok", "empty", "no_targets"}:
            observation["collectorState"] = "partial"
            detail = observation.get("detail", "")
            suffix = ("UI 过滤了 %d 条非当前进程流量" % sum(dropped.values()) if dropped else
                      "当前有 %d 个新进程尚未被本轮连接采样覆盖" % uncovered)
            observation["detail"] = (detail + "；" if detail else "") + suffix
    return proxy


def _connection_observation_unknown(detail):
    """Present an unavailable collector receipt explicitly, never as empty."""
    return {
        "schema": 1, "roundID": "", "observedAt": 0.0,
        "collectorState": "unknown", "targetCount": 0, "parsedCount": 0,
        "acceptedCount": 0, "correlatedCount": 0, "unconfirmedCount": 0,
        "dropped": {}, "detail": detail,
        "uiFilteredCount": 0, "uiDropped": {},
    }


def _nonnegative_int(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def connection_observation(raw, proxy_observed_at):
    """Validate the backend collection receipt before showing it to Swift.

    The collector's counters describe a single proxy sampling round.  A stale
    or malformed receipt is deliberately represented as ``unknown`` so an old
    producer cannot be mistaken for a successful zero-flow round.
    """
    if not isinstance(raw, dict):
        return _connection_observation_unknown("后台未提供连接采集回执")
    if type(raw.get("schema")) is not int or raw.get("schema") != 1:
        return _connection_observation_unknown("连接采集回执格式不受支持")
    round_id = raw.get("round_id")
    observed_at = raw.get("observed_at")
    state = raw.get("collector_state")
    if state == "unknown" and round_id == "":
        detail = raw.get("detail")
        if isinstance(detail, str) and detail and len(detail) <= 512:
            return _connection_observation_unknown(detail)
    if (not isinstance(round_id, str) or not round_id.strip() or len(round_id) > 128
            or not isinstance(observed_at, (int, float)) or isinstance(observed_at, bool)
            or not math.isfinite(observed_at) or observed_at <= 0
            or state not in CONNECTION_COLLECTOR_STATES):
        return _connection_observation_unknown("连接采集回执字段无效")
    if (not isinstance(proxy_observed_at, (int, float)) or isinstance(proxy_observed_at, bool)
            or not math.isfinite(proxy_observed_at) or proxy_observed_at <= 0
            or abs(float(observed_at) - float(proxy_observed_at)) > CONNECTION_OBSERVATION_SKEW_SECONDS):
        return _connection_observation_unknown("连接采集回执与代理采样轮次不一致")
    counter_keys = ("target_count", "parsed_count", "accepted_count", "correlated_count", "unconfirmed_count")
    if any(not _nonnegative_int(raw.get(key)) for key in counter_keys):
        return _connection_observation_unknown("连接采集计数无效")
    target_count, parsed_count, accepted_count, correlated_count, unconfirmed_count = (raw[key] for key in counter_keys)
    if (accepted_count > parsed_count
            or correlated_count + unconfirmed_count > accepted_count):
        return _connection_observation_unknown("连接采集计数关系无效")
    # target_count counts candidate processes, while the remaining counters
    # count connections: one process can legitimately contribute many sockets.
    if target_count == 0 and any((parsed_count, accepted_count, correlated_count, unconfirmed_count)):
        return _connection_observation_unknown("零目标连接采集计数无效")
    if ((state == "no_targets" and target_count != 0)
            or (state == "empty" and (target_count == 0 or parsed_count != 0 or accepted_count != 0))
            or (state == "ok" and accepted_count == 0)):
        return _connection_observation_unknown("连接采集状态与计数不一致")
    dropped = raw.get("dropped")
    if (not isinstance(dropped, dict)
            or any(not isinstance(key, str) or not key or len(key) > 80 or not _nonnegative_int(value)
                   for key, value in dropped.items())):
        return _connection_observation_unknown("连接采集丢弃计数无效")
    detail = raw.get("detail", "")
    if not isinstance(detail, str) or len(detail) > 512:
        return _connection_observation_unknown("连接采集详情无效")
    if state in {"ok", "empty", "no_targets"} and any(dropped.values()):
        state = "partial"
        detail = (detail + "；" if detail else "") + "存在被丢弃的连接证据，采样范围不完整"
    return {
        "schema": 1, "roundID": round_id, "observedAt": float(observed_at),
        "collectorState": state, "targetCount": target_count, "parsedCount": parsed_count,
        "acceptedCount": accepted_count, "correlatedCount": correlated_count,
        "unconfirmedCount": unconfirmed_count, "dropped": dict(dropped), "detail": detail,
        "uiFilteredCount": 0, "uiDropped": {},
    }

def health_snapshot(root, service_text, process_stamp, now, service_rc):
    parts = text(root / "state/heartbeat").strip().split("|")
    values = {}
    for line in service_text.splitlines():
        match = re.match(r"\s*(state|pid)\s*=\s*(\S+)", line)
        if match and match[1] not in values:
            values[match[1]] = match[2]
    data = {"state": "unavailable", "mode": "UNKNOWN", "pid": None, "heartbeatAge": None,
            "started": "", "detail": "正在核对后台状态", "alerts": "未知"}
    mode = text(root / "state/mode").strip()
    if mode == "paused":
        data["alerts"] = "已静默"
    elif mode.startswith("until:"):
        until = mode.partition(":")[2]
        data["alerts"] = "已静默" if until.isdigit() and int(until) > now else "开启"
    elif mode == "armed" or mode.startswith("armed:"):
        data["alerts"] = "开启"
    if service_rc != 0:
        if "Could not find service" in service_text or "Could not find specified service" in service_text:
            data.update(state="stopped", detail="后台任务未加载")
        else:
            data["detail"] = "暂时无法读取 launchd 状态"
        return data
    if values.get("pid", "").isdigit():
        data["pid"] = int(values["pid"])
    data.update(state="degraded", detail="后台任务已加载，等待有效心跳")
    if len(parts) != 5:
        return data
    pid, stamp, epoch, quality, mode = parts
    if not pid.isdigit() or not epoch.isdigit():
        return data
    data["mode"] = mode if mode in ("GUARD", "ACTIVE") else "UNKNOWN"
    data["started"] = stamp
    data["heartbeatAge"] = max(0, now - int(epoch))
    if values.get("state") != "running":
        data["detail"] = "后台进程当前未运行"
    elif data["pid"] != int(pid) or " ".join(stamp.split()) != " ".join(process_stamp.split()):
        data["detail"] = "心跳与当前进程身份不一致"
    elif now < int(epoch) or now - int(epoch) > 30:
        data["detail"] = "心跳已过期"
    elif quality != "ok":
        data["detail"] = "部分监控采样需要检查"
    else:
        data.update(state="running", detail="后台进程存活，采样心跳正常")
    return data

def tail_events(path, limit=100):
    try:
        with path.open("rb") as stream:
            stream.seek(0, 2)
            start = max(0, stream.tell() - 65536)
            stream.seek(start)
            raw = stream.read().decode("utf-8", errors="replace")
        if start:
            raw = raw.partition("\n")[2]
    except OSError:
        return []
    events = []
    titles = {
        "daemon-start": "监控服务已启动", "daemon-stop": "监控服务已停止",
        "install": "安装配置已更新", "uninstall": "监控服务已卸载",
        "state=GUARD": "进入后台警戒", "state=ACTIVE": "进入授权使用",
        "alert-dispatched": "系统提醒已发送", "unauthorized-process": "发现未授权进程",
        "sensitive-open-descriptor": "敏感目录文件描述符", "traffic-counter": "流量采样",
        "connection": "网络端点变化", "session-expired": "授权会话已结束",
        "tag-proxy": "代理核对记录", "scan-failed": "进程扫描失败",
        "launchd-label-candidate": "后台任务名称候选",
    }
    for index, line in enumerate(raw.splitlines()[-limit:]):
        match = re.match(r"^(\S+)\s+(.+)$", line)
        if not match:
            continue
        stamp, message = match.groups()
        try:
            epoch = dt.datetime.fromisoformat(stamp).timestamp()
        except ValueError:
            epoch = None
        key = message.split(" ", 1)[0]
        severity = "info"
        if "scan-failed" in message or "alert-failed" in message:
            severity = "error"
        elif any(word in message for word in ("unauthorized", "sensitive-open", "unavailable", "[配置差异]", "[变化]", "scan-error")):
            severity = "warning"
        elif any(word in message for word in ("未确认", "未验证", "未固定", "alert-dispatched")):
            severity = "notice"
        category = "network" if key in ("tag-proxy", "connection", "traffic-counter") else "process" if key in ("unauthorized-process", "session-expired") or key.startswith("state=") else "service"
        detail = message[len("tag-proxy "):] if message.startswith("tag-proxy ") else message
        events.append({"id": stamp + "|" + str(index) + "|" + key, "timestamp": stamp,
                       "epoch": epoch, "severity": severity, "category": category,
                       "title": titles.get(key, "检测记录"), "detail": detail})
    return list(reversed(events))

def proxy_snapshot(path, raw=None):
    try:
        if raw is None:
            raw = json.loads(text(path))
        if not isinstance(raw, dict) or raw.get("schema") != 1 or not isinstance(raw.get("entry"), dict) or not isinstance(raw.get("api"), dict):
            return None
        entry, api = raw["entry"], raw["api"]
        backend_version, monitored_apps = monitor_capabilities(raw)
        owners = entry.get("owners", [])
        flows = []
        for flow in raw.get("flows", []):
            if not isinstance(flow, dict) or not isinstance(flow.get("pid"), int):
                continue
            def endpoint(value):
                if not isinstance(value, (list, tuple)) or len(value) != 2:
                    return "未确认"
                return ("[" + str(value[0]) + "]" if ":" in str(value[0]) else str(value[0])) + ":" + str(value[1])
            local = endpoint(flow.get("local", []))
            peer = endpoint(flow.get("peer", []))
            protocol = str(flow.get("protocol", "")).upper()
            connection_id = flow.get("connection_id", "")
            stable_key = json.dumps(
                [flow["pid"], protocol, local, peer, str(connection_id)],
                ensure_ascii=False, separators=(",", ":"),
            )
            flow_id = str(flow["pid"]) + "|" + hashlib.sha256(stable_key.encode("utf-8")).hexdigest()[:20]
            destination_ip, destination_port, destination_ip_state, destination_country = destination_evidence(flow)
            flows.append({"id": flow_id, "pid": flow["pid"],
                          "host": str(flow.get("host") or endpoint(flow.get("peer", []))),
                          "peer": peer, "local": local,
                          "protocol": protocol,
                          "path": str(flow.get("path", "")),
                          "interface": str(flow.get("interface", "")),
                          "destinationIP": destination_ip, "destinationPort": destination_port,
                          "destinationIPState": destination_ip_state, "destinationCountry": destination_country,
                          "association": str(flow.get("association", "unconfirmed")),
                          "policy": str(flow.get("policy", "unconfirmed")),
                          "reason": str(flow.get("reason", "")),
                          "chains": [str(value) for value in reversed(flow.get("chains", []))]})
        observed_at = raw.get("observed_epoch", 0)
        first_owner = owners[0] if owners and isinstance(owners[0], dict) else {}
        listener_started = first_owner.get("stamp")
        if (entry.get("state") != "verified" or not isinstance(listener_started, str)
                or not listener_started.strip() or len(listener_started) > 128):
            listener_started = None
        return {
            "backendVersion": backend_version, "monitoredApps": monitored_apps,
            "observedAt": float(observed_at),
            "entryState": str(entry.get("state", "unconfirmed")), "entryReason": str(entry.get("reason", "")),
            "entrySource": str(entry.get("source", "")), "endpoint": str(entry.get("endpoint", "http://127.0.0.1:7890")),
            "listenerPID": first_owner.get("pid") if first_owner else None,
            "listenerPath": str(first_owner.get("executable", "")) if first_owner else "",
            "listenerStarted": listener_started,
            "apiState": str(api.get("state", "unavailable")), "apiReason": str(api.get("reason", "")),
            "mode": str(api.get("mode", "")), "coversProxy": bool(api.get("covers_7890", False)),
            "expectedGroup": str(raw.get("expected_group", "")), "expectedNode": str(raw.get("expected_node", "")),
            "selectedNode": str(api.get("selected_node") or ""), "globalNode": str(api.get("global_node") or ""),
            "pinned": bool(raw.get("pinned", False)), "selectionChanged": bool(raw.get("selection_changed", False)),
            "flows": flows,
            "connectionObservation": connection_observation(raw.get("connection_observation"), observed_at),
        }
    except (TypeError, ValueError, KeyError, IndexError, AttributeError):
        return None

def daemon_proxy_snapshot(root, health, now):
    path = root / "state/proxy-snapshot.json"
    if not path.exists():
        return None, "后台尚未提供代理快照，需要更新 Watch 服务"
    if path.is_symlink():
        return None, "后台代理快照路径异常"
    if health["state"] != "running":
        return None, "后台心跳未通过核对，代理结果暂不作为当前证据"
    try:
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("oversize")
        raw = json.loads(path.read_text(encoding="utf-8"))
        producer = raw.get("producer", {})
        if (producer.get("pid") != health["pid"]
                or " ".join(str(producer.get("started", "")).split()) != " ".join(health["started"].split())):
            return None, "代理快照与当前后台进程身份不一致"
        epoch = raw.get("observed_epoch")
        if not isinstance(epoch, (int, float)) or not 0 <= now - epoch <= 30:
            return None, "后台代理快照已过期，等待下一次采样"
        proxy = proxy_snapshot(path, raw)
        if proxy is None:
            raise ValueError("invalid report")
        return proxy, None
    except (OSError, UnicodeError, ValueError, TypeError, AttributeError):
        return None, "后台代理快照不完整，等待下一次采样"

def snapshot(home, scratch, full=False):
    root = home / "Library/Application Support/ClaudeWatch"
    agent = home / "Library/LaunchAgents" / (LABEL + ".plist")
    log_dir = home / "Library/Logs/ClaudeWatch"
    now = time.time()
    try:
        rc = int(text(scratch / "service-rc").strip())
    except ValueError:
        rc = 1
    health = health_snapshot(root, text(scratch / "service"), text(scratch / "process-stamp"), now, rc)
    installed = (root / "claude-watch.sh").is_file() and agent.is_file()
    auto_start, keep_alive = False, False
    try:
        with agent.open("rb") as stream:
            plist = plistlib.load(stream)
        auto_start = plist.get("RunAtLoad") is True
        keep_alive = plist.get("KeepAlive") is True
    except (OSError, ValueError, plistlib.InvalidFileException):
        pass
    active = None
    process_text = text(root / "state/tracked")
    if full:
        if (scratch / "targets").is_file():
            process_text = text(scratch / "targets")
            active = {int(pid) for pid in text(scratch / "active").split() if pid.isdigit()}
    processes = process_records(process_text, active)
    try:
        roles = json.loads(text(scratch / "process-roles.json"))
        allowed_roles = {"mcp", "chromium_network", "chromium_renderer", "chromium_gpu", "chromium_crashpad"}
        for process in processes:
            role = roles.get(str(process["pid"]), {})
            if (role.get("runtimeRole") in allowed_roles
                    and " ".join(role.get("started", "").split()) == " ".join(process["started"].split())):
                process.update({key: str(role.get(key, ""))[:128] for key in ("runtimeRole", "serviceName", "roleEvidence")})
    except (ValueError, AttributeError, TypeError):
        pass
    proxy, proxy_error = daemon_proxy_snapshot(root, health, now)
    proxy = active_proxy_flows(proxy, processes)
    error = (text(scratch / "full-error").strip() or None) if full else None
    error = error or proxy_error
    try:
        stderr_bytes = (log_dir / "agent.stderr.log").stat().st_size
    except OSError:
        stderr_bytes = 0
    return {
        "capturedAt": now, "health": health, "installed": installed, "autoStart": auto_start,
        "keepAlive": keep_alive, "hasBaseline": (root / "state/baseline.conf").is_file(),
        "stderrBytes": stderr_bytes, "processes": processes,
        "events": tail_events(log_dir / "events.log"), "proxy": proxy, "proxyError": error,
        "backendVersion": proxy.get("backendVersion") if proxy else None,
        "monitoredApps": proxy.get("monitoredApps", []) if proxy else [],
        "logPath": str(log_dir / "events.log"),
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--scratch", required=True)
    parser.add_argument("--full", action="store_true")
    args = parser.parse_args()
    print(json.dumps(snapshot(Path.home(), Path(args.scratch), args.full), ensure_ascii=False, separators=(",", ":")))

