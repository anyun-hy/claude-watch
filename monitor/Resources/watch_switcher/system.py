"""Bounded macOS observations. Tests inject a fake System; nothing runs on import."""
from __future__ import annotations

import json
import ipaddress
import hashlib
import os
import plistlib
import re
import subprocess
import tempfile
import time
from pathlib import Path

from .common import LOCALES, SwitcherError, digest, guard_heartbeat_policy_matches, load_config, read_json, reject_symlink, operation_lock

APP_BUNDLES = {
    "tag": "/Applications/TAG.app",
    "clash-verge": "/Applications/Clash Verge.app",
    "shadowrocket": "/Applications/Shadowrocket.app",
    "clashx": "/Applications/ClashX.app",
    "surge": "/Applications/Surge.app",
}
PROXY_PATHS = {
    "tag": ("/Applications/TAG.app/Contents/",),
    "clash-verge": ("/Applications/Clash Verge.app/Contents/", "/Library/PrivilegedHelperTools/io.github.clash-verge"),
    "shadowrocket": ("/Applications/Shadowrocket.app/",),
    "sing-box": ("/opt/homebrew/Cellar/sing-box/", "/usr/local/Cellar/sing-box/", "/usr/local/bin/sing-box"),
    "clashx": ("/Applications/ClashX.app/", "/Library/PrivilegedHelperTools/com.west2online.ClashX"),
    "surge": ("/Applications/Surge.app/", "/Library/PrivilegedHelperTools/com.nssurge."),
}
ADMIN_TARGET = Path("/Library/Application Support/ClaudeWatch/claude-watch-admin.sh")

_CURL_FAILURES = {
    5: ("proxy_resolve_failed", "代理地址无法解析"),
    6: ("dns_resolution_failed", "域名解析失败"),
    7: ("connection_failed", "无法建立连接"),
    28: ("timeout", "请求超时"),
    35: ("tls_failed", "TLS 握手失败"),
    51: ("tls_failed", "TLS 证书校验失败"),
    52: ("connection_closed", "服务端未返回响应"),
    56: ("connection_failed", "连接传输失败"),
    60: ("tls_failed", "TLS 证书校验失败"),
}


def _query_error(code, message, source, *, http_status=None, queried_at=None):
    """Build a bounded, credential-free online-query error receipt."""
    meanings = {401: "需要认证", 403: "访问被拒绝", 429: "请求受到限流"}
    if http_status in meanings:
        message = "HTTP %s，%s" % (http_status, meanings[http_status])
    elif type(http_status) is int and http_status >= 500:
        message = "HTTP %s，服务端错误" % http_status
    value = {"code": str(code)[:80], "message": str(message)[:240], "source": str(source)[:120],
             "queried_at": float(time.time() if queried_at is None else queried_at)}
    if type(http_status) is int and 100 <= http_status <= 599:
        value["http_status"] = http_status
    return value


def _cached_receipt_error(receipt, source, *, queried_at=None):
    """Preserve cache/backoff causes without exposing a stale success as current."""
    receipt = receipt if isinstance(receipt, dict) else {}
    status = receipt.get("status")
    http_status = receipt.get("httpStatus")
    code = "http_" + str(http_status) if type(http_status) is int else (status if status in ("timeout", "error") else "query_failed")
    message = str(receipt.get("error") or "查询未完成")[:200]
    retry = receipt.get("retry_after")
    try:
        retry = float(retry)
        if retry > 0: message += "；冷却剩余 %d 秒" % min(86400, int(retry))
    except (TypeError, ValueError):
        pass
    value = _query_error(code, message, source, http_status=http_status,
                         queried_at=receipt.get("finishedAt", queried_at if queried_at is not None else time.time()))
    if "；冷却剩余" in message and "冷却剩余" not in value["message"]:
        value["message"] += message[message.index("；冷却剩余"):]
    return value


def asn_number(geo):
    """Extract only the explicit ASN prefix supplied with this egress record."""
    if not isinstance(geo, dict):
        return None
    value = geo.get("org")
    if not isinstance(value, str):
        return None
    match = re.match(r"\s*AS([1-9][0-9]{0,9})(?:\s|$)", value)
    if not match:
        return None
    try:
        number = int(match.group(1))
    except ValueError:
        return None
    return number if number <= 4_294_967_295 else None


def asn_organization(geo, number):
    """Keep the organization label separate from the already rendered ASN."""
    if not isinstance(geo, dict) or not isinstance(number, int) or number <= 0:
        return ""
    value = geo.get("org")
    if not isinstance(value, str):
        return ""
    value = value.strip()
    prefix = re.match(r"^AS([1-9][0-9]{0,9})(?:\s+(.+))?$", value)
    if prefix and int(prefix.group(1)) == number:
        return (prefix.group(2) or "").strip()[:512]
    return value[:512]


def parse_ripe_asn_country(body, number):
    """Accept one RIPEstat country only when its resource is this exact ASN."""
    if not isinstance(number, int) or number <= 0:
        return {}
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        return {}
    data = payload.get("data") if isinstance(payload, dict) else None
    rows = data.get("located_resources") if isinstance(data, dict) else None
    if not isinstance(rows, list) or len(rows) > 64:
        return {}
    countries = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        resource = str(row.get("resource", "")).upper()
        if resource.removeprefix("AS") != str(number):
            continue
        location = row.get("location")
        if isinstance(location, str) and re.fullmatch(r"[A-Z]{2}", location):
            countries.add(location)
    if len(countries) != 1:
        return {}
    result_time = data.get("result_time") if isinstance(data.get("result_time"), str) else ""
    return {"registered_country": countries.pop(), "result_time": result_time[:80]}


def validate_admin_target(target):
    for path in (target, target.parent):
        if path.is_symlink():
            raise SwitcherError("unsafe_admin_helper", "系统组件路径存在符号链接")
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise SwitcherError("unsafe_admin_helper", "系统组件必须由 root 管理且普通用户不可写")
    if not target.is_file():
        raise SwitcherError("unsafe_admin_helper", "系统组件不是普通文件")


class System:
    def __init__(self, paths, resources=None):
        self.paths = paths
        self.resources = Path(resources or Path(__file__).resolve().parent.parent)

    def run(self, argv, timeout=8, *, check=True, input=None):
        env = dict(os.environ, LC_ALL="en_US.UTF-8",
                   PATH="/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin")
        # Shell startup files must never affect an administrative or probe command.
        for key in ("BASH_ENV", "ENV", "CDPATH"):
            env.pop(key, None)
        try:
            result = subprocess.run(argv, input=input, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, errors="replace",
                                    timeout=timeout, env=env)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SwitcherError("command_unavailable", "系统操作不可用或超时") from exc
        if check and result.returncode:
            raise SwitcherError("command_failed", "系统操作失败；未将失败解释为成功")
        return result

    def text(self, argv, timeout=8):
        return self.run(argv, timeout).stdout.strip()

    def optional(self, argv, timeout=8):
        try:
            result = self.run(argv, timeout, check=False)
            return result.stdout.strip() if result.returncode == 0 else None
        except SwitcherError:
            return None

    def process_helper(self, action, *arguments):
        helper = self.resources / "watch-process-control"
        if not helper.is_file():
            raise SwitcherError("helper_missing", "缺少已打包的进程控制组件")
        try:
            value = json.loads(self.text([str(helper), action, *arguments], timeout=22))
        except ValueError as exc:
            raise SwitcherError("invalid_process_snapshot", "进程组件返回格式错误") from exc
        if value.get("status") != "ok":
            raise SwitcherError(value.get("code", "process_error"), value.get("message", "进程核对失败"))
        return value

    def processes(self):
        return self.process_helper("inventory")["processes"]

    def regional_status(self):
        try:
            value = self.process_helper("regional-status", *sorted(set(LOCALES.values())))["regional"]
            return value if isinstance(value, dict) else {"state": "unknown"}
        except (SwitcherError, KeyError, TypeError):
            return {"state": "unknown"}

    def proxy_processes(self):
        # macOS can deny proc_pidpath for root-owned proxy daemons while ps
        # still exposes their UID, executable and start time. This supplement
        # is for observation only; quitting apps always uses the native helper.
        processes = list(self.processes())
        snapshot = self.run(["/bin/ps", "-ww", "-axo", "pid=,ppid=,uid=,lstart=,comm="], check=False)
        if snapshot.returncode or not snapshot.stdout.strip():
            raise SwitcherError("proxy_inventory_unavailable", "无法核对系统代理进程；未判定为断线")
        seen = {p["pid"] for p in processes}
        prefixes = tuple(prefix for values in PROXY_PATHS.values() for prefix in values)
        for line in snapshot.stdout.splitlines():
            fields = line.split(None, 8)
            if len(fields) != 9:
                if any(prefix in line for prefix in prefixes):
                    raise SwitcherError("proxy_inventory_unavailable", "代理进程身份不完整；未判定为断线")
                continue
            try:
                pid, parent, uid = map(int, fields[:3])
            except ValueError:
                continue
            executable = fields[8]
            if uid != 0 or pid <= 1 or pid in seen or not executable.startswith(prefixes):
                continue
            stamp = " ".join(fields[3:8])
            if not re.fullmatch(r"[A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}", stamp):
                raise SwitcherError("proxy_inventory_unavailable", "代理启动身份不可确认；未判定为断线")
            processes.append(dict(pid=pid, parent=parent, uid=uid, executable=executable,
                                  start_stamp=stamp, source="root-proxy-ps"))
            seen.add(pid)
        return processes

    def claude_running(self):
        return bool(self.process_helper("desktop-status")["processes"])

    def session_desktop_matches(self, desktop):
        if not isinstance(desktop, dict): return False
        try:
            pid, seconds, micros = (int(desktop[key]) for key in ("pid", "start_seconds", "start_microseconds"))
        except (KeyError, TypeError, ValueError):
            return False
        processes = self.process_helper("desktop-status").get("processes", [])
        return any(isinstance(item, dict) and item.get("desktop_main") is True and item.get("pid") == pid and
                   item.get("start_seconds") == seconds and item.get("start_microseconds") == micros for item in processes)

    def launcher_matches(self, launcher):
        if not isinstance(launcher, dict) or not isinstance(launcher.get("pid"), int) or not isinstance(launcher.get("start"), str):
            return False
        try: return self._process_start_stamp(launcher["pid"]) == launcher["start"]
        except SwitcherError: return False

    def quit_claude(self):
        self.process_helper("close-desktop")
        if self.claude_running():
            raise SwitcherError("claude_still_running", "Claude 尚未完全退出，未切换数据")

    def launch_claude(self):
        # This is intentionally separate from the account/update operation
        # lock: a guard-triggered exit must never wait for this launch lock.
        with operation_lock(self.paths, "launch"):
            return self._launch_claude()

    def _launch_claude(self):
        """The sole Python controlled-launch path for Claude Desktop."""
        from .audit import require_ready
        from .session_guard import begin_launch_session, bind_launch_process, bind_pending_launcher, lock_session
        if self.claude_running():
            raise SwitcherError("claude_already_running", "Claude 已在运行，不能补建受控启动会话")
        audit_receipt = require_ready(self.paths, self, load_config(self.paths))
        session = begin_launch_session(self.paths, self, audit_receipt)
        session_file = None
        try:
            launcher = self._process_start_stamp(os.getpid())
            bind_pending_launcher(self.paths, session["session_id"], {"pid": os.getpid(), "start": launcher})
            self._write_pending_launcher(os.getpid(), launcher)
            self.run(["/usr/bin/open", "-a", "Claude"], timeout=15)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                processes = self.process_helper("desktop-status").get("processes", [])
                mains = [item for item in processes if isinstance(item, dict) and item.get("desktop_main") is True]
                if len(mains) == 1:
                    bind_launch_process(self.paths, session["session_id"], mains[0])
                    session_file = self._write_claude_session(mains[0])
                    self._clear_pending_launcher()
                    return {"status": "ok", "session_id": session["session_id"], "audit": audit_receipt}
                time.sleep(0.2)
            raise SwitcherError("desktop_identity_unavailable", "Claude 启动后未能确认唯一主进程身份")
        except Exception:
            lock_session(self.paths, "launch_failed", "Claude 受控启动未完成")
            self._clear_pending_launcher()
            if session_file and session_file.exists(): session_file.unlink()
            try:
                if self.claude_running(): self.quit_claude()
            except SwitcherError:
                pass
            raise

    def _write_claude_session(self, process):
        pid = process.get("pid")
        if not isinstance(pid, int) or pid <= 1:
            raise SwitcherError("desktop_identity_unavailable", "Claude 主进程 PID 无效")
        stamp = self._process_start_stamp(pid)
        directory = self.paths.watch / "state" / "sessions"
        reject_symlink(directory, self.paths.home)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix="session.", dir=directory)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write("desktop|claude|%d|%s|0|-|%d\n" % (pid, stamp, int(time.time())))
                stream.flush(); os.fsync(stream.fileno())
            target = Path(temporary + ".session")
            os.replace(temporary, target)
            return target
        finally:
            if os.path.exists(temporary): os.unlink(temporary)

    def _pending_path(self): return self.paths.watch / "state" / "desktop-pending"

    def _write_pending_launcher(self, pid, stamp):
        path = self._pending_path()
        reject_symlink(path, self.paths.home)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, temporary = tempfile.mkstemp(prefix=".desktop-pending.", dir=path.parent)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write("%d|%s|%d\n" % (pid, stamp, int(time.time())))
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary): os.unlink(temporary)

    def _clear_pending_launcher(self):
        path = self._pending_path()
        try:
            reject_symlink(path, self.paths.home)
            if path.exists(): path.unlink()
        except OSError:
            pass

    def _process_start_stamp(self, pid):
        stamp_result = self.run(["/bin/ps", "-p", str(pid), "-o", "lstart="], check=False)
        stamp = " ".join(stamp_result.stdout.split())
        if stamp_result.returncode or not re.fullmatch(r"[A-Za-z]{3} [A-Za-z]{3} \d{1,2} \d{2}:\d{2}:\d{2} \d{4}", stamp):
            raise SwitcherError("desktop_identity_unavailable", "进程启动时间未能确认")
        return stamp

    def guard_egress(self, config, attempts=2, timeout=3):
        """Fast, uncached HTTP exit sample over the system TUN route."""
        errors = []
        route_config = dict(config, proxy_mode="auto", proxy_url="")
        for attempt in range(1, max(1, min(2, int(attempts))) + 1):
            observed = time.time()
            try:
                body, status = self.fetch("https://www.cloudflare.com/cdn-cgi/trace", route_config, timeout=timeout)
                if status != 200:
                    raise SwitcherError("http_" + str(status), "出口检测服务返回 HTTP " + str(status))
                fields = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
                address = ipaddress.ip_address(fields.get("ip", "")); country = str(fields.get("loc", "")).upper()
                if status == 200 and address.is_global and not address.is_multicast and re.fullmatch(r"[A-Z]{2}", country):
                    return {"state": "ok", "ip": str(address), "country": country, "observed_at": observed,
                            "source": "Cloudflare trace（系统 TUN 路由，未缓存出口）"}
                raise SwitcherError("response_format", "出口检测未返回有效公网 IP 与国家")
            except (SwitcherError, ValueError) as exc:
                errors.append(dict(attempt=attempt, code=exc.code if isinstance(exc, SwitcherError) else "response_format",
                                   message=str(exc) if isinstance(exc, SwitcherError) else "出口检测地址格式无效",
                                   observed_at=observed))
        return {"state": "unknown", "error": "; ".join(item["message"] for item in errors), "attempts": errors,
                "observed_at": time.time(),
                "source": "Cloudflare trace（系统 TUN 路由，未缓存出口）"}

    def claude_version(self):
        try:
            data = plistlib.loads(Path("/Applications/Claude.app/Contents/Info.plist").read_bytes())
            if data.get("CFBundleIdentifier") != "com.anthropic.claudefordesktop":
                raise ValueError()
            return str(data.get("CFBundleShortVersionString", ""))
        except (OSError, ValueError):
            return ""

    def network_environment(self):
        """Resolve the active service by its dynamic-store UUID, never by a default name."""
        names = self.optional(["/usr/sbin/networksetup", "-listallnetworkservices"]) or ""
        services = [x for x in names.splitlines()[1:] if x and not x.startswith("*")]
        for family in ("IPv4", "IPv6"):
            result = self.run(["/usr/sbin/scutil"], check=False,
                              input="show State:/Network/Global/" + family + "\nquit\n")
            match = re.search(r"PrimaryService\s*:\s*([A-Fa-f0-9-]{36})", result.stdout)
            if result.returncode or not match: continue
            service = self.run(["/usr/sbin/scutil"], check=False,
                               input="show Setup:/Network/Service/" + match[1] + "\nquit\n")
            name = re.search(r"UserDefinedName\s*:\s*(.+)", service.stdout)
            interface = re.search(r"PrimaryInterface\s*:\s*(\S+)", result.stdout)
            if not service.returncode and name and name[1].strip() in services:
                return {"service": name[1].strip(), "interface": interface[1] if interface else "",
                        "services": services, "source": "scutil PrimaryService → networksetup"}
        return {"service": None, "interface": "", "services": services,
                "source": "活动网络服务未能确认；未使用 Wi-Fi 默认值"}

    def baseline_data(self):
        # The shell owns route/DNS signature serialization. This command only reads;
        # the caller validates proxy evidence and commits the confirmed baseline.
        source = self.resources / "claude-watch.sh"
        value = json.loads(self.text(["/bin/bash", str(source), "baseline-data"], timeout=20))
        if value.get("status") != "ok" or not isinstance(value.get("baseline"), str):
            raise SwitcherError("baseline_incomplete", "环境基线读取不完整")
        return value["baseline"]

    def local(self, config, guard_only=False):
        processes = self.proxy_processes()
        detected = []
        for mode, prefixes in PROXY_PATHS.items():
            matches = [p for p in processes if any(p["executable"].startswith(x) for x in prefixes)]
            if mode in ("tag", "clash-verge"):
                matches = [p for p in matches if "mihomo" in p["executable"].lower()]
            if matches:
                detected.append((mode, matches))
        nc = self.optional(["/usr/sbin/scutil", "--nc", "list"])
        shadow_connected = bool(nc and re.search(r"\(Connected\).*com\.liguangming\.Shadowrocket", nc))
        if shadow_connected and not any(m == "shadowrocket" for m, _ in detected):
            detected.append(("shadowrocket", []))
        requested = config["proxy_mode"]
        candidates = detected if requested == "auto" else [x for x in detected if x[0] == requested]
        selected = candidates[0][0] if len(candidates) == 1 else ""
        proxy = "ok" if selected else ("unknown" if len(candidates) > 1 else "fail")
        proxy_detail = "已识别 " + selected if selected else "代理未运行、身份不完整或存在多个候选"
        interfaces = self.optional(["/sbin/ifconfig"])
        route = self.optional(["/sbin/route", "-n", "get", "198.18.0.1"])
        interface_match = re.search(r"interface:\s+(\S+)", route or "")
        interface = interface_match.group(1) if interface_match else ""
        fake_interfaces = []
        if interfaces is not None:
            current = ""
            for line in interfaces.splitlines():
                if line and not line[0].isspace():
                    current = line.split(":", 1)[0]
                if re.search(r"\binet 198\.1[89]\.", line):
                    fake_interfaces.append(current)
        tun = "ok" if interface in fake_interfaces and selected else ("unknown" if interfaces is None or route is None else "fail")
        if guard_only:
            return {"proxy": proxy, "mode": selected, "tun": tun, "interface": interface}
        tag = read_json(self.paths.watch / "state/proxy-snapshot.json", {})
        observation_unavailable = []
        # TAG evidence is only used when fresh; no other client's fake IP is promoted to TAG proof.
        if selected == "tag":
            captured = tag.get("observed_epoch", 0)
            try: fresh = 0 <= time.time() - float(captured) <= 30
            except (ValueError, TypeError): fresh = False
            producer = tag.get("producer", {})
            try: backend_identity = (self.paths.watch / "state/heartbeat").read_text().split("|")[:2]
            except OSError: backend_identity = []
            bound = isinstance(producer, dict) and backend_identity == [
                str(producer.get("pid", "")), producer.get("started", "")]
            if not fresh or not bound or not self.backend_healthy():
                tag = {}
                proxy = "unknown"
                proxy_detail = "TAG 样本过期、发布者身份不匹配或后台健康未确认"
                observation_unavailable.append("tag_snapshot")
            else:
                entry, api = tag.get("entry", {}), tag.get("api", {})
                if (not isinstance(entry, dict) or not isinstance(api, dict) or
                        entry.get("state") != "verified" or api.get("state") != "available"
                        or api.get("covers_7890") is not True):
                    proxy = "unknown"
                    proxy_detail = "TAG 7890 监听者、控制接口或该入口的覆盖范围未确认"
                    observation_unavailable.append("tag_snapshot")
                elif tag.get("selection_changed"):
                    proxy = "fail"
                    proxy_detail = "TAG 分组或节点偏离已确认的预期"
        else:
            tag = {}
        service_info = self.optional(["/usr/sbin/networksetup", "-getinfo", config["network_service"]])
        ipv6 = "unknown" if service_info is None else (
            "ok" if re.search(r"^IPv6:\s*Off", service_info, re.M | re.I) else "fail")
        locale = self.optional(["/usr/bin/defaults", "read", "-g", "AppleLocale"])
        app_language = self.optional(["/usr/bin/defaults", "read", "com.anthropic.claudefordesktop", "AppleLanguages"])
        system_language = self.optional(["/usr/bin/defaults", "read", "-g", "AppleLanguages"])
        date_format = self.regional_status()
        timezone = self.optional(["/usr/bin/readlink", "/etc/localtime"])
        if timezone and "zoneinfo/" in timezone:
            timezone = timezone.split("zoneinfo/", 1)[1]
        guard = self.guard_status(config)
        guard_state = "ok" if guard else "disabled" if not config.get("guard_enabled") else "unknown"
        guard_detail = ("保护策略已禁用" if guard_state == "disabled" else
                        "保护心跳或后台身份未能确认" if guard_state == "unknown" else "保护心跳已确认")
        # Local observations must remain offline. DNS queries belong exclusively
        # to online(), where the saved online permission is enforced by audit().
        resolutions = {}
        evidence = {"proxy": proxy, "proxy_detail": proxy_detail, "mode": selected, "candidates": [m for m, _ in candidates],
                    "tun": tun, "interface": interface, "ipv6": ipv6, "timezone": timezone,
                    "locale": locale, "language": app_language or system_language,
                    "app_language": app_language, "system_language": system_language, "date_format": date_format,
                    "guard": guard, "guard_state": guard_state, "guard_detail": guard_detail,
                    "dns": resolutions, "tag": tag,
                    "processes": [p for _, items in candidates for p in items]}
        identities = sorted([{key: item.get(key) for key in ("pid", "uid", "executable", "start_stamp", "start_seconds", "start_microseconds")}
                             for item in evidence["processes"] if isinstance(item, dict)],
                            key=lambda item: (item.get("pid", -1), str(item.get("start_stamp", ""))))
        context = {k: evidence[k] for k in ("mode", "tun", "interface")}
        context["processes"] = identities
        if selected == "tag":
            api = tag.get("api", {})
            if not isinstance(api, dict): api = {}
            context["selection"] = {key: api.get(key) for key in ("mode", "selected_node", "global_node")}
            context["group"] = tag.get("expected_group")
        evidence["context"] = digest(context)
        evidence["network_identity"] = context
        evidence["context_id"] = evidence["context"]
        if proxy == "unknown" and not observation_unavailable: observation_unavailable.append("proxy_sampling")
        if tun == "unknown": observation_unavailable.append("tun_sampling")
        evidence["observation_unavailable"] = observation_unavailable
        return evidence

    def guard_status(self, config):
        heartbeat = read_json(self.paths.base / "guard-heartbeat.json", {})
        return bool(config["guard_enabled"] and 0 <= time.time() - heartbeat.get("time", 0) <= 35
                    and heartbeat.get("status") == "ok" and guard_heartbeat_policy_matches(heartbeat, config)
                    and self.backend_healthy())

    def backend_healthy(self):
        try:
            fields = (self.paths.watch / "state/heartbeat").read_text().strip().split("|")
            if len(fields) != 5 or not fields[0].isdigit() or fields[3] != "ok":
                return False
            if not 0 <= time.time() - float(fields[2]) <= 30: return False
            actual = self.optional(["/bin/ps", "-p", fields[0], "-o", "lstart="])
            return actual is not None and " ".join(actual.split()) == " ".join(fields[1].split())
        except (OSError, ValueError):
            return False

    def service_job(self, name):
        definitions = {
            "updater": ("gui/" + str(os.getuid()) + "/io.local.claudewatch.update",
                        self.paths.home / "Library/LaunchAgents/io.local.claudewatch.update.plist"),
            "watchdog": ("system/io.local.claudewatch.timezone", Path("/Library/LaunchDaemons/io.local.claudewatch.timezone.plist")),
            "original": ("system/local.claude-bodyguard", Path("/Library/LaunchDaemons/local.claude-bodyguard.plist")),
        }
        if name not in definitions: raise SwitcherError("invalid_service", "未识别的后台任务")
        label, definition = definitions[name]
        result = self.run(["/bin/launchctl", "print", label], check=False)
        absent = "Could not find service" in result.stderr
        registered = True if result.returncode == 0 else False if absent else None
        state = re.search(r"^\s*state = ([^\n]+)", result.stdout, re.M)
        exit_code = re.search(r"^\s*last exit code = (-?\d+)", result.stdout, re.M)
        definition_hash = None
        trusted = False
        interval = None
        try:
            if not definition.is_symlink() and definition.is_file():
                data = definition.read_bytes()
                value = plistlib.loads(data)
                if not isinstance(value, dict): raise ValueError("invalid service definition")
                definition_hash = hashlib.sha256(data).hexdigest()
                trusted = value.get("Label") == label.split("/")[-1]
                interval = value.get("StartInterval")
                if type(interval) is not int or interval <= 0: interval = None
                if name == "original":
                    trusted = (trusted and definition.stat().st_uid == 0 and
                        isinstance(value.get("ProgramArguments"), list) and
                        "/Library/Application Support/claude-switcher/claude-bodyguard.sh" in value["ProgramArguments"])
                if name == "updater":
                    args = value.get("ProgramArguments")
                    trusted = (trusted and isinstance(args, list) and len(args) == 5 and
                        args[1:] == [str(self.paths.watch / "runtime/switcher.py"), "update", "--auto", "--apply"] and interval == 43200)
        except (OSError, ValueError, plistlib.InvalidFileException): pass
        return {"registered": registered, "state": state[1].strip() if state else "unknown",
                "last_exit": int(exit_code[1]) if exit_code else None,
                "definition": definition_hash, "trusted": trusted, "label": label, "interval": interval}

    def watchdog_state(self):
        target = Path("/Library/Application Support/ClaudeWatch/timezone.target")
        stamp = target.parent / "timezone.last-success"
        try:
            value = target.read_text().strip() if target.stat().st_size < 1024 and target.stat().st_uid == 0 else None
        except OSError: value = None
        state = self.run(["/bin/launchctl", "print", "system/io.local.claudewatch.timezone"], check=False)
        try: last_success = float(stamp.read_text().strip())
        except (OSError, ValueError): last_success = None
        return {"target": value, "registered": state.returncode == 0, "last_success": last_success}

    def admin(self, verb, *arguments):
        import shlex
        allowed = {"timezone", "ipv6", "flush-dns", "watchdog", "uninstall", "legacy-stop", "status"}
        if verb not in allowed or any("\n" in x or "\x00" in x for x in arguments):
            raise SwitcherError("invalid_admin_action", "无效管理员操作")
        source = self.resources / "watch-admin.sh"
        target = ADMIN_TARGET
        if target.is_symlink():
            raise SwitcherError("unsafe_admin_helper", "系统组件路径存在符号链接")
        existing = target.exists()
        if existing: validate_admin_target(target)
        if not source.is_file() and not (existing and verb == "uninstall"):
            raise SwitcherError("admin_helper_missing", "缺少系统辅助组件")
        expected = hashlib.sha256(source.read_bytes()).hexdigest() if source.is_file() else ""
        if existing and verb not in ("status", "uninstall") and hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise SwitcherError("admin_update_required", "系统组件版本不同；请先明确选择“升级系统辅助组件”")
        parent = str(target.parent)
        commands = ["cd /private/tmp"]
        if not existing or verb == "status":
            incoming = shlex.quote(str(target) + ".incoming")
            commands += [
                "test ! -L " + shlex.quote(parent),
                "/usr/bin/install -d -o root -g wheel -m 755 " + shlex.quote(parent),
                "test ! -L " + shlex.quote(str(target)) + " && test ! -L " + incoming,
                "/usr/bin/install -o root -g wheel -m 755 " + shlex.quote(str(source)) + " " + incoming,
                "test \"$(/usr/bin/shasum -a 256 " + incoming + " | /usr/bin/awk '{print $1}')\" = " + expected,
                "/bin/mv -f " + incoming + " " + shlex.quote(str(target)),
            ]
        commands += [
            "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/bash --noprofile --norc "
            + " ".join(shlex.quote(x) for x in (str(target), verb, *arguments)),
        ]
        command = " && ".join(commands)
        prompt = "Claude Watch：安装或升级固定系统组件并执行已确认操作" if not existing or verb == "status" else "Claude Watch：应用已预览的系统配置变更"
        program = "with timeout of 180 seconds\n do shell script " + json.dumps(command, ensure_ascii=False) + (
            " with prompt " + json.dumps(prompt, ensure_ascii=False) + " with administrator privileges\nend timeout")
        self.run(["/usr/bin/osascript", "-e", program], timeout=185)

    def fetch(self, url, config, timeout=8):
        args = ["/usr/bin/curl", "--disable", "--silent", "--show-error", "--max-time", str(timeout),
                "--proto", "=https", "--max-filesize", "1048576", "--write-out", "\n%{http_code}"]
        proxy = config.get("proxy_url") or ("http://127.0.0.1:7890" if config["proxy_mode"] == "tag" else "")
        if proxy:
            args += ["--proxy", proxy, "--noproxy", ""]
        else:
            # TUN probes must not silently use a different inherited shell proxy.
            args += ["--proxy", ""]
        args += [url]
        try:
            result = self.run(args, timeout + 2, check=False)
        except SwitcherError as exc:
            if isinstance(exc.__cause__, subprocess.TimeoutExpired):
                raise SwitcherError("timeout", "请求超时") from exc
            raise
        if result.returncode:
            code, message = _CURL_FAILURES.get(result.returncode, ("network_failed", "诊断请求未完成"))
            raise SwitcherError(code, message)
        body, _, status = result.stdout.rpartition("\n")
        if not status.isdigit() or not 100 <= int(status) <= 599:
            raise SwitcherError("response_format", "HTTP 响应状态格式无效")
        return body, int(status)

    @staticmethod
    def _final_headers(text, final_status):
        """Parse only the final origin response, never proxy CONNECT headers."""
        blocks = [block for block in text.replace("\r\n", "\n").split("\n\n") if block.strip()]
        for block in reversed(blocks):
            lines = block.splitlines()
            if not lines or not lines[0].startswith("HTTP/"):
                continue
            fields = lines[0].split()
            if (len(fields) < 2 or not fields[1].isdigit() or int(fields[1]) < 200 or
                    int(fields[1]) != final_status or "Connection established" in lines[0]):
                continue
            result = {}
            for line in lines[1:]:
                key, sep, value = line.partition(":")
                if sep and key.strip().lower() == "cf-mitigated": result["cf-mitigated"] = value.strip()
            return result
        return {}

    def _service_fetch(self, url, config, timeout=8):
        """Return one uncredentialed TLS-verified response and its final headers."""
        # Test fakes commonly override fetch(url, config); preserve that seam and
        # never bypass it with a real curl process.
        if getattr(self.fetch, "__func__", None) is not System.fetch:
            body, status = self.fetch(url, config)
            return body, status, {}
        fd, name = tempfile.mkstemp(prefix=".claude-watch-headers-", dir="/private/tmp")
        try:
            os.fchmod(fd, 0o600); os.close(fd)
            args = ["/usr/bin/curl", "--disable", "--silent", "--show-error", "--max-time", str(timeout),
                    "--proto", "=https", "--max-filesize", "1048576", "--dump-header", name,
                    "--output", "/dev/null", "--write-out", "%{http_code}"]
            proxy = config.get("proxy_url") or ("http://127.0.0.1:7890" if config["proxy_mode"] == "tag" else "")
            args += ["--proxy", proxy, "--noproxy", ""] if proxy else ["--proxy", ""]
            try:
                result = self.run(args + [url], timeout + 2, check=False)
            except SwitcherError as exc:
                if isinstance(exc.__cause__, subprocess.TimeoutExpired):
                    raise SwitcherError("timeout", "请求超时") from exc
                raise
            if result.returncode:
                code, message = _CURL_FAILURES.get(result.returncode, ("network_failed", "诊断请求未完成"))
                raise SwitcherError(code, message)
            status = result.stdout.strip()
            if not status.isdigit() or not 100 <= int(status) <= 599:
                raise SwitcherError("response_format", "HTTP 响应状态格式无效")
            try: headers = self._final_headers(Path(name).read_text(errors="replace")[:65536], int(status))
            except OSError: headers = {}
            return "", int(status), headers
        finally:
            try: os.close(fd)
            except OSError: pass
            try: os.unlink(name)
            except OSError: pass

    def service_response(self, name, url, config):
        queried_at = time.time()
        source = url
        try:
            _, status, headers = self._service_fetch(url, config)
        except SwitcherError as exc:
            return {"status": "unknown", "transport_reached": False, "access": "network_error",
                    "http_status": None, "source": source, "queried_at": queried_at,
                    "error_code": exc.code, "error": str(exc)}
        is_claude = name == "claude" and url == "https://claude.ai/"
        is_api = name == "api" and url == "https://api.anthropic.com/v1/models"
        challenge = is_claude and status == 403 and headers.get("cf-mitigated", "").lower() == "challenge"
        if is_api and status == 401:
            access, state = "authentication_required", "ok"
        elif challenge:
            access, state = "challenge", "ok"
        elif status == 403:
            access, state = "access_restricted", "warn"
        elif status == 429:
            access, state = "rate_limited", "warn"
        elif status >= 500:
            access, state = "server_error", "warn"
        else:
            access, state = "http_response", "ok" if 200 <= status < 400 else "warn"
        value = {"status": state, "transport_reached": True, "access": access,
                 "http_status": status, "source": source, "queried_at": queried_at}
        if challenge: value["challenge"] = {"provider": "cloudflare", "mitigated": "challenge"}
        return value

    def metadata_query(self, key, loader, *, ttl):
        """Use the shared bounded cache without promoting stale data to current."""
        from netcoffee_client import cached_query
        return cached_query(key, loader, ttl=ttl,
                            cache_dir=self.paths.home / "Library/Application Support/ClaudeWatch/observations")

    def ipinfo_lookup(self, address, config):
        address = str(ipaddress.ip_address(address))
        def loader():
            started = time.time()
            value = {"kind": "ipinfo", "query": address, "queriedAt": started, "finishedAt": started,
                     "status": "error", "httpStatus": None, "data": None, "error": None}
            try:
                body, status = self.fetch("https://ipinfo.io/json", config)
                value["httpStatus"] = status
                if status != 200: raise SwitcherError("http_" + str(status), "IPinfo 返回 HTTP " + str(status))
                data = json.loads(body)
                country = str(data.get("country", "")).upper() if isinstance(data, dict) else ""
                returned = str(ipaddress.ip_address(data.get("ip", ""))) if isinstance(data, dict) else ""
                if not isinstance(data, dict) or not ipaddress.ip_address(returned).is_global or not re.fullmatch(r"[A-Z]{2}", country):
                    raise ValueError("response fields")
                data["country"] = country; value.update(status="complete", data=data)
            except Exception as exc:
                value.update(status="timeout" if "tim" in str(exc).lower() else "error", error=str(exc)[:240])
            value["finishedAt"] = time.time()
            return value
        return self.metadata_query("ipinfo:" + address, loader, ttl=300)

    def ripe_asn_lookup(self, number, config):
        number = int(number)
        def loader():
            started = time.time()
            value = {"kind": "ripe-asn", "query": str(number), "queriedAt": started, "finishedAt": started,
                     "status": "error", "httpStatus": None, "data": None, "error": None}
            try:
                body, status = self.fetch("https://stat.ripe.net/data/rir-stats-country/data.json?resource=AS" + str(number), config)
                value["httpStatus"] = status
                if status != 200: raise SwitcherError("http_" + str(status), "RIPEstat 返回 HTTP " + str(status))
                payload = json.loads(body)
                data = payload.get("data") if isinstance(payload, dict) else None
                if not isinstance(data, dict) or not parse_ripe_asn_country(json.dumps({"data": data}), number):
                    raise ValueError("ASN registration unavailable")
                value.update(status="complete", data=data)
            except Exception as exc:
                value.update(status="timeout" if "tim" in str(exc).lower() else "error", error=str(exc)[:240])
            value["finishedAt"] = time.time()
            return value
        return self.metadata_query("ripe-asn:" + str(number), loader, ttl=86400)

    def egress_reference(self, config):
        """Cross-check Cloudflare's current IP with the shared Net.Coffee lookup."""
        values = {"errors": [], "query_errors": {}, "source_times": {}}
        queried_at = time.time()
        try:
            body, status = self.fetch("https://www.cloudflare.com/cdn-cgi/trace", config)
            if status != 200:
                values["errors"].append("trace")
                values["query_errors"]["trace"] = _query_error("http_" + str(status), "Cloudflare trace 返回 HTTP " + str(status), "Cloudflare trace", http_status=status, queried_at=queried_at)
                return values
            trace = dict(line.split("=", 1) for line in body.splitlines() if "=" in line)
            address = ipaddress.ip_address(trace.get("ip", ""))
            if not address.is_global or address.is_multicast or not re.fullmatch(r"[A-Za-z]{2}", str(trace.get("loc", ""))):
                raise ValueError("fields")
            trace["ip"], trace["loc"] = str(address), trace["loc"].upper()
            values["trace"] = trace; values["source_times"]["trace"] = queried_at
        except SwitcherError as exc:
            values["errors"].append("trace")
            values["query_errors"]["trace"] = _query_error(exc.code, str(exc), "Cloudflare trace", queried_at=queried_at)
            return values
        except ValueError:
            values["errors"].append("trace")
            values["query_errors"]["trace"] = _query_error("response_fields_invalid", "Cloudflare trace 缺少有效 IP 或国家", "Cloudflare trace", queried_at=queried_at)
            return values
        try:
            from netcoffee_client import request as coffee_request
            lookup = coffee_request("lookup", values["trace"]["ip"], cache_dir=self.paths.watch / "observations")
            values["netcoffee_lookup"] = lookup
            source_time = lookup.get("finishedAt", lookup.get("queriedAt", time.time())) if isinstance(lookup, dict) else time.time()
            if not isinstance(lookup, dict) or lookup.get("status") != "complete" or lookup.get("httpStatus") != 200 or not isinstance(lookup.get("data"), dict):
                raise ValueError("lookup unavailable")
            data = lookup["data"]
            query_ip = str(ipaddress.ip_address(lookup.get("query", "")))
            data_ip = str(ipaddress.ip_address(data.get("ip", "")))
            if query_ip != values["trace"]["ip"] or data_ip != values["trace"]["ip"]:
                values["query_errors"]["egress_consistency"] = _query_error("ip_mismatch", "Cloudflare 与 Net.Coffee 出口 IP 不一致", "Cloudflare trace / Net.Coffee", queried_at=source_time)
                values["errors"].append("egress_consistency")
                return values
            country = str(data.get("countryCode") or data.get("country_code") or "").upper()
            if not re.fullmatch(r"[A-Z]{2}", country): raise ValueError("country")
            if country != values["trace"]["loc"]:
                values["query_errors"]["egress_consistency"] = _query_error("country_mismatch", "Cloudflare 与 Net.Coffee 出口国家不一致", "Cloudflare trace / Net.Coffee", queried_at=source_time)
                values["errors"].append("egress_consistency")
            timezone = data.get("timezone") if isinstance(data.get("timezone"), str) else ""
            if not timezone:
                sources = data.get("geo_sources")
                if isinstance(sources, list):
                    zones = {row.get("timezone") for row in sources if isinstance(row, dict) and isinstance(row.get("timezone"), str)}
                    timezone = zones.pop() if len(zones) == 1 else ""
            values["geo"] = {"ip": values["trace"]["ip"], "country": country, "timezone": timezone,
                             "country_source": "Net.Coffee lookup", "timezone_source": "Net.Coffee lookup"}
            values["source_times"]["geo"] = source_time
        except Exception:
            values["errors"].append("netcoffee")
            values["query_errors"]["netcoffee"] = _cached_receipt_error(values.get("netcoffee_lookup"), "Net.Coffee lookup")
        # IPinfo is a fallback only when the primary lookup is absent or lacks
        # country/timezone.  A confirmed primary-source conflict is not hidden.
        geo = values.get("geo", {})
        unique_timezone = False
        if geo.get("country"):
            try:
                from .region import country_timezones
                unique_timezone = len(country_timezones().get(geo["country"], set())) == 1
            except (ImportError, KeyError, TypeError):
                unique_timezone = False
        if "egress_consistency" not in values["query_errors"] and (not geo.get("country") or (not geo.get("timezone") and not unique_timezone)):
            fallback_at = time.time()
            fallback_receipt = {}
            try:
                fallback_receipt = self.ipinfo_lookup(values["trace"]["ip"], config)
                fallback = fallback_receipt.get("data") if fallback_receipt.get("status") == "complete" else {}
                ip = ipaddress.ip_address(fallback.get("ip", ""))
                country = str(fallback.get("country", "")).upper()
                if str(ip) != values["trace"]["ip"] or not re.fullmatch(r"[A-Z]{2}", country) or country != values["trace"]["loc"]:
                    values["errors"].append("egress_consistency")
                    values["query_errors"]["egress_consistency"] = _query_error("fallback_mismatch", "Cloudflare 与 IPinfo 备用出口资料不一致", "Cloudflare trace / IPinfo", queried_at=fallback_receipt.get("finishedAt", fallback_at))
                    return values
                values["geo"] = {"ip": str(ip), "country": country, "timezone": fallback.get("timezone", ""),
                                 "country_source": "IPinfo fallback", "timezone_source": "IPinfo fallback"}
                values["source_times"]["geo"] = fallback_receipt.get("finishedAt", fallback_at)
            except Exception:
                values["errors"].append("geo")
                values["query_errors"]["geo"] = _cached_receipt_error(fallback_receipt, "IPinfo", queried_at=fallback_at)
        return values

    def online(self, config):
        from .stun import probe
        values = self.egress_reference(config)
        errors = list(values.get("errors", []))
        query_errors = values.setdefault("query_errors", {})
        source_times = values.setdefault("source_times", {})
        service_responses = {}
        for name, url, source in (("claude", "https://claude.ai/", "Claude 网页"),
                                  ("api", "https://api.anthropic.com/v1/models", "Anthropic API")):
            response = self.service_response(name, url, config)
            service_responses[name] = response
            values[name] = response.get("http_status") or 0
            source_times[name] = response["queried_at"]
            if response["status"] == "unknown":
                errors.append(name)
                query_errors[name] = _query_error(response.get("error_code", "network_failed"), response.get("error", "诊断请求未完成"), source, queried_at=response["queried_at"])
        lookup = values.get("netcoffee_lookup", {})
        lookup_data = lookup.get("data", {}) if isinstance(lookup, dict) else {}
        trace_ip = values.get("trace", {}).get("ip") if isinstance(values.get("trace"), dict) else ""
        try:
            lookup_bound = (isinstance(lookup, dict) and lookup.get("status") == "complete" and
                            lookup.get("httpStatus") == 200 and isinstance(lookup_data, dict) and
                            str(ipaddress.ip_address(lookup.get("query", ""))) == trace_ip and
                            str(ipaddress.ip_address(lookup_data.get("ip", ""))) == trace_ip)
        except ValueError:
            lookup_bound = False
        number = lookup_data.get("asn") if lookup_bound else None
        try: number = int(number)
        except (TypeError, ValueError): number = None
        if isinstance(number, int) and 0 < number <= 4_294_967_295:
            organization = lookup_data.get("asOrganization") or lookup_data.get("asn_org") or ""
            asn = {"number": number, "organization": str(organization)[:512],
                   "queried_at": lookup.get("finishedAt", time.time()), "source": "Net.Coffee lookup"}
            queried_at = time.time()
            try:
                ripe = self.ripe_asn_lookup(number, config)
                if ripe.get("status") == "complete":
                    asn.update(parse_ripe_asn_country(json.dumps({"data": ripe.get("data")}), number))
                    source_times["asn"] = ripe.get("finishedAt", queried_at)
                    asn["registered_queried_at"] = ripe.get("finishedAt", queried_at)
                else:
                    errors.append("asn")
                    query_errors["asn"] = _cached_receipt_error(ripe, "RIPEstat ASN", queried_at=queried_at)
            except SwitcherError as exc:
                errors.append("asn")
                query_errors["asn"] = _query_error(exc.code, str(exc), "RIPEstat ASN", queried_at=queried_at)
            values["asn"] = asn
        elif "netcoffee" in query_errors:
            errors.append("asn")
            query_errors["asn"] = _query_error("asn_upstream_lookup_unavailable", "因 Net.Coffee 查询失败未能读取 ASN",
                                                 "Net.Coffee lookup", queried_at=time.time())
        values["stun"] = probe()
        values["service_responses"] = service_responses
        values["errors"] = errors
        return values
