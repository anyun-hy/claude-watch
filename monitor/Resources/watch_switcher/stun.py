"""Bounded RFC 5389 IPv4 UDP observations; never a browser-wide guarantee."""
import ipaddress
import copy
import os
import queue
import socket
import struct
import threading
import time

SERVERS = (("stun.miwifi.com", 3478), ("stun.chat.bilibili.com", 3478),
           ("stun.l.google.com", 19302), ("stun.cloudflare.com", 3478))
COOKIE = b"\x21\x12\xa4\x42"
ATTEMPTS = 2
ATTEMPT_TIMEOUT = 3.0
RETRY_DELAY = 0.2


class ProbeError(Exception):
    def __init__(self, stage, code, error, errno=None):
        super().__init__(error)
        self.stage, self.code, self.error, self.errno = stage, code, error, errno


def decode(data, transaction):
    if len(data) < 20 or data[:2] != b"\x01\x01" or data[4:8] != COOKIE or data[8:20] != transaction:
        raise ValueError("unrelated_response")
    size = struct.unpack("!H", data[2:4])[0]
    if size % 4 or len(data) != 20 + size:
        raise ValueError("invalid_length")
    offset = 20
    while offset + 4 <= len(data):
        kind, length = struct.unpack("!HH", data[offset:offset + 4])
        end = offset + 4 + length
        if end > len(data):
            raise ValueError("truncated_attribute")
        value = data[offset + 4:end]
        if kind in (0x0020, 0x0001) and len(value) >= 8:
            count = 4 if value[1] == 1 else 16 if value[1] == 2 else 0
            if not count or length != count + 4:
                raise ValueError("invalid_address")
            raw = value[4:]
            if kind == 0x0020:
                raw = bytes(a ^ b for a, b in zip(raw, COOKIE + transaction))
            address = ipaddress.ip_address(raw)
            if not address.is_global:
                raise ValueError("nonpublic_address")
            return str(address)
        offset = end + (-length % 4)
    raise ValueError("address_missing")


def request(host, port, *, deadline=None, clock=time.monotonic):
    """One strict IPv4 UDP STUN binding request, usable independently."""
    transaction = os.urandom(12)
    try:
        destination = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    except socket.gaierror as exc:
        raise ProbeError("resolve", "dns_resolution_failed", "IPv4 DNS 解析失败：" + str(exc)[:160], exc.errno) from exc
    except OSError as exc:
        raise ProbeError("resolve", "resolve_failed", "地址解析失败：" + str(exc)[:160], exc.errno) from exc
    timeout = ATTEMPT_TIMEOUT
    if deadline is not None:
        timeout = min(timeout, deadline - clock())
        if timeout <= 0:
            raise ProbeError("budget", "budget_exhausted", "DNS 解析后整轮预算已耗尽，未发送 UDP 数据包")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(struct.pack("!HH", 1, 0) + COOKIE + transaction, destination)
        except OSError as exc:
            raise ProbeError("send", "send_failed", "UDP STUN 请求发送失败：" + str(exc)[:160], exc.errno) from exc
        try:
            data, sender = sock.recvfrom(4096)
        except socket.timeout as exc:
            raise ProbeError("receive", "timeout", "等待 UDP STUN 回包超时（%.2f 秒）" % timeout) from exc
        except OSError as exc:
            raise ProbeError("receive", "receive_failed", "UDP STUN 回包接收失败：" + str(exc)[:160], exc.errno) from exc
    if sender != destination:
        raise ProbeError("validation", "unexpected_sender", "STUN 回包来源与目标不一致")
    try:
        return decode(data, transaction)
    except ValueError as exc:
        raise ProbeError("validation", str(exc)[:80] or "invalid_response", "STUN 回包未通过严格校验") from exc


def _failure(exc):
    if isinstance(exc, ProbeError):
        return ("timeout" if exc.code == "timeout" else "budget_exhausted" if exc.code == "budget_exhausted" else
                "unexpected_sender" if exc.code == "unexpected_sender" else "invalid_response" if exc.stage == "validation" else
                "network_error", exc.stage, exc.code, exc.error, exc.errno)
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return "timeout", "request", "timeout", "STUN 请求超时", None
    if isinstance(exc, OSError):
        return "network_error", "request", "network_error", "UDP 网络请求失败", exc.errno
    code = str(exc) or "invalid_response"
    if code == "unexpected_sender":
        return "unexpected_sender", "validation", code, "STUN 回包来源与目标不一致", None
    return "invalid_response", "validation", code[:80], "STUN 回包未通过严格校验", None


def _attempt(host, port, requester, *, wallclock):
    started = wallclock()
    try:
        address = requester(host, port)
    except Exception as exc:
        status, stage, code, error, errno = _failure(exc)
        value = {"started_at": started, "finished_at": wallclock(), "status": status,
                 "error_code": code, "error": error, "stage": stage}
        if errno is not None: value["errno"] = errno
        return None, value
    return address, {"started_at": started, "finished_at": wallclock(), "status": "ok",
                     "error_code": "", "error": "", "stage": "request"}


def probe(servers=SERVERS, requester=request, budget=8, *, clock=time.monotonic, wallclock=time.time, sleeper=time.sleep):
    """Probe all servers concurrently with bounded retries and one hard deadline.

    A blocking requester cannot be killed safely. Its daemon worker is ignored
    after deadline and, because it checks before every retry, cannot send again.
    """
    started = wallclock()
    deadline = clock() + max(0.0, float(budget))
    results = queue.Queue()
    progress, progress_lock = {}, threading.Lock()

    def worker(host, port):
        attempts = []
        for index in range(ATTEMPTS):
            if clock() >= deadline:
                break
            active_requester = (lambda h, p: request(h, p, deadline=deadline, clock=clock)) if requester is request else requester
            address, attempt = _attempt(host, port, active_requester, wallclock=wallclock)
            attempt["attempt"] = index + 1
            attempts.append(attempt)
            with progress_lock:
                progress[(host, port)] = copy.deepcopy(attempts)
            if address is not None:
                if clock() < deadline:
                    results.put({"server": host, "port": port, "status": "ok", "address": address,
                                 "started_at": attempts[0]["started_at"], "finished_at": attempt["finished_at"], "attempts": attempts})
                    return
                break
            if attempt["status"] in ("unexpected_sender", "invalid_response") or index + 1 >= ATTEMPTS:
                break
            remaining = deadline - clock()
            if remaining <= RETRY_DELAY:
                break
            sleeper(min(RETRY_DELAY, remaining))
        finished = wallclock()
        if not attempts:
            attempts.append({"attempt": 1, "started_at": finished, "finished_at": finished,
                             "status": "budget_exhausted", "error_code": "budget_exhausted",
                             "error": "整轮 STUN 预算已耗尽，未发起请求", "stage": "budget"})
        final_status = attempts[-1]["status"]
        if final_status == "ok" and clock() >= deadline:
            # Preserve the actual second response, but do not promote a late
            # response to success or invent a third attempt.
            attempts[-1]["accepted"] = False
            attempts[-1]["deadline_exceeded"] = True
            final_status = "budget_exhausted"
        results.put({"server": host, "port": port, "status": final_status,
                     "started_at": attempts[0]["started_at"], "finished_at": attempts[-1]["finished_at"], "attempts": attempts})

    for host, port in servers:
        threading.Thread(target=worker, args=(host, port), daemon=True).start()
    by_server = {}
    while len(by_server) < len(servers):
        remaining = deadline - clock()
        if remaining <= 0:
            break
        try:
            result = results.get(timeout=remaining)
        except queue.Empty:
            break
        if clock() >= deadline:
            break
        by_server[(result["server"], result["port"])] = result
    finished = wallclock()
    observations = []
    for host, port in servers:
        result = by_server.get((host, port))
        if result is None:
            with progress_lock:
                attempts = copy.deepcopy(progress.get((host, port), []))
            if len(attempts) < ATTEMPTS:
                attempts.append({"attempt": len(attempts) + 1, "started_at": finished, "finished_at": finished,
                                 "status": "budget_exhausted", "error_code": "budget_exhausted",
                                 "error": "整轮 STUN 预算耗尽，工作线程未在截止前返回", "stage": "budget"})
            elif attempts:
                attempts[-1]["accepted"] = False
                attempts[-1]["deadline_exceeded"] = True
            result = {"server": host, "port": port, "status": "budget_exhausted", "started_at": started,
                      "finished_at": finished, "attempts": attempts}
        observations.append(result)
    return {"scope": "原生 IPv4 UDP/STUN 探针，不代表 Claude 或浏览器 ICE", "started_at": started,
            "finished_at": finished, "complete": all(item["status"] == "ok" for item in observations),
            "observations": observations, "missing": sum(item["status"] == "budget_exhausted" for item in observations)}
