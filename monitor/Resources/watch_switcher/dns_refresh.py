"""Bounded GUI DNS renewal at a launch gate; never grants launch permission."""
from __future__ import annotations
import os
import re
import time
import uuid
from .common import SwitcherError, atomic_json, read_json, reject_symlink


def refresh_for_launch(paths, *, timeout=85, clock=time.monotonic, sleep=time.sleep):
    token = os.environ.get("CLAUDE_WATCH_DNS_REFRESH_TOKEN", "")
    if not token:
        return  # CLI callers still face the same freshness gate.
    if not re.fullmatch(r"[0-9a-f]{32}", token):
        raise SwitcherError("dns_refresh_invalid", "DNS 更新请求标识无效")
    directory = paths.base / (".dns-refresh-" + token)
    reject_symlink(directory, paths.home)
    if not directory.is_dir() or directory.stat().st_uid != os.getuid():
        raise SwitcherError("dns_refresh_unavailable", "DNS 检测协作通道不可用，未放行")
    from .audit import dns_receipt_path
    receipt = read_json(dns_receipt_path(paths), {})
    try:
        age = time.time() - float(receipt.get("finished_at", 0))
    except (ValueError, TypeError, AttributeError):
        age = float("inf")
    if isinstance(receipt, dict) and receipt.get("provider") == "ipleak" and 0 <= age <= 8:
        return
    request_id = uuid.uuid4().hex
    request, reply = directory / "request.json", directory / "reply.json"
    reject_symlink(request, paths.home); reject_symlink(reply, paths.home)
    atomic_json(request, {"schema": 1, "id": request_id})
    deadline = clock() + timeout
    while clock() < deadline:
        response = read_json(reply, {})
        if isinstance(response, dict) and response.get("schema") == 1 and response.get("id") == request_id:
            if response.get("ready") is True:
                return  # audit() validates the real receipt, context and risk next.
            raise SwitcherError("dns_refresh_failed", "切号期间 DNS 检测未完成或上下文已变化，未放行")
        sleep(0.15)
    raise SwitcherError("dns_refresh_timeout", "切号期间等待新 DNS 检测超时，未放行")
