"""Validated configuration, private storage and process-wide operation locks."""
from __future__ import annotations

import contextlib
import copy
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import SCHEMA

MODES = ("tag", "clash-verge", "shadowrocket", "sing-box", "clashx", "surge", "auto")
DOMAINS = (
    "claude.ai", "claude.com", "anthropic.com", "claudeusercontent.com",
    "challenges.cloudflare.com", "datadoghq.com", "segment.io", "stripe.com",
    "stripe.network", "stripecdn.com", "intercom.io", "intercomcdn.com",
    "intercomassets.com",
)
LOCALES = dict(US="en_US", JP="ja_JP", CN="zh_CN", TW="zh_TW", HK="zh_HK", SG="en_SG",
               GB="en_GB", DE="de_DE", FR="fr_FR", KR="ko_KR", AU="en_AU", CA="en_CA")
CHECKS = (
    ("proxy", "代理内核"), ("tun", "TUN 网卡"), ("egress", "出口国家"),
    ("ip_history", "IP 一致性"), ("timezone", "时区"), ("locale", "地区与日期格式"),
    ("ipv6", "IPv6 策略"), ("dns", "DNS"), ("stun", "UDP/STUN 出口"),
    ("guard", "保护后台"), ("routing", "代理规则覆盖"), ("language", "Claude 语言"),
    ("asn", "ASN 属性"), ("reachability", "Claude 服务"),
)
DEFAULT_CONFIG = {
    "schema": SCHEMA, "enabled": True, "proxy_mode": "auto", "proxy_group": "", "proxy_url": "",
    "country": "", "timezone": "", "locale": "", "network_service": "Wi-Fi",
    "online_enabled": True, "require_ipv6_off": True, "require_english": True,
    "require_stun": True, "require_dns": True, "require_pinned_rules": False,
    "guard_enabled": True, "timezone_watchdog": False, "auto_update": False,
    "auto_check_on_open": True, "return_to_overview_after_launch": False,
    "expected_egress": [], "expected_resolvers": [], "allow_ip_change": True,
    "update_url": "", "update_public_key": "", "verified_claude_versions": [],
}


class SwitcherError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Paths:
    home: Path

    def __post_init__(self):
        object.__setattr__(self, "home", self.home.resolve())

    @property
    def watch(self): return self.home / "Library/Application Support/ClaudeWatch"
    @property
    def base(self): return self.watch / "switcher"
    @property
    def config(self): return self.base / "config.json"
    @property
    def accounts(self): return self.base / "accounts"
    @property
    def active(self): return self.home / "Library/Application Support/Claude"
    @property
    def state(self): return self.base / "accounts.json"
    @property
    def journal(self): return self.base / "transaction.json"
    @property
    def backend(self): return self.watch / "claude-watch.sh"
    @property
    def legacy(self): return self.home / ".claude-switcher"

    def initialize(self):
        for directory in (self.watch, self.base, self.accounts):
            reject_symlink(directory, self.home)
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)


def reject_symlink(path, boundary=None):
    path = Path(path).absolute()
    if boundary is not None:
        try:
            path.relative_to(Path(boundary).absolute())
        except ValueError:
            raise SwitcherError("path_outside_home", "路径不属于当前用户的数据范围")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise SwitcherError("unsafe_path", "拒绝通过符号链接访问受管理数据")
        if boundary is not None and part == Path(boundary).absolute():
            break


def read_json(path, default=None, limit=2_000_000):
    path = Path(path)
    reject_symlink(path)
    try:
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except FileNotFoundError:
        return copy.deepcopy(default)
    if len(data) > limit:
        raise SwitcherError("oversize_state", "状态文件过大")
    try:
        return json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise SwitcherError("invalid_state", "状态文件损坏；未覆盖原文件") from exc


def atomic_json(path, value):
    path = Path(path)
    reject_symlink(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@contextlib.contextmanager
def operation_lock(paths, name="operation", recovery=None):
    paths.initialize()
    path = paths.base / (name + ".lock")
    reject_symlink(path, paths.home)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise SwitcherError("busy", "已有切换、修复或升级操作正在进行") from exc
        if name == "operation":
            if (paths.base / "setup-transaction.json").exists() and recovery != "setup":
                raise SwitcherError("recovery_required", "先恢复未完成的环境初始化")
            if (paths.base / "update-transaction.json").exists() and recovery != "update":
                raise SwitcherError("recovery_required", "先恢复未完成的整包更新")
            if paths.journal.exists() and recovery != "account":
                raise SwitcherError("recovery_required", "先恢复未完成的账号切换")
        yield
    finally:
        os.close(fd)


def validate_config(value):
    if not isinstance(value, dict) or set(value) - set(DEFAULT_CONFIG):
        raise SwitcherError("invalid_config", "配置包含未知字段")
    result = copy.deepcopy(DEFAULT_CONFIG)
    result.update(value)
    if result["schema"] != SCHEMA or result["proxy_mode"] not in MODES:
        raise SwitcherError("invalid_config", "不支持的配置版本或代理类型")
    for key, default in DEFAULT_CONFIG.items():
        if isinstance(default, bool) and type(result[key]) is not bool:
            raise SwitcherError("invalid_config", key + " 必须是布尔值")
        if isinstance(default, str) and (not isinstance(result[key], str) or len(result[key]) > 16_384):
            raise SwitcherError("invalid_config", key + " 格式错误")
    if result["country"] and not re.fullmatch(r"[A-Z]{2}", result["country"]):
        raise SwitcherError("invalid_config", "国家必须为两位大写代码")
    if result["timezone"] and (not re.fullmatch(r"[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)+", result["timezone"])
                                or ".." in result["timezone"]):
        raise SwitcherError("invalid_config", "无效时区")
    if result["locale"] and not re.fullmatch(r"[a-z]{2,3}_[A-Z]{2}(?:@[-a-zA-Z0-9_=;]+)?", result["locale"]):
        raise SwitcherError("invalid_config", "无效地区格式")
    for key in ("proxy_group", "network_service"):
        if any(c in result[key] for c in "\n\r\x00") or len(result[key]) > 256:
            raise SwitcherError("invalid_config", "代理组或网络服务名称无效")
    from ipaddress import ip_address
    for key in ("expected_egress", "expected_resolvers"):
        if not isinstance(result[key], list) or len(result[key]) > 32:
            raise SwitcherError("invalid_config", "预期地址必须为 IP 列表")
        try:
            if any(not ip_address(x).is_global for x in result[key]):
                raise ValueError()
            result[key] = sorted({str(ip_address(x)) for x in result[key]})
        except (ValueError, TypeError):
            raise SwitcherError("invalid_config", "预期地址必须是有效公网 IP")
    versions = result["verified_claude_versions"]
    if not isinstance(versions, list) or len(versions) > 100 or any(
            not isinstance(x, str) or not re.fullmatch(r"[0-9A-Za-z._+-]{1,80}", x) for x in versions):
        raise SwitcherError("invalid_config", "账号兼容性版本列表无效")
    if result["update_url"]:
        from urllib.parse import urlparse
        url = urlparse(result["update_url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
            raise SwitcherError("invalid_config", "更新源必须为不含凭据的 HTTPS 地址")
    if result["proxy_url"]:
        from urllib.parse import urlparse
        from ipaddress import ip_address
        try:
            url = urlparse(result["proxy_url"])
            assert url.scheme == "http" and ip_address(url.hostname).is_loopback
            assert url.port and not url.username and not url.password and url.path in ("", "/")
            assert not url.query and not url.fragment
        except (ValueError, TypeError, AssertionError):
            raise SwitcherError("invalid_config", "诊断代理必须为数字回环 HTTP 入口")
    return result


def load_config(paths):
    return validate_config(read_json(paths.config, {}))


def save_config(paths, value):
    value = validate_config(value)
    with operation_lock(paths):
        if paths.journal.exists():
            raise SwitcherError("recovery_required", "先恢复未完成的账号事务")
        atomic_json(paths.config, value)
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def event(paths, category, **fields):
    """Only explicit non-credential fields may enter the action log."""
    allowed = {"operation", "account", "status", "code", "version", "action", "count", "elapsed_seconds", "archive_method"}
    record = dict(time=time.time(), category=category,
                  **{k: v for k, v in fields.items() if k in allowed})
    paths.initialize()
    path = paths.base / "events.jsonl"
    reject_symlink(path, paths.home)
    with operation_lock(paths, "events"):
        if path.exists() and path.stat().st_size > 1_048_576:
            older = paths.base / "events.previous.jsonl"
            reject_symlink(older, paths.home)
            os.replace(path, older)
        fd = os.open(path, os.O_APPEND | os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    # Reuse the existing event timeline without copying credentials or file contents.
    log_dir = paths.home / "Library/Logs/ClaudeWatch"
    reject_symlink(log_dir, paths.home)
    log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    shared = log_dir / "events.log"
    reject_symlink(shared, paths.home)
    line = "switcher-" + category + " " + " ".join(
        str(k) + "=" + str(v).replace("\n", " ").replace("\r", " ")
        for k, v in record.items() if k not in ("time", "category"))
    fd = os.open(shared, os.O_APPEND | os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as stream:
        stream.write(time.strftime("%Y-%m-%dT%H:%M:%S%z") + "\t" + line + "\n")
