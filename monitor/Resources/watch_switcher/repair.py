"""Preview-bound repair actions. No writes occur while constructing a plan."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
from pathlib import Path

from .common import (LOCALES, SwitcherError, atomic_json, digest, event, load_config,
                     operation_lock, read_json, reject_symlink, validate_config)
from .rules import merge_path, render_rules
from .services import configure_update_task
from .system import APP_BUNDLES
from .region import reference as region_reference, date_check


def file_text(path, home):
    reject_symlink(path, home)
    try:
        if path.stat().st_size > 2_000_000: raise SwitcherError("oversize_config", "配置过大")
        return path.read_text()
    except FileNotFoundError: return ""


def text_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()


def atomic_text(path, text, home):
    reject_symlink(path, home)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".claude-watch-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)


def make_plan(paths, system, config):
    config = dict(config)
    accepted_locale = config["locale"]
    if config["country"] in LOCALES:
        config["locale"] = LOCALES[config["country"]]
    local = system.local(config)
    dates = local.get("date_format", {})
    if dates.get("has_custom_formats") and date_check(local, config["locale"]) == "fail":
        raise SwitcherError("custom_date_format", "自定义日期模板与出口地区不一致；请先在系统设置中调整，工具不会清空自定义格式")
    mode = local.get("mode") or config["proxy_mode"]
    actions = []
    def add(name, title, scope, before, after):
        actions.append(dict(id=name, title=title, scope=scope, before=before, after=after))
    if local.get("proxy") == "fail" and mode in APP_BUNDLES:
        add("start_proxy", "启动选定代理客户端", "application", False, mode)
    if mode == "clash-verge":
        verge = paths.home / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/verge.yaml"
        text = file_text(verge, paths.home)
        if local.get("tun") != "ok" and re.search(r"^enable_tun_mode:\s*false\s*(?:#.*)?$", text, re.M):
            add("enable_tun", "启用 Clash Verge TUN", "proxy", text_hash(text), True)
        if config["proxy_group"]:
            old = file_text(merge_path(paths), paths.home)
            new = render_rules(old, config["proxy_group"])
            if old != new:
                add("rules", "合并 13 项域名置顶规则", "proxy", text_hash(old), config["proxy_group"])
        if any(x["id"] in ("enable_tun", "rules") for x in actions):
            add("reload_proxy", "重启 Clash Verge 使配置生效（会短暂影响代理）", "application", mode, mode)
    if config["timezone"] and local.get("timezone") != config["timezone"]:
        add("timezone", "设置系统时区", "administrator", local.get("timezone"), config["timezone"])
    if config["require_ipv6_off"] and local.get("ipv6") == "fail":
        add("ipv6", "关闭选定网络服务的 IPv6", "administrator", "enabled", config["network_service"])
    if config["locale"] and local.get("locale") != config["locale"]:
        add("locale", "设置地区与日期格式（保留界面语言）", "preferences", local.get("locale"), config["locale"])
    from .audit import preferred_language
    language = preferred_language(local.get("language")) or ""
    if config["require_english"] and language.split("-")[0].split("_")[0] != "en":
        add("language", "单独将 Claude 客户端语言设为英文", "preferences", "application-default", "en-US")
    if accepted_locale != config["locale"]:
        add("reference", "更新已接受的地区格式参考", "watch", accepted_locale, config["locale"])
    watchdog = system.watchdog_state()
    actual_target = watchdog["target"]
    desired_target = config["timezone"] if config["timezone_watchdog"] else None
    if actual_target != desired_target or (desired_target and not watchdog["registered"]):
        add("watchdog", "设置时区守护", "administrator", actual_target, desired_target)
    update = paths.home / "Library/LaunchAgents/io.local.claudewatch.update.plist"
    source_ready = bool(config["update_url"] and config["update_public_key"])
    if update.exists() != config["auto_update"] and (not config["auto_update"] or source_ready):
        add("updater", "设置每 12 小时自动更新任务", "watch", update.exists(), config["auto_update"])
    if any(x["id"] in ("enable_tun", "rules", "ipv6") for x in actions):
        add("flush_dns", "刷新系统 DNS 缓存", "administrator", None, None)
    plan = dict(schema=1, actions=actions, config_hash=digest(load_config(paths)),
                desired_config=config, context=local.get("context"),
                note="其他代理客户端的规则需在客户端中配置；未列出的设置不会改变")
    plan["id"] = digest(plan)
    return plan


def apply_plan(paths, system, config, expected_id):
    with operation_lock(paths):
        if paths.journal.exists():
            raise SwitcherError("recovery_required", "先恢复账号事务")
        plan = make_plan(paths, system, config)
        if plan["id"] != expected_id:
            raise SwitcherError("stale_plan", "当前环境或配置已变化，请重新预览")
        receipt = dict(schema=1, id=plan["id"], time=time.time(), status="running",
                       actions=[], desired_config=config)
        for action in plan["actions"]:
            try:
                execute_action(paths, system, config, action)
                receipt["actions"].append(dict(action, status="ok"))
            except Exception as exc:
                receipt["actions"].append(dict(action, status="failed",
                    code=exc.code if isinstance(exc, SwitcherError) else "operation_failed"))
                receipt["status"] = "partial"
                atomic_json(paths.base / "last-repair.json", receipt)
                event(paths, "repair", status="partial", action=action["id"])
                return receipt
        updated = dict(config)
        if any(x["id"] == "guard" for x in plan["actions"]): updated["guard_enabled"] = True
        atomic_json(paths.config, validate_config(updated))
        receipt["status"] = "ok"
        atomic_json(paths.base / "last-repair.json", receipt)
        event(paths, "repair", status="ok", count=len(receipt["actions"]))
        return receipt


def execute_action(paths, system, config, action):
    kind = action["id"]
    if kind == "start_proxy":
        system.run(["/usr/bin/open", APP_BUNDLES[action["after"]]])
    elif kind == "reload_proxy":
        system.run(["/usr/bin/osascript", "-e", 'tell application "Clash Verge" to quit'])
        system.run(["/usr/bin/open", APP_BUNDLES["clash-verge"]])
    elif kind == "enable_tun":
        path = paths.home / "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/verge.yaml"
        old = file_text(path, paths.home)
        if text_hash(old) != action["before"]: raise SwitcherError("config_changed", "代理配置已变化")
        new, count = re.subn(r"^(enable_tun_mode:\s*)false(\s*(?:#.*)?)$", r"\g<1>true\2", old, flags=re.M)
        if count != 1: raise SwitcherError("ambiguous_config", "TUN 配置键不唯一")
        atomic_text(path, new, paths.home)
    elif kind == "rules":
        path = merge_path(paths)
        old = file_text(path, paths.home)
        if text_hash(old) != action["before"]: raise SwitcherError("config_changed", "规则文件已变化")
        atomic_text(path, render_rules(old, config["proxy_group"]), paths.home)
    elif kind == "timezone": system.admin("timezone", config["timezone"])
    elif kind == "ipv6": system.admin("ipv6", config["network_service"], "off")
    elif kind == "flush_dns": system.admin("flush-dns")
    elif kind == "watchdog": system.admin("watchdog", config["timezone"] if config["timezone_watchdog"] else "off")
    elif kind == "locale": system.run(["/usr/bin/defaults", "write", "-g", "AppleLocale", config["locale"]])
    elif kind == "language":
        system.run(["/usr/bin/defaults", "write", "com.anthropic.claudefordesktop", "AppleLanguages", "-array", "en-US"])
    elif kind == "guard":
        if not (paths.watch / "runtime/switcher.py").is_file():
            raise SwitcherError("backend_update_required", "请先通过安装命令更新完整后台")
    elif kind == "reference": pass  # Accepted reference commits with the verified plan.
    elif kind == "updater": configure_update_task(paths, system, config["auto_update"])
    else: raise SwitcherError("unknown_action", "未识别的修复操作")


def region_plan(paths, system, config, *, allow_country=None):
    if not config["online_enabled"]:
        raise SwitcherError("online_disabled", "请先明确启用在线检查")
    local = system.local(config)
    if local.get("proxy") != "ok" or local.get("tun") != "ok":
        raise SwitcherError("proxy_unverified", "代理与 TUN 未确认；未发起地区探测")
    if config["proxy_mode"] == "auto":
        selected = local.get("mode")
        if not selected: raise SwitcherError("proxy_ambiguous", "当前客户端未能唯一确认；请核对运行进程与实际入口后重新检测")
        probe_config = dict(config, proxy_mode=selected)
    else: probe_config = config
    try:
        values = system.egress_reference(probe_config)
        measured = region_reference(values.get("trace", {}), values.get("geo", {}))
        if not measured or not measured.get("timezone") or not measured.get("locale"):
            raise ValueError()
        country, timezone = measured["country"], measured["timezone"]
    except (SwitcherError, ValueError, KeyError, TypeError):
        raise SwitcherError("region_inconsistent", "两个来源的出口 IP/国家未能交叉确认")
    if country == "CN" and allow_country != "CN":
        raise SwitcherError("region_confirmation_required", "当前出口为 CN；默认不应用，例外需明确指定")
    locale = measured["locale"]
    desired = dict(config, country=country, timezone=timezone, locale=locale)
    return make_plan(paths, system, validate_config(desired))


def restore_settings(paths, system, receipt_id):
    """Compare-and-restore only settings still equal to our recorded value."""
    with operation_lock(paths):
        receipt = read_json(paths.base / "last-repair.json")
        if not receipt or receipt.get("id") != receipt_id:
            raise SwitcherError("receipt_missing", "未找到对应变更记录")
        config = load_config(paths)
        local = system.local(config)
        restored, skipped = [], []
        for action in reversed(receipt["actions"]):
            if action.get("status") != "ok": continue
            kind, before, after = action["id"], action["before"], action["after"]
            if kind == "timezone" and before and local.get("timezone") == after:
                validate_config(dict(config, timezone=before))
                system.admin("timezone", before); restored.append(kind)
            elif kind == "locale" and before and local.get("locale") == after:
                system.run(["/usr/bin/defaults", "write", "-g", "AppleLocale", before]); restored.append(kind)
            else:
                skipped.append(kind)
        return {"status": "ok", "restored": restored, "skipped": skipped,
                "message": "仅恢复仍匹配变更记录的设置；其余保留供人工核对"}
