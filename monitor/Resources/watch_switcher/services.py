"""User-owned protection/update scheduling; root timezone actions stay separate."""
import os
import plistlib
import time
from pathlib import Path

from .common import SwitcherError, atomic_json, digest, event, guard_policy_digest, load_config, operation_lock, read_json, reject_symlink, sync_directory, validate_config

UPDATE_LABEL = "io.local.claudewatch.update"
TIMEZONE_LABEL = "io.local.claudewatch.timezone"


def job_state(system, name):
    try: return system.service_job(name)
    except (SwitcherError, OSError): return {"registered": None, "definition": None, "trusted": False}


def policy_issues(config):
    issues = []
    def add(key, title, detail): issues.append(dict(id=key, title=title, detail=detail))
    if not config["enabled"]: add("policy", "启动策略尚未启用", "确认环境并开启 Claude Watch 保护后，再运行启动前检查。")
    if not config["online_enabled"]: add("online", "受控启动的联网预检未允许", "此选项只控制启动预检；环境状态页的手动检测会单独请求网络。")
    # Routing readiness is decided by the live rule audit, never by client name.
    if not config["guard_enabled"]: add("guard", "Claude Watch 断线保护未启用", "受控启动要求本工具保护后台具有有效心跳。")
    return issues


def session_status(paths):
    """Read the persisted session projection without probing jobs or network."""
    try:
        from .session_guard import read_session
        raw = read_session(paths)
    except (ImportError, SwitcherError):
        raw = None
    if not raw:
        try: incident = read_json(paths.base / "last-guard-stop.json", {})
        except SwitcherError: incident = {}
        if isinstance(incident, dict) and isinstance(incident.get("reason"), dict):
            return {"state": "locked", "phase": "unbound", "baseline": None, "current": None,
                    "reason": incident["reason"], "risk_evidence": None, "locked_at": incident.get("stopped_at")}
        return {"state": "missing", "phase": "missing", "baseline": None, "current": None,
                "reason": None, "risk_evidence": None, "locked_at": None}
    phase = raw.get("state", "unknown")
    current = raw.get("last_check")
    try: fresh = isinstance(current, dict) and 0 <= time.time() - float(current.get("observed_at")) <= 10
    except (TypeError, ValueError): fresh = False
    if phase == "locked": state = "locked"
    elif phase == "pending": state = "pending"
    elif fresh and raw.get("last_risk_state") == "safe": state = "safe"
    else: state = "unknown"
    return {"state": state, "phase": phase, "baseline": raw.get("baseline"), "current": current,
            "reason": raw.get("reason") or raw.get("last_reason"), "risk_evidence": raw.get("risk_evidence"),
            "locked_at": raw.get("locked_at")}


def service_status(paths, system, config):
    import math
    healthy = system.backend_healthy()
    try: heartbeat = read_json(paths.base / "guard-heartbeat.json", {})
    except SwitcherError: heartbeat = {}
    if not isinstance(heartbeat, dict): heartbeat = {}
    desired_guard = config["guard_enabled"]
    try: guard = bool(config["enabled"] and desired_guard and system.guard_status(config)) if hasattr(system, "guard_status") else False
    except (SwitcherError, TypeError, AttributeError, ValueError): guard = False
    try: watchdog = system.watchdog_state()
    except SwitcherError: watchdog = {"registered": None, "target": None}
    original, update, clock = (job_state(system, key) for key in ("original", "updater", "watchdog"))
    ready = bool(config["update_url"] and config["update_public_key"])
    session_guard = session_status(paths)
    if session_guard["phase"] == "active":
        try: running = system.claude_running()
        except (SwitcherError, AttributeError): running = None
        if running is False:
            session_guard = dict(session_guard, state="idle")
    rows = []
    def add(key, title, state, detail, source, desired=None, last_checked=None):
        if type(last_checked) not in (float, int) or not math.isfinite(last_checked) or last_checked <= 0: last_checked = None
        rows.append(dict(id=key, title=title, state=state, detail=detail, source=source,
                         desired=desired, last_checked=last_checked))
    add("guard", "Claude Watch 保镖", "running" if guard else "inactive" if not desired_guard else "error",
        "后台及保护心跳有效；受控运行时核对会话 IP、中国风险与检测时效，命中阻断条件即退出 Claude。实际会话状态见下方。" if guard else
        "保护已停用。" if not desired_guard else
        "启动策略未启用，保护未生效。" if not config["enabled"] else "未取得有效保护心跳，请核对后台与代理。",
        "本工具保护心跳 / 后台进程身份", desired_guard, heartbeat.get("time"))
    registered = original.get("registered")
    original_state = ("unknown" if registered is None or (registered and not original.get("trusted")) else
                      "inactive" if not registered else "error" if original.get("last_exit") not in (None, 0) else "scheduled")
    interval = original.get("interval")
    schedule = "每 %s 秒检查" % interval if type(interval) is int and interval > 0 else "按原版任务计划检查"
    add("original", "原版 Claude切换器保镖", original_state,
        "已加载，%s；最近退出码：" % schedule + (str(original["last_exit"]) if original.get("last_exit") is not None else "尚未取得") if original_state == "scheduled" else
        "原版任务未加载或状态未能确认；此处只读展示，独立安装与管理。",
        "system/local.claude-bodyguard / 原版任务定义")
    desired_target = config["timezone"] if config["timezone_watchdog"] else None
    active = watchdog.get("registered")
    clock_state = "unknown" if clock.get("registered") is None or active is None else (
        "scheduled" if desired_target and active and watchdog.get("target") == desired_target else
        "inactive" if not desired_target and not active else "mismatch")
    add("watchdog", "时区守护", clock_state,
        "实际目标：%s；已接受目标：%s。任务按计划运行，不持续占用进程。" % (watchdog.get("target") or "未设置", desired_target or "停用"),
        "时区任务注册 / root 管理的目标文件", config["timezone_watchdog"], watchdog.get("last_success"))
    update_state = ("unavailable" if not ready else "unknown" if update.get("registered") is None else
                    "scheduled" if config["auto_update"] and update.get("registered") and update.get("trusted") else
                    "inactive" if not config["auto_update"] and not update.get("registered") else "mismatch")
    add("updater", "自动更新", update_state,
        "缺少本项目发布源或固定公钥；保存的开启意愿不代表可用的更新服务。" if not ready else
        "每 12 小时检查；实际任务：" + ("已加载" if update.get("registered") else "未加载"),
        "本项目发布配置 / 用户更新任务", config["auto_update"])
    return dict(status="ok", observed_at=time.time(), backend_healthy=healthy, services=rows,
                policy_issues=policy_issues(config), update_source_ready=ready, session_guard=session_guard)


def protection_preview(paths, system, changes):
    config = load_config(paths)
    allowed = {"guard_enabled", "timezone_watchdog", "auto_update"}
    if (not isinstance(changes, dict) or len(changes) != 1 or not set(changes) <= allowed or
            any(type(value) is not bool for value in changes.values())):
        raise SwitcherError("invalid_service_change", "每次只预览一个明确的后台开关")
    desired = dict(config, **changes)
    key = next(iter(changes))
    if key == "guard_enabled" and desired[key]:
        if not (paths.watch / "runtime/switcher.py").is_file():
            raise SwitcherError("runtime_missing", "先安装完整后台，再启用保护")
        desired.update(enabled=True, online_enabled=True)
    if key == "auto_update" and desired[key] and not (config["update_url"] and config["update_public_key"]):
        raise SwitcherError("update_source_missing", "发布源与固定公钥未配置，自动更新不可启用")
    desired = validate_config(desired)
    actions, context = [], {}
    if key == "guard_enabled":
        actions.append(dict(id="guard", title="启用 Claude Watch 断线保护" if desired[key] else "停用 Claude Watch 断线保护",
            scope="watch", before=config[key] and config["enabled"], after=desired[key],
            detail=("同时启用保护所需的启动策略；" if desired[key] and not config["enabled"] else "") + "原版保镖保持独立运行。"))
    elif key == "timezone_watchdog":
        previous = system.watchdog_state()
        if key in changes and desired[key]:
            reference = _watchdog_reference(paths)
            desired.update(country=reference["country"], timezone=reference["timezone"])
            desired = validate_config(desired)
        job = job_state(system, "watchdog")
        context = {"job": {k: job.get(k) for k in ("registered", "definition")},
                   "target": previous.get("target")}
        if context["job"]["registered"] is None:
            raise SwitcherError("service_unknown", "无法确认时区任务注册状态，未生成变更")
        if previous.get("target") and not previous.get("registered"):
            raise SwitcherError("service_inconsistent", "时区目标文件与注册状态不一致，请先核对后台")
        actions.append(dict(id="watchdog", title="启用时区守护" if desired[key] else "停用时区守护",
            scope="administrator", before=previous.get("target"), after=desired["timezone"] if desired[key] else None))
    else:
        job = job_state(system, "updater")
        path = paths.home / "Library/LaunchAgents" / (UPDATE_LABEL + ".plist")
        if job.get("registered") is None or path.exists() != job.get("registered"):
            raise SwitcherError("service_inconsistent", "更新任务文件与加载状态未能核对，请先检查后台")
        context = {k: job.get(k) for k in ("registered", "definition")}
        actions.append(dict(id="updater", title="启用每 12 小时更新" if desired[key] else "停用自动更新",
                            scope="watch", before=path.exists(), after=desired[key]))
    def display(value): return "未设置" if value is None else "开启" if value is True else "关闭" if value is False else str(value)
    for action in actions:
        action["detail"] = display(action["before"]) + " → " + display(action["after"]) + ("；" + action["detail"] if action.get("detail") else "")
        if action["id"] == "updater":
            action["detail"] = "保存意愿：%s → %s；实际任务：%s → %s。原版保镖保持并行。" % (
                display(config[key]), display(desired[key]), display(action["before"]), display(action["after"]))
    plan = dict(schema=1, actions=actions, desired_config=desired, config_hash=digest(config),
                context=context, changes=changes, purpose="protection_change")
    plan["id"] = digest(plan)
    return dict(status="ok", **plan)


def _watchdog_reference(paths):
    """Reuse detected facts; clock setup does not require a prior app launch."""
    for name in ("last-environment-detection.json", "last-audit.json"):
        receipt = read_json(paths.base / name, {})
        if not isinstance(receipt, dict): continue
        reference = receipt.get("egress_reference", {})
        transition = receipt.get("context_transition", {})
        if not isinstance(reference, dict) or not isinstance(transition, dict): continue
        try: age = time.time() - float(reference.get("checked_at"))
        except (TypeError, ValueError): continue
        country, timezone = reference.get("country"), reference.get("timezone")
        rows = {row.get("id"): row.get("state") for row in receipt.get("rows", []) if isinstance(row, dict)}
        measured_safe = receipt.get("ready") is True or all(rows.get(key) == "ok" for key in ("proxy", "tun", "egress", "timezone"))
        if (measured_safe and transition.get("state") == "stable" and isinstance(country, str) and country != "CN" and
                isinstance(timezone, str) and "/" in timezone and 0 <= age <= 300):
            return {"country": country, "timezone": timezone}
    raise SwitcherError("reference_required", "本轮出口时区尚未检测完整，重新检测后即可自动生成时区守护预览")


def protection_apply(paths, system, changes, plan_id):
    # The existing setup journal/recovery owns rollback, including interrupted writes.
    from .onboarding import managed_files, rollback
    from .repair import atomic_text, execute_action, file_text
    import json
    with operation_lock(paths):
        plan = protection_preview(paths, system, changes)
        if plan["id"] != plan_id: raise SwitcherError("stale_plan", "后台或设置发生变化，请重新预览")
        desired = plan["desired_config"]
        journal = dict(schema=1, id=plan_id, origin="protection", desired_config=desired, actions=[], files={
            key: {"before": file_text(path, paths.home) if path.exists() else None, "after": None}
            for key, path in managed_files(paths).items()})
        atomic_json(paths.base / "setup-transaction.json", journal)
        try:
            for action in plan["actions"]:
                if action["id"] == "guard": continue  # Configuration commit is journaled below.
                journal["actions"].append(dict(action, state="pending"))
                atomic_json(paths.base / "setup-transaction.json", journal)
                execute_action(paths, system, desired, action)
                journal["actions"][-1]["state"] = "applied"
                atomic_json(paths.base / "setup-transaction.json", journal)
                if action["id"] == "watchdog":
                    actual = system.watchdog_state()
                    if actual.get("target") != action["after"] or bool(actual.get("registered")) != bool(action["after"]):
                        raise SwitcherError("service_unconfirmed", "时区守护变更未能回读确认")
                if action["id"] == "updater" and job_state(system, "updater").get("registered") != action["after"]:
                    raise SwitcherError("service_unconfirmed", "更新任务变更未能回读确认")
            saved = journal["files"]["config"]
            current = file_text(paths.config, paths.home) if paths.config.exists() else None
            if current != saved["before"]:
                raise SwitcherError("external_change", "配置被其他操作更改，未覆盖")
            saved["after"] = json.dumps(desired, ensure_ascii=False, sort_keys=True) + "\n"
            atomic_json(paths.base / "setup-transaction.json", journal)
            atomic_text(paths.config, saved["after"], paths.home)
            sync_directory(paths.base)
            (paths.base / "setup-transaction.json").unlink()
            sync_directory(paths.base)
        except Exception as exc:
            result = rollback(paths, system, journal)
            if result["recovery_required"]: return result
            raise SwitcherError("protection_rolled_back", "后台变更未完成，已恢复原设置。" +
                                (str(exc) if isinstance(exc, SwitcherError) else "请重试")) from exc
        event(paths, "protection", status="ok", service=next(iter(changes)))
        return {"status": "ok", "config": desired, "message": "后台变更已完成；实际保护状态将在下一次采样更新。原版保镖保持并行。"}


def guard_tick(paths, system):
    config = None
    from .session_guard import check_session, close_if_current, lock_session, read_session, record_uncertain
    try:
        config = load_config(paths)
        if not config["enabled"] or not config["guard_enabled"]:
            return {"status": "disabled"}
        local = system.local(dict(config, proxy_mode="auto", proxy_url="", proxy_group=""), guard_only=True)
        known_failure = local["proxy"] == "fail" or local["tun"] == "fail"
        healthy = local["proxy"] == "ok" and local["tun"] == "ok" and system.backend_healthy()
        action = "observe"
        session = None
        if system.claude_running():
            if known_failure:
                session = {"state": "risk", "reason": {"code": "proxy_or_tun_failed",
                           "detail": "代理或 TUN 已确认失效", "source": "本机守护", "observed_at": time.time()}}
                previous = read_session(paths)
                if previous:
                    locked = lock_session(paths, "proxy_or_tun_failed", "代理或 TUN 已确认失效", previous.get("session_id"))
                    if locked: session["session"] = locked
            elif local["proxy"] == "unknown" or local["tun"] == "unknown":
                session = record_uncertain(paths, "proxy_or_tun_unconfirmed", "代理或 TUN 连续未能确认")
            else:
                session = check_session(paths, system, config, risk_reader=_session_risk_reader)
            if session.get("state") in ("risk", "locked"):
                # Do not wait on an account/update transaction before stopping
                # a running Claude process on explicit guard evidence.
                saved = session.get("session") if isinstance(session.get("session"), dict) else None
                expected = saved.get("session_id") if saved else None
                if close_if_current(paths, expected, system.quit_claude):
                    action = "close-desktop"
                    atomic_json(paths.base / "last-guard-stop.json", dict(stopped_at=time.time(),
                                session_id=expected, reason=session.get("reason")))
                    event(paths, "guard", action=action, status="ok", code=(session.get("reason") or {}).get("code", "risk"))
                else:
                    session = {"state": "unknown", "reason": {"code": "session_changed",
                               "detail": "守护检查期间已建立新会话，未退出 Claude", "source": "本机守护", "observed_at": time.time()}}
        receipt = {"status": "ok" if healthy else "degraded", "action": action, "session_guard": session,
                   "time": time.time(), "policy": digest(config), "guard_policy_v1": guard_policy_digest(config)}
    except SwitcherError as exc:
        receipt = {"status": "unknown", "code": exc.code, "message": str(exc), "time": time.time(),
                   "policy": digest(config or {}), "action": "observe"}
        try:
            if system.claude_running():
                session = record_uncertain(paths, "guard_sampling_failed", "保护采样未能完成：" + str(exc))
                receipt["session_guard"] = session
                if session.get("state") in ("risk", "locked"):
                    saved = session.get("session") or {}
                    if close_if_current(paths, saved.get("session_id"), system.quit_claude):
                        receipt["action"] = "close-desktop"
                        atomic_json(paths.base / "last-guard-stop.json", dict(stopped_at=time.time(),
                                    session_id=saved.get("session_id"), reason=session.get("reason")))
        except SwitcherError as stop_error:
            receipt["stop_error"] = str(stop_error)
    atomic_json(paths.base / "guard-heartbeat.json", receipt)
    return receipt


def _session_risk_reader(paths, context_id, current_ip):
    """DNS/WebRTC reader is optional until its persisted policy source exists."""
    try:
        from .automatic_policy import session_risk
        return session_risk(paths, context_id, current_ip)
    except (ImportError, AttributeError):
        return {"state": "unknown", "reason": {"code": "risk_evidence_missing",
                "detail": "DNS/WebRTC 风险证据尚未提供", "source": "自动策略", "observed_at": time.time()}}


def user_update_plist(paths, python):
    return {
        "Label": UPDATE_LABEL,
        "ProgramArguments": [python, str(paths.watch / "runtime/switcher.py"), "update", "--auto", "--apply"],
        "StartInterval": 43200, "RunAtLoad": False,
        "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin"},
        "StandardOutPath": str(paths.base / "update.stdout.log"),
        "StandardErrorPath": str(paths.base / "update.stderr.log"),
    }


def configure_update_task(paths, system, enable):
    import sys
    paths.initialize()
    path = paths.home / "Library/LaunchAgents" / (UPDATE_LABEL + ".plist")
    reject_symlink(path, paths.home)
    domain = "gui/" + str(os.getuid())
    present = system.run(["/bin/launchctl", "print", domain + "/" + UPDATE_LABEL], check=False).returncode == 0
    if present: system.run(["/bin/launchctl", "bootout", domain + "/" + UPDATE_LABEL])
    if enable:
        entry = paths.watch / "runtime/switcher.py"
        if not entry.is_file(): raise SwitcherError("runtime_missing", "先安装完整后台运行组件")
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".pending")
        reject_symlink(temporary, paths.home)
        with temporary.open("xb") as stream:
            stream.write(plistlib.dumps(user_update_plist(paths, sys.executable)))
        temporary.chmod(0o600)
        os.replace(temporary, path)
        system.run(["/bin/launchctl", "bootstrap", domain, str(path)])
    elif path.exists(): path.unlink()
    return {"status": "ok", "enabled": enable}


def disable_legacy(paths, system):
    """Explicit cutover only. Never removes legacy accounts or app data."""
    domain = "gui/" + str(os.getuid()) + "/local.claude-update"
    if system.run(["/bin/launchctl", "print", domain], check=False).returncode == 0:
        system.run(["/bin/launchctl", "bootout", domain])
    system.admin("legacy-stop")
    return {"status": "ok", "message": "旧保护和更新任务已停用；原应用和账号数据保留"}
