#!/usr/bin/env python3
"""Explicit command entry; imports do not start probes or mutate system state."""
import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from watch_switcher.accounts import AccountStore
from watch_switcher.audit import audit, require_ready, record_dns_leak, record_webrtc_risk, dns_receipt_status, dns_row, source_notices
from watch_switcher.common import (CHECKS, Paths, SwitcherError, atomic_json, load_config,
                                  operation_lock, read_json, save_config)
from watch_switcher.repair import apply_plan, atomic_text, make_plan, region_plan, restore_settings
from watch_switcher.rules import discover_groups, merge_path, remove_block
from watch_switcher.services import (configure_update_task, disable_legacy, guard_tick,
                                     service_status, protection_preview, protection_apply)
from watch_switcher.system import System
from watch_switcher.update import Updater


def parser():
    p = argparse.ArgumentParser(description="Claude Watch macOS environment/account runtime")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("self-check")
    sub.add_parser("service-status")
    q = sub.add_parser("protection")
    q.add_argument("action", choices=("preview", "apply"))
    q.add_argument("--plan-id")
    q.add_argument("--apply", action="store_true")
    q = sub.add_parser("environment")
    q.add_argument("--online", action="store_true")
    q.add_argument("--record", action="store_true")
    q.add_argument("--mode", default="auto")
    q = sub.add_parser("dns-leak-record")
    q.add_argument("--apply", action="store_true")
    q = sub.add_parser("webrtc-risk-record")
    q.add_argument("--apply", action="store_true")
    q = sub.add_parser("setup")
    q.add_argument("action", choices=("inspect", "detect", "preview", "apply", "recover"))
    q.add_argument("--mode", default="auto")
    q.add_argument("--online", action="store_true")
    q.add_argument("--candidate-id")
    q.add_argument("--plan-id")
    q.add_argument("--apply", action="store_true")
    for name in ("check", "checkdetail"):
        q = sub.add_parser(name)
        q.add_argument("--online", action="store_true")
        q.add_argument("--require-ready", action="store_true")
        q.add_argument("--no-report", action="store_true")
    q = sub.add_parser("config")
    q.add_argument("action", choices=("show", "set", "enabled"))
    q.add_argument("--apply", action="store_true")
    q = sub.add_parser("account")
    q.add_argument("action", choices=("status", "switch", "recover", "import"))
    q.add_argument("target", nargs="?", choices=("A", "B"))
    q.add_argument("--apply", action="store_true")
    q.add_argument("--ack-unverified-version", action="store_true")
    q = sub.add_parser("launch")
    q.add_argument("--apply", action="store_true")
    for name in ("repair", "fix", "set-region"):
        q = sub.add_parser(name)
        q.add_argument("--apply", action="store_true")
        q.add_argument("--plan-id")
        q.add_argument("--allow-country", choices=("CN",))
    q = sub.add_parser("restore-settings")
    q.add_argument("receipt_id")
    q.add_argument("--apply", action="store_true")
    sub.add_parser("guard-tick")
    q = sub.add_parser("services")
    q.add_argument("action", choices=("update-on", "update-off", "disable-legacy", "refresh-admin"))
    q.add_argument("--apply", action="store_true")
    q = sub.add_parser("update")
    q.add_argument("--apply", action="store_true")
    q.add_argument("--auto", action="store_true")
    q.add_argument("--recover", action="store_true")
    q = sub.add_parser("uninstall")
    q.add_argument("--apply", action="store_true")
    q.add_argument("--purge-accounts", action="store_true")
    q.add_argument("--confirm-data-removal", action="store_true")
    q.add_argument("--remove-managed-rules", action="store_true")
    q = sub.add_parser("logs")
    q.add_argument("--export", type=Path)
    return p


def require_apply(args):
    if not args.apply:
        raise SwitcherError("explicit_apply_required", "此操作需要明确的 --apply；预览不会执行")


def dispatch(args, paths, system):
    if args.command == "service-status": return service_status(paths, system, load_config(paths))
    if args.command == "protection":
        raw = sys.stdin.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024: raise SwitcherError("oversize_config", "后台变更过大")
        changes = json.loads(raw)
        if args.action == "preview": return protection_preview(paths, system, changes)
        require_apply(args)
        if not args.plan_id: raise SwitcherError("plan_required", "先预览具体后台变更")
        return protection_apply(paths, system, changes, args.plan_id)
    if args.command == "environment":
        from watch_switcher.onboarding import observe
        return observe(paths, system, online=args.online, mode=args.mode, persist=args.record)
    if args.command == "webrtc-risk-record":
        require_apply(args)
        raw = sys.stdin.read(768 * 1024 + 1)
        if len(raw.encode("utf-8", "replace")) > 768 * 1024:
            raise SwitcherError("oversize_webrtc_receipt", "WebRTC 检测回执过大")
        value = json.loads(raw)
        probe = value.get("probe") if isinstance(value, dict) and "probe" in value else value
        receipt = record_webrtc_risk(paths, system, probe, expected_context=value.get("expected_context") if isinstance(value, dict) else None)
        return {"status": "ok", "receipt": receipt}
    if args.command == "dns-leak-record":
        require_apply(args)
        raw = sys.stdin.read(768 * 1024 + 1)
        if len(raw.encode("utf-8", "replace")) > 768 * 1024:
            raise SwitcherError("oversize_dns_receipt", "DNS 检测回执过大")
        value = json.loads(raw)
        probe = value.get("probe") if isinstance(value, dict) and "probe" in value else value
        # Command success means the latest observation was durably recorded.
        # The nested receipt can still say timeout/error/unknown and must then
        # block launch, rather than looking like a command transport failure.
        receipt = record_dns_leak(paths, system, probe, expected_context=value.get("expected_context") if isinstance(value, dict) else None)
        context = receipt.get("context", "")
        status = dns_receipt_status(paths, context)
        return {"status": "ok", "receipt": receipt, "dns_row": dns_row(status),
                "context_id": receipt.get("context_id", context), "sampled_at": receipt.get("finished_at")}
    if args.command == "setup":
        from watch_switcher import onboarding
        if args.action == "inspect": return onboarding.inspect(paths, system, args.mode)
        if args.action == "detect": return onboarding.detect(paths, system, args.mode, online=args.online)
        if args.action == "recover":
            require_apply(args)
            return onboarding.recover(paths, system)
        raw = sys.stdin.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024: raise SwitcherError("oversize_config", "初始化选项过大")
        options = json.loads(raw)
        if args.action == "preview": return onboarding.preview(paths, system, args.candidate_id, options)
        require_apply(args)
        return onboarding.apply(paths, system, args.candidate_id, options, args.plan_id)
    config = load_config(paths)
    accounts = AccountStore(paths, system, lambda: require_ready(paths, system, load_config(paths)))
    command = args.command
    if command == "status":
        previous_audit = read_json(paths.base / "last-audit.json")
        from watch_switcher.audit import policy_digest
        if isinstance(previous_audit, dict) and previous_audit.get("policy") != policy_digest(config): previous_audit = None
        return {"status": "ok", "config": config, "accounts": accounts.status(),
                "audit": previous_audit, "service_status": service_status(paths, system, config),
                "netcoffee_lookup": previous_audit.get("netcoffee_lookup") if isinstance(previous_audit, dict) else None,
                "source_notices": previous_audit.get("source_notices", []) if isinstance(previous_audit, dict) else [],
                "repair": read_json(paths.base / "last-repair.json"),
                "guard": read_json(paths.base / "guard-heartbeat.json"),
                "update_recovery_required": (paths.base / "update-transaction.json").exists(),
                "setup_recovery_required": (paths.base / "setup-transaction.json").exists(),
                "proxy_groups": discover_groups(paths),
                "claude_version": system.claude_version()}
    if command == "self-check":
        accounts.state()
        from watch_switcher.upstream_accounts import UpstreamAccountAdapter
        UpstreamAccountAdapter(paths).library_source()
        needed = ["watch-process-control", "watch-admin.sh", "dns_probe.py", "netcoffee_client.py", "watch_switcher/diagnostics.py", "watch_switcher/onboarding.py", "watch_switcher/region.py", "watch_switcher/automatic_policy.py", "watch_switcher/session_guard.py", "watch_switcher/upstream_accounts.py", "watch_switcher/dns_refresh.py"]
        if any(not (system.resources / name).is_file() for name in needed):
            raise SwitcherError("runtime_incomplete", "运行组件不完整")
        return {"status": "ok", "schema": 1, "checks": len(CHECKS)}
    if command == "config":
        if args.action == "show": return config
        if args.action == "enabled":
            return {"status": "ok", "enabled": config["enabled"]}
        require_apply(args)
        raw = sys.stdin.read(64 * 1024 + 1)
        if len(raw) > 64 * 1024: raise SwitcherError("oversize_config", "配置过大")
        return {"status": "ok", "config": save_config(paths, json.loads(raw))}
    if command in ("check", "checkdetail"):
        return audit(paths, system, config, online=args.online, persist=not args.no_report)
    if command == "account":
        if args.action == "status": return accounts.status()
        if args.action == "import": return accounts.import_legacy(apply=args.apply)
        require_apply(args)
        if args.action == "recover": return accounts.recover()
        return accounts.switch(args.target, config, acknowledge_unverified=args.ack_unverified_version)
    if command == "launch":
        require_apply(args)
        # System.launch_claude is the single complete launch gate, shared with
        # account switching and the shell entry. A display receipt never grants
        # permission and disabling protection never selects a weaker gate.
        with operation_lock(paths):
            system.launch_claude()
        return {"status": "ok", "message": "已通过受控入口启动；不代表账号服务可用"}
    if command in ("repair", "fix", "set-region"):
        plan = region_plan(paths, system, config, allow_country=args.allow_country) if command == "set-region" else make_plan(paths, system, config)
        if not args.apply: return plan
        if not args.plan_id: raise SwitcherError("plan_required", "先预览并提交对应 plan-id")
        return apply_plan(paths, system, plan["desired_config"], args.plan_id)
    if command == "restore-settings":
        require_apply(args)
        return restore_settings(paths, system, args.receipt_id)
    if command == "guard-tick": return guard_tick(paths, system)
    if command == "services":
        require_apply(args)
        if args.action == "disable-legacy": return disable_legacy(paths, system)
        if args.action == "refresh-admin":
            system.admin("status")
            return {"status": "ok", "message": "已通过管理员认证刷新系统辅助组件"}
        return configure_update_task(paths, system, args.action == "update-on")
    if command == "update":
        updater = Updater(paths, system)
        if args.recover:
            require_apply(args)
            with operation_lock(paths, recovery="update"): return updater.recover()
        return updater.check(config, apply=args.apply, automatic=args.auto)
    if command == "uninstall":
        if not args.apply:
            return {"status": "preview", "keep_accounts": not args.purge_accounts,
                    "message": "停止新增保护和更新任务；现有 Claude 数据目录不删除"}
        if args.purge_accounts and not args.confirm_data_removal:
            raise SwitcherError("data_confirmation_required", "清理账号库需额外指定 --confirm-data-removal")
        with operation_lock(paths):
            if paths.journal.exists(): raise SwitcherError("recovery_required", "先恢复账号事务")
            atomic_json(paths.config, dict(config, enabled=False, guard_enabled=False, auto_update=False, timezone_watchdog=False))
            configure_update_task(paths, system, False)
            if Path("/Library/Application Support/ClaudeWatch/claude-watch-admin.sh").exists():
                system.admin("uninstall")
            if args.remove_managed_rules:
                path = merge_path(paths)
                if path.exists(): atomic_text(path, remove_block(path.read_text()), paths.home)
            if args.purge_accounts:
                for path in (paths.accounts, paths.base / "ip-history.json", paths.state):
                    if path.is_dir(): shutil.rmtree(path)
                    elif path.exists(): path.unlink()
        return {"status": "ok", "message": "新增后台任务已停止；当前 Claude 资料保留",
                "accounts_removed": args.purge_accounts}
    if command == "logs":
        from watch_switcher.common import reject_symlink
        path = paths.base / "events.jsonl"
        reject_symlink(path, paths.home)
        text = path.read_text()[-1_048_576:] if path.is_file() else ""
        if args.export:
            reject_symlink(args.export)
            with args.export.open("x", encoding="utf-8") as stream:
                stream.write(text)
            return {"status": "ok", "message": "操作记录已导出；不含账号文件内容"}
        return {"status": "ok", "message": "\n".join(text.splitlines()[-100:]) or "暂无操作记录"}
    raise SwitcherError("unknown_command", "未知操作")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["diagnose-proxy"]:
        # This entry must work even with no backend/config or a broken account journal.
        from watch_switcher.diagnostics import main as diagnose_main
        return diagnose_main(arguments[1:])
    args = parser().parse_args(arguments)
    if os.geteuid() == 0:
        print(json.dumps({"status": "error", "code": "user_required", "message": "普通运行组件不能以 root 执行"}, ensure_ascii=False))
        return 4
    paths = Paths(Path.home())
    try:
        result = dispatch(args, paths, System(paths))
        print(json.dumps(result, ensure_ascii=False))
        if args.command in ("check", "checkdetail") and args.require_ready and not result["ready"]: return 4
        if args.command == "config" and args.action == "enabled" and not result["enabled"]: return 3
        return 0 if result.get("status") not in ("partial", "error") else 4
    except (SwitcherError, OSError, ValueError, TypeError, KeyError) as exc:
        print(json.dumps({"status": "error",
                          "code": exc.code if isinstance(exc, SwitcherError) else "operation_failed",
                          "message": str(exc) if isinstance(exc, SwitcherError) else "操作未完成；原状态需核对"},
                         ensure_ascii=False))
        return 4


if __name__ == "__main__":
    sys.exit(main())
