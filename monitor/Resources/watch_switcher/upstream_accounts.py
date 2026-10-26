"""Execute pinned upstream account functions in a private, verified workspace."""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from .common import SwitcherError, atomic_json, digest, event, operation_lock, read_json, reject_symlink, sync_directory

PINNED_COMMIT = "e2da42956bccd39f5e8e2e052c5002b96137f146"
PINNED_SHA256 = "965c7c9b072b6ae2f023941598c29218e8959251704c6e939f54313377ff72ca"

@dataclass
class UpstreamRun:
    target: str
    current: str
    workspace: Path
    data: Path
    accounts: Path
    source_sha256: str
    launch_requested: bool

class UpstreamAccountAdapter:
    def __init__(self, paths, vendor=None):
        self.paths = paths
        resources = Path(__file__).resolve().parents[1]
        candidates = [Path(vendor)] if vendor else [
            resources / "ThirdParty/ClaudeSwitcher/upstream/core/claude-switch.sh",
            resources.parent / "ThirdParty/ClaudeSwitcher/upstream/core/claude-switch.sh"]
        self.vendor = next((p for p in candidates if p.is_file()), None)

    def library_source(self):
        if self.vendor is None: raise SwitcherError("upstream_missing", "缺少已打包的原版切号源码")
        reject_symlink(self.vendor)
        data = self.vendor.read_bytes()
        if hashlib.sha256(data).hexdigest() != PINNED_SHA256:
            raise SwitcherError("upstream_hash_invalid", "原版切号源码校验失败，未执行")
        start = data.index(b"\nstatus() {") + 1
        end = data.index(b'\ncase "' + b'$' + b'{1:-}" in', start)
        block = data[start:end]
        if not block.startswith(b"status() {") or b"switch_to() {" not in block:
            raise SwitcherError("upstream_extract_invalid", "原版账户函数边界不符")
        return block.decode("utf-8")

    def run(self, target, *, workspace=None, copier=None):
        from .accounts import account_id, tree_manifest, verified_copy
        account_id(target)
        library = self.library_source()
        copier = copier or verified_copy
        previous = read_json(self.paths.state, {"schema": 1, "current": None})
        current = previous.get("current") if isinstance(previous, dict) else None
        if current not in (None, "A", "B"): raise SwitcherError("invalid_account_state", "当前资料标记无效")
        self.paths.initialize()
        owned = workspace is None
        work = Path(workspace) if workspace is not None else Path(tempfile.mkdtemp(prefix="claude-upstream-", dir=self.paths.base))
        reject_symlink(work, self.paths.home)
        if not work.resolve().is_relative_to(self.paths.base): raise SwitcherError("unsafe_path", "原版执行目录必须属于本工具私有事务")
        work.mkdir(mode=0o700, exist_ok=True)
        data, base = work / "DATA", work / "BASE"
        try:
            (base / "accounts").mkdir(parents=True, mode=0o700)
            active_input = tree_manifest(self.paths.active) if self.paths.active.exists() else None
            slot_inputs = {}
            if self.paths.active.exists(): copier(self.paths.active, data)
            active_nonempty = data.is_dir() and any(data.iterdir())
            for name in ("A", "B"):
                source = self.paths.accounts / name / "profile"
                if source.exists():
                    slot_inputs[name] = tree_manifest(source)
                    copier(source, base / "accounts" / name)
            (base / "current").write_text(current or "none")
            source_file = work / "functions.sh"; source_file.write_text(library); source_file.chmod(0o600)
            wrapper = work / "run.sh"
            wrapper.write_text('''#!/bin/bash
set -euo pipefail
source "$1"
BASE="$2"
DATA="$3"
log(){ printf '%s\\n' "$*" >> "$BASE/engine.log"; }
quit_claude(){ [[ -d "$BASE/accounts" ]]; }
open(){
  [[ $# == 2 && "$1" == "-a" && "$2" == "Claude" ]] || return 64
  printf 'Claude\\n' > "$BASE/launch_requested"
}
switch_to "$4"
''')
            wrapper.chmod(0o700)
            environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"}
            if os.environ.get("CLAUDE_WATCH_NO_CLONE") == "1" or os.environ.get("CLAUDE_SWITCHER_NO_CLONE") == "1":
                environment["CLAUDE_SWITCHER_NO_CLONE"] = "1"
            result = subprocess.run(["/bin/bash", str(wrapper), str(source_file), str(base), str(data), target],
                                    env=environment, capture_output=True, text=True, timeout=300)
            if result.returncode:
                raise SwitcherError("upstream_run_failed", "原版切号执行失败；真实资料尚未提交（exit %d）" % result.returncode)
            marker = base / "launch_requested"
            if (not data.is_dir() or (base / "current").read_text().strip() != target or
                    not marker.is_file() or marker.read_text().strip() != "Claude"):
                raise SwitcherError("upstream_output_invalid", "原版切号输出不完整，真实资料未提交")
            # Verification invariants: the engine must not lose or invent profile
            # bytes. These assertions do not carry out the switching algorithm.
            archived = (current or "A") if active_input is not None and current != target and (current is not None or active_nonempty) else None
            expected_slots = dict(slot_inputs)
            if archived: expected_slots[archived] = active_input
            expected_data = active_input if current == target else expected_slots.get(target, {})
            if expected_data is None: expected_data = {}
            if tree_manifest(data) != expected_data:
                raise SwitcherError("upstream_output_invalid", "原版载入结果与资料清单不一致，未提交")
            for slot in (base / "accounts").iterdir():
                account_id(slot.name)
                if slot.name not in expected_slots or tree_manifest(slot) != expected_slots[slot.name]:
                    raise SwitcherError("upstream_output_invalid", "原版存档结果校验失败，未提交")
            if any(not (base / "accounts" / name).is_dir() for name in expected_slots):
                raise SwitcherError("upstream_output_invalid", "原版存档输出缺失，未提交")
            return UpstreamRun(target, target, work, data, base / "accounts", PINNED_SHA256, True)
        except (SwitcherError, OSError, subprocess.SubprocessError, ValueError) as error:
            if owned and work.exists(): shutil.rmtree(work)
            if isinstance(error, SwitcherError): raise
            raise SwitcherError("upstream_run_failed", "原版切号工作目录准备或执行失败；真实资料未提交") from error

def _workspace(paths, token):
    if not isinstance(token, str) or len(token) != 32 or any(c not in "0123456789abcdef" for c in token):
        raise SwitcherError("invalid_journal", "原版事务标识无效")
    return paths.base / (".upstream-account-" + token)

def _targets(paths):
    return {"A": paths.accounts / "A", "B": paths.accounts / "B", "active": paths.active}

def _fingerprint(path):
    from .accounts import tree_manifest
    return digest(tree_manifest(path))

def recover_switch(store, journal):
    paths = store.paths
    work = _workspace(paths, journal.get("token"))
    if journal.get("schema") != 3 or journal.get("engine") != PINNED_COMMIT or journal.get("target") not in ("A", "B"):
        raise SwitcherError("invalid_journal", "原版事务记录无效")
    if journal.get("workspace") != str(work) or journal.get("phase") not in ("preparing", "publishing", "installed", "launching", "committed", "restoring"):
        raise SwitcherError("invalid_journal", "原版事务路径或阶段无效")
    reject_symlink(work, paths.home)
    previous = journal.get("previous")
    if not isinstance(previous, dict) or previous.get("current") not in (None, "A", "B"):
        raise SwitcherError("invalid_journal", "原账号标记无效")
    records = journal.get("records")
    if not isinstance(records, list) or len(records) > 3: raise SwitcherError("invalid_journal", "原版提交记录无效")
    targets, used = _targets(paths), set()
    for record in records:
        key = record.get("key")
        if key not in targets or key in used or type(record.get("had_old")) is not bool:
            raise SwitcherError("invalid_journal", "原版提交目标无效")
        used.add(key)
        for field, expected in (("destination", targets[key]), ("old", work / "old" / key), ("next", work / "next" / key)):
            if record.get(field) != str(expected): raise SwitcherError("invalid_journal", "恢复路径被更改")
            reject_symlink(expected, paths.home)
        for field in ("before_hash", "after_hash"):
            value = record.get(field)
            if value is not None and (not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value)):
                raise SwitcherError("invalid_journal", "恢复校验值无效")
    if journal["phase"] == "preparing":
        old_root = work / "old"; reject_symlink(old_root, paths.home)
        if records or (old_root.exists() and any(old_root.iterdir())):
            raise SwitcherError("recovery_conflict", "未提交记录中发现原资料，未删除现场")
        # No real directory has been replaced: do not quit a user-restarted app.
        if work.exists(): shutil.rmtree(work)
        paths.journal.unlink(); sync_directory(paths.base)
        return {"status": "ok", "message": "未提交的工作目录已清理，当前资料未替换"}
    if "active" not in used:
        raise SwitcherError("invalid_journal", "提交记录缺少活动资料")
    if store.system.claude_running(): raise SwitcherError("claude_still_running", "先退出 Claude 再恢复资料")
    state = read_json(paths.state, {"schema": 1, "current": None})
    if journal["phase"] == "committed":
        if not isinstance(state, dict) or state.get("transaction_id") != journal["token"]:
            raise SwitcherError("recovery_conflict", "已提交账号标记发生外部变化")
    else:
        if state != previous and (not isinstance(state, dict) or state.get("transaction_id") != journal["token"]):
            raise SwitcherError("recovery_conflict", "账号标记发生外部变化，未覆盖")
        launched = journal.get("launch_attempted") is True
        journal["phase"] = "restoring"; atomic_json(paths.journal, journal)
        for record in reversed(records):
            destination, old = Path(record["destination"]), Path(record["old"])
            if record.get("restored"):
                if record["had_old"] and (not destination.exists() or _fingerprint(destination) != record["before_hash"]):
                    raise SwitcherError("recovery_conflict", "已恢复的资料又发生变化")
                if not record["had_old"] and destination.exists():
                    raise SwitcherError("recovery_conflict", "恢复后出现新的外部资料，未删除")
                continue
            if old.exists():
                if not record["had_old"] or _fingerprint(old) != record["before_hash"]:
                    raise SwitcherError("recovery_conflict", "原资料校验失败，恢复现场已保留")
                if destination.exists():
                    if record["key"] == "active" and launched:
                        recovered = paths.accounts / ("recovered-" + journal["token"])
                        if recovered.exists(): raise SwitcherError("recovery_conflict", "恢复保存目录已存在")
                        os.replace(destination, recovered)
                    elif _fingerprint(destination) == record["after_hash"]:
                        shutil.rmtree(destination)
                    else: raise SwitcherError("recovery_conflict", "目标被外部修改，未覆盖")
                os.replace(old, destination); sync_directory(destination.parent)
            elif record["had_old"]:
                if not destination.exists() or _fingerprint(destination) != record["before_hash"]:
                    raise SwitcherError("recovery_conflict", "原资料位置无法确认")
            elif destination.exists():
                if record["key"] == "active" and launched:
                    recovered = paths.accounts / ("recovered-" + journal["token"])
                    if recovered.exists(): raise SwitcherError("recovery_conflict", "恢复保存目录已存在")
                    os.replace(destination, recovered)
                elif _fingerprint(destination) == record["after_hash"]:
                    shutil.rmtree(destination)
                else: raise SwitcherError("recovery_conflict", "新建目标被外部修改，未删除")
            record["restored"] = True; atomic_json(paths.journal, journal)
            store.checkpoint("original_restored" if record["key"] == "active" else "snapshot_restored")
        if journal.get("state_existed"): atomic_json(paths.state, previous)
        elif paths.state.exists(): paths.state.unlink()
    if work.exists(): shutil.rmtree(work)
    paths.journal.unlink(); sync_directory(paths.base)
    event(paths, "account", operation="recover", status="ok")
    return {"status": "ok", "message": "已恢复原资料与存档；未自动启动 Claude"}

def run_switch(store, target, config, *, acknowledge_unverified=False):
    from .accounts import account_id, tree_manifest, write_account_manifest, TRANSIENT
    paths = store.paths
    account_id(target)
    adapter = UpstreamAccountAdapter(paths); adapter.library_source()
    started = time.monotonic()
    with operation_lock(paths):
        reject_symlink(paths.active, paths.home)
        previous = store.state()
        if previous["current"] == target:
            return {"status": "ok", "current": target, "message": "当前已是账号 " + target + "，未重复切换"}
        version = store.system.claude_version()
        if not version: raise SwitcherError("claude_missing", "未找到可确认版本的 Claude")
        if version not in config["verified_claude_versions"] and not acknowledge_unverified:
            raise SwitcherError("account_compatibility_unverified", "首次使用此 Claude 版本切换资料，需确认兼容性边界")
        first_import = previous["current"] is None and paths.active.is_dir() and any(p.name not in TRANSIENT for p in paths.active.iterdir())
        for slot in (target,):
            profile = paths.accounts / slot / "profile"
            if profile.exists() and not (first_import and target == "A"):
                manifest = read_json(profile.parent / "manifest.json")
                if not isinstance(manifest, dict) or tree_manifest(profile) != manifest.get("files"):
                    raise SwitcherError("snapshot_corrupt", "账号 " + slot + " 存档校验失败")
        store.preflight(); store.system.quit_claude()
        if store.system.claude_running(): raise SwitcherError("claude_restarted", "Claude 尚在运行，未准备资料")
        token = uuid.uuid4().hex
        work = _workspace(paths, token); reject_symlink(work, paths.home); work.mkdir(mode=0o700)
        old_root, next_root = work / "old", work / "next"
        old_root.mkdir(); next_root.mkdir()
        journal = {"schema": 3, "engine": PINNED_COMMIT, "token": token, "workspace": str(work), "target": target,
                   "phase": "preparing", "previous": previous, "state_existed": paths.state.exists(), "records": [], "launch_attempted": False}
        atomic_json(paths.journal, journal)
        store.copy_metrics = []
        try:
            before = {key: _fingerprint(path) if path.exists() else None for key, path in _targets(paths).items()}
            result = adapter.run(target, workspace=work / "engine", copier=store._copy)
            for slot in ("A", "B"):
                output = result.accounts / slot
                if output.exists():
                    staged = next_root / slot; staged.mkdir()
                    os.replace(output, staged / "profile")
                    write_account_manifest(staged / "manifest.json", {"schema": 1, "files": tree_manifest(staged / "profile"),
                        "created_at": time.time(), "claude_version": version, "upstream_commit": PINNED_COMMIT, "upstream_transaction": token})
            os.replace(result.data, next_root / "active")
            store.checkpoint("snapshot_verified")
            store.preflight()
            if store.system.claude_running(): raise SwitcherError("claude_restarted", "准备期间 Claude 重新启动，未提交")
            for key, destination in _targets(paths).items():
                candidate = next_root / key
                if not candidate.exists(): continue
                if (destination.exists() and _fingerprint(destination) != before[key]) or (not destination.exists() and before[key] is not None):
                    raise SwitcherError("external_change", "准备期间原资料发生变化，未覆盖")
                journal["records"].append({"key": key, "destination": str(destination), "old": str(old_root / key),
                    "next": str(candidate), "had_old": destination.exists(), "before_hash": before[key],
                    "after_hash": _fingerprint(candidate), "restored": False})
            journal["phase"] = "publishing"; atomic_json(paths.journal, journal); store.checkpoint("prepared")
            for record in journal["records"]:
                destination, old, candidate = Path(record["destination"]), Path(record["old"]), Path(record["next"])
                if store.system.claude_running(): raise SwitcherError("claude_restarted", "提交期间 Claude 重新启动，已停止")
                if _fingerprint(candidate) != record["after_hash"]:
                    raise SwitcherError("copy_verification_failed", "待提交资料发生变化，未替换")
                if record["had_old"]:
                    if not destination.exists() or _fingerprint(destination) != record["before_hash"]:
                        raise SwitcherError("external_change", "原资料在提交前发生变化，未覆盖")
                elif destination.exists():
                    raise SwitcherError("external_change", "目标被外部创建，未覆盖")
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if destination.exists(): os.replace(destination, old)
                sync_directory(destination.parent)
                store.checkpoint("old_moved" if record["key"] == "active" else "previous_snapshot_moved")
                os.replace(candidate, destination); sync_directory(destination.parent)
                if _fingerprint(destination) != record["after_hash"]: raise SwitcherError("copy_verification_failed", "提交后资料校验失败")
                store.checkpoint("snapshot_committed" if record["key"] != "active" else "installed")
            journal["phase"] = "installed"; atomic_json(paths.journal, journal)
            store.preflight()
            if store.system.claude_running(): raise SwitcherError("claude_restarted", "启动前出现非预期 Claude 进程")
            journal.update(phase="launching", launch_attempted=True); atomic_json(paths.journal, journal)
            store.system.launch_claude()
            if read_json(paths.state, {"schema": 1, "current": None}) != previous:
                raise SwitcherError("external_change", "启动期间账号标记被外部修改")
            atomic_json(paths.state, {"schema": 1, "current": target, "claude_version": version,
                                     "upstream_commit": PINNED_COMMIT, "transaction_id": token})
            journal["phase"] = "committed"; atomic_json(paths.journal, journal); store.checkpoint("committed")
            shutil.rmtree(work); paths.journal.unlink(); sync_directory(paths.base)
            elapsed = round(time.monotonic() - started, 3)
            event(paths, "account", operation="switch", account=target, status="ok", elapsed_seconds=elapsed, archive_method="upstream-stage")
            return {"status": "ok", "account": target, "login_verified": False, "elapsed_seconds": elapsed,
                    "engine": "upstream-shell", "upstream_commit": PINNED_COMMIT, "source_sha256": result.source_sha256,
                    "archive_method": "upstream-stage", "copies": store.copy_metrics,
                    "message": "原版切号流程已完成，当前资料为 " + target}
        except Exception:
            saved = read_json(paths.journal, {})
            if saved.get("phase") == "committed":
                return {"status": "partial", "account": target, "engine": "upstream-shell",
                        "recovery_required": True, "message": "切号已完成，旧事务目录清理未完成；当前账号保持运行，请稍后恢复清理"}
            if saved.get("phase") != "preparing" and store.system.claude_running(): store.system.quit_claude()
            if paths.journal.exists(): recover_switch(store, saved)
            raise
