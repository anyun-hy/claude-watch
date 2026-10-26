"""Recoverable A/B directory transactions; never claims to migrate Keychain state."""
from __future__ import annotations

import hashlib
import json
import ctypes
import errno
from functools import lru_cache
import os
import shutil
import stat
import sys
import time
import uuid

from .common import SwitcherError, atomic_json, digest, event, operation_lock, read_json, reject_symlink, sync_directory

TRANSIENT = {"SingletonLock", "SingletonCookie", "SingletonSocket"}
ACCOUNT_MANIFEST_LIMIT = 2_000_000  # Match the bounded reader used during recovery.


def write_account_manifest(path, value):
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
    if len(encoded) + 1 > ACCOUNT_MANIFEST_LIMIT:
        raise SwitcherError("oversize_account_manifest", "账号文件清单过大，未替换活动资料")
    atomic_json(path, value)


def account_id(value):
    if value not in ("A", "B"):
        raise SwitcherError("invalid_account", "仅接受账号 A 或 B")
    return value


def tree_manifest(root):
    reject_symlink(root)
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in TRANSIENT)
        for name in dirs + sorted(files):
            if name in TRANSIENT: continue
            path = type(root)(directory) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise SwitcherError("unsupported_account_entry", "账号数据含链接或特殊文件；停止复制")
            if stat.S_ISREG(mode):
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for data in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(data)
                result[str(path.relative_to(root))] = {"size": path.stat().st_size, "sha256": digest.hexdigest()}
    return result


@lru_cache(maxsize=1)
def clone_function():
    if sys.platform != "darwin":
        return None
    try:
        function = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True).clonefile
        function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32)
        function.restype = ctypes.c_int
        return function
    except (OSError, AttributeError):
        return None


def clone_or_copy(source, target, metrics):
    if not stat.S_ISREG(os.lstat(source).st_mode):
        raise SwitcherError("unsupported_account_entry", "账号条目在复制前发生变化")
    if os.path.lexists(target):
        raise FileExistsError(target)
    disabled = os.environ.get("CLAUDE_WATCH_NO_CLONE") == "1" or os.environ.get("CLAUDE_SWITCHER_NO_CLONE") == "1"
    clone = None if disabled else clone_function()
    if clone is not None:
        # SDK sys/clonefile.h: CLONE_NOFOLLOW | CLONE_NOOWNERCOPY.
        if clone(os.fsencode(source), os.fsencode(target), 0x0001 | 0x0002) == 0:
            metrics["cloned_files"] += 1
            return target
        error = ctypes.get_errno()
        if os.path.lexists(target):
            os.unlink(target)  # Only this copy's previously absent destination.
        if error not in (errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV, errno.ENOSYS, errno.EINVAL):
            raise OSError(error, os.strerror(error))
    shutil.copy2(source, target, follow_symlinks=False)
    metrics["copied_files"] += 1
    return target


def verified_copy(source, target, *, metrics=None):
    before = tree_manifest(source)
    required = sum(x["size"] for x in before.values())
    if shutil.disk_usage(target.parent).free < required + 64 * 1024 * 1024:
        raise SwitcherError("disk_full", "剩余空间不足，未替换任何账号目录")
    metrics = {} if metrics is None else metrics
    metrics.update(cloned_files=0, copied_files=0)
    shutil.copytree(source, target, symlinks=False,
                    copy_function=lambda source, target: clone_or_copy(source, target, metrics),
                    ignore=lambda directory, names: set(names) & TRANSIENT)
    for directory, _, files in os.walk(target):
        os.chmod(directory, 0o700)
        for name in files:
            path = os.path.join(directory, name)
            # Keep user-owned executable helpers usable after an account load,
            # while retaining the existing private-to-owner permission policy.
            os.chmod(path, 0o600 | (os.stat(path).st_mode & stat.S_IXUSR))
    if tree_manifest(target) != before or tree_manifest(source) != before:
        raise SwitcherError("copy_verification_failed", "复制校验失败或源数据发生变化")
    metrics["strategy"] = "mixed" if metrics["cloned_files"] and metrics["copied_files"] else (
        "clone" if metrics["cloned_files"] else "copy")
    sync_directory(target)
    return before


class AccountStore:
    def __init__(self, paths, system, preflight, copier=verified_copy, checkpoint=None):
        self.paths, self.system, self.preflight = paths, system, preflight
        self.copier = copier
        self.checkpoint = checkpoint or (lambda stage: None)
        self.copy_metrics = []

    def _copy(self, source, target):
        metrics = {}
        if self.copier is verified_copy:
            manifest = self.copier(source, target, metrics=metrics)
        else:
            manifest = self.copier(source, target)
            metrics["strategy"] = "custom"
        self.copy_metrics.append(metrics)
        return manifest

    def _can_move_archive(self):
        return self.paths.active.stat().st_dev == self.paths.accounts.stat().st_dev

    def state(self):
        state = read_json(self.paths.state, {"schema": 1, "current": None})
        if not isinstance(state, dict) or state.get("schema") != 1 or state.get("current") not in (None, "A", "B"):
            raise SwitcherError("invalid_account_state", "账号状态损坏；需要人工核对")
        return state

    def status(self):
        state = self.state()
        return dict(schema=1, current=state["current"], recovery_required=self.paths.journal.exists(),
                    accounts=[dict(id=x, stored=(self.paths.accounts / x / "profile").is_dir(),
                                   current=state["current"] == x) for x in ("A", "B")],
                    login_verified=False,
                    detail="账号槽位表示本地资料目录，不证明远端账号身份或钥匙串隔离")

    def _snapshot(self, account):
        account_id(account)
        target = self.paths.accounts / account
        reject_symlink(target, self.paths.home)
        stage = self.paths.accounts / ("." + account + "." + uuid.uuid4().hex)
        old = self.paths.accounts / ("." + account + ".old." + uuid.uuid4().hex)
        stage.mkdir(mode=0o700)
        try:
            manifest = self._copy(self.paths.active, stage / "profile")
            write_account_manifest(stage / "manifest.json", {"schema": 1, "files": manifest,
                                                 "created_at": time.time(),
                                                 "claude_version": self.system.claude_version()})
            if target.exists(): os.replace(target, old)
            try: os.replace(stage, target)
            except BaseException:
                if old.exists(): os.replace(old, target)
                raise
            sync_directory(self.paths.accounts)
            if old.exists(): shutil.rmtree(old)
        finally:
            if stage.exists(): shutil.rmtree(stage)

    def _validate_journal(self, journal):
        if not isinstance(journal, dict) or journal.get("schema") not in (1, 2):
            raise SwitcherError("invalid_journal", "恢复记录格式错误")
        token = journal.get("token", "")
        if len(token) != 32 or any(c not in "0123456789abcdef" for c in token):
            raise SwitcherError("invalid_journal", "恢复标识无效")
        account_id(journal.get("target"))
        for key, prefix in (("stage", ".claude-watch-stage-"), ("old", ".claude-watch-old-")):
            expected = self.paths.active.parent / (prefix + token)
            if journal.get(key) != str(expected):
                raise SwitcherError("invalid_journal", "恢复路径不属于此次事务")
            reject_symlink(expected, self.paths.home)
        if journal["schema"] == 2:
            archive = journal.get("archive", {})
            if not isinstance(archive, dict) or not isinstance(journal.get("previous"), dict):
                raise SwitcherError("invalid_journal", "归档恢复记录不完整")
            current = account_id(archive.get("account"))
            previous = journal.get("previous", {})
            if (not journal.get("had_active") or current == journal["target"] or
                    current != (previous.get("current") or "A") or type(archive.get("had_snapshot")) is not bool):
                raise SwitcherError("invalid_journal", "归档事务与原账号不匹配")
            expected_paths = self._archive_paths(current, token)
            for key, expected in expected_paths.items():
                if archive.get(key) != str(expected):
                    raise SwitcherError("invalid_journal", "归档恢复路径不属于此次事务")
                reject_symlink(expected, self.paths.home)
            if journal.get("phase") not in ("prepared", "old_moved", "archived", "installed", "launching", "committed", "restoring", "restored"):
                raise SwitcherError("invalid_journal", "未知归档事务阶段")
            if journal["phase"] in ("restoring", "restored") and (
                    not isinstance(journal.get("restore_hash"), str) or len(journal["restore_hash"]) != 64
                    or any(c not in "0123456789abcdef" for c in journal["restore_hash"])):
                raise SwitcherError("invalid_journal", "恢复校验标识无效")
        return self.paths.active.parent / (".claude-watch-stage-" + token), self.paths.active.parent / (".claude-watch-old-" + token)

    def _archive_paths(self, account, token):
        return dict(slot=self.paths.accounts / account,
                    pending=self.paths.accounts / ("." + account + ".pending." + token),
                    backup=self.paths.accounts / ("." + account + ".previous." + token))

    def _owns_archive(self, directory, token):
        try:
            value = read_json(directory / "manifest.json", {})
        except (SwitcherError, OSError):
            # A damaged older snapshot is not this transaction's original data.
            # If our own marker is damaged, recovery preserves it for manual review.
            return False
        return isinstance(value, dict) and value.get("archive_transaction") == token

    def _archive_move(self, journal, old):
        archive = journal["archive"]
        paths = self._archive_paths(archive["account"], journal["token"])
        pending, slot, backup = (paths[key] for key in ("pending", "slot", "backup"))
        os.replace(old, pending / "profile")
        sync_directory(old.parent)
        sync_directory(pending)
        self.checkpoint("archive_moved")
        manifest = read_json(pending / "manifest.json")
        if tree_manifest(pending / "profile") != manifest["files"]:
            raise SwitcherError("copy_verification_failed", "归档期间原资料发生变化，已停止提交")
        if archive["had_snapshot"]:
            os.replace(slot, backup)
            sync_directory(self.paths.accounts)
        self.checkpoint("previous_snapshot_moved")
        os.replace(pending, slot)
        sync_directory(self.paths.accounts)
        self.checkpoint("snapshot_verified")
        journal["phase"] = "archived"
        atomic_json(self.paths.journal, journal)
        self.checkpoint("archived")

    def _recover_move(self, journal, stage, old):
        paths = self._archive_paths(journal["archive"]["account"], journal["token"])
        slot, pending, backup = (paths[key] for key in ("slot", "pending", "backup"))
        owned = [directory for directory in (pending, slot)
                 if directory.exists() and self._owns_archive(directory, journal["token"])]
        if journal.get("phase") == "committed":
            if slot not in owned or not (slot / "profile").is_dir():
                raise SwitcherError("recovery_conflict", "已提交的归档缺失，保留恢复记录供核对")
            for directory in (old, stage, pending, backup):
                if directory.exists(): shutil.rmtree(directory)
            return
        candidates = ([old] if old.exists() else []) + [directory / "profile" for directory in owned
                                                       if (directory / "profile").exists()]
        if len(candidates) > 1:
            raise SwitcherError("recovery_conflict", "发现多份原资料，未自动覆盖")
        if candidates:
            original = candidates[0]
            reject_symlink(original, self.paths.home)
            journal.update(phase="restoring", restore_hash=digest(tree_manifest(original)))
            atomic_json(self.paths.journal, journal)
            if self.paths.active.exists():
                saved = self.paths.accounts / ("recovered-" + journal["token"])
                if saved.exists(): raise SwitcherError("recovery_conflict", "已有同名恢复资料")
                os.replace(self.paths.active, saved)
            os.replace(original, self.paths.active)
            sync_directory(self.paths.active.parent)
            self.checkpoint("original_restored")
            journal["phase"] = "restored"
            atomic_json(self.paths.journal, journal)
        elif not (self.paths.active.is_dir() and (journal["phase"] == "prepared" or
                (journal["phase"] in ("restoring", "restored") and
                 digest(tree_manifest(self.paths.active)) == journal["restore_hash"]))):
            raise SwitcherError("recovery_conflict", "原资料位置无法确认，未删除任何恢复数据")
        # Restore the previous stored snapshot as well as the live directory.
        if slot in owned:
            shutil.rmtree(slot)
        if backup.exists():
            if slot.exists(): raise SwitcherError("recovery_conflict", "账号存档恢复目标被占用")
            os.replace(backup, slot)
        elif journal["archive"]["had_snapshot"] and not slot.exists():
            raise SwitcherError("recovery_conflict", "此前存档缺失，保留恢复记录")
        for directory in (pending, stage):
            if directory.exists(): shutil.rmtree(directory)
        sync_directory(self.paths.accounts)
        atomic_json(self.paths.state, journal["previous"])

    def _recover(self):
        journal = read_json(self.paths.journal)
        if journal is None: return {"status": "ok", "message": "没有未完成事务"}
        if isinstance(journal, dict) and journal.get("schema") == 3:
            from .upstream_accounts import recover_switch
            return recover_switch(self, journal)
        stage, old = self._validate_journal(journal)
        if self.system.claude_running():
            raise SwitcherError("claude_still_running", "先退出 Claude，再恢复未完成事务")
        previous = journal["previous"]
        if previous.get("current") not in (None, "A", "B"):
            raise SwitcherError("invalid_journal", "恢复记录中的账号无效")
        if journal["schema"] == 2:
            self._recover_move(journal, stage, old)
        elif journal.get("phase") == "committed":
            # Durable current metadata won; only transaction-owned old copies remain.
            if old.exists(): shutil.rmtree(old)
            if stage.exists(): shutil.rmtree(stage)
        else:
            if old.exists():
                if self.paths.active.exists():
                    # Preserve any post-launch writes instead of silently deleting them.
                    saved = self.paths.accounts / ("recovered-" + journal["token"])
                    if saved.exists(): raise SwitcherError("recovery_conflict", "已有同名恢复资料")
                    os.replace(self.paths.active, saved)
                os.replace(old, self.paths.active)
            elif not journal["had_active"] and self.paths.active.exists() and journal["phase"] in ("old_moved", "installed", "launching"):
                os.replace(self.paths.active, self.paths.accounts / ("recovered-" + journal["token"]))
            atomic_json(self.paths.state, previous)
            if stage.exists(): shutil.rmtree(stage)
        self.paths.journal.unlink()
        sync_directory(self.paths.base)
        event(self.paths, "account", operation="recover", status="ok")
        return {"status": "ok", "message": "已恢复未完成事务；可能的新资料保留在 recovered 目录"}

    def recover(self):
        with operation_lock(self.paths, recovery="account"):
            return self._recover()

    def switch(self, target, config, *, acknowledge_unverified=False):
        from .upstream_accounts import run_switch
        return run_switch(self, target, config, acknowledge_unverified=acknowledge_unverified)

    def import_legacy(self, *, apply=False):
        root = self.paths.legacy
        reject_symlink(root, self.paths.home)
        accounts = [x for x in ("A", "B") if (root / "accounts" / x).is_dir()]
        script = self.paths.home / ".local/bin/claude-switch.sh"
        settings = {}
        if script.is_file():
            import re
            text = script.read_text()
            for old, new in (("PROXY_MODE", "proxy_mode"), ("PROXY_GROUP", "proxy_group"),
                             ("COUNTRY_TARGET", "country"), ("TZ_TARGET", "timezone"), ("LOCALE_TARGET", "locale")):
                match = re.search(r'^' + old + r'="([^"\n]*)"', text, re.M)
                if match: settings[new] = match[1]
        preview = dict(status="ok", accounts=accounts, settings=settings,
                       message="仅导入快照和配置；不停止旧后台，不删除旧数据，不修改当前 Claude 目录")
        if not apply: return preview
        with operation_lock(self.paths):
            if self.paths.journal.exists() or any(self.paths.accounts.iterdir()):
                raise SwitcherError("import_conflict", "新账号库非空或存在未完成事务")
            current_file = root / "current"
            reject_symlink(current_file, self.paths.home)
            current = current_file.read_text().strip() if current_file.exists() else None
            if current not in (None, "A", "B"): raise SwitcherError("invalid_legacy_state", "旧账号状态无效")
            from .common import load_config, validate_config
            old_config = load_config(self.paths)
            config = dict(old_config, **settings)
            config = validate_config(config)
            completed = []
            try:
                for account in accounts:
                    target = self.paths.accounts / account
                    target.mkdir(mode=0o700)
                    completed.append(target)
                    manifest = self._copy(root / "accounts" / account, target / "profile")
                    write_account_manifest(target / "manifest.json", {"schema": 1, "files": manifest, "source": "legacy"})
            except Exception:
                for target in completed:
                    shutil.rmtree(target)
                raise
            atomic_json(self.paths.state, {"schema": 1, "current": current, "imported": True})
            atomic_json(self.paths.config, config)
            history_file = root / "iphistory.log"
            reject_symlink(history_file, self.paths.home)
            if history_file.is_file() and history_file.stat().st_size <= 2_000_000:
                from .audit import public_ip
                history = []
                for line in history_file.read_text().splitlines():
                    fields = line.split()
                    if len(fields) == 2 and public_ip(fields[0]):
                        try: stamp = float(fields[1])
                        except ValueError: continue
                        if 0 <= time.time() - stamp <= 172800:
                            history.append({"time": stamp, "ip": public_ip(fields[0])})
                atomic_json(self.paths.base / "ip-history.json", sorted(history, key=lambda x:x["time"])[-2048:])
            event(self.paths, "account", operation="import", status="ok", count=len(accounts))
        return preview
