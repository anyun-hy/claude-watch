"""Pinned-key complete-release updates with a recoverable component journal."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import plistlib
import shutil
import stat
import tempfile
import time
import urllib.parse
import zipfile
from pathlib import Path

from .common import SwitcherError, atomic_json, event, operation_lock, read_json, reject_symlink

MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_EXPANDED = 2 * MAX_ARCHIVE
APP_NAME = "Claude Watch Monitor.app"


def file_hash(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): value.update(block)
    return value.hexdigest()


def safe_https(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise SwitcherError("unsafe_update_url", "更新地址必须是无凭据的 HTTPS 地址")
    return parsed


def verify_envelope(envelope, public_key, system, directory):
    if "-----BEGIN PUBLIC KEY-----" not in public_key or len(public_key) > 16384:
        raise SwitcherError("update_key_missing", "需要固定的发布公钥，不能仅信任同源 SHA256")
    try:
        payload = base64.b64decode(envelope["manifest"], validate=True)
        signature = base64.b64decode(envelope["signature"], validate=True)
        if len(payload) > 2_000_000 or len(signature) > 8192: raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise SwitcherError("invalid_release", "更新清单格式错误")
    key, data, sig = [directory / x for x in ("public.pem", "manifest.json", "manifest.sig")]
    key.write_text(public_key); data.write_bytes(payload); sig.write_bytes(signature)
    try:
        system.run(["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(key),
                    "-signature", str(sig), str(data)])
    except SwitcherError as exc:
        raise SwitcherError("release_signature_invalid", "更新签名不符合固定发布公钥") from exc
    try: manifest = json.loads(payload)
    except ValueError: raise SwitcherError("invalid_release", "签名清单不是有效 JSON")
    if manifest.get("schema") != 1 or manifest.get("runtime_schema") != 1 or manifest.get("admin_abi") != 1:
        raise SwitcherError("release_incompatible", "更新协议、数据格式或管理组件接口不兼容")
    if not isinstance(manifest.get("files"), dict) or not manifest["files"]:
        raise SwitcherError("invalid_release", "缺少完整文件清单")
    if manifest.get("architecture") not in (platform.machine(), "universal"):
        raise SwitcherError("architecture_mismatch", "更新包架构不匹配")
    return manifest


def extract_verified(archive, destination, manifest):
    expected = manifest["files"]
    seen, expanded = set(), 0
    with zipfile.ZipFile(archive) as stream:
        for member in stream.infolist():
            name = member.filename
            path = Path(name)
            if (path.is_absolute() or ".." in path.parts or "\\" in name or "\x00" in name
                    or name in seen or not path.parts or path.parts[0] not in ("app", "runtime", "claude-watch.sh")):
                raise SwitcherError("unsafe_archive", "更新包包含不安全或重复路径")
            seen.add(name)
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                raise SwitcherError("unsafe_archive", "更新包含链接或特殊文件")
            expanded += member.file_size
            if expanded > MAX_EXPANDED or len(seen) > 100_000:
                raise SwitcherError("oversize_release", "更新包超过大小或文件数上限")
            target = destination / path
            if member.is_dir(): target.mkdir(parents=True, exist_ok=True); continue
            if name not in expected: raise SwitcherError("unlisted_file", "更新包存在未签名列出的文件")
            target.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256()
            with stream.open(member) as source, target.open("xb") as output:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk); output.write(chunk)
            if digest.hexdigest() != expected[name]:
                raise SwitcherError("release_hash_mismatch", "更新文件校验失败")
            target.chmod(0o755 if mode & 0o111 else 0o644)
    actual = {str(x.relative_to(destination)) for x in destination.rglob("*") if x.is_file()}
    if actual != set(expected):
        raise SwitcherError("release_incomplete", "更新包文件缺失")
    required = ("claude-watch.sh", "runtime/switcher.py", "runtime/watch-admin.sh",
                "runtime/watch-process-control", "app/" + APP_NAME + "/Contents/Info.plist")
    if any(not (destination / name).is_file() for name in required):
        raise SwitcherError("release_incomplete", "更新包缺少界面或后台组件")


def version_tuple(value):
    import re
    if not isinstance(value, str) or not re.fullmatch(r"\d+\.\d+\.\d+", value):
        raise SwitcherError("invalid_release_version", "版本号必须为三段数字")
    return tuple(map(int, value.split(".")))


class Updater:
    def __init__(self, paths, system, app_path=None, health=None):
        self.paths, self.system = paths, system
        self.app = Path(app_path or "/Applications/" + APP_NAME)
        self.health = health or self._health

    def _health(self):
        result = self.system.run(["/bin/bash", str(self.paths.backend), "switcher", "self-check"], timeout=15)
        if json.loads(result.stdout).get("status") != "ok":
            raise SwitcherError("update_health_failed", "更新后的组件自检未通过")
        label = "gui/" + str(os.getuid()) + "/io.local.claudewatch.agent"
        if self.system.run(["/bin/launchctl", "print", label], check=False).returncode == 0:
            heartbeat = self.paths.watch / "state/heartbeat"
            try: previous = heartbeat.read_text().split("|")[:2]
            except OSError: previous = []
            self.system.run(["/bin/launchctl", "kickstart", "-k", label])
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try: current = heartbeat.read_text().split("|")[:2]
                except OSError: current = []
                if current and current != previous and self.system.backend_healthy(): return
                time.sleep(0.5)
            raise SwitcherError("update_health_failed", "新版后台未产生有效心跳")

    def _download(self, url, target, limit):
        safe_https(url)
        self.system.run(["/usr/bin/curl", "--disable", "--fail", "--silent", "--show-error",
                         "--proto", "=https", "--max-time", "120", "--max-filesize", str(limit),
                         "--output", str(target), url], timeout=125)
        if target.stat().st_size > limit:
            raise SwitcherError("oversize_release", "下载内容过大")

    def check(self, config, *, apply=False, automatic=False):
        if automatic and not config["auto_update"]: return {"status": "disabled"}
        if not config["update_url"] or not config["update_public_key"]:
            return {"status": "unconfigured", "message": "尚未配置自有发布源和固定公钥；未连接上游 main"}
        with operation_lock(self.paths):
            if self.paths.journal.exists() or (self.paths.base / "update-transaction.json").exists():
                raise SwitcherError("recovery_required", "先恢复未完成事务")
            with tempfile.TemporaryDirectory(prefix="update-", dir=self.paths.base) as directory:
                directory = Path(directory)
                envelope_file = directory / "release.json"
                self._download(config["update_url"], envelope_file, 3_000_000)
                envelope = read_json(envelope_file, limit=3_000_000)
                manifest = verify_envelope(envelope, config["update_public_key"], self.system, directory)
                current = read_json(self.paths.base / "release.json")
                if current is None:
                    try:
                        installed_info = plistlib.loads((self.app / "Contents/Info.plist").read_bytes())
                        current = {"version": installed_info["CFBundleShortVersionString"]}
                    except (OSError, ValueError, KeyError):
                        current = {"version": "0.0.0"}
                if version_tuple(manifest["version"]) <= version_tuple(current["version"]):
                    return {"status": "current", "version": current["version"]}
                minimum = tuple(int(x) for x in manifest.get("minimum_macos", "13.0").split("."))
                installed = tuple(int(x) for x in (platform.mac_ver()[0] or "0.0").split("."))
                if installed < minimum: raise SwitcherError("os_incompatible", "系统版本低于更新包要求")
                address = safe_https(manifest["archive_url"])
                origin = safe_https(config["update_url"])
                if address.netloc != origin.netloc:
                    raise SwitcherError("update_origin_mismatch", "清单与更新包必须来自同一已配置发布源")
                if not apply: return {"status": "available", "version": manifest["version"]}
                for p in self.system.processes():
                    if p["executable"].startswith(str(self.app) + "/"):
                        return {"status": "deferred", "message": "退出监控界面后可应用完整更新", "version": manifest["version"]}
                archive = directory / "release.zip"
                self._download(manifest["archive_url"], archive, MAX_ARCHIVE)
                if file_hash(archive) != manifest.get("archive_sha256"):
                    raise SwitcherError("archive_hash_mismatch", "更新包整体校验失败")
                extracted = directory / "payload"; extracted.mkdir()
                extract_verified(archive, extracted, manifest)
                root_helper = Path("/Library/Application Support/ClaudeWatch/claude-watch-admin.sh")
                if root_helper.exists() and file_hash(root_helper) != manifest["files"]["runtime/watch-admin.sh"]:
                    return {"status": "administrator_required",
                            "message": "系统组件需要管理员升级；整包尚未应用，请使用已校验安装包完成升级",
                            "version": manifest["version"]}
                self.system.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(extracted / "app" / APP_NAME)])
                info = plistlib.loads((extracted / "app" / APP_NAME / "Contents/Info.plist").read_bytes())
                if info.get("CFBundleIdentifier") != "io.local.watchpanel" or info.get("CFBundleShortVersionString") != manifest["version"]:
                    raise SwitcherError("release_identity_mismatch", "签名清单与应用身份或版本不匹配")
                return self.apply_payload(extracted, manifest)

    def apply_payload(self, source, manifest):
        """Caller owns operation_lock. Each rename is journaled and reversible."""
        targets = [(source / "app" / APP_NAME, self.app),
                   (source / "runtime", self.paths.watch / "runtime"),
                   (source / "claude-watch.sh", self.paths.backend)]
        records = []
        for incoming, target in targets:
            reject_symlink(target)
            stage = target.with_name(target.name + ".cw-new")
            old = target.with_name(target.name + ".cw-old")
            if stage.exists() or old.exists():
                raise SwitcherError("update_conflict", "发现未清理的组件事务目录")
            records.append(dict(target=str(target), stage=str(stage), old=str(old), existed=target.exists(), started=False))
        journal = {"schema": 1, "phase": "prepared", "records": records, "version": manifest["version"],
                   "previous_release": read_json(self.paths.base / "release.json")}
        journal_path = self.paths.base / "update-transaction.json"
        atomic_json(journal_path, journal)
        try:
            for (incoming, _), record in zip(targets, records):
                stage, target, old = (Path(record[k]) for k in ("stage", "target", "old"))
                record["started"] = True
                atomic_json(journal_path, journal)
                if incoming.is_dir(): shutil.copytree(incoming, stage)
                else: shutil.copy2(incoming, stage)
                if record["existed"]: os.replace(target, old)
                os.replace(stage, target)
            self.health()
            self.reset_replaced_app_accessibility()
            atomic_json(self.paths.base / "release.json", {"version": manifest["version"], "runtime_schema": 1})
            journal["phase"] = "committed"
            atomic_json(journal_path, journal)
            self.recover()
            event(self.paths, "update", status="ok", version=manifest["version"])
            return {"status": "ok", "version": manifest["version"], "message": "完整组件已更新并通过组件自检；不代表账号实机验收"}
        except Exception:
            self.recover()
            label = "gui/" + str(os.getuid()) + "/io.local.claudewatch.agent"
            if self.system.run(["/bin/launchctl", "print", label], check=False).returncode == 0:
                self.system.run(["/bin/launchctl", "kickstart", "-k", label], check=False)
            raise

    def reset_replaced_app_accessibility(self):
        # The native app requests access again on next launch. No other TCC
        # service or application is reset; isolated/custom-path updates skip OS state.
        if self.app != Path('/Applications/' + APP_NAME): return
        self.system.run(['/usr/bin/tccutil', 'reset', 'Accessibility', 'io.local.watchpanel'])
        self.system.run(['/usr/bin/defaults', 'delete', 'io.local.watchpanel', 'accessibilityPromptedBuild'], check=False)

    def recover(self):
        journal_path = self.paths.base / "update-transaction.json"
        journal = read_json(journal_path)
        if not journal: return {"status": "ok", "message": "没有更新事务"}
        expected = [self.app, self.paths.watch / "runtime", self.paths.backend]
        records = journal.get("records", [])
        if journal.get("schema") != 1 or len(records) != 3:
            raise SwitcherError("invalid_update_journal", "更新恢复记录无效")
        for record, target in zip(records, expected):
            for key, suffix in (("target", ""), ("stage", ".cw-new"), ("old", ".cw-old")):
                desired = target.with_name(target.name + suffix)
                if record.get(key) != str(desired): raise SwitcherError("invalid_update_journal", "更新恢复路径无效")
                reject_symlink(desired)
        def remove(path):
            if path.is_dir(): shutil.rmtree(path)
            elif path.exists(): path.unlink()
        for record in reversed(records):
            target, old, stage = (Path(record[k]) for k in ("target", "old", "stage"))
            if journal["phase"] == "committed":
                remove(old)
            elif old.exists():
                remove(target); os.replace(old, target)
            elif record.get("started") and not record["existed"] and not stage.exists():
                remove(target)
            remove(stage)
        if journal["phase"] != "committed":
            previous = journal.get("previous_release")
            if previous is not None: atomic_json(self.paths.base / "release.json", previous)
            else: (self.paths.base / "release.json").unlink(missing_ok=True)
        journal_path.unlink()
        return {"status": "ok", "message": "更新事务已恢复"}
