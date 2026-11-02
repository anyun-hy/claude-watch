#!/usr/bin/env python3
"""User-run Claude Watch full reset, arm64 Rust package, and install."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class Stop(Exception):
    pass


@dataclass(frozen=True)
class Layout:
    home: Path
    app: Path
    system_root: Path
    system_plist: Path
    project: Path
    temporary: Path
    system_uid: int = 0

    @property
    def base(self) -> Path:
        return self.home / "Library/Application Support/ClaudeWatch"

    @property
    def trash(self) -> Path:
        return self.home / ".Trash"

    @property
    def agent(self) -> Path:
        return self.home / "Library/LaunchAgents/io.local.claudewatch.agent.plist"

    @property
    def updater(self) -> Path:
        return self.home / "Library/LaunchAgents/io.local.claudewatch.update.plist"

    @property
    def helper(self) -> Path:
        return self.system_root / "claude-watch-admin.sh"

    def data_paths(self) -> list[Path]:
        return [
            self.base,
            self.home / "Library/Preferences/io.local.watchpanel.plist",
            self.home / "Library/Logs/ClaudeWatch",
            self.home / "Library/Caches/io.local.watchpanel",
            self.home / "Library/WebKit/io.local.watchpanel",
            self.home / "Library/HTTPStorages/io.local.watchpanel",
            self.home / "Library/Saved Application State/io.local.watchpanel.savedState",
            self.home / "Library/Containers/io.local.watchpanel",
            self.home / "Library/Application Scripts/io.local.watchpanel",
        ]


class Runner:
    def locate(self, name: str) -> Optional[str]:
        return shutil.which(name)

    def run(self, args: list[str], *, capture: bool = False, env: Optional[dict[str, str]] = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(args, text=True, capture_output=capture, env=env, check=False)
        except OSError as error:
            raise Stop(f"无法执行 {Path(args[0]).name}：{error.strerror or '系统错误'}") from error


def exists(path: Path) -> bool:
    return os.path.lexists(path)


def safe_user_path(path: Path, home: Path, uid: int) -> None:
    try:
        path.relative_to(home)
    except ValueError as error:
        raise Stop(f"路径不在当前用户目录内：{path}") from error
    for part in (path, *path.parents):
        if part.is_symlink():
            raise Stop(f"路径或其父目录是符号链接：{part}")
        if part == home:
            break
    if exists(path):
        info = path.lstat()
        if info.st_uid != uid or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise Stop(f"路径归属或类型不匹配：{path}")


def read_plist(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise Stop(f"信息文件不存在或不是普通文件：{path}")
    try:
        value = plistlib.loads(path.read_bytes())
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        raise Stop(f"信息文件无法读取：{path}") from error
    if not isinstance(value, dict):
        raise Stop(f"信息文件格式无效：{path}")
    return value


def digest(path: Path) -> str:
    value = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                value.update(block)
    except OSError as error:
        raise Stop(f"无法校验文件：{path}") from error
    return value.hexdigest()


def loaded(runner: Runner, label: str) -> bool:
    result = runner.run(["/bin/launchctl", "print", label], capture=True)
    if result.returncode == 0:
        return True
    if result.returncode == 113:
        return False
    raise Stop(f"无法确认后台任务状态：{label}（退出码 {result.returncode}）")


def process_rows(runner: Runner, uid: int) -> list[str]:
    result = runner.run(["/bin/ps", "-axo", "uid=,command="], capture=True)
    if result.returncode != 0:
        raise Stop("无法检查当前进程。")
    rows = []
    for line in result.stdout.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and fields[0] == str(uid):
            rows.append(fields[1])
    return rows


def check_no_conflicting_work(layout: Layout, runner: Runner, uid: int) -> None:
    for command in process_rows(runner, uid):
        if "/Claude.app/Contents/MacOS/Claude" in command:
            raise Stop("请先正常退出 Claude，再执行完整重置。")
        if any(name in command for name in ("monitor/package-dmg.sh", "monitor/build.sh", "tools/build-rust-components.sh")):
            raise Stop("发现其他打包或编译操作正在进行，请等它完成。")


def check_transactions(layout: Layout) -> None:
    for name in ("transaction.json", "setup-transaction.json", "update-transaction.json", "service-transaction.json"):
        if exists(layout.base / "switcher" / name):
            raise Stop(f"发现未完成的 Watch 事务：{name}")
    for name in ("agent-install-transaction.json", ".runtime.previous"):
        if exists(layout.base / name):
            raise Stop(f"发现未完成的后台事务：{name}")


def check_helper(layout: Layout, runner: Runner, app_present: bool) -> Optional[str]:
    job_loaded = loaded(runner, "system/io.local.claudewatch.timezone")
    system_paths = [layout.system_root, layout.helper, layout.system_plist]
    if any(part.is_symlink() for path in system_paths for part in (path, *path.parents)):
        raise Stop("Watch 系统辅助组件路径是符号链接。")
    if not exists(layout.system_root) and not exists(layout.system_plist) and not job_loaded:
        return None
    if not app_present or not layout.system_root.is_dir() or not layout.helper.is_file():
        raise Stop("Watch 系统辅助组件不完整，请先检查残留。")
    root_info, helper_info = layout.system_root.lstat(), layout.helper.lstat()
    if root_info.st_uid != layout.system_uid or stat.S_IMODE(root_info.st_mode) & 0o022:
        raise Stop("Watch 系统辅助目录的归属或权限异常。")
    if helper_info.st_uid != layout.system_uid or stat.S_IMODE(helper_info.st_mode) != 0o755:
        raise Stop("Watch 系统辅助程序的归属或权限异常。")
    if {item.name for item in layout.system_root.iterdir()} - {"claude-watch-admin.sh", "timezone.target", "timezone.last-success"}:
        raise Stop("Watch 系统辅助目录包含未知文件，请先检查。")
    for child in layout.system_root.iterdir():
        if child.is_symlink() or child.lstat().st_uid != layout.system_uid or not child.is_file():
            raise Stop("Watch 系统辅助目录中有无法确认的文件。")
    bundled = layout.app / "Contents/Resources/watch-admin.sh"
    if bundled.is_symlink() or not bundled.is_file() or digest(bundled) != digest(layout.helper):
        raise Stop("系统辅助程序与已安装应用不一致。")
    if exists(layout.system_plist):
        info = layout.system_plist.lstat()
        value = read_plist(layout.system_plist)
        arguments = ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "/bin/bash", "--noprofile", "--norc", str(layout.helper), "tick"]
        if info.st_uid != layout.system_uid or stat.S_IMODE(info.st_mode) & 0o022 or value.get("Label") != "io.local.claudewatch.timezone" or value.get("ProgramArguments") != arguments:
            raise Stop("Watch 系统时区任务身份不匹配。")
    elif job_loaded:
        raise Stop("Watch 系统时区任务已加载，但定义文件缺失。")
    return digest(layout.helper)


def app_identity(app: Path) -> tuple[str, str]:
    if app.is_symlink() or not app.is_dir():
        raise Stop("已安装应用不是普通目录。")
    info = read_plist(app / "Contents/Info.plist")
    manifest = read_plist(app / "Contents/Resources/BuildInfo.plist")
    if info.get("CFBundleIdentifier") != "io.local.watchpanel" or info.get("CFBundleExecutable") != "ClaudeWatchMonitor":
        raise Stop("已安装应用身份不匹配。")
    if manifest.get("BackendVariant") != "rust-candidate" or manifest.get("Architecture") != "arm64":
        raise Stop("此脚本只支持 arm64 Rust 候选版，请先检查当前应用。")
    version, build = info.get("CFBundleShortVersionString"), info.get("CFBundleVersion")
    if not isinstance(version, str) or not isinstance(build, str) or not build:
        raise Stop("无法确认已安装应用的版本和构建号。")
    return version, build


def json_command(runner: Runner, args: list[str]) -> dict:
    result = runner.run(args, capture=True)
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    if result.returncode != 0:
        raise Stop(f"{Path(args[0]).name} 执行失败（退出码 {result.returncode}）。")
    try:
        value = json.loads(result.stdout)
    except (TypeError, ValueError) as error:
        raise Stop("安装组件返回了无法识别的结果。") from error
    if not isinstance(value, dict):
        raise Stop("安装组件返回格式无效。")
    return value


@dataclass(frozen=True)
class Plan:
    old_identity: Optional[tuple[str, str]]
    old_engine_hash: Optional[str]
    helper_hash: Optional[str]


def preflight(layout: Layout, runner: Runner, uid: int) -> Plan:
    if layout.home.is_symlink() or not layout.home.is_dir() or layout.home.stat().st_uid != uid:
        raise Stop("当前用户目录的归属或类型不匹配。")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise Stop("系统不支持安全目录清理。")
    for path in layout.data_paths() + [layout.agent, layout.updater, layout.trash]:
        safe_user_path(path, layout.home, uid)
    check_transactions(layout)
    check_no_conflicting_work(layout, runner, uid)
    if exists(layout.updater) or loaded(runner, f"gui/{uid}/io.local.claudewatch.update"):
        raise Stop("发现 Watch 更新任务；请先检查是否有更新正在进行。")
    app_present = exists(layout.app)
    old_identity = None
    engine_hash = None
    if app_present:
        if exists(layout.trash) and not layout.trash.is_dir():
            raise Stop("废纸篓不是普通目录。")
        old_identity = app_identity(layout.app)
        if layout.app.stat().st_uid != uid:
            raise Stop("已安装应用不属于当前用户，请先核对。")
        engine = layout.app / "Contents/Resources/watch-engine"
        if engine.is_symlink() or not engine.is_file() or not os.access(engine, os.X_OK):
            raise Stop("已安装应用的卸载组件无效。")
        if runner.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(layout.app)]).returncode != 0:
            raise Stop("已安装应用签名校验失败。")
        plan = json_command(runner, [str(engine), "app-uninstall"])
        if plan.get("status") != "preview" or plan.get("action") != "app-uninstall" or plan.get("installed") != str(layout.app):
            raise Stop("卸载预览与目标应用不一致。")
        engine_hash = digest(engine)
    elif any(exists(path) for path in layout.data_paths() + [layout.agent]):
        raise Stop("应用已不存在，但 Watch 数据或后台任务仍有残留；请先检查。")
    if not app_present and loaded(runner, f"gui/{uid}/io.local.claudewatch.agent"):
        raise Stop("应用已不存在，但 Watch 主后台仍在运行。")
    if not app_present and layout.trash.is_dir() and any(layout.trash.glob("ClaudeWatch-removed-*")):
        raise Stop("废纸篓中有 Watch 卸载目录；请先核查归属。")
    helper_hash = check_helper(layout, runner, app_present)
    return Plan(old_identity, engine_hash, helper_hash)


def cleanup_trashed_app(layout: Layout, uid: int, previous: str, old_identity: tuple[str, str]) -> Path:
    app = Path(previous)
    if app.name != "Claude Watch Monitor.app" or app.parent.parent != layout.trash or not re.fullmatch(r"ClaudeWatch-removed-[0-9a-f]{32}", app.parent.name):
        raise Stop("本次卸载返回的废纸篓路径不匹配。")
    safe_user_path(app.parent, layout.home, uid)
    safe_user_path(app, layout.home, uid)
    info = read_plist(app / "Contents/Info.plist")
    if info.get("CFBundleIdentifier") != "io.local.watchpanel" or info.get("CFBundleExecutable") != "ClaudeWatchMonitor" or (info.get("CFBundleShortVersionString"), info.get("CFBundleVersion")) != old_identity:
        raise Stop("废纸篓中应用的身份或版本不匹配。")
    if {item.name for item in app.parent.iterdir()} - {"Claude Watch Monitor.app", "io.local.claudewatch.agent.plist"}:
        raise Stop("本次卸载目录包含未知内容。")
    agent = app.parent / "io.local.claudewatch.agent.plist"
    if exists(agent):
        safe_user_path(agent, layout.home, uid)
        if read_plist(agent).get("Label") != "io.local.claudewatch.agent":
            raise Stop("废纸篓中的 Watch 后台任务标签不匹配。")
    return app.parent


def wait_for_watch_exit(layout: Layout, runner: Runner, uid: int, old: Optional[Path]) -> None:
    needles = [str(layout.base / "runtime") + "/", str(layout.app) + "/Contents/"]
    if old:
        needles.append(str(old) + "/Contents/")
    for attempt in range(11):
        if not any(any(needle in row for needle in needles) for row in process_rows(runner, uid)):
            return
        if attempt < 10:
            time.sleep(1)
    raise Stop("Watch 进程尚未退出，未清理数据。")


def clean_data(layout: Layout, runner: Runner, uid: int, trashed: Optional[Path]) -> None:
    if exists(layout.app) or exists(layout.system_root) or exists(layout.system_plist):
        raise Stop("应用或系统辅助组件尚未完全卸载。")
    for label in (f"gui/{uid}/io.local.claudewatch.agent", f"gui/{uid}/io.local.claudewatch.update", "system/io.local.claudewatch.timezone"):
        if loaded(runner, label):
            raise Stop(f"后台任务仍在运行：{label}")
    check_transactions(layout)
    if exists(layout.agent) or exists(layout.updater):
        raise Stop("Watch 后台任务文件仍存在。")
    wait_for_watch_exit(layout, runner, uid, trashed / "Claude Watch Monitor.app" if trashed else None)
    paths = layout.data_paths()
    for path in paths:
        safe_user_path(path, layout.home, uid)
    if trashed:
        safe_user_path(trashed, layout.home, uid)
    prefs = layout.home / "Library/Preferences/io.local.watchpanel.plist"
    read = runner.run(["/usr/bin/defaults", "read", "io.local.watchpanel"], capture=True)
    if read.returncode == 0:
        result = runner.run(["/usr/bin/defaults", "delete", "io.local.watchpanel"], capture=True)
        if result.returncode != 0:
            raise Stop("无法清理 Watch 偏好设置。")
    elif exists(prefs) or read.returncode != 1 or not any(token in (read.stderr or "").lower() for token in ("not found", "does not exist")):
        raise Stop("无法确认 Watch 偏好设置状态。")
    for path in paths:
        if path.is_dir():
            shutil.rmtree(path)
        elif exists(path):
            path.unlink()
    if trashed:
        shutil.rmtree(trashed)
    if any(exists(path) for path in paths + ([trashed] if trashed else [])):
        raise Stop("仍有 Watch 数据未能清理。")
    after = runner.run(["/usr/bin/defaults", "read", "io.local.watchpanel"], capture=True)
    if after.returncode != 1 or not any(token in (after.stderr or "").lower() for token in ("not found", "does not exist")):
        raise Stop("无法确认 Watch 偏好设置已清理。")
    for label in (f"gui/{uid}/io.local.claudewatch.agent", f"gui/{uid}/io.local.claudewatch.update", "system/io.local.claudewatch.timezone"):
        if loaded(runner, label):
            raise Stop(f"清理后后台任务仍在运行：{label}")
    wait_for_watch_exit(layout, runner, uid, None)


def acquire_lock(layout: Layout, uid: int):
    lock = layout.temporary / f"claude-watch-reinstall-{uid}.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = None
    try:
        fd = os.open(str(lock), flags, 0o600)
        info = os.fstat(fd)
        if info.st_uid != uid or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            os.close(fd)
            fd = None
            raise Stop("重装锁文件归属或类型异常。")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return os.fdopen(fd, "r+")
    except BlockingIOError as error:
        if fd is not None:
            os.close(fd)
        raise Stop("另一个重装流程正在运行。") from error
    except OSError as error:
        if fd is not None:
            os.close(fd)
        raise Stop("无法取得重装锁。") from error


def perform(layout: Layout, runner: Runner, version: str, build: str, *, dry_run: bool, confirm, uid: int, cargo: str) -> None:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or len(version) > 32:
        raise Stop("应用版本应为数字格式，例如 3.0.0。")
    if not re.fullmatch(r"[1-9][0-9]{0,8}", build):
        raise Stop("build 编号必须是正整数。")
    package_script = layout.project / "monitor/package-dmg.sh"
    required_files = [package_script, layout.project / "monitor/build.sh", layout.project / "tools/build-rust-components.sh",
                      layout.project / "Cargo.toml", layout.project / "Cargo.lock", layout.project / "monitor/Resources/AppIcon.icns",
                      layout.project / "monitor/macos-minimum.txt"]
    if any(path.is_symlink() or not path.is_file() for path in required_files) or not Path(cargo).is_file() or not os.access(cargo, os.X_OK):
        raise Stop("未找到打包脚本或可执行的 Cargo。")
    tools = {name: runner.locate(name) for name in ("xcrun", "xcode-select", "hdiutil", "shasum", "plutil", "python3")}
    if any(path is None for path in tools.values()):
        raise Stop("缺少 Xcode 或打包所需的系统工具。")
    compiler = runner.run([tools["xcrun"], "--find", "swiftc"], capture=True)
    sdk = runner.run([tools["xcrun"], "--sdk", "macosx", "--show-sdk-path"], capture=True)
    if compiler.returncode != 0 or not compiler.stdout.strip() or sdk.returncode != 0 or not sdk.stdout.strip():
        raise Stop("无法确认 Swift 编译器或 macOS SDK。")
    for directory in (layout.project / "monitor/build", layout.project / "monitor/dist"):
        if directory.is_symlink() or (exists(directory) and not directory.is_dir()):
            raise Stop(f"构建目录不是普通目录：{directory}")
        existing = directory if directory.exists() else directory.parent
        if not os.access(existing, os.W_OK | os.X_OK):
            raise Stop(f"构建目录不可写：{existing}")
    tag = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    app_out = layout.project / "monitor/build" / f"Claude Watch Monitor build{build}-{tag}.app"
    dmg_name = f"Claude-Watch-{version}-build{build}-{tag}-arm64.dmg"
    dmg = layout.project / "monitor/dist" / dmg_name
    sha = Path(str(dmg) + ".sha256")
    if any(exists(path) for path in (app_out, dmg, sha)):
        raise Stop("本次输出路径已存在，未覆盖。")
    plan = preflight(layout, runner, uid)
    old = f"{plan.old_identity[0]} / build {plan.old_identity[1]}" if plan.old_identity else "当前未安装"
    print(f"当前：{old}；目标：{version} / build {build}（arm64 Rust 候选版）。")
    print("将永久删除 Claude Watch 的设置、日志、A/B 快照及其自有后台；保留 Claude 登录、TAG 配置和独立原版工具。")
    print("流程先卸载再打包；如果打包失败，旧应用已卸载，请保留输出并检查当前状态。")
    if dry_run:
        print("预演通过：没有卸载、删除、打包或安装。")
        return
    if confirm("输入 y/N 重置并安装继续，其他输入取消：").strip().lower() != "y":
        print("已取消，没有执行重置。")
        return
    with acquire_lock(layout, uid):
        current = preflight(layout, runner, uid)
        if current != plan:
            raise Stop("确认后安装状态发生变化；未执行卸载。")
        trashed = None
        if plan.old_identity:
            engine = layout.app / "Contents/Resources/watch-engine"
            result = json_command(runner, [str(engine), "app-uninstall", "--apply"])
            if result.get("status") != "ok" or result.get("action") != "app-uninstall" or not isinstance(result.get("previous"), str):
                raise Stop("卸载结果未确认；请检查当前状态。")
            trashed = cleanup_trashed_app(layout, uid, result["previous"], plan.old_identity)
        if plan.helper_hash:
            if layout.helper.is_symlink() or not layout.helper.is_file() or digest(layout.helper) != plan.helper_hash:
                raise Stop("系统辅助组件已变化；未继续清理。")
            print("正在卸载 Watch 系统辅助组件；可能需要管理员密码。")
            if runner.run(["/usr/bin/sudo", str(layout.helper), "uninstall"]).returncode != 0:
                raise Stop("系统辅助组件卸载未完成；本地数据保留。")
        clean_data(layout, runner, uid, trashed)
        print("Watch 卸载与数据清理完成。")
        if any(exists(path) for path in (app_out, dmg, sha)):
            raise Stop("本次输出路径已存在，未覆盖。")
        env = os.environ.copy()
        env.update(APP_VERSION=version, BUILD_NUMBER=build, CW_BUILD_ARCH="arm64", CW_BACKEND_VARIANT="rust-candidate", CW_CARGO_BIN=cargo, CW_APP_OUTPUT=str(app_out), DMG_NAME=dmg_name)
        print(f"正在打包 {version} / build {build}。")
        if runner.run(["/bin/bash", str(package_script)], env=env).returncode != 0:
            raise Stop("打包失败，未执行安装。")
        if app_identity(app_out) != (version, build) or dmg.is_symlink() or sha.is_symlink() or not dmg.is_file() or not sha.is_file():
            raise Stop("打包产物或版本不匹配，未执行安装。")
        checksum = sha.read_text().split()
        if not checksum or not re.fullmatch(r"[0-9a-f]{64}", checksum[0]) or digest(dmg) != checksum[0]:
            raise Stop("DMG 校验不匹配，未执行安装。")
        if runner.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app_out)]).returncode != 0:
            raise Stop("新应用签名校验失败，未执行安装。")
        # A user or another process may have installed or restarted Watch while
        # the build was running. Never replace that new state silently.
        check_no_conflicting_work(layout, runner, uid)
        check_transactions(layout)
        if any(exists(path) for path in layout.data_paths() + [layout.app, layout.agent, layout.updater, layout.system_root, layout.system_plist]):
            raise Stop("打包期间 Watch 安装或数据状态发生变化，未执行安装。")
        for label in (f"gui/{uid}/io.local.claudewatch.agent", f"gui/{uid}/io.local.claudewatch.update", "system/io.local.claudewatch.timezone"):
            if loaded(runner, label):
                raise Stop(f"打包期间后台任务重新出现，未执行安装：{label}")
        wait_for_watch_exit(layout, runner, uid, None)
        engine = app_out / "Contents/Resources/watch-engine"
        preview = json_command(runner, [str(engine), "app-install", "--source", str(app_out)])
        if preview.get("status") != "preview" or preview.get("source") != str(app_out) or preview.get("installed") != str(layout.app):
            raise Stop("安装预览不匹配，未执行安装。")
        installed = json_command(runner, [str(engine), "app-install", "--source", str(app_out), "--apply"])
        if installed.get("status") != "ok" or installed.get("version") != version or installed.get("build") != build or installed.get("architecture") != "arm64":
            raise Stop("安装结果未通过版本核对，请检查实际安装状态。")
        if app_identity(layout.app) != (version, build) or runner.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(layout.app)]).returncode != 0:
            raise Stop("已安装应用的身份、版本或签名未通过核对。")
        if not loaded(runner, f"gui/{uid}/io.local.claudewatch.agent"):
            raise Stop("应用已安装，但主后台注册状态未确认。")
        if runner.run(["/usr/bin/open", "-a", str(layout.app)]).returncode != 0:
            raise Stop("应用已安装，但未能自动打开。")
        print(f"已安装 {version} / build {build}；安装包：{dmg}")
        print("请按 macOS 提示授权；实际后台和保护功能仍需打开应用后核验。")


def main() -> int:
    parser = argparse.ArgumentParser(description="完整重置 Claude Watch 后打包并安装指定版本")
    parser.add_argument("version", help="应用版本，例如 3.0.0")
    parser.add_argument("build", help="build 编号，例如 314")
    parser.add_argument("--dry-run", action="store_true", help="只检查和显示操作，不进行修改")
    args = parser.parse_args()
    if sys.platform != "darwin" or platform.machine() != "arm64" or os.getuid() == 0:
        print("此流程需要以普通用户在 Apple Silicon macOS 上运行。", file=sys.stderr)
        return 1
    home = Path.home()
    project = Path(__file__).resolve().parent.parent
    layout = Layout(home, Path("/Applications/Claude Watch Monitor.app"), Path("/Library/Application Support/ClaudeWatch"), Path("/Library/LaunchDaemons/io.local.claudewatch.timezone.plist"), project, Path("/private/tmp"))
    cargo = os.environ.get("CW_CARGO_BIN") or str(home / ".cargo/bin/cargo")
    try:
        perform(layout, Runner(), args.version, args.build, dry_run=args.dry_run, confirm=input, uid=os.getuid(), cargo=cargo)
    except (Stop, OSError, EOFError, KeyboardInterrupt) as error:
        print(f"流程已停止：{error or '用户中断'}", file=sys.stderr)
        print("请检查终端输出；若卸载已经开始，不要重复操作，先确认当前状态。", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
