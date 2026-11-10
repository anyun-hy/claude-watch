#!/usr/bin/env python3
"""Bounded local logs for the existing user-run reinstall command.

No command arguments are persisted. Console bytes remain unchanged; only the
saved copy is filtered. Filtering cannot prove arbitrary output contains no
secrets, so support exports should select run.json's safe fields only.
"""
from __future__ import annotations
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

LIMIT = 512 * 1024
KEEP = 5
MAX_LINE = 32 * 1024
RUN_NAME = re.compile(r"reinstall-\d{8}-\d{6}-[0-9a-f]{8}\Z")
KNOWN = {"run.json", "build.log", "build.log.1", "install.log", "install.log.1"}
SENSITIVE = re.compile(r"authorization|proxy.authorization|cookie|password|passwd|secret|access.token|refresh.token|api.key|credential|bearer\s|sk-[A-Za-z0-9]", re.I)
URL = re.compile(r"\b(?:https?|socks5h?)://[^\s\"'<>]+", re.I)
EMAIL = re.compile(r"\b[^\s@]+@[^\s@]+\.[^\s@]+\b")


def warning() -> None:
    try:
        print("Watch 安装日志不可用；原操作继续，退出状态不变。", file=sys.stderr, flush=True)
    except OSError:
        pass


def check(path: Path, directory: bool) -> None:
    info = path.lstat()
    if info.st_uid != os.getuid() or stat.S_ISLNK(info.st_mode) or info.st_mode & 0o077:
        raise OSError("untrusted log path")
    if directory != stat.S_ISDIR(info.st_mode) or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1)):
        raise OSError("unexpected log type")


def private_dir(path: Path) -> None:
    if not path.exists():
        path.mkdir(mode=0o700)
    check(path, True)


def known_run(path: Path) -> None:
    if not RUN_NAME.fullmatch(path.name):
        raise OSError("unknown log directory")
    check(path, True)
    for entry in path.iterdir():
        if entry.name not in KNOWN:
            raise OSError("unknown log file")
        check(entry, False)


def atomic_summary(path: Path, value: dict) -> None:
    check(path.parent, True)
    data = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    if len(data) > 16 * 1024:
        raise OSError("summary bound")
    if path.exists():
        check(path, False)
    temporary = path.with_name(".summary-" + uuid.uuid4().hex)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def initialize(home: Path, base: Path | None = None, version: str | None = None, build: str | None = None) -> Path:
    # Only the dedicated installer subdirectory is created. The product's
    # reset deletes ClaudeWatch logs, never this independent run directory.
    if base is None:
        library = home / "Library"
        logs = library / "Logs"
        for parent in (home, library, logs):
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise OSError("untrusted log parent")
        base = logs / "ClaudeWatchInstaller"
    private_dir(base)
    runs = []
    for path in base.iterdir():
        if RUN_NAME.fullmatch(path.name):
            known_run(path)
            runs.append(path)
    # Keep only known, wholly owned log artifacts. Unknown files are preserved.
    remove_count = max(0, len(runs) - KEEP + 1)
    completed = []
    for old in sorted(runs):
        summary = old / "run.json"
        if summary.stat().st_size > 16 * 1024:
            raise OSError("oversize previous summary")
        try:
            record = json.loads(summary.read_bytes())
        except (ValueError, TypeError):
            raise OSError("invalid previous summary") from None
        if record.get("status") == "failed" or (record.get("phase") == "install" and record.get("status") == "passed"):
            completed.append(old)
    if len(completed) < remove_count:
        raise OSError("active or unfinished log retention limit reached")
    for old in completed[:remove_count]:
        for child in old.iterdir():
            child.unlink()
        old.rmdir()
    name = "reinstall-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
    run = base / name
    run.mkdir(mode=0o700)
    atomic_summary(run / "run.json", {"schema": 1, "component": "claude-watch-reinstaller", "run_id": name, "target_version": version if version and re.fullmatch(r"[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}", version) else None, "target_build": build if build and re.fullmatch(r"[0-9]{1,10}", build) else None, "started_at": dt.datetime.now(dt.timezone.utc).isoformat(), "status": "running", "phases": [], "saved_output": "bounded_filtered_not_guaranteed_secret_free"})
    return run


def filtered(line: bytes, home: str) -> bytes:
    text = line.decode("utf-8", "replace")
    if SENSITIVE.search(text):
        return b"[sensitive output omitted]\n"
    def clean_url(match: re.Match) -> str:
        from urllib.parse import urlsplit
        try:
            value = urlsplit(match.group())
            return value.scheme + "://" + (value.hostname or "[host]") + "/[path-and-query-omitted]"
        except ValueError:
            return "[URL omitted]"
    text = URL.sub(clean_url, text)
    text = EMAIL.sub("[email omitted]", text)
    if home:
        text = text.replace(home, "$HOME")
    # Terminal control sequences need not be persisted in a diagnostic file.
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return text.encode("utf-8")


class SavedOutput:
    def __init__(self, run: Path, phase: str, home: str, limit: int = LIMIT):
        known_run(run)
        self.path = run / (phase + ".log")
        self.home = home
        self.limit = limit
        self.pending = bytearray()
        self.dropping = False
        self.rotated = False
        self.omitted_lines = 0
        self.available = True

    def _write(self, data: bytes) -> None:
        if self.path.exists():
            check(self.path, False)
            if self.path.stat().st_size + len(data) > self.limit:
                previous = self.path.with_name(self.path.name + ".1")
                if previous.exists():
                    check(previous, False)
                    previous.unlink()
                self.path.rename(previous)
                self.rotated = True
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "ab") as output:
            output.write(data)

    def feed(self, block: bytes, final: bool = False) -> None:
        if not self.available:
            return
        try:
            for part in block.splitlines(keepends=True):
                ended = part.endswith((b"\n", b"\r"))
                if not self.dropping:
                    self.pending.extend(part)
                    if len(self.pending) > min(MAX_LINE, self.limit // 2):
                        self.pending.clear()
                        self.dropping = True
                        self.omitted_lines += 1
                if ended:
                    self._write(b"[oversize output line omitted]\n" if self.dropping else filtered(bytes(self.pending), self.home))
                    self.pending.clear()
                    self.dropping = False
            if final and (self.pending or self.dropping):
                self._write(b"[oversize output line omitted]\n" if self.dropping else filtered(bytes(self.pending), self.home) + b"\n")
                self.pending.clear()
                self.dropping = False
        except OSError:
            self.available = False
            warning()


def update(run: Path | None, phase: str, status: str, code: int | None, elapsed: float, saved: SavedOutput | None, reason: str | None = None) -> None:
    if run is None:
        return
    try:
        known_run(run)
        path = run / "run.json"
        if path.stat().st_size > 16 * 1024:
            raise OSError("summary exceeds bound")
        value = json.loads(path.read_bytes())
        if value.get("schema") != 1 or not isinstance(value.get("phases"), list) or len(value["phases"]) > 8:
            raise OSError("invalid summary")
        value["status"] = "running" if phase == "build" and status == "passed" else status
        value["phase"] = phase
        value["phases"].append({"phase": phase, "status": status, "exit_code": code, "elapsed_ms": round(elapsed * 1000), "reason": reason if reason in {"command_start_failed"} else "child_exit_nonzero" if code else "phase_started" if status == "running" else "phase_completed", "log_available": bool(saved and saved.available), "log_rotated": bool(saved and saved.rotated), "omitted_lines": saved.omitted_lines if saved else 0})
        atomic_summary(path, value)
    except (OSError, ValueError, TypeError, KeyError):
        warning()


def run_phase(run: Path | None, phase: str, command: list[str], home: str) -> int:
    if phase not in {"build", "install"} or not command:
        raise ValueError("invalid phase")
    saved = None
    if run:
        try:
            saved = SavedOutput(run, phase, home)
        except OSError:
            warning()
    started = time.monotonic()
    update(run, phase, "running", None, 0, saved)
    try:
        print(f"Watch {phase} 日志：{run if run else '不可用'}", flush=True)
    except OSError:
        pass
    try:
        # stdin remains the original terminal: the Rust confirmation and sudo
        # password prompt must not receive a pipe, and input is never logged.
        child = subprocess.Popen(command, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError:
        update(run, phase, "failed", 127, time.monotonic()-started, saved, "command_start_failed")
        print("Watch 阶段命令无法启动。", file=sys.stderr, flush=True)
        return 127
    assert child.stdout is not None
    try:
        while True:
            block = os.read(child.stdout.fileno(), 16384)
            if not block:
                break
            try:
                sys.stdout.buffer.write(block)
                sys.stdout.buffer.flush()
            except OSError:
                # A closed console must not stop the owned installer child.
                pass
            if saved:
                saved.feed(block)
        code = child.wait()
    except KeyboardInterrupt:
        # Terminal SIGINT reaches the child's process group too. Do not force
        # terminate an installer/root transaction; observe its actual exit.
        code = child.wait()
    finally:
        child.stdout.close()
        if saved:
            saved.feed(b"", final=True)
    code = code if code >= 0 else 128-code
    update(run, phase, "passed" if code == 0 else "failed", code, time.monotonic()-started, saved)
    try:
        print(f"Watch {phase} {'完成' if code == 0 else '失败'}（退出码 {code}）；结果：{run / 'run.json' if run else '日志不可用'}", flush=True)
    except OSError:
        pass
    return code


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--run")
    parser.add_argument("--version")
    parser.add_argument("--build")
    parser.add_argument("--phase", choices=("build", "install"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    home = Path.home()
    if args.init:
        try:
            print(initialize(home, version=args.version, build=args.build))
        except OSError:
            warning()
        return 0
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    return run_phase(Path(args.run) if args.run else None, args.phase, command, str(home))


if __name__ == "__main__":
    raise SystemExit(main())
