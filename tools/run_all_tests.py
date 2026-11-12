#!/usr/bin/env python3
"""Run the reviewed test inventory, retaining failures and per-step evidence.

This is test tooling, not a production Watch component. No service installation,
real AI launch, VPN modification, or live external probe is in the plan.
"""
from __future__ import annotations

import argparse
import datetime as dt
import glob
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tools/unified_swift_tests.json"


@dataclass
class Step:
    id: str
    category: str
    commands: list[list[str]] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    test_files: list[str] = field(default_factory=list)
    prepare: list[dict] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    success_markers: list[str] = field(default_factory=list)
    failure_patterns: list[str] = field(default_factory=list)
    timeout_seconds: int = 600
    excluded_reason: str | None = None
    notes: list[str] = field(default_factory=list)


class PrerequisiteError(Exception):
    pass


class Interrupted(Exception):
    pass


def clean_environment(source: dict[str, str], repo: Path, run_dir: Path) -> dict[str, str]:
    # Child-mode and opt-in live flags must not change what the parent tests run.
    env = {k: v for k, v in source.items()
           if not k.startswith(("CW_", "WATCH_", "LEAK_BRIDGE_", "UI_REVIEW_"))
           and k not in ("RUST_TEST_THREADS", "RUST_TEST_NOCAPTURE")}
    env.update(CARGO_TARGET_DIR=str(repo / "target"), PYTHONDONTWRITEBYTECODE="1",
               CARGO_TERM_COLOR="never", RUST_TEST_THREADS="1",
               TMPDIR=str(run_dir / "tmp") + "/")
    # HOME and the user's proxy configuration are deliberately not replaced.
    return env


def expand(value: str, variables: dict[str, str]) -> str:
    for key, replacement in variables.items():
        value = value.replace("{" + key + "}", replacement)
    return value


def expand_tree(value, variables: dict[str, str]):
    if isinstance(value, str):
        return expand(value, variables)
    if isinstance(value, list):
        return [expand_tree(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: expand_tree(item, variables) for key, item in value.items()}
    return value


def source_paths(patterns: list[str]) -> list[str]:
    result: list[str] = []
    for pattern in patterns:
        matches = sorted(glob.glob(str(ROOT / pattern)))
        if not matches:
            raise ValueError(f"No source matches {pattern}")
        for match in matches:
            if match not in result:
                result.append(match)
    return result


def build_plan(run_dir: Path) -> tuple[list[Step], dict]:
    manifest = json.loads(MANIFEST.read_text())
    entries = manifest["entries"]
    covered = [p for entry in entries for p in entry.get("test_files", [])]
    actual = {str(p.relative_to(ROOT)) for p in (ROOT / "monitor/tests").glob("*Tests.swift")}
    missing = sorted(actual - set(covered))
    duplicates = sorted({p for p in covered if covered.count(p) > 1})
    if missing or duplicates:
        raise ValueError(f"Swift inventory mismatch: missing={missing}; duplicate={duplicates}")
    minimum = (ROOT / "monitor/macos-minimum.txt").read_text().strip()
    variables = {"repo": str(ROOT), "run_dir": str(run_dir),
                 "engine": str(ROOT / "target/debug/claude-watch-engine")}
    cargo_env = {"CW_CHANNEL_CONTRACT_DIR": str(run_dir / "artifacts")}
    steps = [
        Step("rust.toolchain", "prerequisite", prepare=[{"kind": "installed_rust_toolchain"}],
             notes=["Require the pinned toolchain to exist; do not invoke rustup installation."]),
        Step("macos.gui_session", "prerequisite", prepare=[{"kind": "console_session"}],
             notes=["Checks console ownership only; actual GUI/sandbox errors still fail the affected fixture."]),
        Step("rust.build", "build", [["cargo", "build", "--workspace", "--locked"]],
             dependencies=["rust.toolchain"], timeout_seconds=3600),
        Step("rust.workspace", "test", [["cargo", "test", "--workspace", "--locked", "--no-fail-fast",
              "--", "--test-threads=1", "--nocapture"]], dependencies=["rust.build", "macos.gui_session"],
             environment=cargo_env, timeout_seconds=7200,
             notes=["Default Cargo tests; automatic opt-in cases have separate entries; the root launchd diagnostic requires separate authorization and is excluded.",
                    "May open owned fixture windows and terminate owned child processes."]),
        Step("rust.engine", "prerequisite", dependencies=["rust.build"], prepare=[
            {"kind": "require_file", "path": "{engine}"}]),
        Step("rust.monitor_coverage_fixture", "prerequisite", dependencies=["rust.workspace"], prepare=[
            {"kind": "require_file", "path": "{run_dir}/artifacts/monitor-coverage-wire.json"},
            {"kind": "require_file", "path": "{run_dir}/artifacts/managed-cli-unlinked-visible.json"}],
             notes=["Exported by the workspace test; no duplicate test run."]),
        Step("rust.process_protection_fixture", "prerequisite", dependencies=["rust.workspace"], prepare=[
            {"kind": "require_file", "path": "{run_dir}/artifacts/process-protection-deadlines.json"}],
             notes=["Exported by the workspace process projection test; no duplicate test run."]),
        Step("rust.mechanism_review_fixtures", "prerequisite", dependencies=["rust.workspace"], prepare=[
            {"kind": "require_file", "path": "{run_dir}/artifacts/" + name}
            for name in ("process-disposition-wire.json", "process-disposition-partial.json",
                         "process-disposition-network-failure.json", "script-gateway-wire.json",
                         "entry-product-wire.json", "process-disposition-delivery.json",
                         "process-disposition-deadline.json")],
             notes=["Production payloads from targeted owned fixtures in the Rust workspace tests."]),
        Step("rust.target_discovery_fixture", "prerequisite", dependencies=["rust.workspace"], prepare=[
            {"kind": "require_file", "path": "{run_dir}/artifacts/target-discovery-wire.json"},
            {"kind": "require_file", "path": "{run_dir}/artifacts/target-discovery-pending.json"},
            {"kind": "require_file", "path": "{run_dir}/artifacts/target-discovery-staging.json"}],
             notes=["Exported by the workspace runtime/engine discovery tests; no duplicate Cargo invocation."]),
        Step("python.tools", "test", [[sys.executable, "-m", "unittest", "discover", "-s", "tools/tests",
              "-p", "test_*.py", "-v"]], test_files=sorted(str(p.relative_to(ROOT)) for p in (ROOT / "tools/tests").glob("test_*.py"))),
        Step("python.monitor", "test", [[sys.executable, "-m", "unittest", "discover", "-s", "monitor/tests",
              "-p", "test_*.py", "-v"]], dependencies=["rust.engine"],
             test_files=sorted(str(p.relative_to(ROOT)) for p in (ROOT / "monitor/tests").glob("test_*.py"))),
        Step("contract.account_routing", "test", [[sys.executable, "tools/test-account-progress-routing.py"]]),
        Step("contract.force_routing", "test", [[sys.executable, "tools/test-force-confirmation-routing.py"]]),
        Step("contract.policy_catalog", "test", [[sys.executable, "tools/generate-ai-policy-swift.py", "--check"]]),
        Step("contract.environment_card", "test", [["bash", "monitor/tests/test_environment_card_structure.sh"]]),
        Step("build.shell_syntax", "build", [["bash", "-n", script] for script in
              ("tools/test-all.sh", "monitor/build.sh", "monitor/package-dmg.sh", "tools/build-rust-components.sh")]),
        Step("swift.production_typecheck", "build", [["xcrun", "--sdk", "macosx", "swiftc", "-swift-version", "5",
              "-parse-as-library", "-typecheck", "-target", f"arm64-apple-macosx{minimum}",
              "-module-cache-path", str(run_dir / "swift-cache"), "-framework", "SwiftUI", "-framework", "AppKit",
              "-framework", "WebKit", *source_paths(["monitor/Sources/*.swift"])]], timeout_seconds=900),
    ]
    for file in sorted((ROOT / "monitor/tests").glob("test_*.cjs")):
        steps.append(Step("js." + file.stem, "test", [["node", str(file)]], test_files=[str(file.relative_to(ROOT))]))
    for entry in entries:
        sid = entry["id"]
        work = run_dir / "artifacts" / sid
        local = {**variables, "work_dir": str(work)}
        step = Step(sid, "test", dependencies=entry.get("dependencies", []),
                    test_files=entry.get("test_files", []), prepare=entry.get("prepare", []).copy(),
                    environment=entry.get("environment", {}), success_markers=entry.get("success_markers", []),
                    failure_patterns=entry.get("failure_patterns", [r"(?m)^FAIL:"]),
                    timeout_seconds=entry.get("timeout_seconds", 600), notes=entry.get("safety_notes", []))
        if isinstance(step.notes, str):
            step.notes = [step.notes]
        if entry.get("unselected_modes"):
            step.notes.append("Unselected modes: " + json.dumps(entry["unselected_modes"], ensure_ascii=False))
        kind = entry.get("kind", "swift")
        if kind == "excluded":
            step.category = "excluded"
            step.excluded_reason = entry["reason"]
        elif kind == "script":
            step.commands = [["bash", str(ROOT / entry["script"]), *entry.get("args", [])]]
        elif kind in ("swift", "compile_only"):
            inputs = source_paths(entry.get("sources", []) + entry.get("test_files", []))
            if entry.get("concat_sources"):
                concatenated = str(work / "CombinedTest.swift")
                step.prepare.append({"kind": "concat", "sources": inputs, "destination": concatenated})
                inputs = [concatenated]
            compiler = ["xcrun", "--sdk", "macosx", "swiftc", "-swift-version", "5", "-Onone", "-parse-as-library",
                        "-target", f"arm64-apple-macosx{minimum}", "-module-cache-path", str(run_dir / "swift-cache")]
            for define in entry.get("defines", []):
                compiler += ["-D", define]
            for framework in entry.get("frameworks", ["SwiftUI", "AppKit", "WebKit"]):
                compiler += ["-framework", framework]
            compiler += entry.get("compiler_args", [])
            compiler += inputs + ["-o", str(work / "test")]
            step.commands = [compiler]
            if kind == "compile_only":
                step.category = "build"
            else:
                step.commands.append([str(work / "test"), *entry.get("args", [])])
                for args in entry.get("additional_runs", []):
                    step.commands.append([str(work / "test"), *args])
        else:
            raise ValueError(f"Unknown Swift recipe kind: {kind}")
        step.commands = [[expand(arg, local) for arg in argv] for argv in step.commands]
        step.environment = {k: expand(v, local) for k, v in step.environment.items()}
        step.prepare = expand_tree(step.prepare, local)
        steps.append(step)
    steps += [
        Step("rust.listener_readonly", "host_readonly", [["cargo", "test", "--locked", "-p", "claude-watch-runtime",
              "--test", "live_listener_diagnostics", "system_runner_reports_listener_evidence_without_mutation",
              "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]], dependencies=["rust.build"],
             notes=["Uses two owned ephemeral loopback listeners and real kernel collection; checks the exact selected endpoint, PID and birth identity. Does not require or modify the VPN listener."]),
        Step("webkit.resident_runtime", "test", [["bash", "monitor/tests/run_resident_worker_tests.sh", "--fixture"]],
             dependencies=["rust.build", "macos.gui_session"], timeout_seconds=600),
        Step("rust.signed_peer_build", "build", [["cargo", "test", "--locked", "-p", "claude-watch-system", "--lib",
              "--no-run", "--message-format=json"]], dependencies=["rust.build"]),
        Step("rust.signed_peer", "test", [
              ["/usr/bin/codesign", "--force", "--sign", "-", "--options", "runtime,library", str(run_dir / "artifacts/signed-system-tests")],
              [str(run_dir / "artifacts/signed-system-tests"), "launchd_gateway::tests::gateway_signed_peer_checks_live_code_identity_and_rejects_wrong_uid_or_hash",
               "--ignored", "--exact", "--nocapture", "--test-threads=1"]], dependencies=["rust.signed_peer_build"],
             prepare=[{"kind": "copy_cargo_test", "log_step": "rust.signed_peer_build", "target_name": "claude_watch_system",
                       "destination": str(run_dir / "artifacts/signed-system-tests")}],
             notes=["Signs only a copy of the test executable with free local ad-hoc signing; no installation."]),
        Step("acceptance.real_ai_and_service", "excluded", excluded_reason=
             "Real AI/Finder interaction, root service installation, live VPN changes and long-run physical-machine acceptance are outside this command."),
        Step("probes.external_live", "excluded", excluded_reason=
             "External live DNS/NetCoffee/IPLeak/Resident modes are excluded; fixture modes are used."),
    ]
    for step in steps:
        local = {**variables, "work_dir": str(run_dir / "artifacts" / step.id)}
        step.prepare = expand_tree(step.prepare, local)
    ids = [step.id for step in steps]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate step IDs")
    for step in steps:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", step.id):
            raise ValueError(f"Invalid step ID: {step.id}")
        for dep in step.dependencies:
            if dep not in ids or ids.index(dep) >= ids.index(step.id):
                raise ValueError(f"Invalid dependency order: {step.id} -> {dep}")
    coverage = {"swift_test_files": sorted(actual), "swift_test_count": len(actual),
                "swift_mapped_count": len(actual & set(covered)), "missing": missing, "duplicates": duplicates,
                "scope": "Reviewed automatic fixtures plus read-only listener diagnostics; not production acceptance"}
    return steps, coverage


class Runner:
    def __init__(self, repo: Path, output: Path, steps: list[Step], environment: dict[str, str], coverage: dict | None = None,
                 fixture_tmp: Path | None = None):
        self.repo, self.output, self.steps, self.environment = repo, output, steps, environment
        self.coverage = coverage or {}
        self.results: list[dict] = []
        self.cancelled = False
        self.current: subprocess.Popen | None = None
        self.started = dt.datetime.now(dt.timezone.utc).isoformat()
        self.output.mkdir(parents=True, exist_ok=False)
        for name in ("logs", "artifacts", "swift-cache"):
            (self.output / name).mkdir()
        if fixture_tmp is not None:
            (self.output / "tmp").symlink_to(fixture_tmp, target_is_directory=True)
            self.environment["TMPDIR"] = str(fixture_tmp) + "/"
        else:
            (self.output / "tmp").mkdir()
        self.write_results()

    def write_results(self):
        counts = {s: sum(r["status"] == s for r in self.results)
                  for s in ("passed", "failed", "blocked", "excluded", "interrupted", "not_run")}
        completed = len(self.results) == len(self.steps)
        outcome = ("interrupted" if self.cancelled else "failed" if counts["failed"] or counts["blocked"]
                   else "passed_with_exclusions" if completed and counts["excluded"] else "passed" if completed else "running")
        report = {"schema_version": 1, "started_at": self.started, "outcome": outcome,
                  "completed": completed, "counts": counts, "coverage": self.coverage, "steps": self.results,
                  "scope": self.coverage.get("scope", "Automatic fixture suite only") +
                           "; exclusions and Cargo ignored/subcase gaps are not passes."}
        destination = self.output / "results.json"
        temporary = destination.with_suffix(".tmp")
        temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        temporary.replace(destination)
        lines = ["# Claude Watch test run", "", f"Outcome: **{outcome}**", "",
                 "Step counts (not individual assertions): " + json.dumps(counts), "",
                 "Scope: " + report["scope"], "",
                 "Automatic fixture suite; not installed-service or real-AI acceptance.", "",
                 "| Step | Kind | Result | Seconds | Exit | Log / reason |", "|---|---|---|---:|---:|---|"]
        for result in self.results:
            detail = result.get("reason", "").replace("|", "\\|").replace("\n", " ")
            log = f"[log]({result['log']})" if result.get("log") else ""
            if result.get("coverage_notes"):
                detail += " Conditional skips/ignored cases recorded in results.json."
            lines.append(f"| {result['id']} | {result['category']} | {result['status']} | {result.get('duration_seconds', 0):.2f} | {result.get('exit_code', '')} | {log} {detail} |")
        (self.output / "SUMMARY.md").write_text("\n".join(lines) + "\n")

    def stop_owned_group(self, process: subprocess.Popen):
        # Only the new session created by this runner; never kill by app name.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            process.wait(timeout=5)
            return
        except PermissionError:
            # Darwin can return EPERM for an empty process group, including
            # an exited but unreaped leader. Verify absence instead of treating
            # permission denial itself as proof of successful cleanup.
            if self.group_exists(process.pid):
                raise
            process.wait(timeout=5)
            return
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                break
            except PermissionError:
                if not self.group_exists(process.pid):
                    break
                raise
            time.sleep(0.03)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                if self.group_exists(process.pid):
                    raise
        process.wait(timeout=5)

    @staticmethod
    def group_exists(pgid: int) -> bool:
        observed = subprocess.run(["/bin/ps", "-axo", "pgid=,stat="], stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, timeout=5)
        if observed.returncode != 0:
            raise PermissionError("Cannot confirm owned process-group cleanup with ps")
        # A zombie cannot execute or receive signals. Darwin reports EPERM
        # while such a record remains; wait() below still reaps our leader.
        return any(len(fields) >= 2 and fields[0] == str(pgid) and not fields[1].startswith("Z")
                   for line in observed.stdout.splitlines() if (fields := line.split()))

    def command(self, argv: list[str], env: dict[str, str], log, payload, timeout: float) -> tuple[int, str | None]:
        log.write(("\n$ " + shlex.join(argv) + "\n").encode())
        log.flush()
        process = subprocess.Popen(argv, cwd=self.repo, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        self.current = process
        start = last_heartbeat = time.monotonic()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        reason = None
        try:
            # Do not reap an exited leader while descendants still own its
            # output pipe: its reserved PID keeps the process-group identity
            # from being reused before timeout cleanup.
            while selector.get_map():
                if self.cancelled or time.monotonic() - start > timeout:
                    reason = "interrupted" if self.cancelled else "command timed out"
                    self.stop_owned_group(process)
                    break
                for key, _ in selector.select(timeout=0.2):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if chunk:
                        log.write(chunk)
                        log.flush()
                        payload.write(chunk)
                        payload.flush()
                    else:
                        selector.unregister(key.fileobj)
                if time.monotonic() - last_heartbeat > 30:
                    print(f"  still running ({int(time.monotonic() - start)}s); log is updating", flush=True)
                    last_heartbeat = time.monotonic()
            while reason is None:
                if self.cancelled or time.monotonic() - start > timeout:
                    reason = "interrupted" if self.cancelled else "command timed out"
                    self.stop_owned_group(process)
                    break
                try:
                    process.wait(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    pass
            if reason:
                log.write(("\nRUNNER: " + reason + "\n").encode())
            return process.wait(), reason
        finally:
            selector.close()
            if process.poll() is None:
                self.stop_owned_group(process)
            process.stdout.close()
            self.current = None

    def artifact_path(self, value: str) -> Path:
        path = Path(value).resolve()
        if not path.is_relative_to(self.output.resolve()):
            raise ValueError(f"Refusing artifact write outside this run: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def prepare(self, action: dict):
        kind = action["kind"]
        if kind == "installed_rust_toolchain":
            match = re.search(r'channel\s*=\s*"([^"]+)"', (self.repo / "rust-toolchain.toml").read_text())
            if not match:
                raise PrerequisiteError("Cannot determine pinned Rust toolchain")
            channel = match.group(1)
            if not shutil.which("rustup"):
                raise PrerequisiteError("rustup is required to verify the pinned toolchain without installing it")
            for tool in ("cargo", "rustc"):
                observed = subprocess.run(["rustup", "which", "--toolchain", channel, tool],
                                          env=self.environment, capture_output=True, text=True, timeout=20)
                if observed.returncode != 0 or not Path(observed.stdout.strip()).is_file():
                    raise PrerequisiteError(f"Pinned Rust toolchain {channel} is not installed; no automatic installation attempted")
                if tool == "rustc":
                    self.environment["RUSTC"] = observed.stdout.strip()
            self.environment["RUSTUP_TOOLCHAIN"] = channel
            return
        if kind == "console_session":
            if not Path("/dev/console").exists() or Path("/dev/console").stat().st_uid != os.getuid():
                raise PrerequisiteError("A logged-in graphical session owned by this user is required")
            return
        if kind == "require_file":
            path = Path(action["path"])
            if not path.is_file() or path.stat().st_size == 0:
                raise PrerequisiteError(f"Required fixture was not produced: {path}")
            return
        destination = self.artifact_path(action["destination"])
        if kind == "concat":
            destination.write_text("\n".join(Path(p).read_text() for p in action["sources"]))
        elif kind == "json_extract":
            value = json.loads((self.repo / action["source"]).read_text())
            for key in action["key_path"]:
                value = value[key]
            destination.write_text(json.dumps(value, ensure_ascii=False) + "\n")
        elif kind == "copy_cargo_test":
            log = self.output / "logs" / (action["log_step"] + ".log")
            matches = set()
            for line in log.read_text(errors="replace").splitlines():
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if (isinstance(item, dict) and item.get("reason") == "compiler-artifact"
                        and item.get("target", {}).get("name") == action["target_name"]
                        and item.get("profile", {}).get("test") and item.get("executable")):
                    matches.add(item["executable"])
            if len(matches) != 1:
                raise PrerequisiteError(f"Expected one test executable, found {len(matches)}")
            shutil.copy2(matches.pop(), destination)
        else:
            raise ValueError(f"Unsupported prepare action: {kind}")

    def run(self, preflight_error: str | None = None) -> int:
        for step in self.steps:
            started = time.monotonic()
            result = {"id": step.id, "category": step.category, "commands": step.commands,
                      "test_files": step.test_files, "notes": step.notes, "status": "not_run"}
            prior = {r["id"]: r["status"] for r in self.results}
            bad_deps = [dep for dep in step.dependencies if prior.get(dep) != "passed"]
            # A workspace assertion failure need not discard fresh fixture
            # exports from other passing tests. These steps verify the actual
            # files in this NEW run directory; they never reuse an older run.
            if step.id in ("rust.monitor_coverage_fixture", "rust.process_protection_fixture",
                           "rust.target_discovery_fixture", "rust.mechanism_review_fixtures"):
                bad_deps = [dep for dep in bad_deps if prior.get(dep) != "failed"]
            if step.excluded_reason:
                result.update(status="excluded", reason=step.excluded_reason)
            elif self.cancelled:
                result.update(status="not_run", reason="Run was interrupted")
            elif preflight_error or bad_deps:
                result.update(status="blocked", reason=preflight_error or f"Prerequisites did not pass: {bad_deps}")
            else:
                print(f"[RUN] {step.id}", flush=True)
                log_path = self.output / "logs" / (step.id + ".log")
                payload_path = self.output / "logs" / (step.id + ".output.log")
                result["log"] = str(log_path.relative_to(self.output))
                result["output_log"] = str(payload_path.relative_to(self.output))
                (self.output / "artifacts" / step.id).mkdir(parents=True, exist_ok=True)
                try:
                    with log_path.open("wb") as log, payload_path.open("wb") as payload:
                        for action in step.prepare:
                            log.write(("PREPARE " + json.dumps(action, ensure_ascii=False) + "\n").encode())
                            self.prepare(action)
                        status, reason = 0, None
                        command_results = []
                        for argv in step.commands:
                            if self.cancelled:
                                raise Interrupted()
                            env = {**self.environment, **step.environment}
                            status, reason = self.command(argv, env, log, payload, step.timeout_seconds)
                            command_results.append({"argv": argv, "exit_code": status, "reason": reason})
                            if status != 0 or reason:
                                break
                        result.update(command_results=command_results, exit_code=status)
                        if reason == "interrupted":
                            raise Interrupted()
                        if status != 0 or reason:
                            result.update(status="failed", reason=reason or f"Command exited {status}")
                        else:
                            log.flush()
                            text = payload_path.read_text(errors="replace")
                            missing = [m for m in step.success_markers if m not in text]
                            failures = [p for p in step.failure_patterns if re.search(p, text)]
                            if missing or failures:
                                result.update(status="failed", reason=f"Missing completion markers={missing}; failure markers={failures}")
                            else:
                                result["status"] = "passed"
                except Interrupted:
                    self.cancelled = True
                    result.update(status="interrupted", reason="Interrupted; only owned process group terminated")
                except (PrerequisiteError, FileNotFoundError) as exc:
                    result.update(status="blocked", reason=str(exc))
                except Exception as exc:
                    result.update(status="failed", reason=f"{type(exc).__name__}: {exc}")
                if result.get("reason"):
                    with log_path.open("a") as log:
                        log.write("\nRUNNER RESULT: " + result["reason"] + "\n")
                # Keep real non-coverage on failure too; zero-ignored summaries
                # must not fill or truncate the list of meaningful gaps.
                result["coverage_notes"] = list(dict.fromkeys(line for line in payload_path.read_text(errors="replace").splitlines()
                    if re.search(r"\.\.\. ignored\b|not_run|\bSKIP\b|\bskipped\b|\b[1-9][0-9]* ignored\b", line, re.I)))
            result["duration_seconds"] = round(time.monotonic() - started, 3)
            self.results.append(result)
            self.write_results()
            print(f"[{result['status'].upper()}] {step.id}" + (": " + result["reason"] if result.get("reason") else ""), flush=True)
        print(f"\nSummary: {self.output / 'SUMMARY.md'}\nJSON: {self.output / 'results.json'}", flush=True)
        if self.cancelled:
            return 130
        return 1 if any(r["status"] in ("failed", "blocked", "not_run") for r in self.results) else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New output directory; existing directories are never overwritten")
    parser.add_argument("--list", action="store_true", help="Read-only inventory; do not compile or run anything")
    parser.add_argument("--only", action="append", default=[], metavar="ID", help="Run a named step and its dependencies (repeatable)")
    args = parser.parse_args(argv)
    output = (args.output or ROOT / ".agent/test-runs" /
              (dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8])).absolute()
    steps, coverage = build_plan(output)
    if args.only:
        selected = set(args.only)
        lookup = {s.id: s for s in steps}
        unknown = selected - lookup.keys()
        if unknown:
            parser.error(f"Unknown step IDs: {sorted(unknown)}")
        while True:
            expanded = selected | {dep for sid in selected for dep in lookup[sid].dependencies}
            if selected == expanded:
                break
            selected = expanded
        steps = [s for s in steps if s.id in selected]
        coverage["selection"] = sorted(selected)
        coverage["scope"] = "Selected steps only; not the full fixture suite"
    if args.list:
        print(json.dumps({"coverage": coverage, "steps": [asdict(step) for step in steps]}, ensure_ascii=False, indent=2))
        return 0
    if output.exists():
        parser.error(f"Output directory already exists: {output}")
    env = clean_environment(dict(os.environ), ROOT, output)
    fixture_tmp = Path(tempfile.mkdtemp(prefix="cw-t.", dir="/private/tmp" if platform.system() == "Darwin" else None))
    runner = Runner(ROOT, output, steps, env, coverage, fixture_tmp=fixture_tmp)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda _sig, _frame: setattr(runner, "cancelled", True))
    inputs = [MANIFEST, Path(__file__), ROOT / "tools/test-all.sh"]
    (output / "plan.json").write_text(json.dumps([asdict(s) for s in steps], ensure_ascii=False, indent=2) + "\n")
    metadata = {"python": sys.version.split()[0], "platform": platform.platform(), "fixture_tmp": str(fixture_tmp),
                "source_sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}}
    (output / "run-info.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"Results and logs: {output}", flush=True)
    error = None
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        error = "The native fixture suite requires Apple Silicon macOS; no tests were run"
    elif os.geteuid() == 0:
        error = "Run as the logged-in user, without sudo; UID rejection tests require an unprivileged process"
    elif int(platform.mac_ver()[0].split(".")[0]) < 26:
        error = "Current desktop fixtures target macOS 26 or later"
    return runner.run(error)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as exc:
        print(f"Test runner configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2)
