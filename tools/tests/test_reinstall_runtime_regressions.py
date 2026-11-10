"""Exercise build entry points and the collector parent using private fixtures."""
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(sys.platform == "darwin" and platform.machine() == "arm64", "macOS arm64 build entry")
class ReinstallBuildRegression(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cw-build-entry-")
        self.root = Path(self.temp.name).resolve()
        for name in ("monitor/reinstall.sh", "tools/build-rust-components.sh", "monitor/macos-minimum.txt", "tools/reinstall_log.py"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, target)
        (self.root / "Cargo.toml").write_text("[workspace]\n")
        self.trace = self.root / "calls.jsonl"
        cargo = self.root / "cargo-home/bin/cargo"
        cargo.parent.mkdir(parents=True)
        cargo.write_text(f"#!{sys.executable}\n" + r'''
import json, os, pathlib, sys
root = pathlib.Path(__file__).resolve().parents[2]
with (root / "calls.jsonl").open("a") as out:
    out.write(json.dumps({"kind":"cargo", "args":sys.argv[1:], "environment":{
        key:os.environ.get(key) for key in ("SDKROOT", "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER", "CC_aarch64_apple_darwin", "MACOSX_DEPLOYMENT_TARGET")}}) + "\n")
if os.environ.get("CW_FIXTURE_BUILD_FAILURE") == "1":
    print("fixture compiler failure", file=sys.stderr)
    raise SystemExit(23)
target = root / "target/aarch64-apple-darwin/release"
target.mkdir(parents=True, exist_ok=True)
engine = target / "claude-watch-engine"
engine.write_text("#!" + sys.executable + "\n" + ''' + repr(r'''
import json, pathlib, sys
target = pathlib.Path(__file__).resolve().parent
root = target.parents[2]
with (root / "calls.jsonl").open("a") as out:
    out.write(json.dumps({"kind":"engine", "args":sys.argv[1:]}) + "\n")
if sys.argv[1:] == ["--component-paths"]:
    print(json.dumps({key:str(target/name) for key,name in {
        "native_observer":"watch-native-observer", "process_control":"watch-process-control",
        "sandbox_launcher":"watch-sandbox-launcher", "gateway_broker":"watch-gateway-broker"}.items()}))
else:
    assert sys.argv[1] == "reinstall" and "--dry-run" in sys.argv
    print('{"status":"preview","fixture":true}')
''') + r''')
engine.chmod(0o700)
for name in ("watch-native-observer", "watch-process-control", "watch-sandbox-launcher", "watch-gateway-broker"):
    p = target / name
    p.write_text("#!/bin/sh\nexit 0\n")
    p.chmod(0o700)
''')
        cargo.chmod(0o700)
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("CW_", "WATCH_", "CARGO_TARGET_"))}
        fixture_home = self.root / "home"
        (fixture_home / "Library/Logs").mkdir(parents=True)
        self.env["HOME"] = str(fixture_home)
        self.env["CARGO_HOME"] = str(self.root / "cargo-home")
        self.env["CW_CARGO_BIN"] = str(cargo)

    def tearDown(self):
        self.temp.cleanup()

    def run_script(self, name, *args):
        return subprocess.run(["/bin/bash", str(self.root / name), *args], cwd=self.root,
                              env=self.env, capture_output=True, text=True, timeout=20)

    def test_bootstrap_and_packaging_use_identical_cargo_units_and_environment(self):
        bootstrap = self.run_script("monitor/reinstall.sh", "3.0.0", "378", "--dry-run")
        self.assertEqual(bootstrap.returncode, 0, bootstrap.stderr)
        stage = self.run_script("tools/build-rust-components.sh", "--output", str(self.root / "staging"))
        self.assertEqual(stage.returncode, 0, stage.stderr)
        calls = [json.loads(line) for line in self.trace.read_text().splitlines()]
        cargo = [call for call in calls if call["kind"] == "cargo"]
        self.assertEqual(len(cargo), 2)
        self.assertEqual(cargo[0], cargo[1], "bootstrap and packaging must resolve the same feature graph")
        for name in ("claude-watch-engine", "claude-watch-sandbox-launcher", "claude-watch-gateway-broker"):
            self.assertIn(name, cargo[0]["args"])
        self.assertIn("--locked", cargo[0]["args"])
        engine = [call for call in calls if call["kind"] == "engine"]
        self.assertEqual(engine[0]["args"], ["reinstall", "--version", "3.0.0", "--build", "378",
                                           "--project", str(self.root), "--dry-run"])
        manifest = json.loads((self.root / "staging/components.json").read_text())
        self.assertEqual(len(manifest["components"]), 5)
        summaries = list((Path(self.env["HOME"]) / "Library/Logs/ClaudeWatchInstaller").glob("reinstall-*/run.json"))
        self.assertEqual(len(summaries), 1)
        summary = json.loads(summaries[0].read_text())
        self.assertEqual(summary["status"], "passed")
        self.assertEqual([(p["phase"], p["exit_code"]) for p in summary["phases"] if p["status"] != "running"], [("build", 0), ("install", 0)])

    def test_reinstall_build_failure_keeps_one_compile_and_durable_failed_summary(self):
        self.env["CW_FIXTURE_BUILD_FAILURE"] = "1"
        result = self.run_script("monitor/reinstall.sh", "3.0.0", "378", "--dry-run")
        self.assertEqual(result.returncode, 23, result.stdout + "\n" + result.stderr)
        calls = [json.loads(line) for line in self.trace.read_text().splitlines()]
        self.assertEqual([call["kind"] for call in calls], ["cargo"])
        summaries = list((Path(self.env["HOME"]) / "Library/Logs/ClaudeWatchInstaller").glob("reinstall-*/run.json"))
        self.assertEqual(len(summaries), 1)
        value = json.loads(summaries[0].read_text())
        self.assertEqual(value["status"], "failed")
        self.assertEqual(value["phases"][-1]["exit_code"], 23)
        self.assertIn("fixture compiler failure", (summaries[0].parent / "build.log").read_text())

    def test_build_only_does_not_stage_or_run_the_engine(self):
        build = self.run_script("tools/build-rust-components.sh", "--build-only")
        self.assertEqual(build.returncode, 0, build.stderr)
        calls = [json.loads(line) for line in self.trace.read_text().splitlines()]
        self.assertEqual([call["kind"] for call in calls], ["cargo"])
        self.assertFalse((self.root / "staging").exists())


@unittest.skipUnless(sys.platform == "darwin", "native zsh supervisor")
class ListenerSupervisorRegression(unittest.TestCase):
    def fixture(self, root, *, immediate_exit=False, trap_delay=False):
        collector = root / "watch-native-collector.zsh"
        shutil.copy2(ROOT / "monitor/Resources/watch-native-collector.zsh", collector)
        if trap_delay:
            # A private scheduling seam: let the graceful child finish while
            # its parent's stop trap is still running, before wait resumes.
            source = collector.read_text()
            needle = "trap 'stop_supervised_worker' HUP INT TERM"
            self.assertEqual(source.count(needle), 1)
            collector.write_text(source.replace(needle, "trap 'stop_supervised_worker; /bin/sleep 0.15' HUP INT TERM"))
        collector.chmod(0o700)
        engine = root / "watch-engine"
        engine.write_text(f"#!{sys.executable}\n" + ("raise SystemExit(23)\n" if immediate_exit else r'''
from pathlib import Path
import os, signal, time
root = Path(__file__).resolve().parent
stopping = False
def stop(signum, frame):
    global stopping
    stopping = True
signal.signal(signal.SIGTERM, stop)
(root / "ready").write_text(str(os.getpid()))
until = time.monotonic() + 6
while not stopping and time.monotonic() < until:
    time.sleep(0.02)
if stopping:
    (root / "stopped").write_text(str(os.getpid()))
'''))
        engine.chmod(0o700)
        env = dict(os.environ, TMPDIR=str(root))
        return subprocess.Popen(["/bin/zsh", "-f", str(collector), "daemon", "--apply"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    def test_parent_term_reaches_only_its_owned_worker_and_waits_for_exit(self):
        with tempfile.TemporaryDirectory(prefix="cw-collector-stop-") as directory:
            root = Path(directory).resolve()
            ordinary = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
            parent = self.fixture(root, trap_delay=True)
            try:
                until = time.monotonic() + 3
                while not (root / "ready").is_file() and time.monotonic() < until:
                    time.sleep(0.02)
                self.assertTrue((root / "ready").is_file(), "owned worker must actually start")
                worker_pid = (root / "ready").read_text()
                parent.send_signal(signal.SIGTERM)
                parent.wait(timeout=2)
                self.assertEqual(parent.returncode, 0, "the graceful worker's real exit status must survive a trapped stop")
                self.assertTrue((root / "stopped").is_file(), "parent exit must not orphan its running worker")
                self.assertEqual((root / "stopped").read_text(), worker_pid)
                self.assertIsNone(ordinary.poll(), "an unrelated process must remain alive")
            finally:
                if parent.poll() is None:
                    parent.terminate()
                parent.communicate(timeout=10)
                ordinary.terminate()
                ordinary.wait(timeout=2)

    def test_normal_worker_exit_status_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="cw-collector-exit-") as directory:
            parent = self.fixture(Path(directory).resolve(), immediate_exit=True)
            stdout, stderr = parent.communicate(timeout=5)
            self.assertEqual(parent.returncode, 23, (stdout, stderr))


@unittest.skipUnless(sys.platform == "darwin", "native macOS observation helpers")
class NativeDaemonStartupRegression(unittest.TestCase):
    def test_private_daemon_keeps_publishing_during_partial_discovery_and_stops_its_original_worker(self):
        engine = Path(os.environ.get("CW_REINSTALL_TEST_ENGINE", ROOT / "target/debug/claude-watch-engine"))
        if not engine.is_file():
            self.skipTest("build claude-watch-engine first; unified runner supplies this prerequisite")
        paths = subprocess.run([str(engine), "--component-paths"], capture_output=True, text=True, timeout=5)
        self.assertEqual(paths.returncode, 0, paths.stderr)
        components = json.loads(paths.stdout)
        with tempfile.TemporaryDirectory(prefix="cw-native-startup-", dir="/private/tmp") as directory:
            root = Path(directory)
            runtime, home = root / "runtime", root / "home"
            runtime.mkdir(); home.mkdir()
            for name, source in [("watch-engine", engine), ("watch-native-observer", Path(components["native_observer"])),
                                 ("watch-process-control", Path(components["process_control"])),
                                 ("watch-native-collector.zsh", ROOT / "monitor/Resources/watch-native-collector.zsh")]:
                shutil.copy2(source, runtime / name)
                (runtime / name).chmod(0o700)
            for index in range(24):
                bundle = home / f"Applications/Private {index:02}.app/Contents"
                (bundle / "MacOS").mkdir(parents=True)
                (bundle / "Info.plist").write_text('<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>example.ordinary</string><key>CFBundleExecutable</key><string>PrivateMain</string></dict></plist>')
                # File metadata only. None of these images is executed.
                (bundle / "MacOS/PrivateMain").write_bytes(b"private metadata fixture, never executed")
                (bundle / "MacOS/PrivateMain").chmod(0o700)
            # A permanently unreadable metadata record used to force repeated
            # synchronous scans and stall the whole publisher for >30 seconds.
            broken = home / "Applications/Unreadable Ordinary.app/Contents"
            broken.mkdir(parents=True)
            (broken / "Info.plist").write_text("not a property list")
            env = {key: value for key, value in os.environ.items() if not key.startswith(("CW_", "WATCH_"))}
            started = time.monotonic()
            parent = subprocess.Popen(["/bin/zsh", "-f", str(runtime / "watch-native-collector.zsh"),
                                       "--home", str(home), "daemon", "--apply", "--observe-only"],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            producer = None
            def identity():
                request = {"schema": 1, "round_id": "owned-startup-regression", "targets": [producer]}
                check = subprocess.run([str(runtime / "watch-native-observer"), "identities"], input=json.dumps(request),
                                       capture_output=True, text=True, env=env, timeout=5)
                self.assertEqual(check.returncode, 0, check.stderr)
                return json.loads(check.stdout)["identities"][0]
            try:
                state = home / "Library/Application Support/ClaudeWatch/state"
                snapshot_path = state / "runtime-snapshot.json"
                while not snapshot_path.is_file() and time.monotonic() - started < 15 and parent.poll() is None:
                    time.sleep(0.01)
                self.assertTrue(snapshot_path.is_file(), "first observation must meet the existing 15-second installation window")
                raw = json.loads(snapshot_path.read_text())
                snapshot, producer = raw["snapshot"], raw["producer"]
                publication_seconds = time.monotonic() - started
                self.assertEqual(snapshot["health"]["state"], "degraded")
                self.assertEqual(snapshot["initialObservation"]["application_discovery"], "pending")
                self.assertFalse(snapshot["grants_launch_permission"])
                self.assertIsNone(snapshot["proxy"])
                self.assertEqual(producer["uid"], os.getuid())
                self.assertEqual(producer["parent"], parent.pid)
                self.assertEqual(json.loads((state / "native-listener.json").read_text())["actor"]["worker"], producer)
                current = identity()
                self.assertEqual(current["state"], "ok")
                self.assertEqual(current["identity"], producer)
                readback = subprocess.run([str(runtime / "watch-engine"), "--home", str(home), "snapshot"],
                                          capture_output=True, text=True, env=env, timeout=5)
                self.assertEqual(readback.returncode, 0, readback.stderr)
                self.assertEqual(json.loads(readback.stdout)["health"]["state"], "unavailable", "unregistered private publisher must fail the normal launchd verifier")
                captures, proxy_samples, ages = set(), set(), []
                until = time.monotonic() + 16
                while time.monotonic() < until and parent.poll() is None:
                    current = json.loads(snapshot_path.read_text())
                    self.assertEqual(current["producer"], producer)
                    view = current["snapshot"]
                    capture = view["capturedAt"]
                    captures.add(capture)
                    ages.append(time.time() - capture)
                    proxy = view.get("proxy") or {}
                    if isinstance(proxy.get("observedAt"), (float, int)):
                        proxy_samples.add(proxy["observedAt"])
                    self.assertLess(ages[-1], 8, "slow/partial application discovery must not stale the real publisher")
                    time.sleep(0.1)
                self.assertIsNone(parent.poll(), "private daemon must remain alive throughout observation")
                self.assertGreaterEqual(len(captures), 6, "need sustained fresh rounds, not just the bootstrap heartbeat")
                self.assertGreaterEqual(len(proxy_samples), 2, "need two actual proxy observations, not rereads stamped fresh")
                stopped = time.monotonic()
                parent.send_signal(signal.SIGTERM)
                stdout, stderr = parent.communicate(timeout=5)
                stop_seconds = time.monotonic() - stopped
                self.assertEqual(parent.returncode, 0, (stdout[-1000:], stderr[-1000:]))
                ended = identity()
                self.assertEqual((ended["state"], ended["code"]), ("unknown", "process_exited"))
                print(f"private native daemon: first observation={publication_seconds:.3f}s; captures={len(captures)}; proxy samples={len(proxy_samples)}; max age={max(ages):.3f}s; stop={stop_seconds:.3f}s; original worker exit verified; no registered service or AI launch")
            finally:
                if parent.poll() is None:
                    parent.terminate()
                    try:
                        parent.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        # Cleanup authority is restricted to our still kernel-
                        # verified child in this test's private runtime.
                        if producer is not None:
                            current = identity()
                            if current["state"] == "ok" and current["identity"] == producer:
                                os.kill(producer["pid"], signal.SIGKILL)
                        parent.kill()
                        parent.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
