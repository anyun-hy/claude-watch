#!/usr/bin/env python3
"""Exercise runner argument/environment handling with fake tools, not macOS APIs.

Run: python3 tools/tests/test_guard_regression_runner.py
No Rust/Swift compiler, network, installed configuration, or signals are used.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


FAKE_TOOL = r'''
import json
import os
from pathlib import Path
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["MOCK_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps({"tool": name, "args": args, "env": {
        key: os.environ.get(key) for key in
        ("SDKROOT", "MACOSX_DEPLOYMENT_TARGET", "DEVELOPER_DIR", "TOOLCHAINS")
    }}) + "\n")
if name == "uname":
    print(os.environ["MOCK_OS"] if args == ["-s"] else os.environ["MOCK_ARCH"])
elif name == "xcrun":
    if os.environ.get("MOCK_DISCOVERY_FAIL"):
        sys.exit(2)
    if args == ["--sdk", "macosx", "--find", "swiftc"]:
        print(os.environ["MOCK_COMPILER"])
    elif args == ["--sdk", "macosx", "--show-sdk-path"]:
        print(os.environ["MOCK_SDK"])
    else:
        sys.exit("unexpected xcrun arguments: " + repr(args))
elif name == "swiftc":
    if args == ["--version"]:
        print("mock Swift compiler; no compilation performed")
    elif os.environ.get("MOCK_COMPILE_FAIL"):
        sys.exit("mock compiler failed")
    else:
        output = Path(args[args.index("-o") + 1])
        output.write_text("#!/bin/sh\nprintf 'mock assertions executed\\n'\nexit "
                          + os.environ.get("MOCK_TEST_STATUS", "0") + "\n", encoding="utf-8")
        output.chmod(0o700)
elif name == "cargo":
    sys.exit(int(os.environ.get("MOCK_CARGO_STATUS", "0")))
else:
    sys.exit("unexpected fake tool: " + name)
'''


class GuardRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cw-runner-contract-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repository with spaces"
        (self.root / "tools").mkdir(parents=True)
        (self.root / "monitor").mkdir()
        source = Path(__file__).resolve().parents[1] / "test-guard-regressions.sh"
        self.runner = self.root / "tools/test-guard-regressions.sh"
        shutil.copyfile(source, self.runner)
        self.minimum = self.root / "monitor/macos-minimum.txt"
        self.minimum.write_text("26.0\n", encoding="utf-8")
        self.bin = self.root / "fake tools"
        self.bin.mkdir()
        self.compiler = self.root / "selected developer tools/usr/bin/swiftc"
        self.compiler.parent.mkdir(parents=True)
        for path in [self.bin / name for name in ("uname", "xcrun", "swiftc", "cargo")] + [self.compiler]:
            path.write_text("#!" + sys.executable + "\n" + FAKE_TOOL, encoding="utf-8")
            path.chmod(0o700)
        self.sdk = self.root / "selected developer tools/MacOSX.sdk"
        self.sdk.mkdir()
        self.log = self.root / "calls.jsonl"
        self.builds = self.root / "temporary builds"
        self.builds.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
                        TMPDIR=str(self.builds), MOCK_LOG=str(self.log), MOCK_OS="Darwin",
                        MOCK_ARCH="arm64", MOCK_COMPILER=str(self.compiler), MOCK_SDK=str(self.sdk))
        for key in ("MOCK_DISCOVERY_FAIL", "MOCK_COMPILE_FAIL", "MOCK_TEST_STATUS", "MOCK_CARGO_STATUS"):
            self.env.pop(key, None)
        self.bash = shutil.which("bash")
        self.assertIsNotNone(self.bash)

    def run_script(self, mode="swift"):
        return subprocess.run([self.bash, str(self.runner), mode], env=self.env,
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)

    def calls(self, tool):
        if not self.log.exists():
            return []
        return [row for row in map(json.loads, self.log.read_text(encoding="utf-8").splitlines())
                if row["tool"] == tool]

    def compile_call(self):
        calls = [row for row in self.calls("swiftc") if row["args"] != ["--version"]]
        self.assertEqual(len(calls), 1)
        return calls[0]

    @staticmethod
    def value_after(args, flag):
        return args[args.index(flag) + 1]

    def test_darwin_uses_explicit_sdk_and_project_target_not_inherited_28(self):
        self.env.update(SDKROOT="/wrong/iPhoneOS.sdk", MACOSX_DEPLOYMENT_TARGET="28.0",
                        DEVELOPER_DIR="/selected Xcode.app/Contents/Developer", TOOLCHAINS="custom-selection")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.compile_call()
        self.assertEqual(self.value_after(call["args"], "-sdk"), str(self.sdk))
        self.assertEqual(self.value_after(call["args"], "-target"), "arm64-apple-macosx26.0")
        self.assertEqual(call["env"]["SDKROOT"], str(self.sdk))
        self.assertEqual(call["env"]["MACOSX_DEPLOYMENT_TARGET"], "26.0")
        self.assertEqual(call["env"]["DEVELOPER_DIR"], self.env["DEVELOPER_DIR"])
        self.assertEqual(call["env"]["TOOLCHAINS"], "custom-selection")
        self.assertTrue(all(row["env"]["SDKROOT"] is None for row in self.calls("xcrun")))
        self.assertIn("[swift] target: arm64-apple-macosx26.0", result.stdout)
        self.assertIn("mock assertions executed", result.stdout)
        self.assertEqual(self.calls("cargo"), [])
        self.assertEqual(list(self.builds.iterdir()), [])

    def test_x86_64_and_three_component_project_minimum(self):
        self.env["MOCK_ARCH"] = "x86_64"
        self.minimum.write_text("26.1.2\n", encoding="utf-8")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.value_after(self.compile_call()["args"], "-target"), "x86_64-apple-macosx26.1.2")

    def test_linux_does_not_pick_xcrun_even_when_it_is_on_path(self):
        self.env["MOCK_OS"] = "Linux"
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.compile_call()["args"]
        self.assertNotIn("-sdk", args)
        self.assertNotIn("-target", args)
        self.assertIn("PROCESS_POLICY_TESTS", args)
        self.assertEqual(self.calls("xcrun"), [])

    def test_rust_mode_runs_existing_four_cargo_commands_only(self):
        result = self.run_script("rust")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls("cargo")
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0]["args"], ["check", "--locked", "-p", "claude-watch-runtime", "-p", "claude-watch-engine"])
        self.assertIn("controlled::guard_regressions", calls[1]["args"])
        self.assertIn("desktop_native::close_receipt::tests", calls[2]["args"])
        self.assertIn("supervised_evidence_regressions", calls[3]["args"])
        self.assertEqual(self.calls("swiftc"), [])
        self.assertEqual(self.calls("xcrun"), [])

    def test_invalid_mode_does_not_start_any_tool(self):
        self.assertEqual(self.run_script("invalid").returncode, 2)
        self.assertFalse(self.log.exists())

    def test_invalid_minimum_is_rejected_without_compiling(self):
        self.minimum.write_text("26.0 -D INJECTED\n", encoding="utf-8")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid project macOS minimum", result.stderr)
        self.assertEqual(self.calls("swiftc"), [])

    def test_missing_sdk_is_not_replaced_with_an_implicit_default(self):
        self.env["MOCK_SDK"] = str(self.root / "missing sdk")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SDK is missing", result.stderr)
        self.assertEqual(self.calls("swiftc"), [])

    def test_discovery_failure_does_not_fall_back_to_path_swiftc(self):
        self.env["MOCK_DISCOVERY_FAIL"] = "1"
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot locate swiftc", result.stderr)
        self.assertEqual(self.calls("swiftc"), [])

    def test_compiler_failure_does_not_run_assertions_and_cleans_temporary_files(self):
        self.env["MOCK_COMPILE_FAIL"] = "1"
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no Swift assertions have run", result.stderr)
        self.assertNotIn("mock assertions executed", result.stdout)
        self.assertEqual(list(self.builds.iterdir()), [])

    def test_assertion_binary_failure_remains_nonzero_and_is_not_a_compile_error(self):
        self.env["MOCK_TEST_STATUS"] = "7"
        result = self.run_script()
        self.assertEqual(result.returncode, 7)
        self.assertIn("mock assertions executed", result.stdout)
        self.assertNotIn("compilation failed", result.stderr)
        self.assertEqual(list(self.builds.iterdir()), [])

    def test_unsupported_architecture_is_not_silently_cross_compiled(self):
        self.env["MOCK_ARCH"] = "unknown"
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported macOS test architecture", result.stderr)
        self.assertEqual(self.calls("swiftc"), [])

    def test_all_mode_stops_on_rust_failure_before_starting_swift(self):
        self.env["MOCK_CARGO_STATUS"] = "9"
        result = self.run_script("all")
        self.assertEqual(result.returncode, 9)
        self.assertEqual(len(self.calls("cargo")), 1)
        self.assertEqual(self.calls("swiftc"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
