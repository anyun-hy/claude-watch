import contextlib
import hashlib
import importlib.util
import io
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "reinstall_clean.py"
spec = importlib.util.spec_from_file_location("cw_reinstall_clean", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


def plist(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(value))


def make_app(path, version, build):
    plist(path / "Contents/Info.plist", {
        "CFBundleIdentifier": "io.local.watchpanel", "CFBundleExecutable": "ClaudeWatchMonitor",
        "CFBundleShortVersionString": version, "CFBundleVersion": build,
    })
    plist(path / "Contents/Resources/BuildInfo.plist", {"BackendVariant": "rust-candidate", "Architecture": "arm64"})
    engine = path / "Contents/Resources/watch-engine"
    engine.write_bytes(b"fixture engine")
    engine.chmod(0o700)
    (path / "Contents/Resources/watch-admin.sh").write_bytes(b"fixture helper")


class FakeRunner:
    def __init__(self, layout, uid):
        self.layout, self.uid = layout, uid
        self.calls = []
        self.prefs = True
        self.fail = ""
        self.process_output = ""
        self.jobs = {
            f"gui/{uid}/io.local.claudewatch.agent": True,
            f"gui/{uid}/io.local.claudewatch.update": False,
            "system/io.local.claudewatch.timezone": True,
        }

    def locate(self, name):
        return None if self.fail == "toolchain" else "/fixture/" + name

    def run(self, args, *, capture=False, env=None):
        self.calls.append(tuple(args))
        command = args[0]
        def result(code=0, out="", err=""):
            return subprocess.CompletedProcess(args, code, out, err)
        def reply(value):
            return result(out=json.dumps(value))
        if command == "/bin/ps":
            return result(out=self.process_output)
        if command == "/fixture/xcrun":
            return result(out="/fixture/swiftc\n" if args[1] == "--find" else "/fixture/macos-sdk\n")
        if command == "/bin/launchctl":
            return result(0 if self.jobs.get(args[2], False) else 113)
        if command == "/usr/bin/codesign":
            return result(1 if self.fail == "codesign" else 0)
        if command == "/usr/bin/defaults":
            if args[1] == "read":
                return result(0) if self.prefs else result(1, err="Error: Domain not found.")
            self.prefs = False
            return result()
        if command == "/usr/bin/sudo":
            if self.fail == "admin":
                return result(1)
            for child in self.layout.system_root.iterdir():
                child.unlink()
            self.layout.system_root.rmdir()
            self.layout.system_plist.unlink(missing_ok=True)
            self.jobs["system/io.local.claudewatch.timezone"] = False
            return result()
        if command == "/bin/bash":
            if self.fail == "package":
                return result(1)
            app = Path(env["CW_APP_OUTPUT"])
            make_app(app, env["APP_VERSION"], env["BUILD_NUMBER"])
            dmg = self.layout.project / "monitor/dist" / env["DMG_NAME"]
            dmg.parent.mkdir(parents=True, exist_ok=True)
            dmg.write_bytes(b"fixture dmg")
            digest = hashlib.sha256(dmg.read_bytes()).hexdigest()
            if self.fail == "checksum": digest = "0" * 64
            Path(str(dmg) + ".sha256").write_text(digest + "  " + dmg.name + "\n")
            if self.fail == "reappeared":
                make_app(self.layout.app, "9.9.9", "999")
            return result()
        if command == "/usr/bin/open":
            return result()
        if args[1] == "app-uninstall":
            if "--apply" not in args:
                return reply({"status": "preview", "action": "app-uninstall", "installed": str(self.layout.app)})
            if self.fail == "uninstall":
                return result(4, out=json.dumps({"status": "error", "message": "fixture"}))
            removed = self.layout.trash / ("ClaudeWatch-removed-" + "a" * 32)
            removed.mkdir()
            old = removed / "Claude Watch Monitor.app"
            shutil.move(self.layout.app, old)
            if self.layout.agent.exists(): shutil.move(self.layout.agent, removed / self.layout.agent.name)
            self.jobs[f"gui/{self.uid}/io.local.claudewatch.agent"] = False
            return reply({"status": "ok", "action": "app-uninstall", "previous": str(old)})
        if args[1] == "app-install":
            source = Path(args[3])
            if "--apply" not in args:
                return reply({"status": "preview", "source": str(source), "installed": str(self.layout.app)})
            if self.fail == "install":
                return result(4, out=json.dumps({"status": "error", "message": "fixture"}))
            shutil.copytree(source, self.layout.app)
            plist(self.layout.agent, {"Label": "io.local.claudewatch.agent"})
            self.jobs[f"gui/{self.uid}/io.local.claudewatch.agent"] = True
            version, build = module.app_identity(self.layout.app)
            return reply({"status": "ok", "version": version, "build": build, "architecture": "arm64"})
        raise AssertionError(f"unexpected command: {args}")


class ReinstallTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cw-reinstall-fixture-", dir="/private/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.uid = os.getuid()
        self.layout = module.Layout(self.home, self.root / "Applications/Claude Watch Monitor.app",
                                    self.root / "Library/Application Support/ClaudeWatch",
                                    self.root / "Library/LaunchDaemons/io.local.claudewatch.timezone.plist",
                                    self.root / "project", self.root / "temp", system_uid=self.uid)
        self.layout.temporary.mkdir()
        self.layout.trash.mkdir()
        self.other_trash = self.layout.trash / "unrelated-user-file"
        self.other_trash.write_text("keep trash")
        make_app(self.layout.app, "3.0.0", "313")
        plist(self.layout.agent, {"Label": "io.local.claudewatch.agent"})
        self.layout.system_root.mkdir(parents=True)
        self.layout.helper.write_bytes(b"fixture helper")
        self.layout.helper.chmod(0o755)
        (self.layout.system_root / "timezone.target").write_text("Asia/Tokyo")
        plist(self.layout.system_plist, {"Label": "io.local.claudewatch.timezone", "ProgramArguments": [
            "/usr/bin/env", "-i", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "/bin/bash", "--noprofile", "--norc", str(self.layout.helper), "tick"]})
        (self.layout.base / "switcher").mkdir(parents=True)
        (self.layout.base / "switcher/config.json").write_text("watch settings")
        self.prefs = self.home / "Library/Preferences/io.local.watchpanel.plist"
        self.prefs.parent.mkdir(parents=True)
        self.prefs.write_text("watch prefs")
        self.claude = self.home / "Library/Application Support/Claude/Cookies"
        self.claude.parent.mkdir(parents=True)
        self.claude.write_text("keep Claude login")
        self.claude_cli = self.home / ".claude/credentials"
        self.claude_cli.parent.mkdir()
        self.claude_cli.write_text("keep Claude CLI")
        self.tag = self.home / "Library/Application Support/TAG/config.yaml"
        self.tag.parent.mkdir(parents=True)
        self.tag.write_text("keep TAG config")
        self.original = self.home / ".claude-switcher/data"
        self.original.parent.mkdir()
        self.original.write_text("keep original")
        self.original_service = self.root / "Library/LaunchDaemons/local.claude-bodyguard.plist"
        self.original_service.parent.mkdir(parents=True, exist_ok=True)
        self.original_service.write_text("keep original service")
        self.package = self.layout.project / "monitor/package-dmg.sh"
        self.package.parent.mkdir(parents=True)
        self.package.write_text("fixture package")
        for relative in ["monitor/build.sh", "tools/build-rust-components.sh", "Cargo.toml", "Cargo.lock", "monitor/Resources/AppIcon.icns", "monitor/macos-minimum.txt"]:
            path = self.layout.project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture build input")
        self.cargo = self.root / "cargo"
        self.cargo.write_text("fixture cargo")
        self.cargo.chmod(0o700)
        self.runner = FakeRunner(self.layout, self.uid)

    def perform(self, *, dry=False, answer="重置并安装", confirm=None):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            module.perform(self.layout, self.runner, "3.0.0", "314", dry_run=dry,
                           confirm=confirm or (lambda _: answer), uid=self.uid, cargo=str(self.cargo))

    def assert_preserved(self):
        self.assertEqual(self.claude.read_text(), "keep Claude login")
        self.assertEqual(self.claude_cli.read_text(), "keep Claude CLI")
        self.assertEqual(self.tag.read_text(), "keep TAG config")
        self.assertEqual(self.original.read_text(), "keep original")
        self.assertEqual(self.original_service.read_text(), "keep original service")
        self.assertEqual(self.other_trash.read_text(), "keep trash")

    def test_full_workflow_removes_only_watch_data_and_installs_requested_build(self):
        old_artifact = self.layout.project / "monitor/build/Claude Watch Monitor build313.app"
        old_artifact.mkdir(parents=True)
        (old_artifact / "keep").write_text("previous output")
        self.perform()
        self.assertEqual(module.app_identity(self.layout.app), ("3.0.0", "314"))
        self.assertFalse(self.layout.base.exists())
        self.assertFalse(self.prefs.exists())
        self.assertFalse(self.layout.system_root.exists())
        self.assertFalse(list(self.layout.trash.glob("ClaudeWatch-removed-*")))
        self.assertEqual((old_artifact / "keep").read_text(), "previous output")
        self.assertEqual(len(list((self.layout.project / "monitor/dist").glob("*build314*.dmg"))), 1)
        self.assert_preserved()

    def test_preview_and_cancel_are_read_only(self):
        self.perform(dry=True, confirm=lambda _: self.fail("dry run must not ask"))
        self.perform(answer="取消")
        self.assertTrue(self.layout.app.exists())
        self.assertTrue(self.layout.base.exists())
        self.assertFalse(any("--apply" in call or call[0] in ("/usr/bin/sudo", "/bin/bash", "/usr/bin/open") for call in self.runner.calls))
        self.assertFalse(list(self.layout.temporary.iterdir()))
        self.assert_preserved()

    def test_pending_transaction_blocks_before_uninstall(self):
        (self.layout.base / "switcher/transaction.json").write_text("{}")
        with self.assertRaisesRegex(module.Stop, "未完成"):
            self.perform()
        self.assertTrue(self.layout.app.exists())
        self.assertTrue(self.layout.base.exists())
        self.assertFalse(any("--apply" in call for call in self.runner.calls))
        self.assert_preserved()

    def test_active_update_and_other_package_are_not_interrupted(self):
        self.runner.jobs[f"gui/{self.uid}/io.local.claudewatch.update"] = True
        with self.assertRaisesRegex(module.Stop, "更新任务"):
            self.perform()
        self.runner.jobs[f"gui/{self.uid}/io.local.claudewatch.update"] = False
        self.runner.process_output = f"{self.uid} /bin/bash monitor/package-dmg.sh\n"
        with self.assertRaisesRegex(module.Stop, "正在进行"):
            self.perform()
        self.assertTrue(self.layout.app.exists())
        self.assert_preserved()

    def test_symlink_and_mismatched_helper_stop_before_any_uninstall(self):
        shutil.rmtree(self.layout.base)
        self.layout.base.symlink_to(self.claude.parent, target_is_directory=True)
        with self.assertRaisesRegex(module.Stop, "符号链接"):
            self.perform()
        self.layout.base.unlink()
        (self.layout.base / "switcher").mkdir(parents=True)
        self.layout.helper.write_bytes(b"different")
        with self.assertRaisesRegex(module.Stop, "不一致"):
            self.perform()
        self.assertTrue(self.layout.app.exists())
        self.assert_preserved()

    def test_admin_failure_stops_with_watch_data_intact(self):
        self.runner.fail = "admin"
        with self.assertRaisesRegex(module.Stop, "数据保留"):
            self.perform()
        self.assertFalse(self.layout.app.exists())
        self.assertTrue(self.layout.base.exists())
        self.assertTrue(self.prefs.exists())
        self.assertFalse(any(call[0] == "/bin/bash" for call in self.runner.calls))
        self.assert_preserved()

    def test_no_system_helper_is_supported(self):
        shutil.rmtree(self.layout.system_root)
        self.layout.system_plist.unlink()
        self.runner.jobs["system/io.local.claudewatch.timezone"] = False
        self.perform()
        self.assertEqual(module.app_identity(self.layout.app), ("3.0.0", "314"))
        self.assertFalse(any(call[0] == "/usr/bin/sudo" for call in self.runner.calls))
        self.assert_preserved()

    def test_already_clean_system_can_build_without_repeating_uninstall(self):
        shutil.rmtree(self.layout.app)
        shutil.rmtree(self.layout.base)
        self.prefs.unlink()
        self.layout.agent.unlink()
        shutil.rmtree(self.layout.system_root)
        self.layout.system_plist.unlink()
        self.runner.jobs[f"gui/{self.uid}/io.local.claudewatch.agent"] = False
        self.runner.jobs["system/io.local.claudewatch.timezone"] = False
        self.runner.prefs = False
        self.perform()
        self.assertEqual(module.app_identity(self.layout.app), ("3.0.0", "314"))
        self.assertFalse(any("app-uninstall" in call for call in self.runner.calls))
        self.assert_preserved()

    def test_running_claude_and_unknown_system_files_block_before_uninstall(self):
        self.runner.process_output = f"{self.uid} /Applications/Claude.app/Contents/MacOS/Claude\n"
        with self.assertRaisesRegex(module.Stop, "退出 Claude"):
            self.perform()
        self.runner.process_output = ""
        (self.layout.system_root / "unknown").write_text("do not remove")
        with self.assertRaisesRegex(module.Stop, "未知文件"):
            self.perform()
        self.assertTrue(self.layout.app.exists())
        self.assertTrue((self.layout.system_root / "unknown").exists())
        self.assert_preserved()

    def test_uninstall_failure_does_not_clean_or_package(self):
        self.runner.fail = "uninstall"
        with self.assertRaisesRegex(module.Stop, "执行失败"):
            self.perform()
        self.assertTrue(self.layout.app.exists())
        self.assertTrue(self.layout.base.exists())
        self.assertFalse(any(call[0] in ("/usr/bin/sudo", "/bin/bash") for call in self.runner.calls))
        self.assert_preserved()

    def test_watch_process_that_does_not_exit_is_not_killed_or_cleaned(self):
        self.runner.process_output = f"{self.uid} {self.layout.base}/runtime/watch-engine daemon\n"
        with mock.patch.object(module.time, "sleep", lambda _: None):
            with self.assertRaisesRegex(module.Stop, "尚未退出"):
                self.perform()
        self.assertTrue(self.layout.base.exists())
        self.assertTrue(self.prefs.exists())
        self.assertFalse(any(call[0] == "/bin/bash" for call in self.runner.calls))
        self.assertFalse(any("kill" in call[0] for call in self.runner.calls))
        self.assert_preserved()

    def test_missing_build_dependency_stops_before_any_uninstall(self):
        self.cargo.unlink()
        with self.assertRaisesRegex(module.Stop, "Cargo"):
            self.perform()
        self.assertTrue(self.layout.app.exists())
        self.assertTrue(self.layout.base.exists())
        self.assertEqual(self.runner.calls, [])
        self.assert_preserved()

    def test_missing_macos_minimum_stops_before_any_uninstall(self):
        (self.layout.project / "monitor/macos-minimum.txt").unlink()
        with self.assertRaisesRegex(module.Stop, "打包脚本"):
            self.perform()
        self.assertTrue(self.layout.app.exists())
        self.assertTrue(self.layout.base.exists())
        self.assertEqual(self.runner.calls, [])
        self.assert_preserved()

    def test_missing_toolchain_stops_before_any_uninstall(self):
        self.runner.fail = "toolchain"
        with self.assertRaisesRegex(module.Stop, "系统工具"):
            self.perform()
        self.assertTrue(self.layout.app.exists())
        self.assertTrue(self.layout.base.exists())
        self.assertEqual(self.runner.calls, [])
        self.assert_preserved()

    def test_install_failure_never_opens_application_or_deletes_package(self):
        self.runner.fail = "install"
        with self.assertRaisesRegex(module.Stop, "执行失败"):
            self.perform()
        self.assertFalse(any(call[0] == "/usr/bin/open" for call in self.runner.calls))
        self.assertEqual(len(list((self.layout.project / "monitor/dist").glob("*build314*.dmg"))), 1)
        self.assert_preserved()

    def test_invalid_version_is_rejected_without_calling_system_tools(self):
        with self.assertRaisesRegex(module.Stop, "build"):
            with contextlib.redirect_stdout(io.StringIO()):
                module.perform(self.layout, self.runner, "3.0.0", "314;unsafe", dry_run=True,
                               confirm=lambda _: "", uid=self.uid, cargo=str(self.cargo))
        self.assertEqual(self.runner.calls, [])

    def test_build_and_checksum_failure_never_install(self):
        self.runner.fail = "package"
        with self.assertRaisesRegex(module.Stop, "未执行安装"):
            self.perform()
        self.assertFalse(any("app-install" in call for call in self.runner.calls))
        self.assert_preserved()

    def test_checksum_mismatch_never_installs(self):
        self.runner.fail = "checksum"
        with self.assertRaisesRegex(module.Stop, "校验不匹配"):
            self.perform()
        self.assertFalse(any("app-install" in call for call in self.runner.calls))
        self.assert_preserved()

    def test_app_created_during_build_is_not_replaced(self):
        self.runner.fail = "reappeared"
        with self.assertRaisesRegex(module.Stop, "发生变化"):
            self.perform()
        self.assertEqual(module.app_identity(self.layout.app), ("9.9.9", "999"))
        self.assertFalse(any("app-install" in call for call in self.runner.calls))
        self.assert_preserved()

    def test_missing_app_with_residual_data_stops(self):
        shutil.rmtree(self.layout.app)
        with self.assertRaisesRegex(module.Stop, "仍有残留"):
            self.perform()
        self.assertTrue(self.layout.base.exists())
        self.assert_preserved()

    def test_current_state_change_after_confirmation_stops(self):
        def change(_):
            make_app(self.layout.app, "3.0.0", "999")
            return "重置并安装"
        with self.assertRaisesRegex(module.Stop, "发生变化"):
            self.perform(confirm=change)
        self.assertTrue(self.layout.app.exists())
        self.assertTrue(self.layout.base.exists())
        self.assert_preserved()


if __name__ == "__main__":
    unittest.main()
