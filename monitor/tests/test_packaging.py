#!/usr/bin/env python3
"""Isolated checks for the user-triggered DMG backend installer.

The tests create a temporary app next to a copied .command file.  They never
touch /Applications, launchctl, TAG, or the user's existing watch service.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "Packaging" / "安装或更新后台.command"
APP_NAME = "Claude Watch Monitor.app"


class PackagingInstallerTests(unittest.TestCase):
    def make_fixture(self, *, version: str = "2.2.0", tamper: Optional[str] = None):
        temp = tempfile.TemporaryDirectory(prefix="Claude Watch 包装验证 空格 ")
        self.addCleanup(temp.cleanup)
        package_root = Path(temp.name)
        app = package_root / APP_NAME
        resources = app / "Contents" / "Resources"
        resources.mkdir(parents=True)
        backend = resources / "claude-watch.sh"
        marker = resources / "install-was-run"
        backend.write_text(
            "#!/bin/bash\n"
            f"VERSION='{version}'\n"
            "if [[ \"${1:-}\" == 'install' ]]; then\n"
            f"  : > {marker!s}\n"
            "fi\n",
            encoding="utf-8",
        )
        backend.chmod(0o700)
        expected_sha = hashlib.sha256(backend.read_bytes()).hexdigest()
        if tamper == "version":
            backend.write_text(backend.read_text(encoding="utf-8").replace(version, "9.9.9"), encoding="utf-8")
        elif tamper == "hash":
            backend.write_text(backend.read_text(encoding="utf-8") + "# changed\n", encoding="utf-8")

        with (resources / "BuildInfo.plist").open("wb") as manifest:
            plistlib.dump(
                {
                    "ProductVersion": "2.2.0",
                    "BackendVersion": version,
                    "BackendSHA256": expected_sha,
                },
                manifest,
            )
        command = package_root / "安装或更新后台.command"
        shutil.copy2(INSTALLER, command)
        command.chmod(0o755)
        return package_root, command, marker

    def run_command(self, command: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/bash", str(command)],
            input="取消\n",
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(command.parent),
            capture_output=True,
            check=False,
            timeout=10,
            env={**os.environ, "LC_ALL": "en_US.UTF-8"},
        )

    def test_cancelled_install_does_not_run_backend_in_unicode_space_path(self):
        _, command, marker = self.make_fixture()
        result = self.run_command(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("已取消", result.stdout)
        self.assertFalse(marker.exists(), "dummy backend must not execute after cancellation")

    def test_matching_installed_app_is_reported_and_can_cancel_in_utf8_locale(self):
        package_root, command, marker = self.make_fixture()
        installed_root = package_root / "模拟 Applications"
        shutil.copytree(package_root / APP_NAME, installed_root / APP_NAME)
        command.write_text(command.read_text(encoding="utf-8").replace(
            'APPLICATIONS_APP="/Applications/$APP_NAME"',
            'APPLICATIONS_APP="' + str(installed_root) + '/$APP_NAME"'), encoding="utf-8")
        result = self.run_command(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("已验证 Applications", result.stdout)
        self.assertIn("已取消", result.stdout)
        self.assertFalse(marker.exists())

    def test_tampered_backend_version_is_rejected_before_confirmation(self):
        _, command, marker = self.make_fixture(tamper="version")
        result = self.run_command(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("版本或校验值不匹配", result.stderr)
        self.assertFalse(marker.exists())

    def test_tampered_backend_hash_is_rejected_before_confirmation(self):
        _, command, marker = self.make_fixture(tamper="hash")
        result = self.run_command(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("版本或校验值不匹配", result.stderr)
        self.assertFalse(marker.exists())

    def runtime_fixture(self, tamper=False):
        root, command, marker = self.make_fixture(version="2.4.0")
        resources = root / APP_NAME / "Contents/Resources"
        names = ["switcher.py", "watch-admin.sh", "watch-process-control", "dns_probe.py", "netcoffee_client.py"]
        names += ["watch_switcher/" + name + ".py" for name in
                  ("__init__", "common", "accounts", "audit", "system", "repair", "rules", "services", "stun", "update", "diagnostics", "onboarding", "region", "automatic_policy", "session_guard", "upstream_accounts", "dns_refresh")]
        names += ["ThirdParty/ClaudeSwitcher/UPSTREAM.json", "ThirdParty/ClaudeSwitcher/upstream/core/claude-switch.sh"]
        for name in names:
            item = resources / name
            item.parent.mkdir(parents=True, exist_ok=True)
            item.write_text("# isolated fixture\n")
        module = resources / "switcher.py"
        manifest = resources / "BuildInfo.plist"
        data = plistlib.loads(manifest.read_bytes())
        data.update(SwitcherSchema=1, RuntimeHashes={name: hashlib.sha256((resources/name).read_bytes()).hexdigest() for name in names})
        manifest.write_bytes(plistlib.dumps(data))
        if tamper: module.write_text("# different fixture\n")
        return command, marker

    def test_new_runtime_manifest_verified_before_confirmation(self):
        command, marker = self.runtime_fixture()
        result = self.run_command(command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("已取消", result.stdout)
        self.assertFalse(marker.exists())

    def test_tampered_runtime_rejected_without_installing(self):
        command, marker = self.runtime_fixture(tamper=True)
        result = self.run_command(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())

    def test_incomplete_runtime_catalog_rejected(self):
        command, marker = self.runtime_fixture()
        manifest = command.parent / APP_NAME / "Contents/Resources/BuildInfo.plist"
        data = plistlib.loads(manifest.read_bytes())
        del data["RuntimeHashes"]["watch-process-control"]
        manifest.write_bytes(plistlib.dumps(data))
        self.assertNotEqual(self.run_command(command).returncode, 0)
        self.assertFalse(marker.exists())

    def test_missing_diagnostic_module_is_rejected_before_install(self):
        command, marker = self.runtime_fixture()
        resources = command.parent / APP_NAME / "Contents/Resources"
        (resources / "watch_switcher/diagnostics.py").unlink()
        self.assertNotEqual(self.run_command(command).returncode, 0)
        self.assertFalse(marker.exists())

    def test_missing_shared_metadata_client_is_rejected_before_install(self):
        command, marker = self.runtime_fixture()
        resources = command.parent / APP_NAME / "Contents/Resources"
        (resources / "netcoffee_client.py").unlink()
        self.assertNotEqual(self.run_command(command).returncode, 0)
        self.assertFalse(marker.exists())

    def test_missing_onboarding_module_is_rejected_before_install(self):
        command, marker = self.runtime_fixture()
        resources = command.parent / APP_NAME / "Contents/Resources"
        (resources / "watch_switcher/onboarding.py").unlink()
        self.assertNotEqual(self.run_command(command).returncode, 0)
        self.assertFalse(marker.exists())

    def test_missing_region_module_is_rejected_before_install(self):
        command, marker = self.runtime_fixture()
        resources = command.parent / APP_NAME / "Contents/Resources"
        (resources / "watch_switcher/region.py").unlink()
        self.assertNotEqual(self.run_command(command).returncode, 0)
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
