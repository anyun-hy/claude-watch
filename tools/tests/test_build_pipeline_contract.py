"""No-execution build pipeline contract tests. Reads sources only."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
APP_BUILD = (ROOT / "monitor/build.sh").read_text(encoding="utf-8")
PACKAGE = (ROOT / "monitor/package-dmg.sh").read_text(encoding="utf-8")
RUST = (ROOT / "tools/build-rust-components.sh").read_text(encoding="utf-8")


class BuildPipelineContract(unittest.TestCase):
    def test_one_authoritative_process_helper(self):
        self.assertNotIn("-D PROCESS_HELPER", APP_BUILD)
        self.assertNotIn('build/watch-process-control.$CW_BUILD_ARCH', APP_BUILD)
        self.assertIn('for key in ("engine", "native_observer", "process_control"):', APP_BUILD)
        self.assertIn("shutil.copy2(source, destination)", APP_BUILD)
        self.assertIn('destination.chmod(0o700)', APP_BUILD)

    def test_stage_checks_integrity_before_copy(self):
        self.assertIn('assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]', APP_BUILD)
        self.assertIn('len(set(bundle_names.values()))', RUST)
        self.assertIn('candidate.is_symlink()', RUST)

    def test_app_path_is_the_same_between_build_and_package(self):
        name = "Claude Watch Monitor Rust Candidate.app"
        self.assertIn('APP="$ROOT/build/' + name + '"', APP_BUILD)
        self.assertIn('APP="${CW_APP_OUTPUT:-$ROOT/build/' + name + '}"', PACKAGE)
        self.assertIn('APP=$CW_APP_OUTPUT', APP_BUILD)

    def test_package_invokes_one_build_and_validates_version(self):
        self.assertEqual(len(re.findall(r'(?m)^APP_VERSION="\$APP_VERSION" BUILD_NUMBER="\$BUILD_NUMBER" /bin/bash "\$ROOT/build.sh"$', PACKAGE)), 1)
        self.assertIn('ACTUAL_BUILD', PACKAGE)
        self.assertIn('ACTUAL_VERSION', PACKAGE)
        self.assertIn('/usr/bin/codesign --verify --deep --strict', PACKAGE)

    def test_swift_worker_is_built_and_not_shadowed(self):
        self.assertIn('-D BACKGROUND_LEAK_WORKER', APP_BUILD)
        self.assertIn('watch-leak-worker.$CW_BUILD_ARCH', APP_BUILD)
        self.assertIn('cp "$ROOT/build/watch-leak-worker.$CW_BUILD_ARCH" "$APP/Contents/Resources/watch-leak-worker"', APP_BUILD)

    def test_build_has_no_installer_or_delete_command(self):
        self.assertNotIn('app-uninstall --apply', APP_BUILD)
        self.assertNotIn('reinstall.sh', APP_BUILD)
        self.assertNotIn('rm -rf "/Applications', APP_BUILD)


if __name__ == "__main__":
    unittest.main()
