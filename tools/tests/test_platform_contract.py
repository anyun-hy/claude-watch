"""Docs and deployment-target parity checks; read-only, no build or installation."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class DeploymentContract(unittest.TestCase):
    def test_current_minimum_matches_documented_build_target(self):
        minimum = (ROOT / "monitor/macos-minimum.txt").read_text(encoding="utf-8").strip()
        self.assertRegex(minimum, r"^[0-9]+\.[0-9]+$")
        for path, phrase in [
            ("README.md", f"（现为 macOS {minimum}）"),
            ("monitor/README.md", f"（当前为 macOS {minimum}；"),
        ]:
            self.assertIn(phrase, (ROOT / path).read_text(encoding="utf-8"), path)

    def test_build_and_tests_read_the_same_deployment_file(self):
        build = (ROOT / "monitor/build.sh").read_text(encoding="utf-8")
        runner = (ROOT / "tools/test-final-no-signal.sh").read_text(encoding="utf-8")
        self.assertIn('CW_MACOS_MINIMUM=$(/bin/cat "$ROOT/macos-minimum.txt")', build)
        self.assertIn("MIN=$(cat monitor/macos-minimum.txt)", runner)
        self.assertNotIn("生产应用目标为 macOS 13 以上", (ROOT / "README.md").read_text(encoding="utf-8"))

    def test_process_identity_race_is_not_claimed_atomic(self):
        control = (ROOT / "monitor/Sources/AIProcessControl.swift").read_text(encoding="utf-8")
        self.assertIn("let latest = lookup(target.pid)", control)
        self.assertIn("cannot", control)
        self.assertIn("atomic", control)


if __name__ == "__main__":
    unittest.main()
