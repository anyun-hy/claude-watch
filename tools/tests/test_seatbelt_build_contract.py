"""Exercise build argument validation only; never compile, sign or install."""
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
BUILD_PATH = ROOT / "monitor/build.sh"
BUILD = BUILD_PATH.read_text()


class SeatbeltBuildContract(unittest.TestCase):
    def preflight(self, settings):
        marker = "# The Python backend is retired:"
        self.assertEqual(BUILD.count(marker), 1)
        prefix = BUILD.split(marker, 1)[0]
        prefix += 'printf "resolved:%s|%s\\n" "$CW_NETWORK_BACKEND" "$CW_SIGNING_IDENTITY"\n'
        env = {key: value for key, value in os.environ.items() if not key.startswith("CW_")}
        env.update(settings)
        return subprocess.run(["/bin/bash", "-c", prefix, str(BUILD_PATH)], env=env,
                              text=True, capture_output=True, timeout=5)

    def test_default_and_nono_alias_require_no_paid_identity(self):
        for settings in ({}, {"CW_NETWORK_BACKEND": "seatbelt"}, {"CW_NETWORK_BACKEND": "nono"}):
            with self.subTest(settings=settings):
                result = self.preflight(settings)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "resolved:seatbelt|-")

    def test_retired_or_unknown_backend_never_silently_builds_seatbelt(self):
        for backend in ("network-extension", "network_extension", "ne", "legacy_ne", "unknown"):
            with self.subTest(backend=backend):
                result = self.preflight({"CW_NETWORK_BACKEND": backend})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("only nono/Seatbelt is available", result.stderr)
                self.assertNotIn("resolved:", result.stdout)

    def test_retired_entitlement_and_profile_options_are_rejected(self):
        cases = [{"CW_REQUIRE_ENTITLED_NETWORK_EXTENSION": value} for value in ("1", "true", "2")]
        cases += [{key: "/unused/fixture.profile"} for key in (
            "CW_HOST_PROVISION_PROFILE", "CW_HOST_PROFILE", "CW_APP_PROVISIONING_PROFILE",
            "CW_EXTENSION_PROVISION_PROFILE", "CW_EXTENSION_PROFILE", "CW_EXTENSION_PROVISIONING_PROFILE")]
        for settings in cases:
            with self.subTest(settings=settings):
                result = self.preflight(settings)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("retired", result.stderr.lower())
                self.assertNotIn("resolved:", result.stdout)

    def test_generic_signing_aliases_and_conflict_check_remain(self):
        for alias in ("CW_SIGNING_IDENTITY", "CW_CODESIGN_IDENTITY", "CW_SIGN_IDENTITY"):
            result = self.preflight({alias: "Fixture identity"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "resolved:seatbelt|Fixture identity")
        conflict = self.preflight({"CW_SIGNING_IDENTITY": "one", "CW_CODESIGN_IDENTITY": "two"})
        self.assertNotEqual(conflict.returncode, 0)
        self.assertIn("Conflicting signing", conflict.stderr)

    def test_app_sources_and_package_have_no_extension_implementation(self):
        self.assertNotIn("/SystemExtension/*.swift", BUILD)
        self.assertNotIn("--entitlements", BUILD)
        for source in (ROOT / "monitor/Sources").glob("*.swift"):
            content = source.read_text()
            self.assertNotIn("import NetworkExtension", content, source)
            self.assertNotIn("import SystemExtensions", content, source)
            self.assertNotIn("NetworkExtensionHostManager", content, source)
        self.assertIn('rm -rf "$APP/Contents/Library/SystemExtensions"', BUILD)
        self.assertIn('rm -f "$APP/Contents/embedded.provisionprofile"', BUILD)


if __name__ == "__main__":
    unittest.main()
