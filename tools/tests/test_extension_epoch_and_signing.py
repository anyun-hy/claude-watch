"""Only the new wake/activation wiring and build preflight; never build or activate an app."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BUILD_PATH = ROOT / "monitor/build.sh"
BUILD = BUILD_PATH.read_text()
HOST = (ROOT / "monitor/Sources/NetworkExtensionHostManager.swift").read_text()
EXT = (ROOT / "monitor/SystemExtension/WatchChannelExtension.swift").read_text()


class ExtensionEpochAndSigning(unittest.TestCase):
    def preflight(self, settings):
        # Execute production alias/required-mode/profile-presence checks, ending
        # before the first mkdir, security/profile parser, compiler or codesign.
        marker = '  mkdir -p "$ROOT/build/channel-signing"'
        self.assertEqual(BUILD.count(marker), 1)
        prefix = BUILD.split(marker, 1)[0] + '\nfi\n'
        prefix += 'printf "resolved:%s|%s|%s\\n" "$CW_SIGNING_IDENTITY" "$CW_HOST_PROVISION_PROFILE" "$CW_EXTENSION_PROVISION_PROFILE"\n'
        env = {k: v for k, v in os.environ.items() if not k.startswith("CW_")}
        env.update(settings)
        return subprocess.run(["/bin/bash", "-c", prefix, str(BUILD_PATH)], env=env,
                              text=True, capture_output=True, timeout=5)

    def test_required_mode_rejects_missing_or_ad_hoc_identity(self):
        for alias in [None, "CW_SIGNING_IDENTITY", "CW_CODESIGN_IDENTITY", "CW_SIGN_IDENTITY"]:
            with self.subTest(alias=alias):
                settings = {"CW_REQUIRE_ENTITLED_NETWORK_EXTENSION": "1"}
                if alias:
                    settings[alias] = "-"
                result = self.preflight(settings)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("cannot use an ad-hoc signature", result.stderr)

    def test_supported_signing_aliases_preserve_production_profile_checks(self):
        groups = [
            ("CW_SIGNING_IDENTITY", "CW_HOST_PROVISION_PROFILE", "CW_EXTENSION_PROVISION_PROFILE"),
            ("CW_CODESIGN_IDENTITY", "CW_HOST_PROFILE", "CW_EXTENSION_PROFILE"),
            ("CW_SIGN_IDENTITY", "CW_APP_PROVISIONING_PROFILE", "CW_EXTENSION_PROVISIONING_PROFILE"),
        ]
        with tempfile.TemporaryDirectory(prefix="cw-signing-preflight-") as temporary:
            host = str(Path(temporary) / "host.profile")
            extension = str(Path(temporary) / "extension.profile")
            Path(host).touch()
            Path(extension).touch()
            for identity_key, host_key, extension_key in groups:
                with self.subTest(identity_key=identity_key):
                    settings = {"CW_REQUIRE_ENTITLED_NETWORK_EXTENSION": "1", identity_key: "Fixture Developer ID",
                                host_key: host, extension_key: extension}
                    result = self.preflight(settings)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f"resolved:Fixture Developer ID|{host}|{extension}", result.stdout)
                    del settings[host_key]
                    missing = self.preflight(settings)
                    self.assertNotEqual(missing.returncode, 0)
                    self.assertIn("Set the Developer ID profile", missing.stderr)

    def test_alias_conflicts_and_invalid_required_mode_fail(self):
        groups = [
            ("CW_SIGNING_IDENTITY", "CW_CODESIGN_IDENTITY", "CW_SIGN_IDENTITY"),
            ("CW_HOST_PROVISION_PROFILE", "CW_HOST_PROFILE", "CW_APP_PROVISIONING_PROFILE"),
            ("CW_EXTENSION_PROVISION_PROFILE", "CW_EXTENSION_PROFILE", "CW_EXTENSION_PROVISIONING_PROFILE"),
        ]
        for keys in groups:
            for left, right in [(keys[0], keys[1]), (keys[0], keys[2]), (keys[1], keys[2])]:
                with self.subTest(left=left, right=right):
                    result = self.preflight({left: "one", right: "two"})
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("Conflicting signing identity/profile aliases", result.stderr)
        for value in ["true", "2"]:
            with self.subTest(required=value):
                result = self.preflight({"CW_REQUIRE_ENTITLED_NETWORK_EXTENSION": value})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("must be 0 or 1", result.stderr)

    def test_development_mode_remains_explicitly_available(self):
        for settings in [{}, {"CW_REQUIRE_ENTITLED_NETWORK_EXTENSION": "0"}]:
            result = self.preflight(settings)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("resolved:-||", result.stdout)

    def test_every_host_activation_entry_checks_both_capabilities_before_os_calls(self):
        entries = {
            "startAndActivateIfNeeded": "refreshStatus {",
            "refreshStatus": "NETransparentProxyManager.loadAllFromPreferences",
            "setupAndEnableTransparentProxyConfiguration": "isSettingUpConfiguration = true",
            "requestActivation": "OSSystemExtensionRequest.activationRequest",
        }
        for name, first_effect in entries.items():
            with self.subTest(entry=name):
                body = HOST.split(f"public func {name}(", 1)[1].split("\n    public func ", 1)[0]
                self.assertLess(body.index("guard hasRequiredSigningEntitlements()"), body.index(first_effect))
                self.assertIn("failUnsignedActivation()", body)
        self.assertIn("NetworkExtensionCapabilities.allowsActivation(", HOST)

    def test_sleep_and_wake_install_fence_before_control_queue_work(self):
        sleeping = EXT.split("open override func sleep(", 1)[1].split("open override func wake()", 1)[0]
        self.assertLess(sleeping.index("executionEpoch.suspend()"), sleeping.index("revokeAllLocked("))
        waking = EXT.split("open override func wake()", 1)[1].split("open override func handleNewFlow", 1)[0]
        self.assertLess(waking.index("executionEpoch.wake("), waking.index("revokeAllLocked("))
        self.assertLess(waking.index("revokeAllLocked("), waking.index("controlQueue.async"))
        self.assertLess(waking.index("emitHeartbeat()"), waking.index("controlQueue.async"))
        self.assertIn("executionEpoch.permits(command, acknowledgedBoot: envelope.extension_boot_id, now: now)", EXT)
        self.assertLess(EXT.index("let allowed = executionEpoch.permits("),
                        EXT.index("if let previous = previous, previous.seq == command.command_seq"))


if __name__ == "__main__":
    unittest.main()
