"""Static security contracts. macOS system extension activation still needs device tests."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD = (ROOT / "monitor/build.sh").read_text()
EXT = (ROOT / "monitor/SystemExtension/WatchChannelExtension.swift").read_text()
HOST = (ROOT / "monitor/Sources/NetworkExtensionHostManager.swift").read_text()
DAEMON = (ROOT / "crates/watch-engine/src/daemon_run.rs").read_text()


class ExtensionActivationAndAttribution(unittest.TestCase):
    def test_production_build_requires_explicit_signature_and_profiles(self):
        self.assertIn('CW_CODESIGN_IDENTITY', BUILD)
        self.assertIn('CW_HOST_PROFILE', BUILD)
        self.assertIn('CW_EXTENSION_PROFILE', BUILD)
        self.assertIn('--entitlements "$ROOT/Signing/Extension.entitlements"', BUILD)
        self.assertIn('--entitlements "$ROOT/Signing/Host.entitlements"', BUILD)
        host = (ROOT / "monitor/Signing/Host.entitlements").read_text()
        extension = (ROOT / "monitor/Signing/Extension.entitlements").read_text()
        self.assertIn('com.apple.developer.system-extension.install', host)
        self.assertIn('app-proxy-provider-systemextension', host)
        self.assertIn('app-proxy-provider-systemextension', extension)

    def test_connected_is_not_conflated_with_enabled(self):
        self.assertIn('isSystemExtensionActive: isConnected', HOST)
        self.assertNotIn('isSystemExtensionActive: isEnabled', HOST)

    def test_unknown_source_cannot_silently_bypass(self):
        self.assertIn('sourceAppSigningIdentifier', EXT)
        self.assertIn('sourceAppAuditToken?.count == 32', EXT)
        self.assertIn('hasManagedAncestor(pid: pid, uid: uid, managed: managed)', EXT)
        self.assertIn('|| !validSourceIdentity', EXT)
        self.assertIn('if !isAiFlow {', EXT)
        self.assertIn('authorizedAtRegistration', EXT)
        self.assertIn('isForwardAuthorized(flowID: flowID, pid: flowPid)', EXT)
        self.assertIn('activeFlows[id] = closing', EXT)
        self.assertNotIn('status: "revoked"', EXT.split('private func cleanupFlow(id:', 1)[1].split('private func terminateAllActiveFlowsLocked', 1)[0])

    def test_old_disk_commands_not_authorized_after_restart(self):
        self.assertIn('providerBootEpochSeconds', EXT)
        self.assertIn('issued_at', DAEMON)
        self.assertIn('issuedAt >= providerBootEpochSeconds', EXT)


if __name__ == "__main__":
    unittest.main()
