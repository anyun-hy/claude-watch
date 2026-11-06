"""Static security contracts. macOS system extension activation still needs device tests."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILD = (ROOT / "monitor/build.sh").read_text()
EXT = (ROOT / "monitor/SystemExtension/WatchChannelExtension.swift").read_text()
HOST = (ROOT / "monitor/Sources/NetworkExtensionHostManager.swift").read_text()
DAEMON = (ROOT / "crates/watch-engine/src/daemon_run.rs").read_text()
CONTRACT = (ROOT / "monitor/SystemExtension/ChannelContract.swift").read_text()
IDENTITY = (ROOT / "monitor/SystemExtension/ChannelIdentity.swift").read_text()


class ExtensionActivationAndAttribution(unittest.TestCase):
    def test_production_build_requires_explicit_signature_and_profiles(self):
        self.assertIn('CW_CODESIGN_IDENTITY', BUILD)
        self.assertIn('CW_HOST_PROFILE', BUILD)
        self.assertIn('CW_EXTENSION_PROFILE', BUILD)
        self.assertIn("root / 'Signing' / f'{kind}.entitlements'", BUILD)
        self.assertIn('--entitlements "$ROOT/build/channel-signing/Extension.entitlements"', BUILD)
        self.assertIn('--entitlements "$ROOT/build/channel-signing/Host.entitlements"', BUILD)
        host = (ROOT / "monitor/Signing/Host.entitlements").read_text()
        extension = (ROOT / "monitor/Signing/Extension.entitlements").read_text()
        self.assertIn('com.apple.developer.system-extension.install', host)
        self.assertIn('app-proxy-provider-systemextension', host)
        self.assertIn('app-proxy-provider-systemextension', extension)

    def test_connected_is_not_conflated_with_enabled(self):
        self.assertIn('isSystemExtensionActive: isConnected', HOST)
        self.assertNotIn('isSystemExtensionActive: isEnabled', HOST)
        self.assertIn('guard canInstallSystemExtension()', HOST)

    def test_managed_source_requires_bound_permission(self):
        self.assertIn('sourceAppSigningIdentifier', EXT)
        self.assertNotIn('auditToken?.count == 32 && !managed', CONTRACT)
        self.assertIn('ownership == .unmanaged', CONTRACT)
        self.assertIn('words[1] == info.pbi_uid', IDENTITY)
        self.assertIn('if channelMayBypass(ownership: classification) { return false }', EXT)
        self.assertIn('let permit = families[family], permit.isLive', EXT)
        self.assertGreaterEqual(EXT.count('isForwardAuthorized(flowID: flowID, pid: flowPid)'), 3)
        cleanup = EXT.split('private func cleanupFlow(id:', 1)[1].split('private func terminateFlowsLocked', 1)[0]
        self.assertLess(cleanup.index('if record.connection.cancel()'), cleanup.index('activeFlows.removeValue'))

    def test_old_disk_commands_not_authorized_after_restart(self):
        self.assertIn('providerStartedAt = Date().timeIntervalSince1970', EXT)
        self.assertIn('command.canGrant(providerStartedAt: providerStartedAt, now: now)', EXT)
        self.assertIn('issued_at >= providerStartedAt', CONTRACT)


if __name__ == "__main__":
    unittest.main()
