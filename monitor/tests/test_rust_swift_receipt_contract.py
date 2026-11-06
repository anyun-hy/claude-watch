#!/usr/bin/env python3
"""Decode offline Rust-engine receipts with declarations extracted from Swift sources.

This is deliberately a compile-and-run boundary test: the Swift decoder uses
the production declarations verbatim, rather than shadow structs maintained by
the test.  It only invokes documented read commands against a private home.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "target" / "debug" / "claude-watch-engine"
SWITCHER = ROOT / "monitor" / "Sources" / "SwitcherStore.swift"
MODELS = ROOT / "monitor" / "Sources" / "MonitorModels.swift"
COFFEE = ROOT / "monitor" / "Sources" / "NetCoffeeModels.swift"
LEAK = ROOT / "monitor" / "Sources" / "LeakCheckModels.swift"
INIT_LOG = ROOT / "monitor" / "Sources" / "InitializationConnectionLog.swift"
RUST_ONLINE_LOOKUP = ROOT / "monitor" / "tests" / "fixtures" / "rust-netcoffee-lookup-receipt.json"


def declaration(path: Path, name: str) -> str:
    """Extract one complete production Swift declaration without rewriting it."""
    source = path.read_text(encoding="utf-8")
    starts = (f"struct {name}", f"enum {name}", f"indirect enum {name}", f"private extension {name}")
    start = next((source.find(token) for token in starts if source.find(token) >= 0), -1)
    if start < 0:
        raise AssertionError(f"Swift declaration {name} not found in {path}")
    brace = source.find("{", start)
    if brace < 0:
        raise AssertionError(f"Swift declaration {name} has no body")
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"Swift declaration {name} is unterminated")


def production_models() -> str:
    # Keep this list narrow and ordered by declaration dependency.  Every item
    # is copied byte-for-byte from the app source by declaration(), not modeled
    # again in this test.
    requested = (
        (LEAK, "LeakIPAddress"),
        (COFFEE, "CoffeeJSON"),
        (COFFEE, "JSONEncoder"),
        (COFFEE, "CoffeeReceipt"),
        (SWITCHER, "EnvironmentCheckRow"),
        (SWITCHER, "EnvironmentSourceNotice"),
        (SWITCHER, "EgressReference"),
        (SWITCHER, "GuardRisk"),
        (SWITCHER, "ProtectionFacts"),
        (SWITCHER, "SessionGuardReason"),
        (SWITCHER, "SessionGuardStatus"),
        (SWITCHER, "EnvironmentAuditReceipt"),
        (SWITCHER, "EnvironmentContextTransition"),
        (SWITCHER, "EnvironmentPolicyEvaluation"),
        # The audit receipt carries the engine's display evidence, so the
        # declarations it decodes are part of the same production model.
        (SWITCHER, "EnvironmentTagAPI"),
        (SWITCHER, "EnvironmentTagEvidence"),
        (SWITCHER, "EnvironmentRulesEvidence"),
        (SWITCHER, "EnvironmentLocalFacts"),
        (SWITCHER, "EnvironmentTraceFacts"),
        (SWITCHER, "EnvironmentGeoFacts"),
        (SWITCHER, "EnvironmentOnlineFacts"),
        (SWITCHER, "EnvironmentDisplayFacts"),
        (SWITCHER, "InitializationBackendReceipt"),
        (SWITCHER, "InitializationReceiptEvidence"),
        (INIT_LOG, "BackendInitializationDiagnostics"),
        (SWITCHER, "CurrentEnvironmentReceipt"),
        (SWITCHER, "BackgroundServiceRow"),
        (SWITCHER, "PolicyIssue"),
        (SWITCHER, "BackgroundServiceReceipt"),
        (SWITCHER, "SwitcherAccountSlot"),
        (SWITCHER, "SwitcherAccountState"),
        (MODELS, "Health"),
        (MODELS, "WatchedProcess"),
        (MODELS, "ProcessSourceRole"),
        (MODELS, "MonitoredProduct"),
        (MODELS, "Event"),
        (MODELS, "Flow"),
        (MODELS, "ProxySnapshot"),
        (MODELS, "ConnectionObservation"),
        (MODELS, "ChannelPolicyVersionModel"),
        (MODELS, "ChannelMonitorDisplayState"),
        (MODELS, "PolicySyncState"),
        (MODELS, "BoundProcessTokenModel"),
        (MODELS, "FamilyChannelMonitorState"),
        (MODELS, "ChannelMonitorSnapshot"),
        (MODELS, "ChannelMonitorEvent"),
        (MODELS, "MonitorSnapshot"),
    )
    return "\n\n".join(declaration(path, name) for path, name in requested)


HARNESS = r'''
import Foundation

func fail(_ message: String) -> Never { fputs("FAIL: \(message)\n", stderr); exit(1) }
func data(_ path: String) throws -> Data { try Data(contentsOf: URL(fileURLWithPath: path)) }
func object(_ path: String) throws -> [String: Any] {
    guard let value = try JSONSerialization.jsonObject(with: data(path)) as? [String: Any] else {
        fail("\(path): expected JSON object")
    }
    return value
}
func nested(_ value: [String: Any], _ key: String, _ path: String) throws -> Data {
    guard let item = value[key] else { fail("\(path): missing \(key)") }
    return try JSONSerialization.data(withJSONObject: item)
}
func require(_ condition: Bool, _ message: String) { if !condition { fail(message) } }

@main
struct RustSwiftReceiptContract {
    static func main() throws {
        let arguments = Array(CommandLine.arguments.dropFirst())
        guard arguments.count == 6 else { fail("expected status audit service environment snapshot lookup paths") }
        let decoder = JSONDecoder()
        let status = try object(arguments[0])
        let accounts = try decoder.decode(SwitcherAccountState.self, from: nested(status, "accounts", arguments[0]))
        let serviceFromStatus = try decoder.decode(BackgroundServiceReceipt.self, from: nested(status, "service_status", arguments[0]))
        require(!accounts.detail.isEmpty, "status.accounts.detail is empty")
        require(!serviceFromStatus.services.isEmpty, "status.service_status.services is empty")
        // SwitcherStore intentionally treats status.audit as optional.  A new
        // private --home has no persisted audit, while a populated receipt must
        // still decode with the same production EnvironmentAuditReceipt model.
        if let auditValue = status["audit"], !(auditValue is NSNull) {
            let auditFromStatus = try decoder.decode(EnvironmentAuditReceipt.self, from: nested(status, "audit", arguments[0]))
            require(!auditFromStatus.rows.isEmpty, "status.audit.rows is empty")
        } else {
            require(status["audit"] is NSNull, "status.audit missing or not JSON null")
        }

        let audit = try decoder.decode(EnvironmentAuditReceipt.self, from: data(arguments[1]))
        require(!audit.rows.isEmpty, "checkdetail rows is empty")
        let service = try decoder.decode(BackgroundServiceReceipt.self, from: data(arguments[2]))
        require(!service.services.isEmpty, "service-status services is empty")
        let environment = try decoder.decode(CurrentEnvironmentReceipt.self, from: data(arguments[3]))
        require(!environment.rows.isEmpty, "environment rows is empty")
        let snapshot = try decoder.decode(MonitorSnapshot.self, from: data(arguments[4]))
        require(!snapshot.health.state.isEmpty, "snapshot health state is empty")
        let lookupEnvelope = try object(arguments[5])
        let lookup = try decoder.decode(CoffeeReceipt.self, from: nested(lookupEnvelope, "netcoffee_lookup", arguments[5]))
        require(lookup.sourceURL.hasPrefix("https://"), "Rust online lookup sourceURL was not decoded")
        require(lookup.queriedAt > 0 && lookup.finishedAt >= lookup.queriedAt, "Rust online lookup timestamps were not decoded")
        require(lookup.httpStatus == 200, "Rust online lookup httpStatus was not decoded")
        print("RustSwiftReceiptContract: decoded status nested accounts/audit/service, checkdetail --no-report, service-status, environment, snapshot, and non-null Rust online lookup")
    }
}
'''


class RustSwiftReceiptContractTests(unittest.TestCase):
    maxDiff = None

    def test_offline_engine_receipts_decode_with_real_swift_models(self):
        self.assertTrue(ENGINE.is_file(), f"missing built engine: {ENGINE}; run cargo build first")
        self.assertTrue(RUST_ONLINE_LOOKUP.is_file(), f"missing Rust online lookup fixture: {RUST_ONLINE_LOOKUP}")
        swift_flags = ["-parse-as-library"]
        if platform.system() == "Darwin":
            xcrun = shutil.which("xcrun")
            self.assertIsNotNone(xcrun, "xcrun is required on macOS for the production-model decoder")
            swiftc = subprocess.check_output([xcrun, "--sdk", "macosx", "--find", "swiftc"], text=True).strip()
            sdk = subprocess.check_output([xcrun, "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
            minimum = (ROOT / "monitor" / "macos-minimum.txt").read_text(encoding="utf-8").strip()
            arch = platform.machine()
            swift_flags.extend(["-sdk", sdk, "-target", f"{arch}-apple-macosx{minimum}"])
        else:
            swiftc = shutil.which("swiftc")
            self.assertIsNotNone(swiftc, "swiftc is required for the production-model decoder")
        commands = {
            "status": ["status"],
            "audit": ["checkdetail", "--no-report"],
            "service": ["service-status"],
            "environment": ["environment"],
            "snapshot": ["snapshot"],
        }
        with tempfile.TemporaryDirectory(prefix="cw-rust-swift-receipts-") as temp:
            work = Path(temp)
            home = work / "private-home"
            home.mkdir()
            module_cache = work / "module-cache"
            module_cache.mkdir()
            receipt_paths: dict[str, Path] = {}
            for name, command in commands.items():
                output = subprocess.run(
                    [str(ENGINE), *command, "--home", str(home)],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(output.returncode, 0, f"{' '.join(command)} failed: {output.stderr}\n{output.stdout}")
                receipt_path = work / f"{name}.json"
                receipt_path.write_text(output.stdout, encoding="utf-8")
                # Give Python a clear diagnosis if the engine ever stops emitting JSON.
                self.assertIsInstance(json.loads(output.stdout), dict, f"{name} did not emit an object")
                receipt_paths[name] = receipt_path

            source = work / "RustSwiftReceiptContract.swift"
            source.write_text("import Darwin\n" + production_models() + "\n" + HARNESS, encoding="utf-8")
            executable = work / "RustSwiftReceiptContract"
            compiled = subprocess.run(
                [swiftc, *swift_flags, "-module-cache-path", str(module_cache), str(source), "-o", str(executable)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(compiled.returncode, 0, f"Swift production-model harness failed to compile:\n{compiled.stderr}")
            decoded = subprocess.run(
                [str(executable), *(str(receipt_paths[name]) for name in ("status", "audit", "service", "environment", "snapshot")), str(RUST_ONLINE_LOOKUP)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(decoded.returncode, 0, f"Swift decoder rejected engine receipt:\n{decoded.stderr}\n{decoded.stdout}")
            self.assertIn("non-null Rust online lookup", decoded.stdout)


if __name__ == "__main__":
    unittest.main()
