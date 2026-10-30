#!/usr/bin/env python3
"""Static boundary checks for the opt-in local Rust candidate packager."""

from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "monitor" / "build.sh"
COMPONENTS = ROOT / "tools" / "build-rust-components.sh"
MONITOR_STORE = ROOT / "monitor" / "Sources" / "MonitorStore.swift"
SWITCHER_STORE = ROOT / "monitor" / "Sources" / "SwitcherStore.swift"


class RustCandidatePackagingTests(unittest.TestCase):
    def test_scripts_are_shell_syntax_valid(self):
        for script in (BUILD, COMPONENTS):
            result = subprocess.run(["/bin/bash", "-n", str(script)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_build_rejects_unknown_backend_variant_before_building(self):
        result = subprocess.run(
            ["/bin/bash", str(BUILD)],
            env={**os.environ, "CW_BACKEND_VARIANT": "not-a-variant"},
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unsupported backend variant", result.stderr)

    def test_candidate_rejects_non_arm64_before_building(self):
        result = subprocess.run(
            ["/bin/bash", str(BUILD)],
            env={**os.environ, "CW_BACKEND_VARIANT": "rust-candidate", "CW_BUILD_ARCH": "x86_64"},
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("arm64-only", result.stderr)

    def test_candidate_is_explicit_arm64_and_requires_component_manifest(self):
        text = BUILD.read_text(encoding="utf-8")
        self.assertIn('CW_BACKEND_VARIANT="${CW_BACKEND_VARIANT:-stable}"', text)
        self.assertIn('"$CW_BACKEND_VARIANT" == rust-candidate', text)
        self.assertIn('"$CW_BUILD_ARCH" != arm64', text)
        self.assertIn('RUST_COMPONENTS_MANIFEST', text)
        self.assertIn('Claude Watch Monitor Rust Candidate.app', text)
        self.assertIn('Refusing to build into an installed application path.', text)
        self.assertIn('<key>BackendVariant</key><string>$CW_BACKEND_VARIANT</string>', text)
        self.assertIn('BACKGROUND_LEAK_WORKER', text)
        self.assertIn('watch-leak-worker', text)
        self.assertIn('netcoffee_probe.html', text)
        self.assertIn('<key>BackgroundEvidenceSchema</key><integer>$BACKGROUND_EVIDENCE_SCHEMA</integer>', text)
        self.assertIn('BACKGROUND_EVIDENCE_SCHEMA=1', text)

    def test_background_runtime_helper_has_a_fixed_runtime_contract_test(self):
        test = ROOT / "monitor/tests/run_background_leak_worker_runtime_test.sh"
        text = test.read_text(encoding="utf-8")
        self.assertIn('-D BACKGROUND_LEAK_WORKER', text)
        self.assertIn("BackgroundEvidenceSchema", text)
        self.assertIn("RuntimeHashes", text)
        self.assertIn("('--dns', '--webrtc')", text)
        self.assertIn("start_new_session=True", text)

    def test_background_dns_pipeline_exercises_the_real_webkit_script_offline(self):
        test = ROOT / "monitor/tests/run_background_dns_pipeline_test.sh"
        text = test.read_text(encoding="utf-8")
        self.assertIn("netcoffee_probe.js", text)
        self.assertIn("Object.defineProperty(Image.prototype", text)
        self.assertIn("coffee:trace", text)
        self.assertIn("coffee:dns", text)
        self.assertIn("coffee:geoip", text)
        self.assertIn("BACKGROUND_LEAK_WORKER_TEST", text)

    def test_component_builder_queries_paths_instead_of_hardcoding_native_sources(self):
        text = COMPONENTS.read_text(encoding="utf-8")
        self.assertIn('--bin claude-watch-engine', text)
        self.assertIn('--component-paths', text)
        self.assertIn('"native_observer", "process_control"', text)
        self.assertIn('requires an arm64 host', text)

    def test_gui_runners_select_the_backend_declared_by_build_info(self):
        monitor = MONITOR_STORE.read_text(encoding="utf-8")
        switcher = SWITCHER_STORE.read_text(encoding="utf-8")
        variant = (ROOT / "monitor/Sources/BundledBackendVariant.swift").read_text(encoding="utf-8")
        self.assertIn('values["BackendVariant"]', variant)
        self.assertIn('case "stable": return .stable', variant)
        self.assertIn('case "rust-candidate": return .rustCandidate', variant)
        self.assertIn('case .stable:', monitor)
        self.assertIn('forResource: "snapshot", withExtension: "sh"', monitor)
        self.assertIn('case .rustCandidate:', switcher)
        self.assertIn('forResource: "switcher", withExtension: "py"', switcher)


if __name__ == "__main__":
    unittest.main()
