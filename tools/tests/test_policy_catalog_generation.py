"""Pure Rust-to-Swift policy generation contracts; no app launches or writes."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "tools/generate-ai-policy-swift.py"
SPEC = importlib.util.spec_from_file_location("cw_policy_generator", GENERATOR)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
RUST = (ROOT / "crates/watch-core/src/policy.rs").read_text(encoding="utf-8")
SWIFT = (ROOT / "monitor/Sources/GeneratedPolicyCatalog.swift").read_text(encoding="utf-8")


class PolicyCatalogGeneration(unittest.TestCase):
    def test_checked_in_generated_source_is_exact(self):
        self.assertEqual(MODULE.render(*MODULE.parse(RUST)), SWIFT)

    def test_source_catalog_remains_single_authority_for_structure(self):
        criteria, families = MODULE.parse(RUST)
        self.assertEqual([c["id"] for c in criteria], ["ip", "cn", "dns", "webrtc", "session"])
        self.assertEqual([f["id"] for f in families], ["claude", "openai"])
        self.assertEqual([f["prefix"] for f in families], ["claude", "gpt"])
        # Preserve the configured product defaults; explicit user settings
        # still determine the action independently of this catalog fallback.
        self.assertEqual([f["default"] for f in families], ["force", "close"])
        self.assertEqual({tuple(f["actions"]) for f in families}, {("force", "close", "warn")})

    def test_combined_risk_code_cannot_create_an_extra_ui_switch(self):
        self.assertIn('id: "probe_drift"', RUST)
        self.assertNotIn('id: "probe_drift"', SWIFT)

    def test_duplicate_criterion_is_rejected(self):
        edited = RUST.replace('id: "ip",', 'id: "cn",', 1)
        self.assertNotEqual(edited, RUST)
        with self.assertRaises(ValueError):
            MODULE.parse(edited)

    def test_unknown_action_is_rejected(self):
        edited = RUST.replace('actions: &["force", "close", "warn"]',
                              'actions: &["force", "close", "kill"]', 1)
        self.assertNotEqual(edited, RUST)
        with self.assertRaises(ValueError):
            MODULE.parse(edited)

    def test_unknown_criterion_default_is_rejected(self):
        edited = RUST.replace('default_action: Some("close")',
                              'default_action: Some("kill")', 1)
        self.assertNotEqual(edited, RUST)
        with self.assertRaises(ValueError):
            MODULE.parse(edited)

    def test_ui_contains_localization_only_not_a_second_policy_table(self):
        ui = (ROOT / "monitor/Sources/AIPolicyCatalog.swift").read_text(encoding="utf-8")
        self.assertIn("GeneratedPolicyCatalog.families", ui)
        self.assertNotIn('keyPrefix: "gpt"', ui)
        self.assertNotIn('keyPrefix: "claude"', ui)
        self.assertNotIn('.init(id: "ip", title:', ui)


if __name__ == "__main__":
    unittest.main()
