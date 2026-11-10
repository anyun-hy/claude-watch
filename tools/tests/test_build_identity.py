import importlib.util
import json
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "write-build-identity.py"
spec = importlib.util.spec_from_file_location("build_identity", SCRIPT)
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


class BuildIdentityTests(unittest.TestCase):
    def test_source_receipt_detects_changed_uncommitted_source_and_never_claims_archive_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "crates").mkdir()
            source = root / "crates/fixture.rs"
            source.write_text("fn main() {}")
            first = identity.snapshot(root, "3.0.0", "381")
            self.assertIsNone(first["source_revision"])
            self.assertIsNone(first["source_dirty"])
            receipt = root / "identity.json"
            receipt.write_text(json.dumps(first))
            resources = root / "resources"
            resources.mkdir()
            (resources / "BuildInfo.plist").write_bytes(plistlib.dumps({"ProductVersion": "3.0.0"}))
            command = ["python3", str(SCRIPT), "verify", "--root", str(root), "--snapshot", str(receipt),
                       "--version", "3.0.0", "--build", "381", "--resources", str(resources)]
            subprocess.run(command, check=True, capture_output=True)
            self.assertEqual(json.loads((resources / "BuildIdentity.json").read_text()), first)
            self.assertEqual(plistlib.loads((resources / "BuildInfo.plist").read_bytes())["SourceTreeDigest"], first["source_tree_digest"])
            source.write_text("fn main() { changed(); }")
            failed = subprocess.run(command, capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn(b"Source changed during compilation", failed.stderr)
            self.assertEqual(json.loads((resources / "BuildIdentity.json").read_text()), first)

    def test_git_receipt_tracks_untracked_sources_but_ignores_build_products(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / ".gitignore").write_text("build/\n")
            (root / "source.rs").write_text("original")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
            before = identity.snapshot(root, "3.0.0", "381")
            self.assertFalse(before["source_dirty"])
            (root / "build").mkdir()
            (root / "build/output").write_text("generated")
            self.assertEqual(identity.snapshot(root, "3.0.0", "381"), before)
            (root / "new.rs").write_text("new code")
            after = identity.snapshot(root, "3.0.0", "381")
            self.assertTrue(after["source_dirty"])
            self.assertNotEqual(before["source_tree_digest"], after["source_tree_digest"])
            self.assertEqual(before["source_revision"], after["source_revision"])


if __name__ == "__main__":
    unittest.main()
