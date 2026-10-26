#!/usr/bin/env python3
"""Build a local signed complete-release archive. Does not publish or install."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse
import zipfile


def sha(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""): result.update(data)
    return result.hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--app", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--archive-url", required=True)
    p.add_argument("--signing-key", type=Path, required=True, help="Existing RSA private key; never included in output")
    args = p.parse_args()
    url = urlparse(args.archive_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.fragment:
        p.error("archive URL must be HTTPS without credentials")
    app = args.app.resolve()
    resources = app / "Contents/Resources"
    info = plistlib.loads((resources / "BuildInfo.plist").read_bytes())
    if info.get("SwitcherSchema") != 1 or not re.fullmatch(r"\d+\.\d+\.\d+", info.get("ProductVersion", "")):
        p.error("app lacks a supported release manifest")
    if args.output.exists(): p.error("output directory already exists")
    subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], check=True)
    with tempfile.TemporaryDirectory(prefix="cw-release-") as temporary:
        root = Path(temporary)
        payload = root / "payload"; payload.mkdir()
        shutil.copytree(app, payload / "app/Claude Watch Monitor.app")
        runtime = payload / "runtime"; runtime.mkdir()
        for name, expected in info["RuntimeHashes"].items():
            rel = Path(name)
            if rel.is_absolute() or ".." in rel.parts: p.error("unsafe runtime path")
            source = resources / rel
            if source.is_symlink() or sha(source) != expected: p.error("runtime checksum mismatch")
            target = runtime / rel; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        shutil.copytree(resources / "ThirdParty", runtime / "ThirdParty")
        shutil.copy2(resources / "claude-watch.sh", payload / "claude-watch.sh")
        if sha(payload / "claude-watch.sh") != info["BackendSHA256"]: p.error("backend checksum mismatch")
        files = {}
        archive = root / "release.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for item in sorted(payload.rglob("*")):
                if item.is_symlink(): p.error("symbolic links are not supported in this native release format")
                if item.is_file():
                    name = str(item.relative_to(payload))
                    files[name] = sha(item); z.write(item, name)
        manifest = dict(schema=1, runtime_schema=1, admin_abi=1, version=info["ProductVersion"],
                        architecture=info["Architecture"], minimum_macos=info["MinimumSystemVersion"],
                        archive_url=args.archive_url, archive_sha256=sha(archive), files=files)
        data = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
        manifest_file = root / "manifest.json"; manifest_file.write_bytes(data)
        signature = root / "manifest.sig"
        subprocess.run(["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(args.signing_key.resolve()),
                        "-out", str(signature), str(manifest_file)], check=True)
        envelope = dict(manifest=base64.b64encode(data).decode(),
                        signature=base64.b64encode(signature.read_bytes()).decode())
        args.output.mkdir(parents=True)
        shutil.copy2(archive, args.output / "release.zip")
        (args.output / "release.json").write_text(json.dumps(envelope))
        (args.output / "manifest-readable.json").write_text(json.dumps(manifest, indent=2))
    print("Created signed local release:", args.output)


if __name__ == "__main__":
    main()
