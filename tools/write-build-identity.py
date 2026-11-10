#!/usr/bin/env python3
"""Build-time source receipt. No Python runtime is included in the application."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import subprocess


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def snapshot(root, version, build):
    try:
        revision = git(root, "rev-parse", "HEAD").decode().strip()
        dirty = bool(git(root, "status", "--porcelain", "--untracked-files=normal"))
        names = set(git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")) - {b""}
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Source archives have no commit to claim. Limit fallback to build inputs.
        revision, dirty = None, None
        names = {os.fsencode(str(p.relative_to(root))) for prefix in ("crates", "monitor", "tools", "Cargo.toml", "Cargo.lock")
                 for p in ([root / prefix] if (root / prefix).is_file() else (root / prefix).rglob("*"))
                 if (p.is_file() or p.is_symlink()) and not any(part in ("build", "target", "__pycache__") for part in p.relative_to(root).parts)}
    digest = hashlib.sha256()
    for name in sorted(names):
        path = root / os.fsdecode(name)
        digest.update(len(name).to_bytes(8, "big") + name)
        if path.is_symlink():
            digest.update(b"link\0" + os.fsencode(os.readlink(path)))
        elif path.is_file():
            digest.update(b"file\0" + (path.stat().st_mode & 0o111).to_bytes(4, "big"))
            content = hashlib.sha256()
            with path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    content.update(chunk)
            digest.update(content.digest())
        elif not path.exists():
            digest.update(b"deleted\0")
        else:
            raise ValueError("Unsupported build source entry")
    return dict(schema=1, app_version=version, app_build=build,
                source_revision=revision, source_dirty=dirty, source_tree_digest=digest.hexdigest())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("capture", "verify"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--build", required=True)
    parser.add_argument("--resources", type=Path)
    args = parser.parse_args()
    identity = snapshot(args.root, args.version, args.build)
    if args.phase == "capture":
        args.snapshot.write_text(json.dumps(identity, sort_keys=True) + "\n")
        return
    if json.loads(args.snapshot.read_text()) != identity:
        raise SystemExit("Source changed during compilation; rebuild before packaging this version.")
    if args.resources:
        (args.resources / "BuildIdentity.json").write_text(json.dumps(identity, sort_keys=True) + "\n")
        manifest = args.resources / "BuildInfo.plist"
        data = plistlib.loads(manifest.read_bytes())
        data.update(AppBuild=identity["app_build"], SourceTreeDigest=identity["source_tree_digest"])
        if identity["source_revision"] is not None:
            data["SourceRevision"] = identity["source_revision"]
            data["SourceDirty"] = identity["source_dirty"]
        manifest.write_bytes(plistlib.dumps(data))


if __name__ == "__main__":
    main()
