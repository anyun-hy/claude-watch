#!/usr/bin/env python3
"""Generate UI policy structure from the Rust source of truth (no Rust build)."""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUST = ROOT / "crates/watch-core/src/policy.rs"
TARGET = ROOT / "monitor/Sources/GeneratedPolicyCatalog.swift"

def quoted(body: str, field: str) -> str:
    match = re.search(r"\b" + re.escape(field) + r'\s*:\s*"([a-z_]+)"', body)
    if not match:
        raise ValueError("missing or unsafe policy field " + field)
    return match.group(1)

def values(body: str, field: str) -> list[str]:
    match = re.search(r"\b" + re.escape(field) + r"\s*:\s*&\[(.*?)\]", body, re.S)
    if not match:
        raise ValueError("missing array " + field)
    raw = re.sub(r"//[^\n]*", "", match.group(1)).strip()
    if raw and re.sub(r'"[a-z_]+"|\s|,', "", raw):
        raise ValueError("unexpected array member in " + field)
    return re.findall(r'"([a-z_]+)"', raw)

def parse(src: str) -> tuple[list[dict], list[dict]]:
    scope = src.split("pub const CRITERIA: &[PolicyCriterion] = &[", 1)
    if len(scope) != 2:
        raise ValueError("CRITERIA declaration missing")
    body = scope[1].split("];\n\n/// One AI service", 1)[0]
    criteria = []
    for m in re.finditer(r"PolicyCriterion\s*\{(.*?)\n    \},", body, re.S):
        row = m.group(1)
        ident = quoted(row, "id")
        combined = values(row, "combines")
        default = re.search(r"\bdefault_action\s*:\s*(?:None|Some\(\"([a-z_]+)\"\))", row)
        if default is None:
            raise ValueError("invalid criterion fallback: " + ident)
        criteria.append(dict(id=ident, combines=combined, fallback=default.group(1)))
    if not criteria or len({c["id"] for c in criteria}) != len(criteria):
        raise ValueError("missing or duplicated criteria")
    keyed = [row for row in criteria if not row["combines"]]
    families = []
    for m in re.finditer(r"const\s+[A-Z_]+\s*:\s*PolicyFamily\s*=\s*PolicyFamily\s*\{(.*?)\n\};", src, re.S):
        raw = m.group(1)
        families.append(dict(
            id=quoted(raw, "id"),
            prefix=quoted(raw, "key_prefix"),
            actions=values(raw, "actions"),
            default=quoted(raw, "default_action"),
        ))
    if not families or len({f["id"] for f in families}) != len(families):
        raise ValueError("missing or duplicated families")
    if len({f["prefix"] for f in families}) != len(families):
        raise ValueError("duplicate config prefix")
    for family in families:
        options = family["actions"]
        if (not options or len(set(options)) != len(options)
                or any(a not in ("force", "close", "warn") for a in options)
                or family["default"] not in options):
            raise ValueError("unsupported action set: " + family["id"])
        for criterion in keyed:
            if criterion["fallback"] is not None and criterion["fallback"] not in options:
                raise ValueError("unsupported criterion fallback")
    return keyed, families

def render(keyed: list[dict], families: list[dict]) -> str:
    lines = [
        "// Generated from crates/watch-core/src/policy.rs.",
        "// Do not edit. Run: python3 tools/generate-ai-policy-swift.py --write",
        "// The Rust catalog owns keys, selectable actions, and fallback policy.",
        "struct GeneratedPolicyCriterion {",
        "    let id: String",
        "    let fallback: String",
        "}",
        "struct GeneratedPolicyFamily {",
        "    let id: String",
        "    let keyPrefix: String",
        "    let criteria: [GeneratedPolicyCriterion]",
        "    let actions: [String]",
        "    let defaultAction: String",
        "}",
        "enum GeneratedPolicyCatalog {",
        "    static let families: [GeneratedPolicyFamily] = [",
    ]
    for family in families:
        lines += [
            "        .init(",
            f'            id: "{family["id"]}", keyPrefix: "{family["prefix"]}",',
            "            criteria: [",
        ]
        for row in keyed:
            fallback = row["fallback"] or family["default"]
            lines.append(f'                .init(id: "{row["id"]}", fallback: "{fallback}"),')
        lines += [
            "            ],",
            "            actions: [" + ", ".join('"' + x + '"' for x in family["actions"]) + "],",
            f'            defaultAction: "{family["default"]}"',
            "        ),",
        ]
    lines += ["    ]", "}", ""]
    return "\n".join(lines)

def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        target = render(*parse(RUST.read_text(encoding="utf-8")))
    except (OSError, ValueError) as error:
        print("Cannot read authoritative Rust policy: " + str(error), file=sys.stderr)
        return 1
    if args.write:
        TARGET.write_text(target, encoding="utf-8")
        print("Generated " + str(TARGET.relative_to(ROOT)))
        return 0
    actual = TARGET.read_text(encoding="utf-8") if TARGET.is_file() else ""
    if actual != target:
        print("Policy catalog drift: run python3 tools/generate-ai-policy-swift.py --write", file=sys.stderr)
        return 1
    print("PASS: Swift policy directory exactly matches the Rust policy definition")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
