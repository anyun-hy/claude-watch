#!/usr/bin/env python3
"""Read-only differential testing of the Rust pilot against the current Python function.

This never runs the Bash daemon, queries TAG, reads accounts or applies decisions.
The optional snapshot input is replayed from one already-written file.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import random
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "crates/watch-core/tests/fixtures/tag-policy-v1.json"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def load_reference(source=ROOT / "claude-watch.sh"):
    text = source.read_text(encoding="utf-8").split("<<'PY_TAG'\n", 1)[1].split("\nPY_TAG\n", 1)[0]
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == "connection_policy"]
    if len(nodes) != 1 or nodes[0].decorator_list:
        raise ValueError("legacy_policy_not_unique")
    node = nodes[0]
    if [a.arg for a in node.args.args] != ["chains", "group", "expected_node", "api", "record"]:
        raise ValueError("legacy_policy_signature_changed")
    namespace = {"__builtins__": {"str": str, "isinstance": isinstance, "any": any}}
    # Compile only the pure function, never the embedded adapter's top-level code.
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(source) + ":connection_policy", "exec"), namespace)
    digest = hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
    return namespace["connection_policy"], digest


def legacy_decision(reference, evidence):
    value = copy.deepcopy(evidence)
    state, detail = reference(value["observed_chain"], value["required_group"], value["pinned_node"],
                              value["api"], {"rule": value.get("matched_rule")})
    return {"state": state, "detail": detail}


def request(case):
    return {"schema_version": 1, "request_id": case["id"], "operation": "tag_connection_policy",
            "evidence": case["evidence"]}


def base_evidence():
    return {"observed_chain": ["JP-test", "GLOBAL"], "required_group": "", "pinned_node": "",
            "matched_rule": None,
            "api": {"state": "available", "mode": "global", "route_chains": {"GLOBAL": ["JP-test", "GLOBAL"]}}}


def generated_cases(count=3000, seed=297):
    rng = random.Random(seed)
    for index in range(count):
        mode = rng.choice(["global", "global", "rule", "rule", "direct", "unknown", None])
        root = "GLOBAL" if mode == "global" else rng.choice(["AI", "AI-2", "🇯🇵 テスト"])
        node = rng.choice(["JP-test", "US-test", "日本テスト"])
        selected = [node, root]
        chain = rng.choice([selected, selected, [], ["DIRECT"], ["reject"],
                            [node, "unexpected", root], ["another-node", root]])
        routes = rng.choice([{root: selected}, {root: selected}, {}, {root: None}, {root: []}])
        yield {"id": f"generated-{index:05}", "evidence": {
            "observed_chain": chain, "required_group": rng.choice(["", "", root, "different-group"]),
            "pinned_node": rng.choice(["", "", node, "different-node"]),
            "matched_rule": rng.choice(["Match", "DomainSuffix", "RuleSet", None, "", " \u3000"]),
            "api": {"state": rng.choice(["available", "available", "unavailable"]),
                    "mode": mode, "route_chains": routes}}}


def snapshot_cases(path):
    with path.open("rb") as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("snapshot_too_large")
    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1:
        raise ValueError("snapshot_schema_unsupported")
    api, flows = value.get("api"), value.get("flows")
    if not isinstance(api, dict) or not isinstance(flows, list) or len(flows) > 20_000:
        raise ValueError("snapshot_incomplete")
    cases = []
    for index, flow in enumerate(flows):
        if not isinstance(flow, dict) or flow.get("association") != "correlated":
            continue  # Rust is not replacing identity, tuple, TUN or fake-IP association.
        cases.append({"id": f"snapshot-{index:05}", "evidence": {
            "observed_chain": flow.get("chains", []), "required_group": value.get("expected_group", ""),
            "pinned_node": value.get("expected_node", ""),
            "matched_rule": flow.get("rule") if isinstance(flow.get("rule"), str) else None,
            "api": {"state": api.get("state", "unavailable"), "mode": api.get("mode"),
                    "route_chains": api.get("route_chains", {})}}})
    if not cases:
        raise ValueError("snapshot_has_no_correlated_flows")
    return cases, hashlib.sha256(raw).hexdigest()


def invoke(binary, payload, arguments=("--shadow",), timeout=15):
    try:
        return subprocess.run([str(binary), *arguments], input=payload, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ValueError("shadow_process_timeout") from exc


def validate_response(value, expected_id, *, allow_error=False):
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
            or value["schema_version"] != 1 or value.get("mode") != "shadow"
            or value.get("grants_launch_permission") is not False):
        raise ValueError("response_authority_or_schema_invalid")
    if "error" in value:
        allowed = {"schema_version", "mode", "grants_launch_permission", "request_id", "error"}
        if allow_error and set(value) <= allowed and isinstance(value["error"], str):
            return value
        raise ValueError("shadow_rejected_request")
    if set(value) != {"schema_version", "mode", "grants_launch_permission", "request_id", "result"}:
        raise ValueError("unexpected_response_fields")
    if value["request_id"] != expected_id:
        raise ValueError("response_id_mismatch")
    result = value["result"]
    if (not isinstance(result, dict) or set(result) != {"state", "code", "detail"}
            or result["state"] not in ("match", "mismatch", "unconfirmed")
            or not all(isinstance(v, str) and len(v) <= 1024 for v in result.values())):
        raise ValueError("policy_response_invalid")
    return result


def run_cases(binary, cases):
    frames = b"".join(json.dumps(request(case), ensure_ascii=False, separators=(",", ":"),
                                allow_nan=False).encode() + b"\n" for case in cases)
    started = time.perf_counter()
    completed = invoke(binary, frames)
    elapsed = time.perf_counter() - started
    if completed.returncode != 0:
        raise ValueError(f"shadow_process_failed:{completed.returncode}")
    lines = completed.stdout.splitlines()
    if len(lines) != len(cases):
        raise ValueError("response_count_mismatch")
    results = [validate_response(json.loads(line, object_pairs_hook=unique_object), case["id"])
               for case, line in zip(cases, lines)]
    return results, elapsed


def fault_probes(binary, valid_case):
    valid = json.dumps(request(valid_case), ensure_ascii=False).encode()
    bad_frames = [b'not-json-sensitive-placeholder', b'\xff', b'x' * 65_537,
                  json.dumps({**request(valid_case), "schema_version": 2}).encode(),
                  json.dumps({**request(valid_case), "operation": "launch"}).encode()]
    for bad in bad_frames:
        completed = invoke(binary, bad + b"\n" + valid + b"\n")
        if completed.returncode != 0:
            raise ValueError("fault_probe_process_failed")
        lines = completed.stdout.splitlines()
        if len(lines) != 2:
            raise ValueError("fault_probe_count_mismatch")
        first = json.loads(lines[0], object_pairs_hook=unique_object)
        validate_response(first, None, allow_error=True)
        if "error" not in first or b'sensitive-placeholder' in completed.stdout:
            raise ValueError("fault_probe_not_rejected_or_input_echoed")
        validate_response(json.loads(lines[1], object_pairs_hook=unique_object), valid_case["id"])
    for args in ((), ("--apply",), ("--shadow", "--apply")):
        completed = invoke(binary, b"", arguments=args)
        if completed.returncode != 64 or completed.stdout:
            raise ValueError("apply_or_implicit_mode_not_rejected")
    return len(bad_frames) + 3


def compare(binary, cases, *, reference_source=ROOT / "claude-watch.sh"):
    reference, digest = load_reference(reference_source)
    start = time.perf_counter()
    expected = [legacy_decision(reference, case["evidence"]) for case in cases]
    python_seconds = time.perf_counter() - start
    actual, rust_seconds = run_cases(binary, cases)
    mismatches = []
    counts = {key: 0 for key in ("match", "mismatch", "unconfirmed")}
    for case, old, new in zip(cases, expected, actual):
        counts[new["state"]] += 1
        fixed = case.get("expected", {})
        if (old != {k: new[k] for k in ("state", "detail")}
                or any(new.get(k) != v for k, v in fixed.items())):
            mismatches.append({"id": case["id"], "python": old, "rust": new})
    return {"schema_version": 1, "mode": "shadow", "grants_launch_permission": False,
            "legacy_function_sha256": digest, "cases": len(cases), "states": counts,
            "mismatches": mismatches,
            "timing": {"python_evaluation_seconds": python_seconds,
                       "rust_process_and_json_seconds": rust_seconds,
                       "scope": "Different timing boundaries; not a production performance comparison."}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/release/claude-watch-shadow")
    parser.add_argument("--generated", type=int, default=3000)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not 0 <= args.generated <= 20_000:
        parser.error("--generated must be between 0 and 20000")
    if not args.binary.is_file():
        parser.error("Rust binary not found; build the shadow target first")
    try:
        cases = json.loads(FIXTURES.read_text())["cases"] + list(generated_cases(args.generated))
        snapshot_hash = None
        if args.snapshot:
            extra, snapshot_hash = snapshot_cases(args.snapshot); cases += extra
        result = compare(args.binary.resolve(), cases)
        result["fault_probes_passed"] = fault_probes(args.binary.resolve(), cases[0])
        result["snapshot_sha256"] = snapshot_hash
        if args.report:
            # Explicit output only; never overwrite previous evidence or another file.
            args.report.parent.mkdir(parents=True, exist_ok=True)
            with args.report.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, ensure_ascii=False, indent=2); stream.write("\n")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return int(bool(result["mismatches"]))
    except (ValueError, OSError, KeyError, TypeError, IndexError) as error:
        code = str(error) if re.fullmatch(r"[a-z_]+(?::[0-9-]+)?", str(error)) else "invalid_input_or_output"
        print(json.dumps({"status": "failed", "type": type(error).__name__,
                          "error": code,
                          "grants_launch_permission": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
