"""Harness tests run without Rust and never access a real daemon or account."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("rust_shadow", ROOT / "tools/rust_shadow.py")
shadow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shadow)


class RustShadowHarnessTests(unittest.TestCase):
    def test_reference_is_only_the_pure_function(self):
        function, digest = shadow.load_reference()
        self.assertEqual(set(function.__globals__), {"__builtins__", "connection_policy"})
        self.assertEqual(len(digest), 64)
        value = shadow.base_evidence(); original = copy.deepcopy(value)
        self.assertEqual(shadow.legacy_decision(function, value)["state"], "match")
        self.assertEqual(value, original)

    def test_reference_golden_cases_and_generated_coverage(self):
        function, _ = shadow.load_reference()
        cases = json.loads(shadow.FIXTURES.read_text())["cases"]
        for case in cases:
            with self.subTest(case=case["id"]):
                self.assertEqual(shadow.legacy_decision(function, case["evidence"])["state"], case["expected"]["state"])
        cases = list(shadow.generated_cases())
        self.assertEqual(cases, list(shadow.generated_cases()))
        self.assertEqual({shadow.legacy_decision(function, c["evidence"])["state"] for c in cases}, {"match", "mismatch", "unconfirmed"})

    def test_snapshot_extracts_only_policy_inputs(self):
        value = {"schema": 1, "expected_group": "GLOBAL", "expected_node": "JP-test",
                 "api": {**shadow.base_evidence()["api"], "secret": "not-exported"},
                 "flows": [{"association": "correlated", "chains": ["JP-test", "GLOBAL"], "rule": 7,
                            "host": "private-host", "connection_id": "private-id"},
                           {"association": "unconfirmed", "chains": ["DIRECT"]}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"sample.json";path.write_text(json.dumps(value))
            cases, digest = shadow.snapshot_cases(path)
        self.assertEqual(len(cases), 1);self.assertEqual(len(digest),64)
        self.assertIsNone(cases[0]["evidence"]["matched_rule"])
        self.assertNotIn("not-exported",repr(cases));self.assertNotIn("private-host",repr(cases))
        self.assertNotIn("private-id",repr(cases))

    def test_response_requires_identity_and_no_authority(self):
        value = {"schema_version":1,"request_id":"one","mode":"shadow","grants_launch_permission":False,
                 "result":{"state":"match","code":"global_match","detail":"fixture"}}
        self.assertEqual(shadow.validate_response(value,"one")["state"],"match")
        for key, replacement in (("request_id","other"),("mode","apply"),("grants_launch_permission",True),
                                 ("grants_launch_permission",0),("schema_version",True)):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):shadow.validate_response({**value,key:replacement},"one")
        with self.assertRaises(ValueError):shadow.validate_response({**value,"action":"launch"},"one")

    def test_missing_or_failed_child_output_is_not_success(self):
        case={"id":"one","evidence":shadow.base_evidence()}
        for completed in (subprocess.CompletedProcess([],0,b"",b""),subprocess.CompletedProcess([],1,b"",b"")):
            with mock.patch.object(shadow,"invoke",return_value=completed):
                with self.assertRaises(ValueError):shadow.run_cases(Path("fixture"),[case])
        with mock.patch.object(shadow.subprocess,"run",side_effect=subprocess.TimeoutExpired("fixture",15)):
            with self.assertRaisesRegex(ValueError,"timeout"):shadow.invoke(Path("fixture"),b"")

    def test_duplicate_json_keys_are_rejected(self):
        with self.assertRaisesRegex(ValueError,"duplicate"):
            json.loads('{"schema_version":1,"schema_version":2}',object_pairs_hook=shadow.unique_object)

    def test_error_responses_cannot_smuggle_extra_fields(self):
        response={"schema_version":1,"mode":"shadow","grants_launch_permission":False,"error":"invalid_request"}
        self.assertEqual(shadow.validate_response(response,None,allow_error=True)["error"],"invalid_request")
        with self.assertRaises(ValueError):shadow.validate_response({**response,"apply":True},None,allow_error=True)

    def test_non_object_snapshot_is_rejected_without_legacy_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"sample.json";path.write_text('[]')
            with self.assertRaisesRegex(ValueError,"schema"):shadow.snapshot_cases(path)


if __name__ == "__main__":unittest.main()
