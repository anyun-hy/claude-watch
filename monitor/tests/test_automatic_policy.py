import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "Resources"))
from watch_switcher.automatic_policy import extract_risks

class AutomaticPolicyTests(unittest.TestCase):
    def base(self): return {"trace":{"ip":"8.8.8.8","loc":"JP"},"geo":{"ip":"8.8.8.8","country":"JP","timezone":"Asia/Tokyo"}}
    def test_cn_egress_is_required_risk(self):
        value=self.base(); value["trace"]["loc"]="CN"; value["geo"]["country"]="CN"
        self.assertIn("cn_egress", [x["id"] for x in extract_risks(value)["risks"]])
    def test_cn_dns_and_asn_are_risks_with_distinct_meaning(self):
        value=self.base(); value["dns"]={"receipt":{"dns":{"countries":["CN"]}}}; value["asn"]={"registered_country":"CN"}; value["netcoffee_lookup"]={"data":{"ip":"8.8.8.8"}}
        reasons={x["id"]:x["reason"] for x in extract_risks(value)["risks"]}
        self.assertIn("cn_dns", reasons); self.assertIn("归属风险", reasons["cn_asn_registration"])
    def test_query_failure_is_not_cn_risk(self):
        value={"query_errors":{"netcoffee":{}},"trace":{},"geo":{}}
        self.assertEqual(extract_risks(value)["risks"], [])
    def test_trace_cn_survives_geo_failure_and_old_asn_does_not(self):
        value={"trace":{"ip":"8.8.8.8","loc":"CN"},"geo":{},"asn":{"registered_country":"CN"},"netcoffee_lookup":{"data":{"ip":"1.1.1.1"}}}
        ids=[x["id"] for x in extract_risks(value)["risks"]]
        self.assertIn("cn_egress",ids); self.assertNotIn("cn_asn_registration",ids)

if __name__ == "__main__": unittest.main()
