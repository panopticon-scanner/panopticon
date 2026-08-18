import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skill", "scripts"))
import ocrdb
import synthesize


def _bundle():
    return {"domains": {"SEC": {"entries": {
        "SEC-A1A": {"name": "n1", "default_severity": "MEDIUM"},
        "SEC-B2B": {"name": "n2", "default_severity": "HIGH"}}}}}


class TestVerdictQuality(unittest.TestCase):
    def test_default_severity_lookup(self):
        b = _bundle()
        self.assertEqual(ocrdb.default_severity(b, "SEC-A1A"), "MEDIUM")
        self.assertIsNone(ocrdb.default_severity(b, "SEC-ZZZ"))
        self.assertIsNone(ocrdb.default_severity(None, "SEC-A1A"))

    def test_advisor_corrects_code_with_provenance(self):
        b = _bundle()
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH", "domain": "SEC"}
        cov = synthesize.apply_verdict_quality(
            [f], {id(f): {"code": "SEC-B2B", "verdict": "CONFIRMED", "stage": "primary"}}, b)
        self.assertEqual(f["code"], "SEC-B2B")
        self.assertEqual(f["code_corrected_by"], "agent:advisor")
        self.assertEqual(cov["code_corrections"], 1)

    def test_override_missing_reason_reverts_to_code_default(self):
        b = _bundle()
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "CRITICAL", "domain": "SEC",
             "severity_override": {"from": "MEDIUM", "to": "CRITICAL"}}   # no reason
        cov = synthesize.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "MEDIUM")                 # reverted to code default
        self.assertNotIn("severity_override", f)
        self.assertEqual(cov["overrides"]["count"], 0)

    def test_valid_override_kept_and_counted_up(self):
        b = _bundle()
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "CRITICAL", "domain": "SEC",
             "severity_override": {"from": "MEDIUM", "to": "CRITICAL", "reason": "prod exposed"}}
        cov = synthesize.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(cov["overrides"], {"count": 1, "up": 1, "down": 0})

    def test_backup_confirm_sets_flag(self):
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH"}
        synthesize.apply_verdict_quality(
            [f], {id(f): {"verdict": "CONFIRMED", "stage": "backup"}}, _bundle())
        self.assertTrue(f.get("backup_confirmed"))

    def test_build_report_counts_land_in_ocrdb_coverage(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            fp = os.path.join(tmp_dir, "findings-app-SEC.json")
            with open(fp, "w", encoding="utf-8") as fh:
                json.dump({"findings": [
                    {"domain": "SEC", "code": "SEC-A1A", "severity": "CRITICAL",
                     "title": "t", "description": "x",
                     "location": {"file": "a.py", "line_start": 1}, "category": "authz",
                     "severity_override": {"from": "MEDIUM", "to": "CRITICAL", "reason": "prod"}}]}, fh)
            findings = synthesize.load_findings([fp])
            report = synthesize.build_report(findings, [], "src", None,
                                             "2026-08-15T00:00:00Z")
            ocrdb_cov = report["meta"]["coverage"]["ocrdb"]
            self.assertEqual(ocrdb_cov["overrides"]["count"], 1)
            self.assertIn("code_corrections", ocrdb_cov)

    def test_override_de_escalation_counts_down(self):
        b = _bundle()  # SEC-A1A default MEDIUM
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "LOW", "domain": "SEC",
             "severity_override": {"from": "MEDIUM", "to": "LOW", "reason": "intended lower"}}
        cov = synthesize.apply_verdict_quality([f], {}, b)
        self.assertEqual(cov["overrides"], {"count": 1, "up": 0, "down": 1})

    def test_bundle_absent_missing_reason_override_leaves_severity_no_crash(self):
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "CRITICAL",
             "severity_override": {"from": "MEDIUM", "to": "CRITICAL"}}   # no reason
        cov = synthesize.apply_verdict_quality([f], {}, None)             # bundle absent
        self.assertEqual(f["severity"], "CRITICAL")          # untouched (default_severity None -> can't revert)
        self.assertNotIn("severity_override", f)          # override still dropped + disclosed
        self.assertEqual(cov["code_corrections"], 0)

    def test_backup_confirmed_not_set_for_primary_or_backup_reject(self):
        f1 = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH"}
        synthesize.apply_verdict_quality(
            [f1], {id(f1): {"verdict": "CONFIRMED", "stage": "primary"}}, _bundle())
        self.assertNotIn("backup_confirmed", f1)          # primary confirm != double-confirm
        f2 = {"id": "SEC-2", "code": "SEC-A1A", "severity": "HIGH"}
        synthesize.apply_verdict_quality(
            [f2], {id(f2): {"verdict": "REJECTED", "stage": "backup"}}, _bundle())
        self.assertNotIn("backup_confirmed", f2)          # backup reject != confirm

    def test_code_correction_noops(self):
        b = _bundle()
        f1 = {"id": "SEC-1", "code": "SEC-A1A", "severity": "LOW"}          # verdict has no code
        synthesize.apply_verdict_quality([f1], {id(f1): {"verdict": "CONFIRMED"}}, b)
        self.assertEqual(f1["code"], "SEC-A1A")
        self.assertNotIn("code_corrected_by", f1)
        f2 = {"id": "SEC-2", "code": "SEC-A1A", "severity": "LOW"}          # invalid code
        synthesize.apply_verdict_quality(
            [f2], {id(f2): {"code": "SEC-ZZZ", "verdict": "CONFIRMED"}}, b)
        self.assertEqual(f2["code"], "SEC-A1A")
        self.assertNotIn("code_corrected_by", f2)
        f3 = {"id": "SEC-3", "code": "SEC-A1A", "severity": "LOW"}          # code == finding's own
        cov = synthesize.apply_verdict_quality(
            [f3], {id(f3): {"code": "SEC-A1A", "verdict": "CONFIRMED"}}, b)
        self.assertEqual(cov["code_corrections"], 0)


if __name__ == "__main__":
    unittest.main()
