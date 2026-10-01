import json
import os
import tempfile
import unittest

import scripts.evidence as evidence_mod
import scripts.ocrdb as ocrdb
import scripts.strain_report as strain_mod
import scripts.synth.findings as findings_mod
import scripts.synth.codes as codes_mod
import scripts.synth.report as report_mod


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

    def test_advisor_differing_code_is_not_applied(self):
        # #2101: an advisor's differing OCRDb code is a RECORDED second opinion
        # (evidence.apply_verdict -> provenance.advisor_code), and this step used
        # to overwrite the very code that record is about. It no longer reads the
        # verdict's code at all; severity is the only axis it mutates.
        b = _bundle()
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH", "domain": "SEC"}
        cov = codes_mod.apply_verdict_quality(
            [f], {id(f): {"code": "SEC-B2B", "verdict": "CONFIRMED", "stage": "primary"}}, b)
        self.assertEqual(f["code"], "SEC-A1A")           # the panel's code, published
        self.assertEqual(f["severity"], "HIGH")          # two-axis invariant
        self.assertNotIn("code_corrected_by", f)
        self.assertNotIn("code_corrections", cov)

    def test_live_call_order_records_the_advisor_code_and_never_applies_it(self):
        # The production order is evidence.apply_verdict (synth.verdicts._bind_
        # verdicts) and THEN codes.apply_verdict_quality, a few lines later in
        # resolve_findings. The contradiction #2101 names was only visible
        # COMPOSED: step one wrote the record, step two overwrote the code the
        # record was about, so each step read correctly on its own.
        b = _bundle()
        for advisor_code, where in (("SEC-B2B", "valid in the bundle"),
                                    ("SEC-ZZZ", "absent from the bundle")):
            with self.subTest(advisor_code=advisor_code, where=where):
                f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH",
                     "domain": "SEC", "title": "t",
                     "location": {"file": "app.py", "line_start": 10}}
                v = {"code": advisor_code, "verdict": "CONFIRMED",
                     "stage": "primary", "reasoning": "the advisor's own argument"}
                evidence_mod.apply_verdict(f, v)
                cov = codes_mod.apply_verdict_quality([f], {id(f): v}, b)
                self.assertEqual(f["code"], "SEC-A1A")        # published: the panel's
                self.assertEqual(f["provenance"]["advisor_code"], advisor_code)
                self.assertEqual(f["severity"], "HIGH")       # two-axis invariant
                self.assertNotIn("code_corrected_by", f)
                self.assertNotIn("code_corrections", cov)
                # The record-only CONSUMER still sees it: that is the whole point
                # of recording a disagreement nobody applies.
                self.assertEqual(
                    [(s["code_filed"], s["code_preferred"], s["recurrence"])
                     for s in strain_mod.advisor_recode_signals([f], "run1")],
                    [("SEC-A1A", advisor_code, 1)])

    def test_override_missing_reason_reverts_to_code_default(self):
        b = _bundle()
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "CRITICAL", "domain": "SEC",
             "severity_override": {"from": "MEDIUM", "to": "CRITICAL"}}   # no reason
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "MEDIUM")                 # reverted to code default
        self.assertNotIn("severity_override", f)
        self.assertEqual(cov["overrides"]["count"], 0)
        # #2101's ONE severity consequence, pinned. The revert target is the
        # PUBLISHED code's default. The deleted code-application branch ran
        # earlier in this same loop iteration, so an applied advisor code used to
        # decide this default too: SEC-B2B (HIGH) would have reverted the finding
        # to HIGH. Severity is still mutated only by the override discipline --
        # it is the default the discipline measures against that moved, onto the
        # code the report actually publishes.
        g = {"id": "SEC-2", "code": "SEC-A1A", "severity": "CRITICAL", "domain": "SEC",
             "severity_override": {"from": "MEDIUM", "to": "CRITICAL"}}   # no reason
        cov = codes_mod.apply_verdict_quality(
            [g], {id(g): {"code": "SEC-B2B", "verdict": "CONFIRMED", "stage": "primary"}}, b)
        self.assertEqual(g["severity"], "MEDIUM")     # SEC-A1A's default, not SEC-B2B's HIGH
        self.assertNotIn("severity_override", g)
        self.assertEqual(cov["overrides"]["count"], 0)

    def test_valid_override_kept_and_counted_up(self):
        b = _bundle()
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "CRITICAL", "domain": "SEC",
             "severity_override": {"from": "MEDIUM", "to": "CRITICAL", "reason": "prod exposed"}}
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(cov["overrides"], {"count": 1, "up": 1, "down": 0})

    def test_backup_confirm_sets_flag(self):
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH"}
        codes_mod.apply_verdict_quality(
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
            findings = findings_mod.load_findings([fp])
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="src",
                    fail_on=None,
                    timestamp="2026-08-15T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=findings),
            ))
            ocrdb_cov = report["meta"]["coverage"]["ocrdb"]
            self.assertEqual(ocrdb_cov["overrides"]["count"], 1)
            self.assertNotIn("code_corrections", ocrdb_cov)   # retired with #2101

    def test_override_de_escalation_counts_down(self):
        b = _bundle()  # SEC-A1A default MEDIUM
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "LOW", "domain": "SEC",
             "severity_override": {"from": "MEDIUM", "to": "LOW", "reason": "intended lower"}}
        cov = codes_mod.apply_verdict_quality([f], {}, b)
        self.assertEqual(cov["overrides"], {"count": 1, "up": 0, "down": 1})

    def test_bundle_absent_missing_reason_override_leaves_severity_no_crash(self):
        f = {"id": "SEC-1", "code": "SEC-A1A", "severity": "CRITICAL",
             "severity_override": {"from": "MEDIUM", "to": "CRITICAL"}}   # no reason
        cov = codes_mod.apply_verdict_quality([f], {}, None)             # bundle absent
        self.assertEqual(f["severity"], "CRITICAL")          # untouched (default_severity None -> can't revert)
        self.assertNotIn("severity_override", f)          # override still dropped + disclosed
        self.assertNotIn("code_corrections", cov)         # retired with #2101

    def test_backup_confirmed_not_set_for_primary_or_backup_reject(self):
        f1 = {"id": "SEC-1", "code": "SEC-A1A", "severity": "HIGH"}
        codes_mod.apply_verdict_quality(
            [f1], {id(f1): {"verdict": "CONFIRMED", "stage": "primary"}}, _bundle())
        self.assertNotIn("backup_confirmed", f1)          # primary confirm != double-confirm
        f2 = {"id": "SEC-2", "code": "SEC-A1A", "severity": "HIGH"}
        codes_mod.apply_verdict_quality(
            [f2], {id(f2): {"verdict": "REJECTED", "stage": "backup"}}, _bundle())
        self.assertNotIn("backup_confirmed", f2)          # backup reject != confirm

    def test_no_verdict_code_reaches_the_finding(self):
        b = _bundle()
        f1 = {"id": "SEC-1", "code": "SEC-A1A", "severity": "LOW"}          # verdict has no code
        codes_mod.apply_verdict_quality([f1], {id(f1): {"verdict": "CONFIRMED"}}, b)
        self.assertEqual(f1["code"], "SEC-A1A")
        self.assertNotIn("code_corrected_by", f1)
        f2 = {"id": "SEC-2", "code": "SEC-A1A", "severity": "LOW"}          # invalid code
        codes_mod.apply_verdict_quality(
            [f2], {id(f2): {"code": "SEC-ZZZ", "verdict": "CONFIRMED"}}, b)
        self.assertEqual(f2["code"], "SEC-A1A")
        self.assertNotIn("code_corrected_by", f2)
        f3 = {"id": "SEC-3", "code": "SEC-A1A", "severity": "LOW"}          # a real, differing code
        cov = codes_mod.apply_verdict_quality(
            [f3], {id(f3): {"code": "SEC-B2B", "verdict": "CONFIRMED"}}, b)
        self.assertEqual(f3["code"], "SEC-A1A")           # #2101: not even a valid one
        self.assertNotIn("code_corrected_by", f3)
        self.assertNotIn("code_corrections", cov)


if __name__ == "__main__":
    unittest.main()
