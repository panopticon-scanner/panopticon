import json
import os
import unittest

import jsonschema

import scripts.x0x_report as x0x


def _f(code, domain, sev, title, file, line=1, fid=None, desc="d", refs=None):
    return {"code": code, "domain": domain, "severity": sev,
            "short_title": title, "title": title, "description": desc,
            "id": fid or f"{domain}-{title}", "references": refs or [],
            "location": {"file": file, "line_start": line, "line_end": line + 2}}


class TestX0XReport(unittest.TestCase):
    def test_only_fallback_findings_become_candidates(self):
        findings = [
            _f("COD-X0X", "COD", "LOW", "dup dead block", "a.py"),
            _f("SEC-A1A", "SEC", "HIGH", "sql injection", "b.py"),  # real code -> ignored
        ]
        cands = x0x.build_candidates(findings)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["fallback_code"], "COD-X0X")
        self.assertEqual(cands[0]["domain"], "COD")

    def test_clusters_same_pattern_keeps_distinct_separate(self):
        findings = [
            _f("SEC-X0X", "SEC", "HIGH", "hardcoded id", "page.tsx", 1, "f1"),
            _f("SEC-X0X", "SEC", "CRITICAL", "hardcoded id", "other.tsx", 5, "f2"),
            _f("DAT-X0X", "DAT", "MEDIUM", "no volume", "compose.yml", 1, "f3"),
        ]
        cands = x0x.build_candidates(findings)
        self.assertEqual(len(cands), 2)
        sec = next(c for c in cands if c["domain"] == "SEC")
        self.assertEqual(sec["recurrence"], 2)
        self.assertEqual({o["finding_id"] for o in sec["occurrences"]}, {"f1", "f2"})
        self.assertEqual(sec["severity"], "CRITICAL")   # the most severe finding leads

    def test_domain_case_folded_so_variants_cluster_together(self):
        # #run7 COD-C2D: the domain flows in verbatim (no case-fold upstream)
        # while the title half of the cluster key is lowercased. "SEC" vs "sec"
        # must cluster into ONE candidate, not split -- and the emitted domain
        # must be the canonical upper form.
        findings = [
            _f("SEC-X0X", "SEC", "HIGH", "hardcoded id", "a.tsx", 1, "f1"),
            _f("sec-X0X", "sec", "LOW", "hardcoded id", "b.tsx", 2, "f2"),
        ]
        cands = x0x.build_candidates(findings)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["domain"], "SEC")
        self.assertEqual(cands[0]["recurrence"], 2)
        self.assertEqual({o["finding_id"] for o in cands[0]["occurrences"]},
                         {"f1", "f2"})

    def test_candidate_fields_and_slug_and_cwe_scrape(self):
        f = _f("ARC-X0X", "ARC", "MEDIUM", "Ungated Fixture Provisioning", "x.py",
               3, "f1", desc="runs on every start", refs=["see CWE-400 and CWE-522"])
        c = x0x.build_candidates([f])[0]
        self.assertEqual(c["proposed_name"], "ungated-fixture-provisioning")
        self.assertEqual(c["summary"], "Ungated Fixture Provisioning")
        self.assertEqual(c["description"], "runs on every start")
        self.assertEqual(c["cwe"], ["CWE-400", "CWE-522"])   # scraped from free text
        self.assertEqual(c["occurrences"][0],
                         {"file": "x.py", "line_start": 3, "line_end": 5, "finding_id": "f1"})

    def test_occurrence_requires_file(self):
        f = _f("COD-X0X", "COD", "LOW", "t", None)
        f["location"] = {}   # no file -> no valid occurrence -> candidate dropped
        self.assertEqual(x0x.build_candidates([f]), [])

    def test_domainless_zzz_sentinel(self):
        f = {"code": "ZZZ-X0X", "severity": "MEDIUM", "short_title": "t",
             "id": "z1", "location": {"file": "a.py"}}
        self.assertEqual(x0x.build_candidates([f])[0]["domain"], "ZZZ")

    def test_build_report_shape_and_required_fields(self):
        meta = {"version": "5.0.1", "ocrdb_version": "0.3.1",
                "target": "/repo", "timestamp": "2026-08-18T00:00:00Z"}
        r = x0x.build_report([_f("COD-X0X", "COD", "LOW", "t", "a.py")], meta,
                             run_id="abc123")
        for k in ("schema_version", "generated_by", "ocrdb_version", "candidates"):
            self.assertIn(k, r)
        self.assertEqual(r["generated_by"],
                         {"panopticon_version": "5.0.1", "run_id": "abc123"})
        self.assertEqual(r["ocrdb_version"], "0.3.1")
        self.assertEqual(r["target"], {"name": "/repo"})
        self.assertEqual(r["generated_at"], "2026-08-18T00:00:00Z")
        for c in r["candidates"]:
            for k in ("domain", "summary", "severity", "occurrences"):
                self.assertIn(k, c)
            self.assertTrue(c["occurrences"] and all("file" in o for o in c["occurrences"]))

    def test_empty_when_no_gaps(self):
        r = x0x.build_report([_f("SEC-A1A", "SEC", "HIGH", "t", "a.py")], {}, run_id="r")
        self.assertEqual(r["candidates"], [])
        self.assertEqual(r["generated_by"]["run_id"], "r")
        self.assertEqual(r["ocrdb_version"], "unknown")   # meta lacked it

    def test_run_id_none_falls_back_to_unknown(self):
        self.assertEqual(
            x0x.build_report([], {}, run_id=None)["generated_by"]["run_id"], "unknown")

    def test_conforms_to_schema(self):
        schema_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "skill", "reference", "x0x-report-schema.json")
        with open(schema_path, encoding="utf-8") as fh:
            schema = json.load(fh)
        meta = {"version": "5.0.1", "ocrdb_version": "0.3.1", "target": "/r",
                "timestamp": "t"}
        findings = [_f("COD-X0X", "COD", "LOW", "dup block", "a.py", 1, "f1"),
                    _f("SEC-X0X", "SEC", "HIGH", "hardcoded id", "b.tsx", 5, "f2",
                       refs=["CWE-639"])]
        self.assertIsNone(jsonschema.validate(x0x.build_report(findings, meta, run_id="run-xyz"), schema))
