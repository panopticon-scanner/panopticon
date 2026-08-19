import json
import os
import tempfile
from pathlib import Path
import unittest

import scripts.evidence as evidence
import scripts.synthesize as synthesize

def _bundle(tmp_path, name, verdicts, stage="primary", run_id="R"):
    d = tmp_path / "verdicts"
    d.mkdir(exist_ok=True)
    (d / name).write_text(json.dumps({
        "verdicts": verdicts,
        "_panopticon": {"run_id": run_id, "role": "domain_advisor",
                        "domain": "SEC", "group": "app", "stage": stage}}))
    return str(d)

class TestVerdictBundles(unittest.TestCase):
    def test_bundle_flattens_by_finding_id(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            d_path = _bundle(tmp_path, "verdicts-app-SEC.json",
                        [{"finding_id": "SEC-100", "verdict": "CONFIRMED", "reasoning": "x"},
                         {"finding_id": "SEC-200", "verdict": "REJECTED", "reasoning": "y"}])
            by_fid, bad = evidence.load_verdict_bundles(d_path)
            self.assertEqual(bad, [])
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid, run_id="R")
            self.assertEqual(v["verdict"], "CONFIRMED")
            self.assertEqual(v["run_id"], "R")
            self.assertEqual(v["stage"], "primary")

    def test_backup_overrides_primary_for_same_finding(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            _bundle(tmp_path, "verdicts-app-SEC.json",
                    [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}], stage="primary")
            d_path = _bundle(tmp_path, "verdicts-app-SEC-backup.json",
                        [{"finding_id": "SEC-100", "verdict": "REJECTED"}], stage="backup")
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid, run_id="R")
            self.assertEqual(v["verdict"], "REJECTED")
            self.assertEqual(v["stage"], "backup")

    def test_match_by_id_enforces_run_id(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            d_path = _bundle(tmp_path, "verdicts-app-SEC.json",
                        [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}], run_id="R")
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            f = {"id": "SEC-100"}
            self.assertEqual(evidence.match_verdict_by_id(f, by_fid, run_id="R")["verdict"], "CONFIRMED")
            self.assertIsNone(evidence.match_verdict_by_id(f, by_fid, run_id="OTHER"))
            self.assertIsNone(evidence.match_verdict_by_id({"id": "SEC-999"}, by_fid, run_id="R"))

    def test_single_verdict_files_are_not_bundles(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            v_dir = tmp_path / "verdicts"
            v_dir.mkdir()
            (v_dir / "abc123.json").write_text(json.dumps(
                {"finding_id": "SEC-1", "verdict": "CONFIRMED"}))
            by_fid, bad = evidence.load_verdict_bundles(str(v_dir))
            self.assertEqual(by_fid, {})
            self.assertEqual(bad, [])

    def test_build_report_binds_bundle_verdict_by_finding_id(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            fp = tmp_path / "findings-app-SEC.json"
            fp.write_text(json.dumps({"findings": [
                {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH",
                 "title": "authz bypass", "description": "x",
                 "location": {"file": "app/x.py", "line_start": 4}, "category": "authz"}]}))
            findings = synthesize.load_findings([str(fp)])
            fid = findings[0]["id"]
            d_path = _bundle(tmp_path, "verdicts-app-SEC.json",
                        [{"finding_id": fid, "verdict": "CONFIRMED", "reasoning": "ok"}],
                        run_id="R")
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            report = synthesize.build_report(findings, [], "src", "high",
                                             "2026-08-15T00:00:00Z",
                                             verdicts={}, verdict_bundles=by_fid,
                                             verdicts_supplied=True, verdict_run_id="R")
            self.assertEqual(report["findings"][0]["evidence"]["status"], "advisor_confirmed")

    def test_queue_id_match_not_overwritten_by_fid_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            fp = tmp_path / "findings-app-SEC.json"
            fp.write_text(json.dumps({"findings": [
                {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH", "title": "authz",
                 "description": "x", "location": {"file": "app/x.py", "line_start": 4},
                 "category": "authz"}]}))
            findings = synthesize.load_findings([str(fp)])
            fid = findings[0]["id"]
            qid = evidence.finding_fingerprint(findings[0])
            verdicts = {qid: {"finding_id": fid, "verdict": "REJECTED"}}
            by_fid = {fid: [{"finding_id": fid, "verdict": "CONFIRMED", "run_id": None}]}
            report = synthesize.build_report(findings, [], "src", "high",
                                             "2026-08-15T00:00:00Z", verdicts=verdicts,
                                             verdict_bundles=by_fid, verdicts_supplied=True)
            self.assertEqual(report["findings"], [])
            self.assertEqual(report["discarded_claims"][0]["evidence"]["status"], "rejected")

    def test_bundle_does_not_clobber_own_run_id_or_stage(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            v_dir = tmp_path / "verdicts"
            v_dir.mkdir()
            (v_dir / "verdicts-app-SEC.json").write_text(json.dumps({
                "verdicts": [{"finding_id": "SEC-100", "verdict": "CONFIRMED",
                              "run_id": "OWN", "stage": "backup"}],
                "_panopticon": {"run_id": "BUNDLE", "stage": "primary"}}))
            by_fid, _ = evidence.load_verdict_bundles(str(v_dir))
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid, run_id="OWN")
            self.assertEqual(v["run_id"], "OWN")
            self.assertEqual(v["stage"], "backup")

    def test_non_dict_panopticon_is_tolerated(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            v_dir = tmp_path / "verdicts"
            v_dir.mkdir()
            (v_dir / "verdicts-app-SEC.json").write_text(json.dumps(
                {"verdicts": [{"finding_id": "SEC-1", "verdict": "CONFIRMED"}],
                 "_panopticon": ["oops"]}))
            by_fid, bad = evidence.load_verdict_bundles(str(v_dir))
            self.assertIn("SEC-1", by_fid)

    def test_stale_cross_run_backup_does_not_evict_valid_primary(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            _bundle(tmp_path, "verdicts-app-SEC.json",
                    [{"finding_id": "SEC-100", "verdict": "CONFIRMED"}], stage="primary", run_id="R")
            d_path = _bundle(tmp_path, "verdicts-app-SEC-backup.json",
                        [{"finding_id": "SEC-100", "verdict": "REJECTED"}], stage="backup", run_id="OLD")
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            v = evidence.match_verdict_by_id({"id": "SEC-100"}, by_fid, run_id="R")
            self.assertIsNotNone(v)
            self.assertEqual(v["verdict"], "CONFIRMED")

    def test_load_verdicts_detailed_ignores_bundles(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            v_dir = tmp_path / "verdicts"
            v_dir.mkdir()
            (v_dir / "verdicts-app-SEC.json").write_text(json.dumps(
                {"verdicts": [{"finding_id": "SEC-1", "verdict": "CONFIRMED"}],
                 "_panopticon": {"run_id": "R", "stage": "primary"}}))
            (v_dir / "junk.json").write_text("not json {")
            verds, unloadable = evidence.load_verdicts_detailed(str(v_dir))
            files = {u["file"] for u in unloadable}
            self.assertNotIn("verdicts-app-SEC.json", files)
            self.assertIn("junk.json", files)

    def test_valid_bundle_run_has_zero_unloadable(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            fp = tmp_path / "findings-app-SEC.json"
            fp.write_text(json.dumps({"findings": [
                {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
                 "description": "x", "location": {"file": "a.py", "line_start": 1},
                 "category": "authz"}]}))
            findings = synthesize.load_findings([str(fp)])
            fid = findings[0]["id"]
            vd = tmp_path / "verdicts"
            vd.mkdir()
            (vd / "verdicts-app-SEC.json").write_text(json.dumps(
                {"verdicts": [{"finding_id": fid, "verdict": "CONFIRMED"}],
                 "_panopticon": {"run_id": "R", "role": "domain_advisor",
                                 "domain": "SEC", "group": "app", "stage": "primary"}}))
            out = tmp_path / "report.json"
            cwd = os.getcwd()
            try:
                os.chdir(tmp_path)
                synthesize.main(["--verdicts-dir", str(vd), "--out", str(out), str(fp)])
            finally:
                os.chdir(cwd)
            rep = json.loads(out.read_text())
            self.assertEqual(rep["meta"]["coverage"]["verdicts"]["unloadable"], 0)
            self.assertEqual(rep["findings"][0]["evidence"]["status"], "advisor_confirmed")

    def test_bundle_verdict_counted_in_supplied(self):
        with tempfile.TemporaryDirectory() as d:
            tmp_path = Path(d)
            fp = tmp_path / "findings-app-SEC.json"
            fp.write_text(json.dumps({"findings": [
                {"domain": "SEC", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
                 "description": "x", "location": {"file": "a.py", "line_start": 1},
                 "category": "authz"}]}))
            findings = synthesize.load_findings([str(fp)])
            fid = findings[0]["id"]
            d_path = _bundle(tmp_path, "verdicts-app-SEC.json",
                        [{"finding_id": fid, "verdict": "CONFIRMED"}], run_id=None)
            by_fid, _ = evidence.load_verdict_bundles(d_path)
            report = synthesize.build_report(findings, [], "src", "high",
                                             "2026-08-15T00:00:00Z", verdicts={},
                                             verdict_bundles=by_fid, verdicts_supplied=True)
            vs = report["meta"]["coverage"]["verdicts"]
            self.assertEqual(vs["matched"], 1)
            self.assertGreaterEqual(vs["supplied"], 1)
            self.assertLessEqual(vs["matched"], vs["supplied"])

if __name__ == '__main__':
    unittest.main()
