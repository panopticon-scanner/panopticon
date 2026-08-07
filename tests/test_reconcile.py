import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
import scripts.evidence as evidence
import scripts.reconcile as reconcile

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "reconcile")


class TestLoadReport(unittest.TestCase):
    def test_merges_findings_and_discarded_claims_across_parts(self):
        report = reconcile.load_report(os.path.join(FIXTURES, "run2.json"))
        ids = {f["id"] for f in report["findings"]}
        self.assertEqual(
            ids, {"F-TOOL-1", "F-AGENT-1", "F-GONE-1", "F-DUP-1",
                  "F-DUP-2", "F-GONE-2"})
        self.assertEqual([c["id"] for c in report["discarded_claims"]],
                         ["R-REJ-1"])

    def test_single_file_report_with_no_parts(self):
        report = reconcile.load_report(os.path.join(FIXTURES, "run3.json"))
        self.assertEqual(len(report["findings"]), 3)
        self.assertEqual(len(report["discarded_claims"]), 1)

    def test_rejects_parts_entry_escaping_report_directory(self):
        with self.assertRaises(ValueError):
            reconcile._resolve_part_path(FIXTURES, "../../etc/passwd")

    def test_bare_filename_with_same_dir_part_does_not_raise(self):
        # Regression test: os.path.dirname("run2.json") == "" when the
        # caller passes a bare filename (the normal case when running the
        # CLI from inside the report's own directory). load_report must
        # still resolve the same-directory meta.parts entry rather than
        # spuriously rejecting it as unsafe.
        with tempfile.TemporaryDirectory() as tmpdir:
            shutil.copy(os.path.join(FIXTURES, "run2.json"), tmpdir)
            shutil.copy(os.path.join(FIXTURES, "run2_part2.json"), tmpdir)
            cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                report = reconcile.load_report("run2.json")
            finally:
                os.chdir(cwd)
            self.assertEqual(len(report["findings"]), 6)
            self.assertEqual(len(report["discarded_claims"]), 1)


class TestIterRecords(unittest.TestCase):
    def test_tags_kind_and_recomputes_fingerprint(self):
        report = reconcile.load_report(os.path.join(FIXTURES, "run2.json"))
        records = reconcile.iter_records(report)
        by_id = {r["id"]: r for r in records}
        self.assertEqual(by_id["F-TOOL-1"]["kind"], "finding")
        self.assertEqual(by_id["R-REJ-1"]["kind"], "rejected")
        # recomputed fingerprint must differ from the fixture's placeholder
        # stored value and must match calling evidence directly
        tool_finding = next(f for f in report["findings"] if f["id"] == "F-TOOL-1")
        self.assertEqual(by_id["F-TOOL-1"]["fingerprint"],
                         evidence.finding_fingerprint(tool_finding))
        self.assertEqual(by_id["F-TOOL-1"]["stored_fingerprint"], "deadbeefdeadbeef")
        self.assertNotEqual(by_id["F-TOOL-1"]["fingerprint"], "deadbeefdeadbeef")

    def test_location_file_defaults_to_empty_string(self):
        report = {"findings": [{"id": "X", "panel": "p"}], "discarded_claims": []}
        records = reconcile.iter_records(report)
        self.assertEqual(records[0]["location_file"], "")


class TestBuildDiff(unittest.TestCase):
    def _records(self, name):
        report = reconcile.load_report(os.path.join(FIXTURES, name))
        return reconcile.iter_records(report)

    def test_cohorts_by_recomputed_fingerprint(self):
        r2 = self._records("run2.json")
        r3 = self._records("run3.json")
        diff = reconcile.build_diff(r2, r3, "run2.json", "run3.json")
        recurring_ids = {rec["id"] for entry in diff["recurring"]
                         for rec in entry["run2"]}
        self.assertEqual(recurring_ids, {"F-TOOL-1", "F-AGENT-1", "R-REJ-1"})
        gone_ids = {rec["id"] for entry in diff["fixed_or_gone"]
                   for rec in entry["run2"]}
        self.assertEqual(gone_ids,
                         {"F-GONE-1", "F-GONE-2", "F-DUP-1", "F-DUP-2"})
        new_ids = {rec["id"] for entry in diff["new"] for rec in entry["run3"]}
        self.assertEqual(new_ids, {"F-NEW-1"})

    def test_flags_degenerate_collision_within_one_side(self):
        r2 = self._records("run2.json")
        r3 = self._records("run3.json")
        diff = reconcile.build_diff(r2, r3, "run2.json", "run3.json")
        collided = [d for d in diff["meta"]["degenerate_fingerprints"]
                   if d["run"] == "run2"]
        self.assertEqual(len(collided), 1)
        self.assertEqual(sorted(collided[0]["ids"]), ["F-DUP-1", "F-DUP-2"])

    def test_no_kind_change_when_both_sides_are_findings(self):
        r2 = self._records("run2.json")
        r3 = self._records("run3.json")
        diff = reconcile.build_diff(r2, r3, "run2.json", "run3.json")
        entry = next(e for e in diff["recurring"]
                    for rec in e["run2"] if rec["id"] == "F-TOOL-1")
        self.assertFalse(entry["kind_changed"])

    def test_kind_changed_true_when_finding_becomes_rejected(self):
        # A fingerprint that was a live finding in run2 but a rejected claim in
        # run3 (or vice-versa) must set kind_changed — the signal a triager
        # uses to notice a finding's status flipped across runs.
        fp = "a" * 16
        r2 = [{"id": "X-1", "kind": "finding", "fingerprint": fp}]
        r3 = [{"id": "X-1", "kind": "rejected", "fingerprint": fp}]
        diff = reconcile.build_diff(r2, r3, "run2.json", "run3.json")
        entry = next(e for e in diff["recurring"] if e["fingerprint"] == fp)
        self.assertTrue(entry["kind_changed"])

    def test_meta_counts(self):
        r2 = self._records("run2.json")
        r3 = self._records("run3.json")
        diff = reconcile.build_diff(r2, r3, "run2.json", "run3.json")
        self.assertEqual(diff["meta"]["run2_count"], len(r2))
        self.assertEqual(diff["meta"]["run3_count"], len(r3))
        self.assertEqual(diff["meta"]["run2_report"], "run2.json")


class TestRenderSummary(unittest.TestCase):
    def test_summary_reports_cohort_counts_and_warns_on_collisions(self):
        r2 = reconcile.iter_records(reconcile.load_report(os.path.join(FIXTURES, "run2.json")))
        r3 = reconcile.iter_records(reconcile.load_report(os.path.join(FIXTURES, "run3.json")))
        diff = reconcile.build_diff(r2, r3, "run2.json", "run3.json")
        text = reconcile.render_summary(diff)
        self.assertIn("recurring: 3", text)
        self.assertIn("fixed_or_gone: 4", text)
        self.assertIn("new: 1", text)
        self.assertIn("degenerate fingerprint", text.lower())
        self.assertIn("F-DUP-1", text)
