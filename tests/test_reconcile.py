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
