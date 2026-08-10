import json
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

    def test_carries_category_and_coarse_key(self):
        report = {"findings": [{"id": "X-1", "panel": "security",
                                "category": "injection",
                                "location": {"file": "app/db.py"},
                                "title": "t"}]}
        rec = reconcile.iter_records(report)[0]
        self.assertEqual(rec["category"], "injection")
        self.assertEqual(rec["coarse_key"], ("app/db.py", "security", "injection"))


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
        # Non-recurring run2 findings re-partition by the (file, panel)-clear
        # rule (#914): closed if run3 has zero findings on that (file, panel),
        # else ambiguous. run3's active (file, panel) pairs are
        # {(app/config.py, security), (app/registry.py, architecture),
        # (requirements.txt, security), (app/query.py, security)} — none of
        # them match F-GONE-1's (app/legacy.py, test), F-GONE-2's
        # (app/auth.py, security), or F-DUP-1/F-DUP-2's ("", "") — so all
        # four are closed and none are ambiguous.
        closed_ids = {rec["id"] for entry in diff["closed"]
                     for rec in entry["run2"]}
        self.assertEqual(closed_ids,
                         {"F-GONE-1", "F-GONE-2", "F-DUP-1", "F-DUP-2"})
        ambiguous_ids = {rec["id"] for entry in diff["ambiguous"]
                         for rec in entry["run2"]}
        self.assertEqual(ambiguous_ids, set())
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
        ck = ("f.py", "panel", "cat")
        r2 = [{"id": "X-1", "kind": "finding", "fingerprint": fp, "coarse_key": ck}]
        r3 = [{"id": "X-1", "kind": "rejected", "fingerprint": fp, "coarse_key": ck}]
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


class TestBuildDiffCohorts(unittest.TestCase):
    """#914: coarse-key match + safety-first (file,panel)-clear close gate."""

    def _recs(self, findings):
        return reconcile.iter_records({"findings": findings})

    def _f(self, fid, file, panel, cat, title, source=None):
        f = {"id": fid, "panel": panel, "category": cat,
             "location": {"file": file}, "title": title}
        if source:
            f["source"] = source
        return f

    def _cohort_ids(self, diff, cohort, side):
        return {r["id"] for e in diff[cohort] for r in e.get(side, [])}

    def test_reworded_agent_finding_recurs_via_coarse_key(self):
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "Missing role check")])
        r3 = self._recs([self._f("A3", "auth.py", "security", "authz", "No RBAC on admin route")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertEqual(self._cohort_ids(diff, "recurring", "run2"), {"A"})
        entry = diff["recurring"][0]
        self.assertEqual(entry["match_tier"], "coarse")

    def test_recategorized_on_active_file_is_ambiguous_not_closed(self):
        # SAME (file, panel), DIFFERENT category -> not a coarse match, but the
        # (file,panel) is still active -> ambiguous, never auto-closed.
        r2 = self._recs([self._f("A", "auth.py", "security", "weak-crypto", "MD5")])
        r3 = self._recs([self._f("A3", "auth.py", "security", "crypto-misuse", "MD5 hashing")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertEqual(self._cohort_ids(diff, "ambiguous", "run2"), {"A"})
        self.assertEqual(self._cohort_ids(diff, "closed", "run2"), set())

    def test_genuinely_fixed_file_panel_clear_is_closed(self):
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "Missing role check")])
        r3 = self._recs([self._f("B", "other.py", "code", "structure", "Long function")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertEqual(self._cohort_ids(diff, "closed", "run2"), {"A"})
        self.assertIn("clear", diff["closed"][0]["reason"])

    def test_tool_finding_recurs_via_stable_rule(self):
        t2 = self._recs([self._f("T", "pkg.json", "security", "CVE-2021-1", "lodash",
                                 source="tool:trivy")])
        t3 = self._recs([self._f("T3", "pkg.json", "security", "CVE-2021-1", "lodash 4.17.20",
                                 source="tool:trivy")])
        diff = reconcile.build_diff(t2, t3, "r2", "r3")
        self.assertEqual(self._cohort_ids(diff, "recurring", "run2"), {"T"})

    def test_split_merge_cardinality_both_kept(self):
        # two run2 findings on one coarse key, one run3 finding on it -> both kept.
        r2 = self._recs([self._f("A", "m.py", "code", "dup", "Dup logic A"),
                         self._f("B", "m.py", "code", "dup", "Dup logic B")])
        r3 = self._recs([self._f("C", "m.py", "code", "dup", "Duplicated block")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertEqual(self._cohort_ids(diff, "recurring", "run2"), {"A", "B"})
        self.assertEqual(self._cohort_ids(diff, "closed", "run2"), set())

    def test_title_held_recurs_via_exact_tier(self):
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "Missing role check")])
        r3 = self._recs([self._f("A3", "auth.py", "security", "authz", "Missing role check")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertEqual(diff["recurring"][0]["match_tier"], "exact")

    def test_new_finding_with_unseen_coarse_key(self):
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "x")])
        r3 = self._recs([self._f("A3", "auth.py", "security", "authz", "x re-worded"),
                         self._f("N", "new.py", "code", "logic", "off-by-one")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertEqual(self._cohort_ids(diff, "new", "run3"), {"N"})


class TestRenderSummary(unittest.TestCase):
    def test_summary_reports_cohort_counts_and_warns_on_collisions(self):
        r2 = reconcile.iter_records(reconcile.load_report(os.path.join(FIXTURES, "run2.json")))
        r3 = reconcile.iter_records(reconcile.load_report(os.path.join(FIXTURES, "run3.json")))
        diff = reconcile.build_diff(r2, r3, "run2.json", "run3.json")
        text = reconcile.render_summary(diff)
        self.assertIn("recurring: 3", text)
        self.assertIn("closed: 4", text)
        self.assertIn("ambiguous: 0", text)
        self.assertIn("new: 1", text)
        self.assertIn("degenerate fingerprint", text.lower())
        self.assertIn("F-DUP-1", text)


class TestDeterminism(unittest.TestCase):
    def test_build_diff_is_order_independent_and_byte_stable(self):
        # Stage 1's output must be byte-identical regardless of the order
        # findings arrived in — a stated invariant (the sort discipline in
        # build_diff). Reversing both inputs must not change the serialized diff.
        r2 = reconcile.iter_records(reconcile.load_report(os.path.join(FIXTURES, "run2.json")))
        r3 = reconcile.iter_records(reconcile.load_report(os.path.join(FIXTURES, "run3.json")))
        d1 = reconcile.build_diff(r2, r3, "run2.json", "run3.json")
        d2 = reconcile.build_diff(list(reversed(r2)), list(reversed(r3)),
                                  "run2.json", "run3.json")
        self.assertEqual(json.dumps(d1, sort_keys=True), json.dumps(d2, sort_keys=True))


class TestCli(unittest.TestCase):
    def test_diff_subcommand_writes_json_and_summary(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "diff.json")
            summary = os.path.join(d, "summary.md")
            rc = reconcile.main(["diff",
                                 os.path.join(FIXTURES, "run2.json"),
                                 os.path.join(FIXTURES, "run3.json"),
                                 "--out", out, "--summary", summary])
            self.assertEqual(rc, 0)
            with open(out) as fh:
                diff = json.load(fh)
            self.assertEqual(len(diff["recurring"]), 3)
            self.assertTrue(os.path.exists(summary))
            with open(summary) as fh:
                self.assertIn("recurring: 3", fh.read())
