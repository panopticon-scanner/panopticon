import json
import os
import shutil
import tempfile
import unittest

import scripts.evidence as evidence
import scripts.reconcile as reconcile

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "reconcile")


class TestFixtures(unittest.TestCase):
    """#run7 TST-E1A: the tests below assume a fixed set of fixture files.
    Fail fast with a clear message if the directory or any expected file is
    missing, instead of letting a later test trip on a FileNotFoundError."""

    EXPECTED = ("run2.json", "run2_part2.json", "run3.json")

    def test_fixture_directory_and_files_exist(self):
        self.assertTrue(os.path.isdir(FIXTURES),
                        "reconcile fixture directory missing: %s" % FIXTURES)
        for name in self.EXPECTED:
            path = os.path.join(FIXTURES, name)
            self.assertTrue(os.path.isfile(path),
                            "reconcile fixture missing: %s" % path)


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

    def test_recovers_discarded_claims_from_the_sibling_file(self):
        # #run9 ARC-D1A: a large report spills discarded_claims to a
        # <stem>-discarded.json sibling with a meta.discarded_claims_file pointer
        # (write_report #15), leaving the inline list empty. load_report must follow
        # the pointer, not silently return zero discarded claims on recovery.
        with tempfile.TemporaryDirectory() as d:
            main = os.path.join(d, "report.json")
            with open(main, "w") as fh:
                json.dump({"findings": [{"id": "F1"}], "discarded_claims": [],
                           "meta": {"discarded_claims_file": "report-discarded.json",
                                    "discarded_claims_count": 2}}, fh)
            with open(os.path.join(d, "report-discarded.json"), "w") as fh:
                json.dump({"discarded_claims": [{"id": "D1"}, {"id": "D2"}]}, fh)
            out = reconcile.load_report(main)
            self.assertEqual([f["id"] for f in out["findings"]], ["F1"])
            self.assertEqual([c["id"] for c in out["discarded_claims"]], ["D1", "D2"])

    def test_rejects_parts_entry_escaping_report_directory(self):
        with self.assertRaises(ValueError):
            reconcile._resolve_part_path(FIXTURES, "../../etc/passwd")

    def test_rejects_absolute_path_parts_entry(self):
        with self.assertRaises(ValueError):
            reconcile._resolve_part_path(FIXTURES, "/etc/passwd")

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

    def _diff(self, name_a, name_b):
        return reconcile.build_diff(
            self._records(name_a), self._records(name_b), name_a, name_b
        )

    def test_cohorts_by_recomputed_fingerprint(self):
        diff = self._diff("run2.json", "run3.json")
        recurring_ids = {rec["id"] for entry in diff["recurring"]
                         for rec in entry["run2"]}
        self.assertEqual(recurring_ids, {"F-TOOL-1", "F-AGENT-1", "R-REJ-1"})
        # Non-recurring run2 findings re-partition by the (file, panel)-clear
        # rule (#914): closed if run3 has zero findings on that (file, panel),
        # else ambiguous. run3's active (file, panel) pairs are
        # {(app/config.py, security), (app/registry.py, architecture),
        # (requirements.txt, security), (app/query.py, security)} — none of
        # them match F-GONE-1's (app/legacy.py, test) or F-GONE-2's
        # (app/auth.py, security), so both are closed. F-DUP-1/F-DUP-2 carry
        # NO file (location.file == "") -- final-review F1: an empty file can
        # never be corroborated by a (file,panel) read, so that group is
        # routed to ambiguous instead, never closed on vacuous evidence.
        closed_ids = {rec["id"] for entry in diff["closed"]
                     for rec in entry["run2"]}
        self.assertEqual(closed_ids, {"F-GONE-1", "F-GONE-2"})
        ambiguous_ids = {rec["id"] for entry in diff["ambiguous"]
                         for rec in entry["run2"]}
        self.assertEqual(ambiguous_ids, {"F-DUP-1", "F-DUP-2"})
        self.assertTrue(diff["ambiguous"])
        self.assertIn("no file recorded", diff["ambiguous"][0]["reason"])
        new_ids = {rec["id"] for entry in diff["new"] for rec in entry["run3"]}
        self.assertEqual(new_ids, {"F-NEW-1"})

    def test_flags_degenerate_collision_within_one_side(self):
        diff = self._diff("run2.json", "run3.json")
        collided = [d for d in diff["meta"]["degenerate_fingerprints"]
                   if d["run"] == "run2"]
        self.assertEqual(len(collided), 1)
        self.assertEqual(sorted(collided[0]["ids"]), ["F-DUP-1", "F-DUP-2"])

    def test_no_kind_change_when_both_sides_are_findings(self):
        diff = self._diff("run2.json", "run3.json")
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

    def test_meta_run_counts(self):
        diff = self._diff("run2.json", "run3.json")
        self.assertEqual(diff["meta"]["run2_count"], len(self._records("run2.json")))
        self.assertEqual(diff["meta"]["run3_count"], len(self._records("run3.json")))
        self.assertEqual(diff["meta"]["run2_report"], "run2.json")

    def test_meta_group_counts_and_no_close_guard_in_normal_case(self):
        # M7: meta.counts values (fingerprint-GROUP counts, not record counts)
        # asserted directly. F-DUP-1/F-DUP-2 collide onto ONE fingerprint (both
        # are entirely empty findings, so they hash identically), so "closed"
        # has 2 groups (F-GONE-1, F-GONE-2) and "ambiguous" has 1 group (the
        # F-DUP collision).
        diff = self._diff("run2.json", "run3.json")
        self.assertEqual(diff["meta"]["counts"],
                         {"recurring": 3, "closed": 2, "ambiguous": 1, "new": 1})
        # F2: run2 and run3 file sets overlap normally here -- no guard fires.
        self.assertIsNone(diff["meta"]["close_guard"])


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
        # F4: the re-worded run3 record must appear on the entry's run3 side,
        # not vanish from every cohort.
        self.assertEqual({r["id"] for r in entry["run3"]}, {"A3"})

    def test_recategorized_on_active_file_is_ambiguous_not_closed(self):
        # SAME (file, panel), DIFFERENT category -> not a coarse match, but the
        # (file,panel) is still active -> ambiguous, never auto-closed.
        r2 = self._recs([self._f("A", "auth.py", "security", "weak-crypto", "MD5")])
        r3 = self._recs([self._f("A3", "auth.py", "security", "crypto-misuse", "MD5 hashing")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertEqual(self._cohort_ids(diff, "ambiguous", "run2"), {"A"})
        self.assertEqual(self._cohort_ids(diff, "closed", "run2"), set())

    def test_genuinely_fixed_file_panel_clear_is_closed(self):
        # A second, file-bearing recurring pair keeps run2/run3's file sets
        # overlapping so this exercises the (file,panel)-clear close in
        # isolation from the F2 close_guard (a single-file-each fixture would
        # trivially share zero paths and trip the guard instead).
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "Missing role check"),
                         self._f("K", "keep.py", "code", "structure", "kept")])
        r3 = self._recs([self._f("B", "other.py", "code", "structure", "Long function"),
                         self._f("K3", "keep.py", "code", "structure", "kept")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertIsNone(diff["meta"]["close_guard"])
        self.assertEqual(self._cohort_ids(diff, "closed", "run2"), {"A"})
        entry = next(e for e in diff["closed"] if "A" in {r["id"] for r in e["run2"]})
        self.assertIn("clear", entry["reason"])

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

    def test_kind_changed_true_for_coarse_match_when_kind_flips(self):
        # F4/F5: kind_changed must no longer be hardwired False for a coarse
        # match -- compute it from the coarse-matched run3 records' kinds.
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "Missing role check")])
        r3 = reconcile.iter_records({"findings": [], "discarded_claims": [
            self._f("A3", "auth.py", "security", "authz", "no longer exploitable")]})
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        entry = diff["recurring"][0]
        self.assertEqual(entry["match_tier"], "coarse")
        self.assertTrue(entry["kind_changed"])

    def test_no_file_recorded_routes_to_ambiguous_not_closed(self):
        # F1: an empty location.file means (file,panel)-clear is vacuous --
        # it can never corroborate a fix, so this must refuse to close. A
        # second, file-bearing recurring pair keeps run2/run3's file sets
        # overlapping so this exercises F1 in isolation from the F2
        # close_guard (which would otherwise fire first and mask F1's reason).
        r2 = self._recs([self._f("A", "", "security", "misc", "Something wrong"),
                         self._f("K", "keep.py", "code", "structure", "kept")])
        r3 = self._recs([self._f("K3", "keep.py", "code", "structure", "kept"),
                         self._f("B", "other.py", "code", "structure", "Long function")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertIsNone(diff["meta"]["close_guard"])
        self.assertEqual(self._cohort_ids(diff, "ambiguous", "run2"), {"A"})
        self.assertEqual(self._cohort_ids(diff, "closed", "run2"), set())
        self.assertTrue(diff["ambiguous"])
        entry = next(e for e in diff["ambiguous"] if "A" in {r["id"] for r in e["run2"]})
        self.assertIn("no file recorded", entry["reason"])

    def test_ambiguous_reason_counts_rejected_claims_separately_from_findings(self):
        # F5: a run2 finding whose (file,panel) is active in run3 ONLY via a
        # rejected claim must still be blocked from closing (safe direction),
        # but the reason must say "rejected claim(s)", never call it a
        # "finding".
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "Missing role check")])
        r3 = reconcile.iter_records({"findings": [], "discarded_claims": [
            self._f("R3", "auth.py", "security", "not-a-real-issue", "false positive")]})
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertEqual(self._cohort_ids(diff, "ambiguous", "run2"), {"A"})
        self.assertTrue(diff["ambiguous"])
        reason = diff["ambiguous"][0]["reason"]
        self.assertIn("1 rejected claim(s)", reason)
        self.assertNotIn("finding(s)", reason)

    def test_empty_run3_refuses_to_close_anything(self):
        # F2: an empty run3 must never read as "area clear" for everything.
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "Missing role check")])
        diff = reconcile.build_diff(r2, [], "r2", "r3")
        self.assertEqual(diff["meta"]["close_guard"], "empty_run3")
        self.assertEqual(self._cohort_ids(diff, "closed", "run2"), set())
        self.assertEqual(self._cohort_ids(diff, "ambiguous", "run2"), {"A"})
        self.assertTrue(diff["ambiguous"])   # #run7 review: parity guard before [0] (TST-B3A)
        self.assertIn("zero records", diff["ambiguous"][0]["reason"])

    def test_zero_file_overlap_refuses_to_close_anything(self):
        # F2 sibling: absolute-vs-relative (or otherwise disjoint) path shapes
        # between the two runs must not silently read as "area clear" either.
        r2 = self._recs([self._f("A", "a.py", "security", "authz", "x")])
        r3 = self._recs([self._f("B", "/abs/a.py", "security", "authz", "y")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertEqual(diff["meta"]["close_guard"], "no_file_overlap")
        self.assertEqual(self._cohort_ids(diff, "closed", "run2"), set())
        self.assertEqual(self._cohort_ids(diff, "ambiguous", "run2"), {"A"})
        self.assertTrue(diff["ambiguous"])
        self.assertIn("share zero paths", diff["ambiguous"][0]["reason"])

    def test_degenerate_group_spanning_multiple_coarse_keys_is_ambiguous(self):
        # M5: airtight group-key guard. Unreachable via iter_records today
        # (fingerprint and coarse_key are both derived from the same finding),
        # but a fingerprint group built from records that disagree on
        # coarse_key must still refuse to close -- free insurance.
        r2 = [{"id": "A", "kind": "finding", "fingerprint": "fp1",
              "coarse_key": ("a.py", "security", "authz")},
             {"id": "B", "kind": "finding", "fingerprint": "fp1",
              "coarse_key": ("b.py", "security", "authz")}]
        # r3 shares a file with r2 (so the F2 close_guard stays off and this
        # test exercises M5 in isolation) but neither its fingerprint nor its
        # coarse key matches fp1's group.
        r3 = self._recs([self._f("C", "a.py", "code", "structure", "Long function")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertIsNone(diff["meta"]["close_guard"])
        self.assertEqual(self._cohort_ids(diff, "ambiguous", "run2"), {"A", "B"})
        self.assertTrue(diff["ambiguous"])
        self.assertIn("multiple coarse keys", diff["ambiguous"][0]["reason"])

    def test_new_finding_with_unseen_coarse_key(self):
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "x")])
        r3 = self._recs([self._f("A3", "auth.py", "security", "authz", "x re-worded"),
                         self._f("N", "new.py", "code", "logic", "off-by-one")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        self.assertEqual(self._cohort_ids(diff, "new", "run3"), {"N"})

    def test_exact_match_carries_coarse_key_siblings_on_run3_side(self):
        # #954: run2 A matches run3 A3 EXACTLY (same title -> same fp). Run3
        # sibling S shares A's coarse key under a different title (different
        # fp): `new` suppresses it (its coarse key is in ck2), so unless the
        # exact entry's run3 side carries it, S appears in NO cohort.
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "same title")])
        r3 = self._recs([self._f("A3", "auth.py", "security", "authz", "same title"),
                         self._f("S", "auth.py", "security", "authz", "re-worded sibling")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        entry = diff["recurring"][0]
        self.assertEqual(entry["match_tier"], "exact")
        # exact ordered list, not a set: a broken dedup that duplicated A3
        # would still satisfy a set comparison (run3 is _by_id-sorted)
        self.assertEqual([r["id"] for r in entry["run3"]], ["A3", "S"])
        self.assertEqual(self._cohort_ids(diff, "new", "run3"), set())

    def test_exact_tier_kind_changed_sees_sibling_kind_flip(self):
        # A run3 coarse-sibling that is a REJECTED claim must flip kind_changed
        # on the exact-tier entry, same as it would on the coarse tier.
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "same title")])
        run3_report = {"findings": [self._f("A3", "auth.py", "security", "authz", "same title")],
                       "discarded_claims": [self._f("S", "auth.py", "security", "authz",
                                                    "re-worded, rejected")]}
        r3 = reconcile.iter_records(run3_report)
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        entry = diff["recurring"][0]
        self.assertEqual(entry["match_tier"], "exact")
        self.assertTrue(entry["kind_changed"])

    def test_every_run3_record_lands_in_some_cohort(self):
        # Accounting invariant (#443's spirit): the union of recurring[].run3
        # and new[].run3 ids covers every run3 record -- nothing vanishes.
        r2 = self._recs([self._f("A", "auth.py", "security", "authz", "same title"),
                         self._f("B", "m.py", "code", "dup", "dup A")])
        r3 = self._recs([self._f("A3", "auth.py", "security", "authz", "same title"),
                         self._f("S", "auth.py", "security", "authz", "sibling"),
                         self._f("C", "m.py", "code", "dup", "dup re-worded"),
                         self._f("N", "new.py", "code", "logic", "brand new")])
        diff = reconcile.build_diff(r2, r3, "r2", "r3")
        seen = (self._cohort_ids(diff, "recurring", "run3")
                | self._cohort_ids(diff, "new", "run3"))
        self.assertEqual(seen, {"A3", "S", "C", "N"})
        # and no cohort carries a duplicated record (dedup regression guard)
        all_ids = [r["id"] for e in diff["recurring"] for r in e["run3"]]
        self.assertEqual(len(all_ids), len(set(all_ids)))


class TestRenderSummary(unittest.TestCase):
    def test_summary_reports_cohort_counts_and_warns_on_collisions(self):
        r2 = reconcile.iter_records(reconcile.load_report(os.path.join(FIXTURES, "run2.json")))
        r3 = reconcile.iter_records(reconcile.load_report(os.path.join(FIXTURES, "run3.json")))
        diff = reconcile.build_diff(r2, r3, "run2.json", "run3.json")
        text = reconcile.render_summary(diff)
        self.assertIn("recurring: 3", text)
        self.assertIn("closed: 2", text)
        self.assertIn("ambiguous: 2", text)
        self.assertIn("new: 1", text)
        self.assertIn("degenerate fingerprint", text.lower())
        self.assertIn("F-DUP-1", text)

    def test_summary_lists_ambiguous_entries_for_human_review(self):
        # M2: the ambiguous cohort is the one a human must review, so its
        # fingerprint + reason must be surfaced in the summary, mirroring the
        # existing kind-changed section's style.
        r2 = reconcile.iter_records(reconcile.load_report(os.path.join(FIXTURES, "run2.json")))
        r3 = reconcile.iter_records(reconcile.load_report(os.path.join(FIXTURES, "run3.json")))
        diff = reconcile.build_diff(r2, r3, "run2.json", "run3.json")
        text = reconcile.render_summary(diff)
        self.assertIn("## ambiguous (kept open)", text)
        self.assertTrue(diff["ambiguous"])
        self.assertIn(diff["ambiguous"][0]["fingerprint"], text)
        self.assertIn("no file recorded", text)


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
