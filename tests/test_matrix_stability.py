"""#3651 phase 1: `devtools/matrix_stability.py`, and `compare_runs`' opt-in for runs whose
layouts differ.

Every report here is synthetic and built in the test: no setup or review runs, and no real
run data is read.
"""
import io
import json
import os
from contextlib import redirect_stderr, redirect_stdout

import compare_runs as cr
import matrix_stability as ms

from tests.test_compare_runs import Workspace, agent, report, tool

FA, FB, FC = "sha256:" + "a" * 64, "sha256:" + "b" * 64, "sha256:" + "c" * 64


def confirmed(finding, status="advisor_confirmed"):
    return dict(finding, evidence={"status": status})


def run(findings=(), matrix=FA, layout=None, groups=None, gate="PASS", origin="committed",
        dirty=False, meta=None, **kw):
    """One synthetic report under the matrix `matrix`; `meta` adds to or replaces its meta."""
    doc = report(findings, layout_fingerprint=layout or matrix,
                 meta=dict({"target_dirty": dirty,
                            "matrix": {"origin": origin, "matrix_fingerprint": matrix,
                                       "config_sha256": None, "setup_draft": None}},
                           **(meta or {})), **kw)
    doc["summary"]["gate"] = gate
    doc["groups"] = [{"name": name, "files": files} for name, files in (groups or {}).items()]
    return doc


# Three issues, each at its own place, so each is its own cluster.
SQLI = confirmed(agent(10, severity="CRITICAL", title="sql injection"))
AUTHZ = confirmed(agent(100, file="src/auth.py", category="authz", severity="HIGH",
                        title="missing check"))
XSS = confirmed(agent(200, file="src/view.py", category="xss", severity="HIGH", title="xss"))
CVE = confirmed(tool(5, rule="CVE-1", file="Cargo.lock", severity="HIGH"), "tool_confirmed")


class TestCompareRunsAcceptsDifferentLayoutsOnlyByRequest(Workspace):
    def test_without_the_flag_it_still_refuses(self):
        message = self.refused(run(matrix=FA), run(matrix=FB))
        self.assertIn("layout_fingerprint differs across runs", message)
        self.assertIn(FA, message)
        code, out, err = self._main(run(matrix=FA), run(matrix=FB))
        self.assertEqual(cr.REFUSED, code)
        self.assertEqual("", out)
        self.assertIn("layout_fingerprint differs", err)

    def test_with_the_flag_the_first_line_says_so_and_lists_them(self):
        doc = self.compare(run([SQLI], matrix=FA), run([SQLI], matrix=FB),
                           allow_different_layouts=True)
        self.assertIsNone(doc["identity"]["layout_fingerprint"])
        self.assertEqual([FA, FB], doc["identity"]["layouts"])
        first = cr.summary_lines(doc)[0]
        self.assertTrue(first.startswith("LAYOUTS DIFFER (compared by request): "), first)
        self.assertIn("run1=%s" % FA, first)
        self.assertIn("run2=%s" % FB, first)
        code, out, _err = self._main(run([SQLI], matrix=FA), run([SQLI], matrix=FB),
                                     flags=["--allow-different-layouts"])
        self.assertEqual(0, code)
        self.assertTrue(out.startswith("LAYOUTS DIFFER (compared by request): "))
        # The findings still match: the key holds no group.
        self.assertEqual(1, doc["agreement"]["all"])

    def test_the_flag_changes_nothing_when_the_layouts_agree(self):
        plain = self.compare(run([SQLI]), run([SQLI]))
        flagged = self.compare(run([SQLI]), run([SQLI]), allow_different_layouts=True)
        self.assertEqual(FA, flagged["identity"]["layout_fingerprint"])
        self.assertIsNone(flagged["identity"]["layouts"])
        self.assertEqual(cr.summary_lines(plain), cr.summary_lines(flagged))
        self.assertFalse(cr.summary_lines(plain)[0].startswith("LAYOUTS"))

    def test_the_flag_excuses_no_other_mismatch(self):
        for label, other in (("version", run(matrix=FB, meta={"version": "5.3.1"})),
                             ("profile", run(matrix=FB, profile="custom"))):
            with self.subTest(label=label):
                self.assertIn("%s differs" % label,
                              self.refused(run(matrix=FA), other, allow_different_layouts=True))
        unrecorded = run(matrix=FB)
        del unrecorded["summary"]["health"]["basis"]["layout_fingerprint"]
        self.assertIn("layout_fingerprint is not recorded on every run",
                      self.refused(run(matrix=FA), unrecorded, allow_different_layouts=True))

    def test_a_dirty_tree_is_excused_only_for_a_fresh_matrix_and_only_by_request(self):
        fresh = run([SQLI], matrix=FB, origin="working_tree", dirty=True)
        # Without the flag: refused, as ever.
        self.assertIn("a dirty tree was scanned: run2", self.refused(run([SQLI]), dict(
            fresh, summary=run([SQLI], matrix=FA)["summary"])))
        # With it: accepted, and named in the summary's opening lines.
        doc = self.compare(run([SQLI], matrix=FA), fresh, allow_different_layouts=True)
        self.assertEqual(["run2"], doc["identity"]["dirty_fresh_matrix"])
        self.assertTrue(doc["identity"]["commit_verified"])
        lines = cr.summary_lines(doc)
        self.assertTrue(lines[1].startswith("DIRTY TREE, FRESH MATRIX: run2 "), lines[1])
        self.assertIn("other uncommitted changes cannot be ruled out", lines[1])
        # A dirty tree whose matrix is committed, unknown or unrecorded is still refused.
        for origin in ("committed", "unknown", None):
            with self.subTest(origin=origin):
                dirty = run([SQLI], matrix=FB, origin=origin, dirty=True)
                if origin is None:
                    del dirty["meta"]["matrix"]
                self.assertIn("a dirty tree was scanned: run2", self.refused(
                    run([SQLI], matrix=FA), dirty, allow_different_layouts=True))

    def _main(self, *docs, flags=()):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cr.main(self.paths(*docs) + list(flags))
        return code, out.getvalue(), err.getvalue()


class _Measured(Workspace):
    def measure(self, drafts, baseline=(), **kw):
        draft_paths = [self.write("d%d-report.json" % i, d) for i, d in enumerate(drafts)]
        base_paths = [self.write("b%d-report.json" % i, d) for i, d in enumerate(baseline)]
        return ms.measure(draft_paths, base_paths, **kw)

    def refused(self, drafts, baseline=(), **kw):
        with self.assertRaises(cr.Refused) as ctx:
            self.measure(drafts, baseline, **kw)
        return str(ctx.exception)


class TestWhatItMeasures(_Measured):
    def test_identical_runs_are_perfectly_similar(self):
        doc = self.measure([run([SQLI, AUTHZ], matrix=FA), run([SQLI, AUTHZ], matrix=FB)],
                           [run([SQLI, AUTHZ], matrix=FC), run([SQLI, AUTHZ], matrix=FC)])
        for group in ("drafts", "baseline"):
            for pop in ms.POPULATIONS:
                row = doc["findings"][group][pop]["HIGH+"]
                self.assertEqual((1.0, 1.0, 1), (row["jaccard"]["mean"], row["jaccard"]["min"],
                                                 row["pairs"]))
                self.assertEqual({"clusters": 2, "all": 2, "majority": 2, "only_one": 0},
                                 row["found"])
        self.assertEqual({pop: {level: 0.0 for level in ms.LEVELS} for pop in ms.POPULATIONS},
                         doc["draft_effect"])
        self.assertEqual({"drafts": 2, "baseline": 2}, doc["runs"])
        self.assertEqual(2, doc["matrices"]["drafts_distinct"])

    def test_the_drafts_effect_is_the_baselines_agreement_minus_the_drafts(self):
        # The frozen matrix finds the same two things twice. The two drafts share one of
        # three: |{sqli}| / |{sqli, authz, xss}| = 1/3.
        doc = self.measure([run([SQLI, AUTHZ], matrix=FA), run([SQLI, XSS], matrix=FB)],
                           [run([SQLI, AUTHZ], matrix=FC), run([SQLI, AUTHZ], matrix=FC)])
        drafts = doc["findings"]["drafts"]["gate_eligible"]
        self.assertEqual(0.3333, drafts["HIGH+"]["jaccard"]["mean"])
        self.assertEqual(1.0, drafts["CRITICAL"]["jaccard"]["mean"])
        self.assertEqual(0.0, drafts["HIGH"]["jaccard"]["mean"])
        self.assertEqual({"clusters": 3, "all": 1, "majority": 1, "only_one": 2},
                         drafts["HIGH+"]["found"])
        self.assertEqual(1.0, doc["findings"]["baseline"]["gate_eligible"]["HIGH+"]["jaccard"]["mean"])
        self.assertEqual({"CRITICAL": 0.0, "HIGH": 1.0, "HIGH+": 0.6667},
                         doc["draft_effect"]["gate_eligible"])

    def test_gate_eligible_and_all_active_are_two_populations(self):
        unverified = agent(100, file="src/auth.py", category="authz", severity="HIGH",
                           title="missing check")       # no confirmed evidence
        doc = self.measure([run([SQLI, AUTHZ], matrix=FA), run([SQLI, unverified], matrix=FB)])
        self.assertEqual(1.0, doc["findings"]["drafts"]["all_active"]["HIGH"]["jaccard"]["mean"])
        self.assertEqual(0.0, doc["findings"]["drafts"]["gate_eligible"]["HIGH"]["jaccard"]["mean"])
        # Statuses outside the gate's population do not count as eligible.
        for status in ("tool_reported", "needs_more_info", "unverified", "rejected"):
            with self.subTest(status=status):
                other = self.measure([run([SQLI], matrix=FA),
                                      run([confirmed(agent(10, severity="CRITICAL"), status)],
                                          matrix=FB)])
                self.assertEqual(0.0, other["findings"]["drafts"]["gate_eligible"]["CRITICAL"]
                                 ["jaccard"]["mean"])

    def test_a_tool_finding_is_matched_by_its_fingerprint(self):
        moved = confirmed(tool(900, rule="CVE-1", file="Cargo.lock", severity="HIGH"),
                          "tool_confirmed")            # same rule, another line
        doc = self.measure([run([CVE], matrix=FA), run([moved], matrix=FB)])
        self.assertEqual(1.0, doc["findings"]["drafts"]["gate_eligible"]["HIGH"]["jaccard"]["mean"])

    def test_two_runs_that_found_nothing_are_identical(self):
        doc = self.measure([run(matrix=FA), run(matrix=FB)])
        row = doc["findings"]["drafts"]["gate_eligible"]["HIGH+"]
        self.assertEqual((1.0, 0), (row["jaccard"]["mean"], row["found"]["clusters"]))
        self.assertEqual(1.0, ms.jaccard(set(), set()))
        self.assertEqual(0.0, ms.jaccard({1}, set()))
        self.assertEqual(0.5, ms.jaccard({1, 2}, {2, 3, 4}) * 2)

    def test_a_severity_is_the_highest_one_a_run_gave_in_the_cluster(self):
        low = confirmed(agent(10, severity="HIGH", title="sql injection"))
        doc = self.measure([run([SQLI], matrix=FA), run([low], matrix=FB)])
        found = doc["findings"]["drafts"]["gate_eligible"]
        # One issue, rated CRITICAL by one run and HIGH by the other: together in HIGH+,
        # apart in each level.
        self.assertEqual((1.0, 0.0, 0.0), (found["HIGH+"]["jaccard"]["mean"],
                                           found["CRITICAL"]["jaccard"]["mean"],
                                           found["HIGH"]["jaccard"]["mean"]))

    def test_the_gate_the_letter_and_the_score(self):
        doc = self.measure(
            [run(matrix=FA, gate="PASS", score=80.0, letter="B"),
             run(matrix=FB, gate="FAIL", score=60.0, letter="D"),
             run(matrix=FC, gate="PASS", score=70.0, letter=None, provisional="C")])
        row = doc["outcomes"]["drafts"]
        self.assertEqual({"FAIL": 1, "PASS": 2}, row["gate"])
        self.assertEqual(1, row["gate_flips"])
        self.assertEqual({"B": 1, "C (provisional)": 1, "D": 1}, row["letters"])
        self.assertEqual(3, row["letters_distinct"])
        self.assertEqual({"n": 3, "min": 60.0, "max": 80.0, "mean": 70.0, "stdev": 8.165},
                         row["health"])
        same = self.measure([run(matrix=FA), run(matrix=FB)])["outcomes"]["drafts"]
        self.assertEqual((0, 1, 0.0), (same["gate_flips"], same["letters_distinct"],
                                       same["health"]["stdev"]))

    def test_each_draft_is_scored_against_what_most_baseline_runs_found(self):
        # Three baseline runs: SQLI in all, AUTHZ in two (a majority), XSS in one.
        baseline = [run([SQLI, AUTHZ, XSS], matrix=FC), run([SQLI, AUTHZ], matrix=FC),
                    run([SQLI], matrix=FC)]
        doc = self.measure([run([SQLI], matrix=FA), run([SQLI, AUTHZ, CVE], matrix=FB)], baseline)
        rows = {row["run"]: row["gate_eligible"]["HIGH+"] for row in doc["against_baseline"]}
        self.assertEqual({"baseline_majority": 2, "missed": 1, "added": 0}, rows["draft1"])
        self.assertEqual({"baseline_majority": 2, "missed": 0, "added": 1}, rows["draft2"])
        # A finding only one baseline run made is not in the majority, and finding it again
        # is not an addition.
        again = self.measure([run([SQLI, AUTHZ, XSS], matrix=FA), run([SQLI, AUTHZ], matrix=FB)],
                             baseline)["against_baseline"][0]["gate_eligible"]["HIGH+"]
        self.assertEqual({"baseline_majority": 2, "missed": 0, "added": 0}, again)

    def test_without_a_baseline_there_is_no_effect_to_state(self):
        doc = self.measure([run([SQLI], matrix=FA), run([SQLI], matrix=FB)])
        self.assertIsNone(doc["draft_effect"])
        self.assertIsNone(doc["against_baseline"])
        self.assertNotIn("baseline", doc["findings"])
        self.assertIn("no baseline was given", "\n".join(ms.summary_lines(doc)))


class TestHowFarTheDraftsDiffer(_Measured):
    FILES = ["a.py", "b.py", "c.py", "d.py"]

    def test_co_grouping_is_over_pairs_of_files(self):
        one = {"x": {"a", "b", "c", "d"}}                      # six pairs together
        self.assertEqual({"groups": [1, 1], "names": 1.0, "co_grouping": 1.0},
                         ms.matrix_similarity(one, {"x": {"a", "b", "c", "d"}}))
        # Renaming every group changes the names and not the cut.
        self.assertEqual({"groups": [1, 1], "names": 0.0, "co_grouping": 1.0},
                         ms.matrix_similarity(one, {"y": {"a", "b", "c", "d"}}))
        # Split in half: two pairs still together, of the six that ever were.
        split = ms.matrix_similarity(one, {"x": {"a", "b"}, "z": {"c", "d"}})
        self.assertEqual(([1, 2], 0.5, 0.3333), (split["groups"], split["names"],
                                                 split["co_grouping"]))
        # Every file alone in both: nothing was ever together, so nothing was split.
        alone = {name: {name} for name in "abcd"}
        self.assertEqual(1.0, ms.matrix_similarity(alone, dict(alone))["co_grouping"])
        self.assertEqual(0.0, ms.matrix_similarity(one, alone)["co_grouping"])
        self.assertEqual(1.0, ms.matrix_similarity({}, {})["co_grouping"])

    def test_it_agrees_with_counting_the_pairs_one_by_one(self):
        import itertools
        one = {"p": {"a", "b", "c"}, "q": {"d", "e"}, "r": {"f"}}
        two = {"s": {"a", "b"}, "t": {"c", "d", "e", "f"}}

        def together(partition):
            return {frozenset(pair) for files in partition.values()
                    for pair in itertools.combinations(sorted(files), 2)}

        expected = len(together(one) & together(two)) / len(together(one) | together(two))
        self.assertEqual(round(expected, 4), ms.matrix_similarity(one, two)["co_grouping"])

    def test_the_drafts_movement_is_read_off_each_reports_groups(self):
        doc = self.measure([
            run([SQLI], matrix=FA, groups={"app": self.FILES}),
            run([SQLI], matrix=FB, groups={"app": self.FILES[:2], "lib": self.FILES[2:]}),
            run([SQLI], matrix=FC, groups={"core": self.FILES})])
        movement = doc["matrix_movement"]
        self.assertEqual({"n": 3, "min": 1.0, "max": 2.0, "mean": 1.3333, "stdev": 0.4714},
                         movement["group_counts"])
        pairs = {tuple(row["runs"]): row for row in doc["draft_pairs"]}
        self.assertEqual(0.3333, pairs[("draft1", "draft2")]["matrix"]["co_grouping"])
        self.assertEqual(1.0, pairs[("draft1", "draft3")]["matrix"]["co_grouping"])
        self.assertEqual(0.0, pairs[("draft1", "draft3")]["matrix"]["names"])
        self.assertFalse(pairs[("draft1", "draft2")]["same_matrix"])
        self.assertEqual(3, doc["matrices"]["drafts_distinct"])

    def test_whether_results_follow_the_matrix(self):
        # Three drafts. The two that cut the tree alike find the same things; the third
        # cuts it differently and finds something else.
        doc = self.measure([
            run([SQLI, AUTHZ], matrix=FA, groups={"app": self.FILES}),
            run([SQLI, AUTHZ], matrix=FB, groups={"core": self.FILES}),
            run([SQLI, XSS], matrix=FC, groups={"a": self.FILES[:2], "b": self.FILES[2:]})])
        self.assertEqual(1.0, doc["matrix_movement"]["results_follow_matrix_r"])
        self.assertIn("r = 1.000", "\n".join(ms.summary_lines(doc)))
        # Two runs are one pair: nothing to correlate.
        few = self.measure([run([SQLI], matrix=FA), run([SQLI], matrix=FB)])
        self.assertIsNone(few["matrix_movement"]["results_follow_matrix_r"])
        self.assertIn("not measurable", "\n".join(ms.summary_lines(few)))
        self.assertIsNone(ms._pearson([1.0, 1.0, 1.0], [0.1, 0.5, 0.9]))      # no variance
        self.assertEqual(-1.0, ms._pearson([1, 2, 3], [3, 2, 1]))


class TestWhatItRefusesAndDiscloses(_Measured):
    def test_it_needs_two_draft_runs_and_a_baseline_of_two_or_none(self):
        self.assertIn("at least 2 draft runs", self.refused([run()]))
        self.assertIn("a baseline of one run measures no noise",
                      self.refused([run(matrix=FA), run(matrix=FB)], [run(matrix=FC)]))
        path = self.write("same-report.json", run())
        with self.assertRaises(cr.Refused):
            ms.measure([path, path])
        with self.assertRaises(cr.Refused):
            ms.measure([path, self.write("other-report.json", run(matrix=FB))], [path, path])
        self.assertIn("--line-window", self.refused([run(matrix=FA), run(matrix=FB)], window=-1))

    def test_a_baseline_must_be_one_matrix(self):
        message = self.refused([run(matrix=FA), run(matrix=FB)],
                               [run(matrix=FA), run(matrix=FC)])
        self.assertIn("the baseline is not one matrix", message)
        self.assertIn("2 different fingerprints", message)

    def test_runs_of_another_version_or_commit_are_refused(self):
        self.assertIn("version differs", self.refused(
            [run(matrix=FA), run(matrix=FB, meta={"version": "5.3.1"})]))
        other = run(matrix=FB)
        other["meta"]["target_commit"] = "f" * 40
        self.assertIn("target_commit differs", self.refused([run(matrix=FA), other]))
        self.assertIn("a dirty tree was scanned", self.refused(
            [run(matrix=FA), run(matrix=FB, dirty=True)]))

    def test_a_fresh_matrix_on_a_dirty_tree_is_measured_and_named(self):
        doc = self.measure([run([SQLI], matrix=FA, origin="working_tree", dirty=True),
                            run([SQLI], matrix=FB, origin="working_tree", dirty=True)])
        self.assertEqual(2, doc["dirty_fresh_matrix"])
        self.assertTrue(ms.summary_lines(doc)[0].startswith("DIRTY TREE, FRESH MATRIX: 2 run(s)"))

    def test_drafts_that_share_one_matrix_are_called_what_they_are(self):
        doc = self.measure([run([SQLI], matrix=FA), run([SQLI], matrix=FA)])
        self.assertEqual(1, doc["matrices"]["drafts_distinct"])
        self.assertTrue(doc["draft_pairs"][0]["same_matrix"])
        self.assertIn("the draft runs all share one matrix", "\n".join(ms.summary_lines(doc)))

    def test_a_report_from_before_the_fingerprint_falls_back_to_the_layout_and_says_so(self):
        old = run([SQLI], matrix=FB)
        del old["meta"]["matrix"]
        doc = self.measure([run([SQLI], matrix=FA), old])
        self.assertEqual(["layout_fingerprint", "matrix_fingerprint"],
                         doc["matrices"]["fingerprint_source"])
        self.assertEqual(FB, doc["matrices"]["fingerprints"]["draft2"])
        self.assertIn("predates meta.matrix", "\n".join(ms.summary_lines(doc)))
        # Two matrices with one layout and different floors are two matrices.
        both = self.measure([run([SQLI], matrix=FA, layout=FC), run([SQLI], matrix=FB, layout=FC)])
        self.assertEqual(2, both["matrices"]["drafts_distinct"])

    def test_a_baseline_that_is_one_of_the_drafts_is_noted(self):
        doc = self.measure([run(matrix=FA), run(matrix=FB)], [run(matrix=FA), run(matrix=FA)])
        self.assertTrue(doc["matrices"]["baseline_is_a_draft"])
        self.assertIn("also one of the drafts", "\n".join(ms.summary_lines(doc)))


class TestTheOutputIsAggregatesOnly(_Measured):
    SECRET_TITLE, SECRET_PATH, SECRET_TARGET = "leaky-title-9f3", "src/secret_path_7a1.py", "acme-core"

    def _drafts(self):
        finding = confirmed(agent(10, file=self.SECRET_PATH, severity="CRITICAL",
                                  title=self.SECRET_TITLE))
        return [run([finding], matrix=matrix, groups={"grp-secret-2c": [self.SECRET_PATH]},
                    meta={"target": self.SECRET_TARGET}) for matrix in (FA, FB)]

    def _leaks(self, text):
        from tests.test_compare_runs import SHA
        return [word for word in (self.SECRET_TITLE, self.SECRET_PATH, self.SECRET_TARGET,
                                  "grp-secret-2c", "d0-report.json", SHA, self.dir)
                if word in text]

    def test_neither_the_summary_nor_the_document_names_a_finding_a_path_or_the_target(self):
        doc = self.measure(self._drafts())
        self.assertEqual([], self._leaks(json.dumps(doc)))
        self.assertEqual([], self._leaks("\n".join(ms.summary_lines(doc))))
        self.assertNotIn("detail", doc)

    def test_detail_is_opt_in_and_stays_out_of_the_summary(self):
        doc = self.measure(self._drafts(), detail=True)
        self.assertEqual({"draft1": "d0-report.json", "draft2": "d1-report.json"},
                         doc["detail"]["reports"])
        self.assertEqual(self.SECRET_TITLE, doc["detail"]["clusters"][0]["title"])
        self.assertEqual([], self._leaks("\n".join(ms.summary_lines(doc))))

    def test_the_command_line(self):
        paths = [self.write("d%d-report.json" % i, d) for i, d in enumerate(self._drafts())]
        out_path = os.path.join(self.dir, "stability.json")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = ms.main(paths + ["--out", out_path])
        self.assertEqual((0, ""), (code, err.getvalue()))
        self.assertIn("matrix_stability: 2 draft run(s) under 2 distinct matrices, 0 baseline",
                      out.getvalue())
        self.assertEqual([], self._leaks(out.getvalue()))
        with open(out_path, encoding="utf-8") as fh:
            self.assertEqual(self.measure(self._drafts()), json.load(fh))
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = ms.main(paths[:1])
        self.assertEqual((cr.REFUSED, ""), (code, out.getvalue()))
        self.assertIn("matrix_stability: refused: need at least 2 draft runs", err.getvalue())

    def test_the_order_of_the_runs_does_not_change_the_numbers(self):
        drafts = [run([SQLI, AUTHZ], matrix=FA, groups={"a": ["x", "y"]}, score=70.0),
                  run([SQLI, XSS], matrix=FB, groups={"b": ["x"], "c": ["y"]}, score=80.0),
                  run([CVE], matrix=FC, groups={"a": ["x", "y"]}, score=90.0, gate="FAIL")]
        baseline = [run([SQLI, AUTHZ], matrix=FA), run([SQLI], matrix=FA)]

        def numbers(doc):
            return (doc["findings"], doc["outcomes"], doc["draft_effect"],
                    doc["matrix_movement"])

        self.assertEqual(numbers(self.measure(drafts, baseline)),
                         numbers(self.measure(drafts[::-1], baseline[::-1])))
