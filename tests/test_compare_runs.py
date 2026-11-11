"""#3560: `devtools/compare_runs.py`, the repeat-run reproducibility comparison.

Every report here is synthetic and built in the test: no scan runs and no real
run data is read.
"""
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

import compare_runs as cr

SHA = "0123456789abcdef0123456789abcdef01234567"
DROP = object()     # a meta value that means: leave the key out


def basis(**over):
    value = {"review_type": "full", "groups": 2, "cells_planned": 12, "cells_answered": 12,
             "max_per_group": 48, "max_groups": None, "layout_fingerprint": "sha256:aa",
             "profile": "default", "version": "5.3.0", "ocrdb_version": "1"}
    value.update(over)
    return value


def report(findings=(), meta=None, score=90.0, letter="A", provisional=None, **basis_over):
    m = {"target": "t", "review_type": "repo", "version": "5.3.0", "ocrdb_version": "1",
         "target_commit": SHA, "target_dirty": False}
    m.update(meta or {})
    for key in [k for k, v in m.items() if v is DROP]:
        del m[key]
    return {"meta": m, "findings": list(findings),
            "summary": {"overall_grade": letter, "provisional_grade": provisional,
                        "coverage_certified": provisional is None,
                        "health": {"score": score, "basis": basis(**basis_over)}}}


def agent(line=None, end=None, file="src/app.py", category="injection", severity="HIGH",
          title="SQL built from input", panel="security", code=None):
    f = {"id": "SEC-001", "title": title, "severity": severity, "confidence": "high",
         "panel": panel, "category": category, "evidence": {}, "source": "agent"}
    if file is not None:
        f["location"] = {"file": file}
        if line is not None:
            f["location"]["line_start"] = line
        if end is not None:
            f["location"]["line_end"] = end
    if code:
        f["code"] = code
    return f


def tool(line, rule="B608", file="src/app.py", severity="MEDIUM"):
    f = agent(line, file=file, category="injection", severity=severity, title="bandit " + rule,
              panel="security")
    f["source"] = "tool:bandit"
    f["tool_evidence"] = {"rule_id": rule}
    return f


class Workspace(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.dir = self._t.name
        self.addCleanup(self._t.cleanup)

    def write(self, name, doc):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return path

    def paths(self, *docs):
        return [self.write("r%d-report.json" % i, d) for i, d in enumerate(docs)]

    def compare(self, *docs, **kw):
        return cr.compare(self.paths(*docs), **kw)

    def refused(self, *docs, **kw):
        with redirect_stderr(io.StringIO()), self.assertRaises(cr.Refused) as ctx:
            self.compare(*docs, **kw)
        return str(ctx.exception)


class TestRefusals(Workspace):
    def test_two_matching_runs_are_accepted(self):
        doc = self.compare(report(), report())
        self.assertEqual(SHA, doc["identity"]["target_commit"])
        self.assertTrue(doc["identity"]["commit_verified"])

    def test_one_report_is_not_a_comparison(self):
        self.assertIn("at least 2", self.refused(report()))

    def test_the_same_file_twice_is_refused(self):
        path = self.write("a-report.json", report())
        with self.assertRaises(cr.Refused):
            cr.compare([path, path])

    def test_each_identity_field_must_match(self):
        for label, other in (("version", report(meta={"version": "5.3.1"})),
                             ("ocrdb_version", report(meta={"ocrdb_version": "2"})),
                             ("review_type", report(review_type="delta")),
                             ("layout_fingerprint", report(layout_fingerprint="sha256:bb")),
                             ("profile", report(profile="custom"))):
            with self.subTest(label=label):
                message = self.refused(report(), other)
                self.assertIn("%s differs" % label, message)
                self.assertIn("run1=", message)

    def test_only_full_reviews_are_compared(self):
        for kind in ("delta", "file-scoped"):
            with self.subTest(kind=kind):
                self.assertIn("only full reviews",
                              self.refused(report(review_type=kind), report(review_type=kind)))

    def test_a_report_without_a_basis_is_refused(self):
        old = report()
        del old["summary"]["health"]["basis"]
        self.assertIn("predates #3528", self.refused(report(), old))

    def test_different_commits_are_refused(self):
        message = self.refused(report(), report(meta={"target_commit": "f" * 40}))
        self.assertIn("target_commit differs", message)

    def test_different_commits_are_refused_even_when_unknown_is_allowed(self):
        self.assertIn("target_commit differs", self.refused(
            report(), report(meta={"target_commit": "f" * 40}), allow_unknown_commit=True))

    def test_a_dirty_run_is_refused_even_when_unknown_is_allowed(self):
        message = self.refused(report(), report(meta={"target_dirty": True}),
                               allow_unknown_commit=True)
        self.assertIn("dirty tree", message)
        self.assertIn("run2", message)

    def test_an_unrecorded_commit_or_dirtiness_needs_the_flag(self):
        for missing in ("target_commit", "target_dirty"):
            with self.subTest(missing=missing):
                other = report(meta={missing: DROP})
                self.assertIn("--allow-unknown-commit", self.refused(report(), other))
                doc = self.compare(report(), other, allow_unknown_commit=True)
                self.assertFalse(doc["identity"]["commit_verified"])
                self.assertTrue(cr.summary_lines(doc)[0].startswith("COMMIT UNVERIFIED"))

    def test_a_verified_run_says_nothing_about_the_commit_first(self):
        doc = self.compare(report(), report())
        self.assertTrue(cr.summary_lines(doc)[0].startswith("compare_runs: 2 runs"))

    def test_a_negative_window_is_refused(self):
        self.assertIn("--line-window", self.refused(report(), report(), window=-1))

    def test_an_unreadable_report_is_refused(self):
        bad = os.path.join(self.dir, "bad-report.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("{")
        with redirect_stderr(io.StringIO()), self.assertRaises(cr.Refused):
            cr.compare([bad, self.write("ok-report.json", report())])

    def test_a_missing_part_is_refused_and_present_parts_are_merged(self):
        main = report([agent(10)], meta={"parts": ["split-report_part1.json"]})
        path = self.write("split-report.json", main)
        other = self.write("other-report.json", report([agent(10), agent(90, title="x")]))
        with redirect_stderr(io.StringIO()), self.assertRaises(cr.Refused):
            cr.compare([path, other])
        self.write("split-report_part1.json", {"findings": [agent(90, title="y")]})
        doc = cr.compare([path, other])
        self.assertEqual(2, doc["agreement"]["all"])


class TestMatchKey(Workspace):
    def clusters(self, *runs, window=cr.DEFAULT_LINE_WINDOW):
        return [[(i, f["location"].get("line_start") if "location" in f else None)
                 for i, f, _ in members] for _, members in cr.cluster(list(runs), window)]

    def test_the_window_boundary_is_inclusive_at_w(self):
        self.assertEqual(1, len(self.clusters([agent(40)], [agent(45)])))
        self.assertEqual(2, len(self.clusters([agent(40)], [agent(46)])))

    def test_the_window_is_measured_from_the_span_end(self):
        self.assertEqual(1, len(self.clusters([agent(40, 50)], [agent(55)])))
        self.assertEqual(2, len(self.clusters([agent(40, 50)], [agent(56)])))

    def test_the_window_is_a_parameter(self):
        self.assertEqual(1, len(self.clusters([agent(40)], [agent(50)], window=10)))
        self.assertEqual(2, len(self.clusters([agent(40)], [agent(41)], window=0)))
        self.assertEqual(1, len(self.clusters([agent(40, 41)], [agent(41)], window=0)))

    def test_single_linkage_chains_a_drifting_citation(self):
        self.assertEqual([[(0, 40), (1, 44), (2, 48)]],
                         self.clusters([agent(40)], [agent(44)], [agent(48)]))

    def test_a_reworded_agent_title_still_matches(self):
        self.assertEqual(1, len(self.clusters([agent(40, title="a")], [agent(41, title="b")])))

    def test_panel_and_code_are_not_in_the_key_but_are_reported(self):
        doc = self.compare(report([agent(40, panel="security", code="SEC-INJ-001")]),
                           report([agent(41, panel="code")]))
        (record,) = doc["clusters"]
        self.assertEqual(["code", "security"], record["panels"])
        self.assertEqual(["SEC-INJ-001"], record["codes"])

    def test_file_and_category_split_agent_buckets(self):
        self.assertEqual(2, len(self.clusters([agent(40)], [agent(40, file="src/b.py")])))
        self.assertEqual(2, len(self.clusters([agent(40)], [agent(40, category="crypto")])))
        self.assertEqual(1, len(self.clusters([agent(40, file="./src/app.py")], [agent(40)])))

    def test_tool_findings_match_on_the_fingerprint_whatever_the_line(self):
        self.assertEqual(1, len(self.clusters([tool(10)], [tool(300)])))
        self.assertEqual(2, len(self.clusters([tool(10)], [tool(10, rule="B105")])))

    def test_a_tool_and_an_agent_finding_never_share_a_cluster(self):
        self.assertEqual(2, len(self.clusters([tool(40)], [agent(40)])))

    def test_lineless_and_locationless_findings(self):
        got = self.clusters([agent(None), agent(40)], [agent(None)],
                            [agent(file=None), agent(file=None, category="crypto")])
        self.assertEqual([[(2, None)], [(2, None)], [(0, None), (1, None)], [(0, 40)]],
                         got)

    def test_a_backwards_span_reads_as_its_start(self):
        self.assertEqual((40, 40), cr._span(agent(40, 30)))
        self.assertIsNone(cr._span(agent(True)))


class TestClusterRecords(Workspace):
    def test_a_run_contributing_two_findings_is_flagged_ambiguous(self):
        doc = self.compare(report([agent(40), agent(43)]), report([agent(41)]))
        (record,) = doc["clusters"]
        self.assertTrue(record["ambiguous"])
        self.assertEqual([2, 1], record["counts"])
        self.assertEqual([True, True], record["present"])
        self.assertEqual(1, doc["agreement"]["ambiguous"])

    def test_one_finding_per_run_is_not_ambiguous(self):
        doc = self.compare(report([agent(40)]), report([agent(41)]))
        self.assertFalse(doc["clusters"][0]["ambiguous"])
        self.assertEqual(0, doc["agreement"]["ambiguous"])

    def test_severity_is_the_run_maximum_and_a_split_is_listed(self):
        doc = self.compare(report([agent(40, severity="LOW"), agent(42, severity="HIGH")]),
                           report([agent(41, severity="MEDIUM")]))
        (record,) = doc["clusters"]
        self.assertEqual(["HIGH", "MEDIUM"], record["severity"])
        self.assertEqual({"run1": ["HIGH", "LOW"]}, record["severity_split"])
        self.assertIn("severity split within a run: run1 HIGH/LOW",
                      "\n".join(cr.summary_lines(doc)))

    def test_the_representative_comes_from_the_earliest_run(self):
        doc = self.compare(report([]), report([agent(40, title="second")]),
                           report([agent(41, title="third")]))
        self.assertEqual("second", doc["clusters"][0]["title"])
        self.assertEqual([40, 41], doc["clusters"][0]["lines"])


class TestCriticalHigh(Workspace):
    def test_same_lower_and_missed_are_counted_against_the_top_severity(self):
        doc = self.compare(report([agent(40, severity="CRITICAL")]),
                           report([agent(41, severity="HIGH")]),
                           report([agent(42, severity="MEDIUM")]),
                           report([]))
        (row,) = doc["critical_high"]
        self.assertEqual(("CRITICAL", 1, 2, 1), (row["top"], row["same"], row["lower"],
                                                row["missed"]))
        text = "\n".join(cr.summary_lines(doc))
        self.assertIn("same 1, lower 2, missed 1 -- SQL built from input", text)

    def test_a_consistent_high_is_counted_and_not_listed(self):
        doc = self.compare(report([agent(40)]), report([agent(40)]))
        (row,) = doc["critical_high"]
        self.assertEqual((2, 0, 0), (row["same"], row["lower"], row["missed"]))
        self.assertIn("1 caught at the same severity by every run",
                      "\n".join(cr.summary_lines(doc)))
        self.assertNotIn("same 2", "\n".join(cr.summary_lines(doc)))

    def test_medium_only_clusters_are_not_escalations(self):
        doc = self.compare(report([agent(40, severity="MEDIUM")]), report([]))
        self.assertEqual([], doc["critical_high"])

    def test_an_unknown_severity_is_neither_same_nor_lower(self):
        doc = self.compare(report([agent(40, severity="HIGH")]),
                           report([agent(40, severity="SEVERE")]))
        (row,) = doc["critical_high"]
        self.assertEqual((1, 0, 0), (row["same"], row["lower"], row["missed"]))


class TestAgreementScoresCells(Workspace):
    def test_all_majority_and_only_one(self):
        doc = self.compare(report([agent(10), agent(100), agent(200)]),
                           report([agent(10), agent(100)]),
                           report([agent(10)]))
        agree = doc["agreement"]
        self.assertEqual((3, 1, 2, 1), (agree["clusters"], agree["all"], agree["majority"],
                                        agree["only_one"]))
        self.assertEqual({"all": 0.3333, "majority": 0.6667, "only_one": 0.3333},
                         agree["shares"])

    def test_no_findings_has_no_shares(self):
        agree = self.compare(report(), report())["agreement"]
        self.assertEqual((0, None), (agree["clusters"], agree["shares"]["all"]))

    def test_score_spread(self):
        doc = self.compare(report(score=91.5), report(score=88.0, letter="B"),
                           report(score=None, letter=None, provisional="B"))
        sc = doc["scores"]
        self.assertEqual((88.0, 91.5, 3.5), (sc["min"], sc["max"], sc["spread"]))
        self.assertEqual({"score": None, "letter": None, "provisional": "B",
                          "certified": False}, sc["runs"][2])

    def test_no_scores_has_no_spread(self):
        sc = self.compare(report(score=None), report(score=None))["scores"]
        self.assertEqual((None, None, None), (sc["min"], sc["max"], sc["spread"]))

    def test_a_run_that_lost_cells_is_marked(self):
        doc = self.compare(report(), report(cells_answered=9), report(cells_answered=None))
        self.assertEqual([False, True, None], [c["lost"] for c in doc["cells"]])
        self.assertIn("cells 9/12 LOST CELLS", "\n".join(cr.summary_lines(doc)))


class TestMain(Workspace):
    def test_a_refusal_exits_2_and_names_why(self):
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            code = cr.main(self.paths(report(), report(meta={"target_dirty": True})))
        self.assertEqual(cr.REFUSED, code)
        self.assertIn("refused: a dirty tree", err.getvalue())

    def test_the_json_records_the_window_and_the_text_is_printed(self):
        out_path = os.path.join(self.dir, "cmp.json")
        out = io.StringIO()
        with redirect_stdout(out):
            code = cr.main(self.paths(report([agent(40)]), report([agent(47)]))
                           + ["--out", out_path, "--line-window", "7"])
        self.assertEqual(0, code)
        with open(out_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(7, doc["line_window"])
        self.assertEqual(1, doc["agreement"]["all"])
        self.assertEqual(["run1: r0-report.json", "run2: r1-report.json"], doc["runs"])
        self.assertIn("(line window 7)", out.getvalue())

    def test_target_text_is_made_inert_on_the_terminal(self):
        doc = self.compare(report([agent(40, title="evil\x1b[2Jtitle")]), report([]))
        text = "\n".join(cr.summary_lines(doc))
        self.assertNotIn("\x1b", text)


if __name__ == "__main__":
    unittest.main()
