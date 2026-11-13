"""#3560: `devtools/compare_runs.py`, the repeat-run reproducibility comparison.

Every report here is synthetic and built in the test: no review scan runs and
no real run data is read. #3602's fixture does drive fresh setup before it
builds the two synthetic report envelopes.
"""
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import compare_runs as cr
import scripts.driver as driver
import scripts.hosts as hosts
import scripts.phases.setup as setup
import scripts.run_manifest as run_manifest

from tests._test_helpers import write_host_evidence
from tests.tools.git_repo import make_git_repo

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

    def test_a_commit_out_of_shape_reads_as_unknown(self):
        for value in (5, ["x"], "", SHA.upper(), SHA[:12], {"a": 1}):
            with self.subTest(value=value):
                other = report(meta={"target_commit": value})
                self.assertIn("--allow-unknown-commit", self.refused(report(), other))
                doc = self.compare(report(), other, allow_unknown_commit=True)
                self.assertFalse(doc["identity"]["commit_verified"])
                self.assertEqual(SHA, doc["identity"]["target_commit"])

    def test_a_dirty_flag_that_is_not_a_boolean_reads_as_unknown(self):
        other = report(meta={"target_dirty": "false"})
        self.assertIn("--allow-unknown-commit", self.refused(report(), other))

    def test_an_unrecorded_identity_is_refused_even_when_shared(self):
        for label, over in (("version", {"meta": {"version": None}}),
                            ("ocrdb_version", {"meta": {"ocrdb_version": DROP}}),
                            ("layout_fingerprint", {"layout_fingerprint": None}),
                            ("profile", {"profile": None})):
            with self.subTest(label=label):
                message = self.refused(report(**over), report(**over))
                self.assertIn("%s is not recorded on every run" % label, message)
                self.assertIn("not recorded", self.refused(report(), report(**over)))

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


class TestSetupOwnedWorktreeChanges(Workspace):
    """#3602: setup's own root writes are not user-authored dirt."""

    def setUp(self):
        super().setUp()
        self.repo = self._new_repo({"src/app.py": "value = 1\n"})
        self._run_setup(self.repo)

    def _new_repo(self, files):
        return make_git_repo(
            test_case=self,
            files=files,
            branch="main",
            user_email="t@t",
            user_name="t",
        )

    def _run_setup(self, repo, reset=False):
        write_host_evidence(
            repo, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN}
        )
        argv = ["setup", repo] + (["--reset"] if reset else [])
        args = driver.build_parser().parse_args(argv)
        with mock.patch(
            "scripts.setup_spine.load_bundled_vocabulary",
            return_value=({"names": []}, False),
        ):
            status = setup.run_setup_flow(args)
        self.assertEqual("complete", status["status"], status)

    def _manifest(self, repo=None):
        repo = repo or self.repo
        return run_manifest.build_manifest(
            target=repo,
            review_root=repo,
            host="claude",
            security_mode="standard",
        )

    def _post_setup_report(self, repo=None):
        repo = repo or self.repo
        manifest = self._manifest(repo)
        return report(
            meta={
                "target": repo,
                "target_commit": manifest["target_commit"],
                "target_dirty": manifest["target_dirty"],
            }
        )

    def test_two_reviews_after_fresh_setup_compare_without_an_override(self):
        compared = self.compare(self._post_setup_report(), self._post_setup_report())
        self.assertTrue(compared["identity"]["commit_verified"])

    def test_an_unrelated_edit_after_setup_is_still_refused(self):
        clean = self._post_setup_report()
        with open(os.path.join(self.repo, "src", "app.py"), "w", encoding="utf-8") as fh:
            fh.write("value = 2\n")
        message = self.refused(clean, self._post_setup_report())
        self.assertIn("dirty tree", message)

    def test_editing_either_setup_output_is_still_dirty(self):
        for relpath in (".gitignore", "panopticon.yml"):
            with self.subTest(relpath=relpath):
                repo = self._new_repo({"src/app.py": "value = 1\n"})
                self._run_setup(repo)
                with open(os.path.join(repo, relpath), "a", encoding="utf-8") as fh:
                    fh.write("# user edit\n")
                self.assertIs(self._manifest(repo)["target_dirty"], True)

    def test_staging_a_setup_output_is_still_dirty(self):
        subprocess.run(
            ["git", "-C", self.repo, "add", "--", "panopticon.yml"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        self.assertIs(self._manifest()["target_dirty"], True)

    def test_changing_a_setup_output_mode_is_still_dirty(self):
        path = os.path.join(self.repo, "panopticon.yml")
        os.chmod(path, 0o755)
        self.assertIs(self._manifest()["target_dirty"], True)

    def test_a_clean_tracked_gitignore_append_is_setup_owned(self):
        repo = self._new_repo(
            {"src/app.py": "value = 1\n", ".gitignore": "build/\n"}
        )
        self._run_setup(repo)
        self.assertIs(self._manifest(repo)["target_dirty"], False)

    def test_a_preexisting_gitignore_edit_is_not_claimed_by_setup(self):
        repo = self._new_repo(
            {"src/app.py": "value = 1\n", ".gitignore": "build/\n"}
        )
        with open(os.path.join(repo, ".gitignore"), "a", encoding="utf-8") as fh:
            fh.write("owner-edit/\n")
        self._run_setup(repo)
        self.assertIs(self._manifest(repo)["target_dirty"], True)

    def test_an_edited_receipt_field_is_not_a_machine_stamp(self):
        config = os.path.join(self.repo, "panopticon.yml")
        with open(config, "a", encoding="utf-8") as fh:
            fh.write("# user edit\n")
        manifest_path = run_manifest.manifest_path(self.repo, "setup")
        with open(manifest_path, encoding="utf-8") as fh:
            setup_manifest = json.load(fh)
        receipt = setup_manifest[run_manifest.SETUP_OWNED_WORKTREE]
        receipt["paths"]["panopticon.yml"] = run_manifest._setup_output_identity(config)
        receipt["run_id"] = run_manifest._receipt_run_id(receipt["paths"])
        # The target can rewrite this unsigned outer-manifest field, but it
        # cannot recompute the nested receipt's machine-keyed stamp.
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(setup_manifest, fh)
        subprocess.run(
            ["git", "-C", self.repo, "add", ".gitignore"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        subprocess.run(
            ["git", "-C", self.repo, "-c", "commit.gpgsign=false", "commit",
             "-qm", "commit setup ignore"],
            check=True,
            capture_output=True,
            timeout=30,
        )
        self.assertIs(self._manifest()["target_dirty"], True)

    def test_setup_reset_preserves_ownership_of_unchanged_outputs(self):
        self._run_setup(self.repo, reset=True)
        self.assertIs(self._manifest()["target_dirty"], False)


class TestMalformedInput(Workspace):
    def refused_main(self, *files):
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            code = cr.main(list(files))
        self.assertEqual(cr.REFUSED, code)
        return err.getvalue()

    def test_each_bad_shape_exits_2_naming_the_file(self):
        ok = self.write("ok-report.json", report())
        bad_part = report(meta={"parts": ["bp-report_part1.json"]})
        self.write("bp-report_part1.json", ["not", "an", "object"])
        cases = {"list-report.json": ([report()], "top level is not an object"),
                 "meta-report.json": (dict(report(), meta="m"), "meta is not an object"),
                 "parts-report.json": (report(meta={"parts": "p_part1.json"}),
                                       "meta.parts is not a list of file names"),
                 "partnames-report.json": (report(meta={"parts": [3]}),
                                           "meta.parts is not a list of file names"),
                 "disc-report.json": (report(meta={"discarded_claims_file": 7}),
                                      "discarded_claims_file is not a file name"),
                 "bp-report.json": (bad_part, "malformed continuation file")}
        for name, (doc, why) in cases.items():
            with self.subTest(name=name):
                path = self.write(name, doc)
                message = self.refused_main(path, ok)
                self.assertIn(name, message)
                self.assertIn(why, message)
                self.assertNotIn("Traceback", message)


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

    def test_a_span_at_the_top_of_a_file_never_joins_a_lineless_finding(self):
        self.assertEqual(2, len(self.clusters([agent(1, 5)], [agent(None)])))

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
        self.assertEqual({}, record["severity_split"])    # two HIGHs are not a split

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

    def test_the_representative_is_the_most_severe_then_the_first_line(self):
        doc = self.compare(report([]), report([agent(41, title="alpha")]),
                           report([agent(40, title="zeta")]))
        self.assertEqual("zeta", doc["clusters"][0]["title"])
        self.assertEqual([40, 41], doc["clusters"][0]["lines"])
        doc = self.compare(report([agent(40, title="low", severity="LOW")]),
                           report([agent(43, title="critical", severity="CRITICAL")]))
        self.assertEqual("critical", doc["clusters"][0]["title"])


class TestOrderIndependence(Workspace):
    RUNS = (
        [agent(40, title="a"), agent(43, title="b", severity="CRITICAL"), tool(10),
         agent(None, title="whole file"), agent(file=None, title="repo wide")],
        [agent(44, title="c", severity="MEDIUM"), tool(300), agent(200, title="far"),
         agent(None, title="whole file again", severity="LOW")],
        [agent(48, title="d"), tool(10, rule="B105"), agent(file=None, title="repo")],
    )

    def doc(self, runs):
        return cr.compare([self.write("run%d-report.json" % i, report(list(f)))
                           for i, f in enumerate(runs)])

    def test_reordering_findings_inside_runs_gives_byte_identical_json(self):
        forward = json.dumps(self.doc(self.RUNS), sort_keys=True)
        backward = json.dumps(self.doc([list(reversed(f)) for f in self.RUNS]), sort_keys=True)
        self.assertEqual(forward, backward)

    def test_reordering_runs_only_permutes_the_per_run_lists(self):
        order = (2, 0, 1)
        forward = self.doc(self.RUNS)
        moved = self.doc([list(reversed(self.RUNS[i])) for i in order])
        per_run = ("present", "counts", "severity")
        for a, b in zip(forward["clusters"], moved["clusters"]):
            for key in per_run:
                b[key] = [b[key][order.index(i)] for i in range(len(order))]
            b["severity_split"] = {"run%d" % (order[int(k[3:]) - 1] + 1): v
                                   for k, v in b["severity_split"].items()}
        self.assertEqual(forward["clusters"], moved["clusters"])
        self.assertEqual(forward["agreement"], moved["agreement"])


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

    def test_half_of_an_even_count_is_not_a_majority(self):
        doc = self.compare(report([agent(10)]), report([agent(10)]), report([]), report([]))
        self.assertEqual((0, 0, 0), tuple(doc["agreement"][k]
                                          for k in ("all", "majority", "only_one")))

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
