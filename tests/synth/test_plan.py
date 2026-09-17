"""Tests for scripts.synth.plan: dispatch plans, coverage cells, out-of-scope, the tool
axis and its loaders.
"""
import contextlib
import io
import os
import json
import tempfile
import unittest

import scripts.synthesize as syn
import scripts.synth.findings as findings_mod
import scripts.synth.coverage_io as coverage_io
import scripts.synth.delta as delta_mod
import scripts.synth.plan as plan_mod
import scripts.synth.tool_axis as tool_axis_mod
import scripts.synth.report as report_mod
import scripts.group_runner as gr
import scripts.group_runner as group_runner_mod
from scripts._version import __version__

from tests.synth.helpers import _chdir, _agentic, _cli_args


class TestFloorCellAudit(unittest.TestCase):
    """matrix Sec5.1: a FLOOR (domain, group) cell with no findings file is
    the INCONCLUSIVE story -- certifiable coverage, not just requested."""

    def test_missing_floor_cell_is_inconclusive(self):
        # a coverage file declares SEC as floor; no findings-<g>-SEC.json exists
        cells = coverage_io.audit_floor_cells(
            [{"group": "Auth", "floor": ["SEC"], "effective": ["SEC"]}], present={"Auth": set()}
        )  # no cell findings present
        self.assertEqual(cells["missing_floor"], [["Auth", "SEC"]])

    def test_present_floor_cell_ok(self):
        cells = coverage_io.audit_floor_cells(
            [{"group": "Auth", "floor": ["SEC"], "effective": ["SEC"]}], present={"Auth": {"SEC"}}
        )
        self.assertEqual(cells["missing_floor"], [])

    def test_excluded_floor_cell_not_missing(self):
        # #5.0-11: a floor domain a group opted out of (e.g. a universal global-
        # floor domain) does not run, so it is not a missing floor cell.
        cells = coverage_io.audit_floor_cells(
            [{"group": "Auth", "floor": ["SEC", "DAT"], "excluded": ["DAT"], "effective": ["SEC"]}],
            present={"Auth": {"SEC"}},
        )  # only SEC ran; DAT excluded
        self.assertEqual(cells["missing_floor"], [])

class TestPresentCells(unittest.TestCase):
    """present_cells: derives {group: set(domains)} from findings-<group>-
    <domain>.json names -- the audit_floor_cells `present` input, as build_
    report derives it from ingested_paths."""

    def test_parses_group_and_domain(self):
        self.assertEqual(
            coverage_io.present_cells([os.path.join(".panopticon", "findings-Auth-SEC.json")]),
            {"Auth": {"SEC"}},
        )

    def test_hyphenated_group_name_preserved(self):
        # groups may themselves contain hyphens; the domain is the fixed
        # hyphen-free suffix, so rpartition keeps the rest as the group.
        self.assertEqual(coverage_io.present_cells(["findings-my-group-DAT.json"]), {"my-group": {"DAT"}})

    def test_legacy_panel_suffixed_names_do_not_match(self):
        # lowercase panel tokens (and -panel_review/-lens_sweep-<lens>
        # suffixes) are never a domain code -- no false "present" cell.
        self.assertEqual(
            coverage_io.present_cells(["findings-g1-code-panel_review.json", "findings-g1-security.json"]),
            {},
        )

    def test_multiple_domains_accumulate_per_group(self):
        self.assertEqual(
            coverage_io.present_cells(["findings-Auth-SEC.json", "findings-Auth-DAT.json"]),
            {"Auth": {"SEC", "DAT"}},
        )

    def test_empty_and_none_tolerated(self):
        self.assertEqual(coverage_io.present_cells([]), {})
        self.assertEqual(coverage_io.present_cells(None), {})

class TestToolPolicyMode(unittest.TestCase):
    def _write_plan(self, d, flags):
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        plan = [{"role": "panel_review", "enforced": f} for f in flags]
        with open(os.path.join(d, ".panopticon", "dispatch-plan.json"), "w") as fh:
            json.dump(plan, fh)

    def test_all_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            self._write_plan(d, [True, True])
            self.assertEqual(
                plan_mod.derive_tool_policy_mode(os.path.join(d, ".panopticon")), "enforced"
            )

    def test_none_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            self._write_plan(d, [False, False])
            self.assertEqual(
                plan_mod.derive_tool_policy_mode(os.path.join(d, ".panopticon")), "advisory"
            )

    def test_mixed(self):
        with tempfile.TemporaryDirectory() as d:
            self._write_plan(d, [True, False])
            self.assertEqual(plan_mod.derive_tool_policy_mode(os.path.join(d, ".panopticon")), "mixed")

    def test_no_plan_files_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(plan_mod.derive_tool_policy_mode(d), "unknown")

    def test_report_meta_carries_mode_and_new_version(self):
        f = _agentic()
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-03T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[f]),
            tools=tool_axis_mod.ToolAxis(policy_mode="mixed"),
        ))
        self.assertEqual(report["meta"]["coverage"]["tool_policy_mode"], "mixed")
        self.assertEqual(report["meta"]["version"], __version__)

class TestToolsRanFromDispositions(unittest.TestCase):
    def test_failed_excluded_ok_and_empty_included(self):
        dispositions = {
            "bandit": {"status": "ok", "findings": 3},
            "gitleaks": {"status": "empty", "findings": 0},
            "semgrep": {"status": "failed", "findings": 0, "reason": "empty output file"},
        }
        self.assertEqual(tool_axis_mod.tools_ran_from_dispositions(dispositions), {"bandit", "gitleaks"})

    def test_empty_dispositions_yields_empty_set(self):
        self.assertEqual(tool_axis_mod.tools_ran_from_dispositions({}), set())

    def test_noscan_gets_no_coverage_credit_but_still_counts_as_produced(self):
        # #1335: the two questions this set used to answer at once. A no-op
        # semgrep provided no coverage (so it must not appear in tools_ran or
        # build_executing_tools) but it DID run and produce a document, so the
        # cost ledger must still count its dispatch.
        dispositions = {
            "bandit": {"status": "ok", "findings": 3},
            "gitleaks": {"status": "empty", "findings": 0},
            "semgrep": {"status": "noscan", "findings": 0, "reason": "scanned 0 files"},
            "trivy": {"status": "failed", "findings": 0, "reason": "empty output file"},
        }
        self.assertEqual(tool_axis_mod.tools_ran_from_dispositions(dispositions),
                         {"bandit", "gitleaks"})
        self.assertEqual(tool_axis_mod.tools_produced_from_dispositions(dispositions),
                         {"bandit", "gitleaks", "semgrep"})

class TestToolPolicyModeUnknown(unittest.TestCase):
    def _plan(self, d, entries):
        import json as _json

        with open(os.path.join(d, "dispatch-plan.json"), "w") as fh:
            _json.dump(entries, fh)

    def test_no_plan_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(plan_mod.derive_tool_policy_mode(d), "unknown")

    def test_plan_with_no_enforced_entries_is_advisory(self):
        with tempfile.TemporaryDirectory() as d:
            self._plan(d, [{"role": "panel_review", "enforced": False}])
            self.assertEqual(plan_mod.derive_tool_policy_mode(d), "advisory")

    def test_all_enforced_is_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            self._plan(d, [{"enforced": True}, {"enforced": True}])
            self.assertEqual(plan_mod.derive_tool_policy_mode(d), "enforced")

    def test_some_enforced_is_mixed(self):
        with tempfile.TemporaryDirectory() as d:
            self._plan(d, [{"enforced": True}, {"enforced": False}])
            self.assertEqual(plan_mod.derive_tool_policy_mode(d), "mixed")

class TestDriverPlanReconcile(unittest.TestCase):
    """Reconcile must run over the plan the pipeline ACTUALLY writes, and must
    fail closed on anything it does not recognise.

    #run10: this was TestMultigroupPlanReconcile, whose premise ("the real
    fan-out writes one dispatch-plan-<group>.json PER GROUP") stopped being
    true when the driver started writing a single dispatch-plan-driver.json,
    and whose fixture hand-built the complete 4.x panel contract -- a shape no
    producer emits. The load-bearing property was never the globbing: it is
    that an UNDECLARED findings file is caught. That is kept, retargeted onto
    the driver cell shape, and joined by the stray-plan case below.
    """

    def _setup(self, d, decoy=False, stray_plan=False):
        pan = os.path.join(d, ".panopticon")
        os.makedirs(pan, exist_ok=True)
        cells = [("g1", "COD"), ("g2", "COD")]
        plan = [{"group": g, "domain": dom, "enforced": True,
                 "out_file": os.path.join(pan, "findings-%s-%s.json" % (g, dom))}
                for g, dom in cells]
        with open(os.path.join(pan, plan_mod.DRIVER_DISPATCH_PLAN), "w",
                  encoding="utf-8") as fh:
            json.dump(plan, fh)
        files = []
        for g, dom in cells:
            name = "findings-%s-%s.json" % (g, dom)
            with open(os.path.join(pan, name), "w", encoding="utf-8") as fh:
                json.dump({"findings": [],
                           "_panopticon": {"run_id": "run-1", "role": "domain_panel",
                                           "group": g, "domain": dom}}, fh)
            files.append(os.path.join(".panopticon", name))
        # #1511: the driver snapshots the declared cells at the review->verify
        # boundary, so every real run reaching synthesize HAS one. A fixture that
        # declares cells but skips the snapshot models a state production never
        # produces -- and now (correctly) reads as a deleted baseline.
        gr.snapshot_out_files(plan, out_path=os.path.join(pan, "out-file-hashes.json"))
        if decoy:
            with open(os.path.join(pan, "findings-EVIL.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"findings": []}, fh)
            files.append(".panopticon/findings-EVIL.json")
        if stray_plan:
            # A dispatch-plan-*.json the pipeline never writes.
            with open(os.path.join(pan, "dispatch-plan-g1.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(plan, fh)
        return files

    def _run(self, d, files):
        with _chdir(d):
            out_path = os.path.join(".panopticon", "report.json")
            rc = syn.main(["--target", "t", "--fail-on", "high",
                           "--out", out_path] + files)
            with open(out_path, encoding="utf-8") as fh:
                return rc, json.load(fh)

    def test_driver_plan_reconciles_clean(self):
        with tempfile.TemporaryDirectory() as d:
            rc, report = self._run(d, self._setup(d))
        self.assertEqual(rc, 0)
        integ = report["meta"]["integrity"]
        self.assertEqual(integ["unexpected_findings_files"], [])
        self.assertEqual(integ["invalid_dispatch_plans"], [])
        # RETIRED-HAZARD ANCHOR (5.0 P6.5 Slice B, plan-glob under-read):
        # plans_seen == 1 proves main() found and read the driver plan rather
        # than skipping reconcile -- see skill/reference/integrity-retirement-p65.md.
        self.assertEqual(integ["plans_seen"], 1)

    def test_undeclared_findings_file_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            rc, report = self._run(d, self._setup(d, decoy=True))
        self.assertEqual(rc, 2)  # INCONCLUSIVE -> exit 2
        integ = report["meta"]["integrity"]
        self.assertEqual(integ["unexpected_findings_files"],
                         [".panopticon/findings-EVIL.json"])
        self.assertNotIn(".panopticon/findings-g1-COD.json",
                         integ["unexpected_findings_files"])

    def test_unrecognized_dispatch_plan_fails_closed(self):
        # The retired 4.x branch also served as the reject for a stray
        # dispatch-plan-*.json dropped into the artifacts dir. Deleting it
        # outright would have made such a file silently ignored, so the
        # rejection is now explicit -- and tested, which it never was.
        with tempfile.TemporaryDirectory() as d:
            rc, report = self._run(d, self._setup(d, stray_plan=True))
        self.assertEqual(rc, 2)
        integ = report["meta"]["integrity"]
        self.assertEqual(integ["plans_seen"], 2)
        reasons = " ".join(x["reason"] for x in integ["invalid_dispatch_plans"])
        self.assertIn("unrecognized dispatch-plan file", reasons)
        self.assertIn("dispatch-plan-g1.json",
                      " ".join(x["file"] for x in integ["invalid_dispatch_plans"]))
        self.assertNotIn(
            ".panopticon/findings-g1-code-panel_review.json", integ["unexpected_findings_files"]
        )
        self.assertNotIn(
            ".panopticon/findings-g2-code-panel_review.json", integ["unexpected_findings_files"]
        )

class TestOutOfScope(unittest.TestCase):
    """#441: report-side disclosure when a reviewer's finding cites a file
    outside its group's assigned list."""

    def test_out_of_scope_counted_with_examples(self):
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "findings-g1-code-panel_review.json")
            with open(fp, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {"id": "A-1", "location": {"file": "a.py"}},
                            {"id": "A-2", "location": {"file": "z.py"}},
                        ]
                    },
                    fh,
                )
            plan = [{"group": "g1", "files": ["a.py"], "out_file": "x"}]
            res = plan_mod.out_of_scope_findings([fp], plan)
        self.assertEqual(res["checked"], 2)
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["examples"], [{"group": "g1", "file": "z.py"}])

    def test_no_plan_returns_none_never_zero_claim(self):
        self.assertIsNone(plan_mod.out_of_scope_findings(["findings-g1-code.json"], []))

    def test_unplanned_group_and_tool_files_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "findings-gX-code-panel_review.json")
            with open(fp, "w") as fh:
                json.dump({"findings": [{"id": "A-1", "location": {"file": "z.py"}}]}, fh)
            plan = [{"group": "g1", "files": ["a.py"], "out_file": "x"}]
            res = plan_mod.out_of_scope_findings([fp], plan)
        self.assertEqual(res["checked"], 0)
        self.assertEqual(res["count"], 0)

class PlanLoadersTest(unittest.TestCase):
    """WS-0 S3: the plan.py readers main() used to inline."""

    def test_load_groups_json_tolerates_every_failure(self):
        self.assertEqual(plan_mod.load_groups_json(None), {})
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(plan_mod.load_groups_json(os.path.join(d, "nope.json")), {})
            bad = os.path.join(d, "bad.json")
            with open(bad, "w") as fh:
                fh.write("{not json")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(plan_mod.load_groups_json(bad), {})
            self.assertIn("could not read", err.getvalue())
            lst = os.path.join(d, "list.json")
            with open(lst, "w") as fh:
                json.dump([1, 2], fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(plan_mod.load_groups_json(lst), {})
            self.assertIn("is not a JSON object", err.getvalue())
            good = os.path.join(d, "groups.json")
            with open(good, "w") as fh:
                json.dump({"groups": [{"name": "g1"}], "mode": "repo"}, fh)
            # The reader REPAIRS as well as parses (#1639 P15 R2-6): the file is
            # target-writable and `grading` subscripts `g["files"]`, so an entry
            # without one comes back with the empty list, not a KeyError later.
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                loaded = plan_mod.load_groups_json(good)
            self.assertEqual(loaded["groups"], [{"name": "g1", "files": []}])
            self.assertIn("groups.json:", err.getvalue())

    def test_load_scout_requests_unions_tools_and_counts_profiles(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(plan_mod.load_scout_requests(d), (set(), 0))
            with open(os.path.join(d, "scout-a.json"), "w") as fh:
                json.dump({"tools": ["semgrep", 3, "gitleaks"]}, fh)
            with open(os.path.join(d, "scout-b.json"), "w") as fh:
                json.dump({"tools": "not-a-list"}, fh)
            with open(os.path.join(d, "scout-c.json"), "w") as fh:
                fh.write("[]")   # not a dict -> not a profile
            with open(os.path.join(d, "scout-d.json"), "w") as fh:
                fh.write("{{{")  # unreadable -> skipped
            requested, seen = plan_mod.load_scout_requests(d)
            self.assertEqual(requested, {"semgrep", "gitleaks"})
            self.assertEqual(seen, 2)

    def test_load_scout_requests_announces_a_silent_decline(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "scout-a.json"), "w") as fh:
                json.dump({"tools": []}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(plan_mod.load_scout_requests(d), (set(), 1))
            self.assertIn("requested NO tools", err.getvalue())

    def test_ingest_tool_findings_without_tools_dir_is_not_measured(self):
        with tempfile.TemporaryDirectory() as d:
            cwd = os.getcwd()
            try:
                os.chdir(d)
                # no .panopticon/tools -> silent
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(plan_mod.ingest_tool_findings(_cli_args()),
                                     ([], {}, None, None, []))
                self.assertEqual(err.getvalue(), "")
                # a non-empty default tools dir left un-ingested is announced
                os.makedirs(os.path.join(".panopticon", "tools"))
                with open(os.path.join(".panopticon", "tools", "x.json"), "w") as fh:
                    fh.write("{}")
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(plan_mod.ingest_tool_findings(_cli_args()),
                                     ([], {}, None, None, []))
                self.assertIn("appears un-ingested", err.getvalue())
                # --tools-dir pointing nowhere is still "not measured"
                self.assertEqual(
                    plan_mod.ingest_tool_findings(_cli_args(tools_dir=os.path.join(d, "no")))[2],
                    None)
            finally:
                os.chdir(cwd)

    def test_ingest_tool_findings_with_an_empty_tools_dir_measures_nothing_ran(self):
        with tempfile.TemporaryDirectory() as d:
            tools_dir = os.path.join(d, "tools")
            os.makedirs(tools_dir)
            found, dispositions, ran, suppressed, gated = plan_mod.ingest_tool_findings(
                _cli_args(tools_dir=tools_dir))
            self.assertEqual(found, [])
            self.assertEqual(dispositions, {})
            self.assertEqual(ran, set())   # measured: nothing ran (not None)
            # #1578: measured and dropped nothing -- `{}`, never None, which is
            # the "no ingest ran" reading.
            self.assertEqual(suppressed, {})
            self.assertEqual(gated, [])    # #1701: nothing dropped, nothing gated

    def test_tool_axis_load_reads_the_manifest_and_refuses_foreign_ones(self):
        with tempfile.TemporaryDirectory() as d:
            axis = tool_axis_mod.ToolAxis.load(_cli_args(files=["f.json"]), d, [], {}, None)
            self.assertIsNone(axis.manifest)
            self.assertEqual(axis.policy_mode, "unknown")
            self.assertEqual(axis.ingested_paths, ["f.json"])
            self.assertIsNone(axis.manifest_invalid)   # no file is not a failure
            tm = os.path.join(d, "tools-manifest.json")
            with open(tm, "w") as fh:
                fh.write("{corrupt")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                corrupt = tool_axis_mod.ToolAxis.load(_cli_args(), d, [], {}, None)
            self.assertIsNone(corrupt.manifest)
            # #1644: and the reason is RECORDED, not swallowed into "no manifest".
            self.assertIn("unreadable", corrupt.manifest_invalid)
            self.assertIn("NOT certified", err.getvalue())
            with open(tm, "w") as fh:
                json.dump(["semgrep"], fh)                 # parses, not an object
            with contextlib.redirect_stderr(io.StringIO()):
                notdict = tool_axis_mod.ToolAxis.load(_cli_args(), d, [], {}, None)
            self.assertIsNone(notdict.manifest)
            self.assertIn("not a JSON object", notdict.manifest_invalid)
            with open(tm, "w") as fh:
                json.dump({"selected": ["semgrep"]}, fh)   # pre-5.1: no schema_version
            with self.assertRaises(SystemExit) as cm:
                tool_axis_mod.ToolAxis.load(_cli_args(), d, [], {}, None)
            self.assertIn("lacks schema_version", str(cm.exception))
            with open(tm, "w") as fh:
                # #1692: `selected` is required of a manifest that is accepted
                # at all, so every shape below that IS accepted carries one.
                json.dump({"schema_version": "1", "run_id": "other",
                           "selected": []}, fh)
            with self.assertRaises(SystemExit) as cm:
                tool_axis_mod.ToolAxis.load(_cli_args(run_id="this"), d, [], {}, None)
            self.assertIn("run_id 'other' != this run 'this'", str(cm.exception))
            # same run (or no --run-id) is accepted
            axis = tool_axis_mod.ToolAxis.load(_cli_args(run_id="other"), d, [], {"semgrep": "ok"},
                                          {"semgrep"})
            self.assertEqual(axis.manifest["run_id"], "other")
            self.assertEqual(axis.tools_ran, {"semgrep"})
            self.assertEqual(axis.dispositions, {"semgrep": "ok"})
            clean = tool_axis_mod.ToolAxis.load(_cli_args(), d, [], {}, None)
            self.assertIsNotNone(clean.manifest)
            self.assertIsNone(clean.manifest_invalid)

    def test_a_manifest_that_is_not_a_regular_file_is_unreadable_not_absent(self):
        """Fix round 2 L1: `os.path.isfile` answers "is a regular file", and
        anything else at that path took the ABSENT branch -- the permissive
        scout-derived fallback, certified -- which is the carve-out fix round 1
        closed for regular files. A directory, a dangling symlink and a symlink
        to /dev/null are all things a hostile or broken target can leave at a
        `.panopticon` path; none of them is "no manifest".
        """
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "tools-manifest.json"))
            with contextlib.redirect_stderr(io.StringIO()) as err:
                axis = tool_axis_mod.ToolAxis.load(_cli_args(), d, [], {}, None)
            self.assertIsNone(axis.manifest)
            self.assertIn("unreadable", axis.manifest_invalid)
            self.assertIn("NOT certified", err.getvalue())
        with tempfile.TemporaryDirectory() as d:
            os.symlink(os.path.join(d, "nowhere.json"),
                       os.path.join(d, "tools-manifest.json"))   # dangling
            with contextlib.redirect_stderr(io.StringIO()):
                axis = tool_axis_mod.ToolAxis.load(_cli_args(), d, [], {}, None)
            self.assertIsNone(axis.manifest)
            self.assertIn("unreadable", axis.manifest_invalid)

    def test_tool_axis_load_derives_policy_mode_from_the_plans(self):
        plans = [[{"group": "g1", "domain": "code", "tool_policy": "enforced"}]]
        axis = tool_axis_mod.ToolAxis.load(_cli_args(), ".", plans, {}, None)
        self.assertEqual(axis.policy_mode, plan_mod.derive_tool_policy_mode(plans=plans))

    def test_plan_inputs_load_composes_the_plan_stage(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "scout-g1.json"), "w") as fh:
                json.dump({"tools": ["semgrep"]}, fh)
            with open(os.path.join(d, "coverage-g1.json"), "w") as fh:
                json.dump({"group": "g1", "cells": []}, fh)
            groups_meta = [{"name": "g1", "files": ["a.py"]}]
            plans = ([], 0, 0)
            queue = (None, None)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                pi = plan_mod.PlanInputs.load(d, [], None, groups_meta, plans, queue, {})
            self.assertEqual(err.getvalue(), "")
            self.assertEqual(pi.groups_meta, groups_meta)
            self.assertIsNone(pi.fan_out)          # no plan -> not measured
            self.assertEqual(pi.scout_requested, ["semgrep"])
            self.assertEqual(pi.scout_profiles_seen, 1)
            self.assertEqual(pi.integrity["plans_seen"], 0)
            self.assertEqual(pi.coverages, coverage_io.load_coverage_files(d))
            self.assertEqual(pi.resume, group_runner_mod.resume_stats([], None, None, _verdicts={}))
            self.assertEqual(pi.out_of_scope, plan_mod.out_of_scope_findings([], []))


class TestManifestMustDeclareSelected(unittest.TestCase):
    """#1692: a `tools-manifest.json` carrying only `{"schema_version": 1}`
    certified a run on which no scanner ran at all.

    The file is target-writable by the code's own account, and this shape needs
    no corruption -- only OMISSION. It passed both #17 FATAL checks, and then
    `reconcile`'s present-manifest branch read `selected` as the empty set: no
    `missing`, so nothing absent; every scout request demoted to the non-gating
    `requested_unavailable`; `tools_absent == []`; gate PASS, certified, rc 0.

    A manifest the runner writes ALWAYS carries `selected`, even when it
    selected nothing, so its absence is the read failing -- the #1644 treatment,
    not a repair. Same for any non-list `selected`: the item-20 round-1 comment
    on #1692 measured `"selected": "semgrep"` publishing six one-letter tool
    names into `divergence.tools`, because `lost_required_coverage` iterates a
    string character by character.

    No second gate lever: `manifest_invalid` rides in `meta.integrity`, which is
    what `integrity_ok` already reads, so the gate goes INCONCLUSIVE with every
    other integrity failure.
    """

    TS = "2026-09-17T00:00:00Z"

    def _run(self, manifest, dispositions=None, tools_ran=None):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "tools-manifest.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(manifest, fh)
            with contextlib.redirect_stderr(io.StringIO()) as err:
                axis = tool_axis_mod.ToolAxis.load(
                    _cli_args(), d, [], dispositions or {}, tools_ran)
                report = report_mod.build_report(report_mod.ReportInputs(
                    run=report_mod.RunConfig(target=d, fail_on="high",
                                             timestamp=self.TS),
                    findings=findings_mod.FindingSet(findings=[]),
                    plan=plan_mod.PlanInputs(scout_requested=["semgrep"]),
                    tools=axis))
            return axis, report, err.getvalue()

    def test_schema_version_only_manifest_is_unreadable_not_empty(self):
        axis, report, err = self._run({"schema_version": 1})
        self.assertIsNone(axis.manifest)
        self.assertIn("selected", axis.manifest_invalid)
        self.assertIn("NOT certified", err)
        self.assertEqual(report["meta"]["integrity"]["tools_manifest_invalid"],
                         axis.manifest_invalid)
        self.assertEqual(report["summary"]["gate"], "INCONCLUSIVE")
        self.assertFalse(report["summary"]["coverage_certified"])
        self.assertIn("selected", report["summary"]["coverage_note"])
        # And it claims nothing about the tool axis it could not read.
        self.assertEqual(report["meta"]["coverage"]["divergence"]["tools"], {})

    def test_a_string_selected_never_becomes_one_letter_tool_names(self):
        axis, report, _err = self._run(
            {"schema_version": 1, "selected": "semgrep", "produced": [],
             "missing": []},
            dispositions={}, tools_ran=set())
        self.assertIsNone(axis.manifest)
        self.assertIn("selected", axis.manifest_invalid)
        self.assertEqual(report["meta"]["coverage"]["divergence"]["tools"], {})
        self.assertFalse(report["summary"]["coverage_certified"])

    def test_an_empty_selected_list_is_a_manifest_not_a_failure(self):
        # The shape this fix must NOT reject: the runner ran and honestly
        # selected nothing. `selected: []` is a measurement; a missing key is
        # the absence of one.
        axis, report, _err = self._run(
            {"schema_version": 1, "selected": [], "produced": [], "missing": []})
        self.assertIsNotNone(axis.manifest)
        self.assertIsNone(axis.manifest_invalid)
        self.assertIsNone(report["meta"]["integrity"]["tools_manifest_invalid"])
        self.assertEqual(report["summary"]["gate"], "PASS")
        self.assertTrue(report["summary"]["coverage_certified"])


class TestRedteamGatesVendoredToolFindings(unittest.TestCase):
    """#1701: the driver's own gate lost what the vendored-path exclusion drops.

    #1578 made the CI gate script count the suppressed findings under
    `--security redteam`, but nothing threaded the run's mode into the report
    pipeline, so `driver run --security redteam` still passed a HIGH under
    `app/vendor/` outright -- disclosed as a count, invisible to `summary.gate`.
    A payload parked behind a conventional directory name is exactly what
    redteam mode exists to refuse.

    The mode is CONTROLLER-carried (item 14): `--security`, which
    `phases/synthesize.py` threads from the run manifest. Never
    `RunConfig.security_mode`, which falls back to the target-written
    groups.json -- a target that could pick the mode could turn the gate off.

    In `standard` nothing changes: the suppression stands (a self-scan drowns
    in bundled jQuery otherwise) and the count is disclosed.
    """

    TS = "2026-09-17T00:00:00Z"
    SARIF = {"runs": [{"tool": {"driver": {"name": "bandit", "rules": []}},
                       "results": [{"ruleId": "B105", "level": "error",
                                    "message": {"text": "hardcoded password"},
                                    "locations": [{"physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "app/vendor/patched_auth.py"},
                                        "region": {"startLine": 1,
                                                   "endLine": 4}}}]}]}]}

    def _sarif(self, rel):
        hit = json.loads(json.dumps(self.SARIF))
        (hit["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
         ["artifactLocation"]["uri"]) = rel
        return hit

    def _run(self, security, rel="app/vendor/patched_auth.py", severity="all",
             delta=False, groups_json=None):
        """One synthesis over a single bandit HIGH at `rel`.

        `rel` is the only thing that moves between the suppressed and the
        un-suppressed arm of the fix-round-1 F1 comparison: `app/vendor/...`
        is dropped by the vendored-path exclusion, `app/lib/...` is not, and
        everything else about the two runs is identical.
        """
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, os.path.dirname(rel)))
            with open(os.path.join(d, rel), "w", encoding="utf-8") as fh:
                fh.write("x = 1\n" * 50)     # real LoC, so health is measurable
            tools = os.path.join(d, "tools")
            os.makedirs(tools)
            with open(os.path.join(tools, "bandit.sarif"), "w",
                      encoding="utf-8") as fh:
                json.dump(self._sarif(rel), fh)
            with open(os.path.join(d, "tools-manifest.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"schema_version": 1, "selected": ["bandit"],
                           "produced": ["bandit"], "missing": []}, fh)
            hunks = None
            if delta:
                # A real diff that touches ANOTHER file: the finding below is
                # pre-existing, which is what `--gate-scope on-diff` scopes out.
                hunks = os.path.join(d, "diff-hunks.json")
                with open(hunks, "w", encoding="utf-8") as fh:
                    json.dump({"base": "main", "hunks": {"app/other.py": [[1, 3]]}}, fh)
            if groups_json is not None:
                with open(os.path.join(d, "groups.json"), "w",
                          encoding="utf-8") as fh:
                    json.dump(groups_json, fh)
            args = _cli_args(tools_dir=tools, security=security, fail_on="high",
                             target=d, run_dir=d, severity=severity,
                             diff_hunks=hunks, gate_scope="on-diff")
            with _chdir(d), contextlib.redirect_stderr(io.StringIO()):
                body, disp, ran, suppressed, gated = plan_mod.ingest_tool_findings(args)
                axis = tool_axis_mod.ToolAxis.load(args, d, [], disp, ran,
                                                   suppressed, gated)
                prepared = findings_mod.FindingSet.prepare(args, body, security)
                run = report_mod.RunConfig.from_args(
                    args, groups_json or {}, self.TS) if groups_json is not None \
                    else report_mod.RunConfig(target=d, fail_on="high",
                                              timestamp=self.TS,
                                              security_mode=security,
                                              gate_scope="on-diff")
                report = report_mod.build_report(report_mod.ReportInputs(
                    run=run,
                    findings=findings_mod.FindingSet(
                        findings=prepared[0], doc_policy=prepared[1],
                        catalog=prepared[2]),
                    delta=delta_mod.DeltaContext.from_args(args),
                    plan=plan_mod.PlanInputs(groups_meta=[
                        {"name": "g", "files": [rel]}]),
                    tools=axis))
            return body, report

    def _gate(self, **kw):
        return self._run("redteam", **kw)[1]["summary"]["gate"]

    def test_redteam_fails_the_gate_on_a_vendored_high(self):
        body, report = self._run("redteam")
        summary = report["summary"]
        self.assertEqual(summary["gate"], "FAIL")
        self.assertEqual(summary["gate_severities"]["contributing"], ["HIGH"])
        # It reaches the GATE, never the body: the disclosure stays a count.
        self.assertEqual(body, [])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["summary"]["stats"]["high"], 0)
        # ... and the health grade moves exactly as an un-suppressed HIGH would.
        self.assertGreater(summary["health"]["weighted_defect"], 0)
        # `tools_suppressed` now counts what was suppressed FROM THE GATE, and
        # under redteam the gate counted them: zero, with the segment still
        # named so the drop from the body stays visible.
        self.assertEqual(report["meta"]["coverage"]["tools_suppressed"],
                         {"vendor": 0})

    def test_standard_is_unchanged_and_discloses_the_count(self):
        body, report = self._run("standard")
        summary = report["summary"]
        self.assertEqual(summary["gate"], "PASS")
        self.assertEqual(body, [])
        self.assertEqual(summary["health"]["weighted_defect"], 0)
        self.assertEqual(report["meta"]["coverage"]["tools_suppressed"],
                         {"vendor": 1})

    # -- fix round 1, F1: the gate-counted set takes the gate's own filters ---
    #
    # Each of these runs the SAME bandit HIGH twice, moving only the directory
    # it sits in, and asserts the two arms answer the gate identically. The
    # un-suppressed arm is the oracle: whatever the real population does with
    # this finding under these flags is what the suppressed one must do.

    LIB = "app/lib/patched_auth.py"

    def test_a_pre_existing_vendored_high_is_scoped_out_like_its_twin(self):
        # `--gate-scope on-diff` over a diff that touches another file: the
        # finding is pre-existing either way. Before this fix the vendored arm
        # FAILed while its twin PASSed -- a finding that gates only because of
        # the directory it is in, which inverts #1578.
        self.assertEqual(self._gate(rel=self.LIB, delta=True), "PASS")
        self.assertEqual(self._gate(delta=True), "PASS")
        # ... and because the gate did NOT count it, the drop is back in the
        # `suppressed` tally rather than in the gated one. The two always sum
        # to the ingest's own count, which is what stderr and security_gate say.
        cov = self._run("redteam", delta=True)[1]["meta"]["coverage"]
        self.assertEqual(cov["tools_suppressed"], {"vendor": 1})

    def test_a_vendored_finding_below_the_severity_floor_does_not_count(self):
        # `--severity critical` removes the HIGH from the run entirely; the
        # vendored twin must not survive the floor behind a directory name.
        self.assertEqual(self._gate(rel=self.LIB, severity="critical"), "PASS")
        self.assertEqual(self._gate(severity="critical"), "PASS")
        cov = self._run("redteam", severity="critical")[1]["meta"]["coverage"]
        self.assertEqual(cov["tools_suppressed"], {"vendor": 1})

    def test_the_evidence_axis_is_the_one_remaining_asymmetry(self):
        """The documented, owner-owed difference (see #1578).

        With no delta and no floor the un-suppressed HIGH does NOT gate -- it is
        an unverified tool claim and `gate_policy` is `confirmed_only` -- while
        the suppressed one does, because it is withheld from `findings[]` and
        therefore from the verify round, so it can never earn `tool_confirmed`.
        Pinned rather than left implicit: if the owner rules that vendored tool
        findings go through tool-verify, THIS is the test that must change.
        """
        self.assertEqual(self._gate(rel=self.LIB), "PASS")
        self.assertEqual(self._gate(), "FAIL")
