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
import scripts.synth.plan as plan_mod
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
        cells = plan_mod.audit_floor_cells(
            [{"group": "Auth", "floor": ["SEC"], "effective": ["SEC"]}], present={"Auth": set()}
        )  # no cell findings present
        self.assertEqual(cells["missing_floor"], [["Auth", "SEC"]])

    def test_present_floor_cell_ok(self):
        cells = plan_mod.audit_floor_cells(
            [{"group": "Auth", "floor": ["SEC"], "effective": ["SEC"]}], present={"Auth": {"SEC"}}
        )
        self.assertEqual(cells["missing_floor"], [])

    def test_excluded_floor_cell_not_missing(self):
        # #5.0-11: a floor domain a group opted out of (e.g. a universal global-
        # floor domain) does not run, so it is not a missing floor cell.
        cells = plan_mod.audit_floor_cells(
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
            plan_mod.present_cells([os.path.join(".panopticon", "findings-Auth-SEC.json")]),
            {"Auth": {"SEC"}},
        )

    def test_hyphenated_group_name_preserved(self):
        # groups may themselves contain hyphens; the domain is the fixed
        # hyphen-free suffix, so rpartition keeps the rest as the group.
        self.assertEqual(plan_mod.present_cells(["findings-my-group-DAT.json"]), {"my-group": {"DAT"}})

    def test_legacy_panel_suffixed_names_do_not_match(self):
        # lowercase panel tokens (and -panel_review/-lens_sweep-<lens>
        # suffixes) are never a domain code -- no false "present" cell.
        self.assertEqual(
            plan_mod.present_cells(["findings-g1-code-panel_review.json", "findings-g1-security.json"]),
            {},
        )

    def test_multiple_domains_accumulate_per_group(self):
        self.assertEqual(
            plan_mod.present_cells(["findings-Auth-SEC.json", "findings-Auth-DAT.json"]),
            {"Auth": {"SEC", "DAT"}},
        )

    def test_empty_and_none_tolerated(self):
        self.assertEqual(plan_mod.present_cells([]), {})
        self.assertEqual(plan_mod.present_cells(None), {})

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
            tools=plan_mod.ToolAxis(policy_mode="mixed"),
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
        self.assertEqual(plan_mod.tools_ran_from_dispositions(dispositions), {"bandit", "gitleaks"})

    def test_empty_dispositions_yields_empty_set(self):
        self.assertEqual(plan_mod.tools_ran_from_dispositions({}), set())

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
        self.assertEqual(plan_mod.tools_ran_from_dispositions(dispositions),
                         {"bandit", "gitleaks"})
        self.assertEqual(plan_mod.tools_produced_from_dispositions(dispositions),
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
            self.assertEqual(plan_mod.load_groups_json(good)["groups"], [{"name": "g1"}])

    def test_load_verify_queue_three_outcomes(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(plan_mod.load_verify_queue(d), (None, None))
            qp = os.path.join(d, "verify-queue.json")
            with open(qp, "w") as fh:
                json.dump({"run_id": "r1", "entries": []}, fh)
            queue, invalid = plan_mod.load_verify_queue(d)
            self.assertEqual(queue["run_id"], "r1")
            self.assertIsNone(invalid)
            with open(qp, "w") as fh:
                json.dump({"entries": "nope"}, fh)
            self.assertEqual(plan_mod.load_verify_queue(d),
                             (None, "verify queue has no entries list"))
            with open(qp, "w") as fh:
                fh.write("{")
            queue, invalid = plan_mod.load_verify_queue(d)
            self.assertIsNone(queue)
            self.assertTrue(invalid.startswith("cannot read verify queue: "))

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
                    self.assertEqual(plan_mod.ingest_tool_findings(_cli_args()), ([], {}, None))
                self.assertEqual(err.getvalue(), "")
                # a non-empty default tools dir left un-ingested is announced
                os.makedirs(os.path.join(".panopticon", "tools"))
                with open(os.path.join(".panopticon", "tools", "x.json"), "w") as fh:
                    fh.write("{}")
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(plan_mod.ingest_tool_findings(_cli_args()), ([], {}, None))
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
            found, dispositions, ran = plan_mod.ingest_tool_findings(_cli_args(tools_dir=tools_dir))
            self.assertEqual(found, [])
            self.assertEqual(dispositions, {})
            self.assertEqual(ran, set())   # measured: nothing ran (not None)

    def test_tool_axis_load_reads_the_manifest_and_refuses_foreign_ones(self):
        with tempfile.TemporaryDirectory() as d:
            axis = plan_mod.ToolAxis.load(_cli_args(files=["f.json"]), d, [], {}, None)
            self.assertIsNone(axis.manifest)
            self.assertEqual(axis.policy_mode, "unknown")
            self.assertEqual(axis.ingested_paths, ["f.json"])
            tm = os.path.join(d, "tools-manifest.json")
            with open(tm, "w") as fh:
                fh.write("{corrupt")
            self.assertIsNone(plan_mod.ToolAxis.load(_cli_args(), d, [], {}, None).manifest)
            with open(tm, "w") as fh:
                json.dump({"selected": ["semgrep"]}, fh)   # pre-5.1: no schema_version
            with self.assertRaises(SystemExit) as cm:
                plan_mod.ToolAxis.load(_cli_args(), d, [], {}, None)
            self.assertIn("lacks schema_version", str(cm.exception))
            with open(tm, "w") as fh:
                json.dump({"schema_version": "1", "run_id": "other"}, fh)
            with self.assertRaises(SystemExit) as cm:
                plan_mod.ToolAxis.load(_cli_args(run_id="this"), d, [], {}, None)
            self.assertIn("run_id 'other' != this run 'this'", str(cm.exception))
            # same run (or no --run-id) is accepted
            axis = plan_mod.ToolAxis.load(_cli_args(run_id="other"), d, [], {"semgrep": "ok"},
                                          {"semgrep"})
            self.assertEqual(axis.manifest["run_id"], "other")
            self.assertEqual(axis.tools_ran, {"semgrep"})
            self.assertEqual(axis.dispositions, {"semgrep": "ok"})
            self.assertIsNotNone(plan_mod.ToolAxis.load(_cli_args(), d, [], {}, None).manifest)

    def test_tool_axis_load_derives_policy_mode_from_the_plans(self):
        plans = [[{"group": "g1", "domain": "code", "tool_policy": "enforced"}]]
        axis = plan_mod.ToolAxis.load(_cli_args(), ".", plans, {}, None)
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
            self.assertEqual(pi.coverages, plan_mod.load_coverage_files(d))
            self.assertEqual(pi.resume, group_runner_mod.resume_stats([], None, None, _verdicts={}))
            self.assertEqual(pi.out_of_scope, plan_mod.out_of_scope_findings([], []))
