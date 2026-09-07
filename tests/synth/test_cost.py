"""Tests for scripts.synth.cost: the driver cost ledger and CostInputs.load.
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
import scripts.synth.cost as cost_mod
import scripts.synth.report as report_mod


class TestCostLedgerDriver(unittest.TestCase):
    """meta.cost on the 5.0 driver path (#1030): the ledger enumerates every
    driver dispatch class from its own on-disk artifact. The legacy role filter
    only saw panel_review/lens_sweep, so the driver's review cells (role-less
    domain cells), the cell-batched verify rounds, and the tool scan were all
    silently absent from the ledger."""

    def test_cost_dispatches_without_a_driver_plan(self):
        # driver_cost=None (synthesize pointed at an artifacts dir with no
        # dispatch-plan-driver.json) -> scout + queued-advisor rows only.
        # #run10: this path also emitted `fan_out` rows counted by filtering
        # plan entries on the retired roles, which matched nothing on any
        # reachable run; the always-empty section is gone.
        self.assertEqual(
            cost_mod.cost_dispatches(3, 5, None),
            [
                {"phase": "scout", "role": "scout", "model": None, "count": 3},
                {"phase": "verify", "role": "advisor", "model": None, "count": 5},
            ],
        )

    def test_cost_dispatches_driver_rows(self):
        dc = {
            "review_cells": 36,
            "verify_primary": 26,
            "verify_backup": 19,
            "verify_tools": 17,
            "tool_scan": 5,
        }
        self.assertEqual(
            cost_mod.cost_dispatches(7, 0, dc),
            [
                {"phase": "scout", "role": "scout", "model": None, "count": 7},
                {"phase": "review", "role": "domain_panel", "model": None, "count": 36},
                {"phase": "verify", "role": "domain_advisor", "model": None, "count": 26},
                {"phase": "verify", "role": "domain_advisor_backup", "model": None, "count": 19},
                {"phase": "verify", "role": "tool_advisor", "model": None, "count": 17},
                {"phase": "tools", "role": "scan", "model": None, "count": 5},
            ],
        )

    def test_cost_dispatches_driver_omits_tools_when_none(self):
        dc = {
            "review_cells": 4,
            "verify_primary": 2,
            "verify_backup": 0,
            "verify_tools": 0,
            "tool_scan": 0,
        }
        phases = [(r["phase"], r["role"]) for r in cost_mod.cost_dispatches(1, 0, dc)]
        self.assertNotIn(("tools", "scan"), phases)
        # the verify rounds are pipeline phases: always disclosed, even at 0
        self.assertIn(("verify", "domain_advisor_backup"), phases)
        self.assertIn(("review", "domain_panel"), phases)

    def test_driver_cost_counts_none_without_plan(self):
        with tempfile.TemporaryDirectory() as d:
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano)
            self.assertIsNone(cost_mod.driver_cost_counts(pano, os.path.join(pano, "verdicts"), None))

    def test_driver_cost_counts_from_artifacts(self):
        with tempfile.TemporaryDirectory() as d:
            pano = os.path.join(d, ".panopticon")
            vdir = os.path.join(pano, "verdicts")
            os.makedirs(vdir)
            # the driver plan declares 3 (group, domain) review cells
            with open(os.path.join(pano, "dispatch-plan-driver.json"), "w", encoding="utf-8") as fh:
                json.dump(
                    [
                        {"group": "Auth", "domain": "SEC", "out_file": "x"},
                        {"group": "Auth", "domain": "COD", "out_file": "y"},
                        {"group": "UI", "domain": "COD", "out_file": "z"},
                    ],
                    fh,
                )
            # #1052: the driver writes cell bundles INTO the verdicts/ subdir
            # (_verify_out_file -> verdicts/verdicts-<g>-<d>[-backup].json), not
            # the .panopticon root. 2 primary cell bundles + 1 backup bundle.
            for name in (
                "verdicts-Auth-SEC.json",
                "verdicts-Auth-COD.json",
                "verdicts-Auth-SEC-backup.json",
            ):
                with open(os.path.join(vdir, name), "w", encoding="utf-8") as fh:
                    fh.write("{}")
            # 4 tool-advisor verdicts in the same subdir, keyed by queue_id (a
            # 16-char sha prefix -- never the "verdicts-" bundle prefix).
            for i in range(4):
                with open(
                    os.path.join(vdir, "abc123def456000%d.json" % i), "w", encoding="utf-8"
                ) as fh:
                    fh.write("{}")
            self.assertEqual(
                cost_mod.driver_cost_counts(pano, vdir, {"semgrep", "bandit"}),
                {
                    "review_cells": 3,
                    "verify_primary": 2,
                    "verify_backup": 1,
                    "verify_tools": 4,
                    "tool_scan": 2,
                },
            )

    def test_driver_cost_counts_does_not_mislabel_cell_bundles_as_tool_advisor(self):
        # #1052 regression: the run-5 symptom was domain_advisor:0,
        # domain_advisor_backup:0, tool_advisor:235 -- every cell bundle counted
        # as a tool-advisor dispatch because both live in verdicts/ and the old
        # code globbed bundles from the root (matched nothing) then swept the
        # whole subdir into tool_advisor. Many cell bundles + a couple of tool
        # verdicts must split correctly.
        with tempfile.TemporaryDirectory() as d:
            pano = os.path.join(d, ".panopticon")
            vdir = os.path.join(pano, "verdicts")
            os.makedirs(vdir)
            plan = [{"group": "G%d" % i, "domain": "SEC", "out_file": "x"} for i in range(5)]
            with open(os.path.join(pano, "dispatch-plan-driver.json"), "w", encoding="utf-8") as fh:
                json.dump(plan, fh)
            for i in range(5):  # 5 primary cell bundles
                with open(
                    os.path.join(vdir, "verdicts-G%d-SEC.json" % i), "w", encoding="utf-8"
                ) as fh:
                    fh.write("{}")
            for i in range(2):  # 2 backup cell bundles
                with open(
                    os.path.join(vdir, "verdicts-G%d-SEC-backup.json" % i), "w", encoding="utf-8"
                ) as fh:
                    fh.write("{}")
            for i in range(3):  # 3 genuine tool-advisor verdicts
                with open(
                    os.path.join(vdir, "ff00aa11bb22cc3%d.json" % i), "w", encoding="utf-8"
                ) as fh:
                    fh.write("{}")
            counts = cost_mod.driver_cost_counts(pano, vdir, set())
            self.assertEqual(counts["verify_primary"], 5)
            self.assertEqual(counts["verify_backup"], 2)
            self.assertEqual(counts["verify_tools"], 3)  # NOT 10

    def test_main_emits_driver_cost_from_artifacts(self):
        # End-to-end main() wiring -- the seam the unit tests above don't
        # exercise: cwd-relative .panopticon + --verdicts-dir threading. A
        # driver-shaped .panopticon must yield the review + verify rows in
        # meta.cost, and drop the legacy lumped advisor row.
        prev = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            pano = os.path.join(d, ".panopticon")
            vdir = os.path.join(pano, "verdicts")
            os.makedirs(vdir)
            fpaths, plan = [], []
            for g, dom in (("Auth", "SEC"), ("Auth", "COD")):
                fp = os.path.join(pano, "findings-%s-%s.json" % (g, dom))
                with open(fp, "w", encoding="utf-8") as fh:
                    json.dump(
                        {
                            "findings": [
                                {
                                    "id": "%s-1" % dom,
                                    "title": "t",
                                    "severity": "HIGH",
                                    "confidence": "POSSIBLE",
                                    "domain": dom,
                                    "category": "x",
                                    "source_role": "domain_panel",
                                    "location": {"file": "a.py", "line_start": 1},
                                }
                            ]
                        },
                        fh,
                    )
                fpaths.append(fp)
                plan.append(
                    {"group": g, "domain": dom, "enforced": True, "out_file": os.path.abspath(fp)}
                )
            with open(os.path.join(pano, "dispatch-plan-driver.json"), "w", encoding="utf-8") as fh:
                json.dump(plan, fh)
            # #1052: 2 primary cell bundles + 1 backup + 1 tool-advisor, ALL in
            # the verdicts/ subdir (where the driver actually writes them).
            for name in (
                "verdicts-Auth-SEC.json",
                "verdicts-Auth-COD.json",
                "verdicts-Auth-SEC-backup.json",
            ):
                with open(os.path.join(vdir, name), "w", encoding="utf-8") as fh:
                    json.dump({"verdicts": [], "_panopticon": {"run_id": "r"}}, fh)
            with open(os.path.join(vdir, "ab12cd34ef560000.json"), "w", encoding="utf-8") as fh:
                json.dump({"verdicts": []}, fh)
            out = os.path.join(pano, "report.json")
            try:
                os.chdir(d)
                with (
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    syn.main(
                        ["--target", "t", "--out", out, "--verdicts-dir", ".panopticon/verdicts"]
                        + fpaths
                    )
            finally:
                os.chdir(prev)
            with open(out, encoding="utf-8") as fh:
                cost = json.load(fh)["meta"]["cost"]["dispatches"]
            by = {(r["phase"], r["role"]): r["count"] for r in cost}
            self.assertEqual(by[("review", "domain_panel")], 2)
            self.assertEqual(by[("verify", "domain_advisor")], 2)
            self.assertEqual(by[("verify", "domain_advisor_backup")], 1)
            self.assertEqual(by[("verify", "tool_advisor")], 1)
            self.assertNotIn(("tools", "scan"), by)  # no tool scan ran
            self.assertNotIn(("verify", "advisor"), by)  # legacy lumped row gone

    def test_driver_rows_validate_against_schema(self):
        # the new review/tools phases must pass report-schema (the #1015 class)
        dc = {
            "review_cells": 2,
            "verify_primary": 1,
            "verify_backup": 0,
            "verify_tools": 0,
            "tool_scan": 3,
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-17T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(scout_profiles_seen=2),
            cost=cost_mod.CostInputs(driver_cost=dc),
        ))
        errors, _ = report_mod.validate_report(r)
        self.assertEqual(errors, [], "driver cost rows must pass report-schema")
        phases = {row["phase"] for row in r["meta"]["cost"]["dispatches"]}
        self.assertTrue({"review", "tools"} <= phases)

class CostLoaderTest(unittest.TestCase):
    def test_cost_inputs_load_resolves_under_run_dir(self):
        with tempfile.TemporaryDirectory() as d:
            ci = cost_mod.CostInputs.load(d, None, None)
            self.assertIsNone(ci.driver_cost)     # no dispatch-plan-driver.json -> legacy
            self.assertIsNone(ci.run_usage)
            with open(os.path.join(d, "dispatch-plan-driver.json"), "w") as fh:
                json.dump({"plan": []}, fh)
            ci = cost_mod.CostInputs.load(d, None, None)
            self.assertEqual(ci.driver_cost, cost_mod.driver_cost_counts(d, None, None))
            self.assertIsNotNone(ci.driver_cost)
