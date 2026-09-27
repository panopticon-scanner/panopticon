"""Cost ledger and report schema contracts."""

import os
import json
import tempfile
import unittest
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.cost as cost_mod
import scripts.synth.report as report_mod
from tests._test_helpers import SKILL_ROOT


class TestCostLedger(unittest.TestCase):
    """meta.cost (4.3.2): the run's dispatch ledger, derived from artifacts —
    the 4.x cost baseline every 5.x economics exit criterion keys on."""

    def _f(self, fid, fname):
        return {
            "id": fid,
            "title": fid,
            "severity": "HIGH",
            "confidence": "POSSIBLE",
            "panel": "code",
            "category": "logic",
            "description": "d",
            "location": {"file": fname, "line_start": 1},
        }

    def test_cost_ledger_rows(self):
        # #run10: this fed build_report a hand-built `cost_fan_out` list of
        # panel_review/lens_sweep rows -- the only way that argument was ever
        # non-empty, since the filter behind it matched no plan the pipeline can
        # write. Retargeted onto driver_cost, so the ledger's LIVE path is the
        # one with end-to-end build_report coverage.
        dc = {"review_cells": 4, "verify_primary": 2, "verify_backup": 1,
              "verify_tools": 3, "tool_scan": 2}
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[self._f("A-1", "a.py"), self._f("A-2", "b.py")],
            ),
            plan=plan_mod.PlanInputs(scout_profiles_seen=3),
            cost=cost_mod.CostInputs(driver_cost=dc),
        ))
        cost = r["meta"]["cost"]
        self.assertIsNone(cost["tokens"])
        self.assertEqual(
            cost["dispatches"],
            [
                {"phase": "scout", "role": "scout", "model": None, "count": 3},
                {"phase": "review", "role": "domain_panel", "model": None, "count": 4},
                {"phase": "verify", "role": "domain_advisor", "model": None, "count": 2},
                {"phase": "verify", "role": "domain_advisor_backup", "model": None,
                 "count": 1},
                {"phase": "verify", "role": "tool_advisor", "model": None, "count": 3},
                {"phase": "tools", "role": "scan", "model": None, "count": 2},
            ],
        )

    def test_cost_ledger_without_plans(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f("A-1", "a.py")]),
        ))
        phases = [d["phase"] for d in r["meta"]["cost"]["dispatches"]]
        self.assertEqual(phases, ["scout", "verify"])
        self.assertEqual(r["meta"]["cost"]["dispatches"][0]["count"], 0)

    def test_tokens_surface_host_reported_usage(self):
        # #run10 D4: the driver is a subprocess and cannot observe per-dispatch
        # token usage -- it lives in the HOST's fan-out journal, so meta.cost.tokens
        # sat permanently null while run-10 burned ~21.05M subagent tokens. A host
        # that knows its usage writes usage.json; it is surfaced verbatim.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "usage.json"), "w", encoding="utf-8") as fh:
                json.dump({"total": 21053000, "by_phase": {"review": 10290000}}, fh)
            usage = cost_mod.load_run_usage(d)
        self.assertEqual(usage["total"], 21053000)
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f("A-1", "a.py")]),
            cost=cost_mod.CostInputs(run_usage=usage),
        ))
        self.assertEqual(r["meta"]["cost"]["tokens"]["total"], 21053000)

    def test_tokens_stay_null_without_host_usage(self):
        # No usage.json -> null, exactly as before. We never estimate tokens from
        # the dispatch counts: a fabricated ledger is worse than an honest gap.
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(cost_mod.load_run_usage(d))                 # absent
            with open(os.path.join(d, "usage.json"), "w", encoding="utf-8") as fh:
                fh.write("{not json")
            self.assertIsNone(cost_mod.load_run_usage(d))                 # malformed
            with open(os.path.join(d, "usage.json"), "w", encoding="utf-8") as fh:
                json.dump({}, fh)
            self.assertIsNone(cost_mod.load_run_usage(d))                 # empty
        self.assertIsNone(cost_mod.load_run_usage(""))
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f("A-1", "a.py")]),
        ))
        self.assertIsNone(r["meta"]["cost"]["tokens"])

    def test_cost_in_report_schema(self):
        import json

        with open(
            os.path.join(SKILL_ROOT, "reference", "report-schema.json"),
            encoding="utf-8",
        ) as fh:
            schema = json.load(fh)
        self.assertIn("cost", schema["properties"]["meta"]["properties"])
