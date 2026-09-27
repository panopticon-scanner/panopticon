"""Integrity certification and summary contracts."""

import os
import tempfile
import unittest
import scripts.synthesize as syn
import scripts.synth.findings as findings_mod
import scripts.synth.grading as grading_mod
import scripts.synth.plan as plan_mod
import scripts.synth.integrity as integrity_mod
import scripts.synth.report as report_mod
import scripts.synth.render as render_mod
from tests.synth.helpers import _chdir


class TestIntegrity(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_certify_integrity_not_ok_is_inconclusive(self):
        r = grading_mod.certify("A", [], "high", set(), [], integrity_ok=False)
        self.assertEqual(r["gate"], "INCONCLUSIVE")
        self.assertFalse(r["coverage_certified"])

    def test_certify_integrity_ok_default_unchanged(self):
        r = grading_mod.certify("A", [], "high", set(), [])
        self.assertEqual(r["gate"], "PASS")
        self.assertTrue(r["coverage_certified"])

    def test_certify_integrity_not_ok_fail_still_wins(self):
        # Precedence truth-table (spec requirement): a confirmed CRITICAL
        # finding must still FAIL the gate when integrity is also broken --
        # integrity_ok=False must never downgrade a FAIL to INCONCLUSIVE.
        crit = [{"severity": "CRITICAL", "evidence": {"status": "advisor_confirmed"}}]
        r = grading_mod.certify("F", crit, "high", set(), [], integrity_ok=False)
        self.assertEqual(r["gate"], "FAIL")
        self.assertFalse(r["coverage_certified"])

    def test_certify_integrity_not_ok_off_preserved(self):
        # No --fail-on -> gate is OFF regardless of coverage; integrity_ok
        # must not force it to INCONCLUSIVE.
        r = grading_mod.certify("A", [], None, set(), [], integrity_ok=False)
        self.assertEqual(r["gate"], "OFF")
        self.assertFalse(r["coverage_certified"])

    def test_reconcile_flags_unexpected_and_missing(self):
        plan = [
            {"role": "panel_review", "out_file": ".panopticon/findings-g1-code-panel_review.json"},
            {
                "role": "lens_sweep",
                "out_file": ".panopticon/findings-g1-code-lens_sweep-style.json",
            },
        ]
        ingested = [
            ".panopticon/findings-g1-code-panel_review.json",
            ".panopticon/findings-EVIL-decoy.json",
        ]
        unexpected, missing = integrity_mod.reconcile_findings_files(plan, ingested)
        self.assertEqual(unexpected, [".panopticon/findings-EVIL-decoy.json"])
        self.assertEqual(missing, [".panopticon/findings-g1-code-lens_sweep-style.json"])

    def test_reconcile_skipped_without_plan(self):
        self.assertEqual(integrity_mod.reconcile_findings_files([], ["whatever.json"]), ([], []))
        self.assertEqual(integrity_mod.reconcile_findings_files(None, ["x.json"]), ([], []))

    def test_build_report_emits_integrity_and_inconclusive_on_unexpected(self):
        integ = {
            "unexpected_findings_files": [".panopticon/findings-EVIL.json"],
            "missing_planned_files": [],
            "unenforced_acknowledged": False,
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=integ),
        ))
        # #1644: reconcile adds the manifest-read reason to whatever integrity
        # section it was handed, so the published section is the caller's plus
        # that one key.
        self.assertEqual(r["meta"]["integrity"],
                         dict(integ, tools_manifest_invalid=None,
                              delta_scope_suppressed_git_drivers=None))
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")

    def test_a_missing_owed_snapshot_cannot_certify(self):
        # #1511/#1208: "not measured" must be impossible on a driver run. The
        # snapshot the run owed is gone, so integrity is unproven -- that has to
        # read like the substitution it could be hiding, not like a clean run.
        integ = {
            "unexpected_findings_files": [],
            "missing_planned_files": [],
            "content_mismatched_files": [],
            "content_snapshot_unreadable": False,
            "content_snapshot_missing": True,
            "unenforced_acknowledged": False,
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=integ),
        ))
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        self.assertIs(r["summary"]["coverage_certified"], False)

    # Fix round 1 F8: the PUBLISHED key order, which is the report contract a
    # consumer diffing two runs reads. `integrity_section`'s own order is pinned
    # in tests/synth/test_integrity.py; this is that order as it reaches the
    # artifact, plus the key reconcile appends.
    PUBLISHED_KEYS = [
        "unexpected_findings_files", "missing_planned_files",
        "malformed_findings_files", "duplicate_out_files",
        "mislabeled_findings_files", "cross_domain_findings",
        "unenforced_acknowledged", "ack_stale", "content_hashes_checked",
        "content_mismatched_files", "content_snapshot_unreadable",
        "content_snapshot_missing", "empty_dispatch_plans",
        "invalid_dispatch_plans", "invalid_verify_queue", "plans_seen",
        # SEC-377944137 (#1832): published beside `plans_seen`, the key it
        # guards, and stated on every report for the same reason as the two
        # reconcile appends below.
        "dispatch_plan_missing", "dispatch_plan_mismatched",
        "tools_manifest_invalid",
        # #2013 fix round 1: appended by reconcile beside the key above, and
        # stated on every report for the same reason.
        "delta_scope_suppressed_git_drivers",
    ]

    def test_the_published_integrity_key_order_is_the_contract(self):
        with tempfile.TemporaryDirectory() as d:
            section = integrity_mod.integrity_section([], [], d, 0, 0, None)
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=section),
        ))
        self.assertEqual(list(r["meta"]["integrity"]), self.PUBLISHED_KEYS)

    def test_build_report_integrity_defaults_empty(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G),
        ))
        self.assertEqual(
            r["meta"]["integrity"],
            {
                "unexpected_findings_files": [],
                "missing_planned_files": [],
                "duplicate_out_files": [],
                "mislabeled_findings_files": [],
                "cross_domain_findings": [],
                "empty_dispatch_plans": 0,
                "invalid_dispatch_plans": [],
                "invalid_verify_queue": None,
                "unenforced_acknowledged": False,
                "plans_seen": 0,
                # #1644: stated on every report -- None means the manifest read
                # was clean (or there was none), never "not measured".
                "tools_manifest_invalid": None,
                # #2013 fix round 1: None means this run was not delta-scoped,
                # or nothing was suppressed -- never "not measured".
                "delta_scope_suppressed_git_drivers": None,
            },
        )
        self.assertEqual(r["summary"]["gate"], "PASS")

    def test_build_report_integrity_non_dict_does_not_raise(self):
        # M10: a truthy non-dict integrity (e.g. a stray list) must fall back
        # to the default rather than raise on the .get() calls below it.
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=["not", "a", "dict"]),
        ))
        self.assertEqual(
            r["meta"]["integrity"],
            {
                "unexpected_findings_files": [],
                "missing_planned_files": [],
                "duplicate_out_files": [],
                "mislabeled_findings_files": [],
                "cross_domain_findings": [],
                "empty_dispatch_plans": 0,
                "invalid_dispatch_plans": [],
                "invalid_verify_queue": None,
                "unenforced_acknowledged": False,
                "plans_seen": 0,
                # #1644: stated on every report -- None means the manifest read
                # was clean (or there was none), never "not measured".
                "tools_manifest_invalid": None,
                # #2013 fix round 1: None means this run was not delta-scoped,
                # or nothing was suppressed -- never "not measured".
                "delta_scope_suppressed_git_drivers": None,
            },
        )
        self.assertEqual(r["summary"]["gate"], "PASS")

    def test_present_semantically_invalid_plan_is_inconclusive(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(
                groups_meta=self.G,
                integrity={
                    "plans_seen": 1,
                    "invalid_dispatch_plans": [
                        {"file": "p.json", "reason": "entry 0 is not an object"}
                    ],
                },
            ),
        ))
        self.assertEqual(r["summary"]["gate"], "INCONCLUSIVE")
        self.assertFalse(r["summary"]["coverage_certified"])

    def test_main_rejects_symlinked_artifact_root(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(d, ".panopticon"))
            with _chdir(d):
                self.assertEqual(syn.main(["--fail-on", "high"]), 2)

    def test_missing_alone_does_not_force_inconclusive(self):
        integ = {
            "unexpected_findings_files": [],
            "missing_planned_files": [".panopticon/findings-g1-x.json"],
            "unenforced_acknowledged": False,
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=integ),
        ))
        self.assertEqual(r["summary"]["gate"], "PASS")


class TestRenderSummaryIntegrity(unittest.TestCase):
    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_integrity_line_on_unexpected(self):
        integ = {
            "unexpected_findings_files": [".panopticon/findings-EVIL.json"],
            "missing_planned_files": [],
            "unenforced_acknowledged": False,
        }
        text = render_mod.render_summary(
            report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=integ),
            ))
        )
        self.assertIn("Integrity:", text)
        self.assertIn("findings-EVIL.json", text)

    def test_no_integrity_line_when_clean(self):
        self.assertNotIn(
            "Integrity:", render_mod.render_summary(report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=self.G),
            )))
        )
