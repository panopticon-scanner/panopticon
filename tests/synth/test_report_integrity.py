"""Integrity certification and summary contracts."""

import ast
import contextlib
import io
import json
import os
import tempfile
import unittest
import scripts.synthesize as syn
import scripts.synth.delta as delta_mod
import scripts.synth.findings as findings_mod
import scripts.synth.grading as grading_mod
import scripts.synth.plan as plan_mod
import scripts.synth.integrity as integrity_mod
import scripts.synth.report as report_mod
import scripts.tools.base as tool_base
import scripts.synth.render as render_mod
import scripts.synth.tool_axis as tool_axis_mod
import scripts.synth.validate_schema as validate_schema_mod
import scripts.synth.verdicts as verdicts_mod
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
            {"role": "panel_review", "out_file": ".panopticon/findings-g1-COD.json"},
            {
                "role": "lens_sweep",
                "out_file": ".panopticon/findings-g1-ARC.json",
            },
        ]
        ingested = [
            ".panopticon/findings-g1-COD.json",
            ".panopticon/findings-EVIL-decoy.json",
        ]
        unexpected, missing = integrity_mod.reconcile_findings_files(plan, ingested)
        self.assertEqual(unexpected, [".panopticon/findings-EVIL-decoy.json"])
        self.assertEqual(missing, [".panopticon/findings-g1-ARC.json"])

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
                              unbound_tool_outputs=[],
                              delta_scope_suppressed_git_drivers=None,
                              unknown_severity_findings=[], sec_less_groups=[]))
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
        "malformed_findings_files", "coverage_files_skipped", "unreadable_name_files",
        "duplicate_out_files",
        "mislabeled_findings_files", "cross_domain_findings",
        "unenforced_acknowledged", "ack_stale", "content_hashes_checked",
        "content_mismatched_files", "content_snapshot_unreadable",
        "content_snapshot_missing", "content_snapshot_mismatched",
        "empty_dispatch_plans",
        "invalid_dispatch_plans", "invalid_verify_queue", "plans_seen",
        # SEC-377944137 (#1832): published beside `plans_seen`, the key it
        # guards, and stated on every report for the same reason as the two
        # reconcile appends below.
        "dispatch_plan_missing", "dispatch_plan_mismatched",
        # #2271: threaded in from the run's `groups.json` discovery block, and
        # published last by `integrity_section` -- so they land here, ahead of
        # the two keys `reconcile` appends after it.
        "discovery_git_failure", "discovery_files_truncated",
        "tools_manifest_invalid",
        "unbound_tool_outputs",
        # #2013 fix round 1: appended by reconcile beside the key above, and
        # stated on every report for the same reason.
        "delta_scope_suppressed_git_drivers",
        # #2990: appended by reconcile from the resolved findings.
        "unknown_severity_findings",
        # #3245: appended by reconcile from the coverage records.
        "sec_less_groups",
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
                "unbound_tool_outputs": [],
                # #2013 fix round 1: None means this run was not delta-scoped,
                # or nothing was suppressed -- never "not measured".
                "delta_scope_suppressed_git_drivers": None,
                # #2990: no finding carried an unknown severity.
                "unknown_severity_findings": [],
                # #3245: no coverage records, so no group is named.
                "sec_less_groups": [],
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
                "unbound_tool_outputs": [],
                # #2013 fix round 1: None means this run was not delta-scoped,
                # or nothing was suppressed -- never "not measured".
                "delta_scope_suppressed_git_drivers": None,
                # #2990: no finding carried an unknown severity.
                "unknown_severity_findings": [],
                # #3245: no coverage records, so no group is named.
                "sec_less_groups": [],
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


class TestTheSinkingSetIsOneTable(unittest.TestCase):
    """B19 (#1761, ARC-3284703909): which `meta.integrity` keys sink
    `integrity_ok`, and whether the report ever says which one did.

    The rule used to live in three places with three memberships: this
    module's `integrity_section` published ~20 keys, `tool_axis.reconcile`
    re-spelled 14 of them in a hand-written `or` chain, and
    `render.render_summary` named four -- one of which does not gate. So ten of
    the fourteen sinking keys had no line of their own, nine of them no name on
    the summary at all: it said "incomplete" and the reasons went to stderr.

    `SINKING` began as that chain before it was folded into
    `integrity.INTEGRITY_KEYS`; later integrity reasons such as #2115 are added
    here with their contract. That baseline is what makes
    `test_the_chain_sinks_exactly_these_keys` an equivalence baseline: it
    passed against the hand-written chain and must still pass against the
    comprehension over the table.
    """

    # The 14 terms of the pre-change chain, plus later integrity reasons.
    SINKING = frozenset({
        "unexpected_findings_files", "duplicate_out_files",
        "mislabeled_findings_files", "content_mismatched_files",
        "content_snapshot_unreadable", "content_snapshot_missing",
        "content_snapshot_mismatched",
        "malformed_findings_files", "coverage_files_skipped", "unreadable_name_files", "empty_dispatch_plans",
        "dispatch_plan_missing", "dispatch_plan_mismatched",
        "invalid_dispatch_plans", "invalid_verify_queue",
        "tools_manifest_invalid", "unbound_tool_outputs",
        "delta_scope_suppressed_git_drivers"})
    # Published beside them and read by no gate: a counter, a disclosure, or
    # (cross_domain_findings) a deliberate report-only signal.
    REPORTED = frozenset({
        "missing_planned_files", "cross_domain_findings", "ack_stale",
        "unenforced_acknowledged", "content_hashes_checked", "plans_seen",
        "write_guard_covers_bash",
        # #2271: discovery ran and degraded -- the surface is a SUPERSET (the
        # target's git listing failed, so a raw walk ignored its `.gitignore`)
        # or a PREFIX (the cap cut it) of the intended one. The artifacts on
        # disk are still what they claim, which is what this section gates on,
        # and the truncation disclosure did not gate before this change either.
        "discovery_git_failure", "discovery_files_truncated",
        # #2990: the CRITICAL reading already gates; this explains it.
        "unknown_severity_findings",
        # #3245: SEC was never these groups' floor; the gap is disclosed.
        "sec_less_groups"})
    # The REPORTED keys that DO print a line: a non-gating `**Note:**`, never
    # an `**Integrity:**`. Pinned against the table below so a key that gains
    # or loses a sentence cannot quietly change which test covers it.
    NOTED = frozenset({"cross_domain_findings", "discovery_git_failure",
                       "discovery_files_truncated", "unknown_severity_findings",
                       "sec_less_groups"})
    # `reconcile` appends these two to whatever section it was handed, so
    # `integrity_section` never publishes them and the table's membership test
    # below has to name them explicitly.
    RECONCILE_ADDS = frozenset({"tools_manifest_invalid", "unbound_tool_outputs",
                                "delta_scope_suppressed_git_drivers",
                                "unknown_severity_findings", "sec_less_groups"})
    # One truthy value per key, in the shape the key really carries.
    TRUTHY: dict = {
        "unexpected_findings_files": ["u.json"],
        "coverage_files_skipped": ["coverage-Bad.json"],
        "unreadable_name_files": ["caf\\x09x.py"],
        "missing_planned_files": ["m.json"],
        "malformed_findings_files": [{"file": "b.json", "cell": None,
                                      "defects": [{"index": 0,
                                                   "reason": "not an object"}]}],
        "duplicate_out_files": ["d.json"],
        "mislabeled_findings_files": ["l.json"],
        "cross_domain_findings": [{"file": "x.json", "cell_domain": "ARC",
                                   "finding_domain": "TST", "code": "TST-X0X"}],
        "unenforced_acknowledged": True,
        "ack_stale": True,
        "content_hashes_checked": 2,
        "content_mismatched_files": ["c.json"],
        "content_snapshot_unreadable": True,
        "content_snapshot_missing": True,
        "content_snapshot_mismatched": True,
        "empty_dispatch_plans": 1,
        # The loader's THIRD reason, the one a filename alone cannot be told
        # apart from a plan that does not parse (review finding 8), and -- only
        # a foreign report can carry it -- a row with no reason at all.
        "invalid_dispatch_plans": [
            {"file": "dispatch-plan-decoy.json",
             "reason": "unrecognized dispatch-plan file (expected %s)"
                       % plan_mod.DRIVER_DISPATCH_PLAN},
            {"file": "dispatch-plan-orphan.json"}],
        "invalid_verify_queue": "verify queue has no entries list",
        "plans_seen": 1,
        "dispatch_plan_missing": True,
        "dispatch_plan_mismatched": True,
        "write_guard_covers_bash": True,
        "tools_manifest_invalid": "tools-manifest.json is not an object",
        "unbound_tool_outputs": ["semgrep.sarif"],
        "delta_scope_suppressed_git_drivers": ["diff.external"],
        # #2271: git's own stderr, which is target-influenced free text.
        "discovery_git_failure": "exit 128: fatal: <ROOT>/.git: not a directory",
        "discovery_files_truncated": 7,
        # #2990: the id of the one finding `_inputs` gives an unknown severity.
        "unknown_severity_findings": ["COD-123"],
        # #3245: the one group `_inputs` plans without SEC (`G`'s g1 has code).
        "sec_less_groups": ["g1"],
    }
    SUPPRESSED_DRIVERS = [{"repo": ".", "key": "diff.external"}]

    def _clean_section(self):
        """`integrity_section`'s own answer for a run with nothing wrong."""
        with tempfile.TemporaryDirectory() as d:
            return integrity_mod.integrity_section([], [], d, 0, 0, None)

    def _inputs(self, key=None, *also):
        """build_report inputs with `key` alone made truthy.

        `tools_manifest_invalid` and `delta_scope_suppressed_git_drivers` are
        driven through their OWN inputs: `reconcile` computes both over
        whatever section it was handed, so a value planted in the section
        would be overwritten and the probe would prove nothing. `also` names
        further keys to make truthy, for the ordering test below; only
        section-settable keys belong there, for that same reason.
        """
        section = self._clean_section()
        for name in (key, *also):
            if name:
                section[name] = self.TRUTHY[name]
        delta_key = key == "delta_scope_suppressed_git_drivers"
        # #2990: reconcile reads this key off the findings, so it is driven by
        # one finding whose severity normalize_finding does not know.
        unknown = ([findings_mod.normalize_finding(
            {"id": "COD-123", "title": "t", "severity": "SEVERE",
             "location": {"file": "a.py", "line_start": 1}})]
                   if "unknown_severity_findings" in (key, *also) else [])
        return report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=unknown),
            delta=delta_mod.DeltaContext(
                diff_hunks={"base": "main", "hunks": {}} if delta_key else None),
            plan=plan_mod.PlanInputs(
                groups_meta=self.G, integrity=section,
                # #3245: reconcile reads this key off the coverage records.
                coverages=([{"group": "g1", "effective": ["COD"]}]
                           if "sec_less_groups" in (key, *also) else None),
                git_drivers_suppressed=self.SUPPRESSED_DRIVERS if delta_key else None),
            tools=tool_axis_mod.ToolAxis(
                manifest_invalid=(self.TRUTHY[key]
                                  if key == "tools_manifest_invalid" else None),
                unbound_outputs=(self.TRUTHY[key]
                                 if key == "unbound_tool_outputs" else None)))

    def _integrity_ok(self, key=None):
        """reconcile's OWN `integrity_ok`, never re-spelled here: a test that
        re-states the expression cannot fail when the expression is the bug."""
        inp = self._inputs(key)
        resolved = verdicts_mod.resolve_findings(
            inp.findings, inp.delta, inp.run,
            gated_suppressed=inp.tools.gated_suppressed)
        return tool_axis_mod.reconcile(inp.plan, inp.tools, resolved,
                                       run=inp.run).integrity_ok

    G = [{"name": "g1", "files": ["a.py"]}]
    TS = "2026-01-01T00:00:00Z"

    def test_the_chain_sinks_exactly_these_keys(self):
        self.assertTrue(self._integrity_ok(), "a clean section must certify")
        for key in sorted(self.TRUTHY):
            with self.subTest(key=key):
                self.assertEqual(self._integrity_ok(key), key not in self.SINKING)

    def test_the_table_marks_exactly_the_keys_the_chain_sank(self):
        self.assertEqual(
            {k for k, spec in integrity_mod.INTEGRITY_KEYS.items() if spec.sinks},
            set(self.SINKING))

    def test_the_table_holds_every_published_key_and_nothing_else(self):
        # The published set is built by RUNNING `integrity_section` -- twice,
        # because the `write_guard_covers_bash` disclosure exists only when an
        # ack does -- rather than by reading its dict literal: a table that
        # matched the source text but not the section a run really publishes
        # would pass. A duplicate entry in the table is ruff's F601.
        with tempfile.TemporaryDirectory() as d:
            published = set(integrity_mod.integrity_section([], [], d, 0, 0, None))
            with open(os.path.join(d, "unenforced-ack.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"acknowledged": True, "write_guard_covers_bash": True}, fh)
            published |= set(integrity_mod.integrity_section([], [], d, 0, 0, None))
        self.assertEqual(published & self.RECONCILE_ADDS, set(),
                         "reconcile's own keys are published by integrity_section "
                         "now, so the exception list below is stale")
        self.assertEqual(set(integrity_mod.INTEGRITY_KEYS),
                         published | self.RECONCILE_ADDS)
        self.assertEqual(set(self.TRUTHY), published | self.RECONCILE_ADDS)
        self.assertEqual(self.SINKING | self.REPORTED, set(self.TRUTHY))

    def test_the_table_is_the_schema_s_integrity_property_list(self):
        # The FOURTH spelling of this key set: `report-schema.json` enumerates
        # `meta.integrity`'s properties and nothing tied it to the other three,
        # so the next key added to the table could still ship with a schema that
        # does not describe it -- the drift class this PR exists to close, one
        # file over. Resolved through the same two constants `validate_schema`
        # itself uses, so a moved reference directory cannot make this vacuous.
        #
        # This pin ties the TABLE to the SCHEMA and nothing else: neither of
        # them sees what a run actually publishes, and `meta.integrity` has no
        # `additionalProperties: false`, so a published-but-untabled key stays
        # invisible to it. That side is
        # `test_every_key_integrity_section_publishes_is_in_the_table` below.
        with open(os.path.join(validate_schema_mod.REFERENCE_DIR,
                               validate_schema_mod.REPORT_SCHEMA),
                  encoding="utf-8") as fh:
            schema = json.load(fh)
        declared = (schema["properties"]["meta"]["properties"]["integrity"]
                    ["properties"])
        self.assertEqual(set(declared), set(integrity_mod.INTEGRITY_KEYS))

    def _summary(self, key=None, *also):
        return render_mod.render_summary(
            report_mod.build_report(self._inputs(key, *also)))

    def test_every_sinking_key_is_named_on_the_summary(self):
        # The finding: `content_mismatched_files` -- the #493 R4 tamper check --
        # rendered as the bare word "incomplete", and so did nine more.
        for key in sorted(self.SINKING):
            with self.subTest(key=key):
                sentence = integrity_mod.INTEGRITY_KEYS[key].sentence
                md = self._summary(key)
                self.assertIn("**Integrity:** %s" % sentence.split("%s")[0], md)
                self.assertIn("NOT CERTIFIED", md)
                # the evidence slot is FILLED, not printed as a format string
                self.assertNotIn("%s", md)

    def test_the_three_lines_that_rendered_before_are_unchanged(self):
        self.assertIn("**Integrity:** UNEXPECTED FILES — u.json (not declared by the "
                      "dispatch plan; run not certified)",
                      self._summary("unexpected_findings_files"))
        self.assertIn("**Integrity:** DUPLICATE out_file — d.json (two reviewers share "
                      "a write target; one overwrote the other; run not certified)",
                      self._summary("duplicate_out_files"))
        self.assertIn("**Integrity:** MISLABELED FILES — l.json (the `_panopticon` cell "
                      "stamp disagrees with the filename; possible mis-targeted "
                      "write; run not certified)",
                      self._summary("mislabeled_findings_files"))

    def test_the_tamper_check_names_the_file_it_caught(self):
        # Review finding 9: the measured fact is that the bytes no longer match
        # the snapshot -- `verify_out_file_hashes` also lists a file whose read
        # raised, and the module's own stderr line hedges ("substitution?").
        md = self._summary("content_mismatched_files")
        self.assertIn("**Integrity:** CONTENT CHANGED — c.json (the bytes no longer "
                      "match the fan-out snapshot, or could not be re-read; run "
                      "not certified)", md)

    def test_the_two_unusable_artifact_sentences_say_what_was_measured(self):
        # Review findings 7 and 9. `verify_out_file_hashes` reports the snapshot
        # unreadable when it parses but is not a non-empty dict, and
        # `load_verify_queue` returns "verify queue has no entries list" for a
        # queue that READ fine -- so neither may claim a failed read.
        self.assertIn("**Integrity:** CONTENT SNAPSHOT UNREADABLE — the fan-out "
                      "out-file-hashes.json exists and cannot be read as a "
                      "non-empty object, so no findings file could be verified "
                      "against it (tamper, not an unmeasured run; run not "
                      "certified)", self._summary("content_snapshot_unreadable"))
        self.assertIn("**Integrity:** VERIFY QUEUE UNUSABLE — verify queue has no "
                      "entries list (the queue recording what the advisor round "
                      "was asked to verify could not be read as a queue; run not "
                      "certified)", self._summary("invalid_verify_queue"))

    def test_an_invalid_dispatch_plan_names_the_loader_s_reason(self):
        # Review finding 8: the three reasons include a plan rejected on its
        # NAME, which may parse and may meet the cell contract. The file alone
        # does not say which of the three fired, and it is the only key whose
        # rows carry a reason the summary was dropping.
        # `file: reason`, not `file (reason)` (re-review R2): the reason that
        # motivated naming reasons at all ends in a parenthetical of its own, so
        # the parenthesised form collided -- `…file (expected x.json)) (a plan
        # file on disk …` -- in the common case, not an edge one. A row with no
        # reason says so rather than rendering `None`.
        md = self._summary("invalid_dispatch_plans")
        self.assertIn("**Integrity:** INVALID DISPATCH PLAN — dispatch-plan-decoy.json: "
                      "unrecognized dispatch-plan file (expected %s), "
                      "dispatch-plan-orphan.json: no reason recorded (a plan file "
                      "on disk that does not parse, does not meet the review-cell "
                      "contract, or is not the dispatch plan the driver writes; run "
                      "not certified)" % plan_mod.DRIVER_DISPATCH_PLAN, md)

    def test_a_sink_with_no_evidence_of_its_own_still_states_itself(self):
        # A bare flag has no files to name, so its sentence carries no slot and
        # must read as a complete statement on its own.
        md = self._summary("dispatch_plan_missing")
        self.assertIn("**Integrity:** DISPATCH PLAN MISSING — this run's driver "
                      "dispatched review cells and no dispatch-plan file is present, "
                      "so every plan-keyed check went quiet (deleted evidence; run "
                      "not certified)", md)

    def test_an_unknown_severity_is_a_note_naming_the_finding(self):
        # #2990: the line that explains a CRITICAL nobody wrote.
        report = report_mod.build_report(self._inputs("unknown_severity_findings"))
        self.assertEqual(report["meta"]["integrity"]["unknown_severity_findings"],
                         ["COD-123"])
        md = render_mod.render_summary(report)
        self.assertIn("**Note:** 1 finding(s) — COD-123 carried an unknown or no "
                      "severity and were read as CRITICAL (the value as written "
                      "is kept on each finding, null where none was written). "
                      "Does NOT affect certification.", md)
        self.assertNotIn("**Integrity:**", md)

    def test_the_non_gating_note_is_unchanged_and_is_not_an_integrity_line(self):
        md = self._summary("cross_domain_findings")
        self.assertIn("**Note:** 1 cross-domain finding(s) — ARC→TST ×1. Reviewers "
                      "filed outside their cell's domain; often a catalog gap (X0X). "
                      "Does NOT affect certification.", md)
        self.assertNotIn("**Integrity:**", md)

    def test_cross_domain_note_sorts_mixed_missing_and_named_domains(self):
        inputs = self._inputs("cross_domain_findings")
        inputs.plan.integrity["cross_domain_findings"] = [
            {"cell_domain": "COD", "finding_domain": "TST"},
            {"cell_domain": None, "finding_domain": "ARC"},
        ]
        md = render_mod.render_summary(report_mod.build_report(inputs))
        self.assertIn("2 cross-domain finding(s) — None→ARC ×1, COD→TST ×1", md)

    def test_every_key_integrity_section_publishes_is_in_the_table(self):
        # The RUNTIME side of the membership, and the one the fixture-run check
        # above cannot cover: it makes two `integrity_section` calls (plain, and
        # with an ack present for `write_guard_covers_bash`), so a key published
        # under any THIRD condition is invisible to it -- the re-review planted
        # one under `if dispatch_plan_mismatched:` and the whole battery stayed
        # green. An AST enumeration of every key the function can write does not
        # depend on reaching the branch that writes it.
        #
        # A SUBSET, not set equality: the table also carries the two keys
        # `reconcile` appends, which this function never writes.
        with open(integrity_mod.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        section = next(node for node in ast.walk(tree)
                       if isinstance(node, ast.FunctionDef)
                       and node.name == "integrity_section")
        literal, subscripted = set(), set()
        for node in ast.walk(section):
            if not isinstance(node, ast.Assign):
                continue
            named = [t for t in node.targets
                     if isinstance(t, ast.Name) and t.id == "integrity"]
            if named and isinstance(node.value, ast.Dict):
                literal |= {k.value for k in node.value.keys
                            if isinstance(k, ast.Constant) and isinstance(k.value, str)}
            for target in node.targets:
                if (isinstance(target, ast.Subscript)
                        and isinstance(target.value, ast.Name)
                        and target.value.id == "integrity"
                        and isinstance(target.slice, ast.Constant)):
                    subscripted.add(target.slice.value)
        # Both arms are exercised by the real function today, so a walk that
        # silently stops matching one of them fails here rather than passing
        # vacuously.
        self.assertIn("unexpected_findings_files", literal)
        self.assertIn("write_guard_covers_bash", subscripted)
        self.assertEqual(
            sorted((literal | subscripted) - set(integrity_mod.INTEGRITY_KEYS)), [],
            "keys `integrity_section` can publish that INTEGRITY_KEYS does not name")

    def test_evidence_text_neutralizes_its_own_output(self):
        # Review finding 6: `tools.base.inert_text`'s own docstring states the
        # rule -- fixing untrusted text at the producer is what lets every
        # renderer inherit it instead of each one remembering. This evidence is
        # a findings filename out of the scanned repository's own artifact
        # directory, so a second caller that forgot the wrap would print a
        # target-authored escape sequence straight to an operator's terminal.
        self.assertEqual(
            integrity_mod.evidence_text("unexpected_findings_files",
                                        ["a\x1b[2Kb.json"]),
            r"a\x1b[2Kb.json")
        self.assertEqual(
            integrity_mod.evidence_text("invalid_verify_queue", "q\x07"),
            r"q\x07")

    def test_a_certification_failure_outranks_the_non_gating_note(self):
        # Review finding 12: the `**Note:**` is an aside about the review and
        # the `**Integrity:**` lines are the verdict on the run, so the module's
        # own precedence rule ("an artifact-trust problem outranks a
        # disclosure") puts the failures first. Both still sit above the
        # host-capability disclosure, which is where this cluster landed.
        md = self._summary("mislabeled_findings_files", "cross_domain_findings",
                           "discovery_git_failure", "discovery_files_truncated")
        self.assertLess(md.rindex("**Integrity:**"), md.index("**Note:**"))
        self.assertLess(md.rindex("**Note:**"), md.index("**Host capabilities:**"))
        # Structurally too: every sinking key with a line sits AFTER the last
        # non-gating entry in the table, so an insertion into the wrong block
        # fails here rather than silently flipping the precedence.
        order = list(integrity_mod.INTEGRITY_KEYS.items())
        last_note = max(i for i, (_, s) in enumerate(order) if not s.sinks)
        first_sink = min(i for i, (_, s) in enumerate(order) if s.sinks)
        self.assertLess(last_note, first_sink)

    def test_a_key_with_no_line_of_its_own_prints_neither(self):
        # NOTED is not derived from the table here on purpose -- a test that
        # asks the table which keys print would pass on a table that lost a
        # sentence. It is pinned against it instead, so a key that gains or
        # loses one fails HERE rather than silently moving between the two
        # halves of this pair.
        self.assertEqual(
            {k for k in self.REPORTED if integrity_mod.INTEGRITY_KEYS[k].sentence},
            set(self.NOTED))
        for key in sorted(self.REPORTED - self.NOTED):
            with self.subTest(key=key):
                md = self._summary(key)
                self.assertNotIn("**Integrity:**", md)
                self.assertNotIn("**Note:**", md)

    def test_a_raw_walk_fallback_is_a_non_gating_note(self):
        # #2271: the disclosure that named a DEGRADED surface and reached no
        # human on the driver path. A superset of the intended surface is not
        # an artifact-trust failure, so it must not carry `NOT CERTIFIED`.
        md = self._summary("discovery_git_failure")
        self.assertIn("**Note:** DISCOVERY FELL BACK TO A RAW WALK — exit 128: fatal: "
                      "<ROOT>/.git: not a directory (the target's Git listing failed, "
                      "so the surface does not honour its .gitignore and may be far "
                      "larger than the target's own)", md)
        self.assertNotIn("**Integrity:**", md)
        self.assertNotIn("NOT CERTIFIED", md)

    def test_a_truncated_surface_is_a_non_gating_note(self):
        md = self._summary("discovery_files_truncated")
        self.assertIn("**Note:** DISCOVERY TRUNCATED — 7 files beyond the cap were "
                      "not reviewed", md)
        self.assertNotIn("**Integrity:**", md)
        self.assertNotIn("NOT CERTIFIED", md)

    def test_a_clean_discovery_renders_neither_note(self):
        # `_discovery_block` publishes `files_truncated: 0` on EVERY scan and a
        # `git_failure` of null on every git-listed one, so the common case
        # reaches the renderer as a falsy value and must print nothing. The
        # table's own truthiness rule, asserted rather than assumed.
        section = self._clean_section()
        section["discovery_files_truncated"] = 0
        section["discovery_git_failure"] = None
        md = render_mod.render_summary(report_mod.build_report(
            report_mod.ReportInputs(
                run=report_mod.RunConfig(target="t", fail_on="high",
                                         timestamp=self.TS),
                findings=findings_mod.FindingSet(findings=[]),
                plan=plan_mod.PlanInputs(groups_meta=self.G, integrity=section))))
        self.assertNotIn("DISCOVERY", md)
        self.assertNotIn("**Note:**", md)
        self.assertNotIn("**Integrity:**", md)

    def test_a_hostile_git_failure_string_is_neutralized_and_bounded(self):
        # The string is git's stderr, and the path in it comes off the reviewed
        # tree, so it is the same free text as `invalid_verify_queue`'s reason
        # and goes through the same `inert_text` producer wrap (#1829).
        self.assertEqual(
            integrity_mod.evidence_text("discovery_git_failure", "boom\x1b[2K\n@"),
            r"boom\x1b[2K @")
        long_failure = "x" * 9000
        bounded = integrity_mod.evidence_text("discovery_git_failure", long_failure)
        # The cap plus `inert_text`'s one-character cut marker: a cap
        # regression fails here, not at 8999.
        self.assertEqual(len(bounded), tool_base.INERT_TEXT_MAX + 1)
        self.assertTrue(bounded.startswith("x" * tool_base.INERT_TEXT_MAX))
        # ...and the count is a plain integer, not a quoted or escaped one.
        self.assertEqual(
            integrity_mod.evidence_text("discovery_files_truncated", 7), "7")


class TestAnAbsorbedUnknownSeverityIsNamed(unittest.TestCase):
    """#2990: the ids are taken BEFORE dedupe. Two unknown-severity claims at
    one locus and category both read as CRITICAL and dedupe keeps one; the
    disclosure still names both, since each was written that way."""

    def test_both_claims_are_named(self):
        def claim(fid, title):
            return findings_mod.normalize_finding(
                {"id": fid, "title": title, "severity": "SEVERE", "category": "c",
                 "source": "agent", "location": {"file": "a.py", "line_start": 1}})
        with contextlib.redirect_stderr(io.StringIO()):
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="t", fail_on="high",
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=findings_mod.FindingSet(
                    findings=[claim("COD-101", "one"), claim("COD-102", "two")])))
        self.assertEqual(len(r["findings"]), 1)
        self.assertEqual(r["meta"]["integrity"]["unknown_severity_findings"],
                         ["COD-101", "COD-102"])

    def test_the_ids_are_listed_sorted(self):
        # Twelve ids at twelve loci, handed over in reverse: a set's own order
        # (hash-seeded per process) cannot pass this by chance.
        ids = ["COD-%03d" % n for n in range(200, 212)]
        claims = [findings_mod.normalize_finding(
            {"id": fid, "title": fid, "severity": "SEVERE", "category": "c",
             "location": {"file": "a.py", "line_start": n + 1}})
            for n, fid in enumerate(reversed(ids))]
        with contextlib.redirect_stderr(io.StringIO()):
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="t", fail_on="high",
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=findings_mod.FindingSet(findings=claims)))
        self.assertEqual(r["meta"]["integrity"]["unknown_severity_findings"], ids)

    def test_a_forged_field_on_a_high_is_not_listed(self):
        # #2990 r1: a HIGH that arrives carrying `severity_as_written` is not
        # an unknown severity; the forged field is dropped and nothing listed.
        forged = findings_mod.normalize_finding(
            {"id": "COD-103", "title": "t", "severity": "HIGH", "category": "c",
             "severity_as_written": chr(27) + "[2Jforged",
             "location": {"file": "a.py", "line_start": 1}})
        with contextlib.redirect_stderr(io.StringIO()):
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="t", fail_on="high",
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=findings_mod.FindingSet(findings=[forged])))
        self.assertEqual(r["meta"]["integrity"]["unknown_severity_findings"], [])
        self.assertNotIn("severity_as_written", r["findings"][0])

    def test_stderr_names_unknown_and_absent_apart(self):
        # #3210 MUST 2: both kinds share the key; stderr counts them apart and
        # the finding's own field is null where no severity was written.
        def claim(fid, line, **sev):
            return findings_mod.normalize_finding(
                dict({"id": fid, "title": fid, "category": "c",
                      "location": {"file": "a.py", "line_start": line}}, **sev))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="t", fail_on="high",
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=findings_mod.FindingSet(findings=[
                    claim("COD-301", 1, severity="SEVERE"), claim("COD-302", 2),
                    claim("COD-303", 3, severity="HIGH")])))
        self.assertIn("synthesize: 2 finding(s) read as CRITICAL -- 1 with an unknown "
                      "severity, 1 with none: COD-301, COD-302", err.getvalue())
        self.assertEqual(r["meta"]["integrity"]["unknown_severity_findings"],
                         ["COD-301", "COD-302"])
        written = {f["id"]: f.get("severity_as_written", "<none>") for f in r["findings"]}
        self.assertEqual(written, {"COD-301": "SEVERE", "COD-302": None,
                                   "COD-303": "<none>"})
        self.assertEqual(report_mod.validate_report(r)[0], [])


class TestASecLessCodeGroupIsNamed(unittest.TestCase):
    """#3245: the SEC floor keys on file NAMES, so a config that never lists
    SEC plus a scout steered off it left a code group with no security cell,
    and only `coverage-<group>.json` knew. It is a non-sinking integrity key
    now, printed on a CERTIFIED run, which is the case that matters."""

    TS = "2026-01-01T00:00:00Z"

    def _report(self, coverages, groups_meta):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=groups_meta, coverages=coverages)))

    def test_the_issue_s_repro_group_is_named(self):
        # panopticon.yml: group Api, match [src/server/handler.py], no SEC in
        # panels; the scout returned [COD]; the filename floor did not fire.
        report = self._report([{"group": "Api", "effective": ["COD"]}],
                              [{"name": "Api", "files": ["src/server/handler.py"]}])
        self.assertEqual(["Api"], report["meta"]["integrity"]["sec_less_groups"])
        self.assertTrue(report["summary"]["coverage_certified"])     # disclosed, never sunk

    def test_only_a_code_group_without_sec_is_named(self):
        report = self._report(
            [{"group": "Api", "effective": ["COD"]},
             {"group": "Auth", "effective": ["COD", "SEC"]},
             {"group": "Art", "effective": []},
             {"group": "Lost", "effective": ["COD"]},
             {"group": "", "effective": ["COD"]}],       # names no group, as in planned_pairs
            [{"name": "Api", "files": ["src/server/handler.py"]},
             {"name": "Auth", "files": ["src/auth.py"]},
             {"name": "Art", "files": ["img/logo.png", "img/font.woff2"]}])
        # Auth has SEC; Art has no code; Lost has no file list, which is not "no code".
        self.assertEqual(["Api", "Lost"], report["meta"]["integrity"]["sec_less_groups"])

    def test_both_renderers_print_it_on_a_certified_run(self):
        import scripts.html_report as html_report
        report = self._report([{"group": "Api", "effective": ["COD"]}],
                              [{"name": "Api", "files": ["src/server/handler.py"]}])
        self.assertTrue(report["summary"]["coverage_certified"])
        text = render_mod.render_summary(report)
        line = next(ln for ln in text.splitlines() if "no SEC review cell" in ln)
        self.assertTrue(line.startswith("**Note:**"), line)
        self.assertIn("1 group(s) — Api", line)
        page = html_report.render(report)
        self.assertIn("<div class='integrity-note'>1 group(s) — Api with code have no SEC "
                      "review cell", page)

    def test_a_run_with_every_code_group_reviewed_prints_nothing(self):
        report = self._report([{"group": "Auth", "effective": ["COD", "SEC"]}],
                              [{"name": "Auth", "files": ["src/auth.py"]}])
        self.assertEqual([], report["meta"]["integrity"]["sec_less_groups"])
        self.assertNotIn("no SEC review cell", render_mod.render_summary(report))

