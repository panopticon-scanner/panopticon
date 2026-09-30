"""Integrity certification and summary contracts."""

import ast
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
        # #2271: threaded in from the run's `groups.json` discovery block, and
        # published last by `integrity_section` -- so they land here, ahead of
        # the two keys `reconcile` appends after it.
        "discovery_git_failure", "discovery_files_truncated",
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


class TestTheSinkingSetIsOneTable(unittest.TestCase):
    """B19 (#1761, ARC-3284703909): which `meta.integrity` keys sink
    `integrity_ok`, and whether the report ever says which one did.

    The rule used to live in three places with three memberships: this
    module's `integrity_section` published ~20 keys, `tool_axis.reconcile`
    re-spelled 14 of them in a hand-written `or` chain, and
    `render.render_summary` named four -- one of which does not gate. So ten of
    the fourteen sinking keys had no line of their own, nine of them no name on
    the summary at all: it said "incomplete" and the reasons went to stderr.

    `SINKING` is transcribed from that chain BEFORE it was folded into
    `integrity.INTEGRITY_KEYS`, which is what makes
    `test_the_chain_sinks_exactly_these_keys` an equivalence baseline: it
    passed against the hand-written chain and must still pass against the
    comprehension over the table.
    """

    # The 14 terms of the pre-change chain, in its own order.
    SINKING = frozenset({
        "unexpected_findings_files", "duplicate_out_files",
        "mislabeled_findings_files", "content_mismatched_files",
        "content_snapshot_unreadable", "content_snapshot_missing",
        "malformed_findings_files", "empty_dispatch_plans",
        "dispatch_plan_missing", "dispatch_plan_mismatched",
        "invalid_dispatch_plans", "invalid_verify_queue",
        "tools_manifest_invalid", "delta_scope_suppressed_git_drivers"})
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
        "discovery_git_failure", "discovery_files_truncated"})
    # The REPORTED keys that DO print a line: a non-gating `**Note:**`, never
    # an `**Integrity:**`. Pinned against the table below so a key that gains
    # or loses a sentence cannot quietly change which test covers it.
    NOTED = frozenset({"cross_domain_findings", "discovery_git_failure",
                       "discovery_files_truncated"})
    # `reconcile` appends these two to whatever section it was handed, so
    # `integrity_section` never publishes them and the table's membership test
    # below has to name them explicitly.
    RECONCILE_ADDS = frozenset({"tools_manifest_invalid",
                                "delta_scope_suppressed_git_drivers"})
    # One truthy value per key, in the shape the key really carries.
    TRUTHY: dict = {
        "unexpected_findings_files": ["u.json"],
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
        "delta_scope_suppressed_git_drivers": ["diff.external"],
        # #2271: git's own stderr, which is target-influenced free text.
        "discovery_git_failure": "exit 128: fatal: <ROOT>/.git: not a directory",
        "discovery_files_truncated": 7,
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
        return report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=self.TS),
            findings=findings_mod.FindingSet(findings=[]),
            delta=delta_mod.DeltaContext(
                diff_hunks={"base": "main", "hunks": {}} if delta_key else None),
            plan=plan_mod.PlanInputs(
                groups_meta=self.G, integrity=section,
                git_drivers_suppressed=self.SUPPRESSED_DRIVERS if delta_key else None),
            tools=tool_axis_mod.ToolAxis(
                manifest_invalid=(self.TRUTHY[key]
                                  if key == "tools_manifest_invalid" else None)))

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

    def test_the_non_gating_note_is_unchanged_and_is_not_an_integrity_line(self):
        md = self._summary("cross_domain_findings")
        self.assertIn("**Note:** 1 cross-domain finding(s) — ARC→TST ×1. Reviewers "
                      "filed outside their cell's domain; often a catalog gap (X0X). "
                      "Does NOT affect certification.", md)
        self.assertNotIn("**Integrity:**", md)

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
