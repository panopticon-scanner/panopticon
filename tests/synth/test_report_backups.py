"""#3676: summoned backup advisors that never answered hold the letter back.

Before this, a run whose summoned backups all failed (non-zero exit, empty reply,
timeout) read as fully certified: the findings lost `backup_confirmed` and no
surface said a second opinion was owed and missing. A malformed backup sank
certification with no reason named. Both are now `grade_shortfalls` reasons under
the one shared rule (#3667), counted in `meta.coverage.backups`.
"""

import copy
import json
import os
import tempfile
import types
import unittest
from unittest import mock

import jsonschema

import scripts.evidence as evidence_mod
import scripts.html_report as html_report
import scripts.phases.verify as verify
import scripts.synth.backups as backups_mod
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
import scripts.synthesize as synthesize
from tests.synth.helpers import _agentic, _target_with_files

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "skill", "reference", "report-schema.json")
RUN_ID = "run-1"
GROUPS = [{"name": "g1", "files": ["a.py"]}]


class _RunDir(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.run_dir = d.name
        self.verdicts = os.path.join(d.name, "verdicts")
        os.makedirs(self.verdicts)

    def summon(self, *cells, count=1, parts=1, claims=("SEC-001",), extra=None):
        """Charge each cell's backup, recording `parts` and the `claims` it was
        handed beside it (None: no record of that one)."""
        body: dict = {"%s/%s/backup" % cell: count for cell in cells}
        if parts is not None:
            body.update({"%s/%s/backup/parts" % cell: parts for cell in cells})
        if claims is not None:
            body.update({"%s/%s/backup/claims" % cell: list(claims) for cell in cells})
        body.update(extra or {})
        with open(os.path.join(self.run_dir, backups_mod.ATTEMPTS_FILE), "w",
                  encoding="utf-8") as fh:
            json.dump(body, fh)

    def bundle(self, group, domain, verdicts, *, part=0, run_id=RUN_ID, raw=None,
               stage="backup"):
        name = "verdicts-%s-%s-backup%s.json" % (group, domain,
                                                 "-part%d" % part if part else "")
        with open(os.path.join(self.verdicts, name), "w", encoding="utf-8") as fh:
            fh.write(raw if raw is not None else json.dumps(
                {"verdicts": verdicts, "_panopticon": {"run_id": run_id, "stage": stage}}))
        return name

    def loaded(self):
        """What synthesize's FindingSet holds: the loader's per-file stamps and
        its unloadable rows -- the only verdict reads in the path."""
        accepted = {}
        _by_fid, unloadable = evidence_mod.load_verdict_bundles(self.verdicts, accepted=accepted)
        return accepted, unloadable

    def coverage(self):
        accepted, unloadable = self.loaded()
        return backups_mod.coverage(self.run_dir, accepted, unloadable, RUN_ID)


_VERDICT = {"finding_id": "SEC-001", "verdict": "CONFIRMED", "reasoning": "checked"}


def _block(**counts):
    """A `meta.coverage.backups` block: every count 0 unless given."""
    return dict({"summoned": 0, "answered": 0, "unanswered": 0, "unloadable": 0,
                 "claims_scoped": 0, "claims_unanswered": 0, "scope_not_recorded": 0,
                 "record_unreadable": False}, **counts)


def _verdict(finding_id):
    return dict(_VERDICT, finding_id=finding_id)


class TestBackupCoverage(_RunDir):
    def test_no_record_means_no_block(self):
        self.assertIsNone(self.coverage())
        self.assertIsNone(backups_mod.coverage(None, {}))

    def test_each_summoned_cell_is_counted_once(self):
        self.summon(("g1", "SEC"), ("g2", "SEC"), ("g3", "COD"), ("g4", "SEC"), ("g5", "SEC"),
                    ("g6", "SEC"), ("g7", "SEC"))
        self.bundle("g1", "SEC", [_VERDICT])                    # answered
        self.bundle("g3", "COD", [])                            # empty reply
        self.bundle("g4", "SEC", [_VERDICT], run_id="old-run")  # another run's
        self.bundle("g5", "SEC", None, raw="{not json")         # malformed
        self.bundle("g6", "SEC", [_VERDICT], stage="primary")   # not stamped a backup
        self.bundle("g7", "SEC", [{"verdict": "CONFIRMED"}])    # no entry survives
        # g2: nothing came back at all.
        self.assertEqual(_block(summoned=7, answered=1, unanswered=4, unloadable=2,
                                claims_scoped=7, claims_unanswered=6), self.coverage())

    def test_the_loader_records_stamps_counts_and_echoed_ids_only(self):
        self.bundle("g1", "SEC", [_VERDICT, {"verdict": "CONFIRMED"}, _verdict("B"), _VERDICT])
        accepted, _unloadable = self.loaded()
        self.assertEqual({"verdicts-g1-SEC-backup.json":
                          {"run_id": RUN_ID, "stage": "backup", "kept": 3,
                           "finding_ids": ["B", "SEC-001"]}}, accepted)

    def test_a_chunked_cell_is_answered_only_when_every_part_is(self):
        # #3679 review F1: verify splits a backup scope of more than 25 claims into
        # parts answered separately; one part answering is not the cell answering.
        for written, expected in (((0, 1), "answered"), ((0,), "unanswered"),
                                  ((1,), "unanswered"), ((0, 2), "unanswered"),
                                  ((0, 1, 2), "answered")):
            with self.subTest(written=written):
                for name in os.listdir(self.verdicts):
                    os.remove(os.path.join(self.verdicts, name))
                self.summon(("g1", "SEC"), parts=3 if 2 in written else 2)
                for part in written:
                    self.bundle("g1", "SEC", [_VERDICT], part=part)
                block = self.coverage()
                self.assertEqual(1, block[expected], block)
                if expected == "unanswered":
                    self.assertEqual(["1 backup advisor unanswered"],
                                     backups_mod.shortfall_reasons(block))

    def test_a_part_gap_or_a_stale_part_leaves_the_cell_unanswered(self):
        self.summon(("g1", "SEC"), parts=3)
        self.bundle("g1", "SEC", [_VERDICT], part=0)
        self.bundle("g1", "SEC", [_VERDICT], part=2)
        self.assertEqual(1, self.coverage()["unanswered"])          # part 1 is the gap
        self.bundle("g1", "SEC", [_VERDICT], part=1, run_id="old-run")
        self.assertEqual(1, self.coverage()["unanswered"])          # part 1 is stale
        self.bundle("g1", "SEC", [_VERDICT], part=1)
        self.assertEqual(1, self.coverage()["answered"])
        # A part past the recorded count answers nothing.
        self.summon(("g2", "SEC"), parts=1)
        self.bundle("g2", "SEC", [_VERDICT], part=1)
        self.assertEqual(_block(summoned=1, unanswered=1, claims_scoped=1, claims_unanswered=1),
                         self.coverage())

    def test_no_valid_part_count_is_unanswered(self):
        for parts in (None, 0, -1, True, "1", 1.0):
            with self.subTest(parts=parts):
                if parts is None:
                    self.summon(("g1", "SEC"), parts=None)
                else:
                    self.summon(("g1", "SEC"), parts=parts)
                self.bundle("g1", "SEC", [_VERDICT])
                self.assertEqual(_block(summoned=1, unanswered=1, claims_scoped=1,
                                        claims_unanswered=1), self.coverage())

    def test_without_a_verify_queue_no_backup_is_answered(self):
        # #3679 review F2: a backup cannot be summoned without a queue, so with no
        # run_id to bind to, another run's bundle (or this one's) answers nothing.
        self.summon(("g1", "SEC"))
        self.bundle("g1", "SEC", [_VERDICT], run_id="old-run")
        accepted, unloadable = self.loaded()
        for run_id in (None, RUN_ID):
            with self.subTest(run_id=run_id):
                self.assertEqual(1, backups_mod.coverage(self.run_dir, accepted, unloadable,
                                                         run_id)["unanswered"])
        self.bundle("g1", "SEC", [_VERDICT])
        accepted, unloadable = self.loaded()
        self.assertEqual(1, backups_mod.coverage(self.run_dir, accepted, unloadable,
                                                 None)["unanswered"])
        self.assertEqual(1, backups_mod.coverage(self.run_dir, accepted, unloadable,
                                                 RUN_ID)["answered"])
        # A bundle with no run stamp at all never matches "no run" either.
        self.bundle("g1", "SEC", None, raw=json.dumps(
            {"verdicts": [_VERDICT], "_panopticon": {"stage": "backup"}}))
        accepted, unloadable = self.loaded()
        self.assertIsNone(accepted["verdicts-g1-SEC-backup.json"]["run_id"])
        self.assertEqual(1, backups_mod.coverage(self.run_dir, accepted, unloadable,
                                                 None)["unanswered"])

    def test_only_charged_backup_keys_are_summoned(self):
        self.summon(("g1", "SEC"), count=0,
                    extra={"g2/SEC/primary": 2, "tool/abc": 1, "g3/SEC/backup": True,
                           "backup": 1, "/SEC/backup": 1})
        self.assertEqual(_block(), self.coverage())

    def test_a_group_name_with_a_slash_keeps_its_domain(self):
        self.summon(("api/v1", "SEC"))
        self.assertEqual([("api/v1", "SEC", 1, ["SEC-001"])],
                         backups_mod._summoned(self.run_dir))

    def test_an_unreadable_record_is_its_own_shortfall(self):
        for raw in ("{not json", "[1, 2]"):
            with self.subTest(raw=raw):
                with open(os.path.join(self.run_dir, backups_mod.ATTEMPTS_FILE), "w",
                          encoding="utf-8") as fh:
                    fh.write(raw)
                block = self.coverage()
                self.assertTrue(block["record_unreadable"])
                self.assertIsNone(block["summoned"])
                # Every count is unknown, the claim counts too: none reads as zero.
                self.assertEqual(dict(dict.fromkeys(_block()), record_unreadable=True), block)
                self.assertEqual(["the backup advisor record is unreadable"],
                                 backups_mod.shortfall_reasons(block))

    def test_the_reasons(self):
        self.assertEqual([], backups_mod.shortfall_reasons(None))
        self.assertEqual([], backups_mod.shortfall_reasons(
            {"summoned": 2, "answered": 2, "unanswered": 0, "unloadable": 0}))
        self.assertEqual(["1 backup advisor unanswered", "2 backup advisors unloadable"],
                         backups_mod.shortfall_reasons(
                             {"summoned": 3, "answered": 0, "unanswered": 1, "unloadable": 2}))
        # #3679 review F4: anything but a count of at least one names nothing.
        for bad in ("2", -1, True, 1.5, [1], None, 0):
            with self.subTest(count=bad):
                self.assertEqual([], backups_mod.shortfall_reasons(
                    {"summoned": 1, "unanswered": bad, "unloadable": bad}))


SCOPE = ("A", "B", "C")
PARTIAL = ["1 backup advisor unanswered", "2 findings unanswered by their backup advisors"]


class TestBackupCoverageIsCountedPerScopedClaim(_RunDir):
    """#3695. A backup that answered 1 of the claims it was handed made its cell
    `answered`; the rest lost `backup_confirmed` and nothing named them. Each scoped
    claim is now counted, against the ids verify recorded when it dispatched."""

    def test_a_backup_that_answers_one_of_three_claims_leaves_two_unanswered(self):
        self.summon(("g1", "SEC"), claims=SCOPE)
        self.bundle("g1", "SEC", [_verdict("A")])
        block = self.coverage()
        self.assertEqual(_block(summoned=1, unanswered=1, claims_scoped=3, claims_unanswered=2),
                         block)
        self.assertEqual(PARTIAL, backups_mod.shortfall_reasons(block))

    def test_every_scoped_claim_answered_is_an_answered_cell(self):
        self.summon(("g1", "SEC"), claims=SCOPE)
        self.bundle("g1", "SEC", [_verdict(i) for i in ("C", "A", "B")])
        block = self.coverage()
        self.assertEqual(_block(summoned=1, answered=1, claims_scoped=3), block)
        self.assertEqual([], backups_mod.shortfall_reasons(block))

    def test_only_an_id_in_the_recorded_scope_answers_anything(self):
        # The ids in a bundle are what an advisor wrote. One nobody handed it, or one
        # said twice, must not make up the number.
        self.summon(("g1", "SEC"), claims=SCOPE)
        self.bundle("g1", "SEC", [_verdict(i) for i in ("A", "A", "Z", "Y", "a", "B ")])
        self.assertEqual(_block(summoned=1, unanswered=1, claims_scoped=3, claims_unanswered=2),
                         self.coverage())

    def test_the_claims_of_a_chunked_cell_are_answered_across_its_parts(self):
        self.summon(("g1", "SEC"), parts=2, claims=SCOPE)
        self.bundle("g1", "SEC", [_verdict("A"), _verdict("B")])
        self.assertEqual(_block(summoned=1, unanswered=1, claims_scoped=3, claims_unanswered=1),
                         self.coverage())
        self.bundle("g1", "SEC", [_verdict("C")], part=1)
        self.assertEqual(_block(summoned=1, answered=1, claims_scoped=3), self.coverage())

    def test_a_verdict_answers_only_from_a_recorded_part_of_this_cell_bound_to_this_run(self):
        rest = [_verdict("B"), _verdict("C")]
        cases = (("another run's part", 2, {"part": 1, "run_id": "old-run"}),
                 ("a part stamped primary", 2, {"part": 1, "stage": "primary"}),
                 ("a part past the recorded count", 1, {"part": 1}),
                 ("another cell's bundle", 1, {"domain": "COD"}),
                 ("the cell's own second part", 2, {"part": 1}))
        for label, parts, where in cases:
            with self.subTest(label):
                for name in os.listdir(self.verdicts):
                    os.remove(os.path.join(self.verdicts, name))
                self.summon(("g1", "SEC"), parts=parts, claims=SCOPE)
                self.bundle("g1", "SEC", [_verdict("A")])
                where = dict(where)
                self.bundle("g1", where.pop("domain", "SEC"), rest, **where)
                block = self.coverage()
                if label == "the cell's own second part":         # the control
                    self.assertEqual(_block(summoned=1, answered=1, claims_scoped=3), block)
                else:
                    self.assertEqual(_block(summoned=1, unanswered=1, claims_scoped=3,
                                            claims_unanswered=2), block)

    def test_an_unloadable_backup_still_owes_its_claims(self):
        self.summon(("g1", "SEC"), claims=SCOPE)
        self.bundle("g1", "SEC", None, raw="{not json")
        block = self.coverage()
        self.assertEqual(_block(summoned=1, unloadable=1, claims_scoped=3, claims_unanswered=3),
                         block)
        self.assertEqual(["1 backup advisor unloadable",
                          "3 findings unanswered by their backup advisors"],
                         backups_mod.shortfall_reasons(block))

    def test_with_no_run_to_bind_to_every_scoped_claim_is_unanswered(self):
        self.summon(("g1", "SEC"), claims=SCOPE)
        self.bundle("g1", "SEC", [_verdict(i) for i in SCOPE])
        accepted, unloadable = self.loaded()
        self.assertEqual(_block(summoned=1, unanswered=1, claims_scoped=3, claims_unanswered=3),
                         backups_mod.coverage(self.run_dir, accepted, unloadable, None))
        # A bundle with no run stamp does not match "no run" either.
        self.bundle("g1", "SEC", None, raw=json.dumps(
            {"verdicts": [_verdict(i) for i in SCOPE], "_panopticon": {"stage": "backup"}}))
        accepted, unloadable = self.loaded()
        self.assertEqual(_block(summoned=1, unanswered=1, claims_scoped=3, claims_unanswered=3),
                         backups_mod.coverage(self.run_dir, accepted, unloadable, None))

    def test_a_record_with_no_scope_is_unanswered_and_says_so(self):
        # A record written before the scope was recorded. Nothing shows which claims the
        # backup was owed, so a full answer cannot be told from a partial one.
        self.summon(("g1", "SEC"), claims=None)
        self.bundle("g1", "SEC", [_VERDICT])
        block = self.coverage()
        self.assertEqual(_block(summoned=1, unanswered=1, scope_not_recorded=1), block)
        self.assertEqual(["1 backup advisor unanswered (1 scope not recorded)"],
                         backups_mod.shortfall_reasons(block))

    def test_a_scope_that_is_not_a_list_of_ids_is_no_scope(self):
        for scope in ([], [""], ["A", ""], ["A", 1], "A", {"A": 1}, 3, True, None):
            with self.subTest(scope=scope):
                self.summon(("g1", "SEC"), claims=None,
                            extra={"g1/SEC/backup/claims": scope})
                self.bundle("g1", "SEC", [_verdict("A")])
                self.assertEqual(_block(summoned=1, unanswered=1, scope_not_recorded=1),
                                 self.coverage())

    def test_cells_with_and_without_a_scope_are_counted_apart(self):
        self.summon(("g1", "SEC"), claims=SCOPE,
                    extra={"g2/SEC/backup": 1, "g2/SEC/backup/parts": 1})
        self.bundle("g1", "SEC", [_verdict("A")])
        self.bundle("g2", "SEC", [_VERDICT])
        block = self.coverage()
        self.assertEqual(_block(summoned=2, unanswered=2, claims_scoped=3, claims_unanswered=2,
                                scope_not_recorded=1), block)
        self.assertEqual(["2 backup advisors unanswered (1 scope not recorded)",
                          "2 findings unanswered by their backup advisors"],
                         backups_mod.shortfall_reasons(block))

    def test_a_claim_recorded_twice_is_one_claim(self):
        self.summon(("g1", "SEC"), claims=("A", "B", "A"))
        self.bundle("g1", "SEC", [_verdict("B")])
        self.assertEqual(_block(summoned=1, unanswered=1, claims_scoped=2, claims_unanswered=1),
                         self.coverage())

    def test_the_claims_reason(self):
        reasons = backups_mod.shortfall_reasons
        self.assertEqual(["1 finding unanswered by its backup advisor"],
                         reasons(_block(summoned=1, answered=1, claims_unanswered=1)))
        self.assertEqual(["19 findings unanswered by their backup advisors"],
                         reasons(_block(claims_unanswered=19)))
        for bad in ("2", -1, True, 1.5, [1], None, 0):
            with self.subTest(count=bad):
                self.assertEqual([], reasons(_block(claims_unanswered=bad,
                                                    scope_not_recorded=3)))
                self.assertEqual(["1 backup advisor unanswered"],
                                 reasons(_block(unanswered=1, scope_not_recorded=bad)))
        # The note belongs to the unanswered cells, not to the unloadable ones.
        self.assertEqual(["2 backup advisors unloadable"],
                         reasons(_block(unloadable=2, scope_not_recorded=1)))

    def test_the_rule_is_the_verify_phases_own(self):
        self.summon(("g1", "SEC"), claims=SCOPE)
        self.bundle("g1", "SEC", [_verdict("A")])
        asked = []
        real = evidence_mod.claims_unanswered

        def rule(claim_ids, verdict_ids):
            asked.append((list(claim_ids), sorted(verdict_ids)))
            return real(claim_ids, verdict_ids)

        with mock.patch.object(evidence_mod, "claims_unanswered", rule):
            self.coverage()
            chunk = [{"id": i} for i in SCOPE]
            self.assertFalse(verify._chunk_answered(chunk, [_verdict("A")]))
            self.assertTrue(verify._chunk_answered(chunk, [_verdict(i) for i in SCOPE]))
        self.assertEqual([(list(SCOPE), ["A"]), (list(SCOPE), ["A"]),
                          (list(SCOPE), list(SCOPE))], asked)


class TestTheSharedRule(unittest.TestCase):
    def test_the_claims_with_no_verdict_in_the_order_handed(self):
        rule = evidence_mod.claims_unanswered
        self.assertEqual([], rule([], []))
        self.assertEqual([], rule([], ["A"]))
        self.assertEqual(["C", "A", "B"], rule(["C", "A", "B"], []))
        self.assertEqual(["C", "B"], rule(["C", "A", "B"], ["A", "A", "Z"]))
        self.assertEqual([], rule(["C", "A", "B"], ["B", "C", "A"]))
        self.assertEqual(["A"], rule(["A", "A"], [None, "a"]))
        # Ids are compared as text, as the verdict loader keys them.
        self.assertEqual(["2"], rule([1, 2], ["1"]))
        self.assertEqual([], rule(["1"], [1]))


class TestTheVerifyPhaseSpellsTheSameRecord(unittest.TestCase):
    """synth may not import phases, so the shared names are pinned here."""

    def test_the_attempts_file_key_and_bundle_name_agree(self):
        self.assertEqual(verify._VERIFY_ATTEMPTS_FILE, backups_mod.ATTEMPTS_FILE)
        self.assertEqual("g1/SEC" + backups_mod.BACKUP_SUFFIX,
                         verify._verify_key("g1", "SEC", "backup"))
        self.assertEqual(verify._verify_key("g1", "SEC", "backup") + backups_mod.PARTS_SUFFIX,
                         verify._backup_parts_key("g1", "SEC"))
        self.assertEqual(verify._verify_key("g1", "SEC", "backup") + backups_mod.CLAIMS_SUFFIX,
                         verify._backup_claims_key("g1", "SEC"))
        with tempfile.TemporaryDirectory() as root:
            for part in (0, 2):
                name = os.path.basename(verify._verify_out_file(root, "g1", "SEC", "backup", part))
                with self.subTest(part=part):
                    self.assertEqual([name], backups_mod._cell_files([name], "g1", "SEC"))
                    self.assertEqual(name, backups_mod._part_file("g1", "SEC", part))


def _build(backups, lines=5000):
    with _target_with_files(GROUPS, lines=lines) as tgt:
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target=tgt, fail_on="high",
                                     timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=GROUPS, backups=backups)))


class TestUnansweredBackupsHoldTheLetterBack(unittest.TestCase):
    ALL_FAILED = _block(summoned=5, unanswered=5)

    def test_unanswered_backups_hold_the_letter_and_sink_certification(self):
        r = _build(self.ALL_FAILED)
        summary = r["summary"]
        self.assertEqual((None, "S", False, "INCONCLUSIVE"),
                         (summary["overall_grade"], summary["provisional_grade"],
                          summary["coverage_certified"], summary["gate"]))
        self.assertEqual(["5 backup advisors unanswered"], summary["grade_shortfalls"])
        self.assertIn("5 backup advisors unanswered", summary["coverage_note"])
        self.assertEqual(self.ALL_FAILED, r["meta"]["coverage"]["backups"])

    def test_a_backup_shortfall_is_not_also_a_verify_advisor_one(self):
        # #3674 review: the verify-advisor reason is `unanswered_gate` less the tool
        # ones. A finding whose PRIMARY answered is matched, so an unanswered backup on
        # it never reaches `unanswered_gate`: one reason, never two.
        finding = _agentic(sev="CRITICAL", location={"file": "a.py", "line_start": 1})
        verdicts = {evidence_mod.finding_fingerprint(finding): {
            "finding_id": finding["id"], "verdict": "CONFIRMED", "reasoning": "v"}}
        with _target_with_files(GROUPS, lines=5000) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=tgt, fail_on="high",
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=findings_mod.FindingSet(findings=[finding], verdicts=verdicts,
                                                 verdicts_supplied=True),
                plan=plan_mod.PlanInputs(groups_meta=GROUPS,
                                         backups=_block(summoned=1, unanswered=1))))
        self.assertEqual(["1 backup advisor unanswered"], r["summary"]["grade_shortfalls"])
        self.assertEqual(0, r["meta"]["coverage"]["verdicts"].get("unanswered", 0))

    def test_unloadable_backups_are_named_too(self):
        summary = _build(_block(summoned=2, unloadable=2))["summary"]
        self.assertEqual(["2 backup advisors unloadable"], summary["grade_shortfalls"])
        self.assertIn("2 backup advisors unloadable", summary["coverage_note"])

    def test_answered_backups_change_nothing(self):
        control = _build(None)["summary"]
        answered = _build(_block(summoned=5, answered=5, claims_scoped=9))["summary"]
        self.assertEqual(control, answered)
        self.assertEqual(("S", True, []), (answered["overall_grade"],
                                           answered["coverage_certified"],
                                           answered["grade_shortfalls"]))

    def test_the_terminal_and_html_name_the_backups(self):
        r = _build(self.ALL_FAILED)
        text = render_mod.render_summary(r)
        self.assertIn("**Grade:** S (provisional; 5 backup advisors unanswered)", text)
        self.assertIn("**Coverage:** NOT CERTIFIED — 5 backup advisors unanswered", text)
        page = html_report.render(r)
        self.assertIn("Grade: S (provisional; 5 backup advisors unanswered)", page)
        self.assertIn("NOT CERTIFIED &mdash; 5 backup advisors unanswered", page)

    def test_the_block_matches_the_report_schema(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            validator = jsonschema.Draft7Validator(json.load(fh))
        unreadable = dict.fromkeys(_block(), None)
        unreadable["record_unreadable"] = True
        for backups in (None, self.ALL_FAILED, unreadable,
                        _block(summoned=2, unanswered=2, claims_scoped=3, claims_unanswered=2,
                               scope_not_recorded=1)):
            with self.subTest(backups=backups):
                r = _build(backups)
                self.assertEqual([], [e.message for e in validator.iter_errors(r)])
        for label, change in (("negative count", {"unanswered": -1}),
                              ("a negative claim count", {"claims_unanswered": -1}),
                              ("a claim count that is not a number", {"claims_scoped": "3"}),
                              ("an undeclared key", {"timeouts": 1}),
                              ("a missing flag", "record_unreadable"),
                              ("no claim count", "claims_unanswered"),
                              ("no scoped count", "claims_scoped"),
                              ("no count of unrecorded scopes", "scope_not_recorded")):
            with self.subTest(label):
                bad = copy.deepcopy(_build(self.ALL_FAILED))
                block = bad["meta"]["coverage"]["backups"]
                if isinstance(change, str):
                    del block[change]
                else:
                    block.update(change)
                self.assertNotEqual([], list(validator.iter_errors(bad)))


class TestSynthesizeReadsTheRunRecord(_RunDir):
    def test_the_finding_set_carries_the_loader_stamps(self):
        self.bundle("g1", "SEC", [_VERDICT])
        fs = findings_mod.FindingSet.load(types.SimpleNamespace(verdicts_dir=self.verdicts),
                                          [], "standard", RUN_ID, prepared=([], None, {}))
        self.assertEqual({"verdicts-g1-SEC-backup.json":
                          {"run_id": RUN_ID, "stage": "backup", "kept": 1,
                           "finding_ids": ["SEC-001"]}}, fs.bundle_files)

    def test_plan_inputs_load_carries_the_block(self):
        self.summon(("g1", "SEC"))
        accepted, unloadable = self.loaded()
        plan = plan_mod.PlanInputs.load(self.run_dir, [], self.verdicts, GROUPS,
                                        ([], 0, []), (None, None), {},
                                        verdict_unloadable=unloadable, verdict_run_id=RUN_ID,
                                        bundle_files=accepted)
        self.assertEqual(_block(summoned=1, unanswered=1, claims_scoped=1, claims_unanswered=1),
                         plan.backups)


class TestSynthesizeBindsBackupsToThisRun(_RunDir):
    """#3679 review F2, through `synthesize.main`: a backup answers only when bound
    to this run -- the verify queue's run id, else the driver's `--run-id` (the
    driver writes no queue). With neither, a summoned backup is unanswered."""

    def _report(self, *, bundle_run_id, run_id=None, queue_run_id=None):
        findings = os.path.join(self.run_dir, "findings-g1-SEC.json")
        with open(findings, "w", encoding="utf-8") as fh:
            json.dump({"findings": [{
                "domain": "SEC", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
                "description": "x", "location": {"file": "a.py", "line_start": 1},
                "category": "authz"}]}, fh)
        if queue_run_id is not None:
            with open(os.path.join(self.run_dir, "verify-queue.json"), "w",
                      encoding="utf-8") as fh:
                json.dump({"run_id": queue_run_id, "entries": []}, fh)
        self.summon(("g1", "SEC"))
        self.bundle("g1", "SEC", [_VERDICT], run_id=bundle_run_id)
        out = os.path.join(self.run_dir, "report.json")
        argv = ["--repo", "--run-dir", self.run_dir, "--verdicts-dir", self.verdicts,
                "--out", out]
        if run_id is not None:
            argv += ["--run-id", run_id]
        cwd = os.getcwd()
        try:
            os.chdir(self.run_dir)
            synthesize.main(argv + [findings])
        finally:
            os.chdir(cwd)
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)["meta"]["coverage"]["backups"]

    def test_the_drivers_run_id_binds_the_backup(self):
        self.assertEqual(1, self._report(bundle_run_id=RUN_ID, run_id=RUN_ID)["answered"])

    def test_another_runs_backup_is_unanswered(self):
        self.assertEqual(1, self._report(bundle_run_id="old-run", run_id=RUN_ID)["unanswered"])

    def test_the_queue_run_id_binds_without_a_driver_run_id(self):
        self.assertEqual(1, self._report(bundle_run_id=RUN_ID,
                                         queue_run_id=RUN_ID)["answered"])

    def test_with_no_run_to_bind_to_no_backup_is_answered(self):
        self.assertEqual(1, self._report(bundle_run_id=RUN_ID)["unanswered"])

    def test_a_queue_and_a_driver_run_id_that_disagree_bind_to_nothing(self):
        # #3679 review R2-1: a stale queue (OLD) beside a new run (--run-id NEW) must
        # not let OLD's bundle certify, and NEW's does not answer either.
        for bundle_run_id in ("old-run", RUN_ID):
            with self.subTest(bundle=bundle_run_id):
                for name in os.listdir(self.run_dir):
                    if name.endswith(".json"):
                        os.remove(os.path.join(self.run_dir, name))
                for name in os.listdir(self.verdicts):
                    os.remove(os.path.join(self.verdicts, name))
                self.assertEqual(1, self._report(bundle_run_id=bundle_run_id, run_id=RUN_ID,
                                                 queue_run_id="old-run")["unanswered"])

    def test_the_binding_rule_itself(self):
        rule = synthesize._backup_run_id
        self.assertEqual("a", rule("a", None))
        self.assertEqual("a", rule(None, "a"))
        self.assertEqual("a", rule("a", "a"))
        self.assertIsNone(rule("a", "b"))
        # The driver passes "" when its manifest has no run id: that is no run.
        for queue, driver in (("", ""), (None, ""), ("", None), (None, None)):
            with self.subTest(queue=queue, driver=driver):
                self.assertIsNone(rule(queue, driver))

    def test_a_queue_and_a_driver_run_id_that_agree_bind(self):
        self.assertEqual(1, self._report(bundle_run_id=RUN_ID, run_id=RUN_ID,
                                         queue_run_id=RUN_ID)["answered"])


if __name__ == "__main__":
    unittest.main()
