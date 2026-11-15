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
import unittest

import jsonschema

import scripts.evidence as evidence_mod
import scripts.html_report as html_report
import scripts.phases.verify as verify
import scripts.synth.backups as backups_mod
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
from tests.synth.helpers import _target_with_files

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

    def summon(self, *cells, count=1, extra=None):
        body = {"%s/%s/backup" % cell: count for cell in cells}
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
        self.assertEqual({"summoned": 7, "answered": 1, "unanswered": 4, "unloadable": 2,
                          "record_unreadable": False}, self.coverage())

    def test_the_loader_records_stamps_and_counts_only(self):
        self.bundle("g1", "SEC", [_VERDICT, {"verdict": "CONFIRMED"}])
        accepted, _unloadable = self.loaded()
        self.assertEqual({"verdicts-g1-SEC-backup.json":
                          {"run_id": RUN_ID, "stage": "backup", "kept": 1}}, accepted)

    def test_a_chunked_cell_answers_through_any_part(self):
        self.summon(("g1", "SEC"))
        self.bundle("g1", "SEC", [_VERDICT], part=1)
        self.assertEqual(1, self.coverage()["answered"])

    def test_only_charged_backup_keys_are_summoned(self):
        self.summon(("g1", "SEC"), count=0,
                    extra={"g2/SEC/primary": 2, "tool/abc": 1, "g3/SEC/backup": True,
                           "backup": 1, "/SEC/backup": 1})
        self.assertEqual({"summoned": 0, "answered": 0, "unanswered": 0, "unloadable": 0,
                          "record_unreadable": False}, self.coverage())

    def test_a_group_name_with_a_slash_keeps_its_domain(self):
        self.summon(("api/v1", "SEC"))
        self.assertEqual([("api/v1", "SEC")], backups_mod._summoned(self.run_dir))

    def test_an_unreadable_record_is_its_own_shortfall(self):
        for raw in ("{not json", "[1, 2]"):
            with self.subTest(raw=raw):
                with open(os.path.join(self.run_dir, backups_mod.ATTEMPTS_FILE), "w",
                          encoding="utf-8") as fh:
                    fh.write(raw)
                block = self.coverage()
                self.assertTrue(block["record_unreadable"])
                self.assertIsNone(block["summoned"])
                self.assertEqual(["the backup advisor record is unreadable"],
                                 backups_mod.shortfall_reasons(block))

    def test_the_reasons(self):
        self.assertEqual([], backups_mod.shortfall_reasons(None))
        self.assertEqual([], backups_mod.shortfall_reasons(
            {"summoned": 2, "answered": 2, "unanswered": 0, "unloadable": 0}))
        self.assertEqual(["1 backup advisor unanswered", "2 backup advisors unloadable"],
                         backups_mod.shortfall_reasons(
                             {"summoned": 3, "answered": 0, "unanswered": 1, "unloadable": 2}))


class TestTheVerifyPhaseSpellsTheSameRecord(unittest.TestCase):
    """synth may not import phases, so the shared names are pinned here."""

    def test_the_attempts_file_key_and_bundle_name_agree(self):
        self.assertEqual(verify._VERIFY_ATTEMPTS_FILE, backups_mod.ATTEMPTS_FILE)
        self.assertEqual("g1/SEC" + backups_mod.BACKUP_SUFFIX,
                         verify._verify_key("g1", "SEC", "backup"))
        with tempfile.TemporaryDirectory() as root:
            for part in (0, 2):
                name = os.path.basename(verify._verify_out_file(root, "g1", "SEC", "backup", part))
                with self.subTest(part=part):
                    self.assertEqual([name], backups_mod._cell_files([name], "g1", "SEC"))


def _build(backups, lines=5000):
    with _target_with_files(GROUPS, lines=lines) as tgt:
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target=tgt, fail_on="high",
                                     timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[]),
            plan=plan_mod.PlanInputs(groups_meta=GROUPS, backups=backups)))


class TestUnansweredBackupsHoldTheLetterBack(unittest.TestCase):
    ALL_FAILED = {"summoned": 5, "answered": 0, "unanswered": 5, "unloadable": 0,
                  "record_unreadable": False}

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
        import scripts.evidence as evidence_mod2
        from tests.synth.helpers import _agentic
        finding = _agentic(sev="CRITICAL", location={"file": "a.py", "line_start": 1})
        verdicts = {evidence_mod2.finding_fingerprint(finding): {
            "finding_id": finding["id"], "verdict": "CONFIRMED", "reasoning": "v"}}
        with _target_with_files(GROUPS, lines=5000) as tgt:
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=tgt, fail_on="high",
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=findings_mod.FindingSet(findings=[finding], verdicts=verdicts,
                                                 verdicts_supplied=True),
                plan=plan_mod.PlanInputs(groups_meta=GROUPS, backups={
                    "summoned": 1, "answered": 0, "unanswered": 1, "unloadable": 0,
                    "record_unreadable": False})))
        self.assertEqual(["1 backup advisor unanswered"], r["summary"]["grade_shortfalls"])
        self.assertEqual(0, r["meta"]["coverage"]["verdicts"].get("unanswered", 0))

    def test_unloadable_backups_are_named_too(self):
        summary = _build({"summoned": 2, "answered": 0, "unanswered": 0, "unloadable": 2,
                          "record_unreadable": False})["summary"]
        self.assertEqual(["2 backup advisors unloadable"], summary["grade_shortfalls"])
        self.assertIn("2 backup advisors unloadable", summary["coverage_note"])

    def test_answered_backups_change_nothing(self):
        control = _build(None)["summary"]
        answered = _build({"summoned": 5, "answered": 5, "unanswered": 0, "unloadable": 0,
                           "record_unreadable": False})["summary"]
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
        for backups in (None, self.ALL_FAILED,
                        {"summoned": None, "answered": None, "unanswered": None,
                         "unloadable": None, "record_unreadable": True}):
            with self.subTest(backups=backups):
                r = _build(backups)
                self.assertEqual([], [e.message for e in validator.iter_errors(r)])
        for label, change in (("negative count", {"unanswered": -1}),
                              ("an undeclared key", {"timeouts": 1}),
                              ("a missing flag", None)):
            with self.subTest(label):
                bad = copy.deepcopy(_build(self.ALL_FAILED))
                block = bad["meta"]["coverage"]["backups"]
                if change is None:
                    del block["record_unreadable"]
                else:
                    block.update(change)
                self.assertNotEqual([], list(validator.iter_errors(bad)))


class TestSynthesizeReadsTheRunRecord(_RunDir):
    def test_the_finding_set_carries_the_loader_stamps(self):
        import types
        self.bundle("g1", "SEC", [_VERDICT])
        fs = findings_mod.FindingSet.load(types.SimpleNamespace(verdicts_dir=self.verdicts),
                                          [], "standard", RUN_ID, prepared=([], None, {}))
        self.assertEqual({"verdicts-g1-SEC-backup.json":
                          {"run_id": RUN_ID, "stage": "backup", "kept": 1}}, fs.bundle_files)

    def test_plan_inputs_load_carries_the_block(self):
        self.summon(("g1", "SEC"))
        accepted, unloadable = self.loaded()
        plan = plan_mod.PlanInputs.load(self.run_dir, [], self.verdicts, GROUPS,
                                        ([], 0, []), (None, None), {},
                                        verdict_unloadable=unloadable, verdict_run_id=RUN_ID,
                                        bundle_files=accepted)
        self.assertEqual({"summoned": 1, "answered": 0, "unanswered": 1, "unloadable": 0,
                          "record_unreadable": False}, plan.backups)


if __name__ == "__main__":
    unittest.main()
