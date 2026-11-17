"""#3707: a verdict speaks only for its own cell's instance of a claim.

A claim id is derived from what a reviewer wrote: domain, category, file, title
and line, with no group. So one cell's reviewer can emit a copy of another cell's
claim, and the controller hands that id to the copying cell's advisor as one of
its own. #3704 counted a verdict for any claim its advisor was handed, and
"handed" was decided by id: the copying cell's advisor REJECTED the copy, in
scope, and the other cell's CONFIRMED CRITICAL was discarded. Gate PASS,
certified, no shortfall.

A bundle verdict now counts for a finding only when the bundle is stamped for the
cell that finding came from. Where several cells hold one id, each answers for its
own instance: any CONFIRMED keeps the claim reported, a holding cell that did not
answer leaves it unverified, and only every holding cell dismissing it dismisses
it. A cell that was never asked about the claim dismisses nothing, and its own
instance is dismissed by no other cell.
"""

import json
import os
import types
import unittest

import jsonschema

import scripts.evidence as evidence_mod
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.report as report_mod
import scripts.synth.verdict_scope as scope_mod
import scripts.synth.verdicts as verdicts_mod
from tests.synth.helpers import _target_with_files
from tests.synth.test_verdict_scope import SCHEMA_PATH, _Verdicts, record, verdict

GROUPS = [{"name": "g1", "files": ["a.py"]}, {"name": "g2", "files": ["b.py"]}]
G1, G2 = ("g1", "SEC"), ("g2", "SEC")


def claim(file, title=None, severity="CRITICAL", line=1):
    return {"domain": "SEC", "code": "SEC-A1A", "severity": severity,
            "title": title or "claim in %s" % file, "description": "x", "category": "authz",
            "location": {"file": file, "line_start": line}}


class _TwoCells(_Verdicts):
    """`g2` holds the CRITICAL claim `B`. `g1` holds its own claim `A` and, when it
    copies, a claim with `B`'s identity: the same domain, category, file, title and
    line, so the same id."""

    def cells(self, copy=True, copy_severity="CRITICAL", own_severity="LOW"):
        """`A` is LOW unless a test says otherwise, so the gate is `B`'s to decide."""
        mine = [claim("a.py", severity=own_severity)] + (
            [claim("b.py", severity=copy_severity)] if copy else [])
        self.paths = []
        for group, findings in (("g1", mine), ("g2", [claim("b.py")])):
            self.paths.append(os.path.join(self.run_dir, "findings-%s-SEC.json" % group))
            with open(self.paths[-1], "w", encoding="utf-8") as fh:
                json.dump({"findings": findings}, fh)
        loaded = findings_mod.load_findings(self.paths)
        self.a, self.b = loaded[0]["id"], loaded[-1]["id"]
        self.assertEqual(copy, loaded[1]["id"] == self.b and len(loaded) == 3)
        self.record(record(claims=[f["id"] for f in loaded[:-1]], size=25),
                    record(group="g2", claims=(self.b,), size=25))
        return loaded

    def report(self, fail_on="critical"):
        fs = findings_mod.FindingSet.load(
            types.SimpleNamespace(verdicts_dir=self.verdicts), [], "standard", None,
            prepared=(findings_mod.load_findings(self.paths), None, None),
            run_dir=self.run_dir)
        with _target_with_files(GROUPS, lines=5000) as target:
            return report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=target, fail_on=fail_on,
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=fs, plan=plan_mod.PlanInputs(groups_meta=GROUPS)))

    def facts(self, report):
        """What the acceptance compares: where each claim is and on what evidence, the
        gate, certification, the letter and the shortfalls."""
        summary = report["summary"]
        claims = sorted((f["id"], where, f["evidence"]["status"], f["severity"])
                        for where, found in (("report", report["findings"]),
                                             ("discarded", report["discarded_claims"]))
                        for f in found)
        return {"claims": claims, "gate": summary["gate"],
                "certified": summary["coverage_certified"],
                "letter": (summary["overall_grade"], summary["provisional_grade"]),
                "shortfalls": summary["grade_shortfalls"]}

    def where(self, report, finding_id):
        return [(where, f["evidence"]["status"])
                for where, found in (("report", report["findings"]),
                                     ("discarded", report["discarded_claims"]))
                for f in found if f["id"] == finding_id]


class TestACopiedClaimIsNotTheCopyingCellsToDismiss(_TwoCells):
    """The issue's rows. `silent` is the run where `g1` emits no copy."""

    def silent(self, own):
        self.cells(copy=False)
        self.bundle([verdict(self.a)])
        self.bundle([verdict(self.b, own)], group="g2")
        return self.report()

    def test_the_copying_cells_primary_rejects_what_the_owner_confirmed(self):
        silent = self.facts(self.silent("CONFIRMED"))
        self.cells()
        self.bundle([verdict(self.a), verdict(self.b, "REJECTED")])
        self.bundle([verdict(self.b, "CONFIRMED")], group="g2")
        report = self.report()
        self.assertEqual([("report", "advisor_confirmed")], self.where(report, self.b))
        self.assertEqual(silent, self.facts(report))
        # It was: discarded, gate PASS, certified, the top letter, no shortfall.
        self.assertEqual(("FAIL", True, []), (silent["gate"], silent["certified"],
                                              silent["shortfalls"]))

    def test_the_copying_cells_backup_rejects_what_the_owner_confirmed(self):
        """The backup wins over a primary, but only over its own cell's."""
        silent = self.facts(self.silent("CONFIRMED"))
        self.cells()
        self.record(record(claims=(self.a, self.b), size=25),
                    record(group="g2", claims=(self.b,), size=25),
                    record(stage="backup", claims=(self.b,), size=25))
        self.bundle([verdict(self.a), verdict(self.b, "CONFIRMED")])
        self.bundle([verdict(self.b, "REJECTED")], stage="backup")
        self.bundle([verdict(self.b, "CONFIRMED")], group="g2")
        report = self.report()
        self.assertEqual([("report", "advisor_confirmed")], self.where(report, self.b))
        self.assertEqual(silent, self.facts(report))
        self.assertEqual("FAIL", silent["gate"])

    def test_the_copying_cell_confirms_what_the_owner_rejected(self):
        """The other direction is no better than the silent run: the claim is reported."""
        silent = self.silent("REJECTED")
        self.assertEqual([("discarded", "rejected")], self.where(silent, self.b))
        self.assertEqual("PASS", silent["summary"]["gate"])
        self.cells()
        self.bundle([verdict(self.a), verdict(self.b, "CONFIRMED")])
        self.bundle([verdict(self.b, "REJECTED")], group="g2")
        report = self.report()
        self.assertEqual([("report", "advisor_confirmed")], self.where(report, self.b))
        self.assertEqual("FAIL", report["summary"]["gate"])

    def test_the_copying_cells_backup_confirms_what_the_owner_rejected(self):
        self.cells()
        self.record(record(claims=(self.a, self.b), size=25),
                    record(group="g2", claims=(self.b,), size=25),
                    record(stage="backup", claims=(self.b,), size=25))
        self.bundle([verdict(self.a), verdict(self.b, "CONFIRMED")])
        self.bundle([verdict(self.b, "CONFIRMED")], stage="backup")
        self.bundle([verdict(self.b, "REJECTED")], group="g2")
        report = self.report()
        self.assertEqual([("report", "advisor_confirmed")], self.where(report, self.b))

    def test_a_copy_of_lower_severity_dismisses_nothing_either(self):
        """The id does not hold the severity, so the copy need not match it."""
        self.cells(copy_severity="LOW")
        self.bundle([verdict(self.a), verdict(self.b, "REJECTED")])
        self.bundle([verdict(self.b, "CONFIRMED")], group="g2")
        report = self.report()
        self.assertEqual([("report", "advisor_confirmed")], self.where(report, self.b))
        self.assertEqual(["CRITICAL"], [f["severity"] for f in report["findings"]
                                        if f["id"] == self.b])

    def test_the_owner_not_answering_leaves_it_unverified_whatever_the_copier_says(self):
        self.cells()
        self.bundle([verdict(self.a), verdict(self.b, "REJECTED")])
        report = self.report()
        self.assertEqual([("report", "unverified")], self.where(report, self.b))
        self.assertEqual(["1 finding unanswered by its verify advisor"],
                         report["summary"]["grade_shortfalls"])
        self.assertFalse(report["summary"]["coverage_certified"])

    def test_the_copier_not_answering_leaves_a_rejection_unverified(self):
        """A dismissal needs every holding cell: one that said nothing has not dismissed."""
        self.cells()
        self.bundle([verdict(self.a)])
        self.bundle([verdict(self.b, "REJECTED")], group="g2")
        report = self.report()
        self.assertEqual([("report", "unverified")], self.where(report, self.b))
        self.assertFalse(report["summary"]["coverage_certified"])


class TestACopyBehindADecoy(_TwoCells):
    """The same hole through #2991's restore. `g1` emits a second claim at `B`'s locus
    (the decoy, another title, so another id) beside its copy of `B`. Dedupe keeps the
    first of the three, which is the decoy, and drops both instances of `B`. With the
    decoy and the copy REJECTED, `B` was not restored: it left the report altogether."""

    def scene(self, copy, copy_severity="CRITICAL", owner_severity="CRITICAL"):
        mine = [claim("a.py", severity="LOW"), claim("b.py", title="another reading of b.py")]
        mine += [dict(claim("b.py", severity=copy_severity), description="the copy")] if copy else []
        theirs = [dict(claim("b.py", severity=owner_severity), description="the owner's")]
        self.paths = []
        for group, findings in (("g1", mine), ("g2", theirs)):
            self.paths.append(os.path.join(self.run_dir, "findings-%s-SEC.json" % group))
            with open(self.paths[-1], "w", encoding="utf-8") as fh:
                json.dump({"findings": findings}, fh)
        ids = [f["id"] for f in findings_mod.load_findings(self.paths)]
        self.a, self.b = ids[0], ids[-1]
        self.record(record(claims=ids[:-1], size=25), record(group="g2", claims=(self.b,), size=25))
        self.bundle([verdict(i, "CONFIRMED" if i == self.a else "REJECTED") for i in ids[:-1]])
        self.bundle([verdict(self.b)], group="g2")
        return self.report()

    def test_the_confirmed_claim_is_restored_once(self):
        silent = self.facts(self.scene(copy=False))
        report = self.scene(copy=True)
        self.assertEqual([("report", "advisor_confirmed")], self.where(report, self.b))
        self.assertEqual(silent, self.facts(report))
        self.assertEqual("FAIL", silent["gate"])

    def test_the_instance_restored_is_the_one_dedupe_would_keep(self):
        """The copy is LOW and was loaded first; the owner's CRITICAL is the claim."""
        report = self.scene(copy=True, copy_severity="LOW")
        self.assertEqual([("CRITICAL", "advisor_confirmed")],
                         [(f["severity"], f["evidence"]["status"]) for f in report["findings"]
                          if f["id"] == self.b])
        self.assertEqual("FAIL", report["summary"]["gate"])
        # ...whichever was loaded first: here the more severe instance is the earlier one.
        report = self.scene(copy=True, owner_severity="LOW")
        self.assertEqual([("CRITICAL", "the copy")],
                         [(f["severity"], f["description"]) for f in report["findings"]
                          if f["id"] == self.b])
        # Among equals, the first loaded, as in dedupe.
        report = self.scene(copy=True)
        self.assertEqual(["the copy"], [f["description"] for f in report["findings"]
                                        if f["id"] == self.b])


class TestACellThatWasNeverAsked(_TwoCells):
    """Ruling 1, as revised. A cell with no entry in the dispatch record was never asked
    about its claims. That is a cell below the verify gate. It is also a cell whose
    findings file the driver refused until the review budget ran out, and synthesis reads
    its claims out of that file all the same. Such a cell dismisses nothing, and no other
    cell dismisses its instance: the instance stands as in the run where no other cell
    holds the id. "Asked" is read from the dispatch record, never from a missing bundle."""

    def scene(self, g1_record, owner="REJECTED", copy_severity="LOW"):
        """`g1` holds a LOW copy of `B` (so `g1` is below the gate) and `g1_record` is
        what the record holds for it; `g2`'s own advisor says `owner` of `B`."""
        self.cells(copy_severity=copy_severity)
        self.record(record(group="g2", claims=(self.b,), size=25), g1_record(self))
        self.bundle([verdict(self.b, owner)], group="g2")
        return self.report()

    def no_verdicts(self):
        for name in os.listdir(self.verdicts):
            os.unlink(os.path.join(self.verdicts, name))

    def lone(self, g1_record):
        """The run in which `g2` holds nothing: `g1`'s LOW instance of `B` by itself."""
        self.cells(copy_severity="LOW")
        with open(self.paths[1], "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        self.no_verdicts()
        self.record(g1_record(self))
        return self.report()

    def refused(self, copy, says="REJECTED", copy_severity="CRITICAL", owner_severity="CRITICAL",
                decoy=False):
        """The seat's F1. `g2` holds `B` and the record holds nothing for `g2`: the driver
        refused its findings file, no advisor was dispatched for it, and synthesis reads
        the file. `g1` copies `B`, was asked about its copy and says `says` of it. With
        `decoy`, `g1` also holds another claim at `B`'s line, loaded before the copy, and
        says the same of it."""
        mine = [claim("a.py", severity="LOW")] + (
            [claim("b.py", title="another reading of b.py")] if decoy else []) + (
            [dict(claim("b.py", severity=copy_severity), description="the copy")] if copy else [])
        theirs = [dict(claim("b.py", severity=owner_severity), description="the owner's")]
        self.paths = []
        for group, findings in (("g1", mine), ("g2", theirs)):
            self.paths.append(os.path.join(self.run_dir, "findings-%s-SEC.json" % group))
            with open(self.paths[-1], "w", encoding="utf-8") as fh:
                json.dump({"findings": findings}, fh)
        ids = [f["id"] for f in findings_mod.load_findings(self.paths)]
        self.a, self.b = ids[0], ids[-1]
        self.no_verdicts()
        self.record(record(claims=ids[:-1], size=25))
        self.bundle([verdict(self.a)] + [verdict(i, says) for i in dict.fromkeys(ids[1:-1])])
        return self.report(fail_on="high")

    def published(self, report):
        """`facts`, less the discarded claims; and those, apart."""
        facts = self.facts(report)
        discarded = [c for c in facts["claims"] if c[1] == "discarded"]
        facts["claims"] = [c for c in facts["claims"] if c[1] == "report"]
        return facts, discarded

    NEVER_DISPATCHED = staticmethod(lambda self: {})
    WITHOUT_THE_CLAIM = staticmethod(lambda self: record(claims=(self.a,), size=25))
    WITH_THE_CLAIM = staticmethod(lambda self: record(claims=(self.a, self.b), size=25))
    AT_THE_BACKUP_ONLY = staticmethod(lambda self: {
        **record(claims=(self.a,), size=25),
        **record(stage="backup", claims=(self.b,), size=25)})
    CHARGED_WITH_NO_SCOPE = staticmethod(lambda self: {"g1/SEC/primary": 1})

    def test_a_below_gate_instance_stays_where_the_run_with_no_other_holder_has_it(self):
        """The honest case, and the seat's F2: one cell rates a shared claim below the
        gate, and the other cell's advisor rejects its own instance. The rejected
        instance is the one discarded. The below-gate one stays in the report, unverified
        at its own severity. That is no shortfall, so the run still certifies. It used to
        move to `discarded_claims` on the other cell's word."""
        for label, g1_record in (("never dispatched", self.NEVER_DISPATCHED),
                                 ("dispatched without the claim", self.WITHOUT_THE_CLAIM)):
            with self.subTest(label):
                lone, nothing = self.published(self.lone(g1_record))
                held, discarded = self.published(self.scene(g1_record))
                self.assertEqual(lone, held)
                self.assertEqual(([], [(self.b, "discarded", "rejected", "CRITICAL")]),
                                 (nothing, discarded))
                self.assertIn((self.b, "report", "unverified", "LOW"), held["claims"])
                self.assertEqual(("PASS", True, []),
                                 (held["gate"], held["certified"], held["shortfalls"]))

    def test_no_other_cell_dismisses_an_instance_whose_cell_was_never_asked(self):
        """The seat's F1. An honest cell holds a CRITICAL and has no entry in the record.
        A copier that was asked REJECTS its copy. The run was: discarded, PASS, certified.
        It is the run with no copy: unverified, INCONCLUSIVE, not certified. Whichever
        instance dedupe kept: the copy (as severe, loaded first) or the owner's."""
        silent = self.facts(self.refused(copy=False))
        self.assertEqual(("INCONCLUSIVE", False, [(self.a, "report", "advisor_confirmed", "LOW"),
                                                  (self.b, "report", "unverified", "CRITICAL")]),
                         (silent["gate"], silent["certified"], silent["claims"]))
        self.assertIn("1 finding unanswered by its verify advisor", silent["shortfalls"])
        for copy_severity, kept in (("CRITICAL", "the copy"), ("HIGH", "the owner's"),
                                    ("LOW", "the owner's")):
            with self.subTest(copy_severity=copy_severity):
                copied, discarded = self.published(
                    self.refused(copy=True, copy_severity=copy_severity))
                self.assertEqual(silent, copied)
                # The copy is what is discarded, where dedupe kept it; where dedupe kept
                # the owner's, the rejected copy is merged under a published finding.
                self.assertEqual([(self.b, "discarded", "rejected", copy_severity)]
                                 if kept == "the copy" else [], discarded)

    def test_the_copys_severity_neither_raises_nor_lowers_the_published_instance(self):
        """The instance published is the never-asked cell's own, at its own severity,
        whether the rejected copy was the one dedupe kept (more severe, or as severe and
        loaded first) or the one it dropped."""
        for owner_severity, copy_severity in (("HIGH", "CRITICAL"), ("HIGH", "HIGH"),
                                              ("HIGH", "LOW"), ("LOW", "CRITICAL"),
                                              ("CRITICAL", "LOW")):
            with self.subTest(owner=owner_severity, copy=copy_severity):
                report = self.refused(copy=True, copy_severity=copy_severity,
                                      owner_severity=owner_severity)
                self.assertEqual(
                    [(owner_severity, "the owner's", "unverified")],
                    [(f["severity"], f["description"], f["evidence"]["status"])
                     for f in report["findings"] if f["id"] == self.b])

    def test_a_confirmation_from_a_cell_that_was_asked_still_reports_the_claim_confirmed(self):
        for copy_severity in ("CRITICAL", "LOW"):       # dedupe keeps the copy / the owner's
            with self.subTest(copy_severity=copy_severity):
                report = self.refused(copy=True, says="CONFIRMED", copy_severity=copy_severity)
                self.assertEqual([("report", "advisor_confirmed")], self.where(report, self.b))
                self.assertEqual(["CRITICAL"], [f["severity"] for f in report["findings"]
                                                if f["id"] == self.b])
        # ...and where the never-asked instance is the copy (`g1`, never dispatched,
        # loaded first and as severe), confirmed by the owner's own advisor.
        report = self.scene(self.NEVER_DISPATCHED, owner="CONFIRMED", copy_severity="CRITICAL")
        self.assertEqual([("report", "advisor_confirmed")], self.where(report, self.b))

    def test_behind_a_rejected_decoy_the_never_asked_instance_is_the_one_that_comes_back(self):
        """Dedupe keeps the decoy and drops both instances of `B`: the copy first, as
        severe as the owner's. `g1` REJECTS the decoy and the copy. The copy was
        dismissed and stays merged. The owner's was never asked about, so it comes back."""
        silent = self.facts(self.refused(copy=False))
        copied, discarded = self.published(self.refused(copy=True, decoy=True))
        self.assertEqual(silent, copied)
        self.assertEqual(["rejected"], [status for _id, _where, status, _sev in discarded])
        self.assertNotIn(self.b, [finding_id for finding_id, *_rest in discarded])
        report = self.refused(copy=True, decoy=True)
        self.assertEqual(["the owner's"], [f["description"] for f in report["findings"]
                                           if f["id"] == self.b])

    def test_only_a_confirmation_reaches_it_from_another_cell(self):
        """An asked cell that is unsure of its copy, or says nothing of it, leaves the
        never-asked instance as it would be alone: unverified, never `needs_more_info`."""
        for says in ("NEEDS_MORE_INFO", "REJECTED"):
            with self.subTest(says=says):
                report = self.refused(copy=True, says=says, copy_severity="LOW")
                self.assertEqual([("report", "unverified")], self.where(report, self.b))

    def test_a_cell_that_was_asked_and_said_nothing_still_holds_the_claim(self):
        for label, g1_record in (("at the primary", self.WITH_THE_CLAIM),
                                 ("at the backup only", self.AT_THE_BACKUP_ONLY)):
            with self.subTest(label):
                report = self.scene(g1_record)
                self.assertEqual([("report", "unverified")], self.where(report, self.b))
                self.assertFalse(report["summary"]["coverage_certified"])
                self.assertIn("1 finding unanswered by its verify advisor",
                              report["summary"]["grade_shortfalls"])

    def test_a_cell_the_record_cannot_speak_for_still_holds_the_claim(self):
        """Charged with no scope recorded: nothing shows what it was asked. Fail closed."""
        report = self.scene(self.CHARGED_WITH_NO_SCOPE)
        self.assertEqual([("report", "unverified")], self.where(report, self.b))
        self.assertFalse(report["summary"]["coverage_certified"])

    def test_the_id_is_still_counted_as_held_by_several_cells(self):
        report = self.scene(self.NEVER_DISPATCHED)
        self.assertEqual(1, report["meta"]["coverage"]["verdicts"]["ids_in_several_cells"])


class TestWasACellAsked(unittest.TestCase):
    """`Scope.asked`: read from the dispatch record."""

    def asked(self, body, cell=G1, finding_id="SEC-002"):
        return scope_mod.Scope(body).asked(cell, finding_id)

    def test_a_recorded_scope_that_holds_the_id_at_either_stage(self):
        self.assertIs(True, self.asked(record()))
        self.assertIs(True, self.asked({**record(claims=("SEC-001",)),
                                        **record(stage="backup", claims=("SEC-002",))}))
        self.assertIs(True, self.asked(record(stage="backup")))

    def test_a_cell_the_record_shows_was_not_asked(self):
        self.assertIs(False, self.asked({}))                              # never dispatched
        self.assertIs(False, self.asked(record(group="g2")))              # another cell was
        self.assertIs(False, self.asked(record(claims=("SEC-001",))))     # without this id
        self.assertIs(False, self.asked(record(), finding_id="SEC-0022"))
        self.assertIs(False, self.asked({"g1/SECX/primary": 1, "g10/SEC/primary": 1}))

    def test_a_record_that_cannot_say(self):
        self.assertIsNone(scope_mod.Scope(None).asked(G1, "SEC-002"))     # no record at all
        self.assertIsNone(self.asked({"g1/SEC/primary": 2}))              # charged, no scope
        self.assertIsNone(self.asked({"g1/SEC/backup/parts": 1}))
        broken = dict(record(), **{"g1/SEC/primary/part_size": "25"})
        self.assertIsNone(self.asked(broken))
        self.assertIsNone(self.asked(record(), cell=None))
        # A stage that holds the id answers, whatever the other stage's state.
        self.assertIs(True, self.asked({"g1/SEC/primary": 1, **record(stage="backup")}))
        self.assertIsNone(self.asked({"g1/SEC/primary": 1,
                                      **record(stage="backup", claims=("SEC-001",))}))


class TestAnHonestDuplicateBehavesAsBefore(_TwoCells):
    """Two cells really report one claim. Agreeing, they decide it as one cell would."""

    def test_both_confirm(self):
        self.cells()
        self.bundle([verdict(self.a), verdict(self.b)])
        self.bundle([verdict(self.b)], group="g2")
        report = self.report()
        self.assertEqual([("report", "advisor_confirmed")], self.where(report, self.b))
        self.assertEqual(([], True), (report["summary"]["grade_shortfalls"],
                                      report["summary"]["coverage_certified"]))
        self.assertEqual(2, len(report["findings"]))

    def test_both_reject(self):
        self.cells()
        self.bundle([verdict(self.a), verdict(self.b, "REJECTED")])
        self.bundle([verdict(self.b, "REJECTED")], group="g2")
        report = self.report()
        self.assertEqual([("discarded", "rejected")], self.where(report, self.b))
        self.assertEqual(([], True), (report["summary"]["grade_shortfalls"],
                                      report["summary"]["coverage_certified"]))

    def test_one_unsure_and_one_rejecting_is_not_a_dismissal(self):
        self.cells()
        self.bundle([verdict(self.a), verdict(self.b, "REJECTED")])
        self.bundle([verdict(self.b, "NEEDS_MORE_INFO")], group="g2")
        report = self.report()
        self.assertEqual([("report", "needs_more_info")], self.where(report, self.b))

    def test_the_ids_held_by_several_cells_are_counted(self):
        self.cells(copy=False)
        self.bundle([verdict(self.a)])
        self.bundle([verdict(self.b)], group="g2")
        self.assertEqual(0, self.report()["meta"]["coverage"]["verdicts"]["ids_in_several_cells"])
        self.cells()
        report = self.report()
        self.assertEqual(1, report["meta"]["coverage"]["verdicts"]["ids_in_several_cells"])
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            validator = jsonschema.Draft7Validator(json.load(fh))
        self.assertEqual([], [e.message for e in validator.iter_errors(report)])
        report["meta"]["coverage"]["verdicts"]["ids_in_several_cells"] = "1"
        self.assertNotEqual([], list(validator.iter_errors(report)))

    def test_no_carrier_of_the_cell_reaches_the_report(self):
        self.cells()
        self.bundle([verdict(self.a), verdict(self.b)])
        self.bundle([verdict(self.b)], group="g2")
        report = self.report()
        for finding in report["findings"] + report["discarded_claims"]:
            self.assertEqual([], [key for key in finding if key.startswith("_")])


class TestTheRule(unittest.TestCase):
    """`evidence.across_cells`: one verdict from what each holding cell said of its own
    instance. None is a cell that gave no verdict."""

    @staticmethod
    def said(word, cell="?", **more):
        return dict({"verdict": word, "from": cell}, **more)

    def decide(self, own, **others):
        by_cell = {G1: self.said(own, "g1") if own else None}
        by_cell.update({(name, "SEC"): self.said(word, name) if word else None
                        for name, word in others.items()})
        found = evidence_mod.across_cells(by_cell, G1)
        return (found["verdict"], found["from"]) if found else None

    def test_one_cell_is_its_own_verdict(self):
        for word in ("CONFIRMED", "REJECTED", "NEEDS_MORE_INFO"):
            self.assertEqual((word, "g1"), self.decide(word))
        self.assertIsNone(self.decide(None))
        self.assertIsNone(evidence_mod.across_cells({}, G1))

    def test_any_confirmation_keeps_the_claim(self):
        self.assertEqual(("CONFIRMED", "g2"), self.decide("REJECTED", g2="CONFIRMED"))
        self.assertEqual(("CONFIRMED", "g1"), self.decide("CONFIRMED", g2="REJECTED"))
        self.assertEqual(("CONFIRMED", "g2"), self.decide(None, g2="CONFIRMED"))
        self.assertEqual(("CONFIRMED", "g3"), self.decide("REJECTED", g2=None, g3="CONFIRMED"))
        self.assertEqual(("CONFIRMED", "g1"), self.decide("CONFIRMED", g2="CONFIRMED"))

    def test_a_cell_that_did_not_answer_leaves_it_unverified(self):
        self.assertIsNone(self.decide("REJECTED", g2=None))
        self.assertIsNone(self.decide(None, g2="REJECTED"))
        self.assertIsNone(self.decide("NEEDS_MORE_INFO", g2=None))
        self.assertIsNone(self.decide("REJECTED", g2="REJECTED", g3=None))

    def test_only_every_cell_dismissing_it_dismisses_it(self):
        self.assertEqual(("REJECTED", "g1"), self.decide("REJECTED", g2="REJECTED"))
        self.assertEqual(("NEEDS_MORE_INFO", "g2"),
                         self.decide("REJECTED", g2="NEEDS_MORE_INFO"))
        self.assertEqual(("NEEDS_MORE_INFO", "g1"),
                         self.decide("NEEDS_MORE_INFO", g2="REJECTED"))
        self.assertEqual(("NEEDS_MORE_INFO", "g3"),
                         self.decide("REJECTED", g2="REJECTED", g3="NEEDS_MORE_INFO"))

    def test_among_equals_the_findings_own_cell_speaks_then_the_first_by_name(self):
        by_cell = {("g3", "SEC"): self.said("REJECTED", "g3"),
                   ("g2", "SEC"): self.said("REJECTED", "g2")}
        self.assertEqual("g2", evidence_mod.across_cells(by_cell, G1)["from"])
        by_cell[G1] = self.said("REJECTED", "g1")
        self.assertEqual("g1", evidence_mod.across_cells(by_cell, G1)["from"])
        # The own cell, wherever its name sorts: among rejections and confirmations.
        for word in ("REJECTED", "CONFIRMED", "NEEDS_MORE_INFO"):
            by_cell = {(name, "SEC"): self.said(word, name) for name in ("g1", "g2", "g3")}
            for own in ("g1", "g2", "g3"):
                self.assertEqual(own, evidence_mod.across_cells(by_cell, (own, "SEC"))["from"])

    def test_a_scope_limited_unsure_is_more_favourable_than_a_bare_one(self):
        limited = self.said("NEEDS_MORE_INFO", "g2", missing_evidence=["x.py"])
        by_cell = {G1: self.said("NEEDS_MORE_INFO", "g1"), G2: limited}
        self.assertEqual("g2", evidence_mod.across_cells(by_cell, G1)["from"])


class TestWhichCellsHoldAnId(unittest.TestCase):
    def test_the_cells_come_from_the_findings_files(self):
        findings = [{"id": "X", "_group": "g1", evidence_mod.CELL_DOMAIN_FIELD: "SEC"},
                    {"id": "X", "_group": "g2", evidence_mod.CELL_DOMAIN_FIELD: "SEC"},
                    {"id": "X", "_group": "g2", evidence_mod.CELL_DOMAIN_FIELD: "SEC"},
                    {"id": "Y", "_group": "g1", evidence_mod.CELL_DOMAIN_FIELD: "COD"},
                    {"id": "T", "_group": "g1"},                 # a tool finding: no cell
                    {"id": "Z"}, {"_group": "g1"}, "text"]
        self.assertEqual({"X": {G1, G2}, "Y": {("g1", "COD")}},
                         verdicts_mod.holding_cells(findings))

    def test_a_findings_cell_is_its_file_and_not_what_the_reviewer_wrote(self):
        """A reviewer may file under another domain's code; the cell is the file's."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "findings-g1-SEC.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"findings": [dict(claim("a.py"), domain="TST", code="TST-X0X",
                                             _group="g9", _cell_domain="COD")]}, fh)
            (loaded,) = findings_mod.load_findings([path])
        self.assertEqual("TST", loaded["domain"])
        self.assertEqual(G1, evidence_mod.finding_cell(loaded))


class TestAVerdictCarriesItsBundlesCell(_Verdicts):
    def test_the_stamp_and_not_the_advisor_says_which_cell(self):
        self.record(record(claims=("SEC-001",), size=25))
        self.bundle([dict(verdict("SEC-001"), _cell=["g2", "SEC"], group="g2")])
        by_fid, _accepted, _unloadable = self.load()
        self.assertEqual([G1], [v[evidence_mod.CELL_FIELD] for v in by_fid["SEC-001"]])

    def test_a_verdict_binds_only_to_a_finding_of_its_own_cell(self):
        self.record(record(claims=("SEC-001",), size=25),
                    record(group="g2", claims=("SEC-001",), size=25))
        self.bundle([verdict("SEC-001", "REJECTED")])
        self.bundle([verdict("SEC-001", "CONFIRMED")], group="g2")
        by_fid, _accepted, _unloadable = self.load()

        def own(group):
            finding = {"id": "SEC-001", "_group": group, evidence_mod.CELL_DOMAIN_FIELD: "SEC"}
            found = verdicts_mod.claim_verdict(finding, by_fid, None, {})
            return found and found["verdict"]

        self.assertEqual(("REJECTED", "CONFIRMED", None), (own("g1"), own("g2"), own("g3")))
        # A finding that came from no cell (a tool finding) is no cell's claim, whoever
        # else holds its id and whatever they said of it.
        for holders in ({}, {"SEC-001": {G1, G2}}):
            self.assertIsNone(verdicts_mod.claim_verdict({"id": "SEC-001", "_group": "g1"},
                                                         by_fid, None, holders))
        # ...and a finding of a cell is decided with the other cells that hold its id.
        held = {"id": "SEC-001", "_group": "g1", evidence_mod.CELL_DOMAIN_FIELD: "SEC"}
        self.assertEqual("CONFIRMED", verdicts_mod.claim_verdict(
            held, by_fid, None, {"SEC-001": {G1, G2}})["verdict"])
        # Without the cell that confirmed it, g1's own rejection stands alone; with a
        # third holder that said nothing, and nobody confirming, it is unverified.
        self.assertEqual("REJECTED", verdicts_mod.claim_verdict(
            held, by_fid, None, {"SEC-001": {G1}})["verdict"])
        self.assertIsNone(verdicts_mod.claim_verdict(
            held, by_fid, None, {"SEC-001": {G1, ("g3", "SEC")}}))
        # Where the map names the id, the cells it names decide the claim. A finding
        # whose own cell is not among them was never asked: the others' CONFIRMED reaches
        # it and nothing else of theirs does (ruling 1, revised).
        theirs = {"id": "SEC-001", "_group": "g2", evidence_mod.CELL_DOMAIN_FIELD: "SEC"}
        self.assertIsNone(verdicts_mod.claim_verdict(theirs, by_fid, None, {"SEC-001": {G1}}))
        self.assertIsNone(verdicts_mod.claim_verdict(theirs, by_fid, None, {"SEC-001": set()}))
        self.assertEqual("CONFIRMED", verdicts_mod.claim_verdict(
            dict(theirs, _group="g3"), by_fid, None, {"SEC-001": {G1, G2}})["verdict"])
        # Where it does not name the id at all, the finding's own cell speaks.
        self.assertEqual("CONFIRMED", verdicts_mod.claim_verdict(
            theirs, by_fid, None, {"OTHER": {G1}})["verdict"])


if __name__ == "__main__":
    unittest.main()
