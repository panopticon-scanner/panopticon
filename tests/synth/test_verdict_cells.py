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

import contextlib
import copy
import io
import itertools
import json
import os
import random
import re
import types
import unittest

import jsonschema

import scripts.evidence as evidence_mod
import scripts.reconcile as reconcile_mod
import scripts.score_gate as score_gate
import scripts.ocrdb as ocrdb
import scripts.synth.codes as codes_mod
import scripts.synth.corroborate as corroborate_mod
import scripts.synth.findings as findings_mod
import scripts.synth.plan as plan_mod
import scripts.synth.report as report_mod
import scripts.synth.severity_cap as severity_cap_mod
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
        self.no_verdicts()
        self.record(record(group="g2", claims=(self.b,), size=25), g1_record(self))
        self.bundle([verdict(self.b, owner)], group="g2")
        self.g1_answers_for_its_own_claim(g1_record)
        return self.report()

    def no_verdicts(self):
        for name in os.listdir(self.verdicts):
            os.unlink(os.path.join(self.verdicts, name))

    def g1_answers_for_its_own_claim(self, g1_record):
        """Where the record says `g1` was asked about its own claim `A`, it answered.
        A cell that the record says was asked owes its answer, whatever its claims
        score (round 3, R1), and these scenes are about `B`."""
        if self.a in g1_record(self).get("g1/SEC/primary/claims", ()):
            self.bundle([verdict(self.a)])

    def lone(self, g1_record):
        """The run in which `g2` holds nothing: `g1`'s LOW instance of `B` by itself."""
        self.cells(copy_severity="LOW")
        with open(self.paths[1], "w", encoding="utf-8") as fh:
            json.dump({"findings": []}, fh)
        self.no_verdicts()
        self.record(g1_record(self))
        self.g1_answers_for_its_own_claim(g1_record)
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

    def test_an_unsure_copy_that_wins_the_merge_does_not_take_the_shortfall_with_it(self):
        """The seat's N1. The copy wins dedupe (as severe and loaded first, or more
        severe) and its advisor is unsure. It was: the copy published `needs_more_info`,
        the owner's instance merged under it, nothing owed, PASS, certified. The owner's
        instance is owed an answer and has none, so it comes back, and the run is the
        one with no copy."""
        for owner_severity in ("CRITICAL", "HIGH"):
            with self.subTest(owner_severity=owner_severity):
                silent = self.facts(self.refused(copy=False, owner_severity=owner_severity))
                report = self.refused(copy=True, says="NEEDS_MORE_INFO",
                                      owner_severity=owner_severity)
                self.assertEqual(
                    [("the copy", "CRITICAL", "needs_more_info"),
                     ("the owner's", owner_severity, "unverified")],
                    sorted((f["description"], f["severity"], f["evidence"]["status"])
                           for f in report["findings"] if f["id"] == self.b))
                copied = self.facts(report)
                for key in ("gate", "certified", "shortfalls"):
                    self.assertEqual(silent[key], copied[key], key)
                self.assertEqual(("INCONCLUSIVE", False), (copied["gate"], copied["certified"]))
                self.assertIn("1 finding unanswered by its verify advisor", copied["shortfalls"])

    def test_a_claim_another_cell_confirmed_is_still_owed_its_own_answer(self):
        """What is shown and what is owed are separate (round 2, P1). The copier CONFIRMS
        its copy, so the claim is reported confirmed. The owner's cell was owed an
        answer and never got one: that is still one unanswered finding, as it is with
        no copy, and the run is not certified."""
        silent = self.facts(self.refused(copy=False))
        report = self.refused(copy=True, says="CONFIRMED")
        self.assertEqual([("report", "advisor_confirmed")], self.where(report, self.b))
        copied = self.facts(report)
        self.assertEqual(("FAIL", False, silent["shortfalls"]),
                         (copied["gate"], copied["certified"], copied["shortfalls"]))
        self.assertIn("1 finding unanswered by its verify advisor", copied["shortfalls"])

    def test_reconcile_reads_a_report_with_one_id_in_both_lists(self):
        """The seat's N4. The never-asked instance is in `findings` and its rejected copy
        is in `discarded_claims`, under one id and one fingerprint. `reconcile` does not
        raise and refuses nothing: the claim recurs against itself, nothing is closed or
        ambiguous, and the pair is named once per run under `degenerate_fingerprints`,
        which is its disclosure that one fingerprint holds two records."""
        report = self.refused(copy=True)
        pair = [(where, f["fingerprint"]) for where in ("findings", "discarded_claims")
                for f in report[where] if f["id"] == self.b]
        self.assertEqual(["findings", "discarded_claims"], [where for where, _fp in pair])
        (fingerprint,) = {fp for _where, fp in pair}
        path, out = (os.path.join(self.run_dir, name) for name in ("report.json", "diff.json"))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh)
        with contextlib.redirect_stderr(io.StringIO()) as err, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, reconcile_mod.main(["diff", path, path, "--out", out]))
        self.assertEqual("", err.getvalue())
        with open(out, encoding="utf-8") as fh:
            diff = json.load(fh)
        self.assertEqual({"recurring": 2, "closed": 0, "ambiguous": 0, "new": 0},
                         diff["meta"]["counts"])
        self.assertIsNone(diff["meta"]["close_guard"])
        self.assertEqual([{"fingerprint": fingerprint, "ids": [self.b, self.b], "run": run}
                          for run in ("run2", "run3")], diff["meta"]["degenerate_fingerprints"])
        (claim,) = [entry for entry in diff["recurring"] if entry["fingerprint"] == fingerprint]
        self.assertEqual(["finding", "rejected"], sorted(r["kind"] for r in claim["run3"]))

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

    def test_an_advisor_that_was_asked_and_said_nothing_is_owed_whoever_else_confirmed(self):
        """An honest duplicate with one silent advisor. The claim is reported confirmed,
        on the cell that answered. The cell that was asked and said nothing is one
        unanswered finding, so the run is not certified, whichever cell it was."""
        for silent in ("g1", "g2"):
            with self.subTest(silent=silent):
                self.cells()
                for name in os.listdir(self.verdicts):
                    os.unlink(os.path.join(self.verdicts, name))
                self.bundle([verdict(self.a)] + ([] if silent == "g1" else [verdict(self.b)]))
                self.bundle([] if silent == "g2" else [verdict(self.b)], group="g2")
                report = self.report()
                self.assertEqual([("report", "advisor_confirmed")], self.where(report, self.b))
                summary = report["summary"]
                self.assertEqual(("FAIL", False, ["1 finding unanswered by its verify advisor"]),
                                 (summary["gate"], summary["coverage_certified"],
                                  summary["grade_shortfalls"]))

    def test_one_claim_that_two_cells_left_unanswered_is_counted_once(self):
        self.cells()
        self.bundle([verdict(self.a)])
        self.bundle([], group="g2")
        report = self.report()
        self.assertEqual([("report", "unverified")], self.where(report, self.b))
        self.assertEqual(["1 finding unanswered by its verify advisor"],
                         report["summary"]["grade_shortfalls"])

    def _with_a_low_claim_in_a_cell_below_the_gate(self, same_id, owner):
        """`g1` holds one LOW claim at `B`'s line and is below the verify gate: never
        dispatched. `g2` holds `B` at `owner`'s severity and, with a HIGH claim of its
        own elsewhere, was asked about both. Returns the report and the LOW claim's id."""
        low = dict(claim("b.py", title=None if same_id else "a note on b.py", severity="LOW"),
                   description="g1's")
        theirs = [dict(claim("b.py", severity=owner[0]), description="g2's"),
                  claim("a.py", severity="HIGH")]
        self.paths = []
        for group, findings in (("g1", [low]), ("g2", theirs)):
            self.paths.append(os.path.join(self.run_dir, "findings-%s-SEC.json" % group))
            with open(self.paths[-1], "w", encoding="utf-8") as fh:
                json.dump({"findings": findings}, fh)
        loaded = findings_mod.load_findings(self.paths)
        self.b, other = loaded[1]["id"], loaded[2]["id"]
        self.assertEqual(same_id, loaded[0]["id"] == self.b)
        self.record(record(group="g2", claims=(self.b, other), size=25))
        self.bundle([verdict(other)] + ([verdict(self.b, owner[1])] if owner[1] else []),
                    group="g2")
        return self.report(fail_on="high"), loaded[0]["id"]

    def test_a_claim_that_was_owed_nothing_stays_merged_under_an_unsure_finding(self):
        """Only what is owed comes back from under a finding that is in the report. A
        LOW claim in a cell below the gate, under another cell's unsure CRITICAL, is
        merged as it always was."""
        report, low = self._with_a_low_claim_in_a_cell_below_the_gate(
            same_id=False, owner=("CRITICAL", "NEEDS_MORE_INFO"))
        self.assertEqual([("report", "needs_more_info")], self.where(report, self.b))
        self.assertEqual([], self.where(report, low))
        self.assertEqual([], report["summary"]["grade_shortfalls"])

    def test_a_claim_is_not_published_twice_on_one_verdict(self):
        """`g1`'s LOW instance was never asked about and is the one dedupe kept. `g2`'s
        instance of the same id was asked about and got no answer: it is owed, and it
        would come back, as the same unverified claim a second time. It stays merged,
        and it is still one unanswered finding."""
        report, _low = self._with_a_low_claim_in_a_cell_below_the_gate(
            same_id=True, owner=("LOW", None))
        self.assertEqual([("g1's", "unverified")],
                         [(f["description"], f["evidence"]["status"])
                          for f in report["findings"] if f["id"] == self.b])
        self.assertEqual(["1 finding unanswered by its verify advisor"],
                         report["summary"]["grade_shortfalls"])

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


GROUPS3 = GROUPS + [{"name": "g3", "files": ["c.py"]}]


class TestTheMergeRanksByThePublishedSeverity(_Verdicts):
    """#3727. Dedupe ranked by the severity a reviewer claimed, and the controller lowers
    a severity only afterwards: an override with no reason resets it to its code's
    default (`ARC-A2D` is LOW), and a `TST-A1*` claim is capped at MEDIUM where no test
    can witness it. So a hostile cell claimed CRITICAL and CERTAIN at another cell's
    confirmed CRITICAL, won the merge, and was then demoted: the real finding was in
    neither list, and the run was PASS, certified, letter A.

    The victim is `g2`'s CRITICAL, CONFIRMED by its own advisor. `g1` is the hostile cell."""

    LEVERS = {"an override with no reason": dict(code="ARC-A2D", severity_override={}),
              "a TST-A1 code": dict(code="TST-A1A")}
    CONTROLS = {"an ordinary code": {},
                "an override with a reason": dict(code="ARC-A2D", severity_override={
                    "from": "LOW", "to": "CRITICAL", "reason": "reachable: from the login form"})}
    FILE = "b.sh"           # not Python, so nothing can witness a TST-A1 claim: it is capped

    def run_of(self, hostile, victim_says="CONFIRMED", hostile_says="CONFIRMED", tool=None,
               victim=True, fail_on="critical"):
        """The report for `g1` holding `hostile` (claims) beside `g2`'s victim, and the
        scanner finding `tool` ((finding, verdict word) or None)."""
        for name in os.listdir(self.verdicts):
            os.unlink(os.path.join(self.verdicts, name))
        files = {"g1": [claim("a.py", severity="LOW")] + list(hostile)}
        if victim:
            files["g2"] = [dict(claim(self.FILE), description="the victim")]
        paths = []
        for group, findings in files.items():
            paths.append(os.path.join(self.run_dir, "findings-%s-SEC.json" % group))
            with open(paths[-1], "w", encoding="utf-8") as fh:
                json.dump({"findings": findings}, fh)
        loaded = findings_mod.load_findings(paths)
        mine = [f for f in loaded if f["_group"] == "g1"]
        bodies = [record(claims=[f["id"] for f in mine], size=25)]
        self.bundle([verdict(mine[0]["id"])] + [verdict(f["id"], hostile_says)
                                                for f in mine[1:] if hostile_says])
        if victim:
            self.victim = loaded[-1]["id"]
            bodies.append(record(group="g2", claims=[self.victim], size=25))
            if victim_says:
                self.bundle([verdict(self.victim, victim_says)], group="g2")
        self.record(*bodies)
        if tool is not None:
            finding, said = tool
            loaded.append(dict(finding))
            if said:
                with open(os.path.join(self.verdicts, "%s.json" % evidence_mod.finding_fingerprint(
                        finding)), "w", encoding="utf-8") as fh:
                    json.dump({"finding_id": finding["id"], "verdict": said, "reasoning": "r"}, fh)
        fs = findings_mod.FindingSet.load(
            types.SimpleNamespace(verdicts_dir=self.verdicts), [], "standard", None,
            prepared=(loaded, None, None), run_dir=self.run_dir)
        with _target_with_files(GROUPS, lines=5000) as target, \
                contextlib.redirect_stderr(io.StringIO()):
            return report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=target, fail_on=fail_on,
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=fs, plan=plan_mod.PlanInputs(groups_meta=GROUPS)))

    @staticmethod
    def rows(report, *descriptions):
        return sorted((f["description"], where, f["severity"], f["evidence"]["status"])
                      for where in ("findings", "discarded_claims") for f in report[where]
                      if f["description"] in descriptions)

    @staticmethod
    def verdict_of(report):
        summary = report["summary"]
        return (summary["gate"], summary["coverage_certified"], summary["overall_grade"],
                summary["provisional_grade"], summary["grade_shortfalls"])

    def hostile(self, title, description, **lever):
        return dict(claim(self.FILE, title=title), confidence="CERTAIN",
                    description=description, **lever)

    VICTIM_ROW = ("the victim", "findings", "CRITICAL", "advisor_confirmed")

    def test_route_a_a_copy_that_will_be_demoted_does_not_win_the_merge(self):
        """The copy has the victim's id (`code` is not part of an id). It was the row
        published for the claim, on the victim's own CONFIRMED, at LOW or MEDIUM."""
        silent = self.run_of([])
        self.assertEqual([self.VICTIM_ROW], self.rows(silent, "the victim"))
        self.assertEqual("FAIL", silent["summary"]["gate"])
        for label, lever in self.LEVERS.items():
            for hostile_says in ("CONFIRMED", "REJECTED", "NEEDS_MORE_INFO"):
                with self.subTest(label, hostile_says=hostile_says):
                    report = self.run_of([self.hostile(None, "the copy", **lever)],
                                         hostile_says=hostile_says)
                    self.assertEqual([self.VICTIM_ROW], self.rows(report, "the victim", "the copy"))
                    self.assertEqual(self.verdict_of(silent), self.verdict_of(report))

    def test_route_a_with_a_silent_hostile_advisor_the_claim_is_still_shown_at_its_severity(self):
        for label, lever in self.LEVERS.items():
            with self.subTest(label):
                report = self.run_of([self.hostile(None, "the copy", **lever)], hostile_says=None)
                self.assertEqual([self.VICTIM_ROW], self.rows(report, "the victim", "the copy"))
                self.assertEqual("FAIL", report["summary"]["gate"])

    def test_route_b_a_confirmed_decoy_that_will_be_demoted_does_not_hide_the_victim(self):
        """Another claim at the victim's line and category, CRITICAL and CERTAIN, and
        CONFIRMED by its own advisor. The victim was in neither list, under a LOW or
        MEDIUM row. The victim is the row: the decoy ranks where it will be published,
        loses the merge, and is merged under a confirmed finding like any other claim."""
        silent = self.run_of([])
        for label, lever in self.LEVERS.items():
            with self.subTest(label):
                report = self.run_of([self.hostile("another reading", "the decoy", **lever)])
                self.assertEqual([self.VICTIM_ROW], self.rows(report, "the victim", "the decoy"))
                self.assertEqual(self.verdict_of(silent), self.verdict_of(report))

    def test_the_widening_a_member_that_is_unsure_or_unanswered_is_not_hidden_either(self):
        """Every finding of another cell that is not REJECTED. The victim's advisor is
        unsure, or says nothing: the report showed a confirmed LOW and nothing else."""
        for victim_says, status in (("NEEDS_MORE_INFO", "needs_more_info"), (None, "unverified")):
            with self.subTest(victim_says=victim_says):
                silent = self.run_of([], victim_says=victim_says)
                report = self.run_of([self.hostile("another reading", "the decoy",
                                                   **self.LEVERS["an override with no reason"])],
                                     victim_says=victim_says)
                self.assertEqual([("the decoy", "findings", "LOW", "advisor_confirmed"),
                                  ("the victim", "findings", "CRITICAL", status)],
                                 self.rows(report, "the victim", "the decoy"))
                self.assertEqual(self.verdict_of(silent), self.verdict_of(report))

    def test_the_controls_a_claim_that_keeps_its_severity_still_wins_the_merge(self):
        """An ordinary code, or an override that carries a reason, is not demoted: the
        copy or the decoy is CRITICAL and CERTAIN, wins as before, and the gate fails
        with a CRITICAL shown."""
        for label, lever in self.CONTROLS.items():
            with self.subTest(label, hostile="a copy"):
                report = self.run_of([self.hostile(None, "the copy", **lever)])
                self.assertEqual([("the copy", "findings", "CRITICAL", "advisor_confirmed")],
                                 self.rows(report, "the victim", "the copy"))
                self.assertEqual("FAIL", report["summary"]["gate"])
            with self.subTest(label, hostile="a decoy"):
                report = self.run_of([self.hostile("another reading", "the decoy", **lever)])
                self.assertEqual([("the decoy", "findings", "CRITICAL", "advisor_confirmed")],
                                 self.rows(report, "the victim", "the decoy"))
                self.assertEqual("FAIL", report["summary"]["gate"])

    def scanner_finding(self, severity="HIGH", file=None):
        return {"id": "TL-1", "title": "tool", "description": "the scanner's", "severity": severity,
                "confidence": "POSSIBLE", "panel": "security", "domain": "SEC",
                "category": "other", "source": "tool:semgrep",
                "tool_evidence": {"tool": "semgrep", "rule_id": "r.tool"},
                "location": {"file": file or self.FILE, "line_start": 1},
                "provenance": {"discovered_by": "tool:semgrep",
                               "confirmation_status": "UNVERIFIED"}}

    def test_route_c_a_demoted_decoy_does_not_hide_a_scanner_finding(self):
        """The decoy sits on a scanner finding's line, in any category, CONFIRMED. The
        HIGH scanner finding became one LOW `tool_confirmed` row: PASS, certified, no
        shortfall. It is the scanner's row, as with no decoy: unanswered and owed
        (INCONCLUSIVE), or CONFIRMED at HIGH (FAIL)."""
        for said, row, gate in ((None, ("the scanner's", "findings", "MEDIUM", "tool_reported"),
                                 "INCONCLUSIVE"),
                                ("CONFIRMED", ("the scanner's", "findings", "HIGH", "tool_confirmed"),
                                 "FAIL")):
            tool = (self.scanner_finding(), said)
            silent = self.run_of([], tool=tool, victim=False, fail_on="high")
            self.assertEqual([row], self.rows(silent, "the scanner's"))
            self.assertEqual(gate, silent["summary"]["gate"])
            for (label, lever), demoted in zip(self.LEVERS.items(), ("LOW", "MEDIUM")):
                with self.subTest(label, tool_says=said):
                    report = self.run_of([self.hostile("a decoy", "the decoy", **lever)],
                                         tool=tool, victim=False, fail_on="high")
                    # Under a CONFIRMED scanner row the decoy is merged, as any claim is.
                    # Under one nobody answered for, the confirmed decoy is its own row.
                    decoy = [] if said else [("the decoy", "findings", demoted, "advisor_confirmed")]
                    self.assertEqual(decoy + [row], self.rows(report, "the scanner's", "the decoy"))
                    self.assertEqual(self.verdict_of(silent), self.verdict_of(report))
                    axis = report["meta"]["coverage"]["tool_axis"]
                    self.assertEqual((1, int(said is None)), (axis["queued"], axis["unanswered"]))

    def uncapped_claim(self, severity, claim_says=None, tool_says=None, verify=True, scanner=True):
        """The rows for a `TST-A1A` claim at `severity` on a Python module no test names
        (so it is not capped), with a scanner finding at the same severity on its line.
        No hostile cell. With `verify` off there is no verify phase at all."""
        for name in os.listdir(self.verdicts):
            os.unlink(os.path.join(self.verdicts, name))
        path = os.path.join(self.run_dir, "findings-g2-SEC.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"findings": [dict(claim("b.py", severity=severity), code="TST-A1A",
                                         description="the claim")]}, fh)
        loaded = findings_mod.load_findings([path])
        self.record(record(group="g2", claims=[loaded[0]["id"]], size=25))
        if claim_says:
            self.bundle([verdict(loaded[0]["id"], claim_says)], group="g2")
        if scanner:
            tool = self.scanner_finding(severity, file="b.py")
            loaded.append(tool)
            if tool_says:
                with open(os.path.join(self.verdicts, "%s.json" % evidence_mod.finding_fingerprint(
                        tool)), "w", encoding="utf-8") as fh:
                    json.dump({"finding_id": tool["id"], "verdict": tool_says, "reasoning": "r"}, fh)
        fs = findings_mod.FindingSet.load(
            types.SimpleNamespace(verdicts_dir=self.verdicts if verify else None), [], "standard",
            None, prepared=(loaded, None, None), run_dir=self.run_dir if verify else None)
        with _target_with_files(GROUPS, lines=5000) as target, \
                contextlib.redirect_stderr(io.StringIO()):
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=target, fail_on="high",
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=fs, plan=plan_mod.PlanInputs(groups_meta=GROUPS)))
        return self.rows(report, "the claim", "the scanner's")

    def test_an_uncapped_tst_a1_claim_is_not_shown_as_the_scanners_medium(self):
        """#3728 review, F1: an honest run. The claim ranks at its cap for the merge, so
        the scanner finding wins the pair it used to lose, and is then capped at MEDIUM
        for want of a verdict. The pair as one row is the 5.3 behaviour only where the
        scanner finding would have won anyway. Here main shows the claim at its own
        severity, so it comes back beside the scanner's row."""
        for severity in ("HIGH", "CRITICAL"):
            scanner = ("the scanner's", "findings", "MEDIUM")
            for label, how, status, tool_status in (
                    ("no verify phase", dict(verify=False), "unverified", "tool_reported"),
                    ("the claim owed and unanswered, the scanner unanswered", {}, "unverified",
                     "tool_reported"),
                    ("the claim unsure, the scanner unanswered",
                     dict(claim_says="NEEDS_MORE_INFO"), "needs_more_info", "tool_reported"),
                    ("both unsure", dict(claim_says="NEEDS_MORE_INFO",
                                         tool_says="NEEDS_MORE_INFO"),
                     "needs_more_info", "needs_more_info")):
                with self.subTest(label, severity=severity):
                    self.assertEqual([("the claim", "findings", severity, status),
                                      scanner + (tool_status,)], self.uncapped_claim(severity, **how))
            with self.subTest("the claim alone", severity=severity):
                self.assertEqual([("the claim", "findings", severity, "unverified")],
                                 self.uncapped_claim(severity, scanner=False))
            # A scanner finding an advisor CONFIRMED keeps its severity: a tie, one row.
            with self.subTest("the scanner confirmed", severity=severity):
                self.assertEqual([("the scanner's", "findings", severity, "tool_confirmed")],
                                 self.uncapped_claim(severity, tool_says="CONFIRMED"))

    def test_a_claim_ranked_where_it_settles_stays_one_row_with_the_scanners(self):
        """The other side of F1, and the exemption as ruled: an ordinary claim at HIGH and
        a scanner finding at CRITICAL nobody confirmed. The scanner finding wins the
        pair on its own severity, as it always did, and the pair is its one MEDIUM row."""
        # ...and a claim whose empty override RAISES it to its code's default (LOW to
        # HIGH for `SEC-A1A`): it ranks at HIGH and settles at HIGH, so it is the same.
        raised = dict(claim("b.py", severity="LOW"), severity_override={})
        self.assertEqual("HIGH", codes_mod.severity_after_discipline(raised, ocrdb.load_bundle()))
        for label, mine in (("a plain claim", claim("b.py", severity="HIGH")),
                            ("a claim its override raises", raised)):
            with self.subTest(label):
                for name in os.listdir(self.verdicts):
                    os.unlink(os.path.join(self.verdicts, name))
                path = os.path.join(self.run_dir, "findings-g2-SEC.json")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump({"findings": [dict(mine, description="the claim")]}, fh)
                loaded = findings_mod.load_findings([path]) + [
                    self.scanner_finding("CRITICAL", "b.py")]
                fs = findings_mod.FindingSet.load(
                    types.SimpleNamespace(verdicts_dir=None), [], "standard", None,
                    prepared=(loaded, None, None), run_dir=None)
                with _target_with_files(GROUPS, lines=5000) as target, \
                        contextlib.redirect_stderr(io.StringIO()):
                    report = report_mod.build_report(report_mod.ReportInputs(
                        run=report_mod.RunConfig(target=target, fail_on="high",
                                                 timestamp="2026-01-01T00:00:00Z"),
                        findings=fs, plan=plan_mod.PlanInputs(groups_meta=GROUPS)))
                self.assertEqual([("the scanner's", "findings", "MEDIUM", "tool_reported")],
                                 self.rows(report, "the claim", "the scanner's"))

    def test_a_tie_in_final_severity_stays_one_row(self):
        """Two claims that end at one severity are merged as before: the first loaded,
        or the more confident, is the row."""
        report = self.run_of([dict(claim(self.FILE, title="another reading"),
                                   description="the other")])
        self.assertEqual([("the other", "findings", "CRITICAL", "advisor_confirmed")],
                         self.rows(report, "the victim", "the other"))
        # ...and a demoted claim that ends where another claim is, too.
        report = self.run_of([self.hostile("another reading", "the decoy",
                                           **self.LEVERS["a TST-A1 code"])], victim=False,
                             tool=None)
        self.assertEqual([("the decoy", "findings", "MEDIUM", "advisor_confirmed")],
                         self.rows(report, "the decoy"))

    def test_an_uncapped_tst_a1_claim_comes_back_from_under_a_lower_row(self):
        """A `TST-A1*` claim ranks at its cap for the merge, because whether the cap
        applies needs the run. On a Python module no test names or imports, it is not
        capped. Left under the MEDIUM row that won the tie, a HIGH claim would be shown
        as MEDIUM, so it comes back, unless its own advisor REJECTED it."""
        def scene(said, same_claim=False, plain="MEDIUM", certain=False):
            theirs = dict(claim("b.py", title="untested", severity="HIGH"), code="TST-A1A",
                          description="the TST claim", **({"confidence": "CERTAIN"} if certain else {}))
            for name in os.listdir(self.verdicts):
                os.unlink(os.path.join(self.verdicts, name))
            paths = []
            mine = dict(claim("b.py", title="untested" if same_claim else None, severity=plain),
                        **({"confidence": "POSSIBLE"} if certain else {}))
            for group, findings in (("g1", [dict(mine, description="the MEDIUM")]),
                                    ("g2", [theirs])):
                paths.append(os.path.join(self.run_dir, "findings-%s-SEC.json" % group))
                with open(paths[-1], "w", encoding="utf-8") as fh:
                    json.dump({"findings": findings}, fh)
            loaded = findings_mod.load_findings(paths)
            self.record(record(claims=[loaded[0]["id"]], size=25),
                        record(group="g2", claims=[loaded[1]["id"]], size=25))
            self.bundle([verdict(loaded[0]["id"])])
            if said:
                self.bundle([verdict(loaded[1]["id"], said)], group="g2")
            fs = findings_mod.FindingSet.load(
                types.SimpleNamespace(verdicts_dir=self.verdicts), [], "standard", None,
                prepared=(loaded, None, None), run_dir=self.run_dir)
            with _target_with_files(GROUPS, lines=5000) as target, \
                    contextlib.redirect_stderr(io.StringIO()):
                return report_mod.build_report(report_mod.ReportInputs(
                    run=report_mod.RunConfig(target=target, fail_on="critical",
                                             timestamp="2026-01-01T00:00:00Z"),
                    findings=fs, plan=plan_mod.PlanInputs(groups_meta=GROUPS)))
        medium = ("the MEDIUM", "findings", "MEDIUM", "advisor_confirmed")
        for said, status in (("CONFIRMED", "advisor_confirmed"),
                             ("NEEDS_MORE_INFO", "needs_more_info"), (None, "unverified")):
            with self.subTest(said=said):
                self.assertEqual([medium, ("the TST claim", "findings", "HIGH", status)],
                                 self.rows(scene(said), "the MEDIUM", "the TST claim"))
        self.assertEqual([medium], self.rows(scene("REJECTED"), "the MEDIUM", "the TST claim"))
        # An honest change with nothing demoted: beside a plain claim at its own HIGH, the
        # TST claim used to win on confidence. Ranked at its cap it loses, and the two end
        # at one severity, so it stays merged: the row is the plain claim.
        tie = scene("CONFIRMED", plain="HIGH", certain=True)
        self.assertEqual([("the MEDIUM", "findings", "HIGH", "advisor_confirmed")],
                         self.rows(tie, "the MEDIUM", "the TST claim"))
        # The same where the two are instances of ONE claim, filed under different codes:
        # the claim is already in the report on that verdict, at MEDIUM, and the instance
        # that is published higher still comes back. One id, at two severities.
        report = scene("CONFIRMED", same_claim=True)
        self.assertEqual(1, len({f["id"] for f in report["findings"]}))
        self.assertEqual([medium, ("the TST claim", "findings", "HIGH", "advisor_confirmed")],
                         self.rows(report, "the MEDIUM", "the TST claim"))


class TestTheSeverityIsDecidedOnceAndApplied(unittest.TestCase):
    """#3727. The merge and the restore read the severity a finding will be published
    at before anything is applied. They read it from the function that applies it, so
    what is predicted and what is published cannot drift apart."""

    BUNDLE = ocrdb.load_bundle()

    @classmethod
    def ranged(cls):
        """The catalog as OCRDb 0.7 will ship it for one code: `ARC-A2D` (default LOW)
        with a `severity_range`. No shipped code has one today, and with one an agent
        severity that differs from the default needs no override at all to be reset."""
        bundle = copy.deepcopy(cls.BUNDLE)
        bundle["domains"]["ARC"]["entries"]["ARC-A2D"]["severity_range"] = {
            "floor": "INFO", "ceiling": "MEDIUM"}
        return bundle

    def findings(self):
        """Agent claims and scanner findings under every lever: no override, an empty
        one, one with a reason, a low-default code, a `TST-A1*` code, on two files."""
        out = []
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            for code in ("SEC-A1A", "ARC-A2D", "TST-A1A", "NOT-A-CODE"):
                for override in (None, {}, {"reason": ""}, "not an object",
                                 {"from": "LOW", "to": severity, "reason": "reachable: yes"}):
                    for file in ("b.py", "b.sh"):
                        for tool in (False, True):
                            finding = dict(claim(file, severity=severity), code=code,
                                           id="X-%d" % len(out))
                            if override is not None:
                                finding["severity_override"] = override
                            if tool:
                                finding.update(source="tool:semgrep", tool_evidence={
                                    "tool": "semgrep", "rule_id": "r"})
                            out.append(finding)
        return out

    def test_the_discipline_applies_what_it_predicts(self):
        for bundle in (self.BUNDLE, self.ranged(), None):
            for finding in self.findings():
                predicted = codes_mod.severity_after_discipline(finding, bundle)
                applied = copy.deepcopy(finding)
                with contextlib.redirect_stderr(io.StringIO()):
                    codes_mod.apply_verdict_quality([applied], {}, bundle)
                self.assertEqual(predicted, applied["severity"], finding)
        # It changes nothing itself.
        finding = dict(claim("b.py"), code="ARC-A2D", severity_override={})
        before = copy.deepcopy(finding)
        self.assertEqual("LOW", codes_mod.severity_after_discipline(finding, self.BUNDLE))
        self.assertEqual(before, finding)

    def test_the_levers_the_issue_names(self):
        after = codes_mod.severity_after_discipline
        low = dict(claim("b.py"), code="ARC-A2D")
        self.assertEqual("CRITICAL", after(low, self.BUNDLE))                       # no override
        self.assertEqual("LOW", after(dict(low, severity_override={}), self.BUNDLE))
        self.assertEqual("LOW", after(dict(low, severity_override={"reason": ""}), self.BUNDLE))
        self.assertEqual("CRITICAL", after(dict(low, severity_override={
            "reason": "reachable: from the login form"}), self.BUNDLE))
        # A code the catalog does not know has no default to fall to; nor has no catalog.
        self.assertEqual("CRITICAL", after(dict(low, code="NOT-A-CODE", severity_override={}),
                                           self.BUNDLE))
        self.assertEqual("CRITICAL", after(dict(low, severity_override={}), None))

    def test_the_latent_lever_is_covered_when_a_code_carries_a_range(self):
        """`codes.py`'s third lever: with a `severity_range` on the code, an agent
        severity with no override at all reverts to the default. The merge ranks by it
        the day a catalog carries one."""
        ranged, low = self.ranged(), dict(claim("b.py"), code="ARC-A2D", confidence="CERTAIN")
        self.assertEqual("CRITICAL", codes_mod.severity_after_discipline(low, self.BUNDLE))
        self.assertEqual("LOW", codes_mod.severity_after_discipline(low, ranged))
        self.assertEqual(3, corroborate_mod.merge_rank(low, ranged)[0])
        # A scanner's severity is its own axis: never reset.
        self.assertEqual("CRITICAL", codes_mod.severity_after_discipline(
            dict(low, source="tool:semgrep"), ranged))
        # An override with a reason is clamped into the range.
        self.assertEqual("LOW", codes_mod.severity_after_discipline(
            dict(low, severity_override={"reason": "reachable: yes"}), ranged))
        victim = dict(claim("b.py"), id="V", confidence="POSSIBLE")
        decoy = dict(low, id="D", title="decoy")
        self.assertEqual("D", corroborate_mod.dedupe([dict(victim), dict(decoy)], self.BUNDLE)[0]["id"])
        self.assertEqual("V", corroborate_mod.dedupe([dict(victim), dict(decoy)], ranged)[0]["id"])

    def test_the_caps_apply_what_they_predict(self):
        """A claim's row settles where it is published. A scanner finding's settles at
        its severity before the unverified cap, which is all that differs."""
        run = types.SimpleNamespace(gate_unverified=False, root=None, target="/nonexistent")
        strict = types.SimpleNamespace(gate_unverified=True, root=None, target="/nonexistent")
        capped = 0
        for policy in (run, strict):
            caps = severity_cap_mod.Caps(policy, [])
            for finding in self.findings():
                for status in ("unverified", "tool_reported", "needs_more_info",
                               "advisor_confirmed", "tool_confirmed", "rejected"):
                    settled = caps.settled(finding, status, self.BUNDLE)
                    applied = copy.deepcopy(finding)
                    with contextlib.redirect_stderr(io.StringIO()):
                        codes_mod.apply_verdict_quality([applied], {}, self.BUNDLE)
                    disciplined = applied["severity"]
                    applied["evidence"] = {"status": status}
                    severity_cap_mod.apply([applied], policy, [])
                    if (applied.get("severity_cap") or {}).get("reason") == "unverified_tool":
                        capped += 1
                        self.assertEqual((disciplined, "MEDIUM"), (settled, applied["severity"]))
                    else:
                        self.assertEqual(settled, applied["severity"], (finding, status))
        self.assertGreater(capped, 0)

    def test_the_merge_ranks_a_finding_where_it_can_be_published(self):
        rank = corroborate_mod.merge_rank
        plain = dict(claim("b.py"), confidence="LIKELY")
        self.assertEqual((0, 1), rank(plain, self.BUNDLE))                # CRITICAL, LIKELY
        # An override with no reason: at its code's default.
        self.assertEqual((3, 0), rank(dict(plain, confidence="CERTAIN", code="ARC-A2D",
                                           severity_override={}), self.BUNDLE))
        # A `TST-A1*` claim at CRITICAL or HIGH: at its cap, on any file.
        for severity in ("CRITICAL", "HIGH"):
            for file in ("b.py", "b.sh"):
                self.assertEqual(2, rank(dict(claim(file, severity=severity), code="TST-A1A"),
                                         self.BUNDLE)[0])
        self.assertEqual(3, rank(dict(claim("b.py", severity="LOW"), code="TST-A1A"),
                                 self.BUNDLE)[0])
        # A scanner finding ranks as the scanner said: its cap needs a verdict.
        tool = dict(plain, code="TST-A1A", source="tool:semgrep")
        self.assertEqual(0, rank(tool, self.BUNDLE)[0])
        # `outranks` is the same order, and a tie is False.
        demoted = dict(plain, confidence="CERTAIN", code="ARC-A2D", severity_override={})
        self.assertTrue(corroborate_mod.outranks(plain, demoted, self.BUNDLE))
        self.assertFalse(corroborate_mod.outranks(demoted, plain, self.BUNDLE))
        self.assertFalse(corroborate_mod.outranks(plain, dict(plain), self.BUNDLE))
        self.assertTrue(corroborate_mod.outranks(plain, None, self.BUNDLE))
        self.assertTrue(corroborate_mod.outranks(plain, demoted))          # the vendored catalog
        # With no catalog nothing is known to be demoted: the more confident claim wins.
        self.assertFalse(corroborate_mod.outranks(plain, demoted, None))
        self.assertTrue(corroborate_mod.outranks(demoted, plain, None))

    def test_dedupe_keeps_the_claim_that_will_be_published_higher(self):
        victim = dict(claim("b.py"), id="V", confidence="POSSIBLE")
        decoy = dict(claim("b.py", title="decoy"), id="D", confidence="CERTAIN",
                     code="ARC-A2D", severity_override={})
        for order in ([victim, decoy], [decoy, victim]):
            (kept,) = corroborate_mod.dedupe([dict(f) for f in order])
            self.assertEqual("V", kept["id"])
            self.assertEqual(["D"], [m["id"] for m in kept[corroborate_mod.ABSORBED_FIELD]])
        # Without a catalog nothing is known to be demoted: as claimed, as before.
        (kept,) = corroborate_mod.dedupe([dict(victim), dict(decoy)], None)
        self.assertEqual("D", kept["id"])


class TestNoCellCanMakeAScannerRow(_Verdicts):
    """The two facts the second exemption rests on (#3727): a scanner row's unverified
    cap is not a demotion of the row, and that is safe only because no cell can produce
    such a row, or put under one a claim of another cell that was not under it already."""

    def test_a_cell_cannot_write_a_scanner_finding(self):
        path = os.path.join(self.run_dir, "findings-g1-SEC.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"findings": [dict(claim("b.py"), source="tool:semgrep", reinforced=True,
                                         tool_evidence={"tool": "semgrep", "rule_id": "r"})]}, fh)
        with contextlib.redirect_stderr(io.StringIO()):
            (loaded,) = findings_mod.load_findings([path])
        self.assertNotIn("source", loaded)
        self.assertNotIn("reinforced", loaded)
        self.assertFalse(evidence_mod.is_tool_sourced(loaded))
        self.assertIn("source", findings_mod.AGENT_FORBIDDEN_FIELDS)

    def test_a_third_claim_puts_no_claim_under_the_scanners_row_that_was_not_there(self):
        """One agent claim and one scanner finding at a line collapse into one row. A
        cell that adds a claim there does not put the first claim under the scanner's
        row: where the scanner finding names a rule, the two kinds are then merged
        apart; where it names none and shares the claims' category, they share a
        bucket, and the claim is under the scanner's row exactly as it was without
        the third claim (#3728 review N1)."""
        victim = dict(claim("b.py", severity="HIGH"), id="V", confidence="POSSIBLE")
        third = dict(claim("b.py", title="a third claim", severity="LOW"), id="H")

        def rows(findings):
            return {f["id"]: sorted(m["id"] for m in f.get(corroborate_mod.ABSORBED_FIELD) or ())
                    for f in corroborate_mod.dedupe([dict(f) for f in findings])}

        ruled = {"id": "TL-1", "title": "tool", "severity": "HIGH", "confidence": "CERTAIN",
                 "category": "authz", "source": "tool:semgrep",
                 "tool_evidence": {"tool": "semgrep", "rule_id": "r"},
                 "location": {"file": "b.py", "line_start": 1}}
        self.assertEqual({"TL-1": ["V"]}, rows([victim, ruled]))
        for order in ([victim, third, ruled], [third, victim, ruled], [ruled, third, victim]):
            self.assertEqual({"TL-1": [], "V": ["H"]}, rows(order))
        ruleless = dict(ruled, tool_evidence={"tool": "semgrep"})
        self.assertIsNone(evidence_mod.tool_rule_id(ruleless))
        self.assertEqual({"TL-1": ["V"]}, rows([victim, ruleless]))
        for order in ([victim, third, ruleless], [third, victim, ruleless],
                      [ruleless, third, victim]):
            self.assertEqual({"TL-1": ["H", "V"]}, rows(order))
        # In another category the rule-less scanner finding is apart, as a ruled one is.
        self.assertEqual({"TL-1": [], "V": ["H"]},
                         rows([victim, third, dict(ruleless, category="other")]))


class TestOwedFollowsWhatTheControllerAsked(_Verdicts):
    """Round 3, R1. The driver dispatches by cell FILE and hands the advisors every
    claim in it. So a claim is owed an answer when its cell, the file it was loaded
    from, reaches the verify gate, whatever domain each claim in it declares; and
    whenever the dispatch record says its cell was asked about it."""

    def report(self, paths, fail_on="critical"):
        fs = findings_mod.FindingSet.load(
            types.SimpleNamespace(verdicts_dir=self.verdicts), [], "standard", None,
            prepared=(findings_mod.load_findings(paths), None, None), run_dir=self.run_dir)
        with _target_with_files(GROUPS3, lines=5000) as target, \
                contextlib.redirect_stderr(io.StringIO()):
            return report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=target, fail_on=fail_on,
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=fs, plan=plan_mod.PlanInputs(groups_meta=GROUPS3)))

    def cell_files(self, files):
        for name in os.listdir(self.verdicts):
            os.unlink(os.path.join(self.verdicts, name))
        paths = []
        for group, findings in files.items():
            paths.append(os.path.join(self.run_dir, "findings-%s-SEC.json" % group))
            with open(paths[-1], "w", encoding="utf-8") as fh:
                json.dump({"findings": findings}, fh)
        return paths, findings_mod.load_findings(paths)

    def seats_row(self, declared, with_g1):
        """The seat's row. `findings-g3-SEC.json` holds a LOW copy of claim X and a HIGH
        claim that declares `declared`. g3 was asked about both, answered the HIGH and
        said nothing of X. With `with_g1`, g1 holds X at MEDIUM and CONFIRMS it."""
        high = dict(claim("c.py", title="another", severity="HIGH"),
                    domain=declared, code="%s-A1A" % declared, description="the high")
        files = {"g3": [dict(claim("b.py", title="x", severity="LOW"), description="g3's"), high]}
        if with_g1:
            files["g1"] = [dict(claim("b.py", title="x", severity="MEDIUM"), description="g1's")]
        paths, loaded = self.cell_files(files)
        ids = {f["description"]: f["id"] for f in loaded}
        self.assertEqual(declared, [f["domain"] for f in loaded if f["description"] == "the high"][0])
        bodies = [record(group="g3", claims=[ids["g3's"], ids["the high"]], size=25)]
        self.bundle([verdict(ids["the high"])], group="g3")
        if with_g1:
            self.assertEqual(ids["g1's"], ids["g3's"])
            bodies.append(record(group="g1", claims=[ids["g1's"]], size=25))
            self.bundle([verdict(ids["g1's"])], group="g1")
        self.record(*bodies)
        return self.report(paths)["summary"]

    def test_a_claim_beside_a_high_one_filed_under_another_domain_is_owed_its_answer(self):
        """Scored by declared domain, g3's SEC bucket held the LOW claim alone, below the
        gate, and owed nothing. With g1 confirming its own copy the run was PASS,
        certified, 0 unanswered. It is the run without g1: one finding unanswered. And
        it is the run where the HIGH claim declares SEC, as the rule intends."""
        for declared in ("COD", "SEC"):
            for with_g1 in (True, False):
                with self.subTest(declared=declared, with_g1=with_g1):
                    summary = self.seats_row(declared, with_g1)
                    self.assertEqual(
                        ("INCONCLUSIVE", False, ["1 finding unanswered by its verify advisor"]),
                        (summary["gate"], summary["coverage_certified"],
                         summary["grade_shortfalls"]))

    def one_low_claim(self, body):
        paths, loaded = self.cell_files({"g1": [claim("a.py", severity="LOW")]})
        self.record(body(loaded[0]["id"]))
        return self.report(paths)["summary"]["grade_shortfalls"]

    def test_a_cell_the_record_says_was_asked_owes_its_answer_whatever_it_scores(self):
        owed = ["1 finding unanswered by its verify advisor"]
        # Asked, at either stage, and silent: owed, though one LOW claim is below the gate.
        self.assertEqual(owed, self.one_low_claim(lambda i: record(claims=[i], size=25)))
        self.assertEqual(owed, self.one_low_claim(
            lambda i: record(stage="backup", claims=[i], size=25)))
        # Never dispatched, or dispatched without it: below the gate, owed nothing.
        self.assertEqual([], self.one_low_claim(lambda i: {}))
        self.assertEqual([], self.one_low_claim(lambda i: record(group="g2", claims=[i], size=25)))
        # A record that cannot say (charged, with no scope) changes nothing: the score stands.
        self.assertEqual([], self.one_low_claim(lambda i: {"g1/SEC/primary": 1}))

    def test_the_cell_is_the_file_a_finding_was_loaded_from(self):
        """`Owed` itself: by the file's cell, never by the declared domain; a finding
        loaded from no cell file keeps the older rule."""
        low = {"id": "SEC-1", "severity": "LOW", "domain": "SEC", "_group": "g3",
               evidence_mod.CELL_DOMAIN_FIELD: "SEC"}
        high = {"id": "COD-1", "severity": "HIGH", "domain": "COD", "_group": "g3",
                evidence_mod.CELL_DOMAIN_FIELD: "SEC"}
        owed = verdicts_mod.Owed([low, high])
        self.assertEqual({("g3", "SEC")}, owed.cells)
        self.assertEqual((True, True), (owed(low), owed(high)))
        self.assertEqual(set(), verdicts_mod.Owed([low]).cells)
        self.assertFalse(verdicts_mod.Owed([low])(low))
        # No cell file: a matrix finding by its declared cell, any other finding always.
        declared = {"id": "SEC-2", "severity": "LOW", "domain": "SEC", "_group": "g1"}
        self.assertFalse(verdicts_mod.Owed([declared])(declared))
        self.assertTrue(verdicts_mod.Owed([])({"id": "TL-1", "severity": "LOW"}))


GATE_RANK = {"PASS": 0, "INCONCLUSIVE": 1, "FAIL": 2}
GRADES = ["S", "A", "B", "C", "D", "F", "X"]       # best first
WORDS = (None, "CONFIRMED", "REJECTED", "NEEDS_MORE_INFO")
CONFIRMED_AS = ("advisor_confirmed", "tool_confirmed")


class _Lines(_Verdicts):
    """Runs built from cells and scanner hits at chosen lines of `b.py`."""

    def report_of(self, cells, hits=(), hits_say="CONFIRMED", gate_unverified=False,
                  fail_on="high"):
        """The report for `cells` ({group: [(claim, verdict word or None)]}) and the
        scanner `hits`, which share one verdict (they are one rule: one finding)."""
        for name in os.listdir(self.verdicts):
            os.unlink(os.path.join(self.verdicts, name))
        for name in os.listdir(self.run_dir):
            if name.startswith("findings-"):
                os.unlink(os.path.join(self.run_dir, name))
        paths, bodies = [], []
        for group in sorted(cells):
            paths.append(os.path.join(self.run_dir, "findings-%s-SEC.json" % group))
            with open(paths[-1], "w", encoding="utf-8") as fh:
                json.dump({"findings": [c for c, _said in cells[group]]}, fh)
        loaded = findings_mod.load_findings(paths)
        self.ids = {f["description"]: f["id"] for f in loaded}
        for group in sorted(cells):
            mine = [f for f in loaded if f["_group"] == group]
            bodies.append(record(group=group, claims=[f["id"] for f in mine], size=25))
            self.bundle([verdict(f["id"], said) for f, (_c, said) in zip(mine, cells[group])
                         if said], group=group)
        self.record(*bodies)
        loaded += copy.deepcopy(list(hits))
        if hits and hits_say:
            for fingerprint, finding_id in {(evidence_mod.finding_fingerprint(hit), hit["id"])
                                            for hit in hits}:
                with open(os.path.join(self.verdicts, "%s.json" % fingerprint), "w",
                          encoding="utf-8") as fh:
                    json.dump({"finding_id": finding_id, "verdict": hits_say,
                               "reasoning": "r"}, fh)
        fs = findings_mod.FindingSet.load(
            types.SimpleNamespace(verdicts_dir=self.verdicts), [], "standard", None,
            prepared=(loaded, None, None), run_dir=self.run_dir)
        with _target_with_files(GROUPS, lines=5000) as target, \
                contextlib.redirect_stderr(io.StringIO()):
            return report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=target, fail_on=fail_on,
                                         gate_unverified=gate_unverified,
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=fs, plan=plan_mod.PlanInputs(groups_meta=GROUPS)))

    @staticmethod
    def at(group_file, description, line, end=None, severity="HIGH", title=None, **more):
        location = {"file": group_file, "line_start": line}
        if end is not None:
            location["line_end"] = end
        return dict(claim(group_file, title=title, severity=severity), location=location,
                    description=description, **more)

    @staticmethod
    def hit(line, severity="HIGH", end=None, category="other", rule="r.tool", panel="security"):
        location = {"file": "b.py", "line_start": line}
        if end is not None:
            location["line_end"] = end
        named = "the scanner's" if rule == "r.tool" else "the scanner's %s" % rule
        return {"id": "TL-1" if rule == "r.tool" else "TL-%s" % rule.upper().replace(".", ""),
                "title": "tool", "description": named,
                "severity": severity, "confidence": "POSSIBLE", "panel": panel,
                "domain": "SEC", "category": category, "source": "tool:semgrep",
                "tool_evidence": {"tool": "semgrep", "rule_id": rule}, "location": location,
                "provenance": {"discovered_by": "tool:semgrep",
                               "confirmation_status": "UNVERIFIED"}}

    @staticmethod
    def judged(report):
        """What a cell must not be able to make more lenient: the gate, the
        certification, the letter and the health score."""
        summary = report["summary"]
        return (summary["gate"], summary["coverage_certified"], summary["overall_grade"],
                summary["health"]["score"], summary["health"]["weighted_defect"])

    @staticmethod
    def spans(report, *descriptions):
        return sorted((f["description"], f["severity"], f["evidence"]["status"],
                       f["location"]["line_start"], f["location"].get("line_end"))
                      for f in report["findings"] if f["description"] in descriptions)


class TestAMergeGroupIsCountedOnceAtItsHeaviestFinding(_Lines):
    """#3731. Health is a sum over rows of severity times the lines a row spans, and the
    merge kept the winning row whole. `g2` holds the victim: a HIGH over lines 10 to
    60, CONFIRMED by its own advisor. `g1`, the hostile cell, filed a one-line claim at
    line 10 that won the merge, and the victim's weight fell from 1,250 to 25: the
    letter rose with a confirmed finding still in the report.

    A merge group is counted once, at the heaviest of its findings that count on their
    own. No row's range or severity changes."""

    def victim(self, **more):
        return self.at("b.py", "the victim", 10, end=60, **more)

    def silent(self):
        report = self.report_of({"g2": [(self.victim(), "CONFIRMED")]})
        self.assertEqual([("the victim", "HIGH", "advisor_confirmed", 10, 60)],
                         self.spans(report, "the victim"))
        self.assertEqual(1250, report["summary"]["health"]["weighted_defect"])
        return report

    def test_a_one_line_copy_does_not_lighten_the_claim(self):
        """The copy has the victim's id (a line range is not part of one) and is
        CERTAIN, so it is the instance shown, on the victim's CONFIRMED."""
        silent = self.silent()
        for hostile_says in ("CONFIRMED", None, "NEEDS_MORE_INFO", "REJECTED"):
            with self.subTest(hostile_says=hostile_says):
                copy_ = self.at("b.py", "the copy", 10, confidence="CERTAIN")
                report = self.report_of({"g1": [(copy_, hostile_says)],
                                         "g2": [(self.victim(), "CONFIRMED")]})
                self.assertEqual(self.ids["the copy"], self.ids["the victim"])
                rows = self.spans(report, "the victim", "the copy")
                self.assertEqual([("the copy", "HIGH", "advisor_confirmed", 10, 10)], rows)
                if hostile_says is None:    # its own cell owes an answer: not certified
                    self.assertEqual((False, None), self.judged(report)[1:3])
                    self.assertEqual(self.judged(silent)[3:], self.judged(report)[3:])
                else:
                    self.assertEqual(self.judged(silent), self.judged(report))

    def test_the_row_says_whose_weight_it_carries(self):
        report = self.report_of({"g1": [(self.at("b.py", "the copy", 10, confidence="CERTAIN"),
                                         "CONFIRMED")],
                                 "g2": [(self.victim(), "CONFIRMED")]})
        row, = report["findings"]
        self.assertEqual({"id": self.ids["the victim"], "weight": 1250}, row["weight_from"])
        self.assertEqual([], [key for key in row if key.startswith("_")])
        # ...and a row that weighs what it says weighs it says nothing.
        for key in ("weight_from", "weight_with"):
            self.assertNotIn(key, self.silent()["findings"][0])

    def test_a_confirmed_one_line_decoy_does_not_lighten_it_either(self):
        """Another claim at the line, CONFIRMED by its own advisor and CERTAIN: it is
        the row, and the victim is merged under a confirmed finding as any claim is."""
        silent = self.silent()
        decoy = self.at("b.py", "the decoy", 10, title="another reading", confidence="CERTAIN")
        report = self.report_of({"g1": [(decoy, "CONFIRMED")],
                                 "g2": [(self.victim(), "CONFIRMED")]})
        self.assertEqual([("the decoy", "HIGH", "advisor_confirmed", 10, 10)],
                         self.spans(report, "the victim", "the decoy"))
        self.assertEqual(self.judged(silent), self.judged(report))

    def test_the_instance_that_comes_back_weighs_as_the_one_it_stands_for(self):
        """Under a decoy that is not confirmed, the claim comes back, and of its two
        instances the one the merge would keep: the CERTAIN one-line copy."""
        silent = self.silent()
        decoy = self.at("b.py", "the decoy", 10, title="another reading", severity="CRITICAL",
                        confidence="CERTAIN")
        copy_ = self.at("b.py", "the copy", 10, confidence="CERTAIN")
        report = self.report_of({"g1": [(decoy, "NEEDS_MORE_INFO"), (copy_, None)],
                                 "g2": [(self.victim(), "CONFIRMED")]})
        self.assertEqual([("the copy", "HIGH", "advisor_confirmed", 10, 10),
                          ("the decoy", "CRITICAL", "needs_more_info", 10, 10)],
                         self.spans(report, "the victim", "the copy", "the decoy"))
        self.assertEqual(silent["summary"]["health"], report["summary"]["health"])
        # The row that stands for the victim says whose weight it carries. The decoy
        # weighs nothing: it carries no weight and is not said to be counted with one.
        rows = {f["description"]: f for f in report["findings"]}
        self.assertEqual({"id": self.ids["the victim"], "weight": 1250},
                         rows["the copy"]["weight_from"])
        for key in ("weight_from", "weight_with"):
            self.assertNotIn(key, rows["the decoy"])

    def test_of_two_instances_of_a_claim_the_one_published_higher_comes_back(self):
        """#3727, pinned by name (the property test's stream used to reach it, and no
        longer does). One claim, filed twice: as an uncapped `TST-A1*` HIGH, which the
        merge ranks at MEDIUM, and as a plain MEDIUM that is CERTAIN, which outranks
        it. Under a decoy that is not confirmed, one instance comes back: the one
        published at the higher severity, not the one the merge would keep."""
        decoy = self.at("b.py", "the decoy", 10, title="another reading", severity="CRITICAL",
                        confidence="CERTAIN")
        plain = self.at("b.py", "the plain copy", 10, severity="MEDIUM", confidence="CERTAIN")
        untested = dict(self.at("b.py", "the untested", 10, confidence="POSSIBLE"),
                        code="TST-A1A")
        report = self.report_of({"g1": [(decoy, "NEEDS_MORE_INFO"), (plain, "CONFIRMED")],
                                 "g2": [(untested, "CONFIRMED")]})
        self.assertEqual(self.ids["the plain copy"], self.ids["the untested"])
        self.assertEqual([("the decoy", "CRITICAL", "needs_more_info", 10, 10),
                          ("the untested", "HIGH", "advisor_confirmed", 10, 10)],
                         self.spans(report, "the decoy", "the plain copy", "the untested"))
        self.assertEqual("FAIL", report["summary"]["gate"])

    def test_nothing_is_mixed_and_a_third_cell_cannot_unmix_it(self):
        """Two confirmed claims at one line: a CRITICAL on one line (125) and a HIGH over
        50 lines (1,250). The group weighs 1,250, one finding's own weight, and not the
        CRITICAL's severity on the HIGH's span (6,250). A hostile CRITICAL that its own
        advisor rejects wins the merge and is discarded, so both come back as rows:
        the group is still counted once. As two rows' sum it read 1,375."""
        narrow = self.at("b.py", "the critical", 10, severity="CRITICAL", title="other")
        cells = {"g2": [(self.victim(), "CONFIRMED"), (narrow, "CONFIRMED")]}
        silent = self.report_of(cells)
        self.assertEqual([("the critical", "CRITICAL", "advisor_confirmed", 10, 10)],
                         self.spans(silent, "the victim", "the critical"))
        self.assertEqual(1250, silent["summary"]["health"]["weighted_defect"])
        spoiler = self.at("b.py", "the spoiler", 10, severity="CRITICAL", title="third",
                          confidence="CERTAIN")
        report = self.report_of(dict(cells, g1=[(spoiler, "REJECTED")]))
        self.assertEqual([("the critical", "CRITICAL", "advisor_confirmed", 10, 10),
                          ("the victim", "HIGH", "advisor_confirmed", 10, 60)],
                         self.spans(report, "the victim", "the critical"))
        self.assertEqual(self.judged(silent), self.judged(report))
        light = next(f for f in report["findings"] if f["description"] == "the critical")
        self.assertEqual(self.ids["the victim"], light["weight_with"])

    def test_a_claim_that_covers_two_counted_rows_does_not_lower_their_weight(self):
        """On main today: an uncapped `TST-A1*` HIGH comes back beside the confirmed
        MEDIUM that won their tie (#3728), and health added the two rows, 25 + 5. A
        hostile plain HIGH at the line, CONFIRMED by its own advisor, covers both, and
        the group weighed 25: the run scored better with the hostile cell in it."""
        medium = self.at("b.py", "the medium", 10, severity="MEDIUM", confidence="CERTAIN")
        untested = dict(self.at("b.py", "the untested", 10, title="untested"), code="TST-A1A")
        cells = {"g2": [(medium, "CONFIRMED"), (untested, "CONFIRMED")]}
        silent = self.report_of(cells)
        self.assertEqual([("the medium", "MEDIUM", "advisor_confirmed", 10, 10),
                          ("the untested", "HIGH", "advisor_confirmed", 10, 10)],
                         self.spans(silent, "the medium", "the untested"))
        cover = self.at("b.py", "the cover", 10, title="third", confidence="CERTAIN")
        report = self.report_of(dict(cells, g1=[(cover, "CONFIRMED")]))
        self.assertEqual([("the cover", "HIGH", "advisor_confirmed", 10, 10)],
                         self.spans(report, "the medium", "the untested", "the cover"))
        self.assertGreaterEqual(report["summary"]["health"]["weighted_defect"],
                                silent["summary"]["health"]["weighted_defect"])
        self.assertEqual(25, silent["summary"]["health"]["weighted_defect"])    # once, the heavier

    def test_a_range_that_ends_before_it_starts_is_one_line(self):
        """`line_end: 1` on a claim at line 52. One reader took the end line and
        the health weight did not; the loader now leaves no such range."""
        path = os.path.join(self.run_dir, "findings-g1-SEC.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"findings": [self.at("b.py", "inverted", 52, end=1),
                                    self.at("b.py", "a range", 52, end=60, title="other"),
                                    self.at("b.py", "one line", 7, title="third")]}, fh)
        said = io.StringIO()
        with contextlib.redirect_stderr(said):
            loaded = findings_mod.load_findings([path])
        self.assertEqual([(52, 52), (52, 60), (7, 7)],
                         [(f["location"]["line_start"], f["location"]["line_end"])
                          for f in loaded])
        # The repair is announced, once, for the finding it was made to.
        self.assertEqual(["findings: b.py:52: line_end 1 is before line_start 52 -- read as "
                          "one line"],
                         [line for line in said.getvalue().splitlines() if "line_end" in line])

    def test_a_member_that_does_not_count_on_its_own_adds_nothing(self):
        """As ruled (a): the group weighs as its heaviest finding that would count for
        the gate as its own row. A confirmed scanner finding on one line, and a claim
        over 50 lines that nobody was asked about, are the pair they always were."""
        wide = self.at("b.py", "the claim", 10, end=60, severity="LOW")
        report = self.report_of({"g2": [(wide, None)]}, hits=[self.hit(10)])
        self.assertEqual([("the scanner's", "HIGH", "tool_confirmed", 10, None)],
                         self.spans(report, "the scanner's", "the claim"))
        self.assertEqual(25, report["summary"]["health"]["weighted_defect"])
        self.assertNotIn("weight_from", report["findings"][0])
        # Where an unconfirmed finding counts (`--gate-unverified`), the claim's own
        # weight does: a LOW over 50 lines, which is more than a HIGH on one.
        report = self.report_of({"g2": [(wide, None)]}, hits=[self.hit(10)], gate_unverified=True)
        self.assertEqual([("the scanner's", "HIGH", "tool_confirmed", 10, None)],
                         self.spans(report, "the scanner's", "the claim"))
        self.assertEqual(50, report["summary"]["health"]["weighted_defect"])
        self.assertEqual({"id": self.ids["the claim"], "weight": 50},
                         report["findings"][0]["weight_from"])

    def test_an_absorbed_scanner_finding_weighs_with_the_confirmed_claim_over_it(self):
        """No advisor is asked about a scanner finding that a claim absorbed: the verify
        queue is built on the merged list. Alone, asked and CONFIRMED, a HIGH with a
        40-line hit weighs 1,000. Under a one-line CONFIRMED claim the pair was
        confirmed as one (the row is `tool_confirmed`), and weighs the same. Weighed
        on its own missing verdict it weighed nothing, and the group 25."""
        hits = [self.hit(10, end=49)]
        alone = self.report_of({}, hits=hits)
        self.assertEqual(1000, alone["summary"]["health"]["weighted_defect"])
        claim_ = self.at("b.py", "the claim", 10, confidence="CERTAIN")
        report = self.report_of({"g1": [(claim_, "CONFIRMED")]}, hits=hits, hits_say=None)
        row, = report["findings"]
        self.assertEqual(("the claim", "tool_confirmed", {"id": "TL-1", "weight": 1000}),
                         (row["description"], row["evidence"]["status"], row["weight_from"]))
        self.assertEqual(alone["summary"]["health"], report["summary"]["health"])

    def test_under_a_claim_that_is_not_confirmed_it_does_not_count_as_confirmed(self):
        """The other direction: an unsure, silent or dismissed claim confirms nothing.
        The scanner finding has no answer, weighs nothing, and the run says it is owed
        one."""
        hits = [self.hit(10, end=49)]
        for said in ("NEEDS_MORE_INFO", None, "REJECTED"):
            with self.subTest(claim_says=said):
                claim_ = self.at("b.py", "the claim", 10, confidence="CERTAIN")
                report = self.report_of({"g1": [(claim_, said)]}, hits=hits, hits_say=None)
                self.assertEqual(0, report["summary"]["health"]["weighted_defect"])
                self.assertEqual(("INCONCLUSIVE", False), (
                    report["summary"]["gate"], report["summary"]["coverage_certified"]))
                self.assertEqual([], [f["description"] for f in report["findings"]
                                      if f["evidence"]["status"] in CONFIRMED_AS])

    def test_a_scanner_finding_with_an_answer_of_its_own_is_weighed_on_that(self):
        """Only a finding nobody was asked about is covered. Where its own advisor's
        verdict is on file (a verify round before the claim was filed), that verdict
        stands: REJECTED, it weighs nothing under a CONFIRMED claim."""
        hits = [self.hit(10, end=49)]
        claim_ = self.at("b.py", "the claim", 10, confidence="CERTAIN")
        for said, weight in (("REJECTED", 25), ("NEEDS_MORE_INFO", 25), ("CONFIRMED", 1000)):
            with self.subTest(scanner_says=said):
                report = self.report_of({"g1": [(claim_, "CONFIRMED")]}, hits=hits, hits_say=said)
                self.assertEqual(weight, report["summary"]["health"]["weighted_defect"])

    def test_a_third_claim_that_wins_the_merge_and_says_nothing_does_not_uncover_it(self):
        """A scanner finding that names no rule shares the claims' bucket. Beside one
        CONFIRMED claim it weighs as confirmed. A hostile CRITICAL at the line, with no
        verdict, wins the merge: the confirmed claim comes back, the scanner finding
        stays under the silent one, and any CONFIRMED finding of the group still covers
        it. Covered by the survivor alone, the group fell from 1,000 to 25."""
        ruleless = self.hit(10, end=49, category="authz")
        ruleless["tool_evidence"] = {"tool": "semgrep"}
        mine = (self.at("b.py", "the claim", 10), "CONFIRMED")
        silent = self.report_of({"g2": [mine]}, hits=[ruleless], hits_say=None)
        self.assertEqual(1000, silent["summary"]["health"]["weighted_defect"])
        spoiler = self.at("b.py", "the spoiler", 10, severity="CRITICAL", title="third",
                          confidence="CERTAIN")
        report = self.report_of({"g2": [mine], "g1": [(spoiler, None)]}, hits=[ruleless],
                                hits_say=None)
        self.assertEqual(["the claim", "the spoiler"],
                         sorted(f["description"] for f in report["findings"]))
        self.assertEqual(1000, report["summary"]["health"]["weighted_defect"])

    def test_a_claim_of_the_scanner_findings_category_takes_it_from_a_confirmed_pair(self):
        """The review seat's case. A scanner HIGH that names no rule, over lines 300 to
        349, category authz, is a pair with `g2`'s one-line CONFIRMED HIGH of another
        category: confirmed as one, 1,250. `g1` files a CRITICAL authz claim at the
        line and says nothing: three findings, no pair, and the scanner finding shares
        that claim's bucket. Nobody was asked about it in either run. With `g1` it has
        no confirmed claim over it and weighs nothing, and that run is closed."""
        ruleless = self.hit(300, end=349, category="authz")
        ruleless["tool_evidence"] = {"tool": "semgrep"}
        mine = (self.at("b.py", "the claim", 300, category="other"), "CONFIRMED")
        silent = self.report_of({"g2": [mine]}, hits=[ruleless], hits_say=None)
        self.assertEqual(("FAIL", True, 1250), (
            silent["summary"]["gate"], silent["summary"]["coverage_certified"],
            silent["summary"]["health"]["weighted_defect"]))
        taker = self.at("b.py", "the taker", 300, severity="CRITICAL", title="third",
                        confidence="CERTAIN")
        report = self.report_of({"g2": [mine], "g1": [(taker, None)]}, hits=[ruleless],
                                hits_say=None)
        summary = report["summary"]
        self.assertEqual(25, summary["health"]["weighted_defect"])
        self.assertEqual(("FAIL", False, None), (
            summary["gate"], summary["coverage_certified"], summary["overall_grade"]))
        self.assertTrue([reason for reason in summary["grade_shortfalls"]
                         if "unanswered" in reason], summary["grade_shortfalls"])
        self.assertEqual([("the claim", "HIGH", "advisor_confirmed", 300, 300),
                          ("the taker", "CRITICAL", "tool_reported", 300, 300)],
                         self.spans(report, "the claim", "the taker", "the scanner's"))

    def test_a_reviewer_cannot_write_the_controllers_weight_and_severity_fields(self):
        """`weight_from`, `weight_with` and `severity_from` are what the controller says
        of a merge group and of an aggregated finding. A claim written with them is
        published without them, and the loader says it stripped them."""
        forged = dict(self.at("b.py", "the claim", 10), weight_from={"id": "X", "weight": 0},
                      weight_with="X", severity_from={"file": "b.py", "line_start": 1,
                                                      "shown_hit_severity": "LOW"})
        path = os.path.join(self.run_dir, "findings-g1-SEC.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"findings": [forged]}, fh)
        said = io.StringIO()
        with contextlib.redirect_stderr(said):
            loaded, = findings_mod.load_findings([path])
        for key in ("weight_from", "weight_with", "severity_from"):
            self.assertNotIn(key, loaded)
            self.assertIn("stripped self-asserted %r" % key, said.getvalue())
        report = self.report_of({"g1": [(forged, "CONFIRMED")]})
        row, = report["findings"]
        self.assertEqual([], [key for key in ("weight_from", "weight_with", "severity_from")
                              if key in row])
        self.assertEqual(25, report["summary"]["health"]["weighted_defect"])

    def test_what_a_reviewer_writes_as_other_lines_is_not_weighed(self):
        """`additional_loci` is the scanner aggregation's field. On a claim it is carried
        for the reader, and a reviewer's own is not read: the claim weighs as its range."""
        padded = dict(self.at("b.py", "the claim", 10), additional_loci=[
            {"file": "b.py", "line_start": 300, "line_end": 349}])
        report = self.report_of({"g2": [(padded, "CONFIRMED")]})
        self.assertEqual(25, report["summary"]["health"]["weighted_defect"])

    def test_the_gate_and_the_merge_ask_one_question(self):
        """`counts_on_its_own` is what `_partition_gate` filters by: every status,
        under each gate policy."""
        statuses = ("advisor_confirmed", "tool_confirmed", evidence_mod.BACKUP_SCOPE_LIMITED,
                    "tool_reported", "unverified", "needs_more_info", "rejected")
        for gate_unverified in (False, True):
            run = types.SimpleNamespace(gate_unverified=gate_unverified)
            for status in statuses:
                finding = {"evidence": {"status": status}}
                parts = verdicts_mod._partition_gate([finding], run)
                self.assertEqual(bool(parts.gate_eligible),
                                 verdicts_mod.counts_on_its_own(status, run), status)
        self.assertEqual(
            {"advisor_confirmed", "tool_confirmed", evidence_mod.BACKUP_SCOPE_LIMITED},
            {s for s in statuses
             if verdicts_mod.counts_on_its_own(s, types.SimpleNamespace(gate_unverified=False))})
        self.assertEqual(
            set(statuses) - {"rejected"},
            {s for s in statuses
             if verdicts_mod.counts_on_its_own(s, types.SimpleNamespace(gate_unverified=True))})


class TestAnAggregatedFindingCarriesItsWorstHit(_Lines):
    """#3732. A scanner rule's hits in one file are one finding. The hit shown is the
    lowest line, or a line an agent flagged, and the finding kept that hit's severity
    and span: a rule that fired LOW at line 10 and CRITICAL at line 300 was one LOW
    finding, PASS and letter A, with no hostile cell at all."""

    def test_the_worst_hit_gives_the_severity_whichever_line_it_is_on(self):
        for low, critical in ((10, 300), (300, 10)):
            with self.subTest(low_at=low):
                hits = [self.hit(low, "LOW"), self.hit(critical, "CRITICAL")]
                for order in (hits, hits[::-1]):
                    report = self.report_of({}, hits=order)
                    row, = report["findings"]
                    self.assertEqual(("CRITICAL", "tool_confirmed", 10, 2),
                                     (row["severity"], row["evidence"]["status"],
                                      row["location"]["line_start"], row["occurrences"]))
                    self.assertEqual("FAIL", report["summary"]["gate"])
                    if critical == 10:      # the shown hit is the worst: nothing to say
                        self.assertNotIn("severity_from", row)
                    else:
                        self.assertEqual({"file": "b.py", "line_start": 300,
                                          "shown_hit_severity": "LOW"}, row["severity_from"])

    def test_the_finding_weighs_as_its_widest_hit(self):
        """...whichever hit is shown. The other hits keep their end line."""
        for wide in (10, 300):
            with self.subTest(wide_at=wide):
                hits = [self.hit(line, end=line + 39 if line == wide else None)
                        for line in (10, 300)]
                report = self.report_of({}, hits=hits)
                row, = report["findings"]
                self.assertEqual(25 * 40, report["summary"]["health"]["weighted_defect"])
                self.assertEqual([{"file": "b.py", "line_start": 300}
                                  if wide == 10 else
                                  {"file": "b.py", "line_start": 300, "line_end": 339}],
                                 row["additional_loci"])

    def test_no_claim_at_any_hit_moves_the_finding_or_changes_what_it_weighs(self):
        """A claim at the line of a hit used to move the finding there (#3731: that let
        one cell change how many findings sat on a line it never touched). The shown
        line, the severity and the weight are the same with no claim, and with a claim
        at either hit that its own advisor rejects, for both orders of the hits."""
        for low, critical in ((10, 300), (300, 10)):
            hits = [self.hit(low, "LOW", end=low + 9), self.hit(critical, "CRITICAL")]
            silent = self.report_of({}, hits=hits)
            shown = [(f["description"], f["location"]["line_start"], f["severity"],
                      f["evidence"]["status"], f["occurrences"]) for f in silent["findings"]]
            self.assertEqual([("the scanner's", 10, "CRITICAL", "tool_confirmed", 2)], shown)
            self.assertEqual(125 * 10, silent["summary"]["health"]["weighted_defect"])
            for line in (10, 300):
                for category in ("other", "authz"):     # the hits' own category, and another
                    with self.subTest(low_at=low, claim_at=line, claim_in=category):
                        steer = self.at("b.py", "the claim", line, severity="LOW",
                                        category=category)
                        report = self.report_of({"g1": [(steer, "REJECTED")]}, hits=hits)
                        self.assertEqual(shown, [
                            (f["description"], f["location"]["line_start"], f["severity"],
                             f["evidence"]["status"], f["occurrences"])
                            for f in report["findings"]])
                        self.assertEqual(self.judged(silent), self.judged(report))

    def test_a_claim_at_the_low_hit_does_not_choose_the_severity(self):
        """The issue's case: CRITICAL at 10 and LOW at 300, and a LOW claim at 300 that
        its own advisor confirms. The scanner finding was shown at LOW, at line 300.
        It is the CRITICAL at line 10, and the claim is its own row."""
        hits = [self.hit(10, "CRITICAL"), self.hit(300, "LOW")]
        silent = self.report_of({}, hits=hits)
        claim_ = self.at("b.py", "the claim", 300, severity="LOW", category="other")
        report = self.report_of({"g1": [(claim_, "CONFIRMED")]}, hits=hits)
        self.assertEqual([("the claim", "LOW", "advisor_confirmed", 300, 300),
                          ("the scanner's", "CRITICAL", "tool_confirmed", 10, None)],
                         self.spans(report, "the scanner's", "the claim"))
        self.assertEqual(self.judged(silent)[:3], self.judged(report)[:3])
        self.assertEqual(126, report["summary"]["health"]["weighted_defect"])

    def test_a_counted_scanner_finding_under_a_claim_still_weighs_as_its_widest_hit(self):
        """A claim at the first hit's line absorbs the scanner finding, and both are
        CONFIRMED, so it stays merged. The group weighs as its heaviest finding: the
        scanner finding's HIGH over its 40-line hit (1,000), not the claim's one line
        (125)."""
        hits = [self.hit(52), self.hit(300, end=339)]
        for category in ("authz", "other"):     # another category, and the hits' own
            with self.subTest(claim_in=category):
                claim_ = self.at("b.py", "the claim", 52, severity="CRITICAL",
                                 category=category, confidence="CERTAIN")
                report = self.report_of({"g1": [(claim_, "CONFIRMED")]}, hits=hits)
                row, = report["findings"]
                self.assertEqual(("the claim", "CRITICAL", 52), (
                    row["description"], row["severity"], row["location"]["line_start"]))
                self.assertEqual({"id": "TL-1", "weight": 1000}, row["weight_from"])
                self.assertEqual(1000, report["summary"]["health"]["weighted_defect"])


class TestACellCanOnlySplitAMergeGroup(_Lines):
    """#3731, the fact the group weight rests on: adding any one cell's findings never
    puts two other findings into one merge group that were apart without it. Then a
    group's weight, a maximum, can only become a sum of maxima.

    It was false. An agent's line chose which hit of an aggregated scanner finding was
    shown, so a claim moved a scanner finding from one line to another, and changed
    how many findings sat on a line its cell never touched."""

    @staticmethod
    def groups(findings):
        """The merge groups, as the merge itself records them: each survivor with what
        it absorbed, by description."""
        merged, _integration = corroborate_mod.prepare_for_queue(copy.deepcopy(findings))
        return {frozenset([row["description"]] + [member["description"] for member in
                                                   row.get(corroborate_mod.ABSORBED_FIELD) or ()])
                for row in merged}

    def joined(self, findings, cell):
        """The pairs of other cells' findings that are in one group with `cell`'s
        findings there, and apart without them."""
        less = [f for f in findings if f.get("_group") != cell]
        there = {f["description"] for f in less}
        without = self.groups(less)
        return sorted((x, y) for group in self.groups(findings)
                      for x, y in itertools.combinations(sorted(group & there), 2)
                      if not any(x in apart and y in apart for apart in without))

    def claim_of(self, cell, description, line, category):
        return dict(self.at("b.py", description, line, category=category, title=description),
                    _group=cell, source="agent:panel", panel="security", id=description)

    def test_a_claim_at_a_lower_hit_does_not_leave_a_pair_behind(self):
        """Rule `r2` fires at 10 and 300, rule `r1` at 300, and `g1` has a claim at 300.
        `r2` was shown at 300, the line an agent had flagged: three findings there, and
        no pair. `g3` filed a claim at line 10, `r2` was shown there instead, and `r1`
        and `g1`'s claim were exactly two: one pair, made by a cell that touched
        neither. `r2` is shown at 10 either way now, so they are the same pair with and
        without `g3`, in every order the five findings can arrive in."""
        findings = [self.hit(10, rule="r2", category="authz"),
                    self.hit(300, rule="r2", category="authz"),
                    self.hit(300, rule="r1"),
                    self.claim_of("g1", "g1's claim", 300, "other"),
                    self.claim_of("g3", "g3's claim", 10, "authz")]
        pair = frozenset(["the scanner's r1", "g1's claim"])
        for order in itertools.permutations(findings):
            self.assertEqual([], self.joined(list(order), "g3"))
            self.assertEqual({pair, frozenset(["the scanner's r2"])},
                             self.groups([f for f in order if f.get("_group") != "g3"]))
            # ...and `g3`'s claim is a pair with the scanner finding on its first hit.
            self.assertEqual({pair, frozenset(["the scanner's r2", "g3's claim"])},
                             self.groups(list(order)))

    def test_the_run_does_not_score_better_for_it(self):
        """The same case through the report, everything CONFIRMED. `r1` (HIGH, 25) and
        `g1`'s claim (HIGH, 25) were two rows without `g3`'s claim at line 10, and one
        with it: the run weighed 25 less for a claim that touched neither."""
        hits = [self.hit(10, rule="r2", category="authz"),
                self.hit(300, rule="r2", category="authz"), self.hit(300, rule="r1")]
        mine = (self.at("b.py", "g1's claim", 300, category="other"), "CONFIRMED")
        theirs = (self.at("a.py", "g3's claim", 10, severity="LOW"), "CONFIRMED")
        pull = (self.at("b.py", "g3's pull", 10, severity="LOW", title="pull"), "CONFIRMED")
        without = self.report_of({"g2": [mine], "g1": [theirs]}, hits=hits)
        with_it = self.report_of({"g2": [mine], "g1": [theirs, pull]}, hits=hits)
        self.assertGreaterEqual(with_it["summary"]["health"]["weighted_defect"],
                                without["summary"]["health"]["weighted_defect"])
        self.assertLessEqual(with_it["summary"]["health"]["score"],
                             without["summary"]["health"]["score"])

    def test_a_claim_does_not_bring_one_rule_under_two_panels_together(self):
        """One rule filed under two panels merges at one line (#2361). `security` fires
        at 300 only and `redteam` at 10 and 300, so they are apart: the second is
        shown at 10. A claim at 300 used to move it there, beside the first."""
        findings = [dict(self.hit(300, panel="security"), description="under security"),
                    dict(self.hit(10, panel="redteam"), description="under redteam"),
                    dict(self.hit(300, panel="redteam"), description="under redteam"),
                    self.claim_of("g3", "g3's claim", 300, "authz")]
        for order in itertools.permutations(findings):
            self.assertEqual([], self.joined(list(order), "g3"))

    CASES, SEED = 4000, 3731

    def cluster(self, rng, panels):
        findings = []
        for number in range(rng.randint(2, 6)):
            line = rng.choice((10, 300))
            if rng.random() < 0.4:
                rule = rng.choice(("r1", "r2", None))
                category, panel = rng.choice(("authz", "other")), rng.choice(panels)
                found = self.hit(line, rng.choice(("CRITICAL", "HIGH", "LOW")), category=category,
                                 rule=rule or "none", panel=panel)
                if rule is None:        # names no rule: never aggregated
                    found["tool_evidence"] = {"tool": "semgrep"}
                found["description"] = ("tool %s %s %s" % (rule, category, panel) if rule
                                        else "tool %d" % number)
                findings.append(found)
            else:
                cell = rng.choice(("g1", "g2", "g3"))
                findings.append(dict(
                    self.claim_of(cell, "%s claim %d" % (cell, number), line,
                                  rng.choice(("authz", "other"))),
                    severity=rng.choice(("CRITICAL", "HIGH", "LOW")),
                    confidence=rng.choice(("CERTAIN", "POSSIBLE"))))
        return findings

    def test_the_property(self):
        """Random clusters at two lines: claims of three cells in two categories, and
        scanner findings of two rules (and of none) in two categories, under one panel
        or two. For every cell in every case, no two other findings are joined by it."""
        for panels in (("security",), ("security", "redteam")):
            rng, removed = random.Random(self.SEED), 0
            for number in range(self.CASES):
                findings = self.cluster(rng, panels)
                for cell in sorted({f["_group"] for f in findings if f.get("_group")}):
                    removed += 1
                    joined = self.joined(findings, cell)
                    if joined:
                        self.fail("case %d under %s: %s joins %r in %r" % (
                            number, panels, cell, joined,
                            [(f["description"], f["location"]["line_start"], f["category"])
                             for f in findings]))
            self.assertGreater(removed, self.CASES)


class TestRemovingACellNeverMakesTheRunStricter(_Verdicts):
    """Round 2 of the #3711 review, P4: the property that closes the class. Random
    clusters of 2 to 5 findings at one line: review cells that were asked and cells
    with no entry in the dispatch record (below the gate, or refused), copies of one
    id across cells, every severity, a tool finding, every verdict state, bundle
    verdicts for the cells and a queue-id verdict for the tool finding.

    For every cell in a case: with the cell present, the gate is no better, the run is
    no more certified, nothing owed has gone, and no other finding stands better than
    it does with the cell's findings and verdicts removed.

    Standing, strictest first: confirmed; owed an answer and without one; open (unsure,
    or no verdict and none owed); dismissed. A merged finding takes the place of the
    finding it is merged under.

    ONE EXEMPTION, as ruled: a tool finding that stays merged under a claim was never
    asked about (the queue is built on the merged list) and owes nothing while it is
    merged: under a CONFIRMED claim, or under one that is itself owed and unanswered.
    Without the cell it can be alone and unanswered. That one unanswered tool finding
    is not held against the cell. Where the claim was CONFIRMED, and shown no lower
    than the scanner said of its finding, and the tool finding is all that is owed
    without the cell, the INCONCLUSIVE gate and the certification it costs are not
    held against it either. Under an unanswered claim the gate and the certification
    are held as ever: the run is INCONCLUSIVE and uncertified both ways.

    #3727, severity. A claim may carry a lever the controller applies only after the
    merge: an empty `severity_override` on a code whose default is LOW, or a `TST-A1*`
    code on a file no test can witness (capped at MEDIUM). In each run, every finding in
    the report is at its own final severity, worked out here by the rule, and no
    finding that is not REJECTED is merged under a row of lower severity than its own.

    A SECOND EXEMPTION, as ruled: a scanner finding nobody has confirmed is capped at
    MEDIUM, and a claim merged into it may be shown at that. The pair is the scanner's
    row until an advisor confirms it, as #3231 chose. So the row's level is the
    scanner's severity before that cap. It holds only for a claim the merge ranked
    where it settles: an uncapped `TST-A1*` claim ranked at its cap, and is held against
    the row as shown (review F1). No cell can bring the pair about: a cell cannot write
    a scanner finding, and with a third claim at the line a claim is under the scanner's
    row only if it was without it (`TestNoCellCanMakeAScannerRow`).

    The first exemption needs the confirmed claim to be shown no lower than the scanner
    said of its finding, as the merge itself requires.

    #3731 and #3732, weight. Claims and the scanner finding have ranges of their own,
    some ending before they start; one claim in five is at a second line; and half the
    scanner findings that name a rule fire twice, the second hit at that line with a
    severity and a span of its own. With the cell present the run weighs no less
    (`summary.health.weighted_defect`), scores no better, and has no better letter. No
    exemption is made for the weight of a merge group.

    The scanner finding has a verdict only where an advisor was asked: the tool advisor
    is asked about the scanner findings in the verify queue, which is built on the
    merged list, so one that a claim absorbed has none in that run.

    A THIRD EXEMPTION, as ruled, for a scanner finding nobody was asked about. What no
    advisor was asked cannot be compared with an answer:
    - with the cell it has no answer (a claim absorbed it), and that run is closed:
      not certified, no letter, INCONCLUSIVE or FAIL, and an answer owed. Its weight
      is not compared. Where the run without the cell FAILS, the run with it is
      INCONCLUSIVE and shows the finding, itself or as the claim it is under. A PASS,
      a certification or a letter is never covered;
    - seen from the other side (A), it was asked about only with the cell there. The
      run without the cell owes it an answer: not certified, no letter, INCONCLUSIVE
      or FAIL. The run with the cell has the tool advisor's own answer and is judged
      on it, and where the run without it FAILS, so does the run with it;
    - (B) it counted as confirmed with the claim over it without the cell, and with
      the cell it was asked and its own advisor did not confirm it: its weight is not
      compared.
    In every such case the two runs are identical once the scanner finding's own
    answer is supplied in both. Asking about every scanner finding, absorbed or not,
    is #3734.

    Claims are in two categories (one in four is `other`), so that a pair across
    categories and a bucket within one are both made."""

    CASES, SEED = 900, 3711    # (#3728 review F1's shape is first reached at case 203)
    LINE_FILE = "b.py"
    LOW_DEFAULT = "ARC-A2D"         # an OCRDb code whose default severity is LOW
    CAPPED_TO = {"CRITICAL": "MEDIUM", "HIGH": "MEDIUM"}
    RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def final_of(self, finding, said, capped=True):
        """The severity this finding is published at, by the rule: an override with no
        reason resets it to its code's default; then a `TST-A1*` claim on a file that is
        not Python, or a scanner finding nobody confirmed, is capped at MEDIUM."""
        severity = finding["severity"]
        override = finding.get("severity_override")
        if isinstance(override, dict) and not override.get("reason"):
            self.assertEqual(self.LOW_DEFAULT, finding["code"])
            severity = "LOW"
        if finding["description"] == "tool":
            unconfirmed = capped and said in (None, "NEEDS_MORE_INFO")
            return self.CAPPED_TO.get(severity, severity) if unconfirmed else severity
        if finding["code"] == "TST-A1A" and not self.LINE_FILE.endswith(".py"):
            return self.CAPPED_TO.get(severity, severity)
        return severity

    def write(self, cells, tool, skip=None):
        """The run folder for `cells` ({group: (asked, [(claim, said)])}) and the tool
        finding, less the cell `skip`. Returns every loaded finding."""
        for name in os.listdir(self.verdicts):
            os.unlink(os.path.join(self.verdicts, name))
        paths, bodies = [], []
        for group in sorted(cells):
            if group == skip:
                continue
            asked, claims = cells[group]
            paths.append(os.path.join(self.run_dir, "findings-%s-SEC.json" % group))
            with open(paths[-1], "w", encoding="utf-8") as fh:
                json.dump({"findings": [c for c, _said in claims]}, fh)
        loaded = findings_mod.load_findings(paths)
        for group in sorted(cells):
            if group == skip or not cells[group][0]:
                continue
            mine = [f for f in loaded if f["_group"] == group]
            said = dict(zip((f["description"] for f in mine),
                            (word for _c, word in cells[group][1])))
            bodies.append(record(group=group, claims=[f["id"] for f in mine], size=25))
            self.bundle([verdict(f["id"], said[f["description"]]) for f in mine
                         if said[f["description"]]], group=group)
        self.record(*bodies)
        for path in [os.path.join(self.run_dir, n) for n in os.listdir(self.run_dir)
                     if n.startswith("findings-")]:
            if path not in paths:
                os.unlink(path)
        self.tool_asked = False
        if tool is not None:
            finding, said = tool
            loaded.append(copy.deepcopy(finding))
            if self.second_hit is not None:
                loaded.append(copy.deepcopy(self.second_hit))
            # The tool advisor is asked about the scanner findings in the verify queue,
            # which is built on the merged list before any verdict exists
            # (`verify_tools._tool_verify_queue`). A scanner finding that a claim
            # absorbed is not in it, so in that run it has no verdict at all.
            merged, _integration = corroborate_mod.prepare_for_queue(copy.deepcopy(loaded))
            queue, _cut = evidence_mod.build_verify_queue(merged, None)
            self.tool_asked = any(evidence_mod.is_tool_sourced(entry["finding"]) for entry in queue)
            if said and self.tool_asked:
                with open(os.path.join(self.verdicts, "%s.json" % evidence_mod.finding_fingerprint(
                        finding)), "w", encoding="utf-8") as fh:
                    # #3756: the advisor names every hit of the rule it judged, so
                    # its REJECTED rejects the scanner finding, as this property means.
                    hits = [finding] + ([self.second_hit] if self.second_hit is not None else [])
                    json.dump({"finding_id": finding["id"], "verdict": said, "reasoning": "r",
                               "judged_loci": [hit["location"]["line_start"] for hit in hits]},
                              fh)
        return loaded

    @staticmethod
    def said_of(cells, skip, group, declared, title, line, category):
        """The verdict the claim (`declared`, `title`, `category`, at `line`) has for `group`'s instance, by the
        rule and not by the code under test: a CONFIRMED from any cell that was asked
        reports it confirmed; a cell that was never asked takes nothing else from the
        others; the cells that were asked decide between them, and one that said
        nothing leaves it unverified; only every one of them rejecting it dismisses it."""
        words = [said for g, (asked, claims) in cells.items() if g != skip and asked
                 for c, said in claims
                 if (c["domain"], c["title"], str(c["location"]["line_start"]), c["category"])
                 == (declared, title, line, category)]
        if "CONFIRMED" in words:
            return "CONFIRMED"
        if not cells[group][0] or None in words:
            return None
        return "NEEDS_MORE_INFO" if "NEEDS_MORE_INFO" in words else "REJECTED"

    def run_of(self, cells, tool, skip=None):
        """(report, {tag: (list, status)}, {tag: standing}, {tag: the tag it is merged
        under}) for one run. A standing is the finding's OWN, worked out here."""
        loaded = self.write(cells, tool, skip)
        fs = findings_mod.FindingSet.load(
            types.SimpleNamespace(verdicts_dir=self.verdicts), [], "standard", None,
            prepared=(copy.deepcopy(loaded), None, None), run_dir=self.run_dir)
        with _target_with_files(GROUPS3, lines=5000) as target, \
                contextlib.redirect_stderr(io.StringIO()):
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=target, fail_on="high",
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=fs, plan=plan_mod.PlanInputs(groups_meta=GROUPS3)))
        shown, claims, severity = {}, set(), {}
        for where in ("findings", "discarded_claims"):
            for f in report[where]:
                self.assertNotIn(f["description"], shown, "one finding is in the report twice")
                shown[f["description"]] = (where, f["evidence"]["status"])
                severity[f["description"]] = f["severity"]
                # (At two severities it can be: one claim is filed twice under different
                # codes, by two cells or by one, and the instance that is not capped comes
                # back over the other. The two rows can differ in status as well.)
                row = (f["id"], f["evidence"]["status"], f["severity"])
                self.assertNotIn(row, claims, "one claim is in the report twice on one verdict")
                claims.add(row)
        # The oracle's own view of the merge and of what was owed: dedupe on a fresh
        # copy, and the engagement score over each cell's file.
        fresh = copy.deepcopy(loaded)   # not what the report run was handed, and changed
        engaged = self.engaged(fresh)
        under = {m["description"]: survivor["description"]
                 for survivor in corroborate_mod.prepare_for_queue(copy.deepcopy(fresh))[0]
                 for m in survivor.get(corroborate_mod.ABSORBED_FIELD) or ()}
        # #3732: a rule's hits are one finding, at its first hit and its worst severity.
        hits = [f for f in fresh if f["description"] == "tool"]
        if len(hits) > 1:
            worst = max(hits, key=lambda f: self.RANK[f["severity"]])
            fresh = [f for f in fresh if f["description"] != "tool"] + [
                dict(min(hits, key=lambda f: f["location"]["line_start"]),
                     severity=worst["severity"])]
            tool = (dict(tool[0], severity=worst["severity"]), tool[1])
        stands, words, ids, final = {}, {}, {}, {}
        self.tool_waiting = False
        for f in sorted(fresh, key=lambda f: f["description"] == "tool"):   # the claims first
            tag = f["description"]
            if tag != "tool":
                said = self.said_of(cells, skip, *tag.split(":"))
            elif self.tool_asked:
                said = tool[1]
            else:
                # Nobody was asked about it: a claim absorbed it before the queue was
                # built. Under a CONFIRMED claim the pair is confirmed as one. Under
                # any other it has no answer, and the run still owes one.
                said = "CONFIRMED" if words.get(under.get("tool")) == "CONFIRMED" else None
                self.tool_waiting = said is None
            owed = tag == "tool" or f["_group"] in engaged     # a tool finding always is
            stands[tag] = {"CONFIRMED": 3, "NEEDS_MORE_INFO": 1, "REJECTED": 0,
                           None: 2 if owed else 1}[said]
            words[tag] = said
            final[tag] = self.final_of(f, said)
            ids.setdefault(f["id"], []).append(tag)

        def ranked_below(finding):
            """Did the merge rank this claim below where it settles? A `TST-A1*` claim
            ranks at its cap, and on a Python file no test names it is not capped."""
            return (finding["description"] != "tool" and finding["code"] == "TST-A1A"
                    and final[finding["description"]] in self.CAPPED_TO
                    and self.LINE_FILE.endswith(".py"))

        def row_level(tag, for_finding):
            """The level of the row `tag`, for `for_finding` merged under it: its
            published severity. The second exemption: for a scanner row, its severity
            before the unverified cap, and only for a claim the merge ranked where it
            settles (review F1: one it ranked below is held against the row as shown)."""
            if tag != "tool" or ranked_below(for_finding):
                return self.RANK[severity[tag]]
            return self.RANK[self.final_of(tool[0], tool[1], capped=False)]

        def as_shown(tag):
            where, status = shown[tag]
            if where == "discarded_claims":
                return 0
            if status in CONFIRMED_AS:
                return 3
            return 1 if status == "needs_more_info" else max(stands[tag], 1)

        # What the report shows (P2, P3): every finding is there on its own standing;
        # or an instance of its id is there on the same verdict (or confirmed); or it
        # is merged under a finding that is there and stands no lower.
        # ...and (#3727) each row is at its own final severity, and no finding that is
        # not REJECTED is under a row of lower severity than its own.
        for f in fresh:
            tag = f["description"]
            if tag in shown:
                self.assertEqual(stands[tag], as_shown(tag), "%s is shown as %r" % (tag, shown[tag]))
                self.assertEqual(final[tag], severity[tag], "%s is shown at %s" % (tag, severity[tag]))
                continue
            stand_ins = [other for other in ids[f["id"]]
                         if other in shown and words[other] in (words[tag], "CONFIRMED")]
            if not stand_ins:
                self.assertIn(under.get(tag), shown, "%s is in neither list, and under "
                                                     "nothing that is" % tag)
                self.assertGreaterEqual(as_shown(under[tag]), stands[tag],
                                        "%s is merged under %s" % (tag, under[tag]))
            if words[tag] != "REJECTED":
                rows = stand_ins or [under[tag]]
                self.assertGreaterEqual(
                    max(row_level(row, f) for row in rows), self.RANK[final[tag]],
                    "%s (%s) is under %r" % (tag, final[tag], [(r, severity[r]) for r in rows]))
        return report, shown, stands, under

    @staticmethod
    def owed_count(report):
        """(unanswered findings of either kind, every other shortfall reason)."""
        unanswered, others = 0, []
        for reason in report["summary"]["grade_shortfalls"]:
            counted = re.match(r"(\d+) (?:tool )?findings? unanswered by ", reason)
            if counted:
                unanswered += int(counted.group(1))
            else:
                others.append(reason)
        return unanswered, others

    OTHER_LINE = 300

    def place(self, rng, line):
        """A location at `line`: one line, a range of up to 80, or an inverted range."""
        end = rng.choice((None, None, line, line + rng.randint(1, 80), line - 1 if line > 1 else 0))
        return dict({"file": self.LINE_FILE, "line_start": line},
                    **({} if end is None else {"line_end": end}))

    def case(self, rng):
        cells, tool, used = {}, None, set()
        self.second_hit = None
        if not hasattr(self, "side"):       # a second stream: the first is as it was
            self.side = random.Random(self.SEED * 7919 + 1)
        # Half the cases sit on a file that is not Python: there a `TST-A1*` claim cannot
        # be witnessed and is capped. On a Python file with no test, it is not.
        self.LINE_FILE = rng.choice(("b.py", "b.sh"))
        for _ in range(rng.randint(2, 5)):
            severity = rng.choice(("CRITICAL", "HIGH", "MEDIUM", "LOW"))
            if tool is None and rng.random() < 0.2:
                tool = ({"id": "TL-1", "title": "tool", "description": "tool", "severity": severity,
                         "confidence": "POSSIBLE", "panel": "security", "domain": "SEC",
                         "category": rng.choice(("authz", "other")), "source": "tool:semgrep",
                         # One in three names no rule: in the claims' category it then
                         # shares their bucket in the merge.
                         "tool_evidence": dict({"tool": "semgrep"}, **rng.choice(
                             ({"rule_id": "r.tool"}, {"rule_id": "r.tool"}, {}))),
                         "location": self.place(rng, 1),
                         "provenance": {"discovered_by": "tool:semgrep",
                                        "confirmation_status": "UNVERIFIED"}},
                        rng.choice(WORDS))
                # #3732: half the ruled ones fire twice, the second hit on the other
                # line with a severity and a span of its own. One rule: one finding.
                if tool[0]["tool_evidence"].get("rule_id") and rng.random() < 0.5:
                    self.second_hit = dict(
                        copy.deepcopy(tool[0]), location=self.place(rng, self.OTHER_LINE),
                        severity=rng.choice(("CRITICAL", "HIGH", "MEDIUM", "LOW")))
                continue
            group, title = rng.choice(("g1", "g2", "g3")), rng.choice(("t0", "t1", "t2"))
            # A reviewer may file a claim under another domain's code. The claim is
            # still the cell's: it is in the cell's file, and its advisors are handed it.
            declared = "COD" if rng.random() < 0.25 else "SEC"
            if (group, declared, title) in used:
                continue
            used.add((group, declared, title))
            # #3727: a lever the controller applies after the merge. `code` is not part
            # of an id, so a copy can carry one where the claim it copies has none.
            lever = rng.choice(({}, {}, {}, {"code": self.LOW_DEFAULT, "severity_override": {}},
                                {"code": "TST-A1A"}))
            asked, claims = cells.setdefault(group, (rng.random() < 0.7, []))
            # #3731: a range of its own, sometimes one that ends before it starts; and
            # one claim in five is at the other line, where a second hit can be.
            where = self.place(rng, self.OTHER_LINE if rng.random() < 0.2 else 1)
            category = "other" if self.side.random() < 0.25 else "authz"
            claims.append(({**claim(self.LINE_FILE, title=title, severity=severity),
                            "location": where, "category": category,
                            "domain": declared, "code": "%s-A1A" % declared,
                            "confidence": rng.choice(("CERTAIN", "LIKELY", "POSSIBLE")),
                            "description": "%s:%s:%s:%d:%s" % (
                                group, declared, title, where["line_start"], category), **lever},
                           rng.choice(WORDS) if asked else None))
        # The driver dispatches a cell's advisors only when the cell's claims reach the
        # verify gate. A cell below it is never asked; one above it was asked, or has
        # no entry in the record all the same (its findings file was refused).
        engaged = self.engaged(self.write(cells, None))
        for group, (_asked, claims) in list(cells.items()):
            if group not in engaged:
                cells[group] = (False, [(c, None) for c, _said in claims])
        return cells, tool

    @staticmethod
    def engaged(loaded):
        """The groups whose review cell reaches the verify gate, scored as the driver
        scores it: over every claim in the cell's file, whatever domain each declares."""
        return {group for group in ("g1", "g2", "g3")
                if score_gate.should_engage_primary([f for f in loaded
                                                     if f.get("_group") == group])}

    def test_the_property(self):
        rng = random.Random(self.SEED)
        removed = exempted = compared = unasked = 0
        for number in range(self.CASES):
            cells, tool = self.case(rng)
            with self.subTest(case=number):
                with_report, with_shown, with_stands, under = self.run_of(cells, tool)
                asked, waiting = self.tool_asked, self.tool_waiting
            for cell in sorted(cells):
                with self.subTest(case=number, removed=cell):
                    less_report, less_shown, less_stands, _under = self.run_of(cells, tool, cell)
                    removed += 1
                    summary, without = with_report["summary"], less_report["summary"]
                    # The scanner finding was asked about in one of the two runs only:
                    # they know different things about it (the third exemption).
                    differs = tool is not None and asked != self.tool_asked
                    unasked += differs
                    for tag, stood in less_stands.items():
                        # (Where nobody was asked about the scanner finding, it stands
                        # as the claim it is under does, and that claim is held here.)
                        if tag != "tool" or (asked and self.tool_asked):
                            self.assertGreaterEqual(with_stands[tag], stood, tag)
                    # The first exemption: the tool finding that is merged with the cell
                    # there, and alone and unanswered without it.
                    cover = under.get("tool", "")
                    shown_at = {f["description"]: f["severity"] for f in with_report["findings"]}
                    merged = (tool is not None and "tool" not in with_shown
                              and less_shown.get("tool") == ("findings", "tool_reported"))
                    status = with_shown.get(cover, ("", ""))[1]
                    # Under a CONFIRMED claim, shown no lower than the scanner said of its
                    # finding; or under a claim that is itself owed and unanswered.
                    exempt = int(merged and status in CONFIRMED_AS
                                 and self.RANK[shown_at[cover]] >= self.RANK[tool[0]["severity"]])
                    held = int(merged and status in ("unverified", "tool_reported")
                               and with_stands[cover] == 2)
                    exempted += exempt
                    (owed, others), (less_owed, less_others) = (
                        self.owed_count(with_report), self.owed_count(less_report))
                    # (...or it was asked about with the cell, and absorbed without it.)
                    self.assertGreaterEqual(owed, less_owed - max(exempt, held, int(differs)))
                    self.assertLessEqual(set(less_others), set(others))
                    first = bool(exempt and less_owed == 1)     # ...the one thing owed without it
                    grade, less_grade = summary["overall_grade"], without["overall_grade"]
                    # The third exemption, its second half, the first seen from the other
                    # side: the scanner finding was asked about only with the cell there.
                    # Without the cell it has no answer, and that run still owes one.
                    second_half = differs and asked and self.tool_waiting
                    # ...or without the cell it counted as confirmed with the claim over
                    # it, and with the cell its own advisor did not confirm it.
                    lighter = (differs and asked and tool[1] != "CONFIRMED"
                               and not self.tool_waiting)
                    # The third exemption, its first half, as ruled and no wider: with the
                    # cell the scanner finding has no answer, and without it the run FAILS.
                    third = waiting and without["gate"] == "FAIL" and summary["gate"] != "FAIL"
                    if third:
                        self.assertEqual(("INCONCLUSIVE", False, None), (
                            summary["gate"], summary["coverage_certified"], grade))
                        self.assertGreater(owed, 0)
                        # ...and it is in the report, itself or as the claim it is under.
                        self.assertIn(with_shown.get("tool", with_shown.get(cover))[1],
                                      ("tool_reported", "unverified"))
                    elif second_half:
                        # The run with the cell has the tool advisor's own answer and is
                        # judged on it. The run without is not a pass of any kind.
                        self.assertFalse(without["coverage_certified"])
                        self.assertIsNone(less_grade)
                        self.assertGreater(less_owed, 0)
                        self.assertIn(without["gate"], ("INCONCLUSIVE", "FAIL"))
                        if without["gate"] == "FAIL":       # ...and a FAIL stays one
                            self.assertEqual("FAIL", summary["gate"])
                    elif not first:
                        self.assertGreaterEqual(GATE_RANK[summary["gate"]],
                                                GATE_RANK[without["gate"]])
                        self.assertFalse(summary["coverage_certified"]
                                         and not without["coverage_certified"])
                    else:
                        # (FAIL, where a confirmed finding on another line fails it both ways.)
                        self.assertIn(without["gate"], ("INCONCLUSIVE", "FAIL"))
                        self.assertGreaterEqual(GATE_RANK[summary["gate"]],
                                                GATE_RANK[without["gate"]] - 1)
                        self.assertFalse(without["coverage_certified"])
                    # #3731: the letter and the health score. The run with the cell weighs
                    # no less and scores no better. The third exemption is all that is
                    # set aside: its first half (no answer with the cell), and its second
                    # (an answer only with the cell, and it is not CONFIRMED).
                    health, less_health = summary["health"], without["health"]
                    if waiting:
                        # No answer with the cell: that run is closed, whatever it weighs.
                        self.assertEqual((False, None), (summary["coverage_certified"], grade))
                        self.assertIn(summary["gate"], ("INCONCLUSIVE", "FAIL"))
                        self.assertGreater(owed, 0)
                    elif not lighter:
                        self.assertGreaterEqual(health["weighted_defect"],
                                                less_health["weighted_defect"])
                        self.assertLessEqual(health["score"], less_health["score"])
                        if grade is not None and less_grade is not None:
                            self.assertGreaterEqual(GRADES.index(grade), GRADES.index(less_grade))
                            compared += 1
                        elif grade is not None:     # a letter only with the cell
                            self.assertTrue(first or second_half,
                                            "a letter (%s) only with the cell" % grade)
        # The run means something: cells were removed, letters were compared, and the
        # exemptions are rare.
        self.assertGreater(removed, self.CASES)
        self.assertLess(exempted, removed // 20)
        self.assertLess(unasked, removed // 5)
        self.assertGreater(compared, self.CASES // 4)

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
