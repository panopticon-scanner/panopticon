"""Verdict accounting, evidence, and strict gate contracts."""

import contextlib
import io
import unittest
import scripts.synth.corroborate as corroborate_mod
import scripts.synth.findings as findings_mod
import scripts.synth.grading as grading_mod
import scripts.synth.report as report_mod
import scripts.evidence as evidence_mod
from scripts._version import __version__
from tests.synth.helpers import _agentic, _VERDICT_STATUS


class TestEvidenceReport(unittest.TestCase):
    def _report(self, findings, verdicts=None, gate_unverified=False, fail_on="high"):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="target",
                fail_on=fail_on,
                timestamp="2026-08-03T00:00:00Z",
                gate_unverified=gate_unverified,
            ),
            findings=findings_mod.FindingSet(findings=findings, verdicts=verdicts),
        ))

    def test_summary_carries_the_gate_severity_roles(self):
        # The report must ship the roles, not leave every renderer to re-derive
        # them from fail_on -- which is how the two would drift apart.
        report = self._report([_agentic(sev="HIGH")], fail_on="high")
        roles = report["summary"]["gate_severities"]
        self.assertEqual(roles["fail_on"], "HIGH")
        self.assertEqual(roles["in_play"], ["CRITICAL", "HIGH"])
        # unverified -> not gate-eligible -> in play but NOT contributing, and
        # the gate agrees.
        self.assertEqual(roles["contributing"], [])
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_gate_severity_roles_follow_confirmation(self):
        # Same finding, now confirmed: it becomes gate-eligible, the level turns
        # contributing, and the gate FAILs. The mark tracks the verdict.
        finding = _agentic(sev="HIGH")
        verdicts = {evidence_mod.finding_fingerprint(finding): {
            "finding_id": "AG-001", "verdict": "CONFIRMED", "reasoning": "v"}}
        report = self._report([finding], verdicts=verdicts, fail_on="high")
        self.assertEqual(report["summary"]["gate_severities"]["contributing"], ["HIGH"])
        self.assertEqual(report["summary"]["gate"], "FAIL")

    def test_unverified_keeps_severity_and_does_not_gate(self):
        report = self._report([_agentic(sev="CRITICAL")])
        f = report["findings"][0]
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(f["evidence"]["status"], "unverified")
        self.assertEqual(report["summary"]["gate"], "PASS")
        self.assertIsNone(report["summary"]["overall_grade"])   # no LoC here

    def test_gate_unverified_opts_in(self):
        report = self._report([_agentic(sev="CRITICAL")], gate_unverified=True)
        self.assertEqual(report["summary"]["gate"], "FAIL")
        self.assertIsNone(report["summary"]["overall_grade"])   # no LoC here
        self.assertEqual(report["summary"]["gate_policy"], "include_unverified")

    def test_confirmed_verdict_gates(self):
        finding = _agentic()
        verdicts = {
            evidence_mod.finding_fingerprint(finding): {
                "finding_id": "AG-001",
                "verdict": "CONFIRMED",
                "reasoning": "verified",
            }
        }
        report = self._report([finding], verdicts=verdicts)
        f = report["findings"][0]
        self.assertEqual(f["evidence"]["status"], "advisor_confirmed")
        self.assertEqual(report["summary"]["gate"], "FAIL")
        self.assertIsNone(report["summary"]["overall_grade"])   # no LoC here

    def test_summary_health_counts_only_gate_eligible(self):
        # #1146: the health denominator is the gate-eligible set (same as the
        # letter). A CONFIRMED HIGH spanning 4 lines -> weighted_defect = 25*4.
        # An UNVERIFIED finding is NOT gate-eligible and must not move it.
        confirmed = _agentic(location={"file": "app.py", "line_start": 10, "line_end": 13})
        unverified = _agentic(
            fid="AG-002", location={"file": "app.py", "line_start": 90, "line_end": 99}
        )
        verdicts = {
            evidence_mod.finding_fingerprint(confirmed): {
                "finding_id": "AG-001",
                "verdict": "CONFIRMED",
                "reasoning": "v",
            }
        }
        health = self._report([confirmed, unverified], verdicts=verdicts)["summary"]["health"]
        self.assertEqual(health["population"], "gate_eligible")
        self.assertEqual(health["weighted_defect"], 100)  # 25 * 4, unverified excluded
        self.assertEqual(health["weights"]["critical"], 125)
        self.assertEqual(health["total_loc"], 0)  # file absent in this fixture
        # No readable LoC is an unmeasurable codebase, NOT a health of zero --
        # otherwise a run whose paths fail to resolve grades X for code it never
        # read. See health_score's note.
        self.assertIsNone(health["score"])

    def test_summary_health_score_null_only_when_nothing_measurable(self):
        # An unverified-only report has an empty gate-eligible set -> no weighted
        # defect. In this fixture the reviewed file does not exist either, so
        # total_loc is 0 too and BOTH inputs are zero -- the one genuinely
        # undefined case. A clean repo with real LoC scores 100 (see
        # test_a_clean_repo_scores_a_perfect_100_not_none).
        health = self._report([_agentic()])["summary"]["health"]
        self.assertEqual(health["weighted_defect"], 0)
        self.assertEqual(health["total_loc"], 0)
        self.assertIsNone(health["score"])

    def test_summary_health_states_its_own_formula(self):
        # The score changed shape once; a report that names the expression it
        # used stays interpretable when it changes again.
        health = self._report([_agentic()])["summary"]["health"]
        self.assertEqual(health["formula"], grading_mod.HEALTH_FORMULA)
        self.assertIn("total_loc", health["formula"])
        self.assertIn("weighted_defect", health["formula"])

    def test_rejected_moves_to_discarded_with_severity_intact(self):
        finding = _agentic()
        verdicts = {
            evidence_mod.finding_fingerprint(finding): {
                "finding_id": "AG-001",
                "verdict": "REJECTED",
                "reasoning": "not exploitable",
            }
        }
        report = self._report([finding], verdicts=verdicts)
        self.assertEqual(report["findings"], [])
        d = report["discarded_claims"][0]
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["evidence"]["status"], "rejected")
        self.assertEqual(d["evidence"]["reasoning"], "not exploitable")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_needs_more_info_stays_visible_not_gating(self):
        finding = _agentic()
        verdicts = {
            evidence_mod.finding_fingerprint(finding): {
                "finding_id": "AG-001",
                "verdict": "NEEDS_MORE_INFO",
                "reasoning": "need deploy config",
            }
        }
        report = self._report([finding], verdicts=verdicts)
        f = report["findings"][0]
        self.assertEqual(f["evidence"]["status"], "needs_more_info")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_tool_finding_without_verdict_is_reported_not_gated(self):
        # P2/#446: this is the load-bearing regression test for the Bandit
        # B105 self-scan incident -- an unverified tool claim must NOT gate a
        # build on its own. It is tool_reported until an advisor confirms it.
        tool = {
            "id": "TL-001",
            "title": "sqli",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "source": "tool:semgrep",
            "location": {"file": "app.py", "line_start": 5},
            "provenance": {"discovered_by": "tool:semgrep", "confirmation_status": "TOOL"},
        }
        report = self._report([findings_mod.normalize_finding(tool)])
        self.assertEqual(report["findings"][0]["evidence"]["status"], "tool_reported")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_evidence_stats_counts_everything(self):
        f1 = _agentic()
        # distinct locus for AG-002 so dedupe doesn't collapse it into AG-001
        # (same file/line/category would otherwise keep only the more severe one).
        f2 = _agentic(fid="AG-002", sev="LOW", location={"file": "app.py", "line_start": 99})
        verdicts = {
            evidence_mod.finding_fingerprint(f1): {
                "finding_id": "AG-001",
                "verdict": "REJECTED",
                "reasoning": "r",
            }
        }
        report = self._report([f1, f2], verdicts=verdicts)
        stats = report["summary"]["evidence_stats"]
        self.assertEqual(stats["rejected"], 1)
        self.assertEqual(stats["unverified"], 1)

    def _split_report(self):
        # f1 gets REJECTED -> discarded; f2 stays active. So `stats` (active)
        # and `evidence_stats` (all) count DIFFERENT populations.
        f1 = _agentic()
        f2 = _agentic(fid="AG-002", sev="LOW", location={"file": "app.py", "line_start": 99})
        verdicts = {
            evidence_mod.finding_fingerprint(f1): {
                "finding_id": "AG-001",
                "verdict": "REJECTED",
                "reasoning": "r",
            }
        }
        return self._report([f1, f2], verdicts=verdicts)

    def test_summary_counts_label_the_two_populations(self):
        # #1059: summary.stats counts ACTIVE (kept) findings while
        # summary.evidence_stats counts ALL findings (kept + discarded), so the
        # two histograms' totals differ with nothing saying which is which --
        # the run-5 self-scan's unlabeled 65-vs-30. A labeled counts block plus
        # explicit population tags make each histogram reconcilable.
        summary = self._split_report()["summary"]
        counts = summary["counts"]
        self.assertEqual(counts["active"], 1)
        self.assertEqual(counts["discarded"], 1)
        self.assertEqual(counts["total"], 2)
        self.assertEqual(summary["stats_population"], "active")
        self.assertEqual(summary["evidence_stats_population"], "all")
        self.assertEqual(sum(summary["stats"].values()), counts["active"])
        self.assertEqual(sum(summary["evidence_stats"].values()), counts["total"])

    def test_summary_counts_reconcile_with_report_arrays(self):
        # counts must equal the ACTUAL report array lengths, not a parallel
        # tally that could drift from what the report emits.
        report = self._split_report()
        self.assertEqual(report["summary"]["counts"]["active"], len(report["findings"]))
        self.assertEqual(report["summary"]["counts"]["discarded"], len(report["discarded_claims"]))
        self.assertEqual(
            report["summary"]["counts"]["total"],
            len(report["findings"]) + len(report["discarded_claims"]),
        )

    def test_schema_theater_removed(self):
        report = self._report([_agentic()])
        self.assertNotIn("effort_to_remediate", report["summary"])
        self.assertNotIn("recommendations", report)
        self.assertEqual(report["meta"]["version"], __version__)

    def test_citation_quality_lives_in_evidence(self):
        report = self._report([_agentic(citations={"cwe": ["CWE-89"]})])
        f = report["findings"][0]
        self.assertNotIn("citation_quality", f)
        self.assertIn(f["evidence"]["citation_quality"], ("full", "partial", "minimal", "none"))

    def test_reinforced_tool_agent_merge_without_verdict_does_not_gate(self):
        # P2/#446: a tool HIGH + agent CRITICAL at the same locus reinforce to
        # a single survivor, which is tool-reported by construction (never
        # demoted to mere `corroborated`) -- but reinforcement alone is no
        # longer gate-eligible without an advisor CONFIRMED verdict, same as
        # any other tool claim. Gate stays PASS under --fail-on high.
        tool = {
            "id": "TL-002",
            "title": "sqli",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "source": "tool:semgrep",
            "location": {"file": "app.py", "line_start": 20},
        }
        agent = {
            "id": "AG-201",
            "title": "sqli (agent)",
            "severity": "CRITICAL",
            "confidence": "POSSIBLE",
            "panel": "security",
            "category": "injection",
            "location": {"file": "app.py", "line_start": 20},
        }
        report = self._report([tool, agent])
        self.assertEqual(len(report["findings"]), 1)
        f = report["findings"][0]
        self.assertTrue(f.get("reinforced"))
        self.assertEqual(f["evidence"]["status"], "tool_reported")
        self.assertEqual(report["summary"]["gate"], "PASS")

    def test_unknown_queue_id_verdict_ignored(self):
        # A verdict file whose stem doesn't match any current queue_id (e.g.
        # a stale verdict from a prior pass) must not silently vanish -> spec
        # requires a stderr warning naming it, and the report is unaffected.
        verdicts = {
            "999-UNKNOWN": {"finding_id": "AG-999", "verdict": "CONFIRMED", "reasoning": "r"}
        }
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            report = self._report([_agentic()], verdicts=verdicts)
        f = report["findings"][0]
        self.assertEqual(f["evidence"]["status"], "unverified")
        self.assertIn("999-UNKNOWN", err.getvalue())


class TestSeverityImmutability(unittest.TestCase):
    def test_no_path_mutates_severity(self):
        cases = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cases.append((_agentic(fid="AG-%s" % sev[:2], sev=sev), None))
        cases.append((_agentic(fid="AG-101"), {"verdict": "REJECTED", "reasoning": "r"}))
        cases.append((_agentic(fid="AG-102"), {"verdict": "NEEDS_MORE_INFO", "reasoning": "r"}))
        cases.append((_agentic(fid="AG-103"), {"verdict": "CONFIRMED", "reasoning": "r"}))
        for finding, verdict in cases:
            original = finding["severity"]
            verdicts = (
                {evidence_mod.finding_fingerprint(finding): dict(verdict, finding_id=finding["id"])}
                if verdict
                else None
            )
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on="high",
                    timestamp="2026-08-03T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=[finding], verdicts=verdicts),
            ))
            everywhere = report["findings"] + report["discarded_claims"]
            self.assertEqual(
                everywhere[0]["severity"], original, "severity mutated for verdict=%r" % verdict
            )
            if verdict:
                self.assertEqual(
                    everywhere[0]["evidence"]["status"],
                    _VERDICT_STATUS[verdict["verdict"]],
                    "verdict %r did not actually reach apply_verdict" % verdict,
                )

    def test_no_path_mutates_confidence(self):
        # Amended spec: confidence, like severity, is never mutated by the
        # pipeline after normalize_finding — no exceptions (the legacy
        # dedupe/corroboration confidence bumps are removed).
        cases = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cases.append((_agentic(fid="AG-%s" % sev[:2], sev=sev), None))
        cases.append((_agentic(fid="AG-101"), {"verdict": "REJECTED", "reasoning": "r"}))
        cases.append((_agentic(fid="AG-102"), {"verdict": "NEEDS_MORE_INFO", "reasoning": "r"}))
        cases.append((_agentic(fid="AG-103"), {"verdict": "CONFIRMED", "reasoning": "r"}))
        for finding, verdict in cases:
            original = finding["confidence"]
            verdicts = (
                {evidence_mod.finding_fingerprint(finding): dict(verdict, finding_id=finding["id"])}
                if verdict
                else None
            )
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on="high",
                    timestamp="2026-08-03T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(findings=[finding], verdicts=verdicts),
            ))
            everywhere = report["findings"] + report["discarded_claims"]
            self.assertEqual(
                everywhere[0]["confidence"], original, "confidence mutated for verdict=%r" % verdict
            )
            if verdict:
                self.assertEqual(
                    everywhere[0]["evidence"]["status"],
                    _VERDICT_STATUS[verdict["verdict"]],
                    "verdict %r did not actually reach apply_verdict" % verdict,
                )


class TestVerdictAccountingMeta(unittest.TestCase):
    """#443's own failure surface, made visible in the artifact.

    A run whose verdicts all fail to match used to still gate on tool findings,
    so the breakage was loud. Under strict gating (P2) that same run yields gate
    PASS, grade A, risk LOW -- the safest-looking output there is -- and CI reads
    the JSON, not stderr. meta.verdicts is the detection.
    """

    def _f(self, fid, title, fname):
        return {
            "id": fid,
            "title": title,
            "severity": "HIGH",
            "confidence": "POSSIBLE",
            "panel": "code",
            "category": "logic",
            "description": "d",
            "location": {"file": fname, "line_start": 1},
        }

    def _queue(self, findings):
        prepared, _ = corroborate_mod.prepare_for_queue(findings)
        return evidence_mod.build_verify_queue(prepared)[0]

    def test_counts_matched_unknown_and_unanswered(self):
        a = self._f("A-1", "first claim", "a.py")
        b = self._f("A-2", "second claim", "b.py")
        queue = self._queue([a, b])
        self.assertEqual(len(queue), 2)
        answered = queue[0]
        verdicts = {
            answered["queue_id"]: {
                "verdict": "CONFIRMED",
                "reasoning": "r",
                "finding_id": answered["finding"]["id"],
            },
            # A stale verdict from a previous run: well-formed, but its id is
            # in no queue this run.
            "deadbeefdeadbeef": {
                "verdict": "CONFIRMED",
                "reasoning": "stale",
                "finding_id": "GONE-1",
            },
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[a, b],
                verdicts=verdicts,
                verdicts_supplied=True,
            ),
        ))
        self.assertEqual(
            r["meta"]["coverage"]["verdicts"],
            {
                "queued": 2,
                "cut": 0,
                "supplied": 2,
                "matched": 1,
                "unknown": 1,
                "unanswered": 1,
                "misrouted": 0,
                "unloadable": 0,
            },
        )

    def test_unloadable_verdicts_surfaced_in_coverage(self):
        # #938: corrupt verdict files (passed as verdict_unloadable) surface as
        # a count in meta.coverage, so a lost verdict is visible rather than
        # only reflected as a lower `supplied`.
        a = self._f("A-1", "first claim", "a.py")
        self._queue([a])
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on=None,
                    timestamp="2026-08-05T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(
                    findings=[a],
                    verdicts={},
                    verdicts_supplied=True,
                    verdict_unloadable=[
                        {"file": "x.json", "reason": "unparseable: ..."},
                        {"file": "y.json", "reason": "missing/invalid verdict key"},
                    ],
                ),
            ))
        self.assertEqual(r["meta"]["coverage"]["verdicts"]["unloadable"], 2)
        self.assertIn("un-loadable", err.getvalue())
        # a corrupt file is NOT a misrouted one -- different failure, different
        # remedy, so the two counters must not bleed into each other.
        self.assertEqual(r["meta"]["coverage"]["verdicts"]["misrouted"], 0)

    def test_echo_mismatch_is_dropped_and_reported_as_misrouted(self):
        # match_verdict refuses a verdict that echoes a different finding_id.
        # It is neither matched nor unknown, so supplied - matched - unknown
        # is exactly the echo-rejected count.
        #
        # #1475: it is ALSO counted as `misrouted`. The rejection was always
        # correct; what run-6 lacked was any way to tell it apart from a cell
        # no advisor ever answered, since both only moved `unanswered`. This is
        # the run-6 shape exactly: a verdict file present for the cell, naming
        # somebody else's finding.
        a = self._f("A-1", "first claim", "a.py")
        queue = self._queue([a])
        verdicts = {
            queue[0]["queue_id"]: {
                "verdict": "CONFIRMED",
                "reasoning": "r",
                "finding_id": "SOMEONE-ELSE",
            }
        }
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            r = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(
                    target="t",
                    fail_on=None,
                    timestamp="2026-08-05T00:00:00Z",
                ),
                findings=findings_mod.FindingSet(
                    findings=[a],
                    verdicts=verdicts,
                    verdicts_supplied=True,
                ),
            ))
        self.assertEqual(
            r["meta"]["coverage"]["verdicts"],
            {
                "queued": 1,
                "cut": 0,
                "supplied": 1,
                "matched": 0,
                "unknown": 0,
                "unanswered": 1,
                # the whole point: an advisor DID answer, mislabelled -- not a
                # dispatch that never happened.
                "misrouted": 1,
                "unloadable": 0,
            },
        )
        self.assertEqual(r["summary"]["gate"], "OFF")  # ...and it looks clean
        # stderr must say an advisor answered and was mislabelled, not merely
        # that something is unanswered -- that distinction is the fix.
        self.assertIn("mislabelled", err.getvalue())

    def test_run6_shape_misroute_is_distinguishable_from_a_missing_dispatch(self):
        # The two failures that ran-6 collapsed into one number, side by side.
        # Same queue, same `unanswered: 1`, opposite causes and opposite fixes:
        # one needs the advisor re-dispatched, the other needs its answer
        # relabelled. A report that cannot tell them apart sends the operator
        # digging through raw agent transcripts, which is what it cost here.
        a = self._f("SG-006", "tool claim", "a.py")
        queue = self._queue([a])

        def report(verdicts):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                r = report_mod.build_report(report_mod.ReportInputs(
                    run=report_mod.RunConfig(
                        target="t",
                        fail_on=None,
                        timestamp="2026-08-05T00:00:00Z",
                    ),
                    findings=findings_mod.FindingSet(
                        findings=[a],
                        verdicts=verdicts,
                        verdicts_supplied=True,
                    ),
                ))
            return r["meta"]["coverage"]["verdicts"]

        # (a) no advisor ever answered this cell
        missing = report({})
        # (b) an advisor answered, echoing somebody else's finding (run-6: the
        #     cell dispatched for SG-006 returned ESS-036)
        misrouted = report({queue[0]["queue_id"]: {
            "verdict": "REJECTED", "reasoning": "r", "finding_id": "ESS-036"}})

        self.assertEqual(missing["unanswered"], 1)
        self.assertEqual(misrouted["unanswered"], 1)     # same headline ...
        self.assertEqual(missing["misrouted"], 0)        # ... different cause
        self.assertEqual(misrouted["misrouted"], 1)

    def test_unanswered_is_null_when_no_verdicts_were_supplied(self):
        # 0 would read as "nothing went unanswered" for a run that never ran a
        # verify phase; null says "not measured" (as tool_axis.rejection_rate
        # already does).
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f("A-1", "first claim", "a.py")]),
        ))
        self.assertEqual(
            r["meta"]["coverage"]["verdicts"],
            {
                "queued": 1,
                "cut": 0,
                "supplied": 0,
                "matched": 0,
                "unknown": 0,
                "unanswered": None,
                "misrouted": 0,
                "unloadable": 0,
            },
        )


class TestVerdictCutAccounting(unittest.TestCase):
    def _f(self, fid, sev="MEDIUM"):
        return {
            "id": fid,
            "severity": sev,
            "panel": "code",
            "category": "logic",
            "title": "t-" + fid,
            "confidence": "POSSIBLE",
            "description": "d",
            "location": {"file": fid + ".py", "line_start": 1},
        }

    def test_uncapped_run_reports_cut_zero(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._f("A"), self._f("B")]),
        ))
        v = r["meta"]["coverage"]["verdicts"]
        self.assertEqual(v["cut"], 0)
        self.assertEqual(v["queued"], 2)

    def test_capped_run_reports_the_cut(self):
        findings = [self._f("A", "CRITICAL"), self._f("B", "HIGH"), self._f("C", "LOW")]
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on=None,
                timestamp="2026-08-05T00:00:00Z",
                max_verify=1,
            ),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        v = r["meta"]["coverage"]["verdicts"]
        self.assertEqual(v["queued"], 1)
        self.assertEqual(v["cut"], 2)


class TestStrictGate(unittest.TestCase):
    # P2/#446, combined effect: derive_evidence now checks the advisor
    # verdict before the finding's source, and the verify queue (fingerprint-
    # keyed, queues every finding) can actually route a tool claim to that
    # verdict. Together: an unverified tool HIGH is `tool_reported`, which is
    # not gate-eligible, so it no longer fails the build on its own -- it
    # takes an advisor CONFIRMED to fail the gate. --gate-unverified remains
    # the escape hatch that restores the old "every non-rejected claim gates"
    # behavior.
    def _tool_high(self):
        return {
            "id": "T-1",
            "source": "tool:bandit",
            "severity": "HIGH",
            "panel": "security",
            "category": "secrets",
            "title": "hardcoded password",
            "confidence": "LIKELY",
            "description": "d",
            "location": {"file": "a.py", "line_start": 1},
            "provenance": {"confirmation_reasoning": "B105"},
        }

    def test_unverified_tool_high_no_longer_fails_the_gate(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[self._tool_high()]),
        ))
        self.assertEqual(r["summary"]["gate"], "PASS")
        self.assertEqual(r["findings"][0]["evidence"]["status"], "tool_reported")

    def test_confirmed_tool_high_fails_the_gate(self):
        f = self._tool_high()
        prepared, _ = corroborate_mod.prepare_for_queue([dict(f)])
        queue, _c = evidence_mod.build_verify_queue(prepared)
        qid = queue[0]["queue_id"]
        verdicts = {
            qid: {
                "verdict": "CONFIRMED",
                "finding_id": queue[0]["finding"]["id"],
                "reasoning": "real credential",
            }
        }
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-08-05T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[f],
                verdicts=verdicts,
                verdicts_supplied=True,
            ),
        ))
        self.assertEqual(r["summary"]["gate"], "FAIL")

    def test_gate_unverified_still_includes_tool_reported(self):
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="t",
                fail_on="high",
                timestamp="2026-08-05T00:00:00Z",
                gate_unverified=True,
            ),
            findings=findings_mod.FindingSet(findings=[self._tool_high()]),
        ))
        self.assertEqual(r["summary"]["gate"], "FAIL")
