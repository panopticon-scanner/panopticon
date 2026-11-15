"""#3667: tool findings an advisor never answered stay visible and hold the letter back.

The owner's run looked as if most of its tool findings had vanished. They had
not: the report was over the writer's byte budget, `findings[]` was split into
part files, and every tool finding sat after every agent finding, so the main
`report.json` carried almost none of them. These tests pin the three answers:
the main file explains a split (`meta.parts_findings`, `tool_axis.by_tool`),
`findings[]` is published worst first, and undone verify work holds the letter
back as provisional with its reason (one shared rule, `grading.grade_shortfalls`).
"""

import collections
import copy
import itertools
import json
import os
import tempfile
import types
import unittest

import jsonschema

import scripts.evidence as evidence_mod
import scripts.html_report as html_report
import scripts.synth.findings as findings_mod
import scripts.synth.grading as grading_mod
import scripts.synth.plan as plan_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
from tests.synth.helpers import _agentic, _target_with_files

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "skill", "reference", "report-schema.json")
GROUPS = [{"name": "g1", "files": ["app.py", "package-lock.json"]}]
_IDS = itertools.count(1)


def _tool(tool, rule, line, *, file="app.py", sev="HIGH", panel="security",
          category="injection", package=None, fid=None):
    evidence = {"rule_id": rule}
    if package is not None:
        evidence["package_name"] = package
    return {
        "id": fid or "TL-%03d" % next(_IDS),
        "title": "%s %s" % (tool, rule), "severity": sev, "confidence": "LIKELY",
        "panel": panel, "category": category, "source": "tool:%s" % tool,
        "location": {"file": file, "line_start": line}, "tool_evidence": evidence,
    }


def _advisories(packages=6, per_package=3):
    """A dependency scanner: several distinct advisories per package, all at the
    lockfile's first line -- the shape that filled the owner's part file."""
    return [_tool("osv-scanner", "GHSA-%02d-%02d" % (p, a), 1, file="package-lock.json",
                  category="dependency", package="dep%d" % p)
            for p in range(packages) for a in range(per_package)]


def _build(findings, *, verdicts=None, supplied=True, fail_on="high", lines=5000):
    with _target_with_files(GROUPS, lines=lines) as tgt:
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target=tgt, fail_on=fail_on,
                                     timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[findings_mod.normalize_finding(copy.deepcopy(f)) for f in findings],
                verdicts=verdicts or {}, verdicts_supplied=supplied),
            plan=plan_mod.PlanInputs(groups_meta=GROUPS)))


def _confirm_all(findings):
    out = {}
    for f in findings:
        normalized = findings_mod.normalize_finding(copy.deepcopy(f))
        out[evidence_mod.finding_fingerprint(normalized)] = {
            "finding_id": normalized["id"], "verdict": "CONFIRMED", "reasoning": "checked"}
    return out


def _identity(findings):
    return collections.Counter((f.get("fingerprint"), f.get("id")) for f in findings)


class TestUnansweredToolFindingsStayInTheReport(unittest.TestCase):
    def test_every_unanswered_tool_finding_is_kept_as_tool_reported(self):
        semgrep = [_tool("semgrep", "rule.r%d" % i, 10 + 5 * i) for i in range(5)]
        r = _build(_advisories() + semgrep)
        tools = [f for f in r["findings"] if evidence_mod.is_tool_sourced(f)]
        self.assertEqual(23, len(tools))
        self.assertEqual({"tool_reported"}, {f["evidence"]["status"] for f in tools})
        self.assertEqual({"osv-scanner": 18, "semgrep": 5},
                         dict(collections.Counter(evidence_mod.tool_name(f) for f in tools)))
        axis = r["meta"]["coverage"]["tool_axis"]
        self.assertEqual((23, 23, 0), (axis["queued"], axis["unanswered"], axis["confirmed"]))

    def test_by_tool_reconciles_every_ingested_finding(self):
        agent = _agentic(fid="AG-001", sev="CRITICAL",
                         location={"file": "app.py", "line_start": 40})
        findings = _advisories(2, 2) + [
            # One rule, three hits in one file: one survivor, two aggregated into it.
            _tool("semgrep", "rule.repeat", 10), _tool("semgrep", "rule.repeat", 12),
            _tool("semgrep", "rule.repeat", 14),
            # One rule at one locus from two panels: dedupe keeps one.
            _tool("semgrep", "rule.dup", 20, panel="security"),
            _tool("semgrep", "rule.dup", 20, panel="code"),
            # Alone beside a more severe agent claim at its locus: merged into it.
            _tool("gosec", "G101", 40, sev="LOW"),
            agent,
        ]
        axis = _build(findings)["meta"]["coverage"]["tool_axis"]
        self.assertEqual({
            "gosec": {"ingested": 1, "in_report": 0, "merged_into_agent": 1, "dropped": 0,
                      "dropped_reasons": {}},
            "osv-scanner": {"ingested": 4, "in_report": 4, "merged_into_agent": 0, "dropped": 0,
                            "dropped_reasons": {}},
            "semgrep": {"ingested": 5, "in_report": 2, "merged_into_agent": 0, "dropped": 3,
                        "dropped_reasons": {"aggregated_into_tool_finding": 2,
                                            "deduplicated_into_tool_finding": 1}},
        }, axis["by_tool"])
        for tool, row in axis["by_tool"].items():
            with self.subTest(tool=tool):
                self.assertEqual(row["ingested"], row["in_report"] + row["merged_into_agent"]
                                 + row["dropped"])
                self.assertEqual(row["dropped"], sum(row["dropped_reasons"].values()))

    def test_in_report_counts_the_report_body_and_discarded_claims(self):
        findings = _advisories(1, 3)
        rejected = findings_mod.normalize_finding(copy.deepcopy(findings[0]))
        verdicts = {evidence_mod.finding_fingerprint(rejected): {
            "finding_id": rejected["id"], "verdict": "REJECTED", "reasoning": "not reachable"}}
        r = _build(findings, verdicts=verdicts)
        self.assertEqual(1, len(r["discarded_claims"]))
        row = r["meta"]["coverage"]["tool_axis"]["by_tool"]["osv-scanner"]
        self.assertEqual((3, 3), (row["ingested"], row["in_report"]))
        self.assertEqual(3, len(r["findings"]) + len(r["discarded_claims"]))

    def test_a_report_with_no_tool_findings_has_an_empty_by_tool(self):
        r = _build([_agentic()])
        self.assertEqual({}, r["meta"]["coverage"]["tool_axis"]["by_tool"])


class TestUnansweredToolAdvisorsHoldTheLetterBack(unittest.TestCase):
    REASON = "23 tool findings unanswered by their advisors"

    def _unanswered(self, **kw):
        semgrep = [_tool("semgrep", "rule.r%d" % i, 10 + 5 * i, sev="LOW") for i in range(5)]
        return _build(_advisories() + semgrep, **kw)

    def test_the_letter_is_provisional_with_the_reason(self):
        summary = self._unanswered()["summary"]
        self.assertIsNone(summary["overall_grade"])
        self.assertEqual("S", summary["provisional_grade"])
        self.assertEqual([self.REASON], summary["grade_shortfalls"])
        self.assertFalse(summary["coverage_certified"])
        self.assertIn(self.REASON, summary["coverage_note"])
        self.assertEqual("INCONCLUSIVE", summary["gate"])

    def test_gate_off_still_holds_the_letter_back(self):
        # The owner's run: gate OFF. OFF stays OFF; the letter is still held back.
        summary = self._unanswered(fail_on=None)["summary"]
        self.assertEqual(("OFF", None, "S"), (summary["gate"], summary["overall_grade"],
                                              summary["provisional_grade"]))
        self.assertEqual([self.REASON], summary["grade_shortfalls"])

    def test_the_terminal_and_html_name_the_reason_beside_the_letter(self):
        r = self._unanswered()
        text = render_mod.render_summary(r)
        self.assertIn("**Grade:** S (provisional; %s)" % self.REASON, text)
        self.assertIn("**Coverage:** NOT CERTIFIED — %s" % self.REASON, text)
        self.assertIn("Grade: S (provisional; %s)" % self.REASON, html_report.render(r))

    def test_one_unanswered_tool_finding_reads_in_the_singular(self):
        summary = _build(_advisories(1, 1))["summary"]
        self.assertEqual(["1 tool finding unanswered by its advisor"],
                         summary["grade_shortfalls"])

    def test_answered_tool_findings_certify_the_letter(self):
        findings = _advisories(1, 2)
        summary = _build(findings, verdicts=_confirm_all(findings))["summary"]
        self.assertEqual([], summary["grade_shortfalls"])
        self.assertIsNotNone(summary["overall_grade"])
        self.assertIsNone(summary["provisional_grade"])

    def test_a_run_without_a_verify_phase_owes_no_tool_verdicts(self):
        # No --verdicts-dir at all (a direct invocation): nothing was left undone.
        summary = _build(_advisories(1, 2), supplied=False)["summary"]
        self.assertEqual([], summary["grade_shortfalls"])
        self.assertIsNotNone(summary["overall_grade"])

    def test_an_unanswered_agent_claim_is_not_a_tool_shortfall(self):
        summary = _build([_agentic()])["summary"]
        self.assertEqual([], summary["grade_shortfalls"])


class TestTheSharedShortfallRule(unittest.TestCase):
    """#3667 owner ruling: ONE rule. Any listed reason holds the letter back, so
    #3641's host-cut-short verify phase only adds its reason to the list."""

    def _certify(self, shortfalls, fail_on="high"):
        return grading_mod.certify("A", [], fail_on, set(), [], shortfalls=shortfalls)

    def test_any_reason_holds_the_letter_and_sinks_certification(self):
        cert = self._certify(["verify phase cut short by a host-class failure"])
        self.assertEqual((None, "A", False, "INCONCLUSIVE"),
                         (cert["overall_grade"], cert["provisional_grade"],
                          cert["coverage_certified"], cert["gate"]))
        self.assertEqual("verify phase cut short by a host-class failure", cert["coverage_note"])

    def test_reasons_compose_in_one_note(self):
        cert = self._certify(["2 tool findings unanswered by their advisors", "other"])
        self.assertEqual("2 tool findings unanswered by their advisors; other",
                         cert["coverage_note"])

    def test_no_reason_changes_nothing(self):
        cert = self._certify([])
        self.assertEqual(("A", None, True, "PASS", None),
                         (cert["overall_grade"], cert["provisional_grade"],
                          cert["coverage_certified"], cert["gate"], cert["coverage_note"]))

    def test_grade_shortfalls_reads_the_resolved_count(self):
        self.assertEqual([], grading_mod.grade_shortfalls(types.SimpleNamespace()))
        self.assertEqual([], grading_mod.grade_shortfalls(
            types.SimpleNamespace(unanswered_tools=0)))
        self.assertEqual(["145 tool findings unanswered by their advisors"],
                         grading_mod.grade_shortfalls(types.SimpleNamespace(unanswered_tools=145)))


def _f(fid, sev, status):
    return {"id": fid, "severity": sev, "evidence": {"status": status}}


class TestWorstFirst(unittest.TestCase):
    def test_gate_eligible_then_severity_then_status_then_input_order(self):
        low_counted = _f("A", "LOW", "tool_confirmed")
        critical_reported = _f("B", "CRITICAL", "tool_reported")
        high_unverified = _f("C", "HIGH", "unverified")
        high_needs_info = _f("D", "HIGH", "needs_more_info")
        high_needs_info_2 = _f("E", "HIGH", "needs_more_info")
        high_counted = _f("F", "HIGH", "advisor_confirmed")
        active = [low_counted, critical_reported, high_unverified, high_needs_info,
                  high_needs_info_2, high_counted]
        ordered = report_mod.worst_first(active, [low_counted, high_counted])
        self.assertEqual(["F", "A", "B", "D", "E", "C"], [f["id"] for f in ordered])

    def test_status_order_runs_best_evidence_first(self):
        statuses = ["unverified", "tool_reported", "needs_more_info", "corroborated",
                    evidence_mod.BACKUP_SCOPE_LIMITED, "advisor_confirmed", "tool_confirmed"]
        active = [_f(s, "MEDIUM", s) for s in statuses]
        self.assertEqual(list(reversed(statuses)),
                         [f["id"] for f in report_mod.worst_first(active, [])])

    def test_only_the_order_changes(self):
        active = [_f(str(i), sev, "tool_reported")
                  for i, sev in enumerate(["LOW", "HIGH", "INFO", "CRITICAL", "MEDIUM"])]
        ordered = report_mod.worst_first(active, [])
        self.assertEqual(sorted(map(id, active)), sorted(map(id, ordered)))
        self.assertEqual(["3", "1", "4", "0", "2"], [f["id"] for f in ordered])

    def test_the_report_body_is_published_worst_first(self):
        agents = [_agentic(fid="AG-%03d" % i, sev="MEDIUM",
                           location={"file": "app.py", "line_start": 100 + 10 * i})
                  for i in range(1, 6)]
        r = _build(agents + _advisories(2, 2))
        self.assertEqual(["HIGH"] * 4 + ["MEDIUM"] * 5, [f["severity"] for f in r["findings"]])


class TestASplitReportExplainsItself(unittest.TestCase):
    def _big_report(self):
        agents = [_agentic(fid="AG-%03d" % i, sev="MEDIUM",
                           location={"file": "app.py", "line_start": 10 * i + 1},
                           description="d" * 3000)
                  for i in range(1, 60)]
        return _build(agents + _advisories(6, 4))

    def _write(self, report, max_bytes):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        out = os.path.join(d.name, "report.json")
        paths = render_mod.write_report(report, out, max_bytes=max_bytes)
        with open(out, encoding="utf-8") as fh:
            main = json.load(fh)
        parts = {}
        for name in main["meta"].get("parts") or []:
            with open(os.path.join(d.name, name), encoding="utf-8") as fh:
                parts[name] = json.load(fh)["findings"]
        return main, parts, paths

    def test_the_split_keeps_the_same_findings_and_puts_the_worst_in_the_main_file(self):
        r = self._big_report()
        before = _identity(r["findings"])
        main, parts, _ = self._write(r, 60000)
        self.assertGreaterEqual(len(parts), 2)
        union = list(main["findings"]) + [f for name in sorted(parts) for f in parts[name]]
        self.assertEqual(before, _identity(union))
        self.assertEqual([f["id"] for f in r["findings"]], [f["id"] for f in union])
        # Every HIGH advisory is in the main file; the parts hold only the MEDIUM rest.
        self.assertEqual(24, sum(1 for f in main["findings"]
                                 if f.get("source") == "tool:osv-scanner"))
        self.assertEqual({"MEDIUM"}, {f["severity"] for name in parts for f in parts[name]})

    def test_the_order_does_not_depend_on_whether_the_report_is_split(self):
        r = self._big_report()
        unsplit, parts, _ = self._write(r, 50_000_000)
        self.assertEqual({}, parts)
        split, split_parts, _ = self._write(r, 60000)
        union = list(split["findings"]) + [f for n in sorted(split_parts) for f in split_parts[n]]
        self.assertEqual([f["id"] for f in unsplit["findings"]], [f["id"] for f in union])

    def test_parts_findings_names_what_each_part_holds(self):
        r = self._big_report()
        main, parts, _ = self._write(r, 60000)
        expected = {name: dict(collections.Counter(render_mod.finding_origin(f) for f in fs))
                    for name, fs in parts.items()}
        self.assertEqual(expected, main["meta"]["parts_findings"])
        self.assertEqual(main["meta"]["parts_findings"], r["meta"]["parts_findings"])

    def test_an_unsplit_write_carries_no_stale_parts_findings(self):
        r = self._big_report()
        self._write(r, 60000)
        self.assertIn("parts_findings", r["meta"])
        main, parts, _ = self._write(r, 50_000_000)
        self.assertEqual({}, parts)
        self.assertNotIn("parts_findings", main["meta"])
        self.assertNotIn("parts_findings", r["meta"])

    def test_the_terminal_and_html_say_where_the_findings_sit(self):
        r = self._big_report()
        main, parts, _ = self._write(r, 60000)
        line = render_mod.parts_line(r)
        total = len(r["findings"])
        self.assertTrue(line.startswith("the main JSON file carries %d of %d findings; "
                                        % (len(main["findings"]), total)), line)
        for name, counts in r["meta"]["parts_findings"].items():
            self.assertIn("%s: agent %d" % (name, counts["agent"]), line)
        self.assertIn("**Report parts:** %s" % line, render_mod.render_summary(r))
        self.assertIn("JSON report split: the main JSON file carries", html_report.render(r))

    def test_an_unsplit_report_prints_no_parts_line(self):
        r = self._big_report()
        self._write(r, 50_000_000)
        self.assertIsNone(render_mod.parts_line(r))
        self.assertNotIn("**Report parts:**", render_mod.render_summary(r))

    def test_the_written_main_file_matches_the_report_schema(self):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            validator = jsonschema.Draft7Validator(json.load(fh))
        r = self._big_report()
        self.assertEqual([], [e.message for e in validator.iter_errors(r)])
        main, _, _ = self._write(r, 60000)
        self.assertEqual([], [e.message for e in validator.iter_errors(main)])
        for label, path, value in (
                ("negative count", ("meta", "parts_findings", "report_part2.json", "agent"), 0),
                ("unknown drop reason", ("meta", "coverage", "tool_axis", "by_tool",
                                         "semgrep"), {"ingested": 1, "in_report": 0,
                                                      "merged_into_agent": 0, "dropped": 1,
                                                      "dropped_reasons": {"vanished": 1}}),
                ("non-string shortfall", ("summary", "grade_shortfalls"), [3])):
            with self.subTest(label):
                bad = copy.deepcopy(main)
                node = bad
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = value
                self.assertNotEqual([], list(validator.iter_errors(bad)))


if __name__ == "__main__":
    unittest.main()
