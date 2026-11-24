"""#1476: verdicts that named finding ids absent from the report.

Run-6 supplied 2,043 verdicts; 148 of them (100 distinct ids) named ids that do
not exist in the final report. It cost no coverage (`unanswered: 0`) but bound
roughly 7% of the most expensive phase of a run to nothing -- and if a CONFIRMED
verdict is among the unbound, a real finding is reported as unverified.

The issue quantified it without root-causing it and listed three candidates.
Two are ruled out by reading:

  - a code correction changing the domain prefix: `apply_verdict_quality` never
    rewrote `domain` (and since #2101 does not rewrite `code` either: an advisor's
    differing code is recorded, never applied), and ids are already assigned by
    then;
  - normalization altering title/category: both sides normalize before
    assigning, which `matrix_finding_id`'s contract requires.

The third is real and is what these tests pin: `dedupe` collapses a duplicate
and the non-survivor's id simply disappears, so the verdict that echoed it has
nothing left to bind to.

#3202 withdrew #1476's answer (the survivor carried the dropped ids as aliases
and bound their verdicts): one claim's verdict stood in for another's, a
REJECTED HIGH dismissing an unanswered CRITICAL. #2991's restore covers the
CONFIRMED-loss case instead, by reporting that claim as itself.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import jsonschema

import scripts.evidence as evidence_mod
import scripts.synth.corroborate as corroborate_mod
import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod
import scripts.synth.validate_schema as validate_schema_mod
import scripts.synthesize as syn
from tests._test_helpers import adopt_panopticon, fake_pem, pem_begin
from tests.synth.helpers import _chdir


SCHEMA_PATH = Path(validate_schema_mod.REFERENCE_DIR) / validate_schema_mod.REPORT_SCHEMA


def _finding(**kw):
    f = {"title": "t", "severity": "HIGH", "confidence": "LIKELY",
         "domain": "SEC", "code": "SEC-A1A", "category": "injection",
         "location": {"file": "app/db.py", "line_start": 42}}
    f.update(kw)
    return findings_mod.normalize_finding(f)


class CollapsedIdBindingTest(unittest.TestCase):
    def _pair(self):
        """Two findings at one locus that dedupe collapses into one.

        The categories differ deliberately. `matrix_finding_id` seeds on
        (domain, category, file, title, line_start), so a tool and an agent that
        agree on all five already share an id and nothing can unbind. The lost
        verdicts are the case where they do NOT agree -- a scanner's rule name
        against a reviewer's vocabulary for the same locus -- which dedupe
        collapses "even across categories"."""
        agent = _finding(source="agent:security-reviewer", category="injection")
        tool = _finding(source="tool:semgrep", severity="MEDIUM",
                        category="sql-injection", title="tainted query")
        for f in (agent, tool):
            f["id"] = evidence_mod.matrix_finding_id(f)
        return agent, tool

    def test_dedupe_keeps_the_member_it_collapses(self):
        # #3202: the survivor no longer carries id aliases; dedupe keeps the
        # dropped member itself (#2991's carrier), for restore_confirmed.
        agent, tool = self._pair()
        self.assertNotEqual(agent["id"], tool["id"], "fixture needs two distinct ids")
        survivors = corroborate_mod.dedupe([agent, tool])
        self.assertEqual(len(survivors), 1, "fixture must actually collapse")
        absorbed = [m["id"] for m in survivors[0][corroborate_mod.ABSORBED_FIELD]]
        self.assertEqual(set(absorbed) | {survivors[0]["id"]}, {agent["id"], tool["id"]},
                         "the collapsed member must survive somewhere")
        self.assertNotIn("_merged_ids", survivors[0])

    def test_a_verdict_naming_a_collapsed_id_no_longer_binds_to_the_survivor(self):
        # #3202 withdraws #1476's alias binding: a verdict is about the claim it
        # names. The tool MEDIUM's verdict cannot decide the agent HIGH's fate.
        agent, tool = self._pair()
        survivor = corroborate_mod.dedupe([agent, tool])[0]
        collapsed = next(i for i in (agent["id"], tool["id"]) if i != survivor["id"])
        for verdict in ("CONFIRMED", "REJECTED", "NEEDS_MORE_INFO"):
            with self.subTest(verdict=verdict):
                by_fid = {collapsed: [{"verdict": verdict, "stage": "primary",
                                       "run_id": "RID", "finding_id": collapsed}]}
                self.assertIsNone(evidence_mod.match_verdict_by_id(survivor, by_fid, run_id="RID"))

    def test_a_collapsed_confirmed_is_still_reported_confirmed(self):
        # #1476's original concern, kept as a pin: a CONFIRMED verdict on a
        # collapsed twin must not leave a real finding unverified. #2991's
        # restore now reports that claim as itself instead of lending it.
        agent, tool = self._pair()
        survivor_id = corroborate_mod.dedupe([dict(agent), dict(tool)])[0]["id"]
        collapsed = tool if agent["id"] == survivor_id else agent
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp="2026-10-20T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[agent, tool], verdict_run_id="RID", verdicts_supplied=True,
                verdict_bundles={collapsed["id"]: [{"verdict": "CONFIRMED", "stage": "primary", "run_id": "RID",
                                                    "finding_id": collapsed["id"], "reasoning": "r"}]})))
        statuses = {f["id"]: f["evidence"]["status"] for f in report["findings"]}
        self.assertIn(collapsed["id"], statuses)
        self.assertIn(statuses[collapsed["id"]], ("advisor_confirmed", "tool_confirmed"))

    def test_the_survivors_own_id_still_wins_over_an_alias(self):
        # An alias must never outrank the finding's real id: the survivor's own
        # verdict is the one that adjudicated the finding that survived.
        agent, tool = self._pair()
        survivors = corroborate_mod.dedupe([agent, tool])
        survivor = survivors[0]
        collapsed = next(i for i in (agent["id"], tool["id"]) if i != survivor["id"])
        by_fid = {
            survivor["id"]: [{"verdict": "CONFIRMED", "stage": "primary",
                              "run_id": "RID"}],
            collapsed: [{"verdict": "REFUTED", "stage": "backup", "run_id": "RID"}],
        }
        self.assertEqual(
            evidence_mod.match_verdict_by_id(survivor, by_fid, run_id="RID")["verdict"],
            "CONFIRMED")

    def test_an_alias_verdict_from_another_run_is_still_rejected(self):
        # Aliasing widens WHICH id binds, never which RUN may bind. A stale
        # cross-run verdict must not gain a new way in.
        agent, tool = self._pair()
        survivor = corroborate_mod.dedupe([agent, tool])[0]
        collapsed = next(i for i in (agent["id"], tool["id"]) if i != survivor["id"])
        by_fid = {collapsed: [{"verdict": "CONFIRMED", "stage": "primary",
                               "run_id": "OTHER-RUN"}]}
        self.assertIsNone(
            evidence_mod.match_verdict_by_id(survivor, by_fid, run_id="RID"))

    def test_a_finding_with_no_merges_absorbs_nothing(self):
        f = _finding()
        f["id"] = evidence_mod.matrix_finding_id(f)
        self.assertNotIn(corroborate_mod.ABSORBED_FIELD, corroborate_mod.dedupe([f])[0])


def _with_id(f):
    """Assign the content-derived id load_findings would; build_report expects one."""
    f["id"] = evidence_mod.matrix_finding_id(f)
    return f


class LocationContractTest(unittest.TestCase):
    """#1522 (COD-D1B, advisor-confirmed): report-schema.json required
    location.file AND location.line_start whenever a finding carried a location
    object at all, but normalize_finding legitimately emits one missing both --
    `{"line_end": null, "function": null}` -- for a finding whose payload had no
    location. That is TWO violations (the required array, and null against
    line_end's integer type), and `validate_report` only WARNS, so the shape
    reached the shipped artifact. Third live instance of the class the catalog's
    own COD-D1B entry records.

    Contract decided here: a location, if present, identifies a FILE. A finding
    with no locus at all carries no location key -- which already validates,
    since `location` is not in the finding-level required list. A whole-file
    finding (a missing header, a bad config) is legitimate and keeps its file
    without inventing a line number.
    """

    def _validate(self, finding):
        import json
        import jsonschema
        with SCHEMA_PATH.open(encoding="utf-8") as fh:
            schema = json.load(fh)
        loc_schema = schema["properties"]["findings"]["items"]["properties"]["location"]
        jsonschema.validate(finding["location"], loc_schema)

    def test_a_finding_with_no_locus_carries_no_location_key(self):
        f = findings_mod.normalize_finding(
            {"title": "repo-wide catalog gap", "severity": "INFO",
             "domain": "COD", "code": "COD-A1A", "category": "coverage"})
        self.assertNotIn("location", f,
                         "an empty location object violates the schema it ships under")

    def test_a_whole_file_finding_keeps_its_file_without_a_line(self):
        f = findings_mod.normalize_finding(
            {"title": "missing license header", "severity": "LOW",
             "domain": "COD", "code": "COD-A1A", "category": "style",
             "location": {"file": "src/app.py"}})
        self.assertEqual(f["location"]["file"], "src/app.py")
        self.assertNotIn("line_start", f["location"])
        self.assertNotIn("line_end", f["location"])   # null violates integer
        self._validate(f)

    def test_a_normal_finding_round_trips_through_the_schema(self):
        f = findings_mod.normalize_finding(
            {"title": "sqli", "severity": "HIGH", "domain": "SEC",
             "code": "SEC-A1A", "category": "injection",
             "location": {"file": "app/db.py", "line_start": 42}})
        self.assertEqual(f["location"]["line_end"], 42)
        self._validate(f)

    def test_a_locationless_finding_validates_in_a_whole_report(self):
        # The gap the issue names: every existing fixture builds a well-formed
        # location, so the degrade path was never run through jsonschema.
        import json
        import jsonschema
        import scripts.synth.report as report_mod
        import scripts.synth.plan as plan_mod
        r = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None,
                                     timestamp="2026-01-01T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[_with_id(
                findings_mod.normalize_finding(
                    {"title": "repo-wide gap", "severity": "INFO", "domain": "COD",
                     "code": "COD-A1A", "category": "coverage"}))]),
            plan=plan_mod.PlanInputs(groups_meta=[{"name": "g", "files": []}]),
        ))
        with SCHEMA_PATH.open(encoding="utf-8") as fh:
            jsonschema.validate(r, json.load(fh))


# ----------------------------------------------------------------------
# #3756: a verdict on an aggregated scanner finding covers only the hits it judged.
#
# A scanner rule that fires nine times in one file is ONE finding with a shown line
# and eight `additional_loci`. The advisor was handed all nine, judged five (all
# constants, correctly), said the sixth was "outside the claim's locus", and its one
# REJECTED discarded all nine -- the real command injection among them, in every run.
#
# The rule: REJECTED means every hit is safe. A REJECTED that does not name every hit
# in `judged_loci` is not a rejection of the finding; the finding stays in the report,
# answered and not verified, with the lines nobody judged.

RULE = "security/detect-child-process"
# Eight calls with a constant command, and one (line 63) that interpolates a path
# read from the filesystem: the real one.
LINES = (12, 20, 31, 44, 58, 63, 77, 81, 95)
REAL = 63
SAFE_FIVE = [12, 20, 31, 44, 58]            # what the recorded verdict walked
SOURCE = "\n".join(
    ("  exec(`convert ${fs.readdirSync(dir)[0]} out.png`);" if n == REAL
     else '  exec("git status");' if n in LINES else "  // ...")
    for n in range(1, 101)) + "\n"


def _capture(lines=LINES, path="/src/lib/run.js"):
    return [{"filePath": path, "errorCount": len(lines), "warningCount": 0, "source": "",
             "messages": [{"ruleId": RULE, "severity": 2, "line": n, "column": 3,
                           "endLine": n, "endColumn": 40,
                           "message": "Found child_process.exec() with non Literal "
                                      "first argument"} for n in lines]}]


class _Replay(unittest.TestCase):
    """A recorded verdict replayed through both passes of `synthesize`."""

    def replay(self, verdict, lines=LINES, extra=(), as_bundle=False):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            adopt_panopticon(os.getcwd())
            os.makedirs(os.path.join(d, "lib"))
            with open(os.path.join(d, "lib", "run.js"), "w", encoding="utf-8") as fh:
                fh.write(SOURCE)
            agent = os.path.join(d, "findings-g1-COD.json")
            with open(agent, "w", encoding="utf-8") as fh:
                json.dump({"findings": []}, fh)
            td = os.path.join(d, "tools")
            os.makedirs(td)
            with open(os.path.join(td, "eslint-security.json"), "w", encoding="utf-8") as fh:
                json.dump(_capture(lines), fh)
            self.stdout, self.stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(self.stdout), \
                    contextlib.redirect_stderr(self.stderr):
                rc1 = syn.main(["--repo", "--emit-verify-queue", "--tools-dir", td,
                                "--out", os.path.join(d, "unused.json"), agent])
            self.assertEqual(0, rc1, self.stderr.getvalue())
            with open(os.path.join(d, ".panopticon", "verify-queue.json"),
                      encoding="utf-8") as fh:
                queue = json.load(fh)
            self.assertEqual(1, len(queue["entries"]))
            entry = queue["entries"][0]
            self.claim = entry["finding"]
            if verdict is not None:
                vd = os.path.join(d, "verdicts")
                os.makedirs(vd)
                answer = dict({"run_id": queue["run_id"], "finding_id": self.claim["id"],
                               "confidence": "CERTAIN", "explored": ["lib/run.js"],
                               "references": [], "citations": {}}, **verdict)
                # The queue id names the answer's file; it is read back from the queue
                # this run wrote, so hold it to one plain file name first.
                name = "bundle" if as_bundle else os.path.basename(str(entry["queue_id"]))
                self.assertEqual(name, "bundle" if as_bundle else entry["queue_id"])
                target = os.path.realpath(os.path.join(vd, name + ".json"))
                self.assertEqual(os.path.realpath(vd), os.path.dirname(target))
                with open(target, "w", encoding="utf-8") as fh:
                    json.dump({"verdicts": [answer]} if as_bundle else answer, fh)
                extra = ("--verdicts-dir", vd, *extra)
            out = os.path.join(d, "report.json")
            self.stdout = io.StringIO()
            with contextlib.redirect_stdout(self.stdout), \
                    contextlib.redirect_stderr(self.stderr):
                self.rc = syn.main(["--repo", "--tools-dir", td, "--fail-on", "high",
                                    "--out", out, *extra, agent])
            with open(out, encoding="utf-8") as fh:
                return json.load(fh)

    def one(self, report, where):
        other = "discarded_claims" if where == "findings" else "findings"
        self.assertEqual([], report[other])
        self.assertEqual(1, len(report[where]))
        return report[where][0]


class TestARejectionCoversOnlyTheHitsItJudged(_Replay):
    REASONING = ("Lines 12, 20, 31, 44 and 58 each pass a string literal. Line 63 is a "
                 "different construct with a filesystem-derived path; it is outside the "
                 "claim's locus and was not evaluated here.")

    def test_the_claim_is_one_finding_with_every_hit(self):
        self.replay(None)
        self.assertEqual(12, self.claim["location"]["line_start"])
        self.assertEqual(list(LINES[1:]),
                         [locus["line_start"] for locus in self.claim["additional_loci"]])
        self.assertEqual(9, self.claim["occurrences"])
        self.assertEqual("HIGH", self.claim["severity"])

    def test_the_recorded_case_stays_in_the_report(self):
        # The verdict of the issue: five of nine judged, the real one named as
        # "outside the claim". It discarded all nine.
        report = self.replay({"verdict": "REJECTED", "reasoning": self.REASONING,
                              "judged_loci": SAFE_FIVE})
        finding = self.one(report, "findings")
        ev = finding["evidence"]
        self.assertEqual("needs_more_info", ev["status"])
        self.assertEqual([63, 77, 81, 95], ev["unjudged_loci"])
        self.assertIn(REAL, ev["unjudged_loci"])
        self.assertTrue(ev["reasoning"].startswith(
            "The advisor judged 5 of 9 flagged lines safe; 4 were not judged."), ev["reasoning"])
        self.assertIn(self.REASONING, ev["reasoning"])
        # Every hit is still on the finding.
        self.assertEqual(9, finding["occurrences"])
        self.assertEqual(8, len(finding["additional_loci"]))
        # Not verified, so the scanner's HIGH is capped as any unverified pattern
        # hit is (#3231), and it does not gate.
        self.assertEqual("MEDIUM", finding["severity"])
        self.assertEqual("HIGH", finding["severity_cap"]["from"])
        # Answered: the advisor did reply, and the run is not short of a verdict.
        axis = report["meta"]["coverage"]["tool_axis"]
        self.assertEqual((1, 0, 1, 0), (axis["queued"], axis["rejected"],
                                        axis["needs_more_info"], axis["unanswered"]))
        # ... so certification reads exactly as it does when the rejection stands.
        control = self.replay({"verdict": "REJECTED", "reasoning": "All constants.",
                               "judged_loci": list(LINES)})
        for key in ("coverage_certified", "coverage_note", "gate"):
            self.assertEqual(control["summary"][key], report["summary"][key])
        self.assertNotEqual("FAIL", report["summary"]["gate"])

    def test_it_keeps_its_severity_and_gates_when_unverified_findings_gate(self):
        report = self.replay({"verdict": "REJECTED", "reasoning": self.REASONING,
                              "judged_loci": SAFE_FIVE}, extra=("--gate-unverified",))
        finding = self.one(report, "findings")
        self.assertEqual("HIGH", finding["severity"])
        self.assertEqual("FAIL", report["summary"]["gate"])
        self.assertEqual(1, self.rc)

    def test_a_rejection_that_names_every_hit_stands(self):
        # The control: as on main.
        for judged in (list(LINES), list(reversed(LINES)), list(LINES) + [12, 12, 999]):
            with self.subTest(judged=judged):
                report = self.replay({"verdict": "REJECTED", "reasoning": "All constants.",
                                      "judged_loci": judged})
                finding = self.one(report, "discarded_claims")
                self.assertEqual("rejected", finding["evidence"]["status"])
                self.assertNotIn("unjudged_loci", finding["evidence"])
                self.assertEqual("All constants.", finding["evidence"]["reasoning"])

    def test_one_hit_short_is_not_a_rejection(self):
        for missing in LINES:              # the shown line is a hit like the others
            with self.subTest(missing=missing):
                report = self.replay({"verdict": "REJECTED", "reasoning": "r",
                                      "judged_loci": [n for n in LINES if n != missing]})
                ev = self.one(report, "findings")["evidence"]
                self.assertEqual("needs_more_info", ev["status"])
                self.assertEqual([missing], ev["unjudged_loci"])
                self.assertTrue(ev["reasoning"].startswith(
                    "The advisor judged 8 of 9 flagged lines safe; 1 was not judged."))

    def test_a_host_that_omits_the_field_fails_safe(self):
        # Every verdict saved before this change, and any host whose advisor does
        # not write the field: an answer that covers no hit.
        report = self.replay({"verdict": "REJECTED", "reasoning": "Constants."})
        ev = self.one(report, "findings")["evidence"]
        self.assertEqual("needs_more_info", ev["status"])
        self.assertEqual(list(LINES), ev["unjudged_loci"])
        self.assertTrue(ev["reasoning"].startswith(
            "The advisor judged 0 of 9 flagged lines safe; 9 were not judged."))

    def test_a_wrong_type_is_an_absent_field(self):
        for value in ("12, 20, 31, 44, 58, 63, 77, 81, 95", 12, None, {"12": True},
                      [str(n) for n in LINES], [float(n) for n in LINES],
                      [[n] for n in LINES], [{"line_start": n} for n in LINES],
                      [True] * 9):
            with self.subTest(value=value):
                report = self.replay({"verdict": "REJECTED", "reasoning": "r",
                                      "judged_loci": value})
                ev = self.one(report, "findings")["evidence"]
                self.assertEqual("needs_more_info", ev["status"])
                self.assertEqual(list(LINES), ev["unjudged_loci"])

    def test_a_number_that_is_no_hit_counts_for_nothing(self):
        report = self.replay({"verdict": "REJECTED", "reasoning": "r",
                              "judged_loci": [1, 13, 62, 64, 96, -12, 0, 10 ** 30, 12]})
        ev = self.one(report, "findings")["evidence"]
        self.assertEqual(list(LINES[1:]), ev["unjudged_loci"])

    def test_an_advisor_cannot_say_what_was_left_unjudged(self):
        # The list of unjudged lines is the controller's. A verdict that plants the
        # carrier, or the published key, decides nothing.
        report = self.replay({"verdict": "REJECTED", "reasoning": "r",
                              "judged_loci": SAFE_FIVE, "unjudged_loci": [],
                              evidence_mod.UNJUDGED_FIELD: []})
        ev = self.one(report, "findings")["evidence"]
        self.assertEqual([63, 77, 81, 95], ev["unjudged_loci"])

    def test_a_partial_rejection_names_no_file_the_advisor_was_not_granted(self):
        # `missing_evidence` on a NEEDS_MORE_INFO means "a file I could not read".
        # This advisor rejected; whatever it put there is not that statement.
        report = self.replay({"verdict": "REJECTED", "reasoning": "r",
                              "judged_loci": SAFE_FIVE, "missing_evidence": ["lib/other.js"]})
        ev = self.one(report, "findings")["evidence"]
        self.assertEqual("needs_more_info", ev["status"])
        self.assertNotIn("missing_evidence", ev)

    def test_only_the_controller_s_list_is_published(self):
        for word in ("CONFIRMED", "NEEDS_MORE_INFO"):
            with self.subTest(word=word):
                report = self.replay({"verdict": word, "reasoning": "r",
                                      "unjudged_loci": [63],
                                      evidence_mod.UNJUDGED_FIELD: [63]})
                self.assertNotIn("unjudged_loci", self.one(report, "findings")["evidence"])

    def test_a_scanner_finding_is_answered_by_its_own_verdict_file_only(self):
        # Why the rule is applied to the queue-id answers and not to bundles: a cell's
        # bundle does not speak for a finding that came from no cell, so a bundle
        # that names a scanner finding rejects nothing, with or without the list.
        for extra in ({}, {"judged_loci": list(LINES)}):
            with self.subTest(extra=extra):
                report = self.replay(dict({"verdict": "REJECTED", "reasoning": "r"}, **extra),
                                     as_bundle=True)
                self.assertEqual("tool_reported",
                                 self.one(report, "findings")["evidence"]["status"])

    def test_confirmed_needs_no_list(self):
        # One real hit makes the finding real. Rejecting says "none of these";
        # confirming says "at least one".
        for extra in ({}, {"judged_loci": [REAL]}, {"judged_loci": "63"}):
            with self.subTest(extra=extra):
                report = self.replay(dict({"verdict": "CONFIRMED",
                                           "reasoning": "Line 63 is injectable."}, **extra))
                finding = self.one(report, "findings")
                self.assertEqual("tool_confirmed", finding["evidence"]["status"])
                self.assertNotIn("unjudged_loci", finding["evidence"])
                self.assertEqual("HIGH", finding["severity"])
                self.assertEqual("FAIL", report["summary"]["gate"])

    def test_needs_more_info_is_unchanged(self):
        report = self.replay({"verdict": "NEEDS_MORE_INFO", "reasoning": "Cannot tell.",
                              "judged_loci": SAFE_FIVE})
        ev = self.one(report, "findings")["evidence"]
        self.assertEqual("needs_more_info", ev["status"])
        self.assertNotIn("unjudged_loci", ev)
        self.assertEqual("Cannot tell.", ev["reasoning"])

    def test_a_finding_with_one_hit_is_rejected_as_before(self):
        for extra in ({}, {"judged_loci": [12]}, {"judged_loci": []},
                      {"judged_loci": "nonsense"}):
            with self.subTest(extra=extra):
                report = self.replay(dict({"verdict": "REJECTED", "reasoning": "Constant."},
                                          **extra), lines=(12,))
                finding = self.one(report, "discarded_claims")
                self.assertEqual("rejected", finding["evidence"]["status"])
                self.assertEqual("Constant.", finding["evidence"]["reasoning"])

    def test_two_hits_on_one_line_are_one_line_to_judge(self):
        report = self.replay({"verdict": "REJECTED", "reasoning": "r", "judged_loci": [12, 20]},
                             lines=(12, 12, 20))
        self.assertEqual("rejected", self.one(report, "discarded_claims")["evidence"]["status"])
        report = self.replay({"verdict": "REJECTED", "reasoning": "r", "judged_loci": [12]},
                             lines=(12, 12, 20))
        ev = self.one(report, "findings")["evidence"]
        self.assertEqual([20], ev["unjudged_loci"])
        self.assertTrue(ev["reasoning"].startswith(
            "The advisor judged 1 of 2 flagged lines safe; 1 was not judged."))


class TestTheLinesOfAClaim(unittest.TestCase):
    def finding(self, *lines, source="tool:eslint-security"):
        loci = [{"file": "a.js", "line_start": n} for n in lines[1:]]
        f = {"id": "T-1", "source": source, "location": {"file": "a.js", "line_start": lines[0]}}
        if loci:
            f["additional_loci"], f["occurrences"] = loci, len(lines)
        return f

    def unjudged(self, finding, **verdict):
        return evidence_mod.unjudged_loci(finding, dict({"verdict": "REJECTED"}, **verdict))

    def test_only_a_rejection_of_an_aggregated_scanner_finding_is_checked(self):
        many = self.finding(3, 9, 27)
        self.assertEqual([3, 9, 27], self.unjudged(many))
        self.assertEqual([27], self.unjudged(many, judged_loci=[9, 3]))
        self.assertEqual([], self.unjudged(many, judged_loci=[27, 9, 3]))
        self.assertEqual([], self.unjudged(self.finding(3)))
        for word in ("CONFIRMED", "NEEDS_MORE_INFO", "confirmed", "", None):
            self.assertEqual([], evidence_mod.unjudged_loci(many, {"verdict": word}))
        self.assertEqual([], evidence_mod.unjudged_loci(many, None))
        self.assertEqual([3, 9, 27], evidence_mod.unjudged_loci(many, {"verdict": "rejected"}))

    def test_a_hit_with_no_line_can_never_be_judged(self):
        # Nothing the advisor could write names it, so such a finding is never
        # rejected. It can still be confirmed.
        for odd in (None, "9", 9.0, True):
            finding = self.finding(3, 9)
            finding["additional_loci"][0]["line_start"] = odd
            with self.subTest(line=odd):
                self.assertEqual([3, None], self.unjudged(finding))
                self.assertEqual([None], self.unjudged(finding, judged_loci=[3, 9]))
        finding = self.finding(3, 9)
        finding["location"]["line_start"] = None
        self.assertEqual([None], self.unjudged(finding, judged_loci=[9]))
        finding["additional_loci"] = ["not a locus", {"line_start": 9}]
        self.assertEqual([None], self.unjudged(finding, judged_loci=[9]))
        # An entry that is no locus is a hit nobody can name, not a hit that is not there.
        finding = self.finding(3, 9)
        finding["additional_loci"].append("not a locus")
        self.assertEqual([None], self.unjudged(finding, judged_loci=[3, 9]))

    def test_the_verdict_it_was_given_is_not_changed(self):
        # The loaded verdict is shared: the file accounting reads it after this.
        verdict = {"verdict": "REJECTED", "reasoning": "r", "judged_loci": [3],
                   "missing_evidence": ["x.py"], "finding_id": "T-1"}
        before = json.loads(json.dumps(verdict))
        held = evidence_mod.judged_only(self.finding(3, 9), verdict)
        self.assertEqual(before, verdict)
        self.assertIsNot(held, verdict)
        self.assertEqual(("NEEDS_MORE_INFO", [9], "T-1"),
                         (held["verdict"], held[evidence_mod.UNJUDGED_FIELD],
                          held["finding_id"]))
        # ... and one that stands is returned as it is, not copied.
        whole = dict(verdict, judged_loci=[3, 9])
        self.assertIs(whole, evidence_mod.judged_only(self.finding(3, 9), whole))

    def test_loci_that_are_not_a_list_are_no_aggregation(self):
        for loci in (None, [], "9", {"line_start": 9}):
            finding = self.finding(3)
            finding["additional_loci"] = loci
            with self.subTest(loci=loci):
                self.assertEqual([], self.unjudged(finding))

    def test_an_agent_claim_that_carries_a_scanner_s_lines_is_not_changed(self):
        # `corroborate._carry_aggregation` (#2361) puts a dropped scanner member's
        # lines on an agent survivor. That claim is the agent's, about its own line,
        # and its advisor is not asked for `judged_loci`: as on main. Its REJECTED
        # still discards the carried lines; that is #3786 (5.5.x), not this rule.
        carried = self.finding(3, 9, 27, source="agent:COD")
        self.assertEqual([], self.unjudged(carried))
        del carried["source"]
        self.assertEqual([], self.unjudged(carried))


class TestTheAdvisorIsToldAndTheReceiptCarriesIt(unittest.TestCase):
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def _reference(self, name):
        with open(os.path.join(self.ROOT, "skill", "reference", name), encoding="utf-8") as fh:
            return json.load(fh)

    def test_the_prompt_says_every_hit_is_part_of_the_claim(self):
        with open(os.path.join(self.ROOT, "skill", "agents", "advisor.md"),
                  encoding="utf-8") as fh:
            text = fh.read()
        template = text.split("## Your task", 1)[1]
        self.assertIn('"judged_loci": [', template.split("```json", 1)[1].split("```", 1)[0])
        rule = text.split("## Tool claims", 1)[1]
        for needed in ("`additional_loci`", "part of the claim", "`judged_loci`",
                       "REJECTED only when every"):
            self.assertIn(needed, rule)

    def test_the_prompt_for_an_aggregated_claim_holds_every_line(self):
        import scripts.phases.verify_tools as verify_tools
        finding = {"id": "ESS-001", "title": "exec", "severity": "HIGH",
                   "source": "tool:eslint-security",
                   "location": {"file": "lib/run.js", "line_start": 12},
                   "additional_loci": [{"file": "lib/run.js", "line_start": n}
                                       for n in LINES[1:]],
                   "occurrences": 9}
        with tempfile.TemporaryDirectory() as d:
            adopt_panopticon(d)
            os.makedirs(os.path.join(d, "lib"))
            with open(os.path.join(d, "lib", "run.js"), "w", encoding="utf-8") as fh:
                fh.write(SOURCE)
            with contextlib.redirect_stderr(io.StringIO()):
                entry = verify_tools._tool_verify_entry(
                    d, {"run_id": "rid-1", "host": "claude"}, "q-1", finding, "claude")
        claim = entry["prompt"]
        for n in LINES:
            self.assertIn('"line_start": %d' % n, claim)
        self.assertIn('"occurrences": 9', claim)

    def test_the_receipt_schema_takes_line_numbers_and_nothing_else(self):
        schema = self._reference("advisor-verdict-schema.json")
        verdict = {"finding_id": "ESS-001", "verdict": "REJECTED", "confidence": "CERTAIN",
                   "reasoning": "r", "explored": [], "references": [], "citations": {}}
        jsonschema.validate(verdict, schema)                      # optional
        jsonschema.validate(dict(verdict, judged_loci=[12, 20]), schema)
        jsonschema.validate(dict(verdict, judged_loci=[]), schema)
        for bad in ("12", [12.5], ["12"], [{"line_start": 12}], 12):
            with self.subTest(bad=bad), self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate(dict(verdict, judged_loci=bad), schema)

    def test_the_strict_generation_schema_requires_it(self):
        # Codex generates against a closed projection in which every property is
        # required (#3241), so its tool advisor always writes the field.
        schema = self._reference("tool-advisor-generation-schema.json")
        self.assertIn("judged_loci", schema["required"])
        self.assertEqual({"type": "array", "items": {"type": "integer"}},
                         schema["properties"]["judged_loci"])
        self.assertEqual(sorted(schema["properties"]), sorted(schema["required"]))

    def test_the_report_schema_describes_the_unjudged_lines(self):
        schema = self._reference("report-schema.json")
        found = []

        def walk(node):
            if isinstance(node, dict):
                if "unjudged_loci" in node and "status" in node:
                    found.append(node["unjudged_loci"])
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
        walk(schema)
        self.assertTrue(found)
        for node in found:
            self.assertEqual("array", node["type"])
            self.assertEqual({"type": ["integer", "null"]}, node["items"])


if __name__ == "__main__":
    unittest.main()


class TestARejectedScannerHighIsShownAsRejected(_Replay):
    """#3756, the safety net. An advisor's REJECTED takes a scanner finding out of the
    gate and the grade, and it went to `discarded_claims` with every other rejected
    claim: a count on the terminal and a collapsed block on the page, and a large
    report's main file holds none of them (they move to a sibling file). A rejection of
    a scanner HIGH or CRITICAL is one advisor's word against a scanner's, so it is
    listed where the operator reads, with the advisor's reasoning. Disclosure only:
    the gate, the grade and every count are what they were."""

    ALL = {"verdict": "REJECTED", "reasoning": "Every call passes a string literal.",
           "judged_loci": list(LINES)}

    def test_the_report_lists_it_with_the_advisor_s_reasoning(self):
        report = self.replay(self.ALL)
        discarded = self.one(report, "discarded_claims")
        listed = report["meta"]["rejected_scanner_findings"]
        self.assertEqual(1, listed["count"])
        self.assertEqual([{"id": discarded["id"], "tool": "eslint-security", "rule": RULE,
                           "severity": "HIGH", "file": "lib/run.js", "line_start": 12,
                           "occurrences": 9, "title": discarded["title"],
                           "reasoning": "Every call passes a string literal."}],
                         listed["rows"])

    def test_the_terminal_summary_names_it(self):
        self.replay(self.ALL)
        text = self.stdout.getvalue()
        self.assertIn("## Rejected scanner findings (HIGH and above): 1", text)
        row, = [line for line in text.splitlines() if "lib/run.js:12" in line]
        for needed in ("`[HIGH]`", "eslint-security", RULE, "9 hits",
                       "Every call passes a string literal."):
            self.assertIn(needed, row)
        self.assertIn("not counted by the gate", text)

    def test_the_page_shows_it_open(self):
        import scripts.html_report as html_report
        page = html_report.render(self.replay(self.ALL))
        section = page.split("<section class=\"findings rejected-scanner-findings\">", 1)[1]
        section = section.split("</section>", 1)[0]
        self.assertNotIn("<details", section)          # not collapsed
        for needed in ("Rejected scanner findings", "lib/run.js:12", "eslint-security",
                       "Every call passes a string literal."):
            self.assertIn(needed, section)

    def test_it_changes_no_verdict_and_no_count(self):
        report = self.replay(self.ALL)
        self.assertEqual([], report["findings"])
        self.assertEqual({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                         report["summary"]["stats"])
        self.assertNotEqual("FAIL", report["summary"]["gate"])
        axis = report["meta"]["coverage"]["tool_axis"]
        self.assertEqual((1, 1, 0), (axis["queued"], axis["rejected"], axis["needs_more_info"]))

    def test_nothing_is_listed_when_nothing_qualifies(self):
        import scripts.html_report as html_report
        cases = (("confirmed", {"verdict": "CONFIRMED", "reasoning": "r"}),
                 ("not judged in full", {"verdict": "REJECTED", "reasoning": "r",
                                         "judged_loci": SAFE_FIVE}),
                 ("no verdict", None))
        for label, verdict in cases:
            with self.subTest(case=label):
                report = self.replay(verdict)
                self.assertNotIn("rejected_scanner_findings", report["meta"])
                self.assertNotIn("Rejected scanner findings", self.stdout.getvalue())
                self.assertNotIn("rejected-scanner-findings\">", html_report.render(report))

    def test_the_list_is_scanner_findings_of_high_and_above_only(self):
        import scripts.evidence_sections as evidence_sections

        def claim(source, severity, status="rejected", n=1):
            return {"id": "F-%d" % n, "source": source, "severity": severity,
                    "title": "t%d" % n, "location": {"file": "a.js", "line_start": n},
                    "tool_evidence": {"rule_id": "r"},
                    "evidence": {"status": status, "reasoning": "why"}}
        rejected = [claim("tool:semgrep", "CRITICAL", n=1), claim("tool:semgrep", "HIGH", n=2),
                    claim("tool:semgrep", "MEDIUM", n=3), claim("tool:semgrep", "LOW", n=4),
                    claim("agent:COD", "CRITICAL", n=5), claim(None, "HIGH", n=6),
                    claim("tool:semgrep", "HIGH", status="needs_more_info", n=7),
                    "not a finding", {"source": "tool:semgrep"}]
        listed = evidence_sections.rejected_scanner_findings(rejected)
        self.assertEqual(2, listed["count"])
        self.assertEqual(["F-1", "F-2"], [row["id"] for row in listed["rows"]])
        self.assertIsNone(evidence_sections.rejected_scanner_findings(rejected[2:]))
        self.assertIsNone(evidence_sections.rejected_scanner_findings([]))
        self.assertIsNone(evidence_sections.rejected_scanner_findings(None))

    def test_the_list_is_bounded_and_says_what_it_left_out(self):
        import scripts.evidence_sections as evidence_sections
        import scripts.synth.render as render_mod
        many = [{"id": "F-%03d" % n, "source": "tool:semgrep",
                 "severity": "CRITICAL" if n == 59 else "HIGH", "title": "t",
                 "location": {"file": "a.js", "line_start": n},
                 "tool_evidence": {"rule_id": "r"},
                 "evidence": {"status": "rejected", "reasoning": "x" * 5000}}
                for n in range(60)]
        listed = evidence_sections.rejected_scanner_findings(many)
        self.assertEqual(60, listed["count"])
        self.assertEqual(evidence_sections.REJECTED_SCANNER_ROWS, len(listed["rows"]))
        self.assertEqual(50, evidence_sections.REJECTED_SCANNER_ROWS)
        self.assertEqual("F-059", listed["rows"][0]["id"])       # the most severe first
        self.assertEqual(["F-000", "F-001"], [row["id"] for row in listed["rows"][1:3]])
        for row in listed["rows"]:
            self.assertEqual(evidence_sections.REJECTED_REASONING_CAP, len(row["reasoning"]))
            self.assertTrue(row["reasoning"].endswith(" [cut]"))
        self.assertEqual(600, evidence_sections.REJECTED_REASONING_CAP)
        lines = render_mod.rejected_scanner_lines(listed)
        self.assertIn("## Rejected scanner findings (HIGH and above): 60", lines)
        self.assertEqual(50, sum(1 for line in lines if line.startswith("- `[")))
        self.assertTrue(any("10 more" in line for line in lines))

    def test_a_key_the_bound_would_cut_never_reaches_any_output(self):
        # Seat review of fd8f260d, MEDIUM: the reasoning was cut to its bound BEFORE the
        # report's redaction, and the private-key rule needs both delimiters, so a cut
        # that dropped the END left the key body in plain text in all three outputs.
        import scripts.evidence_sections as evidence_sections
        import scripts.html_report as html_report
        body = "Qk3y" * 100
        for label, reasoning in (
                ("a key whose END is past the bound",
                 "x" * 500 + fake_pem(body=body) + " and so on"),
                ("a key with no END at all", "see " + pem_begin() + "\n" + body)):
            with self.subTest(label):
                report = self.replay(dict(self.ALL, reasoning=reasoning))
                row, = report["meta"]["rejected_scanner_findings"]["rows"]
                self.assertIn("[REDACTED_PRIVATE_KEY]", row["reasoning"])
                self.assertLessEqual(len(row["reasoning"]),
                                     evidence_sections.REJECTED_REASONING_CAP)
                for where, text in (("meta", json.dumps(report["meta"])),
                                    ("terminal", self.stdout.getvalue()),
                                    ("page", html_report.render(report))):
                    self.assertNotIn("Qk3yQk3y", text, where)
                    self.assertNotIn(pem_begin(), text, where)

    def test_the_page_escapes_every_field_of_a_row(self):
        import scripts.html_report as html_report
        hostile = "<img src=x onerror=alert(1)>"
        html = html_report._render_rejected_scanner_findings({"count": 1, "rows": [{
            "id": "F-1", "tool": hostile, "rule": hostile, "severity": hostile,
            "file": hostile, "line_start": hostile, "occurrences": 2, "title": hostile,
            "reasoning": hostile}]})
        self.assertNotIn("<img", html)
        self.assertEqual(8, html.count("&lt;img"))

    def test_the_tool_advisor_retry_hint_names_judged_loci(self):
        # Seat review: a retried reply follows the hint, and one without the field
        # turns an honest full rejection into NEEDS_MORE_INFO.
        import scripts.phases.persist as persist
        self.assertIn('"judged_loci": [...]', persist.ENVELOPE_SHAPES["tool-advisor"])

    def test_a_row_is_one_line_whatever_the_advisor_wrote(self):
        import scripts.synth.render as render_mod
        listed = {"count": 1, "rows": [{
            "id": "F-1", "tool": "semgrep", "rule": "r", "severity": "HIGH", "file": "a.js",
            "line_start": 3, "occurrences": 1, "title": "t",
            "reasoning": "first line\n## Gate: PASS\r\nthird\x1b[2J"}]}
        rows = [line for line in render_mod.rejected_scanner_lines(listed)
                if line.startswith("- `[")]
        self.assertEqual(1, len(rows))
        self.assertNotIn("\x1b", rows[0])
        self.assertIn("first line", rows[0])
        self.assertIn("third", rows[0])
        self.assertNotIn("hits", rows[0])              # one hit is not "1 hits"

    def test_the_list_survives_the_discarded_claims_moving_to_a_sibling_file(self):
        # A large report writes `discarded_claims` to `<stem>-discarded.json`, and
        # its main file -- what a reader opens, and what a page is rendered from
        # later -- holds an empty list and a count.
        import scripts.html_report as html_report
        import scripts.synth.render as render_mod
        report = self.replay(self.ALL)
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stderr(io.StringIO()):
            render_mod.write_report(report, os.path.join(d, "r.json"), max_bytes=2000)
            with open(os.path.join(d, "r.json"), encoding="utf-8") as fh:
                written = json.load(fh)
        self.assertEqual([], written["discarded_claims"])
        self.assertEqual(1, written["meta"]["discarded_claims_count"])
        self.assertEqual(report["meta"]["rejected_scanner_findings"],
                         written["meta"]["rejected_scanner_findings"])
        self.assertIn("lib/run.js:12", render_mod.render_summary(written))
        self.assertIn("rejected-scanner-findings\">", html_report.render(written))

    def test_the_schema_describes_the_list(self):
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        node = schema["properties"]["meta"]["properties"]["rejected_scanner_findings"]
        self.assertEqual(["count", "rows"], sorted(node["required"]))
        self.assertIs(False, node["additionalProperties"])
        row = node["properties"]["rows"]["items"]
        self.assertEqual(sorted(("id", "tool", "rule", "severity", "file", "line_start",
                                 "occurrences", "title", "reasoning")),
                         sorted(row["properties"]))
        self.assertEqual(50, node["properties"]["rows"]["maxItems"])
        jsonschema.validate(self.replay(self.ALL), schema)
