"""#1476: verdicts that named finding ids absent from the report.

Run-6 supplied 2,043 verdicts; 148 of them (100 distinct ids) named ids that do
not exist in the final report. It cost no coverage (`unanswered: 0`) but bound
roughly 7% of the most expensive phase of a run to nothing -- and if a CONFIRMED
verdict is among the unbound, a real finding is reported as unverified.

The issue quantified it without root-causing it and listed three candidates.
Two are ruled out by reading:

  - a code correction changing the domain prefix: `apply_verdict_quality`
    rewrites `code`, never `domain`, and ids are already assigned by then;
  - normalization altering title/category: both sides normalize before
    assigning, which `matrix_finding_id`'s contract requires.

The third is real and is what these tests pin: `dedupe` collapses a duplicate
and the non-survivor's id simply disappears, so the verdict that echoed it has
nothing left to bind to.
"""
import unittest

import scripts.evidence as evidence_mod
import scripts.synth.findings as findings_mod


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

    def test_dedupe_records_the_ids_it_collapses(self):
        agent, tool = self._pair()
        self.assertNotEqual(agent["id"], tool["id"], "fixture needs two distinct ids")
        survivors = findings_mod.dedupe([agent, tool])
        self.assertEqual(len(survivors), 1, "fixture must actually collapse")
        merged = evidence_mod.merged_ids(survivors[0])
        self.assertEqual(set(merged) | {survivors[0]["id"]},
                         {agent["id"], tool["id"]},
                         "the collapsed id must survive somewhere")

    def test_a_verdict_naming_a_collapsed_id_still_binds(self):
        agent, tool = self._pair()
        survivors = findings_mod.dedupe([agent, tool])
        survivor = survivors[0]
        collapsed = next(i for i in (agent["id"], tool["id"]) if i != survivor["id"])
        by_fid = {collapsed: [{"verdict": "CONFIRMED", "stage": "primary",
                               "run_id": "RID", "finding_id": collapsed}]}
        v = evidence_mod.match_verdict_by_id(survivor, by_fid, run_id="RID")
        self.assertIsNotNone(v, "a verdict for the collapsed twin bound to nothing")
        self.assertEqual(v["verdict"], "CONFIRMED")

    def test_the_survivors_own_id_still_wins_over_an_alias(self):
        # An alias must never outrank the finding's real id: the survivor's own
        # verdict is the one that adjudicated the finding that survived.
        agent, tool = self._pair()
        survivors = findings_mod.dedupe([agent, tool])
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
        survivor = findings_mod.dedupe([agent, tool])[0]
        collapsed = next(i for i in (agent["id"], tool["id"]) if i != survivor["id"])
        by_fid = {collapsed: [{"verdict": "CONFIRMED", "stage": "primary",
                               "run_id": "OTHER-RUN"}]}
        self.assertIsNone(
            evidence_mod.match_verdict_by_id(survivor, by_fid, run_id="RID"))

    def test_a_finding_with_no_merges_has_no_aliases(self):
        f = _finding()
        f["id"] = evidence_mod.matrix_finding_id(f)
        self.assertEqual(evidence_mod.merged_ids(f), [])


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
        with open("skill/reference/report-schema.json", encoding="utf-8") as fh:
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
        with open("skill/reference/report-schema.json", encoding="utf-8") as fh:
            jsonschema.validate(r, json.load(fh))


if __name__ == "__main__":
    unittest.main()
