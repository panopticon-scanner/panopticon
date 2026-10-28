"""#3162: the reviewer prompt says to omit a CVSS vector it cannot justify; the
validator used to count that omission as a schema error, so an honest run
reported itself invalid. A missing (or empty) `cvss` is now disclosed in
`meta.cvss_unscored` and never counted in `meta.schema_errors`; a present but
malformed one still is."""

import contextlib
import io
import json
import os
import tempfile
import unittest

import scripts.synthesize as syn
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
from tests.synth.helpers import _chdir

_UNSET = object()


def _finding(fid, severity="HIGH", panel="security", cvss=_UNSET, source="agent:sr"):
    f = {"id": fid, "title": "t %s" % fid, "severity": severity, "confidence": "LIKELY",
         "panel": panel, "category": "c", "source": source,
         "location": {"file": "%s.py" % fid, "line_start": 1}, "exploit_scenario": "e"}
    if cvss is not _UNSET:
        f["cvss"] = cvss
    return f


def _synthesize(findings):
    """The real CLI on one findings file, as the #3160 run did; returns the report."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "findings-g1-SEC.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"findings": findings}, fh)
        out = os.path.join(d, "report.json")
        with _chdir(d), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            syn.main(["--repo", "--target", "t", "--out", out, path])
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)


def _ids(report, *titles):
    """Synthesis assigns its own ids; find the ones it gave these fixtures."""
    return sorted(f["id"] for f in report["findings"] if f["title"] in titles)


class CvssUnscoredTest(unittest.TestCase):
    def test_the_3160_shape_is_disclosed_not_counted_as_schema_errors(self):
        # #3160: two honest agent HIGH security findings with no vector -> 2 errors
        report = _synthesize([_finding("SE-001"), _finding("SE-002"),
                              _finding("SE-003", cvss={"score": 8.1, "vector": "CVSS:3.1/AV:N"})])
        self.assertEqual(0, report["meta"]["schema_errors"])
        self.assertEqual(_ids(report, "t SE-001", "t SE-002"), report["meta"]["cvss_unscored"])

    def test_an_empty_cvss_is_unscored_never_an_error(self):
        for empty in ({}, "", None):
            with self.subTest(cvss=empty):
                report = _synthesize([_finding("SE-001", cvss=empty)])
                self.assertEqual(0, report["meta"]["schema_errors"])
                self.assertEqual(_ids(report, "t SE-001"), report["meta"]["cvss_unscored"])
                self.assertNotIn("cvss", report["findings"][0])

    def test_a_malformed_cvss_in_a_report_is_still_a_schema_error(self):
        # The report-level contract: what validate_report sees present and wrong
        # is an error, never an omission.
        report = _synthesize([_finding("SE-001", cvss={"score": 8.1, "vector": "v"})])
        for bad in ({"score": "high"}, "7.5x", {"score": 7.5, "vector": 3}):
            with self.subTest(cvss=bad):
                report["findings"][0]["cvss"] = bad
                errors, _ = report_mod.validate_report(report)
                self.assertTrue(any("cvss" in e for e in errors), errors)
                self.assertEqual([], report_mod.cvss_unscored(report["findings"]))

    def test_a_reviewers_malformed_cvss_is_dropped_at_ingest_and_disclosed(self):
        # #1639 P15: an agent's off-contract field is repaired or dropped (and
        # announced) before the report, so it can never become a schema error
        # a reviewer can pull. Dropped, the finding has no usable vector.
        report = _synthesize([_finding("SE-001", cvss="7.5x")])
        self.assertEqual(0, report["meta"]["schema_errors"])
        self.assertEqual(_ids(report, "t SE-001"), report["meta"]["cvss_unscored"])

    def test_only_the_findings_the_prompt_asks_to_score_are_listed(self):
        # unit level: a findings file's name fixes its panel and synthesis
        # strips an agent's `source`, so the CLI cannot build these mixes
        self.assertEqual(["RT-001"], report_mod.cvss_unscored([
            _finding("RT-001", severity="CRITICAL", panel="redteam"),      # listed
            _finding("SE-002", severity="MEDIUM"),                          # not asked
            _finding("CO-003", panel="code"),                               # not asked
            _finding("SE-004", source="tool:semgrep"),                      # tool-sourced
            _finding("SE-005", cvss={"score": 8.1, "vector": "v"}),         # scored
        ]))

    def test_a_clean_run_carries_no_disclosure(self):
        report = _synthesize([_finding("SE-001", cvss={"score": 8.1, "vector": "v"})])
        self.assertNotIn("cvss_unscored", report["meta"])
        self.assertNotIn("**Unscored:**", render_mod.render_summary(report))

    def test_the_summary_names_the_count(self):
        report = _synthesize([_finding("SE-001"), _finding("SE-002")])
        self.assertIn("**Unscored:** 2 high-severity security finding(s) carry no CVSS vector",
                      render_mod.render_summary(report))

    def test_the_validator_and_the_disclosure_share_one_predicate(self):
        findings = [_finding("SE-001"), _finding("RT-002", panel="redteam", severity="CRITICAL")]
        _, warnings = report_mod.validate_report({"findings": findings})
        self.assertEqual(len(report_mod.cvss_unscored(findings)),
                         sum("has no cvss" in w for w in warnings))
