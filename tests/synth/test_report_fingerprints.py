"""Finding fingerprint stability and report contracts."""

import unittest
import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod
import scripts.evidence as evidence_mod
from tests.synth.helpers import _agentic


class TestFindingFingerprint(unittest.TestCase):
    """Issues need identity that survives across runs and re-wordings."""

    def _f(self, **kw):
        f = {
            "id": "SG-001",
            "title": "t",
            "severity": "MEDIUM",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "location": {"file": "a.py", "line_start": 10},
        }
        f.update(kw)
        return f

    def test_stable_across_line_moves(self):
        a = evidence_mod.finding_fingerprint(self._f())
        b = evidence_mod.finding_fingerprint(self._f(location={"file": "a.py", "line_start": 99}))
        self.assertEqual(a, b)

    def test_stable_across_agent_rewording(self):
        # Agent prose varies run to run; identity must not.
        a = evidence_mod.finding_fingerprint(
            self._f(title="Module mixes concerns", description="one phrasing")
        )
        b = evidence_mod.finding_fingerprint(
            self._f(title="Module mixes concerns", description="a totally different phrasing")
        )
        self.assertEqual(a, b)

    def test_rule_id_discriminates_tool_findings_at_one_locus(self):
        a = evidence_mod.finding_fingerprint(
            self._f(source="tool:semgrep", tool_evidence={"rule_id": "R-AAA"})
        )
        b = evidence_mod.finding_fingerprint(
            self._f(source="tool:semgrep", tool_evidence={"rule_id": "R-BBB"})
        )
        self.assertNotEqual(a, b)

    def test_different_files_differ(self):
        a = evidence_mod.finding_fingerprint(self._f())
        b = evidence_mod.finding_fingerprint(self._f(location={"file": "b.py", "line_start": 10}))
        self.assertNotEqual(a, b)

    def test_leading_dot_of_a_dotfile_path_is_not_stripped(self):
        # `.github/workflows/ci.yml` and `github/workflows/ci.yml` are different
        # paths; only a `./` prefix is noise.
        a = evidence_mod.finding_fingerprint(self._f(location={"file": ".github/w/ci.yml"}))
        b = evidence_mod.finding_fingerprint(self._f(location={"file": "github/w/ci.yml"}))
        self.assertNotEqual(a, b)

    def test_dot_slash_prefix_is_normalized_away(self):
        a = evidence_mod.finding_fingerprint(self._f(location={"file": "./a.py"}))
        b = evidence_mod.finding_fingerprint(self._f(location={"file": "a.py"}))
        self.assertEqual(a, b)

    def test_report_findings_carry_fingerprints(self):
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on=None, timestamp="2026-08-03T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[_agentic()]),
        ))
        self.assertTrue(report["findings"][0]["fingerprint"])
        self.assertEqual(len(report["findings"][0]["fingerprint"]), 16)
