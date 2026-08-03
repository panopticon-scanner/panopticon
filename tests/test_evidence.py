import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.evidence as evidence


def _finding(**kw):
    f = {"id": "SEC-001", "title": "t", "severity": "HIGH",
         "confidence": "POSSIBLE", "panel": "security", "category": "injection",
         "location": {"file": "app.py", "line_start": 10},
         "citation_quality": "partial"}
    f.update(kw)
    return f


class TestDeriveEvidence(unittest.TestCase):
    def test_tool_sourced_is_tool_confirmed(self):
        f = _finding(source="tool:semgrep",
                     provenance={"confirmation_reasoning": "Reported by semgrep"})
        ev = evidence.derive_evidence(f)
        self.assertEqual(ev["status"], "tool_confirmed")
        self.assertEqual(ev["verified_by"], "tool:semgrep")
        self.assertEqual(ev["reasoning"], "Reported by semgrep")
        self.assertEqual(ev["citation_quality"], "partial")

    def test_confirmed_verdict_is_advisor_confirmed(self):
        ev = evidence.derive_evidence(
            _finding(), {"verdict": "CONFIRMED", "reasoning": "sink verified"})
        self.assertEqual(ev["status"], "advisor_confirmed")
        self.assertEqual(ev["verified_by"], "agent:advisor")
        self.assertEqual(ev["reasoning"], "sink verified")

    def test_rejected_verdict_is_rejected(self):
        ev = evidence.derive_evidence(
            _finding(), {"verdict": "REJECTED", "reasoning": "no sink"})
        self.assertEqual(ev["status"], "rejected")

    def test_needs_more_info_verdict(self):
        ev = evidence.derive_evidence(
            _finding(), {"verdict": "NEEDS_MORE_INFO", "reasoning": "need config"})
        self.assertEqual(ev["status"], "needs_more_info")
        self.assertEqual(ev["reasoning"], "need config")

    def test_verdict_beats_corroboration(self):
        ev = evidence.derive_evidence(
            _finding(corroborated=True, corroborated_by=["security", "database"]),
            {"verdict": "REJECTED", "reasoning": "r"})
        self.assertEqual(ev["status"], "rejected")

    def test_tool_beats_verdict(self):
        # Tool findings never enter the queue; if a verdict is passed anyway,
        # tool_confirmed still wins (precedence rule 1).
        ev = evidence.derive_evidence(
            _finding(source="tool:bandit"), {"verdict": "REJECTED"})
        self.assertEqual(ev["status"], "tool_confirmed")

    def test_cross_panel_corroborated(self):
        ev = evidence.derive_evidence(
            _finding(corroborated=True, corroborated_by=["security", "database"]))
        self.assertEqual(ev["status"], "corroborated")
        self.assertEqual(ev["verified_by"], ["security", "database"])

    def test_reinforced_is_tool_confirmed(self):
        # A tool+agent same-locus merge is tool-reported by construction, so it
        # gates the same as a plain tool finding (amended spec) rather than
        # being demoted to mere `corroborated`.
        ev = evidence.derive_evidence(_finding(reinforced=True))
        self.assertEqual(ev["status"], "tool_confirmed")
        self.assertEqual(ev["verified_by"], "tool+agent")

    def test_default_is_unverified(self):
        ev = evidence.derive_evidence(_finding())
        self.assertEqual(ev["status"], "unverified")
        self.assertIsNone(ev["verified_by"])
        self.assertIsNone(ev["reasoning"])

    def test_never_mutates_severity_or_confidence(self):
        for verdict in (None, {"verdict": "CONFIRMED"}, {"verdict": "REJECTED"},
                        {"verdict": "NEEDS_MORE_INFO"}):
            f = _finding()
            evidence.derive_evidence(f, verdict)
            self.assertEqual(f["severity"], "HIGH")
            self.assertEqual(f["confidence"], "POSSIBLE")

    def test_missing_citation_quality_defaults_none(self):
        f = _finding()
        del f["citation_quality"]
        self.assertEqual(evidence.derive_evidence(f)["citation_quality"], "none")


if __name__ == "__main__":
    unittest.main()
