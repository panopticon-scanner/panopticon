import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
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


class TestFingerprintMoved(unittest.TestCase):
    def _f(self, **over):
        f = {"id": "SEC-1", "panel": "security", "category": "injection",
             "title": "SQL injection", "location": {"file": "a.py",
                                                    "line_start": 3}}
        f.update(over)
        return f

    def test_fingerprint_is_stable_hex(self):
        fp = evidence.finding_fingerprint(self._f())
        self.assertEqual(len(fp), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in fp))

    def test_fingerprint_ignores_line_number(self):
        a = evidence.finding_fingerprint(self._f())
        b = evidence.finding_fingerprint(
            self._f(location={"file": "a.py", "line_start": 99}))
        self.assertEqual(a, b)

    def test_tool_rule_id_reads_both_adapter_families(self):
        self.assertEqual(
            evidence.tool_rule_id({"tool_evidence": {"rule_id": "B105"}}), "B105")
        self.assertEqual(
            evidence.tool_rule_id({"provenance": {"confirmation_reasoning": "SCS0005"}}),
            "SCS0005")
        self.assertIsNone(evidence.tool_rule_id({}))

    def test_synthesize_aliases_still_resolve(self):
        import scripts.synthesize as syn
        self.assertIs(syn.finding_fingerprint, evidence.finding_fingerprint)
        self.assertIs(syn.tool_rule_id, evidence.tool_rule_id)


if __name__ == "__main__":
    unittest.main()
