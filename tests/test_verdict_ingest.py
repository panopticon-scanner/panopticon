import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.evidence as evidence


def _entry(fid="SEC-001", queue_id="000-SEC-001", **kw):
    f = {"id": fid, "title": "t", "severity": "HIGH", "confidence": "POSSIBLE",
         "panel": "security", "category": "injection",
         "location": {"file": "app.py", "line_start": 10},
         "references": ["https://owasp.org"]}
    f.update(kw)
    return {"queue_id": queue_id, "priority": 1, "finding": f}


def _write(d, name, obj):
    path = os.path.join(d, name)
    with open(path, "w") as fh:
        if isinstance(obj, str):
            fh.write(obj)
        else:
            json.dump(obj, fh)
    return path


class TestLoadVerdicts(unittest.TestCase):
    def test_loads_valid_skips_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "000-SEC-001.json",
                   {"finding_id": "SEC-001", "verdict": "CONFIRMED", "reasoning": "r"})
            _write(d, "001-SEC-002.json", "{not json")
            _write(d, "002-SEC-003.json", {"reasoning": "no verdict key"})
            _write(d, "notes.txt", "ignored")
            out = evidence.load_verdicts(d)
        self.assertEqual(set(out), {"000-SEC-001"})

    def test_missing_dir_returns_empty(self):
        self.assertEqual(evidence.load_verdicts("/nonexistent/dir"), {})
        self.assertEqual(evidence.load_verdicts(None), {})

    def test_loads_fenced_verdict(self):
        # Advisors routinely wrap their JSON output in a markdown fence (see
        # agents/advisor.md's own output example) -> must not be treated as
        # malformed, or a CONFIRMED verdict silently degrades to unverified.
        with tempfile.TemporaryDirectory() as d:
            _write(d, "000-SEC-001.json",
                   "```json\n"
                   '{"finding_id": "SEC-001", "verdict": "CONFIRMED", "reasoning": "r"}\n'
                   "```")
            out = evidence.load_verdicts(d)
        self.assertEqual(set(out), {"000-SEC-001"})
        self.assertEqual(out["000-SEC-001"]["verdict"], "CONFIRMED")

    def test_loads_verdict_wrapped_in_prose(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, "000-SEC-001.json",
                   "Here is my verdict: "
                   '{"finding_id": "SEC-001", "verdict": "CONFIRMED", "reasoning": "r"} '
                   "Let me know if you need anything else.")
            out = evidence.load_verdicts(d)
        self.assertEqual(set(out), {"000-SEC-001"})
        self.assertEqual(out["000-SEC-001"]["verdict"], "CONFIRMED")


class TestMatchVerdict(unittest.TestCase):
    def test_match_with_echo(self):
        v = {"finding_id": "SEC-001", "verdict": "CONFIRMED"}
        self.assertIs(evidence.match_verdict(_entry(), {"000-SEC-001": v}), v)

    def test_echo_mismatch_rejected(self):
        v = {"finding_id": "SEC-999", "verdict": "CONFIRMED"}
        self.assertIsNone(evidence.match_verdict(_entry(), {"000-SEC-001": v}))

    def test_missing_echo_accepted_with_warning(self):
        v = {"verdict": "CONFIRMED"}
        self.assertIs(evidence.match_verdict(_entry(), {"000-SEC-001": v}), v)

    def test_no_verdict_returns_none(self):
        self.assertIsNone(evidence.match_verdict(_entry(), {}))


class TestApplyVerdict(unittest.TestCase):
    def test_confirmed_updates_provenance_never_severity(self):
        e = _entry()
        f = e["finding"]
        evidence.apply_verdict(f, {"verdict": "CONFIRMED", "reasoning": "verified",
                                   "model": "claude-sonnet",
                                   "references": ["https://cwe.mitre.org", "https://owasp.org"],
                                   "citations": {"cwe": ["CWE-89"]}})
        self.assertEqual(f["provenance"]["confirmation_status"], "CONFIRMED")
        self.assertEqual(f["provenance"]["confirmed_by"], "agent:advisor")
        self.assertEqual(f["provenance"]["confirmation_reasoning"], "verified")
        self.assertEqual(f["provenance"]["confirmed_by_model"], "claude-sonnet")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["confidence"], "POSSIBLE")
        self.assertEqual(f["citations"]["cwe"], ["CWE-89"])
        # de-duplicated references, order preserved
        self.assertEqual(f["references"],
                         ["https://owasp.org", "https://cwe.mitre.org"])

    def test_rejected_keeps_severity(self):
        e = _entry()
        evidence.apply_verdict(e["finding"], {"verdict": "REJECTED", "reasoning": "no"})
        self.assertEqual(e["finding"]["severity"], "HIGH")
        self.assertEqual(e["finding"]["provenance"]["confirmation_status"], "REJECTED")

    def test_existing_citation_keys_not_overwritten(self):
        e = _entry(citations={"cwe": ["CWE-79"]})
        evidence.apply_verdict(e["finding"],
                               {"verdict": "CONFIRMED",
                                "citations": {"cwe": ["CWE-89"], "owasp": ["A03:2021"]}})
        self.assertEqual(e["finding"]["citations"]["cwe"], ["CWE-79"])
        self.assertEqual(e["finding"]["citations"]["owasp"], ["A03:2021"])


if __name__ == "__main__":
    unittest.main()
