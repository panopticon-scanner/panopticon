import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
import scripts.evidence as evidence


# queue_ids are content fingerprints since P2 (#443): 16 hex chars, optionally
# with a `-<n>` collision suffix. The old positional NNN-FINDING-ID shape the
# fixtures used is one the system can no longer produce. load_verdicts and
# match_verdict stay format-agnostic on purpose -- they key on the filename
# stem -- so these tests pass either way; the fixtures use the real shape so
# they cannot outlive the contract they document.
QID_1 = "4f2a9c1e7b30d85a"
QID_2 = "9c0b1d2e3f4a5b6c"
QID_3 = "1a2b3c4d5e6f7081"


def _entry(fid="SEC-001", queue_id=QID_1, **kw):
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
            _write(d, QID_1 + ".json",
                   {"finding_id": "SEC-001", "verdict": "CONFIRMED", "reasoning": "r"})
            _write(d, QID_2 + ".json", "{not json")
            _write(d, QID_3 + ".json", {"reasoning": "no verdict key"})
            _write(d, "notes.txt", "ignored")
            out = evidence.load_verdicts(d)
        self.assertEqual(set(out), {QID_1})

    def test_missing_dir_returns_empty(self):
        self.assertEqual(evidence.load_verdicts("/nonexistent/dir"), {})
        self.assertEqual(evidence.load_verdicts(None), {})

    def test_loads_fenced_verdict(self):
        # Advisors routinely wrap their JSON output in a markdown fence (see
        # agents/advisor.md's own output example) -> must not be treated as
        # malformed, or a CONFIRMED verdict silently degrades to unverified.
        with tempfile.TemporaryDirectory() as d:
            _write(d, QID_1 + ".json",
                   "```json\n"
                   '{"finding_id": "SEC-001", "verdict": "CONFIRMED", "reasoning": "r"}\n'
                   "```")
            out = evidence.load_verdicts(d)
        self.assertEqual(set(out), {QID_1})
        self.assertEqual(out[QID_1]["verdict"], "CONFIRMED")

    def test_loads_verdict_wrapped_in_prose(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, QID_1 + ".json",
                   "Here is my verdict: "
                   '{"finding_id": "SEC-001", "verdict": "CONFIRMED", "reasoning": "r"} '
                   "Let me know if you need anything else.")
            out = evidence.load_verdicts(d)
        self.assertEqual(set(out), {QID_1})
        self.assertEqual(out[QID_1]["verdict"], "CONFIRMED")

    def test_detailed_reports_unloadable_instead_of_dropping(self):
        # #938: a corrupt / invalid verdict file must be surfaced, not silently
        # dropped to stderr only. load_verdicts_detailed returns the un-loadable
        # files so the caller can put the count in meta.coverage.
        with tempfile.TemporaryDirectory() as d:
            _write(d, QID_1 + ".json",
                   {"finding_id": "SEC-001", "verdict": "CONFIRMED", "reasoning": "r"})
            _write(d, QID_2 + ".json", "{not json")           # unparseable
            _write(d, QID_3 + ".json", {"reasoning": "no verdict key"})  # invalid
            out, unloadable = evidence.load_verdicts_detailed(d)
        self.assertEqual(set(out), {QID_1})
        self.assertEqual({u["file"] for u in unloadable},
                         {QID_2 + ".json", QID_3 + ".json"})
        self.assertTrue(all(u.get("reason") for u in unloadable))

    def test_unescaped_internal_quote_is_reported_not_dropped(self):
        # The exact field failure (#938): an advisor return with an unescaped "
        # inside `reasoning` breaks json.load AND load_json_tolerant's object
        # search, so the verdict is lost. It must land in `unloadable`, never
        # in the verdicts dict.
        with tempfile.TemporaryDirectory() as d:
            _write(d, QID_1 + ".json",
                   '{"finding_id": "SEC-001", "verdict": "REJECTED", '
                   '"reasoning": "the call to "eval" is actually safe here"}')
            out, unloadable = evidence.load_verdicts_detailed(d)
        self.assertEqual(out, {})
        self.assertEqual([u["file"] for u in unloadable], [QID_1 + ".json"])

    def test_load_verdicts_is_wrapper_over_detailed(self):
        with tempfile.TemporaryDirectory() as d:
            _write(d, QID_1 + ".json",
                   {"finding_id": "SEC-001", "verdict": "CONFIRMED", "reasoning": "r"})
            _write(d, QID_2 + ".json", "{not json")
            self.assertEqual(evidence.load_verdicts(d),
                             evidence.load_verdicts_detailed(d)[0])
        # clean dir -> empty unloadable list, never None
        self.assertEqual(evidence.load_verdicts_detailed("/nonexistent")[1], [])


class TestMatchVerdict(unittest.TestCase):
    def test_match_with_echo(self):
        v = {"finding_id": "SEC-001", "verdict": "CONFIRMED"}
        self.assertIs(evidence.match_verdict(_entry(), {QID_1: v}), v)

    def test_echo_mismatch_rejected(self):
        v = {"finding_id": "SEC-999", "verdict": "CONFIRMED"}
        self.assertIsNone(evidence.match_verdict(_entry(), {QID_1: v}))

    def test_missing_echo_accepted_with_warning(self):
        v = {"verdict": "CONFIRMED"}
        self.assertIs(evidence.match_verdict(_entry(), {QID_1: v}), v)

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
