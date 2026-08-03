import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))
import scripts.evidence as evidence


def _finding(fid, sev, **kw):
    f = {"id": fid, "title": "t", "severity": sev, "confidence": "POSSIBLE",
         "panel": "security", "category": "injection",
         "location": {"file": "app.py", "line_start": 10}}
    f.update(kw)
    return f


class TestTriagePriority(unittest.TestCase):
    def test_priority_ordering(self):
        self.assertEqual(evidence.triage_priority(
            _finding("A-001", "CRITICAL", corroborated=True)), 0)
        self.assertEqual(evidence.triage_priority(
            _finding("A-002", "HIGH", reinforced=True)), 0)
        self.assertEqual(evidence.triage_priority(_finding("A-003", "HIGH")), 1)
        self.assertEqual(evidence.triage_priority(
            _finding("A-004", "MEDIUM", corroborated=True)), 2)
        self.assertGreater(evidence.triage_priority(_finding("A-005", "MEDIUM")),
                           evidence.triage_priority(
                               _finding("A-004", "MEDIUM", corroborated=True)))
        self.assertGreater(evidence.triage_priority(_finding("A-006", "LOW")),
                           evidence.triage_priority(_finding("A-005", "MEDIUM")))


class TestBuildVerifyQueue(unittest.TestCase):
    def test_tools_excluded_agentic_included(self):
        fs = [_finding("T-001", "HIGH", source="tool:semgrep"),
              _finding("AG-001", "LOW")]
        entries, cut = evidence.build_verify_queue(fs)
        self.assertEqual(cut, 0)
        self.assertEqual([e["finding"]["id"] for e in entries], ["AG-001"])

    def test_self_asserted_confirmed_still_queued(self):
        f = _finding("AG-002", "HIGH",
                     provenance={"discovered_by": "agent:panel_review",
                                 "confirmation_status": "CONFIRMED"})
        entries, _ = evidence.build_verify_queue([f])
        self.assertEqual(len(entries), 1)

    def test_priority_sorted_and_queue_ids_assigned(self):
        fs = [_finding("AG-010", "LOW"),
              _finding("AG-011", "CRITICAL", corroborated=True),
              _finding("AG-012", "HIGH")]
        entries, _ = evidence.build_verify_queue(fs)
        self.assertEqual([e["finding"]["id"] for e in entries],
                         ["AG-011", "AG-012", "AG-010"])
        self.assertEqual(entries[0]["queue_id"], "000-AG-011")
        self.assertEqual(entries[1]["queue_id"], "001-AG-012")

    def test_entries_reference_original_dicts(self):
        f = _finding("AG-020", "HIGH")
        entries, _ = evidence.build_verify_queue([f])
        self.assertIs(entries[0]["finding"], f)

    def test_max_verify_cuts_lowest_priority(self):
        fs = [_finding("AG-030", "LOW"), _finding("AG-031", "CRITICAL"),
              _finding("AG-032", "HIGH")]
        entries, cut = evidence.build_verify_queue(fs, max_verify=2)
        self.assertEqual(cut, 1)
        self.assertEqual([e["finding"]["id"] for e in entries],
                         ["AG-031", "AG-032"])

    def test_stable_order_for_equal_priority(self):
        fs = [_finding("AG-040", "HIGH"), _finding("AG-041", "HIGH")]
        entries, _ = evidence.build_verify_queue(fs)
        self.assertEqual([e["finding"]["id"] for e in entries],
                         ["AG-040", "AG-041"])


class TestWriteVerifyQueue(unittest.TestCase):
    def test_writes_payload_and_strips_private_keys(self):
        f = _finding("AG-050", "HIGH", _group="g1", _repo_root="/x")
        entries, cut = evidence.build_verify_queue([f])
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "q", "verify-queue.json")
            evidence.write_verify_queue(entries, cut, path)
            with open(path) as fh:
                payload = json.load(fh)
        self.assertEqual(payload["version"], "4.0.0")
        self.assertEqual(payload["cut_by_max_verify"], 0)
        self.assertEqual(payload["entries"][0]["queue_id"], "000-AG-050")
        self.assertNotIn("_group", payload["entries"][0]["finding"])
        self.assertNotIn("_repo_root", payload["entries"][0]["finding"])


if __name__ == "__main__":
    unittest.main()
