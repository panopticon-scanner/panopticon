"""#1131 tool-aware review (SEC-first PoC): a review cell is handed the
static-analysis tool findings already reported in its files, as a
'don't re-derive' map. SEC-only for now (every tool finding is panel:security,
so routing is just file->group); other domains are deferred. The independent
tool-verify round is untouched — this is purely a prompt input."""
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.driver as driver
import scripts.ocrdb as ocrdb


_SARIF = {
    "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": []}},
        "results": [
            {"level": "error", "ruleId": "python.sqli",
             "message": {"text": "SQL injection via string concat"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "app/db.py"},
                 "region": {"startLine": 10}}}]},
            {"level": "warning", "ruleId": "python.weak-hash",
             "message": {"text": "MD5 used for a token"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "app/other.py"},
                 "region": {"startLine": 3}}}]},
        ],
    }]
}


def _synthetic(file, rule="R1", sev="HIGH", line=1, title="t"):
    return {"location": {"file": file, "line_start": line},
            "tool_evidence": {"rule_id": rule}, "severity": sev,
            "title": title, "panel": "security", "source": "tool:semgrep"}


class TestFormatToolHits(unittest.TestCase):
    def test_empty_is_blank(self):
        self.assertEqual(driver._format_tool_hits([]), "")

    def test_renders_framing_and_lines(self):
        out = driver._format_tool_hits(
            [_synthetic("app/db.py", "python.sqli", "HIGH", 10, "SQLi risk")])
        # contract-(c) framing: don't re-file, but do escalate
        self.assertIn("do **not** re-file them", out)
        self.assertIn("Escalate when there is more", out)
        self.assertIn("cite the `rule_id`", out)
        # the hit itself
        self.assertIn("app/db.py:10", out)
        self.assertIn("python.sqli", out)
        self.assertIn("HIGH", out)
        self.assertIn("SQLi risk", out)

    def test_caps_long_lists_with_more_note(self):
        hits = [_synthetic("app/f%d.py" % i, rule="RULE%d" % i, line=i)
                for i in range(driver._TOOL_HITS_CAP + 5)]
        out = driver._format_tool_hits(hits)
        self.assertIn("and 5 more tool finding", out)
        self.assertIn("RULE0", out)                                       # first rendered
        self.assertNotIn("RULE%d " % (driver._TOOL_HITS_CAP + 4), out)    # beyond the cap


class TestToolHitsForCell(unittest.TestCase):
    def setUp(self):
        self.manifest = {"run_id": "R", "security_mode": "standard"}

    def _patch(self, findings):
        return mock.patch("scripts.driver._ingested_tool_findings",
                          return_value=tuple(findings))

    def test_sec_filters_to_cell_files(self):
        findings = [_synthetic("app/db.py", "python.sqli"),
                    _synthetic("app/other.py", "weak-hash")]
        with self._patch(findings):
            out = driver._tool_hits_for_cell("/rr", self.manifest, "SEC", ["app/db.py"])
        self.assertIn("python.sqli", out)       # hit in this cell's files
        self.assertNotIn("weak-hash", out)      # hit in a sibling group's file — excluded

    def test_non_sec_domain_is_blank(self):
        # every tool finding is panel:security; other domains get no map until a
        # rule->domain index exists (deferred). Non-SEC short-circuits before ingest.
        with mock.patch("scripts.driver._ingested_tool_findings") as m:
            self.assertEqual(
                driver._tool_hits_for_cell("/rr", self.manifest, "COD", ["app/db.py"]), "")
            m.assert_not_called()

    def test_no_hit_in_cell_files_is_blank(self):
        with self._patch([_synthetic("app/other.py", "weak-hash")]):
            self.assertEqual(
                driver._tool_hits_for_cell("/rr", self.manifest, "SEC", ["app/db.py"]), "")

    def test_empty_files_short_circuits(self):
        with mock.patch("scripts.driver._ingested_tool_findings") as m:
            self.assertEqual(driver._tool_hits_for_cell("/rr", self.manifest, "SEC", []), "")
            m.assert_not_called()


class TestIngestedToolFindings(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(driver._pano(self.root, "tools"))
        self.addCleanup(self._t.cleanup)
        driver._ingested_tool_findings.cache_clear()
        self.addCleanup(driver._ingested_tool_findings.cache_clear)

    def test_reads_and_normalizes_tools_dir(self):
        with open(driver._pano(self.root, "tools", "semgrep.sarif"), "w") as fh:
            json.dump(_SARIF, fh)
        got = driver._ingested_tool_findings(self.root, False)
        files = {(f.get("location") or {}).get("file") for f in got}
        self.assertEqual(files, {"app/db.py", "app/other.py"})

    def test_missing_tools_dir_is_empty(self):
        self.assertEqual(driver._ingested_tool_findings("/no/such/root", False), ())


class TestCellEntryInjection(unittest.TestCase):
    """End-to-end: a real SARIF in the tools dir flows into the SEC cell prompt
    and nowhere else, and the template renders cleanly (no leftover placeholder)."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(driver._pano(self.root, "tools"))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard"}
        driver._ingested_tool_findings.cache_clear()
        self.addCleanup(driver._ingested_tool_findings.cache_clear)
        with open(driver._pano(self.root, "tools", "semgrep.sarif"), "w") as fh:
            json.dump(_SARIF, fh)

    def test_sec_cell_prompt_carries_tool_hits(self):
        entry = driver._cell_entry(self.root, self.manifest, "Auth", "SEC",
                                   ["app/db.py"], [], "claude", ocrdb.load_bundle())
        self.assertIn("Tool findings already reported", entry["prompt"])
        self.assertIn("python.sqli", entry["prompt"])
        self.assertNotIn("app/other.py", entry["prompt"])   # not one of this cell's files

    def test_non_sec_cell_prompt_has_no_tool_hits(self):
        entry = driver._cell_entry(self.root, self.manifest, "Auth", "DAT",
                                   ["app/db.py"], [], "claude", ocrdb.load_bundle())
        self.assertNotIn("Tool findings already reported", entry["prompt"])
        self.assertNotIn("{tool_hits}", entry["prompt"])     # placeholder resolved, not leaked


if __name__ == "__main__":
    unittest.main()
