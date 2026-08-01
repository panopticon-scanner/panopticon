import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
import scripts.tools.legacy_sarif as legacy
from scripts.tools import ADAPTERS


SARIF = {
    "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": [
            {"id": "sql-injection", "properties": {"tags": ["CWE-89"]}}]}},
        "results": [{
            "ruleId": "sql-injection", "level": "error",
            "message": {"text": "SQL injection"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "app/db.py"},
                "region": {"startLine": 42}}}]}]}]
}


class TestLegacySarifAdapter(unittest.TestCase):
    def test_parse_returns_findings(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        raw = json.dumps(SARIF).encode("utf-8")
        findings = adapter.parse(raw, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:semgrep")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["location"], {"file": "app/db.py", "line_start": 42})
        self.assertTrue(f["id"].startswith("SG-"))
        self.assertIn("CWE-89", f["citations"]["cwe"])

    def test_invoke_raises_not_implemented(self):
        adapter = legacy.LegacySarifAdapter("bandit")
        with self.assertRaises(NotImplementedError):
            adapter.invoke(".")

    def test_prefix_defaults_to_tl_for_unknown_tool(self):
        adapter = legacy.LegacySarifAdapter("unknown")
        self.assertEqual(adapter.prefix, "TL")

    def test_registry_contains_legacy_adapters(self):
        for name in ("semgrep", "bandit", "trivy", "gitleaks", "gosec", "eslint"):
            self.assertIn(name, ADAPTERS)
            self.assertIsInstance(ADAPTERS[name], legacy.LegacySarifAdapter)
            self.assertEqual(ADAPTERS[name].name, name)


if __name__ == "__main__":
    unittest.main()
