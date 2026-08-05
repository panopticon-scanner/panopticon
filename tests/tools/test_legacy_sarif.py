import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "skill"))
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

    def test_parse_attaches_tool_provenance(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        raw = json.dumps(SARIF).encode("utf-8")
        findings = adapter.parse(raw, "g1")
        self.assertEqual(len(findings), 1)
        prov = findings[0].get("provenance")
        self.assertIsNotNone(prov)
        self.assertEqual(prov["discovered_by"], "tool:semgrep")
        self.assertEqual(prov["confirmation_status"], "TOOL")

    def test_invoke_runs_tool_command(self):
        adapter = legacy.LegacySarifAdapter("bandit")
        mock_stdout = json.dumps(SARIF).encode("utf-8")
        with patch.object(subprocess, "run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=1, stdout=mock_stdout, stderr=b""
            )
            stdout, rc = adapter.invoke("/some/target")
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, mock_stdout)
        mock_run.assert_called_once()
        called_args, called_kwargs = mock_run.call_args
        self.assertEqual(called_kwargs.get("cwd"), None)
        self.assertIn("/some/target", called_args[0])

    def test_invoke_runs_gosec_in_target_directory(self):
        adapter = legacy.LegacySarifAdapter("gosec")
        with patch.object(subprocess, "run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b"{}", stderr=b""
            )
            adapter.invoke("/go/project")
        called_args, called_kwargs = mock_run.call_args
        self.assertEqual(called_kwargs.get("cwd"), "/go/project")
        self.assertNotIn("/src", called_args[0])

    def test_invoke_raises_not_implemented_for_unknown_tool(self):
        adapter = legacy.LegacySarifAdapter("unknown")
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

    def test_semgrep_argv_has_offline_flags(self):
        expected = ["semgrep", "scan", "--config", "/opt/semgrep-rules",
                    "--metrics=off", "--disable-version-check",
                    "--sarif", "--quiet", "/src"]
        self.assertEqual(legacy.TOOL_CMD["semgrep"], expected)

    def test_semgrep_argv_suppresses_both_call_home_paths(self):
        # They are separate calls: --metrics=off does not stop the version
        # check, and in a --network none container that check blocks until it
        # times out (measured 2m10s -> 35s on one trivial file).
        argv = legacy.TOOL_CMD["semgrep"]
        self.assertIn("--metrics=off", argv)
        self.assertIn("--disable-version-check", argv)

    def test_trivy_argv_has_offline_flags(self):
        expected = ["trivy", "fs", "--skip-db-update", "--offline-scan",
                    "--format", "sarif", "/src"]
        self.assertEqual(legacy.TOOL_CMD["trivy"], expected)


if __name__ == "__main__":
    unittest.main()
