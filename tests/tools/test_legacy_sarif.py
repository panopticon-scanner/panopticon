import json
import unittest
from unittest import mock

from _test_helpers import FakePopen, first
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
        with mock.patch("scripts.tools.base.subprocess.Popen") as popen_mock:
            popen_mock.return_value = FakePopen(
                stdout=mock_stdout, stderr=b"", returncode=1)
            stdout, rc = adapter.invoke("/some/target")
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, mock_stdout)
        popen_mock.assert_called_once()
        called_args, called_kwargs = popen_mock.call_args
        self.assertEqual(called_kwargs.get("cwd"), None)
        self.assertIn("/some/target", first(called_args))

    def test_invoke_runs_gosec_in_target_directory(self):
        adapter = legacy.LegacySarifAdapter("gosec")
        with mock.patch("scripts.tools.base.subprocess.Popen") as popen_mock:
            popen_mock.return_value = FakePopen(
                stdout=b"{}", stderr=b"", returncode=0)
            adapter.invoke("/go/project")
        called_args, called_kwargs = popen_mock.call_args
        self.assertEqual(called_kwargs.get("cwd"), "/go/project")
        self.assertNotIn("/src", first(called_args))

    def test_invoke_raises_not_implemented_for_unknown_tool(self):
        adapter = legacy.LegacySarifAdapter("unknown")
        with self.assertRaises(NotImplementedError):
            adapter.invoke(".")

    def test_prefix_defaults_to_tl_for_unknown_tool(self):
        adapter = legacy.LegacySarifAdapter("unknown")
        self.assertEqual(adapter.prefix, "TL")

    def test_registry_contains_legacy_adapters(self):
        for name in ("semgrep", "bandit", "trivy", "gitleaks", "gosec"):
            self.assertIn(name, ADAPTERS)
            self.assertIsInstance(ADAPTERS[name], legacy.LegacySarifAdapter)
            self.assertEqual(ADAPTERS[name].name, name)
        self.assertNotIn("eslint", ADAPTERS)

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

    def test_bandit_argv_has_noise_suppression_flags(self):
        argv = legacy.TOOL_CMD["bandit"]
        self.assertIn("-s", argv)
        self.assertIn("B101,B404,B110,B112", argv)

    def test_parse_malformed_json_raises(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        with self.assertRaises(json.JSONDecodeError):
            adapter.parse(b"{not valid sarif", "g1")

    def test_parse_empty_runs_returns_empty(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        findings = adapter.parse(json.dumps({"runs": []}).encode(), "g1")
        self.assertEqual(findings, [])

    def test_parse_empty_results_returns_empty(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        sarif = {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                           "results": []}]}
        findings = adapter.parse(json.dumps(sarif).encode(), "g1")
        self.assertEqual(findings, [])

    def test_parse_missing_result_fields_returns_finding(self):
        # SARIF results with minimal fields should still produce a finding,
        # defaulting severity and tolerating absent locations (#1196).
        adapter = legacy.LegacySarifAdapter("semgrep")
        sarif = {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                           "results": [{"ruleId": "bare-rule"}]}]}
        findings = adapter.parse(json.dumps(sarif).encode(), "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(findings[0]["location"], {})

    def test_parse_unknown_level_defaults_to_info(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        sarif = {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                           "results": [{"ruleId": "weird", "level": "banana"}]}]}
        findings = adapter.parse(json.dumps(sarif).encode(), "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "INFO")


class TestLegacySarifIsApplicable(unittest.TestCase):
    def test_is_always_applicable(self):
        adapter = legacy.LegacySarifAdapter("semgrep")
        self.assertTrue(adapter.is_applicable("/any/path"))
        self.assertTrue(adapter.is_applicable("/another/path"))


if __name__ == "__main__":
    unittest.main()
