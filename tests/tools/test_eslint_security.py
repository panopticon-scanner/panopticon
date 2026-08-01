import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
import scripts.tools.eslint_security as es
from scripts.tools import ADAPTERS


ESLINT_SAMPLE = json.dumps([
    {
        "filePath": "/src/app.js",
        "messages": [
            {
                "ruleId": "security/detect-eval-with-expression",
                "severity": 2,
                "line": 10,
                "column": 5,
                "message": "eval with expression"
            }
        ]
    }
]).encode()


class TestEslintSecurityAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = es.EslintSecurityAdapter().parse(ESLINT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:eslint-security")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["location"]["file"], "app.js")
        self.assertEqual(f["location"]["line_start"], 10)
        self.assertEqual(f["tool_evidence"]["rule_id"], "security/detect-eval-with-expression")

    def test_parse_uses_ess_prefix(self):
        findings = es.EslintSecurityAdapter().parse(ESLINT_SAMPLE, "g1")
        self.assertTrue(findings[0]["id"].startswith("ESS-"))

    def test_parse_uppercases_cwe(self):
        sample = json.dumps([
            {
                "filePath": "/src/app.js",
                "messages": [
                    {
                        "ruleId": "security/detect-eval-with-expression",
                        "severity": 2,
                        "line": 1,
                        "message": "eval with expression"
                    }
                ]
            }
        ]).encode()
        findings = es.EslintSecurityAdapter().parse(sample, "g1")
        self.assertEqual(findings[0]["citations"]["cwe"], ["CWE-95"])

    def test_parse_skips_non_security_rules(self):
        sample = json.dumps([
            {
                "filePath": "/src/app.js",
                "messages": [
                    {
                        "ruleId": "no-unused-vars",
                        "severity": 2,
                        "line": 1,
                        "message": "unused"
                    }
                ]
            }
        ]).encode()
        findings = es.EslintSecurityAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 0)

    def test_parse_maps_severity_one_to_medium(self):
        sample = json.dumps([
            {
                "filePath": "/src/app.js",
                "messages": [
                    {
                        "ruleId": "security/detect-object-injection",
                        "severity": 1,
                        "line": 5,
                        "message": "object injection"
                    }
                ]
            }
        ]).encode()
        findings = es.EslintSecurityAdapter().parse(sample, "g1")
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_parse_handles_empty_results(self):
        findings = es.EslintSecurityAdapter().parse(json.dumps([]).encode(), "g1")
        self.assertEqual(len(findings), 0)

    def test_strip_prefix_removes_src_and_leading_slash(self):
        adapter = es.EslintSecurityAdapter()
        self.assertEqual(adapter._strip_prefix("/src/app.js"), "app.js")
        self.assertEqual(adapter._strip_prefix("src/app.js"), "app.js")
        self.assertEqual(adapter._strip_prefix("/app.js"), "app.js")
        self.assertEqual(adapter._strip_prefix("app.js"), "app.js")

    def test_is_applicable_detects_js_files(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "app.js"), "w").close()
            self.assertTrue(es.EslintSecurityAdapter().is_applicable(d))

    def test_is_applicable_detects_ts_files(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "app.ts"), "w").close()
            self.assertTrue(es.EslintSecurityAdapter().is_applicable(d))

    def test_is_applicable_detects_jsx_tsx_files(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "component.jsx"), "w").close()
            open(os.path.join(d, "component.tsx"), "w").close()
            self.assertTrue(es.EslintSecurityAdapter().is_applicable(d))

    def test_is_applicable_detects_package_json(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "package.json"), "w").close()
            self.assertTrue(es.EslintSecurityAdapter().is_applicable(d))

    def test_is_applicable_false_when_no_relevant_files(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(es.EslintSecurityAdapter().is_applicable(d))

    def test_invoke_runs_eslint_security(self):
        adapter = es.EslintSecurityAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"[]", returncode=0))
        with mock.patch("scripts.tools.eslint_security.subprocess.run", fake_run):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"[]")
        self.assertEqual(rc, 0)
        args, kwargs = fake_run.call_args
        self.assertEqual(args[0][0], "eslint")
        self.assertIn("--no-config-lookup", args[0])
        self.assertIn("security", args[0])
        self.assertIn("--format", args[0])
        self.assertIn("json", args[0])
        self.assertEqual(kwargs["capture_output"], True)
        self.assertEqual(kwargs["timeout"], 300)

    def test_invoke_enables_all_rule_cwe_rules(self):
        adapter = es.EslintSecurityAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"[]", returncode=0))
        with mock.patch("scripts.tools.eslint_security.subprocess.run", fake_run):
            adapter.invoke("/tmp/fake")
        args, _ = fake_run.call_args
        cmd = args[0]
        for rule in es.RULE_CWE:
            self.assertIn("--rule", cmd)
            self.assertIn(f"{rule}: error", cmd)

    def test_adapter_metadata(self):
        adapter = es.EslintSecurityAdapter()
        self.assertEqual(adapter.name, "eslint-security")
        self.assertEqual(adapter.prefix, "ESS")

    def test_registry_contains_adapter(self):
        self.assertIn("eslint-security", ADAPTERS)
        self.assertIsInstance(ADAPTERS["eslint-security"], es.EslintSecurityAdapter)

    def test_prefix_does_not_collide_with_legacy_eslint(self):
        # Legacy eslint SARIF adapter uses the "ES" prefix; eslint-security must
        # use a distinct prefix to avoid finding-ID collisions.
        self.assertNotEqual(es.EslintSecurityAdapter().prefix, "ES")


if __name__ == "__main__":
    unittest.main()
