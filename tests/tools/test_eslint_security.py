import json
import os
import tempfile
import unittest
from unittest import mock

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

    def test_parse_tool_evidence_has_only_rule_id(self):
        findings = es.EslintSecurityAdapter().parse(ESLINT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["tool_evidence"], {"rule_id": "security/detect-eval-with-expression"})

    def test_parse_uses_ess_prefix(self):
        findings = es.EslintSecurityAdapter().parse(ESLINT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
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
        self.assertEqual(len(findings), 1)
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

    def _one(self, rule, eslint_severity):
        return json.dumps([{
            "filePath": "/src/app.js",
            "messages": [{"ruleId": rule, "severity": eslint_severity,
                          "line": 5, "message": "m"}],
        }]).encode()

    def test_severity_is_rule_derived_not_eslint_level(self):
        # #1118: invoke() forces every rule to eslint 'error' (level 2), so the
        # level carries no severity signal -- severity comes from RULE_SEVERITY.
        # A HIGH-mapped rule stays HIGH even if eslint reports level 1 ...
        f = es.EslintSecurityAdapter().parse(
            self._one("security/detect-eval-with-expression", 1), "g1")
        self.assertEqual(f[0]["severity"], "HIGH")
        # ... and a MEDIUM-mapped rule stays MEDIUM even at level 2 (previously
        # every level-2 message was emitted HIGH -- the dead branch, #1118).
        f = es.EslintSecurityAdapter().parse(
            self._one("security/detect-object-injection", 2), "g1")
        self.assertEqual(f[0]["severity"], "MEDIUM")

    def test_every_enabled_rule_has_an_explicit_severity(self):
        # no enabled rule may fall through to the default -- keeps the CWE and
        # severity maps in lockstep as rules are added (#1118).
        for rule in es.RULE_CWE:
            self.assertIn(rule, es.RULE_SEVERITY, rule)

    def test_parse_handles_empty_results(self):
        findings = es.EslintSecurityAdapter().parse(json.dumps([]).encode(), "g1")
        self.assertEqual(len(findings), 0)

    def test_strip_prefix_removes_src_and_leading_slash(self):
        adapter = es.EslintSecurityAdapter()
        self.assertEqual(adapter._strip_prefix("/src/app.js"), "app.js")
        self.assertEqual(adapter._strip_prefix("src/app.js"), "src/app.js")
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
        with mock.patch("scripts.tools.base.subprocess.run", fake_run), \
             mock.patch.object(es.EslintSecurityAdapter, "_lintable_sources",
                               return_value=["x.js"]):
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
        with mock.patch("scripts.tools.base.subprocess.run", fake_run), \
             mock.patch.object(es.EslintSecurityAdapter, "_lintable_sources",
                               return_value=["x.js"]):
            adapter.invoke("/tmp/fake")
        args, _ = fake_run.call_args
        cmd = args[0]
        for rule in es.RULE_CWE:
            self.assertIn("--rule", cmd)
            self.assertIn(f"{rule}: error", cmd)

    def test_invoke_pins_cwd_away_from_scanned_target(self):
        # eslint resolves plugins relative to the child process's cwd, not
        # the linted path on argv. If cwd stays inside the scanned target, a
        # hostile node_modules/eslint-plugin-security shipped by that target
        # would be loaded and executed ahead of the trusted global plugin
        # (#83). cwd must be pinned to a directory that can never contain a
        # scanned target's own node_modules.
        adapter = es.EslintSecurityAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"[]", returncode=0))
        with mock.patch("scripts.tools.base.subprocess.run", fake_run), \
             mock.patch.object(es.EslintSecurityAdapter, "_lintable_sources",
                               return_value=["x.js"]):
            adapter.invoke("/tmp/fake-target")
        _args, kwargs = fake_run.call_args
        expected_cwd = os.path.dirname(os.path.abspath(es.__file__))
        self.assertEqual(kwargs.get("cwd"), expected_cwd)
        self.assertNotEqual(kwargs.get("cwd"), "/tmp/fake-target")

    def test_invoke_sets_node_path_exclusively_ignoring_inherited(self):
        # #715: an inherited NODE_PATH must never be prepended. Node searches
        # NODE_PATH left-to-right, so a hostile inherited /evil/node_modules
        # would shadow the trusted eslint-plugin-security. The adapter must set
        # NODE_PATH to the trusted global dir ALONE.
        adapter = es.EslintSecurityAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"[]", returncode=0))
        with mock.patch("scripts.tools.base.subprocess.run", fake_run), \
             mock.patch.object(es.EslintSecurityAdapter, "_lintable_sources",
                               return_value=["x.js"]), \
             mock.patch.dict(os.environ, {"NODE_PATH": "/evil/node_modules"}), \
             mock.patch("os.path.isdir",
                        side_effect=lambda p: p == "/usr/local/lib/node_modules"):
            adapter.invoke("/tmp/fake-target")
        _args, kwargs = fake_run.call_args
        self.assertEqual(kwargs["env"].get("NODE_PATH"), "/usr/local/lib/node_modules")
        self.assertNotIn("/evil", kwargs["env"].get("NODE_PATH", ""))

    def test_invoke_drops_inherited_node_path_when_no_global_dir(self):
        # If neither trusted global dir exists, the inherited value must still
        # be dropped rather than left to leak in.
        adapter = es.EslintSecurityAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"[]", returncode=0))
        with mock.patch("scripts.tools.base.subprocess.run", fake_run), \
             mock.patch.object(es.EslintSecurityAdapter, "_lintable_sources",
                               return_value=["x.js"]), \
             mock.patch.dict(os.environ, {"NODE_PATH": "/evil/node_modules"}), \
             mock.patch("os.path.isdir", return_value=False):
            adapter.invoke("/tmp/fake-target")
        _args, kwargs = fake_run.call_args
        self.assertNotIn("NODE_PATH", kwargs["env"])

    def test_invoke_passes_absolute_target_path(self):
        # Once cwd is pinned away from the target, the linted path on argv
        # must be absolute so linting still resolves the right directory
        # regardless of the pinned cwd.
        adapter = es.EslintSecurityAdapter()
        fake_run = mock.Mock(return_value=mock.Mock(stdout=b"[]", returncode=0))
        with mock.patch("scripts.tools.base.subprocess.run", fake_run), \
             mock.patch.object(es.EslintSecurityAdapter, "_lintable_sources",
                               return_value=["x.js"]):
            adapter.invoke("relative/target")
        args, _kwargs = fake_run.call_args
        cmd = args[0]
        self.assertEqual(cmd[-1], os.path.abspath("relative/target"))

    # #984: applicable-but-nothing-to-lint -> ran-clean empty, not a skip.
    def test_invoke_short_circuits_when_only_package_json(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "package.json"), "w").close()
            fake_run = mock.Mock()
            with mock.patch("scripts.tools.base.subprocess.run", fake_run):
                stdout, rc = es.EslintSecurityAdapter().invoke(d)
        self.assertEqual((stdout, rc), (b"[]", 0))
        fake_run.assert_not_called()   # eslint never invoked -> ran-clean empty

    def test_invoke_short_circuits_when_source_only_in_node_modules(self):
        with tempfile.TemporaryDirectory() as d:
            nm = os.path.join(d, "node_modules", "dep")
            os.makedirs(nm)
            open(os.path.join(nm, "index.js"), "w").close()
            open(os.path.join(d, "package.json"), "w").close()
            fake_run = mock.Mock()
            with mock.patch("scripts.tools.base.subprocess.run", fake_run):
                stdout, rc = es.EslintSecurityAdapter().invoke(d)
        self.assertEqual((stdout, rc), (b"[]", 0))
        fake_run.assert_not_called()

    def test_invoke_runs_eslint_when_real_source_present(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "app.js"), "w").close()
            fake_run = mock.Mock(return_value=mock.Mock(stdout=b"[]", returncode=0))
            with mock.patch("scripts.tools.base.subprocess.run", fake_run):
                es.EslintSecurityAdapter().invoke(d)
        fake_run.assert_called_once()   # source present -> eslint really runs
        self.assertEqual(fake_run.call_args[0][0][0], "eslint")

    def test_parse_includes_provenance(self):
        findings = es.EslintSecurityAdapter().parse(ESLINT_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["provenance"]["discovered_by"], "tool:eslint-security")
        self.assertEqual(findings[0]["provenance"]["confirmation_status"], "TOOL")

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
