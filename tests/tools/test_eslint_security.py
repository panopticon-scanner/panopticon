import json
import os
import tempfile
import unittest
from unittest import mock

from _test_helpers import FakePopen, first
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
    def _only(self, findings):
        """The sole parsed finding, guarded so an empty/short parse fails
        diagnosably (run-9 TST-B3A) instead of as a bare IndexError."""
        self.assertEqual(len(findings), 1)
        return findings[0]

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

    def test_heuristic_rules_get_likely_confidence(self):
        # ARC-A4A run-7: FP-prone heuristic rules should not claim CERTAIN.
        adapter = es.EslintSecurityAdapter()
        heuristic_finding = self._only(adapter.parse(
            self._one("security/detect-object-injection", 2), "g1"))
        self.assertEqual(heuristic_finding["confidence"], "LIKELY")
        timing_finding = self._only(adapter.parse(
            self._one("security/detect-possible-timing-attacks", 2), "g1"))
        self.assertEqual(timing_finding["confidence"], "LIKELY")
        non_heuristic_finding = self._only(adapter.parse(
            self._one("security/detect-eval-with-expression", 2), "g1"))
        self.assertEqual(non_heuristic_finding["confidence"], "CERTAIN")

    def test_severity_is_rule_derived_not_eslint_level(self):
        # #1118: invoke() forces every rule to eslint 'error' (level 2), so the
        # level carries no severity signal -- severity comes from RULE_SEVERITY.
        # A HIGH-mapped rule stays HIGH even if eslint reports level 1 ...
        f = es.EslintSecurityAdapter().parse(
            self._one("security/detect-eval-with-expression", 1), "g1")
        self.assertEqual(self._only(f)["severity"], "HIGH")
        # ... and a MEDIUM-mapped rule stays MEDIUM even at level 2 (previously
        # every level-2 message was emitted HIGH -- the dead branch, #1118).
        f = es.EslintSecurityAdapter().parse(
            self._one("security/detect-object-injection", 2), "g1")
        self.assertEqual(self._only(f)["severity"], "MEDIUM")

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

    def test_invoke_runs_eslint_with_generated_flat_config(self):
        # #run7: eslint 10 loads plugins via a flat config, not `--plugin`.
        adapter = es.EslintSecurityAdapter()
        fake_run = FakePopen(stdout=b"[]", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        return_value=fake_run) as popen_mock, \
             mock.patch.object(es.EslintSecurityAdapter, "_lintable_sources",
                               return_value=["x.js"]):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual((stdout, rc), (b"[]", 0))
        cmd = popen_mock.call_args[0][0]
        self.assertEqual(cmd[0], "eslint")
        self.assertIn("--config", cmd)
        self.assertTrue(cmd[cmd.index("--config") + 1].endswith("eslint.config.mjs"))
        self.assertIn("--no-config-lookup", cmd)   # target's own config never executed
        self.assertIn("--format", cmd)
        self.assertIn("json", cmd)
        self.assertEqual(cmd[-1], os.path.abspath("/tmp/fake"))

    def test_invoke_reports_nonzero_exit(self):
        import contextlib, io
        adapter = es.EslintSecurityAdapter()
        fake_run = FakePopen(stdout=b"[]", stderr=b"eslint config error",
                             returncode=2)
        buf = io.StringIO()
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        return_value=fake_run), \
             mock.patch.object(es.EslintSecurityAdapter, "_lintable_sources",
                               return_value=["x.js"]), \
             contextlib.redirect_stderr(buf):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"[]")
        self.assertEqual(rc, 2)
        self.assertIn("tool eslint exited 2", buf.getvalue())
        self.assertIn("eslint config error", buf.getvalue())

    def test_flat_config_imports_plugin_and_enables_all_rules(self):
        cfg = es._flat_config()
        self.assertIn("import security from", cfg)
        # explicit .js entry -- ESM cannot import a bare directory (#run7)
        self.assertRegex(cfg, r'import security from "[^"]+\.js"')
        for rule in es.RULE_CWE:
            self.assertIn('"%s": "error"' % rule, cfg)   # every mapped rule ON

    def test_plugin_entry_is_absolute_trusted_path(self):
        # #83/#715: the plugin must be the TRUSTED global one, never a hostile
        # copy in the scanned target's node_modules. Importing by ABSOLUTE path
        # in the flat config makes plugin resolution independent of cwd/NODE_PATH,
        # so nothing the target ships can shadow it.
        with mock.patch("os.path.isfile",
                        side_effect=lambda p: p.startswith("/usr/local/lib/node_modules")):
            entry = es._plugin_entry()
        self.assertEqual(
            entry, "/usr/local/lib/node_modules/eslint-plugin-security/index.js")
        self.assertTrue(os.path.isabs(entry))

    def test_invoke_passes_absolute_target_path(self):
        # Once cwd is pinned away from the target, the linted path on argv
        # must be absolute so linting still resolves the right directory
        # regardless of the pinned cwd.
        adapter = es.EslintSecurityAdapter()
        fake_run = FakePopen(stdout=b"[]", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        return_value=fake_run) as popen_mock, \
             mock.patch.object(es.EslintSecurityAdapter, "_lintable_sources",
                               return_value=["x.js"]):
            adapter.invoke("relative/target")
        args, _kwargs = popen_mock.call_args
        cmd = args[0]
        self.assertEqual(cmd[-1], os.path.abspath("relative/target"))

    # #984: applicable-but-nothing-to-lint -> ran-clean empty, not a skip.
    def test_invoke_short_circuits_when_only_package_json(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "package.json"), "w").close()
            fake_run = mock.Mock()
            with mock.patch("scripts.tools.base.subprocess.Popen", fake_run):
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
            with mock.patch("scripts.tools.base.subprocess.Popen", fake_run):
                stdout, rc = es.EslintSecurityAdapter().invoke(d)
        self.assertEqual((stdout, rc), (b"[]", 0))
        fake_run.assert_not_called()

    def test_invoke_runs_eslint_when_real_source_present(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "app.js"), "w").close()
            fake_run = FakePopen(stdout=b"[]", stderr=b"", returncode=0)
            with mock.patch("scripts.tools.base.subprocess.Popen",
                            return_value=fake_run) as popen_mock:
                es.EslintSecurityAdapter().invoke(d)
        popen_mock.assert_called_once()   # source present -> eslint really runs
        self.assertEqual(popen_mock.call_args[0][0][0], "eslint")

    def test_parse_includes_provenance(self):
        findings = es.EslintSecurityAdapter().parse(ESLINT_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(first(findings)["provenance"]["discovered_by"], "tool:eslint-security")
        self.assertEqual(first(findings)["provenance"]["confirmation_status"], "TOOL")

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
