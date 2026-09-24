import json
import os
import tempfile
import unittest
from unittest import mock

from _test_helpers import FakePopen, first
from conftest import REPO_ROOT
import scripts.tools.eslint_security as es
from scripts.tools import ADAPTERS
from scripts.ingest_tools import ingest_dir_detailed


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

    def test_native_parse_error_representations_retain_findings_and_file_facts(self):
        for bad in (
            {"fatalErrorCount": 1, "messages": []},
            {"messages": [{"ruleId": None, "fatal": True, "message": "hostile text"}]},
            {"messages": [{"ruleId": None, "message": "Parsing error: hostile text"}]},
        ):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as d:
                raw = json.dumps(json.loads(ESLINT_SAMPLE) + [
                    {"filePath": "/src/nested/bad.tsx", **bad}]).encode()
                findings, facts = es.EslintSecurityAdapter().parse_with_file_coverage(raw, "g1")
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["severity"], "HIGH")
                self.assertEqual(facts["status"], "partial")
                self.assertEqual((facts["parsed_files"], facts["unparsed_files"]), (1, 1))
                self.assertEqual(facts["files"], [{"file": "nested/bad.tsx", "reason": "parse_error"}])
                with open(os.path.join(d, "eslint-security.json"), "wb") as fh:
                    fh.write(raw)
                findings, disp = ingest_dir_detailed(d, "g1")
                self.assertEqual(len(findings), 1)
                self.assertEqual(disp["eslint-security"]["status"], "ok")
                self.assertEqual(disp["eslint-security"]["file_coverage"], facts)
                self.assertNotIn("hostile", json.dumps(disp))

    def test_all_unparsed_is_disclosed_without_clean_file_claim(self):
        findings, facts = es.EslintSecurityAdapter().parse_with_file_coverage(
            b'[{"filePath":"/src/bad.js","fatalErrorCount":1,"messages":[]}]', "g1")
        self.assertEqual(findings, [])
        self.assertEqual((facts["status"], facts["parsed_files"], facts["unparsed_files"]),
                         ("partial", 0, 1))

    def test_coverage_paths_and_counts_are_bounded(self):
        rows = [{"filePath": "/src/" + "x" * 400 + "\n.js", "fatalErrorCount": 1,
                 "messages": []} for _ in range(125)]
        facts = es.file_coverage(rows)
        self.assertEqual(facts["unparsed_files"], 125)
        self.assertEqual(len(facts["files"]), 100)
        self.assertEqual(facts["files_omitted"], 25)
        self.assertTrue(all(len(f["file"]) <= 240 and "\n" not in f["file"]
                            for f in facts["files"]))

    def test_malformed_envelopes_and_native_types_fail_closed(self):
        metadata = {"version": 1, "typescript_parser": "unavailable", "files": [], "files_count": 0}
        invalid = [None, {}, {"results": []}, [{"filePath": "x", "messages": "bad"}],
                   [{"filePath": "x", "messages": [], "fatalErrorCount": True}],
                   [{"filePath": "x", "messages": [{"fatal": "false"}]}]]
        for key, value in (("version", True), ("typescript_parser", "present"),
                           ("files_count", -1), ("files_count", True),
                           ("files", ["x.ts"]), ("files_count", 1), ("extra", "hostile")):
            invalid.append({"panopticon_eslint": {**metadata, key: value}, "results": []})
        for document in invalid:
            with self.subTest(document=document):
                with self.assertRaisesRegex(ValueError, "invalid ESLint"):
                    es.EslintSecurityAdapter().parse(json.dumps(document).encode(), "g1")

    def test_old_image_keeps_js_findings_and_discloses_typescript(self):
        for files in (["good.js", "bad.ts", "view.tsx"], ["good.jsx"], ["only.ts"]):
            with self.subTest(files=files), tempfile.TemporaryDirectory() as target:
                for name in files:
                    open(os.path.join(target, name), "w").close()
                with mock.patch.object(es, "_TS_PARSER_ENTRY", os.path.join(target, "absent")), \
                     mock.patch.object(es, "run_tool", return_value=(ESLINT_SAMPLE, 1)) as run:
                    raw, rc = es.EslintSecurityAdapter().invoke(target)
                findings, facts = es.EslintSecurityAdapter().parse_with_file_coverage(raw, "g1")
                self.assertEqual(facts["status"], "partial")
                self.assertEqual(facts["capabilities_unavailable"], ["typescript_parser"])
                self.assertEqual(facts["unavailable_files"], sum(p.endswith((".ts", ".tsx")) for p in files))
                self.assertEqual(len(findings), int(files != ["only.ts"]))
                self.assertEqual(run.call_count, int(files != ["only.ts"]))
                self.assertIn(rc, (0, 1))
        self.assertNotIn("tsParser", es._flat_config(False))
        self.assertIn("noInlineConfig: true", es._flat_config(False))

    def test_native_module_sources_invoke_eslint_with_or_without_ts_parser(self):
        for extension in ("cjs", "mjs"):
            for parser_present in (False, True):
                for adjacent_ts in (False, True):
                    with self.subTest(extension=extension, parser=parser_present, ts=adjacent_ts), \
                         tempfile.TemporaryDirectory() as target:
                        parser = os.path.join(target, "trusted-parser-entry")
                        if parser_present:
                            open(parser, "w").close()
                        open(os.path.join(target, "exploit." + extension), "w").close()
                        if adjacent_ts:
                            open(os.path.join(target, "app.ts"), "w").close()
                        adapter = es.EslintSecurityAdapter()
                        self.assertTrue(adapter.is_applicable(target))
                        rows = json.loads(ESLINT_SAMPLE)
                        self.assertEqual(len(rows), 1)
                        rows[0]["filePath"] = "/src/exploit." + extension
                        with mock.patch.object(es, "_TS_PARSER_ENTRY", parser), \
                             mock.patch.object(es, "run_tool", return_value=(json.dumps(rows).encode(), 1)) as run:
                            raw, rc = adapter.invoke(target)
                        run.assert_called_once()
                        findings, coverage = adapter.parse_with_file_coverage(raw, "g1")
                        self.assertEqual(rc, 1)
                        self.assertEqual(len(findings), 1)
                        self.assertEqual(findings[0]["location"]["file"], "exploit." + extension)
                        self.assertEqual(findings[0]["severity"], "HIGH")
                        self.assertEqual(coverage["unavailable_files"], int(adjacent_ts and not parser_present))
                        self.assertEqual(coverage["status"], "complete" if parser_present else "partial")

    def test_existing_parser_import_failure_is_not_suppressed(self):
        with tempfile.TemporaryDirectory() as target:
            parser = os.path.join(target, "parser-entry")
            open(parser, "w").close()
            open(os.path.join(target, "good.js"), "w").close()
            with mock.patch.object(es, "_TS_PARSER_ENTRY", parser), \
                 mock.patch.object(es, "run_tool", return_value=(b"", 2)):
                self.assertEqual(es.EslintSecurityAdapter().invoke(target), (b"", 2))

    def test_null_rule_inline_warning_is_not_fatal(self):
        raw = json.dumps([{"filePath": "/src/good.js", "fatalErrorCount": 0,
                           "messages": [{"ruleId": None, "fatal": False,
                                         "severity": 1,
                                         "message": "Unused eslint-disable directive"}]}]).encode()
        self.assertEqual(es.EslintSecurityAdapter().parse(raw, "g1"), [])

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
        self.assertEqual(rc, 0)
        self.assertEqual(es.EslintSecurityAdapter().parse(stdout, "g1"), [])
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

    def test_flat_config_covers_all_formats_and_ignores_inline_directives(self):
        cfg = es._flat_config()
        self.assertIn("**/*.{js,jsx,cjs,mjs}", cfg)
        self.assertIn("**/*.{ts,tsx}", cfg)
        self.assertIn("ecmaFeatures: { jsx: true }", cfg)
        self.assertIn("parser: tsParser", cfg)
        self.assertIn("project: false", cfg)
        self.assertEqual(cfg.count("noInlineConfig: true"), 2)
        self.assertRegex(cfg, r'import tsParser from "/opt/panopticon-node/node_modules/@typescript-eslint/parser/dist/index.js"')

    def test_invoke_runs_from_the_target_and_keeps_the_config_outside_it(self):
        # #1877 round 2: eslint is the second documented cwd=target exception
        # (see tests/tools/test_adapter_cwd_confinement.py for the argument).
        # Its cwd is not a config-lookup surface, it is the flat config's BASE
        # PATH -- measured on the pinned eslint 10.9.0, a scratch cwd gave no
        # output and exit 2, "File ignored because it is located outside of
        # the base path". Two halves, pinned together: the PROCESS runs in the
        # target, and the generated CONFIG still does not live there (the
        # /src mount is read-only, and a config inside the tree is a config
        # the target could collide with).
        adapter = es.EslintSecurityAdapter()
        seen = {}

        def _record(cmd, **kwargs):
            seen["cwd"] = kwargs.get("cwd")
            seen["cfg"] = cmd[cmd.index("--config") + 1]
            return FakePopen(stdout=b"[]", stderr=b"", returncode=0)

        with mock.patch("scripts.tools.base.subprocess.Popen", side_effect=_record), \
             mock.patch.object(es.EslintSecurityAdapter, "_lintable_sources",
                               return_value=["x.js"]):
            adapter.invoke("relative/target")
        target = os.path.abspath("relative/target")
        self.assertEqual(seen["cwd"], target)
        self.assertFalse(seen["cfg"].startswith(target + os.sep),
                         "the generated config lives inside the target")
        # #1877 re-review R3: the config scratch used to be the cwd and rode on
        # the class pin's cleanup assertion; now that eslint is allowlisted
        # there, this is the one place that pins the scratch does not outlive
        # invoke().
        self.assertFalse(os.path.exists(os.path.dirname(seen["cfg"])),
                         "the config scratch directory outlived invoke()")

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

    def test_the_image_local_node_tree_wins_over_the_global_dirs(self):
        # #1734: the image stopped installing eslint globally -- `npm install
        # -g` resolved 136 transitive packages fresh from the registry and ran
        # their install scripts as root, so the tree now comes from `npm ci`
        # against a committed lockfile, in its own prefix. The adapter has to
        # look THERE first. The two global dirs stay after it so an older
        # published image, which a pinned digest can still pull, keeps working.
        present = ("/opt/panopticon-node/node_modules",
                   "/usr/local/lib/node_modules")
        with mock.patch("os.path.isfile",
                        side_effect=lambda p: p.startswith(present)):
            entry = es._plugin_entry()
        self.assertEqual(
            "/opt/panopticon-node/node_modules/eslint-plugin-security/index.js",
            entry)

    def test_the_adapter_and_the_dockerfile_name_the_same_prefix(self):
        # Two files have to agree on one path and neither imports the other, so
        # the agreement is asserted rather than assumed: a Dockerfile that
        # installs into a renamed prefix would leave the adapter resolving the
        # plugin by bare specifier, which is the "Cannot find module" empty
        # output that silently sank coverage certification in #run7.
        with open(os.path.join(REPO_ROOT, "Dockerfile"), encoding="utf-8") as fh:
            dockerfile = fh.read()
        prefix = first(es._GLOBAL_NODE_DIRS, "node_modules dir")
        self.assertEqual("/opt/panopticon-node/node_modules", prefix)
        self.assertIn("COPY tools-image/node/package.json "
                      "tools-image/node/package-lock.json "
                      "%s/" % os.path.dirname(prefix), dockerfile)
        self.assertIn('ENV PATH="%s/.bin:${PATH}"' % prefix, dockerfile)

    def test_invoke_passes_absolute_target_path(self):
        # The linted path on argv is absolute so it names the same directory
        # whatever the cwd is -- which also keeps it honest now that the cwd
        # is the target itself (#1877 round 2).
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
