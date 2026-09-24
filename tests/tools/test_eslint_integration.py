"""#1528: eslint-security's two RCE-relevant controls were only ever asserted at
argv level.

`invoke()` generates a flat config and relies on two concrete defences:
`--no-config-lookup`, which stops the SCANNED TARGET's own eslint.config.js from
being discovered and EXECUTED, and importing the plugin by absolute path, which
defeats a hostile `node_modules` shadow copy (#83/#715). `test_eslint_security.py`
pins both in the argv against a FakePopen -- which does catch a dropped flag, as
the run-11 advisor correctly noted.

What no test covered is their EFFECT against the real, npm-installed binary.
eslint's config discovery and plugin loading have drifted on upgrade before (the
#run7 note in that same file), and argv assertions are blind to that entirely.
This runs the real thing.
"""
import json
import os
import shutil
import tempfile
import unittest

from _test_helpers import assert_adapter_finds, skip_or_fail
from scripts.tools.eslint_security import EslintSecurityAdapter
from .conftest import OK_SCAN_EXIT_CODES, in_tools_image


class TestEslintSecurityIntegration(unittest.TestCase):
    def setUp(self):
        if not in_tools_image():
            skip_or_fail(self, "not running inside panopticon-tools; eslint needs "
                               "the image's baked assets")
        if not shutil.which("eslint"):
            skip_or_fail(self, "eslint not installed on this host")

    def test_flags_eval_in_the_vendored_js_fixture(self):
        findings = assert_adapter_finds(self, "eslint-security", "insecure-js",
                                        ok_codes=OK_SCAN_EXIT_CODES)
        rules = {(f.get("tool_evidence") or {}).get("rule_id") for f in findings}
        self.assertTrue(
            any("security/" in (r or "") for r in rules),
            "expected a rule from eslint-plugin-security -- the plugin is "
            "loaded by ABSOLUTE PATH, so an empty result here can mean the "
            "plugin failed to load rather than that the code is clean: %s"
            % sorted(r for r in rules if r))

    def _scan(self, sources, extra_files=None):
        with tempfile.TemporaryDirectory() as target:
            for name, body in {**sources, **(extra_files or {})}.items():
                path = os.path.join(target, name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
            adapter = EslintSecurityAdapter()
            self.assertTrue(adapter.is_applicable(target))
            raw, rc = adapter.invoke(target)
            self.assertIn(rc, OK_SCAN_EXIT_CODES, (rc, raw[:1000]))
            return adapter, raw, target

    def test_real_js_ts_jsx_tsx_syntax_yields_eval_at_each_relative_path(self):
        sources = {
            'sample.js': 'const input = process.argv[2]; eval(input);',
            'sample.ts': 'const input: string = process.argv[2]; eval(input);',
            'sample.jsx': 'const view = <div/>; eval(process.argv[2]);',
            'sample.tsx': 'const input: string = process.argv[2]; const view = <div/>; eval(input);',
        }
        adapter, raw, _ = self._scan({"nested/" + name: body
                                     for name, body in sources.items()})
        findings = adapter.parse(raw, "g1")
        eval_hits = {f["location"]["file"]: f for f in findings
                     if f["tool_evidence"]["rule_id"] ==
                     "security/detect-eval-with-expression"}
        self.assertEqual(len(eval_hits), len(sources))
        for name in sources:
            self.assertTrue(any(path.endswith("/nested/" + name)
                                for path in eval_hits), (name, eval_hits))
        for path, finding in eval_hits.items():
            self.assertFalse(os.path.isabs(path), path)
            self.assertEqual(finding["severity"], "HIGH")

    def test_malformed_typescript_and_jsx_fail_parsing(self):
        for name, source in (("bad.ts", "const x: = 1;"),
                             ("bad.jsx", "const x = <div>;"),
                             ("bad.tsx", "const x: = <div/>;")):
            with self.subTest(name=name):
                adapter, raw, _ = self._scan({"nested/" + name: source,
                                              "good.js": "eval(process.argv[2]);"})
                self.assertTrue(any(row.get("fatalErrorCount") for row in json.loads(raw)))
                with self.assertRaisesRegex(ValueError, "ESLint parsing failed"):
                    adapter.parse(raw, "g1")

    def test_inline_disable_directives_cannot_hide_eval(self):
        source = 'const input = process.argv[2]; eval(input);'
        for directive in ('/* eslint-disable */',
                          '/* eslint-disable security/detect-eval-with-expression */',
                          ''):
            with self.subTest(directive=directive):
                adapter, raw, _ = self._scan({"nested/sample.js":
                                               directive + "\n" + source})
                findings = adapter.parse(raw, "g1")
                self.assertTrue(any(
                    f["location"]["file"].endswith("/nested/sample.js")
                    and f["tool_evidence"]["rule_id"] ==
                    "security/detect-eval-with-expression"
                    for f in findings), findings)

    def test_target_config_and_shadow_modules_do_not_execute(self):
        with tempfile.TemporaryDirectory() as markers:
            marker = os.path.join(markers, "executed")
            hostile = "require('fs').writeFileSync(%s, 'executed');" % json.dumps(marker)
            extra = {"eslint.config.js": hostile,
                     "node_modules/eslint-plugin-security/index.js": hostile,
                     "node_modules/@typescript-eslint/parser/dist/index.js": hostile}
            adapter, raw, _ = self._scan(
                {"sample.ts": "const input: string = process.argv[2]; eval(input);"},
                extra)
            findings = adapter.parse(raw, "g1")
            self.assertTrue(any(f["tool_evidence"]["rule_id"] ==
                                "security/detect-eval-with-expression"
                                for f in findings), findings)
            self.assertFalse(os.path.exists(marker))

    def test_package_only_tree_is_clean(self):
        adapter, raw, _ = self._scan({}, {"package.json": "{}"})
        self.assertEqual(adapter.parse(raw, "g1"), [])
