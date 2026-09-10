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
import shutil
import unittest

from _test_helpers import assert_adapter_finds, skip_or_fail
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
