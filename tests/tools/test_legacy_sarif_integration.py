"""#1528: the five LegacySarifAdapter tools had no live-tool coverage at all.

semgrep, bandit, trivy, gitleaks and gosec are dispatched through
`LegacySarifAdapter`, which spawns the real binary -- yet every test exercising
them handed it a `FakePopen`. Of the registry's 15 adapters, six had a
`test_*_integration.py` invoking the real tool; these five were among the nine
that did not, so a detection regression or upstream drift on an image rebuild
had nothing to fail.

Targets are GENERATED rather than vendored, for two independent reasons:

* gitleaks and gosec need a credential-shaped string. Deriving it at runtime
  from a plain seed means no such literal is committed to this public repo --
  after the NVD_API_KEY incident that is worth more than fixture convenience.
  It also matters mechanically: `tests/tools/` is NOT covered by the security
  gate's `tests/fixtures/*` exclusion, so a literal here would trip our own
  gitleaks in CI.
* semgrep's built-in default ignore list drops `tests/` and `test/` RELATIVE TO
  THE PROJECT ROOT, so a fixture committed under `tests/fixtures/` is invisible
  to it. Measured directly: seven identical files planted in one git repo under
  tests/, test/, src/, lib/, app/, fixtures/ and docs/ -- semgrep reported five,
  omitting exactly `tests/` and `test/`. (The relative path is what matters, not
  the directory name: the same file scanned with `/tmp/t/tests` AS the root is
  found, because then it is not under a `tests/` prefix.) Filed separately as
  #1584; here it simply means the target must be generated.

trivy is the exception -- it reads dependency manifests, the vendored
`vulnerable-python` fixture already carries one, and it is not path-sensitive.

Rule ids are asserted deliberately. If an upgrade renames or drops one this test
fails, and that IS the signal #1528 exists to produce, not noise to silence.
Triage the change; do not loosen the assertion reflexively.
"""
import hashlib
import os
import shutil
import tempfile
import unittest

from _test_helpers import (assert_adapter_finds, assert_adapter_finds_at,
                           skip_or_fail)
from .conftest import OK_SCAN_EXIT_CODES, in_tools_image

# Derived, never literal: the committed source carries a seed, not a
# credential-shaped string. There is genuinely no secret here -- not a hidden
# one -- so our own scanners have nothing to flag and nothing is being evaded.
DERIVED_SECRET = hashlib.sha256(
    b"panopticon-adapter-integration-fixture").hexdigest()[:40]


def _materialise(root, files):
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path) or root, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return root


class _LiveTool(unittest.TestCase):
    """Toolchain-gated: a clean skip on a dev machine, a hard failure in the
    environment that sets PANOPTICON_REQUIRE_INTEGRATION=1."""

    binary = ""

    def setUp(self):
        if not in_tools_image():
            skip_or_fail(self, "not running inside panopticon-tools; %s needs "
                               "the image's baked assets, not just the binary"
                         % self.binary)
        if not shutil.which(self.binary):
            skip_or_fail(self, "%s not installed on this host" % self.binary)

    def rules_in(self, findings):
        return {(f.get("tool_evidence") or {}).get("rule_id") for f in findings}

    def find_in(self, tool, files):
        with tempfile.TemporaryDirectory() as d:
            _materialise(d, files)
            return assert_adapter_finds_at(self, tool, d,
                                           ok_codes=OK_SCAN_EXIT_CODES,
                                           label=tool + " target")


class TestSemgrepIntegration(_LiveTool):
    binary = "semgrep"

    def test_semgrep_flags_eval_of_untrusted_input(self):
        findings = self.find_in("semgrep", {
            "app.js": "const userInput = process.argv[2];\neval(userInput);\n"})
        self.assertTrue(
            any(f["location"]["file"].endswith("app.js") for f in findings),
            "semgrep reported findings but none against the planted file: %s"
            % sorted(f["location"]["file"] for f in findings))


class TestBanditIntegration(_LiveTool):
    binary = "bandit"

    def test_bandit_flags_planted_python_weaknesses(self):
        # The eval / md5 / shell=True below are INERT STRING CONTENT written to
        # a temp file for bandit to read. Nothing here executes them, and the
        # file is deleted with the temp dir. Planting exactly what the scanner
        # is supposed to catch is the only way to prove it still catches it.
        findings = self.find_in("bandit", {"app.py": (
            "import hashlib, subprocess\n"
            "def weak(p):\n"
            "    return hashlib.md5(p.encode()).hexdigest()\n"
            "def run(cmd):\n"
            "    return subprocess.call(cmd, shell=True)\n"
            "def load(s):\n"
            "    return eval(s)\n")})
        rules = self.rules_in(findings)
        # B101/B404/B110/B112 are suppressed by the adapter's own -s list, so
        # these three prove the invocation reaches real analysis rather than
        # returning an empty-but-well-formed SARIF (the #1457 gosec shape).
        self.assertTrue({"B307", "B324", "B602"} & rules,
                        "expected eval/md5/shell=True rules, got %s" % sorted(rules))


class TestGitleaksIntegration(_LiveTool):
    binary = "gitleaks"

    def test_gitleaks_detects_a_planted_credential(self):
        findings = self.find_in("gitleaks", {
            "config.yml": 'service:\n  api_key: "%s"\n' % DERIVED_SECRET})
        self.assertIn("generic-api-key", self.rules_in(findings))


class TestGosecIntegration(_LiveTool):
    binary = "gosec"

    def test_gosec_reads_go_source_and_flags_a_hardcoded_credential(self):
        # The Dockerfile runs this same shape at BUILD time (#1457: gosec with
        # no Go toolchain exits 0 having read zero files and parses perfectly).
        # This is the same proof at test time, through the adapter.
        findings = self.find_in("gosec", {
            "go.mod": "module verify\n\ngo 1.21\n",
            "main.go": 'package verify\n\nvar apiKey = "%s"\n' % DERIVED_SECRET})
        self.assertIn("G101", self.rules_in(findings))


class TestTrivyIntegration(_LiveTool):
    binary = "trivy"

    def test_trivy_flags_vulnerable_dependencies(self):
        # The one vendored target of the five: trivy reads a manifest, and
        # `vulnerable-python` already has one.
        findings = assert_adapter_finds(self, "trivy", "vulnerable-python",
                                        ok_codes=OK_SCAN_EXIT_CODES)
        self.assertTrue(
            any((f.get("citations") or {}).get("cve") or
                (f.get("tool_evidence") or {}).get("rule_id")
                for f in findings),
            "trivy findings carry neither a CVE citation nor a rule id")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
