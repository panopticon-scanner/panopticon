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
* semgrep 1.177.0's built-in ignore list used to drop `tests/` and `test/` at a
  project root. The scanner-owned argv now replaces that list without its four
  common-test entries and ignores target `.semgrepignore`/`.gitignore` files.
  The generated real-Git and non-Git regression below proves both paths remain
  covered. Intentional fixture findings are still pruned and disclosed later by
  the ingest policy; they are not a reason to hide the rest of `tests/` here.

trivy is the exception -- it reads dependency manifests, the vendored
`vulnerable-python` fixture already carries one, and it is not path-sensitive.

Rule ids are asserted deliberately. If an upgrade renames or drops one this test
fails, and that IS the signal #1528 exists to produce, not noise to silence.
Triage the change; do not loosen the assertion reflexively.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pytest

from tests._test_helpers import (assert_adapter_finds, assert_adapter_finds_at,
                           only, skip_or_fail)
from scripts import run_tools, tools_manifest
from scripts.tools.legacy_sarif import LegacySarifAdapter
from tests.tools.helpers import OK_SCAN_EXIT_CODES, in_tools_image

# Derived, never literal: the committed source carries a seed, not a
# credential-shaped string. There is genuinely no secret here -- not a hidden
# one. The value is reproducible by anyone reading this file, and it exists so
# gitleaks and gosec can be PROVEN to still detect a credential-shaped string.
#
# The NAME is deliberate, and was not always this one. Calling it a SECRET
# tripped CodeQL's py/clear-text-storage-sensitive-data (high): that query's
# source is the IDENTIFIER, so a name saying "secret" that reaches a file write
# is, on its face, cleartext storage of a credential. The name was simply wrong
# -- this is a digest of public input -- so it now says what the value is. The
# strings written below are byte-for-byte unchanged, which is the line between
# fixing a misnomer and hiding from a scanner: gitleaks and gosec fire exactly
# as before.
DECOY_DIGEST = hashlib.sha256(
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

    def find_in(self, tool, files, *, matches):
        with tempfile.TemporaryDirectory() as d:
            _materialise(d, files)
            return assert_adapter_finds_at(self, tool, d,
                                           ok_codes=OK_SCAN_EXIT_CODES,
                                           label=tool + " target",
                                           matches=matches)


class TestSemgrepIntegration(_LiveTool):
    binary = "semgrep"

    def test_semgrep_flags_eval_of_untrusted_input(self):
        findings = self.find_in("semgrep", {
            "app.js": "const userInput = process.argv[2];\neval(userInput);\n"},
            matches=lambda f: (
                f["tool_evidence"]["rule_id"] ==
                "opt.semgrep-rules.javascript.browser.security.eval-detected"
                and f["location"]["file"].endswith("/app.js")
                and f["location"]["line_start"] == 2))
        self.assertTrue(
            any(f["location"]["file"].endswith("app.js") for f in findings),
            "semgrep reported findings but none against the planted file: %s"
            % sorted(f["location"]["file"] for f in findings))

    def test_semgrep_scans_test_code_despite_target_ignore_files(self):
        planted = {
            "src/control.js": "const value = process.argv[2];\neval(value);\n",
            "app/semgrepignored.js": "const value = process.argv[2];\neval(value);\n",
            "test/gitignored.js": "const value = process.argv[2];\neval(value);\n",
            "tests/defaultignored.js": "const value = process.argv[2];\neval(value);\n",
            ".semgrepignore": "app/\ntests/\n",
            ".gitignore": "test/\n",
        }
        expected = {"src/control.js", "app/semgrepignored.js", "test/gitignored.js",
                    "tests/defaultignored.js"}
        for git_root in (False, True):
            with self.subTest(git_root=git_root), tempfile.TemporaryDirectory() as root:
                _materialise(root, planted)
                if git_root:
                    subprocess.run(["git", "init", "-q", root], check=True)
                raw, rc = LegacySarifAdapter("semgrep").invoke(root)
                self.assertIn(rc, OK_SCAN_EXIT_CODES)
                findings = LegacySarifAdapter("semgrep").parse(raw, "g1")
                locations = {
                    f["location"]["file"].replace(os.sep, "/")
                    for f in findings
                    if (f.get("tool_evidence") or {}).get("rule_id") ==
                    "opt.semgrep-rules.javascript.browser.security.eval-detected"
                }
                seen = {rel for rel in expected
                        if any(path.endswith("/" + rel) for path in locations)}
                self.assertEqual(seen, expected, (git_root, sorted(locations)))


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
            "    return eval(s)\n")},
            matches=lambda f: (
                (f["tool_evidence"]["rule_id"],
                 f["location"]["line_start"]) in {("B307", 7), ("B602", 5)}
                and f["location"]["file"].endswith("/app.py")
            ))
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
            "config.yml": 'service:\n  api_key: "%s"\n' % DECOY_DIGEST},
            matches=lambda f: (
                f["tool_evidence"]["rule_id"] == "generic-api-key"
                and f["location"]["file"].endswith("/config.yml")
                and f["location"]["line_start"] == 2))
        self.assertIn("generic-api-key", self.rules_in(findings))

    def test_target_config_cannot_replace_default_rules(self):
        adapter = LegacySarifAdapter("gitleaks")
        with tempfile.TemporaryDirectory() as root:
            for case in ("normal", "hostile", "hostile_env", "malformed", "clean"):
                target = os.path.join(root, case)
                os.mkdir(target)
                _materialise(target, {"config.yml": (
                    'service:\n  api_key: "%s"\n' % DECOY_DIGEST
                    if case != "clean" else "service:\n  timeout: 20\n")})
                if case.startswith("hostile"):
                    _materialise(target, {
                        ".gitleaks.toml": (
                            'title = "target overrides rules"\n'
                            '[[rules]]\nid = "never-matches"\n'
                            'description = "poisoned rule set"\n'
                            'regex = "THIS_LITERAL_DOES_NOT_EXIST_IN_THE_TARGET"\n'),
                    })
                if case == "malformed":
                    _materialise(target, {".gitleaks.toml": "[rules\n"})
                if case == "hostile_env":
                    with mock.patch.dict(os.environ, {
                            "GITLEAKS_CONFIG": os.path.join(target, ".gitleaks.toml")}):
                        raw, rc = adapter.invoke(target)
                else:
                    raw, rc = adapter.invoke(target)
                self.assertIn(rc, OK_SCAN_EXIT_CODES, (case, rc))
                self.assertNotIn(DECOY_DIGEST.encode(), raw)
                findings = adapter.parse(raw, "g1")
                results = [result for run in json.loads(raw).get("runs", [])
                           for result in run.get("results", [])]
                if case == "clean":
                    self.assertEqual(rc, 0)
                    self.assertEqual(findings, [])
                    self.assertEqual(results, [])
                else:
                    self.assertEqual(rc, 1, case)
                    self.assertIn("generic-api-key", self.rules_in(findings), case)
                    self.assertTrue(any(
                        f["location"]["file"].endswith("config.yml") and
                        f["location"]["line_start"] == 2 for f in findings), case)
                    snippets = [loc["physicalLocation"]["region"]["snippet"]["text"]
                                for result in results
                                for loc in result.get("locations", [])]
                    self.assertTrue(snippets, case)
                    self.assertTrue(all(s == "REDACTED" for s in snippets), case)


@pytest.mark.docker
class TestGitleaksRunToolsDocker(unittest.TestCase):
    """Host Docker regression through the production dispatcher and capture path.

    The in-image adapter lane has no Docker daemon. This separate class runs
    only with an explicit host opt-in; strict mode makes missing prerequisites
    failures once the lane has opted in.
    """

    _image_id = None

    def setUp(self):
        if os.environ.get("PANOPTICON_GITLEAKS_HOST_DOCKER") != "1":
            # strict-skip-exempt: this class belongs to the separate host Docker lane
            self.skipTest("host Docker Gitleaks regression requires explicit opt-in")
        if self.__class__._image_id is None:
            image = os.environ.get("PANOPTICON_GITLEAKS_TEST_IMAGE", "")
            if not image:
                skip_or_fail(self, "PANOPTICON_GITLEAKS_TEST_IMAGE is unset")
            try:
                inspected = subprocess.run(
                    ["docker", "image", "inspect", "--format", "{{.Id}}", image],
                    capture_output=True, text=True, timeout=30, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                skip_or_fail(self, "Docker image inspection unavailable: %s" % exc)
            if inspected.returncode != 0:
                skip_or_fail(self, "Docker image unavailable: %s: %s" %
                             (image, inspected.stderr.strip()))
            image_id = inspected.stdout.strip()
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                self.fail("Docker did not resolve an immutable image ID: %r" % image_id)

            dockerfile = Path(__file__).resolve().parents[2] / "Dockerfile"
            match = re.search(r"^ARG GITLEAKS_VERSION=(\S+)$",
                              dockerfile.read_text(encoding="utf-8"), re.MULTILINE)
            self.assertIsNotNone(match, "Dockerfile lost its Gitleaks version pin")
            version = subprocess.run(
                ["docker", "run", "--rm", image_id, "gitleaks", "version"],
                capture_output=True, text=True, timeout=30, check=False)
            self.assertEqual(version.returncode, 0, version.stderr)
            self.assertRegex(version.stdout.strip(),
                             r"(?:^|[^0-9A-Za-z])v?%s(?:$|[^0-9A-Za-z])" %
                             re.escape(match.group(1)))
            self.__class__._image_id = image_id

    def _scan(self, root, *, mode, credential, ignore):
        target = root / "target"
        target.mkdir()
        config = target / "config.yml"
        config.write_text(
            'service:\n  api_key: "%s"\n' % DECOY_DIGEST if credential
            else 'service:\n  timeout: 20\n', encoding="utf-8")
        if ignore:
            (target / ".gitleaksignore").write_text(
                "/src/config.yml:generic-api-key:2\n", encoding="utf-8")
        original = {p.name: p.read_bytes() for p in target.iterdir()}
        captures = root / "captures"
        written = run_tools.run_tools(
            str(target), ["gitleaks"], str(captures),
            image=self.__class__._image_id, security_mode=mode)
        manifest_path = root / "tools-manifest.json"
        tools_manifest.write_manifest(str(manifest_path), ["gitleaks"], written)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(original,
                         {p.name: p.read_bytes() for p in target.iterdir()},
                         "the source tree changed during the scan")
        return written, manifest

    def test_ignore_file_matrix_through_real_run_tools(self):
        for credential, ignore in ((True, True), (True, False),
                                   (False, True), (False, False)):
            for mode in ("standard", "redteam"):
                with self.subTest(credential=credential, ignore=ignore, mode=mode):
                    with tempfile.TemporaryDirectory() as scratch:
                        root = Path(scratch)
                        written, manifest = self._scan(
                            root, mode=mode, credential=credential, ignore=ignore)
                        self.assertEqual(len(written), 1, manifest)
                        self.assertEqual(Path(written[0]).name, "gitleaks.sarif")
                        self.assertEqual(manifest["selected"], ["gitleaks"])
                        self.assertEqual(manifest["produced"], ["gitleaks"])
                        self.assertEqual(manifest["missing"], [])
                        self.assertTrue(manifest["redacted"])
                        posture = ("neutralised" if ignore and mode == "redteam"
                                   else "honoured" if ignore else "absent")
                        self.assertEqual(manifest["ignore_files"],
                                         {"gitleaks": posture})
                        capture = Path(only(written, "Gitleaks capture")).read_bytes()
                        self.assertNotIn(DECOY_DIGEST.encode(), capture)
                        results = [result for run in json.loads(capture).get("runs", [])
                                   for result in run.get("results", [])]
                        expected = int(credential and (not ignore or mode == "redteam"))
                        self.assertEqual(len(results), expected, results)
                        if expected:
                            result = only(results, "Gitleaks SARIF result")
                            self.assertEqual(result["ruleId"], "generic-api-key")
                            location = only(result["locations"],
                                            "Gitleaks SARIF location")["physicalLocation"]
                            self.assertTrue(location["artifactLocation"]["uri"].endswith(
                                "/config.yml"), location)
                            self.assertEqual(location["region"]["startLine"], 2)
                            self.assertEqual(location["region"]["snippet"]["text"],
                                             "REDACTED")

    def test_unsafe_redteam_symlink_is_missing_coverage(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            target = root / "target"
            target.mkdir()
            config = target / "config.yml"
            config.write_text('service:\n  api_key: "%s"\n' % DECOY_DIGEST,
                              encoding="utf-8")
            ignore = target / ".gitleaksignore"
            ignore.symlink_to("config.yml")
            original = config.read_bytes()
            captures = root / "captures"
            written = run_tools.run_tools(
                str(target), ["gitleaks"], str(captures),
                image=self.__class__._image_id, security_mode="redteam")
            manifest_path = root / "tools-manifest.json"
            tools_manifest.write_manifest(str(manifest_path), ["gitleaks"], written)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(written, [])
            self.assertEqual(manifest["selected"], ["gitleaks"])
            self.assertEqual(manifest["produced"], [])
            self.assertEqual(manifest["missing"], ["gitleaks"])
            self.assertEqual(manifest["ignore_files"], {})
            self.assertFalse(manifest["redacted"])
            self.assertFalse((captures / "gitleaks.sarif").exists())
            self.assertEqual(config.read_bytes(), original)
            self.assertTrue(ignore.is_symlink())
            self.assertEqual(os.readlink(ignore), "config.yml")


class TestGosecIntegration(_LiveTool):
    binary = "gosec"

    def test_gosec_reads_go_source_and_flags_a_hardcoded_credential(self):
        # The Dockerfile runs this same shape at BUILD time (#1457: gosec with
        # no Go toolchain exits 0 having read zero files and parses perfectly).
        # This is the same proof at test time, through the adapter.
        findings = self.find_in("gosec", {
            "go.mod": "module verify\n\ngo 1.21\n",
            "main.go": 'package verify\n\nvar apiKey = "%s"\n' % DECOY_DIGEST},
            matches=lambda f: (
                f["tool_evidence"]["rule_id"] == "G101"
                and f["location"]["file"] == "main.go"
                and f["location"]["line_start"] == 3))
        self.assertIn("G101", self.rules_in(findings))


class TestTrivyIntegration(_LiveTool):
    binary = "trivy"

    def test_trivy_flags_vulnerable_dependencies(self):
        # The one vendored target of the five: trivy reads a manifest, and
        # `vulnerable-python` already has one.
        findings = assert_adapter_finds(self, "trivy", "vulnerable-python",
                                        ok_codes=OK_SCAN_EXIT_CODES,
                                        matches=lambda f: (
                                            f["tool_evidence"]["rule_id"] == "CVE-2023-32681"
                                            and f["location"]["file"] == "requirements.txt"
                                            and f["citations"]["cve"] == ["CVE-2023-32681"]))
        self.assertTrue(
            any((f.get("citations") or {}).get("cve") or
                (f.get("tool_evidence") or {}).get("rule_id")
                for f in findings),
            "trivy findings carry neither a CVE citation nor a rule id")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
