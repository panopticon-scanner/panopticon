import contextlib
import io
import json
import os
import tempfile
import shutil
import unittest
from unittest import mock

from _test_helpers import FakePopen, first
import scripts.tools.brakeman as br
from tests.tools.conftest import FIXTURE_ROOT

# Hand-built sample used for unit-level parse-shape assertions. It is NOT a
# real Brakeman scan; for integration coverage see test_railsgoat_fixture_shape.
BRAKEMAN_SAMPLE = json.dumps({
    "warnings": [
        {
            "warning_type": "SQL Injection",
            "message": "Possible SQL injection",
            "file": "app/controllers/users_controller.rb",
            "line": 12,
            "link": "https://brakemanscanner.org/docs/warning_types/sql_injection/",
            "confidence": "High",
            "code": "User.where(\"id = #{params[:id]}\")",
        }
    ]
}).encode()


class TestBrakemanAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = br.BrakemanAdapter().parse(BRAKEMAN_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:brakeman")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["confidence"], "CERTAIN")
        self.assertEqual(f["location"]["file"], "app/controllers/users_controller.rb")
        self.assertEqual(f["location"]["line_start"], 12)
        self.assertIn("CWE-89", f["citations"]["cwe"])

    def test_confidence_and_cwe_mappings(self):
        adapter = br.BrakemanAdapter()
        test_cases = [
            ("Cross-Site Scripting", "Medium", "LIKELY", "CWE-79"),
            ("Command Injection", "Low", "POSSIBLE", "CWE-78"),
            ("Redirect", "High", "CERTAIN", "CWE-601"),
            ("Dangerous Eval", "High", "CERTAIN", "CWE-94"),
            ("Cross-Site Request Forgery", "Medium", "LIKELY", "CWE-352"),
        ]
        for wt, conf, expected_conf, expected_cwe in test_cases:
            payload = json.dumps({
                "warnings": [{
                    "warning_type": wt,
                    "message": f"Test {wt}",
                    "file": "app/models/user.rb",
                    "line": 10,
                    "confidence": conf,
                    "code": "eval(x)",
                }]
            }).encode()
            findings = adapter.parse(payload, "g1")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["confidence"], expected_conf)
            self.assertIn(expected_cwe, findings[0]["citations"]["cwe"])

    def test_unknown_warning_type_and_confidence_fallbacks(self):
        adapter = br.BrakemanAdapter()
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            findings = adapter.parse(json.dumps({
                "warnings": [{
                    "warning_type": "Mystery Warning",
                    "message": "Something unmapped",
                    "file": "app/models/y.rb",
                    "line": 3,
                    "confidence": "High",
                }]
            }).encode(), "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(findings[0]["confidence"], "CERTAIN")
        self.assertEqual(findings[0].get("citations", {}).get("cwe", []), [])
        self.assertIn("unmapped warning_type 'Mystery Warning'", buf.getvalue())

        # Unknown confidence normalizes to POSSIBLE regardless of warning_type.
        findings = adapter.parse(json.dumps({
            "warnings": [{
                "warning_type": "SQL Injection",
                "message": "Known type, odd confidence",
                "file": "app/models/z.rb",
                "line": 5,
                "confidence": "Tentative",
            }]
        }).encode(), "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], "POSSIBLE")
        self.assertIn("CWE-89", findings[0]["citations"]["cwe"])

    # --- applicability: brakeman scans RAILS, nothing else ------------------
    # #calibration-1 (fzf): a bare Gemfile used to be enough. fzf is a Go
    # program with a Gemfile for its Ruby test harness, so brakeman was
    # selected, refused to run ("Please supply the path to a Rails
    # application", exit 4), produced nothing, and its absence GATED the run.

    def _tree(self, d, files=(), dirs=()):
        for sub in dirs:
            os.makedirs(os.path.join(d, sub), exist_ok=True)
        for rel, body in files:
            path = os.path.join(d, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        return d

    def test_rails_config_markers_apply(self):
        for marker in ("config/routes.rb", "config/application.rb",
                       "config/environment.rb"):
            with tempfile.TemporaryDirectory() as d:
                self._tree(d, files=[(marker, "Rails.application\n")])
                self.assertTrue(br.BrakemanAdapter().is_applicable(d), marker)

    def test_app_mvc_tree_applies(self):
        for sub in ("app/controllers", "app/models", "app/views"):
            with tempfile.TemporaryDirectory() as d:
                self._tree(d, dirs=[sub])
                self.assertTrue(br.BrakemanAdapter().is_applicable(d), sub)

    def test_gemfile_applies_only_when_it_depends_on_rails(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d, files=[("Gemfile", "source 'x'\ngem 'rails', '~> 7.0'\n")])
            self.assertTrue(br.BrakemanAdapter().is_applicable(d))
        with tempfile.TemporaryDirectory() as d:
            # a Ruby TEST HARNESS is not a Rails app -- this is the fzf shape
            self._tree(d, files=[("Gemfile", "source 'x'\ngem 'rspec'\ngem 'rubocop'\n")])
            self.assertFalse(br.BrakemanAdapter().is_applicable(d))
        with tempfile.TemporaryDirectory() as d:
            self._tree(d, files=[("Gemfile", "# gem 'rails'\ngem 'rake'\n")])
            self.assertFalse(br.BrakemanAdapter().is_applicable(d),
                             "a commented-out rails dependency must not count")

    def test_plain_gem_and_empty_tree_do_not_apply(self):
        with tempfile.TemporaryDirectory() as d:
            self._tree(d, files=[("mygem.gemspec", "Gem::Specification.new\n")])
            self.assertFalse(br.BrakemanAdapter().is_applicable(d),
                             "a plain gem is not a brakeman target")
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(br.BrakemanAdapter().is_applicable(d))
        self.assertFalse(br.BrakemanAdapter().is_applicable("/nonexistent/path"))

    def test_parse_includes_provenance(self):
        findings = br.BrakemanAdapter().parse(BRAKEMAN_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(first(findings)["provenance"]["discovered_by"], "tool:brakeman")
        self.assertEqual(first(findings)["provenance"]["confirmation_status"], "TOOL")

    def test_parse_empty_findings(self):
        findings = br.BrakemanAdapter().parse(b"{}", "g1")
        self.assertEqual(findings, [])
        findings = br.BrakemanAdapter().parse(b'{"warnings": []}', "g1")
        self.assertEqual(findings, [])

    def test_invoke_runs_brakeman_json(self):
        adapter = br.BrakemanAdapter()
        fake_run = FakePopen(stdout=b"{}", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        return_value=fake_run) as popen_mock:
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(rc, 0)
        popen_mock.assert_called_once_with(
            ["brakeman", "--format", "json", "--quiet", "--run-all-checks", "/tmp/fake"],
            stdout=mock.ANY,
            stderr=mock.ANY,
        )

    def test_invoke_remaps_rc_2_and_3_to_success(self):
        adapter = br.BrakemanAdapter()
        for rc_in in (2, 3):
            fake_run = FakePopen(stdout=b"{}", stderr=b"", returncode=rc_in)
            with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake_run):
                stdout, rc = adapter.invoke("/tmp/fake")
            self.assertEqual(rc, 0, f"rc={rc_in} should be remapped to 0")

    def test_invoke_leaves_rc_4_as_failure(self):
        adapter = br.BrakemanAdapter()
        fake_run = FakePopen(stdout=b"{}", stderr=b"", returncode=4)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake_run):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(rc, 4)

    def test_new_warning_type_uses_mapped_severity(self):
        # COD-C3B run-7: newly mapped warning types must not silently fall back.
        adapter = br.BrakemanAdapter()
        for wt, expected_sev in (
            ("Path Traversal", "HIGH"),
            ("Weak Hash", "MEDIUM"),
            ("Timing Attack", "LOW"),
            ("Command Injection", "HIGH"),
        ):
            payload = json.dumps({
                "warnings": [{
                    "warning_type": wt,
                    "message": f"Test {wt}",
                    "file": "app/controllers/x.rb",
                    "line": 7,
                    "confidence": "Medium",
                }]
            }).encode()
            findings = adapter.parse(payload, "g1")
            self.assertEqual(first(findings)["severity"], expected_sev, wt)

    def test_unmapped_warning_type_emits_stderr_and_defaults_medium(self):
        adapter = br.BrakemanAdapter()
        payload = json.dumps({
            "warnings": [{
                "warning_type": "Future Mystery Warning",
                "message": "Something new",
                "file": "app/models/y.rb",
                "line": 3,
                "confidence": "High",
            }]
        }).encode()
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            findings = adapter.parse(payload, "g1")
        self.assertEqual(first(findings)["severity"], "MEDIUM")
        self.assertIn("unmapped warning_type 'Future Mystery Warning'", buf.getvalue())

    def test_railsgoat_fixture_shape(self):
        """Integration probe against the real RailsGoat fixture when available.

        Skips outside the fixtures image; when present, asserts that parsed
        findings carry the real Brakeman fields we map from (warning_type,
        confidence, CWE).
        """
        target = os.path.join(FIXTURE_ROOT, "railsgoat")
        if not os.path.isdir(target):
            self.skipTest("railsgoat fixture not vendored (run inside the fixtures image)")
        if not shutil.which("brakeman"):
            self.skipTest("brakeman not installed on this host")
        adapter = br.BrakemanAdapter()
        self.assertTrue(adapter.is_applicable(target),
                        "brakeman should apply to the railsgoat project")
        raw, rc = adapter.invoke(target)
        self.assertIn(rc, (0, 1, 2, 3), f"brakeman errored (rc {rc}) on railsgoat")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected brakeman findings against railsgoat")
        for f in findings:
            self.assertIn(f["tool_evidence"]["rule_id"], f["title"])
            self.assertIn(f["confidence"], ("CERTAIN", "LIKELY", "POSSIBLE"))
            self.assertTrue(f.get("citations", {}).get("cwe"),
                            "expected at least one CWE citation")


if __name__ == "__main__":
    unittest.main()
