"""Controlled contracts for fixture findings; no external scanner is invoked."""
import os
import tempfile
import unittest
from unittest import mock

import _test_helpers as helpers
from scripts.tools import ADAPTERS


class FakeAdapter:
    def __init__(self, findings, *, applicable=True, rc=1):
        self.findings = findings
        self.applicable = applicable
        self.rc = rc
        self.invoked = []
        self.groups = []

    def is_applicable(self, target):
        return self.applicable

    def invoke(self, target):
        self.invoked.append(target)
        return b"controlled fixture output", self.rc

    def parse(self, raw, group):
        assert raw == b"controlled fixture output"
        self.groups.append(group)
        return self.findings


def finding(rule, path, package=None):
    return {"tool_evidence": {"rule_id": rule, "package_name": package},
            "location": {"file": path, "line_start": 2}}


class TestSharedAdapterExpectation(unittest.TestCase):
    def test_matcher_is_required_and_keyword_only(self):
        with self.assertRaisesRegex(TypeError, "matches"):
            helpers.assert_adapter_finds(self, "controlled", "missing-fixture")
        with self.assertRaisesRegex(TypeError, "positional"):
            helpers.assert_adapter_finds_at(
                self, "controlled", "/inert", "g1", (0, 1), "label", lambda row: True)

    def test_planted_content_passes_and_all_findings_are_returned(self):
        unrelated = finding("OTHER", "other.js")
        planted = finding("eval-rule", "app.js")
        rows = [unrelated, planted]
        fake = FakeAdapter(rows)
        seen = []
        with tempfile.TemporaryDirectory() as target, mock.patch.dict(ADAPTERS, {"controlled": fake}):
            returned = helpers.assert_adapter_finds_at(
                self, "controlled", target, "special-group", (1,), "planted eval",
                matches=lambda row: seen.append(row) or (
                    row["tool_evidence"]["rule_id"] == "eval-rule"
                    and row["location"]["file"] == "app.js"))
        self.assertIs(returned, rows)
        self.assertEqual(seen, rows)
        self.assertEqual(fake.groups, ["special-group"])
        self.assertEqual(len(fake.invoked), 1)

    def test_unrelated_nonempty_output_fails_with_fixture_and_bounded_details(self):
        fake = FakeAdapter([finding("OTHER", "other.js")])
        with tempfile.TemporaryDirectory() as target, mock.patch.dict(ADAPTERS, {"controlled": fake}):
            with self.assertRaisesRegex(AssertionError, "planted eval.*OTHER.*other.js"):
                helpers.assert_adapter_finds_at(
                    self, "controlled", target, label="planted eval",
                    matches=lambda row: row["tool_evidence"]["rule_id"] == "eval-rule")

    def test_long_scanner_fields_have_bounded_mismatch_preview(self):
        fake = FakeAdapter([finding("RULE-" + "R" * 10000,
                                    "path/" + "F" * 10000,
                                    "PACKAGE-" + "P" * 10000)])
        with tempfile.TemporaryDirectory() as target, mock.patch.dict(ADAPTERS, {"controlled": fake}):
            with self.assertRaises(AssertionError) as caught:
                helpers.assert_adapter_finds_at(
                    self, "controlled", target, label="long-fields fixture",
                    matches=lambda row: row["tool_evidence"]["rule_id"] == "eval-rule")
        message = str(caught.exception)
        self.assertIn("long-fields fixture", message)
        self.assertIn("no finding matches expected planted content", message)
        for prefix in ("RULE-", "path/", "PACKAGE-"):
            self.assertIn(prefix, message)
        self.assertLess(len(message), 400)
        self.assertNotIn("R" * 100, message)
        self.assertNotIn("F" * 100, message)
        self.assertNotIn("P" * 100, message)

    def test_empty_wrong_exit_and_nonapplicability_fail_separately(self):
        for fake, message in (
            (FakeAdapter([]), "expected controlled findings"),
            (FakeAdapter([finding("eval-rule", "app.js")], rc=4), "errored \\(rc 4\\)"),
            (FakeAdapter([finding("eval-rule", "app.js")], applicable=False), "should apply"),
        ):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as target, \
                    mock.patch.dict(ADAPTERS, {"controlled": fake}):
                with self.assertRaisesRegex(AssertionError, message):
                    helpers.assert_adapter_finds_at(
                        self, "controlled", target,
                        matches=lambda row: row["tool_evidence"]["rule_id"] == "eval-rule")
            if not fake.applicable:
                self.assertEqual(fake.invoked, [])

    def test_named_fixture_forwards_callable_and_missing_mode(self):
        rows = [finding("eval-rule", "app.js")]
        fake = FakeAdapter(rows)
        with tempfile.TemporaryDirectory() as target, \
                mock.patch.object(helpers, "fixture_path", return_value=target), \
                mock.patch.dict(ADAPTERS, {"controlled": fake}):
            returned = helpers.assert_adapter_finds(
                self, "controlled", "planted-fixture", "other-group", (1,),
                matches=lambda row: row["location"]["file"] == "app.js")
        self.assertIs(returned, rows)
        self.assertEqual(fake.groups, ["other-group"])
        for required, error in ((False, unittest.SkipTest), (True, AssertionError)):
            with self.subTest(required=required), \
                    mock.patch.object(helpers, "fixture_path", return_value=None), \
                    mock.patch.object(helpers, "require_integration", return_value=required):
                with self.assertRaisesRegex(error, "missing-fixture"):
                    helpers.assert_adapter_finds(
                        self, "controlled", "missing-fixture", matches=lambda row: True)


class TestIntegrationCallerPredicates(unittest.TestCase):
    def test_semgrep_caller_rejects_wrong_rule_and_wrong_file(self):
        from tools.test_legacy_sarif_integration import TestSemgrepIntegration

        case = TestSemgrepIntegration("test_semgrep_flags_eval_of_untrusted_input")
        rule = "opt.semgrep-rules.javascript.browser.security.eval-detected"
        for row, should_pass in (
            (finding(rule, "tmp/app.js"), True),
            (finding("unrelated-rule", "tmp/app.js"), False),
            (finding(rule, "tmp/other.js"), False),
        ):
            with self.subTest(row=row), mock.patch.dict(ADAPTERS, {"semgrep": FakeAdapter([row])}):
                if should_pass:
                    case.test_semgrep_flags_eval_of_untrusted_input()
                else:
                    with self.assertRaisesRegex(AssertionError, "planted content"):
                        case.test_semgrep_flags_eval_of_untrusted_input()

    def test_bundler_caller_rejects_wrong_package_and_wrong_file(self):
        from tools.test_ruby_integration import TestRubyIntegration

        case = TestRubyIntegration("test_bundler_audit_finds_railsgoat_vulns")
        for row, should_pass in (
            (finding("CVE-2026-33168", "Gemfile.lock", "actionview"), True),
            (finding("CVE-2026-33168", "Gemfile.lock", "other"), False),
            (finding("CVE-2026-33168", "other.lock", "actionview"), False),
        ):
            row["tool_evidence"]["vulnerable_versions"] = "8.0.4"
            with self.subTest(row=row), \
                    mock.patch.object(helpers, "fixture_path", return_value=os.getcwd()), \
                    mock.patch.dict(ADAPTERS, {"bundler-audit": FakeAdapter([row])}):
                if should_pass:
                    case.test_bundler_audit_finds_railsgoat_vulns()
                else:
                    with self.assertRaisesRegex(AssertionError, "planted content"):
                        case.test_bundler_audit_finds_railsgoat_vulns()
