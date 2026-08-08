import os
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import file_issues


def _completed(returncode=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


FINDING = {
    "fingerprint": "deadbeefcafe0001",
    "id": "SEC-007",
    "location": {"file": "skill/scripts/run_tools.py", "line_start": 42},
    "severity": "HIGH",
    "evidence": {"status": "advisor_confirmed"},
    "confidence": "LIKELY",
    "description": "example",
}


class TestBodyProvenance(unittest.TestCase):
    def test_defaults_preserve_run2_footer(self):
        """body_for() with no run overrides must still describe run 2, so the
        one existing caller (reconcile_apply's recovery test) and any bare call
        keep working."""
        body = file_issues.body_for(FINDING)
        self.assertIn("self-scan run 2, 2026-08-04", body)
        self.assertIn(file_issues.RUN_STATE_DOC, body)
        self.assertIn(
            "https://github.com/panopticon-scanner/panopticon/blob/main/"
            "docs/superpowers/2026-08-04-self-scan-report.json", body)

    def test_run_overrides_thread_into_footer(self):
        body = file_issues.body_for(
            FINDING,
            report="docs/superpowers/2026-08-08-self-scan-report.json",
            report_url="https://example.test/run3.json",
            run_label="run 3",
            run_date="2026-08-08",
            run_state_doc="docs/superpowers/2026-08-08-self-scan-run-state.md")
        self.assertIn("self-scan run 3, 2026-08-08", body)
        self.assertIn("https://example.test/run3.json", body)
        self.assertIn("docs/superpowers/2026-08-08-self-scan-run-state.md", body)
        self.assertNotIn("run 2, 2026-08-04", body)

    def test_provenance_anchor_lines_are_stable(self):
        """The Fingerprint / Finding id / Location lines are the cross-run
        identity that reconcile recovery parses; parameterizing the report
        provenance must never disturb them."""
        body = file_issues.body_for(FINDING, run_label="run 3", run_date="2026-08-08")
        self.assertIn("**Fingerprint:** `deadbeefcafe0001`", body)
        self.assertIn("**Finding id in report:** `SEC-007`", body)
        self.assertIn("**Location:** `skill/scripts/run_tools.py:42`", body)


class TestRepoRootPortability(unittest.TestCase):
    """#602: REPO_ROOT was a hardcoded machine-specific absolute path; on any
    other machine scrub() silently no-opped and leaked local paths into public
    issues. It is now detected dynamically."""

    def test_repo_root_is_dynamic_absolute_with_trailing_sep(self):
        root = file_issues.repo_root()
        self.assertTrue(root.endswith("/"))
        self.assertTrue(os.path.isabs(root))
        # Detected root is this checkout — file_issues.py lives under it.
        self.assertTrue(os.path.abspath(__file__).startswith(root))

    def test_scrub_strips_the_detected_root(self):
        abs_path = file_issues.repo_root() + "skill/scripts/run_tools.py"
        self.assertEqual(file_issues.scrub("see %s here" % abs_path),
                         "see skill/scripts/run_tools.py here")

    def test_scrub_does_not_rewrite_sibling_prefixes(self):
        sibling = file_issues.repo_root().rstrip("/") + "-docs/guide.md"
        self.assertEqual(file_issues.scrub("see %s here" % sibling),
                         "see %s here" % sibling)

    def test_repo_relative_passes_through_relative_and_foreign_paths(self):
        self.assertEqual(file_issues.repo_relative("skill/a.py"), "skill/a.py")
        self.assertEqual(file_issues.repo_relative("/elsewhere/b.py"),
                         "/elsewhere/b.py")
        self.assertEqual(
            file_issues.repo_relative(file_issues.repo_root() + "c.py"), "c.py")


class TestKeyForNormalization(unittest.TestCase):
    """#607/#488: the ledger key's location component must be repo-relative so
    it matches the scrubbed issue body and recovers losslessly."""

    def test_absolute_location_keys_relative(self):
        f = {"fingerprint": "fp1", "id": "SEC-1",
             "location": {"file": file_issues.repo_root() + "skill/x.py"}}
        self.assertEqual(file_issues.key_for(f, rejected=False),
                         "fp1|SEC-1|skill/x.py|finding")

    def test_relative_location_unchanged(self):
        f = {"fingerprint": "fp1", "id": "SEC-1",
             "location": {"file": "skill/x.py"}}
        self.assertEqual(file_issues.key_for(f, rejected=False),
                         "fp1|SEC-1|skill/x.py|finding")

    def test_missing_location_keys_empty(self):
        self.assertEqual(file_issues.key_for({"fingerprint": "fp1", "id": "X"},
                                             rejected=True),
                         "fp1|X||rejected")


class TestCreateEmptyStdout(unittest.TestCase):
    """GitHub secondary rate limits make `gh issue create` exit 0 with empty
    stdout. create() must back off and retry, never crash on splitlines()[-1]."""

    def test_empty_stdout_then_url_retries_and_returns(self):
        calls = [_completed(0, ""), _completed(0, "https://gh/issues/900")]
        with mock.patch.object(file_issues.subprocess, "run",
                               side_effect=calls) as run, \
             mock.patch.object(file_issues.time, "sleep") as slept:
            url = file_issues.create("t", "b", ["self-scan"], dry=False)
        self.assertEqual(url, "https://gh/issues/900")
        self.assertEqual(run.call_count, 2)
        slept.assert_called()  # backed off between the empty response and retry

    def test_persistent_empty_stdout_returns_none_without_crashing(self):
        with mock.patch.object(file_issues.subprocess, "run",
                               return_value=_completed(0, "")), \
             mock.patch.object(file_issues.time, "sleep"):
            url = file_issues.create("t", "b", ["self-scan"], dry=False)
        self.assertIsNone(url)  # gave up after retries; run continues, no exception


if __name__ == "__main__":
    unittest.main()
