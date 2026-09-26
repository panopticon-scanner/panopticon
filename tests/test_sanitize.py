"""#run12 SEC: scrub() is the shared chokepoint of every script that posts to a
PUBLIC GitHub issue (file_issues.py, file_fixmes.py, triage.py), but it only
stripped repo-root paths -- it did no secret redaction at all.

Only file_issues.py was incidentally covered, because it reads a report.json
that synth/render.py had already run through redact_tree(). file_fixmes.py
(markdown FIXME doc) and triage.py (JSONL ledger rows) never touch that path,
so a secret in either went to GitHub verbatim. These tests pin redaction to the
chokepoint itself, so coverage no longer depends on which artifact a filer reads.
"""
import unittest
import subprocess
from types import SimpleNamespace
from unittest import mock

from _test_helpers import fake_aws_key
import sanitize
import scripts.redact as redact

# Spelled whole on purpose. gitleaks' `generic-api-key` rule fires on a
# credential-shaped value ONLY when a keyword (`secret`, `token`, `key`, ...)
# sits beside it; a constant named UUID is not one, which is exactly why
# tests/test_capture_goldens.py composes the same value through fake_uuid()
# for a constant named SECRET. Renaming this one re-breaks the merge gate.
UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"


class TestScrubRedactsSecrets(unittest.TestCase):
    def test_bare_repo_root_and_child_path_have_bounded_replacements(self):
        root = "/fixture/repo/"
        text = ("At /fixture/repo, read /fixture/repo/a.py; "
                "keep /fixture/repo-sibling and /other/fixture/repo intact")
        with mock.patch.object(sanitize, "repo_root", return_value=root):
            self.assertEqual(sanitize.scrub(text),
                             "At the repo root, read a.py; "
                             "keep /fixture/repo-sibling and /other/fixture/repo intact")

    def test_scrub_masks_a_bare_uuid_secret(self):
        out = sanitize.scrub("generic-api-key detected: %s" % UUID)
        self.assertNotIn(UUID, out)
        self.assertIn("[REDACTED_UUID]", out)

    def test_scrub_masks_a_github_token(self):
        secret = "ghp_" + "A" * 36
        out = sanitize.scrub("leaked %s in the log" % secret)
        self.assertNotIn(secret, out)
        self.assertIn("[REDACTED_TOKEN]", out)

    def test_scrub_delegates_rather_than_copying_patterns(self):
        """Every format redact() knows must also be masked by scrub(). Guards
        against someone growing a second, drifting pattern list here."""
        for secret in ("ghp_" + "A" * 36, "github_pat_" + "b" * 40,
                       "sk-" + "c" * 32, fake_aws_key("1234567890ABCDEF"),
                       "xoxb-1234567890-abcdefghij", "AIza" + "D" * 35, UUID):
            text = "value: %s" % secret
            self.assertEqual(sanitize.scrub(text), redact.redact(text), secret)
            self.assertNotIn(secret, sanitize.scrub(text), secret)

    def test_scrub_masks_secret_that_has_been_defanged_first(self):
        """Callers do scrub(defang(text)). defang() inserts zero-width spaces;
        if a future defang rule ever split a token, redaction would silently
        stop matching. This is the tripwire for that."""
        for secret in ("ghp_" + "A" * 36, UUID):
            out = sanitize.scrub(sanitize.defang("found %s here" % secret))
            self.assertNotIn(secret, out, secret)

    def test_scrub_still_strips_the_repo_root(self):
        """Regression guard: redaction must not displace scrub's original job."""
        abs_path = sanitize.repo_root() + "skill/scripts/run_tools.py"
        self.assertEqual(sanitize.scrub("see %s here" % abs_path),
                         "see skill/scripts/run_tools.py here")

    def test_scrub_leaves_ordinary_prose_alone(self):
        for prose in ("store the ghp_ token in the env",
                      "run tag claude-redteam-repo-20260909-6cc4359b",
                      "fingerprint a1b2c3d4e5f60718"):
            self.assertEqual(sanitize.scrub(prose), prose, prose)


class TestRepoRootFallback(unittest.TestCase):
    def test_failed_git_detection_returns_normalized_cwd(self):
        failures = (SimpleNamespace(returncode=1, stdout="/wrong/repo\n"),
                    SimpleNamespace(returncode=0, stdout=" \n"),
                    OSError("git unavailable"),
                    subprocess.TimeoutExpired(["git"], 10))
        for result in failures:
            with self.subTest(result=result), \
                    mock.patch.object(sanitize.os, "getcwd", return_value="/fixture/work//"), \
                    mock.patch.object(sanitize.subprocess, "run") as run:
                if isinstance(result, Exception):
                    run.side_effect = result
                else:
                    run.return_value = result
                self.assertEqual(sanitize._detect_repo_root(), "/fixture/work/")
                run.assert_called_once_with(["git", "rev-parse", "--show-toplevel"],
                                            capture_output=True, text=True, timeout=10)


class TestResidualAutolinks(unittest.TestCase):
    def test_github_issue_form_and_documented_www_delimiters(self):
        for delimiter in ("", " ", "\n", "\t", "*", "_", "~", "("):
            text = delimiter + "www.example.test"
            self.assertEqual(sanitize.defang(text), delimiter + "w\u200bww.example.test")
        for text in ("GH-123", "(GH-123)", "See GH-123."):
            out = sanitize.defang(text)
            self.assertNotIn("GH-123", out)
            self.assertIn("GH-\u200b123", out)
            self.assertEqual(sanitize.defang(out), out)
        text = "GH-123 _www.example.test"
        self.assertEqual(sanitize.defang(sanitize.defang(text)), sanitize.defang(text))

    def test_ordinary_identifiers_and_paths_are_unchanged(self):
        for text in ("myGH-123", "MY_GH-123", "GH-123suffix", "src/GH-123/file.py",
                     "GH-123.py", "prefix-GH-123", "GH-123/notes", "www", "mywww.example.test"):
            self.assertEqual(sanitize.defang(text), text)


if __name__ == "__main__":
    unittest.main()
