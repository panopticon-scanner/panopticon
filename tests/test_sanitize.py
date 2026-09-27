"""#run12 SEC: scrub() is the shared chokepoint of every script that posts to a
PUBLIC GitHub issue (file_issues.py, file_fixmes.py, triage.py), but it only
stripped repo-root paths -- it did no secret redaction at all.

Only file_issues.py was incidentally covered, because it reads a report.json
that synth/render.py had already run through redact_tree(). file_fixmes.py
(markdown FIXME doc) and triage.py (JSONL ledger rows) never touch that path,
so a secret in either went to GitHub verbatim. These tests pin redaction to the
chokepoint itself, so coverage no longer depends on which artifact a filer reads.
"""
import contextlib
import os
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from tests._test_helpers import fake_aws_key
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
            # A real directory, not a fabricated one: the fallback now refuses a
            # cwd that is not an existing directory, so the trailing-separator
            # normalisation this pins has to be measured on one that is.
            with self.subTest(result=result), tempfile.TemporaryDirectory() as cwd, \
                    mock.patch.object(sanitize.os, "getcwd",
                                      return_value=os.path.realpath(cwd) + "//"), \
                    mock.patch.object(sanitize.subprocess, "run") as run:
                if isinstance(result, Exception):
                    run.side_effect = result
                else:
                    run.return_value = result
                self.assertEqual(sanitize._detect_repo_root(),
                                 os.path.realpath(cwd) + "/")
                run.assert_called_once_with(["git", "rev-parse", "--show-toplevel"],
                                            capture_output=True, text=True, timeout=10)


class TestRepoRootBinding(unittest.TestCase):
    """ARC-1735086130 (#1777): the root came from the ambient cwd and a degenerate
    one was RETURNED rather than refused. With `git` failing and the cwd at `/`,
    the probe got `scrub()` output with every `/` deleted (and an empty-match
    second substitution); run from a different checkout, the prefix is wrong, so
    scrub strips nothing and the operator's absolute paths reach a public issue.

    `subprocess.run` is stubbed in every case here rather than trusting `git` to
    be absent from PATH: a shim on the box would make these pass vacuously.
    """

    @contextlib.contextmanager
    def _no_cache(self):
        saved = sanitize._REPO_ROOT_CACHE
        sanitize._REPO_ROOT_CACHE = None
        try:
            yield
        finally:
            sanitize._REPO_ROOT_CACHE = saved

    def _git_fails(self):
        return mock.patch.object(sanitize.subprocess, "run",
                                 side_effect=OSError("git unavailable"))

    def _git_reports(self, toplevel):
        return mock.patch.object(sanitize.subprocess, "run",
                                 return_value=SimpleNamespace(returncode=0,
                                                              stdout=toplevel + "\n"))

    def test_degenerate_cwd_is_refused_instead_of_deleting_every_slash(self):
        text = "see /Users/me/repo/skill/scripts/driver.py:12 and http://x/y"
        calls = (("_detect_repo_root", lambda: sanitize._detect_repo_root()),
                 ("repo_root", lambda: sanitize.repo_root()),
                 ("scrub", lambda: sanitize.scrub(text)),
                 ("repo_relative", lambda: sanitize.repo_relative("/Users/me/repo/a.py")))
        for name, call in calls:
            with self.subTest(call=name), self._no_cache(), self._git_fails(), \
                    mock.patch.object(sanitize.os, "getcwd", return_value="/"):
                with self.assertRaises(RuntimeError) as caught:
                    call()
                self.assertIn("filesystem root", str(caught.exception))
                # A refused detection must not be cached as a usable root.
                self.assertIsNone(sanitize._REPO_ROOT_CACHE)

    def test_git_reporting_the_filesystem_root_is_refused_as_well(self):
        with self._no_cache(), self._git_reports("/"):
            with self.assertRaises(RuntimeError):
                sanitize.repo_root()

    def test_explicit_root_binds_the_prefix_and_a_wrong_root_strips_nothing(self):
        under_checkout = sanitize.repo_root() + "skill/scripts/driver.py"
        text = "see %s:12" % under_checkout
        with tempfile.TemporaryDirectory() as other:
            self.assertEqual(sanitize.scrub(text, root=other), text)
            self.assertEqual(sanitize.repo_relative(under_checkout, root=other),
                             under_checkout)
        self.assertEqual(sanitize.scrub(text, root=sanitize.repo_root()),
                         "see skill/scripts/driver.py:12")
        self.assertEqual(sanitize.repo_relative(under_checkout, root=sanitize.repo_root()),
                         "skill/scripts/driver.py")

    def test_both_detection_branches_and_an_explicit_root_are_realpathd(self):
        """An operator can pass the LOGICAL root a shell shows them while the
        locations carry the physical one, and the prefix would match nothing.
        Measured on this box: `git rev-parse --show-toplevel` and `os.getcwd()`
        both report the physical path, so the realpath is a no-op on the two
        detection branches -- both are stubbed with a logical path here, which
        is what keeps them defensive should a git ever report one."""
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(os.path.realpath(d), "checkout")
            os.mkdir(real)
            logical = os.path.join(d, "logical")
            os.symlink(real, logical)
            self.assertNotEqual(logical, real)
            location = os.path.join(real, "skill/scripts/driver.py")
            self.assertEqual(sanitize.scrub("at " + location, root=logical),
                             "at skill/scripts/driver.py")
            with self._no_cache(), self._git_reports(logical):
                self.assertEqual(sanitize.repo_root(), real + "/")
            with self._no_cache(), self._git_fails(), \
                    mock.patch.object(sanitize.os, "getcwd", return_value=logical):
                self.assertEqual(sanitize.repo_root(), real + "/")

    def test_a_degenerate_or_relative_explicit_root_is_refused(self):
        for root in ("/", "", ".", "skill/scripts"):
            with self.subTest(root=root):
                with self.assertRaises(RuntimeError):
                    sanitize.scrub("see /a/b.py", root=root)
                with self.assertRaises(RuntimeError):
                    sanitize.repo_relative("/a/b.py", root=root)

    def test_a_root_that_is_not_an_existing_directory_is_refused(self):
        """A typo'd, vanished or file-shaped root is absolute and non-degenerate,
        so the earlier checks pass it -- and then it strips nothing, which is the
        leak this module exists to prevent, reached through the explicit door."""
        with tempfile.TemporaryDirectory() as d:
            a_file = os.path.join(d, "report.json")
            with open(a_file, "w", encoding="utf-8") as fh:
                fh.write("{}")
            for root in (os.path.join(d, "no-such-checkout"), a_file):
                with self.subTest(root=root):
                    for name, call in (("scrub", lambda: sanitize.scrub(
                                            "see /a/b.py", root=root)),
                                       ("repo_relative", lambda: sanitize.repo_relative(
                                            "/a/b.py", root=root))):
                        with self.subTest(call=name):
                            with self.assertRaises(RuntimeError) as caught:
                                call()
                            self.assertIn("not a directory", str(caught.exception))

    def test_each_door_refuses_with_the_remedy_that_fits_it(self):
        """A caller who passed `root=` cannot act on "pass the root explicitly",
        so the explicit door has its own remedy; the detection branches keep
        theirs byte-exact."""
        with self._no_cache(), self._git_fails(), \
                mock.patch.object(sanitize.os, "getcwd", return_value="/"):
            with self.assertRaises(RuntimeError) as detected:
                sanitize.repo_root()
        self.assertEqual(
            str(detected.exception),
            "git rev-parse failed and the cwd is the filesystem root; run the"
            " filer from the checkout or pass the root explicitly")
        with self.assertRaises(RuntimeError) as explicit:
            sanitize.scrub("see /a/b.py", root="/")
        self.assertIn("pass an absolute path to an existing checkout",
                      str(explicit.exception))
        self.assertNotIn("pass the root explicitly", str(explicit.exception))


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

    def test_gh_reference_is_defanged_in_every_form_github_links(self):
        # Measured against GitHub's renderer on 2026-09-27 (gfm mode, this repo as
        # context): GH-N links in any letter case and beside '/', '-', '.' or a
        # non-ASCII letter (#2192; COD-3436467706).
        cases = [
            ("gh-1", "gh", "1"),
            ("Gh-1", "Gh", "1"),
            ("gH-2175", "gH", "2175"),
            ("src/GH-123/file.py", "GH", "123"),
            ("GH-123.py", "GH", "123"),
            ("prefix-GH-123", "GH", "123"),
            ("GH-123/notes", "GH", "123"),
            (".GH-1", "GH", "1"),
            ("éGH-1", "GH", "1"),
            ("src/gh-123/file.py", "gh", "123"),
            ("gh-123.py", "gh", "123"),
            ("prefix-gh-123", "gh", "123"),
        ]
        for text, letters, digits in cases:
            out = sanitize.defang(text)
            self.assertNotIn(letters + "-" + digits, out)
            self.assertIn(letters + "-​" + digits, out)
            self.assertEqual(sanitize.defang(out), out)

    def test_gh_reference_after_ascii_lookalike_letters_is_defanged(self):
        # A module-level re.IGNORECASE case-folds the lookbehind's ASCII class too,
        # so these non-ASCII look-alikes wrongly blocked the match even though none
        # of them is an ASCII letter, digit or underscore; GitHub's renderer links
        # all five (fix round 1 F1; #2192; COD-3436467706).
        cases = {
            "KGH-1": "KGH-​1",  # KELVIN SIGN
            "İGH-1": "İGH-​1",  # LATIN CAPITAL LETTER I WITH DOT ABOVE
            "ıGH-1": "ıGH-​1",  # LATIN SMALL LETTER DOTLESS I
            "ſGH-1": "ſGH-​1",  # LATIN SMALL LETTER LONG S
            "Kgh-1": "Kgh-​1",  # KELVIN SIGN, lower-case gh
        }
        for text, expected in cases.items():
            out = sanitize.defang(text)
            self.assertEqual(out, expected)
            self.assertEqual(sanitize.defang(out), out)

    def test_hash_reference_after_non_ascii_letter_is_defanged(self):
        out = sanitize.defang("é#1")
        self.assertEqual(out, "é#​1")
        self.assertEqual(sanitize.defang(out), out)

    def test_http_reference_is_defanged_in_every_form_github_links(self):
        # _HTTP_RE used '\b', a Unicode word boundary, so a digit, underscore or
        # non-ASCII letter right before the scheme wrongly blocked the match;
        # GitHub's own boundary is only an ASCII letter (fix round 1 F2; #2192;
        # COD-3436467706).
        cases = {
            "1http://example.com": "1h​ttp://example.com",
            "_http://example.com": "_h​ttp://example.com",
            "_https://example.com": "_h​ttps://example.com",
            "x_http://example.com": "x_h​ttp://example.com",
            "éhttp://example.com": "éh​ttp://example.com",
            "中http://example.com": "中h​ttp://example.com",
            "ßhttp://example.com": "ßh​ttp://example.com",
            "ıhttp://example.com": "ıh​ttp://example.com",  # dotless i
            "Khttp://example.com": "Kh​ttp://example.com",  # Kelvin sign
            "١http://example.com": "١h​ttp://example.com",  # Arabic-indic 1
            "HtTp://example.com": "H​tTp://example.com",  # mixed case, letters kept
        }
        for text, expected in cases.items():
            out = sanitize.defang(text)
            self.assertEqual(out, expected)
            self.assertEqual(sanitize.defang(out), out)

    def test_autolink_http_still_inert_and_idempotent(self):
        out = sanitize.defang("<http://example.com>")
        self.assertNotIn("<http://", out)
        self.assertEqual(sanitize.defang(out), out)

    def test_forms_github_does_not_link_are_unchanged(self):
        for text in ("myGH-123", "MY_GH-123", "GH-123suffix", "1GH-1", "GH-1é",
                     "x_gh-123", "mygh-123", "x#1", "_#1", "1#1",
                     "www", "mywww.example.test",
                     "xhttps://example.com", "Xhttp://example.com", "Fhttp://example.com"):
            self.assertEqual(sanitize.defang(text), text)


if __name__ == "__main__":
    unittest.main()
