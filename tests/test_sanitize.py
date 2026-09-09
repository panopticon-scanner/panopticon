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

import sanitize
import scripts.redact as redact

UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"


class TestScrubRedactsSecrets(unittest.TestCase):
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
                       "sk-" + "c" * 32, "AKIA1234567890ABCDEF",
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


if __name__ == "__main__":
    unittest.main()
