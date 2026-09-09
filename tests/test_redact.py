"""#run7 SEC-B2C: the single-source secret redaction shared by the driver
(tool output) and synthesize (shareable report bodies)."""
import unittest

import scripts.redact as redact


class TestRedact(unittest.TestCase):
    def test_masks_each_secret_format(self):
        cases = {
            "ghp_" + "A" * 36: "[REDACTED_TOKEN]",
            "github_pat_" + "b" * 40: "[REDACTED_TOKEN]",
            "sk-" + "c" * 32: "[REDACTED_KEY]",
            "AKIA" + "1234567890ABCDEF": "[REDACTED_AWS_KEY]",
            "xoxb-" + "1234567890-abcdefghij": "[REDACTED_SLACK_TOKEN]",
            "AIza" + "D" * 35: "[REDACTED_GOOGLE_KEY]",
        }
        for secret, marker in cases.items():
            out = redact.redact("leak: %s here" % secret)
            self.assertIn(marker, out, secret)
            self.assertNotIn(secret, out, secret)

    def test_masks_bearer_keeping_prefix(self):
        out = redact.redact("Authorization: Bearer " + "z" * 24)
        self.assertIn("Bearer [REDACTED]", out)
        self.assertNotIn("z" * 24, out)

    def test_masks_pem_private_key_block(self):
        pem = ("-----BEGIN RSA PRIVATE KEY-----\n"
               "MIIEpAIBAAKCAQEA...secret...\n"
               "-----END RSA PRIVATE KEY-----")
        out = redact.redact("here it is:\n%s\nend" % pem)
        self.assertIn("[REDACTED_PRIVATE_KEY]", out)
        self.assertNotIn("secret", out)

    def test_preserves_prose_that_only_mentions_a_format(self):
        # anchored to prefix+length -> a bare mention is NOT a well-formed token
        for prose in ("store the ghp_ token in the env",
                      "an sk- key is required", "the AKIA prefix identifies AWS",
                      "use a Bearer token"):
            self.assertEqual(redact.redact(prose), prose, prose)

    def test_empty_and_non_string(self):
        self.assertEqual(redact.redact(""), "")
        self.assertEqual(redact.redact(None), "")
        self.assertEqual(redact.redact(123), "123")

    def test_redact_tree_deep_walks_without_mutating_input(self):
        secret = "ghp_" + "Q" * 36
        src = {"findings": [{"id": "F1", "severity": "HIGH", "line": 5,
                             "description": "token %s leaked" % secret,
                             "references": ["see %s" % secret],
                             "location": {"file": "src/a.py"}}]}
        out = redact.redact_tree(src)
        # input untouched
        self.assertIn(secret, src["findings"][0]["description"])
        # copy fully masked, structure + non-string scalars preserved
        f = out["findings"][0]
        self.assertNotIn(secret, f["description"])
        self.assertIn("[REDACTED_TOKEN]", f["description"])
        self.assertNotIn(secret, f["references"][0])
        self.assertEqual(f["id"], "F1")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["line"], 5)                 # int passes through
        self.assertEqual(f["location"]["file"], "src/a.py")

    def test_redact_tree_scalar_passthrough(self):
        self.assertEqual(redact.redact_tree(42), 42)
        self.assertEqual(redact.redact_tree(None), None)
        self.assertEqual(redact.redact_tree(True), True)


class TestRedactBareUuidSecret(unittest.TestCase):
    """#run12 SEC: every pattern above needs a token prefix (ghp_, sk-, AKIA) or
    an assignment (Bearer). A secret *scanner* emits the secret with that context
    stripped -- gitleaks reported a leaked API key as the bare snippet
    `<uuid>` -- so nothing matched and the live key rode
    into the shareable report. Shape, not context, is the only thing left to
    match on. Synthetic UUID below; the real one is rotated and dead.
    """

    UUID = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"

    def test_masks_a_bare_uuid_shaped_secret(self):
        out = redact.redact("generic-api-key detected: %s" % self.UUID)
        self.assertIn("[REDACTED_UUID]", out)
        self.assertNotIn(self.UUID, out)

    def test_masks_uppercase_uuid(self):
        out = redact.redact("key %s here" % self.UUID.upper())
        self.assertIn("[REDACTED_UUID]", out)
        self.assertNotIn(self.UUID.upper(), out)

    def test_masks_uuid_inside_a_finding_tree(self):
        src = {"description": "the value %s appears in .env" % self.UUID}
        out = redact.redact_tree(src)
        self.assertNotIn(self.UUID, out["description"])
        self.assertIn("[REDACTED_UUID]", out["description"])

    def test_does_not_mask_panopticon_identifiers(self):
        """The rule is deliberately the hyphenated 8-4-4-4-12 form only. These
        real identifier shapes must survive, or every report gets mangled."""
        for benign in ("claude-redteam-repo-20260909-6cc4359b",   # run tag
                       "a1b2c3d4e5f60718",                        # fingerprint
                       "0b8ee306",                                # short hex
                       "d41d8cd98f00b204e9800998ecf8427e",        # md5, 32 hex
                       "2026-09-09", "v5.1.0-rc1"):
            self.assertEqual(redact.redact("id %s ok" % benign),
                             "id %s ok" % benign, benign)


if __name__ == "__main__":
    unittest.main()
