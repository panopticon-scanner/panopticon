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


if __name__ == "__main__":
    unittest.main()
