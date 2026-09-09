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


class TestRedactAdditionalVendorFormats(unittest.TestCase):
    """Each format below was FP-measured before being added: zero matches across
    run-12 finding text, all tracked source, and the goldens -- while firing on a
    well-formed specimen. All are anchored to a vendor prefix, or (JWT) to a
    three-segment base64url structure, which is what buys that zero. Contrast
    TestRedactRejectsGenericDetection."""

    CASES = {
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk": "[REDACTED_JWT]",
        "glpat-" + "A" * 20: "[REDACTED_TOKEN]",
        "npm_" + "b" * 36: "[REDACTED_TOKEN]",
        "hf_" + "c" * 34: "[REDACTED_TOKEN]",
        "SG." + "d" * 22 + "." + "e" * 43: "[REDACTED_KEY]",
        "dop_v1_" + "0" * 64: "[REDACTED_KEY]",
        "sk_live_" + "f" * 24: "[REDACTED_KEY]",
        "pypi-" + "g" * 40: "[REDACTED_TOKEN]",
        "xapp-1-" + "H" * 20: "[REDACTED_SLACK_TOKEN]",
    }

    def test_masks_each_added_format(self):
        for secret, marker in self.CASES.items():
            out = redact.redact("leak: %s here" % secret)
            self.assertIn(marker, out, secret)
            self.assertNotIn(secret, out, secret)

    def test_added_formats_survive_the_tree_walk(self):
        jwt = [k for k in self.CASES if k.startswith("eyJ")][0]
        out = redact.redact_tree({"d": "header %s trailer" % jwt})
        self.assertNotIn(jwt, out["d"])


class TestRedactRejectsGenericDetection(unittest.TestCase):
    """Why redact.py has no entropy / long-hex / long-base64 rule, pinned so it
    is not 'improved' back in.

    Measured across run-12 finding text, tracked source, and the goldens:
      hex>=32       ->  13 distinct in source,  26 in goldens (git SHAs, hashes)
      base64>=32    ->  75 distinct in source, 111 in goldens (mostly paths)
      entropy>=4.0  -> 402 distinct in source, 499 in goldens (URLs, paths)

    This project's text is saturated with exactly the shapes a generic detector
    keys on, and masking them breaks reconcile, integrity checking, and the
    readability of every report. A noisy detector is unusable as a REDACTOR --
    it mangles silently. The identifiers below must survive untouched."""

    MUST_SURVIVE = (
        "3d3c42e5aac5ba805825da76410c181273ba90b1",   # git SHA-1, 40 hex
        "6cc4359bc7b24170b30d62615bdca076",           # content hash, 32 hex
        "d41d8cd98f00b204e9800998ecf8427e",           # md5
        "claude-redteam-repo-20260909-6cc4359b",      # run tag
        "/mnt/panopticon/skill/scripts/synth/render.py",
        "https://github.com/panopticon-scanner/panopticon/pull/1566",
        "a1b2c3d4e5f60718",                           # finding fingerprint
    )

    def test_project_identifiers_are_never_masked(self):
        for ident in self.MUST_SURVIVE:
            self.assertEqual(redact.redact("ref %s ok" % ident),
                             "ref %s ok" % ident, ident)


class TestUuidIdentityKeysAreNotSecrets(unittest.TestCase):
    """The UUID rule shipped in #1566 masked SARIF identity fields, because the
    measurement that justified it used `git grep -E '\\b...'` -- and git grep's
    POSIX ERE does NOT honour \\b, so it reported 0 matches where plain grep
    finds 11. Never trust a zero from `git grep -E` with \\b.

    What the goldens actually contain is a clean natural experiment:
        gosec            "guid":   24 UUIDs -- SARIF rule identity, benign
        dependency-check "source": 12 UUIDs -- CVE data source, benign
        gitleaks         "text":    2 UUIDs -- the real leaked secret
    A legitimate UUID is introduced by a key that names it as an identifier; a
    leaked secret is not. That asymmetry is the discriminator."""

    UUID = "f2856fc0-85b7-373f-83e7-6f8582243547"

    def test_sarif_rule_guid_survives(self):
        src = '{"rules": [{"guid": "%s", "id": "G404"}]}' % self.UUID
        self.assertEqual(redact.redact(src), src)

    def test_dependency_check_source_uuid_survives(self):
        src = '{"vuln": {"source": "%s"}}' % self.UUID
        self.assertEqual(redact.redact(src), src)

    def test_identity_key_tolerates_whitespace_variants(self):
        for src in ('{"guid":"%s"}' % self.UUID,
                    '{"guid" :  "%s"}' % self.UUID):
            self.assertEqual(redact.redact(src), src, src)

    def test_a_snippet_field_is_still_masked(self):
        """gitleaks reports the secret under `text`. That must still be caught."""
        src = '{"snippet": {"text": "%s"}}' % self.UUID
        out = redact.redact(src)
        self.assertNotIn(self.UUID, out)
        self.assertIn("[REDACTED_UUID]", out)

    def test_a_bare_uuid_with_no_key_is_still_masked(self):
        out = redact.redact("generic-api-key detected: %s" % self.UUID)
        self.assertNotIn(self.UUID, out)

    def test_tree_walk_preserves_identity_uuids_by_key(self):
        """redact_tree() walks string LEAVES, so the key is not inside the string
        and the textual lookbehind cannot see it. The walker must carry the key
        down, or the fix works on one entry point and not the other -- which is
        the exact half-fix shape that caused the original leak."""
        src = {"rules": [{"guid": self.UUID, "id": "G404"}]}
        self.assertEqual(redact.redact_tree(src)["rules"][0]["guid"], self.UUID)

    def test_tree_walk_still_masks_a_snippet_uuid(self):
        src = {"snippet": {"text": self.UUID}}
        out = redact.redact_tree(src)
        self.assertNotIn(self.UUID, out["snippet"]["text"])

    def test_tree_walk_identity_exemption_is_uuid_only(self):
        """An identity key exempts a UUID, not arbitrary content: a real token
        parked under `source` is still masked."""
        secret = "ghp_" + "A" * 36
        out = redact.redact_tree({"source": secret})
        self.assertNotIn(secret, out["source"])

    def test_unknown_key_fails_closed_and_masks(self):
        """Only keys that explicitly name an identifier are exempt. Anything
        else -- including a key we have never seen -- is masked."""
        src = '{"apiKey": "%s"}' % self.UUID
        self.assertNotIn(self.UUID, redact.redact(src))


if __name__ == "__main__":
    unittest.main()
