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

    def test_an_unterminated_pem_does_not_swallow_what_follows_it(self):
        """#1639 P11 F1: the PEM rule is the ONE pattern here that is not
        anchored to a character class -- it used to be `.*?` under DOTALL, so a
        BEGIN with no END of its own ran on until it found somebody else's END
        and deleted everything in between. A truncated key snippet (gitleaks
        quotes one in the committed golden) plus any later complete block is all
        it takes."""
        text = ("-----BEGIN RSA PRIVATE KEY-----\nMIIBtruncated\n"
                "KEEP THIS LINE\n"
                "-----BEGIN RSA PRIVATE KEY-----\nMIIBrealkey\n"
                "-----END RSA PRIVATE KEY-----\n")
        out = redact.redact(text)
        self.assertIn("KEEP THIS LINE", out)
        self.assertIn("[REDACTED_PRIVATE_KEY]", out)
        self.assertNotIn("MIIBrealkey", out)

    # A PEM as it is embedded in C/C++/Java/older-Python source: one
    # double-quoted literal per line, concatenated. Quotes sit INSIDE the block,
    # which is why a `[^"]`-bounded body could not match it.
    QUOTED_SOURCE_PEM = (
        'KEY = ("-----BEGIN RSA PRIVATE KEY-----\\n"\n'
        '       "MIIEpAIBAAKCAQEAxLEAKEDKEYBODY0123456789abcdef\\n"\n'
        '       "-----END RSA PRIVATE KEY-----")')

    def test_masks_a_pem_quoted_from_source_as_adjacent_string_literals(self):
        """#1639 P11 round 2 N1: the round-1 `[^"]` bound silently stopped
        masking this shape -- a real private key published into report.json and
        written unmasked into `.panopticon/tools/`. The body is bounded by
        LENGTH now, not by a character class, so the quotes are irrelevant."""
        out = redact.redact("app/crypto.py embeds it:\n" + self.QUOTED_SOURCE_PEM)
        self.assertIn("[REDACTED_PRIVATE_KEY]", out)
        self.assertNotIn("MIIEpAIBAAKCAQEAxLEAKEDKEYBODY", out)

    def test_masks_that_same_shape_in_a_report_leaf(self):
        """The report path is per-leaf (`redact_tree`), which is where the
        reviewer found it published: the finding text is one string, so the
        leaf walk offers no protection the pattern does not provide itself."""
        out = redact.redact_tree({"findings": [
            {"id": "SEC-1", "location": {"file": "app/crypto.py", "line_start": 4},
             "description": "committed key:\n" + self.QUOTED_SOURCE_PEM}]})
        f = out["findings"][0]
        self.assertIn("[REDACTED_PRIVATE_KEY]", f["description"])
        self.assertNotIn("MIIEpAIBAAKCAQEAxLEAKEDKEYBODY", f["description"])
        # Structure and non-secret leaves untouched.
        self.assertEqual(f["location"], {"file": "app/crypto.py", "line_start": 4})
        self.assertEqual(f["id"], "SEC-1")

    def test_a_pem_body_is_length_bounded_so_a_flat_pass_cannot_run_away(self):
        """What replaces the `"` bound: a body over 16 KiB does not match AT
        ALL -- not the header, not the filler, not the END. A real private key
        is a couple of KiB, so the bound costs nothing on the shapes that
        matter, and it is what keeps a flat pass over a structured document
        from swallowing an unbounded run of fields between two blocks."""
        far = ("-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 20000 +
               "\n-----END RSA PRIVATE KEY-----")
        out = redact.redact("before " + far + " after")
        self.assertNotIn("[REDACTED_PRIVATE_KEY]", out)
        self.assertEqual(out, "before " + far + " after")

    def test_an_unterminated_pem_over_the_bound_is_not_a_runaway(self):
        """The same bound from the other side: a BEGIN with no END anywhere
        leaves the document exactly as it was (nothing masked), rather than the
        engine scanning to EOF for a close that never comes."""
        text = ("-----BEGIN RSA PRIVATE KEY-----\n" + "B" * 20000 +
                "\nTRAILING EVIDENCE\n")
        self.assertEqual(redact.redact(text), text)

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


class TestOnlyThePemRuleMayCrossAQuote(unittest.TestCase):
    """#1639 P11 round 3 NF2: the flat pass is what a NON-JSON capture gets
    (spotbugs' XML) and what a stderr excerpt gets, and its safety argument --
    stated in `redact.py`, in `run_tools._redact_capture` and in PANOPTICON.md --
    is that a match cannot run out of one field and into the next, because every
    pattern is anchored to a character class that excludes `"`.

    Exactly one rule is exempt: the PEM body, which MUST cross quotes (source
    code embeds a key one double-quoted literal per line) and is bounded by
    length instead. Nothing pinned any of that until now, so a future rule
    written with `[\\s\\S]`, a DOTALL `.`, or a class containing `"` could
    silently re-open #1639's structure defect on the one path that has no parse.

    The pattern list comes from the module, never a copy, and the corpus below
    must exercise every entry in it -- so a new rule that no sample matches
    fails `test_every_pattern_is_exercised_by_the_corpus` rather than slipping
    through this guard untested.
    """

    # One well-formed sample per rule in `redact._PATTERNS`. Not credentials:
    # every body is filler of the right shape and length.
    SAMPLES = (
        "ghp_" + "A" * 36,
        "github_pat_" + "b" * 40,
        "sk-" + "C" * 32,
        "Authorization: Bearer " + "D" * 24,
        "AKIA1234567890ABCDEF",
        "xoxb-1234567890-abcdefghij",
        "AIza" + "E" * 35,
        "xapp-1-" + "F" * 20,
        "glpat-" + "G" * 24,
        "npm_" + "H" * 36,
        "hf_" + "I" * 34,
        "pypi-" + "J" * 40,
        "SG." + "K" * 22 + "." + "L" * 43,
        "dop_v1_" + "a1b2c3d4" * 8,
        "sk_live_" + "M" * 24,
        "eyJ" + "N" * 12 + ".eyJ" + "O" * 12 + "." + "P" * 20,
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBfiller\n-----END RSA PRIVATE KEY-----",
        "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    )

    def _pem_rule(self):
        """The one exempt rule, identified by its own source rather than by
        position, so reordering `_PATTERNS` cannot silently exempt another."""
        pem = [pat for pat, _repl in redact._PATTERNS
               if "PRIVATE KEY" in pat.pattern]
        self.assertEqual(len(pem), 1, "expected exactly one PEM rule: %s" % pem)
        return pem[0]

    def _probes(self, sample):
        """A quote INSIDE a token, and a quote between two of them -- the two
        shapes a JSON/XML field boundary actually takes."""
        mid = len(sample) // 2
        return (sample[:mid] + '"' + sample[mid:],
                sample + '", "' + sample)

    def test_no_rule_but_the_pem_body_matches_across_a_quote(self):
        pem = self._pem_rule()
        offenders = []
        for pat, _repl in redact._PATTERNS:
            if pat is pem:
                continue
            for sample in self.SAMPLES:
                for probe in self._probes(sample):
                    for m in pat.finditer(probe):
                        if '"' in m.group(0):
                            offenders.append((pat.pattern, m.group(0)[:80]))
        self.assertEqual(offenders, [],
                         "a rule other than the PEM body spans a quote: %s"
                         % offenders)

    def test_the_pem_rule_really_does_cross_a_quote(self):
        """Non-vacuity: the probe shape CAN express a crossing, so the guard
        above is capable of failing. This is also the behaviour round 2 restored
        -- a key quoted out of C/Java source one literal per line."""
        probe = ('KEY = ("-----BEGIN RSA PRIVATE KEY-----\\n"\n'
                 '       "MIIBfiller\\n"\n'
                 '       "-----END RSA PRIVATE KEY-----")')
        m = self._pem_rule().search(probe)
        self.assertIsNotNone(m)
        self.assertIn('"', m.group(0))

    def test_every_pattern_is_exercised_by_the_corpus(self):
        """The guard above is only as good as its corpus: a rule that matches
        nothing here would be checked vacuously. Add a sample when you add a
        rule."""
        unexercised = [pat.pattern for pat, _repl in redact._PATTERNS
                       if not any(pat.search(s) for s in self.SAMPLES)]
        self.assertEqual(unexercised, [],
                         "add a well-formed sample for: %s" % unexercised)
