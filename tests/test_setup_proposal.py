import os
import sys
import unittest
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "skill", "scripts"))
import setup_proposal as sp

DATA = os.path.join(os.path.dirname(__file__), "..", "skill", "data")
VOCAB = os.path.join(DATA, "capability_vocabulary.yml")
AFFINITY = os.path.join(DATA, "capability_affinity.yml")


class TestLoaders(unittest.TestCase):
    def test_vocabulary_loads_fixture(self):
        vocab, errors = sp.load_vocabulary(VOCAB)
        self.assertEqual(errors, [])
        self.assertIn("Checkout", vocab["names"])
        self.assertIn("**/checkout/**", vocab["hints"]["Checkout"])

    def test_affinity_loads_fixture_and_validates_domains(self):
        vocab, _ = sp.load_vocabulary(VOCAB)
        affinity, errors = sp.load_affinity(AFFINITY, vocab)
        self.assertEqual(errors, [])
        self.assertEqual(affinity["Checkout"], ["SEC", "DAT", "ACC", "OPS"])
        # every fixture affinity key is a known vocabulary capability
        self.assertTrue(set(affinity).issubset(set(vocab["names"])))

    def test_vocabulary_flags_duplicate_and_empty_names(self):
        import tempfile
        doc = "capabilities:\n  - name: A\n  - name: A\n  - hints: [x]\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        _v, errors = sp.load_vocabulary(p)
        os.unlink(p)
        self.assertTrue(any("duplicate" in e for e in errors))
        self.assertTrue(any("name" in e for e in errors))

    def test_affinity_flags_unknown_domain_and_capability(self):
        import tempfile
        vocab = {"names": ["Auth"], "hints": {"Auth": []}}
        doc = "affinity:\n  Auth: [SEC, ZZZ]\n  Ghost: [SEC]\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        _a, errors = sp.load_affinity(p, vocab)
        os.unlink(p)
        self.assertTrue(any("ZZZ" in e and "domain" in e for e in errors))
        self.assertTrue(any("Ghost" in e and "capability" in e for e in errors))

    # Regression tests for robustness guards

    def test_vocabulary_scalar_hints_produces_error_no_char_explosion(self):
        import tempfile
        doc = 'capabilities:\n  - name: Auth\n    hints: "**/auth/**"\n'
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        vocab, errors = sp.load_vocabulary(p)
        os.unlink(p)
        # Must have error about hints needing to be list
        self.assertTrue(any("hints must be a list" in e for e in errors))
        # Must NOT have char-exploded hints (no single-char entries)
        self.assertEqual(vocab["hints"]["Auth"], [])

    def test_vocabulary_bare_string_entry_produces_error_no_crash(self):
        import tempfile
        doc = "capabilities:\n  - Auth\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        vocab, errors = sp.load_vocabulary(p)
        os.unlink(p)
        # Must have error about capability entry being a mapping
        self.assertTrue(any("must be a mapping" in e for e in errors))
        # No capability should be added
        self.assertEqual(vocab["names"], [])

    def test_vocabulary_non_mapping_doc_produces_error(self):
        import tempfile
        doc = "capabilities"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        vocab, errors = sp.load_vocabulary(p)
        os.unlink(p)
        self.assertTrue(any("root must be a mapping" in e for e in errors))
        self.assertEqual(vocab["names"], [])

    def test_vocabulary_non_list_capabilities_produces_error(self):
        import tempfile
        doc = "capabilities: {Auth: {hints: []}}\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        vocab, errors = sp.load_vocabulary(p)
        os.unlink(p)
        self.assertTrue(any("capabilities must be a list" in e for e in errors))
        self.assertEqual(vocab["names"], [])

    def test_affinity_scalar_domains_produces_error_no_char_explosion(self):
        import tempfile
        vocab = {"names": ["Auth"], "hints": {"Auth": []}}
        doc = "affinity:\n  Auth: SEC\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        affinity, errors = sp.load_affinity(p, vocab)
        os.unlink(p)
        # Must have error about domains needing to be list
        self.assertTrue(any("domains must be a list" in e for e in errors))
        # Must NOT have char-exploded domains (no single-char entries like 'S', 'E', 'C')
        self.assertEqual(affinity.get("Auth"), [])

    def test_affinity_non_mapping_doc_produces_error(self):
        import tempfile
        vocab = {"names": ["Auth"], "hints": {"Auth": []}}
        doc = "affinity"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        affinity, errors = sp.load_affinity(p, vocab)
        os.unlink(p)
        self.assertTrue(any("root must be a mapping" in e for e in errors))
        self.assertEqual(affinity, {})

    def test_affinity_non_mapping_affinity_block_produces_error(self):
        import tempfile
        vocab = {"names": ["Auth"], "hints": {"Auth": []}}
        doc = "affinity: [SEC]\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        affinity, errors = sp.load_affinity(p, vocab)
        os.unlink(p)
        self.assertTrue(any("affinity must be a mapping" in e for e in errors))
        self.assertEqual(affinity, {})

    def test_affinity_unknown_capability_excluded_from_result(self):
        import tempfile
        vocab = {"names": ["Auth"], "hints": {"Auth": []}}
        doc = "affinity:\n  Auth: [SEC]\n  Ghost: [SEC]\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        affinity, errors = sp.load_affinity(p, vocab)
        os.unlink(p)
        # Ghost should not be in returned affinity dict
        self.assertNotIn("Ghost", affinity)
        self.assertIn("Auth", affinity)
        self.assertTrue(any("Ghost" in e for e in errors))


class TestAssemble(unittest.TestCase):
    def setUp(self):
        self.vocab, _ = sp.load_vocabulary(VOCAB)
        self.affinity, _ = sp.load_affinity(AFFINITY, self.vocab)

    def _p(self, groups):
        return {"groups": groups}

    def test_matched_capability_gets_affinity_floor(self):
        proposal = self._p([{"capability": "Checkout",
                             "match": ["src/checkout/**"],
                             "tests": ["tests/checkout/**"]}])
        groups, disc = sp.assemble(proposal, self.vocab, self.affinity)
        self.assertEqual(groups["Checkout"]["panels"], ["SEC", "DAT", "ACC", "OPS"])
        self.assertEqual(groups["Checkout"]["match"], ["src/checkout/**"])
        entry = next(g for g in disc["groups"] if g["name"] == "Checkout")
        self.assertFalse(entry["custom"])
        self.assertEqual(entry["floor_source"], "affinity")

    def test_custom_group_gets_empty_floor(self):
        proposal = self._p([{"capability": "custom:GraphQLGateway",
                             "match": ["src/gateway/**"], "tests": []}])
        groups, disc = sp.assemble(proposal, self.vocab, self.affinity)
        self.assertEqual(groups["GraphQLGateway"]["panels"], [])
        entry = next(g for g in disc["groups"] if g["name"] == "GraphQLGateway")
        self.assertTrue(entry["custom"])
        self.assertEqual(entry["floor_source"], "empty(scout-only)")

    def test_unknown_capability_treated_as_custom(self):
        # a label not in the vocabulary and not prefixed -> custom, empty floor
        proposal = self._p([{"capability": "Telemetry", "match": ["src/tel/**"]}])
        groups, _disc = sp.assemble(proposal, self.vocab, self.affinity)
        self.assertEqual(groups["Telemetry"]["panels"], [])

    def test_malformed_proposal_returns_none_and_errors(self):
        for bad in ({"groups": "nope"}, {"groups": []},
                    {"groups": [{"capability": "Auth", "match": []}]},
                    {"groups": [{"capability": "Auth"}]}):
            groups, disc = sp.assemble(bad, self.vocab, self.affinity)
            self.assertIsNone(groups)
            self.assertTrue(disc["errors"])

    def test_assembled_groups_pass_groups_schema(self):
        proposal = self._p([{"capability": "Auth", "match": ["src/auth/**"]}])
        groups, _ = sp.assemble(proposal, self.vocab, self.affinity)
        parsed, errors = __import__("groups_schema").parse_groups({"groups": groups})
        self.assertEqual(errors, [])
        self.assertEqual(parsed["Auth"]["floor"], {"SEC"})

    def test_duplicate_group_name_collision_merges_and_discloses(self):
        # Auth and custom:Auth collide on group name "Auth"
        # First (matched) wins floor; match/tests union
        proposal = self._p([{"capability": "Auth", "match": ["src/auth/**"], "tests": ["tests/auth/**"]},
                            {"capability": "custom:Auth", "match": ["src/oauth/**"], "tests": ["tests/oauth/**"]}])
        groups, disc = sp.assemble(proposal, self.vocab, self.affinity)
        # Only one group named "Auth" in output
        self.assertIn("Auth", groups)
        # First occurrence's floor (SEC from affinity) is preserved
        self.assertEqual(groups["Auth"]["panels"], ["SEC"])
        # Match and tests are unioned
        self.assertEqual(groups["Auth"]["match"], ["src/auth/**", "src/oauth/**"])
        self.assertEqual(groups["Auth"]["tests"], ["tests/auth/**", "tests/oauth/**"])
        # disclosure["groups"] has only one entry for Auth (the first)
        auth_entries = [g for g in disc["groups"] if g["name"] == "Auth"]
        self.assertEqual(len(auth_entries), 1)
        self.assertFalse(auth_entries[0]["custom"])  # First is matched, not custom
        # collision is recorded
        self.assertEqual(len(disc["collisions"]), 1)
        collision = disc["collisions"][0]
        self.assertEqual(collision["name"], "Auth")
        self.assertEqual(collision["capability"], "custom:Auth")

    def test_bare_custom_prefix_rejected_in_validation(self):
        # "custom:" with no name after should be rejected
        proposal = self._p([{"capability": "custom:", "match": ["src/**"]}])
        groups, disc = sp.assemble(proposal, self.vocab, self.affinity)
        self.assertIsNone(groups)
        self.assertTrue(any("custom:" in e or "empty" in e for e in disc["errors"]))

    def test_known_capability_with_no_affinity_entry_marked_missing(self):
        # Build a vocab with a capability not in affinity
        vocab = {"names": ["Auth", "NoAffinity"], "hints": {"Auth": [], "NoAffinity": []}}
        affinity = {"Auth": ["SEC"]}  # NoAffinity is intentionally missing
        proposal = self._p([{"capability": "NoAffinity", "match": ["src/missing/**"]}])
        groups, disc = sp.assemble(proposal, vocab, affinity)
        # Group is created with empty floor
        self.assertEqual(groups["NoAffinity"]["panels"], [])
        # But floor_source distinguishes it from custom
        entry = next(g for g in disc["groups"] if g["name"] == "NoAffinity")
        self.assertFalse(entry["custom"])
        self.assertEqual(entry["floor_source"], "affinity(missing)")


class TestMergeAdditive(unittest.TestCase):
    def test_first_run_adopts_all_claiming_groups(self):
        assembled = {"Auth": {"match": ["src/auth/**"], "tests": [], "panels": ["SEC"]}}
        claims = {"Auth": ["src/auth/login.py"]}
        merged, diff = sp.merge_additive({}, assembled, claims)
        self.assertIn("Auth", merged)
        self.assertEqual([g["name"] for g in diff["new_groups"]], ["Auth"])

    def test_existing_group_is_never_rewritten(self):
        committed = {"Auth": {"match": ["src/auth/**"], "tests": ["tests/auth/**"],
                              "panels": ["SEC", "ACC"]}}  # owner added ACC
        assembled = {"Auth": {"match": ["src/auth/**"], "tests": [], "panels": ["SEC"]}}
        claims = {"Auth": []}  # claims nothing new
        merged, diff = sp.merge_additive(committed, assembled, claims)
        self.assertEqual(merged["Auth"]["panels"], ["SEC", "ACC"])  # floor untouched
        self.assertEqual(merged["Auth"]["match"], ["src/auth/**"])  # not duplicated
        self.assertEqual(diff["dropped_redundant"], ["Auth"])

    def test_existing_group_extended_with_new_globs_only(self):
        committed = {"Auth": {"match": ["src/auth/**"], "tests": [], "panels": ["SEC"]}}
        assembled = {"Auth": {"match": ["src/auth/**", "src/oauth/**"], "tests": [],
                              "panels": ["SEC"]}}
        claims = {"Auth": ["src/oauth/idp.py"]}
        merged, diff = sp.merge_additive(committed, assembled, claims)
        self.assertEqual(merged["Auth"]["match"], ["src/auth/**", "src/oauth/**"])
        self.assertEqual(diff["extended_groups"][0]["added_match"], ["src/oauth/**"])
        self.assertEqual(merged["Auth"]["panels"], ["SEC"])  # floor still not touched

    def test_new_group_added_when_it_claims_files(self):
        committed = {"Auth": {"match": ["src/auth/**"], "tests": [], "panels": ["SEC"]}}
        assembled = {"Checkout": {"match": ["src/checkout/**"], "tests": [],
                                  "panels": ["SEC", "DAT"]}}
        claims = {"Checkout": ["src/checkout/pay.py"]}
        merged, diff = sp.merge_additive(committed, assembled, claims)
        self.assertIn("Checkout", merged)
        self.assertIn("Auth", merged)  # existing preserved
        self.assertEqual(diff["new_groups"][0]["name"], "Checkout")

    def test_redundant_group_dropped(self):
        assembled = {"Ghost": {"match": ["src/ghost/**"], "tests": [], "panels": []}}
        merged, diff = sp.merge_additive({"A": {"match": ["a/**"], "tests": [],
                                                "panels": []}}, assembled, {"Ghost": []})
        self.assertNotIn("Ghost", merged)
        self.assertEqual(diff["dropped_redundant"], ["Ghost"])

    def test_dump_round_trips_through_groups_schema(self):
        import groups_schema
        groups = {"Checkout": {"match": ["src/checkout/**"],
                               "tests": ["tests/checkout/**"],
                               "panels": ["SEC", "DAT"]}}
        text = sp.dump_groups_yaml(groups)
        doc = yaml.safe_load(text)
        parsed, errors = groups_schema.parse_groups(doc)
        self.assertEqual(errors, [])
        self.assertEqual(parsed["Checkout"]["floor"], {"SEC", "DAT"})
        self.assertEqual(parsed["Checkout"]["tests"], ["tests/checkout/**"])

    def test_dump_handles_leading_wildcard_globs(self):
        """Regression: leading-* globs must round-trip without ScannerError."""
        import groups_schema
        groups = {"Auth": {"match": ["**/auth/**", "**/login/**"],
                           "tests": [],
                           "panels": ["SEC"]}}
        text = sp.dump_groups_yaml(groups)
        # Must not raise ScannerError on leading '*'
        doc = yaml.safe_load(text)
        # Must parse successfully
        parsed, errors = groups_schema.parse_groups(doc)
        self.assertEqual(errors, [])
        # Leading-** globs must be preserved verbatim
        self.assertIn("**/auth/**", parsed["Auth"]["match"])
        self.assertIn("**/login/**", parsed["Auth"]["match"])

    def test_merge_does_not_mutate_committed(self):
        """Regression: merged lists must be independent of committed lists."""
        committed = {"Auth": {"match": ["src/auth/**"], "tests": [],
                              "panels": ["SEC"]}}
        # Keep a reference to verify it's not mutated
        committed_panels_id = id(committed["Auth"]["panels"])
        merged, _ = sp.merge_additive(committed, {}, {})
        # Mutate merged
        merged["Auth"]["panels"].append("NEW")
        # Committed must be unchanged
        self.assertEqual(committed["Auth"]["panels"], ["SEC"])
        # And the list object must be different (deep copy)
        self.assertNotEqual(id(merged["Auth"]["panels"]), committed_panels_id)


if __name__ == "__main__":
    unittest.main()
