import os
import tempfile
import unittest
import yaml

import scripts.groups_schema as groups_schema  # noqa: E402
import scripts.setup_proposal as sp  # noqa: E402

DATA = os.path.join(os.path.dirname(__file__), "..", "skill", "data")
VOCAB = os.path.join(DATA, "capability_vocabulary.yml")
AFFINITY = os.path.join(DATA, "capability_affinity.yml")


class TestLoaders(unittest.TestCase):
    def test_vocabulary_loads_fixture(self):
        vocab, errors = sp.load_vocabulary(VOCAB)
        self.assertEqual(errors, [])
        self.assertIn("Checkout", vocab["names"])
        self.assertIn("**/checkout/**", vocab["hints"]["Checkout"])

    def test_vocabulary_is_the_r1_calibrated_roster(self):
        vocab, errs = sp.load_vocabulary(VOCAB)
        self.assertEqual(errs, [])
        names = set(vocab["names"])
        # 13 capabilities: the 12 seed + the ratified UI carve-out
        self.assertEqual(len(vocab["names"]), 13)
        self.assertIn("UI", names)
        self.assertNotIn("Integrations", names)  # ratified out (R-2)
        for seed in ["Auth", "Accounts", "Checkout", "Billing", "Catalog",
                     "Search", "Fulfillment", "Notifications", "Reporting",
                     "Admin", "API", "Platform"]:
            self.assertIn(seed, names)
        # loader-consumed hints still present (non-empty for a hinted label)
        self.assertTrue(vocab["hints"].get("Auth"))

    def test_vocabulary_carries_tier_and_definition_metadata(self):
        with open(VOCAB, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)  # read raw for the additive keys
        by_name = {c["name"]: c for c in doc["capabilities"]}
        self.assertEqual(by_name["Checkout"]["tier"], "vertical")
        self.assertEqual(by_name["Platform"]["tier"], "universal")
        self.assertEqual(by_name["UI"]["tier"], "universal")
        for c in doc["capabilities"]:  # every cap has definition + boundary + tier
            self.assertTrue(c.get("definition"))
            self.assertTrue(c.get("boundary"))
            self.assertIn(c.get("tier"), ("universal", "vertical"))

    def test_affinity_loads_fixture_and_validates_domains(self):
        vocab, _ = sp.load_vocabulary(VOCAB)
        affinity, errors = sp.load_affinity(AFFINITY, vocab)
        self.assertEqual(errors, [])
        self.assertEqual(affinity["Checkout"], ["SEC", "ACC"])
        # every fixture affinity key is a known vocabulary capability
        self.assertTrue(set(affinity).issubset(set(vocab["names"])))

    def test_affinity_is_the_r1_calibrated_table(self):
        vocab, _ = sp.load_vocabulary(VOCAB)
        affinity, errs = sp.load_affinity(AFFINITY, vocab)
        self.assertEqual(errs, [])
        self.assertEqual(len(affinity), 13)
        expected_floors = {
            "Auth": ["SEC"],
            "Accounts": ["SEC", "ACC"],
            "Checkout": ["SEC", "ACC"],
            "Billing": ["SEC"],
            "Catalog": [],
            "Search": [],
            "Fulfillment": [],
            "Notifications": ["OPS"],
            "Reporting": [],
            "Admin": ["SEC", "ACC", "OPS"],
            "API": ["SEC"],
            "Platform": ["OPS", "SEC"],
            "UI": [],
        }
        self.assertEqual(affinity, expected_floors)
        # no global-floor domains leaked into any row
        for dom in ("COD", "DAT", "TST", "ARC"):
            for label, floor in affinity.items():
                self.assertNotIn(dom, floor, f"{dom} leaked into {label}")

    def test_vocabulary_flags_duplicate_and_empty_names(self):
        doc = "capabilities:\n  - name: A\n  - name: A\n  - hints: [x]\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        _v, errors = sp.load_vocabulary(p)
        os.unlink(p)
        self.assertTrue(any("duplicate" in e for e in errors))
        self.assertTrue(any("name" in e for e in errors))

    def test_affinity_flags_unknown_domain_and_capability(self):
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
        doc = "capabilities"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        vocab, errors = sp.load_vocabulary(p)
        os.unlink(p)
        self.assertTrue(any("root must be a mapping" in e for e in errors))
        self.assertEqual(vocab["names"], [])

    def test_vocabulary_non_list_capabilities_produces_error(self):
        doc = "capabilities: {Auth: {hints: []}}\n"
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write(doc)
            p = fh.name
        vocab, errors = sp.load_vocabulary(p)
        os.unlink(p)
        self.assertTrue(any("capabilities must be a list" in e for e in errors))
        self.assertEqual(vocab["names"], [])

    def test_affinity_scalar_domains_produces_error_no_char_explosion(self):
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
        self.assertEqual(groups["Checkout"]["panels"], ["SEC", "ACC"])
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

    def test_capability_case_and_whitespace_canonicalized_keeps_floor(self):
        # #run7 COD-C2D: a known capability differing only by case or surrounding
        # whitespace must canonicalize to its vocab spelling and KEEP its
        # calibrated affinity floor, never be misrouted to scout-only (a silent
        # security downgrade).
        for variant in ("auth", "AUTH", "Auth ", "  Auth"):
            proposal = self._p([{"capability": variant, "match": ["src/auth/**"]}])
            groups, disc = sp.assemble(proposal, self.vocab, self.affinity)
            self.assertIsNotNone(groups, variant)
            self.assertIn("Auth", groups, variant)                 # canonical name
            self.assertEqual(groups["Auth"]["panels"], ["SEC"], variant)  # floor kept
            entry = disc["groups"][0]
            self.assertFalse(entry["custom"], variant)
            self.assertEqual(entry["floor_source"], "affinity", variant)
            self.assertEqual(entry["normalized"], {"from": variant, "to": "Auth"})

    def test_exact_case_capability_records_no_normalization(self):
        # #run7 COD-C2D: an already-canonical name carries normalized=None.
        proposal = self._p([{"capability": "Auth", "match": ["src/auth/**"]}])
        _g, disc = sp.assemble(proposal, self.vocab, self.affinity)
        self.assertIsNone(disc["groups"][0]["normalized"])

    def test_case_variants_of_same_capability_collide_into_one_group(self):
        # #run7 COD-C2D: two spellings of one vocab capability canonicalize to the
        # same name and merge (not two scout-only groups).
        proposal = self._p([
            {"capability": "Auth", "match": ["src/auth/**"]},
            {"capability": "auth", "match": ["src/oauth/**"]},
        ])
        groups, disc = sp.assemble(proposal, self.vocab, self.affinity)
        self.assertEqual(set(groups), {"Auth"})
        self.assertEqual(groups["Auth"]["match"], ["src/auth/**", "src/oauth/**"])
        self.assertTrue(disc["collisions"])

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


class TestValidateProposalCaps(unittest.TestCase):
    """#1107: an untrusted proposal is bounded before it reaches assemble()'s
    collision merge -- group count, per-group match/tests counts, entry length."""

    def _errs(self, groups):
        return sp.validate_proposal({"groups": groups})

    def test_too_many_groups_rejected(self):
        groups = [{"capability": "custom:g%d" % i, "match": ["a"]}
                  for i in range(sp._MAX_GROUPS + 1)]
        self.assertTrue(any("too many groups" in e for e in self._errs(groups)))

    def test_too_many_match_entries_rejected(self):
        g = {"capability": "custom:g",
             "match": ["m%d" % i for i in range(sp._MAX_GROUP_ENTRIES + 1)]}
        self.assertTrue(any("too many match entries" in e for e in self._errs([g])))

    def test_too_many_tests_entries_rejected(self):
        g = {"capability": "custom:g", "match": ["a"],
             "tests": ["t%d" % i for i in range(sp._MAX_GROUP_ENTRIES + 1)]}
        self.assertTrue(any("too many tests entries" in e for e in self._errs([g])))

    def test_overlong_entry_rejected(self):
        g = {"capability": "custom:g", "match": ["x" * (sp._MAX_ENTRY_LEN + 1)]}
        self.assertTrue(any("exceeds" in e for e in self._errs([g])))

    def test_within_caps_is_valid(self):
        g = {"capability": "custom:g", "match": ["src/**"], "tests": ["t/**"]}
        self.assertEqual(self._errs([g]), [])

    def test_non_integer_schema_version_rejected(self):
        # #run7 TST-A2D: the schema_version type guard (an untrusted-input branch)
        # had no coverage -- a non-int must be rejected.
        errs = sp.validate_proposal(
            {"schema_version": "1", "groups": [{"capability": "custom:g",
                                                "match": ["a"]}]})
        self.assertTrue(any("schema_version must be an integer" in e for e in errs))

    def test_integer_schema_version_accepted(self):
        # #run7 TST-A2D: a present, valid integer schema_version validates clean.
        errs = sp.validate_proposal(
            {"schema_version": 1, "groups": [{"capability": "custom:g",
                                              "match": ["a"]}]})
        self.assertEqual(errs, [])


if __name__ == "__main__":
    unittest.main()
