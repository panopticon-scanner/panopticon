"""Pure helpers behind scoped `tests:` matching and the Tests sweep (5.2 spec §4)."""
import os
import unittest

import yaml
from conftest import SKILL_ROOT

import scripts.tests_axis as ta


class TestTokens(unittest.TestCase):
    def test_splits_separators_and_camel_case(self):
        self.assertEqual(ta.tokens("RateLimiting"), ["rate", "limiting"])
        self.assertEqual(ta.tokens("rate_limiting"), ["rate", "limiting"])
        self.assertEqual(ta.tokens("test_discovery_catalog"), ["test", "discovery", "catalog"])
        self.assertEqual(ta.tokens("checkout.spec"), ["checkout", "spec"])
        self.assertEqual(ta.tokens("HTTPServer"), ["http", "server"])
        self.assertEqual(ta.tokens("APIs"), ["apis"], "acronym plural is one token")
        self.assertEqual(ta.tokens("Identity & Access"), ["identity", "access"])
        self.assertEqual(ta.tokens("x0x_report"), ["x0x", "report"])
        self.assertEqual(ta.tokens("__tests__"), ["tests"])
        self.assertEqual(ta.tokens(""), [])

    def test_name_keys_fold_plurals_and_dedupe(self):
        keys = ta.name_keys("Auth", ["Authentication", "auth", "Identity & Access"])
        self.assertEqual(keys, [("auth",), ("authentication",), ("identity", "access")])
        self.assertEqual(ta.name_keys("ToolAdapters"), [("tool", "adapter")])
        self.assertEqual(ta.name_keys("APIs"), [("api",)])
        self.assertEqual(ta.name_keys("SMS"), [("sms",)], "3-letter tokens are not singularized")

    def test_group_labels_split_subgroup_ids(self):
        self.assertEqual(ta.group_labels("Auth"), ["Auth"])
        self.assertEqual(ta.group_labels("Auth:API"), ["Auth", "API"])

    def test_stem_tokens_strip_test_affixes(self):
        self.assertEqual(ta.stem_tokens("tests/test_driver.py"), ["driver"])
        self.assertEqual(ta.stem_tokens("e2e/checkout.spec.ts"), ["checkout"])
        self.assertEqual(ta.stem_tokens("internal/auth/server_test.go"), ["server"])
        self.assertEqual(ta.stem_tokens("src/AuthServiceTests.cs"), ["auth", "service"])
        self.assertEqual(ta.stem_tokens("spec/models/user_spec.rb"), ["user"])
        self.assertEqual(ta.stem_tokens("tests/test_x0x_report.py"), ["x0x", "report"])


class TestPathCarriesName(unittest.TestCase):
    AUTH = ta.name_keys("Auth", ["Authentication"])

    def test_directory_segment(self):
        self.assertTrue(ta.path_carries_name("tests/auth/test_login.py", self.AUTH))
        self.assertTrue(ta.path_carries_name("tests/authentication/x_test.go", self.AUTH))
        self.assertTrue(ta.path_carries_name("tests/auth_handlers/x.py", self.AUTH), "run inside a segment")

    def test_filename_stem_after_affix_strip(self):
        self.assertTrue(ta.path_carries_name("e2e/auth.spec.ts", self.AUTH))
        self.assertTrue(ta.path_carries_name("tests/test_auth.py", self.AUTH))
        self.assertTrue(ta.path_carries_name("tests/test_auth_flow.py", self.AUTH))

    def test_segment_prefix_of_a_multi_token_key(self):
        keys = ta.name_keys("ToolAdapters")
        self.assertTrue(ta.path_carries_name("tests/tools/test_gosec.py", keys))
        self.assertFalse(ta.path_carries_name("tests/adapters/test_gosec.py", keys),
                         "a later token alone is not a prefix")

    def test_prefix_rule_is_confined_to_the_canonical_name(self):
        # R1 tightening: an alias's leading token must not claim by prefix --
        # `test_setup.py` is not Onboarding's just because SetupWizard is an
        # alias, and `test_data.py` is not ImportExport's via DataImport.
        onboarding = ta.name_keys("Onboarding", ["SetupWizard", "Signup"])
        self.assertFalse(ta.path_carries_name("tests/test_setup.py", onboarding))
        self.assertTrue(ta.path_carries_name("tests/test_setup_wizard.py", onboarding),
                        "the whole alias still carries")
        self.assertTrue(ta.path_carries_name("tests/signup/test_form.py", onboarding))

    def test_fused_camel_case_key_matches_its_flat_spelling(self):
        # `OAuth` tokenizes to o|auth but every path spells it `oauth`.
        for name, path in (("OAuth", "tests/oauth/test_flow.py"),
                           ("GraphQL", "tests/test_graphql.py"),
                           ("WebSocket", "tests/websockets/test_ping.py")):
            self.assertTrue(ta.path_carries_name(path, ta.name_keys(name)), name)
        self.assertFalse(ta.path_carries_name("tests/test_oauthlib_shim.py",
                                              ta.name_keys("OAuth")),
                         "fused key matches a whole token, not a substring")

    def test_no_carry(self):
        self.assertFalse(ta.path_carries_name("tests/checkout/test_cart.py", self.AUTH))
        self.assertFalse(ta.path_carries_name("tests/test_authorization.py", self.AUTH),
                         "tokens must match whole, not as substrings")


class TestGlobPrefixes(unittest.TestCase):
    def test_literal_detection(self):
        self.assertTrue(ta.is_literal_glob("tests/test_driver.py"))
        self.assertTrue(ta.is_literal_glob("!tests/test_driver.py"))
        self.assertFalse(ta.is_literal_glob("tests/**"))
        self.assertFalse(ta.is_literal_glob("**/*_test.go"))
        self.assertFalse(ta.is_literal_glob("tests/test_?.py"))
        self.assertTrue(ta.is_literal_glob("tests/[ab].py"),
                        "discovery._glob_to_re has no character classes: `[ab]` is literal")
        self.assertFalse(ta.is_literal_glob("conftest.py"),
                         "a slash-less basename matches at every depth")

    def test_literal_prefix(self):
        self.assertEqual(ta.literal_prefix("internal/authentication/**/*_test.go"), "internal/authentication")
        self.assertEqual(ta.literal_prefix("**/*_test.go"), "")
        self.assertEqual(ta.literal_prefix("src/auth*/**"), "src")
        self.assertEqual(ta.literal_prefix("tests/test_driver.py"), "tests/test_driver.py")
        self.assertEqual(ta.literal_prefix("!src/x/**"), "src/x")

    def test_distinguishing_prefixes_are_owned_by_one_top_level_group(self):
        catalog = {
            "Auth": {"match": ["internal/auth/**", "shared/**"]},
            "API": {"match": ["internal/api/**", "shared/**", "!shared/legacy/**"]},
            "API:Handlers": {"match": ["internal/api/handlers/**"], "parent": "API"},
            "Ops": {"match": ["**/*.sh"]},
        }
        got = ta.distinguishing_prefixes(catalog)
        self.assertEqual(got["Auth"], ["internal/auth"])
        self.assertEqual(got["API"], ["internal/api", "internal/api/handlers"],
                         "subgroup prefixes roll up to the top-level owner")
        self.assertEqual(got["Ops"], [], "no literal prefix, nothing distinguishing")
        self.assertNotIn("shared", got["Auth"] + got["API"], "shared prefix belongs to nobody")

    def test_scope_ok(self):
        keys = ta.name_keys("Auth")
        prefixes = ["internal/auth"]
        self.assertTrue(ta.scope_ok("internal/auth/x_test.go", keys, prefixes))
        self.assertTrue(ta.scope_ok("tests/auth/x_test.go", keys, prefixes))
        self.assertFalse(ta.scope_ok("internal/api/x_test.go", keys, prefixes))
        self.assertFalse(ta.scope_ok("internal/authz/x_test.go", keys, prefixes),
                         "prefix match is segment-wise, not string-wise")


class TestAffinity(unittest.TestCase):
    def test_shared_dir_depth(self):
        self.assertEqual(ta.shared_dir_depth("crates/core/tests/x.rs", "crates/core"), 2)
        self.assertEqual(ta.shared_dir_depth("crates/core/tests/x.rs", "crates/search"), 1)
        self.assertEqual(ta.shared_dir_depth("tests/x.rs", "crates/core"), 0)
        self.assertEqual(ta.shared_dir_depth("crates/core/x.rs", "crates/core/tests"), 2)

    def test_attach_by_affinity_longest_prefix_wins(self):
        homes = {"Core": ["crates/core"], "Search": ["crates/searcher", "crates/search"]}
        attached, unattached = ta.attach_by_affinity(
            ["crates/core/tests/a.rs", "crates/searcher/tests/b.rs", "tests/c.rs", "crates/x.rs"],
            homes)
        self.assertEqual(attached, {"Core": ["crates/core/tests/a.rs"],
                                    "Search": ["crates/searcher/tests/b.rs"]})
        self.assertEqual(unattached, ["crates/x.rs", "tests/c.rs"],
                         "depth 1 never attaches (a shared top-level dir says nothing); "
                         "zero depth never does")

    def test_depth_one_does_not_attach_even_without_a_tie(self):
        attached, unattached = ta.attach_by_affinity(["crates/x.rs"], {"Core": ["crates/core"]})
        self.assertEqual(attached, {})
        self.assertEqual(unattached, ["crates/x.rs"])

    def test_attach_tie_at_depth_over_one_goes_to_first_name(self):
        homes = {"B": ["a/b"], "A": ["a/b"]}
        attached, _ = ta.attach_by_affinity(["a/b/t.py"], homes)
        self.assertEqual(attached, {"A": ["a/b/t.py"]})


class TestTestsCatalogData(unittest.TestCase):
    def test_seed_globs_are_the_spec_list(self):
        with open(os.path.join(SKILL_ROOT, "data", "tests_catalog.yml"), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        self.assertRegex(str(doc.get("version")), r"^\d+\.\d+\.\d+$")
        match = doc["groups"]["Tests"]["match"]
        for glob in ["tests/**", "test/**", "spec/**", "e2e/**", "__tests__/**", "**/__tests__/**",
                     "integration/**", "cypress/**", "playwright/**", "load/**", "benchmarks/**"]:
            self.assertIn(glob, match)
        self.assertEqual(list(doc["groups"]), ["Tests"])


if __name__ == "__main__":
    unittest.main()
