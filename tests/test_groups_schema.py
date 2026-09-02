# tests/test_groups_schema.py
import unittest

import scripts.groups_schema as gs


class TestGroupsSchema(unittest.TestCase):
    def test_parses_full_group(self):
        doc = {"groups": {"Checkout": {
            "match": ["src/checkout/**"], "tests": ["tests/checkout/**"],
            "panels": ["SEC", "DAT", "ACC"], "exclude": ["OPS"]}}}
        groups, errors = gs.parse_groups(doc)
        self.assertEqual(errors, [])
        g = groups["Checkout"]
        self.assertEqual(g["match"], ["src/checkout/**"])
        self.assertEqual(g["tests"], ["tests/checkout/**"])
        self.assertEqual(g["floor"], {"SEC", "DAT", "ACC"})
        self.assertEqual(g["exclude"], {"OPS"})

    def test_defaults_missing_optionals(self):
        groups, errors = gs.parse_groups({"groups": {"G": {"match": ["a/**"]}}})
        self.assertEqual(errors, [])
        self.assertEqual(groups["G"]["tests"], [])
        self.assertEqual(groups["G"]["floor"], set())
        self.assertEqual(groups["G"]["exclude"], set())

    def test_parse_groups_accepts_legacy_list_form(self):
        # #run7 ARC-D2B: a list-valued `groups:` must normalize to a catalog, not
        # silently become {} -- which dropped every committed group to Commons/._N
        # on the --repo-scan reader (_matrix_catalog) path.
        doc = {"groups": [
            {"name": "Auth", "match": ["src/auth/**"], "panels": ["SEC"]},
            {"name": "Api", "match": ["src/api/**"]},
            {"name": None, "match": ["x"]},          # nameless entry ignored, no crash
        ]}
        groups, errors = gs.parse_groups(doc)
        self.assertEqual(errors, [])
        self.assertEqual(set(groups), {"Auth", "Api"})
        self.assertEqual(groups["Auth"]["match"], ["src/auth/**"])

    def test_unknown_domain_is_error(self):
        doc = {"groups": {"G": {"match": ["a/**"], "panels": ["ZZZ"]}}}
        _g, errors = gs.parse_groups(doc)
        self.assertTrue(any("ZZZ" in e and "domain" in e for e in errors))

    def test_floor_and_exclude_overlap_is_error(self):
        doc = {"groups": {"G": {"match": ["a/**"], "panels": ["SEC"], "exclude": ["SEC"]}}}
        _g, errors = gs.parse_groups(doc)
        self.assertTrue(any("SEC" in e and "both floor and exclude" in e for e in errors))

    def test_empty_match_is_error(self):
        _g, errors = gs.parse_groups({"groups": {"G": {"match": []}}})
        self.assertTrue(any("match" in e for e in errors))

    def test_scalar_match_does_not_char_explode(self):
        groups, errors = gs.parse_groups({"groups": {"G": {"match": "src/checkout/**"}}})
        self.assertTrue(any("match" in e for e in errors))
        self.assertEqual(groups["G"]["match"], [])   # not ['s','r','c', ...]

    def test_non_list_panels_is_error_not_crash(self):
        groups, errors = gs.parse_groups({"groups": {"G": {"match": ["a/**"], "panels": 5}}})
        self.assertTrue(any("panels" in e and "list" in e for e in errors))
        self.assertEqual(groups["G"]["floor"], set())

    def test_non_list_tests_is_error(self):
        groups, errors = gs.parse_groups({"groups": {"G": {"match": ["a/**"], "tests": "tests/x"}}})
        self.assertTrue(any("tests" in e and "list" in e for e in errors))
        self.assertEqual(groups["G"]["tests"], [])

    def test_non_dict_group_value_is_error_not_crash(self):
        groups, errors = gs.parse_groups({"groups": {"G": "src/checkout/**"}})
        self.assertTrue(any("mapping" in e for e in errors))
        self.assertEqual(groups["G"]["match"], [])   # normalized to all-defaults, no raise

    def test_valid_group_names_accepted(self):
        for name in ("Checkout", "skill_1", "API", "UI", "Platform", "a.b-c"):
            groups, errors = gs.parse_groups({"groups": {name: {"match": ["a/**"]}}})
            self.assertIn(name, groups, name)
            self.assertFalse(any("invalid" in e for e in errors), (name, errors))

    def test_path_traversal_group_name_rejected(self):
        # #5.0-02: a name that would escape .panopticon in an artifact filename.
        for bad in ("../../etc/passwd", "a/b", "..", "a/../b", "a\\b"):
            groups, errors = gs.parse_groups({"groups": {bad: {"match": ["a/**"]}}})
            self.assertNotIn(bad, groups, bad)
            self.assertTrue(any("invalid" in e for e in errors), bad)

    def test_injection_group_name_rejected(self):
        # #5.0-02: control chars / newlines would inject into the trusted prompt;
        # leading dot / over-long are also rejected.
        for bad in ("a\nInjected: some dummy text", "a\x00b", ".hidden", "a" * 100):
            groups, errors = gs.parse_groups({"groups": {bad: {"match": ["a/**"]}}})
            self.assertNotIn(bad, groups, repr(bad))
            self.assertTrue(any("invalid" in e for e in errors), repr(bad))


    def test_non_string_match_element_is_error(self):
        groups, errors = gs.parse_groups({"groups": {"G": {"match": ["a/**", 123, ""]}}})
        self.assertTrue(any("match entries must be non-empty strings" in e for e in errors))
        self.assertEqual(groups["G"]["match"], ["a/**"])

    def test_non_string_tests_element_is_error(self):
        groups, errors = gs.parse_groups({"groups": {"G": {"match": ["a/**"], "tests": ["t/**", None, "   "]}}})
        self.assertTrue(any("tests entries must be non-empty strings" in e for e in errors))
        self.assertEqual(groups["G"]["tests"], ["t/**"])


def test_leaf_is_self_parent():
    g, errs = gs.parse_groups({"groups": {"Auth": {"match": ["src/auth/**"], "panels": ["SEC"]}}})
    assert errs == []
    assert g["Auth"]["parent"] == "Auth"
    assert g["Auth"]["match"] == ["src/auth/**"]
    assert g["Auth"]["floor"] == {"SEC"}

def test_parent_expands_to_flat_subgroup_ids():
    doc = {"groups": {"UI": {
        "Admin": {"match": ["src/ui/admin/**"], "exclude": ["DAT"]},
        "Components": {"match": ["src/ui/components/**"]}}}}
    g, errs = gs.parse_groups(doc)
    assert errs == []
    assert set(g) == {"UI:Admin", "UI:Components"}
    assert g["UI:Admin"]["parent"] == "UI"
    assert g["UI:Admin"]["exclude"] == {"DAT"}
    assert g["UI:Components"]["parent"] == "UI"

def test_empty_body_is_error():
    _g, errs = gs.parse_groups({"groups": {"X": {}}})
    assert any("X" in e for e in errs)

def test_subgroups_cannot_nest():
    doc = {"groups": {"UI": {"Admin": {"Deep": {"match": ["a"]}}}}}
    _g, errs = gs.parse_groups(doc)
    assert any("nest" in e.lower() for e in errs)

def test_colon_in_authored_name_rejected():
    _g, errs = gs.parse_groups({"groups": {"UI:Admin": {"match": ["a"]}}})
    assert any("invalid" in e.lower() for e in errs)

def test_flat_groups_yaml_backcompat():
    # existing leaf-only doc: same normalized shape + parent=self
    g, errs = gs.parse_groups({"groups": {"A": {"match": ["a/**"], "tests": ["t/**"]}}})
    assert errs == [] and g["A"]["parent"] == "A" and g["A"]["tests"] == ["t/**"]


class TestChunkNameCollision(unittest.TestCase):
    """A group over --max-per-group splits into `<id>_1`, `<id>_2`, ... and the
    unmatched residual lands in `Ungrouped_N`. Those names come from the same
    flat-id space an author writes in, so an authored name can be minted a
    second time by the chunker -- and two groups with one name share one
    findings-<group>-<domain>.json, so one cell's findings silently replace the
    other's. The collision is rejected where it is authored."""

    def _errs(self, doc):
        return gs.parse_groups(doc)[1]

    def test_authored_name_collides_with_a_siblings_chunk_names(self):
        errs = self._errs({"groups": {
            "API": {"match": ["app/api/**"]},
            "API_1": {"match": ["legacy/**"]}}})
        self.assertTrue(errs, "API_1 beside API is the chunker's own name")
        self.assertIn("API_1", errs[0])
        self.assertIn("silently clobber", errs[0])

    def test_collision_is_caught_inside_a_parent_too(self):
        # Chunk names are minted from the FLAT id, so the check must see
        # `Product:API` -> `Product:API_1`, not the bare subgroup name.
        errs = self._errs({"groups": {"Product": {
            "API": {"match": ["app/api/**"]},
            "API_1": {"match": ["legacy/**"]}}}})
        self.assertTrue(errs)
        self.assertIn("Product:API_1", errs[0])

    def test_the_residual_sink_name_is_reserved(self):
        for name in ("Ungrouped", "Ungrouped_2"):
            with self.subTest(name=name):
                errs = self._errs({"groups": {name: {"match": ["a/**"]}}})
                self.assertTrue(errs, "%s shares a findings file with the sink" % name)

    def test_sink_name_is_reserved_only_at_top_level(self):
        # `Product:Ungrouped` is namespaced -- it chunks to `Product:Ungrouped_1`
        # and can never collide with the bare `Ungrouped_1` sink.
        self.assertEqual(self._errs({"groups": {"Product": {
            "Ungrouped": {"match": ["a/**"]}}}}), [])

    def test_an_underscore_number_name_is_fine_without_the_sibling(self):
        # The name alone is not the problem; only the pair is. Rejecting every
        # `Foo_1` would break legitimate catalogs.
        self.assertEqual(self._errs({"groups": {"API_1": {"match": ["a/**"]}}}), [])

    def test_scoping_does_not_produce_a_false_positive(self):
        # Top-level `API_1` and subgroup `P:API` occupy different id spaces:
        # P:API chunks to `P:API_1`, which cannot collide with `API_1`.
        self.assertEqual(self._errs({"groups": {
            "API_1": {"match": ["a/**"]},
            "P": {"API": {"match": ["b/**"]}}}}), [])

    def test_sink_constant_matches_discoverys(self):
        # groups_schema stays import-pure, so the sink name is duplicated.
        # Pin them together rather than let them drift apart silently.
        import scripts.discovery as discovery
        self.assertEqual(gs.RESIDUAL_SINK, discovery.UNGROUPED_SINK)


def test_exclude_paths_valid_and_absent():
    assert gs.parse_exclude_paths({"exclude_paths": ["tests/fixtures/**", "vendor/**"]}) == (["tests/fixtures/**", "vendor/**"], [])
    assert gs.parse_exclude_paths({}) == ([], [])

def test_exclude_paths_invalid_types():
    globs, errs = gs.parse_exclude_paths({"exclude_paths": ["ok", 3, ""]})
    assert errs and globs == ["ok"]
    _g, errs2 = gs.parse_exclude_paths({"exclude_paths": "not-a-list"})
    assert errs2


if __name__ == "__main__":
    unittest.main()
