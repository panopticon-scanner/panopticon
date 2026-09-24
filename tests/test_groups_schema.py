# tests/test_groups_schema.py
import unittest
from unittest import mock

import pytest

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


def test_the_settings_parser_lives_in_config_schema_now():
    # #1681 Plan 2: one settings parser in the tree, and it is the one that
    # knows the trust classes.
    assert not hasattr(gs, "parse_settings")
    assert not hasattr(gs, "SETTINGS_INT_KEYS")


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

    def test_casefolded_authored_and_minted_names_collide(self):
        cases = [
            {"API": {"match": ["a"]}, "api": {"match": ["b"]}},
            {"API": {"match": ["a"]}, "api_1": {"match": ["b"]}},
            {"Product": {"API": {"match": ["a"]}},
             "product": {"api_1": {"match": ["b"]}}},
            {"ungrouped_1": {"match": ["a"]}},
        ]
        for groups in cases:
            with self.subTest(groups=groups):
                errs = self._errs({"groups": groups})
                self.assertTrue(errs)
                self.assertIn("rename", " ".join(errs).lower())

    def test_casefolded_chunk_names_remain_namespaced(self):
        self.assertEqual(self._errs({"groups": {
            "API_1": {"match": ["a"]},
            "Product": {"api": {"match": ["b"]}}}}), [])

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


def test_exclude_paths_rejects_negation():
    # #1740 re-review nit: `exclude_paths:` documents no `!` negation, and the
    # two consumers disagreed on it (the tool matcher honoured it, discovery
    # did not). A negated entry is an error and is dropped, so neither side
    # ever sees it.
    globs, errs = gs.parse_exclude_paths({"exclude_paths": ["tests/**", "!tests/critical/**"]})
    assert globs == ["tests/**"]
    assert any("negation" in e for e in errs), errs


if __name__ == "__main__":
    unittest.main()


class TestGlobsAreRefusedRatherThanMiscompiled(unittest.TestCase):
    """#1501: a glob the compiler cannot translate must not reach it. The
    failure it replaces is silent -- an empty group and an inflated
    `Ungrouped`, which is the signal we read as catalog coverage -- so the
    error has to name the fix, not just the fault.
    """

    def test_character_class_in_match_is_an_error(self):
        _groups, errors = gs.parse_groups(
            {"groups": {"Native": {"match": ["src/*.[ch]"]}}})
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("group Native: match glob 'src/*.[ch]'", errors[0])
        self.assertIn("'*.c' and '*.h'", errors[0])

    def test_character_class_in_tests_is_an_error(self):
        _groups, errors = gs.parse_groups(
            {"groups": {"G": {"match": ["src/**"], "tests": ["t/file[0-9].py"]}}})
        self.assertEqual([e for e in errors if "tests glob" in e], errors)
        self.assertEqual(len(errors), 1, errors)

    def test_a_subgroup_glob_is_checked_under_its_flat_id(self):
        _groups, errors = gs.parse_groups(
            {"groups": {"UI": {"Admin": {"match": ["ui/[ab]/**"]}}}})
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("group UI:Admin: match glob", errors[0])

    def test_exclude_paths_is_checked_too(self):
        globs, errors = gs.parse_exclude_paths({"exclude_paths": ["vendor/[0-9]*/**"]})
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("exclude_paths: entry glob", errors[0])
        # the valid-entry list is still returned, as for the other shape errors
        self.assertEqual(globs, ["vendor/[0-9]*/**"])

    def test_trailing_slash_is_accepted_now_that_it_compiles(self):
        _groups, errors = gs.parse_groups(
            {"groups": {"Docs": {"match": ["docs/", "/build/"],
                                 "tests": ["tests/"]}}})
        self.assertEqual(errors, [])

    def test_glob_defect_is_none_for_ordinary_globs(self):
        for glob in ("src/**", "*.md", "!vendor/**", "a/b/c.py", "doc?.md",
                     "**/vendor/**", "/README.md", "LICENSE*", "docs/"):
            with self.subTest(glob=glob):
                self.assertIsNone(gs.glob_defect(glob))


@pytest.mark.parametrize(("pattern", "path", "matches"), [
    ("src/*.py", "src/file.py", True),
    ("src/*.py", "nested/src/file.py", False),
    ("/file.py", "file.py", True),
    ("/file.py", "nested/file.py", False),
    ("*.py", "deep/nested/file.py", True),
    ("*.py", "deep/nested/file.py/child", False),
    ("src/*", "src/", True),
    ("src/*", "src/a/b", False),
    ("src/?", "src/a", True),
    ("src/?", "src/", False),
    ("src/?", "src//", False),
    ("src/**/file", "src/file", True),
    ("src/**/file", "src/a/b/file", True),
    ("src/**/file", "src//file", False),
    ("src/**/file", "src/a//file", False),
    ("src/**/file", "src/afile", False),
    ("src/**", "src/", True),
    ("src/**", "src//a/b", True),
    ("src/a**z", "src/a/b/z", True),
    ("src/a**/z", "src/az", True),
    ("src/a**/z", "src/a/z", False),
    ("src/a**/z", "src/ab/z", True),
    ("docs/", "docs", False),
    ("docs/", "docs/", True),
    ("docs/", "nested/docs/guide/file", True),
    ("src/docs/", "nested/src/docs/file", False),
    ("src/docs/", "src/docs/file", True),
    ("**/" * 25 + "x", "a/b/x", True),
    ("a***z", "a/b/z", True),
    ("file.[ch]", "file.c", False),
    ("file.[ch]", "file.[ch]", False),
    ("file.txt", "file.txt\n", False),
    ("file.txt", "line\nbreak/file.txt", True),
    ("src/*", "src/line\nbreak", True),
    ("src/?", "src/\n", True),
    ("src/**", "src/line\nbreak/deep/file", True),
    ("src/**/file", "src/line\nbreak/file", True),
    ("src/**/file", "src/line\nbreak/file\n", False),
    ("docs/", "docs/line\nbreak", True),
    ("src/line\nbreak", "src/line\nbreak", True),
    ("", "", True),
    ("*", "", True),
    ("**/x", "/x", False),
    ("x", "/x", True),
    ("x", "a//x", True),
    ("src/**/a?.py", "src/deep/ab.py", True),
    ("src/**/a?.py", "src/deep/a/b.py", False),
    ("/src/*.py", "nested/src/a.py", False),
    ("literal", "deep/literal", True),
    ("literal", "deep/notliteral", False),
    ("/literal", "deep/literal", False),
    ("literal", "literal\n", False),
    ("x?y", "x\ny", True),
    ("x?y", "x/y", False),
    ("/", "a/", True),
    ("/", "a", False),
    ("**/*?*", "a/b", True),
    ("**/*?*", "a/", False),
    ("a**/*/**/z", "a/b/c/z", True),
    ("a**/*/**/z", "a//b/z", False),
    ("**/?**/?", "ac/b", True),
    ("**/?**/?", "a/b", False),
    ("**/?**/?", "a//b", False),
    ("/docs/", "nested/docs/file", False),
    ("/docs/", "docs/file", True),
    ("?" * 256, "a" * 256, True),
    ("?" * 256, "a" * 255, False),
    ("a" * 230 + "?" * 25 + "/", "a" * 230 + "b" * 25 + "/deep", True),
    ("a" * 230 + "?" * 25 + "/", "a" * 230 + "b" * 24 + "/deep", False),
])
def test_bounded_glob_semantics(pattern, path, matches):
    assert bool(gs.glob_to_re(pattern).match(path)) is matches


def test_glob_matching_does_not_compile_a_regex():
    # Regex-shaped .pattern remains diagnostics only, including invalid globs.
    with mock.patch.object(gs.re, "compile", side_effect=AssertionError("regex matcher")):
        for pattern, path in [("src/**/x", "src/a/x"), ("*.py", "a/b.py")]:
            matcher = gs.glob_to_re(pattern)
            assert isinstance(matcher.pattern, str)
            assert matcher.match(path)
        assert gs.glob_to_re("[ab]").match("a") is None
        assert gs.glob_to_re("a*" * 21).match("a" * 21) is None
        assert gs.glob_to_re("a" * 257).match("a" * 257) is None


def test_bounded_glob_ordered_exclusion_and_negation():
    patterns = ["src/**", "!src/keep/**", "src/keep/generated/*"]
    assert gs.matched_glob("src/drop.py", patterns) == "src/**"
    assert gs.matched_glob("src/keep/a.py", patterns) is None
    assert gs.matched_glob("src/keep/generated/a.py", patterns) == patterns[-1]
    assert gs.matched_glob("src/keep/generated/deep/a.py", patterns) is None


def test_invalid_glob_warning_is_still_once_per_caller(capsys):
    with mock.patch.object(gs, "_warned_globs", set()):
        for _ in range(2):
            assert gs.glob_to_re("[ab]", "test-one").match("a") is None
        assert gs.glob_to_re("[ab]", "test-two").match("a") is None
    stderr = capsys.readouterr().err
    assert stderr.count("matches nothing") == 2
    assert "test-one" in stderr and "test-two" in stderr


def test_compiled_glob_cache_is_bounded_and_independent_of_caller():
    gs._compile_glob.cache_clear()
    first = gs.glob_to_re("src/**/a?.py", "one")
    second = gs.glob_to_re("src/**/a?.py", "two")
    assert first.match("src/deep/ab.py") and second.match("src/deep/ab.py")
    assert gs._compile_glob.cache_info().hits == 1
    for index in range(600):
        gs.glob_to_re(f"literal-{index}")
    info = gs._compile_glob.cache_info()
    assert info.currsize == info.maxsize == 512
    # Eviction cannot change results or diagnostic text on recompilation.
    rebuilt = gs.glob_to_re("src/**/a?.py")
    assert rebuilt.pattern == first.pattern
    assert rebuilt.match("src/deep/ab.py")
    assert rebuilt.match("nested/src/deep/ab.py") is None
    gs._compile_glob.cache_clear()


def test_over_complex_glob_warning_repeats_with_each_caller(capsys):
    for label in ("first", "first", "second"):
        for pattern in ("a*" * 21, "a" * 257):
            assert gs.glob_to_re(pattern, label).match("a") is None
    stderr = capsys.readouterr().err
    assert stderr.count("ignoring over-complex") == 6
    assert stderr.count("first:") == 4
    assert stderr.count("second:") == 2
