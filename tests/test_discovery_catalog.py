"""Catalog, glob semantics, group objects, and assign-by-catalog tests."""
import os
import tempfile
import unittest

from discovery_test_helpers import orchestrator, touch, run_scan_with_err


class TestGlobSemantics(unittest.TestCase):
    """#499 match patterns are gitignore-flavored: '*' stays inside a path
    segment, '**' crosses segments, a pattern with no '/' matches the basename
    at any depth, and '!' re-excludes with last-match-wins."""

    def _m(self, path, patterns):
        return orchestrator.match_patterns(path, patterns)

    def test_star_does_not_cross_slash(self):
        self.assertTrue(self._m("skill/scripts/run.py", ["skill/scripts/*.py"]))
        self.assertFalse(self._m("skill/scripts/tools/x.py", ["skill/scripts/*.py"]))

    def test_double_star_crosses_slash(self):
        self.assertTrue(self._m("skill/scripts/tools/x.py", ["skill/scripts/**"]))
        self.assertTrue(self._m("a/b/c/d.py", ["a/**/d.py"]))

    def test_adjacent_double_stars_collapse_no_redos(self):
        # A repo-supplied groups.yml `match:` pattern with many adjacent `**/`
        # segments used to compile to sequential `(?:[^/]+/)*` quantifiers --
        # the catastrophic-backtracking ReDoS shape that could hang discovery.
        # Adjacent runs now fold to one; matching stays correct.
        rx = orchestrator._glob_to_re("**/" * 25 + "x")
        self.assertLessEqual(rx.pattern.count("(?:[^/]+/)*"), 1)
        self.assertTrue(rx.match("a/b/c/x"))
        self.assertFalse(rx.match("a/b/c/y"))
        self.assertTrue(self._m("a/b/x", ["**/" * 25 + "x"]))

    def test_single_star_chain_no_redos(self):
        rx = orchestrator._glob_to_re("*/" * 20 + "file.py")
        path = "a/" * 20 + "file.py"
        self.assertTrue(rx.match(path))
        self.assertFalse(rx.match("a/" * 19 + "file.py"))
        self.assertTrue(self._m(path, ["*/" * 20 + "file.py"]))

    def test_no_slash_matches_basename_at_any_depth(self):
        self.assertTrue(self._m("README.md", ["*.md"]))
        self.assertTrue(self._m("docs/deep/notes.md", ["*.md"]))
        self.assertFalse(self._m("docs/notes.md.bak", ["*.md"]))

    def test_negation_last_match_wins(self):
        pats = ["skill/scripts/**", "!skill/scripts/tools/**"]
        self.assertTrue(self._m("skill/scripts/run.py", pats))
        self.assertFalse(self._m("skill/scripts/tools/x.py", pats))
        # a later positive can re-include
        self.assertTrue(self._m(
            "skill/scripts/tools/base.py",
            pats + ["skill/scripts/tools/base.py"]))

    def test_question_mark_single_segment_char(self):
        self.assertTrue(self._m("a/v1.py", ["a/v?.py"]))
        self.assertFalse(self._m("a/v12.py", ["a/v?.py"]))


class TestCatalogMatchGroups(unittest.TestCase):
    """#499: intensional groups. A groups.yml with match: patterns gives files
    stable group identities; files matching no group are auto-chunked AND
    disclosed as ungrouped_files — coverage honesty at the discovery layer."""

    CATALOG = (
        "groups:\n"
        "  pipeline:\n"
        "    match: ['skill/scripts/*.py', '!skill/scripts/tools/**']\n"
        "  adapters:\n"
        "    match:\n"
        "      - 'skill/scripts/tools/**'\n"
        "  docs:\n"
        "    match: ['*.md']\n"
    )

    def _setup(self, d):
        for rel in ["skill/scripts/run.py", "skill/scripts/tools/pip.py",
                    "README.md", "docs/notes.md", "orphan/loner.py"]:
            touch(d, rel)
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w", encoding="utf-8") as fh:
            fh.write(self.CATALOG)

    def test_files_assigned_to_stable_named_groups(self):
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            out, err = run_scan_with_err(d)
            by_name = {g["name"]: g["files"] for g in out["groups"]}
            self.assertEqual(by_name["pipeline"], ["skill/scripts/run.py"])
            self.assertEqual(by_name["adapters"], ["skill/scripts/tools/pip.py"])
            self.assertEqual(sorted(by_name["docs"]), ["README.md", "docs/notes.md"])
            # leftover chunks keep the legacy ._N naming
            self.assertIn("orphan/loner.py",
                          [f for n, fs in by_name.items() if n.startswith("._")
                           for f in fs])
            self.assertEqual(out["ungrouped_files"], ["orphan/loner.py"])
            self.assertEqual(out["counts"]["ungrouped"], 1)
            self.assertIn("ungrouped", err)  # loud, not silent

    def test_first_matching_group_wins(self):
        # docs also glob-matches nothing else here, but a file matching two
        # groups must land in the FIRST (catalog order), exactly once.
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            out, _ = run_scan_with_err(d)
            all_files = [f for g in out["groups"] for f in g["files"]]
            self.assertEqual(len(all_files), len(set(all_files)))

    def test_oversize_match_group_chunks_with_suffixes(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(20):
                full = os.path.join(d, "pkg", "m%02d.py" % i)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                open(full, "w").close()
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write("groups:\n  pkg:\n    match: ['pkg/**']\n")
            out, _ = run_scan_with_err(d)
            names = [g["name"] for g in out["groups"]]
            self.assertEqual(names, ["pkg_1", "pkg_2"])
            self.assertEqual(sum(len(g["files"]) for g in out["groups"]), 20)

    def test_catalog_without_match_keys_keeps_legacy_chunking(self):
        with tempfile.TemporaryDirectory() as d:
            full = os.path.join(d, "src", "app.py")
            os.makedirs(os.path.dirname(full), exist_ok=True)
            open(full, "w").close()
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write("groups:\n  Products:\n    patterns: ['**/product*']\n")
            out, _ = run_scan_with_err(d)
            self.assertTrue(all(g["name"].startswith("._") for g in out["groups"]))
            self.assertNotIn("ungrouped_files", out)

    def test_exclude_paths_pruned_before_grouping_and_disclosed(self):
        # Task 4 (#1136): a committed top-level `exclude_paths:` glob prunes
        # matching files BEFORE catalog_groups/assign_by_catalog runs, so they
        # land in NEITHER a named group NOR the ._N leftover chunk -- and the
        # prune is disclosed (globs + count), never silently dropped.
        # (Uses paths NOT already pruned by the unrelated fixture-dir heuristic
        # -- docs/secret/** would otherwise match the `docs` group's `*.md`,
        # vendor/** would otherwise fall to a ._N leftover -- to prove this is
        # exclude_paths doing the work, not #434's fixture pruning.)
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            touch(d, "docs/secret/leak.md")
            touch(d, "vendor/dep.py")
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w", encoding="utf-8") as fh:
                fh.write(self.CATALOG + "exclude_paths: ['docs/secret/**', 'vendor/**']\n")
            out, _err = run_scan_with_err(d)
            all_files = [f for g in out["groups"] for f in g["files"]]
            self.assertNotIn("docs/secret/leak.md", all_files)
            self.assertNotIn("vendor/dep.py", all_files)
            self.assertNotIn("docs/secret/leak.md", out.get("ungrouped_files", []))
            self.assertNotIn("vendor/dep.py", out.get("ungrouped_files", []))
            self.assertEqual(sorted(out["exclude_paths"]), ["docs/secret/**", "vendor/**"])
            self.assertEqual(out["excluded_count"], 2)

    def test_exclude_paths_absent_is_zero_behavior_change(self):
        # Back-compat: no `exclude_paths:` key -> no disclosure fields, and
        # the previously-covered "orphan" leftover behavior is untouched.
        with tempfile.TemporaryDirectory() as d:
            self._setup(d)
            out, _err = run_scan_with_err(d)
            self.assertNotIn("exclude_paths", out)
            self.assertNotIn("excluded_count", out)
            self.assertEqual(out["ungrouped_files"], ["orphan/loner.py"])


class TestGroupObjParent(unittest.TestCase):
    """Task 7: every group `discovery` emits carries a `parent` field, so
    `groups.json` records it for Task 6's synthesize roll-up. Back-compat:
    a leaf/leftover group self-parents (parent == name)."""

    def test_group_obj_defaults_to_self_parent(self):
        g = orchestrator._group_obj("leaf", ["a.py"], "standard")
        self.assertEqual(g["parent"], "leaf")

    def test_group_obj_uses_explicit_parent(self):
        g = orchestrator._group_obj("UI:Admin", ["a.py"], "standard", parent="UI")
        self.assertEqual(g["parent"], "UI")

    def test_catalog_groups_subgroup_carries_parent(self):
        # Mimics _matrix_catalog's parse_groups-shaped output for a
        # `UI: {Admin: {match: [...]}}` subgroup, alongside a flat leaf.
        catalog = {
            "UI:Admin": {"match": ["ui/admin/**"], "tests": [], "floor": set(),
                         "exclude": set(), "parent": "UI"},
            "docs": {"match": ["*.md"], "tests": [], "floor": set(),
                    "exclude": set(), "parent": "docs"},
        }
        files = ["ui/admin/panel.py", "README.md", "orphan.py"]
        groups, leftovers = orchestrator.catalog_groups(files, catalog, 15, "standard")
        by_name = {g["name"]: g for g in groups}
        self.assertEqual(by_name["UI:Admin"]["parent"], "UI")
        # leaf group self-parents
        self.assertEqual(by_name["docs"]["parent"], "docs")
        # leftover ._N chunk self-parents
        leftover_groups = [g for g in groups if g["name"].startswith("._")]
        self.assertEqual(len(leftover_groups), 1)
        self.assertEqual(leftover_groups[0]["parent"], leftover_groups[0]["name"])
        self.assertEqual(leftovers, ["orphan.py"])

    def test_catalog_groups_oversize_subgroup_chunks_keep_parent(self):
        catalog = {
            "UI:Admin": {"match": ["ui/admin/**"], "tests": [], "floor": set(),
                         "exclude": set(), "parent": "UI"},
        }
        files = ["ui/admin/m%02d.py" % i for i in range(20)]
        groups, _leftovers = orchestrator.catalog_groups(files, catalog, 15, "standard")
        names = sorted(g["name"] for g in groups)
        self.assertEqual(names, ["UI:Admin_1", "UI:Admin_2"])
        self.assertTrue(all(g["parent"] == "UI" for g in groups))


class TestCommonsCatalog(unittest.TestCase):
    """Task 5 (#499): a curated Commons vocabulary (Docs/CI/Build/Config/Deps)
    names committed-unmatched leftover files before the true residual falls
    to `._N`. Committed groups always win -- Commons only ever sees
    leftovers."""

    def test_commons_names_leftovers_before_dot_n(self):
        catalog = {"App": {"match": ["src/**"]}}
        groups, leftovers = orchestrator.catalog_groups(
            ["src/app.py", "README.md", "Dockerfile", "weird.xyz"],
            catalog, max_per_group=50, security_mode="standard")
        names = {g["name"] for g in groups}
        self.assertIn("Docs", names)   # README.md -> Docs
        self.assertIn("Build", names)  # Dockerfile -> Build
        self.assertTrue(any(n.startswith("._") for n in names))  # weird.xyz -> residual
        self.assertIn("src/app.py",
                       next(g["files"] for g in groups if g["name"] == "App"))
        # weird.xyz is the true residual -- disclosed, not silently absorbed.
        self.assertEqual(leftovers, ["weird.xyz"])

    def test_committed_group_wins_over_commons(self):
        # A committed `src/**` group claims src/app.py -- Commons never sees it.
        catalog = {"App": {"match": ["src/**"]}}
        groups, _leftovers = orchestrator.catalog_groups(
            ["src/app.py"], catalog, max_per_group=50, security_mode="standard")
        names = {g["name"] for g in groups}
        self.assertEqual(names, {"App"})

    def test_commons_group_self_parents(self):
        groups, _leftovers = orchestrator.catalog_groups(
            ["README.md"], {}, max_per_group=50, security_mode="standard")
        by_name = {g["name"]: g for g in groups}
        self.assertEqual(by_name["Docs"]["parent"], "Docs")

    def test_commons_never_collides_with_committed_group_name(self):
        # A committed group named `Docs` (a Commons category name a user may
        # plausibly author) must NOT be re-emitted by the Commons pass: two
        # groups named `Docs` would write to the SAME findings-Docs-<domain>.json
        # (silent clobber) and produce a duplicate report node. Committed wins;
        # the leftover README falls to the committed `Docs` group's `match`, and
        # Commons is suppressed for that name entirely -> exactly one `Docs`.
        catalog = {"Docs": {"match": ["docs/**", "README.md"]}}
        groups, _leftovers = orchestrator.catalog_groups(
            ["docs/guide.md", "README.md"],
            catalog, max_per_group=50, security_mode="standard")
        docs_groups = [g for g in groups if g["name"] == "Docs"]
        self.assertEqual(len(docs_groups), 1)              # no duplicate node
        self.assertEqual(sorted(docs_groups[0]["files"]),
                         ["README.md", "docs/guide.md"])   # committed group owns both
        self.assertEqual(docs_groups[0]["parent"], "Docs")  # committed leaf, not Commons


class TestAssignByCatalog(unittest.TestCase):
    """Direct coverage for assign_by_catalog's gitignore-style semantics."""

    def test_negation_and_last_match_wins_inside_group(self):
        # A broad claim followed by a negation should exclude the negated path,
        # and a later re-claim should override the negation.
        catalog = {
            "Scripts": {
                "match": [
                    "skill/scripts/**",
                    "!skill/scripts/tools/**",
                    "skill/scripts/tools/pip.py",
                ]
            }
        }
        assigned, leftovers = orchestrator.assign_by_catalog(
            ["skill/scripts/run.py", "skill/scripts/tools/pip.py",
             "skill/scripts/tools/other.py"], catalog)
        self.assertEqual(assigned, {"Scripts": [
            "skill/scripts/run.py",
            "skill/scripts/tools/pip.py",
        ]})
        self.assertEqual(leftovers, ["skill/scripts/tools/other.py"])

    def test_first_matching_group_wins_across_groups(self):
        catalog = {
            "First": {"match": ["src/**"]},
            "Second": {"match": ["src/app.py"]},
        }
        assigned, leftovers = orchestrator.assign_by_catalog(["src/app.py"], catalog)
        self.assertEqual(assigned, {"First": ["src/app.py"]})
        self.assertEqual(leftovers, [])

    def test_tests_patterns_are_evaluated_with_match_patterns(self):
        catalog = {"Core": {"match": ["src/core/**"], "tests": ["!src/core/old/**"]}}
        assigned, leftovers = orchestrator.assign_by_catalog(
            ["src/core/new.py", "src/core/old/legacy.py"], catalog)
        self.assertEqual(assigned, {"Core": ["src/core/new.py"]})
        self.assertEqual(leftovers, ["src/core/old/legacy.py"])
