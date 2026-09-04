"""Catalog, glob semantics, group objects, and assign-by-catalog tests."""
import os
import tempfile
import unittest

from discovery_test_helpers import (orchestrator, touch, run_scan_with_err,
                                    run_scan_helper)


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

    def test_catastrophic_single_star_pattern_is_capped(self):
        # #run7 SEC-H4A: `a*a*...Z` compiles to `a[^/]*a[^/]*...Z` -- the (.*a)+
        # ReDoS shape, UNaffected by the **-collapse. An over-wildcarded pattern
        # (from an untrusted target groups.yml) is rejected to a never-matching
        # regex instead of hanging discovery before any dispatch.
        import time
        rx = orchestrator._glob_to_re("a*" * 30 + "Z")
        start = time.monotonic()
        self.assertIsNone(rx.match("a" * 40))            # never-match, no hang
        self.assertLess(time.monotonic() - start, 1.0)   # would be >5s unbounded
        # a normal glob with a handful of wildcards is unaffected
        self.assertTrue(
            orchestrator._glob_to_re("tests/fixtures/**").match("tests/fixtures/x.py"))

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
                          [f for n, fs in by_name.items() if n.startswith("Ungrouped_")
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
            # Pin the cap rather than relying on the default: this test is
            # about the CHUNKING behaviour (a match group over the cap splits
            # into `<name>_<i>`), not about whatever DEFAULT_MAX_PER_GROUP
            # happens to be. It silently stopped testing anything when the
            # default moved 15 -> 64 and 20 files no longer split.
            out, _ = run_scan_with_err(d, "--max-per-group", "15")
            names = [g["name"] for g in out["groups"]]
            self.assertEqual(names, ["pkg_1", "pkg_2"])
            self.assertEqual(sum(len(g["files"]) for g in out["groups"]), 20)

    def test_catalog_without_match_keys_fails_loud(self):
        # #run8 COD-B1A (owner decision 2026-08-26): a committed groups.yml that
        # DECLARES a group but uses an unknown key (`patterns:` instead of
        # `match:`) yields no usable match-group. This used to silently discard
        # the operator's committed catalog and fall back to whole-repo default
        # chunking; it now FAILS LOUD so a misconfigured/typo'd catalog can't be
        # ignored with only an easy-to-miss stderr line as evidence.
        with tempfile.TemporaryDirectory() as d:
            full = os.path.join(d, "src", "app.py")
            os.makedirs(os.path.dirname(full), exist_ok=True)
            open(full, "w").close()
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write("groups:\n  Products:\n    patterns: ['**/product*']\n")
            rc, out, err = run_scan_helper(d)
            self.assertEqual(rc, 1)
            self.assertIn("declares groups but none survived", err)
            self.assertEqual(out, {})   # no degraded whole-repo catalog emitted

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
        # The residual sink's chunks parent to the SINK, not to themselves.
        # They used to self-parent, back when `parent` was the only roll-up
        # axis and a chunk had nowhere else to point. Now that `chunk_of`
        # carries the chunk relationship, a self-parenting `Ungrouped_1` would
        # fold into a report node named after a chunk -- the machine's naming
        # leaking into the output, which is what `chunk_of` exists to stop.
        # Both axes point at `Ungrouped`; the unit self-parents from there.
        leftover_groups = [g for g in groups if g["name"].startswith("Ungrouped_")]
        self.assertEqual(len(leftover_groups), 1)
        self.assertEqual(leftover_groups[0]["parent"], orchestrator.UNGROUPED_SINK)
        self.assertEqual(leftover_groups[0]["chunk_of"], orchestrator.UNGROUPED_SINK)
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
        self.assertTrue(any(n.startswith("Ungrouped_") for n in names))  # weird.xyz -> residual
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


class TestChunkOfAxis(unittest.TestCase):
    """`chunk_of` is the machine roll-up axis: the review unit a group was
    split out of when it outgrew max_per_group. It exists so nothing has to
    recover that relationship by parsing `_<n>` off a name -- an inference that
    cannot tell a chunk of `API` from a committed group named `API_1` (#1480).

    It is deliberately independent of `parent`, the authored axis. A chunk of
    `Product:API` carries chunk_of="Product:API" and parent="Product", so the
    report folds in two hops (chunks -> unit -> authored parent) while
    groups_schema's "subgroups cannot nest" stays literally true."""

    def _by_name(self, groups):
        return {g["name"]: g for g in groups}

    def test_an_unsplit_group_is_its_own_whole(self):
        groups, _ = orchestrator.catalog_groups(
            ["src/a.py"], {"App": {"match": ["src/**"]}},
            max_per_group=50, security_mode="standard")
        self.assertEqual(self._by_name(groups)["App"]["chunk_of"], "App")

    def test_chunks_name_the_unit_they_came_from(self):
        groups, _ = orchestrator.catalog_groups(
            ["src/f%02d.py" % i for i in range(10)],
            {"App": {"match": ["src/**"]}},
            max_per_group=4, security_mode="standard")
        chunks = [g for g in groups if g["name"].startswith("App_")]
        self.assertEqual(len(chunks), 3)
        self.assertEqual({g["chunk_of"] for g in chunks}, {"App"})
        # ...and `App` itself is never emitted -- it is a fold target, not a cell.
        self.assertNotIn("App", {g["name"] for g in groups})

    def test_the_two_axes_stay_independent_under_a_parent(self):
        # The case the field exists for: chunking must not dissolve the
        # authored review unit. Both axes are needed to place a chunk.
        catalog = {"Product:API": {"match": ["app/api/**"], "parent": "Product"}}
        groups, _ = orchestrator.catalog_groups(
            ["app/api/f%02d.py" % i for i in range(10)], catalog,
            max_per_group=4, security_mode="standard")
        for g in groups:
            self.assertEqual(g["chunk_of"], "Product:API")   # machine axis
            self.assertEqual(g["parent"], "Product")         # authored axis

    def test_residual_sink_folds_to_itself_on_both_axes(self):
        # A self-parenting sink CHUNK would make `Ungrouped_1` a report node,
        # which is the chunk name leaking into the output all over again.
        groups, _ = orchestrator.catalog_groups(
            ["a.xyz", "b.xyz"], {}, max_per_group=1, security_mode="standard")
        sink = [g for g in groups if g["name"].startswith("Ungrouped_")]
        self.assertEqual(len(sink), 2)
        for g in sink:
            self.assertEqual(g["chunk_of"], orchestrator.UNGROUPED_SINK)
            self.assertEqual(g["parent"], orchestrator.UNGROUPED_SINK)

    def test_both_axes_terminate(self):
        # Every group's fold target is either itself or a name that is not a
        # group, so neither walk can cycle.
        files = ["src/f%02d.py" % i for i in range(10)] + ["README.md", "odd.xyz"]
        groups, _ = orchestrator.catalog_groups(
            files, {"App": {"match": ["src/**"]}},
            max_per_group=4, security_mode="standard")
        names = {g["name"] for g in groups}
        for g in groups:
            for axis in ("chunk_of", "parent"):
                target = g[axis]
                self.assertTrue(target == g["name"] or target not in names,
                                "%s.%s -> %s is a second hop through a real "
                                "group" % (g["name"], axis, target))

    def test_the_fold_reconstructs_every_file_exactly_once(self):
        files = ["app/api/f%03d.py" % i for i in range(150)]
        catalog = {"Product:API": {"match": ["app/api/**"], "parent": "Product"}}
        groups, _ = orchestrator.catalog_groups(
            files, catalog, max_per_group=32, security_mode="standard")
        folded = []
        for g in groups:
            if g["chunk_of"] == "Product:API":
                folded.extend(g["files"])
        self.assertEqual(sorted(folded), sorted(files))
        self.assertEqual(len(folded), len(set(folded)))   # chunks are disjoint


class TestGroupNameUniqueness(unittest.TestCase):
    """One group name means one findings-<group>-<domain>.json. Two groups
    sharing a name means one silently overwrites the other's cell, so the
    emitted set is checked before it is returned. groups_schema rejects the
    collisions visible in a committed catalog; this is the backstop for the
    ones that only appear once chunking has run."""

    def test_emitted_groups_have_unique_names(self):
        # The real path: a catalog large enough to chunk, plus Commons and a
        # residual sink, must never mint the same name twice.
        catalog = {"App": {"match": ["src/**"]}}
        files = ["src/d%d/f%03d.py" % (i // 10, i) for i in range(60)]
        files += ["README.md", "Dockerfile", "weird.xyz"]
        groups, _residual = orchestrator.catalog_groups(
            files, catalog, max_per_group=16, security_mode="standard")
        names = [g["name"] for g in groups]
        self.assertGreater(len(names), 4, "expected chunking to have happened")
        self.assertEqual(len(names), len(set(names)))

    def test_a_duplicate_name_raises_instead_of_clobbering(self):
        with self.assertRaises(ValueError) as ctx:
            orchestrator._assert_unique_names(
                [{"name": "Docs"}, {"name": "App_1"}, {"name": "Docs"}])
        msg = str(ctx.exception)
        self.assertIn("Docs", msg)
        self.assertNotIn("App_1", msg)   # names the offender, not the innocent

    def test_unique_names_pass_through(self):
        self.assertIsNone(orchestrator._assert_unique_names(
            [{"name": "A"}, {"name": "A_1"}, {"name": "B"}]))


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
