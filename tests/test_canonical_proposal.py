"""#3651 phase 2, option (b): a setup proposal is written one way, whatever order and spelling
the agent returned it in.

The rule the whole of it answers to: canonicalising changes how a proposal is WRITTEN and
never what it claims -- on the tree setup saw, and on every later one, because the config
setup writes is reused on every later commit. So each rule is tested twice over: on the
tree, and on the tree plus files that were not there when setup ran.
"""
import itertools
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import yaml

import scripts.discovery as discovery
import scripts.discovery_catalog as discovery_catalog
import scripts.groups_schema as groups_schema
import scripts.grouping_engine as grouping_engine
import scripts.matrix_identity as matrix_identity
import scripts.matrix_provenance as matrix_provenance
import scripts.setup_flow as setup_flow
import scripts.setup_proposal as sp
import scripts.tests_axis as tests_axis

FILES = ("src/app.py", "src/auth/login.py", "src/auth/token.py", "src/gen/models.py",
         "lib/util.py", "lib/net/http.py", "docs/guide.md", "docs/api/index.md",
         "pkg/docs/readme.md", "README", "tools/README", "a/b/c/d.py", "a/x.py")

# Paths chosen to tell every rewrite apart from its neighbour: nested and top-level, a
# basename that repeats at two depths, a directory name that repeats at two depths.
CORPUS = FILES + ("docs", "docs/", "src", "src/auth", "a/b", "a/b/c", "README.md",
                  "x/README", "auth/login.py", "src/auth/deep/er/f.py", "srcx/app.py",
                  "lib", "lib/util.pyc", "a/b/x.py", "", "/src/app.py", "./src/app.py",
                  "x/src.py", "x/srcmap/y.py", "src", "srcmap.py", "/", "//", "/src/x")

# Every path of one to three segments over a small alphabet, and every glob of one to three
# segments over another, each with and without a leading `/`, `//` and a trailing `/`.
# Small enough to try every pair; wide enough to hold every case a review has found.
PATHS = tuple("/".join(parts) for depth in (1, 2, 3)
              for parts in itertools.product(("a", "b", "ab", "x.py"), repeat=depth))
GLOBS = tuple(lead + "/".join(parts) + trail
              for depth in (1, 2, 3)
              for parts in itertools.product(("a", "b", "*", "**", "***", "a*", "a**", ""),
                                             repeat=depth)
              for lead in ("", "/", "//") for trail in ("", "/"))


def _matcher(glob):
    return groups_schema.glob_to_re(glob.lstrip("!"), "test")


def _matches(glob, paths=CORPUS):
    matcher = _matcher(glob)
    return {path for path in paths if matcher.match(path)}


class TestAGlobIsSpelledOneWay(unittest.TestCase):
    REWRITES = {
        # a trailing `/` on an anchored pattern is `/**`
        "src/auth/": "src/auth/**", "a/b/c/": "a/b/c/**", "/docs/": "docs/**",
        "src/**/": "src/**/**",
        # a run of `**/`, or of stars, is one
        "src/**/**/login.py": "src/**/login.py", "a/**/**/**/d.py": "a/**/d.py",
        "lib/***": "lib/**", "src/****/x": "src/**/x", "***": "**",
        # one leading `/` beside another `/` adds nothing
        "/src/app.py": "src/app.py", "/lib/**": "lib/**", "/a/**/d.py": "a/**/d.py",
        "/src/x": "src/x",
        # ...and they compose
        "/src/**/**/auth/": "src/**/auth/**",
        # A rewrite is all or nothing, so each of these pins a condition: a rule one step
        # looser would be refused by the proof, and leave the whole glob as written.
        "/lib/**/**": "lib/**/**",      # `**/**` is not folded to `**`
        "//x/": "//x/**",               # a doubled leading slash is not halved
        "a***/": "a**/",                # an unanchored trailing slash is not expanded
        "/a***": "/a**",                # a lone leading slash, the anchor, is not dropped
    }

    def test_each_rewrite_matches_exactly_what_the_original_did(self):
        for written, canonical in self.REWRITES.items():
            with self.subTest(written=written):
                self.assertEqual(canonical, sp.normalize_glob(written))
                self.assertEqual(_matches(written), _matches(canonical))
                self.assertEqual(_matches(written, PATHS), _matches(canonical, PATHS))
                self.assertEqual(_matcher(written).pattern, _matcher(canonical).pattern)
                self.assertEqual("!" + canonical, sp.normalize_glob("!" + written))
                self.assertEqual(canonical, sp.normalize_glob(canonical))      # a fixed point

    def test_what_cannot_be_proven_equivalent_is_left_as_written(self):
        # Each of these has a tempting "simpler" spelling that claims different paths.
        for written, tempting in (("docs/", "docs/**"),          # unanchored: any depth
                                  ("/README", "README"),         # the slash is the anchor
                                  ("./src/**", "src/**"),        # taken literally: nothing
                                  ("src/auth", "src/auth/**"),   # the path itself only
                                  ("README", "/README"),
                                  ("src**/**", "src**"),         # its only `/` is the anchor
                                  ("//src/x", "/src/x"),         # a literal leading slash
                                  ("//", "/**")):                # nothing, not everything
            with self.subTest(written=written):
                self.assertNotEqual(tempting, sp.normalize_glob(written))
                self.assertEqual(_matches(written), _matches(sp.normalize_glob(written)))
                self.assertNotEqual(_matches(written), _matches(tempting),
                                    "the corpus must tell these two apart")
        for untouched in ("docs/", "/README", "./src/**", "src/auth", "README", "src**/**",
                          "//src/x", "src/**", "*.py", "lib/*.py", "src/app.py", "**", "a/?/c",
                          "", "!", "lib/**/**", "**/**", "a/**/**x.py", "**/***/"):
            self.assertEqual(untouched, sp.normalize_glob(untouched))
        for not_text in (None, 3, ["src/"]):
            self.assertIs(not_text, sp.normalize_glob(not_text))

    def test_a_glob_the_compiler_refuses_is_never_touched(self):
        for defect in ("src/[abc]/", "/lib/[!a]/", "a/**/**/[x]"):
            with self.subTest(defect=defect):
                self.assertTrue(groups_schema.glob_defect(defect), "not a defect any more")
                self.assertEqual(defect, sp.normalize_glob(defect))

    def test_a_rewrite_is_made_only_when_both_spellings_fall_on_one_side_of_the_limits(self):
        # The compiler checks its limits BEFORE it drops a leading `/` or expands a trailing
        # one. So a pattern can match as written and not once respelled, and the reverse.
        long_dir = "d/" + "x" * 253 + "/"                    # 256: matches; 258 expanded
        self.assertEqual(256, len(long_dir))
        self.assertEqual(long_dir, sp.normalize_glob(long_dir))
        self.assertTrue(_matcher(long_dir).match("d/" + "x" * 253 + "/f"))
        self.assertFalse(_matcher(long_dir + "**").match("d/" + "x" * 253 + "/f"))
        over = "/lib/" + "x" * 252                           # 257: nothing; 256 once dropped
        self.assertEqual(257, len(over))
        self.assertEqual(over, sp.normalize_glob(over))
        self.assertFalse(_matcher(over).match(over[1:]))
        self.assertTrue(_matcher(over[1:]).match(over[1:]))
        starry = "s/" + "*a" * 19 + "/"                      # 19 stars: matches; 21 expanded
        self.assertEqual(starry, sp.normalize_glob(starry))
        too_starry = "/s/" + "*a" * 21                       # nothing either way: untouched
        self.assertEqual(too_starry, sp.normalize_glob(too_starry))
        # One under each limit still is rewritten.
        self.assertEqual("d/" + "x" * 251 + "/**", sp.normalize_glob("d/" + "x" * 251 + "/"))
        self.assertEqual("lib/" + "x" * 251, sp.normalize_glob("/lib/" + "x" * 251))

    def test_every_rewrite_in_a_space_of_globs_matches_what_the_original_did(self):
        # No table: every glob in the space, against every path in the space.
        rewritten = 0
        for written in GLOBS:
            canonical = sp.normalize_glob(written)
            self.assertEqual(canonical, sp.normalize_glob(canonical), written)   # a fixed point
            if canonical == written:
                continue
            rewritten += 1
            self.assertEqual(_matches(written, PATHS + CORPUS), _matches(canonical, PATHS + CORPUS),
                             "%r became %r" % (written, canonical))
            self.assertEqual(tests_axis.literal_prefix(written),
                             tests_axis.literal_prefix(canonical), written)
        self.assertGreater(rewritten, 300)                   # the space is not all fixed points

    def test_a_rewrite_the_compiler_reads_differently_is_refused_whatever_it_is(self):
        # The proof is run, not assumed: a wrong rule cannot get a rewrite through.
        for wrong in ("docs/**", "x", "src/app.py"):
            with mock.patch.object(sp, "_respell", side_effect=lambda pat, wrong=wrong: wrong):
                for written in ("docs/", "/README", "src/auth/", "lib/**"):
                    self.assertEqual(written, sp.normalize_glob(written), wrong)
        # ...and one it reads the same way does.
        with mock.patch.object(sp, "_respell", side_effect=lambda pat: "src/auth/**"):
            self.assertEqual("src/auth/**", sp.normalize_glob("src/auth/"))
        # A spelling that keeps the matcher and moves the group's home directory is refused.
        with mock.patch.object(sp.tests_axis, "literal_prefix", side_effect=len):
            self.assertEqual("src/auth/", sp.normalize_glob("src/auth/"))


class TestAGlobListIsWrittenOneWay(unittest.TestCase):
    def test_a_plain_union_is_sorted_and_de_duplicated(self):
        self.assertEqual(["lib/**", "src/**", "tools/**"],
                         sp.canonical_globs(["tools/**", "src/**", "lib/**", "src/**"]))
        # Two spellings of one glob are one glob.
        self.assertEqual(["src/auth/**"], sp.canonical_globs(["src/auth/", "/src/auth/**"]))
        self.assertEqual([], sp.canonical_globs(None))
        self.assertEqual([], sp.canonical_globs([]))
        # Unless the group is one the config already has: sorted, never respelled.
        self.assertEqual(["/src/auth/**", "src/auth/"],
                         sp.canonical_globs(["src/auth/", "/src/auth/**", "src/auth/"],
                                            respell=False))

    def test_a_list_with_a_negation_keeps_its_order_and_its_repeats(self):
        # Last match wins: these three lists claim three different sets of files.
        for written in (["src/**", "!src/gen/**"], ["!src/gen/**", "src/**"],
                        ["src/**", "!src/gen/**", "src/**"], ["z/**", "!z/a/**", "a/**"]):
            with self.subTest(written=written):
                self.assertEqual(written, sp.canonical_globs(written))
                self.assertEqual(written, sp.canonical_globs(written, tests=True))
        self.assertEqual({"src/app.py", "src/auth/login.py", "src/auth/token.py"},
                         self._claimed(["src/**", "!src/gen/**"]))
        self.assertEqual(self._claimed(["src/**"]), self._claimed(["!src/gen/**", "src/**"]))
        self.assertEqual(self._claimed(["src/**"]),
                         self._claimed(["src/**", "!src/gen/**", "src/**"]))
        # Each glob is still spelled canonically, in place.
        self.assertEqual(["src/**", "!src/gen/**"], sp.canonical_globs(["/src/**", "!src/gen/"]))

    def test_a_tests_list_is_never_respelled(self):
        # `pkg/src/` names one path outright; `pkg/src/**` is a wildcard, scoped to the group.
        self.assertTrue(tests_axis.is_literal_glob("pkg/src/"))
        self.assertFalse(tests_axis.is_literal_glob("pkg/src/**"))
        for written in (["pkg/src/"], ["/lib/x.py"], ["a/**/**/t.py"], ["!pkg/src/"]):
            with self.subTest(written=written):
                self.assertEqual(written, sp.canonical_globs(written, tests=True))
                self.assertNotEqual(written, sp.canonical_globs(written))    # a match list is

    def test_a_tests_list_is_sorted_only_when_its_globs_are_all_of_one_kind(self):
        # All literal: each credits its file outright, in any order.
        self.assertEqual(["lib/a.py", "lib/b.py"],
                         sp.canonical_globs(["lib/b.py", "lib/a.py", "lib/b.py"], tests=True))
        # All wildcards: each is scoped the same way, in any order.
        self.assertEqual(["a/*", "z/**"], sp.canonical_globs(["z/**", "a/*", "z/**"], tests=True))
        # One of each: the LAST to match decides how a file is credited. Kept as written.
        for written in (["lib/new.py", "lib/**"], ["lib/**", "lib/new.py"],
                        ["lib/**", "lib/new.py", "lib/**"], ["conftest.py", "t/unit/a.py"]):
            with self.subTest(written=written):
                self.assertEqual(written, sp.canonical_globs(written, tests=True))
        self.assertEqual([], sp.canonical_globs(None, tests=True))
        # The two orders really do credit differently: a literal outright, a wildcard only
        # inside the group's scope.
        outcomes = []
        for tests in (["lib/new.py", "lib/**"], ["lib/**", "lib/new.py"]):
            catalog = {"AuthZone": {"match": ["src/auth/**"], "tests": tests},
                       "Lib": {"match": ["lib/**"], "tests": []}}
            assigned, _left, _warn = discovery_catalog.assign_scoped(["lib/new.py"], catalog)
            outcomes.append(sorted(assigned))
        self.assertEqual([["Lib"], ["AuthZone"]], outcomes)

    def _claimed(self, globs):
        return {path for path in FILES if discovery_catalog.match_patterns(path, globs)}


def _group(match, tests=(), layers=()):
    return {"match": list(match), "tests": list(tests), "panels": [], "layers": list(layers),
            "profile": {}}


class TestGroupsAreWrittenInOneOrder(unittest.TestCase):
    def test_groups_that_can_share_no_path_are_in_name_order(self):
        groups = {"Search": _group(["lib/**"]), "Auth": _group(["src/auth/**"]),
                  "Docs2": _group(["docs/**"])}
        for order in (("Search", "Auth", "Docs2"), ("Docs2", "Search", "Auth"),
                      ("Auth", "Docs2", "Search")):
            with self.subTest(order=order):
                self.assertEqual(["Auth", "Docs2", "Search"], sp.canonical_order(
                    {name: groups[name] for name in order}))

    def test_two_groups_that_could_both_match_a_path_keep_the_proposals_order(self):
        # `Zeta` takes all of src, `Alpha` its auth corner. First match wins, so which is
        # listed first decides where login.py goes; name order would put Alpha first always.
        general, specific = _group(["src/**"]), _group(["src/auth/**"])
        self.assertEqual(["Zeta", "Alpha"], sp.canonical_order({"Zeta": general, "Alpha": specific}))
        self.assertEqual(["Alpha", "Zeta"], sp.canonical_order({"Alpha": specific, "Zeta": general}))
        # A group that can share no path with either still takes its place by name.
        self.assertEqual(["Lib", "Zeta", "Alpha"], sp.canonical_order(
            {"Zeta": general, "Alpha": specific, "Lib": _group(["lib/**"])}))
        self.assertEqual(["Zeta", "Alpha", "Zz"], sp.canonical_order(
            {"Zz": _group(["lib/**"]), "Zeta": general, "Alpha": specific}))

    def test_overlap_is_over_every_path_there_could_be_not_the_files_there_are(self):
        # No file on any tree is consulted. These two share no file on a tree with no
        # `src/auth/*.md` -- and would on the first commit that adds one.
        code, prose = _group(["src/auth/**"]), _group(["**/*.md"])
        self.assertEqual(["Prose", "Auth"], sp.canonical_order({"Prose": prose, "Auth": code}))
        self.assertEqual(["Auth", "Prose"], sp.canonical_order({"Auth": code, "Prose": prose}))

    def test_a_chain_of_overlaps_keeps_every_link(self):
        chain = {"C": _group(["a/**"]), "B": _group(["a/b/**"]), "A": _group(["a/b/c/**"])}
        self.assertEqual(["C", "B", "A"], sp.canonical_order(chain))
        self.assertEqual(["A", "B", "C"], sp.canonical_order(
            {name: chain[name] for name in ("A", "B", "C")}))

    def test_a_group_reaches_paths_through_its_tests_and_its_layers_too(self):
        by_tests = {"Zeta": _group(["lib/**"], tests=["src/auth/**"]),
                    "Alpha": _group(["src/auth/**"])}
        self.assertEqual(["Zeta", "Alpha"], sp.canonical_order(by_tests))
        by_layer = {"Zeta": _group(["lib/**"], layers=[{"layer": "API", "match": ["src/auth/**"]}]),
                    "Alpha": _group(["src/auth/**"])}
        self.assertEqual(["Zeta", "Alpha"], sp.canonical_order(by_layer))
        # A negation takes paths away and gives none: it is no reason to keep an order.
        self.assertEqual(["Alpha", "Zeta"], sp.canonical_order(
            {"Zeta": _group(["lib/**", "!src/auth/**"]), "Alpha": _group(["src/auth/**"])}))

    def test_two_globs_are_apart_only_when_their_fixed_leading_segments_part_ways(self):
        apart = (("lib/**", "src/auth/**"), ("a/x.py", "a/b/**"), ("/lib/", "src/x/"),
                 ("src/auth/login.py", "src/auth/token.py"), ("a/b/*/x", "a/c/**"),
                 ("/src/**", "lib/util.py"))
        together = (("src/**", "src/auth/**"), ("**/*.md", "src/auth/**"), ("README", "lib/**"),
                    ("*.py", "lib/**"), ("a/*/c", "a/b/**"), ("a/b", "a/b/c"), ("docs/", "src/**"),
                    ("//lib/x", "src/**"), ("a/[[]b]/**", "a/c/**"), ("lib/**", "lib/**"),
                    ("a**/x", "b/**"), ("src/[abc]/", "lib/**"), ("a/[]]/x", "a/]/x"),
                    ("a/?/c", "a/b/**"), ("a/b?/c", "a/bc/**"))
        for one, two in apart:
            with self.subTest(apart=(one, two)):
                self.assertFalse(sp.may_share_a_path(_group([one]), _group([two])))
                self.assertFalse(sp.may_share_a_path(_group([two]), _group([one])))
        for one, two in together:
            with self.subTest(together=(one, two)):
                self.assertTrue(sp.may_share_a_path(_group([one]), _group([two])))
                self.assertTrue(sp.may_share_a_path(_group([two]), _group([one])))
        self.assertFalse(sp.may_share_a_path(_group([]), _group(["**"])))
        self.assertFalse(sp.may_share_a_path(_group(["!src/**"]), _group(["src/**"])))

    def test_no_two_globs_called_apart_match_one_path_anywhere_in_a_space_of_both(self):
        # Soundness, by trying everything: "apart" is a promise about every path there is.
        matched = {glob: _matches(glob, PATHS) for glob in GLOBS}
        apart = 0
        for one, two in itertools.combinations(GLOBS, 2):
            if not sp.may_share_a_path(_group([one]), _group([two])):
                apart += 1
                self.assertFalse(matched[one] & matched[two], "%r and %r" % (one, two))
        self.assertGreater(apart, 1000)                      # the rule does call pairs apart

    def test_canonicalise_rewrites_globs_and_order_and_nothing_else(self):
        proposal = {"Zeta": dict(_group(["tools/**", "/lib/", "lib/**"], tests=["t/b.py", "t/a.py"],
                                        layers=[{"layer": "API", "match": ["y/**", "/x/"],
                                                 "canonical": "API"}]),
                                 panels=["SEC", "COD"], profile={"purpose": "p"}),
                    "Alpha": _group(["src/**", "!src/gen/"], tests=["u/v/", "/u/w/**"])}
        before = json.dumps(proposal, sort_keys=True)
        out = sp.canonicalise(proposal)
        self.assertEqual(["Alpha", "Zeta"], list(out))
        self.assertEqual(["lib/**", "tools/**"], out["Zeta"]["match"])
        self.assertEqual(["t/a.py", "t/b.py"], out["Zeta"]["tests"])
        self.assertEqual([{"layer": "API", "match": ["x/**", "y/**"], "canonical": "API"}],
                         out["Zeta"]["layers"])
        self.assertEqual((["SEC", "COD"], {"purpose": "p"}),
                         (out["Zeta"]["panels"], out["Zeta"]["profile"]))
        self.assertEqual(["src/**", "!src/gen/**"], out["Alpha"]["match"])
        self.assertEqual(["u/v/", "/u/w/**"], out["Alpha"]["tests"])       # mixed: as written
        self.assertEqual(before, json.dumps(proposal, sort_keys=True), "the input was mutated")
        # A group the config already has is sorted and not respelled, layers included.
        kept = sp.canonicalise(proposal, as_written={"Zeta"})
        self.assertEqual(["/lib/", "lib/**", "tools/**"], kept["Zeta"]["match"])
        self.assertEqual(["/x/", "y/**"], kept["Zeta"]["layers"][0]["match"])
        self.assertEqual(["src/**", "!src/gen/**"], kept["Alpha"]["match"])

    def test_canonicalising_twice_changes_nothing_more(self):
        table = list(TestAGlobIsSpelledOneWay.REWRITES) + ["/src/x", "src/**/", "lib/**/**",
                                                           "//src/x", "docs/", "**/***/"]
        for written in table:
            with self.subTest(written=written):
                proposal = {"Zeta": _group([written, "lib/**"], tests=[written],
                                           layers=[{"layer": "L", "match": [written]}]),
                            "Alpha": _group(["!" + written, "src/**"])}
                once = sp.canonicalise(proposal)
                self.assertEqual(once, sp.canonicalise(once))
                self.assertEqual(list(once), list(sp.canonicalise(once)))
        whole = {"G%03d" % n: _group(GLOBS[n::40]) for n in range(40)}
        once = sp.canonicalise(whole)
        self.assertEqual(once, sp.canonicalise(once))
        self.assertEqual(list(once), list(sp.canonicalise(once)))


class _Ingest(unittest.TestCase):
    def setUp(self):
        self.state = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.state, True)
        patch = mock.patch.dict(os.environ, {"PANOPTICON_STATE_DIR": self.state})
        patch.start()
        self.addCleanup(patch.stop)

    def _repo(self, committed=None, later=()):
        root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        for relative in FILES + tuple(later):
            os.makedirs(os.path.dirname(os.path.join(root, relative)), exist_ok=True)
            with open(os.path.join(root, relative), "w", encoding="utf-8") as fh:
                fh.write("x = 1\n")
        os.makedirs(os.path.join(root, ".panopticon"))
        if committed:
            with open(os.path.join(root, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n" + committed)
        return root

    def _ingest(self, groups, committed=None):
        """(draft text, result) for a proposal of `groups` over a fresh copy of the tree."""
        root = self._repo(committed)
        path = os.path.join(root, ".panopticon", "setup-proposal.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"groups": groups}, fh)
        result = setup_flow.ingest_proposal(root, path)
        self.assertTrue(result["ok"], result)
        with open(result["draft"], encoding="utf-8") as fh:
            return fh.read(), result

    def _cells(self, draft_text, later=()):
        """The files each group of a draft realises by the run-time rule, on the tree --
        or on the tree plus `later`, files that were not there when setup wrote the draft."""
        root = self._repo(later=later)
        with open(os.path.join(root, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write(draft_text)
        groups, residual = discovery.catalog_groups(
            [f for f in discovery.discover_repo_files(root) if f != "panopticon.yml"],
            discovery._matrix_catalog(root), 48)
        return {group["name"]: sorted(group["files"]) for group in groups}, sorted(residual)

    def _as_written(self, groups, committed=None):
        """The draft setup would write with no canonicalising at all."""
        with mock.patch.object(sp, "canonicalise", side_effect=lambda a, as_written=(): a):
            return self._ingest(groups, committed)[0]

    def _fingerprint(self, draft_text):
        """The `matrix_fingerprint` a run over this draft would report (#3680)."""
        root = self._repo()
        with open(os.path.join(root, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write(draft_text)
        catalog = discovery._matrix_catalog(root)
        groups, _residual = discovery.catalog_groups(
            [f for f in discovery.discover_repo_files(root) if f != "panopticon.yml"], catalog, 48)
        return matrix_identity.matrix_fingerprint(
            groups, [{"group": name, "floor": sorted(leaf.get("floor") or ())}
                     for name, leaf in catalog.items()])


AUTH = {"capability": "custom:AuthZone", "match": ["src/auth/**"]}
LIB = {"capability": "custom:Lib", "match": ["lib/**", "tools/**"]}
PROSE = {"capability": "custom:Prose", "match": ["docs/**", "pkg/docs/**"]}
APP = {"capability": "custom:WholeApp", "match": ["src/**", "!src/gen/**"]}


class TestEquivalentDraftsComeOutByteEqual(_Ingest):
    def test_glob_order_duplicate_globs_and_group_order_do_not_reach_the_draft(self):
        # The coordinator's pin: two drafts that differ ONLY in those three things.
        one, _result = self._ingest([AUTH, LIB, PROSE])
        two, _result = self._ingest([
            dict(PROSE, match=["pkg/docs/**", "docs/**", "docs/**"]),
            dict(LIB, match=["tools/**", "lib/**", "tools/**", "lib/**"]),
            AUTH])
        self.assertEqual(one, two)
        self.assertEqual(matrix_provenance.text_digest(one), matrix_provenance.text_digest(two))
        self.assertRegex(matrix_provenance.text_digest(one), r"\Asha256:[0-9a-f]{64}\Z")
        drafted = yaml.safe_load(one)["groups"]
        self.assertEqual(["AuthZone", "Lib", "Prose"], list(drafted))
        self.assertEqual(["lib/**", "tools/**"], drafted["Lib"]["match"])

    def test_two_spellings_of_one_glob_do_not_reach_the_draft(self):
        one, _result = self._ingest([AUTH, LIB])
        two, _result = self._ingest([dict(LIB, match=["/lib/", "/tools/***"]),
                                     dict(AUTH, match=["/src/auth/"])])
        self.assertEqual(one, two)

    def test_two_spellings_of_one_custom_name_do_not_reach_the_draft(self):
        halves = [{"capability": "custom:lib", "match": ["lib/**"]},
                  {"capability": "custom:Lib", "match": ["tools/**"]}]
        one, _result = self._ingest(halves)
        two, _result = self._ingest(halves[::-1])
        self.assertEqual(one, two)
        self.assertEqual(["Lib"], list(yaml.safe_load(one)["groups"]))      # sorts first

    def test_setup_records_the_canonical_drafts_hash(self):
        text, result = self._ingest([PROSE, AUTH])
        root = os.path.dirname(result["draft"])
        self.assertEqual("unchanged", matrix_provenance.draft_state(
            root, matrix_provenance.text_digest(text)))


class TestNoCellMoves(_Ingest):
    """The acceptance test: for every fixture, what each group realises is the same whether
    the proposal is planned as written or in canonical form."""

    FIXTURES = {
        "disjoint, reversed": [PROSE, LIB, AUTH],
        "a negation": [APP, LIB],
        "general before specific": [APP, AUTH, LIB],
        "specific before general": [AUTH, APP, LIB],
        "a chain": [{"capability": "custom:C", "match": ["a/**"]},
                    {"capability": "custom:B", "match": ["a/b/**"]},
                    {"capability": "custom:A", "match": ["a/b/c/**"]}],
        "a chain, reversed": [{"capability": "custom:A", "match": ["a/b/c/**"]},
                              {"capability": "custom:B", "match": ["a/b/**"]},
                              {"capability": "custom:C", "match": ["a/**"]}],
        "an unanchored basename": [{"capability": "custom:Readmes", "match": ["README"]},
                                   {"capability": "custom:Tools", "match": ["tools/**"]}],
        "spelling variants": [dict(LIB, match=["/lib/", "tools/**/**"]),
                              dict(AUTH, match=["/src/auth/", "src/auth/**"])],
        "duplicates and a redundant group": [LIB, dict(LIB, capability="custom:Again"), AUTH],
        "scoped tests": [dict(AUTH, tests=["docs/api/**"]), PROSE],
    }

    def _plans(self, groups, committed=None):
        root = self._repo(committed)
        vocab, _e = sp.load_vocabulary(setup_flow.setup_spine._VOCAB_PATH)
        affinity, _e = sp.load_affinity(setup_flow.setup_spine._AFFINITY_PATH, vocab)
        layers, _e = sp.load_layers(setup_flow.setup_spine._LAYERS_PATH)
        assembled, disclosure = sp.assemble({"groups": groups}, vocab, affinity, layers=layers,
                                            review_root=root)
        self.assertIsNotNone(assembled, disclosure)
        files = discovery.discover_repo_files(root)
        committed_matrix = setup_flow.committed_matrix(root)
        written = grouping_engine.plan_groups(files, committed_matrix, assembled, 48)
        canonical = grouping_engine.plan_groups(
            files, committed_matrix, sp.canonicalise(assembled, as_written=set(committed_matrix)),
            48)
        return written, canonical

    def test_every_fixture_realises_the_same_cells_either_way(self):
        for name, groups in self.FIXTURES.items():
            with self.subTest(fixture=name):
                written, canonical = self._plans(groups)
                self.assertEqual(setup_flow.realised_cells(written),
                                 setup_flow.realised_cells(canonical))
                self.assertTrue(any(written["claims"].values()), "the fixture claims nothing")

    def test_the_draft_setup_writes_realises_what_the_proposal_asked_for(self):
        # End to end, by the RUN-TIME rule: the draft as written by setup, read back by
        # discovery, gives each group the files the proposal's own order gave it.
        for name, groups in self.FIXTURES.items():
            with self.subTest(fixture=name):
                text, result = self._ingest(groups)
                cells, _residual = self._cells(text)
                written, _canonical = self._plans(groups)
                for group, files in written["claims"].items():
                    if files:
                        self.assertEqual(sorted(files), cells.get(group), group)
                self.assertEqual([], [w for w in result["disclosure"]["warnings"]
                                      if "used as written" in w])

    def test_a_run_reports_one_matrix_fingerprint_before_and_after(self):
        # The instrument the design named: the fingerprint a run would report over the draft
        # setup wrote WITHOUT canonicalising equals the one over the draft it writes now.
        for name, groups in self.FIXTURES.items():
            with self.subTest(fixture=name):
                plain = self._as_written(groups)
                canonical, _result = self._ingest(groups)
                self.assertEqual(self._fingerprint(plain), self._fingerprint(canonical))
        # ...and the fixtures are not all already canonical: most drafts did change.
        changed = 0
        for groups in self.FIXTURES.values():
            changed += self._as_written(groups) != self._ingest(groups)[0]
        self.assertGreaterEqual(changed, 5)

    def test_the_two_orders_of_an_overlap_stay_two_different_matrices(self):
        general_first, _r = self._ingest([APP, AUTH, LIB])
        specific_first, _r = self._ingest([AUTH, APP, LIB])
        self.assertNotEqual(general_first, specific_first)
        self.assertNotEqual(self._fingerprint(general_first), self._fingerprint(specific_first))
        first, _residual = self._cells(general_first)
        second, _residual = self._cells(specific_first)
        self.assertNotIn("AuthZone", first)                 # the whole app took its files
        self.assertEqual(["src/auth/login.py", "src/auth/token.py"], second["AuthZone"])
        # ...and in each, the pair kept the order it was proposed in.
        self.assertEqual(["AuthZone", "WholeApp"],
                         [n for n in yaml.safe_load(specific_first)["groups"] if n != "Lib"])

    def test_committed_groups_are_never_rewritten_or_moved(self):
        committed = ("  Zed:\n    match: ['tools/**', 'lib/**', 'lib/**']\n"
                     "  Mid:\n    match: ['/docs/']\n")
        text, _result = self._ingest([PROSE, AUTH], committed=committed)
        drafted = yaml.safe_load(text)["groups"]
        self.assertEqual(["Zed", "Mid"], list(drafted)[:2])
        self.assertEqual(["tools/**", "lib/**", "lib/**"], drafted["Zed"]["match"])
        self.assertEqual(["/docs/"], drafted["Mid"]["match"])
        self.assertEqual(["AuthZone"], list(drafted)[2:3])


class TestACanonicalFormThatWouldMoveAFileIsNotUsed(_Ingest):
    def test_the_proposal_is_used_as_written_and_the_report_says_so(self):
        # A canonicaliser that gets the order wrong (pure name order) on a proposal whose
        # order is semantic. The check that plans both ways catches it.
        def by_name(assembled, as_written=()):
            return {name: assembled[name] for name in sorted(assembled)}

        as_written, _r = self._ingest([APP, AUTH, LIB])
        with mock.patch.object(sp, "canonicalise", side_effect=by_name):
            guarded, result = self._ingest([APP, AUTH, LIB])
        self.assertEqual(self._cells(as_written), self._cells(guarded))
        # The real canonical form puts `Lib` first (it shares no file with the others); the
        # guarded run kept the proposal's own order. `AuthZone` claims nothing either way,
        # because `WholeApp` was listed first.
        self.assertEqual(["Lib", "WholeApp"], list(yaml.safe_load(as_written)["groups"]))
        self.assertEqual(["WholeApp", "Lib"], list(yaml.safe_load(guarded)["groups"]))
        warnings = [w for w in result["disclosure"]["warnings"] if "used as written" in w]
        self.assertEqual(1, len(warnings), result["disclosure"]["warnings"])
        self.assertIn("would move files between groups", warnings[0])

    def test_two_groups_that_trade_equal_numbers_of_files_are_caught_too(self):
        # A canonicaliser whose respelling is wrong: it hands each group the other's globs.
        # Both groups keep their kind, their panels and their file COUNT (two each), so
        # only the files themselves tell the two plans apart.
        one = {"capability": "custom:One", "match": ["a/**"]}
        two = {"capability": "custom:Two", "match": ["lib/**"]}

        def traded(assembled, as_written=()):
            return {"One": dict(assembled["One"], match=assembled["Two"]["match"]),
                    "Two": dict(assembled["Two"], match=assembled["One"]["match"])}

        as_written, _r = self._ingest([one, two])
        with mock.patch.object(sp, "canonicalise", side_effect=traded):
            guarded, result = self._ingest([one, two])
        self.assertEqual(as_written, guarded)
        self.assertEqual(["a/b/c/d.py", "a/x.py"], self._cells(guarded)[0]["One"])
        self.assertEqual(["lib/net/http.py", "lib/util.py"], self._cells(guarded)[0]["Two"])
        self.assertEqual(1, sum("used as written" in w for w in result["disclosure"]["warnings"]))

    def test_two_plans_are_the_same_only_when_every_part_is(self):
        one = {"name": "One", "kind": "vertical", "files": 2, "domains": ["COD", "SEC"]}
        docs = {"name": "Docs", "kind": "commons", "files": 1, "domains": ["COD"]}

        def plan(claims=None, leaves=None, ungrouped=None, leaf_files=None):
            return {"claims": claims or {"One": ["a.py", "b.py"]},
                    "report": {"leaves": leaves or [one, docs],
                               "ungrouped": ungrouped or ["x.py", "y.py"]},
                    "leaf_files": leaf_files or {"One": ["a.py", "b.py"], "Docs": ["d.md"],
                                                 "Prose": ["d.md"]}}

        same = setup_flow.realised_cells(plan())
        # Listing order is not a difference.
        self.assertEqual(same, setup_flow.realised_cells(plan(
            claims={"One": ["b.py", "a.py"]}, ungrouped=["y.py", "x.py"],
            leaves=[docs, dict(one, domains=["SEC", "COD"])],
            leaf_files={"Docs": ["d.md"], "One": ["b.py", "a.py"]})))
        for moved, other in (
                ("a claimed file", plan(claims={"One": ["a.py", "c.py"]})),
                ("a leaf's panels", plan(leaves=[dict(one, domains=["COD"]), docs])),
                ("a leaf's kind", plan(leaves=[dict(one, kind="layer"), docs])),
                ("a leaf's name", plan(leaves=[one, dict(docs, name="Prose")])),
                ("a leaf's file, its count unchanged",
                 plan(leaf_files={"One": ["a.py", "z.py"], "Docs": ["d.md"]})),
                ("an ungrouped file", plan(ungrouped=["x.py", "z.py"]))):
            with self.subTest(moved=moved):
                self.assertNotEqual(same, setup_flow.realised_cells(other))

    def test_two_layers_of_one_group_that_trade_equal_numbers_of_files_are_caught(self):
        # The plan's report holds each leaf's COUNT. Two layers of one vertical can swap
        # their globs and keep every count, every claim and every panel.
        files = (["app/one/f%d.py" % n for n in range(8)]
                 + ["app/two/f%d.py" % n for n in range(8)])

        def big(first, second):
            return {"Big": dict(_group(["app/**"], layers=[
                {"layer": "First", "match": [first], "canonical": False},
                {"layer": "Second", "match": [second], "canonical": False}]), panels=["SEC"])}

        written = grouping_engine.plan_groups(files, {}, big("app/one/**", "app/two/**"), 4)
        traded = grouping_engine.plan_groups(files, {}, big("app/two/**", "app/one/**"), 4)
        self.assertEqual(["app/one/f%d.py" % n for n in range(8)], written["leaf_files"]["Big:First"])
        self.assertEqual(["app/two/f%d.py" % n for n in range(8)], traded["leaf_files"]["Big:First"])
        # Everything the guard used to compare agrees...
        self.assertEqual(written["claims"], traded["claims"])
        self.assertEqual(written["report"]["leaves"], traded["report"]["leaves"])
        self.assertEqual(written["report"]["ungrouped"], traded["report"]["ungrouped"])
        # ...and the files do not.
        self.assertNotEqual(setup_flow.realised_cells(written), setup_flow.realised_cells(traded))
        # Every leaf the report names has its files on record, and the count is theirs.
        for plan in (written, traded):
            self.assertEqual({leaf["name"]: leaf["files"] for leaf in plan["report"]["leaves"]},
                             {name: len(mine) for name, mine in plan["leaf_files"].items()})

    def test_a_proposal_already_in_canonical_form_is_planned_once(self):
        with mock.patch.object(grouping_engine, "plan_groups",
                               wraps=grouping_engine.plan_groups) as planned:
            self._ingest([AUTH, LIB])
        self.assertEqual(1, planned.call_count)
        with mock.patch.object(grouping_engine, "plan_groups",
                               wraps=grouping_engine.plan_groups) as planned:
            self._ingest([LIB, AUTH])
        self.assertEqual(2, planned.call_count)



class TestTheDraftMeansTheSameOnALaterTree(_Ingest):
    """A draft is written once and reused on every later commit. So for each rule: the draft
    setup writes, and the draft it would write with no canonicalising at all, must give
    every group the same files on the tree PLUS files that were not there at setup."""

    def _both(self, groups, later, committed=None):
        """(cells as written, cells canonicalised, the canonical draft), on the later tree.
        Neither ingest may warn: these are proposals the guard has no objection to today."""
        written = self._as_written(groups, committed)
        canonical, result = self._ingest(groups, committed)
        self.assertEqual([], [w for w in result["disclosure"]["warnings"] if "as written" in w])
        return self._cells(written, later), self._cells(canonical, later), canonical

    def test_a_tests_glob_keeps_its_spelling_so_it_keeps_its_scope(self):
        # `pkg/src/` is literal: it credits `pkg/src/a.py` to AuthZone outright. Spelled
        # `pkg/src/**` it would be a wildcard, out of AuthZone's scope, and Other's.
        groups = [dict(AUTH, tests=["pkg/src/"]), {"capability": "custom:Other", "match": ["pkg/**"]}]
        written, canonical, draft = self._both(groups, later=("pkg/src/a.py",))
        self.assertEqual(written, canonical)
        self.assertIn("pkg/src/a.py", canonical[0]["AuthZone"])
        self.assertEqual(["pkg/src/"], yaml.safe_load(draft)["groups"]["AuthZone"]["tests"])

    def test_a_tests_list_of_both_kinds_keeps_its_order(self):
        # The last tests glob to match decides. Sorted, the literal would come last and
        # hand a later `lib/new.py` to AuthZone outright; as written the wildcard does, and
        # it is out of AuthZone's scope, so Lib has the file.
        groups = [dict(AUTH, tests=["lib/new.py", "lib/**"]), LIB]
        written, canonical, draft = self._both(groups, later=("lib/new.py",))
        self.assertEqual(written, canonical)
        self.assertIn("lib/new.py", canonical[0]["Lib"])
        self.assertEqual(["lib/new.py", "lib/**"],
                         yaml.safe_load(draft)["groups"]["AuthZone"]["tests"])

    def test_a_glob_whose_only_slash_anchors_it_keeps_that_slash(self):
        # `src**/**` is anchored at the root. `src**` is not: it would take any later file
        # whose NAME starts with src, wherever it is.
        groups = [{"capability": "custom:Sources", "match": ["src**/**"]}, LIB]
        written, canonical, draft = self._both(groups, later=("vendor/srcmap.py", "srcgen/x.py"))
        self.assertEqual(written, canonical)
        self.assertIn("srcgen/x.py", canonical[0]["Sources"])
        self.assertNotIn("vendor/srcmap.py", canonical[0]["Sources"])
        self.assertEqual(["src**/**"], yaml.safe_load(draft)["groups"]["Sources"]["match"])

    def test_a_doubled_leading_slash_stays_doubled(self):
        # `//src/new.py` matches nothing, on any tree. `/src/new.py` is a file.
        groups = [dict(LIB, match=["//src/new.py", "lib/**"]), AUTH]
        written, canonical, draft = self._both(groups, later=("src/new.py",))
        self.assertEqual(written, canonical)
        self.assertNotIn("src/new.py", canonical[0]["Lib"])
        self.assertEqual(["//src/new.py", "lib/**"], yaml.safe_load(draft)["groups"]["Lib"]["match"])

    def test_a_glob_over_the_compilers_limit_is_not_brought_under_it(self):
        # 257 characters: the compiler ignores it. Without its leading `/` it is 256, and
        # would claim the file it names.
        name = "x" * 252
        groups = [dict(LIB, match=["/lib/" + name, "lib/**"]), dict(AUTH, match=["/lib/" + name])]
        written = self._as_written(groups)
        canonical, _result = self._ingest(groups)
        self.assertEqual(["/lib/" + name, "lib/**"], yaml.safe_load(canonical)["groups"]["Lib"]["match"])
        self.assertEqual(self._cells(written), self._cells(canonical))
        # Read by the matcher itself, on a path no tree here needs to hold.
        self.assertFalse(discovery_catalog.match_patterns("lib/" + name, ["/lib/" + name]))
        self.assertTrue(discovery_catalog.match_patterns("lib/" + name, ["lib/" + name]))

    def test_two_groups_that_overlap_only_on_a_later_tree_keep_their_order(self):
        # Nothing under src/auth is prose today, so today these two share no file. The
        # first commit that adds `src/auth/notes.md` is Prose's as written, because Prose
        # was listed first. Name order would hand it to AuthZone.
        groups = [{"capability": "custom:Prose", "match": ["**/*.md"]}, AUTH]
        written, canonical, draft = self._both(groups, later=("src/auth/notes.md",))
        self.assertEqual(written, canonical)
        self.assertIn("src/auth/notes.md", canonical[0]["Prose"])
        self.assertEqual(["Prose", "AuthZone"], list(yaml.safe_load(draft)["groups"]))

    def test_every_fixture_means_the_same_on_a_later_tree(self):
        later = ("src/auth/notes.md", "lib/new.py", "pkg/src/a.py", "src/new.py", "tools/x/README",
                 "a/b/new.py", "a/b/c/e/f.py", "docs/api/v2/x.md", "src/gen/extra.py", "new/README",
                 "vendor/srcmap.py", "lib/net/deep/er.py", "x/docs/y.md", "srcx/app.py")
        for name, groups in TestNoCellMoves.FIXTURES.items():
            with self.subTest(fixture=name):
                written, canonical, _draft = self._both(groups, later)
                self.assertEqual(written, canonical)

    def test_a_glob_the_committed_group_already_carries_is_not_added_again_respelled(self):
        # The merge compares a proposal's globs with the committed group's as TEXT. Respelled
        # first, `lib/` would no longer equal the committed `lib/` and be added beside it.
        committed = "  Lib:\n    match: ['/lib/']\n"
        groups = [dict(LIB, match=["/lib/", "tools/"]), AUTH]
        text, _result = self._ingest(groups, committed=committed)
        drafted = yaml.safe_load(text)["groups"]
        self.assertEqual(["/lib/", "tools/"], drafted["Lib"]["match"])
        self.assertEqual(self._as_written(groups, committed), text)


if __name__ == "__main__":
    unittest.main()
