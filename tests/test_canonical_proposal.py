"""#3651 phase 2, option (b): a setup proposal is written one way, whatever order and spelling
the agent returned it in.

The rule the whole of it answers to: canonicalising changes how a proposal is WRITTEN and
never what it claims. Every group ends up with the same files, before and after.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import yaml

import scripts.discovery as discovery
import scripts.groups_schema as groups_schema
import scripts.grouping_engine as grouping_engine
import scripts.matrix_identity as matrix_identity
import scripts.matrix_provenance as matrix_provenance
import scripts.setup_flow as setup_flow
import scripts.setup_proposal as sp

FILES = ("src/app.py", "src/auth/login.py", "src/auth/token.py", "src/gen/models.py",
         "lib/util.py", "lib/net/http.py", "docs/guide.md", "docs/api/index.md",
         "pkg/docs/readme.md", "README", "tools/README", "a/b/c/d.py", "a/x.py")

# Paths chosen to tell every rewrite apart from its neighbour: nested and top-level, a
# basename that repeats at two depths, a directory name that repeats at two depths.
CORPUS = FILES + ("docs", "docs/", "src", "src/auth", "a/b", "a/b/c", "README.md",
                  "x/README", "auth/login.py", "src/auth/deep/er/f.py", "srcx/app.py",
                  "lib", "lib/util.pyc", "a/b/x.py", "", "/src/app.py", "./src/app.py")


def _matches(glob):
    return {path for path in CORPUS if groups_schema.glob_to_re(glob.lstrip("!"), "test").match(path)}


class TestAGlobIsSpelledOneWay(unittest.TestCase):
    def test_each_rewrite_matches_exactly_what_the_original_did(self):
        cases = {
            # a trailing `/` on an anchored pattern is `/**`
            "src/auth/": "src/auth/**", "a/b/c/": "a/b/c/**", "/docs/": "docs/**",
            # a run of `**/`, or of stars, is one
            "src/**/**/login.py": "src/**/login.py", "a/**/**/**/d.py": "a/**/d.py",
            "lib/***": "lib/**", "src/****/x": "src/**/x",
            # "any directories, then anything" is "anything"
            "lib/**/**": "lib/**", "**/**": "**", "a/**/**x.py": "a/**x.py",
            "src/**/**/**": "src/**",
            # a leading `/` beside another `/` adds nothing
            "/src/app.py": "src/app.py", "/lib/**": "lib/**", "/a/**/d.py": "a/**/d.py",
            # ...and they compose
            "/src/**/**/auth/": "src/**/auth/**",
        }
        for written, canonical in cases.items():
            with self.subTest(written=written):
                self.assertEqual(canonical, sp.normalize_glob(written))
                self.assertEqual(_matches(written), _matches(canonical))
                self.assertEqual("!" + canonical, sp.normalize_glob("!" + written))
                self.assertEqual(canonical, sp.normalize_glob(canonical))      # a fixed point

    def test_what_cannot_be_proven_equivalent_is_left_as_written(self):
        # Each of these has a tempting "simpler" spelling that claims different files.
        for written, tempting in (("docs/", "docs/**"),          # unanchored: any depth
                                  ("/README", "README"),         # the slash is the anchor
                                  ("./src/**", "src/**"),        # taken literally: nothing
                                  ("src/auth", "src/auth/**"),   # the path itself only
                                  ("README", "/README")):
            with self.subTest(written=written):
                self.assertEqual(written, sp.normalize_glob(written))
                self.assertNotEqual(_matches(written), _matches(tempting),
                                    "the corpus must tell these two apart")
        for untouched in ("src/**", "*.py", "lib/*.py", "src/app.py", "**", "a/?/c", "", "!"):
            self.assertEqual(untouched, sp.normalize_glob(untouched))
        for not_text in (None, 3, ["src/"]):
            self.assertIs(not_text, sp.normalize_glob(not_text))

    def test_a_glob_the_compiler_refuses_is_never_touched(self):
        for defect in ("src/[abc]/", "/lib/[!a]/", "a/**/**/[x]"):
            with self.subTest(defect=defect):
                self.assertTrue(groups_schema.glob_defect(defect), "not a defect any more")
                self.assertEqual(defect, sp.normalize_glob(defect))

    def test_a_rewrite_that_would_cross_the_compilers_limit_is_not_made(self):
        # The compiler checks its limits BEFORE it expands a trailing `/`. So a pattern just
        # under one means something as written, and nothing once `**` is appended.
        long_dir = "d/" + "x" * 253 + "/"
        self.assertEqual(256, len(long_dir))
        self.assertEqual(long_dir, sp.normalize_glob(long_dir))
        starry = "s/" + "*a" * 19 + "/"
        self.assertEqual(19, starry.count("*"))
        self.assertEqual(starry, sp.normalize_glob(starry))
        # ...and both DO match as written, which is what expanding them would have lost.
        self.assertTrue(groups_schema.glob_to_re(long_dir, "test").match("d/" + "x" * 253 + "/f"))
        self.assertFalse(groups_schema.glob_to_re(long_dir + "**", "test").match(
            "d/" + "x" * 253 + "/f"))
        self.assertEqual((256, 20), (sp._MAX_GLOB_CHARS, sp._MAX_GLOB_STARS))
        # One under the limit still is rewritten.
        self.assertEqual("d/" + "x" * 251 + "/**", sp.normalize_glob("d/" + "x" * 251 + "/"))


class TestAGroupsGlobsAreListedOneWay(unittest.TestCase):
    def test_a_plain_union_is_sorted_and_de_duplicated(self):
        self.assertEqual(["lib/**", "src/**", "tools/**"],
                         sp.canonical_globs(["tools/**", "src/**", "lib/**", "src/**"]))
        # Two spellings of one glob are one glob.
        self.assertEqual(["src/auth/**"], sp.canonical_globs(["src/auth/", "/src/auth/**"]))
        self.assertEqual([], sp.canonical_globs(None))
        self.assertEqual([], sp.canonical_globs([]))

    def test_a_list_with_a_negation_keeps_its_order_and_its_repeats(self):
        # Last match wins: these three lists claim three different sets of files.
        for written in (["src/**", "!src/gen/**"], ["!src/gen/**", "src/**"],
                        ["src/**", "!src/gen/**", "src/**"], ["z/**", "!z/a/**", "a/**"]):
            with self.subTest(written=written):
                self.assertEqual(written, sp.canonical_globs(written))
        self.assertEqual({"src/app.py", "src/auth/login.py", "src/auth/token.py"},
                         self._claimed(["src/**", "!src/gen/**"]))
        self.assertEqual(self._claimed(["src/**"]), self._claimed(["!src/gen/**", "src/**"]))
        self.assertEqual(self._claimed(["src/**"]),
                         self._claimed(["src/**", "!src/gen/**", "src/**"]))
        # Each glob is still spelled canonically, in place.
        self.assertEqual(["src/**", "!src/gen/**"], sp.canonical_globs(["/src/**", "!src/gen/"]))

    def _claimed(self, globs):
        from scripts import discovery_catalog
        return {path for path in FILES if discovery_catalog.match_patterns(path, globs)}


def _group(match, tests=(), layers=()):
    return {"match": list(match), "tests": list(tests), "panels": [], "layers": list(layers),
            "profile": {}}


class TestGroupsAreWrittenInOneOrder(unittest.TestCase):
    def test_groups_that_share_no_file_are_in_name_order(self):
        groups = {"Search": _group(["lib/**"]), "Auth": _group(["src/auth/**"]),
                  "Docs2": _group(["docs/**"])}
        for order in (("Search", "Auth", "Docs2"), ("Docs2", "Search", "Auth"),
                      ("Auth", "Docs2", "Search")):
            with self.subTest(order=order):
                self.assertEqual(["Auth", "Docs2", "Search"], sp.canonical_order(
                    {name: groups[name] for name in order}, FILES))

    def test_two_groups_that_both_match_a_file_keep_the_proposals_order(self):
        # `Zeta` takes all of src, `Alpha` its auth corner. First match wins, so which is
        # listed first decides where login.py goes; name order would put Alpha first always.
        general, specific = _group(["src/**"]), _group(["src/auth/**"])
        self.assertEqual(["Zeta", "Alpha"], sp.canonical_order(
            {"Zeta": general, "Alpha": specific}, FILES))
        self.assertEqual(["Alpha", "Zeta"], sp.canonical_order(
            {"Alpha": specific, "Zeta": general}, FILES))
        # A group that shares no file with either still takes its place by name.
        self.assertEqual(["Lib", "Zeta", "Alpha"], sp.canonical_order(
            {"Zeta": general, "Alpha": specific, "Lib": _group(["lib/**"])}, FILES))
        self.assertEqual(["Zeta", "Alpha", "Zz"], sp.canonical_order(
            {"Zz": _group(["lib/**"]), "Zeta": general, "Alpha": specific}, FILES))

    def test_overlap_is_over_the_files_that_exist_not_over_the_globs_text(self):
        # These two globs could overlap on a tree that had `src/auth/x.md`. This one has
        # no such file, so their order decides nothing here and name order applies.
        code, prose = _group(["src/auth/**"]), _group(["**/*.md"])
        self.assertEqual(["Auth", "Prose"],
                         sp.canonical_order({"Prose": prose, "Auth": code}, FILES))
        self.assertEqual(["Prose", "Auth"], sp.canonical_order(
            {"Prose": prose, "Auth": code}, FILES + ("src/auth/notes.md",)))

    def test_a_chain_of_overlaps_keeps_every_link(self):
        chain = {"C": _group(["a/**"]), "B": _group(["a/b/**"]), "A": _group(["a/b/c/**"])}
        self.assertEqual(["C", "B", "A"], sp.canonical_order(chain, FILES))
        self.assertEqual(["A", "B", "C"], sp.canonical_order(
            {name: chain[name] for name in ("A", "B", "C")}, FILES))

    def test_a_group_reaches_files_through_its_tests_and_its_layers_too(self):
        by_tests = {"Zeta": _group(["lib/**"], tests=["src/auth/**"]),
                    "Alpha": _group(["src/auth/**"])}
        self.assertEqual(["Zeta", "Alpha"], sp.canonical_order(by_tests, FILES))
        by_layer = {"Zeta": _group(["lib/**"], layers=[{"layer": "API", "match": ["src/auth/**"]}]),
                    "Alpha": _group(["src/auth/**"])}
        self.assertEqual(["Zeta", "Alpha"], sp.canonical_order(by_layer, FILES))

    def test_canonicalise_rewrites_globs_and_order_and_nothing_else(self):
        proposal = {"Zeta": dict(_group(["tools/**", "/lib/", "lib/**"], tests=["b", "a"],
                                        layers=[{"layer": "API", "match": ["y/**", "x/**"],
                                                 "canonical": "API"}]),
                                 panels=["SEC", "COD"], profile={"purpose": "p"}),
                    "Alpha": _group(["src/**", "!src/gen/"])}
        before = json.dumps(proposal, sort_keys=True)
        out = sp.canonicalise(proposal, FILES)
        self.assertEqual(["Alpha", "Zeta"], list(out))
        self.assertEqual(["lib/**", "tools/**"], out["Zeta"]["match"])
        self.assertEqual(["a", "b"], out["Zeta"]["tests"])
        self.assertEqual([{"layer": "API", "match": ["x/**", "y/**"], "canonical": "API"}],
                         out["Zeta"]["layers"])
        self.assertEqual((["SEC", "COD"], {"purpose": "p"}),
                         (out["Zeta"]["panels"], out["Zeta"]["profile"]))
        self.assertEqual(["src/**", "!src/gen/**"], out["Alpha"]["match"])
        self.assertEqual(before, json.dumps(proposal, sort_keys=True), "the input was mutated")
        self.assertEqual(out, sp.canonicalise(out, FILES))                     # a fixed point


class _Ingest(unittest.TestCase):
    def setUp(self):
        self.state = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.state, True)
        patch = mock.patch.dict(os.environ, {"PANOPTICON_STATE_DIR": self.state})
        patch.start()
        self.addCleanup(patch.stop)

    def _repo(self, committed=None):
        root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        for relative in FILES:
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

    def _cells(self, draft_text):
        """The files each group of a draft realises on the tree, by the run-time rule."""
        root = self._repo()
        with open(os.path.join(root, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write(draft_text)
        groups, residual = discovery.catalog_groups(
            [f for f in discovery.discover_repo_files(root) if f != "panopticon.yml"],
            discovery._matrix_catalog(root), 48)
        return {group["name"]: sorted(group["files"]) for group in groups}, sorted(residual)

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
        two, _result = self._ingest([dict(LIB, match=["/lib/", "tools/**/**"]),
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
            files, committed_matrix, sp.canonicalise(assembled, files), 48)
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
                with mock.patch.object(sp, "canonicalise", side_effect=lambda a, files: a):
                    plain, _result = self._ingest(groups)
                canonical, _result = self._ingest(groups)
                self.assertEqual(self._fingerprint(plain), self._fingerprint(canonical))
        # ...and the fixtures are not all already canonical: most drafts did change.
        changed = 0
        for groups in self.FIXTURES.values():
            with mock.patch.object(sp, "canonicalise", side_effect=lambda a, files: a):
                plain, _result = self._ingest(groups)
            changed += plain != self._ingest(groups)[0]
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
        def by_name(assembled, files):
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

        def traded(assembled, files):
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
        def plan(claims=None, leaves=None, ungrouped=None):
            return {"claims": claims or {"One": ["a.py", "b.py"]},
                    "report": {"leaves": leaves or [
                        {"name": "One", "kind": "vertical", "files": 2, "domains": ["COD", "SEC"]},
                        {"name": "Docs", "kind": "commons", "files": 1, "domains": ["COD"]}],
                        "ungrouped": ungrouped or ["x.py", "y.py"]}}

        same = setup_flow.realised_cells(plan())
        # Listing order is not a difference.
        self.assertEqual(same, setup_flow.realised_cells(plan(
            claims={"One": ["b.py", "a.py"]}, ungrouped=["y.py", "x.py"], leaves=[
                {"name": "Docs", "kind": "commons", "files": 1, "domains": ["COD"]},
                {"name": "One", "kind": "vertical", "files": 2, "domains": ["SEC", "COD"]}])))
        one = {"name": "One", "kind": "vertical", "files": 2, "domains": ["COD", "SEC"]}
        docs = {"name": "Docs", "kind": "commons", "files": 1, "domains": ["COD"]}
        for moved, other in (
                ("a claimed file", plan(claims={"One": ["a.py", "c.py"]})),
                ("a leaf's panels", plan(leaves=[dict(one, domains=["COD"]), docs])),
                ("a leaf's kind", plan(leaves=[dict(one, kind="layer"), docs])),
                ("a leaf's size", plan(leaves=[one, dict(docs, files=2)])),
                ("a leaf's name", plan(leaves=[one, dict(docs, name="Prose")])),
                ("an ungrouped file", plan(ungrouped=["x.py", "z.py"]))):
            with self.subTest(moved=moved):
                self.assertNotEqual(same, setup_flow.realised_cells(other))

    def test_a_proposal_already_in_canonical_form_is_planned_once(self):
        with mock.patch.object(grouping_engine, "plan_groups",
                               wraps=grouping_engine.plan_groups) as planned:
            self._ingest([AUTH, LIB])
        self.assertEqual(1, planned.call_count)
        with mock.patch.object(grouping_engine, "plan_groups",
                               wraps=grouping_engine.plan_groups) as planned:
            self._ingest([LIB, AUTH])
        self.assertEqual(2, planned.call_count)


if __name__ == "__main__":
    unittest.main()
