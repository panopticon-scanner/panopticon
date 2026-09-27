"""Catalog, scan brief, spine, and budget construction."""

import json
import os
from unittest import mock


import scripts.coverage_model as coverage_model
import scripts.grouping_engine as grouping_engine
import scripts.setup_flow as setup_flow


from tests.setup_helpers import (
    _repo,
    SetupFixtureBase,
)

def test_committed_matrix_prints_the_symlink_disclosure(tmp_path, capsys):
    # `_committed_matrix` printed doc.ERRORS and returned {} on no document.
    # A refused symlink resolves to no document with no error at all, so the
    # one signal the operator had was never printed and the empty matrix read
    # as "nothing committed" -- `_matrix_catalog` prints disclosures first for
    # exactly this reason.
    (tmp_path / "elsewhere.yml").write_text("version: 1\ngroups: {}\n")
    (tmp_path / "panopticon.yml").symlink_to(tmp_path / "elsewhere.yml")
    assert setup_flow.committed_matrix(str(tmp_path)) == {}
    err = capsys.readouterr().err
    assert "symlink" in err
    assert "panopticon.yml" in err

def test_committed_exclude_paths_prints_the_symlink_disclosure(tmp_path, capsys):
    (tmp_path / "elsewhere.yml").write_text("version: 1\nexclude_paths: ['vendor/**']\n")
    (tmp_path / "panopticon.yml").symlink_to(tmp_path / "elsewhere.yml")
    assert setup_flow._committed_exclude_paths(str(tmp_path)) == []
    err = capsys.readouterr().err
    assert "symlink" in err

class TestSetupFlow(SetupFixtureBase):
    """Catalog, scan brief, spine, and budget construction."""

    def test_committed_matrix_preserves_order(self):
        d = _repo(self, with_committed=True)
        cm = setup_flow.committed_matrix(d)
        self.assertEqual(cm["Checkout"]["match"], ["src/checkout/**"])
        self.assertEqual(cm["Checkout"]["panels"], ["SEC"])

    def test_committed_matrix_keeps_parent_structure(self):
        # 5.2: a #1305 parent must come back as {"subgroups": {...}}, not as an
        # empty leaf that the additive merge would then "extend" into a leaf.
        d = _repo(self)
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups:\n  Checkout:\n    API:\n      match: ['src/checkout/api/**']\n"
                     "      panels: [SEC]\n    Core:\n      match: ['src/checkout/**']\n")
        cm = setup_flow.committed_matrix(d)
        self.assertEqual(list(cm["Checkout"]["subgroups"]), ["API", "Core"])
        self.assertEqual(cm["Checkout"]["subgroups"]["API"]["panels"], ["SEC"])
        self.assertEqual(cm["Checkout"]["subgroups"]["Core"],
                         {"match": ["src/checkout/**"], "tests": [], "panels": [], "exclude": []})
        self.assertNotIn("match", cm["Checkout"])

    def test_scan_brief_includes_vocabulary_hints(self):
        d = _repo(self)
        vocab = {"names": ["Auth"], "hints": {"Auth": ["**/auth/**", "**/login/**"]}}
        path = setup_flow.render_scan_brief(d, vocab)
        with open(path, encoding="utf-8") as fh:
            brief = fh.read()
        self.assertIn("Auth", brief)
        self.assertIn("**/auth/**", brief)  # the hint globs reach the classifier

    def test_the_codex_scan_brief_renders_the_codex_tool_surface(self):
        # #1677: the setup-scan entry is UNREGISTERED, so no
        # `developer_instructions` translates tool names for it -- this brief
        # is the only document telling that agent what it may call, and it
        # promised Read/Grep/Glob to a runner that enables none of them.
        d = _repo(self)
        vocab = {"names": ["Auth"], "hints": {"Auth": ["**/auth/**"]}}
        with open(setup_flow.render_scan_brief(d, vocab, host="codex"),
                  encoding="utf-8") as fh:
            policy = fh.read().split("## Tool policy", 1)[1]
        self.assertIn("panopticon_scope", policy)
        self.assertIn("There is no shell.", policy)
        for absent in ("Read", "Grep", "Glob"):
            self.assertNotIn(absent, policy, absent)

    def test_the_scan_brief_without_a_host_is_unchanged(self):
        d = _repo(self)
        vocab = {"names": ["Auth"], "hints": {"Auth": ["**/auth/**"]}}
        with open(setup_flow.render_scan_brief(d, vocab), encoding="utf-8") as fh:
            policy = fh.read().split("## Tool policy", 1)[1]
        self.assertIn("Your only tools are Read, Grep, Glob.", policy)

    def test_render_capability_catalog_is_full_prose(self):
        # #1500: definition/boundary/aliases/examples/see_also all reach the
        # brief, hints are labelled non-authoritative, entries keep file order.
        vocab = {
            "names": ["Auth", "Checkout"],
            "hints": {"Auth": ["**/auth/**", "**/login/**"]},
            "entries": {
                "Auth": {"definition": "Identity: sign-in, sessions, tokens.",
                         "boundary": "Authorization rules on resources are the owning vertical.",
                         "aliases": ["authentication", "login"],
                         "examples": [{"repo": "authelia", "path": "internal/authentication/"},
                                      {"repo": "gotify", "path": "auth/"}],
                         "see_also": ["Users"]},
                "Checkout": {"definition": "Cart to order."}}}
        text = setup_flow.render_capability_catalog(vocab)
        self.assertEqual(text.split("\n\n")[0], "\n".join([
            "### Auth",
            "Definition: Identity: sign-in, sessions, tokens.",
            "Boundary: Authorization rules on resources are the owning vertical.",
            "Aliases: authentication, login",
            "Hints (non-authoritative): **/auth/**, **/login/**",
            "Examples: authelia `internal/authentication/`; gotify `auth/`",
            "See also: Users"]))
        self.assertEqual(text.split("\n\n")[1], "### Checkout\nDefinition: Cart to order.")
        # the 5.0 shape (names + hints, no entries) still renders
        self.assertEqual(setup_flow.render_capability_catalog(
            {"names": ["Auth"], "hints": {"Auth": ["**/auth/**"]}}),
            "### Auth\nHints (non-authoritative): **/auth/**")
        self.assertEqual(setup_flow.render_capability_catalog({"names": []}),
                         "(no capability catalog bundled)")

    def test_render_layer_catalog_tells_the_agent_when_there_are_no_layers(self):
        self.assertEqual(setup_flow.render_layer_catalog(None),
                         "(no layer catalog bundled -- do not propose `layers`)")
        self.assertEqual(setup_flow.render_layer_catalog({"names": []}),
                         "(no layer catalog bundled -- do not propose `layers`)")
        layers = {"names": ["API"], "hints": {"API": ["**/api/**"]},
                  "entries": {"API": {"definition": "Inbound request handling.",
                                      "aliases": ["controllers", "routes"]}}}
        self.assertEqual(setup_flow.render_layer_catalog(layers), "\n".join([
            "### API", "Definition: Inbound request handling.",
            "Aliases: controllers, routes",
            "Hints (non-authoritative): **/api/**"]))

    def test_load_bundled_layers_present_and_absent(self):
        layers, present = setup_flow.load_bundled_layers()
        self.assertTrue(present)
        self.assertIn("API", layers["names"])
        self.assertIn("definition", layers["entries"]["API"])
        with mock.patch.object(setup_flow, "_LAYERS_PATH", "/nonexistent/layers.yml"):
            self.assertEqual(setup_flow.load_bundled_layers(), ({"names": []}, False))
        d = _repo(self)
        bad = os.path.join(d, "layers.yml")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("layers: [{name: Core}]\n")   # reserved name -> loader error
        self.assertEqual(setup_flow.load_bundled_layers(bad), ({"names": []}, False))

    def test_scan_brief_carries_both_catalogs_and_the_surfaces_enum(self):
        d = _repo(self)
        vocab = {"names": ["Auth"], "hints": {"Auth": ["**/auth/**"]},
                 "entries": {"Auth": {"definition": "Identity: sign-in, sessions, tokens."}}}
        layers = {"names": ["API"], "entries": {"API": {"definition": "Inbound request handling."}}}
        with open(setup_flow.render_scan_brief(d, vocab, layers=layers), encoding="utf-8") as fh:
            brief = fh.read()
        self.assertIn("## Capability catalog", brief)
        self.assertIn("### Auth\nDefinition: Identity: sign-in, sessions, tokens.", brief)
        self.assertIn("## Layer catalog", brief)
        self.assertIn("### API\nDefinition: Inbound request handling.", brief)
        for surface in coverage_model.SURFACES:      # every profile surface is offered
            self.assertIn(surface, brief)
        self.assertIn('"layers"', brief)
        self.assertIn('"profile"', brief)
        self.assertNotIn("{", brief.split("```json")[0])   # no unrendered placeholder before the JSON example
        # layers=None: the brief tells the agent not to propose layers
        with open(setup_flow.render_scan_brief(d, vocab), encoding="utf-8") as fh:
            self.assertIn("do not propose `layers`", fh.read())

    def test_build_spine_tree_languages_frameworks_and_claims(self):
        d = self._spine_repo()
        spine = setup_flow.build_spine(d)
        self.assertEqual(spine["schema_version"], 1)
        # code = total - commons - test tree, over the shipped classifiers.
        # #1681 Task 7 (R12): the committed root `panopticon.yml` is an
        # ordinary repo file (it counts in `total`), and the Commons vocabulary
        # claims it under `Config`, so it falls through to `commons`, not `code`.
        self.assertEqual(spine["files"],
                         {"total": 13, "code": 5, "commons": 6, "test_tree": 2})
        self.assertEqual((spine["cap"], spine["ceiling"], spine["ceiling_source"]),
                         (48, 4, "formula"))
        # depth-2 rows, most files first, ties by path; deeper files roll up
        self.assertEqual(spine["tree"][:3], [
            {"path": ".", "files": 4, "ext": ".json"},   # + panopticon.yml
            {"path": "src/search", "files": 3, "ext": ".go"},
            {"path": "src/checkout", "files": 2, "ext": ".py"}])
        self.assertEqual(spine["tree_more"], 0)
        # languages count CODE files only (tests and commons excluded)
        self.assertEqual(spine["languages"], [{"language": "Go", "files": 3},
                                              {"language": "Python", "files": 2}])
        self.assertEqual(spine["manifests"], ["package.json", "pyproject.toml"])
        self.assertEqual(spine["frameworks"], ["Django", "React"])
        # committed groups claim first; Commons is counted on the leftovers
        self.assertEqual(spine["claimed"]["committed"], {"Checkout": 2})
        self.assertEqual(spine["claimed"]["commons"],
                         {"Build": 2, "CI": 1, "Config": 1, "Docs": 2})
        self.assertEqual(spine["test_trees"], [{"path": "tests/checkout", "files": 1},
                                               {"path": "tests/search", "files": 1}])
        json.dumps(spine)                                  # serializable

    def test_build_spine_size_precedence_matches_ingest(self):
        d = self._spine_repo()
        # max_per_group: 2 is below the 8-48 band (#1681 Plan 2): the spine
        # sees the clamped 8, the same number a run would apply.
        self._settings(d, "settings:\n  max_per_group: 2\n  max_groups: 6\n")
        spine = setup_flow.build_spine(d)
        self.assertEqual((spine["cap"], spine["ceiling"], spine["ceiling_source"]),
                         (8, 6, "config"))
        spine = setup_flow.build_spine(d, max_per_group=3, max_groups=9)
        self.assertEqual((spine["cap"], spine["ceiling"], spine["ceiling_source"]),
                         (3, 9, "cli"))
        self._settings(d, "")
        spine = setup_flow.build_spine(d, max_per_group=2)
        # 5 code files at cap 2 -> max(4, 2 * ceil(5 / 2)) = 6
        self.assertEqual((spine["cap"], spine["ceiling"], spine["ceiling_source"]),
                         (2, 6, "formula"))

    def test_build_spine_rows_are_bounded_and_sanitized(self):
        d = _repo(self)
        files = ["pkg%03d/mod.py" % i for i in range(90)] + ["evil` dir/x.py"]
        spine = setup_flow.build_spine(d, files=files)
        self.assertEqual(len(spine["tree"]), setup_flow._MAX_TREE_ROWS)
        self.assertEqual(spine["tree_more"], 91 - setup_flow._MAX_TREE_ROWS)
        # the odd name sorts first (1 file each, ties by path) and is neutralised:
        # backtick stripped, the whitespace survivor repr()-quoted (#1120)
        self.assertEqual(spine["tree"][0]["path"], "'evil dir'")
        self.assertNotIn("`", json.dumps(spine))
        self.assertEqual(spine["claimed"], {"committed": {}, "commons": {}, "groups_yml": False})

    def test_spine_lists_every_committed_leaf_and_says_why_nothing_is_claimed(self):
        # A committed group whose globs match nothing today still appears (as
        # 0) -- the agent must not re-propose it -- and the "nothing claimed"
        # wording distinguishes no committed config from one without match: globs.
        d = self._spine_repo()
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups:\n  Checkout:\n    match: ['src/checkout/**']\n"
                     "  Legacy:\n    match: ['src/gone/**']\n")
        spine = setup_flow.build_spine(d)
        self.assertEqual(spine["claimed"]["committed"], {"Checkout": 2, "Legacy": 0})
        self.assertTrue(spine["claimed"]["groups_yml"])
        text = setup_flow.format_spine(spine)
        self.assertIn("    Legacy                                       0", text)
        self.assertIn("0 = its globs match nothing today", text)
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups:\n  Checkout: [src/checkout/pay.py]\n")
        spine = setup_flow.build_spine(d)
        self.assertEqual(spine["claimed"]["committed"], {"Checkout": 0})
        os.remove(os.path.join(d, "panopticon.yml"))
        spine = setup_flow.build_spine(d)
        self.assertEqual(spine["claimed"]["committed"], {})
        self.assertFalse(spine["claimed"]["groups_yml"])
        self.assertIn("nothing (no committed config)", setup_flow.format_spine(spine))
        self.assertIn("nothing (it has no match: globs)",
                      setup_flow.format_spine(dict(spine, claimed={
                          "committed": {}, "commons": {}, "groups_yml": True})))

    def test_budget_quotes_the_engine_floor_and_min_ceiling(self):
        d = self._spine_repo()
        budget = setup_flow.format_budget(setup_flow.build_spine(d))
        self.assertIn("a layer under %d files merges back" % grouping_engine.FLOOR, budget)
        self.assertIn("= max(%d, 2 * ceil(code_files / cap))" % grouping_engine.MIN_CEILING,
                      budget)

    def test_format_spine_and_budget_render_the_brief_sections(self):
        d = self._spine_repo()
        spine = setup_flow.build_spine(d, max_groups=5)
        text = setup_flow.format_spine(spine)
        self.assertIn("src/search                                   3  .go", text)
        self.assertIn("Languages (code files): Go (3), Python (2)", text)
        self.assertIn("Frameworks (from manifests): Django, React", text)
        self.assertIn("Already claimed by the committed root config", text)
        self.assertIn("    Checkout                                     2", text)
        self.assertIn("Claimed by the Commons classifier", text)
        self.assertIn("the Tests sweep will catch these", text)
        self.assertIn("    tests/search                                 1", text)
        budget = setup_flow.format_budget(spine)
        self.assertIn("- files: 13 total = 5 code + 6 commons + 2 test tree", budget)
        self.assertIn("--max-per-group): 48", budget)
        self.assertIn("ceiling (CODE review groups this repo affords): 5 from --max-groups", budget)
        self.assertIn("propose `layers` ONLY for a vertical you estimate OVER the cap (48 files)",
                      budget)
        # #1506: the ceiling budgets CODE leaves. Saying so in the brief is the
        # difference between an agent proposing the verticals the repo affords
        # and one holding back to leave room for Tests and Commons -- leaves it
        # does not control and that are not charged to this number.
        self.assertIn("`Tests` and the Commons categories are formed by the engine "
                      "and are not counted against it", budget)
        self.assertNotIn("{", text + budget)     # nothing left for render_prompt to choke on

    def test_write_and_read_spine_round_trip(self):
        d = self._spine_repo()
        self.assertIsNone(setup_flow.read_spine(d))
        spine = setup_flow.build_spine(d)
        path = setup_flow.write_spine(d, spine)
        self.assertEqual(os.path.basename(path), "setup-spine.json")
        self.assertEqual(setup_flow.read_spine(d), spine)
        with open(path, "w") as fh:
            fh.write("[]")
        self.assertIsNone(setup_flow.read_spine(d))          # not a v1 mapping
        with open(path, "w") as fh:
            fh.write("{not json")
        self.assertIsNone(setup_flow.read_spine(d))

    def test_scan_brief_renders_the_spine_and_the_budget(self):
        d = self._spine_repo()
        vocab = {"names": ["Auth"], "hints": {"Auth": ["**/auth/**"]}}
        path = setup_flow.render_scan_brief(d, vocab, spine=setup_flow.build_spine(d, max_groups=7))
        with open(path, encoding="utf-8") as fh:
            brief = fh.read()
        self.assertIn("## Repository spine", brief)
        self.assertIn("src/search                                   3  .go", brief)
        self.assertIn("## Size arithmetic", brief)
        self.assertIn("ceiling (CODE review groups this repo affords): 7 from --max-groups", brief)
        # a brief with no spine argument builds one with the default sizes
        path = setup_flow.render_scan_brief(d, vocab)
        with open(path, encoding="utf-8") as fh:
            self.assertIn("--max-per-group): 48", fh.read())

    def test_sanitize_spine_token_neutralizes_adversarial_input(self):
        # #run7 TST-A2D: _sanitize_spine_token (#1120 prompt-injection defense for
        # untrusted repo dir names embedded in the scan brief) had NO adversarial
        # coverage. Lock the invariants: control chars + backticks are stripped;
        # whitespace/quote survivors are repr()-escaped so a crafted dir name
        # can't break out of its brief line.
        san = setup_flow._sanitize_spine_token
        self.assertEqual(san("ab`c"), "abc")                 # backtick stripped
        self.assertNotIn("`", san("`rm -rf /`"))
        self.assertEqual(san("a\x00b\x1fc\x7f"), "abc")      # control bytes stripped
        self.assertNotIn("\n", san("line1\nIGNORE PREVIOUS"))  # newline stripped
        self.assertNotIn("\t", san("a\tb"))
        self.assertEqual(san("two words"), repr("two words"))  # space -> repr()
        self.assertEqual(san('say "hi"'), repr('say "hi"'))    # quotes -> repr()
        self.assertEqual(san("it's"), repr("it's"))
        self.assertEqual(san("src"), "src")                  # clean token untouched

