import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.coverage_model as coverage_model
import scripts.grouping_engine as grouping_engine
import scripts.setup_flow as setup_flow
import shutil


def _repo(test_case, with_committed=False):
    d = os.path.realpath(tempfile.mkdtemp())
    os.makedirs(os.path.join(d, "src", "checkout"))
    with open(os.path.join(d, "src", "checkout", "pay.py"), "w") as fh:
        fh.write("x = 1\n")
    os.makedirs(os.path.join(d, ".panopticon"))
    test_case.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
    if with_committed:
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n")
    return d


def test_check_groups_manifest_reports_corrupt_yaml(tmp_path):
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text("not: [valid yaml: [")
    name, ok, detail = setup_flow._check_groups_manifest(str(tmp_path))
    assert name == "groups-manifest"
    assert ok is False
    assert "corrupt" in detail.lower() or "parse" in detail.lower()


class TestSetupFlow(unittest.TestCase):
    def _gitignore(self, repo):
        with open(os.path.join(repo, ".gitignore"), encoding="utf-8") as fh:
            return fh.read()

    def test_provision_seeds_gitignore_and_config(self):
        d = _repo(self)
        res = setup_flow.provision(d)
        cfg_path = os.path.join(d, ".panopticon", "config.json")
        self.assertTrue(os.path.isfile(cfg_path))
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            self.assertIn(".panopticon/*", fh.read())
        self.assertTrue(res["config_created"])
        # #run7 TST-B1C: assert the seeded CONTENT, not just existence -- the
        # gh_config_dir=null (inherit-ambient) default is the contract driver
        # reads, and a regression to the wrong shape would pass an existence-only
        # check.
        with open(cfg_path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), {"gh_config_dir": None})

    def test_provision_leaves_blanket_panopticon_ignore_untouched(self):
        # #1135: a repo that already blanket-ignores .panopticon/ must NOT have
        # its .gitignore rewritten -- no in-place migration to .panopticon/*, no
        # !.panopticon/ re-exposing the directory.
        d = _repo(self)
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write("node_modules/\n.panopticon/\n")
        res = setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertIn(".panopticon/", gi)
        self.assertNotIn(".panopticon/*", gi)   # not migrated
        self.assertNotIn("!.panopticon/", gi)   # dir not re-exposed
        self.assertFalse(res["groups_yml_committable"])
        self.assertIn("git add -f", res.get("gitignore_note", ""))

    def test_provision_fresh_repo_adds_committable_block(self):
        d = _repo(self)  # no .gitignore
        res = setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertIn(".panopticon/*", gi)
        self.assertIn("!.panopticon/groups.yml", gi)
        self.assertTrue(res["groups_yml_committable"])

    def test_provision_appends_negations_to_star_form(self):
        # .panopticon/* already present (committable-compatible), negations
        # missing -> append them (pure append), never rewrite the existing line.
        d = _repo(self)
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write(".panopticon/*\n")
        res = setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertEqual(gi.count(".panopticon/*"), 1)   # not duplicated
        self.assertIn("!.panopticon/groups.yml", gi)
        self.assertTrue(res["groups_yml_committable"])

    def test_provision_gitignore_idempotent_second_run_noop(self):
        d = _repo(self)
        setup_flow.provision(d)
        after_first = self._gitignore(d)
        res2 = setup_flow.provision(d)
        self.assertEqual(res2["gitignore_added"], [])
        self.assertEqual(self._gitignore(d), after_first)   # byte-identical

    def test_committed_matrix_preserves_order(self):
        d = _repo(self, with_committed=True)
        cm = setup_flow.committed_matrix(d)
        self.assertEqual(cm["Checkout"]["match"], ["src/checkout/**"])
        self.assertEqual(cm["Checkout"]["panels"], ["SEC"])

    def test_committed_matrix_keeps_parent_structure(self):
        # 5.2: a #1305 parent must come back as {"subgroups": {...}}, not as an
        # empty leaf that the additive merge would then "extend" into a leaf.
        d = _repo(self)
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Checkout:\n    API:\n      match: ['src/checkout/api/**']\n"
                     "      panels: [SEC]\n    Core:\n      match: ['src/checkout/**']\n")
        cm = setup_flow.committed_matrix(d)
        self.assertEqual(list(cm["Checkout"]["subgroups"]), ["API", "Core"])
        self.assertEqual(cm["Checkout"]["subgroups"]["API"]["panels"], ["SEC"])
        self.assertEqual(cm["Checkout"]["subgroups"]["Core"],
                         {"match": ["src/checkout/**"], "tests": [], "panels": [], "exclude": []})
        self.assertNotIn("match", cm["Checkout"])

    def test_ingest_never_flattens_a_committed_parent(self):
        d = _repo(self)
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Checkout:\n    API:\n      match: ['src/checkout/api/**']\n"
                     "    Core:\n      match: ['src/checkout/**']\n")
        os.makedirs(os.path.join(d, "src", "search"))
        with open(os.path.join(d, "src", "search", "q.py"), "w") as fh:
            fh.write("y = 2\n")
        proposal = {"groups": [
            {"capability": "Checkout", "match": ["src/checkout/**", "src/pay/**"]},
            {"capability": "Search", "match": ["src/search/**"]}]}
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump(proposal, fh)
        res = setup_flow.ingest_proposal(d, pp)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["diff"]["dropped_redundant"], ["Checkout"])   # claims nothing new
        self.assertEqual([g["name"] for g in res["diff"]["new_groups"]], ["Search"])
        import yaml as _yaml
        with open(res["draft"], encoding="utf-8") as fh:
            drafted = _yaml.safe_load(fh)["groups"]
        self.assertEqual(list(drafted["Checkout"]), ["API", "Core"])     # parent intact
        self.assertEqual(drafted["Search"]["match"], ["src/search/**"])

    def test_ingest_writes_draft_with_affinity_floor(self):
        d = _repo(self)
        proposal = {"groups": [{"capability": "Checkout",
                                "match": ["src/checkout/**"], "tests": []}]}
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump(proposal, fh)
        res = setup_flow.ingest_proposal(d, pp)
        self.assertTrue(res["ok"])
        draft = os.path.join(d, ".panopticon", "groups.yml.draft")
        self.assertTrue(os.path.isfile(draft))
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml")))
        # #run7 TST-B1A: assert the affinity FLOOR the test is named for actually
        # lands in the draft -- Checkout -> [SEC, ACC] per capability_affinity.yml.
        # The old test checked only ok/draft-exists, so an empty-panels regression
        # (the exact failure the setup-scan floor guards against) stayed green.
        import yaml as _yaml
        with open(draft, encoding="utf-8") as fh:
            drafted = _yaml.safe_load(fh)
        self.assertEqual(drafted["groups"]["Checkout"]["panels"], ["SEC", "ACC"])
        floor_sources = {g["name"]: g["floor_source"]
                         for g in res["disclosure"]["groups"]}
        self.assertEqual(floor_sources["Checkout"], "affinity")

    def test_ingest_malformed_proposal_fails_no_draft(self):
        d = _repo(self)
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump({"groups": [{"capability": "", "match": []}]}, fh)
        res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertTrue(res["errors"])
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_ingest_missing_proposal_fails_no_draft(self):
        d = _repo(self)
        res = setup_flow.ingest_proposal(d, os.path.join(d, ".panopticon", "nope.json"))
        self.assertFalse(res["ok"])
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_ingest_oversized_proposal_refused(self):
        # #1107: a target-shipped proposal over the byte cap is refused before parse
        d = _repo(self)
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            fh.write("[" + "0," * 600000 + "0]")   # > 1 MiB of JSON
        res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertTrue(any("exceeds" in e for e in res["errors"]))
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_ingest_cap_bounds_the_read_not_a_prior_stat(self):
        # #run10 COD-F1B: the cap was os.path.getsize() followed by a SEPARATE
        # unbounded open()+json.load(), so the bytes actually read were never
        # bounded -- a stat that under-reports (or a file that grows between the
        # two calls) got slurped whole. Prove the bound is on the READ: a stat
        # that lies about the size must not buy an unbounded read.
        d = _repo(self)
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            fh.write("[" + "0," * 600000 + "0]")       # > 1 MiB on disk
        with mock.patch("scripts.setup_flow.os.path.getsize", return_value=10):
            res = setup_flow.ingest_proposal(d, pp)    # stat says "tiny"
        self.assertFalse(res["ok"])                    # still refused, on read size
        self.assertTrue(any("exceeds" in e for e in res["errors"]))

    def test_ingest_accepts_a_proposal_under_the_cap(self):
        # The bounded read must not truncate a legitimate proposal.
        d = _repo(self)
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump({"groups": [{"capability": "Auth", "match": ["src/auth/**"]}]}, fh)
        res = setup_flow.ingest_proposal(d, pp)
        self.assertTrue(res["ok"], res.get("errors"))

    def test_scan_brief_includes_vocabulary_hints(self):
        d = _repo(self)
        vocab = {"names": ["Auth"], "hints": {"Auth": ["**/auth/**", "**/login/**"]}}
        path = setup_flow.render_scan_brief(d, vocab)
        with open(path, encoding="utf-8") as fh:
            brief = fh.read()
        self.assertIn("Auth", brief)
        self.assertIn("**/auth/**", brief)  # the hint globs reach the classifier

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

    def _spine_repo(self):
        # A small polyglot repo: a committed vertical, a second unclaimed one,
        # docs/CI/manifests for Commons, two test trees, two manifests that
        # name frameworks. Non-git, so discovery walks the tree.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        files = {
            "src/checkout/pay.py": "x = 1\n",
            "src/checkout/api/routes.py": "x = 1\n",
            "src/search/a.go": "package s\n",
            "src/search/b.go": "package s\n",
            "src/search/deep/c.go": "package s\n",
            "docs/guide.md": "# g\n",
            "README.md": "# r\n",
            ".github/workflows/ci.yml": "on: push\n",
            "tests/checkout/test_pay.py": "def test(): pass\n",
            "tests/search/search_test.go": "package s\n",
            "package.json": '{"dependencies": {"react": "18"}}\n',
            "pyproject.toml": "[project]\ndependencies = ['django']\n",
        }
        for rel, body in files.items():
            os.makedirs(os.path.join(d, os.path.dirname(rel)) or d, exist_ok=True)
            with open(os.path.join(d, rel), "w") as fh:
                fh.write(body)
        os.makedirs(os.path.join(d, ".panopticon"))
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n")
        return d

    def test_build_spine_tree_languages_frameworks_and_claims(self):
        d = self._spine_repo()
        spine = setup_flow.build_spine(d)
        self.assertEqual(spine["schema_version"], 1)
        # code = total - commons - test tree, over the shipped classifiers
        self.assertEqual(spine["files"],
                         {"total": 12, "code": 5, "commons": 5, "test_tree": 2})
        self.assertEqual((spine["cap"], spine["ceiling"], spine["ceiling_source"]),
                         (48, 4, "formula"))
        # depth-2 rows, most files first, ties by path; deeper files roll up
        self.assertEqual(spine["tree"][:3], [
            {"path": ".", "files": 3, "ext": ".json"},
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
        self.assertEqual(spine["claimed"]["commons"], {"Build": 2, "CI": 1, "Docs": 2})
        self.assertEqual(spine["test_trees"], [{"path": "tests/checkout", "files": 1},
                                               {"path": "tests/search", "files": 1}])
        json.dumps(spine)                                  # serializable

    def test_build_spine_size_precedence_matches_ingest(self):
        d = self._spine_repo()
        with open(os.path.join(d, ".panopticon", "config.json"), "w") as fh:
            json.dump({"max_per_group": 2, "max_groups": 6}, fh)
        spine = setup_flow.build_spine(d)
        self.assertEqual((spine["cap"], spine["ceiling"], spine["ceiling_source"]),
                         (2, 6, "config"))
        spine = setup_flow.build_spine(d, max_per_group=3, max_groups=9)
        self.assertEqual((spine["cap"], spine["ceiling"], spine["ceiling_source"]),
                         (3, 9, "cli"))
        os.remove(os.path.join(d, ".panopticon", "config.json"))
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
        # wording distinguishes no groups.yml from one without match: globs.
        d = self._spine_repo()
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Checkout:\n    match: ['src/checkout/**']\n"
                     "  Legacy:\n    match: ['src/gone/**']\n")
        spine = setup_flow.build_spine(d)
        self.assertEqual(spine["claimed"]["committed"], {"Checkout": 2, "Legacy": 0})
        self.assertTrue(spine["claimed"]["groups_yml"])
        text = setup_flow.format_spine(spine)
        self.assertIn("    Legacy                                       0", text)
        self.assertIn("0 = its globs match nothing today", text)
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Checkout: [src/checkout/pay.py]\n")
        spine = setup_flow.build_spine(d)
        self.assertEqual(spine["claimed"]["committed"], {"Checkout": 0})
        os.remove(os.path.join(d, ".panopticon", "groups.yml"))
        spine = setup_flow.build_spine(d)
        self.assertEqual(spine["claimed"]["committed"], {})
        self.assertFalse(spine["claimed"]["groups_yml"])
        self.assertIn("nothing (no groups.yml)", setup_flow.format_spine(spine))
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
        self.assertIn("Already claimed by the committed groups.yml", text)
        self.assertIn("    Checkout                                     2", text)
        self.assertIn("Claimed by the Commons classifier", text)
        self.assertIn("the Tests sweep will catch these", text)
        self.assertIn("    tests/search                                 1", text)
        budget = setup_flow.format_budget(spine)
        self.assertIn("- files: 12 total = 5 code + 5 commons + 2 test tree", budget)
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

    def test_readiness_returns_checks(self):
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        checks = setup_flow.readiness(d, host="claude",
                                      runner=lambda *a, **k: type("R", (), {"returncode": 1})())
        check_dict = {c[0]: (c[1], c[2]) for c in checks}
        self.assertIn("target-root", check_dict)
        self.assertTrue(check_dict["target-root"][0])

    def test_readiness_checks_driver_roles_not_legacy(self):
        # #5.0-15: enforced-shells must verify the driver's scout/domain_panel/
        # domain_advisor shells, NOT the retired panel_review/lens_sweep.
        import dispatch
        d = _repo(self)
        with mock.patch.object(dispatch, "_is_registered", return_value=False):
            checks = setup_flow.readiness(
                d, host="claude",
                runner=lambda *a, **k: type("R", (), {"returncode": 0})())
        es = next(c for c in checks if c[0] == "enforced-shells")
        self.assertFalse(es[1])                       # unregistered -> not ok
        for role in ("scout", "domain_panel", "domain_advisor"):
            self.assertIn(role, es[2])
        self.assertNotIn("panel_review", es[2])
        self.assertNotIn("lens_sweep", es[2])

    def test_readiness_generic_host_enforced_shells_informational(self):
        # #5.0-15: the generic host runs unenforced -> informational (None), not FAIL.
        d = _repo(self)
        checks = setup_flow.readiness(
            d, host="generic",
            runner=lambda *a, **k: type("R", (), {"returncode": 0})())
        es = next(c for c in checks if c[0] == "enforced-shells")
        self.assertIsNone(es[1])

    def test_readiness_probes_carry_timeout(self):
        # #1106: every docker/codex readiness probe must be bounded.
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        seen = []
        def runner(cmd, **kw):
            seen.append(kw.get("timeout"))
            return type("R", (), {"returncode": 0})()
        setup_flow.readiness(d, host="codex", runner=runner)  # docker + codex probes
        self.assertTrue(seen)
        self.assertTrue(all(t == setup_flow._PROBE_TIMEOUT for t in seen), seen)

    def test_readiness_hung_probe_is_failed_check_not_crash(self):
        # A probe that times out (or a missing binary) becomes a failed check,
        # never an unhandled exception that freezes the preflight (#1106).
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        def runner(cmd, **kw):
            raise setup_flow.subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        checks = {c[0]: c[1] for c in setup_flow.readiness(
            d, host="claude", runner=runner)}
        self.assertFalse(checks["docker"])

    def test_readiness_docker_ok_but_tools_image_absent(self):
        # #run7 TST-A2F: the common "Docker installed but the panopticon-tools
        # image isn't built" state (docker ok, tools-image absent) had no
        # coverage -- every prior runner returned one fixed rc for all commands.
        d = _repo(self)
        os.makedirs(os.path.join(d, ".git"))
        def runner(cmd, **kw):
            rc = 1 if cmd[:3] == ["docker", "image", "inspect"] else 0
            return type("R", (), {"returncode": rc})()
        checks = {c[0]: (c[1], c[2]) for c in setup_flow.readiness(
            d, host="generic", runner=runner)}
        self.assertTrue(checks["docker"][0])
        self.assertFalse(checks["tools-image"][0])
        self.assertIn("image absent", checks["tools-image"][1])

    def test_readiness_driver_roles_parity_guard_trips_on_drift(self):
        # #run7 ARC-A4C: _driver_roles is a hand-maintained shadow of the active
        # dispatch.ROLE_FILES roles. If a role is renamed/removed there, readiness
        # must fail loudly rather than silently drop that shell from the check.
        import dispatch
        d = _repo(self)
        shrunk = {k: v for k, v in dispatch.ROLE_FILES.items()
                  if k != "domain_advisor"}
        with mock.patch.object(dispatch, "ROLE_FILES", shrunk):
            with self.assertRaises(RuntimeError):
                setup_flow.readiness(
                    d, host="claude",
                    runner=lambda *a, **k: type("R", (), {"returncode": 0})())

    def test_ingest_missing_bundled_data_fails_no_draft(self):
        # #run7 TST-A2B: the bundled-vocabulary-missing branch (a broken install)
        # was unreachable in tests -- drive it via a bogus data path.
        d = _repo(self)
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/**"]}]}, fh)
        with mock.patch.object(setup_flow, "_VOCAB_PATH", "/nonexistent/vocab.yml"):
            res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertTrue(any("missing" in e for e in res["errors"]))
        self.assertFalse(os.path.isfile(
            os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_ingest_malformed_bundled_vocab_fails_no_draft(self):
        # #run7 TST-A2B: the vocab/affinity load-error branch (verr/aerr) -- a
        # present-but-corrupt bundle must fail loudly with a data error, no draft.
        d = _repo(self)
        bad = os.path.join(d, "bad_vocab.yml")
        with open(bad, "w") as fh:
            fh.write("capabilities: not-a-list\n")   # load_vocabulary -> error
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/**"]}]}, fh)
        with mock.patch.object(setup_flow, "_VOCAB_PATH", bad):
            res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertTrue(any("data error" in e for e in res["errors"]))
        self.assertFalse(os.path.isfile(
            os.path.join(d, ".panopticon", "groups.yml.draft")))

    def test_provision_treats_globstar_panopticon_ignore_as_blanket(self):
        # #run7 ARC-A2B: a `**/`-prefixed blanket ignore also excludes the
        # .panopticon directory, so git can't re-include groups.yml out of it.
        # Provision must leave it untouched (not append a committable block that
        # can't take effect) and report groups.yml not committable.
        d = _repo(self)
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write("node_modules/\n**/.panopticon/\n")
        res = setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertNotIn(".panopticon/*", gi)   # not migrated
        self.assertNotIn("!.panopticon/", gi)   # dir not re-exposed
        self.assertFalse(res["groups_yml_committable"])


    # --- 5.2 stage 3 wiring: size policy, layers, the setup report -----------

    def _write_proposal(self, d, proposal):
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump(proposal, fh)
        return pp

    def test_config_overrides_honour_positive_ints_only(self):
        d = _repo(self)
        self.assertEqual(setup_flow.config_overrides(d),
                         {"max_per_group": None, "max_groups": None})
        with open(os.path.join(d, ".panopticon", "config.json"), "w") as fh:
            json.dump({"max_per_group": 32, "max_groups": "8"}, fh)
        self.assertEqual(setup_flow.config_overrides(d),
                         {"max_per_group": 32, "max_groups": None})
        with open(os.path.join(d, ".panopticon", "config.json"), "w") as fh:
            json.dump({"max_per_group": True, "max_groups": 0}, fh)
        self.assertEqual(setup_flow.config_overrides(d),
                         {"max_per_group": None, "max_groups": None})
        with open(os.path.join(d, ".panopticon", "config.json"), "w") as fh:
            fh.write("not json")
        self.assertEqual(setup_flow.config_overrides(d),
                         {"max_per_group": None, "max_groups": None})

    def test_ingest_writes_the_report_and_resolves_cap_cli_over_config(self):
        d = _repo(self)
        with open(os.path.join(d, ".panopticon", "config.json"), "w") as fh:
            json.dump({"max_per_group": 2, "max_groups": 6}, fh)
        pp = self._write_proposal(d, {"groups": [{"capability": "Checkout",
                                                  "match": ["src/checkout/**"], "tests": []}]})
        res = setup_flow.ingest_proposal(d, pp)
        self.assertTrue(res["ok"], res)
        self.assertEqual((res["report"]["cap"], res["report"]["ceiling"]), (2, 6))
        self.assertEqual(res["report_path"], os.path.join(d, ".panopticon", "setup-report.md"))
        with open(res["report_path"], encoding="utf-8") as fh:
            text = fh.read()
        self.assertTrue(text.startswith("# Setup report\n"))
        self.assertIn("| Checkout | vertical | 1 | 1 |", text)
        with open(os.path.join(d, ".panopticon", "setup-report.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(sorted(doc), ["diff", "disclosure", "report", "schema_version"])
        self.assertEqual(doc["report"], res["report"])
        self.assertEqual(doc["diff"], res["diff"])
        # CLI beats config; an explicit ceiling beats config too
        res = setup_flow.ingest_proposal(d, pp, max_per_group=3, max_groups=9)
        self.assertEqual((res["report"]["cap"], res["report"]["ceiling"]), (3, 9))

    def test_ingest_layers_a_new_vertical_over_the_cap_into_the_draft(self):
        # 12 files, cap 8: the proposed API layer (6) and the residual Core (6)
        # both clear the floor, so the draft carries Checkout as a parent.
        d = _repo(self)
        for sub in ("api", "core"):
            os.makedirs(os.path.join(d, "src", "checkout", sub), exist_ok=True)
            for i in range(6):
                with open(os.path.join(d, "src", "checkout", sub, "f%d.py" % i), "w") as fh:
                    fh.write("x = %d\n" % i)
        os.remove(os.path.join(d, "src", "checkout", "pay.py"))
        pp = self._write_proposal(d, {"groups": [{
            "capability": "Checkout", "match": ["src/checkout/**"], "tests": [],
            "layers": [{"layer": "API", "match": ["src/checkout/api/**"]}]}]})
        res = setup_flow.ingest_proposal(d, pp, max_per_group=8)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["diff"]["new_groups"][0]["subgroups"], ["API", "Core"])
        import yaml as _yaml
        with open(res["draft"], encoding="utf-8") as fh:
            drafted = _yaml.safe_load(fh)["groups"]
        self.assertEqual(list(drafted["Checkout"]), ["API", "Core"])
        self.assertEqual(drafted["Checkout"]["API"]["match"], ["src/checkout/api/**"])
        self.assertEqual(drafted["Checkout"]["Core"]["match"],
                         ["src/checkout/**", "!src/checkout/api/**"])
        self.assertEqual(drafted["Checkout"]["API"]["panels"], ["SEC", "ACC"])   # floor rides
        self.assertIn("- Checkout: API (6), Core (6, carrier)", open(res["report_path"]).read())

    def test_ingest_missing_layer_catalog_fails_no_draft(self):
        d = _repo(self)
        pp = self._write_proposal(d, {"groups": [{"capability": "Checkout",
                                                  "match": ["src/checkout/**"], "tests": []}]})
        with mock.patch.object(setup_flow, "_LAYERS_PATH", os.path.join(d, "nope.yml")):
            res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertIn("layer data is missing", res["errors"][0])
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml.draft")))
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "setup-report.md")))


class TestSeedGroupsManifestInjection(unittest.TestCase):
    """#1108: hostile top-level directory names must not inject YAML structure
    into the seeded groups.yml -- the seeder validates via the schema and
    serializes with yaml.safe_dump instead of hand-formatting untrusted text."""

    def test_injection_dir_names_are_dropped_and_file_parses(self):
        import yaml as _yaml
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        # a benign dir plus two hostile top-level names: a YAML metacharacter
        # (':') and an embedded newline -- both legal on POSIX, both would break
        # or inject under naive "%s:" text-templating.
        for sub, fname in (("app", "main.py"), ("ev:il", "f.py"), ("ev\nil", "g.py")):
            os.makedirs(os.path.join(d, sub))
            with open(os.path.join(d, sub, fname), "w") as fh:
                fh.write("x = 1\n")
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        path, created, names = setup_flow._seed_groups_manifest(d)
        self.assertTrue(created)
        with open(path, encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh.read())          # parses cleanly -> no injection
        self.assertEqual(set(doc["groups"]), {"app"})  # hostile names dropped
        self.assertEqual(doc["groups"]["app"]["match"], ["app/**"])
        self.assertEqual(names, ["app"])

    def test_atomic_create_never_clobbers_a_racing_manifest(self):
        # #run7 COD-F1B: the top-of-function isfile() guard is a fast path, not a
        # lock. If a manifest appears AFTER that check (a concurrent seed), the
        # O_EXCL create must refuse to truncate it -- created=False, bytes intact.
        # Simulate the race by masking ONLY the manifest path on the fast-path
        # check so execution falls through to the atomic create against a file
        # that already exists on disk.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "app"))
        with open(os.path.join(d, "app", "main.py"), "w") as fh:
            fh.write("x = 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        path = os.path.join(d, ".panopticon", "groups.yml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("groups:\n  Winner:\n    match: ['src/**']\n")
        real_isfile = os.path.isfile
        target = os.path.realpath(path)
        def masked(p):
            return False if os.path.realpath(p) == target else real_isfile(p)
        with mock.patch("os.path.isfile", side_effect=masked):
            _p, created, _names = setup_flow._seed_groups_manifest(d)
        self.assertFalse(created)
        with open(path, encoding="utf-8") as fh:
            self.assertIn("Winner", fh.read())   # existing manifest not clobbered


if __name__ == "__main__":
    unittest.main()


def _git_repo(test_case, gitignore):
    """A real git checkout whose .gitignore is exactly `gitignore`."""
    import subprocess
    d = _repo(test_case)
    for argv in (["init", "-q"], ["config", "user.name", "T"],
                 ["config", "user.email", "t@example.com"]):
        subprocess.run(["git", "-C", d] + argv, check=True,
                       capture_output=True)
    with open(os.path.join(d, ".gitignore"), "w") as fh:
        fh.write(gitignore)
    subprocess.run(["git", "-C", d, "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", d, "commit", "-qm", "init"], check=True,
                   capture_output=True)
    return d


def _status(repo):
    import subprocess
    return subprocess.run(["git", "-C", repo, "status", "--porcelain"],
                          capture_output=True, text=True).stdout


class TestGlobFormBlanketIgnore(unittest.TestCase):
    """#1509: this repo's own .gitignore blanket-ignores the directory with the
    GLOB form `.panopticon*/` -- deliberately, so a preserved run renamed
    `.panopticon.prev-<stamp>` stays ignored. `_PANOPTICON_DIR_BLANKET` knew
    only the literal spellings, so setup read the repo as un-blanketed, appended
    the committable block, and its `!.panopticon/` negations then RE-EXPOSED
    groups.yml. That is the #1135 failure mode recurring for a new spelling --
    and it silently flipped the repo's policy from "groups.yml is local" to
    "groups.yml is committable" without being asked.
    """

    def test_glob_form_blanket_is_left_untouched(self):
        d = _git_repo(self, "node_modules/\n.panopticon*/\n")
        res = setup_flow.provision(d)
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            gi = fh.read()
        self.assertNotIn(".panopticon/*", gi)      # no committable block
        self.assertNotIn("!.panopticon/", gi)      # directory not re-exposed
        self.assertFalse(res["groups_yml_committable"])

    def test_setup_leaves_a_glob_blanketed_tree_clean(self):
        # The first thing a new adopter sees after `driver setup` must not be an
        # unexplained diff in a file they did not touch -- and a self-scan run
        # straight after setup would start on a dirty tree, which validate reads
        # as a tamper signal.
        d = _git_repo(self, "node_modules/\n.panopticon*/\n"
                            ".claude/settings.local.json\n")
        setup_flow.provision(d)
        self.assertEqual(_status(d), "")

    def test_the_literal_form_still_behaves_as_before(self):
        d = _git_repo(self, ".panopticon/\n.claude/settings.local.json\n")
        res = setup_flow.provision(d)
        self.assertEqual(_status(d), "")
        self.assertFalse(res["groups_yml_committable"])

    def test_a_committable_form_repo_still_gets_its_negations(self):
        # `.panopticon/*` ignores the CONTENTS, not the directory, so a negation
        # can still re-include groups.yml -- this form must keep working.
        d = _git_repo(self, ".panopticon/*\n")
        res = setup_flow.provision(d)
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            gi = fh.read()
        self.assertIn("!.panopticon/groups.yml", gi)
        self.assertTrue(res["groups_yml_committable"])

    def test_a_fresh_git_repo_still_gets_the_full_block(self):
        d = _git_repo(self, "node_modules/\n")
        res = setup_flow.provision(d)
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            gi = fh.read()
        self.assertIn(".panopticon/*", gi)
        self.assertTrue(res["groups_yml_committable"])

    def test_glob_form_is_recognised_without_git(self):
        # Not every target is a checkout; the pattern fallback must know the
        # same spellings git does, or a non-git tree regresses to the bug.
        d = _repo(self)
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write(".panopticon*/\n")
        res = setup_flow.provision(d)
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            gi = fh.read()
        self.assertNotIn("!.panopticon/", gi)
        self.assertFalse(res["groups_yml_committable"])


class TestDraftPreservesTopLevelKeys(unittest.TestCase):
    """#1504: the merge and the draft writer both operate on the `groups:`
    mapping ONLY. A committed groups.yml carrying the 5.1 top-level
    `exclude_paths:` list (#1136 -- the first-class replacement for the Fixtures
    sink group) came out of the draft WITHOUT it.

    The completion message then tells the operator to move the draft over the
    committed file. Following that on a repo that excludes a deliberately
    vulnerable fixture corpus silently puts the corpus back in scope for every
    domain and every tool scan -- the exact regression exclude_paths exists to
    prevent, and one this project's own redteam self-scan depends on.
    """

    def test_dump_emits_a_committed_exclude_paths_list(self):
        import scripts.setup_proposal as sp
        import scripts.groups_schema as groups_schema
        import yaml
        text = sp.dump_groups_yaml(
            {"Checkout": {"match": ["src/checkout/**"], "panels": ["SEC"]}},
            exclude_paths=["tests/fixtures/**", "vendor/**"])
        doc = yaml.safe_load(text)
        globs, errors = groups_schema.parse_exclude_paths(doc)
        self.assertEqual(errors, [])
        self.assertEqual(globs, ["tests/fixtures/**", "vendor/**"])

    def test_dump_omits_the_key_when_there_is_nothing_to_carry(self):
        import scripts.setup_proposal as sp
        import yaml
        text = sp.dump_groups_yaml({"G": {"match": ["a/**"], "panels": ["SEC"]}})
        self.assertNotIn("exclude_paths", yaml.safe_load(text))

    def test_the_groups_mapping_still_round_trips(self):
        import scripts.setup_proposal as sp
        import scripts.groups_schema as groups_schema
        import yaml
        text = sp.dump_groups_yaml(
            {"Checkout": {"match": ["src/checkout/**"], "panels": ["SEC"]}},
            exclude_paths=["tests/fixtures/**"])
        groups, errors = groups_schema.parse_groups(yaml.safe_load(text))
        self.assertEqual(errors, [])
        self.assertIn("Checkout", groups)

    def test_ingest_carries_the_committed_exclusions_into_the_draft(self):
        import scripts.groups_schema as groups_schema
        import yaml
        d = _repo(self)
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n"
                     "  Checkout:\n"
                     "    match: ['src/checkout/**']\n"
                     "    panels: [SEC]\n"
                     "exclude_paths:\n"
                     "  - tests/fixtures/**\n")
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/checkout/**"]}]}, fh)
        res = setup_flow.ingest_proposal(d, pp)
        self.assertTrue(res.get("ok"), res.get("errors"))
        with open(res["draft"], encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        globs, errors = groups_schema.parse_exclude_paths(doc)
        self.assertEqual(errors, [])
        self.assertEqual(globs, ["tests/fixtures/**"])


class TestReadinessCannotAssertWhatItDidNotCheck(unittest.TestCase):
    """#1344 F2: P2/P3 cease to be expressible."""

    def _check(self, host):
        return dict((name, (ok, detail))
                    for name, ok, detail in
                    setup_flow._check_host_shells(host, lambda *a, **k: None))

    def test_codex_no_longer_claims_enforcement_it_never_verified(self):
        # #1344 F2: pin this against real registration state, not whatever
        # happens to be under ~/.codex/agents on the machine running the
        # suite -- a developer box that has ever run `--emit-host-agents
        # codex` for real would otherwise make `ok` legitimately True and
        # the assertion below flaky-by-environment rather than a check on
        # the code.
        import dispatch
        with mock.patch.object(dispatch, "_is_registered", return_value=False):
            ok, detail = self._check("codex")["enforced-shells"]
        self.assertIsNot(ok, True,
                         "readiness asserted enforcement without checking it")
        self.assertNotIn("codex_exec", detail,
                         "codex_exec was removed; readiness must not cite it")

    def test_codex_reports_enforced_when_its_shells_really_are_registered(self):
        # The other half of test_codex_no_longer_claims_enforcement_it_never
        # _verified. That one proves the hardcoded True is gone; this one
        # proves a REAL True still arrives, so "derived from a check" is
        # demonstrated in both directions rather than asserted in a docstring.
        import dispatch
        with mock.patch.object(dispatch, "_is_registered", return_value=True):
            ok, detail = self._check("codex")["enforced-shells"]
        self.assertTrue(ok)
        self.assertNotIn("codex_exec", detail)

    def test_gemini_is_not_told_to_run_a_command_that_raises(self):
        ok, detail = self._check("gemini")["enforced-shells"]
        self.assertNotIn("--emit-host-agents gemini", detail)
        self.assertIsNot(ok, True)

    def test_a_host_that_registers_no_shells_says_so_honestly(self):
        for name in ("gemini", "generic"):
            with self.subTest(host=name):
                ok, detail = self._check(name)["enforced-shells"]
                self.assertIsNone(ok, "not-applicable is None, not False")
                self.assertIn("registers no", detail)

    def test_claude_still_reports_its_shells(self):
        # The one host with real shells must keep the check it already had.
        result = self._check("claude")
        self.assertIn("enforced-shells", result)

    def test_codex_still_reports_whether_the_cli_is_there(self):
        # The one honest check in the old codex branch. It must survive the
        # rewrite that deletes the dishonest one next to it.
        calls = []

        def runner(cmd, **kwargs):
            calls.append(cmd)
            raise OSError("not installed")

        result = dict((name, (ok, detail)) for name, ok, detail
                      in setup_flow._check_host_shells("codex", runner))
        self.assertIn(["codex", "--version"], calls,
                      "readiness stopped probing for the Codex CLI")
        ok, detail = result["codex-cli"]
        self.assertFalse(ok)
        self.assertIn("Codex CLI unavailable", detail)
