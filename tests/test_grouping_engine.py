"""Size policy of the 5.2 grouping engine (spec §5.3 steps 3-5; D1, D4, R2)."""
import unittest

import yaml

import scripts.discovery as discovery
import scripts.groups_schema as groups_schema
import scripts.grouping_engine as ge
import scripts.setup_proposal as sp


def _files(prefix, n, ext=".go"):
    return ["%s/f%02d%s" % (prefix, i, ext) for i in range(n)]


AUTH = (_files("src/auth/http", 10) + _files("src/auth/jobs", 8)
        + _files("src/auth/core", 40))
SEARCH = _files("src/search", 12)
ALL = sorted(AUTH + SEARCH)
LAYERS = [{"layer": "API", "match": ["src/auth/http/**"], "canonical": True},
          {"layer": "Worker", "match": ["src/auth/jobs/**"], "canonical": True}]


class TestCeiling(unittest.TestCase):
    def test_ceiling_formula(self):
        self.assertEqual(ge.ceiling_for(0, 48), 4)
        self.assertEqual(ge.ceiling_for(97, 48), 6)          # 2 * ceil(97/48) = 6
        self.assertEqual(ge.ceiling_for(200, 48), 10)
        self.assertEqual(ge.ceiling_for(1000, 48), 42)
        self.assertEqual(ge.ceiling_for(1000, 0), 2000, "cap floors at 1")
        self.assertEqual(ge.ceiling_for(-5, 48), 4)

    def test_count_code_files_is_classifier_based(self):
        files = ["src/a.py", "src/b.py", "tests/test_a.py", "docs/guide.md",
                 "README.md", ".github/workflows/ci.yml", "e2e/login.spec.ts"]
        code, commons, tests = ge.count_code_files(files)
        self.assertEqual((code, commons, tests), (2, 3, 2))
        self.assertEqual(ge.count_code_files([]), (0, 0, 0))


class TestPlanLayers(unittest.TestCase):
    def test_under_cap_drops_proposed_layers(self):
        layers, notes = ge.plan_layers(AUTH, LAYERS, cap=100, all_files=ALL)
        self.assertIsNone(layers)
        self.assertEqual(notes, ["58 files <= cap 100: proposed layers not needed, dropped"])
        self.assertEqual(ge.plan_layers(AUTH, [], cap=100, all_files=ALL), (None, []))

    def test_over_cap_without_layers_falls_back_to_chunking(self):
        layers, notes = ge.plan_layers(AUTH, [], cap=48, all_files=ALL)
        self.assertIsNone(layers)
        self.assertIn("falls back to mechanical chunking (chunk_files)", notes[0])

    def test_residual_core_is_the_carrier_and_comes_last(self):
        layers, notes = ge.plan_layers(AUTH, LAYERS, cap=48, all_files=ALL)
        self.assertEqual([ly["layer"] for ly in layers], ["API", "Worker", "Core"])
        self.assertEqual([len(ly["files"]) for ly in layers], [10, 8, 40])
        self.assertEqual([ly["carrier"] for ly in layers], [False, False, True])
        self.assertEqual(layers[2]["match"], [])
        self.assertTrue(all(ly["canonical"] for ly in layers))
        self.assertEqual(notes, [])
        self.assertEqual(sorted(f for ly in layers for f in ly["files"]), sorted(AUTH))

    def test_no_residual_makes_the_largest_layer_the_carrier(self):
        specs = LAYERS + [{"layer": "Service", "match": ["src/auth/core/**"], "canonical": True}]
        layers, notes = ge.plan_layers(AUTH, specs, cap=48, all_files=ALL)
        self.assertEqual([ly["layer"] for ly in layers], ["API", "Worker", "Service"])
        self.assertTrue(layers[2]["carrier"])
        self.assertEqual(notes, ["no residual: layer Service (40 files) is the carrier"])

    def test_leaking_layer_is_dropped(self):
        specs = [{"layer": "API", "match": ["**/http/**", "src/search/**"], "canonical": True},
                 {"layer": "Worker", "match": ["src/auth/jobs/**"], "canonical": True}]
        layers, notes = ge.plan_layers(AUTH, specs, cap=48, all_files=ALL)
        self.assertEqual([ly["layer"] for ly in layers], ["Worker", "Core"])
        self.assertEqual(notes, ["layer API dropped: its globs match 12 file(s) outside "
                                 "the vertical (e.g. src/search/f00.go)"])

    def test_under_floor_layer_merges_into_the_carrier(self):
        # (three literal globs: `_glob_to_re` has no character classes, #1501)
        specs = LAYERS + [{"layer": "CLI", "canonical": True, "match": [
            "src/auth/core/f00.go", "src/auth/core/f01.go", "src/auth/core/f02.go"]}]
        layers, notes = ge.plan_layers(AUTH, specs, cap=48, all_files=ALL)
        self.assertEqual([ly["layer"] for ly in layers], ["API", "Worker", "Core"])
        self.assertEqual(len(layers[2]["files"]), 40)          # 37 residual + 3 CLI
        self.assertEqual(layers[2]["absorbed"], ["CLI"])
        self.assertEqual(notes, ["layer CLI (3 files) merged into Core (under floor 6)"])

    def test_everything_dropped_or_merged_means_unlayered(self):
        specs = [{"layer": "API", "match": ["src/search/**"], "canonical": True}]
        layers, notes = ge.plan_layers(AUTH, specs, cap=48, all_files=ALL)
        self.assertIsNone(layers)
        self.assertIn("every proposed layer was dropped", notes[1])
        tiny = [{"layer": "API", "match": ["src/auth/http/f00.go"], "canonical": True}]
        layers, notes = ge.plan_layers(AUTH, tiny, cap=48, all_files=ALL)
        self.assertIsNone(layers)
        self.assertEqual(notes, ["layer API (1 files) merged into Core (under floor 6)",
                                 "a single layer remains: vertical stays unlayered and "
                                 "falls back to mechanical chunking (chunk_files)"])

    def test_first_layer_wins_overlapping_globs(self):
        specs = [{"layer": "Service", "match": ["src/auth/**"], "canonical": True},
                 {"layer": "API", "match": ["src/auth/http/**"], "canonical": True}]
        layers, notes = ge.plan_layers(AUTH, specs, cap=48, all_files=ALL)
        self.assertIsNone(layers, "API matched nothing, merged, one layer left")
        self.assertEqual(notes[0], "no residual: layer Service (58 files) is the carrier")


class TestMergeSmallestLayer(unittest.TestCase):
    def _layers(self):
        return ge.plan_layers(AUTH, LAYERS, cap=48, all_files=ALL)[0]

    def test_smallest_non_carrier_merges_into_carrier(self):
        out, note = ge.merge_smallest_layer(self._layers())
        self.assertEqual(note, "layer Worker (8 files) merged into Core")
        self.assertEqual([ly["layer"] for ly in out], ["API", "Core"])
        self.assertEqual(len(out[1]["files"]), 48)
        self.assertEqual(out[1]["absorbed"], ["Worker"])

    def test_smallest_carrier_is_absorbed_by_the_largest(self):
        layers = self._layers()
        layers[2]["files"] = layers[2]["files"][:2]              # Core shrinks to 2
        out, note = ge.merge_smallest_layer(layers)
        self.assertEqual(note, "layer Core (2 files) merged into API")
        self.assertEqual([ly["layer"] for ly in out], ["Worker", "API"])
        self.assertTrue(out[1]["carrier"])
        self.assertEqual(out[1]["absorbed"], ["Core"])
        self.assertFalse(layers[0]["carrier"], "input not mutated")

    def test_ties_break_on_proposal_order_and_single_layer_is_stable(self):
        layers = [{"layer": "A", "files": ["x/1"], "match": [], "canonical": True,
                   "carrier": False, "absorbed": []},
                  {"layer": "B", "files": ["x/2"], "match": [], "canonical": True,
                   "carrier": False, "absorbed": []},
                  {"layer": "Core", "files": ["x/3"], "match": [], "canonical": True,
                   "carrier": True, "absorbed": []}]
        out, note = ge.merge_smallest_layer(layers)
        self.assertEqual(note, "layer Core (1 files) merged into A")
        self.assertEqual([ly["layer"] for ly in out], ["B", "A"])
        self.assertEqual(ge.merge_smallest_layer(out[1:]), (out[1:], "nothing to merge"))


class TestApplyCeiling(unittest.TestCase):
    def test_under_ceiling_is_untouched(self):
        layered = {"Auth": ge.plan_layers(AUTH, LAYERS, cap=48, all_files=ALL)[0]}
        out, notes, over = ge.apply_ceiling(layered, other_leaves=2, ceiling=5)
        self.assertEqual([ly["layer"] for ly in out["Auth"]], ["API", "Worker", "Core"])
        self.assertEqual((notes, over), ([], 0))

    def test_collapses_smallest_anywhere_until_under(self):
        auth = ge.plan_layers(AUTH, LAYERS, cap=48, all_files=ALL)[0]
        big = _files("src/big/a", 30) + _files("src/big/b", 7) + _files("src/big/c", 30)
        big_specs = [{"layer": "API", "match": ["src/big/a/**"], "canonical": True},
                     {"layer": "CLI", "match": ["src/big/b/**"], "canonical": True}]
        bigl = ge.plan_layers(big, big_specs, cap=48, all_files=ALL + big)[0]
        out, notes, over = ge.apply_ceiling({"Auth": auth, "Big": bigl}, other_leaves=1, ceiling=4)
        # 7 leaves -> 4: Big.CLI(7) then Auth.Worker(8) then Auth.API(10) -> Auth unlayered
        self.assertEqual(notes, [
            "Big: layer CLI (7 files) merged into Core (ceiling 4 exceeded: 7 leaves)",
            "Auth: layer Worker (8 files) merged into Core (ceiling 4 exceeded: 6 leaves)",
            "Auth: layer API (10 files) merged into Core (ceiling 4 exceeded: 5 leaves)",
            "Auth: a single layer remains, vertical unlayered (falls back to mechanical chunking)"])
        self.assertEqual(list(out), ["Big"])
        self.assertEqual([ly["layer"] for ly in out["Big"]], ["API", "Core"])
        self.assertEqual(over, 0)

    def test_verticals_are_never_merged(self):
        auth = ge.plan_layers(AUTH, LAYERS, cap=48, all_files=ALL)[0]
        out, notes, over = ge.apply_ceiling({"Auth": auth}, other_leaves=10, ceiling=4)
        self.assertEqual(out, {}, "layers all collapsed")
        self.assertEqual(over, 7, "10 leaves + 1 unlayered Auth = 11, ceiling 4")


class TestLayerBodies(unittest.TestCase):
    def test_carrier_carries_negations_tests_and_every_leaf_the_floor(self):
        vertical = {"match": ["src/auth/**"], "tests": ["tests/auth/**"], "panels": ["SEC"]}
        layers = ge.plan_layers(AUTH, LAYERS, cap=48, all_files=ALL)[0]
        body = ge.layer_bodies(vertical, layers)
        self.assertEqual(list(body["subgroups"]), ["API", "Worker", "Core"])
        self.assertEqual(body["subgroups"]["API"],
                         {"match": ["src/auth/http/**"], "tests": [], "panels": ["SEC"], "exclude": []})
        self.assertEqual(body["subgroups"]["Core"], {
            "match": ["src/auth/**", "!src/auth/http/**", "!src/auth/jobs/**"],
            "tests": ["tests/auth/**"], "panels": ["SEC"], "exclude": []})

    def test_bodies_reproduce_the_partition_through_assign_scoped(self):
        vertical = {"match": ["src/auth/**"], "tests": [], "panels": []}
        layers = ge.plan_layers(AUTH, LAYERS, cap=48, all_files=ALL)[0]
        flat = sp.flatten_groups({"Auth": ge.layer_bodies(vertical, layers)})
        assigned, leftovers, _ = discovery.assign_scoped(ALL, flat, aliases={})
        self.assertEqual(leftovers, SEARCH)
        for ly in layers:
            self.assertEqual(assigned["Auth:" + ly["layer"]], ly["files"])

    def test_carrier_from_a_proposed_layer_uses_the_verticals_globs(self):
        vertical = {"match": ["src/auth/**"], "tests": [], "panels": []}
        specs = LAYERS + [{"layer": "Service", "match": ["src/auth/core/**"], "canonical": True}]
        layers = ge.plan_layers(AUTH, specs, cap=48, all_files=ALL)[0]
        body = ge.layer_bodies(vertical, layers)
        self.assertEqual(body["subgroups"]["Service"]["match"],
                         ["src/auth/**", "!src/auth/http/**", "!src/auth/jobs/**"])
        flat = sp.flatten_groups({"Auth": body})
        assigned, _, _ = discovery.assign_scoped(ALL, flat, aliases={})
        self.assertEqual(len(assigned["Auth:Service"]), 40)


# --- plan_groups / format_report -------------------------------------------

REPO = sorted(
    _files("internal/auth/http", 10) + _files("internal/auth/jobs", 8)
    + _files("internal/auth/core", 40)
    + ["internal/auth/core/f00_test.go", "internal/auth/http/server_test.go"]
    + _files("internal/search", 12) + ["internal/search/query_test.go"]
    + _files("internal/billing", 7) + ["internal/billing/schema.sql"]
    + _files("cmd/app", 3)
    + ["tests/auth/login_test.go", "tests/e2e/checkout.spec.ts", "tests/e2e/login.spec.ts",
       "tests/helpers.go", "tests/search/query_test.go", "tests/fixtures_test.go",
       "tests/conftest.py"]
    + ["README.md", "docs/guide.md", "docs/api.md", "Makefile", "go.mod", "go.sum",
       ".github/workflows/ci.yml", ".env.example", "Dockerfile"]
    + ["internal/legacy/old.go", "internal/legacy/older.go", "pkg/util/strings.go"])
COMMITTED = {"Billing": {"match": ["internal/billing/**"], "tests": [], "panels": ["SEC"],
                         "exclude": []}}
_EMPTY_PROFILE = {"surfaces": [], "entry_points": [], "trust_boundaries": []}
ASSEMBLED = {
    "Auth": {"match": ["internal/auth/**"], "tests": ["tests/auth/**", "**/*_test.go"],
             "panels": ["SEC"], "profile": {"surfaces": ["auth"], "entry_points": [],
                                            "trust_boundaries": []},
             "layers": [{"layer": "API", "match": ["internal/auth/http/**"], "canonical": True},
                        {"layer": "Worker", "match": ["internal/auth/jobs/**"], "canonical": True}]},
    "Search": {"match": ["internal/search/**"], "tests": ["tests/search/**"], "panels": [],
               "layers": [], "profile": _EMPTY_PROFILE},
    # a committed leaf: extra glob matches nothing -> redundant; its layer is moot
    "Billing": {"match": ["internal/billing/**", "internal/payments/**"], "tests": [],
                "panels": ["SEC"], "profile": _EMPTY_PROFILE,
                "layers": [{"layer": "API", "match": ["internal/billing/api/**"], "canonical": True}]},
    "Spelunking": {"match": ["internal/nothing/**"], "tests": [], "panels": [], "layers": [],
                   "profile": _EMPTY_PROFILE},
}

GOLDEN_REPORT = """\
# Setup report

## Size

- files: 103 total = 87 code + 9 commons + 7 test tree
- cap: 48 files per dispatch unit; ceiling: 8 leaves
- leaves: 7 (committed 1, verticals 1, layers 3, Tests 1, Commons 1)
- leaf size: min 5 / mean 13.9 / max 42
- estimated cells: >= 22 (dispatch units x floor domains; the scout only widens)

## Leaves

| leaf | kind | files | units | floor |
|---|---|---|---|---|
| Billing | committed | 8 | 1 | COD, DAT, SEC |
| Auth:API | layer | 11 | 1 | COD, SEC, TST |
| Auth:Worker | layer | 8 | 1 | COD, SEC |
| Auth:Core | layer | 42 | 1 | ARC, COD, SEC, TST |
| Search | vertical | 14 | 1 | ARC, COD, TST |
| Tests | tests | 5 | 1 | ARC, COD, SEC, TST |
| Commons | commons | 9 | 1 | ARC, COD, SEC |

## Layers

- Auth: API (11), Worker (8), Core (42, carrier)

## Tests

- swept 5 test-tree file(s) into `Tests` (formed last, mechanical at run time)

## Commons

- Commons: 9

## Ungrouped -- capabilities your catalog is missing (6 files)

- cmd/app: 3
- internal/legacy: 2
- pkg/util: 1

Ungrouped code is reviewed (chunked as `Ungrouped_N`) and yields well; a high Ungrouped count is a coverage signal, not waste. Name the capability and add a group.

## Proposal outcome

- Billing: claimed nothing new, dropped as redundant
- Spelunking: claimed nothing new, dropped as redundant

## Names

- custom: Spelunking (floor none, empty(scout-only))
- authentication -> Auth
- warning: Auth: layer 'tests' dropped (reserved or not a layer -- tests are the tests: axis, config and docs are Commons)
"""

DISCLOSURE = {
    "groups": [
        {"name": "Auth", "capability": "Auth", "custom": False, "floor": ["SEC"],
         "floor_source": "affinity", "normalized": {"from": "authentication", "to": "Auth"}},
        {"name": "Spelunking", "capability": "custom:Spelunking", "custom": True, "floor": [],
         "floor_source": "empty(scout-only)", "normalized": None}],
    "errors": [], "collisions": [],
    "warnings": ["Auth: layer 'tests' dropped (reserved or not a layer -- tests are the "
                 "tests: axis, config and docs are Commons)"]}


class TestPlanGroups(unittest.TestCase):
    """Golden test (spec §8): synthetic layout + fixed proposal -> byte-stable
    groups, claims and report."""

    def test_golden_layered(self):
        res = ge.plan_groups(REPO, COMMITTED, ASSEMBLED, cap=48, aliases={}, ceiling=8)
        self.assertEqual(res["groups"]["Auth"], {"subgroups": {
            "API": {"match": ["internal/auth/http/**"], "tests": [], "panels": ["SEC"], "exclude": []},
            "Worker": {"match": ["internal/auth/jobs/**"], "tests": [], "panels": ["SEC"], "exclude": []},
            "Core": {"match": ["internal/auth/**", "!internal/auth/http/**", "!internal/auth/jobs/**"],
                     "tests": ["tests/auth/**", "**/*_test.go"], "panels": ["SEC"], "exclude": []}}})
        self.assertEqual(res["groups"]["Search"],
                         {"match": ["internal/search/**"], "tests": ["tests/search/**"], "panels": []})
        self.assertEqual(set(res["groups"]), {"Auth", "Search", "Billing", "Spelunking"})
        self.assertEqual(set(res["claims"]), {"Auth", "Search"})
        self.assertEqual(len(res["claims"]["Auth"]), 61)      # 58 code + 2 colocated + tests/auth
        self.assertIn("tests/auth/login_test.go", res["claims"]["Auth"])
        self.assertNotIn("tests/fixtures_test.go", res["claims"]["Auth"], "scope-rejected")
        self.assertEqual(res["report"]["files"], {"total": 103, "code": 87, "commons": 9, "test_tree": 7})
        self.assertEqual(res["report"]["ungrouped"], [
            "cmd/app/f00.go", "cmd/app/f01.go", "cmd/app/f02.go",
            "internal/legacy/old.go", "internal/legacy/older.go", "pkg/util/strings.go"])
        self.assertEqual(ge.format_report(res["report"], DISCLOSURE), GOLDEN_REPORT)

    def test_default_ceiling_collapses_layers_and_says_so(self):
        # 87 code files / cap 48 -> ceiling 4; 5 non-layer leaves already exceed it,
        # so every Auth layer collapses and the vertical falls back to chunking.
        res = ge.plan_groups(REPO, COMMITTED, ASSEMBLED, cap=48, aliases={})
        r = res["report"]
        self.assertEqual((r["ceiling"], r["over_ceiling_by"]), (4, 1))
        self.assertEqual(r["ceiling_notes"], [
            "Auth: layer Worker (8 files) merged into Core (ceiling 4 exceeded: 7 leaves)",
            "Auth: layer API (11 files) merged into Core (ceiling 4 exceeded: 6 leaves)",
            "Auth: a single layer remains, vertical unlayered (falls back to mechanical chunking)"])
        self.assertNotIn("subgroups", res["groups"]["Auth"])
        self.assertEqual([lf["name"] for lf in r["leaves"]],
                         ["Billing", "Auth", "Search", "Tests", "Commons"])
        self.assertEqual(r["leaves"][1]["units"], 2, "61 files at cap 48 -> 2 chunks")
        text = ge.format_report(r)
        self.assertIn("- **over ceiling by 1** -- raise `max_groups`", text)
        self.assertIn("- Auth: unlayered", text)
        self.assertNotIn("## Names", text)

    def test_committed_parent_is_skipped_and_tests_suppressed(self):
        committed = {"Auth": {"subgroups": {
            "API": {"match": ["internal/auth/http/**"], "tests": [], "panels": [], "exclude": []},
            "Core": {"match": ["internal/auth/**"], "tests": [], "panels": [], "exclude": []}}}}
        assembled = dict(ASSEMBLED)
        assembled["Tests"] = {"match": ["tests/**"], "tests": [], "panels": [], "layers": [],
                              "profile": _EMPTY_PROFILE}
        res = ge.plan_groups(REPO, committed, assembled, cap=48, aliases={}, ceiling=8)
        r = res["report"]
        self.assertEqual(r["skipped_committed_parent"], ["Auth"])
        # the proposal stays in groups/claims so merge_additive can classify it
        # (it claimed tests/auth via its scoped tests: glob -> "skipped", not
        # "redundant"); its globs never enter the run-time catalog
        self.assertNotIn("subgroups", res["groups"]["Auth"])
        self.assertEqual(res["claims"]["Auth"], ["tests/auth/login_test.go"])
        self.assertNotIn("Auth", [lf["name"] for lf in r["leaves"]])
        merged, diff = sp.merge_additive(committed, res["groups"], res["claims"])
        self.assertEqual(diff["skipped_committed_parent"], ["Auth"])
        self.assertEqual(list(merged["Auth"]["subgroups"]), ["API", "Core"])
        self.assertTrue(r["tests"]["suppressed"])
        self.assertEqual(r["tests"]["swept"], 0)
        # 7 test-tree files minus the one Search's scoped tests: glob claims;
        # the committed Auth parent has no tests: axis, so its test stays here
        self.assertEqual(len(res["claims"]["Tests"]), 6, "the proposed Tests owns the tree")
        self.assertEqual([lf["name"] for lf in r["leaves"]][:2], ["Auth:API", "Auth:Core"])
        text = ge.format_report(r)
        self.assertIn("- Auth: committed parent left untouched", text)
        self.assertIn("proposed layers API, Worker dropped", text)
        self.assertIn("- sweep suppressed", text)

    def test_setup_partition_reproduces_at_run_time(self):
        # The leaf sizes the report promises are what groups.yml.draft yields
        # when the scan assigns files through it.
        res = ge.plan_groups(REPO, COMMITTED, ASSEMBLED, cap=48, aliases={}, ceiling=8)
        merged, diff = sp.merge_additive(COMMITTED, res["groups"], res["claims"])
        self.assertEqual(diff["dropped_redundant"], ["Billing", "Spelunking"])
        parsed, errors = groups_schema.parse_groups(yaml.safe_load(sp.dump_groups_yaml(merged)))
        self.assertEqual(errors, [])
        catalog = {n: {"match": b["match"], "tests": b["tests"]} for n, b in parsed.items()}
        assigned, leftovers, warnings = discovery.assign_scoped(REPO, catalog, aliases={})
        self.assertEqual(warnings, [])
        promised = {lf["name"]: lf["files"] for lf in res["report"]["leaves"]
                    if lf["kind"] in ("committed", "vertical", "layer")}
        self.assertEqual({n: len(fs) for n, fs in assigned.items()}, promised)
        self.assertEqual(len(leftovers), 20)          # 5 tests + 9 commons + 6 ungrouped

    def test_deterministic_across_input_order(self):
        a = ge.plan_groups(REPO, COMMITTED, ASSEMBLED, cap=48, aliases={}, ceiling=8)
        b = ge.plan_groups(list(reversed(REPO)), COMMITTED, ASSEMBLED, cap=48, aliases={}, ceiling=8)
        self.assertEqual(a, b)

if __name__ == "__main__":
    unittest.main()
