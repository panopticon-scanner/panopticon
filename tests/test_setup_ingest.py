"""Proposal ingest, draft configuration, and settings behavior."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import yaml

import scripts.setup_flow as setup_flow


from tests.setup_helpers import (
    _repo,
    SetupFixtureBase,
)

class TestSetupFlow(SetupFixtureBase):
    """Proposal ingest, draft configuration, and settings behavior."""

    def test_ingest_never_flattens_a_committed_parent(self):
        d = _repo(self)
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups:\n  Checkout:\n    API:\n      match: ['src/checkout/api/**']\n"
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
        with open(res["draft"], encoding="utf-8") as fh:
            drafted = yaml.safe_load(fh)["groups"]
        self.assertEqual(list(drafted["Checkout"]), ["API", "Core"])     # parent intact
        self.assertEqual(drafted["Search"]["match"], ["src/search/**"])

    def test_ingest_writes_draft_with_affinity_floor(self):
        with self._ingest_fixture() as (d, pp):
            res = setup_flow.ingest_proposal(d, pp)
            self.assertTrue(res["ok"])
            draft = setup_flow.repo_config.draft_path(d)
            self.assertTrue(os.path.isfile(draft))
            self.assertIsNone(setup_flow.repo_config.resolve(d).path)
            # #run7 TST-B1A: assert the affinity FLOOR the test is named for
            # actually lands in the draft -- Checkout -> [SEC, ACC] per
            # capability_affinity.yml. The old test checked only ok/draft-exists,
            # so an empty-panels regression (the exact failure the setup-scan
            # floor guards against) stayed green.
            with open(draft, encoding="utf-8") as fh:
                drafted = yaml.safe_load(fh)
            self.assertEqual(drafted["groups"]["Checkout"]["panels"], ["SEC", "ACC"])
            floor_sources = {g["name"]: g["floor_source"]
                             for g in res["disclosure"]["groups"]}
            self.assertEqual(floor_sources["Checkout"], "affinity")

    def test_ingest_writes_the_draft_at_the_root_with_version_and_settings(self):
        with self._ingest_fixture() as (d, pp):
            result = setup_flow.ingest_proposal(d, pp, max_per_group=12)
            self.assertTrue(result["ok"])
            self.assertEqual(result["draft"], os.path.join(d, "panopticon.yml.draft"))
            with open(result["draft"], encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("version: 1\n", text)
            self.assertIn("settings:\n  max_per_group: 12\n", text)
            self.assertTrue(os.path.isfile(os.path.join(d, ".panopticon", "setup-report.md")))

    def test_the_draft_drops_a_committed_gate_key_the_cli_cannot_express(self):
        # The #1504 failure one key over used to be about NOT DROPPING a
        # committed setting the CLI cannot express -- `max_verify` used to
        # survive into the draft for exactly that reason. #1681 Plan 2
        # reclassifies `max_verify` as a GATE key: it is refused at run time
        # regardless of what the draft says, so carrying it forward would
        # suggest that promoting the draft makes it stick. The draft is the
        # committed GRAIN settings OVERLAID by what was passed; a gate key
        # is never one of them.
        with self._ingest_fixture() as (d, pp):
            with open(os.path.join(d, "panopticon.yml"), "w") as fh:
                fh.write("version: 1\ngroups: {}\n"
                         "settings:\n  max_per_group: 8\n  max_verify: 4\n")
            result = setup_flow.ingest_proposal(d, pp, max_per_group=12)
            self.assertTrue(result["ok"], result.get("errors"))
            with open(result["draft"], encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            self.assertEqual(doc["settings"], {"max_per_group": 12})

    def test_the_draft_keeps_the_committed_sizes_clamped_when_no_flags_were_passed(self):
        # #1681 Plan 2: the committed `max_groups: 3` is below the 4-64 band,
        # so it is clamped the same way a run would clamp it -- the draft
        # carries the number a run will actually use, not the raw file value.
        with self._ingest_fixture() as (d, pp):
            with open(os.path.join(d, "panopticon.yml"), "w") as fh:
                fh.write("version: 1\ngroups: {}\n"
                         "settings:\n  max_per_group: 8\n  max_groups: 3\n")
            result = setup_flow.ingest_proposal(d, pp)
            with open(result["draft"], encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            self.assertEqual(doc["settings"], {"max_per_group": 8, "max_groups": 4})

    def test_the_draft_omits_settings_a_repo_never_asked_for(self):
        with self._ingest_fixture() as (d, pp):
            result = setup_flow.ingest_proposal(d, pp)
            with open(result["draft"], encoding="utf-8") as fh:
                self.assertNotIn("settings", yaml.safe_load(fh))

    def test_ingest_refuses_an_authored_but_invalid_root_config(self):
        # `driver run` fails loud on this tree; setup was the only path that
        # proceeded -- `_committed_matrix` returns {} for any unreadable
        # document, so the merge ran against an EMPTY matrix, dropped the
        # operator's `exclude_paths:`, and the completion message told them to
        # move a draft that discards what they authored over the real file.
        with self._ingest_fixture() as (d, pp):
            with open(os.path.join(d, "panopticon.yml"), "w") as fh:
                fh.write("groups:\n  Auth:\n    match: ['src/auth/**']\n"
                         "exclude_paths: ['vendor/**']\n")      # no `version: 1`
            res = setup_flow.ingest_proposal(d, pp)
            self.assertFalse(res["ok"])
            self.assertTrue(any("version: 1" in e for e in res["errors"]), res["errors"])
            self.assertFalse(os.path.isfile(setup_flow.repo_config.draft_path(d)))
            self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "setup-report.md")))

    def test_ingest_refuses_a_symlinked_root_config_and_leaves_the_link(self):
        with self._ingest_fixture() as (d, pp):
            outside = os.path.join(d, "elsewhere.yml")
            with open(outside, "w") as fh:
                fh.write("version: 1\ngroups: {}\n")
            link = os.path.join(d, "panopticon.yml")
            os.symlink(outside, link)
            res = setup_flow.ingest_proposal(d, pp)
            self.assertFalse(res["ok"])
            self.assertTrue(any("symlink" in e for e in res["errors"]), res["errors"])
            self.assertTrue(os.path.islink(link))
            self.assertFalse(os.path.isfile(setup_flow.repo_config.draft_path(d)))
            self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "setup-report.md")))

    def test_ingest_malformed_proposal_fails_no_draft(self):
        d = _repo(self)
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump({"groups": [{"capability": "", "match": []}]}, fh)
        res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertEqual(res["errors"], [
            "proposal rejected -- no draft written:",
            "  - proposal group #0: missing/empty capability",
            "  - proposal group #0: match must be a non-empty list of strings",
        ])
        self.assertFalse(os.path.isfile(setup_flow.repo_config.draft_path(d)))

    def test_ingest_missing_proposal_fails_no_draft(self):
        d = _repo(self)
        res = setup_flow.ingest_proposal(d, os.path.join(d, ".panopticon", "nope.json"))
        self.assertFalse(res["ok"])
        self.assertFalse(os.path.isfile(setup_flow.repo_config.draft_path(d)))

    def test_ingest_oversized_proposal_refused(self):
        # #1107: a target-shipped proposal over the byte cap is refused before parse
        d = _repo(self)
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            fh.write("[" + "0," * 600000 + "0]")   # > 1 MiB of JSON
        res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertTrue(any("exceeds" in e for e in res["errors"]))
        self.assertFalse(os.path.isfile(setup_flow.repo_config.draft_path(d)))

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
            setup_flow.repo_config.draft_path(d)))

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
            setup_flow.repo_config.draft_path(d)))

    def test_config_overrides_honour_positive_ints_only(self):
        d = _repo(self)
        self.assertEqual(setup_flow.config_overrides(d),
                         {"max_per_group": None, "max_groups": None})
        self._root_settings(d, "settings:\n  max_per_group: 32\n  max_groups: '8'\n")
        self.assertEqual(setup_flow.config_overrides(d),
                         {"max_per_group": 32, "max_groups": None})
        self._root_settings(d, "settings:\n  max_per_group: true\n  max_groups: 0\n")
        self.assertEqual(setup_flow.config_overrides(d),
                         {"max_per_group": None, "max_groups": None})
        self._root_settings(d, "settings: not-a-mapping\n")
        self.assertEqual(setup_flow.config_overrides(d),
                         {"max_per_group": None, "max_groups": None})

    def test_config_overrides_read_settings_from_the_root_file(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\nsettings:\n  max_per_group: 12\n  max_groups: 0\n")
            self.assertEqual(setup_flow.config_overrides(d),
                             {"max_per_group": 12, "max_groups": None})

    def test_config_overrides_ignore_a_stale_config_json(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "config.json"), "w") as fh:
                fh.write('{"max_per_group": 5}')
            self.assertEqual(setup_flow.config_overrides(d), {"max_per_group": None, "max_groups": None})

    def test_config_overrides_are_clamped_to_the_band(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\nsettings:\n  max_per_group: 5000\n"
                         "  max_groups: 1\n")
            self.assertEqual(setup_flow.config_overrides(d),
                             {"max_per_group": 48, "max_groups": 4})

    def test_config_overrides_ignore_a_gate_key(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\nsettings:\n  security: redteam\n")
            self.assertEqual(setup_flow.config_overrides(d),
                             {"max_per_group": None, "max_groups": None})

    def test_the_draft_carries_grain_keys_only(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\nsettings:\n  max_per_group: 20\n"
                         "  max_verify: 9\n  security: redteam\n"
                         "  allow_unenforced: true\n")
            settings = setup_flow._draft_settings(d, None, None)
        self.assertEqual(settings, {"max_per_group": 20})

    def test_the_draft_keeps_a_committed_include_fixtures(self):
        # Final review F3: the draft is what the completion message tells the
        # operator to move over the committed file, and it was assembled from
        # `config_overrides`, which answers with the two SIZE knobs alone --
        # so a committed `include_fixtures: true` was lost by following
        # panopticon's own promotion instruction. Every GRAIN key the config
        # resolves survives; a gate or operator-only key still never does.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\nsettings:\n  max_per_group: 20\n"
                         "  include_fixtures: true\n  security: redteam\n"
                         "  allow_unenforced: true\n")
            settings = setup_flow._draft_settings(d, None, None)
        self.assertEqual(settings, {"max_per_group": 20, "include_fixtures": True})

    def test_an_out_of_band_setup_flag_is_written_but_warned_about(self):
        with tempfile.TemporaryDirectory() as d:
            with contextlib.redirect_stderr(io.StringIO()) as err:
                settings = setup_flow._draft_settings(d, 5000, None)
            self.assertEqual(settings["max_per_group"], 5000)
            self.assertIn("a run will clamp it to 48", err.getvalue())

    def test_ingest_writes_the_report_and_resolves_cap_cli_over_config(self):
        d = _repo(self)
        # max_per_group: 2 is below the 8-48 band (#1681 Plan 2) and clamps to 8.
        self._root_settings(d, "settings:\n  max_per_group: 2\n  max_groups: 6\n")
        pp = self._write_proposal(d, {"groups": [{"capability": "Checkout",
                                                  "match": ["src/checkout/**"], "tests": []}]})
        res = setup_flow.ingest_proposal(d, pp)
        self.assertTrue(res["ok"], res)
        self.assertEqual((res["report"]["cap"], res["report"]["ceiling"]), (8, 6))
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
        with open(res["draft"], encoding="utf-8") as fh:
            drafted = yaml.safe_load(fh)["groups"]
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
        self.assertFalse(os.path.isfile(setup_flow.repo_config.draft_path(d)))
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "setup-report.md")))

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
        text = sp.dump_config_yaml(
            {"Checkout": {"match": ["src/checkout/**"], "panels": ["SEC"]}},
            exclude_paths=["tests/fixtures/**", "vendor/**"])
        doc = yaml.safe_load(text)
        globs, errors = groups_schema.parse_exclude_paths(doc)
        self.assertEqual(errors, [])
        self.assertEqual(globs, ["tests/fixtures/**", "vendor/**"])

    def test_dump_omits_the_key_when_there_is_nothing_to_carry(self):
        import scripts.setup_proposal as sp
        text = sp.dump_config_yaml({"G": {"match": ["a/**"], "panels": ["SEC"]}})
        self.assertNotIn("exclude_paths", yaml.safe_load(text))

    def test_the_groups_mapping_still_round_trips(self):
        import scripts.setup_proposal as sp
        import scripts.groups_schema as groups_schema
        text = sp.dump_config_yaml(
            {"Checkout": {"match": ["src/checkout/**"], "panels": ["SEC"]}},
            exclude_paths=["tests/fixtures/**"])
        groups, errors = groups_schema.parse_groups(yaml.safe_load(text))
        self.assertEqual(errors, [])
        self.assertIn("Checkout", groups)

    def test_dump_config_yaml_puts_version_first_and_settings_last(self):
        import setup_proposal as sp
        text = sp.dump_config_yaml({"App": {"match": ["src/**"]}},
                                   exclude_paths=["vendor/**"],
                                   settings={"max_per_group": 48, "max_groups": None})
        body = text.split(
            "# parent; its subgroups are its layers and roll up to it in the report.\n"
            "# settings: max_per_group (8-48) / max_groups (4-64) / include_fixtures;\n"
            "# gate keys only tighten the review, operator flags are refused.\n", 1)[1]
        self.assertTrue(body.startswith("version: 1\n"))
        self.assertLess(body.index("groups:"), body.index("exclude_paths:"))
        self.assertLess(body.index("exclude_paths:"), body.index("settings:"))
        self.assertIn("  max_per_group: 48\n", body)
        self.assertNotIn("max_groups", body)          # None is omitted
        doc = yaml.safe_load(body)
        self.assertEqual(doc["version"], 1)

    def test_dump_config_yaml_omits_empty_settings_and_exclusions(self):
        import setup_proposal as sp
        body = sp.dump_config_yaml({"App": {"match": ["src/**"]}}, header=False)
        self.assertEqual(body, "version: 1\ngroups:\n  App:\n    match:\n    - src/**\n")

    def test_ingest_carries_the_committed_exclusions_into_the_draft(self):
        import scripts.groups_schema as groups_schema
        d = _repo(self)
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n"
                     "groups:\n"
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

