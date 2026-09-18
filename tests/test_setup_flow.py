import ast
import contextlib
import dataclasses
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

import scripts.coverage_model as coverage_model
import scripts.grouping_engine as grouping_engine
import scripts.host_disclosure as host_disclosure
import scripts.host_probes as host_probes
import scripts.hosts as hosts
import scripts.probes.codex as codex_probes
import scripts.probes.common as probes_common
import scripts.setup_flow as setup_flow
import shutil


def _isolate_codex_probes(test_case):
    """Readiness assertions must never invoke a real Codex runtime probe."""
    for name, probe_id in (
        ("probe_codex_tool_policy", "codex-effective-tools"),
        ("probe_codex_read_scope", "codex-read-scope"),
    ):
        patcher = mock.patch.object(
            codex_probes, name,
            return_value=(hosts.UNKNOWN, probe_id, "isolated test fixture"))
        patcher.start()
        test_case.addCleanup(patcher.stop)


def _repo(test_case, with_committed=False):
    d = os.path.realpath(tempfile.mkdtemp())
    os.makedirs(os.path.join(d, "src", "checkout"))
    with open(os.path.join(d, "src", "checkout", "pay.py"), "w") as fh:
        fh.write("x = 1\n")
    os.makedirs(os.path.join(d, ".panopticon"))
    test_case.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
    if with_committed:
        body = "groups:\n  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n"
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\n" + body)
    return d


def test_check_groups_manifest_reports_an_unreadable_root_config(tmp_path):
    (tmp_path / "panopticon.yml").write_text("not: [valid yaml: [")
    name, ok, detail = setup_flow._check_groups_manifest(str(tmp_path))
    assert name == "groups-manifest"
    assert ok is False
    assert "unreadable" in detail.lower()


def test_check_groups_manifest_reports_a_refused_symlink_not_absence(tmp_path):
    # A symlink at the config path resolves to NO document and NO error
    # (`repo_config` refuses to follow it), so reading only `doc.doc` reports
    # the planted link as "nothing configured yet" -- an informational row for
    # a refusal, and a silent fall back to whole-repo chunking.
    (tmp_path / "elsewhere.yml").write_text("version: 1\ngroups: {}\n")
    (tmp_path / "panopticon.yml").symlink_to(tmp_path / "elsewhere.yml")
    name, ok, detail = setup_flow._check_groups_manifest(str(tmp_path))
    assert name == "groups-manifest"
    assert ok is False
    assert "symlink" in detail


def test_check_groups_manifest_does_not_gate_on_a_stale_config_json(tmp_path):
    # The other side of the line above: a leftover retired JSON config is
    # INFORMATIONAL -- `scan_execute` prints it -- and must not turn an
    # un-set-up tree's row into a readiness failure. Only a refusal does that.
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "config.json").write_text('{"max_per_group": 5}')
    name, ok, detail = setup_flow._check_groups_manifest(str(tmp_path))
    assert name == "groups-manifest"
    assert ok is None
    assert "no committable config yet" in detail


def test_check_groups_manifest_never_raises_on_a_legacy_tree(tmp_path):
    # #1681: `phases/readiness` calls this directly, so a tree still carrying
    # the legacy matrix file and no root config must produce a readiness ROW
    # naming the migration remedy -- not a ValueError out of discovery.
    (tmp_path / ".git").mkdir()
    (tmp_path / ".panopticon").mkdir()
    (tmp_path / ".panopticon" / "groups.yml").write_text("groups: {}\n")

    class _Ok:
        returncode, stdout, stderr = 0, "", ""

    def ok_runner(argv, capture_output, text, timeout=None):
        return _Ok()

    checks = setup_flow.setup_readiness(str(tmp_path), host="claude",
                                        runner=ok_runner,
                                        environ={"NVD_API_KEY": "k"})
    row = {c[0]: c for c in checks}["groups-manifest"]
    assert row[1] is False
    assert "migrate-config" in row[2]


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


class TestSetupFlow(unittest.TestCase):
    def setUp(self):
        _isolate_codex_probes(self)

    def _gitignore(self, repo):
        with open(os.path.join(repo, ".gitignore"), encoding="utf-8") as fh:
            return fh.read()

    def test_provision_ignores_the_draft_and_never_writes_config_json(self):
        with tempfile.TemporaryDirectory() as d:
            summary = setup_flow.provision(d)
            with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
                gi = fh.read()
            self.assertIn("panopticon.yml.draft", gi)
            self.assertNotIn("!.panopticon/groups.yml", gi)
            self.assertFalse(os.path.exists(os.path.join(d, ".panopticon", "config.json")))
            self.assertIsNone(summary["stale_config_json"])
            self.assertFalse(summary["legacy_present"])

    def test_provision_discloses_a_stale_config_json(self):
        # #1681: the retired file is never read and never deleted for the
        # operator -- it is DISCLOSED, so nobody keeps editing a dead file.
        d = _repo(self)
        with open(os.path.join(d, ".panopticon", "config.json"), "w") as fh:
            json.dump({"max_per_group": 5}, fh)
        summary = setup_flow.provision(d)
        self.assertIn("settings:", summary["stale_config_json"])

    def test_provision_leaves_blanket_panopticon_ignore_untouched(self):
        # #1135: a repo that already blanket-ignores .panopticon/ must NOT have
        # its .gitignore rewritten -- no in-place migration to .panopticon/*, no
        # !.panopticon/ re-exposing the directory.
        d = _repo(self)
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write("node_modules/\n.panopticon/\n")
        setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertIn(".panopticon/", gi)
        self.assertNotIn(".panopticon/*", gi)   # not migrated
        self.assertNotIn("!.panopticon/", gi)   # dir not re-exposed
        # the draft lives at the ROOT now, so it is ignored either way
        self.assertIn(setup_flow.repo_config.DRAFT_NAME, gi)

    def test_provision_never_re_exposes_the_artifact_directory(self):
        # M5: `!.panopticon/` existed to re-include the directory so that
        # `.panopticon/groups.yml` could be committed out of it. Since #1681
        # nothing under there is committable -- the config is a root file --
        # so the negation buys a target nothing and re-exposes a directory of
        # run artifacts to the next `git add .`.
        d = _repo(self)
        setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertIn(".panopticon/*", gi)       # run artifacts still ignored
        self.assertNotIn("!", gi)                # and nothing re-included

    def test_provision_fresh_repo_adds_the_artifact_block(self):
        d = _repo(self)  # no .gitignore
        setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertIn(".panopticon/*", gi)
        # M5: no negation of any kind -- neither the per-file one the legacy
        # matrix needed nor the directory one that re-included it.
        self.assertNotIn("!.panopticon/", gi)
        self.assertNotIn("!.panopticon/groups.yml", gi)   # nothing there is committed

    def test_provision_leaves_an_existing_star_form_alone(self):
        # .panopticon/* already present -> nothing to add for it (pure append,
        # never a rewrite). M5: there is no directory negation to append after
        # it any more, so the only new lines are the always-ignore entries.
        d = _repo(self)
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write(".panopticon/*\n")
        setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertEqual(gi.count(".panopticon/*"), 1)   # not duplicated
        self.assertNotIn("!.panopticon/", gi)
        self.assertIn(setup_flow.repo_config.DRAFT_NAME, gi)

    def test_seed_writes_a_versioned_root_config_through_the_one_writer(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "src"))
            open(os.path.join(d, "src", "a.py"), "w").close()
            path, created, names = setup_flow.seed_flat_manifest(d)
            self.assertEqual(path, os.path.join(d, "panopticon.yml"))
            self.assertTrue(created)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn("version: 1\n", text)
            self.assertIn("src", names)

    def test_seed_never_clobbers_and_reads_the_root_file_back(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Kept:\n    match: ['k/**']\n")
            path, created, names = setup_flow.seed_flat_manifest(d)
            self.assertFalse(created)
            self.assertEqual(names, ["Kept"])

    def test_seed_never_creates_through_a_planted_link(self):
        # `repo_config.resolve` refuses to follow a symlink at either config
        # name, and the O_EXCL|O_NOFOLLOW create then refuses it a second time
        # -- so a planted link is reported as an existing config, never written
        # through (the dangling-creation primitive #1577 closed for the seed).
        with tempfile.TemporaryDirectory() as d:
            outside = os.path.join(d, "not-yet-there.yml")
            os.symlink(outside, os.path.join(d, "panopticon.yml"))
            _path, created, _names = setup_flow.seed_flat_manifest(d)
            self.assertFalse(created)
            self.assertFalse(os.path.exists(outside), "the link's target was created")

    def test_provision_refuses_a_legacy_tree(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write("groups: {}\n")
            with self.assertRaisesRegex(ValueError, "migrate-config"):
                setup_flow.provision(d)

    def test_migrate_config_round_trips_the_legacy_groups(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            legacy = ("groups:\n  Orchestration:\n    Phases:\n      match: ['skill/scripts/phases/**']\n"
                      "      tests: ['tests/phases/**']\n  CI:\n    match: ['.github/**']\n"
                      "exclude_paths: ['vendor/**']\n")
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write(legacy)
            path, message = setup_flow.migrate_config(d)
            self.assertEqual(path, os.path.join(d, "panopticon.yml"))
            self.assertTrue(os.path.isfile(os.path.join(d, ".panopticon", "groups.yml")))  # left for the operator
            self.assertIn("delete", message)
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            self.assertEqual(doc["version"], 1)
            self.assertEqual(list(doc["groups"]), ["Orchestration", "CI"])       # order preserved
            self.assertEqual(doc["groups"]["Orchestration"]["Phases"]["tests"], ["tests/phases/**"])
            self.assertEqual(doc["exclude_paths"], ["vendor/**"])

    def test_migrate_config_normalizes_the_legacy_list_form(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write("groups:\n  - name: App\n    match: ['app/**']\n"
                         "  - name: Web\n    match: ['web/**']\n")
            path, _message = setup_flow.migrate_config(d)
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            self.assertEqual(list(doc["groups"]), ["App", "Web"])
            self.assertEqual(doc["groups"]["App"]["match"], ["app/**"])

    def _legacy(self, d, body, mode="w"):
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        path = os.path.join(d, ".panopticon", "groups.yml")
        with open(path, mode) as fh:
            fh.write(body)
        return path

    def test_migrate_config_refuses_an_unreadable_legacy_file(self):
        # The cap, the shape and the parse are all refusals in the SAME
        # currency -- ValueError -- so `driver migrate-config` has one thing
        # to catch and the operator one kind of message to read.
        with tempfile.TemporaryDirectory() as d:
            self._legacy(d, "groups: [valid yaml: [")
            with self.assertRaisesRegex(ValueError, "unreadable"):
                setup_flow.migrate_config(d)
        with tempfile.TemporaryDirectory() as d:
            self._legacy(d, "- just\n- a list\n")
            with self.assertRaisesRegex(ValueError, "must be a mapping"):
                setup_flow.migrate_config(d)
        cap = setup_flow.repo_config.MAX_CONFIG_BYTES
        with tempfile.TemporaryDirectory() as d:
            self._legacy(d, "groups:\n  App:\n    match: ['a/**']\n#" + "x" * cap)
            with self.assertRaisesRegex(ValueError, "exceeds %d bytes" % cap):
                setup_flow.migrate_config(d)

    def test_migrate_config_refuses_a_symlinked_legacy_file(self):
        # A target repo can commit `.panopticon/groups.yml` as a link to any
        # file the invoking user can read; migrate would otherwise parse it and
        # publish whatever it found as the repo's own config.
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, "elsewhere.yml"), "w") as fh:
                fh.write("groups:\n  Sneaky:\n    match: ['**']\n")
            os.symlink(os.path.join(d, "elsewhere.yml"),
                       os.path.join(d, ".panopticon", "groups.yml"))
            with self.assertRaisesRegex(ValueError, "to migrate"):
                setup_flow.migrate_config(d)
            self.assertIsNone(setup_flow.repo_config.resolve(d).path)

    def test_migrate_config_refuses_when_a_root_file_exists_or_no_legacy(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, "no `.panopticon/groups.yml`"):
                setup_flow.migrate_config(d)
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
                fh.write("groups: {}\n")
            with open(os.path.join(d, "panopticon.yml"), "w") as fh:
                fh.write("version: 1\ngroups: {}\n")
            with self.assertRaisesRegex(ValueError, "already exists"):
                setup_flow.migrate_config(d)

    def test_migrate_config_refuses_a_symlinked_root_config(self):
        # A REFUSED symlink at either config name resolves to `path is None`
        # WITH a disclosure. Guarding on the path alone read that as "no root
        # config", migration proceeded, and the one writer's unlink-and-retry
        # then destroyed the operator's link and wrote a regular file over it.
        legacy = "groups:\n  App:\n    match: ['app/**']\n"
        outside_text = "version: 1\ngroups: {}\n"
        with tempfile.TemporaryDirectory() as d:
            self._legacy(d, legacy)
            outside = os.path.join(d, "elsewhere.yml")
            with open(outside, "w") as fh:
                fh.write(outside_text)
            link = os.path.join(d, "panopticon.yml")
            os.symlink(outside, link)
            with self.assertRaisesRegex(ValueError, "symlink"):
                setup_flow.migrate_config(d)
            self.assertTrue(os.path.islink(link), "the operator's symlink was replaced")
            with open(outside, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), outside_text)   # never written through
            with open(os.path.join(d, ".panopticon", "groups.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), legacy)         # legacy file untouched

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
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups:\n  Checkout:\n    API:\n      match: ['src/checkout/api/**']\n"
                     "      panels: [SEC]\n    Core:\n      match: ['src/checkout/**']\n")
        cm = setup_flow.committed_matrix(d)
        self.assertEqual(list(cm["Checkout"]["subgroups"]), ["API", "Core"])
        self.assertEqual(cm["Checkout"]["subgroups"]["API"]["panels"], ["SEC"])
        self.assertEqual(cm["Checkout"]["subgroups"]["Core"],
                         {"match": ["src/checkout/**"], "tests": [], "panels": [], "exclude": []})
        self.assertNotIn("match", cm["Checkout"])

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
        import yaml as _yaml
        with open(res["draft"], encoding="utf-8") as fh:
            drafted = _yaml.safe_load(fh)["groups"]
        self.assertEqual(list(drafted["Checkout"]), ["API", "Core"])     # parent intact
        self.assertEqual(drafted["Search"]["match"], ["src/search/**"])

    @contextlib.contextmanager
    def _ingest_fixture(self):
        """A temp repo with a valid setup-proposal.json on disk, yielded as
        (repo, proposal_path). One proposal body, shared by every test that
        needs a successful ingest."""
        d = _repo(self)
        proposal = {"groups": [{"capability": "Checkout",
                                "match": ["src/checkout/**"], "tests": []}]}
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump(proposal, fh)
        yield d, pp

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

    def test_the_draft_carries_a_committed_setting_the_cli_cannot_express(self):
        # The #1504 failure one key over: the draft used to be told the two
        # numbers the CLI passes and nothing else, so a committed `max_verify`
        # -- live, read by driver._cli_flags -- vanished the moment the
        # operator followed the completion message and moved the draft over.
        # The draft is the committed settings OVERLAID by what was passed.
        with self._ingest_fixture() as (d, pp):
            with open(os.path.join(d, "panopticon.yml"), "w") as fh:
                fh.write("version: 1\ngroups: {}\n"
                         "settings:\n  max_per_group: 8\n  max_verify: 4\n")
            result = setup_flow.ingest_proposal(d, pp, max_per_group=12)
            self.assertTrue(result["ok"], result.get("errors"))
            with open(result["draft"], encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            self.assertEqual(doc["settings"], {"max_per_group": 12, "max_verify": 4})

    def test_the_draft_keeps_the_committed_sizes_when_no_flags_were_passed(self):
        with self._ingest_fixture() as (d, pp):
            with open(os.path.join(d, "panopticon.yml"), "w") as fh:
                fh.write("version: 1\ngroups: {}\n"
                         "settings:\n  max_per_group: 8\n  max_groups: 3\n")
            result = setup_flow.ingest_proposal(d, pp)
            with open(result["draft"], encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            self.assertEqual(doc["settings"], {"max_per_group": 8, "max_groups": 3})

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

    def test_provision_refuses_an_authored_but_invalid_root_config(self):
        # The `scan` half of the same hole: setup's first write is the
        # .gitignore scaffold, and it went ahead against a config nothing
        # downstream can read.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "panopticon.yml"), "w") as fh:
                fh.write("groups: {}\n")                        # no `version: 1`
            with self.assertRaisesRegex(ValueError, "version: 1"):
                setup_flow.provision(d)

    def test_provision_refuses_a_symlinked_root_config(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "elsewhere.yml"), "w") as fh:
                fh.write("version: 1\ngroups: {}\n")
            link = os.path.join(d, "panopticon.yml")
            os.symlink(os.path.join(d, "elsewhere.yml"), link)
            with self.assertRaisesRegex(ValueError, "symlink"):
                setup_flow.provision(d)
            self.assertTrue(os.path.islink(link))

    def test_provision_still_scaffolds_a_tree_with_no_config(self):
        # The other side of the line: a FIRST run has no root config at all,
        # and a leftover retired JSON config beside it is informational (it is
        # printed, not refused). Neither may turn setup into a refusal.
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "config.json"), "w") as fh:
                fh.write('{"max_per_group": 5}')
            summary = setup_flow.provision(d)
            self.assertIn(".panopticon/*", self._gitignore(d))
            self.assertIn("no longer read", summary["stale_config_json"])

    def test_ingest_malformed_proposal_fails_no_draft(self):
        d = _repo(self)
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump({"groups": [{"capability": "", "match": []}]}, fh)
        res = setup_flow.ingest_proposal(d, pp)
        self.assertFalse(res["ok"])
        self.assertTrue(res["errors"])
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
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups:\n  Checkout:\n    match: ['src/checkout/**']\n"
                     "    panels: [SEC]\n")
        return d

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

    def _settings(self, d, body):
        """Re-write the spine repo's root config with `settings:` appended."""
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups:\n  Checkout:\n    match: ['src/checkout/**']\n"
                     "    panels: [SEC]\n" + body)

    def test_build_spine_size_precedence_matches_ingest(self):
        d = self._spine_repo()
        self._settings(d, "settings:\n  max_per_group: 2\n  max_groups: 6\n")
        spine = setup_flow.build_spine(d)
        self.assertEqual((spine["cap"], spine["ceiling"], spine["ceiling_source"]),
                         (2, 6, "config"))
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

    def test_readiness_driver_roles_are_derived_not_shadowed(self):
        # #run7 ARC-A4C once guarded a hand-maintained shadow of
        # dispatch.ROLE_FILES against drift with a RuntimeError. #1606 removed
        # the shadow: _driver_roles IS probes.common.DRIVER_ROLES, which derives
        # from ROLE_FILES, so drift cannot happen and the trip is gone. Pinned
        # so a future "local copy" cannot quietly reintroduce the gap that
        # left `advisor` unchecked.
        import dispatch
        self.assertIs(probes_common.DRIVER_ROLES, setup_flow._driver_roles)
        self.assertEqual(tuple(sorted(dispatch.ROLE_FILES)), setup_flow._driver_roles)

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

    def test_provision_treats_globstar_panopticon_ignore_as_blanket(self):
        # #run7 ARC-A2B: a `**/`-prefixed blanket ignore also excludes the
        # .panopticon directory, so git can't re-include anything out of it.
        # Provision must leave it untouched (not append a committable block that
        # can't take effect).
        d = _repo(self)
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write("node_modules/\n**/.panopticon/\n")
        setup_flow.provision(d)
        gi = self._gitignore(d)
        self.assertNotIn(".panopticon/*", gi)   # not migrated
        self.assertNotIn("!.panopticon/", gi)   # dir not re-exposed


    # --- 5.2 stage 3 wiring: size policy, layers, the setup report -----------

    def _write_proposal(self, d, proposal):
        pp = os.path.join(d, ".panopticon", "setup-proposal.json")
        with open(pp, "w") as fh:
            json.dump(proposal, fh)
        return pp

    def _root_settings(self, d, body):
        with open(os.path.join(d, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups: {}\n" + body)

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

    def test_ingest_writes_the_report_and_resolves_cap_cli_over_config(self):
        d = _repo(self)
        self._root_settings(d, "settings:\n  max_per_group: 2\n  max_groups: 6\n")
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
        self.assertFalse(os.path.isfile(setup_flow.repo_config.draft_path(d)))
        self.assertFalse(os.path.isfile(os.path.join(d, ".panopticon", "setup-report.md")))


class TestSeedGroupsManifestInjection(unittest.TestCase):
    """#1108: hostile top-level directory names must not inject YAML structure
    into the seeded root config -- the seeder validates via the schema and
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
        path, created, names = setup_flow._seed_groups_manifest(d)
        self.assertTrue(created)
        with open(path, encoding="utf-8") as fh:
            doc = _yaml.safe_load(fh.read())          # parses cleanly -> no injection
        self.assertEqual(set(doc["groups"]), {"app"})  # hostile names dropped
        self.assertEqual(doc["groups"]["app"]["match"], ["app/**"])
        self.assertEqual(names, ["app"])

    def test_atomic_create_never_clobbers_a_racing_manifest(self):
        # #run7 COD-F1B: the top-of-function resolve() guard is a fast path, not
        # a lock. If a config appears AFTER that check (a concurrent seed), the
        # O_EXCL create must refuse to truncate it -- created=False, bytes
        # intact. Simulate the race by making the fast-path resolve answer
        # "nothing committed" so execution falls through to the atomic create
        # against a file that already exists on disk.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "app"))
        with open(os.path.join(d, "app", "main.py"), "w") as fh:
            fh.write("x = 1\n")
        path = os.path.join(d, "panopticon.yml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("version: 1\ngroups:\n  Winner:\n    match: ['src/**']\n")
        absent = setup_flow.repo_config.Resolution(None, [])
        with mock.patch.object(setup_flow.repo_config, "resolve", return_value=absent):
            _p, created, _names = setup_flow._seed_groups_manifest(d)
        self.assertFalse(created)
        with open(path, encoding="utf-8") as fh:
            self.assertIn("Winner", fh.read())   # existing config not clobbered


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
    only the literal spellings, so setup read the repo as un-blanketed and
    appended a committable block its `!.panopticon/` negation then RE-EXPOSED
    the directory with -- rewriting a policy nobody had asked it to touch.
    Since #1681 nothing committable lives under there, but the rule stands:
    provision APPENDS, and never rewrites what a repo already decided.
    """

    def test_glob_form_blanket_is_left_untouched(self):
        d = _git_repo(self, "node_modules/\n.panopticon*/\n")
        setup_flow.provision(d)
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            gi = fh.read()
        self.assertNotIn(".panopticon/*", gi)      # no committable block
        self.assertNotIn("!.panopticon/", gi)      # directory not re-exposed

    def test_setup_leaves_a_glob_blanketed_tree_clean(self):
        # The first thing a new adopter sees after `driver setup` must not be an
        # unexplained diff in a file they did not touch -- and a self-scan run
        # straight after setup would start on a dirty tree, which validate reads
        # as a tamper signal.
        d = _git_repo(self, "node_modules/\n.panopticon*/\n"
                            ".claude/settings.local.json\n"
                            + setup_flow.repo_config.DRAFT_NAME + "\n")
        setup_flow.provision(d)
        self.assertEqual(_status(d), "")

    def test_the_literal_form_still_behaves_as_before(self):
        d = _git_repo(self, ".panopticon/\n.claude/settings.local.json\n"
                            + setup_flow.repo_config.DRAFT_NAME + "\n")
        setup_flow.provision(d)
        self.assertEqual(_status(d), "")

    def test_a_contents_form_repo_gets_no_negation(self):
        # `.panopticon/*` ignores the CONTENTS, not the directory, so the
        # directory is visible without being re-included -- and since M5
        # nothing under it is committable, so nothing re-includes it.
        d = _git_repo(self, ".panopticon/*\n")
        setup_flow.provision(d)
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            gi = fh.read()
        self.assertNotIn("!.panopticon/", gi)
        self.assertEqual(gi.count(".panopticon/*"), 1)

    def test_a_fresh_git_repo_still_gets_the_full_block(self):
        d = _git_repo(self, "node_modules/\n")
        setup_flow.provision(d)
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            gi = fh.read()
        self.assertIn(".panopticon/*", gi)
        self.assertIn(setup_flow.repo_config.DRAFT_NAME, gi)

    def test_glob_form_is_recognised_without_git(self):
        # Not every target is a checkout; the pattern fallback must know the
        # same spellings git does, or a non-git tree regresses to the bug.
        d = _repo(self)
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write(".panopticon*/\n")
        setup_flow.provision(d)
        with open(os.path.join(d, ".gitignore"), encoding="utf-8") as fh:
            gi = fh.read()
        self.assertNotIn("!.panopticon/", gi)


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
        text = sp.dump_config_yaml(
            {"Checkout": {"match": ["src/checkout/**"], "panels": ["SEC"]}},
            exclude_paths=["tests/fixtures/**", "vendor/**"])
        doc = yaml.safe_load(text)
        globs, errors = groups_schema.parse_exclude_paths(doc)
        self.assertEqual(errors, [])
        self.assertEqual(globs, ["tests/fixtures/**", "vendor/**"])

    def test_dump_omits_the_key_when_there_is_nothing_to_carry(self):
        import scripts.setup_proposal as sp
        import yaml
        text = sp.dump_config_yaml({"G": {"match": ["a/**"], "panels": ["SEC"]}})
        self.assertNotIn("exclude_paths", yaml.safe_load(text))

    def test_the_groups_mapping_still_round_trips(self):
        import scripts.setup_proposal as sp
        import scripts.groups_schema as groups_schema
        import yaml
        text = sp.dump_config_yaml(
            {"Checkout": {"match": ["src/checkout/**"], "panels": ["SEC"]}},
            exclude_paths=["tests/fixtures/**"])
        groups, errors = groups_schema.parse_groups(yaml.safe_load(text))
        self.assertEqual(errors, [])
        self.assertIn("Checkout", groups)

    def test_dump_config_yaml_puts_version_first_and_settings_last(self):
        import setup_proposal as sp
        import yaml
        text = sp.dump_config_yaml({"App": {"match": ["src/**"]}},
                                   exclude_paths=["vendor/**"],
                                   settings={"max_per_group": 48, "max_groups": None})
        body = text.split(
            "# parent; its subgroups are its layers and roll up to it in the report.\n"
            "# settings: max_per_group / max_groups / max_verify (positive ints).\n", 1)[1]
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
        import yaml
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


class TestReadinessCannotAssertWhatItDidNotCheck(unittest.TestCase):
    """#1344 F2: P2/P3 cease to be expressible."""

    def setUp(self):
        _isolate_codex_probes(self)

    def _check(self, host):
        # #1599: the posture probe is mocked and a real tree is named. This
        # used to reach `host_probes.run_probes` with repo_root=None, which
        # read ~/.claude/agents and ~/.codex/agents on whatever machine ran
        # the suite -- these assertions are about the REGISTRY, not about the
        # developer's home directory.
        with mock.patch.object(host_probes, "run_probes",
                               return_value=_shell_less_artifact(host)):
            return dict((name, (ok, detail))
                        for name, ok, detail in
                        setup_flow._check_host_shells(host, lambda *a, **k: None,
                                                      "."))

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

        # #1599: mocked, and given a tree. Unmocked this reached the live
        # Codex probes and read the home directory of whoever ran the suite;
        # the subject here is the `codex --version` call recorded in `calls`.
        with mock.patch.object(host_probes, "run_probes",
                               return_value=_shell_less_artifact("codex")):
            result = dict((name, (ok, detail)) for name, ok, detail
                          in setup_flow._check_host_shells("codex", runner, "."))
        self.assertIn(["codex", "--version"], calls,
                      "readiness stopped probing for the Codex CLI")
        ok, detail = result["codex-cli"]
        self.assertFalse(ok)
        self.assertIn("Codex CLI unavailable", detail)


def _mixed_artifact(host):
    """A host-capabilities.json envelope with a genuinely MIXED posture: one
    proven, one refuted, three unknown -- each on a DIFFERENT capability, per
    the plan's Global Constraint. Same shape as
    tests/test_host_disclosure.py's module-level MIXED fixture, redefined
    locally rather than imported so this file does not reach into another
    test module for its data."""
    return {
        "schema_version": 1, "host": host, "probed_at": "T",
        "capabilities": {
            hosts.TOOL_POLICY_ENFORCED: {
                "state": hosts.REFUTED, "by": "shadow-shell-scan",
                "detail": "the reviewed tree ships .claude/agents/panopticon-scout.md"},
            hosts.ARTIFACT_WRITE_GUARD: {
                "state": hosts.PROVEN, "by": "write-guard-armed",
                "detail": "round-trip denied"},
            hosts.USAGE_LEDGER: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "no transcript directory"},
            hosts.READ_SCOPE_CONFINED: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "claude proves this since plan 5; other hosts do not claim it"},
            hosts.MODEL_BINDING: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "dispatch entries carry model=None until F4 binds them"},
        },
    }


def _all_proven_artifact(host):
    """Every capability PROVEN, for pairing with a host that CLAIMS all five
    (see test_an_all_proven_host_says_so_rather_than_reporting_nothing) -- an
    all-proven artifact alone is not enough: the synthetic fixture pins the
    shape; claude proves read_scope_confined since plan 5, other hosts do
    not claim it, so hosts.posture()'s claim-mask would still force that one
    to unknown on a host that does not claim it, and the NOT-PROVEN headline
    would fire regardless of what this fixture says."""
    return {
        "schema_version": 1, "host": host, "probed_at": "T",
        "capabilities": {cap: {"state": hosts.PROVEN, "by": "fixture",
                               "detail": "proven"} for cap in hosts.CAPABILITIES},
    }


def _shell_less_artifact(host):
    """What `run_probes` really returns for a host that registers no shells and
    claims nothing: five honest unknowns, each with its OWN reason.

    Not mixed across STATES, because gemini/generic cannot reach a mixed one --
    `hosts.posture()`'s claim-mask forces every non-refuted state to unknown
    for a host that claims nothing, so a proven entry here would be a fixture
    asserting something the registry cannot produce. Mixed where it can be:
    five different details, and one capability whose `by` names a probe that
    actually ran (the shadow scan runs for any host, claim or no claim), so a
    renderer that hard-codes one capability's shape fails on the other four.
    """
    return {
        "schema_version": 1, "host": host, "probed_at": "T",
        "capabilities": {
            hosts.TOOL_POLICY_ENFORCED: {
                "state": hosts.UNKNOWN, "by": "shadow-shell-scan",
                "detail": "host %r discovers no project-scoped agents" % host},
            hosts.ARTIFACT_WRITE_GUARD: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "no probe: host %r does not claim this capability, "
                          "so there is nothing to prove" % host},
            hosts.USAGE_LEDGER: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "no probe: host %r does not claim this capability, "
                          "so there is nothing to prove" % host},
            hosts.READ_SCOPE_CONFINED: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "no probe: host %r does not claim this capability, "
                          "so there is nothing to prove" % host},
            hosts.MODEL_BINDING: {
                "state": hosts.UNKNOWN, "by": None,
                "detail": "no probe in F3a: dispatch entries still carry "
                          "model=None (spec 8, F4)"},
        },
    }


def _runner_ok(cmd, **kwargs):
    """A `runner` that never touches a real process. The new host-capability
    probing code does not take `runner` at all (host_probes.run_probes is
    mocked directly in these tests); this only stands in for the codex-cli
    `_probe` call other hosts' checks make, which none of these tests reach."""
    return subprocess.CompletedProcess(cmd, 0, "", "")


class TestReadinessProbesThePostureAndNamesTheFix(unittest.TestCase):
    """#1344 F3b Task 6, surface 4 (spec 5.1). `driver setup` has no run
    directory, so there is no artifact to read -- readiness must probe. All
    assertions here go through host_disclosure's own constants/behaviour
    rather than hand-rolled substrings, per the plan's standing rule: "NOT
    PROVEN" contains "PROVEN" as a substring, so a bare `assertIn("PROVEN",
    ...)` cannot tell the all-proven case from a 1-of-5 NOT-PROVEN case."""

    def test_readiness_reports_every_unproven_capability_with_its_remedy(self):
        with mock.patch.object(host_probes, "run_probes",
                               return_value=_mixed_artifact("claude")):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        named = {c[0]: c for c in checks}
        refuted = named["host-capability:" + hosts.TOOL_POLICY_ENFORCED]
        self.assertIs(False, refuted[1])
        self.assertIn("shadow-shell-scan", refuted[2])
        self.assertIn("fix:", refuted[2])
        unknown = named["host-capability:" + hosts.USAGE_LEDGER]
        self.assertIsNone(unknown[1], "unknown is NOT APPLICABLE, not failed")

    def test_a_proven_capability_gets_no_readiness_row(self):
        with mock.patch.object(host_probes, "run_probes",
                               return_value=_mixed_artifact("claude")):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        self.assertNotIn("host-capability:" + hosts.ARTIFACT_WRITE_GUARD,
                         [c[0] for c in checks])

    def test_an_all_proven_host_says_so_rather_than_reporting_nothing(self):
        # 5.1's inverse: absence of warnings must mean "measured and proven",
        # never "nobody looked". The synthetic fixture pins the shape; claude
        # proves this capability since plan 5, other hosts do not claim it
        # -- test_host_disclosure.py's TestTheInverseCarriesEqualWeight
        # hits the identical trap and resolves it the same way: patch a real
        # host's claims to all five rather than asserting something the real
        # registry cannot produce. Claude's claims are patched (not a wholly
        # synthetic host name) so shell_format/registration_dir stay real and
        # _check_host_shells still reaches the probing code -- a synthetic
        # HostSpec with no shell_format would return from the enforced-shells
        # branch before ever getting there, proving nothing about this
        # surface.
        assert setup_flow.hosts is hosts, (
            "setup_flow's hosts import has drifted from the canonical "
            "scripts.hosts module -- patching hosts.HOSTS below would be a "
            "silent no-op")
        claiming = dataclasses.replace(hosts.HOSTS["claude"],
                                       claims=frozenset(hosts.CAPABILITIES))
        with mock.patch.dict(hosts.HOSTS, {"claude": claiming}), \
                mock.patch.object(host_probes, "run_probes",
                                  return_value=_all_proven_artifact("claude")):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        row = {c[0]: c for c in checks}["host-capabilities"]
        self.assertIs(True, row[1])
        self.assertEqual(host_disclosure.ALL_PROVEN, row[2])

    def test_an_operational_note_does_not_downgrade_an_all_proven_row(self):
        # N2: readiness reads `head == ALL_PROVEN` as its PASS. An operational
        # fact appended to the capability lines made `head` something else on
        # every headless run whose CLI lacks --json-schema, so a fully proven
        # host reported WARN for a flag that gates nothing.
        artifact = dict(_all_proven_artifact("claude"))
        artifact[hosts.CLI_FLAGS] = {
            hosts.OUTPUT_SCHEMA: {"flag": "--json-schema", "advertised": False,
                                  "detail": "`claude --help` does not advertise it"}}
        claiming = dataclasses.replace(hosts.HOSTS["claude"],
                                       claims=frozenset(hosts.CAPABILITIES))
        with mock.patch.dict(hosts.HOSTS, {"claude": claiming}), \
                mock.patch.object(host_probes, "run_probes", return_value=artifact):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        row = {c[0]: c for c in checks}["host-capabilities"]
        self.assertIs(True, row[1])
        self.assertEqual(host_disclosure.ALL_PROVEN, row[2])

    def test_a_probe_failure_does_not_crash_readiness(self):
        # Readiness must survive a probe that raises; a setup command that
        # tracebacks tells the operator nothing about what to fix.
        with mock.patch.object(host_probes, "run_probes",
                               side_effect=OSError("boom")):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        row = {c[0]: c for c in checks}["host-capabilities"]
        self.assertIsNone(row[1])
        self.assertIn("could not be probed", row[2])


class TestReadinessNeverReadsAnUnreadableEnvelopeAsProof(unittest.TestCase):
    """`host_disclosure.lines()` returns [] for TWO different reasons -- every
    capability is proven, AND the envelope is unreadable (`caps is None or host
    is None`). Readiness collapsed them into one `ok=True, ALL_PROVEN` row,
    which is precisely what `headline()`'s docstring says must never happen:
    "an empty result from a missing artifact would render as the all-proven
    case and turn 5.1's guarantee inside out". It also rendered as a PASSING
    readiness check rather than a limitation.

    Readiness reads the module's three-outcome contract instead of re-deriving
    a two-outcome one from `lines()`.
    """

    BAD = {
        "host is not a string": {"host": None, "capabilities": {
            hosts.TOOL_POLICY_ENFORCED: {"state": hosts.REFUTED,
                                         "by": "shadow-shell-scan",
                                         "detail": "ships panopticon-scout.md"}}},
        "capabilities is not a mapping": {"host": "claude",
                                          "capabilities": "garbage"},
        "the artifact is not a dict at all": "not-a-dict",
        "the artifact is empty": {},
    }

    def test_an_unreadable_envelope_reports_no_evidence_not_all_proven(self):
        for name, bad in self.BAD.items():
            with self.subTest(envelope=name):
                with mock.patch.object(host_probes, "run_probes",
                                       return_value=bad):
                    checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
                row = {c[0]: c for c in checks}["host-capabilities"]
                # By EQUALITY against the module's own constants: "1 of 5 NOT
                # PROVEN" contains "PROVEN", so no substring test here can tell
                # the two apart.
                self.assertEqual(("host-capabilities", None,
                                  host_disclosure.NO_EVIDENCE), row)

    def test_no_evidence_emits_no_per_capability_rows(self):
        # Nothing was measured, so there is no per-capability verdict to
        # report. Five rows whose detail is a bare capability name would be
        # "unenforced alone" -- a mood, not a disclosure (5.1).
        with mock.patch.object(host_probes, "run_probes", return_value={}):
            checks = setup_flow._check_host_shells("claude", _runner_ok, ".")
        self.assertEqual([], [c for c in checks
                              if c[0].startswith("host-capability:")])


class TestShellLessHostsGetTheWholeDisclosure(unittest.TestCase):
    """`gemini` and `generic` are the two registry rows that claim NOTHING and
    register no shells, so five-of-five-unproven is their entire story -- and
    the `enforced-shells` early return handed them one line that named the
    host and no capability, no probe and no remedy. 5.1 names no exemption for
    shell-less hosts.

    Both rows are still exercised after gemini left the selectable set (#1621,
    2026-09-13): `_check_host_shells` reads the REGISTRY, which still knows
    gemini, and the disclosure it owes a shell-less host is a fact about the
    row rather than about whether `--host` will accept the name.
    """

    def _rows(self, host):
        with mock.patch.object(host_probes, "run_probes",
                               return_value=_shell_less_artifact(host)):
            return dict((c[0], c) for c in
                        setup_flow._check_host_shells(host, _runner_ok, "."))

    def test_the_enforced_shells_row_it_already_had_survives(self):
        for host in ("gemini", "generic"):
            with self.subTest(host=host):
                row = self._rows(host)["enforced-shells"]
                self.assertIsNone(row[1])
                self.assertIn("registers no", row[2])

    def test_it_gets_a_headline_and_a_row_per_capability_with_the_remedy(self):
        for host in ("gemini", "generic"):
            with self.subTest(host=host):
                rows = self._rows(host)
                head = rows["host-capabilities"]
                self.assertIsNone(head[1])
                self.assertNotEqual(host_disclosure.ALL_PROVEN, head[2])
                self.assertNotEqual(host_disclosure.NO_EVIDENCE, head[2])
                for capability in hosts.CAPABILITIES:
                    with self.subTest(capability=capability):
                        row = rows["host-capability:" + capability]
                        self.assertIn(capability, row[2])
                        self.assertIn(host, row[2])
                        # the remedy VERBATIM, per capability -- five distinct
                        # strings, so a surface that rendered one of them for
                        # all five fails here.
                        self.assertIn(host_disclosure.remedy(capability, host),
                                      row[2])


class TestReadinessDoesNotSwallowTheLaunchGuard(unittest.TestCase):
    """N-M3: readiness's `except Exception` around run_probes turned the
    suite's no-live-launch refusal into a benign "posture could not be probed"
    row. That is exactly the failure I-5 exists to remove, on exactly the path
    that forced `_isolate_codex_probes` to exist -- readiness reaches a live
    Codex probe. Latent today, because nothing in the suite gets that far;
    structural, because the guarantee has to hold for the test nobody has
    written yet."""

    @staticmethod
    def _runner(cmd, **kw):
        """readiness also probes `codex --version`; that must never be the
        real binary (the guardrails' "suite never launches a host binary",
        which a PATH-shim run catches). Every readiness call here injects it.
        """
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    def test_readiness_with_no_injected_runner_cannot_reach_the_real_cli(self):
        """N-M3 round 2 fixed the two tests below by injecting a runner. That
        is discipline, and discipline is what failed here: readiness probes
        `codex --version` through a runner bound as a DEFAULT ARGUMENT, so the
        autouse guard could not reach it and the NEXT test to forget would
        launch the real binary and stay green. With the launcher read from a
        module attribute, forgetting is now loud.
        """
        from scripts import codex_host
        d = _repo(self)
        with self.assertRaises(codex_host.LaunchRefused):
            setup_flow.readiness(d, host="codex")

    def test_a_refused_live_launch_escapes_readiness(self):
        from scripts import codex_host
        d = _repo(self)
        with mock.patch.object(
                host_probes, "run_probes",
                side_effect=codex_host.LaunchRefused("test tried to launch the real codex CLI")):
            with self.assertRaises(codex_host.LaunchRefused):
                setup_flow.readiness(d, host="codex", runner=self._runner)

    def test_every_other_probe_failure_is_still_a_readiness_row(self):
        d = _repo(self)
        with mock.patch.object(host_probes, "run_probes",
                               side_effect=RuntimeError("probe exploded")):
            rows = setup_flow.readiness(d, host="codex", runner=self._runner)
        posture = dict((name, detail) for name, _ok, detail in rows)
        self.assertIn("host-capabilities", posture)
        self.assertIn("probe exploded", posture["host-capabilities"])


class TestSetupArtifactWritesDoNotFollowSymlinks(unittest.TestCase):
    """#1577 (SEC-D1C): the five `--setup` artifact writes were plain `open()`
    on paths derived from an untrusted target tree.

    `plan_contract.artifact_root()` validates that the `.panopticon` DIRECTORY
    is not a symlink; it never looks at the LEAF. A target that force-commits
    `.panopticon/setup-report.md -> ~/.bash_profile` (or plain
    `.gitignore -> ~/.ssh/authorized_keys`, which needs no `-f` at all) had
    panopticon's own boilerplate written or appended through the link, as the
    invoking user, on the documented first step for a repo nobody has vetted.

    The fix is the writer this repo already converged on -- `runio`'s confined
    `O_NOFOLLOW` pair -- not a sixth spelling of the check. It answers in two
    ways, and which one fires is a property of the path, not of the caller: a
    leaf under `.panopticon` whose link resolves OUT of it is REFUSED
    (`_confine_artifact_path`, the whole-path guard), while a link the
    confinement has nothing to say about -- `.gitignore` sits in the repo root,
    not the artifact tree -- is neutralized by `O_NOFOLLOW` and replaced by a
    fresh regular file. Either way the link's target is never opened.
    """

    def _victim(self, d, name="victim.txt"):
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("SECRET")
        return path

    def _assert_untouched(self, victim):
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual("SECRET", fh.read(), "the link's target was written")

    def test_ensure_gitignore_does_not_append_through_a_planted_link(self):
        d = _repo(self)
        victim = self._victim(d)
        gi = os.path.join(d, ".gitignore")
        os.symlink(victim, gi)
        setup_flow._ensure_gitignore(d)
        self._assert_untouched(victim)
        self.assertFalse(os.path.islink(gi), "the link survived the write")
        with open(gi, encoding="utf-8") as fh:
            self.assertIn(".panopticon/*", fh.read())

    def test_write_spine_does_not_write_through_a_planted_link(self):
        d = _repo(self)
        victim = self._victim(d)
        os.symlink(victim, os.path.join(d, ".panopticon", "setup-spine.json"))
        with self.assertRaises(ValueError):
            setup_flow.write_spine(d, setup_flow.build_spine(d))
        self._assert_untouched(victim)

    def test_render_scan_brief_does_not_write_through_a_planted_link(self):
        d = _repo(self)
        victim = self._victim(d)
        os.symlink(victim, os.path.join(d, ".panopticon", "setup-scan-brief.md"))
        vocab, _present = setup_flow.load_bundled_vocabulary()
        with self.assertRaises(ValueError):
            setup_flow.render_scan_brief(d, vocab)
        self._assert_untouched(victim)

    def test_ingest_proposal_does_not_write_through_planted_links(self):
        d = _repo(self)
        root = os.path.join(d, ".panopticon")
        with open(os.path.join(root, "setup-proposal.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/checkout/**"], "tests": []}]}, fh)
        # #1681: the draft is at the ROOT now, so the two halves of the guard
        # answer differently and BOTH are asserted here. `_confine_artifact_path`
        # raises only for a path that escapes `.panopticon` through a symlinked
        # component, so the ValueError below comes from the REPORT plants; at
        # the root the link is refused by O_NOFOLLOW and then unlinked and
        # replaced with a fresh regular file (#1095's contract, the one
        # `.gitignore` has always had). Either way nothing is written THROUGH a
        # link -- which is what every victim staying SECRET proves.
        draft = setup_flow.repo_config.draft_path(d)
        plants = {setup_flow.repo_config.DRAFT_NAME: draft}
        for name in ("setup-report.md", "setup-report.json"):
            plants[name] = os.path.join(root, name)
        for name, planted in plants.items():
            os.symlink(self._victim(d, "victim-%s" % name), planted)
        with self.assertRaises(ValueError):
            setup_flow.ingest_proposal(d)
        for name in plants:
            self._assert_untouched(os.path.join(d, "victim-%s" % name))
        self.assertFalse(os.path.islink(draft), "the root link survived the write")
        self.assertTrue(os.path.isfile(draft))

    def test_the_writes_still_land_on_an_honest_tree(self):
        # The guard must not be the thing that breaks setup: same artifacts,
        # no plants, all written.
        d = _repo(self)
        with open(os.path.join(d, ".panopticon", "setup-proposal.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/checkout/**"], "tests": []}]}, fh)
        setup_flow._ensure_gitignore(d)
        setup_flow.write_spine(d, setup_flow.build_spine(d))
        vocab, _present = setup_flow.load_bundled_vocabulary()
        setup_flow.render_scan_brief(d, vocab)
        self.assertTrue(setup_flow.ingest_proposal(d)["ok"])
        for rel in (".gitignore", setup_flow.repo_config.DRAFT_NAME,
                    ".panopticon/setup-spine.json", ".panopticon/setup-scan-brief.md",
                    ".panopticon/setup-report.md", ".panopticon/setup-report.json"):
            self.assertTrue(os.path.isfile(os.path.join(d, rel)), rel)

    def test_a_planted_intermediate_panopticon_directory_is_refused(self):
        # The sibling half of the same plant: a real leaf under a `.panopticon`
        # that is itself a link out of the tree. `artifact_root` already refuses
        # this -- the assertion is that the writes stay behind it rather than
        # acquiring their own weaker check.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        outside = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(outside, ignore_errors=True))
        os.symlink(outside, os.path.join(d, ".panopticon"))
        with self.assertRaises(ValueError):
            setup_flow.write_spine(d, {"schema_version": 1})
        self.assertEqual([], os.listdir(outside))


# --- #1598 / #1599: readiness may not probe without a tree to probe ---------
# A test that DELIBERATELY calls `_check_host_shells` without a repo_root --
# the two below are the only ones -- marks the line so the AST guard at the
# bottom of this file can tell it from a site that simply forgot.
_REPO_ROOT_EXEMPT = "repo-root-exempt:"


class TestReadinessWithoutATreeSaysWhatIsMissing(unittest.TestCase):
    """#1598: called without `repo_root`, `_check_host_shells` handed the
    argument straight to `host_probes.run_probes` as `review_root`, where
    `probe_shadow_shells` joined it with a relative path and raised. The
    try/except turned that into an honest-but-useless readiness row:

        ('host-capabilities', None, "posture could not be probed: expected
         str, bytes or os.PathLike object, not NoneType")

    Non-gating and true, and no operator can act on it. An internal type
    error is not a remedy (spec 5.1: "name the capability, the host, the
    probe, and the remedy").

    #1599 is the same defect seen from the tests' side: reaching
    `run_probes` at all made two unit tests depend on whatever
    `~/.claude/agents` holds on the machine running the suite.
    """

    def _rows(self, host="claude"):
        probe = mock.patch.object(
            host_probes, "run_probes",
            side_effect=AssertionError("readiness probed with no tree to probe"))
        with probe as spy:
            checks = setup_flow._check_host_shells(host, _runner_ok)  # repo-root-exempt: the subject
        return spy, {c[0]: c for c in checks}

    def test_the_row_names_the_missing_argument_not_a_typeerror(self):
        _spy, rows = self._rows()
        _name, ok, detail = rows["host-capabilities"]
        self.assertIsNone(ok, "a caller's omission is not a host fault")
        self.assertIn("repo_root", detail)
        self.assertNotIn("NoneType", detail)
        self.assertNotIn("os.PathLike", detail)

    def test_no_probe_runs_when_there_is_nothing_to_probe(self):
        # #1599's root cause. The probes read `~/.claude/agents`,
        # `~/.codex/agents` and `.claude/settings.local.json`; a unit test that
        # supplied no tree was measuring the developer's home directory.
        spy, _rows = self._rows()
        spy.assert_not_called()

    def test_the_checks_it_can_still_make_survive(self):
        # Not a bare refusal: `enforced-shells` needs no tree, so it is still
        # reported. Only the posture row -- the one that needs a tree -- says
        # it could not be established.
        _spy, rows = self._rows()
        self.assertIn("enforced-shells", rows)
        self.assertEqual([], [n for n in rows if n.startswith("host-capability:")],
                         "no per-capability verdict may be invented from no probe")


class TestNoReadinessUnitTestReachesALiveProbe(unittest.TestCase):
    """#1599, made durable. Two tests in this file called
    `_check_host_shells(host, runner)` with `repo_root` defaulting to None and
    reached `host_probes.run_probes` unmocked -- verified harmless (the
    write-guard round-trip runs in its own TemporaryDirectory and the rest are
    read-only stats), but they measured the developer's home directory rather
    than the code.

    An AST guard, not a grep: the call is spelled across two lines at one site
    and a text rule would read the argument count off whichever line it
    matched (`git grep -E` silently ignores `\\b` and returns a false zero).
    """

    EXEMPT = _REPO_ROOT_EXEMPT
    _SKIP_DIRS = {"fixtures", "goldens", "__pycache__"}

    def _offenders(self):
        root = os.path.dirname(os.path.abspath(__file__))
        offenders = []
        for base, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in self._SKIP_DIRS)
            for name in sorted(f for f in files if f.endswith(".py")):
                path = os.path.join(base, name)
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
                lines = text.splitlines()
                for node in ast.walk(ast.parse(text, path)):
                    if not isinstance(node, ast.Call):
                        continue
                    func = node.func
                    if not (isinstance(func, ast.Attribute)
                            and func.attr == "_check_host_shells"):
                        continue
                    if len(node.args) >= 3 or any(kw.arg == "repo_root"
                                                  for kw in node.keywords):
                        continue
                    source = "\n".join(lines[node.lineno - 1:node.end_lineno])
                    if self.EXEMPT in source:
                        continue
                    offenders.append("%s:%d: %s"
                                     % (os.path.relpath(path, root), node.lineno,
                                        ast.unparse(node)))
        return offenders

    def test_every_call_site_supplies_the_tree_it_wants_probed(self):
        self.assertEqual(
            [], self._offenders(),
            "a readiness test with no repo_root measures whatever is under "
            "$HOME on this machine. Pass one, or mark the line "
            "`# %s <why>`:\n%s" % (self.EXEMPT, "\n".join(self._offenders())))

    def test_the_scanner_actually_finds_the_call_sites(self):
        # Guards the guard: a walk that matched nothing would report a clean
        # pass over an unread tree.
        root = os.path.dirname(os.path.abspath(__file__))
        seen = 0
        for base, dirs, files in os.walk(root):
            dirs[:] = sorted(d for d in dirs if d not in self._SKIP_DIRS)
            for name in sorted(f for f in files if f.endswith(".py")):
                with open(os.path.join(base, name), encoding="utf-8") as fh:
                    text = fh.read()
                for node in ast.walk(ast.parse(text, name)):
                    if (isinstance(node, ast.Call)
                            and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "_check_host_shells"):
                        seen += 1
        self.assertGreater(seen, 5, "the call-site scan found almost nothing")
