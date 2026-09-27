"""Provisioning, seed, migration, and gitignore behavior."""

import json
import os
import tempfile
import unittest
from unittest import mock

import yaml

import scripts.setup_flow as setup_flow
import shutil


from tests.setup_helpers import (
    _repo,
    _git_repo,
    _status,
    SetupFixtureBase,
)

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

class TestSetupFlow(SetupFixtureBase):
    """Provisioning, seed, migration, and gitignore behavior."""

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

class TestSeedGroupsManifestInjection(unittest.TestCase):
    """#1108: hostile top-level directory names must not inject YAML structure
    into the seeded root config -- the seeder validates via the schema and
    serializes with yaml.safe_dump instead of hand-formatting untrusted text.
    #1481: that validation must also drop a name the schema only accepts WITH
    an error -- a case twin, a chunk twin, or the reserved Ungrouped sink."""

    def test_injection_dir_names_are_dropped_and_file_parses(self):
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
            doc = yaml.safe_load(fh.read())          # parses cleanly -> no injection
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

    def test_collision_names_are_dropped_and_seeded_config_is_runnable(self):
        # COD-2612640453: parse_groups ACCEPTS a colliding name -- it only
        # reports it as an error -- so keeping "every name in parsed" kept a
        # chunk twin (src/src_1) and the reserved Ungrouped sink too. A seed
        # that writes either one reports success on a config the run path
        # then refuses.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        for sub in ("lib", "src", "src_1", "Ungrouped"):
            os.makedirs(os.path.join(d, sub))
            with open(os.path.join(d, sub, "mod.py"), "w") as fh:
                fh.write("x = 1\n")
        path, created, names = setup_flow._seed_groups_manifest(d)
        self.assertTrue(created)
        self.assertEqual(names, ["lib", "src"])          # src_1, Ungrouped dropped
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh.read())
        self.assertEqual(set(doc["groups"]), {"lib", "src"})
        # The run path's own gate: a seeded config it would refuse must not
        # be produced in the first place.
        catalog = setup_flow.discovery._matrix_catalog(d)
        self.assertEqual(set(catalog), {"lib", "src"})

    def test_case_twin_drops_the_later_sorted_name(self):
        # A case-insensitive dev filesystem cannot hold both Docs/ and docs/,
        # so this exercises the case-twin path the way probe_d2_seed.py does:
        # mock discover_repo_files rather than create the pair on disk.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "docs"))
        with open(os.path.join(d, "docs", "a.md"), "w") as fh:
            fh.write("# x\n")
        with mock.patch.object(setup_flow.discovery, "discover_repo_files",
                                return_value=["Docs/a.md", "docs/b.md"]):
            path, created, names = setup_flow._seed_groups_manifest(d)
        self.assertTrue(created)
        # _reserved_name_errors names the LATER id in sorted order ('docs'
        # sorts after 'Docs') as the collision, so 'docs' is the one dropped.
        self.assertEqual(names, ["Docs"])
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh.read())
        self.assertEqual(set(doc["groups"]), {"Docs"})
        catalog = setup_flow.discovery._matrix_catalog(d)
        self.assertEqual(set(catalog), {"Docs"})

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
