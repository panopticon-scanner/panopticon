"""#3651: a report says which matrix it ran under, so two reports can be compared honestly.

Setup proposes a different matrix nearly every run, and a review's results move with it.
`matrix_identity` is the hashing (pure); `matrix_provenance` is the Git and state-directory
half the driver runs once, when a run's manifest is created.
"""
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import yaml

import scripts.build_disclosure as build_disclosure
import scripts.discovery as discovery
import scripts.driver as driver
import scripts.html_report as html_report
import scripts.matrix_identity as mi
import scripts.matrix_provenance as mp
import scripts.phases.runio as runio
import scripts.run_manifest as run_manifest
import scripts.safe_git as safe_git
import scripts.setup_flow as setup_flow
import scripts.synth.validate_schema as validate_schema
import scripts.synthesize as syn
from tests._test_helpers import (adopt_panopticon, all_proven_artifact, docker_probe_runner,
                                 hard_link_or_skip)
from tests.orchestrate_helpers import FakeRunner, LoopCase
from tests.setup_helpers import SetupFixtureBase
from tests.synth.helpers import _chdir
from tests.tools.git_repo import make_git_repo

FILES = {"src/app.py": "x = 1\n", "src/auth/login.py": "x = 2\n", "lib/util.py": "x = 3\n"}
SHA = "sha256:" + "ab" * 32


def _config(groups, **top):
    """A config document: `groups` is a list of (name, body) so its order is the test's."""
    return dict({"version": 1, "groups": dict(groups)}, **top)


def _realise(test_case, groups):
    """(run-time groups, coverage records, config_sha256) for a config over FILES, through
    the real config reader, catalog and file assignment."""
    root = os.path.realpath(tempfile.mkdtemp())
    test_case.addCleanup(shutil.rmtree, root, True)
    for relative, body in FILES.items():
        os.makedirs(os.path.dirname(os.path.join(root, relative)), exist_ok=True)
        with open(os.path.join(root, relative), "w", encoding="utf-8") as fh:
            fh.write(body)
    with open(os.path.join(root, "panopticon.yml"), "w", encoding="utf-8") as fh:
        yaml.safe_dump(_config(groups), fh, sort_keys=False)
    catalog = discovery._matrix_catalog(root)
    realised, _residual = discovery.catalog_groups(
        [f for f in discovery.discover_repo_files(root) if f != "panopticon.yml"], catalog, 48)
    coverages = [{"group": name, "floor": sorted(leaf.get("floor") or ())}
                 for name, leaf in catalog.items()]
    return realised, coverages, mp.config_digest(root)[1]


class TestTheFingerprintIsOfTheMatrixAsApplied(unittest.TestCase):
    APP = ("app", {"match": ["src/**"], "panels": ["SEC"]})
    AUTH = ("auth", {"match": ["src/auth/**"], "panels": ["SEC", "ARC"]})
    LIB = ("lib", {"match": ["lib/**"], "panels": ["COD"]})

    def _fingerprint(self, *groups):
        realised, coverages, config = _realise(self, groups)
        return mi.matrix_fingerprint(realised, coverages), config, mi.realised(realised, coverages)

    def test_two_orderings_that_realise_the_same_cells_hash_the_same(self):
        # `app` and `lib` share no file, so which comes first decides nothing.
        one, config_one, cells = self._fingerprint(self.APP, self.LIB)
        two, config_two, _cells = self._fingerprint(self.LIB, self.APP)
        self.assertEqual(one, two)
        self.assertEqual({"app": {"files": ["src/app.py", "src/auth/login.py"], "panels": ["SEC"]},
                          "lib": {"files": ["lib/util.py"], "panels": ["COD"]}}, cells)
        # ...while the config AS WRITTEN did change, and its hash says so.
        self.assertNotEqual(config_one, config_two)

    def test_an_order_that_moves_a_file_is_a_different_matrix(self):
        # `src/**` and `src/auth/**` overlap, and groups claim first-match-wins: the same two
        # groups in the other order put login.py somewhere else. An order-free hash of the
        # config would call these one matrix. They are not.
        first, _config_first, cells_first = self._fingerprint(self.APP, self.AUTH)
        second, _config_second, cells_second = self._fingerprint(self.AUTH, self.APP)
        self.assertNotEqual(first, second)
        self.assertEqual(["src/app.py", "src/auth/login.py"], cells_first["app"]["files"])
        self.assertEqual(["src/auth/login.py"], cells_second["auth"]["files"])
        self.assertEqual(["src/app.py"], cells_second["app"]["files"])

    def test_a_groups_floor_panels_are_part_of_the_matrix(self):
        # `layout_fingerprint` cannot see this: the files are the same, the review is not.
        with_sec, _c, _cells = self._fingerprint(self.APP, self.LIB)
        without, _c, _cells = self._fingerprint(("app", {"match": ["src/**"], "panels": ["COD"]}),
                                                self.LIB)
        self.assertNotEqual(with_sec, without)

    def test_a_groups_name_is_part_of_the_matrix(self):
        named, _c, _cells = self._fingerprint(self.APP, self.LIB)
        renamed, _c, _cells = self._fingerprint(("core", self.APP[1]), self.LIB)
        self.assertNotEqual(named, renamed)

    def test_it_is_free_of_listing_order_and_of_what_a_scout_added(self):
        groups = [{"name": "a", "files": ["x.py", "y.py"]}, {"name": "b", "files": ["z.py"]}]
        coverages = [{"group": "a", "floor": ["SEC", "COD"]}, {"group": "b", "floor": ["ARC"]}]
        base = mi.matrix_fingerprint(groups, coverages)
        self.assertRegex(base, r"\Asha256:[0-9a-f]{64}\Z")
        shuffled = [{"name": "b", "files": ["z.py"]}, {"name": "a", "files": ["y.py", "x.py", "x.py"]}]
        self.assertEqual(base, mi.matrix_fingerprint(shuffled, list(reversed(coverages))))
        # A coverage record as the driver writes it: what the scout added is beside the
        # floor (`scout_added`) and inside `effective`, and is in neither case the matrix.
        self.assertEqual(base, mi.matrix_fingerprint(shuffled, [
            {"group": "a", "floor": ["COD", "SEC"], "scout_added": ["TST", "DBA"],
             "effective": ["COD", "SEC", "TST", "DBA"]},
            {"group": "b", "floor": ["ARC"], "scout_added": ["SEC"],
             "effective": ["ARC", "SEC"]}]))
        # A floor panel the group excludes does not run, so it is not in the matrix.
        self.assertEqual(
            mi.matrix_fingerprint(groups, [{"group": "a", "floor": ["SEC"]},
                                           {"group": "b", "floor": ["ARC"]}]),
            mi.matrix_fingerprint(groups, [{"group": "a", "floor": ["SEC", "COD"],
                                            "excluded": ["COD"]},
                                           {"group": "b", "floor": ["ARC"]}]))
        for moved in ([{"name": "a", "files": ["x.py"]}, {"name": "b", "files": ["y.py", "z.py"]}],
                      groups[:1]):
            self.assertNotEqual(base, mi.matrix_fingerprint(moved, coverages))

    def test_malformed_run_artifacts_are_hashed_never_raised_on(self):
        for groups, coverages in ((None, None), ("x", 3), ([None, 3, {"name": 4}, {"files": []}],
                                                           [None, {"group": 1}, {"floor": "x"}])):
            self.assertEqual(mi.matrix_fingerprint([], []), mi.matrix_fingerprint(groups, coverages))
        self.assertEqual({"a": {"files": ["f"], "panels": []}},
                         mi.realised([{"name": "a", "files": ["f", 3, None]}],
                                     [{"group": "a", "floor": "SEC"}]))


class TestTheConfigHashIsOfTheConfigAsWritten(unittest.TestCase):
    TEXT = ("version: 1\ngroups:\n  app:\n    match: ['src/**', '!src/gen/**']\n"
            "    panels: [SEC, COD]\n  lib:\n    match: ['lib/**']\n"
            "exclude_paths: ['vendor/**']\nsettings:\n  max_per_group: 12\n")

    def test_key_order_comments_and_whitespace_do_not_count(self):
        respelled = ("# a comment\nsettings: {max_per_group: 12}\nexclude_paths:\n  - vendor/**\n"
                     "groups:\n  app:\n    panels: [COD, SEC]   # the set, in another order\n"
                     "    match:\n      - src/**\n      - '!src/gen/**'\n"
                     "  lib: {match: [lib/**]}\nversion: 1\n")
        self.assertEqual(mp.text_digest(self.TEXT), mp.text_digest(respelled))
        self.assertRegex(mp.text_digest(self.TEXT), r"\Asha256:[0-9a-f]{64}\Z")

    def test_what_can_change_the_review_does_count(self):
        base = mp.text_digest(self.TEXT)
        for changed in (
                # Group order: groups claim files first-match-wins.
                self.TEXT.replace("  app:\n    match: ['src/**', '!src/gen/**']\n"
                                  "    panels: [SEC, COD]\n  lib:\n    match: ['lib/**']\n",
                                  "  lib:\n    match: ['lib/**']\n  app:\n"
                                  "    match: ['src/**', '!src/gen/**']\n    panels: [SEC, COD]\n"),
                # Glob order: a `!` glob makes the last match win.
                self.TEXT.replace("['src/**', '!src/gen/**']", "['!src/gen/**', 'src/**']"),
                self.TEXT.replace("[SEC, COD]", "[SEC]"),
                self.TEXT.replace("vendor/**", "third_party/**"),
                self.TEXT.replace("max_per_group: 12", "max_per_group: 24"),
                self.TEXT.replace("  lib:", "  library:")):
            with self.subTest(changed=changed):
                self.assertNotEqual(base, mp.text_digest(changed))

    def test_how_the_review_judges_is_not_the_matrix(self):
        gated = self.TEXT.replace("  max_per_group: 12\n",
                                  "  max_per_group: 12\n  fail_on: high\n  security: redteam\n")
        self.assertEqual(mp.text_digest(self.TEXT), mp.text_digest(gated))

    def test_a_config_a_run_would_refuse_has_no_identity(self):
        for text in ("", "version: 1\n", "version: 1\ngroups: []\n", "{not yaml",
                     "version: 1\ngroups:\n  app:\n    match: 'src/**'\n"):
            with self.subTest(text=text):
                self.assertIsNone(mp.text_digest(text))


class TestTheBlockIsPinnedToItsVocabulary(unittest.TestCase):
    def test_every_field_is_what_the_schema_says_or_null(self):
        self.assertEqual({"origin": "committed", "matrix_fingerprint": SHA,
                          "config_sha256": SHA, "setup_draft": None},
                         mi.block(SHA, origin="committed", config=SHA, draft="unchanged"))
        self.assertEqual("unchanged", mi.block(SHA, origin="working_tree",
                                               draft="unchanged")["setup_draft"])
        for origin in (None, "", "reused", "COMMITTED", 3, ["committed"]):
            self.assertEqual("unknown", mi.block(SHA, origin=origin)["origin"])
        for bad in (None, "", "abc", "sha256:xyz", "sha256:" + "a" * 63, 7, SHA.upper()):
            block = mi.block(bad, origin="working_tree", config=bad, draft="edited")
            self.assertEqual((None, None, None), (block["matrix_fingerprint"],
                                                 block["config_sha256"], block["setup_draft"]))

    def test_unknown_is_never_reported_as_reused(self):
        for origin in ("unknown", None, "anything"):
            line = build_disclosure.matrix_line(mi.block(SHA, origin=origin))
            self.assertIn("origin=unknown", line)
            self.assertNotIn("reused", line)
            self.assertIn(build_disclosure.MATRIX_COMPARABLE, line)
        # The line pins the vocabulary itself: it also renders reports it did not write.
        for origin in ("reused", "COMMITTED", None, 3, ["committed"], ""):
            line = build_disclosure.matrix_line({"origin": origin, "matrix_fingerprint": SHA})
            self.assertIn("origin=unknown", line)
            self.assertNotIn("reused", line)
        self.assertIn("fingerprint=unmeasured; config=unrecorded",
                      build_disclosure.matrix_line({"origin": "committed"}))


def _git(root, *argv):
    return subprocess.run(["git", "-C", root, *argv], check=True, capture_output=True, text=True)


class TestWhetherTheConfigIsInTheReviewedCommit(unittest.TestCase):
    GROUPS = "groups:\n  app:\n    match: ['src/**']\n"

    def _repo(self, **kw):
        return make_git_repo(test_case=self, files=dict(FILES), groups_yml=self.GROUPS, **kw)

    def _write(self, root, text, name="panopticon.yml"):
        with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_a_tracked_unmodified_config_is_committed(self):
        root = self._repo()
        self.assertEqual("committed", mp.origin(root, "panopticon.yml"))
        described = mp.describe(root)
        self.assertEqual(("committed", "panopticon.yml", None),
                         (described["origin"], described["config"], described["setup_draft"]))
        self.assertRegex(described["config_sha256"], r"\Asha256:[0-9a-f]{64}\Z")

    def test_a_modified_config_is_the_working_trees(self):
        root = self._repo()
        self._write(root, "version: 1\n" + self.GROUPS + "# edited after the commit\n")
        self.assertEqual("working_tree", mp.origin(root, "panopticon.yml"))
        # Staged is still not committed.
        _git(root, "add", "panopticon.yml")
        self.assertEqual("working_tree", mp.origin(root, "panopticon.yml"))
        _git(root, "commit", "-qm", "commit the edit")
        self.assertEqual("committed", mp.origin(root, "panopticon.yml"))

    def test_a_modification_git_status_was_told_to_ignore_is_still_seen(self):
        # An index flag hides the edit from `git status`. The bytes are compared, not the status.
        root = self._repo()
        _git(root, "update-index", "--assume-unchanged", "panopticon.yml")
        self._write(root, "version: 1\n" + self.GROUPS.replace("src/**", "lib/**"))
        self.assertEqual("", _git(root, "status", "--porcelain").stdout)
        self.assertEqual("working_tree", mp.origin(root, "panopticon.yml"))

    def test_an_untracked_config_is_the_working_trees_ignored_or_not(self):
        root = make_git_repo(test_case=self, files=dict(FILES))
        self._write(root, "version: 1\n" + self.GROUPS)
        self.assertEqual("working_tree", mp.origin(root, "panopticon.yml"))
        self._write(root, "panopticon.yml\n", name=".gitignore")
        _git(root, "add", ".gitignore")
        _git(root, "commit", "-qm", "ignore it")
        self.assertEqual("", _git(root, "status", "--porcelain").stdout)
        self.assertEqual("working_tree", mp.origin(root, "panopticon.yml"))

    def test_the_alias_name_is_measured_the_same_way(self):
        root = make_git_repo(test_case=self, files=dict(FILES))
        self._write(root, "version: 1\n" + self.GROUPS, name=".panopticon.yml")
        self.assertEqual("working_tree", mp.describe(root)["origin"])
        _git(root, "add", ".panopticon.yml")
        _git(root, "commit", "-qm", "commit the alias")
        self.assertEqual((".panopticon.yml", "committed"),
                         (mp.describe(root)["config"], mp.describe(root)["origin"]))

    def test_a_symlinked_config_is_never_committed(self):
        root = self._repo()
        target = os.path.join(root, "real.yml")
        os.replace(os.path.join(root, "panopticon.yml"), target)
        os.symlink("real.yml", os.path.join(root, "panopticon.yml"))
        self.assertEqual("unknown", mp.origin(root, "panopticon.yml"))
        # The config reader refuses the link outright, so there is no config to describe.
        self.assertEqual({"origin": "unknown", "config": None, "config_sha256": None,
                          "setup_draft": None}, mp.describe(root))
        # A link the commit itself holds is no better.
        _git(root, "add", "-A")
        _git(root, "commit", "-qm", "commit the link")
        self.assertEqual("unknown", mp.describe(root)["origin"])

    def test_a_directory_at_the_name_in_the_commit_is_not_this_file(self):
        root = make_git_repo(test_case=self, files={"panopticon.yml/x.txt": "x\n"})
        shutil.rmtree(os.path.join(root, "panopticon.yml"))
        self._write(root, "version: 1\n" + self.GROUPS)
        self.assertEqual("working_tree", mp.origin(root, "panopticon.yml"))

    def test_what_git_cannot_say_is_unknown(self):
        plain = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, plain, True)
        self._write(plain, "version: 1\n" + self.GROUPS)
        self.assertEqual("unknown", mp.origin(plain, "panopticon.yml"))       # not a checkout
        unborn = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, unborn, True)
        _git(unborn, "init", "-q")
        self._write(unborn, "version: 1\n" + self.GROUPS)
        self.assertEqual("unknown", mp.origin(unborn, "panopticon.yml"))      # no commit yet
        root = self._repo()
        self.assertEqual("unknown", mp.origin(root, None))
        self.assertEqual("unknown", mp.origin(root, "src/app.py"))            # not a config name
        self.assertEqual("unknown", mp.origin(root, "../panopticon.yml"))
        os.remove(os.path.join(root, "panopticon.yml"))
        self.assertEqual("unknown", mp.origin(root, "panopticon.yml"))        # nothing on disk

    def test_a_refused_or_failing_probe_is_unknown_and_never_raises(self):
        root = self._repo()
        for failure in (safe_git.RepositoryRefused("refused"), OSError("no git"),
                        subprocess.TimeoutExpired("git", 15)):
            with self.subTest(failure=failure), \
                    mock.patch.object(safe_git, "probe", side_effect=failure):
                self.assertEqual("unknown", mp.origin(root, "panopticon.yml"))
                self.assertEqual("unknown", mp.describe(root)["origin"])
        for stdout in ("", "not-an-object-id\n", "zz" * 20 + "\n"):
            reply = mock.Mock(returncode=0, stdout=stdout, stderr="")
            with self.subTest(stdout=stdout), mock.patch.object(safe_git, "probe",
                                                                return_value=reply):
                self.assertEqual("unknown", mp.origin(root, "panopticon.yml"))
        # The tree verifies and the path lookup answers nonsense: still unknown, not "modified".
        tree = mock.Mock(returncode=0, stdout="a" * 40 + "\n", stderr="")
        for stdout in ("", "not-an-object-id\n", "a" * 39 + "\n"):
            held = mock.Mock(returncode=0, stdout=stdout, stderr="")
            with self.subTest(held=stdout), mock.patch.object(safe_git, "probe",
                                                              side_effect=[tree, held]):
                self.assertEqual("unknown", mp.origin(root, "panopticon.yml"))
        with mock.patch.object(mp, "config_digest", side_effect=RuntimeError("boom")):
            self.assertEqual({"origin": "unknown", "config": None, "config_sha256": None,
                              "setup_draft": None}, mp.describe(root))

    def test_a_review_root_below_the_repository_top_asks_about_its_own_file(self):
        # #3680 review: `HEAD:<name>` is resolved from the repository's top level. A review
        # root of `sub/`, holding an untracked copy with the committed root config's exact
        # bytes, would then read as committed. It is anchored to the review root.
        root = self._repo()
        sub = os.path.join(root, "sub")
        os.makedirs(sub)
        shutil.copy(os.path.join(root, "panopticon.yml"), os.path.join(sub, "panopticon.yml"))
        self.assertEqual("committed", mp.origin(root, "panopticon.yml"))
        self.assertEqual("working_tree", mp.origin(sub, "panopticon.yml"))
        self.assertEqual("working_tree", mp.describe(sub)["origin"])
        # ...and once that copy is itself committed, it is the subdirectory's committed config.
        _git(root, "add", "sub/panopticon.yml")
        _git(root, "commit", "-qm", "a config for the subdirectory")
        self.assertEqual("committed", mp.origin(sub, "panopticon.yml"))
        self._write(sub, "version: 1\n" + self.GROUPS + "# edited\n")
        self.assertEqual(("working_tree", "committed"),
                         (mp.origin(sub, "panopticon.yml"), mp.origin(root, "panopticon.yml")))

    # -- #3684: the commit spells the config another way --------------------------------

    def _spelled_by_the_commit(self, name="Panopticon.yml"):
        """A repository whose commit holds the config as `name`, and the path of the file
        `panopticon.yml` opens. On a filesystem that folds case that is the committed file
        already; on one that does not, a hard link makes it so: one file, two names."""
        root = make_git_repo(test_case=self,
                             files=dict(FILES, **{name: "version: 1\n" + self.GROUPS}))
        exact = os.path.join(root, "panopticon.yml")
        if not os.path.lexists(exact):
            hard_link_or_skip(os.path.join(root, name), exact)
        self.assertTrue(os.path.samefile(exact, os.path.join(root, name)))
        return root

    def test_a_config_the_commit_spells_in_another_case_is_committed(self):
        # `HEAD:./panopticon.yml` is case-sensitive whatever the filesystem is. The target's
        # own committed matrix read as the working tree's, and a dirty run of it could then
        # be excused as "a fresh matrix" by `compare_runs --allow-different-layouts`.
        root = self._spelled_by_the_commit()
        self.assertEqual("committed", mp.origin(root, "panopticon.yml"))
        described = mp.describe(root)
        self.assertEqual(("committed", "panopticon.yml", None),
                         (described["origin"], described["config"], described["setup_draft"]))
        self._write(root, "version: 1\n" + self.GROUPS + "# edited after the commit\n")
        self.assertEqual("working_tree", mp.origin(root, "panopticon.yml"))

    def test_head_is_asked_about_each_other_name_until_it_holds_one(self):
        root = self._spelled_by_the_commit()
        hard_link_or_skip(os.path.join(root, "panopticon.yml"), os.path.join(root, "A-copy.yml"))
        asked = []
        real = safe_git.probe

        def probe(target, args, **kw):
            asked.append(list(args))
            return real(target, args, **kw)

        with mock.patch.object(safe_git, "probe", side_effect=probe):
            self.assertEqual("committed", mp.origin(root, "panopticon.yml"))
        self.assertEqual([["rev-parse", "--verify", "HEAD^{tree}"],
                          ["rev-parse", "--verify", "HEAD:./panopticon.yml"],
                          ["rev-parse", "--verify", "HEAD:./A-copy.yml"],       # not in HEAD
                          ["rev-parse", "--verify", "HEAD:./Panopticon.yml"]], asked)

    def test_another_name_the_commit_does_not_hold_is_still_the_working_trees(self):
        root = make_git_repo(test_case=self, files=dict(FILES))
        self._write(root, "version: 1\n" + self.GROUPS)
        hard_link_or_skip(os.path.join(root, "panopticon.yml"), os.path.join(root, "copy.yml"))
        self.assertEqual("working_tree", mp.origin(root, "panopticon.yml"))

    def test_the_other_names_are_this_file_s_only_sorted_and_capped(self):
        root = self._repo()
        exact = os.path.join(root, "panopticon.yml")
        info = os.lstat(exact)
        self.assertEqual([], mp._other_names(root, "panopticon.yml", info))
        self._write(root, "version: 1\n" + self.GROUPS, name="same-bytes.yml")  # another file
        self.assertEqual([], mp._other_names(root, "panopticon.yml", info))
        for n in (3, 1, 2):
            hard_link_or_skip(exact, os.path.join(root, "link-%d.yml" % n))
        self.assertEqual(["link-1.yml", "link-2.yml", "link-3.yml"],
                         mp._other_names(root, "panopticon.yml", os.lstat(exact)))
        for n in range(4, 12):
            hard_link_or_skip(exact, os.path.join(root, "link-%02d.yml" % n))
        names = mp._other_names(root, "panopticon.yml", os.lstat(exact))
        self.assertEqual((8, 8), (len(names), mp._OTHER_NAMES_MAX))
        self.assertEqual(sorted(names), names)
        self.assertEqual("link-04.yml", names[0])

    def test_the_same_inode_number_on_another_device_is_not_another_name(self):
        root = self._repo()
        info = os.lstat(os.path.join(root, "panopticon.yml"))

        class Entry:
            def __init__(self, name, device):
                self.name, self._device = name, device

            def inode(self):
                return info.st_ino

            def stat(self, follow_symlinks=True):
                assert follow_symlinks is False
                return mock.Mock(st_dev=self._device)

        listing = mock.MagicMock()
        listing.__enter__.return_value = [Entry("mounted.yml", info.st_dev + 1),
                                          Entry("Panopticon.yml", info.st_dev)]
        with mock.patch.object(mp.os, "scandir", return_value=listing):
            self.assertEqual(["Panopticon.yml"], mp._other_names(root, "panopticon.yml", info))

    def test_a_review_root_that_cannot_be_listed_is_unknown(self):
        root = make_git_repo(test_case=self, files=dict(FILES))
        self._write(root, "version: 1\n" + self.GROUPS)
        with mock.patch.object(mp.os, "scandir", side_effect=PermissionError(13, "refused")):
            self.assertEqual("unknown", mp.origin(root, "panopticon.yml"))
        self.assertEqual("working_tree", mp.origin(root, "panopticon.yml"))

    def test_only_rev_parse_is_asked_of_the_target(self):
        root = self._repo()
        asked = []
        real = safe_git.probe

        def probe(target, args, **kw):
            asked.append(list(args))
            return real(target, args, **kw)

        with mock.patch.object(safe_git, "probe", side_effect=probe):
            self.assertEqual("committed", mp.origin(root, "panopticon.yml"))
        self.assertEqual([["rev-parse", "--verify", "HEAD^{tree}"],
                          ["rev-parse", "--verify", "HEAD:./panopticon.yml"]], asked)


class _StateDir(unittest.TestCase):
    """Each test gets its own operator state directory, never the real one."""

    def setUp(self):
        super().setUp()
        self.state = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.state, True)
        patch = mock.patch.dict(os.environ, {"PANOPTICON_STATE_DIR": self.state})
        patch.start()
        self.addCleanup(patch.stop)

    def _drafts(self):
        return os.path.join(self.state, mp.DRAFTS_NAME)


class TestSetupsDraftIsRememberedOutsideTheTarget(_StateDir):
    OTHER = "sha256:" + "cd" * 32

    def _target(self):
        root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        return root

    def test_a_recorded_draft_is_compared_by_hash(self):
        root = self._target()
        self.assertIsNone(mp.draft_state(root, SHA))
        self.assertTrue(mp.record_draft(root, SHA))
        self.assertEqual("unchanged", mp.draft_state(root, SHA))
        self.assertEqual("differs", mp.draft_state(root, self.OTHER))
        self.assertIsNone(mp.draft_state(root, None))
        self.assertIsNone(mp.draft_state(self._target(), SHA))       # another target's record
        self.assertTrue(mp.record_draft(root, self.OTHER))           # the latest draft wins
        self.assertEqual(("differs", "unchanged"),
                         (mp.draft_state(root, SHA), mp.draft_state(root, self.OTHER)))

    def test_a_draft_with_no_digest_forgets_the_record_it_replaces(self):
        # #3680 review: setup's latest draft did not parse. The one on record is then no
        # longer "setup's last draft", and keeping it would say so of an older config.
        root, other = self._target(), self._target()
        mp.record_draft(root, SHA)
        mp.record_draft(other, self.OTHER)
        self.assertFalse(mp.record_draft(root, None))
        self.assertIsNone(mp.draft_state(root, SHA))
        self.assertEqual("unchanged", mp.draft_state(other, self.OTHER))    # only its own
        self.assertFalse(mp.record_draft(root, "not-a-hash"))               # nothing left to forget
        self.assertEqual("unchanged", mp.draft_state(other, self.OTHER))

    def test_the_record_is_private_and_holds_no_path(self):
        root = self._target()
        mp.record_draft(root, SHA)
        info = os.stat(self._drafts())
        self.assertEqual(0o600, stat.S_IMODE(info.st_mode))
        with open(self._drafts(), encoding="utf-8") as fh:
            text = fh.read()
        self.assertNotIn(root, text)
        self.assertEqual([SHA], list(json.loads(text)["drafts"].values()))
        self.assertEqual([mp.DRAFTS_NAME], os.listdir(self.state))   # no staging file left

    def test_a_file_in_the_target_cannot_vouch_for_a_draft(self):
        # The record is read from the operator's state directory and from nowhere else.
        root = self._target()
        planted = {"schema_version": mp.DRAFTS_SCHEMA_VERSION,
                   "drafts": {mp._target_key(root): SHA}}
        for where in (root, os.path.join(root, ".panopticon")):
            os.makedirs(where, exist_ok=True)
            with open(os.path.join(where, mp.DRAFTS_NAME), "w", encoding="utf-8") as fh:
                json.dump(planted, fh)
        self.assertIsNone(mp.draft_state(root, SHA))

    def test_a_record_that_is_not_ours_or_not_private_is_ignored(self):
        root = self._target()
        mp.record_draft(root, SHA)
        os.chmod(self._drafts(), 0o644)                              # readable by others
        self.assertIsNone(mp.draft_state(root, SHA))
        os.chmod(self._drafts(), 0o600)
        self.assertEqual("unchanged", mp.draft_state(root, SHA))
        moved = self._drafts() + ".real"
        os.replace(self._drafts(), moved)
        os.symlink(moved, self._drafts())                            # a link
        self.assertIsNone(mp.draft_state(root, SHA))
        os.remove(self._drafts())
        os.link(moved, self._drafts())                               # a second name
        self.assertIsNone(mp.draft_state(root, SHA))

    def test_a_malformed_record_is_no_record(self):
        root = self._target()
        key = mp._target_key(root)
        for body in ("", "{", "[]", json.dumps({"schema_version": 99, "drafts": {key: SHA}}),
                     json.dumps({"schema_version": 1, "drafts": [key]}),
                     json.dumps({"schema_version": 1, "drafts": {key: "not-a-hash"}}),
                     "x" * (mp._MAX_DRAFTS_BYTES + 1)):
            with self.subTest(body=body[:40]):
                with open(os.open(self._drafts(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
                          "w", encoding="utf-8") as fh:
                    fh.write(body)
                self.assertIsNone(mp.draft_state(root, SHA))
        # Oversized is refused for its size, not because it happens not to parse: this one
        # is a valid record followed by enough blank space to pass the cap.
        valid = json.dumps({"schema_version": 1, "drafts": {key: SHA}})
        with open(os.open(self._drafts(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
                  "w", encoding="utf-8") as fh:
            fh.write(valid)
        self.assertEqual("unchanged", mp.draft_state(root, SHA))
        with open(self._drafts(), "a", encoding="utf-8") as fh:
            fh.write(" " * (mp._MAX_DRAFTS_BYTES + 1 - len(valid)))
        self.assertIsNone(mp.draft_state(root, SHA))

    def test_what_is_not_a_hash_is_not_recorded_and_the_record_is_bounded(self):
        root = self._target()
        for bad in (None, "", "abc", "sha256:xyz"):
            self.assertFalse(mp.record_draft(root, bad))
        self.assertFalse(os.path.exists(self._drafts()))
        with mock.patch.object(mp, "_MAX_TARGETS", 3):
            targets = [self._target() for _ in range(5)]
            for target in targets:
                mp.record_draft(target, SHA)
        self.assertEqual([None, None, "unchanged", "unchanged", "unchanged"],
                         [mp.draft_state(target, SHA) for target in targets])

    def test_a_state_directory_that_cannot_be_written_costs_only_the_note(self):
        blocked = os.path.join(self.state, "a-file")
        with open(blocked, "w", encoding="utf-8") as fh:
            fh.write("not a directory")
        with mock.patch.dict(os.environ, {"PANOPTICON_STATE_DIR": blocked}):
            self.assertFalse(mp.record_draft(self._target(), SHA))
            self.assertIsNone(mp.draft_state(self._target(), SHA))


class TestSetupRecordsWhatItDrafted(_StateDir, SetupFixtureBase):
    def test_the_draft_moved_into_place_is_setups_proposal_until_it_is_edited(self):
        with self._ingest_fixture() as (repo, proposal):
            _git(repo, "init", "-q")
            _git(repo, "config", "user.name", "T")
            _git(repo, "config", "user.email", "t@example.com")
            _git(repo, "add", "src")
            _git(repo, "commit", "-qm", "init")
            result = setup_flow.ingest_proposal(repo, proposal)
            self.assertTrue(result["ok"], result)
            # A run before the operator adopts the draft has no config at all.
            self.assertIsNone(mp.describe(repo)["config"])
            os.replace(result["draft"], os.path.join(repo, "panopticon.yml"))
            adopted = mp.describe(repo)
            self.assertEqual(("working_tree", "unchanged"),
                             (adopted["origin"], adopted["setup_draft"]))
            with open(os.path.join(repo, "panopticon.yml"), encoding="utf-8") as fh:
                text = fh.read()
            self.assertEqual(mp.text_digest(text), adopted["config_sha256"])
            # A comment is not an edit; a changed glob is.
            with open(os.path.join(repo, "panopticon.yml"), "a", encoding="utf-8") as fh:
                fh.write("# reviewed by the team\n")
            self.assertEqual("unchanged", mp.describe(repo)["setup_draft"])
            with open(os.path.join(repo, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write(text.replace("src/checkout/**", "src/**"))
            self.assertEqual(("working_tree", "differs"),
                             (mp.describe(repo)["origin"], mp.describe(repo)["setup_draft"]))
            # Once committed it is the repository's matrix, whoever first drafted it.
            _git(repo, "add", "panopticon.yml")
            _git(repo, "commit", "-qm", "adopt the matrix")
            self.assertEqual(("committed", None),
                             (mp.describe(repo)["origin"], mp.describe(repo)["setup_draft"]))

    def test_a_draft_that_does_not_parse_clears_the_last_one(self):
        with self._ingest_fixture() as (repo, proposal):
            self.assertTrue(setup_flow.ingest_proposal(repo, proposal)["ok"])
            with open(os.path.join(repo, "panopticon.yml.draft"), encoding="utf-8") as fh:
                digest = mp.text_digest(fh.read())
            self.assertEqual("unchanged", mp.draft_state(repo, digest))
            with mock.patch.object(mp, "text_digest", return_value=None):
                self.assertTrue(setup_flow.ingest_proposal(repo, proposal)["ok"])
            self.assertIsNone(mp.draft_state(repo, digest))

    def test_a_refused_ingest_records_nothing(self):
        with self._ingest_fixture() as (repo, proposal):
            with open(proposal, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            self.assertFalse(setup_flow.ingest_proposal(repo, proposal)["ok"])
            self.assertFalse(os.path.exists(self._drafts()))


class TestTheReportSaysWhichMatrix(unittest.TestCase):
    """Through the real `synthesize.py`: the JSON block, the terminal line and the HTML."""

    def _run(self, *flags, floors=(("g1", ["SEC"]),)):
        with tempfile.TemporaryDirectory() as d, _chdir(d):
            adopt_panopticon(d)
            run_dir = os.path.join(d, ".panopticon")
            groups = [{"name": name, "files": ["%s/a.py" % name]} for name, _floor in floors]
            with open(os.path.join(run_dir, "groups.json"), "w", encoding="utf-8") as fh:
                json.dump({"mode": "repo", "groups": groups}, fh)
            for name, floor in floors:
                with open(os.path.join(run_dir, "coverage-%s.json" % name), "w",
                          encoding="utf-8") as fh:
                    json.dump({"group": name, "floor": floor, "effective": floor + ["TST"]}, fh)
            cells = []
            for name, floor in floors:
                for domain in floor:
                    cell = os.path.join(run_dir, "findings-%s-%s.json" % (name, domain))
                    with open(cell, "w", encoding="utf-8") as fh:
                        json.dump({"findings": []}, fh)
                    cells.append(cell)
            out = os.path.join(d, "report.json")
            terminal = io.StringIO()
            with contextlib.redirect_stdout(terminal), contextlib.redirect_stderr(io.StringIO()):
                syn.main(["--repo", "--run-dir", run_dir, "--groups",
                          os.path.join(run_dir, "groups.json"), "--out", out, *flags, *cells])
            with open(out, encoding="utf-8") as fh:
                report = json.load(fh)
            with open(out + ".html", encoding="utf-8") as fh:
                page = fh.read()
        self.assertEqual([], validate_schema.schema_errors(report))
        return report, terminal.getvalue(), page

    def _line(self, text):
        return next(line for line in text.splitlines() if "Matrix: origin=" in line)

    def test_a_direct_run_measures_the_fingerprint_and_calls_the_origin_unknown(self):
        report, terminal, page = self._run()
        matrix = report["meta"]["matrix"]
        self.assertEqual(("unknown", None, None),
                         (matrix["origin"], matrix["config_sha256"], matrix["setup_draft"]))
        self.assertEqual(mi.matrix_fingerprint(
            [{"name": "g1", "files": ["g1/a.py"]}], [{"group": "g1", "floor": ["SEC"]}]),
            matrix["matrix_fingerprint"])
        self.assertIn("**Provenance:** `%s`" % build_disclosure.matrix_line(matrix), terminal)
        self.assertIn(html_report._escape(build_disclosure.matrix_line(matrix)), page)

    def test_the_drivers_record_reaches_all_three_surfaces(self):
        cases = (
            (("--matrix-origin", "committed", "--matrix-config-sha256", SHA),
             "origin=committed (reused: the config is in the reviewed commit, unmodified)", False),
            (("--matrix-origin", "working_tree", "--matrix-config-sha256", SHA,
              "--matrix-setup-draft", "unchanged"),
             "origin=working_tree (FRESH: the config is not in the reviewed commit; it is "
             "setup's last draft, unchanged)", True),
            (("--matrix-origin", "working_tree", "--matrix-setup-draft", "differs"),
             "FRESH: the config is not in the reviewed commit; it is not setup's last draft", True),
            (("--matrix-origin", "working_tree"),
             "FRESH: the config is not in the reviewed commit; no setup draft is on record", True),
            (("--matrix-origin", "unknown"),
             "origin=unknown (whether the config is in the reviewed commit could not be "
             "measured)", True))
        for flags, said, hedged in cases:
            with self.subTest(flags=flags):
                report, terminal, page = self._run(*flags)
                matrix = report["meta"]["matrix"]
                self.assertEqual(flags[1], matrix["origin"])
                line = self._line(terminal)
                self.assertIn(said, line)
                self.assertIn("fingerprint=" + matrix["matrix_fingerprint"], line)
                self.assertIn("config=" + (matrix["config_sha256"] or "unrecorded"), line)
                self.assertEqual(hedged, build_disclosure.MATRIX_COMPARABLE in line)
                self.assertIn(html_report._escape(build_disclosure.matrix_line(matrix)), page)

    def test_the_fingerprint_follows_the_floors_this_run_was_set(self):
        one, _t, _p = self._run()
        same, _t, _p = self._run("--matrix-origin", "committed")
        other, _t, _p = self._run(floors=(("g1", ["SEC", "COD"]),))
        fingerprint = one["meta"]["matrix"]["matrix_fingerprint"]
        self.assertEqual(fingerprint, same["meta"]["matrix"]["matrix_fingerprint"])
        self.assertNotEqual(fingerprint, other["meta"]["matrix"]["matrix_fingerprint"])
        # The layout fingerprint cannot tell those two apart, and is not changed by this.
        self.assertEqual(one["summary"]["health"]["basis"]["layout_fingerprint"],
                         other["summary"]["health"]["basis"]["layout_fingerprint"])

    def test_the_parser_refuses_a_word_outside_the_vocabulary(self):
        for flag, word in (("--matrix-origin", "reused"), ("--matrix-setup-draft", "edited")):
            with self.subTest(flag=flag), self.assertRaises(SystemExit), \
                    contextlib.redirect_stderr(io.StringIO()):
                syn.build_parser().parse_args([flag, word])

    def test_the_schema_pins_the_block(self):
        report, _terminal, _page = self._run("--matrix-origin", "working_tree")
        for wrong in (dict(report["meta"]["matrix"], origin="reused"),
                      dict(report["meta"]["matrix"], matrix_fingerprint="abc"),
                      dict(report["meta"]["matrix"], setup_draft="edited"),
                      dict(report["meta"]["matrix"], path="/x"),
                      {"origin": "committed"}, "committed"):
            with self.subTest(wrong=wrong):
                broken = dict(report, meta=dict(report["meta"], matrix=wrong))
                self.assertTrue(validate_schema.schema_errors(broken))

    def test_a_report_written_before_the_block_existed_still_renders(self):
        report, _terminal, _page = self._run()
        del report["meta"]["matrix"]
        self.assertEqual("", build_disclosure.matrix_line(None))
        self.assertNotIn("Matrix:", " ".join(build_disclosure.provenance_lines(report["meta"])))
        self.assertEqual([], validate_schema.schema_errors(report))


def setUpModule():
    global _patches
    _patches = (mock.patch("scripts.host_probes.run_probes",
                           side_effect=lambda host, target, **kw: all_proven_artifact(host)),
                mock.patch("scripts.phases.readiness_checks.DOCKER_RUNNER",
                           docker_probe_runner()))
    for patch in _patches:
        patch.start()


def tearDownModule():
    for patch in _patches:
        patch.stop()


class TestTheDriverMeasuresItOnceAtRunStart(_StateDir, LoopCase):
    def _loop(self, d, floor):
        return self._run_loop(d, floor, FakeRunner())

    def _report(self, d):
        with open(runio._report_out(d), encoding="utf-8") as fh:
            return json.load(fh)

    def _as_checkout(self, d):
        _git(d, "init", "-q")
        _git(d, "config", "user.name", "T")
        _git(d, "config", "user.email", "t@example.com")
        with open(os.path.join(d, ".gitignore"), "w", encoding="utf-8") as fh:
            fh.write(".panopticon/\n")
        _git(d, "add", "-A")
        _git(d, "commit", "-qm", "init")

    def test_a_run_over_a_committed_config_reports_a_reused_matrix(self):
        d, floor = self._repo()
        self._as_checkout(d)
        self.assertEqual("complete", self._loop(d, floor)["status"])
        recorded = run_manifest.load_manifest(d)[run_manifest.MATRIX]
        self.assertEqual(("committed", "panopticon.yml", None),
                         (recorded["origin"], recorded["config"], recorded["setup_draft"]))
        matrix = self._report(d)["meta"]["matrix"]
        self.assertEqual(("committed", recorded["config_sha256"]),
                         (matrix["origin"], matrix["config_sha256"]))
        self.assertRegex(matrix["matrix_fingerprint"], r"\Asha256:[0-9a-f]{64}\Z")

    def test_a_run_over_setups_fresh_draft_says_so(self):
        d, floor = self._uncommitted_config()
        mp.record_draft(d, mp.config_digest(d)[1])               # as setup does for its draft
        self.assertEqual("complete", self._loop(d, floor)["status"])
        matrix = self._report(d)["meta"]["matrix"]
        self.assertEqual(("working_tree", "unchanged"), (matrix["origin"], matrix["setup_draft"]))
        self.assertIn("FRESH", build_disclosure.matrix_line(matrix))

    def test_a_target_that_is_not_a_checkout_is_unknown_never_reused(self):
        d, floor = self._repo()
        self.assertEqual("complete", self._loop(d, floor)["status"])
        self.assertEqual("unknown", run_manifest.load_manifest(d)[run_manifest.MATRIX]["origin"])
        self.assertEqual("unknown", self._report(d)["meta"]["matrix"]["origin"])

    def _uncommitted_config(self):
        """A checkout whose config is on disk and not in its commit."""
        d, floor = self._repo()
        os.replace(os.path.join(d, "panopticon.yml"), os.path.join(d, "kept.yml"))
        self._as_checkout(d)
        os.replace(os.path.join(d, "kept.yml"), os.path.join(d, "panopticon.yml"))
        _git(d, "rm", "-q", "--cached", "kept.yml")
        _git(d, "commit", "-qm", "the config is not in the commit")
        return d, floor

    def test_it_is_measured_once_so_a_resume_reports_the_run_as_it_began(self):
        d, floor = self._uncommitted_config()
        # The same flags `LoopCase` loops with: a different threshold would be flag drift.
        args = driver.build_parser().parse_args(["run", d, "--no-tools", "--fail-on", "high"])
        calls = []
        real = mp.describe

        def describe(root, **kw):
            calls.append(root)
            return real(root, **kw)

        with mock.patch.object(mp, "describe", side_effect=describe):
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertNotEqual("error", driver.run(args)["status"])
            began = dict(run_manifest.load_manifest(d)[run_manifest.MATRIX])
            self.assertEqual(("working_tree", None), (began["origin"], began["setup_draft"]))
            # The world changes mid-run: setup now records this very config as its draft. A
            # second measurement would say "unchanged". The run's record does not move.
            mp.record_draft(d, began["config_sha256"])
            self.assertEqual("unchanged", real(d)["setup_draft"])
            self.assertEqual("complete", self._loop(d, floor)["status"])
        self.assertEqual(1, len(calls))
        self.assertEqual(began, run_manifest.load_manifest(d)[run_manifest.MATRIX])
        self.assertIsNone(self._report(d)["meta"]["matrix"]["setup_draft"])

    def test_the_manifest_key_and_the_childs_flags_are_one_vocabulary(self):
        self.assertEqual("matrix", run_manifest.MATRIX)
        parser = syn.build_parser()
        for origin in mi.ORIGINS:
            self.assertEqual(origin, parser.parse_args(["--matrix-origin", origin]).matrix_origin)
        for draft in mi.DRAFTS:
            self.assertEqual(draft, parser.parse_args(
                ["--matrix-setup-draft", draft]).matrix_setup_draft)
        self.assertEqual(set(mi.ORIGINS), set(build_disclosure.MATRIX_ORIGINS))
        self.assertEqual(set(mi.DRAFTS), set(build_disclosure.MATRIX_DRAFTS))


if __name__ == "__main__":
    unittest.main()
