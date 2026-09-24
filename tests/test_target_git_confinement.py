"""#2006: EVERY target-facing Git call is confined, not just validate's.

#1985 hardened `validate.capture_tree_baseline`, `validate._tree_delta` and
`runio.resolve_review_root` onto `safe_git.probe` and left three calls at the
same trust boundary on the old path -- `discovery._git` (six call sites,
including the `status --porcelain -z` that `_worktree_dirty` runs before
dispatch), `discovery.resolve_base`'s `rev-parse --verify`, and
`run_manifest._target_provenance`'s `rev-parse HEAD` + `status`, the last with
no `env=` at all. The reviewer executed the first one: a target that sets
`core.fsmonitor` to a command got that command run during discovery.

Every test here plants a REAL hostile command in a real temporary repository
and asserts a marker file never appears. Each fixture is proved live first (a
plain `git status` in the same repository DOES write the marker), because
"the marker is absent" is also what a broken fixture produces.

The suite launches only `git`, only against repositories it creates itself
under the session temp root, which `tests/conftest.py` already refuses to place
inside any checkout.
"""
import ast
import contextlib
import io
import os
import subprocess
import unittest
from unittest import mock

from conftest import SKILL_ROOT
import scripts.diff_map as diff_map
import scripts.discovery as discovery
import scripts.phases.runio as runio
import scripts.phases.validate as validate_phase
import scripts.run_manifest as run_manifest
import scripts.safe_git as safe_git
import scripts.setup_flow as setup_flow

from tools.git_repo import (add_plumbing_submodule, hostile_marker,
                            make_git_repo, path_shim_git, plant_clean_filter,
                            plant_filter_command, plant_fsmonitor_command,
                            plant_hook)


def _plain_status(repo):
    """The unhardened call these modules used to make, as the control."""
    return subprocess.run(["git", "-C", repo, "status", "--porcelain"],
                          capture_output=True, text=True, timeout=30)


class HostileFixturesAreLive(unittest.TestCase):
    """Vacuity guard: prove the planted commands run before asserting they do not."""

    def test_a_planted_fsmonitor_command_runs_under_plain_git(self):
        repo = make_git_repo(test_case=self, panopticon=True)
        marker = plant_fsmonitor_command(repo)
        _plain_status(repo)
        self.assertTrue(os.path.exists(marker),
                        "fixture is inert: git never ran core.fsmonitor")

    def test_a_planted_clean_filter_runs_under_plain_git(self):
        repo = make_git_repo(test_case=self, panopticon=True)
        marker = plant_clean_filter(repo)
        _plain_status(repo)
        self.assertTrue(os.path.exists(marker),
                        "fixture is inert: git never ran filter.fixture.clean")

    def test_a_path_shim_git_is_reachable_on_an_inherited_path(self):
        repo = make_git_repo(test_case=self, panopticon=True)
        marker = hostile_marker(repo, "shim-marker")
        path_shim_git(os.path.join(repo, "bin"), marker)
        env = dict(os.environ, PATH=os.path.join(repo, "bin") + os.pathsep + os.environ["PATH"])
        subprocess.run(["git", "-C", repo, "status"], capture_output=True,
                       text=True, timeout=30, env=env)
        self.assertTrue(os.path.exists(marker),
                        "fixture is inert: the shim was never first on PATH")


class DiscoveryIsConfined(unittest.TestCase):
    """`discovery._git` is the shared invocation for this module's git calls."""

    def _repo(self):
        repo = make_git_repo(test_case=self, panopticon=True,
                             files={"a.py": "value = 1\n"})
        with open(os.path.join(repo, "b.py"), "w", encoding="utf-8") as fh:
            fh.write("value = 2\n")
        subprocess.run(["git", "-C", repo, "add", "b.py"], check=True,
                       capture_output=True, timeout=30)
        subprocess.run(["git", "-C", repo, "commit", "-qm", "second"], check=True,
                       capture_output=True, timeout=30)
        return repo

    def test_worktree_dirty_never_runs_the_targets_fsmonitor(self):
        repo = self._repo()
        marker = plant_fsmonitor_command(repo)
        self.assertIs(discovery._worktree_dirty(repo), False)
        self.assertFalse(os.path.exists(marker))

    def test_worktree_dirty_still_answers_with_the_filter_suppressed(self):
        # #2013 inverts #2006's refusal: the dirtiness answer is the one thing
        # `_worktree_dirty` exists to produce, and a git-lfs target must still
        # get one. The filter is emptied, so it never runs -- the invariant the
        # refusal was protecting is unchanged.
        repo = self._repo()
        marker = plant_clean_filter(repo)
        self.assertIs(discovery._worktree_dirty(repo), True)   # a.py was rewritten
        self.assertFalse(os.path.exists(marker))

    def test_changed_files_and_listing_never_run_the_targets_fsmonitor(self):
        repo = self._repo()
        marker = plant_fsmonitor_command(repo)
        self.assertEqual(discovery.collect_changed_files(repo, base="main"), [])
        self.assertIn("a.py", discovery._git_listed_files(repo))
        self.assertFalse(os.path.exists(marker))

    def test_resolve_base_never_runs_the_targets_fsmonitor(self):
        repo = self._repo()
        marker = plant_fsmonitor_command(repo)
        self.assertEqual(discovery.resolve_base(repo), ("main", "fallback"))
        self.assertFalse(os.path.exists(marker))

    def test_no_discovery_git_call_can_be_the_targets_own_git(self):
        repo = self._repo()
        marker = hostile_marker(repo, "shim-marker")
        path_shim_git(os.path.join(repo, "bin"), marker)
        with mock.patch.dict(os.environ,
                             {"PATH": os.path.join(repo, "bin") + os.pathsep + os.environ["PATH"]}):
            self.assertIs(discovery._worktree_dirty(repo, exclude=("bin",)), True)
            self.assertEqual(discovery.resolve_base(repo), ("main", "fallback"))
            self.assertIn("a.py", discovery._git_listed_files(repo))
        self.assertFalse(os.path.exists(marker))


class TargetProvenanceIsConfined(unittest.TestCase):
    """`run_manifest._target_provenance` runs at manifest build, on the target."""

    def _repo(self):
        return make_git_repo(test_case=self, panopticon=True,
                             files={"a.py": "value = 1\n"})

    def _head(self, repo):
        return subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=30).stdout.strip()

    def test_provenance_never_runs_the_targets_fsmonitor(self):
        repo = self._repo()
        marker = plant_fsmonitor_command(repo)
        commit, dirty = run_manifest._target_provenance(repo)
        self.assertEqual(commit, self._head(repo))
        self.assertIs(dirty, False)
        self.assertFalse(os.path.exists(marker))

    def test_a_command_filter_is_suppressed_and_dirtiness_is_still_known(self):
        # #2013: #2006 recorded dirtiness as unknown here, because the tree was
        # refused. It is suppressed instead, so provenance keeps BOTH facts --
        # and the keys it emptied are disclosed to the caller's list.
        repo = self._repo()
        marker = plant_clean_filter(repo)
        suppressed = []
        with contextlib.redirect_stderr(io.StringIO()):
            commit, dirty = run_manifest._target_provenance(repo, suppressed=suppressed)
        self.assertEqual(commit, self._head(repo))
        self.assertIs(dirty, True)
        self.assertEqual(suppressed, [(".", "filter.fixture.clean")])
        self.assertFalse(os.path.exists(marker))

    def test_a_clean_target_discloses_an_empty_suppression_list(self):
        # The absence of a suppression has to mean "measured and did not
        # happen", never "this run had no opinion".
        repo = self._repo()
        suppressed = []
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            commit, dirty = run_manifest._target_provenance(repo, suppressed=suppressed)
        # An EMPTY `.panopticon` is invisible to git, so this tree is clean.
        self.assertEqual((commit, dirty), (self._head(repo), False))
        self.assertEqual(suppressed, [])
        self.assertNotIn("SUPPRESSED", err.getvalue())

    def test_provenance_cannot_be_the_targets_own_git(self):
        repo = self._repo()
        marker = hostile_marker(repo, "shim-marker")
        path_shim_git(os.path.join(repo, "bin"), marker)
        with mock.patch.dict(os.environ,
                             {"PATH": os.path.join(repo, "bin") + os.pathsep + os.environ["PATH"]}):
            commit, dirty = run_manifest._target_provenance(repo)
        self.assertEqual(commit, self._head(repo))
        self.assertIs(dirty, True)      # the shim directory is untracked dirt
        self.assertFalse(os.path.exists(marker))

    def test_an_inherited_git_environment_cannot_redirect_the_provenance(self):
        # #1985's own regression test treats this shape as a defect elsewhere.
        # Distinct content, so the two HEADs differ by construction: identical
        # fixtures would commit the same tree in the same second and the
        # redirection this asserts against would be invisible.
        repo = self._repo()
        other = make_git_repo(test_case=self, panopticon=True,
                              files={"a.py": "value = 2  # the other repo\n"})
        with mock.patch.dict(os.environ, {"GIT_DIR": os.path.join(other, ".git"),
                                          "GIT_WORK_TREE": other,
                                          "GIT_CONFIG_COUNT": "1",
                                          "GIT_CONFIG_KEY_0": "core.fsmonitor",
                                          "GIT_CONFIG_VALUE_0": "printf hit > /dev/null; cat"}):
            commit, _dirty = run_manifest._target_provenance(repo)
        self.assertEqual(commit, self._head(repo))
        self.assertNotEqual(self._head(repo), self._head(other))

    def test_a_non_git_target_still_records_nulls(self):
        directory = self.enterContext(__import__("tempfile").TemporaryDirectory())
        self.assertEqual(run_manifest._target_provenance(directory), (None, None))


class NoRawTargetGitArgvRemains(unittest.TestCase):
    """The regression shape, read from the AST rather than grepped.

    #1989 rewrote `_worktree_dirty` in the same batch as #1985 and left it on
    the raw path, so the rule has to be checkable by a test rather than
    remembered. `MODULES` is exactly what it claims: this guard covers those
    five files and nothing else, so a sixth module that starts running git
    against the target is NOT protected until it is named here.
    """

    MODULES = ("discovery.py", "run_manifest.py", "diff_map.py", "setup_flow.py",
               os.path.join("phases", "runio.py"))

    # Functions that genuinely cannot use the probe. Small and explicit (never
    # a pattern): each entry is a decision, and a decision that stops being
    # true fails below as a stale entry.
    EXEMPT = {
        ("diff_map.py", "acquire_pr"):
            "it BUILDS the review root rather than reading one, and its steps "
            "are `gh pr view`, `git fetch`, `git worktree add` and "
            "`git update-ref` -- network and mutating work that needs the "
            "operator's own HOME, gitconfig and credential helper, which is "
            "exactly what the probe's fresh allowlisted environment strips. "
            "Its read-only `worktree list`/`rev-parse` steps could move, and "
            "`worktree add` runs the target's SMUDGE filters, so this is a "
            "known residual with a real trade-off, not a clean exemption",
        ("diff_map.py", "release_worktree"):
            "the teardown half of the same `--pr` worktree lifecycle, and it "
            "has to stay paired with it. `git worktree remove --force` is a "
            "MUTATION, not a probe: under the preflight a hostile target "
            "config would refuse the teardown (the caller tolerates every "
            "failure by design, #1082) and leak the throwaway worktree it was "
            "there to delete -- a worse outcome than the read it never does",
    }

    def _bare_git_argv(self, name):
        """Every `["git", ...]` literal in one module, with its function."""
        path = os.path.join(SKILL_ROOT, "scripts", name)
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), path)
        found = []
        for top in ast.walk(tree):
            if not isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(top):
                if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
                    continue
                first = node.elts[0]
                if isinstance(first, ast.Constant) and first.value == "git":
                    found.append((top.name, node.lineno, ast.unparse(node)))
        return found

    def test_no_module_builds_a_bare_git_argv(self):
        offenders = []
        for name in self.MODULES:
            for function, lineno, source in self._bare_git_argv(name):
                if (name, function) in self.EXEMPT:
                    continue
                offenders.append("%s:%d (%s): %s" % (name, lineno, function, source))
        self.assertEqual(
            offenders, [],
            "a git argv built by hand runs the TARGET's git off the inherited "
            "PATH with the target's config live; route it through "
            "safe_git.probe:\n  %s" % "\n  ".join(offenders))

    def test_no_exemption_outlives_its_reason(self):
        stale = [entry for entry in self.EXEMPT
                 if not any(function == entry[1]
                            for function, _l, _s in self._bare_git_argv(entry[0]))]
        self.assertEqual(stale, [],
                         "exempted functions that no longer build a bare git "
                         "argv -- drop the entry: %s" % stale)

    def test_the_guard_can_actually_see_an_offender(self):
        # Vacuity guard: an empty offender list is also what a guard that reads
        # nothing produces. `acquire_pr` is the known offender, so the finder
        # must report it even though the policy above exempts it.
        found = self._bare_git_argv("diff_map.py")
        self.assertTrue([f for f, _l, _s in found if f == "acquire_pr"], found)



class DeltaMapIsConfined(unittest.TestCase):
    """`diff_map._run_git` is the delta map's only git invocation.

    #2006 fix round 1: it resolved a trusted git (so the target could never BE
    the git that runs) but launched it with `PATH` alone -- no
    `GIT_CONFIG_NOSYSTEM`/`GIT_CONFIG_SYSTEM`/`GIT_CONFIG_GLOBAL`, no
    `core.fsmonitor=false`, no preflight -- for `merge-base`, `diff` and
    `ls-files` on the reviewed tree during every delta review.
    """

    def _repo(self):
        repo = make_git_repo(test_case=self, panopticon=True,
                             files={"a.py": "value = 1\n"})
        subprocess.run(["git", "-C", repo, "checkout", "-q", "-b", "feature"],
                       check=True, capture_output=True, timeout=30)
        with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("value = 3\n")
        subprocess.run(["git", "-C", repo, "commit", "-qam", "change"], check=True,
                       capture_output=True, timeout=30)
        return repo

    def test_the_hunk_map_never_runs_the_targets_fsmonitor(self):
        repo = self._repo()
        marker = plant_fsmonitor_command(repo)
        self.assertIn("a.py", diff_map.hunk_map(repo, "main"))
        self.assertFalse(os.path.exists(marker))

    def test_the_hunk_map_is_honest_with_a_command_filter_suppressed(self):
        # #2013: the map is produced rather than refused, and the filter still
        # never runs. `plant_clean_filter` commits a.py again, so the hunk the
        # map must find is the one it adds.
        repo = self._repo()
        marker = plant_clean_filter(repo)
        self.assertIn("a.py", diff_map.hunk_map(repo, "main"))
        self.assertFalse(os.path.exists(marker))

    def test_the_anchors_never_run_the_targets_fsmonitor(self):
        repo = self._repo()
        marker = plant_fsmonitor_command(repo)
        anchors = diff_map.diff_anchors(repo, "main")
        self.assertTrue(anchors["delta_end"])
        self.assertFalse(os.path.exists(marker))

    def test_the_delta_map_cannot_be_the_targets_own_git(self):
        repo = self._repo()
        marker = hostile_marker(repo, "shim-marker")
        path_shim_git(os.path.join(repo, "bin"), marker)
        with mock.patch.dict(os.environ,
                             {"PATH": os.path.join(repo, "bin") + os.pathsep + os.environ["PATH"]}):
            self.assertIn("a.py", diff_map.hunk_map(repo, "main"))
        self.assertFalse(os.path.exists(marker))


class ASuppressionIsDisclosedNotARefusal(unittest.TestCase):
    """#2013: the same two operator-facing entry points, after the inversion.

    #2006 fix round 1 ruling 2 made a refused target a named stderr line rather
    than a traceback out of `main()`. #2013 removes the refusal for this cause:
    a target that configures clean/diff drivers is SCANNED with those drivers
    emptied, so discovery completes and the manifest's provenance says which
    keys were neutralized. Refusal survives only where the override cannot be
    shown effective, which no real repository reaches.
    """

    def _hostile_repo(self):
        # groups_yml is committed by the helper, so the scan has a matrix and
        # reaches the delta computation rather than refusing earlier.
        repo = make_git_repo(test_case=self, panopticon=True,
                             groups_yml="groups:\n  App:\n    match:\n    - '**/*.py'\n")
        return repo, plant_clean_filter(repo)

    def test_discovery_completes_with_the_drivers_suppressed(self):
        repo, marker = self._hostile_repo()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = discovery.main(["--repo", repo, "--repo-scan", "--scope-changed"])
        self.assertEqual(rc, 0, err.getvalue())
        self.assertNotIn("fails closed", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())
        self.assertFalse(os.path.exists(marker))

    def test_the_run_manifest_discloses_the_suppression_on_stderr(self):
        # Suppression is DISCLOSED, never silent: one line naming the keys
        # (never their values -- those are commands the target authored).
        repo, marker = self._hostile_repo()
        err = io.StringIO()
        suppressed = []
        with contextlib.redirect_stderr(err):
            commit, dirty = run_manifest._target_provenance(repo, suppressed=suppressed)
        self.assertTrue(commit)
        self.assertIs(dirty, True)
        self.assertEqual(suppressed, [(".", "filter.fixture.clean")])
        line = err.getvalue()
        self.assertIn("SUPPRESSED", line)
        self.assertIn("filter.fixture.clean", line)
        self.assertNotIn("printf hit", line)             # never the value
        self.assertFalse(os.path.exists(marker))

    def test_the_manifest_records_the_suppressed_keys(self):
        repo, marker = self._hostile_repo()
        with contextlib.redirect_stderr(io.StringIO()):
            manifest = run_manifest.build_manifest(
                target=repo, review_root=repo, host="claude",
                security_mode="standard")
        self.assertEqual(manifest["git_drivers_suppressed"],
                         [{"repo": ".", "key": "filter.fixture.clean"}])
        self.assertFalse(os.path.exists(marker))

    def test_a_clean_target_records_an_empty_list(self):
        repo = make_git_repo(test_case=self, panopticon=True)
        manifest = run_manifest.build_manifest(
            target=repo, review_root=repo, host="claude", security_mode="standard")
        self.assertEqual(manifest["git_drivers_suppressed"], [])


class RepositoryHooksNeverRun(unittest.TestCase):
    """#2006 fix round 2, C2: `.git/hooks` needs no config, so no config
    refusal can catch it. Every probe launch has to suppress hooks outright.

    Two vectors the reviewer executed on the pre-fix tree: `post-index-change`
    on the preflighted `status` (which is #1985's own baseline path), and
    `reference-transaction` on an allowlisted `symbolic-ref` WRITE.
    """

    def _repo(self):
        return make_git_repo(test_case=self, panopticon=True,
                            files={"a.py": "value = 1\n"})

    def test_a_planted_hook_runs_under_plain_git(self):
        # Vacuity guard for both tests below.
        repo = self._repo()
        marker = plant_hook(repo, "post-index-change")
        with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("value = 2\n")
        _plain_status(repo)
        self.assertTrue(os.path.exists(marker),
                        "fixture is inert: git never ran the hook")

    def test_status_never_runs_the_targets_index_hook(self):
        repo = self._repo()
        marker = plant_hook(repo, "post-index-change")
        with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("value = 2\n")
        self.assertIs(discovery._worktree_dirty(repo), True)
        self.assertFalse(os.path.exists(marker))

    def test_an_allowlisted_symbolic_ref_write_never_runs_the_ref_hook(self):
        repo = self._repo()
        marker = plant_hook(repo, "reference-transaction")
        proc = safe_git.probe(repo, ["symbolic-ref", "refs/heads/probe-zz",
                                     "refs/heads/main"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertFalse(os.path.exists(marker))

    def test_the_baseline_probe_never_runs_the_targets_index_hook(self):
        repo = self._repo()
        marker = plant_hook(repo, "post-index-change")
        with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("value = 2\n")
        validate_phase.capture_tree_baseline(repo)
        self.assertFalse(os.path.exists(marker))


class SubmoduleDirtStaysVisibleWithAPathspec(unittest.TestCase):
    """#2006 fix round 2, I1: the pin must survive a `--` in the caller's argv.

    `--ignore-submodules=none` was APPENDED, so `status … -- <pathspec>` parsed
    it as a FILENAME: rc=0, no error, and #1985's guarantee that a target
    cannot hide submodule dirt from the integrity guard was silently gone.

    The submodule is registered with plumbing (`update-index --cacheinfo`), not
    `git submodule add`, so this test also runs where that shell script cannot.
    """

    def _parent_with_a_dirty_submodule(self):
        child = make_git_repo(test_case=self, files={"f.txt": "x\n"}, branch=None)
        parent = make_git_repo(test_case=self, panopticon=True,
                               files={"a.py": "value = 1\n"})
        worktree = add_plumbing_submodule(parent, child)
        with open(os.path.join(worktree, "f.txt"), "a", encoding="utf-8") as fh:
            fh.write("dirty\n")
        # The target's own preference to hide it -- the case #1985 pinned.
        subprocess.run(["git", "-C", parent, "config", "submodule.sub.ignore", "all"],
                       check=True, capture_output=True, timeout=30)
        return parent

    def test_the_fixture_really_hides_the_dirt_without_the_pin(self):
        # Vacuity guard: prove the hiding preference works, or the test below
        # proves nothing about the pin.
        parent = self._parent_with_a_dirty_submodule()
        out = subprocess.run(["git", "-C", parent, "status", "--porcelain", "-z"],
                             capture_output=True, text=True, timeout=30).stdout
        self.assertNotIn("sub", out)

    def test_a_pathspec_status_still_reports_submodule_dirt(self):
        parent = self._parent_with_a_dirty_submodule()
        proc = safe_git.probe(parent, ["status", "--porcelain", "-z", "--", "sub", "a.py"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("sub", proc.stdout)

    def test_the_pin_is_placed_before_any_pathspec_separator(self):
        seen = []

        def runner(argv, **kwargs):
            seen.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        safe_git.probe(str(make_git_repo(test_case=self)),
                       ["status", "--porcelain", "-z", "--", "a.py"], runner=runner)
        argv = seen[-1]
        self.assertIn("--ignore-submodules=none", argv)
        self.assertLess(argv.index("--ignore-submodules=none"), argv.index("--"))


class SetupAndRunioAreConfined(unittest.TestCase):
    """#2006 fix round 2, I2: the two callers "every target-facing git call" missed.

    `setup_flow._git_blanket_pattern` ran bare `["git", "-C", repo,
    "check-ignore", ...]` with NO `env=` at all -- the same shape this PR calls
    a defect in `run_manifest` -- against the reviewed repo during setup.
    `runio._foreign_manifest` resolved a trusted git but launched it without the
    `GIT_CONFIG_*` suppression and without `core.fsmonitor=false`, the exact
    shape ruling 1 fixed in `diff_map`.
    """

    def _repo(self, **kwargs):
        return make_git_repo(test_case=self, panopticon=True,
                             files={"a.py": "value = 1\n", ".gitignore": ".panopticon/\n"},
                             **kwargs)

    def test_the_blanket_pattern_probe_never_runs_the_targets_fsmonitor(self):
        repo = self._repo()
        marker = plant_fsmonitor_command(repo)
        self.assertEqual(setup_flow._git_blanket_pattern(repo), ".panopticon/")
        self.assertFalse(os.path.exists(marker))

    def test_an_inherited_git_environment_cannot_redirect_the_blanket_probe(self):
        # The reviewer's case: with GIT_DIR pointing at another repo, the answer
        # came from that repo, not from the one asked about.
        asked = make_git_repo(test_case=self, panopticon=True,
                              files={"a.py": "value = 1\n"})     # NOTHING ignored here
        other = self._repo()                                      # ignores .panopticon/
        with mock.patch.dict(os.environ, {"GIT_DIR": os.path.join(other, ".git"),
                                          "GIT_WORK_TREE": other}):
            self.assertEqual(setup_flow._git_blanket_pattern(asked), "")
        self.assertEqual(setup_flow._git_blanket_pattern(other), ".panopticon/")

    def test_the_foreign_manifest_check_never_runs_the_targets_fsmonitor(self):
        repo = self._repo()
        marker = plant_fsmonitor_command(repo)
        manifest = os.path.join(repo, ".panopticon", "run-manifest.json")
        os.makedirs(os.path.dirname(manifest), exist_ok=True)
        with open(manifest, "w", encoding="utf-8") as fh:
            fh.write("{}")
        # Untracked (gitignored) manifest: not committed into the target.
        self.assertIs(runio._foreign_manifest({"review_root": repo}, repo, manifest), False)
        self.assertFalse(os.path.exists(marker))

    def test_a_committed_manifest_is_still_detected_as_foreign(self):
        # The signal itself must keep working through the probe.
        repo = self._repo()
        manifest = os.path.join(repo, ".panopticon", "run-manifest.json")
        os.makedirs(os.path.dirname(manifest), exist_ok=True)
        with open(manifest, "w", encoding="utf-8") as fh:
            fh.write("{}")
        subprocess.run(["git", "-C", repo, "add", "-f",
                        os.path.relpath(manifest, repo)], check=True,
                       capture_output=True, timeout=30)
        subprocess.run(["git", "-C", repo, "commit", "-qm", "smuggle"], check=True,
                       capture_output=True, timeout=30)
        self.assertIs(runio._foreign_manifest({"review_root": repo}, repo, manifest), True)



class DiffDriversAreSuppressed(unittest.TestCase):
    """#2006 fix round 2, C1: the reviewer's `diff.external` reproduction.

    An external diff driver's output REPLACES git's, so one repo-local line
    (`diff.external = true`) made `diff_map.hunk_map` return `{}` -- the
    on-diff gate scoped to nothing, which is the vacuous PASS `DiffMapError`
    exists to prevent (#5.0-08) -- while executing target-authored code.

    #2013: the driver is emptied rather than the target refused, so the map is
    HONEST (the hunks git would have produced) instead of either empty or
    absent. Each test proves the fixture live first with a plain `git diff` in
    the same repository, because an absent marker is also what an inert
    fixture produces.
    """

    def _repo(self):
        repo = make_git_repo(test_case=self, panopticon=True,
                             files={"a.py": "value = 1\n"})
        subprocess.run(["git", "-C", repo, "checkout", "-q", "-b", "feature"],
                       check=True, capture_output=True, timeout=30)
        with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("value = 3\n")
        subprocess.run(["git", "-C", repo, "commit", "-qam", "change"], check=True,
                       capture_output=True, timeout=30)
        return repo

    def test_the_map_is_honest_without_a_driver(self):
        # Vacuity guard: the same call DOES produce hunks when nothing is set.
        self.assertIn("a.py", diff_map.hunk_map(self._repo(), "main"))

    def _plant(self, repo, key, attribute=None):
        marker = hostile_marker(repo, "diff-marker")
        if attribute:
            with open(os.path.join(repo, ".gitattributes"), "w", encoding="utf-8") as fh:
                fh.write("a.py %s\n" % attribute)
        subprocess.run(["git", "-C", repo, "config", key,
                        "sh -c 'printf hit > %s; exit 0'" % marker],
                       check=True, capture_output=True, timeout=30)
        # Vacuity guard, per fixture: a plain `git diff` DOES run it, and the
        # driver's output replaces git's (an EMPTY diff -- C1's own symptom).
        plain = subprocess.run(["git", "-C", repo, "diff", "--unified=0", "main"],
                               capture_output=True, text=True, timeout=30)
        self.assertTrue(os.path.exists(marker),
                        "fixture is inert: git never ran %s" % key)
        self.assertEqual(plain.stdout, "", "fixture did not replace git's diff")
        os.remove(marker)
        return marker

    def test_diff_external_is_emptied_and_the_map_stays_honest(self):
        repo = self._repo()
        marker = self._plant(repo, "diff.external")
        self.assertIn("a.py", diff_map.hunk_map(repo, "main"))
        self.assertFalse(os.path.exists(marker))

    def test_an_attribute_scoped_diff_command_is_emptied(self):
        repo = self._repo()
        marker = self._plant(repo, "diff.hostile.command", attribute="diff=hostile")
        self.assertIn("a.py", diff_map.hunk_map(repo, "main"))
        self.assertFalse(os.path.exists(marker))

    def test_an_attribute_scoped_textconv_is_emptied(self):
        repo = self._repo()
        marker = self._plant(repo, "diff.hostile.textconv", attribute="diff=hostile")
        self.assertIn("a.py", diff_map.hunk_map(repo, "main"))
        self.assertFalse(os.path.exists(marker))


class TargetGitDriversAreSuppressed(unittest.TestCase):
    """#2013: the probe EMPTIES every driver command the target configured.

    #2006 refused such a target, which made a `git lfs install --local` or
    git-crypt checkout unreviewable on every path that touches git. The probe
    now composes a `-c <key>=` override per key it found, proves each one reads
    empty, and discloses the pairs; the target's command still never runs, and
    the answers the callers need (dirtiness, submodule dirt, the hunk map) are
    still produced.

    Real repositories, real planted commands, marker-absence assertions -- the
    discipline of this module. Each fixture shape is proved live by a plain git
    call first, here or in `HostileFixturesAreLive`.
    """

    def _repo(self):
        return make_git_repo(test_case=self, panopticon=True,
                             files={"a.py": "value = 1\n"})

    def _feature_repo(self):
        repo = self._repo()
        subprocess.run(["git", "-C", repo, "checkout", "-q", "-b", "feature"],
                       check=True, capture_output=True, timeout=30)
        return repo

    def test_a_planted_process_filter_runs_under_plain_git(self):
        # Vacuity guard for the one fixture shape this class adds.
        repo = self._repo()
        marker = plant_filter_command(repo, "process")
        _plain_status(repo)
        self.assertTrue(os.path.exists(marker),
                        "fixture is inert: git never started filter.fixture.process")

    def test_status_still_reports_the_dirt_with_a_clean_filter_emptied(self):
        repo = self._repo()
        marker = plant_clean_filter(repo)
        suppressed = []
        proc = safe_git.probe(repo, ["status", "--porcelain", "-z"], suppressed=suppressed)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("a.py", proc.stdout)
        self.assertEqual(suppressed, [(".", "filter.fixture.clean")])
        self.assertFalse(os.path.exists(marker))

    def test_a_required_driver_does_not_break_the_emptied_probe(self):
        # `-c filter.fixture.clean=` ALONE is `fatal: clean filter 'fixture'
        # failed` (rc 128, measured) when the driver is required, so the
        # required flag is part of the override set, not just the command line.
        repo = self._repo()
        marker = plant_clean_filter(repo)
        subprocess.run(["git", "-C", repo, "config", "filter.fixture.required", "true"],
                       check=True, capture_output=True, timeout=30)
        suppressed = []
        proc = safe_git.probe(repo, ["status", "--porcelain", "-z"], suppressed=suppressed)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("a.py", proc.stdout)
        self.assertEqual(suppressed, [(".", "filter.fixture.clean"),
                                      (".", "filter.fixture.required")])
        self.assertFalse(os.path.exists(marker))

    def test_every_driver_shape_on_one_target_is_listed_and_inert(self):
        repo = self._feature_repo()
        process = plant_filter_command(repo, "process")       # commits a.py again
        with open(os.path.join(repo, "a.py"), "w", encoding="utf-8") as fh:
            fh.write("after?\n")
        with open(os.path.join(repo, ".gitattributes"), "a", encoding="utf-8") as fh:
            fh.write("a.py diff=hostile\n")
        external = hostile_marker(repo, "external-marker")
        command = hostile_marker(repo, "command-marker")
        textconv = hostile_marker(repo, "textconv-marker")
        for key, marker in (("diff.external", external),
                            ("diff.hostile.command", command),
                            ("diff.hostile.textconv", textconv)):
            subprocess.run(["git", "-C", repo, "config", key,
                            "sh -c 'printf hit > %s; exit 0'" % marker],
                           check=True, capture_output=True, timeout=30)
        suppressed = []
        proc = safe_git.probe(repo, ["diff", "--unified=0", "HEAD"], suppressed=suppressed)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("a.py", proc.stdout)      # the real diff, not a driver's
        self.assertEqual(sorted(suppressed),
                         [(".", "diff.external"), (".", "diff.hostile.command"),
                          (".", "diff.hostile.textconv"),
                          (".", "filter.fixture.process")])
        for marker in (process, external, command, textconv):
            self.assertFalse(os.path.exists(marker), marker)

    def test_a_filter_inside_a_submodule_is_reached_by_the_override(self):
        """The `-c` propagation proof, measured rather than assumed.

        `status --ignore-submodules=none` runs `git status --porcelain=2` as a
        CHILD process inside each submodule, and that child applies the
        submodule's own clean filter. `-c` reaches it through
        `GIT_CONFIG_PARAMETERS`; nothing else in the probe does.
        """
        child = make_git_repo(test_case=self, files={"a.py": "value = 1\n"},
                              branch=None)
        parent = make_git_repo(test_case=self, panopticon=True,
                               files={"a.py": "value = 1\n"})
        worktree = add_plumbing_submodule(parent, child)
        marker = plant_clean_filter(worktree)
        # Vacuity guard: the parent's own status DOES run the submodule's filter.
        subprocess.run(["git", "-C", parent, "status", "--porcelain", "-z",
                        "--ignore-submodules=none"], capture_output=True, timeout=30)
        self.assertTrue(os.path.exists(marker),
                        "fixture is inert: the submodule's filter never ran")
        os.remove(marker)
        suppressed = []
        proc = safe_git.probe(parent, ["status", "--porcelain", "-z"],
                              suppressed=suppressed)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("sub", proc.stdout)       # the submodule dirt is still seen
        self.assertEqual(suppressed, [("sub", "filter.fixture.clean")])
        self.assertFalse(os.path.exists(marker))


if __name__ == "__main__":
    unittest.main()
