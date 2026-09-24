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
                            plant_fsmonitor_command, plant_hook)


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

    def test_worktree_dirty_fails_closed_on_a_command_filter(self):
        repo = self._repo()
        marker = plant_clean_filter(repo)
        with self.assertRaises(OSError) as caught:
            discovery._worktree_dirty(repo)
        self.assertIn("filter", str(caught.exception))
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

    def test_a_command_filter_loses_dirtiness_and_never_runs(self):
        # The commit is still known, so provenance keeps what it can prove;
        # dirtiness becomes None (unknown) rather than a value obtained by
        # running the target's command.
        repo = self._repo()
        marker = plant_clean_filter(repo)
        commit, dirty = run_manifest._target_provenance(repo)
        self.assertEqual(commit, self._head(repo))
        self.assertIsNone(dirty)
        self.assertFalse(os.path.exists(marker))

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

    def test_the_hunk_map_fails_loud_on_a_command_filter_without_running_it(self):
        repo = self._repo()
        marker = plant_clean_filter(repo)
        with self.assertRaises(diff_map.DiffMapError) as caught:
            diff_map.hunk_map(repo, "main")
        self.assertIn("filter", str(caught.exception))
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


class ARefusalIsAMessageNotATraceback(unittest.TestCase):
    """#2006 fix round 1, ruling 2: fail closed, but never as a traceback.

    `validate.capture_tree_baseline` already turns this exact refusal into a
    named line on stderr naming the cause, and fails closed. Discovery's CLI is
    the other operator-facing entry point and must do the same: an unhandled
    OSError out of `main()` is a stack trace the operator has to decode, and it
    does not say which config key was refused.
    """

    def _hostile_repo(self):
        # groups_yml is committed by the helper, so the scan has a matrix and
        # reaches the delta computation rather than refusing earlier.
        repo = make_git_repo(test_case=self, panopticon=True,
                             groups_yml="groups:\n  App:\n    match:\n    - '**/*.py'\n")
        return repo, plant_clean_filter(repo)

    def test_discovery_refuses_with_a_named_message_and_a_non_zero_exit(self):
        repo, marker = self._hostile_repo()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            rc = discovery.main(["--repo", repo, "--repo-scan", "--scope-changed"])
        self.assertEqual(rc, 2)
        message = err.getvalue()
        self.assertIn("filter.fixture.clean", message)   # WHICH key was refused
        self.assertIn("fails closed", message)
        self.assertNotIn("Traceback", message)
        self.assertFalse(os.path.exists(marker))

    def test_the_run_manifest_says_so_without_failing_the_run(self):
        # Provenance is recorded, never enforced (#1492), so a refusal must not
        # abort a run -- but it must not be silent either.
        repo, marker = self._hostile_repo()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            commit, dirty = run_manifest._target_provenance(repo)
        self.assertTrue(commit)
        self.assertIsNone(dirty)
        self.assertIn("filter.fixture.clean", err.getvalue())
        self.assertFalse(os.path.exists(marker))


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


if __name__ == "__main__":
    unittest.main()


class DiffDriversAreRefused(unittest.TestCase):
    """#2006 fix round 2, C1: the reviewer's `diff.external` reproduction.

    An external diff driver's output REPLACES git's, so one repo-local line
    (`diff.external = true`) made `diff_map.hunk_map` return `{}` -- the
    on-diff gate scoped to nothing, which is the vacuous PASS `DiffMapError`
    exists to prevent (#5.0-08) -- while executing target-authored code.
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

    def test_diff_external_is_refused_not_silently_obeyed(self):
        repo = self._repo()
        marker = hostile_marker(repo, "diff-marker")
        subprocess.run(["git", "-C", repo, "config", "diff.external",
                        "sh -c 'printf hit > %s; exit 0'" % marker],
                       check=True, capture_output=True, timeout=30)
        with self.assertRaises(diff_map.DiffMapError) as caught:
            diff_map.hunk_map(repo, "main")
        self.assertIn("diff.external", str(caught.exception))
        self.assertFalse(os.path.exists(marker))

    def test_an_attribute_scoped_diff_command_is_refused(self):
        repo = self._repo()
        marker = hostile_marker(repo, "diff-marker")
        with open(os.path.join(repo, ".gitattributes"), "w", encoding="utf-8") as fh:
            fh.write("a.py diff=hostile\n")
        subprocess.run(["git", "-C", repo, "config", "diff.hostile.command",
                        "sh -c 'printf hit > %s; exit 0'" % marker],
                       check=True, capture_output=True, timeout=30)
        with self.assertRaises(diff_map.DiffMapError) as caught:
            diff_map.hunk_map(repo, "main")
        self.assertIn("diff.hostile.command", str(caught.exception))
        self.assertFalse(os.path.exists(marker))
