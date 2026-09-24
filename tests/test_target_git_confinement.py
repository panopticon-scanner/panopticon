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
import os
import subprocess
import unittest
from unittest import mock

from conftest import SKILL_ROOT
import scripts.discovery as discovery
import scripts.run_manifest as run_manifest

from tools.git_repo import (hostile_marker, make_git_repo, path_shim_git,
                            plant_clean_filter, plant_fsmonitor_command)


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
    remembered. Scoped to the two modules this issue closes: `diff_map._run_git`
    resolves a trusted git but still runs without the config suppression or the
    preflight, and is a separate residual, not something this guard may claim.
    """

    MODULES = ("discovery.py", "run_manifest.py")

    def test_neither_module_builds_a_bare_git_argv(self):
        offenders = []
        for name in self.MODULES:
            path = os.path.join(SKILL_ROOT, "scripts", name)
            with open(path, encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), path)
            for node in ast.walk(tree):
                if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
                    continue
                first = node.elts[0]
                if isinstance(first, ast.Constant) and first.value == "git":
                    offenders.append("%s:%d: %s" % (name, node.lineno,
                                                    ast.unparse(node)))
        self.assertEqual(
            offenders, [],
            "a git argv built by hand runs the TARGET's git off the inherited "
            "PATH with the target's config live; route it through "
            "safe_git.probe:\n  %s" % "\n  ".join(offenders))


if __name__ == "__main__":
    unittest.main()
