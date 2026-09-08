"""#1256 (COD-B2C, advisor-confirmed): hunk_map fails open when merge-base cannot run.

`hunk_map` returns `{}` when `git merge-base HEAD <base>` exits non-zero, on the
documented assumption that "an upstream loud-fail already guards this". That
guard is `resolve_base_or_die`, and it verifies the base ref RESOLVES TO A
COMMIT -- which is a different question from whether HEAD and that commit share
an ancestor.

merge-base also fails, with a perfectly valid base commit, when there is no
common ancestor. The everyday way to reach that is a SHALLOW CLONE: CI checkouts
default to depth 1, so the fork point simply is not in the local history. An
empty hunk map scopes the on-diff gate to nothing, which passes vacuously -- the
exact #5.0-08 hazard the sibling code paths already raise on.
"""
import os
import subprocess
import unittest

import scripts.diff_map as diff_map

from tools.git_repo import make_git_repo


def _git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], check=True,
                          capture_output=True, text=True, timeout=30)


class MergeBaseFailClosedTest(unittest.TestCase):
    def _unrelated_histories(self):
        """A repo whose `other` branch shares no ancestor with HEAD."""
        repo = make_git_repo(test_case=self, files={"app.py": "value = 1\n"})
        _git(repo, "checkout", "-q", "--orphan", "other")
        # -rf, not --cached: leaving the file untracked in the worktree blocks
        # the checkout back to main.
        _git(repo, "rm", "-rqf", ".")
        with open(os.path.join(repo, "island.py"), "w", encoding="utf-8") as fh:
            fh.write("x = 1\n")
        _git(repo, "add", "island.py")
        _git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "orphan")
        _git(repo, "checkout", "-q", "main")
        return repo

    def test_the_fixture_really_has_no_common_ancestor(self):
        repo = self._unrelated_histories()
        mb = subprocess.run(["git", "-C", repo, "merge-base", "HEAD", "other"],
                            capture_output=True, text=True, timeout=30)
        self.assertNotEqual(mb.returncode, 0,
                            "fixture must reproduce a failing merge-base")
        rev = subprocess.run(["git", "-C", repo, "rev-parse", "--verify", "-q",
                              "other^{commit}"], capture_output=True, text=True,
                             timeout=30)
        self.assertEqual(rev.returncode, 0,
                         "the base must be a VALID commit -- that is the point")

    def test_no_common_ancestor_raises_instead_of_scoping_to_nothing(self):
        repo = self._unrelated_histories()
        with self.assertRaises(diff_map.DiffMapError) as ctx:
            diff_map.hunk_map(repo, "other")
        self.assertIn("common ancestor", str(ctx.exception))

    def test_the_message_names_the_shallow_clone_remedy(self):
        # The common way to hit this is a depth-1 CI checkout, and an operator
        # staring at a stack trace cannot act on it.
        repo = self._unrelated_histories()
        with self.assertRaises(diff_map.DiffMapError) as ctx:
            diff_map.hunk_map(repo, "other")
        self.assertIn("unshallow", str(ctx.exception))

    def test_a_normal_base_still_produces_a_map(self):
        repo = make_git_repo(test_case=self, files={"app.py": "value = 1\n"})
        _git(repo, "checkout", "-q", "-b", "feature")
        with open(os.path.join(repo, "app.py"), "w", encoding="utf-8") as fh:
            fh.write("value = 2\n")
        _git(repo, "add", "app.py")
        _git(repo, "-c", "commit.gpgsign=false", "commit", "-qm", "change")
        self.assertIn("app.py", diff_map.hunk_map(repo, "main"))

    def test_diff_anchors_reports_the_missing_fork_point_as_none(self):
        # diff_anchors is disclosure, not a gate: it records what it could
        # resolve. It must not raise -- but a null delta_start beside a
        # non-null base_commit is the visible trace of the same condition.
        repo = self._unrelated_histories()
        anchors = diff_map.diff_anchors(repo, "other")
        self.assertIsNotNone(anchors["base_commit"])
        self.assertIsNone(anchors["delta_start"])


if __name__ == "__main__":
    unittest.main()
