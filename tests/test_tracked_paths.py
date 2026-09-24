"""#2025: `.panopticon/` must carry no tracked file except a pinned allow-list.

`.gitignore` line 7, `.panopticon*/`, is a blanket ignore for the run-artifacts
sink (the glob form matters: a bare `.panopticon/` stops matching a preserved
run renamed to `.panopticon.prev-20260803`, which is how 3.1MB of run-1
scratch was committed by accident once already). Nothing in `.gitignore`
re-includes any path under `.panopticon/` with a `!` negation as of this
writing, so the only way a file lands there tracked is `git add -f` past the
ignore -- which is exactly what happened to the WS9 remediation ledger this
issue untracks (`git rm --cached`, forward-only: the file stays on disk,
history is untouched).

This is deliberately NOT `scripts.discovery.discover_repo_files` /
`_git_listed_files`: those union tracked + untracked-but-unignored paths (the
reviewable surface), which is the wrong question here -- this test is only
about what is committed. No such helper exists for a bare `ls-files` read in
tests/_test_helpers.py or elsewhere under tests/, so this calls git directly,
bounded and skip-clean.
"""
import shutil
import subprocess
import unittest

from conftest import REPO_ROOT

# The allow-list. Empty on purpose: repository configuration (the review
# matrix) lives in root panopticon.yml (#1681), not under `.panopticon/`, and
# no `.gitignore` negation re-includes anything under this directory. Add an
# entry here -- with a comment naming the negation rule that allows it --
# only if that ever changes; never widen this test to "whatever git currently
# lists".
ALLOWED_TRACKED_PANOPTICON_PATHS = ()  # nothing is deliberately un-ignored


class TrackedPathsUnderPanopticonDirTest(unittest.TestCase):

    def test_no_unexpected_tracked_paths_under_panopticon_dir(self):
        git = shutil.which("git")
        if git is None:
            self.skipTest("git not on PATH")
        try:
            result = subprocess.run(
                [git, "ls-files", "-z", "--", ".panopticon"],
                cwd=REPO_ROOT, capture_output=True, timeout=30, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.skipTest("git ls-files unavailable: %s" % exc)
        if result.returncode != 0:
            self.skipTest("git ls-files failed (not a git checkout?): %s"
                          % result.stderr.decode("utf-8", "replace").strip())
        tracked = tuple(p for p in result.stdout.decode("utf-8", "surrogateescape")
                        .split("\0") if p)
        self.assertEqual(
            tracked, ALLOWED_TRACKED_PANOPTICON_PATHS,
            "tracked path(s) under .panopticon/ outside the pinned allow-list "
            "(added with `git add -f` past .gitignore's `.panopticon*/`?): "
            "%r -- see #2025" % (tracked,))


if __name__ == "__main__":
    unittest.main()
