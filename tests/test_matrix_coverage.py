"""#1638 P06: the committed matrix must claim every runtime module and every test.

Run-13 reviewed eighteen runtime modules in `Ungrouped_1` -- the residual sink --
because `.panopticon/groups.yml` had not grown with the tree. The visible
consequence was P13: `phases/review.py` builds each cell's test inventory from
the claiming group's `tests:` axis, so a module whose tests no group claims is
reviewed against an EMPTY inventory, and the reviewer duly reported "no
automated coverage" for code whose tests that same session had just run green.
Neither half is a review-coverage gap -- the sink is still reviewed -- which is
exactly why nothing failed loudly for eighteen files at once.

The guard therefore asserts three things about the committed matrix:

* every runtime file is claimed by some group (architecture context), and
* every test file is claimed by some group's `tests:` axis, not by its `match:`
  (only the `tests:` axis reaches the reviewer as the inventory), and
* no leaf is over the cap, because an oversize leaf is split into
  `<name>_1` chunks at run time and `matrix.get("Reporting:Core_1")` is a miss:
  the chunk is reviewed with an empty test inventory, which is P13 again.

It reads only this repo's own tree, through the SAME two discovery entry points
the run and `driver readiness` use -- `discover_repo_files` for the listing
(`git ls-files` in a git checkout, an `EXCLUDE_DIR_GLOBS`-pruned walk otherwise)
and `_matrix_catalog` for the catalog -- so the guard and the run can never
disagree about what the matrix claims. No target, no network, no host binary,
and nothing read from outside the repo root.
"""
import os
import unittest

from conftest import REPO_ROOT
import scripts.discovery as discovery

# The surfaces a reviewer is expected to see with its architecture context.
# `skill/scripts/**/*.py` is the package; `skill/workflows/**` the dispatch
# workflow scripts; `skill/agents/**` the prompt templates; `scripts/*.py` the
# repo-root CLIs; `skill/reference/*.json` the shipped contracts (the schemas
# every artifact is validated against, the CWE catalog, the OCRDb bundle) --
# `verdict-bundle-schema.json` shipped in #1637 and landed in `Ungrouped_1` the
# same week this guard was written, which is the case for including them.
# Prose under skill/ is deliberately NOT here: `.md` is Commons/Docs by design.
RUNTIME_SURFACE = (
    "skill/scripts/**/*.py",
    "skill/workflows/**",
    "skill/agents/**",
    "scripts/*.py",
    "skill/reference/*.json",
)
# `tests/fixtures/**` is deliberately-vulnerable corpus: discovery prunes it
# (include_fixtures=False) and the matrix excludes it via `exclude_paths`. The
# negation here states the same boundary rather than relying on either.
TEST_SURFACE = (
    "tests/**/*.py",
    "!tests/fixtures/**",
)

# Files that genuinely have no home in ONE group. Small and explicit on
# purpose (never a glob): each entry is a decision, and a decision that stops
# being true shows up as a stale-entry failure below.
ALLOWLIST = {
    "tests/__init__.py":
        "empty package marker -- no behaviour to review",
    "tests/conftest.py":
        "pytest session plumbing every group's tests import (path anchors, the "
        "temp HOME, the LAUNCH_SEAMS refusal). Pinning it to one vertical hands "
        "that vertical's reviewer the whole suite's plumbing and every other "
        "reviewer none",
    "tests/_test_helpers.py":
        "cross-suite assertion helpers (first/only), imported from every "
        "vertical for the same reason",
}

_CLAIM_ADVICE = ("add it to .panopticon/groups.yml — a file no group claims is "
                 "reviewed as Ungrouped without its architecture context or "
                 "its tests")


def _surface(files, globs):
    """The repo files on one surface, gitignore-style (discovery's matcher)."""
    return [f for f in files if discovery.match_patterns(f, globs)]


def _tagged(body):
    """One group's `match:` + `tests:` as the tagged list `_decide` reads."""
    return ([(p, "match") for p in (body.get("match") or [])]
            + [(p, "tests") for p in (body.get("tests") or [])])


class TestMatrixCoverage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = discovery._matrix_catalog(REPO_ROOT)
        files = discovery.discover_repo_files(REPO_ROOT)
        cls.runtime = [f for f in _surface(files, RUNTIME_SURFACE)
                       if f not in ALLOWLIST]
        cls.tests = [f for f in _surface(files, TEST_SURFACE)
                     if f not in ALLOWLIST]
        cls.assigned, cls.leftovers, _warnings = discovery.assign_scoped(
            cls.runtime + cls.tests, cls.catalog)

    def _unclaimed(self, surface):
        claimed = set(self.leftovers)
        return [f for f in surface if f in claimed]

    def test_committed_matrix_is_readable(self):
        # Without this the two assertions below fail with "everything is
        # unclaimed", which reads as a matrix that lost 300 files rather than
        # as a catalog that failed to load.
        self.assertTrue(
            self.catalog,
            ".panopticon/groups.yml declares no groups: the review matrix is "
            "missing or unparseable, and every file would fall back to an "
            "Ungrouped_N chunk. Run `python3 skill/scripts/driver.py readiness .`")

    def test_the_listing_is_not_empty(self):
        # Vacuity guard. Every assertion below is "nothing was left out", which
        # a listing that returned NOTHING also satisfies -- and the listing has
        # two implementations (`git ls-files`, and an os.walk when git is
        # absent or the checkout is not a work tree), so the empty one is
        # reachable by environment rather than by code change. The floors are
        # deliberately far below the real counts (118 runtime / 184 tests when
        # this was written): this is checking for zero, not pinning a size.
        self.assertGreater(len(self.runtime), 50, "runtime listing collapsed")
        self.assertGreater(len(self.tests), 100, "test listing collapsed")

    def test_every_runtime_file_is_claimed(self):
        missing = self._unclaimed(self.runtime)
        self.assertEqual(
            missing, [],
            "%d runtime file(s) no group in .panopticon/groups.yml claims:\n"
            "  %s\n%s" % (len(missing), "\n  ".join(missing), _CLAIM_ADVICE))

    def test_every_test_file_is_claimed_by_a_tests_axis(self):
        missing = self._unclaimed(self.tests)
        self.assertEqual(
            missing, [],
            "%d test file(s) no group in .panopticon/groups.yml claims:\n"
            "  %s\n%s" % (len(missing), "\n  ".join(missing), _CLAIM_ADVICE))

    def test_test_files_ride_the_tests_axis_not_match(self):
        on_tests = set(self.tests)
        wrong = []
        for group, claimed in sorted(self.assigned.items()):
            tagged = _tagged(self.catalog.get(group) or {})
            for path in claimed:
                if path not in on_tests:
                    continue
                _matched, tag, glob = discovery._decide(path, tagged)
                if tag != "tests":
                    wrong.append("%s (claimed by %s's match: %r)"
                                 % (path, group, glob))
        self.assertEqual(
            wrong, [],
            "%d test file(s) claimed by a `match:` glob:\n  %s\n"
            "phases/review.py builds the cell's test inventory from the "
            "group's `tests:` axis only, so a test claimed by `match:` is "
            "reviewed as code and never reaches a reviewer as coverage"
            % (len(wrong), "\n  ".join(wrong)))

    def test_no_leaf_is_over_the_cap(self):
        cap = discovery.DEFAULT_MAX_PER_GROUP
        # Count over the WHOLE reviewable tree, not just the two surfaces
        # above: run-time chunking counts every file a leaf claims.
        assigned, _left, _w = discovery.assign_scoped(
            discovery.discover_repo_files(REPO_ROOT), self.catalog)
        over = ["%s: %d files" % (name, len(files))
                for name, files in sorted(assigned.items()) if len(files) > cap]
        self.assertEqual(
            over, [],
            "%d leaf(s) over the %d-file cap:\n  %s\n"
            "an oversize leaf is split into `<name>_N` chunks at run time, and "
            "a chunk name has no entry in the matrix -- its cell is reviewed "
            "with an empty test inventory (#1638 P13). Split the leaf into "
            "layers in .panopticon/groups.yml instead."
            % (len(over), cap, "\n  ".join(over)))

    def test_allowlist_entries_still_exist(self):
        stale = [path for path in sorted(ALLOWLIST)
                 if not os.path.isfile(os.path.join(REPO_ROOT, path))]
        self.assertEqual(
            stale, [],
            "allowlisted path(s) that no longer exist: %s -- drop the entry"
            % ", ".join(stale))


if __name__ == "__main__":
    unittest.main()
