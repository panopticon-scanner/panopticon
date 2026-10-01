"""#1638 P06: the committed matrix must claim every runtime module and every test.

Run-13 reviewed eighteen runtime modules in `Ungrouped_1` -- the residual sink --
because `panopticon.yml` had not grown with the tree. The visible
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

Not `discovery.load_catalog`: it neither flattens the matrix (parent) form nor
carries `tests:` at all, so a catalog read through it claims nothing on either
axis for a layered group and this guard would be permanently RED -- 292 of the
302 files on the surfaces below, against the very matrix that claims them. It
returns a truthy dict while doing it, so the emptiness would not announce
itself. `discovery.py`'s own scan path and `phases/readiness.py` both use
`_matrix_catalog`; this is the same read they do.
"""
import os
import unittest

from tests._test_helpers import REPO_ROOT
import scripts.discovery as discovery

# The surfaces a reviewer is expected to see with its architecture context.
# `skill/scripts/**/*.py` is the package; `skill/workflows/**` the dispatch
# workflow scripts; `skill/agents/**` the prompt templates; `scripts/**/*.py`
# the repo-root CLIs; `skill/reference/**/*.{json,yml,yaml}` the shipped
# contracts (the schemas every artifact is validated against, the CWE catalog,
# the OCRDb bundle, the model profiles) -- `verdict-bundle-schema.json` shipped
# in #1637 and landed in `Ungrouped_1` the same week this guard was written,
# which is the case for including them.
#
# Every glob is RECURSIVE and every extension a contract ships in is named: a
# single-level glob fails silently, seeing neither `scripts/sub/x.py` nor the
# next `.yml` contract, which is the drift this guard exists to catch
# (`test_the_runtime_surface_reaches_nested_paths` pins it). Prose under skill/
# is deliberately NOT here: `.md` is Commons/Docs by design.
RUNTIME_SURFACE = (
    "skill/scripts/**/*.py",
    "skill/workflows/**",
    "skill/agents/**",
    "scripts/**/*.py",
    "skill/reference/**/*.json",
    "skill/reference/**/*.yml",
    "skill/reference/**/*.yaml",
)
# `tests/fixtures/**` is deliberately-vulnerable corpus: discovery prunes it
# (include_fixtures=False) and the matrix excludes it via `exclude_paths`. The
# negation here states the same boundary rather than relying on either.
TEST_SURFACE = (
    "tests/**/*.py",
    "!tests/fixtures/**",
)

# Layered groups whose leaves are held under a 40-file fence in front of the
# 48-file cap (#2315, #2273). Both earned it the same way: a leaf reached the
# cap, and the file that would have tipped it over belonged to whoever happened
# to add it next rather than to anyone who had decided where the split goes.
# `test_every_guarded_group_is_in_the_matrix` keeps a stale name from making
# the guard vacuous.
GUARDED_BY_HEADROOM = ("ToolAdapters", "RepoProfiling")

# Files that genuinely have no home in ONE group. Small and explicit on
# purpose (never a glob): each entry is a decision, and a decision that stops
# being true shows up as a stale-entry failure below.
ALLOWLIST = {
    "tests/__init__.py":
        "empty package marker -- no behaviour to review",
    "tests/conftest.py":
        "pytest session safety setup (the "
        "temp HOME and LAUNCH_SEAMS refusal). Pinning it to one vertical hands "
        "that vertical's reviewer the whole suite's plumbing and every other "
        "reviewer none",
    "tests/_test_helpers.py":
        "cross-suite assertion helpers (first/only), imported from every "
        "vertical for the same reason",
}

_CLAIM_ADVICE = ("add it to panopticon.yml — a file no group claims is "
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
        # ONE listing for the whole class: the cap assertion counts the same
        # tree the claim assertions read, and there is no second `git ls-files`
        # that could answer differently.
        cls.files = discovery.discover_repo_files(REPO_ROOT)
        cls.runtime = [f for f in _surface(cls.files, RUNTIME_SURFACE)
                       if f not in ALLOWLIST]
        cls.tests = [f for f in _surface(cls.files, TEST_SURFACE)
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
            "panopticon.yml declares no groups: the review matrix is "
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

    def test_the_runtime_surface_reaches_nested_paths(self):
        # A surface glob is a definition, not a listing, so a shallow one fails
        # SILENTLY: the file that drifted is simply never looked at, and the
        # guard stays green while the matrix rots. `skill/reference/*.json`
        # without `*.yml` is that asymmetry today -- `model-profiles.yml` is a
        # shipped contract sitting off-surface for no reason but the glob.
        # Most of these paths do not exist: they are the shapes the tree may
        # grow next.
        for path in ("scripts/sub/tool.py",
                     "skill/reference/model-profiles.yml",
                     "skill/reference/sub/thing-schema.json",
                     "skill/reference/sub/profiles.yaml",
                     "skill/scripts/phases/deep/nested.py",
                     "skill/agents/sub/role.md"):
            with self.subTest(path=path):
                self.assertTrue(
                    discovery.match_patterns(path, RUNTIME_SURFACE),
                    "%s is off the runtime surface: the guard would never see "
                    "it drift into Ungrouped" % path)

    def test_every_runtime_file_is_claimed(self):
        missing = self._unclaimed(self.runtime)
        self.assertEqual(
            missing, [],
            "%d runtime file(s) no group in panopticon.yml claims:\n"
            "  %s\n%s" % (len(missing), "\n  ".join(missing), _CLAIM_ADVICE))

    def test_every_test_file_is_claimed(self):
        missing = self._unclaimed(self.tests)
        self.assertEqual(
            missing, [],
            "%d test file(s) no group in panopticon.yml claims:\n"
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
        assigned, _left, _w = discovery.assign_scoped(self.files, self.catalog)
        over = ["%s: %d files" % (name, len(files))
                for name, files in sorted(assigned.items()) if len(files) > cap]
        self.assertEqual(
            over, [],
            "%d leaf(s) over the %d-file cap:\n  %s\n"
            "an oversize leaf is split into `<name>_N` chunks at run time, and "
            "a chunk name has no entry in the matrix -- its cell is reviewed "
            "with an empty test inventory (#1638 P13). Split the leaf into "
            "layers in panopticon.yml instead."
            % (len(over), cap, "\n  ".join(over)))

    def test_guarded_group_leaves_keep_headroom(self):
        # #2315: `ToolAdapters:Integration` reached 48 of 48 the moment
        # `tests/tools/test_sarif_utils.py` joined it through `tests/tools/**`,
        # so the NEXT adapter or adapter test would have turned the cap
        # assertion above red for whoever added it -- a stranger to the split
        # decision, mid-PR. That leaf's growth surface is a glob over two whole
        # directories, which is the one shape that grows without anybody
        # choosing to, so it gets a guard with room to land in: the cap is the
        # wall, and this is the fence in front of it.
        #
        # #2273 parametrises it over `RepoProfiling` too, because that group
        # reached the wall with no fence at all: it sat AT 48, and the two
        # discovery policies that came out of `discovery.py` were parked in
        # `Orchestration:Core` one after the other rather than claimed where
        # they belong -- a cap hit twice, by two PRs, neither of which had
        # chosen to decide the question. Guarding the group a split just
        # relieved is the point: the fence is what makes the NEXT split this
        # subsystem's own decision instead of the next contributor's surprise.
        headroom = 40
        assigned, _left, _w = discovery.assign_scoped(self.files, self.catalog)
        for group in GUARDED_BY_HEADROOM:
            with self.subTest(group=group):
                tight = ["%s: %d files" % (name, len(files))
                         for name, files in sorted(assigned.items())
                         if name.split(":")[0] == group and len(files) > headroom]
                self.assertEqual(
                    tight, [],
                    "%d %s leaf(s) above the %d-file headroom (the cap is "
                    "%d):\n  %s\nsplit the leaf into another layer in "
                    "panopticon.yml now, while the split is still this PR's "
                    "decision rather than the next contributor's surprise "
                    "(#2315, #2273). If the leaf is one whose siblings are "
                    "literal paths, a layer may have been reordered behind "
                    "its globs: `ToolAdapters:Contract` must stay listed "
                    "before `Integration`."
                    % (len(tight), group, headroom,
                       discovery.DEFAULT_MAX_PER_GROUP, "\n  ".join(tight)))

    def test_every_guarded_group_is_in_the_matrix(self):
        # The guard above is a list of NAMES, and a name that stops matching
        # any leaf makes it vacuous rather than red: rename `RepoProfiling` and
        # its leaves go unfenced while the loop still reports a pass over an
        # empty comprehension. Same failure mode as a shallow surface glob.
        missing = [group for group in GUARDED_BY_HEADROOM
                   if not any(name.split(":")[0] == group
                              for name in self.catalog)]
        self.assertEqual(
            missing, [],
            "GUARDED_BY_HEADROOM names no longer in panopticon.yml: %s -- the "
            "headroom guard silently stopped covering them. Rename the entry "
            "or drop it with the group." % ", ".join(missing))

    def test_allowlist_entries_still_exist(self):
        stale = [path for path in sorted(ALLOWLIST)
                 if not os.path.isfile(os.path.join(REPO_ROOT, path))]
        self.assertEqual(
            stale, [],
            "allowlisted path(s) that no longer exist: %s -- drop the entry"
            % ", ".join(stale))

    def test_literal_catalog_entries_still_exist(self):
        # The guard above covers ALLOWLIST. The matrix carries literal entries
        # beside its globs -- about 320 when this was written -- and a literal
        # that stops existing is dead text rather than a failure: rename
        # `tests/tools/test_base.py` and `ToolAdapters:Contract` goes on
        # listing the old name while the renamed file falls back to
        # `Integration`'s `tests/tools/**` glob -- the leaf split quietly
        # un-splits itself, and the headroom guard above is the only thing
        # that would ever notice (#2315 review, finding 6).
        #
        # A stale `!` negation is dead the same way: it holds out a path that
        # is no longer there, so whatever it was written to keep out of the
        # leaf has been renamed into it. Patterns are SKIPPED rather than
        # resolved -- a glob matching nothing is a different question (every
        # catalog glob matches today; a forward-written one is allowed).
        #
        # Resolution follows `discovery.glob_to_re`, not `os.path.exists`: a
        # literal with no `/` is unanchored and matches its basename at any
        # depth, so it is live while any reviewable file carries that name;
        # one with a `/` is root-anchored (a leading `/` is stripped), names a
        # tree when it ends in `/` and a file otherwise. A bare directory
        # path without the slash matches nothing, so `exists` would bless
        # dead text there (#2454 review).
        stale = []
        for group, body in sorted(self.catalog.items()):
            for axis in ("match", "tests"):
                for entry in (body.get(axis) or []):
                    if any(ch in entry for ch in "*?["):
                        continue
                    target = entry[1:] if entry.startswith("!") else entry
                    if "/" not in target:
                        live = any(f == target or f.endswith("/" + target)
                                   for f in self.files)
                    else:
                        probe = os.path.join(REPO_ROOT, target.lstrip("/"))
                        live = (os.path.isdir(probe) if target.endswith("/")
                                else os.path.isfile(probe))
                    if not live:
                        stale.append("%s: %s" % (group, entry))
        self.assertEqual(
            stale, [],
            "literal catalog path(s) that no longer exist: %s -- drop or "
            "rename the entry (#2454)" % ", ".join(stale))


if __name__ == "__main__":
    unittest.main()
