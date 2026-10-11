"""#1761/#1762/#1763 (ARC-A1*, run-14 ARC-2609514778 HIGH and five siblings):
the 700-line ceiling, extended to the flat modules and the entry scripts.

`tests/test_layout.py` rule 5 ratchets the four packages -- `synth`, `phases`,
`runners`, `probes` -- and every module under that ratchet is under the
ceiling. Nothing ratcheted the rest of `skill/scripts/`, `scripts/` or the
`tools/` adapter package, so the
largest modules in the tree were the unmeasured ones: `run_tools.py` went from
1231 to 2215 lines in the six days after the finding was written, because the
whole post-run scanner-policy series landed there and nothing pushed back. The
ratchet exists to make growth a visible decision; on this surface it was
invisible for twenty modules at once.

So the same ceiling applies here, as a SHRINK-ONLY allowlist. `PENDING` pins
every module already over the ceiling at the count it had when this guard
landed, and such a module may only get smaller. A number here is never raised
-- a module that needs more room gets split; the splits owed are tracked in
#1762/#1763 -- and a module that reaches the ceiling loses its entry, so the
allowlist cannot outlive the work it records. A module that shrinks but stays
over the ceiling lowers its pin to the new count in the same change, so the
allowlist stays a measurement and not a permission.

`LINE_CEILING` is imported from rule 5 rather than restated: two ratchets that
disagree about the number are two different rules. Lines are counted the way
rule 5 counts them (`len(text.splitlines())`), for the same reason.
"""
import os
import tempfile
import unittest

from tests._test_helpers import REPO_ROOT
from tests.test_layout import LINE_CEILING

# The surface: `*.py` directly under each of these, which is everything the
# package ratchet does not reach -- the entry scripts (`driver.py`,
# `synthesize.py`, `orchestrate.py`, `host_probes.py`), the flat modules they
# share, the repo-root CLIs, and the `tools/` adapter package, which rule 5's
# PACKAGES tuple does not name (its `base.py` is ARC-2990316730). NOT
# recursive: `skill/scripts/synth/*` and friends are rule 5's, and tests are
# nobody's business here.
SURFACES = ("skill/scripts", "scripts", "skill/scripts/tools")

# path -> the line count it had when this guard landed (2026-09-26, main
# de4675d; measured with `wc -l`, which agrees with `splitlines()` on every
# file here). An entry is a debt, not a permission: it may only go DOWN, and it
# must disappear once the module is at or under LINE_CEILING, and it is lowered
# to the new count whenever the module shrinks. Twenty modules, and the five
# with a fix shape written down are the first ones owed:
# `run_tools.py` (ARC-2609514778 -- all four extractions have now landed,
# scanner config, capture, manifest and the virtualenv scope, and the pin below
# is what they did not reach: docker detection, language detection, selection,
# the docker argv and the CLI), `setup_flow.py` (ARC-1181155147),
# `orchestrate.py`
# (ARC-4087467862), `driver.py` (ARC-3080609219) and `tools/base.py`
# (ARC-2990316730).
PENDING: dict[str, int] = {
    "scripts/bump_pins.py": 871,
    "scripts/reconcile_apply.py": 829,
    "scripts/triage.py": 792,
    "skill/scripts/diff_map.py": 1215,
    "skill/scripts/discovery.py": 1931,
    "skill/scripts/driver.py": 1228,
    "skill/scripts/evidence.py": 982,
    "skill/scripts/html_report.py": 1568,
    "skill/scripts/ingest_tools.py": 1100,
    "skill/scripts/loop_batch.py": 822,
    "skill/scripts/orchestrate.py": 737,
    "skill/scripts/read_guard_hook.py": 786,
    "skill/scripts/run_tools.py": 815,
    "skill/scripts/safe_git.py": 852,
    "skill/scripts/setup_flow.py": 1335,
    "skill/scripts/setup_proposal.py": 741,
    "skill/scripts/tools/base.py": 798,
    "skill/scripts/write_guard_hook.py": 1184,
}


def _flat_modules(root=REPO_ROOT):
    """Every `*.py` directly on the flat surface, as sorted relative paths."""
    found = []
    for surface in SURFACES:
        directory = os.path.join(root, *surface.split("/"))
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".py"):
                continue
            if os.path.isfile(os.path.join(directory, name)):
                found.append(surface + "/" + name)
    return sorted(found)


def _line_count(relative, root=REPO_ROOT):
    with open(os.path.join(root, *relative.split("/")), encoding="utf-8") as fh:
        return len(fh.read().splitlines())


def _over_ceiling(pending, root=REPO_ROOT):
    """Modules above their own ceiling: LINE_CEILING, or their pin if pinned."""
    rows = []
    for relative in _flat_modules(root):
        count = _line_count(relative, root)
        ceiling = pending.get(relative, LINE_CEILING)
        if count > ceiling:
            rows.append("%s: %d lines (ceiling %d)" % (relative, count, ceiling))
    return rows


def _graduated(pending, root=REPO_ROOT):
    """Pinned modules that have reached the ceiling: the entry must go."""
    known = set(_flat_modules(root))
    rows = []
    for relative, pinned in sorted(pending.items()):
        if relative not in known:
            continue                      # stale entry; reported on its own
        count = _line_count(relative, root)
        if count <= LINE_CEILING:
            rows.append("%s: %d lines (pinned at %d)" % (relative, count, pinned))
    return rows


def _stale(pending, root=REPO_ROOT):
    """Pinned paths that are no longer a flat module (moved, split, deleted)."""
    known = set(_flat_modules(root))
    return sorted(relative for relative in pending if relative not in known)


class FlatModuleCeilingTest(unittest.TestCase):

    def test_no_flat_module_or_entry_script_is_over_its_ceiling(self):
        over = _over_ceiling(PENDING)
        self.assertEqual(
            over, [],
            "%d flat module(s)/entry script(s) over the %d-line ceiling:\n  %s\n"
            "Split the module (the extractions are tracked in #1762/#1763), or "
            "shrink it. Never raise the number: a PENDING pin may only go down, "
            "and a new module gets no pin at all."
            % (len(over), LINE_CEILING, "\n  ".join(over)))

    def test_a_pinned_module_that_reached_the_ceiling_leaves_the_allowlist(self):
        graduated = _graduated(PENDING)
        self.assertEqual(
            graduated, [],
            "%d PENDING module(s) now at or under the %d-line ceiling:\n  %s\n"
            "drop the entry -- the allowlist is the list of splits still owed, "
            "and a pin left behind quietly re-permits the growth it recorded"
            % (len(graduated), LINE_CEILING, "\n  ".join(graduated)))

    def test_pending_names_only_modules_that_are_still_on_the_surface(self):
        stale = _stale(PENDING)
        self.assertEqual(
            stale, [],
            "PENDING names path(s) that are no longer a flat module: %s -- drop "
            "the entry (a moved or split module is the ratchet working)"
            % ", ".join(stale))


class RatchetMechanicsTest(unittest.TestCase):
    """The two ways a shrink-only allowlist rots, proved on the real tree with
    fake mappings -- no module is edited to make a point."""

    def _largest(self):
        modules = _flat_modules()
        relative = max(modules, key=lambda path: _line_count(path))
        return relative, _line_count(relative)

    def _smallest(self):
        modules = _flat_modules()
        relative = min(modules, key=lambda path: _line_count(path))
        return relative, _line_count(relative)

    def test_a_pinned_module_that_grew_past_its_pin_is_named(self):
        relative, count = self._largest()
        if count <= LINE_CEILING:
            self.skipTest("no module on the surface is over the ceiling: PENDING "
                          "is paid off, and this mechanics test has no subject")
        rows = _over_ceiling({relative: count - 1})
        self.assertIn("%s: %d lines (ceiling %d)" % (relative, count, count - 1), rows)

    def test_a_pinned_module_under_the_ceiling_is_reported_as_graduated(self):
        relative, count = self._smallest()
        self.assertLessEqual(count, LINE_CEILING)
        pending = {relative: count}
        self.assertEqual(_graduated(pending),
                         ["%s: %d lines (pinned at %d)" % (relative, count, count)])
        # and it is not ALSO reported as over its ceiling: a pin is a ceiling.
        self.assertEqual([row for row in _over_ceiling(pending)
                          if row.startswith(relative + ":")], [])

    def test_a_pin_for_a_path_that_left_the_surface_is_stale(self):
        self.assertEqual(_stale({"skill/scripts/gone.py": 900}),
                         ["skill/scripts/gone.py"])

    def test_the_surface_is_every_flat_module_and_nothing_nested(self):
        with tempfile.TemporaryDirectory() as directory:
            for relative in ("skill/scripts/driver.py", "scripts/triage.py",
                             "skill/scripts/tools/base.py", "skill/scripts/tools/x/y.py",
                             "skill/scripts/synth/report.py", "scripts/sub/tool.py",
                             "tests/test_thing.py", "skill/scripts/notes.md"):
                path = os.path.join(directory, *relative.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("x = 1\n")
            self.assertEqual(_flat_modules(directory),
                             ["scripts/triage.py", "skill/scripts/driver.py",
                              "skill/scripts/tools/base.py"])

    def test_a_last_line_without_a_newline_still_counts(self):
        # `splitlines()`, not `count("\n")`: rule 5's reading, so the two
        # ratchets cannot disagree about a file that ends mid-line.
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "scripts")
            os.makedirs(path)
            with open(os.path.join(path, "x.py"), "w", encoding="utf-8") as fh:
                fh.write("one\ntwo\nthree")        # no trailing newline
            self.assertEqual(_line_count("scripts/x.py", directory), 3)


if __name__ == "__main__":
    unittest.main()
