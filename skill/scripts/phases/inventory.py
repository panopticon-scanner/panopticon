"""Phase 4 -- the review cell's TEST INVENTORY verdict and its prompt block.

#1638 P13. A domain panel's reads are fenced to its own cell, so it cannot
tell "this inventory lists no test" (a fact about the review matrix) from "no
test exists" (a fact about the repository). Run-13 published the second
reading of the first fact for a module whose 138 tests that same session had
run green, and the advisor could only return NEEDS_MORE_INFO: the claim was
unadjudicable, not merely wrong.

The driver is the one party that CAN tell them apart -- it assigned every file
in the tree to a group -- so it answers the question for the reviewer and
publishes the answer (`meta.coverage.test_inventory`, the HTML, the dispatch
entry). Nothing here asks an agent to record it: the prompt block only says
what the reviewer may and may not conclude.

Split out of `review.py` at fix round 1: the verdict, its two basename
filters and the prompt text are one cohesive concern, and `review.py` was at
658 of the 700-line package ceiling with it inlined. `skill/scripts/phases/**`
already claims this file in the committed matrix, so no config edit was
needed (the P06 guard is green either way).
"""
import os

import scripts.discovery as discovery
import scripts.grouping_engine as grouping_engine

from . import coverage
from . import runio

# How many foreign test paths -- and foreign group names -- the `split` note
# lists before it says "and N more". Five is enough for a reviewer to
# recognise the pattern and short enough that a badly-split 300-file group in
# a 30-group matrix cannot flood the prompt with either.
PATHS_SHOWN = 5


def test_target_stem(path):
    """`a` for `tests/test_a.py` or `a_test.go`, else None -- the one naming
    convention this detector claims to understand. It is deliberately
    conservative: a test named after nothing in the cell is simply not
    counted, which under-reports `split` rather than inventing one."""
    stem = os.path.splitext(os.path.basename(path or ""))[0]
    if stem.startswith("test_"):
        return stem[len("test_"):] or None
    if stem.endswith("_test"):
        return stem[:-len("_test")] or None
    return None


def unit_stems(files):
    """`(module stems, tested stems, has own tests)` for one review unit.

    A file is a TEST when EITHER of discovery's two test classifications says
    so: `discovery.is_test_file` (the naming rule `partition_test_files` uses,
    which matches `test_*.py` at any depth -- `solo/tests/test_widget.py`, not
    just the top-level tree) or `classify_files`' `tests` kind (the Tests
    sweep's seed globs, which cover the plumbing the naming rule misses --
    `conftest.py`, `_test_helpers.py`, the golden corpora).

    A non-test file is a MODULE only when `grouping_engine.classify_files` --
    the same classifier `count_code_files` sizes a repo with -- calls it
    `code`. Before that filter `pyproject.toml`, `LICENSE` and every `.md`
    counted as modules, which is how this repo's own `Commons` group read
    `split` on `tests/test_pyproject.py` (fix round 1, F4).

    `has own tests` is the third answer because it is a different question
    from the committed `tests:` axis: a group that claims its tests through
    `match:`, or the auto-formed `Tests` sweep, HOLDS them in its own read
    grant, so telling its reviewer they "may exist outside your scope" is
    false and telling it to make no coverage claim suppresses findings it can
    legitimately make (fix round 1, F2).
    """
    files = list(files or ())
    kinds = grouping_engine.classify_files(files)
    modules, tested, own = set(), set(), False
    for f in files:
        if discovery.is_test_file(f) or kinds.get(f) == "tests":
            own = True
            target = test_target_stem(f)
            if target:
                tested.add(target)
            continue
        if kinds.get(f) != "code":
            continue
        stem = os.path.splitext(os.path.basename(f))[0]
        if stem:
            modules.add(stem)
    return modules, tested, own


def unit_stems_map(units):
    """`{unit: unit_stems(files)}` -- ONE `classify_files` pass per unit.

    Fix round 2, N2. `foreign_tests` compares one unit's module stems against
    every other unit's files, and deriving the other unit's stems inside that
    pair loop made the pass O(units^2) over a classifier that walks ~230 glob
    patterns per file: 1.4s at 11 units, 22.9s at 44, and `review_execute`
    recomputes the whole thing on every invocation. Built once here, read
    N times there.
    """
    return {u: unit_stems(files) for u, files in units.items()}


def readable_tests(unit_tests, files):
    """The `Tests:` inventory a cell may actually READ, given its own `files`.

    Fix round 2, N1. The inventory VERDICT belongs to the authored unit, so a
    chunk inherits its parent's -- but the read guard is still built from the
    chunk's own file list, and listing the parent's whole `tests:` axis handed
    a chunk four paths its own scope fence guarantees are denials (the prompt
    says "review ONLY the files listed above … a call outside it is denied
    with a reason, and recorded", so the entry contradicted itself).

    Two sources, both confined to `files` by construction: the unit's `tests:`
    entries this cell actually holds (literal paths; a glob is not a path and
    is left to the caller's unchunked branch), and the test files in its own
    list. `discovery.is_test_file` rather than `classify_files` deliberately --
    it is a regex over the name, so this stays off the N2 hot path.
    """
    in_scope = set(files or ())
    return sorted({t for t in (unit_tests or ()) if t in in_scope}
                  | {f for f in in_scope if discovery.is_test_file(f)})


def foreign_tests(unit, stems, units, stems_of):
    """{other unit: [test paths]} for tests NAMED after this unit's modules
    that some OTHER unit claims.

    Read off the run's own assignment (`groups.json`), which is the matrix's
    `tests:`/`match:` axes already resolved against the real tree by
    `discovery.assign_scoped` -- so this answers "who was actually handed
    this test file", not "whose glob might have matched it". That is the
    question the reviewer needs: a test in another unit's file list is a test
    THIS reviewer will never be shown.

    A UNIT, not a group: chunks of one authored leaf are folded together
    before this runs, because a sibling chunk is the same config entry
    and blaming it named a group the operator cannot find (fix round 1, F3).

    `stems_of` is `unit_stems_map(units)` -- built ONCE by the caller, because
    computing it here would re-classify every other unit's files for every
    unit (fix round 2, N2).

    Two filters keep basename matching usable. A module this unit already has
    a same-named test for is excluded by the caller (`unit_stems`' `tested`
    set): `phases/synthesize.py` with `tests/phases/test_synthesize.py` in
    the same unit is covered here, whatever `tests/test_synthesize.py`
    belongs to. And a test the other unit has its OWN same-named module for
    is not stolen: a tree with `dispatch.py` and `workflows/dispatch.js` in
    different units would otherwise have `tests/test_dispatch.py` flag both,
    and the unit that owns the module the test is named after is the likelier
    subject. What survives both is the run-13 shape -- a test named after a
    module NOBODY who holds it owns.

    Matching stays approximate: two same-named modules in units that BOTH
    lack a matching test still flag each other. That errs toward `split`,
    which costs a named module its no-coverage claim and nothing else -- the
    reviewer still grades every file the list does not name. The opposite
    error is the one this exists to stop.
    """
    if not stems:
        return {}
    out = {}
    for other, other_files in units.items():
        if other == unit:
            continue
        theirs = stems_of[other][0]
        hits = sorted(f for f in other_files or ()
                      for stem in [test_target_stem(f)]
                      if stem in stems and stem not in theirs)
        if hits:
            out[other] = hits
    return out


def note(review_root, unit, files, tests, units=None, stems_of=None):
    """`(state, prompt line)` for one review unit's test inventory (#1638 P13).

    `split` outranks `empty`: both mean the inventory is not to be trusted,
    but only `split` can say WHERE the tests went, which is the difference
    between a diagnostic an operator can act on and one they cannot. A unit
    that has its own tests AND is missing others named after its modules is
    also `split` -- the inventory is incomplete, which is the same defect at
    a smaller scale.

    `complete` requires only that the reviewer HAS tests: either the
    committed `tests:` axis lists some, or the cell's own files include test
    files (fix round 1, F2). A unit holding no CODE at all is `complete` for
    the same reason read the other way -- there is nothing here whose
    coverage could be claimed absent, so there is no untrustworthy inventory
    to warn about. Both of this repo's doc/plumbing groups (`Commons`,
    `Tests`) are that case, and flagging them would send an operator to fix a
    matrix that is not broken. `empty` is what is left: code, and no tests to
    judge it by.

    `units` defaults to reading `groups.json` and folding chunks onto their
    authored unit; `stems_of` to `unit_stems_map(units)`. `review_execute`
    passes both, so the whole batch reads `groups.json` once and classifies
    each unit's files once, however many units it dispatches.
    """
    if units is None:
        units, unit_of = coverage._discovered_units(review_root)
        unit = unit_of.get(unit, unit)
        files = units.get(unit, files)
    if stems_of is None:
        stems_of = unit_stems_map(units)
    stems, tested, own_tests = stems_of.get(unit) or unit_stems(files)
    foreign = foreign_tests(unit, stems - tested, units, stems_of)
    if foreign:
        # #1190 AGT-A1A, via fix round 3: these are TARGET-tree paths and
        # group names from the run's own `groups.json`, pasted into a single
        # prompt line. A filename carrying a newline would otherwise start
        # attacker-controlled lines in a reviewer's prompt -- the same defect
        # `_abs_file_list` was hardened against, through a channel P13 opened.
        # The SAME function, not a copy: one escaping rule for every path this
        # prompt shows.
        paths = sorted(runio._prompt_safe(p)
                       for hits in foreign.values() for p in hits)
        shown = paths[:PATHS_SHOWN]
        names = sorted(runio._prompt_safe(str(n)) for n in foreign)
        named = names[:PATHS_SHOWN]
        return "split", (
            "split — %d test file(s) matching this group's modules are "
            "claimed by group %s%s: %s%s. Tests for this code EXIST and are "
            "outside your scope."
            % (len(paths), ", ".join(named),
               " (and %d more group(s))" % (len(names) - len(named))
               if len(names) > len(named) else "",
               ", ".join(shown),
               " (and %d more)" % (len(paths) - len(shown))
               if len(paths) > len(shown) else ""))
    if stems and not (tests or own_tests):
        return "empty", (
            "empty — the review matrix assigns this group no test file at "
            "all. That is a gap in the matrix, not evidence about the "
            "target: tests for these files may exist outside your scope.")
    return "complete", (
        "complete — the tests this group was given are its own and no test "
        "named after its modules is claimed elsewhere.")


# #1638 P13 fix round 1 (F1): the inventory guidance is TST-shaped -- it
# governs coverage claims and it is the TST cell that makes them. Rendered
# into every cell it produced a `TST-X0X` finding from SEC/ARC/COD panels,
# which `synth.codes` rewrites to the CELL's domain, `synth.integrity` counts
# as a cross-domain finding (the shape that once sank a certification), and
# `x0x_report` clusters into target-specific OCRDb candidates under domains
# that never saw a test. And the groups most likely to flag have no TST cell
# at all -- `coverage_model` keeps TST in the floor only on a test-file
# signal -- so every one of those diagnostics was the mis-routed kind.
#
# It also asks for NO finding. The state is computed by the driver, stamped
# on the dispatch entry, persisted, and published in `meta.coverage
# .test_inventory` and the HTML: laundering a deterministic driver-side fact
# through an LLM adds no information and one failure mode. The findings
# envelope has no non-finding channel to put it in either
# (`findings-envelope-schema.json` is `additionalProperties: false` over
# `findings`/`_panopticon`/`schema_version`), and inventing one is not this
# change's business. What the reviewer owes is a WITHHELD claim, not a record.
TST_GUIDANCE = """
For the `TST` domain, review the group's tests (listed above) for quality and \
coverage against the code they cover.

Inventory: %s

**The inventory is not the repository.** `Tests:` above is this group's slice of the review matrix, not a listing of the target's test suite, and your reads are fenced to this cell — so you cannot see whether a test for these files exists somewhere else. The `Inventory:` line says which case you are in. The driver computed it and has ALREADY recorded it in this run's report (`meta.coverage.test_inventory`): **file no finding about it.** What it governs is what you may conclude.

- `complete` — the tests you were given are this group's own and nothing named after its modules is missing. A file here with no test covering it IS a `TST` coverage gap: report it against the menu code that fits.
- `split` — part of this group's coverage is claimed by another group, and the `Inventory:` line names those test files. Do NOT claim absent coverage for a module one of them is named after; grade every other file in your list normally.
- `empty` — the matrix assigned this cell no test at all and none is in your file list. Make no "no automated coverage" claim from here; review the code you were given for the `TST` defects you can actually see, and leave absence alone.

A claim that **no automated coverage exists** is a claim about the repository. Make it only on `complete`, from tests you have actually read. Deriving it from an empty inventory is how run-13 reported a module as untested in a session that had just run its 138 tests green — tests that existed, outside this review's scope.
"""


def render_tst_guidance(domain, inventory_line):
    """The `{tst_guidance}` block for a cell, or "" for every non-TST domain."""
    if domain != "TST":
        return ""
    return TST_GUIDANCE % inventory_line
