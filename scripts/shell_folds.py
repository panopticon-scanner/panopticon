#!/usr/bin/env python3
"""The folds a job is read in, and the body a descriptor reads in each of them.

Split out of `scripts/shell_command.py` at that module's size (699 of its 700 lines), byte for byte (#3112): the
state each fold sets (`_NO_FOLD`, `_ACTIONS`), the places a step may stand in and the other bodies a link or a `cd`
may put on a descriptor (`_PLACES`, `_BODIES`, `_BODY_FOLDS`, `_reached`, `sources`, `carrier`, `body_read`), and
`folds`/`_folds`, the readings `workflow_guard.job_defects` reads a job in. `shell_command` imports every name back
under its own, so nothing that read `shell_command.folds` or `shell_reader.folds` moved; this module imports nothing
from `shell_command`, so the layers still run one way.

Stdlib only, like everything under it.
"""
import itertools
import os
from typing import Callable

from shell_defaults import _HALVES, _THROUGH, _masks
from shell_quote import Unreadable
from shell_wrappers import _SHADOWED

# A locale string `$"…"`: bash reads the double-quoted string, dash keeps the `$`. `main`'s reading is dash's;
# where a job met one, `folds` reads it once more bash's way (#3048): the union, `main`'s reading never lost.
_LOCALE = {"on": False, "met": False}
# The caches a flip of `_LOCALE["on"]` leaves stale, each a `cache_clear` (#3048 review round 2): one keyed on the
# text alone, `workflow_programs._parsed`, held bash's reading of a `$"…"` past the fold, for the jobs after it.
_STALE: list[Callable[[], None]] = []
# A call of a function the step defines (#3047, #3091): `main` reads it as it did; where a job holds one, `folds`
# reads the job once more with each such call standing for its body as the call makes it, the call's words in
# the body's positionals, and the body read nowhere else there (`workflow_called_fetches.called`) -- the union,
# `main`'s reading never lost.
_CALLED = {"on": False, "met": False}


# The action of each `find` a fold reads where the guard asks how a stage uses a file
# (`find_action`), and whether one held another: `folds` reads each of them (#2918). And whether the
# fold reads that action in its `find`'s place (`act`, for `acted`), and whether a fold of `main`'s
# met a `find` with one (`acts`; #2935 round 3). `_NO_FOLD` is the state outside `folds`: `main`'s.
_NO_FOLD = {"at": 0, "more": False, "act": False, "acts": False}
_ACTIONS = dict(_NO_FOLD)


# The places a step may stand in, and the paths a word may reach, that the reader keeps: past them
# the oldest places read as one a value decides, and a word reaches every file held (`sources`).
_PLACES = 16
# The body a fold reads on a descriptor a link or a `cd` may give another (`body_read`): 0 `main`'s,
# then each other in turn; and whether a stage held one more, which `folds` then reads (round 3).
_BODIES = {"at": 0, "more": False}
# The other bodies one stage may be given that the folds read. Each is one more reading of the whole
# job, on top of every fold `main` reads, so the count is kept small: the steps that hold any hold one
# or two, 4 is twice that, and one more is a step the reader refuses, reported whole (`body_read`).
_BODY_FOLDS = 4


def _reached(word, context):
    """The other paths `word` may name where the step's links and `cd`s took effect (`track`): a name it
    linked, or a path below one, as each target the link was given; then each relative one in each
    directory a `cd` may have moved the step to -- a `$` word where a value decides a link's name, as
    `shell_reader.input_alias_fd` reads a word a value decides. A word bash expands is read as any other (round 3)."""
    if not context or not (context.links or context.cwds):
        return []
    path = os.path.normpath(word)
    paths = [target + path[len(link):] for link, targets in context.links.items() for target in targets
             if link and (path == link or path.startswith(link + "/"))]
    if "" in context.links and not path.startswith("/"):
        paths.append("$" + path)
    paths += [cwd.rstrip("/") + "/" + relative for relative in (path, *paths) for cwd in context.cwds
              if not relative.startswith(("/", "$"))]
    return paths


def sources(word, context, read):
    """What `word`, the operand of an input redirection, may reach (#2919): `read` of it as written,
    first -- `shell_reader.input_alias_fd`'s answer, `main`'s reading -- then the answers that differ
    from it among the other paths the step's links and `cd`s may give it (`_reached`), `?` where
    they are more than the reader keeps; with no `context`, a here-string's text, as written alone.
    A record adds a reading and takes none away, the reader knowing no `ln` or `cd` to have run:
    the pipe and the files held are read off every answer (`carrier`), and a body off the first in
    every fold `main` reads, off each other in a fold of its own (`body_read`, round 3 -- round 2
    read the first body any answer held, in place of `main`'s)."""
    first = read(word)
    more: list[str] = []
    reached = _reached(word, context)
    for path in reached[:_PLACES]:
        answer = read(path)
        if answer not in (None, first, *more):
            more.append(answer)
    if len(reached) > _PLACES and "?" not in (first, *more):
        more.append("?")
    return (first, *more)


def carrier(word, context, read):
    """`sources` as the one descriptor whose holdings a redirection carries: the one `word` reaches
    as written, another a link or a `cd` may give it, or `?` -- every file held -- where they are
    two."""
    first, *more = sources(word, context, read)
    reached = [answer for answer in (first, *more) if answer]
    return "?" if len(reached) > 1 else reached[0] if reached else first


def body_read(bodies, reached):
    """The heredoc or here-string body a descriptor reads, its operand reaching `reached` (`sources`),
    of the `bodies` each descriptor holds (#2919 round 3): the one its operand names as written, or
    none -- `main`'s reading, and the one every fold `main` reads takes, so a link or a `cd` the
    shell never makes takes no reading away. Each OTHER body a record may put there -- on a
    descriptor it reaches, or on any one where it reaches more than the reader keeps (`?`) -- is one
    more reading beside it, read in a fold of its own (`folds`); more of them than `_BODY_FOLDS` are a
    step the reader refuses there (`Unreadable`), reported whole."""
    first, *more = reached
    main = bodies.get(first) if first and first != "?" else None
    others = list(dict.fromkeys(body for fd, body in bodies.items() if ("?" in more or fd in more) and body != main))
    at = _BODIES["at"]
    if not others or not at:
        _BODIES["more"] = _BODIES["more"] or bool(others)
        return main
    if len(others) > _BODY_FOLDS:
        raise Unreadable("a link or a `cd` may put more than %d bodies on one descriptor" % _BODY_FOLDS)
    _BODIES["more"] = _BODIES["more"] or len(others) > at
    return others[min(at, len(others)) - 1]


def _flip(state, on):
    """`state["on"] = on` -- `_LOCALE`'s or `_CALLED`'s; where that flips, every `_STALE` cache is cleared: keyed on a
    text alone, it holds the other fold's reading of a `$"…"` or of a call (#3048 review round 2, #3047)."""
    if state["on"] != on:
        state["on"] = on
        for clear in _STALE:
            clear()


def folds(unsure):
    """`_folds`, the folds a job is read in -- and where one of them met a `builtin` it may read through
    (`_through`), each of them once more with every such word read through to the builtin it names, as bash runs
    it (#2665). So the reading that leaves the word alone, `main`'s and what dash does with it, is never lost,
    and the guard REPORTs where either reads a defect."""
    _THROUGH.update(on=False, met=False)
    _flip(_LOCALE, False)
    _LOCALE["met"] = False
    _flip(_CALLED, False)
    _CALLED["met"] = False
    _SHADOWED["names"] = set()                  # (#2670) the wrappers' names this job's steps define
    try:
        yield from _folds(unsure)
        if _THROUGH["met"]:
            _THROUGH["on"] = True
            yield from _folds(unsure)
        if _LOCALE["met"]:                      # `$"…"` bash's way (#3048)
            _THROUGH["on"] = False
            _flip(_LOCALE, True)
            yield from _folds(unsure)
        if _CALLED["met"]:                      # each call of a function the step defines, as its body (#3047)
            _THROUGH["on"] = False
            _flip(_LOCALE, False)
            _flip(_CALLED, True)
            yield from _folds(unsure)
    finally:
        _THROUGH.update(on=False, met=False)
        _flip(_LOCALE, False)
        _LOCALE["met"] = False
        _flip(_CALLED, False)
        _CALLED["met"] = False
        _SHADOWED["names"] = None


def _folds(unsure):
    """The folds `workflow_guard.job_defects` reads a job in, each its `sure`: one, and a second that
    leaves every `Unsure` statement out where `unsure()` then finds one -- every command word bash
    may expand to nothing read as its W, as `main` reads it; then, for each set of those whose halves
    read apart, the first `_HALF_CAP` a job holds, those folds again with that set read empty, so the
    guard REPORTs where any reading of them runs (#2856 round 13, the round-13 ruling: the union, no
    half ranked; every reading, #2929). Each reads every `find`'s first action where the guard asks
    how a stage uses a file, then, while one held another, its next (`find_action`), so the guard
    REPORTs where any action uses it (#2918). Those are `main`'s folds, each descriptor reading the
    body `main` reads there; where a link or a `cd` may put another on one (`body_read`), all of them
    follow again once for each such body, so the guard REPORTs where either is the one read and no
    reading of `main`'s is lost (#2919 round 3). And where `acted`
    met a `find` with an action in them, each of those follows again with each action in its `find`'s
    place (#2935 round 3: `main`'s reading is never lost, and the guard REPORTs where either reads a
    defect)."""
    _HALVES.update(empty=frozenset(), words={}, both=False, on=True, drops=False, both_dropped=False)
    _ACTIONS["acts"] = False
    try:
        for body in range(1 + _BODY_FOLDS):     # `main`'s, then at most `_BODY_FOLDS` others (`body_read`)
            _BODIES.update(at=body, more=False)
            for act in (False, True):
                read: set = set()
                while masks := [mask for mask in _masks() if mask not in read]:
                    _HALVES["empty"] = masks[0]
                    read.add(masks[0])
                    for at in itertools.count():
                        _ACTIONS.update(at=at, more=False, act=act)
                        yield False
                        if unsure():
                            yield True
                        if not _ACTIONS["more"]:
                            break
                if not _ACTIONS["acts"]:
                    break
            if not _BODIES["more"]:
                return
    finally:
        _HALVES.update(empty=frozenset(), words={}, both=False, on=False, drops=False, both_dropped=False)
        _ACTIONS.update(_NO_FOLD)
        _BODIES.update(at=0, more=False)
