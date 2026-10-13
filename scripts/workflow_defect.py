#!/usr/bin/env python3
"""Why one fetch is a defect: the judgment of a single download against the checks around it.

Split out of `scripts/workflow_guard.py` at that module's size (700 of its 700 lines, with #3050, #3051
and #2433 to build on it), byte for byte: `_defect`, which says why one fetch is unverified, and what it
asks -- whether a check may clear a use (`_binds`), whether a use's `if:` runs after a failed step
(`_runs_after_failure`), which half of a check's condition the use does not share (`_unshared`) -- with
the three reasons a checksum the job ran clears nothing (`_SOFT_STEP`, `_UNSHARED_IF`,
`_UNSHARED_BRANCH`). `workflow_guard` imports every name back under its own, so nothing that read
`workflow_guard._binds` or `workflow_guard._UNSHARED_BRANCH` moved; this module imports nothing from it,
so the layers still run one way.
"""
import os
import re

import shell_reader
from workflow_checks import clears_nested as _clears_nested, contextual as _check_at_use
from workflow_fetch import _describe, _remedy, streams_to_executor
from workflow_forms import at_directory, names_file, stdin_program
from workflow_programs import VALUE_PROGRAM
from workflow_uses import EXECUTORS, uses as _uses


# Why a checksum this job ran clears nothing. A refused check is KEPT with its reason rather than
# dropped, because "no checksum in the job names this file" and "the checksum that names it was
# handed to a `|| true`" are different sentences, and only one of them is true of any given step.
_SOFT_STEP = ("is in a step carrying `continue-on-error: true`, so the job "
              "carries on past its failure")
_UNSHARED_IF = ("runs under an `if:` the use does not share, so it may be "
                "skipped while the use is not")
_UNSHARED_BRANCH = ("is written inside an `if`/`while` branch the use is not "
                    "in, so it may be skipped while the use runs")


def _unshared(conditions, check, use):
    """Which half of the check's condition the use does not share."""
    when = conditions.get(check) or (None, None)
    theirs = conditions.get(use) or (None, None)
    if when[1] and when[1] != theirs[1]:
        return _UNSHARED_BRANCH
    return _UNSHARED_IF


def _runs_after_failure(when):
    """True when a step `if:` runs even after an earlier step failed -- `always()`,
    `failure()` or `!cancelled()` (any expression holding one, whitespace and case
    aside). `success()`, a plain expression and no `if:` are skipped then, so stay gated."""
    cond = re.sub(r"\s+", "", when[0] or "").lower() if when else ""
    return any(call in cond for call in ("always()", "failure()", "!cancelled()"))


def _binds(conditions, check, use):
    """May a check at statement `check` clear a use at statement `use`?

    Only if the check runs whenever the use does. Its condition is two halves -- the step's `if:`
    and the `if`/`while` branch it sits in (`workflow_forms.regions`); a check binds where both
    match, as written (no evaluation): a check and use sharing one `if:` (fleet's shape -- fetch,
    checksum and `unzip`) bind; a different condition, or one the use lacks, does not. A use
    whose `if:` RUNS AFTER A FAILED step (`_runs_after_failure` -- `always()`, `failure()` or
    `!cancelled()`) is refused unless the check shares it, since it runs on even when an earlier
    step's checksum stopped. Residual (#2608): a same-`if:` match in another step still binds --
    conditions cannot tell it from a true same-step one; stability of the `if:` is assumed."""
    when = conditions.get(check)
    theirs = conditions.get(use)
    if _runs_after_failure(theirs) and when != theirs:
        return False
    return when is None or when == theirs


def _defect(fetch, index, stmts, checks, conditions=None, unread=(), working=None, scopes=None):
    """Why this fetch is unverified; unread forms add uses, never replace parsed uses."""
    if fetch.url is None and fetch.dest is None:
        # `wget -i list.txt`, an argv assembled in a variable, `xargs curl -O`: a download whose
        # target this guard cannot name is not a clean step, it is an unread one.
        return ("runs `%s` with unresolved transfers: no URL and no destination "
                "this guard could parse, so it cannot say what arrived or whether "
                "anything checked it -- use explicit single-download commands "
                "with named files (`-o <path>`) and `sha256sum -c` checks" % fetch.tool)
    if fetch.dest is None or streams_to_executor(fetch, EXECUTORS):
        if not fetch.piped_to:
            return None
        if stdin_program(fetch.piped_to[:1]) == VALUE_PROGRAM:
            return ("pipes a download into `%s`, a command word this guard does not follow -- "
                    "download it to a file, `sha256sum -c` that file, then run it"
                    % shell_reader.readable(fetch.piped_to[0]))
        if os.path.basename(fetch.piped_to[0]) not in EXECUTORS:
            return None
        # Nothing landed on disk, so no checksum anywhere in the step can be
        # about these bytes: the only fix is to stop streaming them into a
        # shell (`curl ... | sh`, `eval "$(curl ...)"`, `bash <(curl ...)`).
        return ("hands %s straight to `%s`, so there is no file to check -- "
                "download it to a file, `sha256sum -c` that file, then run it"
                % (shell_reader.readable(fetch.url) or "a download",
                   " ".join(shell_reader.readable(t) for t in fetch.piped_to)))
    if shell_reader.has_substitution(fetch.dest):
        return ("fetches %s to an unknown destination (%s) containing a shell "
                "substitution, so this guard cannot bind the downloaded file "
                "to a checksum or later use -- name a stable file and verify it"
                % (shell_reader.readable(fetch.url) or "a download",
                   shell_reader.readable(fetch.dest)))
    working = working or {}
    dest = at_directory(fetch.dest, getattr(fetch.dest, "directory", working.get(index, ".")))
    names, uses = _uses(stmts, dest, after=index, working=working, scopes=scopes)
    uses += [(i, "may be run by a form the guard cannot read") for i in unread if i >= index]
    if not uses:
        return None                             # fetched and only read: not this rule
    conditions = conditions or {}
    naming = [(i, why) for i, text, why in checks if i > index
              and any(names_file(text, name, getattr(i, "directory", working.get(i, ".")))
                      for name in sorted(names))]
    first_use, how = next(((u, h) for u, h in uses if not any(  # the first use no check clears
        _clears_nested(why, i, u) and _binds(conditions, i, u)
        for i, why in naming)), (None, None))
    if first_use is None:
        return None
    naming = [(i, _check_at_use(why, i, first_use)) for i, why in naming]
    cleared = [i for i, why in naming if why is None and _binds(conditions, i, first_use)]
    if cleared:
        # Ordering is the substance: a checksum that runs after the bytes are made runnable is theatre.
        return ("verifies %s only AFTER %s -- fetches %s, so %s"
                % (shell_reader.readable(fetch.dest), how, _describe(fetch),
                   _remedy(fetch.dest)))
    if naming:
        # It NAMED the file. Saying "does not name" here sends the author
        # hunting a spelling bug in a line that is spelled right.
        why = (next((w for _i, w in naming if w), None)
               or _unshared(conditions, naming[0][0], first_use))
        return ("fetches %s and %s; the checksum that names %s %s -- %s"
                % (_describe(fetch), how, shell_reader.readable(fetch.dest),
                   why, _remedy(fetch.dest)))
    if [i for i, _text, why in checks if i > index
            and _check_at_use(why, i, first_use) is None]:
        return ("fetches %s and %s; no checksum in the job names %s, and a "
                "checksum of a different file verifies nothing -- %s"
                % (_describe(fetch), how, shell_reader.readable(fetch.dest),
                   _remedy(fetch.dest)))
    return ("fetches %s and %s with nothing verifying what arrived -- %s"
            % (_describe(fetch), how, _remedy(fetch.dest)))
