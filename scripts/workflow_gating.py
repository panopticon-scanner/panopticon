#!/usr/bin/env python3
"""Whether a `run:` step's failure is allowed to matter, with no rule on top.

Split out of `scripts/workflow_forms.py` (#2331's follow-ups, fix round one of
#2334) the way `scripts/workflow_operands.py` was: it had reached its size,
and this part is a layer of its own. `workflow_forms` re-exports it for the
guard.

A checksum is a gate only when its failure stops the step, and the shell
around it decides that, not the command:

    `swallowed`                the separator, the `!` and the `if`/`while`
                               around a check, and whether an `||` branch
                               after it fails the step (`_stops_the_job`)
    `_stops_step`              the imported function-call/status proof: how
                               far a failure reaches in the step's own shell
                               (`workflow_function_calls`)

The layers run one way: this module imports nothing from `workflow_forms`,
which sits above it and hosts `step_credit`, the step's own answer -- the one
gating question that needs that layer's readers, the branch bodies
(`regions`) and the `set`s (`_errexit_states`) -- and `workflow_guard` sits
on top of both. It reads `workflow_function_calls` BELOW it for the mutually
recursive function/status proof, then `workflow_posture` for `seed` and `_errexit`,
the option words `flattened` shares, split out there at this module's size
(#2620) and re-exported here so no caller moved -- which reads the option
tables in `workflow_programs` under it (#2443). `Inlined` -- a statement
of a script `workflow_forms.flattened` reads in place -- lives here because
both layers read it.

Stdlib only, like everything under it.
"""
import collections

import shell_reader
from shell_reader import command, conditional, negated
from workflow_function_calls import (FunctionGate, PipelineGate, Reach as Reach, _CLOSES,
                                     _DETACHED, _LOST as _LOST, _NO_E as _NO_E,
                                     _NO_PIPEFAIL as _NO_PIPEFAIL, _OPENS, _RESCUED,
                                     _SET_E as _SET_E, _control_depths, _function_scope,
                                     _function_syntax, _posture_barrier, _stops_the_job,
                                     _stops_step as _stops_step, clears as clears)
from workflow_posture import (_errexit as _errexit, _rejected as _rejected,
                              _takes_value as _takes_value, seed as seed)


# A statement of a script handed to a shell, as `flattened` inlines it, with
# its bodies below the command running it (`regions`), and why a checksum there
# clears nothing: as its pipeline's last command, and as an earlier one (None:
# it may clear).
Inlined = collections.namedtuple("Inlined", "stages separator region credit")


def _structural_groups(stage):
    """Leading brace and subshell opens/closes carried by this stage."""
    braces = []
    for token in stage.argv:
        if token not in shell_reader.KEYWORDS:
            break
        if token in ("{", "}"):
            braces.append(token)
    return stage.group_open + braces.count("{"), stage.group_close + braces.count("}")


def _pipeline_groups(stage):
    """Compound opens/closes that keep one pipeline stage alive."""
    opens, closes = _structural_groups(stage)
    for token in stage.argv:
        if token not in shell_reader.KEYWORDS:
            break
        opens += token in _OPENS and token != "{"
        closes += token in _CLOSES and token != "}"
    return opens, closes


def _pipeline_end(stmts, index, position):
    """The last readable statement of a pipeline stage starting here."""
    depth, started = 0, False
    for following in range(index, len(stmts)):
        first = position if following == index else 0
        for stage in stmts[following].stages[first:]:
            opens, closes = _pipeline_groups(stage)
            if not started and not stage.argv and not opens:
                continue
            started = True
            depth += opens - closes
        if started and depth <= 0:
            return following
    # A closer the reader dropped leaves the boundary unknown. Refuse the
    # remainder of the step rather than crediting a potentially concurrent use.
    return len(stmts) - 1


def _piped_group_end(stmts, index):
    """The piped close of a structural group open at `index`, or None.

    A group opened later is a sequential sibling or child, so its pipeline
    is not concurrent with the check.
    """
    depth = 0
    for statement in stmts[:index + 1]:
        for stage in statement.stages:
            opens, closes = _structural_groups(stage)
            depth += opens - closes
    remaining, opened_after = depth, 0
    if remaining <= 0:
        return None
    for following, statement in enumerate(stmts[index + 1:], index + 1):
        for position, stage in enumerate(statement.stages):
            opens, closes = _structural_groups(stage)
            opened_after += opens
            for _close in range(closes):
                if opened_after:
                    opened_after -= 1
                    continue
                remaining -= 1
                if position + 1 < len(statement.stages):
                    return _pipeline_end(stmts, following, position + 1)
                if remaining <= 0:
                    return None
    return None


def _piped_function_end(stmts, index):
    """The first pipeline entered by a call of this function.

    A top-level call has the pipeline's readable end. Where a prior statement
    makes posture uncertain, or the call is conditional, nested, or in a list,
    use the step's end: no later use is cleared by an unproved boundary.
    """
    function = _function_scope(stmts, index)
    if function is None:
        return None
    name, close = function
    controls = _control_depths(stmts)
    functions = {function for statement in stmts for stage in statement.stages
                 if (function := _function_syntax(stage.argv)[0]) is not None}
    uncertain = False
    for call in range(close + 1, len(stmts)):
        statement = stmts[call]
        if any(_function_syntax(stage.argv)[0] == name for stage in statement.stages):
            uncertain = True
            continue
        for position, stage in enumerate(statement.stages[:-1]):
            if command(stage.argv)[:1] == [name]:
                if (uncertain or controls[call] or negated(stage.argv)
                        or conditional(stage.argv)):
                    return len(stmts) - 1
                scope = _function_scope(stmts, call)
                if scope is not None or statement.separator in ("&", "&&", "||"):
                    return len(stmts) - 1
                return _pipeline_end(stmts, call, position + 1)
        if _posture_barrier(statement, functions):
            uncertain = True
    return None


def swallowed(stmts, index, statement, stage, credit=None):
    """Why this check's failure would go nowhere, or None.

    Phrased to follow "the checksum that names <file>", because that is the
    sentence a reader gets when the check they wrote did not clear the fetch
    they wrote it for. What is read here is the shell right around the check
    -- an `Inlined` statement's `credit` first, then its separator, `!` and
    `if` -- and `credit` is the step's own answer for the statement, read
    last: `step_credit`'s, the guard's `_SOFT_STEP` pair where the step
    carries `continue-on-error: true` (`job_defects`), or None where it has
    none. A `Reach` answer is a check ahead of `&&`, which still stops what
    its list runs, its own command where the list's end is lost, or a group
    gate that takes effect only after its concurrent pipeline (`clears`).
    """
    if isinstance(statement, Inlined) and statement.credit[stage is not statement.stages[-1]]:
        return statement.credit[stage is not statement.stages[-1]]
    if statement.separator == "&":
        return _DETACHED
    if statement.separator == "||":
        # Only the two posture answers in a credit pair mean `-e` is off;
        # job-level policy such as `continue-on-error` does not alter the shell.
        why = credit[0] if isinstance(credit, tuple) else None
        errexit = not (why == _SET_E or
                       isinstance(why, str) and why.startswith("runs under `shell:"))
        stops = _stops_the_job(
            stmts, index, errexit, isinstance(credit, tuple) and credit[1] is None
        )
        if isinstance(stops, FunctionGate) and why and errexit:
            # Keep the proved call as a lower bound and a Reach as its upper
            # bound; an ordinary refusal still applies to the whole check.
            return FunctionGate(stops.through, why) if isinstance(why, Reach) else why
        if isinstance(stops, Reach):
            return stops
        if not stops:
            return why if not errexit and why else _RESCUED
    # `if`, `while` and `!` govern the PIPELINE, and they sit on its head:
    # in `if echo "<sha>  x" | sha256sum -c -; then` -- the spelling this
    # module's own remedy text recommends -- the checksum is the second stage
    # and its own argv says nothing about the test wrapped around it. Ask the
    # head as well as the stage, because a one-stage statement is both.
    head = statement.stages[0].argv if statement.stages else stage.argv
    if negated(head) or negated(stage.argv):
        return "is negated, so the failing path is the THEN branch"
    if conditional(head) or conditional(stage.argv):
        return "is an `if`/`while` test, which errexit does not apply to"
    why = credit[stage is not statement.stages[-1]] if credit else None
    piped_end = _piped_group_end(stmts, index) if why is None or isinstance(why, Reach) else None
    function_end = _piped_function_end(stmts, index) if piped_end is None else None
    if function_end is not None:
        # The definition is not itself piped. `step_credit`'s pipeline slot
        # nevertheless carries the call site's pipefail posture across these
        # reader statements, so use it before applying the function's bound.
        why = credit[1] if credit else None
        piped_end = function_end
    return (PipelineGate(piped_end, why)
            if piped_end is not None and (why is None or isinstance(why, Reach)) else why)
