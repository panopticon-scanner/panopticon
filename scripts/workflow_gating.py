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
    `_stops_step`              how far a check's failure reaches in the step's
                               own shell, whose `-e` and `pipefail` its
                               `shell:` starts (`seed`): the rest of an `&&`
                               list, or what follows a group the check ends
                               (`Reach`, `clears`), in the sentences below

The layers run one way: this module imports nothing from `workflow_forms`,
which sits above it and hosts `step_credit`, the step's own answer -- the one
gating question that needs that layer's readers, the branch bodies
(`regions`) and the `set`s (`_errexit_states`) -- and `workflow_guard` sits
on top of both. It reads `workflow_posture` BELOW it -- `seed` and `_errexit`,
the option words `flattened` shares, split out there at this module's size
(#2620) and re-exported here so no caller moved -- which reads the option
tables in `workflow_programs` under it (#2443). `Inlined` -- a statement
of a script `workflow_forms.flattened` reads in place -- lives here because
both layers read it.

Stdlib only, like everything under it.
"""
import collections
import os
import re

import shell_reader
from shell_reader import command, conditional, negated
from workflow_posture import (_errexit as _errexit, _rejected as _rejected,
                              _takes_value as _takes_value, seed as seed)


# A statement of a script handed to a shell, as `flattened` inlines it, with
# its bodies below the command running it (`regions`), and why a checksum there
# clears nothing: as its pipeline's last command, and as an earlier one (None:
# it may clear).
Inlined = collections.namedtuple("Inlined", "stages separator region credit")


# --- whether a command's failure is allowed to matter -------------------------

# A check whose non-zero exit nobody sees is not a check. A step with no
# `shell:` runs `bash -e {0}`, and that `-e` is what makes `sha256sum -c` a
# GATE -- and the shell around the command decides whether that survives. `&`
# detaches it; `||` hands the failure to a branch, which rescues it ONLY if
# that branch ends the job; `if`/`while`/`!` make it a test, and errexit never
# applies to a test; a `set +e` ahead of it turns errexit off; and a command
# piped after it takes the pipeline's status unless `pipefail` holds, which a
# step has from `shell: bash`, from a `shell:` template that writes it (`bash
# -euxo pipefail {0}`, `seed`), or from a `set -o pipefail` or `shopt -so
# pipefail` before it (`step_credit`).
# The `|| ...` branches that keep a check a check: they fail the step, which
# is exactly what errexit would have done.
_GROUP_OPEN = ("{", "(")
_FUNCTION_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_FUNCTION_TOKEN = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)\(\)$")
_CONTROL_OPEN = ("if", "while", "until", "for", "case")
_CONTROL_CLOSE = ("fi", "done", "esac")


def _known_status(argv, inherited):
    """Known exit status, or None when this command's result is not proved."""
    if not argv:
        return inherited
    name = os.path.basename(argv[0])
    if name in ("exit", "return"):
        if len(argv) == 1 or argv[1] == "$?":
            return inherited
        if len(argv) != 2 or not re.fullmatch(r"[+-]?[0-9]+", argv[1]):
            return None
        return int(argv[1]) % 256
    if name == "false" and len(argv) == 1:
        return 1
    if name == "true" and len(argv) == 1:
        return 0
    return None


def _function_syntax(argv):
    """A function header's name and the structural braces in this argv."""
    leading, start = [], 0
    while start < len(argv) and argv[start] in shell_reader.KEYWORDS and argv[start] != "function":
        if argv[start] in ("{", "}"):
            leading.append(argv[start])
        start += 1
    name, end = None, start
    if start < len(argv) and argv[start] == "function":
        if start + 1 < len(argv) and _FUNCTION_NAME.fullmatch(argv[start + 1]):
            name, end = argv[start + 1], start + 2
    elif start < len(argv) and (match := _FUNCTION_TOKEN.fullmatch(argv[start])):
        name, end = match[1], start + 1
    elif (start + 1 < len(argv) and _FUNCTION_NAME.fullmatch(argv[start])
          and argv[start + 1] == "()"):
        name, end = argv[start], start + 2
    if name is None:
        return None, leading
    for token in argv[end:]:
        if token not in shell_reader.KEYWORDS:
            break
        if token in ("{", "}"):
            leading.append(token)
    return name, leading


def _function_scope(stmts, index):
    """The brace-function containing `index`, as (name, closing index)."""
    depth, active, pending, candidate = 0, [], [], None
    for position, statement in enumerate(stmts):
        for stage in statement.stages:
            name, braces = _function_syntax(stage.argv)
            if name is not None:
                pending.append([name, position, None])
            for token in braces:
                if token == "{":
                    depth += 1
                    if pending:
                        scope = pending.pop()
                        scope[2] = depth
                        active.append(scope)
                else:
                    if active and active[-1][2] == depth:
                        scope = active.pop()
                        if scope is candidate:
                            return scope[0], position
                    depth = max(0, depth - 1)
        if position == index:
            candidate = active[-1] if active else (pending[-1] if pending else None)
            if candidate is None:
                return None
    return (candidate[0], len(stmts) - 1) if candidate is not None else None


def _control_depths(stmts):
    """Conditional or loop depth as each statement runs.

    A call in a body may never run, so it cannot prove a gate for a later use.
    Braces and subshells are deliberately absent: their calls do run when the
    enclosing top-level statement runs, and `_stops_step` judges their status.
    """
    depth, states = 0, []
    for statement in stmts:
        for stage in statement.stages:
            for token in stage.argv:
                if token not in shell_reader.KEYWORDS:
                    break
                if token in _CONTROL_CLOSE:
                    depth = max(0, depth - 1)
                elif token in _CONTROL_OPEN:
                    depth += 1
        states.append(depth)
    return states


def _posture_barrier(statement, functions):
    """Whether this statement may change shell posture before a later call.

    Exact `set` states live in `workflow_forms`, above this module. Stop this
    lower-layer proof at a mutator, sourced/evaluated text, or a known function
    call rather than carrying the definition-time `-e` state past it.
    """
    for stage in statement.stages:
        argv = command(stage.argv)
        while len(argv) > 1 and argv[0] in ("builtin", "command"):
            argv = command(argv[1:])
        if argv[:1] and argv[0] in ("set", "shopt", "unset", "eval", ".", "source"):
            return True
        if argv[:1] and argv[0] in functions:
            return True
    return False


def _gating_function_call(stmts, name, after, errexit, seen=()):
    """The first proved call whose failure stops the step, or None.

    A call in a group is proved by that group's status. A call in another
    function is proved only when that containing function has its own proved
    call; `seen` makes malformed or recursive definitions fail closed. With
    errexit off, only a call whose explicit rescue exits can prove the gate.
    """
    if name in seen:
        return None
    on, fails = [errexit] * len(stmts), [False] * len(stmts)
    controls = _control_depths(stmts)
    functions = {function for statement in stmts for stage in statement.stages
                 if (function := _function_syntax(stage.argv)[0]) is not None}
    for position in range(after + 1, len(stmts)):
        statement = stmts[position]
        if any(_function_syntax(stage.argv)[0] == name for stage in statement.stages):
            return None                         # a later definition overwrites this body
        if len(statement.stages) != 1:
            continue
        stage = statement.stages[0]
        argv = command(stage.argv)
        scope = _function_scope(stmts, position)
        direct = (stage.argv[:1] == [name] or
                  stage.argv[:1] == ["{"] and argv[:1] == [name] or
                  scope is not None and argv[:1] == [name])
        if (not direct or controls[position] or negated(stage.argv) or conditional(stage.argv)
                or statement.separator in ("&", "&&")):
            if _posture_barrier(statement, functions):
                return None
            continue
        if statement.separator == "||":
            stops = _stops_the_job(stmts, position, errexit)
        else:
            stops = _stops_step(stmts, position, on, fails) is None
        if not stops:
            continue
        if scope is None:
            return position
        outer, close = scope
        outer_call = _gating_function_call(stmts, outer, close, errexit, seen + (name,))
        if outer_call is not None:
            return outer_call
        return None
    return None


def _stops_the_job(stmts, index, errexit=True, pipefail=False):
    """True if the `||` branch after `stmts[index]` fails the step.

    `sha256sum -c - || exit 1` and `... || { echo "::error::"; exit 1; }` are
    gates, not swallows -- and they are the cheap hardened spellings, so
    refusing them would push authors toward the exemption list instead.
    Where `errexit` is off a branch that only FAILS stops nothing (`|| false`
    sets a status the step carries on past), so there it has to `exit`.
    """
    following = stmts[index + 1:index + 11]
    if not following:
        return False
    first_stage = following[0].stages[0] if following[0].stages else None
    first = first_stage.argv if first_stage else []
    grouped = bool(first_stage and (first_stage.group_open or
                                    (first and first[0] in _GROUP_OPEN)))
    status = 1  # The rescue is entered only after the checksum fails.
    # A rescue can close a subshell the check opened on the same statement:
    # `( CHECK || exit 1 )`. Start inside that shell so its `)` is not read as
    # an unmatched closer; the non-zero exit becomes the subshell's status.
    inherited_subshells = max(0, sum(
        stage.group_open - stage.group_close for stage in stmts[index].stages
    ))
    inherited_depth = (max(inherited_subshells, _nesting(stmts[index]))
                       if inherited_subshells else 0)
    depth, subshell_depth = inherited_depth, inherited_subshells
    exited_subshell = None
    stopped_job = exited = False
    end = index
    for end, statement in enumerate(following, index + 1):
        if (exited_subshell is None and (statement.separator == "&" or
                len(statement.stages) != 1 and not (depth and _closes(statement)) or
                any(negated(stage.argv) for stage in statement.stages))):
            return False
        for stage in statement.stages:
            depth += stage.group_open + stage.argv.count("{")
            subshell_depth += stage.group_open
            if exited_subshell is None and not stopped_job:
                # The bounded status walk does not evaluate conditional arms.
                if any(t in ("if", "then", "elif", "else", "fi", "while",
                             "until", "do", "done", "case", "esac", "for")
                       for t in stage.argv):
                    return False
                argv = command(stage.argv)
                if argv:
                    name = os.path.basename(argv[0])
                    status = _known_status(argv, status)
                    if name in ("exit", "return"):
                        if subshell_depth:
                            if name == "return":
                                return False
                            exited_subshell = subshell_depth
                        else:
                            stopped_job, exited = True, name == "exit"
            depth -= stage.group_close + stage.argv.count("}")
            subshell_depth -= stage.group_close
            if depth < 0 or subshell_depth < 0:
                return False
            if not depth and len(statement.stages) > 1:
                break                           # the other pipeline stages run concurrently
            if exited_subshell is not None and subshell_depth < exited_subshell:
                exited_subshell = None
        if depth == 0 or not grouped and not inherited_depth:
            if (statement.separator in ("&&", "||") and not stopped_job
                    and not inherited_depth):
                return False
            break
        if statement.separator in ("&&", "||") and exited_subshell is None:
            return False
    finished = depth == 0 if grouped or inherited_depth else True
    function = _function_scope(stmts, index)
    # An inherited subshell's non-zero status is also the function's status;
    # the call-site proof below still decides whether that status stops use.
    returns_failure = function is not None and inherited_subshells > 0
    stops = (finished and status is not None and status != 0
             and (errexit or exited or returns_failure)
             and (len(stmts[end].stages) == 1 or pipefail))
    if not stops or not inherited_subshells:
        return stops
    # An exit inside `( )` sets that subshell's status, then follows its closer,
    # skipping unreachable commands; it does not decide what encloses the shell.
    # Decline a function body at its proven call. For ordinary groups, reuse the
    # group-status walk from the closer with the step's recorded pipefail state.
    if function is not None:
        name, close = function
        call = _gating_function_call(stmts, name, close, errexit)
        return FunctionGate(call) if call is not None else False
    separator = stmts[end].separator
    if separator == "||":
        return _stops_the_job(stmts, end, errexit, pipefail)
    if separator in ("&", "&&"):
        return False
    on = [errexit] * len(stmts)
    fails = [pipefail] * len(stmts)
    return _stops_step(stmts, end, on, fails) is None


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


# Why a check the step's own shell runs does not stop the step, as
# `step_credit` finds it -- the first two as `swallowed` does too, and those
# and `_NO_PIPEFAIL` again for the group a check ends, whose status is the
# check's (`_ENDS`). Where a sentence gives this guard's reading rather than
# what bash does, it says so: `_SET_E`, `_NO_E` and `_NO_PIPEFAIL` are also
# the fail-closed answers for a `set` or template it does not read (review
# N-3, N-7), and `_LOST` is the one for a list whose end the reader lost.
_DETACHED = "is detached with `&`"
_RESCUED = "hands its failure to a `||` branch that does not fail the step"
_ENDS = "ends a group that %s"
_SET_E = ("runs after a `set +e` or a spelling of it (`set +o errexit`, `shopt -uo errexit`, "
          "`builtin set +e`), which this guard reads as turning errexit off from where it is "
          "written, and is not in the step's last command, so the step carries on past its "
          "failure")
_NO_E = ("runs under `shell: %s`, which this guard reads as starting without errexit, and is "
         "not in the step's last command, so the step carries on past its failure")
_NO_PIPEFAIL = ("is piped into another command where this guard reads `pipefail` as off, so "
                "the pipeline takes that command's status and the step carries on past its "
                "failure (`shell: bash` turns pipefail on, and so does a `set -o pipefail` "
                "before it where the shell is bash)")
_AHEAD = ("runs ahead of `&&`, where the shell suspends `-e`, so its failure skips only the "
          "rest of that list and the step carries on past it")
_LOST = ("runs ahead of `&&` in a list whose end this guard cannot read (for example a line "
         "ending in `(` or starting with `)`, or a `case` inside `$(...)`), so it clears "
         "nothing after its own command in that list")


class Reach(str):
    """A check's bounded reach, or a pipeline gate derived from one.

    `span` statements are the rest of an `&&` list its failure skips, or its
    own command where the list's end is lost (`_LOST`). `PipelineGate` keeps
    that bound, if any, and excludes the pipeline that runs concurrently.
    """

    span: int | None

    def __new__(cls, span, why=_AHEAD):
        reach = str.__new__(cls, why)
        reach.span = span
        return reach


_SAME_PIPELINE = ("runs in the same pipeline as that use, so the shell may start both before "
                  "the checksum's failure is known")
_BOUNDED_PIPELINE = ("; a use in the same pipeline starts concurrently, and a use after that "
                     "reach still runs")


class PipelineGate(Reach):
    """A check that gates only uses after its concurrent pipeline finishes."""

    through: int

    def __new__(cls, through, reach=None):
        gate = str.__new__(cls, _SAME_PIPELINE if reach is None
                           else str(reach) + _BOUNDED_PIPELINE)
        gate.span = None if reach is None else reach.span
        gate.through = through
        return gate


class FunctionGate(Reach):
    """A check defined in a function, effective only after its proven call."""

    through: int

    def __new__(cls, through):
        gate = str.__new__(
            cls, "is inside a function that has not run through a failure gate before that use")
        gate.span = 0
        gate.through = through
        return gate


def clears(why, check, use):
    """Whether the check stops this use within its reach and pipeline."""
    if check >= use:
        return False
    if why is None:
        return True
    if isinstance(why, FunctionGate):
        return why.through < use
    if isinstance(why, PipelineGate):
        return (use > why.through and
                (why.span is None or use - check <= why.span))
    return isinstance(why, Reach) and why.span is not None and use - check <= why.span


# The keywords that open a compound command, and the ones that close it.
_OPENS, _CLOSES = ("if", "while", "until", "for", "case", "{"), ("fi", "done", "esac", "}")


def _nesting(statement):
    """The compound commands this statement opens, less those it closes: its
    subshell parentheses, and the keywords that lead its commands."""
    depth = 0
    for stage in statement.stages:
        depth += stage.group_open - stage.group_close
        for token in stage.argv:
            if token not in shell_reader.KEYWORDS:
                break
            depth += (token in _OPENS) - (token in _CLOSES)
    return depth


def _closes(statement):
    """Whether this statement closes a group: a `}`, or a subshell's `)` at
    the head of its line (the reader drops a `)` that stands alone)."""
    first = statement.stages[0] if statement.stages else None
    return first is not None and (first.argv == ["}"] or not first.argv and first.group_close > 0)


def _lost_case(stmts):
    """Whether these statements close a `case` they never open: the `esac`
    of a `$(case ...)` whose substitution the reader ended at the pattern's
    `)`, which leaves every count read across it short (review I-4)."""
    opened = 0
    for statement in stmts:
        for stage in statement.stages:
            for token in stage.argv:
                if token not in shell_reader.KEYWORDS:
                    break
                opened += (token == "case") - (token == "esac")
                if opened < 0:
                    return True
    return False


def _stops_step(stmts, position, on, fails):
    """How much of the step a failure in its top-level statement `position`
    stops: None for all of it, -1 for none of it, `_LOST` for its own
    statement only, the refusal where a group it ends lets it go, else the
    index of the last statement it still stops.

    A check that ends a `{ }` group, or a `( )` whose `(` line the reader
    dropped, is that group's status, and what follows the statements closing
    its groups decides: `&`, a pipe where pipefail is off, an `||` branch
    that does not fail the step, or an `&&` list the group heads (review
    I-2). Ahead of `&&` the answer is the end of the list -- the first `||`
    or the list's own end, a compound command in it taken whole -- or of the
    `( )` or `{ }` group the list ends, whose status is the list's. That
    status still stops the step as the step's last command, through an `||`
    branch that stops the step, or as a subshell's where `-e` holds -- a
    piped group runs in one, whose status pipefail passes on -- never a
    plain `{ ...; }` group's, which `-e` lets pass, and not from a group
    detached with `&`, or piped where pipefail is off (`fails`).

    A count of compound commands that never balances, or a list that closes
    a subshell no statement up to the check opened, or is followed by the
    `)` of one (review I-3), is a paren the reader lost -- it drops a `(`
    that ends a line and a `)` alone on one -- and a list that closes a
    `case` it never opened is a `$(...)` it ended at a `case` pattern's `)`,
    whatever the count says (`_lost_case`, review I-4): there the list's end
    is unknown, and the failure stops only its own statement (`_LOST`, review
    I-1, N-7)."""
    last, close = len(stmts) - 1, position
    while close < last and stmts[close].separator not in ("&", "&&", "||") and _closes(
            stmts[close + 1]):
        close += 1                              # the check ends a group: read the group
        if stmts[close].separator == "&":
            return _ENDS % _DETACHED
        if len(stmts[close].stages) > 1 and not fails[close]:
            return _ENDS % _NO_PIPEFAIL
    separator = stmts[close].separator
    if close > position and separator == "||":
        return None if _stops_the_job(
            stmts, close, on[position], fails[position]) else _ENDS % _RESCUED
    if close > position and separator == "&&":
        return _stops_step(stmts, close, on, fails)     # the group heads a list of its own
    if separator != "&&":
        stops = (on[position] or close == last or
                 separator == "||" and _stops_the_job(stmts, position, False, fails[position]))
        return None if stops else -1
    end, depth = position, 0
    while end < last and (depth > 0 or not depth and stmts[end].separator == "&&"):
        end += 1
        depth += _nesting(stmts[end])
    opened = sum(stage.group_open - stage.group_close for statement in stmts[:position + 1]
                 for stage in statement.stages)
    if depth > 0 or depth < 0 and opened < 1 or _lost_case(stmts[position + 1:end + 1]):
        return _LOST                            # a lost paren: the list's end is unknown
    closed_subshells = 0
    while (not depth or depth < 0) and end < last and stmts[end].separator not in (
            "&", "&&", "||") and _closes(stmts[end + 1]):
        end, depth = end + 1, depth - 1          # the list ends enclosing groups
        if stmts[end].stages[0].argv != ["}"]:
            closed_subshells += 1
            if opened < closed_subshells:
                return _LOST                    # a `)` whose `(` the reader dropped
    here = stmts[end]
    if depth < 0 and (here.separator == "&" or len(here.stages) > 1 and not fails[end]):
        return end                              # the group's failure goes nowhere
    if depth < 0 and here.separator == "&&":
        return _stops_step(stmts, end, on, fails)   # the group heads a list of its own
    if here.separator == "||":
        return None if _stops_the_job(stmts, end, all(on[position:end + 2]),
                                      all(fails[position:end + 2])) else end
    subshell = depth < 0 and on[end] and (len(here.stages) > 1 or any(
        stage.group_close for stage in here.stages))    # a piped group runs in one too
    return None if subshell or end == last and here.separator != "&" else end
