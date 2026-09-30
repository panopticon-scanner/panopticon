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
    `step_credit`              the step's own `-e` and `pipefail`, which its
                               `shell:` starts (`seed`) and a `set` moves, how
                               far a check ahead of `&&` reaches -- the rest of
                               its list -- and what follows a group the check
                               ends (`_stops_step`, `Reach`, `clears`)

`Inlined` -- a statement of a script `workflow_forms.flattened` reads in place
-- lives here because both layers read it, and so does `_errexit`, the option
words `seed` and `flattened` share. `step_credit` reads the branch bodies
(`regions`) and the `set`s (`_errexit_states`) with the readers of the layer
above, imported when it runs, because that layer imports this one.

Stdlib only, like everything under it.
"""
import collections
import os
import re

import shell_reader
from shell_reader import command, conditional, negated


# A statement of a script handed to a shell, as `flattened` inlines it, with
# its bodies below the command running it (`regions`), and why a checksum there
# clears nothing: as its pipeline's last command, and as an earlier one (None:
# it may clear).
Inlined = collections.namedtuple("Inlined", "stages separator region credit")


def _errexit(words, state=False, name="errexit"):
    """Whether these shell or `set` options leave `-e` on, from `state` -- or
    the option `-o name` sets, for `pipefail`, which no letter spells."""
    words = iter(words)
    for word in words:
        if word == "--" or word[:1] not in ("-", "+") or word[:2] == "++":
            break
        if word[:2] != "--":                    # bash's long options carry none
            if "e" in word[1:] and name == "errexit":
                state = word[0] == "-"
            if "o" in word[1:] and next(words, None) == name:
                state = word[0] == "-"
    return state


def seed(shell):
    """(`-e`, `pipefail`) as a step whose `shell:` is `shell` starts (#2338).

    GitHub runs a step with no `shell:` as `bash -e {0}` (`sh -e {0}` where
    bash is missing) and `shell: sh` as `sh -e {0}`: `-e` and no pipefail.
    Only `shell: bash` adds it (`bash --noprofile --norc -eo pipefail {0}`),
    and a template (`bash {0}`, `bash -eo pipefail {0}`) runs with exactly
    the options it writes.
    """
    words = (shell or "").split()
    if len(words) < 2:
        return True, words == ["bash"]
    return _errexit(words[1:]), _errexit(words[1:], False, "pipefail")


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


def _stops_the_job(stmts, index, errexit=True):
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
    depth = subshell_depth = 0
    exited_subshell = None
    stopped_job = exited = False
    for statement in following:
        if (statement.separator == "&" or len(statement.stages) != 1 or
                any(negated(stage.argv) for stage in statement.stages)):
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
            if exited_subshell is not None and subshell_depth < exited_subshell:
                exited_subshell = None
        if not grouped or depth == 0:
            if statement.separator in ("&&", "||") and not stopped_job:
                return False
            break
        if statement.separator in ("&&", "||"):
            return False
    return ((not grouped or depth == 0) and status is not None and status != 0
            and (errexit or exited))


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
    its list runs (`clears`).
    """
    if isinstance(statement, Inlined) and statement.credit[stage is not statement.stages[-1]]:
        return statement.credit[stage is not statement.stages[-1]]
    if statement.separator == "&":
        return _DETACHED
    if statement.separator == "||" and not _stops_the_job(stmts, index):
        return _RESCUED
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
    return credit[stage is not statement.stages[-1]] if credit else None


# Why a check the step's own shell runs does not stop the step, as
# `step_credit` finds it -- the first two as `swallowed` does too, and those
# and `_NO_PIPEFAIL` again for the group a check ends, whose status is the
# check's (`_ENDS`).
_DETACHED = "is detached with `&`"
_RESCUED = "hands its failure to a `||` branch that does not fail the step"
_ENDS = "ends a group that %s"
_SET_E = ("runs after a `set +e` or a spelling of it (`set +o errexit`, `shopt -uo errexit`, "
          "`builtin set +e`), which this guard reads as turning errexit off from where it is "
          "written, and is not in the step's last command, so the step carries on past its "
          "failure")
_NO_E = ("runs under `shell: %s`, which starts without errexit, and is not in the step's "
         "last command, so the step carries on past its failure")
_NO_PIPEFAIL = ("is piped into another command where `pipefail` is off, so the pipeline "
                "takes that command's status and the step carries on past its failure "
                "(`shell: bash` turns pipefail on, and so does a `set -o pipefail` before it "
                "where the shell is bash)")
_AHEAD = ("runs ahead of `&&`, where the shell suspends `-e`, so its failure skips only the "
          "rest of that list and the step carries on past it")


def step_credit(flat, shell=None):
    """{index: (why, why piped)} for the statements of one step's `read` in
    which a failing check does not stop the step, in `Inlined.credit`'s shape
    (the second answer is a check's with a command piped after it); a step
    whose `shell:` is `shell`. `swallowed` reads it last.

    `flattened` credits a script handed on only as far as the command that
    runs it, and the step's own shell decides the rest: its `-e`, for that
    command and for a check written at the top alike, and its pipefail, for
    a check piped at the top (`flattened` asks it of the command) -- each as
    the `shell:` starts it (`seed`) and a `set` moves it, read the way
    `_errexit_states` reads a child script. Without pipefail a piped check's
    status is lost to the command after it. Where `-e` is off, a failure
    stops the step only in its last command or through an `||` branch that
    exits. Ahead of `&&` the shell suspends `-e`, so a failure there stops
    only the rest of its list, a `Reach` of that many statements; a check
    that ends a group answers as the group does (`_stops_step`).

    The guard has no model of an exit status or a trap, so four readings
    here are fail-closed, and bash stops the step on each (review N-1): with
    `-e` off, a check the step then tests through `$?` (`rc=$?; if [ $rc -ne
    0 ]; then exit 1; fi`), or through `[ $rc -eq 0 ] || exit 1`, or that
    `trap 'exit 1' ERR` guards, is still refused; and so is `CHECK && [[ -f a
    || -f b ]] || exit 1`, whose rescue is lost where the reader splits the
    `[[ ]]` at its inner `||`.
    """
    from workflow_forms import _errexit_states, regions   # the layer above (module docstring)
    at = [index for index, statement in enumerate(flat) if not isinstance(statement, Inlined)]
    stmts = [flat[index] for index in at]
    (errexit, pipefail), where, start = seed(shell), regions(stmts), 0
    on, fails = _errexit_states(stmts, errexit, where, shell=shell), _errexit_states(
        stmts, pipefail, where, "pipefail", shell)
    credit: dict[int, tuple] = {}
    for position, index in enumerate(at):
        stops = _stops_step(stmts, position, on, fails)
        for inner in range(start, index + 1):
            why = (stops if stops is None or isinstance(stops, str)
                   else Reach(at[stops] - inner) if stops >= 0
                   else _SET_E if errexit else _NO_E % shell)
            piped = why if inner < index or fails[position] else _NO_PIPEFAIL
            if why or piped:
                credit[inner] = (why, piped)
        start = index + 1
    return credit


class Reach(str):
    """A check's refusal that still clears the `span` statements after it:
    the rest of the `&&` list its failure skips (`step_credit`, `clears`)."""

    span: int

    def __new__(cls, span):
        reach = str.__new__(cls, _AHEAD)
        reach.span = span
        return reach


def clears(why, check, use):
    """Whether a check at statement `check`, refused for `why` (None: it
    stops the step), stops the use at statement `use`."""
    return check < use and (why is None or isinstance(why, Reach) and use - check <= why.span)


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


def _stops_step(stmts, position, on, fails):
    """How much of the step a failure in its top-level statement `position`
    stops: None for all of it, -1 for none of it, the refusal where a group it
    ends lets it go, else the index of the last statement it still stops.

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

    A count of compound commands that never balances, or that closes a
    subshell no statement up to the check opened, is a paren the reader lost
    -- it drops a line holding only `(` or `)`, and ends a `$(...)` at a
    `case` pattern's `)` -- and there the list's end is unknown: the failure
    stops only its own statement (review I-1)."""
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
        return None if _stops_the_job(stmts, close, on[position]) else _ENDS % _RESCUED
    if close > position and separator == "&&":
        return _stops_step(stmts, close, on, fails)     # the group heads a list of its own
    if separator != "&&":
        stops = (on[position] or close == last or
                 separator == "||" and _stops_the_job(stmts, position, False))
        return None if stops else -1
    end, depth = position, 0
    while end < last and (depth > 0 or not depth and stmts[end].separator == "&&"):
        end += 1
        depth += _nesting(stmts[end])
    if depth > 0 or depth < 0 and sum(stage.group_open - stage.group_close for statement
                                      in stmts[:position + 1] for stage in statement.stages) < 1:
        return position                         # a lost paren: the list's end is unknown
    if not depth and end < last and stmts[end].separator not in ("&", "||") and _closes(
            stmts[end + 1]):
        end, depth = end + 1, -1                # the list ends its group
    here = stmts[end]
    if depth < 0 and (here.separator == "&" or len(here.stages) > 1 and not fails[end]):
        return end                              # the group's failure goes nowhere
    if depth < 0 and here.separator == "&&":
        return _stops_step(stmts, end, on, fails)   # the group heads a list of its own
    if here.separator == "||":
        return None if _stops_the_job(stmts, end, all(on[position:end + 2])) else end
    subshell = depth < 0 and on[end] and (len(here.stages) > 1 or any(
        stage.group_close for stage in here.stages))    # a piped group runs in one too
    return None if subshell or end == last and here.separator != "&" else end
