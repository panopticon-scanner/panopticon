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
on top of both. It reads `workflow_programs` BELOW it, for the option letters
a shell takes, which that module reads too (#2443). `Inlined` -- a statement
of a script `workflow_forms.flattened` reads in place -- lives here because
both layers read it, and so does `_errexit`, the option words `seed` and
`flattened` share.

Stdlib only, like everything under it.
"""
import collections
import os
import re

import shell_reader
from shell_reader import command, conditional, negated
from workflow_programs import SET_OPTION_NAMES, SET_OPTIONS, VALUE_OPTIONS


# A statement of a script handed to a shell, as `flattened` inlines it, with
# its bodies below the command running it (`regions`), and why a checksum there
# clears nothing: as its pipeline's last command, and as an earlier one (None:
# it may clear).
Inlined = collections.namedtuple("Inlined", "stages separator region credit")


def _takes_value(words, at):
    """Whether bash's `set` reads `words[at]` as the option NAME an `o`
    before it takes: any word that is not itself an option word. `set -o -e`
    prints the settings and the `-e` still turns errexit ON -- rc 1 on bash
    3.2.57 and 5.2.21 with a `false` behind it, and no `SURVIVED` -- and so
    does `set -oo pipefail -e`. A shell's COMMAND LINE takes the next word
    whatever it spells: `bash -oo pipefail -c P` answers `-c: invalid option
    name`, rc 2, and runs nothing at all (`invocation` below, and
    `workflow_programs._past_options`, which counts the same way)."""
    return at < len(words) and words[at][:1] not in ("-", "+")


def _rejected(words):
    """Whether bash refuses this `set` WHOLE: one of its option words carries
    a letter the builtin lacks (`set -Z -e`, `set -eO foo`), or is a LONG one
    -- bash's `set` has none, and answers `set --posix -e` with `set: --:
    invalid option` (review NIT 4) -- or an `o` in it takes a value that is
    no option NAME (`set -o foo`, #2560). A bad LETTER leaves no option
    changed (rc 2, #2443); a bad NAME keeps what the words before it set, as
    the third paragraph says (rc 1 on bash 3.2.57, 2 on 5.2.21). dash and
    `sh` die at the `set` instead, so nothing runs there at all. `set --` is
    the positional spelling that ends the options, not a refusal:
    `set -- "$@"` reads as it always did.

    Read over the words `_errexit` reads, taking one value per `o` LETTER
    exactly as it does -- as bash does, and as
    `workflow_programs._past_options` and `stdin_program` already did -- so
    the two walks agree about which words are values. `set -oo pipefail
    errexit` turns errexit ON and leaves no positional behind (`$#` is 0 on
    bash 3.2.57 and 5.2.21), where the per-word count this replaced read the
    `errexit` as the end of the options (#2559, review NIT 6 of #2551). The
    shape that count was keeping out, `set -oo x -Ze`, is caught by the NAME
    now: `x` is the first `o`'s value and no name, so both bashes answer
    `set: x: invalid option name` and set nothing; the second `o` has no
    value, and `-Ze` is read as an option word (`_takes_value`).

    Reading a refused NAME as setting NOTHING is the fail-closed pick rather
    than bash to the letter: bash applies the names BEFORE the bad one and
    stops there, so `set -o pipefail -o foo` leaves pipefail on (rc 0, both
    bashes) -- but where the one it applied was errexit, the failing `set`
    exits the shell under it and nothing after it runs at all (`set -e -o
    foo`: rc 1 on 3.2.57, rc 2 on 5.2.21, nothing printed after). An unknown
    LETTER is not like that: bash validates a WORD's letters before applying
    that word, so `set -o errexit -Z` leaves errexit OFF (rc 0) -- but a name
    an earlier word applied stays, and `set -ox pipefail -Z` or
    `set -oo pipefail x` leaves pipefail ON and survives, read here as OFF:
    over-reports only. A value the guard cannot read (`$X`, `${X:-pipefail}`,
    a lifted `$(cmd)`) is a refused NAME too: with `X=foo`, both bashes
    answer `set -o $X -e` with `invalid option name`, leave errexit off and
    run what follows, so reading it ON would fail open -- the opposite pick
    from `_refused_name`, whose ON means the program runs and is reported."""
    words, at = list(words), 0
    while at < len(words):
        word, at = words[at], at + 1
        if word == "--" or word[:1] not in ("-", "+") or word[:2] == "++":
            return False
        if word[:2] == "--" or any(letter not in SET_OPTIONS for letter in word[1:]):
            return True
        for letter in word[1:]:
            if letter in VALUE_OPTIONS and _takes_value(words, at):
                if words[at] not in SET_OPTION_NAMES:
                    return True                 # `set -o foo`: no option of that name
                at += 1                         # `-o name`'s value, as `_errexit` takes it
    return False


def _errexit(words, state=False, name="errexit", invocation=False):
    """Whether these shell or `set` options leave `-e` on, from `state` -- or
    the option `-o name` sets, for `pipefail`, which no letter spells.

    One value per `o` LETTER, as bash counts them and `_rejected` reads them
    (#2559): the second `o` of `set -oo pipefail errexit` takes `errexit`.
    `invocation`: these words are a shell's COMMAND LINE -- a `shell:`
    template's (`seed`) or a child shell's (`flattened`, #2444) -- where
    `-O shopt` takes a value, which bash's `set` does not: it rejects `-O`.
    There an `o` takes the next word whatever it spells, where the builtin
    reads a NAME only from a word that is not an option (`_takes_value`).
    A `set` bash refuses whole turns NOTHING on (`_rejected`, #2443, #2560);
    a `+e` in it still reads as off, fail-closed either way.
    """
    words = list(words)
    rejected = not invocation and _rejected(words)
    at = 0
    while at < len(words):
        word, at = words[at], at + 1
        if word == "--" or word[:1] not in ("-", "+") or word[:2] == "++":
            break
        if word[:2] == "--":                    # bash's long options carry none
            continue
        turns_on = not (rejected and word[0] == "-")
        for letter in word[1:]:
            if letter == "e" and name == "errexit" and turns_on:
                state = word[0] == "-"
            elif letter == "o" and (invocation or _takes_value(words, at)):
                if at < len(words) and words[at] == name and turns_on:
                    state = word[0] == "-"
                at += 1                         # `-o name`'s value
            elif letter == "O" and invocation:
                at += 1                         # `bash -O extglob {0}`
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
    return _errexit(words[1:], invocation=True), _errexit(words[1:], False, "pipefail", True)


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
    its list runs, or its own command where the list's end is lost (`clears`).
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
    """A check's refusal that still clears the `span` statements after it:
    the rest of the `&&` list its failure skips, or of its own command where
    the list's end is lost (`_LOST`), in the words `why` gives it
    (`step_credit`, `clears`)."""

    span: int

    def __new__(cls, span, why=_AHEAD):
        reach = str.__new__(cls, why)
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
    opened = sum(stage.group_open - stage.group_close for statement in stmts[:position + 1]
                 for stage in statement.stages)
    if depth > 0 or depth < 0 and opened < 1 or _lost_case(stmts[position + 1:end + 1]):
        return _LOST                            # a lost paren: the list's end is unknown
    if not depth and end < last and stmts[end].separator not in ("&", "||") and _closes(
            stmts[end + 1]):
        end, depth = end + 1, -1                # the list ends its group
        if stmts[end].stages[0].argv != ["}"] and opened < 1:
            return _LOST                        # a `)` whose `(` the reader dropped
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
