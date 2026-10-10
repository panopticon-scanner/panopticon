#!/usr/bin/env python3
"""Branch regions and shell-option credit for workflow statements.

This control-flow layer is split byte for byte from :mod:`workflow_forms`.
It imports only lower workflow layers; the public facade re-exports every
name so existing callers keep the same objects.
"""
import os

import shell_reader
from shell_reader import command, statements
from workflow_gating import (Inlined, Reach, _LOST, _NO_E, _NO_PIPEFAIL, _SET_E,
                             _errexit, _stops_step, conditional_contexts as paths,
                             conditional_reach as reach, inlined_stops, seed,
                             statement_analysis)
from workflow_programs import scripts


# The shell words that open a body which MAY NOT RUN, and the ones that close
# it. The reader is flat -- statements, not a tree -- but these words arrive as
# the first token of the statement they introduce, which is enough to say
# whether something was written INSIDE a branch.
_BRANCH_OPEN = ("then", "do", "case")
_BRANCH_ALTERNATE = ("else", "elif")
_BRANCH_CLOSE = ("fi", "done", "esac")


def _arm(statement):
    """Does this statement open a `case` arm?

    The `;;` that ends an arm does not survive the statement split (it is two
    empty separators), but the PATTERN that starts the next one does, as the
    first word where a command was expected: `a)`, `*)`, `(a)`, and -- because
    the split cuts on `|` -- the `b)` of an `a|b)` alternation, which is why
    every stage is asked and not only the first.
    """
    return any(stage.argv and shell_reader.is_arm(stage.argv[0])
               for stage in statement.stages)


def regions(stmts):
    """{statement index: the branch body it sits in}, absent = it always runs.

    `if c; then A; fi` runs A only when c held, so a `sha256sum -c` written in
    A cannot clear a use written outside it -- the shell twin of an `if:` on a
    step, refused for the same reason. Bodies nest, so the value is the whole
    stack: two statements share a branch only when they share every enclosing
    one, and `else`/`elif` end the body before them rather than nesting inside
    it, which is what makes two arms of one `if` different answers.

    A `case` arm is a body of exactly that kind, and it is the one the reader
    has to be told about: `esac` is the only word that closes anything, so
    without the arm patterns every arm of one `case` shares a region and a
    checksum in `a)` clears a use in `b)` -- the last spelling left that bought
    the credit `if`/`else` had just stopped giving.

    Read at the head of the statement only. A keyword is a keyword where a
    command was expected; `echo then` is an argument, and counting it would
    open a body that never closes. A statement of a script handed to a shell
    (`Inlined`) sits in the body of the command running it and in its own
    script's bodies: that script's keywords never touch these (review I-3).
    """
    where = {}
    stack: list[tuple[int, str]] = []
    opened, inlined = 0, []
    for index, statement in enumerate(stmts):
        if isinstance(statement, Inlined):          # placed with its carrier's body
            inlined.append((index, statement.region))
            continue
        head = statement.stages[0].argv if statement.stages else []
        token = head[0] if head else None
        if token in _BRANCH_CLOSE:
            while stack and stack[-1][1] == "arm":
                stack.pop()                     # `esac` ends the open arm too
            if stack:
                stack.pop()
        elif token in _BRANCH_ALTERNATE:
            if stack:
                stack.pop()
            if token == "else":
                opened += 1
                stack.append((opened, "branch"))
        elif token in _BRANCH_OPEN:
            opened += 1
            stack.append((opened, "case" if token == "case" else "branch"))
        elif stack and stack[-1][1] in ("case", "arm") and _arm(statement):
            if stack[-1][1] == "arm":
                stack.pop()                     # this pattern ends the last arm
            opened += 1
            stack.append((opened, "arm"))
        here = tuple(identity for identity, _kind in stack)
        for at, region in inlined + [(index, ())]:
            if here + region:
                where[at] = here + region
        inlined = []
    return where


# The words a `set` this module reads may stand behind: `builtin` and `eval`
# run it in this shell, as `command` does, in either order.
_SETTERS = ("builtin", "command", "eval", "set", "shopt")


def _as_set(argv):
    """`shopt -s -o NAME...` or `shopt -u -o NAME...` (`-so`, `-uo`, `-os`) as
    the `set -o NAME...` or `set +o NAME...` it spells; any other argv as it
    is. Without `-o` shopt names options of its own, and without `-s` or
    `-u` it only reports them."""
    if argv[:1] != ["shopt"]:
        return argv
    flags, rest = "", argv[1:]
    while rest and rest[0][:1] == "-" and rest[0] != "--":
        flags, rest = flags + rest[0][1:], rest[1:]
    if "o" not in flags or ("s" in flags) == ("u" in flags):
        return argv
    sign = "-o" if "s" in flags else "+o"
    rest = rest[1:] if rest[:1] == ["--"] else rest
    return ["set"] + [word for option in rest for word in (sign, option)]


def _errexit_states(stmts, state, where, name="errexit", shell=None):
    """Whether `-e` (or `-o name`) holds as each of `stmts` runs, from `state`
    at the top, and after the last, in `shell` (a step's `shell:`, None for
    the default, or the name of a script's runner).

    A `set` turns an option on only as a plain statement outside a branch,
    group, list or background job, and off within its current subshell; visible
    `( )` restores caller state. `shopt -s -o` and `shopt -u -o` become `set`
    forms (`_as_set`, #2335, #2338); plain `shopt` turns on only under bash. A
    setter behind `builtin`, `command` or `eval`, including an `eval` script
    (#2335, review N-6), runs in this shell. The guard reads those as able only
    to turn off, a fail-closed choice, though bash can turn them on."""
    depth, states, subshells = 0, [], []
    bash = os.path.basename((shell or "bash").split()[0]) == "bash"
    for index, statement in enumerate(stmts):
        states.append(state)
        for stage in statement.stages:
            subshells.extend([state] * stage.group_open)
            argv = command(stage.argv)
            while len(argv) > 1 and argv[0] in ("builtin", "eval") and argv[1] in _SETTERS:
                argv = command(argv[1:])        # `builtin set`, `eval set`, either way round
            argv = _as_set(argv)
            if argv and argv[0] == "set":
                plain = (not depth and not stage.group_open and index not in where
                         and (stage.argv[0] == "set" or bash and stage.argv[0] == "shopt")
                         and len(statement.stages) == 1
                         and statement.separator not in ("&", "&&", "||")
                         and not (index and stmts[index - 1].separator in ("&&", "||")))
                state = (_errexit(argv[1:], state, name) if plain
                         else state and _errexit(argv[1:], state, name))
            for text in scripts(argv) if argv[:1] == ["eval"] else ():
                inner = statements(text)
                state = state and _errexit_states(inner, state, regions(inner), name, shell)[-1]
            depth = max(0, depth + stage.group_open + stage.argv.count("{")
                        - stage.group_close - stage.argv.count("}"))
            for _close in range(min(stage.group_close, len(subshells))):
                state = subshells.pop()
    return states + [state]


def step_credit(flat, shell=None):
    """{index: (why, why piped)} for the statements of one step's `read` in
    which a failing check does not stop the step, in `Inlined.credit`'s shape
    (the second answer is a check's with a command piped after it); a step
    whose `shell:` is `shell`. An explicit `(None, None)` retains pipefail-on
    state for enclosing status walks. `swallowed` reads the pair last.

    `flattened` bounds a handed script's credit at its carrier; the step's shell
    decides whether that carrier stops it using `shell:`'s initial `-e` and
    pipefail and each `set` read by `_errexit_states`. Without pipefail a piped
    check's status is lost to the next command. With `-e` off, failure stops the
    step only in its last command or through an exiting `||` branch. Ahead of
    `&&`, failure reaches only its list: `Reach` bounds that list, `_LOST` an
    unread list to its command, and an inherited step refusal to the handed
    script's carrier. `conditional_reach` bounds skipped conditional checks; a
    check ending a group answers as `_stops_step` says.

    The guard has no model of an exit status or a trap, so four readings
    here are fail-closed, and bash stops the step on each (review N-1): with
    `-e` off, a check the step then tests through `$?` (`rc=$?; if [ $rc -ne
    0 ]; then exit 1; fi`), or through `[ $rc -eq 0 ] || exit 1`, or that
    `trap 'exit 1' ERR` guards, is still refused; and so is `CHECK && [[ -f a
    || -f b ]] || exit 1`, whose rescue is lost where the reader splits the
    `[[ ]]` at its inner `||`.
    """
    at = [index for index, statement in enumerate(flat) if not isinstance(statement, Inlined)]
    stmts = [flat[index] for index in at]
    (errexit, pipefail), where, start = seed(shell), regions(stmts), 0
    on, fails = _errexit_states(stmts, errexit, where, shell=shell), _errexit_states(
        stmts, pipefail, where, "pipefail", shell)
    path_map = paths(stmts)
    credit: dict[int, tuple] = {}
    for position, index in enumerate(at):
        stops, body = _stops_step(stmts, position, on, fails), flat[start:index]
        body_analysis = statement_analysis(body)
        for inner in range(start, index + 1):
            why = (Reach(index - inner, _LOST) if stops is _LOST
                   else stops if stops is None or isinstance(stops, str)
                   else Reach(at[stops] - inner) if stops >= 0
                   else _SET_E if errexit else _NO_E % shell)
            why = Reach(index - inner, why) if inner < index and type(why) is str and inlined_stops(body, 0, len(body), inner - start, analysis=body_analysis) else why
            why = reach(why, stmts, path_map.get(position, ()), at, index, inner, on, fails)
            piped = why if inner < index or fails[position] else _NO_PIPEFAIL
            if why or piped or fails[position]:
                credit[inner] = (why, piped)
        start = index + 1
    return credit
