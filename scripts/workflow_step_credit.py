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


def _body_words(argv):
    """The command in a branch-body statement, before wrapper resolution."""
    words = list(argv)
    while words and (words[0] in ("then", "do", "else") or shell_reader.is_arm(words[0])):
        words.pop(0)
    return words


def _static(word):
    """Whether a word is independent of shell expansion."""
    return not shell_reader.dynamic(word, shell_reader.has_substitution)


def _literal_for(words):
    """Whether this is a ``for`` over at least one wholly literal word."""
    return (len(words) >= 4 and words[0] == "for" and words[2] == "in"
            and all(_static(word) for word in words[3:]))


def _case_subject(words):
    """A literal ``case`` subject, or None where its value is not fixed."""
    return str(words[1]) if (len(words) == 3 and words[0] == "case"
                             and words[2] == "in" and _static(words[1])) else None


def _arm_pattern(word):
    """A case arm's pattern text, without the reader's structural marker."""
    markers = getattr(word, "markers", {})
    keys = [key for key, (kind, _value) in markers.items()
            if kind == "arm" and word.startswith(key)]
    if len(keys) != 1 or not word.endswith(")"):
        return None
    return str(word)[len(keys[0]):-1]


def _safe_case_literal(text):
    """Whether quote removal cannot change this case word's meaning."""
    return all(character.isalnum() or character in "_./-" for character in text)


def _plain_stage(stage):
    """Whether a stage has no redirect or group syntax that can skip it."""
    return (not stage.reads and not stage.writes and not stage.heredoc
            and not stage.substitutions and not stage.group_open and not stage.group_close
            and stage.stdin_heredoc is None and stage.pipe_input_fds == ("0",)
            and stage.pipe_output_fds == ("1",))


def _case_match(subject, word):
    """True/False for a proved case match, None for an unread pattern."""
    pattern = _arm_pattern(word)
    if pattern is None or shell_reader.has_substitution(word):
        return None
    # Only an unquoted pathname-pattern token proves the catch-all. A quoted
    # or escaped ``*`` has the same text after parsing but remains a plain
    # token, and is a literal star to the shell.
    if pattern == "*" and isinstance(word, shell_reader.Rewritten):
        return True
    if subject is None:
        return None
    # Quoting is gone at this layer.  Restrict exact matches to characters
    # whose shell meaning is unchanged by quoting: in particular, treating a
    # quoted ``|`` as an arm alternation or an unquoted ``~`` as literal would
    # make a branch look certain when it is not.
    return (subject == pattern
            if _safe_case_literal(subject) and _safe_case_literal(pattern) else None)


def _proved_branch_statements(stmts):
    """Indexes inside every branch this bounded reader proves will run.

    This is deliberately narrower than shell execution. It recognizes only
    the three #2439 forms: ``if true``, a proved case arm, and ``for`` over a
    literal non-empty list. Unknown, alternate, while and until bodies stay
    fail-closed.
    """
    proved: set[int] = set()
    stack: list[dict] = []
    pending_if: list[tuple[bool, int]] = []
    pending_loop: list[tuple[bool, int]] = []
    # A redirect, pipeline, or background marker on compound syntax applies
    # to the whole compound command. The flat reader sees it only at one end,
    # so decline every branch proof rather than retroactively revoke indexes.
    for statement in stmts:
        if isinstance(statement, Inlined) or not statement.stages:
            continue
        head = statement.stages[0].argv
        token = head[0] if head else None
        if (token in _BRANCH_OPEN + _BRANCH_ALTERNATE + _BRANCH_CLOSE
                or token in ("if", "for", "while", "until") or _arm(statement)):
            if (len(statement.stages) != 1 or statement.separator == "&"
                    or not _plain_stage(statement.stages[0])):
                return proved
    for index, statement in enumerate(stmts):
        if isinstance(statement, Inlined):
            continue
        head = statement.stages[0].argv if statement.stages else []
        token = head[0] if head else None
        if token in _BRANCH_CLOSE:
            while stack and stack[-1]["kind"] == "arm":
                stack.pop()
            if stack:
                stack.pop()
        elif token in _BRANCH_ALTERNATE:
            if stack:
                stack.pop()
            if token == "else":
                stack.append({"kind": "branch", "proved": False})
            else:
                pending_if.append((False, index))
        elif token == "then":
            candidate, opened = pending_if.pop() if pending_if else (False, -2)
            stack.append({"kind": "branch", "proved": candidate and opened == index - 1})
        elif token == "do":
            candidate, opened = pending_loop.pop() if pending_loop else (False, -2)
            stack.append({"kind": "loop", "proved": candidate and opened == index - 1})
        elif token == "case":
            entry = not index or stmts[index - 1].separator not in ("&&", "||")
            stack.append({"kind": "case", "proved": entry,
                          "subject": _case_subject(head), "seen": False})
        elif _arm(statement):
            if stack and stack[-1]["kind"] == "arm":
                stack.pop()
            if not stack or stack[-1]["kind"] != "case":
                stack.append({"kind": "case", "proved": False,
                              "subject": None, "seen": False})
            case = stack[-1]
            word = next(stage.argv[0] for stage in statement.stages
                        if stage.argv and shell_reader.is_arm(stage.argv[0]))
            # A prior arm can match under shell options the reader does not
            # model (for example bash's nocasematch), so only the first arm
            # can be proved from the flattened syntax alone.
            sure = not case["seen"] and _case_match(case["subject"], word) is True
            case["seen"] = True
            stack.append({"kind": "arm", "proved": sure})

        words = _body_words(head)
        if words[:1] == ["case"] and token != "case":
            stack.append({"kind": "case", "proved": True,
                          "subject": _case_subject(words), "seen": False})
        if words[:1] == ["if"]:
            entry = not index or stmts[index - 1].separator not in ("&&", "||")
            pending_if.append((entry and words == ["if", "true"], index))
        elif words[:1] == ["for"]:
            entry = not index or stmts[index - 1].separator not in ("&&", "||")
            pending_loop.append((entry and _literal_for(words), index))
        elif words[:1] in (["while"], ["until"]):
            pending_loop.append((False, index))

        if stack and all(frame["proved"] for frame in stack):
            proved.add(index)

        effective = command(head)
        if effective[:1] in (["break"], ["continue"]):
            for frame in reversed(stack):
                if frame["kind"] == "loop":
                    frame["proved"] = False
                    break
        # An arbitrary earlier body command can hide a loop transfer (a
        # function call or ``eval break``).  The first executable statement
        # is still certain to run; later statements are not proved here.
        structural = ("if", "case", "for", "while", "until", "fi", "done", "esac", "elif")
        if words and words[0] not in structural:
            for frame in stack:
                if frame["kind"] == "loop":
                    frame["proved"] = False
    return proved


def _same_shell_setter(argv, bash):
    """Whether static wrappers leave a written setter in this shell."""
    words = _body_words(argv)
    if not words or not all(_static(word) for word in words):
        return False
    return (words[0] == "set"
            or bash and words[0] == "shopt"
            or len(words) > 1 and words[0] in ("command", "eval") and words[1] == "set")


def _static_eval(argv):
    """Whether this argv reaches an expansion-free ``eval`` of one ``set``."""
    words = _body_words(argv)
    if not (len(words) > 1 and words[0] == "eval"
            and all(_static(word) for word in words[1:])):
        return False
    inner = statements(" ".join(map(str, words[1:])))
    return bool(len(inner) == 1 and len(inner[0].stages) == 1
                and inner[0].separator not in ("&", "&&", "||")
                and _body_words(inner[0].stages[0].argv)[:1] == ["set"])


def _errexit_states(stmts, state, where, name="errexit", shell=None):
    """Whether `-e` (or `-o name`) holds as each of `stmts` runs, from `state`
    at the top, and after the last, in `shell` (a step's `shell:`, None for
    the default, or the name of a script's runner).

    A `set` turns an option on as a plain statement outside a group, list or
    background job, including in a branch `_proved_branch_statements` knows
    runs; everywhere else it can only turn one off. Visible `( )` restores
    caller state. `shopt -s -o` and `shopt -u -o` become `set` forms
    (`_as_set`, #2335, #2338), and turn on only under bash. A static `command`
    or `eval` around `set` runs that setter in this shell too; `builtin`, a
    wrapped `shopt`, and a dynamic eval retain their fail-closed reading."""
    depth, states, subshells = 0, [], []
    bash = os.path.basename((shell or "bash").split()[0]) == "bash"
    proved = _proved_branch_statements(stmts)
    for index, statement in enumerate(stmts):
        states.append(state)
        for stage in statement.stages:
            subshells.extend([state] * stage.group_open)
            argv = command(stage.argv)
            while len(argv) > 1 and argv[0] in ("builtin", "eval") and argv[1] in _SETTERS:
                argv = command(argv[1:])        # `builtin set`, `eval set`, either way round
            argv = _as_set(argv)
            if argv and argv[0] == "set":
                direct = bool(stage.argv and (stage.argv[0] == "set"
                                              or bash and stage.argv[0] == "shopt"))
                certain = ((index not in where and direct)
                           or (index not in where or index in proved)
                           and _same_shell_setter(stage.argv, bash) and _plain_stage(stage))
                plain = (not depth and not stage.group_open
                         and certain
                         and len(statement.stages) == 1
                         and statement.separator not in ("&", "&&", "||")
                         and not (index and stmts[index - 1].separator in ("&&", "||")))
                state = (_errexit(argv[1:], state, name) if plain
                         else state and _errexit(argv[1:], state, name))
            for text in scripts(argv) if argv[:1] == ["eval"] else ():
                inner = statements(text)
                inner_state = _errexit_states(inner, state, regions(inner), name, shell)[-1]
                plain = (not depth and not stage.group_open
                         and (index not in where or index in proved)
                         and _static_eval(stage.argv) and _plain_stage(stage)
                         and len(statement.stages) == 1
                         and statement.separator not in ("&", "&&", "||")
                         and not (index and stmts[index - 1].separator in ("&&", "||")))
                state = inner_state if plain else state and inner_state
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
