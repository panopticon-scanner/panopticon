#!/usr/bin/env python3
"""Function-body and forked-scope readers for downloaded-file use discovery.

Split out of `scripts/workflow_uses.py` at that module's 700-line ceiling,
byte for byte: function ranges and removal, the compound/group walk whose
assignments live in another shell, and the bounded end of a function body.
`workflow_uses` re-exports every name, so existing callers keep their imports.

This is a leaf over the shell reader's command view, function-call syntax,
and the literal-parenthesis count owned by `workflow_values`.
"""
from shell_reader import command
from workflow_function_calls import _FUNCTION_TOKEN, _function_scope, _function_syntax
from workflow_values import _literals


def _function_ranges(stmts):
    """Definition starts and the indices occupied by each function body."""
    starts: dict[int, list[tuple[str, int, int]]] = {}
    occupied: set[int] = set()
    for index, statement in enumerate(stmts):
        for stage in statement.stages:
            name = _function_syntax(stage.argv)[0]
            if name is None:
                continue
            scope = _function_scope(stmts, index)
            if scope is None:
                continue
            close = scope[1]
            starts.setdefault(index, []).append((name, index, close))
            occupied.update(range(index, close + 1))
    return starts, occupied


def _function_changes(stage, functions, writable):
    """Apply a certain `unset -f`; definitions are installed by their range."""
    if not writable:
        return
    argv = command(stage.argv)
    if argv[:1] == ["unset"] and "-f" in argv:
        for word in argv[1:]:
            if not str(word).startswith("-"):
                functions.pop(str(word), None)


# The words that open a group or compound `_forked` follows, and each one's close.
_COMPOUNDS = {"{": "}", "if": "fi", "case": "esac", "for": "done", "select": "done",
              "while": "done", "until": "done"}


def _forked(stmts, index):
    """The statements the step's shell forks (#2425) in a child the statement
    at `index` is not in: a `( ... )` subshell's past its opening statement,
    an `&&`/`||` list's sent to the background whole (`T=x && : &`), and
    every statement of a `{ ...; }` group or an `if`, `case`, `for`,
    `select`, `while` or `until` compound, from its head to its close, that
    is piped into, piped on, run by `coproc`, or sent to the background by
    its own `&` or the one ending its list (`if T=x; then :; fi &`) -- a
    list is not followed past a compound command, so `T=x && if c; then :;
    fi &` reads `T=x` as sure (a limit) -- and, never sure outside it, a
    compound that is a function's body (`g() for T in x; do :; done`, `{ f()
    { :; }; }`, `_openers`), which runs only where it is called. Their
    assignments end with the child, as `working_directories` keeps a
    subshell's `cd`; a use in the same child sees them as its own; a use in
    a later stage of the statement that closes it is outside it (`{ T=x; } |
    sh "$T"`). A keyword is one only where the stage's command would stand
    (`_openers`); an array literal's parentheses count as a group's, which
    marks a multi-line literal's word lines unsure."""
    forked: set[int] = set()
    opened: list[tuple[int, bool, str]] = []
    subshells: list[int] = []
    header = False                          # a function header's body is still to come

    def fork(start, end, onward=False):     # `onward`: the close's statement pipes on past it
        if not (start <= index < end or index == end and not onward):
            forked.update(range(start, end + 1))

    for position, statement in enumerate(stmts):
        end = position                      # the end of its `&&`/`||` list
        while stmts[end].separator in ("&&", "||") and end + 1 < len(stmts):
            end += 1
        if stmts[end].separator == "&":
            fork(position, end)
        last = len(statement.stages) - 1
        for number, stage in enumerate(statement.stages):
            subshells += [position + 1] * stage.group_open
            for _ in range(min(stage.group_close, len(subshells))):
                fork(subshells.pop(), position, number < last)
            words, header = _openers(stage, header)
            for word, child in words:
                if str(word) in _COMPOUNDS:
                    opened.append((position, child or number > 0, _COMPOUNDS[str(word)]))
                elif opened and word == opened[-1][2]:
                    start, piped, _close = opened.pop()
                    if piped or number < last or stmts[end].separator == "&":
                        fork(start, position, number < last)
    for start in subshells:                 # a group the step leaves open
        fork(start, len(stmts) - 1)
    return forked


def _openers(stage, header=False):
    """The words `_forked` reads in `stage` for a compound's head or close,
    each with whether the compound surely runs apart from the step's shell,
    and whether a function header ends the stage with its body to come
    (`header`: `g()` or `function g()` alone on its line). They are the lead
    words -- the compound right after a function header is its body -- and
    what the reader leaves in the command: the `select`, the compound after
    `coproc` (and its NAME), which runs in a child, and the body `{` of a
    function defined after a keyword on its line, which the reader splits
    into its name, a group of its own `()` and the `{`."""
    argv = command(stage.argv)
    lead = stage.argv[:len(stage.argv) - len(argv)]
    words = []
    for number, word in enumerate(lead):
        words.append((word, header))
        header = (bool(_FUNCTION_TOKEN.fullmatch(str(word))) or word == "()"
                  or lead[number - 1:number] == ["function"])
    if argv[:1] == ["select"]:
        words.append((argv[0], header))
    elif argv[:1] == ["coproc"]:
        words += [(word, True) for word in argv[1:3] if str(word) in _COMPOUNDS][:1]
    elif argv[1:2] == ["{"] and min(stage.group_open, stage.group_close) > _literals(stage):
        words.append((argv[1], True))
    return words, header and not argv and stage.group_open <= _own_parens(stage)


def _body_end(stmts, start, close):
    """The last statement of the body defined at `start`, and whether its end
    was found: `close`, where `_function_ranges` found the `}`, or where a
    subshell body's parentheses close, opened on the definition's line
    (`g() ( ... )`, past a `function NAME()` header's own `()`: `_own_parens`)
    or the next -- searched for to the step's end, past a `}` inside the body
    that `_function_ranges` takes for its close."""
    following = stmts[start + 1].stages[:1] if start + 1 < len(stmts) else []
    for stage in stmts[start].stages:
        name, braces = _function_syntax(stage.argv)
        opens = stage.group_open - _own_parens(stage) > _literals(stage)
        if name and "{" not in braces and (opens or any(map(_opens, following))):
            depth = 0
            for end in range(start if opens else start + 1, len(stmts)):
                depth += sum(item.group_open - item.group_close for item in stmts[end].stages)
                if depth <= 0:
                    return end, True
            return close, False
    return close, close < len(stmts) - 1 or any("}" in _function_syntax(stage.argv)[1]
                                                for stage in stmts[close].stages)


def _own_parens(stage):
    """1 where the reader reads a `function NAME()` header's own `()` as a group."""
    return int(stage.argv[:1] == ["function"] and stage.group_close > _literals(stage)
               and not any(_FUNCTION_TOKEN.fullmatch(str(word)) or word == "()"
                           for word in stage.argv))


def _opens(stage):
    """Whether `stage` opens a group, past its array literals' parentheses."""
    return stage.group_open > _literals(stage)
