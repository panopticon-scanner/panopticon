#!/usr/bin/env python3
"""Bounded shell-status and Bash ``ERR``-trap gates for workflow checks.

This layer recognizes only status paths whose failed-check branch is fixed by
the parsed statements.  It does not evaluate shell expressions: the status
must be captured immediately, compared numerically with zero, and handed to a
literal non-zero ``exit``.  The trap proof is narrower still: a literal,
top-level Bash ``ERR`` handler whose one command exits non-zero.
"""
import os
import re

import shell_reader
from shell_reader import command
from workflow_function_calls import _function_syntax


_CAPTURE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=\$\?$")


def _plain(statement):
    """The sole, local stage of a statement, or None."""
    if len(statement.stages) != 1 or statement.separator == "&":
        return None
    stage = statement.stages[0]
    if (stage.reads or stage.writes or stage.heredoc or stage.substitutions
            or stage.group_open or stage.group_close or stage.stdin_heredoc is not None
            or stage.pipe_input_fds != ("0",) or stage.pipe_output_fds != ("1",)):
        return None
    return stage


def _live(word, values):
    """Whether ``word`` is one of ``values`` and its dollar is expanded."""
    return str(word) in values and getattr(word, "live_dollar", True)


def _capture(statement):
    if statement.separator in ("&&", "||"):
        return None
    stage = _plain(statement)
    words = list(stage.argv) if stage is not None else []
    match = _CAPTURE.fullmatch(str(words[0])) if len(words) == 1 else None
    return match[1] if match and _live(words[0], (match[0],)) else None


def _test(statement, name):
    """(``if`` form, true on failed status, Bash-only, command), or None."""
    stage = _plain(statement)
    raw = stage.argv if stage is not None else ()
    words = command(raw)
    conditional = bool(raw[:1] == ["if"])
    bash = bool(words[:1] == ["[["] and words[-1:] == ["]]"])
    if words[:1] == ["["] and words[-1:] == ["]"] or bash:
        expression = words[1:-1]
    else:
        return None
    if len(expression) != 3 or expression[1] not in ("-eq", "-ne"):
        return None
    references = ("$?",) if name is None else ("$" + name, "${%s}" % name)
    left = _live(expression[0], references) and str(expression[2]) == "0"
    right = _live(expression[2], references) and str(expression[0]) == "0"
    return ((conditional, expression[1] == "-ne", bash, str(words[0]))
            if left or right else None)


def _exit(statement, leading_then=False):
    stage = _plain(statement)
    if stage is None:
        return False
    raw, words = stage.argv, command(stage.argv)
    if leading_then != bool(raw[:1] == ["then"]):
        return False
    return (len(words) == 2 and words[0] == "exit"
            and re.fullmatch(r"[+-]?[0-9]+", str(words[1])) is not None
            and int(words[1]) % 256 != 0)


def _bash(shell):
    words = (shell or "bash").split()
    return bool(words and os.path.basename(words[0]) == "bash")


def _same_step(index, owner, postures):
    return postures is None or postures.get(index, (None, None, object()))[2] == owner


def step_end(stmts, index, owner=None, postures=None):
    """Last statement in ``index``'s workflow step."""
    end = index
    while end + 1 < len(stmts) and _same_step(end + 1, owner, postures):
        end += 1
    return end


def _functions(stmts, owner, postures):
    found = set()
    for at, statement in enumerate(stmts):
        if not _same_step(at, owner, postures):
            continue
        for stage in statement.stages:
            name = _function_syntax(stage.argv)[0]
            if name is None and len(stage.argv) > 1 and stage.argv[0] == "function":
                name = str(stage.argv[1])
            if name is not None:
                found.add(name)
    return found


def _status_prefix_safe(stmts, index, name, owner, postures, functions):
    """Whether prior same-shell text cannot replace the status primitives."""
    for at, statement in enumerate(stmts[:index]):
        if not _same_step(at, owner, postures):
            continue
        for stage in statement.stages:
            if _function_syntax(stage.argv)[0] is not None:
                continue
            words = command(stage.argv)
            tool = os.path.basename(words[0]) if words else ""
            if tool in ("trap", "eval", ".", "source", "alias", "enable") or tool in functions:
                return False
            flags = "".join(word[1:] for word in words[1:] if word.startswith("-"))
            if (tool == "readonly" or tool in ("declare", "typeset") and "r" in flags):
                operands = [str(word).split("=", 1)[0] for word in words[1:]
                            if not word.startswith("-")]
                if name in operands:
                    return False
    return True


def status_gate(stmts, index, shell, analysis, owner=None, postures=None):
    """Last handler statement when an immediate status path exits, else None."""
    if (analysis.enclosing[index] is not None or index + 1 >= len(stmts)
            or not _same_step(index + 1, owner, postures)):
        return None
    at, name = index + 1, _capture(stmts[index + 1])
    if name is not None:
        at += 1
    if (at >= len(stmts) or not _same_step(at, owner, postures)
            or analysis.enclosing[at] is not None):
        return None
    tested = _test(stmts[at], name)
    if tested is None:
        return None
    conditional, failure_true, bash_only, test_command = tested
    functions = _functions(stmts, owner, postures)
    if ("exit" in functions or test_command in functions
            or not _status_prefix_safe(stmts, index, name, owner, postures, functions)
            or bash_only and not _bash(shell)):
        return None
    if not conditional:
        branch = "&&" if failure_true else "||"
        return (at + 1 if stmts[at].separator == branch and at + 1 < len(stmts)
                and _same_step(at + 1, owner, postures)
                and _exit(stmts[at + 1]) else None)
    if (not failure_true or at + 2 >= len(stmts)
            or not _same_step(at + 1, owner, postures)):
        return None
    exits = at + 1
    if not _exit(stmts[exits], leading_then=True):
        if (stmts[exits].stages and stmts[exits].stages[0].argv == ["then"]
                and exits + 2 < len(stmts)
                and _same_step(exits + 1, owner, postures)
                and _exit(stmts[exits + 1])):
            exits += 1
        else:
            return None
    close = exits + 1
    stage = _plain(stmts[close]) if close < len(stmts) else None
    return (close if _same_step(close, owner, postures)
            and stage is not None and stage.argv == ["fi"] else None)


def _stopping_trap(statement):
    """Whether this is a literal ``trap 'exit N' ERR`` with non-zero N."""
    stage = _plain(statement)
    raw = stage.argv if stage is not None else []
    if not (raw[:1] == ["trap"] or raw[:2] in (["builtin", "trap"],
                                                ["command", "trap"])):
        return False
    words = command(stage.argv) if stage is not None else []
    if words[:1] == ["builtin"]:
        words = words[1:]
    if len(words) < 3 or words[0] != "trap" or "ERR" not in words[2:]:
        return False
    body = list(shell_reader.statements(words[1]))
    return len(body) == 1 and _exit(body[0])


def stopping_err_trap(stmts, index, shell, analysis, owner=None, postures=None):
    """Whether an unreplaced top-level stopping Bash ERR trap guards index."""
    if not _bash(shell) or analysis.enclosing[index] is not None:
        return False
    functions = _functions(stmts, owner, postures)
    if "exit" in functions:
        return False
    active = tainted = False
    for at, statement in enumerate(stmts[:index]):
        if not _same_step(at, owner, postures):
            continue
        for stage in statement.stages:
            words = command(stage.argv)
            name = os.path.basename(words[0]) if words else ""
            is_trap = name == "trap" or words[:2] == ["builtin", "trap"]
            if is_trap:
                forced = stage.argv[:2] in (["builtin", "trap"], ["command", "trap"])
                active = (not tainted and ("trap" not in functions or forced)
                          and analysis.enclosing[at] is None
                          and _stopping_trap(statement))
            elif name in ("eval", ".", "source", "alias", "enable") + tuple(functions):
                active, tainted = False, True
    return active
