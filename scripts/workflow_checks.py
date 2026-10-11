#!/usr/bin/env python3
"""Checksum discovery for the workflow fetch-and-execute guard.

Checks and uses keep their outer statement number for job-level conditions,
plus a private local position when they occur in a command substitution. That
lets the guard apply the substitution shell's own failure reach without
mistaking checks in sibling substitutions for gates.
"""
import os
import re

from shell_reader import command, statements
from workflow_forms import (STDOUT, at_directory, clears, regions, step_credit,
                            statement_analysis, swallowed, working_directories)


CHECKSUM_TOOLS = ("sha256sum", "sha512sum", "sha384sum", "shasum")
_DIGEST = re.compile(r"\b[0-9a-f]{40,128}\b"
                     r"|\$\{?\w*(?:SHA|SUM|DIGEST|HASH|CHECKSUM)\w*\}?", re.I)
_NO_DIGEST = ("carries no digest, so it says which file to read and not what "
              "should have arrived")
_OTHER_SUBSTITUTION = ("is inside another command-substitution context, so its failure does "
                       "not gate that use")


class Nested(int):
    """An outer statement index retaining its nested shell position and cwd."""

    path: tuple
    index: int
    directory: str

    def __new__(cls, outer, path, index, directory):
        point = int.__new__(cls, outer)
        point.path, point.index, point.directory = path, index, directory
        return point


def operands(argv):
    return [token for token in argv[1:] if not token.startswith("-")]


def _has_check_flag(argv):
    for token in argv[1:]:
        if token in ("-c", "--check"):
            return True
        if token.startswith("-") and not token.startswith("--") and "c" in token:
            return True
    return False


def _checked_text(statement, position, stage, argv, written, directory):
    """Text read from a heredoc, a locally written file, or the prior stage."""
    if stage.heredoc:
        return stage.heredoc
    files = [at_directory(path, directory) for path in operands(argv) + stage.reads
             if path not in STDOUT]
    files = [path for path in files if not re.fullmatch(r"\d+", path)]
    if files:
        known = [written[path] for path in files if path in written]
        return "\n".join(known) if known else None
    if position:
        return " ".join(command(statement.stages[position - 1].argv))
    return None


def _record_writes(statement, written, directory):
    """Record text left in files for a later `sha256sum -c <file>`."""
    for position, stage in enumerate(statement.stages):
        argv = command(stage.argv)
        text = " ".join(argv) + ("\n" + stage.heredoc if stage.heredoc else "")
        targets = list(stage.writes)
        if argv and os.path.basename(argv[0]) == "tee":
            targets += operands(argv)
            if position:
                text = " ".join(command(statement.stages[position - 1].argv))
        for target in targets:
            written[at_directory(target, directory)] = text


def checks(stmts, credit=None, working=None, outer=None, path=(), scope=None,
           written=None, directory="."):
    """[(outer statement, checked text, refusal or None)], including substitutions."""
    found, analysis = [], statement_analysis(stmts)
    written = {} if written is None else dict(written)
    working = working or {}
    for index, statement in enumerate(stmts):
        here = working.get(index, directory)
        point = index if outer is None else Nested(outer, path, index, here)
        here_scope = index if outer is None else "%sI%d" % (scope, index)
        for position, stage in enumerate(statement.stages):
            argv = command(stage.argv)
            for nested, text in enumerate(stage.substitutions):
                inner = list(statements(text))
                child_scope = "%sS%d_%d" % (here_scope, position, nested)
                own = step_credit(inner, "bash {0}")
                dirs = working_directories(inner, regions(inner), child_scope, own, here)
                found += checks(inner, own, dict(enumerate(dirs)), int(point),
                                path + ((index, position, nested),), child_scope,
                                written, here)
            if not argv or os.path.basename(argv[0]) not in CHECKSUM_TOOLS:
                continue
            if not _has_check_flag(argv):
                continue
            text = _checked_text(statement, position, stage, argv, written, here) or ""
            why = (_NO_DIGEST if not _DIGEST.search(text) else
                   swallowed(stmts, index, statement, stage,
                             (credit or {}).get(index), analysis))
            found.append((point, text, why))
        _record_writes(statement, written, here)
    return found


def inside(statement, outer, directory=".", scope=0, path=(), index=None):
    """Stages under one outer statement, retaining each nested shell position."""
    point = outer if index is None else Nested(outer, path, index, directory)
    for position, stage in enumerate(statement.stages):
        where = " inside a command substitution" if path else ""
        yield point, statement, position, stage, where, directory
        for nested, text in enumerate(stage.substitutions):
            inner = list(statements(text))
            child_scope = "%sS%d_%d" % (scope, position, nested)
            own = step_credit(inner, "bash {0}")
            working = working_directories(inner, regions(inner), child_scope, own, directory)
            child_path = path + (((outer if index is None else index), position, nested),)
            for child_index, child in enumerate(inner):
                yield from inside(child, outer, working[child_index],
                                  "%sI%d" % (child_scope, child_index),
                                  child_path, child_index)


def clears_nested(why, check, use):
    """Apply a nested check's local reach to a use in that shell or its child."""
    if isinstance(check, Nested):
        if not isinstance(use, Nested):
            return False
        if check.path == use.path:
            return clears(why, check.index, use.index)
        if use.path[:len(check.path)] == check.path:
            return clears(why, check.index, use.path[len(check.path)][0])
        return False
    return clears(why, check, use)


def contextual(why, check, use):
    """Put a nested refusal in the local context of one candidate use."""
    if isinstance(check, Nested):
        if not isinstance(use, Nested) or use.path[:len(check.path)] != check.path:
            return _OTHER_SUBSTITUTION
        local_use = (use.index if check.path == use.path
                     else use.path[len(check.path)][0])
        return why.at_use(check.index, local_use) if hasattr(why, "at_use") else why
    return why.at_use(check, use) if hasattr(why, "at_use") else why
