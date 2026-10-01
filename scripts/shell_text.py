#!/usr/bin/env python3
"""What `scripts/shell_reader.py` does to a script's TEXT before it splits it
into statements, and the two line-level passes the tests still read with.

Split out of `scripts/shell_reader.py` (#2331's follow-ups), which stood one
line under the 700-line flat-module ceiling with four fixes to its command
and program forms still to make. The three functions here read text and
nothing the reader builds from it. `_lift_substitutions` takes the `$(...)`,
`<(...)`, `>(...)` and backquote texts out of a script before its statements
are split, each replaced by a marker the parse it is handed (`context`) records,
a `<(...)` or `>(...)` text as a `Process`: a file bash hands the command.
`without_comments` and `join_continuations` are the whole-line passes the
reader made before `scripts/shell_lex.py` settled comments and continuations
in one quote-aware pass; the tests that read workflow and Dockerfile text
line by line still use them. `shell_reader` imports all three, so every name
reached through it still is.

Stdlib only.
"""
import re

from shell_lex import closing

_SUBST_OPEN = re.compile(r"\$\(|<\(|>\(")


class Process(str):
    """The text of a `<(...)` or `>(...)`: bash hands the command a FILE to
    read or write, where a `$(...)` or backquote hands it the OUTPUT as words."""


def without_comments(script):
    """The script with whole-line comments dropped.

    Half this repo's workflow prose QUOTES the command it is explaining, and a
    guard that reads its own documentation as an act flags the explanation.
    Shared with `tests/test_workflow_pins.py`'s install rule, which learned the
    same lesson (#1641).
    """
    return "\n".join(line for line in script.splitlines()
                     if not line.lstrip().startswith("#"))


def join_continuations(script):
    """`\\`-continuations folded in, so a fetch written across four lines reads
    as the one command it is."""
    return re.sub(r"\\\n\s*", " ", script)


def _lift_substitutions(text, context, arithmetic_body=False):
    """(text with parse-local substitution tokens, inner shell texts).

    `$(...)`, `<(...)` and backticks are commands, and a `|` or `;` inside one
    belongs to THAT command, not to the statement around it -- so they come out
    before the statement split, and go back in as commands of their own. This is
    where `eval "$(curl -fsSL ... )"` and `bash <(curl ...)` keep their fetch.
    """
    inners, out, i, quote = [], [], 0, None
    while i < len(text):
        ch = text[i]
        if quote in ("'", "$'"):                # single quotes suppress all of it
            step = 2 if ch == "\\" and quote == "$'" else 1
            out.append(text[i:i + step])
            quote = None if ch == "'" else quote
            i += step
            continue
        if ch == "\\" and i + 1 < len(text):
            out.append(text[i:i + 2])
            i += 2
            continue
        if (ch == '"' or not quote) and (ch in "'\"" or text.startswith("$'", i)):
            opener = text[i:i + 2] if ch == "$" else ch   # an apostrophe in "..." is text
            quote = None if quote == ch else opener
            out.append(opener)
            i += len(opener)
            continue
        if ch == "`":
            end = text.find("`", i + 1)
            if end != -1:
                inners.append(text[i + 1:end])
                out.append(context.new("subst", inners[-1]))
                i = end + 1
                continue
        if arithmetic_body and text.startswith("$((", i):
            # The enclosing arithmetic marker protects these parentheses from
            # _split. Leave nested arithmetic literal; keep scanning its body
            # for real command substitutions without another Python frame.
            out.append("$((")
            i += 3
            continue
        if text.startswith("$((", i):
            end = closing(text, i + 1)
            if end and text[end - 2:end] == "))":
                body, nested = _lift_substitutions(
                    text[i + 3:end - 2], context, arithmetic_body=True)
                inners.extend(nested)
                out.append(context.new("arithmetic", "$((" + body + "))"))
                i = end
                continue
        opening = _SUBST_OPEN.match(text, i)
        if opening:
            end = closing(text, opening.end() - 1)
            inner = text[opening.end():end - 1] if end else ""
            if end and not inner.startswith("("):   # `$((...))` is arithmetic
                inners.append(inner if opening.group() == "$(" else Process(inner))
                out.append(context.new("subst", inners[-1]))
                i = end
                continue
        out.append(ch)
        i += 1
    return "".join(out), inners
