#!/usr/bin/env python3
"""Quote-aware shell words shared by the lexer and reader.

The helpers here are pure functions of text and an index. They spell heredoc
delimiters, exact here-string words, and Bash's ASCII ANSI-C quoting without
holding any lexer state. Stdlib only.
"""
import re

# bash's metacharacters: a word ends at any of them, and a `#` right after one
# begins a comment.
_BREAK = " \t\n;&|()<>"
# A quoted part of a heredoc's delimiter word, and the escapes "..." removes.
_QUOTED = re.compile(r"'([^']*)'|\$'((?:[^'\\]|\\.)*)'|\$?\"((?:[^\"\\]|\\.)*)\"",
                     re.S)
_DQ_ESCAPE = re.compile(r'\\([$`"\\])|\\\n')
# What bash has to PARSE, not just unquote, to spell a delimiter: a `$(`,
# `${`, `$[` or backquote in the word, or an escape `$'...'` decodes (`\x41`).
_PARSED = re.compile(r"`|\$[({\[]")
_ANSI_SIMPLE = dict(zip("abefnrtv\\'\"?E", "\a\b\x1b\f\n\r\t\v\\'\"?\x1b"))
_ANSI_ESCAPE = re.compile(
    r"\\(?:([abefnrtv\\'\"?E])|([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|"
    r"u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|c(.)|\n|(.)|(\Z))", re.S)


def ansi_c(body: str) -> str | None:
    """Bash's ASCII text for `$'body'`; None for an unknown escape (#2470)."""
    stopped = unknown = False

    def decoded(match: re.Match[str]) -> str:
        nonlocal stopped, unknown
        if stopped:
            return ""
        simple, octal, hexa, short, long, control, other, ended = match.groups()
        if simple is not None:
            return _ANSI_SIMPLE[simple]
        if other is not None or ended is not None:
            unknown = True
            return ""
        if control is not None:
            if not control.isascii():
                raise Unreadable("an ANSI-C escape decodes outside ASCII")
            value = 127 if control == "?" else ord(control.upper()) & 31
        else:
            digits = octal or hexa or short or long
            if digits is None:               # A backslash-newline is gone.
                return ""
            value = int(digits, 8 if octal is not None else 16)
        if value > 127:
            raise Unreadable("an ANSI-C escape decodes outside ASCII")
        stopped = not value                # Bash truncates this quoted part at NUL.
        return chr(value)
    text = _ANSI_ESCAPE.sub(decoded, body).partition("\0")[0]
    return None if unknown else text


class Unreadable(Exception):
    """A script `lex` does not read: it nests `((` so deep that deciding each
    one, as bash does, would read it more than `_REREAD` times over, a
    substitution closes over a heredoc or queues one after an `EOF)`, a case
    arm cannot be attributed, or a heredoc delimiter needs a shell parse.
    `workflow_guard.job_defects` reports its step."""


def _word(text: str, i: int) -> tuple[str, bool, int] | int | None:
    """(delimiter, quoted, end) for the heredoc word after an operator ending
    at `i`: the word as bash compares lines with it -- quotes removed, quoted
    if any part of it was. None when no word follows, a `#` there starts a
    comment, or a quote in it never closes. Where the word starts, when bash
    has to PARSE it to spell it (`_PARSED`, or the `(` of an extglob pattern
    after it)."""
    while text.startswith((" ", "\t", "\\\n"), i):  # a `\`-newline: gone, as in code
        i += 2 if text[i] == "\\" else 1
    start, quoted = i, False
    parts: list[str] = []
    while i < len(text) and text[i] not in _BREAK:
        match = _QUOTED.match(text, i)
        if _PARSED.match(text, i) or (match and _PARSED.search(match[3] or "")):
            return start
        if match:
            single, ansi, double = match.groups()
            if single is not None:
                parts.append(single)
            elif ansi is not None:      # Bash's ASCII ANSI-C escapes
                if (decoded := ansi_c(ansi)) is None:
                    return start
                parts.append(decoded)
            else:
                parts.append(_DQ_ESCAPE.sub(lambda m: m[1] or "", double))
            quoted, i = True, match.end()
        elif text[i] in "'\"" or text.startswith(("$'", '$"'), i):
            return None
        elif text[i] == "\\":
            if not text.startswith("\n", i + 1):
                parts.append(text[i + 1:i + 2])
                quoted = True
            i += 2
        else:
            parts.append(text[i])
            i += 1
    if i == start or text[start] == "#":
        return None
    return start if text.startswith("(", i) else ("".join(parts), quoted, i)


def _string(text: str, i: int) -> tuple[str, int] | None:
    """(text, end) for the word after a `<<<` ending at `i` when bash hands
    it to the command as written (#2293): its quotes and escapes removed, and
    nothing left that bash expands -- no `$` or backquote outside '...' and
    $'...' that no backslash escapes, no unquoted `~`, no `$'...'` escape
    outside Bash's ASCII table, no `$"..."`. Glob and brace characters
    are text to it. None for an unquoted `[`, which may open a subscript, a
    word no quote closes, no word and a comment: those are read as code."""
    while text.startswith((" ", "\t", "\\\n"), i):
        i += 2 if text[i] == "\\" else 1
    start, parts = i, []
    while i < len(text) and text[i] not in _BREAK:
        match = _QUOTED.match(text, i)
        if match:
            single, ansi, double = match.groups()
            if single is not None:
                parts.append(single)
            elif ansi is not None and (decoded := ansi_c(ansi)) is not None:
                parts.append(decoded)
            elif (double is not None and match[0][0] == '"'
                  and not set("$`") & set(re.sub(r"\\.", "", double, flags=re.S))):
                parts.append(_DQ_ESCAPE.sub(lambda m: m[1] or "", double))
            else:
                return None
            i = match.end()
        elif text[i] in "$`~[\"'":
            return None
        else:
            parts.append(text[i + 1:i + 2].replace("\n", "") if text[i] == "\\" else text[i])
            i += 2 if text[i] == "\\" else 1
    if i == start or text[start] == "#" or text.startswith("(", i):
        return None
    return "".join(parts), i
