#!/usr/bin/env python3
"""Which characters of a shell word bash expands as a pattern (#2294).

Split out of `scripts/shell_lex.py` (#1793's follow-ups, re-review of round
one), whose room the next readings of `lex` need: this module holds the marks
and what a marked word says, the lexer the text bash reads them in.

Bash expands an unquoted brace (`{sh,-c}`, `{a..b}`) or pathname pattern
(`*`, `?`, `[...]`) into any number of words before a command sees them.
`patterned` marks each such character no quote or backslash covers, before
`shell_reader` splits a stage into words, and `is_pattern` asks a word split
out of it whether bash expands it -- `leads`, whether into one a shell reads
as an option, of the words `shell_words` says a shell looks for one in
(re-review N-C). What never becomes a command's words is kept unmarked where
it is read: `lex` escapes each character `patterned` would mark inside an
arithmetic command, a conditional's `[[ ... ]]` and an array literal
(re-review I-5), and `patterned` passes a `${...}` through.

Stdlib only.
"""
import re


# Put before each character of a brace or pathname pattern that no quote or
# backslash covers (`patterned`), and before an extglob group's `@`, `+` or
# `!` (`shell_lex.lex`): bash expands such a word into any number of words
# before a command sees it (#2294), and a word split out of the text after
# its quotes are gone still says so (`is_pattern`).
MARK = "\ue000"             # a private-use character
GLOB = "*?[{},"             # the characters it goes before
# Put before each quote or backslash inside a marked `[...]` (`patterned`):
# with the quotes gone, `leads` must not read `[a'-'c]` as the range `[a-c]`.
QUOTED = "\ue001"
# Put before each `$` a quote or a backslash covers (`patterned`): with the
# quotes gone, `shell_reader._stage` must still tell `"$SUDO"`, a word bash
# keeps empty, from `$SUDO`, one it drops (#2472).
QUOTED_DOLLAR = "\ue003"
# The members of a `[...]` that matches no `-`: letters, digits, `_` and `.`,
# and ranges between two letters or digits (`leads`).
_PLAIN = re.compile(r"(?:[A-Za-z0-9](?:-[A-Za-z0-9])?|[_.])+")
# The `$...` and `${...}` a word begins with, each of which may be empty; the
# reader hands `leads` a substitution it lifted as `${}`.
_HEAD = re.compile(r"^(?:\$(?:\{[^{}]*\}|\w+|[^\w{%s]))*" % MARK)


def patterned(text: str) -> str:
    """`text` with `MARK` before each `*`, `?`, `[`, `{`, `}` and `,` outside
    quotes, read as `shell_lex.closing` reads them -- but none inside a
    `${...}`, whose characters are the expansion's own (`${x#*/}`, `${a[1]}`:
    review N-1 of #1793's follow-ups), and not the `[` right after a `$` no
    backslash takes, which opens `$[...]`. An arithmetic command's reach here
    escaped (`shell_lex.lex`), and a `$((...))` lifted. `QUOTED` goes before
    each quote or backslash inside a marked `[...]`, `QUOTED_DOLLAR` before
    each `$` a quote or a backslash covers (#2472)."""
    out, i, quote, dollar, bracket = [], 0, "", -2, -1
    while i < len(text):
        ch = text[i]
        end = not quote and text.startswith("${", i) and _expansion_end(text, i + 2)
        if end:
            out.append(text[i:end])
            i = end
            continue
        size = 2 if ch == "\\" and quote != "'" or not quote and text.startswith("$'", i) else 1
        if bracket >= 0 and (size == 2 or not quote and ch in "'\""):
            out.append(QUOTED)
        if quote and ch == "$" or size == 2 and text.startswith("\\$", i):
            out.append(QUOTED_DOLLAR)
        if quote and size == 1 and ch == quote[-1]:
            quote = ""
        elif not quote and (ch in "'\"" or ch == "$" and size == 2):
            quote = text[i:i + size]
        elif not quote and ch in GLOB and not (ch in "[{" and dollar == i - 1):
            out.append(MARK)
            if ch == "[" and bracket < 0:   # its members start here, and a `]` first is one
                bracket = i + 1 + text.startswith(("!", "^"), i + 1)
        elif not quote and (ch == "]" and bracket >= 0 and i > bracket or ch.isspace()):
            bracket = -1
        dollar = i if not quote and ch == "$" else dollar
        out.append(text[i:i + size])
        i += size
    return "".join(out)


def _expansion_end(text: str, i: int) -> int | None:
    """Index just past the `}` ending the `${` whose body starts at `i`, read
    as bash reads it: quotes and a backslash hold theirs, a `${` nests, and any
    other `}` ends it -- a bare `{` opens nothing, so `${x:-{a}b}` is `{ab}`.
    None if nothing ends it, and then `patterned` marks it as before."""
    depth, quote = 1, ""
    while i < len(text):
        ch = text[i]
        if ch == "\\" and quote != "'":
            i += 2
            continue
        if quote:
            quote = "" if ch == quote[-1] else quote
        elif text.startswith("$'", i):
            quote, i = "$'", i + 1
        elif ch in "'\"":
            quote = ch
        elif text.startswith("${", i):
            depth, i = depth + 1, i + 1
        elif ch == "}":
            depth -= 1
            if not depth:
                return i + 1
        i += 1
    return None


def leads(word: str) -> bool:
    """Whether a word `patterned` marked may expand to one beginning with
    `-`, which a shell reads as an option (review N-3): past the `_HEAD` it
    may begin with (`sh $X{-c,…}`), it begins with `-`, or with a marked `*`,
    `?`, `{` or extglob group, or with a marked `[...]` not all `_PLAIN` --
    negated, a class, a `$`, a `-` of its own, anything quoted or marked in
    it -- so never `[a-c]*.sh` (re-review N-C of #1793's follow-ups). What
    such a head holds is a value the guard does not follow, in `sh $X/*.sh`
    as in `sh $X`; where it is the whole word, the words after it are read
    as programs it may make (`workflow_programs.candidates`, #2344)."""
    word = _HEAD.sub("", word, count=1)
    if word.startswith("-"):
        return True
    if not word.startswith(MARK):
        return False
    if not word.startswith(MARK + "["):
        return True
    end = word.find("]", 3)                 # a `]` first in it is a member
    return not _PLAIN.fullmatch(word[2:end] if end > 2 else "")


def shell_words(argv: list[str]) -> list[str]:
    """The words of a shell's argv a pattern may turn into `-c` and its
    script (review N-3): its options, their values -- one for each `o` or `O`
    in a short option word, so `-eo pipefail` as `-o pipefail` (#2344) --
    and the first word that is neither, its program; none after `--`, which
    ends its options."""
    words, owed = [], 0
    for word in argv[1:]:
        if word == "--":
            break
        words.append(word)
        if owed:
            owed -= 1
        elif word.startswith(("-", "+")):
            owed = 0 if word[:2] == "--" else sum(letter in "oO" for letter in word[1:])
        else:
            break
    return words


def is_pattern(word: str) -> bool:
    """Whether a word `patterned` marked is one bash expands: a marked `*`,
    `?` or extglob group, a marked `[` with a `]` after it, or a marked `{`
    with a marked `}` after it and a marked `,` or a `..` between. From the
    first `{` to the last `}`, so a word it misreads is one bash may not
    expand, never the other way round."""
    if any(MARK + ch in word for ch in "*?@+!"):
        return True
    at = word.find(MARK + "[")
    if at >= 0 and "]" in word[at:]:
        return True
    at, end = word.find(MARK + "{"), word.rfind(MARK + "}")
    return 0 <= at < end and (MARK + "," in word[at:end] or ".." in word[at:end])
