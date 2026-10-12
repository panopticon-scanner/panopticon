#!/usr/bin/env python3
"""What an option word spells, and what it only holds (#3020, #3023, #2889).

A reader that asks an option word for a letter reads the word's TEXT. A lifted substitution stands
in that text as a marker of the parse, `@@shell-<hex>-N@@` (`shell_tokens._Parse`): its hex is
drawn at random for every parse, and its fixed text spells `s`, `h`, `e` and `l`. Read for letters,
`sh -$(echo c) 'P'` was a `-c` only where the hex held a `c`, and `curl -fsSL$(true) URL | sh` was
`curl -h`, which fetches nothing. So a reader asks the word here: `written`, the word without
what was lifted out of it; `lifted`, whether it holds lifted text at all, or where a letter would
be read; and `spells`, whether a letter is written in it or may be printed into it.

A marker is known two ways. The word a parse hands back carries its own (`_Token.markers`). A
word of a text read AGAIN carries none: `echo "sh -$(echo c) 'P'" | sh` hands the guard a text
the first parse's marker stands in, opaque (`workflow_forms._weighed`, #2482), and the parse of
that text hands back plain words. There the marker is known as `shell_tokens._keyed` knows one
(#2929): by its shape (`_MARK`) and by the nonce this process alone mints (`_NONCE`), which no
text of the target's holds but by chance -- so text the target wrote in a marker's shape stays
its text.

A parameter reference is text the word does not write either (#2889): `X=c; sh -$X 'P'` runs
`P`, and `sh -$cmd` writes no `c`, whatever its name's letters are. So `$NAME`, `${...}`, a
positional `$1`, the set `$@` or `$*` and the flags `$-` stand in a word as a marker does, and
every answer here holds for them: what such a reference prints may be any letter, or none. Not
the four that print digits alone -- the count `$#`, the status `$?`, the process ids `$$` and `$!`
-- nor a length, `${#X}`: a digit spells no option's letter, so those stay written, as `main`
read them. An ANSI-C word no text spells reaches a reader as a `$`, a backslash and what was
written after them (`shell_quote.ansi_c`): to the word's end it is such a reference too.

Below every reader that asks it: it reads the word it is handed and those two patterns of
`shell_tokens`, and nothing else.
"""

import shell_tokens

# The characters of a parameter's NAME: ASCII letters and `_`, and digits after the first.
_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_"


def _references(text):
    """Where each parameter reference stands in `text`: (start, end) pairs. `$NAME`, `$1`, `$@`,
    `$*` and `$-`; `${...}` to its closing brace, a nested one counted; a `$` and a backslash to
    the word's end. None for a `$` that begins no expansion (`-e$`) or one that prints digits
    alone (`$#`, `$?`, `$$`, `$!`, `${#X}`)."""
    at = text.find("$")
    while at >= 0:
        end, after = at + 1, text[at + 1:at + 2]
        if after == "{" and text[at + 2:at + 3] != "#":
            depth = 0
            while end < len(text):
                depth += (text[end] == "{") - (text[end] == "}")
                end += 1
                if not depth:
                    break
        elif after and after in _LETTERS:
            while end < len(text) and text[end] in _LETTERS + "0123456789":
                end += 1
        elif after == "\\":
            end = len(text)
        elif after and after in "0123456789@*-":
            end += 1
        if end > at + 1:
            yield at, end
        at = text.find("$", max(end, at + 2))


def _spans(word):
    """Where each marker and each parameter reference stands in `word`: (start, end) pairs, in
    order."""
    text, own = str(word), getattr(word, "markers", None)
    if not own and "@@" not in text and "$" not in text:
        return []
    spans = set(_references(text))
    for key in own or ():
        at = 0
        for before in text.split(key)[:-1]:
            spans.add((at + len(before), at + len(before) + len(key)))
            at += len(before) + len(key)
    for found in shell_tokens._MARK.finditer(text):
        if shell_tokens._NONCE.match(found.group()):
            spans.add(found.span())
    return sorted(spans)


def before(word):
    """`word`'s text up to the first marker or reference in it: what is written where no expansion
    can move it. A letter after one stands wherever what the expansion prints puts it."""
    spans = _spans(word)
    return str(word)[:spans[0][0]] if spans else str(word)


def written(word):
    """`word` as it is WRITTEN: its text with every marker and every reference in it out."""
    text, kept, at = str(word), [], 0
    for start, end in _spans(word):
        kept.append(text[at:start])
        at = end
    return "".join(kept) + text[at:]


def lifted(word, start=0, end=None):
    """Whether lifted text -- a `$(...)`, a backquote, a `<(...)` -- or a parameter reference
    begins in `word`, anywhere or from `start` up to `end`: what the shell prints there may be any
    letter, or none."""
    return any(start <= at and (end is None or at < end) for at, _end in _spans(word))


def spells(word, letter):
    """Whether the option word `word` may carry `letter`: it is written in it, or the word holds
    lifted text or a reference, which may print it."""
    return letter in written(word) or lifted(word)
