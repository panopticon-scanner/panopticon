#!/usr/bin/env python3
"""What an option word spells, and what it only holds (#3020, #3023).

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

Below every reader that asks it: it reads the word it is handed and those two patterns of
`shell_tokens`, and nothing else.
"""

import shell_tokens


def _spans(word):
    """Where each marker stands in `word`: (start, end) pairs, in order."""
    text, own = str(word), getattr(word, "markers", None)
    if not own and "@@" not in text:
        return []
    spans = set()
    for key in own or ():
        at = 0
        for before in text.split(key)[:-1]:
            spans.add((at + len(before), at + len(before) + len(key)))
            at += len(before) + len(key)
    for found in shell_tokens._MARK.finditer(text):
        if shell_tokens._NONCE.match(found.group()):
            spans.add(found.span())
    return sorted(spans)


def written(word):
    """`word` as it is WRITTEN: its text with every marker in it out."""
    text, kept, at = str(word), [], 0
    for start, end in _spans(word):
        kept.append(text[at:start])
        at = end
    return "".join(kept) + text[at:]


def lifted(word, start=0, end=None):
    """Whether lifted text -- a `$(...)`, a backquote, a `<(...)` -- begins in `word`, anywhere or
    from `start` up to `end`: what the shell prints there may be any letter, or none."""
    return any(start <= at and (end is None or at < end) for at, _end in _spans(word))


def spells(word, letter):
    """Whether the option word `word` may carry `letter`: it is written in it, or the word holds
    lifted text, which may print it."""
    return letter in written(word) or lifted(word)
