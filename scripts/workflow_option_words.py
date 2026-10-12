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

That rule has ONE switch, and it is here (`ruled`). Every reader the rule changed asks it before
it answers by the rule, so with it off (`as_before`) each of them answers word for word as `main`
did -- wherever `main` answers at all: its search for a cluster called itself once a word and ran
out of stack past a thousand of them, where the loop that stands for it answers; and an answer the
rule gave is noted, so a caller can read BOTH ways wherever one was given and neither where none
was (`beside`). The guard does, for the whole job: what `main` reported is
reported still, whatever a reader makes of the words the rule finds.

Below every reader that asks it: it reads the word it is handed and those two patterns of
`shell_tokens`, and nothing else.
"""

import contextlib
import contextvars
import re

import shell_tokens

# Set while the readers answer as they did before the rule (`as_before`), and the note of the
# reading in hand: whether the rule has answered in it (`ruled`, `beside`).
_OFF: contextvars.ContextVar[bool] = contextvars.ContextVar("as_before", default=False)
_HEARD: contextvars.ContextVar[list | None] = contextvars.ContextVar("heard", default=None)


@contextlib.contextmanager
def as_before():
    """While this holds, the rule answers nothing (`ruled`): a word holds no reference, owes no
    NAME, a tilde is the operand `main` read it as and no `wget` may stream -- every reader as
    `main` had it."""
    token = _OFF.set(True)
    try:
        yield
    finally:
        _OFF.reset(token)


def ruled(answer=True):
    """Whether the rule answers here: `answer`, and never while `as_before` holds. A reader asks
    EVERY answer it owes the rule through this and reads the switch nowhere else, so where this
    was never true a reading is, step for step, the one it is with the rule off; and where it was,
    the reading in hand is told (`beside`)."""
    if _OFF.get() or not answer:
        return False
    heard = _HEARD.get()
    if heard is not None:
        heard[0] = True
    return True


def beside(read, refused=()):
    """(`read()` as `main` answers it, `read()` under the rule): the SAME object twice where the
    rule answered nothing in it, since that reading is `main`'s; else `read()` once more with the
    rule off (`as_before`), for a caller to keep `main`'s answer first and whole and the rule's
    beside it. A reading inside another tells that one what it heard. Where the rule's reading
    raises an error of `refused`'s kind, `main`'s reading alone is the answer, twice: what the rule
    alone reads may be text a reader refuses, which `main`'s reading never met (a reading that
    raises it with the rule off too raises it still)."""
    if _OFF.get():
        found = read()
        return found, found
    outer = _HEARD.get()
    heard: list[bool | None] = [False]           # None: the rule's reading was refused
    token = _HEARD.set(heard)
    try:
        found = read()
    except refused:
        found = heard[0] = None
    finally:
        _HEARD.reset(token)
    if heard[0] is False:
        return found, found
    if outer is not None:
        outer[0] = True
    with as_before():
        mains = read()
    return mains, (mains if heard[0] is None else found)


# The characters of a parameter's NAME: ASCII letters and `_`, and digits after the first.
_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_"

# A length or a count, which prints digits alone: `${#}`, `${#X}`, `${#X[1]}`, `${#1}`, `${#@}`,
# `${#?}`. Any other `${#...}` is the count `$#` under an operator, and prints the operator's
# word: `${#+c}` is `c`.
_LENGTH = re.compile(r"\$\{#(?:[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]{}]*\])?|[0-9]+|[@*#?$!-])?\}")


def _references(text):
    """Where each parameter reference stands in `text`: (start, end) pairs. `$NAME`, `$1`, `$@`,
    `$*` and `$-`; `${...}` to its closing brace, a `${` nested in it counted and a bare `{` not,
    which closes nothing (`${X:-{}` ends at its one `}`); a `$` and a backslash to the word's end.
    None for a `$` that begins no expansion (`-e$`) or one that prints digits alone (`$#`, `$?`,
    `$$`, `$!`, and a length, `_LENGTH`)."""
    at = text.find("$")
    while at >= 0:
        end, after = at + 1, text[at + 1:at + 2]
        if after == "{" and not _LENGTH.match(text, at):
            depth = 0
            while end < len(text):
                depth += (text[end - 1:end + 1] == "${") - (text[end] == "}")
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
    """Where each marker and, by the rule (`ruled`), each parameter reference stands in `word`:
    (start, end) pairs, in order. A marker may stand INSIDE a reference (`${X:-$(...)}`)."""
    text, own = str(word), getattr(word, "markers", None)
    references = list(_references(text)) if "$" in text else []
    if not own and "@@" not in text and not references:
        return []
    spans = set(references) if ruled(references) else set()
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
        at = max(at, end)                       # one inside another ends no later than it
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
