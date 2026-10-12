#!/usr/bin/env python3
"""The words that may stand where a shell reads its options: its option slot.

Split out of `scripts/workflow_options.py` at that module's size (699 of its 700 lines; #2889), byte
for byte: the three readers of a word in the slot -- a value that may spell an option (`_value`,
`_VALUE`), a word that may still stand before the program (`_before_operand`, `_BARE`) and one that
may spell an option once expanded (`_may_spell_option`) -- and the two a second walk asks of such a
word (#2858): whether a quoted expansion is always exactly ONE word (`_one_word`, with its patterns
`_ONE_PARAMETER`, `_ONE_DEFAULT` and `_DEFAULT_PARAMETER`) and whether a word is written as itself
(`_literal`). `workflow_options` imports every name back under its own, and `workflow_programs`
re-exports the ones it did before, so nothing that read `workflow_options._value` or
`workflow_programs._before_operand` moved; this module imports nothing from either, so the layers
still run one way: the reader below it, the option grammar and its walks above.

Since #2889 a word here may be read for what an expansion makes of it: a tilde alone is a value
(`_TILDE`, read BESIDE `main`'s reading of it, `_reopened`), and a word after an option word that
holds an expansion may be the NAME that word owes (`_may_be_name`, which asks the word what is
written in it, `workflow_option_words`). Each asks the rule first (`ruled`): with it off, a tilde
is the operand it was and no word is a NAME.

Stdlib only, like everything under it.
"""
import re

import shell_reader
from workflow_option_words import lifted, ruled, written


# The quoted forms proven to be exactly one word (#2858 round 8, an allowlist): text, `"$X"`,
# `"${X}"`, `"$1"`, `"$*"`, `"${A[*]}"`, `"$#"` and kin, and `"${X:-…}"`/`"${X:=…}"` whose default
# is text or such a `$Y`. Anything else -- `@`, `${!X}` (with `X=@`, `"$@"`), `${#X}`, `${X%…}` -- is not.
# Read by a scan, one token at a time, not one regular expression: a `$NAME` beside text could be
# split two ways there, and a failing match backtracked exponentially (CodeQL).
_ONE_PARAMETER = re.compile(r"\$(?:[A-Za-z_]\w*|[0-9#?$*!-])|\$\{(?:[A-Za-z_]\w*(?:\[\*\])?|[0-9]+|[*#?])\}")
_ONE_DEFAULT = re.compile(r"\$\{[A-Za-z_]\w*:?[-=]")
_DEFAULT_PARAMETER = re.compile(r"\$[A-Za-z_]\w*|\$\{[A-Za-z_]\w*\}")


def _one_word(word):
    """Whether `word` is a quoted expansion that is always exactly ONE word (#2858 rounds 7-8): every
    `$` of it quoted (`shell_reader.kept`) and nothing in it but the forms the allowlist above names.
    `"$@"`, `"${A[@]}"` and `"${!X}"` may be no word or several, and an unknown form is read as they
    are: as an expansion like `$X` (`bash --rcfile "$@" -nor -c P` runs `P` with no parameters)."""
    if not getattr(word, "kept", False):
        return False
    text, at = str(word), 0
    while at < len(text):
        if text[at] not in "$`\\":
            at += 1
            continue
        found = _ONE_PARAMETER.match(text, at) if text[at] == "$" else None
        if found:
            at = found.end()
            continue
        found = _ONE_DEFAULT.match(text, at) if text[at] == "$" else None
        if not found:
            return False
        at = found.end()
        while at < len(text) and text[at] != "}":   # the default: text or a plain `$Y`
            if text[at] in "`\\{!@":
                return False
            found = _DEFAULT_PARAMETER.match(text, at) if text[at] == "$" else None
            if text[at] == "$" and not found:
                return False
            at = found.end() if found else at + 1
        if at >= len(text):
            return False
        at += 1
    return True


def _literal(word):
    """Whether `word` is written as itself, with nothing in it a shell expands (#2858 round 9): a
    plain `str`, which the reader leaves only for text no pattern, brace or lifted
    substitution reaches -- it types an unquoted `*`, `?`, `[x]`, `{a,b}` or `@(x)` as `Rewritten`
    (`/nonexistent*` may vanish under `nullglob`), and `"*"` or `\\*` as the plain `*` they are --
    holding no `$` or backquote it could not lift (`${X:-${Y}}`, nested, stays plain) and not
    beginning with a `~`, which it leaves plain quoted or not (`HOME=-i; bash ~`). Such a `-o` value
    outside the name table is a refusal whether it is a misspelt name or no name at all (`-`,
    `/dev/stdin`: both bashes answer `invalid option name` and exit 2, #2606)."""
    return type(word) is str and "$" not in word and "`" not in word and word[:1] != "~"


# A word bash expands, where a shell reads its options, that may spell one (#2344): past the
# `$NAME`, `${...}` or `$(...)` it begins with, nothing but letters -- `$X`, `"${X:--c}"`,
# `$(echo -c)`, `${X}c`, not `$X/x.sh` -- a `$'…'` beginning with an unknown or non-ASCII escape
# that `shell_quote.ansi_c` cannot spell, such as `$'\q'` or `$'\u00e9'`, or a word xargs puts a
# line of its input in (`{}`).
_VALUE = re.compile(r"(?:\$(?:\{[^{}]*\}|\w+|\(\.\.\.\)|[^\w{(\\]))+[A-Za-z]*|\$\\.*", re.S)


# A tilde alone (#2889): bash and dash write `$HOME` for `~`, and bash `$PWD`, `$OLDPWD` and a
# directory of its stack for `~+`, `~-` and `~1` -- ONE word, whatever the variable holds, so where
# a shell reads its options it is a value as `$X` is: `HOME=-c; sh ~ 'P'` runs `P`, and
# `HOME=sh; ~ -c 'P'` does. Not `~/x` or `~user`, a path: no shell takes a cluster holding a `/`.
# The reader hands a quoted `"~"` on as the same word, so that one is read as a value too.
_TILDE = re.compile(r"~[+-]?[0-9]*")


def _value(word):
    """Whether `word` is such a value, or a tilde alone (`_TILDE`); a pattern is `leads`'s to read."""
    if isinstance(word, shell_reader.Rewritten):
        return getattr(word, "lead", None) is None
    return bool(_VALUE.fullmatch(shell_reader.readable(word))) or ruled(_TILDE.fullmatch(word))


# The letters an option's value is spelled with, as every `-o` or `-O` name of
# bash, dash, zsh and ksh is: letters, digits, `_` and `-` (#2484).
_BARE = re.compile(r"[A-Za-z0-9_-]+")


def _before_operand(word, tilde=False):
    """Whether `word`, after a value in a shell's options, may still stand
    before its program: an option word (`-…`, `+…`, `-`, `--`), an option's
    value (`_BARE`), or a word bash expands -- a `$`, a lifted substitution,
    a pattern (`shell_reader.dynamic`) -- which may vanish or be either. A tilde alone is such a
    word where `tilde` (#2889), and the operand `main` read it as where not."""
    return (word[:1] in ("-", "+") or bool(_BARE.fullmatch(word)) or tilde and ruled(_TILDE.fullmatch(word))
            or shell_reader.dynamic(word, shell_reader.has_substitution))


def _may_spell_option(word, tilde=False):
    """Whether `word`, PAST the first operand, may be an option word once it is expanded: a word
    bash expands (`shell_reader.dynamic`) that begins with `-`, a `$` or a lifted substitution, or a
    pattern or an `xargs -I` replacement (`Rewritten`). One that begins with literal text of its own
    (`x$Y`, `echo $Y`) is none. A tilde alone is one where `tilde` (#2889)."""
    return tilde and ruled(_TILDE.fullmatch(word)) or shell_reader.dynamic(word, shell_reader.has_substitution) and (
        shell_reader.readable(word)[:1] in ("-", "$") or isinstance(word, shell_reader.Rewritten))


def _reopened(rest):
    """The words after a value that may be the program (#2344, #2484): up to the FIRST OPERAND, and
    every word after a later one that may spell an option. Read twice since #2889, once with a
    tilde alone the operand `main` read it as and once with it the value it is, the second BESIDE
    the first: `X=-x; HOME=-c; sh $X ~ 'P'` runs `P`, which only the second weighs, and where the
    first operand moves a word only the first weighed is weighed still. A word is kept by its
    PLACE, so `main`'s words stand first and exactly as it handed them on."""
    places: dict = {}
    for tilde in (False, True):
        end = next((k for k, after in enumerate(rest, 1) if not _before_operand(after, tilde)), len(rest))
        more = next((k for k in range(end, len(rest)) if _may_spell_option(rest[k], tilde)), len(rest))
        places.update(dict.fromkeys([*range(end), *range(more + 1, len(rest))]))
    return [rest[place] for place in places]


def _may_be_name(word):
    """Whether `word` may be the NAME an `o` or `O` takes (#2889): letters, digits, `_` and `-`, as
    every such name of bash, dash, zsh and ksh is (`_BARE`), beside whatever an expansion in it
    prints (`err$X`, `$N`) -- and never an option word, which no shell takes for a name. No table
    is asked: bash's `-O` takes a shopt name and zsh's `-o` one of its own, and both lists move
    with the version, so a word shaped as a name may be one."""
    text = written(word)
    return ruled(word[:1] not in ("-", "+") and (_BARE.fullmatch(text) or not text and lifted(word)))
