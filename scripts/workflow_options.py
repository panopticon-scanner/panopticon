#!/usr/bin/env python3
"""The option grammar a shell reads, and the words that may stand in its option slot.

Split out of `scripts/workflow_programs.py` at that module's 700-line ceiling (#2331's follow-ups),
byte for byte: the letter and name tables bash, dash and `set` take (`SET_OPTIONS`, `SHELL_OPTIONS`,
`VALUE_OPTIONS`, `SET_OPTION_NAMES`, `SHELL_OPTION_NAMES`, the shells measured to refuse a letter,
`_MEASURED_SHELLS`), the refusal readers over them (`_refused`, `_refused_name`) and the walk to the
operand after a `-c` cluster (`_past_options`), and the three readers of a word where a shell reads
its options -- a value that may spell one (`_value`), a word that may still stand before the program
(`_before_operand`) and one that may spell an option once expanded (`_may_spell_option`). A leaf:
it reads `shell_reader` and nothing above it. `workflow_programs` re-exports every name, so nothing
that imported one from there moved.

Stdlib only, like everything under it.
"""
import os
import re

import shell_reader


# The short option letters a shell takes, where it reads them: bash 5.2.21's `set` builtin (`set -eo
# pipefail`, `set +x`, `set -r`), and besides those a command line's own (`sh -c`, `bash -ilr`,
# `bash -D`, `bash -O extglob`, and the `-I`/`-V` dash takes where bash does not). A letter outside
# the table is one the shell REFUSES -- `set: -Z: invalid option`, rc 2 and no option changed; `sh
# -c -K P` exits before it reads `P` -- which is what `workflow_posture._errexit` and
# `_past_options` read it as (#2443, #2475). Measured, letter by letter, on bash 3.2.57, bash
# 5.2.21, dash, zsh 5.9 and ksh 93u+, each table is the fail-closed pick for the direction its
# reader takes. For the builtin, where an unknown letter means nothing was SET, bash 5.2.21's
# letters: that is bash 3.2.57's less the `i` and `I` which 5.2 refuses and SURVIVES, which would be
# the fail-open direction, and dash refuses more of them still but dies at the `set`, which runs
# nothing. For a command line, where it means nothing RUNS, the UNION over the shells that refuse at
# all -- and only those shells may be read that way, because zsh runs twenty of these letters and
# ksh runs `-G` (`_MEASURED_SHELLS`). Which take a VALUE: `-o name`, and bash's `-O shopt` on a
# command line.
SET_OPTIONS = "abefhkmnoprtuvxBCEHPT"
SHELL_OPTIONS = SET_OPTIONS + "cilsDOIV"
VALUE_OPTIONS = "oO"
# The shells whose command-line letters the comment above measured as REFUSED: `sh` (bash in sh mode
# on this box, dash on a runner), `bash` and `dash`. The other names of `_SHELL_STRING` are not here
# -- zsh runs `-K`, `-F`, `-S`, `-d`, `-g`, `-w`, `-y` and thirteen more, ksh runs `-G`, and `ash`
# could not be measured (this box has none) -- so for them an option word is read ON.
_MEASURED_SHELLS = ("sh", "bash", "dash")
# The option NAMES an `-o` takes, where a shell reads them: bash 5.2.21's `set -o` listing -- which
# is bash 3.2.57's, name for name -- and besides those the three dash prints that bash has no such
# option for. A name outside the table is one the shell REFUSES: `set: foo: invalid option name`,
# and on a command line `bash -c -o foo P` exits 2 before it reads `P`, which is what
# `workflow_posture._rejected` and `_refused_name` read it as (#2560). Measured on bash 3.2.57, bash
# 5.2.21 and dash, each table is the fail-closed pick for the direction its reader takes, as the
# letter tables are. For the BUILTIN, where a refused name means nothing was SET, bash's 27 alone:
# dash dies at such a `set`, so nothing runs there at all, and its own names would only add ones
# bash refuses. For a COMMAND LINE, where it means nothing RUNS, the UNION -- dash runs `-o stdin`,
# `-o interactive` and `-o debug`, which bash exits 2 on, and dash has no `pipefail`, which bash
# takes. `-O` takes a SHOPT name instead, a table this guard does not keep (`_refused_name`).
SET_OPTION_NAMES = ("allexport", "braceexpand", "emacs", "errexit", "errtrace", "functrace",
                    "hashall", "histexpand", "history", "ignoreeof", "interactive-comments",
                    "keyword", "monitor", "noclobber", "noexec", "noglob", "nolog", "notify",
                    "nounset", "onecmd", "physical", "pipefail", "posix", "privileged",
                    "verbose", "vi", "xtrace")
SHELL_OPTION_NAMES = SET_OPTION_NAMES + ("interactive", "stdin", "debug")


def _refused_name(argv, at):
    """Whether the shell `argv[0]` refuses the `-o` VALUE in the option word
    `argv[at]`, running nothing: a name outside `SHELL_OPTION_NAMES`, handed
    to a shell measured to refuse one at all (`sh -c -o foo P`, `sh -co foo
    P`, `+o foo`; `_MEASURED_SHELLS`, as `_refused` reads a letter).

    One value per `o` or `O` letter, as `_past_options` counts them, and only an `o`'s is a `set -o`
    name: `-O` takes a shopt name, and a table of those is not kept here. A value that is not all
    letters -- bar the hyphen of `interactive-comments` -- is read ON and fail-closed, as an option
    word that is not all letters is: `sh -c -o $X P` runs `P` wherever `X` holds a name the shell
    takes, and `${X:-pipefail}` is one spelling of that."""
    if type(argv[0]) is not str or os.path.basename(argv[0]) not in _MEASURED_SHELLS:
        return False
    value = at
    for letter in argv[at][1:]:
        value += letter in VALUE_OPTIONS
        if letter == "o" and value < len(argv) and argv[value].replace("-", "").isalpha():
            if argv[value] not in SHELL_OPTION_NAMES:
                return True
    return False


def _refused(argv, at):
    """Whether the shell `argv[0]` refuses the option word `argv[at]`
    outright, running nothing: a cluster of LETTERS with one outside
    `SHELL_OPTIONS`, handed to a shell that refuses such a letter at all
    (`sh -c -K P`, `sh -cK P`, `+Z`; `_MEASURED_SHELLS`).

    False for every other command word, which the walk then reads ON as it did before #2475: zsh and
    ksh, which RUN letters bash refuses, the unmeasured `ash`, and any word not WRITTEN as that name
    -- a `$X`, a lifted `$(echo sh)`, a pattern, or a `${X:-sh}` default read as the shell it spells
    (`shell_wrappers.Defaulted`, #2337), every one of which is a `str` SUBCLASS here. The program
    such a command word is handed is #2337/#2344's own report, and a letter table cannot overrule
    it, because `X` may hold `zsh`.

    A word that is not all letters is read on too, and fail-closed: bash,
    dash and ksh refuse a digit or a brace (`-1`, `-I{}`, `-nw5`) but zsh
    RUNS `-1`, and all five run the program after `sh -c -u$X P` wherever
    `X` is empty, so a word holding an expansion is never a refusal."""
    if type(argv[0]) is not str or os.path.basename(argv[0]) not in _MEASURED_SHELLS:
        return False                            # a `str` subclass is a name not written
    letters = argv[at][1:]
    return letters.isalpha() and any(letter not in SHELL_OPTIONS for letter in letters)


def _past_options(argv, at):
    """The first operand after `argv[at]`, the cluster that carries `-c`.

    Bash and dash read on through the option words after `-c` (#2332): `sh -c -e P`, `bash -c -x P`
    and `sh -c +x P` all run `P`. Each `o` or `O` in a word takes the next word as its value (`-c -o
    pipefail P`, `-co pipefail P`); a `-` or `--` ends the options, and the word after it is the
    program even if it begins with `-`; a `--long` word after `-c` is one both shells refuse, and
    nothing runs. So is a word of letters one of which the shell in hand refuses (`sh -c -K P`, `sh
    -cK P`, `_refused`): it exits before it reads `P`, so no program is handed over (#2475), and an
    `-o` whose value is no option NAME is one too (`_refused_name`, #2560).
    """
    while True:
        if _refused(argv, at) or _refused_name(argv, at):
            return []                           # the shell exits before the program
        at += 1 + sum(letter in VALUE_OPTIONS for letter in argv[at][1:])
        if at >= len(argv) or argv[at].startswith("--") and argv[at] != "--":
            return []
        if argv[at] in ("-", "--"):
            return argv[at + 1:at + 2]
        if not argv[at].startswith(("-", "+")):
            return [argv[at]]


# A word bash expands, where a shell reads its options, that may spell one (#2344): past the
# `$NAME`, `${...}` or `$(...)` it begins with, nothing but letters -- `$X`, `"${X:--c}"`,
# `$(echo -c)`, `${X}c`, not `$X/x.sh` -- a `$'…'` beginning with an unknown or non-ASCII escape
# that `shell_quote.ansi_c` cannot spell, such as `$'\q'` or `$'\u00e9'`, or a word xargs puts a
# line of its input in (`{}`).
_VALUE = re.compile(r"(?:\$(?:\{[^{}]*\}|\w+|\(\.\.\.\)|[^\w{(\\]))+[A-Za-z]*|\$\\.*", re.S)


def _value(word):
    """Whether `word` is such a value; a pattern is `leads`'s to read."""
    if isinstance(word, shell_reader.Rewritten):
        return getattr(word, "lead", None) is None
    return bool(_VALUE.fullmatch(shell_reader.readable(word)))


# The letters an option's value is spelled with, as every `-o` or `-O` name of
# bash, dash, zsh and ksh is: letters, digits, `_` and `-` (#2484).
_BARE = re.compile(r"[A-Za-z0-9_-]+")


def _before_operand(word):
    """Whether `word`, after a value in a shell's options, may still stand
    before its program: an option word (`-…`, `+…`, `-`, `--`), an option's
    value (`_BARE`), or a word bash expands -- a `$`, a lifted substitution,
    a pattern (`shell_reader.dynamic`) -- which may vanish or be either."""
    return (word[:1] in ("-", "+") or bool(_BARE.fullmatch(word))
            or shell_reader.dynamic(word, shell_reader.has_substitution))


def _may_spell_option(word):
    """Whether `word`, PAST the first operand, may be an option word once it is expanded: a word
    bash expands (`shell_reader.dynamic`) that begins with `-`, a `$` or a lifted substitution, or a
    pattern or an `xargs -I` replacement (`Rewritten`). One that begins with literal text of its own
    (`x$Y`, `echo $Y`) is none."""
    return shell_reader.dynamic(word, shell_reader.has_substitution) and (
        shell_reader.readable(word)[:1] in ("-", "$") or isinstance(word, shell_reader.Rewritten))
