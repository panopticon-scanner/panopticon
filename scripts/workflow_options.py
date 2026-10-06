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
# A shell's LONG options, where bash reads them (#2616), in EITHER spelling bash takes -- two
# dashes anywhere among its options, one dash only in the LEADING run of long options (`-login`,
# `--norc -login`, `-rcfile f -login`; after a short-option word `-help` is the letters `-h -e -l
# -p`, and `bash -e -help <<'EOF'` runs the heredoc: #2858 round 2) -- `long_option` reads both:
# the two that take a FILE
# (`--rcfile f`, `--init-file f`), measured to run the program after it on bash 5.2.21 and 3.2.57;
# the flags, the UNION of the two versions' lists (5.2's `--pretty-print`, 3.2's `--protected`),
# read ON as the letters are; and the five that run nothing (`LONG_EXITS`): four print and exit
# (`bash --version <<'EOF'` reads no stdin, measured on both), and `--wordexp` expands stdin as
# words (3.2) or is refused (5.2). A FILE option as the last word is refused too. A word outside the
# tables, or one with a value glued on (`--rcfile=f`, `-rcfile=f`: rc 2 and rc 1, nothing run), is
# one bash refuses -- `bash: --bogus: invalid option`, rc 2, no stdin read -- and dash refuses every
# long option (`Illegal option --`), so for a shell in `_MEASURED_SHELLS` such a word is a refusal
# (`_refused_long`); zsh and ksh read on. A one-dash word that spells none of these is a letter
# cluster, as bash reads it (`-bogus` is `-b -o gus`, refused at `g`).
LONG_VALUE_OPTIONS = ("--rcfile", "--init-file")
LONG_EXITS = ("--help", "--version", "--dump-strings", "--dump-po-strings", "--wordexp")
LONG_OPTIONS = ("--debug", "--debugger", "--login", "--noediting", "--noprofile", "--norc",
                "--posix", "--pretty-print", "--protected", "--restricted", "--verbose") + LONG_EXITS
_LONG = re.compile(r"-{1,2}([a-z][a-z-]*)")


def long_option(argv, at):
    """The `--name` the word `argv[at]` spells, where it is one of `LONG_OPTIONS` or
    `LONG_VALUE_OPTIONS`: in bash's two-dash spelling for any shell, and in its one-dash spelling
    (`-login`) only for a shell that is `bash` or `sh`, which may be bash, and only while the words
    before it are long options too (`_leading`): bash parses the one-dash names in that leading run
    alone, and after a short-option word `-help` is the letters `-h -e -l -p` (#2858 round 2). To
    dash a one-dash word is a cluster of letters (`dash -login` fails at `-g`), and zsh and ksh
    are not measured. None for any other word: a letter cluster, a word with a value glued on,
    `-`, `--`, or a name not written as itself (a `str` subclass)."""
    word = argv[at]
    found = _LONG.fullmatch(word) if type(word) is str else None
    if not found:
        return None
    if word[1] != "-" and (os.path.basename(argv[0]) not in ("bash", "sh") or not _leading(argv, at)):
        return None
    name = "--" + found[1]
    return name if name in LONG_OPTIONS or name in LONG_VALUE_OPTIONS else None


def _leading(argv, at):
    """Whether every word before `argv[at]` is a long option, in either spelling, or the FILE
    one takes -- the leading run in which bash reads one-dash long names."""
    owed = 0
    for i in range(1, at):
        if owed:
            owed -= 1
            continue
        word = argv[i]
        name = long_option(argv, i)
        if name is None and not (type(word) is str and word[:2] == "--" and word != "--"):
            return False
        owed = name in LONG_VALUE_OPTIONS
    return True


def _runs_nothing(argv, at):
    """Whether the option word `argv[at]` keeps a measured shell from running ANY of its program
    though it reads it, exiting 0 (#2858 round 3): a cluster of letters holding `n` (noexec: `bash
    -n -s <<'EOF'`, and `-version` after a short option, the letters `v e r s i o n`) or `D`
    (`--dump-strings` by letter), or `-o noexec`. The stdin walk answers as for a refusal -- the
    body is not the shell's program and no check in it counts -- so a use after is reported and
    a download in the body is not: nothing runs. `-t` runs ONE command and is read on."""
    if type(argv[0]) is not str or os.path.basename(argv[0]) not in _MEASURED_SHELLS:
        return False
    word = argv[at]
    if type(word) is not str or long_option(argv, at):
        return False
    if word == "-o" and at + 1 < len(argv) and argv[at + 1] == "noexec":
        return True
    letters = word[1:]
    return letters.isalpha() and (word[:1] == "-" and "n" in letters or word[:1] in "-+" and "D" in letters)


def _void(argv, at):
    """Whether the option word `argv[at]` leaves a measured shell no program to run at the step's
    own level: refused outright (`_refused`, `_refused_name`) or read and never run (`_runs_nothing`)."""
    return _refused(argv, at) or _refused_name(argv, at) or _runs_nothing(argv, at)


def _refused_name(argv, at):
    """Whether the shell `argv[0]` refuses the `-o` VALUE in the option word
    `argv[at]`, running nothing: a name outside `SHELL_OPTION_NAMES`, handed
    to a shell measured to refuse one at all (`sh -c -o foo P`, `sh -co foo
    P`, `+o foo`; `_MEASURED_SHELLS`, as `_refused` reads a letter).

    One value per `o` or `O` letter, as `_past_options` counts them, and only an `o`'s is a `set -o`
    name: `-O` takes a shopt name, and a table of those is not kept here. A value holding an
    expansion is read ON and fail-closed, as an option word that is not all letters is: `sh -c -o
    $X P` runs `P` wherever `X` holds a name the shell takes, and `${X:-pipefail}` is one spelling
    of that; a value written as itself that is no name (`-`, `/dev/stdin`) is a refusal (#2606)."""
    if type(argv[0]) is not str or os.path.basename(argv[0]) not in _MEASURED_SHELLS:
        return False
    if long_option(argv, at):
        return False                            # `-noediting` is a long option, not `-o editing`
    value = at
    for letter in argv[at][1:]:
        value += letter in VALUE_OPTIONS
        if letter == "o" and value < len(argv) and _literal(argv[value]):
            if argv[value] not in SHELL_OPTION_NAMES:
                return True
    return False


def _dash_s(argv, at):
    """Whether an `s` stands in the `-c` cluster `argv[at]` or in a later option word before the
    operand -- the string -- so dash reads stdin after the string (`sh -cs true`, `sh -c -s
    true`, `sh -c -o pipefail -s true`, #2647); an `-s` after the string is a parameter (`sh -c
    true -s`). Values owed by `o`/`O` and a long option's FILE are skipped, as the shell skips them."""
    owed = 0
    for i in range(at, len(argv)):
        word = argv[i]
        if owed:
            owed -= 1
            continue
        if word in ("-", "--") or word[:1] not in ("-", "+"):
            return False
        if (long := long_option(argv, i)) or word[:2] in ("--", "++"):
            owed = long in LONG_VALUE_OPTIONS
            continue
        if "s" in word[1:]:
            return True
        owed = sum(letter in VALUE_OPTIONS for letter in word[1:])
    return False


def _literal(word):
    """Whether `word` is written as itself, with no expansion in it: a plain `str` -- no
    `Defaulted`, `Rewritten` or lifted-text token -- holding no `$`. Such a `-o` value outside
    the name table is a refusal whether it is a misspelt name or no name at all (`-`,
    `/dev/stdin`: both bashes answer `invalid option name` and exit 2, #2606)."""
    return type(word) is str and "$" not in word


def _refused_long(argv, at):
    """Whether the shell `argv[0]` refuses the long option word `argv[at]` outright, running
    nothing (#2616): for `bash`, and for `sh`, which may be bash (the fail-closed reading), a
    two-dash word outside the tables, a word in either spelling with a value glued on
    (`--rcfile=f`, `-rcfile=f`), or one of `LONG_EXITS`, which prints and exits; for `dash` any
    two-dash word (a one-dash one is a letter cluster to it, `_refused`'s). `--` is no option.
    False for a name not written as itself, as `_refused` answers, and for every shell outside
    `_MEASURED_SHELLS`."""
    if type(argv[0]) is not str or os.path.basename(argv[0]) not in _MEASURED_SHELLS:
        return False
    word, name = argv[at], long_option(argv, at)
    if os.path.basename(argv[0]) == "dash":
        return word[:2] == "--" and word != "--"
    if name:                                    # `bash -rcfile` with no FILE after it: rc 2
        return name in LONG_EXITS or name in LONG_VALUE_OPTIONS and at + 1 >= len(argv)
    glued = _LONG.fullmatch(word.split("=", 1)[0]) if "=" in word else None
    return word[:2] == "--" and word != "--" or bool(glued and long_option([*argv[:at], word.split("=", 1)[0]], at))


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
    if long_option(argv, at):
        return False                            # `-login` is `--login`, no cluster of letters
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
            return []                           # a two-dash word after `-c`: refused (`-help` is letters)
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
