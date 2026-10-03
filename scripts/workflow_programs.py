#!/usr/bin/env python3
"""Which program a command hands a shell, read off its argv and its stage.

Split out of `scripts/workflow_forms.py` (#2331's follow-ups) the way `scripts/workflow_operands.py`
and `scripts/workflow_gating.py` were: that module had 51 lines of room left, fewer than the third
batch of those follow-ups adds to these readers. What is here answers one question of one command --
which program it hands a shell -- and reads no statement around it, only, for a program piped into
it, the stage in front of it (#2333):

    `scripts`         the script handed to `eval` or `sh -c` as a STRING, which is the same act one
                      quote away from a substitution, `Opaque` where a `$(...)` among its text
                      prints part of it
    `stdin_program`   whether an interpreter's program arrives on its standard input instead, which
                      is the same act one REDIRECTION away (`bash -s <<'EOF'`), and in what
                      language, where a table names it (`$CMD` is a value none places)
    `stdin_scripts`   the quoted body that program is, where it is or may be shell, or the text an
                      `echo` or `printf` pipes in (`printed`), each a `Stdin` naming the shell the
                      step itself runs to read it, under whose `-e` a check in it runs -- or none,
                      where no check in it counts
    `unprinted`       the printer piping one in whose text `printed` cannot spell out, for
                      `unread_program` to weigh
    `candidates`      the words that may be the program, up to the first operand and past a later
                      word that may spell an option, where a value this module does not follow
                      stands in a shell's options
    `dynamic_program` the program word a LITERAL shell is handed that is all expansion
                      (`sh -c "$P"`, `sh -c "$(cat f)"`), which spells no command at all

`workflow_forms` imports all six and `Opaque`: its `flattened` reads each script found here in
place of the command handed it -- a stdin one under its reader's `-e`, and with no check in it
counted where it has none, behind a string, under a `$` command word (`VALUE_PROGRAM`) or where it
is `Opaque` -- its `unread_program` weighs the candidates, the unprinted and the dynamic program,
and the guard takes `stdin_program` and `SHELL_PROGRAM` through it and `VALUE_PROGRAM` directly.
The option-letter tables below are read here and in `workflow_posture._errexit`, the one layer up
that reads a shell's options too (#2443, #2475).

Stdlib only, like everything under it.
"""
import os
import re

import shell_lex
import shell_reader


# A shell handed a SCRIPT as a string: `eval "curl ... -o x"`, `sh -c "..."`.
# The text is shell and this module reads shell, so the quotes are not a
# grammar it lacks -- only one it was not looking through. `python3 -c` and
# `perl -e` are NOT here: that text is another language, and the gap list says
# so.
_SHELL_STRING = ("sh", "bash", "dash", "ash", "ksh", "zsh")


class Opaque(str):
    """A script `scripts` hands on from a string holding a lifted `$(...)` or backquote among text
    of its own, written as `shell_reader.readable` renders it (`sh $(...)`, #2486). Bash reads what
    the substitution PRINTS as part of the script, and nothing here reads that, so
    `workflow_forms.flattened` reads the rest in place and counts no check in it:
    `bash -ec "$(echo 'true ||') <check>"` never runs the check."""


def scripts(argv):
    """The shell scripts this command is handed as a string, in order, each the text bash hands the
    shell: a double-quoted `\\$` or `` \\` `` without its backslash (`shell_reader._stage`'s
    `spelled`, #2342).

    A word that is all expansion -- one lifted `$(...)` or backquote, or several beside `$` words
    (`$P$(...)`) -- is never one: it spells no command, and `dynamic_program` reports it (#2483,
    #2486). Nor is a word holding a heredoc, a `<(...)` or any other marker: each stands for text
    held in the parse it came from, and the guard's `_walk` already credits what is inside it. A
    `$(...)` or backquote among text of the word's own does not make it none (#2486):
    `eval "sh $(echo tool)"` hands on `sh $(...)`, `Opaque`, whose `sh` is weighed as
    `sh $(echo tool)`'s is -- the substitution's own text still read where `_walk` reads it, what it
    prints read nowhere (#2487), and no marker of this parse left to reach another. A text so
    rendered that the reader refuses is none, as before #2486: `eval "cat <<$(a b) …"` takes its
    delimiter from what `a b` prints, and `cat <<$(...)` is no spelling to end the body at, so the
    string is unread and the rest of the step read.
    """
    return [script for script in map(_script, _program_words(argv)) if script is not None]


def _program_words(argv):
    """The words where a program stands: `eval`'s, or a shell's `-c` operand."""
    name = os.path.basename(argv[0]) if argv else ""
    if name == "eval":
        return [t for t in argv[1:] if not t.startswith("-")]
    return _after_dash_c(argv) if name in _SHELL_STRING else []


def _script(word):
    """`word` as `scripts` hands it on, or None where it is no script."""
    keys = getattr(word, "markers", {})
    if not keys:
        return getattr(word, "spelled", word)
    text = shell_reader.readable(word)
    if _all_expansion(text) or not all(
            shell_reader.yields_words(shell_reader.derived(key, word)) for key in keys):
        return None
    try:
        shell_reader.statements(text)
    except shell_lex.Unreadable:
        return None
    return Opaque(text)


def _after_dash_c(argv):
    """The script operand of a shell's `-c`, wherever the flag was clustered.

    `sh -ec`, `bash -lc`, `bash -euc` are the ordinary CI idiom, not an
    obfuscation, and a short-option cluster carrying a lowercase `c` IS `-c`:
    no shell spells anything else that way. Requiring `-c` as its own token
    let every clustered spelling through. The script is the first operand
    after the options, which need not be the next word: `_past_options`.
    """
    for position, token in enumerate(argv[1:], start=1):
        if token == "--":
            break
        if token.startswith("-") and not token.startswith("--") and "c" in token:
            return _past_options(argv, position)
    return []


# The short option letters a shell takes, where it reads them: bash 5.2.21's
# `set` builtin (`set -eo pipefail`, `set +x`, `set -r`), and besides those a
# command line's own (`sh -c`, `bash -ilr`, `bash -D`, `bash -O extglob`, and
# the `-I`/`-V` dash takes where bash does not). A letter outside the table is
# one the shell REFUSES -- `set: -Z: invalid option`, rc 2 and no option
# changed; `sh -c -K P` exits before it reads `P` -- which is what
# `workflow_posture._errexit` and `_past_options` read it as (#2443, #2475).
# Measured, letter by letter, on bash 3.2.57, bash 5.2.21, dash, zsh 5.9 and
# ksh 93u+, each table is the fail-closed pick for the direction its reader
# takes. For the builtin, where an unknown letter means nothing was SET,
# bash 5.2.21's letters: that is bash 3.2.57's less the `i` and `I` which 5.2
# refuses and SURVIVES, which would be the fail-open direction, and dash
# refuses more of them still but dies at the `set`, which runs nothing. For a
# command line, where it means nothing RUNS, the UNION over the shells that
# refuse at all -- and only those shells may be read that way, because zsh
# runs twenty of these letters and ksh runs `-G` (`_MEASURED_SHELLS`). Which
# take a VALUE: `-o name`, and bash's `-O shopt` on a command line.
SET_OPTIONS = "abefhkmnoprtuvxBCEHPT"
SHELL_OPTIONS = SET_OPTIONS + "cilsDOIV"
VALUE_OPTIONS = "oO"
# The shells whose command-line letters the comment above measured as REFUSED:
# `sh` (bash in sh mode on this box, dash on a runner), `bash` and `dash`. The
# other names of `_SHELL_STRING` are not here -- zsh runs `-K`, `-F`, `-S`,
# `-d`, `-g`, `-w`, `-y` and thirteen more, ksh runs `-G`, and `ash` could not
# be measured (this box has none) -- so for them an option word is read ON.
_MEASURED_SHELLS = ("sh", "bash", "dash")
# The option NAMES an `-o` takes, where a shell reads them: bash 5.2.21's
# `set -o` listing -- which is bash 3.2.57's, name for name -- and besides
# those the three dash prints that bash has no such option for. A name outside
# the table is one the shell REFUSES: `set: foo: invalid option name`, and on a
# command line `bash -c -o foo P` exits 2 before it reads `P`, which is what
# `workflow_posture._rejected` and `_refused_name` read it as (#2560). Measured
# on bash 3.2.57, bash 5.2.21 and dash, each table is the fail-closed pick for
# the direction its reader takes, as the letter tables are. For the BUILTIN,
# where a refused name means nothing was SET, bash's 27 alone: dash dies at
# such a `set`, so nothing runs there at all, and its own names would only add
# ones bash refuses. For a COMMAND LINE, where it means nothing RUNS, the UNION
# -- dash runs `-o stdin`, `-o interactive` and `-o debug`, which bash exits 2
# on, and dash has no `pipefail`, which bash takes. `-O` takes a SHOPT name
# instead, a table this guard does not keep (`_refused_name`).
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

    One value per `o` or `O` letter, as `_past_options` counts them, and only
    an `o`'s is a `set -o` name: `-O` takes a shopt name, and a table of
    those is not kept here. A value that is not all letters -- bar the hyphen
    of `interactive-comments` -- is read ON and fail-closed, as an option
    word that is not all letters is: `sh -c -o $X P` runs `P` wherever `X`
    holds a name the shell takes, and `${X:-pipefail}` is one spelling of
    that."""
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

    False for every other command word, which the walk then reads ON as it
    did before #2475: zsh and ksh, which RUN letters bash refuses, the
    unmeasured `ash`, and any word not WRITTEN as that name -- a `$X`, a
    lifted `$(echo sh)`, a pattern, or a `${X:-sh}` default read as the shell
    it spells (`shell_wrappers.Defaulted`, #2337), every one of which is a
    `str` SUBCLASS here. The program such a command word is handed is
    #2337/#2344's own report, and a letter table cannot overrule it, because
    `X` may hold `zsh`.

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

    Bash and dash read on through the option words after `-c` (#2332): `sh
    -c -e P`, `bash -c -x P` and `sh -c +x P` all run `P`. Each `o` or `O`
    in a word takes the next word as its value (`-c -o pipefail P`, `-co
    pipefail P`); a `-` or `--` ends the options, and the word after it is
    the program even if it begins with `-`; a `--long` word after `-c` is
    one both shells refuse, and nothing runs. So is a word of letters one of
    which the shell in hand refuses (`sh -c -K P`, `sh -cK P`, `_refused`):
    it exits before it reads `P`, so no program is handed over (#2475), and an
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


# A word bash expands, where a shell reads its options, that may spell one
# (#2344): past the `$NAME`, `${...}` or `$(...)` it begins with, nothing but
# letters -- `$X`, `"${X:--c}"`, `$(echo -c)`, `${X}c`, not `$X/x.sh` -- a
# `$'…'` the reader leaves undecoded (`shell_lex.ansi_c`) whose text BEGINS
# with an escape, `$'\x2dc'` but not `$'-\x63'` (a residual), or a word
# xargs puts a line of its input in (`{}`).
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


def candidates(argv):
    """(the value, [the words it may make the program]) for a shell handed a value where it reads
    its options (`_VALUE`, #2344): `X=-c; sh $X 'curl … | sh'` runs that string, as
    `sh $(echo -c) '…'` and `echo -c | xargs -I{} sh {} '…'` do. This module follows no value, so a
    word after it may be the program, a dynamic one too (`"$Y"`, `"$(…)"`, a pattern), which
    `unread_program` weighs too (review N2 of #2331) -- up to the FIRST OPERAND, the first word that
    can be none of an option word, an option's value (`_BARE`) or anything once expanded
    (`_before_operand`), with the option words before it weighed, harmlessly, as `-c` strings. Where
    the value spells `-c`, the words after that operand are positional parameters (#2484). A value
    ending in `o` or `O` makes the next word an option name, which the shell refuses where it is not
    bare: `X=-cO; bash $X 'echo hi' '…'` runs nothing. But the operand may be an option's own value
    (`X=--rcfile; bash $X /dev/null …`), and the shell then reads on: its program can follow only
    (i) in a literal `-c` cluster, which `scripts` reads wherever it stands, (ii) behind a word that
    expands to one, or (iii) as a script file, which the operand reader reads, or on stdin, which
    nothing here reads past a value (#2605, #2616). So the first word past the operand that may
    spell an option once expanded (`_may_spell_option`: `$Y`, `-$Y`, `$(echo -c)`) re-opens every
    word after it, though not itself, which is `$0`, an option word or a script's file name, never a
    `-c` string, unless brace expansion spells one (`{-c,…}`, a `Rewritten` word nothing weighs).
    The price: a value that was `-c` after all has a later program-like parameter weighed again, as
    before #2484 (`X=-c; sh $X 'echo hi' "$Y" '…'` runs only `echo hi`). (None, []) where the
    options end first, at a program, a `-c` whose string `scripts` reads, or a `-` or `--`. A value
    that is the command word, handed a `-c` cluster, may be a shell itself (#2337,
    `CMD=sh; $CMD -c '…'`): the program after the options is the candidate. A `$(…)` or backquote
    value with no word after it is its own: bash makes the shell's words of its output, the program
    among them (`sh $(echo tool)`), where a `<(…)` hands it a file (`shell_reader.yields_words`)."""
    if argv[1:] and _value(argv[0]) and argv[1][:1] == "-" != argv[1][1:2] and "c" in argv[1]:
        return argv[0], _past_options(argv, 1)
    if not argv or os.path.basename(argv[0]) not in _SHELL_STRING:
        return None, []
    owed = 0
    for at, word in enumerate(argv[1:], start=1):
        if owed:
            owed -= 1
        elif _value(word):
            rest = argv[at + 1:]
            end = next((k for k, after in enumerate(rest, 1) if not _before_operand(after)), len(rest))
            more = next((k for k in range(end, len(rest)) if _may_spell_option(rest[k])), len(rest))
            return word, rest[:end] + rest[more + 1:] or (
                [word] if shell_reader.yields_words(word) else [])
        elif word in ("-", "--") or word[:1] not in ("-", "+") or word[:2] != "--" and "c" in word:
            break
        elif word[:2] != "--":
            owed = sum(letter in VALUE_OPTIONS for letter in word[1:])
    return None, []


# What a `$` may carry without braces: a name, or the positional SET `$@` or
# `$*`, three spellings of one thing (review r0 finding 2). Not the bare `$-`,
# `$#`, `$$` or `$?` (their braced forms ARE matched): a program named by one
# of those is a path the fetch-and-exec rule or #2294 already reports.
_NAME = re.compile(r"\w+|[@*]")


def _all_expansion(text):
    """Whether `text` is nothing but expansion -- `$P`, `${P}`, `"$P"` as the reader hands it on
    with its quotes dropped, `$P$Q`, `$@`, a nest of any depth (`${A:-${B:-${C}}}`, r0 finding 3),
    and a lifted `$(...)` or backquote as `shell_reader.readable` renders it (`$P$(...)`, #2486) --
    and so spells no command at all for `flattened` to read (#2483). `${A}x`, `echo $X` and an
    unbalanced `${A` are not: they hold text of their own. Blanks around it and a trailing `;` are
    no text of its own: `sh -c "$(cat f) "`, the `run: |` spelling. Braces are counted rather than
    matched by pattern, because no regular expression can balance them. A `<(...)` renders as
    `$(...)` too, so whether each hands on words is the caller's to ask of the token."""
    at, text = 0, text.strip(" \t\n").removesuffix(";").rstrip(" \t\n")
    while at < len(text):
        if text.startswith("$(...)", at):       # a lifted substitution, rendered
            at += 6
            continue
        if text[at] != "$" or at + 1 >= len(text):
            return False
        if text[at + 1] == "{":
            depth, at = 1, at + 2
            while at < len(text) and depth:
                depth += (text[at] == "{") - (text[at] == "}")
                at += 1
            if depth:
                return False                # `${A`: no closing brace, no expansion
            continue
        name = _NAME.match(text, at + 1)
        if not name:
            return False
        at = name.end()
    return at > 0                           # `sh -c ""` hands over no program


def dynamic_program(argv):
    """(how this command hands a shell a program, the word it hands it) where that word is ENTIRELY
    expansion, else (None, None).

    `sh -c "$P"`, `bash -c "${P}"`, `sh -ec "$P"`, `eval "$P"`, `sh -c "$@"` and `${X:-sh} -c "$P"`,
    whose command word the reader rewrites to its default, so the shell is literal by the time it
    arrives here (`_all_expansion`). `flattened` reads such a word as no command at all, which left
    the program UNREAD wherever a literal shell took one while the `$CMD -c "$P"` twin `candidates`
    finds was reported: `unread_program` now says it of both. So is a word of lifted `$(...)` or
    backquote substitutions that hand on words, `$` words beside them or not (`sh -c "$(cat f)"`,
    `eval sh "$(echo tool)"`, `sh -c "$P$(cat f)"`, #2486), asked here before `scripts` drops it:
    bash runs what they print, and nothing here reads that (#2487). The price is #2483's: beside an
    unverified download, `sh -c "$(date)"` and `eval "$(ssh-agent -s)"` are reported though they run
    none of it. A `<(...)` or `>(...)` hands a file, not words (`shell_reader.yields_words`), and is
    not one; nor is a string that MIXES literal text with an expansion (`sh -c "echo $X"`), which is
    read as written (`Opaque` where a `$(...)` is among its text). `set -- "$P"` IS one, and
    `eval set -- "$OPTS"` runs nothing of the value as a command: an accepted over-report, because a
    `;` in that value does run (r0 finding 4)."""
    name = os.path.basename(argv[0]) if argv else ""
    for word in _program_words(argv):
        keys = getattr(word, "markers", {})
        text = shell_reader.readable(word) if keys else getattr(word, "spelled", word)
        if _all_expansion(text) and all(
                shell_reader.yields_words(shell_reader.derived(key, word)) for key in keys):
            return (name if name == "eval" else name + " -c"), (word if keys else text)
    return None, None


# An interpreter given no program to run reads one from its STANDARD INPUT, and
# a heredoc is the shortest way a `run:` step writes one down: `bash -s <<'EOF'`
# hands over a script exactly as `sh -c '<script>'` does, one redirection away
# (#1839, run-14 SEC-3915165799). Four answers, because the guard needs four.
SHELL_PROGRAM = "shell"        # the body is shell, which this module reads
FOREIGN_PROGRAM = "foreign"    # a program in a language it has no grammar for
VALUE_PROGRAM = "value"        # the command word is a value no table places; the body may be shell
# The interpreters of the second kind. `python3 -c` and `perl -e` are already
# ruled another language by `scripts` above, and a heredoc is the same text one
# redirection over.
_FOREIGN = ("python", "python3", "perl", "ruby", "node", "php", "pwsh")
# The operands that ARE standard input.
_STDIN_OPERANDS = ("-", "/dev/stdin", "/dev/fd/0")


def stdin_program(argv):
    """Whether this command's PROGRAM is its standard input, and in what.

    `SHELL_PROGRAM` for a shell reading a script from stdin (`bash -s`, a bare
    `sh`, `dash -`), `FOREIGN_PROGRAM` for a program in a language this module
    does not read (`python3 -`), `VALUE_PROGRAM` for one under a value-form
    command word no table places (`$CMD`, `$PYTHON -`), and None when the
    program is somewhere else -- a file (`bash x.sh`), a `-c` string, a `-m`
    module -- which makes stdin that program's input DATA and not an act of
    this job's own.

    Read as OPERANDS rather than as a full option grammar: an interpreter's
    first word that is not an option is its program, and a shell's `-s` says
    every word after it is a positional parameter instead. See the guard's gap
    list for the spelling that leaves behind. A letter the shell refuses is
    read on, fail-closed: `sh -K <<'EOF'` runs nothing in bash or dash, but
    only `_past_options` asks `_refused` (#2475), for a `-c` cluster. A stdin
    operand (`-`, `/dev/stdin`) after an option owed a value ends the walk
    there, except under a literal shell, whose `-o` takes it as an option name
    and refuses it (`bash -o - x.sh` exits 2): python's `-O` takes no value,
    so `python3 -O - file.py <<'EOF'` runs its heredoc.

    A `-c` string or `eval`'s is ordinarily such a FILE-like place too (the
    `-c` string itself, not stdin, is the program) -- UNLESS that string is
    itself one statement whose own command is a stdin-reading shell (#2500):
    `eval 'bash -s'` and `bash -c 'sh'` then answer SHELL_PROGRAM for the
    ENCLOSING command, so its heredoc, here-string or pipe is read as
    `bash -s`'s or `sh`'s program, not `eval`'s or `-c`'s -- a download in it
    is caught -- and no check in it counts (`_stdin` names no reader), so a
    body ending in its check is reported though the step stops at it.
    `eval 'echo hi'` and `bash -c 'cat'` are not stdin-reading shells, so
    they are unaffected. A `-c` cluster the shell refuses hands over no
    string (`_past_options`), so `bash -c -K 'sh' <<'EOF'`, which runs
    nothing, is not read so; an INNER shell's refused letter is read on, as
    above, so `eval 'bash -K -s'` and `bash -c 'sh -K'` are, though bash and
    dash refuse them and run nothing -- fail-closed. The reading looks at most
    64 strings deep (`_stdin`'s `depth`) and answers SHELL_PROGRAM past that,
    fail-closed, so seventy `eval`s before `echo hi <<'EOF'` over-report; with
    `workflow_forms.flattened` asking once per stage, an `eval eval … bash -s`
    chain costs time linear in its length and never overflows the stack (final
    review F1: it was cubic, 37 s at 200, and raised RecursionError at 1,600).

    For a SHELL, a value form or a word that may vanish (`_value`) does not
    END the walk there either (#2485): `X=-s; sh $X <<'EOF'` runs the
    heredoc in bash 3.2.57, 5.2.21 and dash alike, as `bash <<'EOF' $(true)`
    and `sh $X` with `X` unset do, where `$X`'s empty expansion drops the
    word outright. Read IN PLACE rather than weighed, fail-closed: `X`
    may just as well spell a FILE (`X=script.sh`) or an option nothing
    runs under -- one the shell refuses (`X=-K`, where bash and dash
    exit 2), `X=-n` (they read the heredoc and run none of it) or a
    bare `X=-c` (no string, rc 2) -- so this over-reports there; the
    guard's gap list names the class. No check in the body counts either
    (`_stdin` names no reader): where `X` names a file no shell reads the
    body, so `X=/dev/null` runs a download past a body that is only the
    check, and `X=-s`, which stops at it, over-reports too. A
    `<(...)`/`>(...)` is NOT such a word, though `_value` matches its marker
    too: it always substitutes a real path, never empty, so
    `bash <(curl ...)` keeps reading as the FILE it is (`yields_words` tells
    a process substitution from a command substitution, whose OUTPUT may
    vanish instead) -- true only where EVERY substitution in the word is a
    process one; a MIXED word (`$(true)<(...)`) still reads as may-vanish
    even though bash always substitutes a real path for it too -- an
    over-report the guard's gap list does not separately name, beside the
    ones it does (`X=script.sh`, `X=-K`, `X=-n`).

    A value-form COMMAND word (`$CMD`, `"$CMD"`, `${CMD}`, `$(echo sh)`,
    `$PYTHON -`) with stdin on it answers VALUE_PROGRAM (#2473): a name no
    table places may hold a shell, another language's interpreter or `true`.
    SHELL would read another language's program as though it were one, and
    report nothing for `$PYTHON - <<'EOF'` even beside a fetch (review I-2);
    FOREIGN leaves the body unread, an `Idle` report `kept` drops beside no
    reported fetch (#2499), so `CMD=sh; $CMD <<'EOF'` running `curl ... |
    sh` read CLEAN. As VALUE its QUOTED body is read as shell all the same,
    additively (`stdin_scripts`; `workflow_forms.flattened` counts no check
    in it, since `$CMD` may not run it) -- a body no interpreter runs, `$CAT
    <<'EOF' > f`, over-reports -- and the guard's `_unread_stdin` reports the
    hand-off `Idle` under a sentence of its own. Its walk takes a shell's
    `-c`, `-s`, vanishing-operand and option-value rules, since the word may
    be a shell (`$CMD -s -- "$V" <<'EOF'` and `$CMD -oe pipefail <<'EOF'` read
    the heredoc, as does `$PYTHON -Ou - file.py <<'EOF'`, a stdin operand
    being no option's value; `$PYTHON -s file.py <<'EOF'`, `$PYTHON -Ou
    file.py <<'EOF'` and an interpreter's own option value spelled `$`
    (`$NODE -e "$CODE" <<'EOF'`, `$PYTHON -m "$MOD" <<'EOF'`, read past as
    a vanishing operand) over-report a hand-off, like `$PYTHON -O file.py`),
    and an EXPANDING body is read nowhere, so `$CMD <<EOF` running a download
    reads CLEAN beside no reported fetch: option b's price, which `python3 -
    <<EOF` pays too. No option word behind a `$` word is a refusal (#2475's
    per-shell scoping: `CMD` may hold zsh, which runs `-K`), so `CMD=sh; $CMD
    -K <<'EOF'` is read and its hand-off said, though every shell measured
    refuses `-K` and runs nothing -- fail-closed. #2500's reading stays
    SHELL_PROGRAM's: an inner `$CMD` makes no enclosing `eval` or `-c` string
    a stdin shell, so the body of `CMD=sh; eval "$CMD" <<'EOF'` or `export
    CMD=sh; bash -c '$CMD' <<'EOF'` is never read, though bash runs it: a
    `curl ... | sh` there reads CLEAN alone, and beside a reported fetch only
    the word is reported, as a `dynamic_program` (`Idle`, #2483), never the
    stream -- a gap filed under #2331.
    """
    return _stdin(argv, 0)[0]


def stdin_reader(argv):
    """The `reader` (`Stdin`) of this command's stdin: None where no shell is sure to read it."""
    return _stdin(argv, 0)[1]


class Stdin(str):
    """A script `stdin_scripts` read off standard input, and its `reader` (`_stdin`): the argv of
    the shell the step itself runs to read it, under whose `-e` a check in it runs; `()` where
    that shell's own options read stdin but its `-c` string names the shell that reads it
    (`bash -s -c 'sh'`), whose statements are the step's own and no check in them counts; or None,
    where no shell is sure to read it and nothing in it is the step's own."""
    reader: "list[str] | tuple[()] | None" = None


def _stdin(argv, depth):
    """(`stdin_program`'s answer, the reader `Stdin` carries) in one walk.

    The reader of a shell the step runs itself is that shell, whatever its options say: a step's
    own `bash -n -s` reads as it always has. Behind a string (#2500) there is none: what the inner
    shell is, what it reads and what becomes of its failure are the step's to change --
    `sh() { :; }`, `< $F`, `( … ) || true` -- so its body is read, no check in it counts and
    nothing else in it is the step's own; but where the holder's own options read stdin
    (`bash -s -c 'sh'`, by `_options`), the step reads the body as the holder's program, and the
    reader is `()`. Nor is there one past a word that may vanish (#2485), which may name a FILE,
    nor under a `$` command word (#2473). `depth` counts the strings walked so far, at most 64."""
    if not argv:
        return None, None
    kind, reader = _options(argv, depth)
    found = scripts(argv)
    if found:
        # bash's `eval` joins ALL of its own words -- `-`-prefixed ones too
        # -- into ONE string before running it (`eval bash -s x.sh` is
        # `bash -s x.sh`, still reading stdin, not `bash x.sh` alone); a
        # shell's `-c` STRING is already one word, `_after_dash_c`'s own.
        # `scripts()`'s OWN join drops `-`-words for its literal-text
        # callers, a filter wrong for this join (review R1-I2) -- re-join
        # eval's words here instead of using `scripts()`'s filtered list. A
        # leading `--` is dropped first: bash's `eval` ends its own options
        # there (`eval -- bash -s` reads stdin), but dash's runs `--` as a
        # command and nothing runs -- fail-closed where a step's `sh` is dash.
        is_eval = os.path.basename(argv[0]) == "eval"
        words = [t for t in (argv[1:] if is_eval else found) if not shell_reader.is_marker(t)]
        if is_eval and words and getattr(words[0], "spelled", words[0]) == "--":
            words = words[1:]
        text = " ".join(getattr(t, "spelled", t) for t in words)
        parsed = shell_reader.statements(text)
        if (len(parsed) == 1 and len(parsed[0].stages) == 1
                and (depth >= 64                # bounded: past 64 strings, fail-closed
                     or _stdin(shell_reader.command(parsed[0].stages[0].argv), depth + 1)[0]
                     == SHELL_PROGRAM)):
            # Read, and no check in it counts: the step's own only where its holder reads stdin.
            return SHELL_PROGRAM, () if kind == SHELL_PROGRAM and reader else None
    return kind, reader


def _options(argv, depth):
    """`_stdin`'s answer from the command's own words alone, its strings aside: what its options
    and operands say the program on its standard input is, and its reader."""
    name = os.path.basename(argv[0])
    shell = name in _SHELL_STRING
    foreign = name in _FOREIGN
    # `<(...)`/`>(...)` are a `_value`-matching marker too (`readable` renders
    # every substitution alike), but they never vanish -- a process
    # substitution always substitutes a real path, never empty, never word-
    # split away, unlike `$(...)`/backticks, whose OUTPUT may be (#2485's
    # `$(true)`). `yields_words` is the one already here that tells them apart.
    value = not shell and not foreign and _value(argv[0]) and (
        not shell_reader.has_substitution(argv[0]) or shell_reader.yields_words(argv[0]))
    if not (shell or foreign or value):
        return None, None
    answer = SHELL_PROGRAM if shell else FOREIGN_PROGRAM if foreign else VALUE_PROGRAM
    reader = argv if shell and not depth else None
    rest = iter(argv[1:])
    for token in rest:
        if token in _STDIN_OPERANDS:
            return answer, reader
        if not token.startswith(("-", "+")):
            if (shell or value) and _value(token) and (
                    not shell_reader.has_substitution(token) or shell_reader.yields_words(token)):
                reader = None               # ... but it may name a FILE: no check counts
                continue                    # the walk goes on as if absent
            return None, None               # the program is this file
        letters = "" if token[:2] in ("--", "++") else token[1:]
        if (shell or value) and "c" in letters:
            return None, None               # the program is the `-c` string
        if (shell or value) and "s" in letters:
            return answer, reader           # the words after `-s` are parameters
        # A shell's option word takes a value for each `o` or `O` in it (#2344,
        # `bash -oe pipefail`), and so does a `$` word's, which may be a shell;
        # another interpreter's, one where it ends so. Only a shell takes a
        # stdin operand for that value (and refuses `-o -`, rc 2): python's
        # `-O` takes none, so in `python3 -O - file.py` the `-` is stdin.
        owed = (sum(letter in VALUE_OPTIONS for letter in letters) if shell or value
                else int(bool(letters) and letters[-1] in VALUE_OPTIONS))
        for _ in range(owed):
            if next(rest, None) in _STDIN_OPERANDS and not shell:
                return answer, reader       # the program is stdin after all
    return answer, reader


def stdin_scripts(argv, stage, before=None):
    """The QUOTED heredoc script this stage hands an interpreter, if it does.

    `bash -s <<'EOF' … EOF` is `sh -c '<script>'` one redirection away: with a
    quoted delimiter the interpreter reads the body as the text it was written
    as, so reading it here is exactly as sound as reading that string -- and a
    `curl … | sh` inside it is the same defect it is at the top level; so is
    `sh <<< '…'` (#2293). What EXPANDS is read nowhere: the guard's
    `_unread_stdin`. Read here too is the text an `echo` or `printf` in front
    of it (`before`) pipes in, where `printed` spells it out (#2333): `echo
    'sh tool' | sh`; where it does not, `unprinted` has the printer.

    Each comes as a `Stdin` naming its `reader` (`_stdin`), the shell under whose `-e`
    `workflow_forms.flattened` counts a check in it: a literal shell the step runs, whatever stands
    in front of it (`sudo bash -s` reads as it always has, and so does `bash -s -c 'echo hi'`, whose
    string names no shell that reads stdin); `()` for the body of a holder whose own options read
    stdin (`bash -s -c 'sh'`), the step's own statements, with no check counting; and None behind a
    string that names the shell reading it (`eval 'bash -s'`, `bash -c 'sh'`), past a word that may
    vanish or under a `$` command word, where no shell is sure to read it and nothing in it is the
    step's own (`workflow_forms.Unsure`).

    Behind a `$` command word (VALUE_PROGRAM, #2473) the quoted body and the
    printed text are read the same way, as shell, though the word may hold
    none: what they fetch or run is read as at the top level, and
    `workflow_forms.flattened` counts no check there; inside a `$(...)`,
    `workflow_forms.substitution_script` weighs the printed text as a
    shell's. `unprinted` weighs a shell's printer only, so a pipe into it
    whose text no printer spells out (`echo "$X" | $CMD`) is unread, filed
    under #2331.
    """
    here = stage.stdin_heredoc
    if here is None and _piped(stage, before):
        text = printed(shell_reader.command(before.argv))
        here = None if text is None else (text, False)
    kind, reader = (None, None) if here is None or here[1] else _stdin(argv, 0)
    if kind not in (SHELL_PROGRAM, VALUE_PROGRAM):
        return []
    text = Stdin(here[0])
    text.reader = reader
    return [text]


def _piped(stage, before):
    """Whether this stage's descriptor 0 finally reads what `before` writes."""
    return before is not None and before.stdout_to_pipe and stage.stdin_from_pipe


# The commands whose output is the text of their words (#2333).
_PRINTERS = ("echo", "printf")


def printed(argv):
    """The text this `echo` or `printf` writes where its words spell it out,
    or None: `echo` of words no expansion changes (a `spelled` one's, #2342),
    after the `-n`, `-e` and `-E` bash's `echo` takes, or `printf` of such a
    format with no `%`, or of `%s`, `%s\\n` or `%b` and one such word. A
    backslash is left unspelled where the printer may read it as an escape
    (dash's `echo` does), but a format's `\\n`."""
    if not argv or os.path.basename(argv[0]) not in _PRINTERS or any(
            shell_reader.dynamic(w, shell_reader.has_substitution) and not hasattr(w, "spelled")
            for w in argv[1:]):
        return None
    words = [getattr(w, "spelled", w) for w in argv[1:]]
    if os.path.basename(argv[0]) == "echo":
        options = 0
        while options < len(words) and re.fullmatch("-[neE]+", words[options]):
            options += 1
        end = "" if any("n" in word for word in words[:options]) else "\n"
        text = " ".join(words[options:])
        return None if "\\" in text else text + end
    words = words[1:] if words[:1] == ["--"] else words
    if not words or words[0][:1] == "-":
        return None
    if words[0] in ("%s", "%s\\n") and len(words) == 2:
        return words[1] + words[0][2:].replace("\\n", "\n")
    if "%" in words[0] and not (words[0] == "%b" and len(words) == 2):
        return None
    text = (words[1] if "%" in words[0] else words[0]).replace("\\n", "\n")
    return None if "\\" in text else text


def unprinted(argv, stage, before):
    """The `echo` or `printf` in front of this shell piping it its program
    where `printed` does not spell that text out (`echo "$X" | sh`, #2333),
    or []."""
    producer = (shell_reader.command(before.argv)
                if stage.stdin_heredoc is None and _piped(stage, before) else [])
    if (not producer or os.path.basename(producer[0]) not in _PRINTERS
            or printed(producer) is not None or stdin_program(argv) != SHELL_PROGRAM):
        return []
    return producer
