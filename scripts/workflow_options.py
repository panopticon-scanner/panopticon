#!/usr/bin/env python3
"""The option grammar a shell reads, and the words that may stand in its option slot.

Split out of `scripts/workflow_programs.py` at that module's 700-line ceiling (#2331's follow-ups),
byte for byte: the letter and name tables bash, dash and `set` take (`SET_OPTIONS`, `SHELL_OPTIONS`,
`VALUE_OPTIONS`, `SET_OPTION_NAMES`, `SHELL_OPTION_NAMES`, the shells measured to refuse a letter,
`_MEASURED_SHELLS`), the refusal readers over them (`_refused`, `_refused_name`) and the walk to the
operand after a `-c` cluster (`_past_options`), and the three readers of a word where a shell reads
its options -- a value that may spell one (`_value`), a word that may still stand before the program
(`_before_operand`) and one that may spell an option once expanded (`_may_spell_option`); and,
from #2858 round 9, the certificate every clear and credit the stdin and string walks add asks for
(`certified`, `Sure`, `_sure_shell`, `_cleared`), with `main`'s own walks as their floor. A leaf:
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
# A shell's LONG options, where bash reads them (#2616), in EITHER spelling bash takes, and only in
# the LEADING run of long options (`-login`, `--norc -login`, `-rcfile f -login`): after a short-option
# word a two-dash one is refused (`bash -e --norc`: `--: invalid option`, measured on 5.2.21 and
# 3.2.57, #2858 round 9) and `-help` is the letters `-h -e -l -p` (`bash -e -help <<'EOF'` runs the
# heredoc: round 2) -- `long_option` reads both spellings, `_refused_long` the refusal:
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
# `--pretty-print` (5.2) prints the program bash reads from stdin or a FILE and runs none of it --
# unless the run leaves the shell interactive, which 5.2 obeys over it (`--pretty-print -i` runs, `-i
# +i` and `--rcfile -i` do not: `_state`, round 9) -- and 3.2 and dash refuse it; bash takes it only
# in the leading run of long options (`bash -i --pretty-print` is refused). A login run sources
# `~/.bash_profile` first, and an interactive one `~/.bashrc`, either of which may read stdin itself
# (`_startup_free`). A `-c` string after it still runs under 5.2 (`bash --pretty-print -c P` runs `P`,
# round 7), so no string reader refuses it.
LONG_PRINTED = ("--pretty-print",)
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
    if word[1] != "-" and (os.path.basename(argv[0]) not in ("bash", "sh") or at >= _run(argv)[0]):
        return None
    name = "--" + found[1]
    return name if name in LONG_OPTIONS or name in LONG_VALUE_OPTIONS else None


_RUNS: dict[int, tuple[list, int, tuple[int, int, bool, int]]] = {}


def _run(argv):
    """One left-to-right pass over a command's option words, kept per argv (#2858 round 3): the
    index past the LEADING run of long options, a run that holds through a word that may expand to
    nothing or to a long option (`X=; bash $X -login` runs: the shell takes `-login` as leading);
    the index of the first word that may EXPAND -- an option word, a long option's FILE or an
    `o`/`O` name alike (#2858 round 4) -- at or after which nothing is sure: the expansion may
    vanish, so the next word is the FILE (`X=; bash --rcfile $X --version` runs), or spell `+n`, `+o
    noexec`'s name or `--rcfile` itself (`X=--rcfile; bash $X -K -s` runs), so no refusal, exit or
    noexec there clears, and no check in the body is credited (`_credited`); and whether the shell
    runs NONE of its program when its options end, where the run holds no expansion -- the last of
    `-n`/`+n` and `-o noexec`/`+o noexec` wins (each `o`/`O` of a cluster takes a word, in order:
    `-eo noexec`, `-Oo extglob noexec`), and `-D`/`+D` print strings and run nothing. Computed once
    per argv: a run of ten thousand words costs what the walk does."""
    hit = _RUNS.get(id(argv))
    if hit is not None and hit[0] is argv and hit[1] == len(argv):
        return hit[2]
    bash = type(argv[0]) in (str, Sure) and os.path.basename(argv[0]) in ("bash", "sh")
    leading, expansion, end = 1, len(argv), len(argv)
    in_run, noexec, dumps, owed, string, filed = True, False, False, 0, False, False
    for i in range(1, len(argv)):
        word = argv[i]
        if string and not owed and word[:1] not in ("-", "+"):
            end = i                             # the `-c` string itself: the options end at it
            break
        if not _literal(word) and expansion == len(argv) and not (filed and _one_word(word)):
            expansion = i                       # may vanish, or spell any word: nothing after is sure
        filed = False                           # a quoted one-word FILE is the FILE (rounds 6-7)
        if owed:                                # a long option's FILE or an `o`'s name
            owed -= 1
            if in_run:
                leading = i + 1
            continue
        if not _literal(word):                  # possibly empty, possibly an option word
            if in_run:
                leading = i + 1
            continue
        if word in ("-", "--") or word[:1] not in ("-", "+"):
            end = i
            break                               # the options end
        found = _LONG.fullmatch(word)
        name = "--" + found[1] if found and (word[1] == "-" or bash and in_run) else None
        if name not in LONG_OPTIONS and name not in LONG_VALUE_OPTIONS:
            name = None
        if name or word[:2] in ("--", "++"):
            if in_run:
                leading = i + 1
            owed = filed = name in LONG_VALUE_OPTIONS
            continue
        in_run = False
        letters = word[1:]
        if not letters.isalpha():
            continue
        values = [letter for letter in letters if letter in VALUE_OPTIONS]
        owed, string = len(values), string or "c" in letters
        if "n" in letters:
            noexec = word[0] == "-"
        if any(letter == "o" and argv[i + 1 + k:i + 2 + k] == ["noexec"] for k, letter in enumerate(values)):
            noexec = word[0] == "-"             # each `o`/`O` takes a word, in order (`-Oo extglob noexec`)
        if "D" in letters:                      # strings printed, nothing run, whatever `+n` says
            dumps = True
    result = (leading, expansion, (noexec or dumps) and expansion == len(argv), end)
    if len(_RUNS) > 256:
        _RUNS.clear()
    _RUNS[id(argv)] = (argv, len(argv), result)
    return result


def _credited(argv, kind, reader, shell=None):
    """(`kind`, the reader under whose `-e` a check in the body counts): `reader`, or None where the
    shell's option run holds a word that may expand (`_run`, #2858 round 4) -- `-o $X` may be `-o
    noexec`, `--rcfile $X` may hand the next word over as the FILE, `-s $X` may be `-n` -- so
    whether the body runs at all is not the step's to say. For a `shell` (its program kind) no
    certificate covers (`_sure_shell`, round 9), never less than `main`'s walk read and no check
    counted that it did not count (`_main_walk`); for one it covers, no check counted where the run
    reads a startup file the step may have written (`_startup_free`) unless `main` counted it too."""
    if reader is argv and _run(argv)[1] < len(argv):
        reader = None
    if shell and not (_sure_shell(argv) and _startup_free(argv)):
        reads, counts = _main_walk(argv)
        kind = kind or (shell if reads and not _sure_shell(argv) else None)
        reader = None if reader is argv and not counts else reader
    return kind, reader


# What a measured shell reads as its program on standard input (`workflow_programs._options`).
_STDIN_OPERANDS = ("-", "/dev/stdin", "/dev/fd/0")


def _main_walk(argv):
    """(whether the body is read as the program, whether a check in it counts): `main`'s stdin walk
    for a shell at the step's own level, word for word as it stood at 7e9223e6, kept for a command
    no certificate covers (#2858 round 9) -- the floor this module never reads below there."""
    counts, value_option, options = True, False, True
    rest = iter(argv[1:])
    for token in rest:
        if token in _STDIN_OPERANDS:
            return True, counts
        if token == "--":
            options = False
            continue
        if not token.startswith(("-", "+")):
            if _value(token) and (not shell_reader.has_substitution(token) or shell_reader.yields_words(token)):
                counts, value_option = False, value_option or options
                continue
            return value_option, False
        letters = "" if token[:2] in ("--", "++") else token[1:]
        if "c" in letters:
            return False, False
        if "s" in letters:
            return True, counts
        for _ in range(sum(letter in VALUE_OPTIONS for letter in letters)):
            next(rest, None)
    return True, counts


def _long_word(argv, at):
    """What the stdin walk does with the long option word `argv[at]` at the step's own level:
    None where it is no long word; "void" where the shell refuses it or prints and exits, running
    nothing (`_refused_long`), or prints the program and runs none of it (`--pretty-print` where
    the run leaves the shell not interactive, `_state`) -- each only where `_cleared` holds (#2858
    round 9: a sure shell, a literal run, no startup file before the print); "unsure" where one of
    those would hold for a literal `bash` but `_cleared` does not, so the body is the program and no
    check in it counts; "file" where the next word is its FILE; "on" otherwise. A word at or after
    one that may expand is neither (`_run`, round 4): it may be a FILE (`X=--rcfile; bash $X
    -version` runs) or letters, so the walk reads on."""
    name = long_option(argv, at)
    word = argv[at]
    if name is None and not (type(word) is str and word[:2] in ("--", "++")):
        return None
    printed = name in LONG_PRINTED and at < _run(argv)[1] and not _state(argv)[0]
    if _refused_long(argv, at) or printed:
        return "void" if _cleared(argv, at, printed) else "unsure"
    return "file" if name in LONG_VALUE_OPTIONS else "on"


_STATES: dict[int, tuple[list, int, tuple[bool, bool, bool]]] = {}


def _state(argv):
    """(interactive, login, no rc file) as the option run leaves them (#2858 round 9, rule 4), read
    as bash and dash read it: each cluster's letters in order, the last `i` state winning (`-i +i`
    is off, `+i -i` on), each `o`/`O` taking the next word as its value and a long FILE option the
    next as its FILE (`--rcfile -i` holds no `-i`), `-o interactive` interactive, and nothing past
    the run's end (`-s -- -i` hands `-i` on as a parameter). Meaningful where the run is literal,
    which every reader of it asks first (`_cleared`); kept per argv, as `_run` is."""
    hit = _STATES.get(id(argv))
    if hit is not None and hit[0] is argv and hit[1] == len(argv):
        return hit[2]
    interactive = login = norc = False
    owed: list[str] = []
    for at in range(1, _run(argv)[3]):
        word = argv[at]
        if owed:
            kind = owed.pop(0)
            norc = norc or kind == "file" and word == "/dev/null"
            interactive = interactive or kind == "o" and word == "interactive"
            continue
        name = long_option(argv, at)
        if name or word[:2] in ("--", "++"):
            login, norc = login or name == "--login", norc or name == "--norc"
            owed = ["file"] if name in LONG_VALUE_OPTIONS else []
            continue
        for letter in word[1:]:
            interactive = word[:1] == "-" if letter == "i" else interactive
            login = login or letter == "l" and word[:1] == "-"
            owed += [letter] if letter in VALUE_OPTIONS else []
    if len(_STATES) > 256:
        _STATES.clear()
    _STATES[id(argv)] = (argv, len(argv), (interactive, login, norc))
    return interactive, login, norc


def _startup_free(argv):
    """Whether the run reads no startup file the step may have written before its program (#2858
    round 9, rule 4; measured on bash 5.2.21 and 3.2.57, where such a file may read stdin itself):
    no login (`-l`, `--login`, `-login`: `~/.bash_profile`), and no interactive shell (`~/.bashrc`)
    but with `--norc`, `-norc` or an rc FILE of `/dev/null`. A `BASH_ENV` or `ENV` the step sets is
    `shadowed`'s to find; one the job's `env:` sets is a gap the guard names."""
    interactive, login, norc = _state(argv)
    return not login and (not interactive or norc)


def _cleared(argv, at, startup=False):
    """Whether a clear this PR adds fires at the option word `argv[at]` (#2858 round 9, the
    literal-only ruling): the shell is surely itself (`_sure_shell`, rules 1 and 3), no word up to
    `argv[at]` may expand (`_run`, rule 2), and -- for a clear that starts the shell (`startup`:
    `--pretty-print`'s print, a lone `-`'s FILE, `-s -c`) -- the whole run is literal and reads no
    startup file (`_startup_free`, rule 4). A refusal, an exit and noexec read none: `bash -l -n`
    and `bash --login --version` run nothing, measured."""
    expansion = _run(argv)[1]
    return _sure_shell(argv) and at < expansion and (
        not startup or expansion == len(argv) and _startup_free(argv))


def _runs_nothing(argv, at):
    """Whether a measured shell, its option word `argv[at]` among them, runs NONE of its program
    though it reads it, exiting 0 (#2858 round 3): the whole run's last state (`_run`) -- `-n`
    (noexec: `bash -n -s <<'EOF'`, and `-version` after a short option, the letters `v e r s i o
    n`) or `-o noexec`, each undone by a later `+n` / `+o noexec` (`bash -n +n -s` runs), or `-D`
    (strings printed) -- and only where the run holds no word that may expand, which may be `+n`
    (`X=+n; bash -n $X -s` runs) or hand `-n` over as a FILE (#2858 round 4). The stdin walk answers
    as for a refusal -- the body is not the shell's program and no check in it counts -- so a use
    after is reported and a download in the body is not: nothing runs. `-t` runs ONE command and is
    read on."""
    if os.path.basename(argv[0]) not in _MEASURED_SHELLS:
        return False                            # whether it is surely that shell: `_cleared`'s
    return type(argv[at]) is str and _run(argv)[2]   # the whole run's last state (`-n +n` runs)


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
    if type(argv[0]) not in (str, Sure) or os.path.basename(argv[0]) not in _MEASURED_SHELLS:
        return False
    if long_option(argv, at) or at >= _run(argv)[1]:
        return False                            # `-noediting` is long; after `$X` nothing is sure
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


# What a word that may expand is read as, in turn, where the `-c` string is looked for (#2858
# round 4): gone (an empty `$X`), itself, a long option taking the next word as its FILE
# (`X=--rcfile`), and a short option ending the leading run of long options (`X=-e`).
_READINGS = ((), None, ("--rcfile",), ("-e",))


def _in_every_reading(argv, walk):
    """`walk(argv)` where no word in the option run may expand (`_run`); else the words `walk` finds
    in ANY reading of the words that may (`_READINGS`, one reading for all of them at once), in
    order and once each, the step's own words only: a string runs where one reading runs it (`X=;
    bash --rcfile $X -nor -c P` runs `P`, `-nor` the rc file), and a refusal or an exit holds
    within its reading alone (`X=; bash --rcfile $X --version -c P` runs `P` too)."""
    _, first, _, end = _run(argv)
    if first >= len(argv):
        return walk(argv)
    found: list = []
    for reading in _READINGS:                   # the words the options end at stay as written
        words = [argv[0]] + [part for at, word in enumerate(argv[1:], start=1) for part in (
            (word,) if reading is None or at >= end or _literal(word)
            or not reading and _one_word(word) else reading)]    # `"$X"` never vanishes; `"$@"` may
        for word in walk(words):
            if any(word is mine for mine in argv) and not any(word is seen for seen in found):
                found.append(word)
    return found


def _dash_c_operand(argv):
    """The script operand of a shell's `-c` in one reading, every word as written: the first operand
    after the options past a cluster carrying `c` (`_past_options`), or none where an option word
    before the cluster is one the shell refuses (#2606, #2616: `bash -o pipefial -c P`) or a `--`
    ends the options first. An option's value is skipped before anything else is asked of it, a
    `--` too (`bash -rcfile -- -c P` runs `P`: the `--` is the rc file). Past an operand -- the
    FILE -- every later word is the FILE's parameter, and a FILE may hand its parameters to a shell
    (`printf 'exec bash "$@"' > w.sh; bash w.sh -c P` runs `P`, and `eval "$4"` runs `P` after `-o
    pipefial`): there no word refuses, exits, owes a value or ends the search, before the cluster
    carrying `c` or after it (`_past_options`' `past`, round 6), and its operand is handed on as
    `main` reads it (#2858 round 5) -- for what it runs alone (`_sure_string`)."""
    owed, past = 0, False
    for position, token in enumerate(argv[1:], start=1):
        if owed and not past:                   # an option's value, not an option word
            owed -= 1
            continue
        if token == "--" and not past:
            break
        long = long_option(argv, position)
        if long is None and token.startswith("-") and not token.startswith("--") and "c" in token:
            return _past_options(argv, position, past)
        if past:
            continue                            # the FILE's parameter: nothing bash refuses
        if long or token[:2] == "--":
            if _refused_long(argv, position):
                return []
            owed = long in LONG_VALUE_OPTIONS
        elif token[:1] in ("-", "+"):
            if _refused(argv, position) or _refused_name(argv, position):
                return []
            owed = sum(letter in VALUE_OPTIONS for letter in token[1:])
        else:
            past = True                         # an operand: the FILE, its parameters after it
    return []


def _sure_string(argv, word):
    """Whether the shell `argv[0]` surely RUNS `word`, the `-c` string `_after_dash_c` found (#2858
    round 6): no word in its option run may expand, the run keeps no `-n`, `-o noexec` or `-D`
    (`_run`), and the run ends at the string -- the cluster before any operand. Else the string
    is read for what it runs, and a check in it counts for nothing, as in a stdin body no shell is
    sure to read: past an operand it is the FILE's parameter (`bash /dev/null -- -c '<check>'`
    runs no check), after an expansion it may be the FILE or `--version`'s (`X=-s; bash $X -- -c
    '<check>'`), and under noexec the shell reads it and runs none of it."""
    _, expansion, nothing, end = _run(argv)
    if expansion < len(argv) or nothing:
        return False
    at = end + (argv[end:end + 1] in (["-"], ["--"]))
    return at < len(argv) and argv[at] is word


def _after_value(argv, at):
    """`workflow_programs.candidates`' answer for the value `argv[at]`: the words after it up to the
    first operand, and any after a later word that may spell an option -- or the value itself,
    where its output is words (`sh $(echo tool)`)."""
    rest = argv[at + 1:]
    end = next((k for k, after in enumerate(rest, 1) if not _before_operand(after)), len(rest))
    more = next((k for k in range(end, len(rest)) if _may_spell_option(rest[k])), len(rest))
    return argv[at], rest[:end] + rest[more + 1:] or (
        [argv[at]] if shell_reader.yields_words(argv[at]) else [])


def _value_after_dash_c(argv, at):
    """The index of the operand after the `-c` cluster `argv[at]` where that operand is a parameter
    expansion (`$Y`, `"$Y"`, `${Y:-}`; a `$(...)` is the dynamic program's), or None: it may be an
    option word or nothing, so the string may be a later word (`Y=-c; bash -c $Y P`, `Y=` and
    `Y=-e` run `P`, measured; #2858 round 7), and it stands where the shell reads its options."""
    found = _past_options(argv, at)
    k = next((i for i in range(at + 1, len(argv)) if found and argv[i] is found[0]), None)
    if k is None or not _value(argv[k]) or argv[k - 1] in ("-", "--") and _one_word(argv[k]):
        return None                             # after `-c --` a `$Y` may vanish (round 8), a member never
    return None if shell_reader.has_substitution(argv[k]) else k


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
    """Whether `word` is written as itself, with nothing in it a shell expands (#2858 round 9, rule 2):
    a plain `str` or `Sure` word, which the reader leaves only for text no pattern, brace or lifted
    substitution reaches -- it types an unquoted `*`, `?`, `[x]`, `{a,b}` or `@(x)` as `Rewritten`
    (`/nonexistent*` may vanish under `nullglob`), and `"*"` or `\\*` as the plain `*` they are --
    holding no `$` or backquote it could not lift (`${X:-${Y}}`, nested, stays plain) and not
    beginning with a `~`, which it leaves plain quoted or not (`HOME=-i; bash ~`). Such a `-o` value
    outside the name table is a refusal whether it is a misspelt name or no name at all (`-`,
    `/dev/stdin`: both bashes answer `invalid option name` and exit 2, #2606)."""
    return type(word) in (str, Sure) and "$" not in word and "`" not in word and word[:1] != "~"


class Sure(str):
    """A command word `certified` marks (#2858 round 9): written as itself, reached through literal
    words, in a step that leaves it its own name. Read as the `str` it is everywhere but where a
    clear or a credit this module adds asks for a shell that is surely itself (`_sure_shell`)."""


# The spellings of a measured shell that are surely it once `certified`: by PATH, or in `/bin` or
# `/usr/bin` -- not `./bash` or `~/bin/sh`, a file the step itself may have written.
_SURE_SHELLS = _MEASURED_SHELLS + tuple(d + s for d in ("/bin/", "/usr/bin/") for s in _MEASURED_SHELLS)


def _sure_shell(argv):
    """Whether `argv[0]` is surely the measured shell it names (#2858 round 9, rules 1 and 3): a `Sure`
    word, spelled as `_SURE_SHELLS` lists. Every clear and check credit this module adds asks it."""
    return type(argv[0]) is Sure and argv[0] in _SURE_SHELLS


def _refused_long(argv, at):
    """Whether the shell `argv[0]` refuses the long option word `argv[at]` outright, running
    nothing (#2616): for `bash`, and for `sh`, which may be bash (the fail-closed reading), a
    two-dash word outside the tables or past the leading run of long options, a word in either
    spelling with a value glued on
    (`--rcfile=f`, `-rcfile=f`), or one of `LONG_EXITS`, which prints and exits; for `dash` any
    two-dash word (a one-dash one is a letter cluster to it, `_refused`'s). `--` is no option.
    False for every shell outside `_MEASURED_SHELLS`; read by the name it spells, a `${X:-bash}` too,
    since whether the shell is surely that one is every reader's own question (#2858 round 9:
    `_cleared`, `_sure_shell`)."""
    if os.path.basename(argv[0]) not in _MEASURED_SHELLS:
        return False
    word, name = argv[at], long_option(argv, at)
    if at >= _run(argv)[1]:
        return False                            # after `$X` the word may be its FILE: read on
    if os.path.basename(argv[0]) == "dash":
        return word[:2] == "--" and word != "--"
    if word[:2] == "--" and word != "--" and at >= _run(argv)[0]:
        return True                             # past the leading run: `bash -e --norc` is refused
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
    (`shell_wrappers.Defaulted`, #2337), every one of which is a `str` SUBCLASS here (`Sure` is
    the one subclass written as itself: `certified`'s mark, #2858 round 9). The program
    such a command word is handed is #2337/#2344's own report, and a letter table cannot overrule
    it, because `X` may hold `zsh`.

    A word that is not all letters is read on too, and fail-closed: bash,
    dash and ksh refuse a digit or a brace (`-1`, `-I{}`, `-nw5`) but zsh
    RUNS `-1`, and all five run the program after `sh -c -u$X P` wherever
    `X` is empty, so a word holding an expansion is never a refusal."""
    if type(argv[0]) not in (str, Sure) or os.path.basename(argv[0]) not in _MEASURED_SHELLS:
        return False                            # a `str` subclass is a name not written
    if long_option(argv, at) or at >= _run(argv)[1]:
        return False                            # `-login` is long; after `$X` nothing is sure
    letters = argv[at][1:]
    return letters.isalpha() and any(letter not in SHELL_OPTIONS for letter in letters)


def _past_options(argv, at, past=False):
    """The first operand after `argv[at]`, the cluster that carries `-c`.

    Bash and dash read on through the option words after `-c` (#2332): `sh -c -e P`, `bash -c -x P`
    and `sh -c +x P` all run `P`. Each `o` or `O` in a word takes the next word as its value (`-c -o
    pipefail P`, `-co pipefail P`); a `-` or `--` ends the options, and the word after it is the
    program even if it begins with `-`; a `--long` word after `-c` is one both shells refuse, and
    nothing runs. So is a word of letters one of which the shell in hand refuses (`sh -c -K P`, `sh
    -cK P`, `_refused`): it exits before it reads `P`, so no program is handed over (#2475), and an
    `-o` whose value is no option NAME is one too (`_refused_name`, #2560). Past an operand (`past`)
    the words are the FILE's parameters, which no shell parses: none refuses or exits and a long one
    takes no value, so the first that is no option word is the one handed on (`echo 'eval "$4"' >
    w.sh; bash w.sh -c -o - P` runs `P`, #2858 round 6).
    """
    while True:
        if not past and (_refused(argv, at) or _refused_name(argv, at)):
            return []                           # the shell exits before the program
        at += 1 + (argv[at][:2] != "--" and sum(letter in VALUE_OPTIONS for letter in argv[at][1:]))
        if at >= len(argv):
            return []
        if not past and (argv[at].startswith("--") and argv[at] != "--" or long_option(argv, at)):
            return []                           # a long option after `-c`: refused
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
