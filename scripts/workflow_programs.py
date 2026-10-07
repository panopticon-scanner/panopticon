#!/usr/bin/env python3
"""Which program a command hands a shell, read off its argv and its stage.

Split out of `scripts/workflow_forms.py` (#2331's follow-ups) the way `scripts/workflow_operands.py`
and `scripts/workflow_gating.py` were: that module had 51 lines of room left, fewer than the third
batch of those follow-ups adds to these readers. What is here answers one question of one command --
which program it hands a shell -- and reads no statement around it, only, for a program piped into
it, the stages in front of it in its pipeline (#2333, #2478):

    `scripts`         the script handed to `eval` or `sh -c` as a STRING, which is the same act one
                      quote away from a substitution, `Opaque` where a `$(...)` among its text
                      prints part of it
    `stdin_program`   whether an interpreter's program arrives on its standard input instead, which
                      is the same act one REDIRECTION away (`bash -s <<'EOF'`), and in what
                      language, where a table names it (`$CMD` is a value none places)
    `stdin_command`   the command whose stdin-program answer an enclosing `eval` or `sh -c`
                      inherits, preserving an inner `$CMD` for the guard's hand-off report
    `stdin_scripts`   the body that program is, where it is or may be shell: the heredoc or
                      here-string a `cat` printer in front hands down the pipe (`handed`, #2467), or
                      the text (one per distinct reading, `spellings`, #2476 R-F1) an `echo` or
                      `printf` pipes in under the runner `shell` (`printed`), through pass-through
                      stages (`producer`, #2478) too, each a `Stdin` naming the shell the step runs
                      to read it, under whose `-e` a check runs -- or none, where none counts
    `unprinted`       the printer piping one in whose text no reading `spellings` gives spells out,
                      or, where one between rewrites it, the stage in front and that text (#2478,
                      review I-1) -- for `unread_program` to weigh; never a heredoc-fed `cat`
                      handing it on intact (`printed` or `_unread_stdin` has it, #2467, R-F13);
                      `printed`, `spellings`, `producer`, `unspelled` (its answer), `ANY`, `Named`,
                      `handed`, the pipe test `_piped` and the `_PRINTERS` table live in
                      `workflow_printers`, re-exported here
    `runs_under`      the shell a stdin body is read under (#2476): another reader's basename
                      (`sudo sh` → `sh`), the holder's plain name where its words through a `-c`
                      string are all literal, or `Named(name)` -- both readings -- behind a value, a
                      default or an `eval`/`-c` string that may name the reading shell
    `candidates`      the words that may be the program, up to the first operand and past a later
                      word that may spell an option, where a value this module does not follow
                      stands in a shell's options
    `dynamic_program` the program word a LITERAL shell is handed that is all expansion
                      (`sh -c "$P"`, `sh -c "$(cat f)"`), which spells no command at all

`workflow_forms` imports all but `stdin_command` (the guard's) and `Opaque`: its `flattened` reads
each script found here in place of the command handed it -- a stdin one under its reader's `-e`
(`runs_under`), and with no check in it counted where it has none, behind a string, under a `$`
command word (`VALUE_PROGRAM`) or where it is `Opaque` -- its `unread_program` weighs the
candidates, the unprinted and the dynamic program, and the guard takes `stdin_program` and
`SHELL_PROGRAM` through it, `VALUE_PROGRAM`, `ANY`, `handed` and `stdin_command` directly. The
option-letter tables of `workflow_options` are read here and in `workflow_posture._errexit`, the one layer up that
reads a shell's options too (#2443, #2475).

Stdlib only, like everything under it.
"""
import functools
import os
import re

import shell_lex
import shell_reader
from shell_text import Process
from workflow_options import (LONG_VALUE_OPTIONS, SET_OPTION_NAMES as SET_OPTION_NAMES, _dash_s, long_option,
                              SET_OPTIONS as SET_OPTIONS, _credited, _run, Sure, _cleared, _sure_shell,
                              SHELL_OPTION_NAMES as SHELL_OPTION_NAMES, _STDIN_OPERANDS,
                              SHELL_OPTIONS as SHELL_OPTIONS, VALUE_OPTIONS, _BARE as _BARE,
                              _MEASURED_SHELLS as _MEASURED_SHELLS, _VALUE as _VALUE,
                              _before_operand as _before_operand, _may_spell_option,
                              _past_options, _long_word, _refused as _refused, _refused_long,
                              _refused_name as _refused_name, _sure_string, _value, _void,
                              _after_value, _value_after_dash_c, _literal, _one_word)
from workflow_sure import (_dash_c_strings, _floor_candidates, certified as certified, inner_command,
                          uncertified as uncertified)
from workflow_printers import (ANY as ANY, Named as Named, _PRINTERS as _PRINTERS, _piped as _piped,
                               file_operand as file_operand, handed as handed, operand, rendered,
                               printed as printed, producer as producer, spellings as spellings,
                               substituted, unspelled as unspelled, unsubstituted)


# A shell handed a SCRIPT as a string: `eval "curl ... -o x"`, `sh -c "..."`. The text is shell and
# this module reads shell, so the quotes are not a grammar it lacks -- only one it was not looking
# through. `python3 -c` and `perl -e` are NOT here: that text is another language, and the gap list
# says so.
_SHELL_STRING = ("sh", "bash", "dash", "ash", "ksh", "zsh")


class Opaque(str):
    """A script `scripts` hands on from a string holding a lifted `$(...)` or backquote among text
    of its own, as `rendered` writes it: `sh $(...)` (#2486), or `sh tool` where one printer prints
    `tool` (#2487). Bash reads what the substitution PRINTS as part of the script, word-split where
    unquoted (the reader drops quotes), so `workflow_forms.flattened` reads it in place and counts
    no check in it: `bash -ec "$(echo 'true ||') <check>"` never runs the check."""


def scripts(argv):
    """The shell scripts this command is handed as a string, in order, each the text bash hands the
    shell: a double-quoted `\\$` or `` \\` `` without its backslash (`shell_reader._stage`'s
    `spelled`, #2342).

    A word that is all expansion as `rendered` writes it -- one lifted `$(...)` or backquote, or
    several beside `$` words (`$P$(...)`) -- is never one: it spells no command, and
    `dynamic_program` reports it (#2483, #2486). Nor is a word holding a heredoc, a `<(...)` or any
    other marker: each stands for text held in the parse it came from, and the guard's `_walk`
    already credits what is inside it. A `$(...)` or backquote among text of the word's own does not
    make it none (#2486): `eval "sh $(cat f)"` hands on `sh $(...)`, `Opaque`, whose `sh` is weighed
    as `sh $(cat f)`'s is, and `eval "sh $(echo tool)"` `sh tool`, what its one printer prints
    (#2487) -- the substitution's own text still read where `_walk` reads it, and no marker of this
    parse left to reach another. A text so rendered that the reader refuses is none, as before
    #2486: `eval "cat <<$(a b) …"` takes its delimiter from what `a b` prints, and `cat <<$(...)` is
    no spelling to end the body at, so the string is unread and the rest of the step read."""
    shell = bool(argv) and os.path.basename(argv[0]) in _SHELL_STRING
    out = []
    for word in _program_words(argv):
        script = _script(word)
        if script is not None and shell and not _sure_string(argv, word):
            script = Handed(script)
        if script is not None:
            out.append(script)
    return out


class Handed(str):
    """A `-c` string `scripts` hands on that the shell is not sure to run (`_sure_string`, #2858
    round 6): read for what it runs, with no `reader` under whose `-e` a check in it counts, as
    `workflow_forms.flattened` reads a stdin body no shell is sure to read (`Stdin`)."""
    reader = None


def _program_words(argv):
    """The words where a program stands: `eval`'s -- joined as the ONE word bash runs where a
    statement is split across them (`_joined`), else one by one as before -- or a shell's `-c`
    operand."""
    name = os.path.basename(argv[0]) if argv else ""
    if name == "eval":
        joined = _joined(argv)
        return [joined] if joined is not None else [t for t in argv[1:] if not t.startswith("-")]
    return _after_dash_c(argv) if name in _SHELL_STRING else []


# A word of `eval`'s that begins or ends with a control or redirection operator, or is one: the
# statement it belongs to continues in the word beside it, which bash sees once it has joined
# them and a reading of the words one by one never does (#2673).
_EDGE = re.compile(r"^(?:\|\||&&|[|&;<>(){}])|(?:\|\||&&|[|&;<>(){}])$")


def _joined(argv):
    """`eval`'s words as the ONE text bash runs, where reading them one by one would miss a
    statement split across two of them (#2673: `eval 'curl … |' 'sh'`, `'…' '|' 'sh'`,
    `'sh -c "$(curl …' ')"'`): any word `_EDGE` matches makes the join -- a space between the
    words after a leading `--`, where bash ends `eval`'s own options (dash runs `--` as a
    command and nothing after it: fail-closed where a step's `sh` is dash). The join keeps every
    word's lifted text (`shell_reader._Token`) and its `spelled` form, so `_script` reads it as
    one word: `Opaque` where a `$(...)` stands among text, none where it is all expansion. None
    where no word is such an edge: the words then read one by one, as they did, each a script
    whose operands `workflow_operands` re-parses with its quoting kept."""
    words = argv[1:]
    if words and getattr(words[0], "spelled", words[0]) == "--":
        words = words[1:]
    if len(words) < 2 or not any(_EDGE.search(str(word)) for word in words):
        return None
    markers = {key: value for word in words for key, value in getattr(word, "markers", {}).items()}
    joined = shell_reader._Token(" ".join(words), markers) if markers else " ".join(words)
    if any(hasattr(word, "spelled") for word in words):
        joined = joined if markers else shell_reader._Token(joined, {})
        setattr(joined, "spelled", " ".join(getattr(word, "spelled", word) for word in words))
    return joined


def _script(word):
    """`word` as `scripts` hands it on, or None where it is no script. A plain text, `eval`'s join
    among them, is handed on as it is; a word holding lifted text is `rendered`, and is no script
    where it is all expansion or holds a marker that is neither a substitution handing on words nor
    a `<(...)`/`>(...)` handing a FILE (#2684: `sh $(...) <(...)` reads as `sh` handed a word that
    may vanish and a file operand, not as nothing)."""
    keys = getattr(word, "markers", {})
    if not keys:
        return getattr(word, "spelled", word)
    text = rendered(word)
    if _all_expansion(text) or not all(
            shell_reader.yields_words(shell_reader.derived(key, word))
            or isinstance(keys[key][1], Process) for key in keys):
        return None
    try:
        shell_reader.statements(text)
    except shell_lex.Unreadable:
        return None
    return Opaque(text)


def _after_dash_c(argv):
    """The script operand of a shell's `-c`, wherever the flag was clustered (`sh -ec`, `bash -lc`,
    `bash -euc`: a short-option cluster carrying a lowercase `c` IS `-c`, the ordinary CI idiom): the
    first operand after the options, which need not be the next word -- in every reading of a word in
    the option run that may expand (#2858 round 4), and `main`'s where the shell is not sure (round 9)."""
    return _dash_c_strings(argv)


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
    `stdin_program` keeps possible past a value (#2605); a literal long option remains #2616. So
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
    return _floor_candidates(argv, _candidates(argv))


def _candidates(argv):
    """`candidates`' answer for a shell, read off its option words as the shell reads them."""
    owed = 0
    for at, word in enumerate(argv[1:], start=1):
        if owed:
            owed -= 1
        elif _value(word):
            return _after_value(argv, at)
        elif word in ("-", "--") or word[:1] not in ("-", "+"):
            break                               # the options end: a program, or `-`/`--`
        elif (long := long_option(argv, at)) or word[:2] == "--":
            if _refused_long(argv, at) and _sure_shell(argv):   # `bash --bogus $X '…'` runs nothing (#2616)
                break
            owed = long in LONG_VALUE_OPTIONS    # `bash -rcfile FILE $X '…'`: the FILE is its value
        elif "c" in word:                       # a `-c` cluster, whose string `scripts` reads --
            k = _value_after_dash_c(argv, at)   # unless it is a `$Y` (`Y=-c; bash -c $Y P`, round 7)
            if k is not None:
                return _after_value(argv, k)
            break
        else:
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
    `eval sh "$(cat f)"`, `sh -c "$P$(cat f)"`, #2486), asked here as `readable` writes it: bash
    runs what they print, a catch-all even where one printer spells it (`rendered`, #2487). The
    price is #2483's: beside an unverified download, `sh -c "$(date)"` and `eval "$(ssh-agent -s)"`
    are reported though they run none of it. A `<(...)` or `>(...)` hands a file, not words
    (`shell_reader.yields_words`), and is not one; nor is a string that MIXES literal text with an
    expansion (`sh -c "echo $X"`), which is read as written (`Opaque` where a `$(...)` is among its
    text). `set -- "$P"` IS one, and `eval set -- "$OPTS"` runs nothing of the value as a command:
    an accepted over-report, because a `;` in that value does run (r0 finding 4)."""
    name = os.path.basename(argv[0]) if argv else ""
    for word in _program_words(argv):
        keys = getattr(word, "markers", {})
        text = shell_reader.readable(getattr(word, "spelled", word))
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
# The interpreters of the second kind. `python3 -c` and `perl -e` are already ruled another language
# by `scripts` above, and a heredoc is the same text one redirection over.
_FOREIGN = ("python", "python3", "perl", "ruby", "node", "php", "pwsh")


def stdin_program(argv):
    """Whether this command's PROGRAM is its standard input, and in what.

    `SHELL_PROGRAM` for a shell reading a script from stdin (`bash -s`, a bare `sh`, `dash -`),
    `FOREIGN_PROGRAM` for a program in a language this module does not read (`python3 -`),
    `VALUE_PROGRAM` for one under a value-form command word no table places (`$CMD`, `$PYTHON -`),
    and None when the program is somewhere else -- a file (`bash x.sh`), a `-c` string, a `-m`
    module -- which makes stdin that program's input DATA and not an act of this job's own.

    Read as OPERANDS rather than as a full option grammar: an interpreter's first word that is not
    an option is its program, and a shell's `-s` says every word after it is a positional parameter
    instead. See the guard's gap list for the spelling that leaves behind. At the step's own
    level a SURE shell's refused option word (`_sure_shell`, #2858 r9) -- a letter outside `SHELL_OPTIONS`
    (`sh -K <<'EOF'`, #2603), a `-o` value that is no name it takes (`bash -o pipefial`, `sh -o -`,
    #2606) or a long option outside its table (`bash --bogus`, #2616) -- runs nothing, as
    `_past_options` reads one after a `-c` (#2475); behind a string an inner shell's is read ON,
    fail-closed (#2500). A `--rcfile FILE` is skipped whole (#2616); a lone `-` with a word after
    it is bash's end of options, and that word, literal or one word, the script FILE (`bash - x.sh`,
    #2654) -- for a sure shell, with no word before it that may expand (`X=-s; bash $X - x.sh`); after
    `-s` the options are still read, and a `c` among them puts the program in the string (`bash -s
    -c true`, #2647), where `--`, `-` or an operand leaves it on stdin. A stdin operand after an
    option owed a value ends the walk there for another interpreter: python's `-O` takes no value,
    so `python3 -O - file.py <<'EOF'` runs its heredoc.

    A `-c` string or `eval`'s is ordinarily such a FILE-like place too (the `-c` string itself, not
    stdin, is the program) -- UNLESS that string is itself one statement whose own command is a
    stdin-reading shell (#2500): `eval 'bash -s'` and `bash -c 'sh'` then answer SHELL_PROGRAM for
    the ENCLOSING command, so its heredoc, here-string or pipe is read as `bash -s`'s or `sh`'s
    program, not `eval`'s or `-c`'s -- a download in it is caught -- and no check in it counts
    (`_stdin` names no reader), so a body ending in its check is reported though the step stops at
    it. `eval 'echo hi'` and `bash -c 'cat'` are not stdin-reading shells, so they are unaffected. A
    `-c` cluster the shell refuses hands over no string (`_past_options`), so `bash -c -K 'sh'
    <<'EOF'`, which runs nothing, is not read so; an INNER shell's refused letter is read on, as
    above, so `eval 'bash -K -s'` and `bash -c 'sh -K'` are, though bash and dash refuse them and
    run nothing -- fail-closed. The reading looks at most 64 strings deep (`_stdin`'s `depth`) and
    answers SHELL_PROGRAM past that, fail-closed, so seventy `eval`s before `echo hi <<'EOF'`
    over-report; with `workflow_forms.flattened` asking once per stage, an `eval eval … bash -s`
    chain costs time linear in its length and never overflows the stack (final review F1: it was
    cubic, 37 s at 200, and raised RecursionError at 1,600).

    For a SHELL, a value form or a word that may vanish (`_value`) does not END the walk there
    either (#2485): `X=-s; sh $X <<'EOF'` runs the heredoc in bash 3.2.57, 5.2.21 and dash alike, as
    `bash <<'EOF' $(true)` and `sh $X` with `X` unset do, where `$X`'s empty expansion drops the
    word outright. Read IN PLACE rather than weighed, fail-closed: `X` may just as well spell a FILE
    (`X=script.sh`) or an option nothing runs under -- one the shell refuses (`X=-K`, where bash and
    dash exit 2), `X=-n` (they read the heredoc and run none of it) or a bare `X=-c` (no string, rc
    2) -- so this over-reports there; the guard's gap list names the class. No check in the body
    counts either (`_stdin` names no reader): where `X` names a file no shell reads the body, so
    `X=/dev/null` runs a download past a body that is only the check, and `X=-s`, which stops at it,
    over-reports too. A `<(...)`/`>(...)` is NOT such a word, though `_value` matches its marker
    too: it always substitutes a real path, never empty, so `bash <(curl ...)` keeps reading as the
    FILE it is (`yields_words` tells a process substitution from a command substitution, whose
    OUTPUT may vanish instead); a MIXED word (`$(true)<(...)`) may yet split an option off before
    that path (`$(echo '-s ')<(...)` is `-s /dev/fd/63`, measured, #2858 round 9), and reads as one
    that may vanish -- beside the ones the gap list names (`X=script.sh`, `X=-K`, `X=-n`).

    A FILE after a value in the shell's option slot keeps stdin possible (#2605): the value may be
    `-s`, making that file and every later word a parameter, or `--rcfile`, making the file that
    option's value. This reads `sh $X file.sh <<'EOF'` fail-closed at the disclosed `X=-e` price. An
    explicit `--` before the value ends the option slot.

    A value-form COMMAND word (`$CMD`, `"$CMD"`, `${CMD}`, `$(echo sh)`, `$PYTHON -`) with stdin on
    it answers VALUE_PROGRAM (#2473): a name no table places may hold a shell, another language's
    interpreter or `true`. SHELL would read another language's program as though it were one, and
    report nothing for `$PYTHON - <<'EOF'` even beside a fetch (review I-2); FOREIGN leaves the body
    unread, an `Idle` report `kept` drops beside no reported fetch (#2499), so `CMD=sh; $CMD
    <<'EOF'` running `curl ... | sh` read CLEAN. As VALUE its body is read as shell all the same,
    additively (`stdin_scripts`; `workflow_forms.flattened` counts no check in it, since `$CMD` may
    not run it) -- a body no interpreter runs, `$CAT <<'EOF' > f`, over-reports -- and the guard's
    `_unread_stdin` reports the hand-off `Idle`. Its walk takes a shell's `-c`, `-s`,
    vanishing-operand and option-value rules, since the word may be a shell (`$CMD -s -- "$V"
    <<'EOF'` and `$CMD -oe pipefail <<'EOF'` read the heredoc, as does `$PYTHON -Ou - file.py
    <<'EOF'`, a stdin operand being no option's value; `$PYTHON -s file.py <<'EOF'`, `$PYTHON -Ou
    file.py <<'EOF'` and an interpreter's own option value spelled `$` (`$NODE -e "$CODE" <<'EOF'`,
    `$PYTHON -m "$MOD" <<'EOF'`, read past as a vanishing operand) over-report a hand-off, like
    `$PYTHON -O file.py`), An EXPANDING VALUE body is read after substitutions become value words
    (#2597), while a literal shell's stays unread and loud. No option word behind a `$` word is a
    refusal (#2475's per-shell scoping: `CMD` may hold zsh, which runs `-K`), so `CMD=sh; $CMD -K
    <<'EOF'` is read and its hand-off said, though every shell measured refuses `-K` and runs
    nothing -- fail-closed. #2500's inheritance includes VALUE_PROGRAM too (#2599): an inner `$CMD`
    makes an enclosing `eval` or `-c` string a value stdin reader, so its quoted body is read as
    shell and the hand-off names the inner word. This is fail-closed: an unset P makes the heredoc
    on `sh -c "$P"` run nothing, but it is reported. Without stdin, #2483's dynamic-program answer
    stays.
    """
    return _stdin(argv, 0)[0]


def stdin_reader(argv):
    """The `reader` (`Stdin`) of this command's stdin: None where no shell is sure to read it."""
    return _stdin(argv, 0)[1]


def stdin_command(argv):
    """The argv whose stdin-program answer this command inherits, or `argv` itself."""
    return _stdin_details(argv, 0)[2]


class Stdin(str):
    """A script `stdin_scripts` read off standard input or a `<(...)` FILE, and its `reader`
    (`_stdin`): the argv of the shell the step itself runs to read it, under whose `-e` a check in
    it runs; `()` where that shell's own options read stdin but its `-c` string names the shell that
    reads it (`bash -s -c 'sh'`), whose statements are the step's own and no check in them counts;
    or None, where no shell is sure to read it and nothing in it is the step's own."""
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
    return _stdin_details(argv, depth)[:2]


def _stdin_details(argv, depth):
    """`_stdin` plus the command whose answer an enclosing string inherits (#2599)."""
    if not argv:
        return None, None, argv
    kind, reader = _credited(argv, *_options(argv, depth), os.path.basename(argv[0]) in _SHELL_STRING and SHELL_PROGRAM)
    found = _eval_words(argv) if os.path.basename(argv[0]) == "eval" else scripts(argv)
    if found:
        text = " ".join(getattr(t, "spelled", t) for t in found)
        parsed = _parsed(text)
        if len(parsed) == 1 and len(parsed[0].stages) == 1:
            inner = inner_command(argv, parsed[0].stages[0])
            if depth >= 64:                    # bounded: past 64 strings, fail-closed
                return SHELL_PROGRAM, (() if kind == SHELL_PROGRAM and reader else None), inner
            inherited = _stdin_details(inner, depth + 1)
            if inherited[0] in (SHELL_PROGRAM, VALUE_PROGRAM):
                # No check in an inherited body counts; only a holder reading it is its reader.
                inherited_reader = () if inherited[0] == SHELL_PROGRAM and reader is not None else None
                return inherited[0], inherited_reader, inherited[2]
    return kind, reader, argv


def _eval_words(argv):
    """The words `_stdin_details` joins for `eval`: bash joins ALL of its own words -- `-`-prefixed
    ones too -- into ONE string before running it (`eval bash -s x.sh` is `bash -s x.sh`, still
    reading stdin, not `bash x.sh` alone), so `scripts()`'s filtered list is wrong for this join
    (review R1-I2). A leading `--` is dropped first: bash's `eval` ends its own options there
    (`eval -- bash -s` reads stdin), but dash's runs `--` as a command and nothing runs --
    fail-closed where a step's `sh` is dash. A word holding lifted text is `rendered` (#2683: `"sh
    $(echo -s)"` is `sh -s`, one printer spelling it, and `"sh $(cat f)"` is `sh $(...)`, a word
    that may vanish, not dropped whole; #2764: `"$(echo 'sh')"` is `sh`), and one that is all
    expansion once rendered, or whose rendering the reader refuses (`cat <<$(a b)`, #2486), is
    dropped, as every such word was: `eval "$(cat x)"` names no shell (#2483 reports the word,
    never the body)."""
    words = argv[1:]
    if words and getattr(words[0], "spelled", words[0]) == "--":
        words = words[1:]
    out = []
    for word in words:
        if getattr(word, "markers", None):
            text = rendered(word)
            try:
                if _all_expansion(text) or not _parsed(text):
                    continue
            except shell_lex.Unreadable:
                continue                    # a rendering the reader refuses is no word (#2486)
            out.append(text)
        else:
            out.append(word)
    return out


@functools.lru_cache(maxsize=1024)
def _parsed(text):
    """`shell_reader.statements(text)`, kept: an `eval` chain is asked at every one of its levels
    and the walk below reads up to 64 of them each time, so the same suffix is parsed many times
    over (final review F1: two hundred `eval`s). Read only, never mutated, by `_stdin_details`."""
    return shell_reader.statements(text)


def _options(argv, depth):
    """`_stdin`'s answer from the command's own words alone, its strings aside: what its options
    and operands say the program on its standard input is, and its reader."""
    name = os.path.basename(argv[0])
    shell = name in _SHELL_STRING
    foreign = name in _FOREIGN
    # `<(...)`/`>(...)` match `_value` too (`readable` renders every substitution alike) but never
    # vanish: a real path, never empty or split away, unlike `$(...)`'s OUTPUT (#2485's `$(true)`).
    value = not shell and not foreign and _value(argv[0]) and (
        not shell_reader.has_substitution(argv[0]) or shell_reader.yields_words(argv[0]))
    if not (shell or foreign or value):
        return None, None
    answer = SHELL_PROGRAM if shell else FOREIGN_PROGRAM if foreign else VALUE_PROGRAM
    reader = argv if shell and not depth else None
    options, value_option, parameters = True, False, False
    at = 1
    while at < len(argv):
        token = argv[at]
        at += 1
        if token in _STDIN_OPERANDS:
            # A lone `-` ends a shell's options as `--` does, and the word after it, if any, is the
            # script FILE: `bash - /dev/null` runs the file and stdin is its data (#2654) -- where that
            # word is literal or one word and the shell sure (`_cleared`, #2858 round 9); else it may
            # vanish (`X=; bash - ${X:-${Y}}`, `bash - "$@"`) and stdin is the program, as after `$X`.
            if token == "-" and shell and options and not parameters and at < len(argv) and _run(argv)[1] > at - 1:
                sure = (_literal(argv[at]) or _one_word(argv[at])) and _cleared(argv, at - 1, True)
                return (None, None) if sure else (answer, None)
            return answer, reader
        if token == "--":
            options = False
            if parameters:
                return answer, reader       # `bash -s -- -c x`: the rest are parameters (#2647)
            continue
        if not token.startswith(("-", "+")) or not options:
            if parameters:
                return answer, reader       # `bash -s arg -c x`: a parameter, not a `-c` (#2647)
            if (shell or value) and _value(token) and (
                    not shell_reader.has_substitution(token) or shell_reader.yields_words(token)):
                reader = None               # ... but it may name a FILE: no check counts
                value_option = value_option or options
                continue                    # the walk goes on as if absent
            return (answer, reader) if value_option or shell and _run(argv)[1] < at - 1 else (None, None)
        if word := _long_word(argv, at - 1):
            # A long option, in either spelling (#2616): refused or printing and exiting, nothing runs
            # where the shell is sure (#2858 r9); after a `$X` it may be letters (r3); a FILE is skipped.
            if shell and not depth and word in ("void", "unsure"):
                return (None, None) if word == "void" else (answer, None)
            at += word == "file"
            continue
        letters = token[1:]
        if parameters and shell_reader.dynamic(token, shell_reader.has_substitution):
            return answer, reader           # `bash -s -$X -c x`: `$X` may spell `-c sh` first
        if (shell or value) and "c" in letters:
            # The program is the `-c` string -- for bash. dash runs it and THEN, with an `-s` among
            # its options, reads stdin (`_dash_s`, #2647), so for `dash` and `sh` the body is the
            # program, the step's own text with no check credited (`()`): the string may eat stdin
            # first, and bash never reads it. So too after a word that may expand, where the
            # cluster may be a FILE or a long name (`X=; bash --rcfile $X -e -norc` runs, #2858).
            # After bash's own `-s` the reader is kept: a stdin shell the string names reads it.
            if shell and (at > _run(argv)[1] or name in ("sh", "dash") and (parameters or _dash_s(argv, at - 1))):
                return answer, None if at > _run(argv)[1] else ()
            if parameters and not _cleared(argv, at - 1, True):
                return answer, None         # `bash -s -c x`: only a sure bash leaves stdin unread (r9)
            return None, reader if parameters else None
        if (shell or value) and "s" in letters:
            if value:
                return answer, reader       # a `$` word: the words after `-s` are parameters
            # bash keeps reading options after `-s`, and a `c` among them puts the program in
            # the string (#2647): the walk goes on, and an operand, `--` or `-` ends it here.
            parameters = True
        # A shell's option word takes a value for each `o` or `O` in it (#2344,
        # `bash -oe pipefail`), and so does a `$` word's, which may be a shell;
        # another interpreter's, one where it ends so. Only a shell takes a
        # stdin operand for that value (and refuses `-o -`, rc 2): python's
        # `-O` takes none, so in `python3 -O - file.py` the `-` is stdin.
        # A measured shell refuses a `-o` name outside its table, or a value that is no name
        # at all, and exits before it reads stdin (#2606); `-n` reads it and runs none (#2858 r3).
        # Only at the step's own level: behind a string the inner shell is read ON (#2500).
        if shell and not depth and _void(argv, at - 1):
            return (None, None) if _cleared(argv, at - 1) else (answer, None)
        owed = (sum(letter in VALUE_OPTIONS for letter in letters) if shell or value
                else int(bool(letters) and letters[-1] in VALUE_OPTIONS))
        for _ in range(owed):
            if at < len(argv) and argv[at] in _STDIN_OPERANDS and not shell:
                return answer, reader       # the program is stdin after all
            at += 1
    return answer, reader


def runs_under(argv, reader, name):
    """The shell `workflow_forms.flattened` reads a stdin text's body under: another READER's
    basename, where one differs from the holder's own argv (`sudo sh` → `sh`); the holder's plain
    `name`, where the reader IS its own argv, no word of its own before `--`, up to and including a
    `-c` string (`_after_dash_c`: the words after it are parameters, R-F16; found by identity, so to
    `--` where that word's object recurs, as CPython's one-character `+` can), may spell an option
    once expanded (`_may_spell_option`, R-F12: `bash <<'EOF'`, `bash -s -c 'echo hi'`), and the
    command word is written as itself, not a `${X:-sh}` default (`Defaulted`, R-F15); or
    `Named(name)`, read by the printers as `ANY` -- no reader at all (#2473), a `-c`/`eval` string
    naming the shell that reads the body (`bash -c 'sh'`, `bash -s -c 'sh'`, `eval 'bash -s'`:
    #2500, R-F7), or such a word, an option's value too, that may name one at runtime (`bash $X`,
    `X='-c sh'` → `sh`; `bash -o $X`, `bash -$X`: R-F9, R-F12; refutes #2485's bash-or-nothing)."""
    if reader and reader is not argv:
        return os.path.basename(reader[0])  # another reader names itself (`sudo sh` → `sh`)
    words = argv[1:argv.index("--")] if "--" in argv else argv[1:]
    string = [w for w in _after_dash_c(argv) if sum(v is w for v in argv) == 1]
    words = words[:next((i + 1 for i, w in enumerate(words) if string and w is string[0]), None)]
    if reader and type(argv[0]) in (str, Sure) and not any(map(_may_spell_option, words)):
        return name                         # its own text, no word that may spell an option
    return Named(name)                      # a string, a value, a default, or no reader: both ways


def stdin_scripts(argv, stage, before=None, shell=None):
    """The script this stage hands an interpreter on its stdin, if it does, or as a `<(...)` FILE.

    A quoted delimiter hands over the body as written, so reading it is as sound as an `eval`
    string; `curl … | sh` is the same defect, as is `sh <<< '…'` (#2293), and so is the quoted
    heredoc or here-string a `cat` printer in front hands down the pipe (`handed`, #2467). An
    expanding body stays unread for a literal shell (the guard's `_unread_stdin`). Behind a value
    command word, it is read after command and arithmetic substitutions become value words (#2597),
    since the outer read owns them. Text an `echo` or `printf` in front (`before`) pipes in is read
    too, one text per distinct reading of the runner `shell` (`spellings`, #2476), where `printed`
    spells it (#2333): `echo 'sh tool' | sh`; else `unprinted` has it -- each through pass-through
    stages too (`producer`, #2478). A FILE's text is its one printer's (`substituted`).

    Each comes as a `Stdin` naming its `reader` (`_stdin`), the shell under whose `-e`
    `workflow_forms.flattened` counts a check in it: a literal shell the step runs, whatever stands
    in front of it (`sudo bash -s` reads as it always has, and so does `bash -s -c 'echo hi'`, whose
    string names no shell that reads stdin); `()` for the body of a holder whose own options read
    stdin (`bash -s -c 'sh'`), the step's own statements, with no check counting; and None behind a
    string that names the shell reading it (`eval 'bash -s'`, `bash -c 'sh'`), past a word that may
    vanish, under a `$` command word, or where the printer spells two readings (R-F8) or one and an
    unspelled one (R-F11), where no shell is sure to read it and nothing in it is the step's own
    (`workflow_forms.Unsure`). A FILE's `reader` is the shell or `source` reading it (#2487, #2495).

    Behind a `$` command word (VALUE_PROGRAM, #2473) the body and printed text are tagged and read
    as shell, though the word may hold none; `workflow_forms.flattened` counts no check there.
    `bound_stdin` drops that uncertain read when a job fetch binds the word (#2607). Inside a
    `$(...)`, `workflow_forms.substitution_script` weighs printed text as a shell's. `unprinted`
    weighs a shell's printer only, so `echo "$X" | $CMD` remains unread, filed under #2331."""
    here = stage.stdin_heredoc or handed(stage, before)
    if (filed := substituted(operand(argv))) is not None or here is not None:   # `<(...)` FILE
        readings = texts = [here[0] if filed is None else filed]
    else:
        source, intact = producer(stage, before)
        readings = spellings(shell_reader.command(source.argv), source, shell) if intact else []
        texts = [t for t in readings if t is not None]
    if not texts:
        return []
    expands = filed is None and here is not None and here[1]
    kind, reader = (SHELL_PROGRAM, argv) if filed is not None else _stdin(argv, 0)
    if kind not in (SHELL_PROGRAM, VALUE_PROGRAM) or expands and kind != VALUE_PROGRAM:
        return []
    if expands:
        context = shell_reader._Parse(texts[0])
        lifted = shell_reader._lift_substitutions(texts[0], context)[0]
        texts = [context.pattern.sub("$VALUE", lifted)]
    out = []
    for spelled in texts:
        text = Stdin(spelled)
        text.reader = reader if len(readings) == 1 else None
        setattr(text, "bound", stdin_command(argv)[0] if kind == VALUE_PROGRAM else None)
        out.append(text)
    # A FILE program beside a heredoc (#2764): the FILE is the program, and where its one
    # statement's command is a shell reading stdin (`bash <(echo 'sh') <<'EOF'`, `source <(echo
    # sh) <<'EOF'`), the heredoc is THAT shell's program -- read as shell, no reader (#2500).
    if filed is not None and stage.stdin_heredoc is not None and not stage.stdin_heredoc[1]:
        parsed = shell_reader.statements(filed)
        if len(parsed) == 1 and len(parsed[0].stages) == 1 and _stdin(
                shell_reader.command(parsed[0].stages[0].argv), 1)[0] in (SHELL_PROGRAM, VALUE_PROGRAM):
            text = Stdin(stage.stdin_heredoc[0])
            setattr(text, "bound", None)
            out.append(text)
    return out


def unprinted(argv, stage, before, shell=None):
    """The name and texts `unread_program` weighs (each text apart, review N-1) for the program this
    shell reads where no printer spells it out, or [] (`unspelled`, once `stdin_program` names a
    shell reading stdin; else a `<(...)` FILE's, `unsubstituted`, #2487): the `echo` or `printf`
    `producer` finds in `before` (the stages in front) where a reading `spellings` gives is
    unspelled (`echo "$X" | sh`, an escape outside `_decoded`'s table, EITHER reading of a
    `Named`/`ANY` runner: #2333, #2476 R-F1); where one between rewrites the text (`base64 -d`:
    #2478, R-P4), that text and the LAST stage in front's words, so a fetch in either is weighed
    (review I-1); past `_DEPTH`, a LOUD answer (`_PAST_DEPTH`). Never a heredoc-fed `cat` handing it
    on intact (`printed` or `_unread_stdin` has it, R-F13)."""
    if stage.stdin_heredoc is not None or stdin_program(argv) != SHELL_PROGRAM:
        return unsubstituted(operand(argv))
    return unspelled(stage, before, shell)
