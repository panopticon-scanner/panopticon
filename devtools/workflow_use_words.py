#!/usr/bin/env python3
"""The command words a use is read through, split out of `workflow_uses` whole (#3143, at its fold of #3145):
the programs that run a file they are handed (`INTERPRETERS`, `UNPACKERS`, `EXECUTORS`), the argvs the step's own
values make of a stage (`_resolved`, `_on_stdin`, #2425), and the value command word the guard's second walk reads
as a possible runner (`_value_command` and its helpers, #3143). `workflow_uses` imports each of them back, and
re-exports the names its callers reach there.
"""
import os
import re

import shell_lex
import shell_reader
from shell_reader import command
from workflow_forms import same_file
from workflow_programs import _SHELL_STRING, scripts
from workflow_values import _as_word, valued_argvs

INTERPRETERS = ("sh", "bash", "dash", "zsh", "ksh", "ash", "csh", "tcsh", "fish", "mksh",
                "python", "python3", "perl", "ruby", "node", "php", "pwsh", "java", "eval", "source",
                ".")

# Unpacking a downloaded archive executes its bytes too: they choose what
# lands on disk and under what name.
UNPACKERS = ("tar", "unzip", "install", "gunzip", "bsdtar")

EXECUTORS = INTERPRETERS + UNPACKERS

# ONE whole reference (`$T`, `${T}`, `${T:-d}`, `${a[0]}`): bash splits its value unquoted.
_WHOLE = re.compile(r"\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*(?:\[[0-9]+\]|:?[-=][^{}]*)?\})", re.A)


def _first_operand(words):
    """The first word of `words` that is no option: the one a shell named by a value command word would run as its
    script (#3143) -- the fetched file in `$SHELL ./t`, `head` in `$S head -n 99 t`, where `$S` may be nothing in
    front of a name the reader knows (#2472, #3003) and a shell there would run `head`, not `t`; None where none."""
    return next((word for word in words if not str(word).startswith("-")), None)


# A default the reader reads its own way (`${X:-sh}` as `sh`, `${X:=cat}` as `cat`, a wrapper's as the wrapper: #2472)
# and an array spliced whole (`"${CMD[@]}"`), which the guard resolves at its splice (#2770): neither is a value this
# guard cannot name. An alternate (`${A:+echo}`) is: it reads as a bare reference in its place (#3003).
_OWN_FORM = re.compile(r"^\$\{[A-Za-z_@*#?0-9]+(?:\[[^]]*\])?:?[-=]")

_SPLICE = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\[[@*]\]\}$")

# One expansion in a command word's text: a braced one (one level of braces inside), a name, a positional, `$@`, `$*`.
_EXPANSION = re.compile(r"\$(?:\{(?:[^{}]|\{[^{}]*\})*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9@*])")


def _value_command(word):
    """Whether a command word holds a live `$` expansion (`$SHELL`, `"$RUN"`, `"$@"`, `${X#y}`, `${P}sh`) whose
    program may be a shell -- the text after its last expansion ends some name of `INTERPRETERS` and holds no `/`
    (`$S/x` runs an `x`; `a$` expands nothing) -- so that, where the table gives it no value at all, the union rule
    reads it as a possible runner of the fetched file that is its first operand (`use`, #3143). Not a single-quoted
    `'$X'`, a default the reader reads its own way (`_OWN_FORM`) or an array spliced whole (`_SPLICE`); an alternate
    is one, the bare reference it reads as, and a word with no `_Token` facts reads live: the fail-closed direction.
    A command substitution (`$(which sh) ./t`) keeps `main`'s reading, a named limit."""
    text = str(word)
    if _OWN_FORM.match(text) or _SPLICE.match(text) or getattr(word, "live_dollar", True) is False:
        return False
    ends = [found.end() for found in _EXPANSION.finditer(text)]
    if not ends:
        return False
    tail = text[ends[-1]:]
    return "/" not in tail and any(name.endswith(tail) for name in INTERPRETERS)


def _unvalued(argv, table):
    """Whether `table` gives `argv` no value at all -- `_resolved` makes no argv of it -- so that a value command
    word there may name any program (`use`, #3143)."""
    return next(_resolved(argv, table), None) is None


def _value_stage(statement, position, argv):
    """Whether the second walk asks the table about this stage (`uses`, #3143) -- `static_values` walks the step up
    to it: its command word is a value command word, or it is a `cat` whose next stage holds a `$`."""
    if argv and os.path.basename(argv[0]) == "cat" and position + 1 < len(statement.stages):
        return any("$" in str(word) for word in statement.stages[position + 1].argv)
    return bool(argv) and _value_command(argv[0])


def _copied(how, name, dest):
    """`how`, naming the copy of `dest` it reaches the file through (`uses`)."""
    if same_file(name, dest):
        return how
    shown = re.sub(r"^\$CWD[^/]*/", "", name).replace("$UP", "..")
    return how + " (as `%s`, copied from it earlier)" % shown


def _on_stdin(argv):
    """Whether a shell argv the table MADE may run its standard input (#2425: a `-c` string's own
    program), as `_resolved` asks: not where that string is ONE bare `cat` or `tee` (no operand but
    `-`, no redirection) that only hands its input on (`CMD=sh; $CMD -c 'cat' < f`); any other may,
    failing closed (`cat "$0"`, `tee x`, `csh`, `echo sh`). The rule is the table's: the use as
    written keeps main's reading, a printer's stream unfollowed: `sh -c 'cat' < f` over-reports."""
    strings = scripts(argv) if os.path.basename(argv[0]) in _SHELL_STRING else []
    try:
        parsed = list(shell_reader.statements(strings[0])) if len(strings) == 1 else []
    except shell_lex.Unreadable:
        parsed = []
    if len(parsed) != 1 or len(parsed[0].stages) != 1:
        return True
    stage, inner = parsed[0].stages[0], command(parsed[0].stages[0].argv)
    return bool(inner) and (os.path.basename(str(inner[0])) not in ("cat", "tee") or bool(
        stage.reads or stage.writes) or not set(map(str, inner[1:])) <= {"-"})


def _resolved(argv, table):
    """The argvs `use()` weighs after `argv` as written (#2425, #2489): `valued_argvs`' argvs, on
    the terms it leaves its caller -- a word that was ONE whole reference (`_WHOLE`) split on its
    value's blanks, then `command()` re-reading the argv, one left empty or a shell whose `-c`
    string is a bare printer (`_on_stdin`) dropped -- and none where nothing resolves. A first word
    the table put there that is an assignment is the command bash runs, so no argv is made of it --
    behind a written `env`/`sudo` it is theirs, and main's dynamic-operand report stands."""
    mark = object()     # never resolves: it fences each word, so a made word's source is known
    fenced = [part for word in argv for part in (mark, word)]
    for words in valued_argvs(fenced, table):
        if words is fenced:                 # `[argv]` itself: nothing resolved
            return
        sources, source, kept = iter(argv), "", []
        for word in words:
            if word is mark:
                source = next(sources)
            elif word is not source and _WHOLE.fullmatch(source) and re.search("[ \t\n]", word):
                kept += [_as_word(shell_reader.derived(part, word), source)
                         for part in re.split("[ \t\n]+", word) if part]
            else:
                kept.append(word)
        if kept and kept[0] is not argv[0] and shell_reader._ASSIGNMENT.match(kept[0]):
            continue                        # bash runs it as the command: never an assignment
        if (kept := command(kept, argv)) and _on_stdin(kept):   # (#2670) which words the table made, by `argv`
            yield kept
