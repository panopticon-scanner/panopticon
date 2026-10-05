#!/usr/bin/env python3
r"""A step's own literal values read into the two words its readers key on (#2468, #2600, #2601).

`workflow_uses.static_values` reads a USE through the values the step itself assigns (#2425,
#2489). Two readers sit where no use is asked and see only a stage or its pipeline: the printer
rules (`workflow_printers.printed`), which weigh the text `echo "$X" | sh` hands the shell, and
the stdin-program rules (`workflow_programs.stdin_program`, `workflow_forms.flattened`), which
read `$CMD <<'EOF'` as a hand-off to a word no table places, its body read as shell with no
check credited. `annotate` runs ONCE over a step's raw statements, before `flattened` reads them
(`workflow_guard.read`), and marks two kinds of word IN PLACE through the table live at each
statement, so no reader below it changes. A marked word is ONE whole reference
(`workflow_uses._WHOLE`: `$X`, `${X}`, `"$X"`, as the reader drops quotes, and `${X:-d}`,
`${X=d}` or `${a[0]}`, which `workflow_values.valued` reads too):

    a command word  the first word `shell_reader.command` keeps (prefix assignments and wrappers
                    off) becomes `shell_wrappers.Defaulted`, #2337's marker of a command word
                    read as the NAME it holds: `CMD=sh; $CMD <<'EOF'` reads as `sh <<'EOF'`,
                    gated under its `-e`, and `CMD=true`, `CMD=cat`, `PYTHON=python3` or
                    `NODE=node` as their literal twins (#2600, #2601), behind a wrapper too
                    (`env $CMD`) -- where the name is one the guard reads (`_NAMES`: a shell, a
                    foreign interpreter, a printer, `cat`, `true`) and the step's own shell
                    surely runs the word where it stands (`_surely_run`)
    a printer word  a word of an `echo` or `printf` stage (`workflow_printers._PRINTERS`, read
                    after the command word above) gets the reader's `spelled` attribute with the
                    value's text, as `shell_reader._stage` gives a `\$` word one, the word itself
                    kept as written so every other reader sees what it saw: `X='curl … | sh';
                    echo "$X" | sh` reads as the literal `echo 'curl … | sh' | sh` does (#2468)
                    -- where the text the stage prints, its words and these values, fetches (a
                    `curl` or `wget` word, `_FETCH_WORD`)

Either mark stands only where every program the statement then hands a shell is plain
(`_complete`), and is taken back otherwise.

Each only where the name holds EXACTLY ONE candidate, not empty, and the word resolves to ONE
literal text (`valued`): no lifted `$(...)`, no `$` (a reference, `$Y` or the stand-in `$X`, an
operator expansion `${Y//a/b}`, a `$(...)`, a GitHub `${{ … }}` the runner fills in), no
backquote, no `<(` or `>(`. The shell a printer feeds runs those where the reader, its quotes
gone, reads text: `X='$(echo sh) tool'` after a download keeps the base's unspelled-printer
answer, where its spelled program names no command and reads CLEAN. A glob, a brace, a `~` or a
`$'…'` the assignment decoded is spelled as written, and weighed as the literal twin's is. A
command word's text is a plain name (`_PLAIN`: bash splits and globs an unquoted value, so
`CMD='sh -e'` and `CMD='s*'` are no one command) that `command()` still keeps as the command: an
assignment, keyword or wrapper text (`CMD=X=1`, `W=env`) is left to `workflow_uses` at the use.
Nor is a word marked that the reader keeps as a command where bash runs none: a `case` subject,
or a word of an array literal the reader left unfolded (`a=("$X")` in a `case` arm, #2348).
Anywhere else -- two candidates, the stand-in, `""`, a name the step never assigns, a value that
expands, a runner the guard does not read (`csh`, `./tool`), a command word in a group, a
compound, a function body, a negation, a list or the background, a printed text that fetches
nothing, a program no plain one -- the word stays AS WRITTEN and reads as it did: `Idle`, the
`$CMD` hand-off, the gates-off body, the unspelled printer, fail-closed.

The prices. A resolved word reads as its literal twin, the twin's named prices and filed gaps
with it (`CMD=sh; $CMD -c 'cat' < i.sh` takes #2793's over-report) -- so a mark is made only
where the step's own shell surely runs the word as it stands, only for a name the guard reads,
and only where each program the statement hands a shell is one the twin's reading gets right;
and a printer's value only where its text fetches. That reading takes a program's statements for
the step's own, which a shell running it in a child of its own does not: an `exit 0`, an `exec`
or a `trap 'exit 0' EXIT` before a check ends the child alone, a `T=other` or a `cd` stays in
it, a call to the step's `verify` finds no function there, a first `cat` swallows the rest of a
program it reads on descriptor 0, and `sh -n` runs none of it -- each CLEAN in the literal twin
where bash runs the download (#2666 files the `exit`, the call and the write, under #2608). A
program is plain (`_plain`) where none of that can happen: each statement a pipeline of simple
commands, with no group, compound, function, list, background, assignment, wrapper, keyword or
expansion, no command word `_HELD` (a builtin that ends, sources or changes the shell) or named
as a function the step may define, a first command that reads no program on descriptor 0, its
own programs plain; and the shell reading it takes no option but `-e`, `-u`, `-x`, `-v`, `-s`,
`-c`, `--norc`, `--noprofile` and an `-o` of `_QUIET_SET` (`_quiet`). Elsewhere the base's
hand-off stands, an over-report too where the program was sound (`set -e`, `X=1` or `cd` in a
body, a check behind `|| exit 1`). The spelled program reads as the literal does: a fetch into a
runner the guard does not list (`X='curl … | csh'; echo "$X" | sh`) is #2792's gap here as at
the top level. A foreign interpreter's program is not read: `PERL=perl; $PERL <<'EOF'` with a
backquoted `curl … | sh`, or `PYTHON=python3; $PYTHON -c "os.system('sh tool')"`, which run it,
read CLEAN as `perl` and `python3 -c` do (#2601's price; the base reported them through its
gates-off shell reading); beside a reported fetch the foreign `Idle` report stands. Quotes are
gone to the reader: a single-quoted printer word `echo '$X' | sh`, which bash prints as `$X` for
a child that holds no `X`, is spelled as the value and over-reports (the table's quoting price);
and a value that expands reads as the base, so `X='echo $(curl … | sh)'` before `echo "$X" |
sh`, which bash runs, stays `Idle` and CLEAN, the base's gap (its literal twin is reported,
unspelled). A value is spelled wherever a printer prints it, the stream going nowhere too (`echo
"$X" > f`); `printed` is asked only where a shell reads a program, so no answer moves there. A
command word read through a value is #2337's `Defaulted`, whose rules come with it -- no option
letter is read as its refusal, and a printer in its body reads both ways -- as far as the
plain-program rule leaves them anything to read: `X=sh; $X -cK '…'` (`-K` is no quiet option)
and `CMD=bash; $CMD <<'EOF'` around `echo 'sh\ttool' | sh` (bash's text is no plain name) keep
the base's over-report, where their literal twins read CLEAN. The table's own prices carry over:
a value the shell may not assign stays a second candidate, so the word stays as written (`if c;
then X=other; fi`), and `T+=x` on a name the step never assigned holds the known suffix alone;
and a word inside a function body reads the body's own values, not its caller's (`f() { echo
"$X" | sh; }; f` stays CLEAN). Not read: a `$(...)` child `workflow_guard._walk` parses, and a
`-c`, `eval` or heredoc script `flattened` parses, are read after `annotate` and inherit no mark
-- a first cut, a follow-up; an empty value, which bash drops so the next word runs (`CMD=; $CMD
sh <<'EOF'`); a `${X:-sh}` command word, #2337's default, which `command()` reads before any
value; and a whole `"${a[@]}"`, no one word.

Stdlib only, like everything under it.
"""
import os
import re

import shell_lex
import shell_reader
from shell_reader import command
from shell_wrappers import Defaulted
from workflow_fetch import FETCHERS
from workflow_function_calls import _function_syntax
from workflow_printers import ANY, _PRINTERS
from workflow_programs import _FOREIGN, scripts, stdin_scripts
from workflow_uses import _WHOLE, _control_kinds, static_values
from workflow_values import _OPENER, Values, _literals, valued

# The name a whole reference reads; what makes a value no literal -- a `$`, a backquote or a
# process substitution, each expanded by the shell that reads it or by the runner; the plain
# name a command word's value must be, with no blank, pattern, quote or operator in it; the
# names whose literal reading the guard models; and a fetcher's word in a printed text.
_NAMED = re.compile(r"\$\{?([A-Za-z_]\w*)", re.A)
_EXPANDS = re.compile(r"[$`]|[<>]\(")
_PLAIN = re.compile(r"[\w./+-]+", re.A)
_NAMES = (*shell_reader._SHELLS, *_FOREIGN, *_PRINTERS, "cat", "true")
_FETCH_WORD = re.compile(r"(?<![\w./-])(?:%s)(?![\w.-])" % "|".join(FETCHERS), re.A)

# What a program a mark hands a shell may not run (`_plain`): every builtin and keyword of bash,
# dash, ksh and zsh that ends, sources, waits on or changes the shell -- all of them but the
# printers, the tests, `true`, `false`, `:` and `pwd`; the commands its first statement may be
# where descriptor 0 is the program itself, as they read none of it; a fetcher's word that reads
# it; a function header in any text of the step; and how deep a program's own programs are read.
_HELD = frozenset((
    ".", "alias", "autoload", "bg", "bind", "break", "builtin", "caller", "cd", "chdir", "command",
    "compgen", "complete", "compopt", "continue", "coproc", "declare", "dirs", "disable", "disown",
    "emulate", "enable", "eval", "exec", "exit", "export", "fc", "fg", "float", "function",
    "functions", "getopts", "hash", "help", "history", "integer", "jobs", "kill", "let", "local",
    "logout", "mapfile", "nameref", "noglob", "popd", "pushd", "read", "readarray", "readonly",
    "repeat", "return", "select", "set", "setopt", "shift", "shopt", "source", "suspend", "time",
    "times", "trap", "type", "typeset", "ulimit", "umask", "unalias", "unset", "unsetopt", "wait",
    "zmodload", "!", "[[", "]]", *shell_reader.KEYWORDS))
_SILENT = (*_PRINTERS, "true", "false", ":", "test", "[", "pwd", "chmod", "mkdir")
_STDIN_WORD = re.compile(r"^-$|[@=<]-$|^-\w*[TKdFHbi]-$|^/dev/(?:stdin|fd/0)$")
# The options a shell reading a program may take for the mark to stand (`_quiet`): `-e`, `-u`,
# `-x`, `-v`, `-s`, `-c` and `-o` naming one of `_QUIET_SET`, which the guard reads or which change
# nothing it reads -- not `-n` or `-D`, which run nothing, `-t`, which runs one command, `-i`, `-l`.
_QUIET = re.compile(r"-[ceusvx]*|--norc|--noprofile")
_QUIET_O = re.compile(r"-[ceusvx]*o")
_QUIET_SET = ("errexit", "nounset", "pipefail", "xtrace", "verbose")
_HEADER = re.compile(r"\b([A-Za-z_][\w-]*)\s*\(\s*\)|\bfunction\s+([A-Za-z_][\w-]*)", re.A)
_ENVIRON = re.compile(r"(?<![\w${])(?:PATH|SHELLOPTS|BASHOPTS|BASH_ENV|ENV|IFS|POSIXLY_CORRECT)"
                      r"(?!\w)", re.A)
_DEPTH = 8


def annotate(stmts):
    """Mark `stmts` in place, in order, through the step's own values, and return them: a command
    word that is one whole reference the table resolves to one literal becomes `Defaulted(text)`
    where the step surely runs it, and a printer's whole-reference words get `spelled` where the
    text it prints fetches -- each kept only where every program the statement then hands a shell
    is `_plain` (the module docstring has the rule). The table at a statement is built only where
    one of its stages holds such a word, and `_surely_run` read only once a command word is one."""
    sure: list[list[bool]] = []              # `_surely_run`'s answer, once a command word asks
    reach: list[set[str] | None] = []        # `_defined`'s answer, once a mark asks for it
    for index, statement in enumerate(stmts):
        table: Values | None = None     # the table at this statement, once a word asks
        written = [list(stage.argv) for stage in statement.stages]
        for stage in statement.stages:
            argv = command(stage.argv)
            if argv and not _printer(argv):
                for at, word in _references(stage, argv[:1]):
                    sure = sure or [_surely_run(stmts)]
                    if not sure[0][index]:
                        continue
                    table = table or static_values(stmts, index)
                    text = _literal(word, table)
                    if text is not None and _commands(stage, at, text):
                        stage.argv[at] = Defaulted(text)
                argv = command(stage.argv)
            if argv and _printer(argv):
                spelled = []
                for at, word in _references(stage, argv[1:]):
                    table = table or static_values(stmts, index)
                    text = _literal(word, table)
                    if text is not None:
                        spelled.append((at, word, text))
                printed = " ".join([*map(str, argv[1:]), *(text for _at, _w, text in spelled)])
                for at, word, text in spelled if _FETCH_WORD.search(printed) else ():
                    # the word as written, its markers kept
                    stage.argv[at] = shell_reader._Token(str(word), shell_reader._markers(word))
                    setattr(stage.argv[at], "spelled", text)
        if any(new is not old for stage, was in zip(statement.stages, written)
               for new, old in zip(stage.argv, was)):
            reach = reach or [_defined(stmts)]
            if reach[0] is None or not _complete(statement, reach[0]):     # read as written
                for stage, was in zip(statement.stages, written):
                    stage.argv[:] = was
    return stmts


def _printer(argv):
    """Whether `argv` (a command as `command()` keeps it) is an `echo` or a `printf`."""
    return os.path.basename(str(argv[0])) in _PRINTERS


def _references(stage, words):
    """(place in `stage.argv`, word) for each of `words` that is ONE whole reference, found by
    identity in the stage's own argv -- one `command()` made itself (`env -S`) is none -- where
    bash runs the stage's command: not a `case` subject, nor a word of an array literal the
    reader left unfolded (`a=` and its words in an opened group, #2348), which bash assigns."""
    for word in words:
        if _WHOLE.fullmatch(str(word)) and not hasattr(word, "spelled"):
            at = next((at for at, item in enumerate(stage.argv) if item is word), None)
            if at is None or stage.argv[at - 1:at] == ["case"] or stage.group_open and any(
                    _OPENER.match(str(item)) for item in stage.argv[:at]):
                continue
            yield at, word


def _literal(word, table):
    """The ONE literal text whole reference `word` stands for through `table`, or None: its name
    holds one candidate, not empty, and the word resolves to one text with no lifted `$(...)`, no
    `$`, no backquote and no process substitution (`_EXPANDS`)."""
    named = _NAMED.match(str(word))
    name = named[1] if named else ""
    held = [*table.scalars.get(name, []), *table.arrays.get(name, [])]
    if len(held) != 1 or not held[0]:
        return None
    texts = valued(word, table)
    if len(texts) != 1:
        return None
    text = texts[0]
    if not text or shell_reader.is_marker(text) or _EXPANDS.search(text):
        return None
    return str(text)


def _commands(stage, at, text):
    """Whether `text` in place of the command word at `stage.argv[at]` is one command bash runs,
    the reader keeps as the command, and the guard reads: a plain name (`_PLAIN`: no blank,
    pattern, quote or operator) of a program in `_NAMES` -- a runner it does not list (`csh`,
    `./tool`) keeps the base's fail-closed hand-off, as its literal twin reads CLEAN (#2792) --
    and not a word `command()` reads past (an assignment, a keyword, a wrapper)."""
    if not _PLAIN.fullmatch(text) or os.path.basename(text) not in _NAMES:
        return False
    trial = list(stage.argv)
    trial[at] = marked = Defaulted(text)
    kept = command(trial)
    return bool(kept) and kept[0] is marked


def _surely_run(stmts):
    """Per statement: whether the step's own shell surely runs its command where it stands -- at
    the top level, outside every `{ }` and `( )` (a `{` after a function header the reader split
    into a name and a `( )`, `g ( ) {`, opens one too), in no compound (`_control_kinds`), with no
    keyword, function header or `case` arm in front of it (no `!`, no `if` or `while` test, no
    body run later), in no `&&` or `||` list and not in the background. Elsewhere a resolved word
    would take its literal twin's reading where that reading has a filed gap (#2666: a `}` or an
    `exit` in a body read as the step's own) or the table a named limit (a body's values)."""
    kinds = _control_kinds(stmts)
    depth, out = 0, []
    for index, statement in enumerate(stmts):
        before, plain = depth, True
        for stage in statement.stages:
            lead = stage.argv[:max(0, len(stage.argv) - len(command(stage.argv)))]
            literals = _literals(stage)        # an array literal's `( )`: no group to bash
            grouped = stage.group_open != literals or stage.group_close != literals
            depth += (stage.argv if grouped else lead).count("{") - lead.count("}")
            depth += stage.group_open - stage.group_close
            plain = plain and not grouped and not any(
                word in shell_reader.KEYWORDS or shell_reader._FUNCTION.match(word)
                or shell_reader.is_arm(word) for word in map(str, lead))
        serial = statement.separator not in ("&&", "||", "&") and not (
            index and stmts[index - 1].separator in ("&&", "||"))
        out.append(before == depth == 0 and plain and serial and not kinds[index])
    return out


def _complete(statement, defined, depth=0):
    """Whether every program a stage of `statement` hands a shell is `_plain`: a `-c` or `eval`
    string, and -- descriptor 0 the program -- a heredoc or here-string body, a `<(...)` FILE, or
    what a printer or a heredoc-fed `cat` pipes in, each reading of an `echo` (`ANY`): the texts
    `workflow_forms.flattened` reads in place (`scripts`, `stdin_scripts`); the shell reading one
    `_quiet`, with no `-s` beside a `-c` string (`bash -s -c true` runs `true`, not the body) and
    no output redirect (the reader takes `<>` for one, and bash's `&>` for one where a dash step
    backgrounds the command); and no stage's command a name the step may define as a function
    (`sh() { :; }`)."""
    for at, stage in enumerate(statement.stages):
        argv = command(stage.argv)
        if not argv:
            continue
        name, strings = os.path.basename(str(argv[0])), scripts(argv)
        texts = stdin_scripts(argv, stage, statement.stages[:at], ANY)
        shell = bool(strings or texts) and name in shell_reader._SHELLS
        letters = _quiet(argv) if shell else ""
        if name in defined or shell and (letters is None or stage.writes or strings and texts
                                         and "s" in letters):
            return False
        if not all(_plain(text, defined, depth, False) for text in strings) or not all(
                _plain(text, defined, depth, True) for text in texts):
            return False
    return True


def _quiet(argv):
    """The letters of shell `argv`'s option words, up to its first operand or `--`, where all are
    `_QUIET` -- a `-o` cluster (`_QUIET_O`) takes one of `_QUIET_SET`, no `+` turns an option off,
    a long option (`--norc`) adds no letter -- and an operand after them is a `-c` string or a
    `-s` parameter, not a FILE the shell runs instead (`sh - /dev/null`); else None."""
    words, letters = [str(word) for word in argv[1:]], ""
    while words and words[0][:1] in ("-", "+") and words[0] != "--":
        word = words.pop(0)
        letters += "" if word[:2] == "--" else word
        if _QUIET_O.fullmatch(word):
            if not words or words.pop(0) not in _QUIET_SET:
                return None
        elif not _QUIET.fullmatch(word):
            return None
    words = words[1:] if words[:1] == ["--"] else words
    return letters if not words or "c" in letters or "s" in letters else None


def _plain(text, defined, depth, fed):
    """Whether a shell runs program `text` as the guard reads it in place, the step's own: every
    statement a pipeline of simple commands run in order -- no group, compound, function, list or
    background, no assignment, wrapper or keyword in front, no expansion -- whose command words are
    literal names, none `_HELD` (`exit`, `exec`, `set`, `cd`, `read`, `trap`, `eval`, `alias`, ...)
    nor a function the step may define (`defined`), whose first command reads none of the program
    where descriptor 0 is the program (`fed`: `_silent`; a `cat` there swallows the rest), and
    whose own programs are plain too. A shell running anything else in a child of its own runs it
    otherwise than in place: `exit 0` before a check ends the child, not the step; `T=other`, `cd`
    and `alias` stay in it; `verify` is no function there."""
    if depth > _DEPTH or _EXPANDS.search(text):
        return False
    try:
        inner = shell_reader.statements(text)
    except shell_lex.Unreadable:
        return False
    for statement in inner:
        if statement.separator in ("&&", "||", "&"):
            return False
        for at, stage in enumerate(statement.stages):
            argv = command(stage.argv)
            name = os.path.basename(str(argv[0])) if argv else ""
            if (not argv or len(argv) != len(stage.argv) or stage.group_open or stage.group_close
                    or not (_PLAIN.fullmatch(str(argv[0])) or argv[0] in ("[", ":"))
                    or name in _HELD or name in defined
                    or fed and not at and stage.stdin_from_pipe and not _silent(name, argv)):
                return False
        if not _complete(statement, defined, depth + 1):
            return False
    return True


def _silent(name, argv):
    """Whether command `argv`, named `name`, reads none of its standard input: one of `_SILENT`, a
    fetcher no word of which names it (`curl -d @-`, `wget -i -`), or an option word no shell finds
    a command by (`-e`, which dash's `echo -e` prints)."""
    if name in FETCHERS:
        return not any(_STDIN_WORD.search(str(word)) for word in argv[1:])
    return name in _SILENT or name.startswith("-")


def _defined(stmts):
    """Every name the step may define as a function, read wide: a header `_function_syntax` reads,
    one the reader split (`g ( )`, `g ( ) {`), and one in any text a stage holds -- a heredoc, a
    string, a substitution (`_HEADER`) -- where a shell reading it in place would define it. Or
    None where any text names the variables that choose or start the shell a mark names (`PATH`,
    `SHELLOPTS`, `BASH_ENV`, `ENV`, `IFS`, ... `_ENVIRON`): a fake `sh` first on `PATH`, and
    `SHELLOPTS=noexec`, which runs none of a body, reach it, and no mark stands in the step."""
    names = set()
    for statement in stmts:
        for stage in statement.stages:
            argv, kept = [str(word) for word in stage.argv], [str(word) for word in command(
                stage.argv)]
            names.add(_function_syntax(argv)[0])
            if stage.group_open == stage.group_close == 1 and kept[1:] in ([], ["{"]):
                names.add(kept[0] if kept else None)
            bodies = [body[0] for body in (stage.stdin_heredoc,) if body]
            for text in (" ".join(argv), stage.heredoc or "", *bodies, *stage.substitutions):
                if _ENVIRON.search(str(text)):
                    return None
                names.update(a or b for a, b in _HEADER.findall(str(text)))
    return names - {None}
