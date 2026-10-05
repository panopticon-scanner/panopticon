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
                    foreign interpreter, a printer, `cat`, `true`), bare or in a system
                    directory (`_bare`: another path, `./sh`, may name a file the step wrote),
                    and the step's own shell surely runs the word where it stands (`_surely_run`)
    a printer word  a word of an `echo` or `printf` stage (`workflow_printers._PRINTERS`, read
                    after the command word above) gets the reader's `spelled` attribute with the
                    value's text, as `shell_reader._stage` gives a `\$` word one, the word itself
                    kept as written so every other reader sees what it saw: `X='curl … | sh';
                    echo "$X" | sh` reads as the literal `echo 'curl … | sh' | sh` does (#2468)
                    -- where the text the stage prints, its words and these values, fetches (a
                    `curl` or `wget` word, `_FETCH_WORD`) and the stage stands in no `if` or
                    `while` test (`_in_tests`)

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
expands, a runner the guard does not read (`csh`, `./tool`) or a path to one it does (`./sh`), a
command word in a group, a compound, a function body, a negation, a list or the background,
either word in a test (`if` or `while`, a line apart from its keyword too), a printed text that
fetches nothing, a program no plain one -- the word stays AS WRITTEN and reads as it did: `Idle`,
the `$CMD` hand-off, the gates-off body, the unspelled printer, fail-closed.

The prices. A resolved word reads as its literal twin, the twin's named prices and filed gaps
with it (`CMD=sh; $CMD -c 'cat' < i.sh` takes #2793's over-report) -- so a mark is made only
where the step's own shell surely runs the word as it stands, only for a name the guard reads,
and only where each program the statement hands a shell is one the twin's reading gets right;
and a printer's value only where its text fetches, in no test (a failed check a line into an `if`
or `while` test stops nothing, and the twin reads it as stopping the step). That reading takes a
program's statements for the step's own, which a shell running it in a child of its own does not:
an `exit 0`, an `exec` or a `trap 'exit 0' EXIT` before a check ends the child alone, a `T=other`,
a `printf -v T other` or a `cd` stays in it, a call to the step's `verify` finds no function
there, a first `cat` or `curl -d @/dev/stdin` swallows the rest of a program it reads on
descriptor 0, a `curl -o /dev/stdin` adds to it on Linux, and `sh -n` runs none of it -- each
CLEAN in the literal twin where bash runs the download (#2666 files the `exit`, the call and the
write, under #2608). A program is plain (`_plain`) where none of that is known to happen: a
measured shell reads it, by a name `_bare` reads (`sh`, `bash` or `dash`, `_MEASURED_SHELLS`:
zsh's `bye` or `~/.zshenv` and ksh's `newgrp` end one unseen, and `./sh` may be a file the step
wrote), under no option but `-e`, `-u`, `-x`, `-v`, `-s`, `-c`, `--norc`, `--noprofile` and an
`-o` of `_QUIET_SET` (`_quiet`); each statement is a pipeline of simple commands, with no group,
compound, function, list, background, assignment, wrapper, keyword or expansion, no command word
`_HELD` (a builtin that ends, sources or changes the shell), `printf -v` (which assigns) or named
as a function the step may define; a first command reads no program on descriptor 0 -- a fetcher
only under options that read no file and URLs that read nothing local (`_FETCH_QUIET`,
`_FETCH_OPERAND`), and nothing by a path the step may have written (`./true`); its own programs
are plain. No mark stands in a step that sources a file, evals a text, imports a function
(`BASH_FUNC_`) or rebinds a command (`hash -p`), any of which may define a name no text of the
step spells, nor in one that names a variable or a file that starts the shell or a fetcher
otherwise (`PATH`, `BASH_ENV`, `PS4`, `~/.curlrc`: `_ENVIRON`) or a path to a descriptor
(`/dev/stdin`, `/proc/self/fd/0`, `cd /dev`: `_DESCRIPTOR`). Elsewhere the base's hand-off stands,
an over-report too where the program was sound (`set -e`, `X=1` or `cd` in a body, a check behind
`|| exit 1`, `curl -V`). The spelled program reads as the literal does: a fetch into a
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
from workflow_programs import _FOREIGN, _MEASURED_SHELLS, scripts, stdin_scripts
from workflow_uses import _WHOLE, _control_kinds, static_values
from workflow_values import _OPENER, Values, _literals, valued

# The name a whole reference reads; what makes a value no literal -- a `$`, a backquote or a
# process substitution, each expanded by the shell that reads it or by the runner; the plain
# name a command word's value must be, with no blank, pattern, quote or operator in it; the
# names whose literal reading the guard models; the directories a bare name's lookup reaches
# too (`_bare`); and a fetcher's word in a printed text.
_NAMED = re.compile(r"\$\{?([A-Za-z_]\w*)", re.A)
_EXPANDS = re.compile(r"[$`]|[<>]\(")
_PLAIN = re.compile(r"[\w./+-]+", re.A)
_NAMES = (*shell_reader._SHELLS, *_FOREIGN, *_PRINTERS, "cat", "true")
_SYSTEM = ("/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin")
_FETCH_WORD = re.compile(r"(?<![\w./-])(?:%s)(?![\w.-])" % "|".join(FETCHERS), re.A)

# What a program a mark hands a shell may not run (`_plain`): every builtin and keyword of bash
# and dash, the shells that may read it (`_MEASURED_SHELLS`), that ends, sources, waits on or
# changes the shell -- all of them but the printers, the tests, `true`, `false`, `:` and `pwd` --
# with some of ksh's and zsh's besides; and the commands a statement may start with where
# descriptor 0 is the program itself, as they read none of it.
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
# The option words under which a fetcher reads no file, descriptor 0 among them (`_silent`):
# output, retry and verbosity options, and `-` (stdout) as the value of `-o` or `-O`; and its
# other words: a URL of a scheme that reads nothing local (not `file:`, which reads a file, nor
# `telnet:`, which reads descriptor 0) with no `{` or `[` for curl to expand, or a word with no
# scheme at all (the file `-o` writes).
_FETCH_QUIET = re.compile(r"-|-[fsSLqOo#]+-?|--(?:fail|silent|show-error|location|quiet|output|"
                          r"output-document|remote-name|retry|retry-delay|max-time|"
                          r"connect-timeout|create-dirs|no-verbose|https-only|proto|compressed|"
                          r"progress-bar|tlsv1(?:\.[0-3])?)(?:=\S*)?", re.A)
_FETCH_OPERAND = re.compile(r"(?i:https?|ftps?)://[^{}\[\]]*|[^:{}\[\]]*", re.A)
# The options a shell reading a program may take for the mark to stand (`_quiet`): `-e`, `-u`,
# `-x`, `-v`, `-s`, `-c` and `-o` naming one of `_QUIET_SET`, which the guard reads or which change
# nothing it reads -- not `-n` or `-D`, which run nothing, `-t`, which runs one command, `-i`, `-l`.
_QUIET = re.compile(r"-[ceusvx]*|--norc|--noprofile")
_QUIET_O = re.compile(r"-[ceusvx]*o")
_QUIET_SET = ("errexit", "nounset", "pipefail", "xtrace", "verbose")
# A function header in any text of the step; the variables that choose, start or trace a shell,
# load code into it or rebind its commands, the prefix of a function bash imports from the
# environment, and the files and variables a fetcher starts from (`~/.curlrc` with `data =
# @/dev/stdin` reads the rest of a fed program); the paths that name a descriptor (`/dev/stdin`,
# `/dev/fd/0`, `/proc/self/fd/0`, or `/dev` itself for a `cd`), through which a fetcher's output
# or a redirect lands in a fed program on Linux, where its shell runs it (`curl -o /dev/stdin`);
# the commands that may define or rebind a name no text of the step spells, and a word of a `trap`
# action or a `mapfile -C` callback that runs one (`_sources`); and how deep a program's own
# programs are read.
_HEADER = re.compile(r"\b([A-Za-z_][\w-]*)\s*\(\s*\)|\bfunction\s+([A-Za-z_][\w-]*)", re.A)
_ENVIRON = re.compile(r"(?<![\w${])(?:(?:PATH|SHELLOPTS|BASHOPTS|BASH_ENV|ENV|IFS|POSIXLY_CORRECT"
                      r"|PS4|BASH_CMDS|LD_PRELOAD|LD_LIBRARY_PATH|HOME|CURL_HOME|XDG_CONFIG_HOME"
                      r"|WGETRC|CURL_CA_BUNDLE|SSL_CERT_FILE)(?!\w)|BASH_FUNC_)|curlrc|wgetrc",
                      re.A)
_DESCRIPTOR = re.compile(r"dev/(?:stdin|fd)(?![\w.-])|(?<![\w.-])/(?:dev|proc)/?(?![\w./-])|proc/",
                         re.A)
_SOURCES = (".", "source", "eval", "builtin", "enable", "hash")
_SOURCING = re.compile(r"(?<![^\s;&|(){}])(?:\.|source|eval|builtin|enable|hash)(?![^\s;&|(){}])"
                       r"|[$`]")
_DEPTH = 8


def annotate(stmts):
    """Mark `stmts` in place, in order, through the step's own values, and return them: a command
    word that is one whole reference the table resolves to one literal becomes `Defaulted(text)`
    where the step surely runs it, and a printer's whole-reference words get `spelled` where the
    text it prints fetches, in no test -- each kept only where every program the statement then
    hands a shell is `_plain` (the module docstring has the rule). The table at a statement is
    built only where one of its stages holds such a word, `_surely_run` read only once a command
    word is one, and `_in_tests` once a printed text fetches."""
    sure: list[list[bool]] = []              # `_surely_run`'s answer, once a command word asks
    reach: list[set[str] | None] = []        # `_defined`'s answer, once a mark asks for it
    tested: list[list[bool]] = []            # `_in_tests`' answer, once a printed text fetches
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
                fetches = bool(spelled and _FETCH_WORD.search(printed))
                if fetches:
                    tested = tested or [_in_tests(stmts)]
                    fetches = not tested[0][index]
                for at, word, text in spelled if fetches else ():
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
    pattern, quote or operator) of a program in `_NAMES`, bare or in a system directory (`_bare`)
    -- a runner it does not list (`csh`, `./tool`) keeps the base's fail-closed hand-off, as its
    literal twin reads CLEAN (#2792), and so does any other path (`./sh`, `b/bash`), which may
    name a file the step wrote -- and not a word `command()` reads past (an assignment, a
    keyword, a wrapper)."""
    if not _PLAIN.fullmatch(text) or _bare(text) not in _NAMES:
        return False
    trial = list(stage.argv)
    trial[at] = marked = Defaulted(text)
    kept = command(trial)
    return bool(kept) and kept[0] is marked


def _bare(word):
    """The name command word `word` runs by, as the guard reads it: the word where it is bare, or
    its basename in a directory a bare name's lookup reaches too (`_SYSTEM`: `/bin/sh`); else
    None -- another path (`./sh`, `b/bash`, `/tmp/sh`) may name a file the step wrote."""
    head, name = os.path.split(str(word))
    return name if head in ("", *_SYSTEM) else None


def _surely_run(stmts):
    """Per statement: whether the step's own shell surely runs its command where it stands -- at
    the top level, outside every `{ }` and `( )` (a `{` after a function header the reader split
    into a name and a `( )`, `g ( ) {`, opens one too), in no compound (`_control_kinds`), with no
    keyword, function header or `case` arm in front of it (no `!`, no `if` or `while` test, a line
    apart from its keyword too (`_in_tests`), no body run later), in no `&&` or `||` list and not
    in the background. Elsewhere a resolved word would take its literal twin's reading where that
    reading has a filed gap (#2666: a `}` or an `exit` in a body read as the step's own) or
    another (a failed check a line into a test read as stopping the step), or the table a named
    limit (a body's values)."""
    kinds, tests = _control_kinds(stmts), _in_tests(stmts)
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
        out.append(before == depth == 0 and plain and serial and not kinds[index]
                   and not tests[index])
    return out


def _in_tests(stmts):
    """Per statement: whether it stands in an `if`, `elif`, `while` or `until` test -- from the
    keyword's statement to the `then` or `do` ending the test, a line apart too -- where a failure
    stops nothing and the literal twin's reading has a gap (`if` NL `sh <<'EOF'` NL `then`)."""
    opened: list[bool] = []         # per open `if` .. `then` or loop .. `do`: whether a test
    out = []
    for statement in stmts:
        testing = any(opened)
        for stage in statement.stages:
            kept = command(stage.argv)        # the reader keeps `select` as a command word
            lead = stage.argv[:max(0, len(stage.argv) - len(kept))] + kept[:1]
            for word in map(str, lead):
                if word in ("if", "elif", "while", "until", "for", "select"):
                    opened.append(word in ("if", "elif", "while", "until"))
                elif word in ("then", "do") and opened:
                    opened.pop()
        out.append(testing or any(opened))
    return out


def _complete(statement, defined, depth=0):
    """Whether every program a stage of `statement` hands a shell is `_plain`: a `-c` or `eval`
    string, and -- descriptor 0 the program -- a heredoc or here-string body, a `<(...)` FILE, or
    what a printer or a heredoc-fed `cat` pipes in, each reading of an `echo` (`ANY`): the texts
    `workflow_forms.flattened` reads in place (`scripts`, `stdin_scripts`); the shell reading one
    a measured one, by a name `_bare` reads (`sh`, `bash`, `dash`: `_MEASURED_SHELLS` -- zsh's
    `bye` and `~/.zshenv`, or ksh's `newgrp`, end a program no reading here sees end, and `./sh`
    may be a file the step wrote), and `_quiet`, with no `-s` beside a `-c` string (`bash -s -c
    true` runs `true`, not the body) and no output redirect (the reader takes `<>` for one, and
    bash's `&>` for one where a dash step backgrounds the command); and no stage's command a name
    the step may define as a function (`sh() { :; }`)."""
    for at, stage in enumerate(statement.stages):
        argv = command(stage.argv)
        if not argv:
            continue
        name, strings = os.path.basename(str(argv[0])), scripts(argv)
        texts = stdin_scripts(argv, stage, statement.stages[:at], ANY)
        shell = bool(strings or texts) and name in shell_reader._SHELLS
        letters = _quiet(argv) if shell else ""
        if name in defined or shell and (_bare(argv[0]) not in _MEASURED_SHELLS or letters is None
                                         or stage.writes or strings and texts and "s" in letters):
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
    literal names, none `_HELD` (`exit`, `exec`, `set`, `cd`, `read`, `trap`, `eval`, `alias`, ...),
    `printf -v` (which assigns) nor a function the step may define (`defined`), whose first command
    reads none of the program where descriptor 0 is the program (`fed`: `_silent`; a `cat` there
    swallows the rest, and so may a `./true` the step wrote), and whose own programs are plain
    too. A shell running anything else in a child of its own runs it otherwise than in place:
    `exit 0` before a check ends the child, not the step; `T=other`, `printf -v T other`, `cd`
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
                    or name == "printf" and len(argv) > 1 and str(argv[1]).startswith("-v")
                    or fed and not at and stage.stdin_from_pipe and not _silent(argv)):
                return False
        if not _complete(statement, defined, depth + 1):
            return False
    return True


def _silent(argv):
    """Whether command `argv` reads none of its standard input, by the name `_bare` reads (another
    path, `./true` or `./curl`, may name a file the step wrote, and is none of these): one of
    `_SILENT`, a fetcher every option word of which reads no file (`_FETCH_QUIET`: `-fsSL`,
    `-o F`, `--retry N`) -- any other may name descriptor 0, under any name (`-d @-`,
    `-d @/dev/stdin`, `-T F` where `F` links to it, `-K F`, `wget -i -`) -- and every other word
    of which is an `http`, `https`, `ftp` or `ftps` URL with no glob or a word with no scheme, the
    file `-o` writes (`_FETCH_OPERAND`; `file:///dev/stdin` reads it, and a step that names a
    descriptor, `-o /dev/stdin`, is `_defined`'s), or an option word no shell finds a command by
    (`-e`, which dash's `echo -e` prints), not the bare `-` (zsh's precommand modifier)."""
    name = _bare(argv[0])
    if name in FETCHERS:
        return all((_FETCH_QUIET if word.startswith("-") else _FETCH_OPERAND).fullmatch(word)
                   for word in map(str, argv[1:]))
    return name in _SILENT or name is not None and name.startswith("-") and name != "-"


def _defined(stmts):
    """Every name the step may define as a function that a text of the step spells: a header
    `_function_syntax` reads, one the reader split (`g ( )`, `g ( ) {`), and one in any text a
    stage holds -- a heredoc, a string, a substitution (`_HEADER`) -- where a shell reading it in
    place would define it. Or None where the step sources a file, evals a text, imports a function
    or rebinds a command (`_sources`; a `BASH_FUNC_` variable), any of which may define a name no
    text spells (`. ./defs.sh`, `eval "$(printf '%s() { :; }' sh)"`), or where any text, a
    redirect's target too, names the variables that choose, start or trace the shell a mark names
    (`PATH`, `SHELLOPTS`, `BASH_ENV`, `ENV`, `IFS`, `PS4`, ... `_ENVIRON`), the files and
    variables a fetcher starts from (`.curlrc`, `CURL_HOME`, `HOME`, `WGETRC`), or a path to a
    descriptor (`/dev/stdin`, `/dev/fd/0`, `/proc/self/fd/0`, a link to one, a `cd /dev`:
    `_DESCRIPTOR`): a fake `sh` first on `PATH`, `SHELLOPTS=noexec`, which runs none of a body, a
    `.curlrc` that has `curl` read the rest of a fed program, and a `curl -o /dev/stdin` that adds
    the download to it on Linux reach it, and no mark stands in the step."""
    names = set()
    for index, statement in enumerate(stmts):
        for stage in statement.stages:
            argv, kept = [str(word) for word in stage.argv], command(stage.argv)
            if kept and _sources(kept, stmts, index):
                return None
            kept = [str(word) for word in kept]
            names.add(_function_syntax(argv)[0])
            if stage.group_open == stage.group_close == 1 and kept[1:] in ([], ["{"]):
                names.add(kept[0] if kept else None)
            bodies = [body[0] for body in (stage.stdin_heredoc,) if body]
            for text in (" ".join(argv), *stage.writes, stage.heredoc or "", *bodies,
                         *stage.substitutions):
                if _ENVIRON.search(str(text)) or _DESCRIPTOR.search(str(text)):
                    return None
                names.update(a or b for a, b in _HEADER.findall(str(text)))
    return names - {None}


def _sources(kept, stmts, index):
    """Whether command `kept` (as `command()` keeps it, at statement `index`) may define or rebind
    a name no text of the step spells: a command word one of `_SOURCES` -- `.`, `source`, `eval`,
    `builtin` (`builtin . ./defs.sh`), `enable` (a loaded builtin) or `hash` (`hash -p ./x sh`) --
    or one no table resolves to another literal (`S=.; $S ./defs.sh`, `$(echo .) ./defs.sh`), or a
    `trap` or `mapfile` whose text to run later runs one or expands (`_SOURCING`: a `DEBUG` trap
    runs before the next command, a `mapfile -C` callback per line read)."""
    word = kept[0]
    text: str | None = str(word)
    if _EXPANDS.search(str(word)) or shell_reader.is_marker(word):
        text = _literal(word, static_values(stmts, index)) if _WHOLE.fullmatch(str(word)) else None
    return text is None or text in _SOURCES or text in ("trap", "mapfile", "readarray") and any(
        shell_reader.is_marker(item) or _SOURCING.search(str(item)) for item in kept[1:])
