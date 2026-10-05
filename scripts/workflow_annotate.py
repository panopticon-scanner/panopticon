#!/usr/bin/env python3
r"""A step's own literal values read into the two words its readers key on (#2468, #2600, #2601).

`workflow_uses.static_values` reads a USE through the values the step itself assigns (#2425,
#2489). Two readers see only a stage or its pipeline: the printer rules
(`workflow_printers.printed`) weigh the text `echo "$X" | sh` hands a shell, and the stdin-program
rules (`workflow_programs.stdin_program`, `workflow_forms.flattened`) read `$CMD <<'EOF'` as a
hand-off to a word no table places, its body read as shell with no check credited. `annotate`
runs once over a step's raw statements, before `flattened` reads them (`workflow_guard.read`),
and marks a word in place where the step's table holds one literal for it, so the statement reads
as its literal twin and no reader below changes. A command word becomes
`shell_wrappers.Defaulted`, #2337's marker of a word read as the name it holds (`CMD=sh; $CMD
<<'EOF'` reads as `sh <<'EOF'`, gated under its `-e`; `CMD=cat` or `PYTHON=python3` as their
twins); a printer's word gets the reader's `spelled` text, the word kept as written
(`X='curl … | sh'; echo "$X" | sh` reads as the literal printer). A mark stands only where every
rule below holds, and is taken back where one fails: the word then reads as the base read it.

 1. One literal (`_literal`): the word is ONE whole reference (`workflow_uses._WHOLE`: `$X`,
    `${X}`, `"$X"`, `${X:-d}`, `${a[0]}`) whose name holds one candidate, not empty, and which
    resolves (`valued`) to one text with no `$`, backquote, `<(` or `>(` (`_EXPANDS`).
 2. Surely run (`_surely_run`, `_references`): a command word stands at the top level -- in no
    group, compound, function body, negation, `&&` or `||` list or background -- and is no `case`
    subject or word of an array literal, where the twin's reading has a filed gap (#2666).
 3. In no test (`_in_tests`): neither word stands in an `if`, `elif`, `while` or `until` test, a
    line apart from its keyword too, where a failed check stops nothing.
 4. A name the guard reads (`_commands`): a command word's text is a plain name (`_PLAIN`: bash
    splits and globs a value) in `_NAMES` -- a shell, a foreign interpreter, a printer, `cat`,
    `true` -- that `command()` still keeps as the command (not `X=1`, `env`, `if`).
 5. A measured shell, a system path (`_bare`): a name counts bare or in a directory of `_SYSTEM`
    (`./sh` may be a file the step wrote), and a shell that reads a program is one of
    `_MEASURED_SHELLS` (zsh's `bye` or `~/.zshenv` and ksh's `newgrp` end one unseen).
 6. A plain program (`_complete`, `_quiet`, `_plain`, `_silent`): each program the statement
    hands a shell -- a `-c` string, a heredoc or here-string body, a `<(...)`, what a printer or a
    `cat` pipes in -- runs in place as the step's own, where a child shell runs otherwise (#2666):
    its shell under `_quiet` options, with no output redirect; each statement a pipeline of simple
    commands with literal names, none `_HELD` (a builtin that ends, sources or changes the shell)
    nor `printf -v`; a first command reading none of a program fed on descriptor 0 (`_SILENT`, or
    a fetcher whose options are `_FETCH_QUIET` and whose operands are `_FETCH_OPERAND`).
 7. No definition (`_vetoed`, `_rebinds`): no mark stands in a step that defines a function or an
    alias anywhere (`f() {`, `function f`, `g ( )`, `alias f=…` behind `command` too, `_HEADER`
    in any text), declares a nameref (`declare -n`), or sources, evals or rebinds a command
    (`_SOURCES`, through a value too: `S=.; $S x`) or runs a command word no table resolves
    (`_resolved`): a call, an alias or a reference may change a value the table holds. Nor one
    that reaches an assigning builtin through a value (`R=read; $R CMD`: the table reads a literal
    command word only), glues an array name to `read -a` (`read -aCMD`), or assigns before a
    special builtin (`CMD=true :`), which dash and bash's POSIX mode keep; nor one that runs
    `wait -p` (bash 5.1 unsets the name first) or a word `NAME[` (`CMD[ 0 ]=true` is one
    assignment to bash), or hands a builtin that names what it sets (`_NAMING`) a word bash
    expands by a brace or a glob first (`read {C,}MD`, `export {-f,} CMD=x`, `unset C?D`). No mark
    stands for a name spelled as a whole word anywhere in the step
    (`_spelled`: `XCMD`, `CMD2` are other names) but in a plain reference, an option word (`-X`,
    `--CMD`) or an assignment word -- `NAME=` or `NAME+=` starting a command's word, a prefix or
    an argument (`CMD=true $CMD`, `env CMD=x`), which assigns in the step's shell only where the
    table reads it or a rule above refuses the step -- outside `let` and `[[`, whose arithmetic
    assigns, and outside a declaration bash may refuse or alter (`_DECLARES`): `local` (no
    function stands in a marked step), `readonly` (a later assignment fails while the table reads
    it), `declare`/`typeset` (absent under `sh`; their options print, fail on bash 3.2 or alter
    the value), `export` with an option word. Any other spelling (`read NAME`, `wait -p NAME`,
    `NAME[0]=`, `printf -v NAME`, `R=NAME`, `${NAME:=x}`, `let NAME=1`) may change what bash holds.
 8. No trap (`_rebinds`, `_LATER`): nor in one that traps `DEBUG`, `RETURN` or `ERR`, or traps
    an action not empty, `-` or a literal `rm` (`_TRAP_SAFE`), or sets a `mapfile -C` callback, or
    names `trap`, `mapfile` or `readarray` in any other text: each runs a text later, which may
    change a value or run the download after the check the twin credits has stopped the step.
 9. No environment word (`_ENVIRON`): nor in one any text of which names a variable or a file
    that starts, traces or loads code into a shell or a fetcher, or rebinds its names (`PATH`,
    `BASH_ENV`, `PS4`, `BASH_FUNC_`, `BASH_ALIASES`, `HOME`, `~/.curlrc`).
10. No descriptor path (`_DESCRIPTOR`): nor in one any text of which names a path to a descriptor
    (`/dev/stdin`, `/proc/self/fd/0`, `cd /dev`), through which a fetch lands in a fed program.
11. No shell of the step's own (`_ON_PATH`): nor in one any text of which names a path whose
    basename is in `_NAMES` outside `_SYSTEM`'s directories (`~/.dotnet/tools/sh`, `./bin/cat`),
    or which redirects into a file by such a name: it may put its own `sh` first on the PATH.
12. No output a runner reads unseen (`_spills`): a resolved non-shell (`cat`, a printer, `true`)
    writes no file but `/dev/null`, feeds no `>(...)`, and pipes only into a measured shell,
    spelled as its stage's first word, that reads the stream as its program.
13. A value bash still holds (`_literal`): no name bash sets itself (`_BASH_SETS`: `$_`,
    `BASH_REMATCH`, `REPLY`, `PWD`, ..., and `COMP_*`, `READLINE_*`), and no unbraced `$NAME` a
    shorter held name prefixes (`"$C"h` reaches the reader as `$Ch`).
14. A printed fetch, read once (`_spell`, `_Step`, `_Fold`): a printer's words are spelled only
    where its stage pipes into another (`printed`'s only reader) and the text it prints, its
    words and these values, fetches (`_FETCH_WORD`: a `curl` or `wget` word). What the rules ask
    of a step is worked out once, on the first ask, and the table read forward once: a statement
    `static_values` reads past -- in a loop body, a forked child, a `while` head -- holds no
    value, so no word there is spelled and no command word there resolved.

The prices -- where a mark reads otherwise than bash:

 - The twin's: a resolved word reads as its literal twin, the twin's named prices and filed gaps
   with it -- `CMD=sh; $CMD -c 'cat' < i.sh` takes #2793's over-report, a fetch into a runner the
   guard does not list (`X='curl … | csh'; echo "$X" | sh`) is #2792's gap, and a foreign
   interpreter's program is not read (#2601: `PERL=perl; $PERL <<'EOF'` around a backquoted
   `curl … | sh` reads CLEAN as `perl` does; beside a reported fetch its `Idle` report stands).
 - The table's: a value that expands (`X='echo $(curl … | sh)'`) reads as the base, `Idle` and
   CLEAN (#2815); a value the shell may not assign is a second candidate, so the word stays as
   written (`if c; then X=other; fi`, #2816); a single-quoted printer word (`echo '$X' | sh`) is
   spelled as the value and over-reports, and `T+=x` on a name the step never assigned holds the
   suffix alone (#2733, filed with this PR).
 - Not read: a `$(...)` child `workflow_guard._walk` parses, and a `-c`, `eval` or heredoc script
   `flattened` parses, are read after `annotate` and inherit no mark (#2814); an empty value,
   which bash drops so the next word runs (`CMD=; $CMD sh <<'EOF'`), stays as written (#2472);
   and a `${X:-sh}` command word is #2337's default, read before any value.
 - The step's own: a name the guard reads written into a directory on the runner's PATH by an
   earlier step, by a text that names no such path (`cd ~/.local/bin; cp /usr/bin/true sh`), or
   by one that spells the name through an expansion (`tools/$N`, `tools/{sh,x}`), is not seen
   (#2733, filed with this PR).

A refused mark keeps the base's answer, an over-report where the program was sound (`set -e`,
`X=1` or `cd` in a body, a check behind `|| exit 1`, a trap `rm -f "$T"`, `$CAT <<'EOF' > i.sh`,
a `( true )` or `X=1 a=(x) true` the reader cannot tell from a header `g ( )`, a header inside a
quoted or printed text, a builtin a value names (`G=getopts; $G t CMD -t`),
`CMD=true command :`, whose assignment no shell keeps, `let CMD=1`, whose integer names no
command, a prefix to `let` or `[[` (`CMD=true let X=1`), `declare CMD=true` or `readonly CMD=true`
with no later assignment, whose value bash keeps, `export -n`, `--` or `+x` before `CMD=true`,
whose assignment bash keeps too, a later `CMD=true` to a `readonly CMD=sh`, which stops the step,
an option word in a body or a redirect (a heredoc's `curl -X` spells `X`), or a bare mention of
the name in another word, `echo CMD`).
A step in which no word is marked reads byte for byte as before.

Stdlib only, like everything under it.
"""
import functools
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
from workflow_uses import _WHOLE, _cleared, _control_kinds, _forked, _table_certainty
from workflow_values import _OPENER, Values, _literals, record, valued

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
# The names bash sets itself, and the prefixes of its completion and `bind -x` ones: a step's
# assignment to one is not what a later word reads (`$_` is the last command's last word).
_BASH_SETS = frozenset((
    "_", "BASH_ARGC", "BASH_ARGV", "BASH_ARGV0", "BASH_COMMAND", "BASH_EXECUTION_STRING",
    "BASH_LINENO", "BASH_REMATCH", "BASH_SOURCE", "BASH_SUBSHELL", "BASH_VERSINFO", "BASHPID",
    "COLUMNS", "COPROC", "DIRSTACK", "EPOCHREALTIME", "EPOCHSECONDS", "EUID", "FUNCNAME",
    "GROUPS", "HISTCMD", "HOSTNAME", "LINENO", "LINES", "MAPFILE", "OLDPWD", "OPTARG", "OPTIND",
    "PIPESTATUS", "PPID", "PWD", "RANDOM", "REPLY", "SECONDS", "SHLVL", "SRANDOM", "UID"))
_BASH_PREFIXES = ("COMP_", "READLINE_")

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
# load code into it or rebind its commands or aliases, the prefix of a function bash imports from
# the environment, and the files and variables a fetcher starts from (`~/.curlrc` with `data =
# @/dev/stdin` reads the rest of a fed program); the paths that name a descriptor (`/dev/stdin`,
# `/dev/fd/0`, `/proc/self/fd/0`, or `/dev` itself for a `cd`), through which a fetcher's output
# or a redirect lands in a fed program on Linux, where its shell runs it (`curl -o /dev/stdin`);
# the commands that may define or rebind a name no text of the step spells; a trap action that
# runs nothing (empty, `-`, or `rm` of literal paths) and the conditions whose traps run between
# the step's own commands; the words that set a text to run later; a path to a name the guard
# reads, its directory the group; and how deep a program's own programs are read.
_HEADER = re.compile(r"\b([A-Za-z_][\w-]*)\s*\(\s*\)|\bfunction\s+([A-Za-z_][\w-]*)", re.A)
_ENVIRON = re.compile(r"(?<![\w${])(?:(?:PATH|SHELLOPTS|BASHOPTS|BASH_ENV|ENV|IFS|POSIXLY_CORRECT"
                      r"|PS4|BASH_CMDS|BASH_ALIASES|LD_PRELOAD|LD_LIBRARY_PATH|HOME|CURL_HOME"
                      r"|XDG_CONFIG_HOME|WGETRC|CURL_CA_BUNDLE|SSL_CERT_FILE)(?!\w)|BASH_FUNC_)"
                      r"|curlrc|wgetrc", re.A)
_DESCRIPTOR = re.compile(r"dev/(?:stdin|fd)(?![\w.-])|(?<![\w.-])/(?:dev|proc)/?(?![\w./-])|proc/",
                         re.A)
_SOURCES = (".", "source", "eval", "builtin", "enable", "hash")
# The POSIX special builtins, before which dash and bash's POSIX mode keep a prefix assignment.
_SPECIAL = (":", ".", "break", "continue", "eval", "exec", "exit", "export", "readonly", "return",
            "set", "shift", "times", "trap", "unset")
_ASSIGNS = re.compile(r"[A-Za-z_]\w*(?:\[[^]]*\])?\+?=", re.A)
# The builtins whose words name what they set, unset or declare, and what bash expands a word by
# into words no text spells (`read {C,}MD`, `unset C?D`, `printf -v {C,%b}MD 'sh\c'`).
_NAMING = ("read", "unset", "wait", "getopts", "select", "mapfile", "readarray", "printf",
           "local", "readonly", "declare", "typeset", "export")
_EXPANDED = re.compile(r"[{}*?[]")
_TRAP_SAFE = re.compile(r"(?:rm(?: -[rf]+)*(?: [\w./-]+)+)?|-", re.A)
_TRAPPED = frozenset(("DEBUG", "RETURN", "ERR"))
_LATER = re.compile(r"(?<![\w./-])(?:trap|mapfile|readarray)(?![\w./-])", re.A)
# A name's spellings (`_spelled`): a run of name characters; what may follow `${NAME` in a
# reference that only reads (`=` and `:=` assign); what follows a name in a word assigning it;
# and the commands whose assignment words bash may refuse, alter or read as arithmetic.
_RUN = re.compile(r"\w+", re.A)
_READS = re.compile(r"\}|:?[-+?]|[#%/^,@\[]|:\d", re.A)
_OWN = re.compile(r"\+?=", re.A)
_DECLARES = ("let", "[[", "local", "readonly", "declare", "typeset")
_ON_PATH = re.compile(r"(?<![^\s\"'=:;|&<>(){}!])([^\s\"'=:;|&<>(){}!]*)/(?:%s)(?![\w.+/-])"
                      % "|".join(_NAMES), re.A)
_DEPTH = 8


def annotate(stmts):
    """Mark `stmts` in place, in order, through the step's own values, and return them: a command
    word that is one whole reference the table resolves to one literal becomes `Defaulted(text)`,
    and a printer's whole-reference words get `spelled` -- each kept only where the module
    docstring's rules hold, and taken back, the statement read as written, where one fails. What
    a rule asks of the step is worked out on its first ask (`_Step`): a step with no whole
    reference builds nothing, and one with no mark reads no veto."""
    step = _Step(stmts)
    for index, statement in enumerate(stmts):
        written = [list(stage.argv) for stage in statement.stages]
        for position, stage in enumerate(statement.stages):
            argv = command(stage.argv)
            if argv and not _printer(argv):
                for at, word in _references(stage, argv[:1]):
                    text = _literal(word, step.fold.at(index)) if step.sure[index] else None
                    if text is not None and _commands(stage, at, text) and step.plain(word):
                        stage.argv[at] = Defaulted(text)
                argv = command(stage.argv)
            if argv and _printer(argv) and position + 1 < len(statement.stages):
                _spell(stage, argv, step, index)
        if any(new is not old for stage, was in zip(statement.stages, written)
               for new, old in zip(stage.argv, was)):
            vetoed = step.vetoed
            if vetoed or not _complete(statement):         # read as written
                for stage, was in zip(statement.stages, written):
                    stage.argv[:] = was
            if vetoed:                                      # and so every later statement
                break
    return stmts


class _Step:
    """What the rules ask of a step's statements, each worked out once, on its first ask: the
    statements in a test (`_in_tests`), the ones the step surely runs (`_surely_run`), the table
    at each (`_Fold`), and whether no mark stands in it (`_vetoed`, with a table of its own)."""

    def __init__(self, stmts):
        self.stmts = stmts

    @functools.cached_property
    def tests(self):
        return _in_tests(self.stmts)

    @functools.cached_property
    def sure(self):
        return _surely_run(self.stmts, self.tests)

    @functools.cached_property
    def fold(self):
        return _Fold(self.stmts)

    @functools.cached_property
    def vetoed(self):
        return _vetoed(self.stmts, _Fold(self.stmts))

    @functools.cached_property
    def spelled(self):
        return _spelled(self.stmts)

    def plain(self, word):
        """Whether whole reference `word`'s name is spelled in the step only as rule 7 allows (no
        name `_spelled` returns), read as the step stood before any mark: each mark asks first."""
        named = _NAMED.match(str(word))
        return named is not None and named[1] not in self.spelled


class _Fold:
    """The step's table at each statement asked, in order, read forward once (rule 14). Where
    `workflow_uses.static_values` reads a statement by walking only the ones before it -- in a
    step that defines no function, at a statement in no forked child, loop body or `while` or
    `until` head (`_folds`) -- it reads each of them as sure as `_table_certainty` says and
    outside every child the shell forks (`_forked`): the same walk for each such statement, which
    one table read forward serves. Elsewhere, where it would read past the statement or a
    child's own values, and in a step that defines a function (rule 7), the fold holds no value
    and the word stays as written."""

    def __init__(self, stmts):
        self.stmts, self.table, self.read = stmts, Values(), 0
        self.kinds, self.forked = _control_kinds(stmts), _forked(stmts, len(stmts))
        self.defines = any(_function_syntax(stage.argv)[0] for statement in stmts
                           for stage in statement.stages)

    def at(self, index):
        """The table live at statement `index`."""
        if self.defines or index < self.read or not self._folds(index):
            return Values()
        for position in range(self.read, index):
            stages = self.stmts[position].stages
            if stages:
                certain, direct_loop = _table_certainty(self.stmts, position, self.kinds)
                certain = certain and position not in self.forked and len(stages) == 1
                _cleared(stages[-1], {}, {}, certain, direct_loop, self.table)
                record(self.table, stages[-1], certain)
        self.read = index
        return self.table

    def _folds(self, index):
        """Whether `static_values` reads statement `index` as the fold does: in no forked child,
        so its `_forked` set is the step's own; in no loop body, which it reads past `index` too
        (an earlier pass ran it); and in no `while` or `until` head, whose body it reads."""
        head = self.stmts[index].stages[0].argv if self.stmts[index].stages else []
        lead = head[:len(head) - len(command(head))]
        return index not in self.forked and "do" not in self.kinds[index] and not (
            {"while", "until"} & set(map(str, lead)))


def _spelled(stmts):
    """The names the step spells otherwise than rule 7 allows: each run of name characters in its
    statements' texts -- each word, redirect target or source, heredoc body and substitution, the
    reader's markers taken out -- that is no plain reference (`$NAME`, or `${NAME` and an operator
    that reads, `_READS`) and, in a command's word, neither follows its leading `-` or `--` (`-X`,
    `--CMD`) nor starts it before `=` or `+=` (`CMD=true $CMD`, `env CMD=x`) where the command
    keeps that assignment as written: not one of `_DECLARES` (`let CMD=1`, `local CMD=x`) nor an
    `export` with an option word (`export -n CMD=x`, `export -- CMD=x`). A run is the name only
    where it equals it: `XCMD`, `CMD2` and `$CMDX` spell other names."""
    out = set()
    for statement in stmts:
        for stage in statement.stages:
            kept = [str(word) for word in command(stage.argv)]
            declares = bool(kept) and (kept[0] in _DECLARES or kept[0] == "export" and any(
                word[:1] in ("-", "+") for word in kept[1:]))
            bodies = [body[0] for body in (stage.stdin_heredoc,) if body]
            texts = [*stage.writes, *stage.reads, stage.heredoc or "", *bodies,
                     *stage.substitutions]
            for word, own in [*((word, True) for word in stage.argv),
                              *((text, False) for text in texts)]:
                text = str(word)
                for marker in shell_reader._markers(word):
                    text = text.replace(marker, "\0")
                for run in _RUN.finditer(text):
                    start, end = run.span()
                    before = text[max(0, start - 2):start]
                    if before.endswith("$") or before == "${" and _READS.match(text, end):
                        continue                                    # a reference that reads
                    if own and (text[:start] in ("-", "--") or not start and not declares
                                and _OWN.match(text, end)):
                        continue                                    # an option or assignment
                    out.add(run[0])
    return out


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
    """The ONE literal text whole reference `word` stands for through `table`, or None (rules 1
    and 13): its name holds one candidate, not empty, and is no name bash sets itself
    (`_BASH_SETS`, `_BASH_PREFIXES`) nor, unbraced, one a shorter held name prefixes (a quote
    joined `"$C"h` into `$Ch`); and the word resolves to one text with no lifted `$(...)`, no
    `$`, no backquote and no process substitution (`_EXPANDS`)."""
    named = _NAMED.match(str(word))
    name = named[1] if named else ""
    if name in _BASH_SETS or name.startswith(_BASH_PREFIXES) or not str(word).startswith(
            "${") and any(name[:cut] in table.scalars or name[:cut] in table.arrays
                          for cut in range(1, len(name))):
        return None
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


def _spell(stage, argv, step, index):
    """Give each whole-reference word of printer `argv`, a stage piped into another, its value's
    `spelled` text, the word itself kept as written so every other reader sees what it saw, as
    `shell_reader._stage` gives a `\\$` word one -- where it stands in no test, its name is spelled
    only as rule 7 allows, and the text it prints, its words and these values, fetches (rule 14)."""
    words = list(_references(stage, argv[1:]))
    if not words or step.tests[index]:
        return
    spelled = []
    for at, word in words:
        text = _literal(word, step.fold.at(index))
        if text is not None and step.plain(word):
            spelled.append((at, word, text))
    printed = " ".join([*map(str, argv[1:]), *(text for _at, _word, text in spelled)])
    for at, word, text in spelled if _FETCH_WORD.search(printed) else ():
        stage.argv[at] = shell_reader._Token(str(word), shell_reader._markers(word))
        setattr(stage.argv[at], "spelled", text)


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


def _surely_run(stmts, tests):
    """Per statement: whether the step's own shell surely runs its command where it stands -- at
    the top level, outside every `{ }` and `( )` (a `{` after a function header the reader split
    into a name and a `( )`, `g ( ) {`, opens one too), in no compound (`_control_kinds`), with no
    keyword, function header or `case` arm in front of it (no `!`, no body run later), in no `&&`
    or `||` list, not in the background, and in no test (`tests`, `_in_tests`' answer). Elsewhere
    a resolved word would take its literal twin's reading where that reading has a filed gap
    (#2666: a `}` or an `exit` in a body read as the step's own) or another (a failed check a
    line into a test read as stopping the step), or the table a named limit (a body's values)."""
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


def _complete(statement, depth=0):
    """Whether every program a stage of `statement` hands a shell is `_plain` (rule 6): a `-c` or
    `eval` string, and -- descriptor 0 the program -- a heredoc or here-string body, a `<(...)`
    FILE, or what a printer or a heredoc-fed `cat` pipes in, each reading of an `echo` (`ANY`):
    the texts `workflow_forms.flattened` reads in place (`scripts`, `stdin_scripts`); the shell
    reading one a measured one, by a name `_bare` reads, and `_quiet`, with no `-s` beside a `-c`
    string (`bash -s -c true` runs `true`, not the body) and no output redirect (the reader takes
    `<>` for one, and bash's `&>` for one where a dash step backgrounds the command); and no
    resolved non-shell's output reaching a runner the twin's reading does not weigh (`_spills`,
    rule 12)."""
    for at, stage in enumerate(statement.stages):
        argv = command(stage.argv)
        if not argv:
            continue
        name, strings = os.path.basename(str(argv[0])), scripts(argv)
        texts = stdin_scripts(argv, stage, statement.stages[:at], ANY)
        shell = bool(strings or texts) and name in shell_reader._SHELLS
        letters = _quiet(argv) if shell else ""
        if shell and (_bare(argv[0]) not in _MEASURED_SHELLS or letters is None
                      or stage.writes or strings and texts and "s" in letters):
            return False
        if isinstance(argv[0], Defaulted) and not shell and _spills(statement, at):
            return False
        if not all(_plain(text, depth, False) for text in strings) or not all(
                _plain(text, depth, True) for text in texts):
            return False
    return True


def _spills(statement, at):
    """Whether what stage `at` of `statement` writes may reach a runner the twin's reading does
    not weigh (rule 12): a file but `/dev/null` (`$CAT <<'EOF' > i.sh`, then `sh i.sh`), a
    `>(...)`, or a next stage other than a measured shell spelled as its own first word that
    reads the stream as its program -- not `tee i.sh`, `xargs sh -c`, `env sh`, `sh -c 'cat >
    i.sh'` or `sh i.sh`."""
    stage, stages = statement.stages[at], statement.stages
    if any(str(word) != "/dev/null" for word in stage.writes) or stage.substitutions:
        return True
    if at + 1 == len(stages):
        return False
    after = stages[at + 1]
    argv = command(after.argv)
    return not (argv and len(argv) == len(after.argv) and _bare(argv[0]) in _MEASURED_SHELLS
                and stdin_scripts(argv, after, stages[:at + 1], ANY))


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


def _plain(text, depth, fed):
    """Whether a shell runs program `text` as the guard reads it in place, the step's own: every
    statement a pipeline of simple commands run in order -- no group, compound, function, list or
    background, no assignment, wrapper or keyword in front, no expansion -- whose command words are
    literal names, none `_HELD` (`exit`, `exec`, `set`, `cd`, `read`, `trap`, `eval`, `alias`, ...)
    nor `printf -v` (which assigns), whose first command reads none of the program where
    descriptor 0 is the program (`fed`: `_silent`; a `cat` there swallows the rest, and so may a
    `./true` the step wrote), and whose own programs are plain too. A shell running anything else
    in a child of its own runs it otherwise than in place: `exit 0` before a check ends the child,
    not the step; `T=other`, `printf -v T other`, `cd` and `alias` stay in it."""
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
                    or name in _HELD
                    or name == "printf" and len(argv) > 1 and str(argv[1]).startswith("-v")
                    or fed and not at and stage.stdin_from_pipe and not _silent(argv)):
                return False
        if not _complete(statement, depth + 1):
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
    descriptor, `-o /dev/stdin`, is `_vetoed`'s), or an option word, by which sh, bash and dash
    find no command (`-e`, which dash's `echo -e` prints)."""
    name = _bare(argv[0])
    if name in FETCHERS:
        return all((_FETCH_QUIET if word.startswith("-") else _FETCH_OPERAND).fullmatch(word)
                   for word in map(str, argv[1:]))
    return name in _SILENT or name is not None and name.startswith("-")


def _vetoed(stmts, fold):
    """Whether no mark stands in the step (rules 7 to 11): where a stage's command, as `_resolved`
    reads it through `fold`, may change what a later word holds or runs (`_rebinds`), is reached
    through a value and is no name in `_NAMES` or is `printf -v`, or is one of `_SPECIAL` behind
    a prefix assignment (`_ASSIGNS`) or one of `_NAMING` with a word holding a brace or a glob
    (`_EXPANDED`); or where a text a stage holds -- its words, a redirect's
    target, a heredoc, a substitution -- names an environment word (`_ENVIRON`), a descriptor
    path (`_DESCRIPTOR`), a function header (`_HEADER`), or a name the guard reads by a path
    outside `_SYSTEM`'s directories (`_ON_PATH`), or redirects into a file by such a name, or --
    past the words of a `trap` or a `mapfile` `_rebinds` reads -- names `trap`, `mapfile` or
    `readarray` (`_LATER`: a child's trap runs at its exit, the download too)."""
    for index, statement in enumerate(stmts):
        for stage in statement.stages:
            kept = command(stage.argv)
            name = _resolved(kept[0], fold, index) if kept else ""
            if name is None or _rebinds(stage, name, [str(word) for word in kept[1:]]):
                return True
            # a command word reached through a value: the table reads only a literal one
            if kept and (_EXPANDS.search(str(kept[0])) or shell_reader.is_marker(kept[0])) and (
                    name not in _NAMES or name == "printf" and any(
                        str(word).startswith("-v") for word in kept[1:])):
                return True
            # a prefix assignment that dash and bash's POSIX mode keep before a special builtin
            lead = [str(word) for word in stage.argv[:len(stage.argv) - len(kept)]]
            if kept and name in _SPECIAL and any(_ASSIGNS.match(word) for word in lead):
                return True
            # a name bash expands by a brace or a glob first (before `=`, outside a `${...}`)
            if name in _NAMING and any(_EXPANDED.search(re.sub(r"\$\{[^{}]*\}", "", str(word))
                                                        .split("=", 1)[0]) for word in kept[1:]):
                return True
            bodies = [body[0] for body in (stage.stdin_heredoc,) if body]
            words = " ".join(map(str, stage.argv))
            texts = [*map(str, stage.writes), stage.heredoc or "", *bodies,
                     *map(str, stage.substitutions)]
            if any(os.path.basename(str(target)) in _NAMES for target in stage.writes) or any(
                    _ENVIRON.search(text) or _DESCRIPTOR.search(text) or _HEADER.search(text)
                    or any(found[1] not in _SYSTEM for found in _ON_PATH.finditer(text))
                    for text in (words, *texts)):
                return True
            later = texts if name in ("trap", "mapfile", "readarray") else [words, *texts]
            if any(_LATER.search(text) for text in later):
                return True
    return False


def _resolved(word, fold, index):
    """The name command word `word`, at statement `index`, runs by: the word as written, or the
    ONE literal a whole reference holds through `fold`'s table (`S=.; $S ./defs.sh` runs `.`);
    None where neither is known (`$(echo .) ./defs.sh`)."""
    if not (_EXPANDS.search(str(word)) or shell_reader.is_marker(word)):
        return str(word)
    return _literal(word, fold.at(index)) if _WHOLE.fullmatch(str(word)) else None


def _rebinds(stage, name, words):
    """Whether command `name`, with `words` after it, may change what a later word holds or runs
    (rules 7 and 8): one of `_SOURCES` -- `.`, `source`, `eval`, `builtin` (`builtin . ./x`),
    `enable` (a loaded builtin) or `hash` (`hash -p ./x sh`) -- an `alias`, a function header the
    reader split (`g ( )`, `g ( ) {`: any other a text holds is `_HEADER`'s), a `declare`,
    `typeset` or `local` whose option word holds `n` (a nameref: `declare -n CMD=y; y=true`), a
    `read` that glues an array name to `-a` (`read -aCMD`), a `wait -p`, a command word `NAME[`
    (bash reads `CMD[ 0 ]=true` as one assignment, the reader as `CMD[`), a `trap` that runs a
    text (not `_TRAP_SAFE`) or traps one of `_TRAPPED` (bash runs a `DEBUG` trap before each
    command), or a `mapfile -C` callback, run per line read."""
    literals = _literals(stage)        # an array literal's `( )`: no header
    if name in _SOURCES or name == "alias" or name and words in ([], ["{"]) and (
            stage.group_open - literals == stage.group_close - literals == 1):
        return True
    if name in ("declare", "typeset", "local"):
        return any(word[:1] in ("-", "+") and "n" in word for word in words)
    if name == "read":                  # an array name glued to `-a` (`read -aCMD`)
        return any(word[:1] == "-" and "a" in word[1:-1] for word in words)
    if name == "wait":                  # `wait -p NAME` unsets NAME first (bash 5.1)
        return any(word[:1] == "-" and "p" in word for word in words)
    if re.fullmatch(r"[A-Za-z_]\w*\[", name):    # `CMD[ 0 ]=true`, one assignment to bash
        return True
    if name == "trap":
        return bool(words) and not (_TRAP_SAFE.fullmatch(words[0])
                                    and not _TRAPPED & {word.upper() for word in words[1:]})
    return name in ("mapfile", "readarray") and any(
        word[:1] == "-" and "C" in word for word in words)
