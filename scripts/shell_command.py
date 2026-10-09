#!/usr/bin/env python3
"""What stands in FRONT of a shell command, and the command behind it.

Split out of `scripts/shell_reader.py` at that module's size (699 of its 700
lines), byte for byte: the keywords, assignment and function-header spellings
a statement may open with, the shells and the default or optional `$` words
that may stand for one (#2337, #2472), and the one walk that strips them all
(`_command_result`) to answer `command`, `command_as_written`,
`unresolved_wrapper`, `wrapper_words`, `negated` and `conditional` -- and
`reads_held` and `find_action`, the commands a `find` runs past them (#2881
round 4, #2918). The reader
imports every name back under its own, so nothing that read
`shell_reader.command` or `shell_reader.KEYWORDS` moved; this module imports
nothing from the reader, so the layers still run one way.

Stdlib only, like everything under it.
"""
import itertools
import os
import re

from shell_patterns import shell_words
from shell_tokens import derived, has_substitution, is_arm, readable, spelled
from shell_wrappers import WRAPPERS, Defaulted, Rewritten, dynamic, unwrap


# Shell keywords that stand in FRONT of the command: `if curl ...; then`,
# `while true; do /tmp/payload; done`. Statements are split on `;`, so each of
# these arrives as the first word of the statement it introduces -- and a guard
# that reads `if` as the command sees neither the fetch nor the use.
KEYWORDS = ("if", "then", "elif", "else", "fi", "do", "done", "while", "until",
            "for", "case", "esac", "in", "!", "{", "}", "(", ")", "function",
            "()")

# The words that make the following command CONDITIONAL rather than fatal: a
# command in an `if`/`while` test decides a branch, and `set -e` never applies
# to it. A guard reading exit statuses has to know the difference.
CONDITIONS = ("if", "elif", "while", "until")

# A word bash reads as an assignment in front of a command (#2348): `NAME=`,
# `NAME+=`, and to an array element, `a[1]=x` or `a[1]+=x`, which bash globs
# nothing in; an array literal (`a=(1 2)`) is folded into its word by `_stage`.
# Behind a wrapper the words are the wrapper's, and only `NAME=` is popped
# there, as `env X=1` and `sudo X=1` take it: `sudo a[1]=x` is a pattern.
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]*\])?\+?=")
_ENVIRONMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_FUNCTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*\(\)$")

# The shells whose options and program word a pattern may rewrite into a `-c`
# and its script (`sh {-c,'…'}`, review N-3): `workflow_programs._SHELL_STRING`.
_SHELLS = ("sh", "bash", "dash", "ash", "ksh", "zsh")
# A command word that is a parameter's default or alternate (#2337): `${X:-sh}`,
# `"${X-bash}"`, `${X:=sh}`, `${X:+sh}`. Where it spells a shell it is read as
# that shell, which bash runs wherever `X` leaves the word to it.
_DEFAULTS = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=+]([^{}$`'\"\\\s]+)\}")
# The same read whole, its default holding blanks (`${X:-bash -s}`): only a word the reader split
# at blanks no quote or backslash covers, where bash splits the default too, once expanded (#2731);
# a literal glued after the `}` joins its last word (`${X:-/usr/bin/env s}h`, #2856 round 11) --
# none bash would glob (`${X:-bash -s}*` is `-s*`, an option no shell takes).
_WHOLE_DEFAULTS = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=+]([^{}$`'\"\\]+)\}([^\s{}$`'\"\\*?[]*)")
# A command word bash may expand to nothing (#2856 rounds 12 and 13, the round-11 and round-12 B2): an
# alternate (`${X:+W}`, `${X+W}`), a default with no colon, which a name set empty leaves empty
# (`${X-W}`, `${X=W}`), a pattern taken off or replaced (`${X#W}`, `${X%%W}`, `${X/p/W}`) and a case
# change (`${X^^W}`, `${X,W}`), whose W is a pattern and never the command -- of a name, an indirection
# (`${!X…}`), an element (`${X[0]…}`, `${X[@]…}`), a positional parameter, `$@` and `$*`, `$!` with no
# background job, and `$-`, empty under dash with no options. Empty, it is the literal glued after its
# `}`, or nothing, and the next word runs; its other half is `_alternate`'s (`_command_result`).
_VANISHING = re.compile(r"\$\{(!?[A-Za-z_]\w*(?:\[[^]]*\])?|[0-9]+|[@*!-])(:?\+|[-=]|##?|%%?|//?|\^\^?|,,?)"
                        r"[^{}]*\}([^\s{}$`'\"\\*?[]*)")
# The halves `_command_result` reads of the command words bash may expand to nothing (`folds`): the
# ones this fold reads empty -- none, as `main` reads them, then all (`_ALL`), then each other set of
# those whose halves read apart, by place (`_half`, #2929) -- and whether one with both halves was met.
_HALVES: dict = {"empty": frozenset(), "words": {}, "both": False, "on": False}
_ALL = frozenset({None})
# The command words bash may expand to nothing whose every reading the folds read; one more reads as
# a command the guard cannot read, wherever it runs (#2929).
_HALF_CAP = 3
# A default's parameter and operator (`_strips`): only `#`, `?` and `$` are never unset or empty -- `$-`
# is, under dash with no options, and `$0` in a `-c` text run with an empty `$0` -- and an
# indirection (`${!Y:-W}`) is read as its name is (#2856 round 13, the round-12 B1: the seat's `excfix`).
_PARAMETER = re.compile(r"\$\{(!?[A-Za-z_]\w*(?:\[[^]]*\])?|[#?$!@*-]|[0-9]+)(:?[-=+])")
# A command word that is ONE unquoted reference, with no default or one that
# hands on (`$SUDO`, `${SUDO}`, `${SUDO:-}`, `${X:-sudo}`), in front of a name
# the reader knows: an optional wrapper spelled by variable (#2472). Empty or
# unset, bash drops the word and the next one is the command -- bash 5.2.21,
# 3.2.57 and dash all run `$SUDO sh -c 'curl … | sh'`'s pipeline with `SUDO`
# unset -- and set to `sudo` the next one runs too, so `_command_result` reads
# the rest as the command. That fails CLOSED where the value runs nothing of
# it (`SUDO=apt-get`; a literal `echo` or `true` `workflow_annotate` resolves
# first). A quoted `"$SUDO"` keeps its word (`_stage`'s `quoted`): bash runs
# the empty string and stops. The names: the shells, the wrappers, the foreign
# interpreters and the fetchers -- the last two pinned equal to
# `workflow_programs._FOREIGN` and `workflow_fetch.FETCHERS` by test.
_OPTIONAL = re.compile(r"\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*(?::?[-+=]([^{}$`'\"\\\s]*))?\})")
_INTERPRETERS = ("python", "python3", "perl", "ruby", "node", "php", "pwsh")
_FETCHERS = ("curl", "wget")
OPTIONAL_NEXT = (*_SHELLS, *WRAPPERS, *_INTERPRETERS, *_FETCHERS)


def _optional(argv):
    """How many leading words of `argv` bash may drop in front of a name the
    reader knows (`_OPTIONAL`, #2472): each unquoted, one reference, with no
    default or one that is itself a wrapper (`${X:-sudo}`); 0 where the word
    after them is not in `OPTIONAL_NEXT`."""
    count = 0
    while count < len(argv) - 1:
        word = argv[count]
        match = None if getattr(word, "kept", False) else _OPTIONAL.fullmatch(word)
        if not match or match[1] and os.path.basename(match[1]) not in WRAPPERS:
            break
        count += 1
    return count if count and os.path.basename(argv[count]) in OPTIONAL_NEXT else 0


def _shell_default(word):
    """The words a command word that is a shell's one-word default runs as (`${X:-sh}`: `sh`), or
    None: `"${SH:-bash}"` is `bash` (#2337), and `"${SH:- bash}"`, `${X:-"bash -s"}` and
    `${X:-bash\\ -s}` name no shell. A default holding a blank the reader marks is read whole
    (`_default_words`)."""
    default = _DEFAULTS.fullmatch(word)
    return [default[1]] if default and os.path.basename(default[1]) in _SHELLS else None


def _default_words(whole):
    """The words bash makes of a command word it expands whole, its name unset (#2731): the default,
    a literal glued after the `}` joining its last word -- a lifted `$(…)` too, which keeps it dynamic
    (#2856 round 12, the round-11 F2) -- split where bash splits it, at a space, a tab or a newline,
    never a Unicode or vertical space (round 11, F2), each word a token keeping the reader's marks of
    what it holds (`spelled`: in one pass over the word, round 12's B3), so a lifted `$(…)` stays
    dynamic behind a wrapper and a `<(…)` a file. None where `_WHOLE_DEFAULTS` does not read the
    word: a `$NAME` or a nested default in it, or a parameter that is no NAME."""
    default = _WHOLE_DEFAULTS.fullmatch(whole)
    if not default:
        return None
    return [spelled(part, whole) for part in re.split(r"[ \t\n]+", (default[1] + default[2]).strip(" \t\n"))]


def _strips(whole):
    """Whether `main`'s split words of a command word read whole (`_command_result`) end in the
    default's `}`, which comes off them: a default (`-`, `=`) or alternate (`+`) bash may expand --
    not where the parameter is never unset or empty (`${#:-…}`, `${?:-…}`, `${$:-…}`), nor an
    assignment to a parameter that is no NAME (`${1:=…}`, an error that runs nothing; #2856 round
    12, B1; round 13 reads `$-`, `$0` and `${!Y:-W}`, which may be empty, the round-12 B1)."""
    found = _PARAMETER.match(whole)
    if not found:
        return False
    parameter, operator = found[1], found[2]
    if operator.endswith("=") and not (parameter[0].isalpha() or parameter[0] == "_"):
        return False
    return not (parameter in ("#", "?", "$") and operator in ("-", ":-"))


def _alternate(argv, whole, span):
    """`argv` with its command word `whole` read as bash expands it where its name is set (for `-`
    and `=`, unset): its W, as `_default_words` reads a default -- a command the reader knows is
    that command, its words the reader's own; one it does not know, the word whole -- or past
    `_WHOLE_DEFAULTS`, `main`'s split words, the default's `}` off their last (#2856 rounds 11-12)."""
    argv, words = list(argv), _default_words(whole)
    if words and os.path.basename(words[0]) in OPTIONAL_NEXT:
        # A default naming a command the reader knows -- a shell, a wrapper, a foreign
        # interpreter, a fetcher, by path too -- is that command, its words the reader's own
        # (`${X:-bash -s}`, `${X:-/usr/bin/env sh -c}`, `${X:-/usr/bin/curl -fsSL} URL`).
        argv[0:span] = [Defaulted(words[0]), *words[1:]]
    elif words or os.path.basename(argv[0]) not in OPTIONAL_NEXT:
        argv[0:span] = [whole]          # a name the guard does not follow, read whole
    # Else `main`'s split words stay: past `_WHOLE_DEFAULTS` (`${X:-$HOME/bin/env sh -c}`,
    # `${1:-/bin/sh -c}`), their first names a known command by its basename (#2856 round 11)
    # -- the default's `}` off their last word, at its first `}`, and a word of it alone gone;
    # a word `main` reads as a pattern stays (`/usr/bin/ba}[s]h`; #2856 round 12, B1).
    elif _strips(whole) and not isinstance(argv[span - 1], Rewritten) and (
            cut := argv[span - 1].partition("}"))[1]:
        argv[span - 1:span] = [derived(cut[0] + cut[2], argv[span - 1])] if cut[0] + cut[2] else []
    return argv


def _runs(argv):
    """How much a reading of a command may run that the guard reports, with the command as read, so
    that two halves of an expansion bash may make empty, each what the guard may report where the
    other is not, are a command it cannot read (#2856 round 13): 5 a command it cannot read,
    reported wherever it runs; 4 a shell, a foreign interpreter, `eval`, `source`, `.` or an
    unpacker, reported where it runs a download; 3 a fetcher, where what it fetches runs; 2 a word
    the guard does not follow (`$X`), where a download is piped to it or a `-c` follows it; and 1
    any other command, or none."""
    if argv and getattr(argv[0], "whole", None) is not None:
        argv = [spelled(str(argv[0]), argv[0]), *argv[1:]]     # `main`'s words, kept: read once
    command_, reason, _heads = _command_result(argv)
    head = os.path.basename(command_[0]) if command_ else ""
    if reason or head in (*_SHELLS, *_INTERPRETERS, *_UNPACKERS, "eval", "source", "."):
        return (5 if reason else 4), command_
    if head in _FETCHERS or command_ and dynamic(command_[0], has_substitution):
        return (3 if head in _FETCHERS else 2), command_
    return 1, command_


def _command_result(argv, optional=True):
    """Shared parse result for execution extraction and unread decisions: the
    command, why it or a wrapper in front of it cannot be read (or None), and
    the words read as wrappers, as written. A command word that is a shell's
    default (`${X:-sh}`, `_DEFAULTS`) is read as that shell; `$` words in front
    of a known name are dropped (`_optional`) unless `optional` is False, the
    reading `workflow_annotate` takes to find the word a step's table resolves."""
    argv = list(argv)
    heads: list[str] = []
    # `xargs` appends words from its input to the argv behind it, so the
    # innermost wrapper read after one (`behind`, with its argv) was read from
    # an argv that is not the one that runs (#2227).
    appended, behind, vanished = False, None, None
    while argv:
        if (_ENVIRONMENT if heads else _ASSIGNMENT).match(argv[0]):
            argv.pop(0)
            continue
        if argv[0] in KEYWORDS:
            keyword = argv.pop(0)
            if keyword == "function" and argv and _NAME.match(argv[0]):
                argv.pop(0)                     # `function f { ... }`
            continue
        # A function header is not a command: `f() { curl ... ; }` and its
        # `f () {` spelling both put a name where the command was expected,
        # which is where a long step keeps its download. A `case` arm pattern
        # (`a) curl ... ;;`) is the same class, and hid the fetch outright.
        if _FUNCTION.match(argv[0]) or is_arm(argv[0]):
            argv.pop(0)
            continue
        if len(argv) > 1 and argv[1] == "()" and _NAME.match(argv[0]):
            del argv[0:2]
            continue
        # The command word, where the reader split it `main`'s way at a bare blank inside its
        # `${…}`, is read whole, as bash expands it before it splits it (#2731): the one place the
        # reader's whole word is read, since it decides the program; every other word -- an
        # assignment, a keyword, an operand -- is `main`'s (#2856 round 8).
        if (whole := getattr(argv[0], "whole", None)) is not None:
            span = getattr(argv[0], "span", 1)
            if vanishing := _VANISHING.fullmatch(whole):
                # Bash may expand it to nothing, the literal glued after the `}` or none, and run the
                # next word (`${X:+/usr/bin/env true} sh`, `${X#env true}sh -c`), or, its name set, an
                # alternate's W (`X=1; ${X:+sh -c} '…'`) -- for `-` and `=`, its name unset, the
                # default. Both halves are read, and the guard REPORTs where either runs (#2856 round
                # 13: the round-12 ruling, round 6's rule, and the round-13 ruling's union -- no half
                # ranked): W, as `main` reads it, and where `folds` reads the job again, the word
                # expanded to nothing; two the guard may each report where the other is not -- two
                # commands among a shell's kind, a fetcher and a word it does not follow, but for that
                # word in front of a shell's kind -- are a command it cannot read (`_runs`). A
                # pattern's or a case change's other half is the name's own value, which no half
                # names (#2899).
                # The guard asks a stage's command many times: its halves are read once for its words.
                halves = getattr(argv[0], "halves", {})
                if (rest := tuple(map(str, argv[span:]))) not in halves:
                    empty = ([spelled(vanishing[3], whole)] if vanishing[3] else []) + argv[span:]
                    alternate = _alternate(argv, whole, span) if vanishing[2][-1:] in "+-=" else None
                    # `$-` and `$0` are never unset: `${0+W}` is always its W, and `${--W}` never is.
                    if vanishing[1] in ("-", "0") and vanishing[2] in ("+", "-", "="):
                        empty, alternate = (None, alternate) if vanishing[2] == "+" else (empty, None)
                    apart, differs = None, False
                    if empty is not None and alternate is not None:
                        (ran, read), (ran_empty, read_empty) = _runs(alternate), _runs(empty)
                        differs = (ran, read) != (ran_empty, read_empty)
                        if read != read_empty and 2 <= min(ran, ran_empty) and max(ran, ran_empty) < 5 and {
                                ran, ran_empty} != {2, 4}:
                            apart = "`%s` runs `%s`, or `%s` where it expands to nothing" % (
                                readable(whole), readable(read[0]), readable(read_empty[0]))
                    argv[0].halves = halves = {**halves, rest: (empty, alternate, apart, differs)}
                empty, alternate, apart, differs = halves[rest]
                vanished = apart or vanished
                # Both halves: read W, then empty where the fold reads all, or this place (`_half`).
                read_empty, past = (_half(whole, differs) if empty is not None and alternate is not None
                                    else (alternate is None, None))
                vanished = vanished or past
                if empty is not None and read_empty:
                    argv = list(empty)
                    continue                    # the next word, read from the top; the W below
                argv = list(alternate)
            else:
                argv = _alternate(argv, whole, span)
        dropped = _optional(argv) if optional and not heads else 0
        if dropped:
            del argv[:dropped]                  # bash drops them, or they hand on (#2472)
            continue
        if words := None if heads else _shell_default(argv[0]):
            argv[0:1] = [Defaulted(words[0]), *words[1:]]   # the NAME, marked as unwritten
        head = os.path.basename(argv[0])
        if heads and dynamic(argv[0], has_substitution):
            return argv, "has a dynamic command operand behind a wrapper", heads
        if isinstance(argv[0], Rewritten):
            return argv, "`%s` is a pattern bash expands before anything runs" % readable(
                argv[0]), heads
        if head not in WRAPPERS:
            break
        heads.append(argv[0])
        if len(heads) > 16:
            return argv, "has too many nested wrappers", heads
        inner, reason = unwrap(argv, head, has_substitution)
        if reason:
            return argv, "`%s` %s" % (head, reason), heads
        behind = (head, argv) if appended else None
        appended = appended or head == "xargs"
        argv = inner
    reason = None
    if behind and not argv:
        # It runs nothing as written, but the appended words may be its
        # command (`xargs ionice`, `xargs flock FILE`, `xargs env FOO=1`) or
        # the last word it reads a pid from (`xargs taskset -p ...`).
        head, argv = behind
        reason = "`%s` has no command as written, and xargs appends words to it" % head
    if reason is None and argv and os.path.basename(argv[0]) in _SHELLS:
        word = next((w for w in shell_words(argv) if getattr(w, "lead", False)), None)
        if word is not None:
            reason = "`%s` is a pattern bash expands where `%s` looks for `-c` or a script" % (
                readable(word), os.path.basename(argv[0]))
    return argv, reason or vanished, heads


def command(argv):
    """`argv` with supported wrappers stripped; unresolved forms stay lists."""
    return _command_result(argv)[0]


def _half(whole, differs):
    """Whether this fold reads empty a command word bash may expand to nothing that has both halves,
    and why the guard cannot read it where its halves read apart and it is one past the `_HALF_CAP`
    such words a job holds (#2929): outside `folds` never, as `main` reads it; in them, where the
    fold reads all, or, its halves apart, its place -- where its parse stands and its order there
    (`shell_tokens._Parse.whole`), the same in every parse of that place and never its text."""
    if not _HALVES["on"]:
        return False, None
    _HALVES["both"], words, past = True, _HALVES["words"], None
    if differs and whole.at not in words and len(words) >= _HALF_CAP:
        past = "`%s` is a command word bash may expand to nothing beside %d more, whose readings the guard does not combine" % (
            readable(whole), _HALF_CAP)
    elif differs:
        words.setdefault(whole.at)
    return _HALVES["empty"] is _ALL or differs and whole.at in _HALVES["empty"], past


def _masks():
    """The sets of command words bash may expand to nothing a fold reads empty, in order: none, all
    where one has both halves, then each other set of those whose halves read apart -- of the first
    `_HALF_CAP` alone, so the folds never grow past 8 (#2929)."""
    words = list(_HALVES["words"])[:_HALF_CAP]
    some = [frozenset(word for at, word in enumerate(words) if bits >> at & 1) for bits in range(1, (1 << len(words)) - 1)]
    return [frozenset()] + ([_ALL] + some if _HALVES["both"] else [])


def folds(unsure):
    """The folds `workflow_guard.job_defects` reads a job in, each its `sure`: one, and a second that
    leaves every `Unsure` statement out where `unsure()` then finds one -- every command word bash
    may expand to nothing read as its W, as `main` reads it; then, for each set of those whose halves
    read apart, the first `_HALF_CAP` a job holds, those folds again with that set read empty, so the
    guard REPORTs where any reading of them runs (#2856 round 13, the round-13 ruling: the union, no
    half ranked; every reading, #2929). Each reads every `find`'s first action where the guard asks
    how a stage uses a file, then, while one held another, its next (`find_action`), so the guard
    REPORTs where any action uses it (#2918)."""
    _HALVES.update(empty=frozenset(), words={}, both=False, on=True)
    read: set = set()
    try:
        while masks := [mask for mask in _masks() if mask not in read]:
            _HALVES["empty"] = masks[0]
            read.add(masks[0])
            for at in itertools.count():
                _ACTIONS.update(at=at, more=False)
                yield False
                if unsure():
                    yield True
                if not _ACTIONS["more"]:
                    break
    finally:
        _HALVES.update(empty=frozenset(), words={}, both=False, on=False)
        _ACTIONS.update(at=0, more=False)


# The checksum tools a check is credited with (`workflow_checks.CHECKSUM_TOOLS`, pinned equal by test).
_CHECKERS = ("sha256sum", "sha512sum", "sha384sum", "shasum")
# The unpackers the guard reads as running what they unpack (`workflow_uses.UNPACKERS`, pinned equal).
_UNPACKERS = ("tar", "unzip", "install", "gunzip", "bsdtar")


def credited_zero(argv, reads, writes, zero, held):
    """A stage's reads and writes, where each `reads[at]`, `at` in `zero`, is a file `0<>` opened on
    standard input, and `held` the one fd 0 still holds when the command runs (#2657): a checksum
    tool (`_CHECKERS`) reads that one alone, and only where it names no list but its standard input
    (`-`, `/dev/stdin`, `/dev/fd/0`; a word of digits after `-a` is an option's, `shasum -a 256`). Each other
    is a write, as `main` reads `0<>`, so no check is credited with a file it does not read (`-c
    0<> sums < self`, `-c self 0<> sums`; #2856 round 12, the round-11 B5). Any other command keeps
    the files it was given: a shell reads its program there (#2657)."""
    tool = command(argv) if zero else []
    if not tool or os.path.basename(tool[0]) not in _CHECKERS:
        return reads, writes
    # A word of digits is an option's only right after `-a` / `--algorithm` (`shasum -a 256`), and
    # past `--` every word is an operand, so a list is named there (#2856 round 13, the round-12 B5:
    # the seat's `digitfix`); `dropped` is a set, so the reads are filtered in one pass (B6).
    stdin = "--" not in tool[1:] and all(
        word in ("/dev/stdin", "/dev/fd/0") or word.isdigit() and previous in ("-a", "--algorithm")
        for previous, word in zip(tool, tool[1:]) if not word.startswith("-"))
    dropped = {at for at in zero if at != held or not stdin}
    return [read for at, read in enumerate(reads) if at not in dropped], writes + [reads[at] for at in sorted(dropped)]


def command_as_written(argv):
    """`command(argv)` with a leading `$` word kept as the command (#2472), for
    the reader that resolves such a word through the step's own table."""
    return _command_result(argv, optional=False)[0]


# The tests after which `find` runs a command of its own on what it walks, each read (`_actions`;
# #2881 round 4, every one #2918) -- `workflow_operands.described` reads them here.
_FIND_EXEC = ("-exec", "-execdir", "-ok", "-okdir")
# The distinct actions of one `find` the guard reads; one with more reads as a command it cannot
# read (`_unread`), so neither the scan nor the folds grow with the words (#2918).
_FIND_CAP = 8
# The action of each `find` a fold reads where the guard asks how a stage uses a file
# (`find_action`), and whether one held another: `folds` reads each of them (#2918).
_ACTIONS = {"at": 0, "more": False}


def _actions(argv):
    """The distinct commands a `find` may run, `argv` its command, at most one more than `_FIND_CAP`
    (#2918): the words after each of `_FIND_EXEC` it holds -- in any order, past any test or
    operator, and where a test's operand spells one too (`-name -exec`), so a word read as one
    fails closed -- to its `;`, or to a `+` right after `{}` (`-exec true {} + -exec sh …`)."""
    found: dict[tuple, None] = {}
    if not argv or os.path.basename(argv[0]) != "find":
        return []
    for at, word in enumerate(argv):
        if at and word in _FIND_EXEC and len(found) <= _FIND_CAP:
            end = next((end for end in range(at + 1, len(argv)) if argv[end] == ";" or (
                argv[end] == "+" and end > at + 1 and argv[end - 1] == "{}")), len(argv))
            found.setdefault(tuple(argv[at + 1:end]))
    return [list(words) for words in found]


def _reader(argv):
    """Whether a command reads what a descriptor holds open (#2881): an interpreter -- not a check,
    credited by its basename (round 5) -- or a command word the step's values decide (`$SH`, not
    `$X/sha256sum`)."""
    name = os.path.basename(argv[0])
    return name not in _CHECKERS and (dynamic(argv[0], has_substitution) or name in (
        *_SHELLS, *_INTERPRETERS, "eval", "source", "."))


def reads_held(argv):
    """Whether the command a stage runs reads what a descriptor holds open (`_reader`) -- where that
    is a `find`, whether any command its actions run does, its wrappers stripped (round 4: the
    first alone, `find /dev/null -exec sh /dev/fd/3 \\;`; every one, #2918)."""
    argv = command(argv)
    return any(_reader(inner) for inner in ([command(words) for words in _actions(argv)] or [argv]) if inner)


def find_action(argv):
    """The command an action of a `find` runs, `argv` its command, as `use()` reads it through
    `workflow_operands.described` -- its wrappers stripped -- or None: in each fold
    the next, so every one is read where the guard asks how the stage uses a file (`folds`, #2918);
    past `_FIND_CAP` the first alone, the `find` read as a command the guard cannot read (`_unread`)."""
    actions = _actions(argv)
    if not actions:
        return None
    if len(actions) <= _FIND_CAP:
        _ACTIONS["more"] = _ACTIONS["more"] or len(actions) > _ACTIONS["at"] + 1
    return command(actions[min(_ACTIONS["at"], len(actions) - 1)])


def _unread(argv):
    """Why a command a `find` runs cannot be read, `argv` its command, or None (#2918): more actions
    than `_FIND_CAP`, a reason its wrappers give (`-exec sudo $X …`), or a command word bash or
    `find` decides, as behind a wrapper -- a `$` word, a substitution, or `{}`, each path it walks
    (`find /usr/bin/sh -exec {} …`)."""
    actions = _actions(argv)
    if len(actions) > _FIND_CAP:
        return "`find` holds more than %d actions" % _FIND_CAP
    for inner, why, _heads in map(_command_result, actions):
        if why:
            return "a command `find` runs: %s" % why
        if inner and (dynamic(inner[0], has_substitution) or "{}" in inner[0]):
            return "`find` runs `%s`, a command word it or bash decides as it runs" % readable(inner[0])
    return None


def unresolved_wrapper(argv):
    """Why a wrapper at this command's head -- or, with none, a pattern bash
    expands where the command starts (#2294) -- cannot be resolved, if any;
    or why a command a `find` there runs cannot be (`_unread`, #2918)."""
    argv, reason, _heads = _command_result(argv)
    return reason or _unread(argv)


def wrapper_words(argv):
    """The words read as wrappers in front of the command, as written.

    A wrapper is known by its basename, so `./flock` is read as `flock` and
    read through, though what runs is the file at ./flock (#2227).
    """
    return _command_result(argv)[2]


def negated(argv):
    """True if this command runs under a `!` -- its own, or a `! { ... }` group's, which the
    reader marks on the stage's first word (`shell_tokens.bang`; #2664 round 13).

    `if ! sha256sum -c sums; then ...; fi` takes the THEN branch when the
    command FAILED, which inverts what its exit status means to everything
    reading it. Same family as `command()`: what stands in front of the
    command, rather than the command itself.
    """
    if argv and getattr(argv[0], "negated", False):
        return True
    for token in _heads(argv):
        if token == "!":
            return True
    return False


def _heads(argv):
    """The words that stand in front of the command, in order, stopping at the command: the
    keywords, the assignments, and a function header (`g()`, `function g`) -- whose body's
    first statement on the header's line runs under what stands before it (`g() { ! { CHECK`,
    PR #2855's fix round), as `command()` reads past the header too."""
    previous = None
    for token in argv:
        if token in KEYWORDS or _ASSIGNMENT.match(token) or _FUNCTION.match(token) or (
                previous == "function" and _NAME.match(token)):
            previous = token
            yield token
            continue
        return


def conditional(argv):
    """True if this command is an `if`/`while` TEST rather than a step.

    `if sha256sum -c sums; then ...; fi` runs the check for its answer, not
    for its effect: errexit does not apply to a condition, so the script sails
    on past a mismatch exactly as `... || true` does.
    """
    for token in _heads(argv):
        if token in CONDITIONS:
            return True
    return False
