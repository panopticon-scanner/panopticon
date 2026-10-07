#!/usr/bin/env python3
"""What stands in FRONT of a shell command, and the command behind it.

Split out of `scripts/shell_reader.py` at that module's size (699 of its 700
lines), byte for byte: the keywords, assignment and function-header spellings
a statement may open with, the shells and the default or optional `$` words
that may stand for one (#2337, #2472), and the one walk that strips them all
(`_command_result`) to answer `command`, `command_as_written`,
`unresolved_wrapper`, `wrapper_words`, `negated` and `conditional`. The reader
imports every name back under its own, so nothing that read
`shell_reader.command` or `shell_reader.KEYWORDS` moved; this module imports
nothing from the reader, so the layers still run one way.

Stdlib only, like everything under it.
"""
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
# A command word bash expands to nothing where its name is unset (#2856 round 12, the round-11 B2): an
# alternate (`${X:+W}`, `${X+W}`), or a pattern taken off or replaced (`${X#W}`, `${X%%W}`, `${X/p/W}`),
# whose W is a pattern and never the command. Unset, it is the literal glued after its `}`, or nothing.
_VANISHING = re.compile(r"\$\{([A-Za-z_]\w*|[0-9]+|[@*])(:?\+|##?|%%?|//?)[^{}]*\}([^\s{}$`'\"\\*?[]*)")
# Where a step may set a name (`_sets`): an assignment word, its own, a prefix's or a declaration's
# (`X=1`, `export X=1`, `a[0]=x`; empty where its value stops at once, `X=` or `X=""`), `${X:=…}`,
# and a name a builtin that sets one, or arithmetic, spells (`read X`, `for X in`, `(( X++ ))`).
_SET_WORD = re.compile(r"(?:^|(?<=[\s;&|(`{]))([A-Za-z_]\w*)(?:\[[^\]\n]*\])?\+?=(?:\"\"|'')?([\s;&|)]|$)?", re.M)
_SETTING = re.compile(r"\$\{([A-Za-z_]\w*):?=|(?:^|(?<=[\s;&|(`{]))(?:read|export|declare|typeset|local|readonly"
                      r"|for|select|getopts|mapfile|readarray|printf|let)\s([^;&|\n]*)|\(\(([^()]*)\)\)", re.M)
_SPELLED = re.compile(r"(?<![\w$-])[A-Za-z_]\w*")
# A `set` that sets the positional parameters (`set -- 1`), past its options.
_SET_POSITIONAL = re.compile(r"(?:^|(?<=[\s;&|(`{]))set\s+(?:[-+]\w*\s+)*--\s+[^\s;&|]", re.M)
# A default's parameter and operator (`_strips`): `#`, `?`, `$`, `-` and `0` are never unset or empty.
_PARAMETER = re.compile(r"\$\{([#?$!@*-]|[0-9]+|[A-Za-z_]\w*(?:\[[^]]*\])?)(:?[-=+])")
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


def _sets(whole, name, colon):
    """Whether the step `whole` was read from may set `name` -- with `colon`, to a value not empty
    (`${X:+W}` asks that, `${X+W}` only whether it is set) -- as `_SET_WORD` and `_SETTING` find
    it, once a step; `$0` always, and the positional parameters where a `set --` sets them. A name
    only `eval`, `.`, the environment or a caller sets, and a function's arguments, read as unset
    (#2856 round 12, the round-11 B2's set half)."""
    context = getattr(whole, "step", None)
    if context is None or name == "0":
        return context is not None
    if getattr(context, "sets", None) is None:
        named, valued = set(), set()
        for match in _SET_WORD.finditer(context.source):
            named.add(match[1])
            if match[2] is None:
                valued.add(match[1])
        for match in _SETTING.finditer(context.source):
            spelled_here = match[2] if match[2] is not None else match[3] or ""
            names = {match[1]} if match[1] else set(_SPELLED.findall(spelled_here))
            named |= names
            valued |= names
        if _SET_POSITIONAL.search(context.source):
            named.add("@")              # every positional parameter, as `set --` may set each
        context.sets = (named, valued | (named & {"@"}))
    if not (name[0].isalpha() or name[0] == "_"):
        name = "@"
    return name in context.sets[1 if colon else 0]


def _strips(whole):
    """Whether `main`'s split words of a command word read whole (`_command_result`) end in the
    default's `}`, which comes off them: a default (`-`, `=`) or alternate (`+`) bash may expand --
    not where the parameter is never unset or empty (`${#:-…}`, `${?:-…}`), nor an assignment to a
    parameter that is no NAME (`${1:=…}`, an error that runs nothing; #2856 round 12, B1)."""
    found = _PARAMETER.match(whole)
    if not found:
        return False
    parameter, operator = found[1], found[2]
    if operator.endswith("=") and not (parameter[0].isalpha() or parameter[0] == "_"):
        return False
    return not (parameter in ("#", "?", "$", "-", "0") and operator in ("-", ":-"))


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
    appended, behind = False, None
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
            vanishing = _VANISHING.fullmatch(whole)
            if vanishing and not (vanishing[2].endswith("+") and _sets(whole, vanishing[1], vanishing[2] == ":+")):
                # Its name unset, bash expands it to nothing and runs the next word, or the literal
                # glued after the `}` (`${X:+/usr/bin/env true} sh`, `${X#env true}sh -c`); a step
                # that sets the name runs the alternate, read below (#2856 round 12, B2).
                argv[0:span] = [spelled(vanishing[3], whole)] if vanishing[3] else []
                continue
            words = _default_words(whole)
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
    return argv, reason, heads


def command(argv):
    """`argv` with supported wrappers stripped; unresolved forms stay lists."""
    return _command_result(argv)[0]


# The checksum tools a check is credited with (`workflow_checks.CHECKSUM_TOOLS`, pinned equal by test).
_CHECKERS = ("sha256sum", "sha512sum", "sha384sum", "shasum")


def credited_zero(argv, reads, writes, zero, held):
    """A stage's reads and writes, where each `reads[at]`, `at` in `zero`, is a file `0<>` opened on
    standard input, and `held` the one fd 0 still holds when the command runs (#2657): a checksum
    tool (`_CHECKERS`) reads that one alone, and only where it names no list but its standard input
    (`-`, `/dev/stdin`, `/dev/fd/0`; a word of digits is an option's, `shasum -a 256`). Each other
    is a write, as `main` reads `0<>`, so no check is credited with a file it does not read (`-c
    0<> sums < self`, `-c self 0<> sums`; #2856 round 12, the round-11 B5). Any other command keeps
    the files it was given: a shell reads its program there (#2657)."""
    tool = command(argv) if zero else []
    if not tool or os.path.basename(tool[0]) not in _CHECKERS:
        return reads, writes
    stdin = all(word in ("/dev/stdin", "/dev/fd/0") or word.isdigit() for word in tool[1:] if not word.startswith("-"))
    dropped = [at for at in zero if at != held or not stdin]
    return [read for at, read in enumerate(reads) if at not in dropped], writes + [reads[at] for at in dropped]


def command_as_written(argv):
    """`command(argv)` with a leading `$` word kept as the command (#2472), for
    the reader that resolves such a word through the step's own table."""
    return _command_result(argv, optional=False)[0]


def unresolved_wrapper(argv):
    """Why a wrapper at this command's head -- or, with none, a pattern bash
    expands where the command starts (#2294) -- cannot be resolved, if any."""
    return _command_result(argv)[1]


def wrapper_words(argv):
    """The words read as wrappers in front of the command, as written.

    A wrapper is known by its basename, so `./flock` is read as `flock` and
    read through, though what runs is the file at ./flock (#2227).
    """
    return _command_result(argv)[2]


def negated(argv):
    """True if this command runs under a `!`.

    `if ! sha256sum -c sums; then ...; fi` takes the THEN branch when the
    command FAILED, which inverts what its exit status means to everything
    reading it. Same family as `command()`: what stands in front of the
    command, rather than the command itself.
    """
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
