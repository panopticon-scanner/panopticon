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
from shell_tokens import derived, has_substitution, is_arm, readable
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
    a literal glued after the `}` joining its last word, split where bash splits it -- at a space, a
    tab or a newline, never a Unicode or vertical space (#2856 round 11, F2) -- each word a token
    keeping the reader's marks of what it holds (`derived`), so a lifted `$(…)` stays dynamic behind
    a wrapper and a `<(…)` a file. None where `_WHOLE_DEFAULTS` does not read the word: a `$NAME` or
    a nested default in it, a parameter that is no NAME, a substitution glued after the `}`."""
    default = _WHOLE_DEFAULTS.fullmatch(whole)
    if not default or has_substitution(derived(default[2], whole)):
        return None
    return [derived(part, whole) for part in re.split(r"[ \t\n]+", (default[1] + default[2]).strip(" \t\n"))]


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
            span, words = getattr(argv[0], "span", 1), _default_words(whole)
            if words and os.path.basename(words[0]) in OPTIONAL_NEXT:
                # A default naming a command the reader knows -- a shell, a wrapper, a foreign
                # interpreter, a fetcher, by path too -- is that command, its words the reader's own
                # (`${X:-bash -s}`, `${X:-/usr/bin/env sh -c}`, `${X:-/usr/bin/curl -fsSL} URL`).
                argv[0:span] = [Defaulted(words[0]), *words[1:]]
            elif words or os.path.basename(argv[0]) not in OPTIONAL_NEXT:
                argv[0:span] = [whole]          # a name the guard does not follow, read whole
            # Else `main`'s split words stay: past `_WHOLE_DEFAULTS` (`${X:-$HOME/bin/env sh -c}`,
            # `${1:-/bin/sh -c}`), their first names a known command by its basename (#2856 round 11).
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
