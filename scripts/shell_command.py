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
from shell_tokens import has_substitution, is_arm, readable
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


def assigns(word, environment=False):
    """Whether bash reads `word` as an assignment in front of a command (#2348), or, behind a
    wrapper, as one `env` takes (`environment`): the spelling matches and nothing before its
    operator was quoted or escaped (`shell_reader._stage`'s `quoted`, #2480) -- `"X=1" sh tool`
    and `A\\+=x sh tool` run a command named `X=1` / `A+=x`, and `"X"=1` one named `X=1`."""
    return bool((_ENVIRONMENT if environment else _ASSIGNMENT).match(word)) and not getattr(
        word, "quoted", False)


def disables(word):
    """Whether this assignment in front of a shell starts it so that it runs nothing of its
    program (#2648): `SHELLOPTS=noexec` -- bash takes the variable from its environment and
    turns `noexec` on before it reads a line. The check the program holds then never runs,
    so `_command_result` refuses the command rather than credit it."""
    name, _, value = word.partition("=")
    return name == "SHELLOPTS" and "noexec" in value.split(":")

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_FUNCTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*\(\)$")

# The shells whose options and program word a pattern may rewrite into a `-c`
# and its script (`sh {-c,'…'}`, review N-3): `workflow_programs._SHELL_STRING`.
_SHELLS = ("sh", "bash", "dash", "ash", "ksh", "zsh")
# A command word that is a parameter's default or alternate (#2337): `${X:-sh}`,
# `"${X-bash}"`, `${X:=sh}`, `${X:+sh}`. Where it spells a shell it is read as
# that shell, which bash runs wherever `X` leaves the word to it.
_DEFAULTS = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=+]([^{}$`'\"\\]+)\}")
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
# The names bash and dash have only as BUILTINS, no file of their name on any PATH: a wrapper
# that execs its command (`env`, `sudo`, `nice`, `nohup`, `exec`, `setsid`, `timeout`, `xargs` and
# the rest of `WRAPPERS` bar `command`) finds none and runs nothing, rc 127 (#2670). `time` stays
# read through: the keyword at a pipeline's head runs the builtin, and this walk cannot tell the
# external `time` of a later stage from it (fail-closed: `echo x | time eval …` over-reports).
_BUILTIN_ONLY = ("eval", "source", ".", "set", "export", "readonly", "declare", "typeset", "local",
                 "unset", "shift", "exit", "return", "break", "continue", "cd", "trap", "wait",
                 "alias", "unalias", "shopt", "exec", "builtin", "command")
_EXECS = tuple(w for w in WRAPPERS if w not in ("command", "time"))
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
        if assigns(argv[0], environment=bool(heads)):
            if disables(argv[0]):
                return argv, "is started under `%s`, which runs nothing of what it reads" % argv[0], heads
            argv.pop(0)
            continue
        if argv[0] in KEYWORDS:
            keyword = argv.pop(0)
            if keyword == "function" and argv and _NAME.match(argv[0]):
                argv.pop(0)                     # `function f { ... }`
            continue
        if argv[0] == "builtin" and len(argv) > 1 and not heads and _NAME.match(argv[1]):
            argv.pop(0)                         # `builtin eval …` runs the builtin (#2665), as `command` does
            continue
        if (argv[0] == "jobs" and len(argv) > 2 and not heads and argv[1][:1] == "-"
                and argv[1][1:].isalpha() and "x" in argv[1]):
            del argv[:2]                        # `jobs -x WORDS` runs WORDS in the step's shell (#2836)
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
        dropped = _optional(argv) if optional and not heads else 0
        if dropped:
            del argv[:dropped]                  # bash drops them, or they hand on (#2472)
            continue
        default = None if heads or getattr(argv[0], "kept", False) else _DEFAULTS.fullmatch(argv[0])
        if default and default[1].split() and os.path.basename(default[1].split()[0]) in _SHELLS:
            name, *rest = default[1].split()    # bash splits an unquoted default (#2731)
            argv[0:1] = [Defaulted(name), *rest]    # the NAME, marked as unwritten
        head = os.path.basename(argv[0])
        if heads and dynamic(argv[0], has_substitution):
            return argv, "has a dynamic command operand behind a wrapper", heads
        if isinstance(argv[0], Rewritten):
            return argv, "`%s` is a pattern bash expands before anything runs" % readable(
                argv[0]), heads
        if head not in WRAPPERS:
            break
        if head == "env" and any(disables(w) for w in argv[1:] if assigns(w, environment=True)):
            return argv, "starts its command under `SHELLOPTS=noexec`, which runs nothing of what it reads", heads
        heads.append(argv[0])
        if len(heads) > 16:
            return argv, "has too many nested wrappers", heads
        inner, reason = unwrap(argv, head, has_substitution)
        if reason:
            return argv, "`%s` %s" % (head, reason), heads
        if head in _EXECS and inner and os.path.basename(inner[0]) in _BUILTIN_ONLY:
            heads.pop()                         # `env eval …`: not found, nothing runs (#2670)
            break
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
    for token in argv:
        if token == "!":
            return True
        if token in KEYWORDS or assigns(token):
            continue
        return False
    return False


def conditional(argv):
    """True if this command is an `if`/`while` TEST rather than a step.

    `if sha256sum -c sums; then ...; fi` runs the check for its answer, not
    for its effect: errexit does not apply to a condition, so the script sails
    on past a mismatch exactly as `... || true` does.
    """
    for token in argv:
        if token in CONDITIONS:
            return True
        if token in KEYWORDS or assigns(token):
            continue
        return False
    return False
