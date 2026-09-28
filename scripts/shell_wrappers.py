#!/usr/bin/env python3
"""What stands in front of a command without being it: `sudo`, `env FOO=1`,
`timeout 300` -- the closed table of those words, and the option grammar each
one is read with.

Split out of `scripts/shell_reader.py` (#2227) so the table can grow without
the reader doing so. The reader's `command()` walks what stands in front of a
command -- assignments, keywords, function headers, case arms and these words
-- and hands each wrapper here. A word not in `WRAPPERS` is the command
itself. A word in it is read by its own grammar, never searched for something
that looks like a command: `sudo --user=curl ordinary sh` runs `ordinary`.
What a grammar cannot settle leaves the wrapper UNRESOLVED, with the reason
`unwrap` returns, and `scripts/workflow_guard.py` reports that step rather
than reading past it -- an option the table does not know (it may take a
value, and then the command starts a word later than any guess), and an
option or option value the shell expands (`$`, a substitution), which may be
any number of words once it has.

The getopt-shaped wrappers share one reading of their options: short flags,
short options taking a value, long flags, long options taking one. The five
from util-linux (`setsid`, `ionice`, `taskset`, `flock`, `chrt`; the table
follows 2.39.3) end their options at the first word that is not one, and
some then have operands of their own before the command (`_operands`): a
mask, a lock file or a priority, which must be static for the command's
place to be known; a pid or a list of ids, which is acted on while nothing
runs; and flock's `-c STRING`, which a shell runs. `unbuffer` is a Tcl
script, not getopt (`_unbuffer`).

Stdlib only. `unwrap(argv, head, has_substitution)` is the entry point.
"""
import re
import signal

# Leading words that are not the command: `sudo`, `env FOO=1`, `timeout 300`.
WRAPPERS = ("sudo", "command", "exec", "nohup", "nice", "stdbuf", "env",
            "time", "timeout", "xargs", "doas", "setsid", "ionice", "taskset",
            "flock", "chrt", "unbuffer")
_DURATION = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")


# Supported wrapper options: short flags, short operands, long flags, long operands.
# Unknown options retain the wrapper: never search arbitrary words for a command.
_WRAPPER_OPTIONS = {
    "sudo": ("AbEHiknPSs", "CDghpRTurt", "askpass background reset-timestamp preserve-env preserve-groups set-home non-interactive stdin shell login",
             "close-from chdir group host prompt chroot command-timeout user role type"),
    "timeout": ("v", "ks", "foreground preserve-status verbose", "kill-after signal"),
    "nice": ("", "n", "", "adjustment"),
    "env": ("iv", "uCPS", "ignore-environment debug default-signal ignore-signal block-signal",
            "unset chdir split-string"),
    "stdbuf": ("", "ioe", "", "input output error"),
    "xargs": ("0prtx", "EILPnds", "null no-run-if-empty interactive verbose exit",
              "eof replace max-lines max-procs max-args delimiter max-chars"),
    "exec": ("cl", "a", "", ""),
    "command": ("p", "", "", ""),
    "nohup": ("", "", "", ""),
    "time": ("pav", "fo", "portability append verbose", "format output"),
    "doas": ("ns", "u", "", ""),
    # util-linux 2.39.3, whose optstrings all start with `+`: options end at
    # the first word that is not one, and `_operands` reads what follows.
    "setsid": ("cfwhV", "", "ctty fork wait help version", ""),
    "ionice": ("thV", "cnpPu", "ignore help version", "class classdata pid pgid uid"),
    "taskset": ("apchV", "", "all-tasks pid cpu-list help version", ""),
    # `--nonblock` is the spelling flock's usage prints; getopt_long takes it
    # as the one long option it abbreviates, `--nonblocking`.
    "flock": ("sxeunoFhV", "wE", "shared exclusive unlock nonblocking nonblock nb close "
              "no-fork verbose help version", "timeout wait conflict-exit-code"),
    "chrt": ("abdfimoprRvhV", "DPT", "all-tasks batch deadline fifo idle max other pid rr "
             "reset-on-fork verbose help version", "sched-runtime sched-period sched-deadline"),
}
# The wrappers `_operands` reads once their options end.
_UTIL_LINUX = ("setsid", "ionice", "taskset", "flock", "chrt")
# The long options whose short letter `_operands` asks about.
_LETTER = {"help": "h", "version": "V", "pid": "p", "pgid": "P", "uid": "u",
           "max": "m"}
# The pid `taskset -p` and `chrt -p` act on instead of running anything. Both
# read it from the LAST word, and a zero there -- or -1, chrt's own "no pid" --
# runs the command after the mask or priority after all, so only a static
# positive pid is read as running nothing.
_PID = re.compile(r"0*[1-9][0-9]*")


def _env_split(value):
    """A bounded, static subset of GNU env's -S grammar (not shell syntax)."""
    if len(value) > 4096:
        return None
    words: list[str] = []
    word: list[str] = []
    quote, started, i = None, False, 0
    while i < len(value):
        ch = value[i]
        if ch in "'\"" and quote in (None, ch):
            quote = None if quote == ch else ch
            started = True
        elif ch.isspace() and quote is None:
            if started:
                words.append("".join(word))
                if len(words) > 128:
                    return None
                word, started = [], False
        elif ch == "#" and not started:
            break
        elif (ch == "\\" and (quote != "'" or
              (i + 1 < len(value) and value[i + 1] in "\\'"))):
            i += 1
            if i == len(value):
                return None
            escaped = value[i]
            if escaped == "c":
                if quote == '"':
                    return None
                break
            if escaped == "_":
                if quote != '"':
                    if started:
                        words.append("".join(word))
                        word, started = [], False
                    i += 1
                    continue
                escaped = " "
            elif escaped in "fnrtv":
                escaped = {"f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}[escaped]
            elif escaped not in "\"#$'\\":
                return None
            word.append(escaped)
            started = True
        elif ch == "$" and quote != "'":
            return None  # GNU expands ${NAME}; its value is not static here.
        else:
            word.append(ch)
            started = True
        i += 1
    if quote:
        return None
    if started:
        words.append("".join(word))
    return words if len(words) <= 128 else None


def _signal_list(value):
    """Accept only signal names/numbers the host's stdlib can identify."""
    known = {name.removeprefix("SIG") for name in signal.Signals.__members__}
    numbers = {member.value for member in signal.Signals}
    return bool(value) and all(
        part in known or (part.isascii() and part.isdecimal()
                          and len(part) <= 3 and int(part) in numbers)
        for part in value.split(","))


def _operands(head, operands, seen, has_substitution):
    """(command suffix, unresolved reason) where a util-linux wrapper's options
    end: help and version print and exit, and so does `chrt -m`."""
    if seen & {"h", "V"} or (head == "chrt" and "m" in seen):
        return [], None
    if head == "ionice":
        # -p, -P and -u act on running ids, and every operand is another one;
        # with no operand ionice prints its own class, or refuses a class it
        # was given nothing to apply to. None of these runs anything.
        if seen & {"p", "P", "u"} or not operands:
            return [], None
        return operands, None
    if head in ("taskset", "chrt") and "p" in seen:
        if operands and _PID.fullmatch(operands[-1]):
            return [], None
        return None, "has a -p pid that is not a static positive number"
    if head in ("taskset", "flock", "chrt") and operands:
        # The mask, the lock file or the priority decides where the command
        # starts, and an expansion there may be any number of words. Being
        # static and present is all that is asked of it.
        if has_substitution(operands[0]) or "$" in operands[0]:
            return None, "has a dynamic operand before its command"
        operands = operands[1:]
        if head == "flock" and not operands:
            return [], None             # `flock FD` locks a descriptor: nothing runs
        if head == "flock" and operands[0] in ("-c", "--command"):
            # flock refuses anything but exactly one STRING, and runs it as
            # `$SHELL -c STRING` (`/bin/sh` when SHELL is unset or empty): a
            # shell handed its script as a string, read as `sh -c` is.
            if len(operands) != 2:
                return None, "needs exactly one command string after %s" % operands[0]
            return ["sh", "-c", operands[1]], None
    return (operands, None) if operands else (None, "is missing a command")


def _unbuffer(words):
    """(command suffix, unresolved reason) for `unbuffer [-p] program [args]`.

    Not getopt: unbuffer is a Tcl script (expect 5.45.4's example) that asks
    only whether its first word is exactly `-p`, and hands every other word to
    `spawn -noecho`. spawn reads leading `-` words as switches of its own
    (`-ignore SIG`, `-open ID`, ...) before the program, so a `-` word where
    the program belongs is one of those, not the program.
    """
    if words[:1] == ["-p"]:
        words = words[1:]
    if words and words[0].startswith("-"):
        return None, "has a spawn switch before its command"
    return (words, None) if words else (None, "is missing a command")


def unwrap(argv, head, has_substitution):
    """(command suffix, unresolved reason), with no arbitrary operand search.

    `has_substitution` is `shell_reader.has_substitution`: the reader imports
    this module, so it hands over its test for a lifted `$(...)` rather than
    this module importing it back.
    """
    if head == "unbuffer":
        return _unbuffer(argv[1:])
    flags, values, long_flags, long_values = _WRAPPER_OPTIONS[head]
    i = 1
    splits = 0
    noexec = False
    seen: set[str] = set()      # each option read: its letter, or a long name `_LETTER` does not map
    while i < len(argv) and argv[i].startswith("-"):
        argument, i = argv[i], i + 1
        if has_substitution(argument) or "$" in argument:
            return None, "has a dynamic option"
        if argument == "--":
            break
        if head == "sudo" and argument in ("-K", "--remove-timestamp"):
            if len(argv) == 2:
                return [], None  # Timestamp removal has no command mode.
            return None, "combines timestamp removal with a command or option"
        if head == "sudo" and argument == "-h" and len(argv) == 2:
            return [], None  # Standalone -h requests help; -h HOST runs a command.
        if head == "sudo" and argument in ("-l", "--list", "-v", "--validate",
                                           "--help", "-V", "--version"):
            noexec = True  # Explicit sudo query/maintenance modes.
            continue
        if head == "command" and argument in ("-v", "-V"):
            noexec = True  # Shell command lookup, not execution.
            continue
        if head == "nice" and re.fullmatch(r"-\d+", argument):
            continue
        if argument.startswith("--"):
            name, sep, value = argument[2:].partition("=")
            seen.add(_LETTER.get(name, name))
            if head == "env" and name in ("default-signal", "ignore-signal",
                                           "block-signal"):
                if sep and not _signal_list(value):
                    return None, "has an unsupported signal list"
                continue  # Optional argument only in the = form.
            if ((head == "sudo" and name == "preserve-env") or
                    (head == "xargs" and name in ("replace", "eof", "max-lines"))):
                continue  # Optional operands are accepted only after '='.
            if name in long_values.split():
                if head == "env" and name == "split-string":
                    if not sep:
                        return None, "needs --split-string=STRING"
                    split = _env_split(value)
                    if split is None or splits >= 4:
                        return None, "has an unsupported split-string"
                    argv = argv[:i] + split + argv[i:]
                    splits += 1
                    continue
                if i >= len(argv) and not sep:
                    return None, "is missing an option operand"
                if not sep and (has_substitution(argv[i]) or "$" in argv[i]):
                    return None, "has a dynamic option operand"
                i += not sep
            elif name not in long_flags.split() or sep:
                return None, "has an unknown option"
            continue
        if argument == "-":
            if head == "env":
                break  # env's legacy ignore-environment flag ends option parsing
            return None, "has an unknown option"
        for j, ch in enumerate(argument[1:], 2):
            seen.add(ch)
            if ch in values:
                if head == "env" and ch == "S":
                    value = argument[j:] if j < len(argument) else (argv[i] if i < len(argv) else None)
                    if value is None:
                        return None, "is missing a split-string operand"
                    if has_substitution(value):
                        return None, "has a dynamic split-string"
                    split = _env_split(value)
                    if split is None or splits >= 4:
                        return None, "has an unsupported split-string"
                    if j == len(argument):
                        i += 1
                    argv = argv[:i] + split + argv[i:]
                    splits += 1
                    break
                if j == len(argument) and i >= len(argv):
                    return None, "is missing an option operand"
                if j == len(argument) and (has_substitution(argv[i]) or "$" in argv[i]):
                    return None, "has a dynamic option operand"
                i += j == len(argument)
                break
            if ch not in flags:
                return None, "has an unknown option"
    if head in _UTIL_LINUX:
        return _operands(head, argv[i:], seen, has_substitution)
    if head == "timeout":
        if i >= len(argv) or not _DURATION.fullmatch(argv[i]):
            return None, "has no supported duration"
        i += 1
    if noexec:
        return [], None
    if not argv[i:]:
        if head == "env":
            return [], None  # env without a command prints its environment.
        return None, "is missing a command"
    return argv[i:], None
