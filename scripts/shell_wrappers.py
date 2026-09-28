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

Stdlib only. `unwrap(argv, head, has_substitution)` is the entry point.
"""
import re
import signal

# Leading words that are not the command: `sudo`, `env FOO=1`, `timeout 300`.
WRAPPERS = ("sudo", "command", "exec", "nohup", "nice", "stdbuf", "env",
            "time", "timeout", "xargs", "doas")
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
}


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


def unwrap(argv, head, has_substitution):
    """(command suffix, unresolved reason), with no arbitrary operand search.

    `has_substitution` is `shell_reader.has_substitution`: the reader imports
    this module, so it hands over its test for a lifted `$(...)` rather than
    this module importing it back.
    """
    flags, values, long_flags, long_values = _WRAPPER_OPTIONS[head]
    i = 1
    splits = 0
    noexec = False
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
