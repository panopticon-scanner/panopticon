#!/usr/bin/env python3
"""The `$` command words bash may expand into something else, or into nothing.

Split out of `scripts/shell_command.py` at that module's size (633 of its 700
lines, with #2919 to fold onto it; #2993), byte for byte: the shells and the
other names such a word may stand in front of, the default and alternate
spellings (#2337, #2731), the optional wrapper spelled by variable (#2472),
the word that may vanish and the halves the folds read of it (#2856, #2929),
and the readers of one word -- `_optional`, `_shell_default`,
`_default_words`, `_strips`, `_alternate`, `_half` and `_masks`.
`shell_command` imports every name back under its own, so nothing that read
`shell_command._OPTIONAL` or `shell_reader.OPTIONAL_NEXT` moved; this module
imports nothing from it or from the reader, so the layers still run one way.

Stdlib only, like everything under it.
"""
import contextvars
import os
import re

from shell_tokens import derived, has_substitution, readable, spelled
from shell_wrappers import WRAPPERS, Defaulted, Rewritten, dynamic, set_to, unwrap


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
# those whose halves read apart, by place (`_half`, #2929) -- and whether one with both halves was met,
# in one of `main`'s folds ("both") or only in the folds that read the second walk's newer words as nothing
# ("both_dropped", `_drops`).
_HALVES: dict = {"empty": frozenset(), "words": {}, "both": False, "on": False, "drops": False, "both_dropped": False}
_ALL = frozenset({None})
# In a fold's set (`_masks`), the mark of the folds that read the second walk's newer words as nothing (`_drops`):
# each of the others once more, where one of them met such a word ("drops").
_DROPPED = "dropped"
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
_FETCHERS = ("curl", "wget", "aria2c", "axel", "fetch", "http", "https", "gh", "git",
             "pip", "pip3")
OPTIONAL_NEXT = (*_SHELLS, *WRAPPERS, *_INTERPRETERS, *_FETCHERS)
# The second walk's own, beside `_OPTIONAL` (#3002, #3007, and the limits #2997's fix named): the other words that
# are nothing with their name unset. A positional parameter, `$@`, `$!` with no background job; an element or all of
# an array, an indirection; a pattern taken off or replaced, a case change, a substring, an `@` transformation; an
# alternate, whatever it holds; a default that is only blanks, or only one more name that may be unset. None holds a
# blank but that default and a substring counted from the end (`${S: -1}`): a word the reader kept whole for its two
# halves is `_command_result`'s to read. `$0` is the script's name, and `$*` a pattern `main` reports. Two that no
# shell makes nothing of are left out: a default that would assign to a positional parameter, `$@` or `$*`
# (`${1:=}`: bash and dash both refuse it), and a case change or a transformation of an indirection (`${!S^^}`,
# `${!S@Q}`: bash 5.2.21 refuses the unset name, and 3.2.57 has neither).
_NOTHING = re.compile(
    r"\$(?:[1-9@!]|\{(?![0-9@*]+:?=|![A-Za-z_]\w*[\^,@])(?:!?(?:[A-Za-z_]\w*(?:\[[^]{}\s]*\])?|[1-9][0-9]*)|[@*])"
    r"(?:(?:##?|%%?|//?|\^\^?|,,?|:[0-9]|@[A-Za-z]|:?\+)[^{}\s]*|:[ \t]+-?[0-9][^{}\s]*"
    r"|:?[-=](?:[ \t\n]*|\$[A-Za-z_]\w*|\$\{[A-Za-z_]\w*(?::?[-=])?\}))?\})")
# A word that stood whole in double quotes (`double`, `shell_reader._stage`) and that bash makes no word of all the
# same: every positional parameter or every element of an array (`"$@"`, `"${a[@]}"`), cut, changed or replaced
# by an alternate, and an array's keys (`"${!a[@]}"`). Not with a default, whose word the quotes keep where there
# is no element (`"${a[@]:-}"`); and not in single quotes, where `$@` is two characters.
_SPLAT = re.compile(r"\$(?:@|\{(?:![A-Za-z_]\w*\[@\]|(?:@|[A-Za-z_]\w*\[@\])"
                    r"(?:(?:##?|%%?|//?|\^\^?|,,?|:[0-9]|@[A-Za-z]|:?\+)[^{}\s]*)?)\})")
# The printers a word that is nothing may stand in front of (#3007): what they write is what a shell behind the
# pipe runs (`workflow_printers`), and a `cat` hands on the file it reads.
PRINTERS_NEXT = ("echo", "printf", "cat")


def _drops():
    """Whether this fold reads as nothing the words the second walk alone drops since #3002 -- and reads on from
    a default that names a wrapper (#3007, #3038): never in the main pass or outside `shell_command.folds`, and in
    the second walk only in the folds `_masks` adds once a fold asked, which this notes. So every fold `main` reads
    is read as it was, and the guard REPORTs where either reading does: a check one of these words stands in front
    of is credited in the folds that drop the word, and never takes a report from the ones that keep it (#3037)."""
    if not WALKED_DEFAULTS.get() or not _HALVES["on"]:
        return False
    _HALVES["drops"] = True
    return _DROPPED in _HALVES["empty"]


def _optional(argv, nothing=False, drops=None):
    """How many leading words of `argv` bash may drop in front of a name the
    reader knows (`_OPTIONAL`, #2472): each unquoted, one reference, with no
    default or one that is itself a wrapper (`${X:-sudo}`); 0 where the word
    after them is not in `OPTIONAL_NEXT`. The second walk (`WALKED_DEFAULTS`)
    knows that word by its one-word default too (#2963), and knows `eval`,
    `.` and `source` behind words that may each be nothing (#2997). It drops
    an alternate that names no command it reads the word as (#3003): with its
    name unset `${S:+echo}` is nothing, as `${S:+sudo}` is. And it knows
    `builtin` and `jobs` as it knows `eval`, in the folds that read them through
    (#2665, #2836); behind `builtin` (`nothing`) it counts the words that may each be
    nothing, whatever follows them, as bash looks up the first word it keeps there.
    In folds of its own (`_drops`) the second walk drops the other words that are nothing with their name unset
    too (`_NOTHING`, and a quoted `"$@"`: `_SPLAT`), and knows a printer behind such words, and a word the reader
    kept whole, which `_command_result` then reads as it reads one that stands first (#3002, #3007); there a
    default naming a wrapper is a word a builtin runs behind where the job's steps set its name so (`_set`,
    #3038). `drops` is whether this count reads so: unsaid, it is the count that does where the two differ and
    the fold is one of those, and the count `main`'s folds read everywhere else."""
    walked = WALKED_DEFAULTS.get()
    if drops is None:
        count = _optional(argv, nothing, False)
        return more if walked and (more := _optional(argv, nothing, True)) != count and _drops() else count
    count, loose = 0, True
    while count < len(argv) - 1:
        word = argv[count]
        match = None if getattr(word, "kept", False) else _OPTIONAL.fullmatch(word)
        if not match and drops and (_SPLAT.fullmatch(word) if getattr(word, "double", False)
                                    else not getattr(word, "kept", False) and _NOTHING.fullmatch(word)):
            count += 1                          # (#3002) nothing with its name unset: a builtin runs behind it too
            continue
        if not match:
            break
        if match[1] and os.path.basename(match[1]) not in WRAPPERS:
            # (#3003) `main` stops at a word that names no wrapper, and for a default it is right: the
            # word stays where its name is unset. An alternate's does not, so the second walk goes on
            # past one -- but for one the reader reads as the command it names (`_shell_default`: a
            # shell, a fetcher, `eval`). `$T ${X:+sh} -c P` runs `sh -c P` where `X` is set, and reads
            # so, as `main` read it. And past a default whose name the job's steps set to `command` or to
            # nothing (`_set`, #3038): the word is that, whatever the default names.
            if not (drops and _set(word, match[1])) and (
                    not walked or word[-len(match[1]) - 2] != "+" or _shell_default(word)):
                break
        # (#2997) A builtin runs behind a word that is NOTHING with its name unset -- a bare reference, an
        # empty default, an alternate (`${S:+sudo}`) -- or that is `command`, by name or by path (macOS has
        # a `/usr/bin/command` that runs one). No wrapper that execs can run a builtin: `sudo eval 'P'` and
        # `env . ./t` run nothing of `P` or of `t`.
        loose = loose and (not match[1] or word[-len(match[1]) - 2] == "+"
                           or os.path.basename(match[1]) == "command" or drops and _set(word, match[1]))
        count += 1
    if nothing:
        return count if loose else 0
    after = _DEFAULTS.fullmatch(argv[count]) if count and walked else None                    # (#2963)
    name = after[1] if after else argv[count]
    if count and loose and walked and (name in ("eval", ".", "source")                        # (#2997)
                                       or name in ("builtin", "jobs") and _through()):       # (#2665, #2836)
        return count
    if count and drops and (getattr(argv[count], "whole", None) is not None                  # (#3002)
                            or os.path.basename(argv[count]) in PRINTERS_NEXT):               # (#3007)
        return count
    if drops and count > 1 and _shell_default(argv[count - 1], argv[count - 1:]):
        return count - 1                        # (#3007) the words in front of a default that reads on as its wrapper

    def named_fetch_subcommand(program, words):
        """Whether a multi-command fetcher reaches the one adapter models.

        `_FETCHERS` mirrors the guard's command vocabulary, but `git push`,
        `gh issue` and `pip list` are not downloads. Keep their bounded root
        options here so an optional word is dropped only where the command
        behind it can reach the adapter; an unknown option still reaches a
        later expected subcommand so that adapter can fail closed.
        """
        commands = {
            "git": ("clone",),
            "gh": ("release", "download"),
            "pip": ("download",),
            "pip3": ("download",),
        }.get(program)
        if commands is None:
            return True
        short_values, long_values, short_flags, long_flags, informational = {
            "git": ("c", {"config", "config-env"}, "", {
                "no-pager", "paginate", "literal-pathspecs", "glob-pathspecs",
                "noglob-pathspecs", "icase-pathspecs", "no-optional-locks",
                "no-replace-objects",
            }, {"-h", "--help", "--version"}),
            "gh": ("R", {"repo", "hostname"}, "", {
                "no-update-notifier", "prompt", "no-prompt",
            }, {"-h", "--help", "--version"}),
            "pip": ("", {
                "proxy", "timeout", "retries", "cert", "client-cert", "cache-dir",
                "log", "python", "keyring-provider", "exists-action", "trusted-host",
                "use-feature", "use-deprecated",
            }, "qv", {
                "quiet", "verbose", "isolated", "require-virtualenv", "no-input",
                "no-proxy-env", "no-cache-dir", "disable-pip-version-check", "no-color",
            }, {"-h", "--help", "-V", "--version"}),
            "pip3": ("", {
                "proxy", "timeout", "retries", "cert", "client-cert", "cache-dir",
                "log", "python", "keyring-provider", "exists-action", "trusted-host",
                "use-feature", "use-deprecated",
            }, "qv", {
                "quiet", "verbose", "isolated", "require-virtualenv", "no-input",
                "no-proxy-env", "no-cache-dir", "disable-pip-version-check", "no-color",
            }, {"-h", "--help", "-V", "--version"}),
        }[program]
        words, expected, at = list(words), 0, 0
        while at < len(words):
            word, at = str(words[at]), at + 1
            if word == commands[expected]:
                expected += 1
                if expected == len(commands):
                    return True
                continue
            if word in informational:
                return False
            if word == "--":
                continue
            if not word.startswith("-") or word == "-":
                return False
            if word.startswith("--"):
                option, separator, inline = word[2:].partition("=")
                if option in long_values:
                    if not separator:
                        if at >= len(words):
                            return False
                        at += 1
                elif option not in long_flags or separator and inline not in ("true", "false"):
                    return commands[expected] in map(str, words[at:])
                continue
            offset = 1
            while offset < len(word):
                option, offset = word[offset], offset + 1
                if option in short_values:
                    if offset == len(word):
                        if at >= len(words):
                            return False
                        at += 1
                    break
                if option not in short_flags:
                    return commands[expected] in map(str, words[at:])
        return False

    head = os.path.basename(name)
    known = head in OPTIONAL_NEXT and named_fetch_subcommand(head, argv[count + 1:])
    return count if count and known else 0


def _set(word, default):
    """Whether a builtin runs behind `word`, a default, by what the job's steps set its name to
    (`shell_wrappers.set_to`, #3038): `command` or `builtin` -- or nothing, where no colon stands in the word and
    bash then makes no word of it (`S=; ${S-sudo} eval 'P'`). An alternate is its own word where its name is set."""
    name = re.match(r"\$\{([A-Za-z_]\w*)", word)
    if not name or word[-len(default) - 2] == "+":
        return False
    return set_to("runs", name[1]) or word[-len(default) - 3] != ":" and set_to("empty", name[1])


# A default of several words that names a wrapper, where the job's steps set its name to `command` or `builtin`
# (#3038): the word is that one there and a builtin runs behind it, so the folds read it as they read a word bash
# may expand to nothing -- its own words, and the words behind it alone. The groups are `_VANISHING`'s.
_SET_DEFAULT = re.compile(r"\$\{([A-Za-z_]\w*)(:?[-=])[^{}]*\}([^\s{}$`'\"\\*?[]*)")


def _vanishing(whole):
    """`_VANISHING`'s reading of a command word the reader kept whole, or -- the second walk's -- `_SET_DEFAULT`'s."""
    found = _VANISHING.fullmatch(whole)
    if not found and WALKED_DEFAULTS.get() and (default := _SET_DEFAULT.fullmatch(whole)) and set_to("runs", default[1]):
        words = _default_words(whole)
        return default if words and os.path.basename(words[0]) in WRAPPERS and _drops() else None
    return found


# Whether a ONE-WORD default is read as the command it names where that is a fetcher or `eval`, as
# `main` reads one that names a shell (#2963): with `X` unset `${X:-curl} URL | sh` fetches as `curl
# URL | sh` does, and `${X:-eval} 'P'` runs `P`. It is the second walk's reading. `workflow_options.
# mains_answer` turns it off while the main pass reads such a word as `main` does, one the guard does
# not follow; so the job REPORTs where either reading does. `_optional` reads it too: a `$` word in
# front of such a default is one bash may drop (`$SUDO ${X:-curl} URL | sh`). The same flag turns on
# `_optional`'s reading of `eval`, `.` and `source` behind such a word (#2997), and its dropping of
# an alternate that names no wrapper (#3003).
WALKED_DEFAULTS: contextvars.ContextVar[bool] = contextvars.ContextVar("walked_defaults", default=True)
# Whether this fold reads a `builtin` through to the builtin it names, and whether a fold met one it may read so
# (`_through`, `shell_command.folds`; #2665). Bash runs `builtin eval 'P'` as `eval 'P'`; dash has no `builtin`,
# runs nothing of it, and goes on where no `-e` stops it. So `main`'s reading, the word a command the guard does
# not follow, is dash's, and stays: the second walk reads a job that holds such a word in every fold it reads any
# job in, then in each of them again with the word read through, and the guard REPORTs where either reading does.
_THROUGH = {"on": False, "met": False}


def _through(mains=False):
    """Whether this fold reads through a `builtin` that stands in front of a builtin's name (#2665): never in
    the main pass, and in the second walk only in the folds `shell_command.folds` reads again for the one a
    fold met here -- which this notes. `mains` is the answer in the main pass, for a word `main` read through
    already (a shell's `eval` behind `sudo -s`, #2670): its reading stays there."""
    if not WALKED_DEFAULTS.get():
        return mains
    _THROUGH["met"] = True
    return _THROUGH["on"]


def _shell_default(word, argv=()):
    """The words a command word that is a one-word default runs as, where the default names a shell
    (`${X:-sh}`: `sh`) or, in the second walk (`WALKED_DEFAULTS`, #2963), a fetcher or `eval`; else
    None: `"${SH:-bash}"` is `bash` (#2337), and `"${SH:- bash}"`, `${X:-"bash -s"}` and
    `${X:-bash\\ -s}` name no shell. A default holding a blank the reader marks is read whole
    (`_default_words`). One naming `builtin` or `jobs` is that word in the folds that read it through (#2665,
    #2836). With `argv`, the stage the word starts, the second walk reads a default naming a WRAPPER too
    (#3007): `_optional` drops one in front of a name it knows, and in front of the wrapper's own words
    (`${SUDO:-sudo} -E sh -c 'P'`) nothing read the command behind them. It is that wrapper where it takes one
    of the words for itself and they read on to a command word that is written out -- but `time`, a reserved
    word no expansion makes, an alternate, which is nothing with its name unset, and a word the step's table
    holds another literal for (`kept`). In the folds that read the second walk's newer words (`_drops`); a `$`
    word where the wrapper's words end stays a command the guard does not follow, as behind a written wrapper
    it is one it cannot read."""
    default = _DEFAULTS.fullmatch(word)
    if default and argv and WALKED_DEFAULTS.get() and word[-len(default[1]) - 2] != "+" and (
            head := os.path.basename(default[1])) in WRAPPERS and head != "time" and not getattr(word, "kept", False):
        inner, reason = unwrap([default[1], *argv[1:]], head, has_substitution)
        return [default[1]] if inner and not reason and len(inner) < len(argv) - 1 and not dynamic(
            inner[0], has_substitution) and _drops() else None
    known = (*_SHELLS, *_FETCHERS, "eval") if WALKED_DEFAULTS.get() else _SHELLS
    return [default[1]] if default and (os.path.basename(default[1]) in known          # (#2665, #2836)
                                        or default[1] in ("builtin", "jobs") and _through()) else None


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


def _half(whole, differs):
    """Whether this fold reads empty a command word bash may expand to nothing that has both halves,
    and why the guard cannot read it where its halves read apart and it is one past the `_HALF_CAP`
    such words a job holds (#2929): outside `folds` never, as `main` reads it; in them, where the
    fold reads all, or, its halves apart, its place -- where its parse stands and its order there
    (`shell_tokens._Parse.whole`), the same in every parse of that place and never its text."""
    if not _HALVES["on"]:
        return False, None
    _HALVES["both_dropped" if _DROPPED in _HALVES["empty"] else "both"], words, past = True, _HALVES["words"], None
    if differs and whole.at not in words and len(words) >= _HALF_CAP:
        past = "`%s` is a command word bash may expand to nothing beside %d more, whose readings the guard does not combine" % (
            readable(whole), _HALF_CAP)
    elif differs:
        words.setdefault(whole.at)
    return None in _HALVES["empty"] or differs and whole.at in _HALVES["empty"], past


def _masks():
    """The sets of command words bash may expand to nothing a fold reads empty, in order: none, all
    where one has both halves, then each other set of those whose halves read apart -- of the first
    `_HALF_CAP` alone, so the folds never grow past 8 (#2929). Where a fold met a word the second walk's newer
    reading drops (`_drops`), each of those once more with `_DROPPED` in it: the same halves, and such words
    read as nothing -- 16 at most, and `main`'s own all among them. `main`'s readings take the sets of halves
    only where one of `main`'s folds met a word with both: one met behind a dropped word alone is read in the
    dropped words' folds, and every fold of `main`'s would read the same whatever its set."""
    words = list(_HALVES["words"])[:_HALF_CAP]
    some = [frozenset(word for at, word in enumerate(words) if bits >> at & 1) for bits in range(1, (1 << len(words)) - 1)]
    masks: list[frozenset] = [frozenset()] + ([_ALL] + some if _HALVES["both"] else [])
    if not _HALVES["drops"]:
        return masks
    dropped: list[frozenset] = [frozenset()] + ([_ALL] + some if _HALVES["both"] or _HALVES["both_dropped"] else [])
    return masks + [mask | {_DROPPED} for mask in dropped]
