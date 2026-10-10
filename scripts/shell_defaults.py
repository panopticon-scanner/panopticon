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
import os
import re

from shell_tokens import derived, readable, spelled
from shell_wrappers import WRAPPERS, Defaulted, Rewritten


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
