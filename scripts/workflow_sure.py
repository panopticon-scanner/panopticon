#!/usr/bin/env python3
"""Which command words are surely the shells they name, and what `main` read where none is (#2858
round 9, the literal-only ruling).

The stdin and string walks of `workflow_programs` see one command at a time, and a step may make
`bash` mean something else before it: a function or alias of that name, a sourced file, an `eval`, a
startup file named in `BASH_ENV`. `shadowed` reads the step's text for any of these, and `certified`
marks every command word it leaves its own name `Sure` (`workflow_options`) -- the certificate each
clear and check credit those walks add asks for (`_sure_shell`, `_cleared`); `workflow_forms.flattened`
calls it at a step's top and in each script it reads inside one, and `inner_command` hands it on to
the string #2500's walk parses itself. Where no certificate holds, the walks read no less than `main`
read: `_dash_c_strings` and `_floor_candidates` here, `_main_walk` in `workflow_options`. Split out of
`workflow_options` at that module's 700-line ceiling. Stdlib only; it reads `shell_reader` and
`workflow_options` and nothing above them.
"""
import os
import re

import shell_reader
from workflow_options import (VALUE_OPTIONS, _MEASURED_SHELLS, Sure, _after_value, _dash_c_operand,
                              _in_every_reading, _literal, _past_options, _sure_shell, _value)


# What may change what a command word runs, anywhere in a step's text (#2858 round 9, rule 3): a
# function of a measured shell's or a wrapper's name (`bash() {`, `function sh`), a quoted string's
# text too (`eval 'bash() { :; }'`); and, for every name at once, an alias (dash expands one wherever
# it stands) or `expand_aliases`, a sourced file, an `eval` of a word it does not spell (`eval "$X"`,
# by its parsed words at a stage, by a `$` or backquote on its line in a carried text), `hash`,
# `enable`, a name a shell reads at
# startup or the lookup reads (`BASH_ENV`, `ENV`, `PATH`, `BASH_FUNC_…`, `BASH_CMDS`); and a write
# that may plant such a name where a later bare word finds it (the coordinator's (c)): a target named
# like one, a compression suffix aside (`curl -o ~/.cargo/bin/bash`, `cp t /snap/bin/sh`, `ln -sf zsh
# /bin/sh`), one not written as itself (`curl -o "$OUT"`, `> "$DIR/$N"`), or an archive unpacked. Read
# as raw text: a match no shell would take costs the step what `main` read, never a clear.
_NAMES = "|".join(map(re.escape, _MEASURED_SHELLS + shell_reader.WRAPPERS))
_DEFINED = re.compile(r"""(?:^|[\s;&|(){}<>'"`])['"]?(%s)['"]?\s*\(\s*\)|\bfunction\s+['"]?(%s)\b""" % (_NAMES, _NAMES))
_EVERY = re.compile(r"\b(?:alias|source|hash|enable|expand_aliases|BASH_ALIASES|BASH_CMDS)\b|BASH_FUNC_|(?m:^(?=[^\n]*\beval\b)[^\n]*[$`])"
                    r"|(?:^|[\s;&|(){}`])\.(?=\s|$)"
                    r"|(?<![\w$])(?<!\$\{)(?:BASH_ENV|ENV|PATH|SHELLOPTS|BASHOPTS|POSIXLY_CORRECT)(?!\w)")
_NAMED = re.compile(r"(?:%s)(?:\.(?:gz|xz|bz2|zst|lz|lzma|Z))?" % _NAMES)
_PLANTED = re.compile(r"(?:/|>>?\s*['\"]?|-[A-Za-z]*[oO]\s*['\"]?)%s(?=$|[\s'\"`;|&)<>])" % _NAMED.pattern)
_UNSURE_WRITE = re.compile(r">>?\s*['\"]?[$`]|(?:-[A-Za-z]*[oOP]|--output(?:-document)?|--directory-prefix)[=\s]*['\"]?[$`]"
                           r"|(?m:^(?=[^\n]*\b(?:cp|mv|ln|install|rsync|tee|dd|scp|ditto)\b)[^\n]*[$`])"
                           r"|\b(?:tar|unzip|7z|cpio|gunzip|bunzip2|unxz|unzstd|unlzma)\b")
_WRITERS = ("curl", "wget", "cp", "mv", "ln", "install", "rsync", "tee", "dd", "scp", "ditto")
_UNPACKERS = ("tar", "unzip", "7z", "cpio", "gunzip", "bunzip2", "unxz", "unzstd", "unlzma", "xz", "zstd",
              "gzip", "bzip2")


def _plants(stage, argv):
    """Whether `stage`, running `argv`, may write a file a later bare shell or wrapper word finds (the
    coordinator's (c)): a redirection target, or a writer's word after its command, named like one
    (`_NAMED`) or not written as itself; a path among its words named like one; or an unpacker."""
    name = os.path.basename(str(argv[0])) if argv else ""
    targets = list(stage.writes) + (list(argv[1:]) if name in _WRITERS else [])
    if name in _UNPACKERS or any(not _literal(t) or _NAMED.fullmatch(os.path.basename(str(t))) for t in targets):
        return True
    return any("/" in str(w) and _NAMED.fullmatch(os.path.basename(str(w))) for w in argv[1:])


def _carried(word):
    """`word`'s text and every lifted text it carries (`shell_reader._markers`)."""
    return "\n".join([str(word)] + [str(value) for _kind, value in getattr(word, "markers", {}).values()])


def shadowed(stmts):
    """The names of `_MEASURED_SHELLS` and the wrappers the reader looks through (`WRAPPERS`) that a
    step's statements may not run as themselves (#2858 round 9, rule 3; `_DEFINED`, `_EVERY`): all of
    them where it may change them all, else the ones it defines -- read off every word, heredoc body,
    substitution and redirection the stages carry."""
    names = set()
    for statement in stmts:
        for stage in statement.stages:
            argv = shell_reader.command(stage.argv)
            first = argv[:1]
            if first and first[0] == "eval" and not all(map(_literal, argv[1:])):
                return set(_MEASURED_SHELLS + shell_reader.WRAPPERS)
            words = [word for word in stage.argv if not (first and word is first[0])]
            nested = "\n".join(list(stage.substitutions) + [stage.heredoc or ""])
            carried = "\n".join([_carried(word) for word in words] + [
                str(target) for target in (*stage.writes, *stage.reads)] + [nested])
            # A write's raw spelling is read in a text a shell runs -- a heredoc, a substitution, one word
            # of the command (a `-c` string) -- never across its words or in its wrappers (`bash -o $X`,
            # `/usr/bin/env bash`): those `_plants` reads by the command they belong to.
            texts = "\x00".join([nested] + [_carried(word) for word in argv[1:]])
            if (_EVERY.search(carried + "\n" + "\n".join(_carried(word) for word in first))
                    or _PLANTED.search(texts) or _UNSURE_WRITE.search(texts) or _plants(stage, argv)):
                return set(_MEASURED_SHELLS + shell_reader.WRAPPERS)
            names |= {found[0] or found[1] for found in _DEFINED.findall(carried)}
    return names


_ASSIGNED = re.compile(r"[A-Za-z_]\w*(?:\[[^]]*\])?\+?=")


def certified(stmts, holder=None):
    """`stmts`, each command word in it marked `Sure` in place where nothing may change what it runs
    (#2858 round 9, rule 3) -- at a step's top (`holder` None) where `shadowed` finds nothing in the
    whole step, and in a script `workflow_forms.flattened` reads inside it (`holder`, the argv that
    hands the script on) where the holder's own word is `Sure`. A word is marked where it is written
    as itself (`_literal`) and every word in front of it in its stage is too, or an assignment: an
    optional `$S` in front (`S='bash -s'; $S bash --version`) or `sudo -u "$U"` may run anything."""
    if isinstance(stmts, Uncertified) or (shadowed(stmts) if holder is None else type(holder[0]) is not Sure):
        return stmts
    for statement in stmts:
        for stage in statement.stages:
            if (at := _reached(stage)) is not None:
                stage.argv[at] = Sure(stage.argv[at])
    return stmts


# A job's earlier step that writes `$GITHUB_ENV` or `$GITHUB_PATH` sets `PATH`, `BASH_ENV` and the rest for
# every later one (#2858 round 9), and one that may plant a shell or a wrapper (`_PLANTED`, `_UNSURE_WRITE`)
# leaves one a later bare word may find: no word after either is surely the shell it names. Raw text.
_JOB = re.compile(r"GITHUB_(?:ENV|PATH)\b")


class Uncertified(list):
    """A step's statements `certified` leaves unmarked (`uncertified`)."""


def uncertified(stmts, before=()):
    """`stmts` as `Uncertified` where a step in front of this one in its job (`before`, each `(name,
    script, ...)`, as `workflow_guard.job_defects` holds them) writes `$GITHUB_ENV` or `$GITHUB_PATH`
    (`_JOB`); else `stmts` itself. A fresh parse either way: nothing marked here is shared."""
    return Uncertified(stmts) if any(pattern.search(step[1] or "") for step in before
                                     for pattern in (_JOB, _PLANTED, _UNSURE_WRITE)) else stmts


def _reached(stage):
    """The index in `stage.argv` of the command `shell_reader.command` finds, where it is written as
    itself and every word in front of it is too, or an assignment; else None."""
    argv, words = shell_reader.command(stage.argv), stage.argv
    at = len(words) - len(argv)
    if argv and words[at] is argv[0] and _literal(argv[0]) and all(
            _literal(word) or _ASSIGNED.match(word) for word in words[:at]):
        return at
    return None


def inner_command(holder, stage):
    """The command of `stage`, one statement of a string `holder` hands on (`eval 'bash -s'`, `bash -c
    'sh'`: #2500's walk, which reads its own cached parse), as a new argv whose word is `Sure` where
    the holder's is and the stage reaches it through literal words (`_reached`) -- the cached parse
    itself is never marked, since another step may share it."""
    argv = list(shell_reader.command(stage.argv))
    if argv and type(holder[0]) is Sure and _reached(stage) is not None:
        argv[0] = Sure(argv[0])
    return argv


def _dash_c_strings(argv):
    """`workflow_programs._after_dash_c`'s answer: the operand after a `-c` cluster in every reading
    (`_in_every_reading`); for a shell no certificate covers (`_sure_shell`, #2858 round 9), with
    `main`'s own answer beside it -- the first `-c` cluster before a `--`, and its first operand --
    so no refusal before the cluster or long FILE option there reads less than `main` read."""
    found = _in_every_reading(argv, _dash_c_operand)
    if not _sure_shell(argv):
        at = next((k for k, token in enumerate(argv[1:], start=1) if token == "--" or token.startswith("-")
                   and not token.startswith("--") and "c" in token), None)
        if at is not None and argv[at] != "--":
            found += [word for word in _past_options(argv, at) if not any(word is seen for seen in found)]
    return found


def _floor_candidates(argv, found):
    """`workflow_programs.candidates`' answer `found` for a shell, with `main`'s beside it where no
    certificate covers the shell (#2858 round 9): the first value word among its options and the words
    after it, as `main` read them -- no long option taking a FILE and no refusal ending the walk."""
    if _sure_shell(argv):
        return found
    owed = 0
    floor: tuple = (None, [])
    for at, word in enumerate(argv[1:], start=1):
        if owed:
            owed -= 1
        elif _value(word):
            floor = _after_value(argv, at)
            break
        elif word in ("-", "--") or word[:1] not in ("-", "+") or word[:2] != "--" and "c" in word:
            break
        elif word[:2] != "--":
            owed = sum(letter in VALUE_OPTIONS for letter in word[1:])
    words = list(found[1]) + [word for word in floor[1] if not any(word is seen for seen in found[1])]
    return (floor[0] if found[0] is None else found[0]), words
