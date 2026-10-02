#!/usr/bin/env python3
"""What an operand of a `run:` step stands for, with no rule on top.

Split out of `scripts/workflow_forms.py` (#1793's follow-ups, re-review of
round one) the way that module came out of the guard: it had reached its
size, and this part is a layer of its own. `workflow_forms` re-exports it
for the guard.

The guard binds a use to a download by NAME, and shell has several ways to
designate a file without ever writing its name:

    `same_file`, `names_file`  exactly, and for a checksum's text, word for
                               word
    `covers`                   by a glob, by a word bash expands that ends
                               in a download's basename, by one written out
                               where the download's path expands (#2345 and
                               its mirror #2442), or by the directory a
                               recursive command walks
    `may_run`                  a command word bash expands that ends in a
                               download's basename (#2310) or written out
                               where the download's path expands (#2442), or
                               a bare name a download written into a
                               directory on PATH answers to (#2308)
    `described`                the operands handed over by `find -exec` or
                               `xargs`
    `chmod_targets`            the files a `chmod` changes, its mode apart

Stdlib only, like everything under it.
"""
import fnmatch
import os
import re

import shell_reader
from shell_reader import command
from shell_wrappers import dynamic


def _chmod_operands(argv):
    """Separate the mode from the file operands after chmod's leading options."""
    rest = iter(argv[1:])
    for mode in rest:
        if mode == "--":
            mode = next(rest, "")
            break
        if mode.startswith("--reference"):
            return "", []
        if mode in ("--recursive", "--verbose", "--changes", "--silent", "--quiet",
                    "--preserve-root", "--no-preserve-root") or re.fullmatch(r"-[Rvcf]+", mode):
            continue
        break
    else:
        return "", []
    return mode, list(rest)


def chmod_targets(argv):
    """Files chmod changes; the mode itself must never count as a target."""
    return _chmod_operands(argv)[1]


def chmod_executable(argv):
    """Whether chmod's MODE operand can set an execute bit, including X.

    Only the mode operand counts; a later filename called `u+x` is not a mode.
    Reference-file modes are unresolved here, as before; they are not symbolic.
    """
    mode, _targets = _chmod_operands(argv)
    if re.fullmatch(r"[0-7]{3,4}", mode):
        return any(int(digit) % 2 for digit in mode[-3:])
    if not re.fullmatch(r"[ugoa]*[+=-][rwxXstugo]*(?:[+=-][rwxXstugo]*)*"
                        r"(?:,[ugoa]*[+=-][rwxXstugo]*(?:[+=-][rwxXstugo]*)*)*", mode):
        return False
    return any(op in "+=" and any(bit in permissions for bit in "xX")
               for op, permissions in re.findall(r"([+=-])([rwxXstugo]*)", mode))


def same_file(token, path):
    return os.path.normpath(token) == os.path.normpath(path)


# `mv`/`cp` of a fetched file into one of these is what makes it runnable by
# name for the rest of the job.
BIN_DIRS = ("/usr/local/bin", "/usr/bin", "/usr/local/sbin", "/usr/sbin",
            "/opt/bin", "/bin", "/sbin")
# Where `may_run` looks a bare command name up (#2308): those, and the runner
# user's `~/.local/bin` in the four spellings a step writes it (review N-4).
# The rest of a runner's PATH, and what a step puts on it, are the gap list's.
PATH_DIRS = BIN_DIRS + ("$HOME/.local/bin", "${HOME}/.local/bin", "~/.local/bin",
                        "/home/runner/.local/bin")


def _last_part(token, dest):
    """Does one of these two spellings bind to the other's LAST part?

    ONE predicate for #2345's rule and #2442's mirror of it, because the
    asymmetry between the two was the bug: a word bash expands is read by its
    last part against a download's basename, and so -- the mirror -- is a word
    written out against a download whose own path expands. `curl -o
    "$PWD/cuda_1.run"; sh cuda_1.run` runs the download in every shell and read
    clean, while the same fetch under `sh cuda_*.run` was reported: the glob
    reached it and the commoner spelling did not. The mirror needs that basename
    WRITTEN -- with the last part expanding too (`-o "$PWD/$F"`) there is no name
    to bind -- and an option word is never a use of anything. `derived` carries
    the dest's lifted substitutions into its basename, so the text standing for
    one (`-o "$PWD/$(date +%s).run"`) is never read as a name written out.
    """
    name = os.path.basename(os.path.normpath(dest))
    if os.path.basename(os.path.normpath(token)) != name:
        return False
    return dynamic(token, shell_reader.has_substitution) or (
        not token.startswith("-") and dynamic(dest, shell_reader.has_substitution)
        and not dynamic(shell_reader.derived(name, dest), shell_reader.has_substitution))


def may_run(word, dest):
    """Does running this COMMAND word run `dest`? By its spelling; by its
    basename where bash expands the word first (#2310); by PATH, for a bare
    name (#2308).

    `"$PWD/tool"` and `"$(pwd)/tool"` run the `tool` a step just fetched, and
    the guard does not evaluate the shell to learn where they point: so a
    word `shell_wrappers.dynamic` calls dynamic -- a `$`, a `$(...)` or
    backquotes, a `Rewritten` word -- that ends in the download's basename is
    read as running it, wherever the fetch put it. Loose on the side that
    RUNS only: a checksum still binds by its exact spelling (`names_file`), or
    one of `$OTHER/tool` would clear a `./tool` it never read. A word whose
    LAST part expands (`"$T"`) matches only a download whose basename is that
    same text -- refusing it outright needs a command position the reader
    does not have, where `case "$1" in` reads as the command `$1`.

    A bare name (`tool`) is looked up on PATH, so it is read as running a
    download written into one of `PATH_DIRS` under that name (`curl -o
    /usr/local/bin/tool`), whether or not a builtin or an earlier directory
    answers to it first. The run side only, again: a checksum of the bare
    `tool` reads `./tool`, so it does not clear `/usr/local/bin/tool`.

    `_last_part` carries the mirror of the first of those (#2442): a word
    written out runs a download whose own path expands (`curl -o "$PWD/tool"`,
    then `./tool`), wherever a PATH lookup would have found it or not.
    """
    name = os.path.basename(os.path.normpath(dest))
    return same_file(word, dest) or _last_part(word, dest) or (
        word == name and os.path.dirname(os.path.normpath(dest)) in PATH_DIRS)


def names_file(content, dest):
    """Does this checked text name `dest`?

    Word-exact against the path, and NEVER a substring match: `/tmp/payload-old`
    must not clear `/tmp/payload`. A checksum list legitimately carries bare
    names, so a BARE dest may also be matched by its basename -- but only a
    bare one: with a directory in the dest, `x.sh` is a different file, and
    accepting it is the unbound checksum this rule exists to refuse, wearing a
    shorter path.
    """
    base = os.path.basename(dest)
    bare = not os.path.dirname(dest)
    return any(same_file(word, dest)
               or (bare and base and same_file(word, base))
               for word in content.split())


# An operand that carries a glob metacharacter DESCRIBES files rather than
# naming one, which is the whole of what `chmod +x *.sh` had over the rule.
_GLOB = re.compile(r"[*?\[]")
# In a word bash expands as a pattern, a brace or extglob group, a `$...` and
# a `$(...)` stand for any text where a glob is matched, and a leading `./`
# names what the name after it names: so `sh ./cuda_*.run` runs a download
# `cuda_1.run` (re-review N-C). With a `$` in it, or in the download's name,
# only the shell knows the directory, so the last parts bind, as in `may_run`
# (#2345); so do they for a bare download and a glob with a directory part,
# which reaches it from another directory: the guard follows no `cd`.
_GROUP = re.compile(r"\{[^{}]*\}|[@+!*?]\([^()]*\)")
_EXPANSION = re.compile(r"\$\{[^{}]*\}|\$\(\.\.\.\)|\$(?:\w+|[^\w{])")
_HERE = re.compile(r"^(?:\./+)+")
# `find`'s ways of running a command over what it walked. The operand is `{}`,
# which names nothing at all.
_FIND_EXEC = ("-exec", "-execdir", "-ok", "-okdir")
_RECURSIVE = ("-R", "-r", "--recursive")


def covers(token, dest, recursive=False):
    """Does this operand stand for `dest`, even without naming it?

    Four spellings, and the guard binds by NAME, so each one hid a use:
    exactly (`chmod +x /tmp/payload`), by a word bash expands that ends in
    the download's basename (`sh "$PWD/payload"`, #2345: its last part must
    be that name as written, and an option word is never one), by a glob
    (`chmod +x /tmp/*.sh`, or a word bash expands, read as `_GROUP` says),
    and by the directory a recursive command walks (`chmod -R +x /tmp`). A
    glob is matched against the whole path with a leading `./` on either
    dropped -- and, one bash expands, by the last parts where a `$` spells
    either directory or it has one a bare dest does not (`_GROUP`'s comment
    says why). #2345's arm is `_last_part`, which carries its mirror too
    (#2442): a word written OUT stands for a download whose own path expands,
    so `sh cuda_1.run` reads the fetch to `"$PWD/cuda_1.run"` that only the
    glob reached. The directory part over-reports: after a fetch of
    `install.sh`, `chmod +x scripts/*.sh` or `sh scripts/*.sh` is refused,
    though bash never touches `install.sh` -- kept, as restricting it to
    `..` would reopen `cd ..; sh repo/cuda_*.run`, which bash runs. The run
    side only, as in `may_run`: a checksum binds by `names_file`.
    """
    if same_file(token, dest):
        return True
    glob, loose, pattern = token, False, getattr(token, "lead", None) is not None
    if pattern:                                     # a word bash expands (the reader's)
        glob = shell_reader.readable(token)
        loose = bool(_EXPANSION.search(glob))
        while _GROUP.search(glob) or _EXPANSION.search(glob):
            glob = _GROUP.sub("*", _EXPANSION.sub("*", glob))
    elif not token.startswith("-") and _last_part(token, dest):
        return True
    if _GLOB.search(glob):
        glob, dest = _HERE.sub("", glob), _HERE.sub("", dest)
        if loose or pattern and ("$" in dest or os.path.dirname(glob) and not os.path.dirname(dest)):
            glob, dest = os.path.basename(glob), os.path.basename(dest)
        return fnmatch.fnmatch(dest, glob)
    if recursive and not token.startswith("-"):
        prefix = os.path.normpath(token)
        if prefix == ".":
            return not os.path.isabs(dest)
        if prefix == os.sep:
            # `normpath("/")` is `/`, so the plain prefix test would ask
            # whether the path starts with `//`: the widest walk of all bound
            # nothing at all.
            return os.path.isabs(dest)
        return os.path.normpath(dest).startswith(prefix + os.sep)
    return False


# `find [-H|-L|-P] [-D <opts>] [-O<n>] <starting-point...> <expression>`: the
# options in front of the starting points are not predicates, and reading one
# as "the roots end here" leaves the binding with nothing.
_FIND_LEADING = ("-H", "-L", "-P")


def _walked(argv):
    """The roots a `find` walks: its starting points, or `.` when it has none.

    The two spellings a maintainer writes without thinking -- `find -L /tmp …`
    and `find -name x …` -- both used to yield no roots at all, which is how a
    closed form quietly reopens.
    """
    i = 1
    while i < len(argv):
        if argv[i] in _FIND_LEADING or argv[i].startswith("-O"):
            i += 1
            continue
        if argv[i] == "-D":
            i += 2
            continue
        break
    roots = []
    for token in argv[i:]:
        if token.startswith("-") or token in ("(", "!"):
            break
        roots.append(token)
    return roots or ["."]


def _recursive(argv):
    return any(token in _RECURSIVE for token in argv[1:])


def described(statement, position, stage, argv):
    r"""(the command that really runs, the operands it is handed, does it walk).

    Two shapes give a command its operands without writing them down, and both
    made a download runnable with no use this rule could read: `find <roots>
    ... -exec chmod +x {} \;` substitutes each hit for `{}`, and `... | xargs
    chmod +x` reads them off the pipe -- where `command()` strips `xargs` as a
    wrapper, leaving a `chmod +x` with no operands at all. The roots stand in
    for what was walked, and a walk binds like a recursive flag.
    """
    for predicate in _FIND_EXEC:
        if os.path.basename(argv[0]) == "find" and predicate in argv:
            inner = [t for t in argv[argv.index(predicate) + 1:]
                     if t not in ("{}", ";", "+")]
            if inner:
                return inner, _walked(argv), True
    # `command()` strips what stands in FRONT of the command, and `argv` is
    # what it left: so the wrappers are the prefix, and an `xargs` anywhere
    # else is an operand -- a file that happens to be called `xargs` hands
    # nothing over.
    lead = stage.argv[:len(stage.argv) - len(argv)]
    if position and any(os.path.basename(t) == "xargs" for t in lead):
        previous = command(statement.stages[position - 1].argv)
        if previous and os.path.basename(previous[0]) == "find":
            return argv, _walked(previous), True
        return argv, previous[1:] if previous else [], _recursive(argv)
    return argv, [], _recursive(argv)
