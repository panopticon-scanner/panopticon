"""#3701: match a pattern UNDER a directory, with the directory taken as it is spelled.

`glob.glob(os.path.join(directory, "findings-*.json"))` reads the whole joined
string as one pattern, so a `[`, `*` or `?` in `directory` is a wildcard too. A
review root at `repo[x]/` then matched nothing: `[x]` is the character class
"x", which is the directory `repox`, not `repo[x]`. The run found none of its
own findings files, dispatch plans, scout replies or coverage files, lost every
agent finding with no reason given, and `--reset` deleted the flat artifacts of
the SIBLING `repox` and left its own. An empty `repo[x]/` beside
`repox/requirements-dev.txt` read as a Python tree.

`glob` has a second fault, which this module also closes: it swallows the error
of a directory it cannot list and returns nothing, so "no such file" and "could
not look" read the same. Here they do not. A directory that is not there
matches nothing; one that is there and cannot be listed raises `Unlistable`,
and each caller says what that means for it (an audit that is owed and was not
produced, a reset that cleared nothing, a report that was not surfaced).

No module in the package calls `glob`, this one included. That is what
`tests/test_safe_glob.py` checks: it fails if any module here calls `glob.glob`
or `glob.iglob`, with one exception it names, `guard_rules.py`, which is loaded
with the standard library alone, cannot import this module, and escapes its
directory itself. (Matching a NAME against a pattern with `fnmatch`, as
`first_party_advisory.py` and `codex_read_tools.py` do, lists no directory and
is not this module's business.)
"""
import fnmatch
import ntpath
import os
import re

import scripts.inert as inert

_MAGIC = re.compile(r"[*?\[]")
_SEPARATORS = "".join(sep for sep in (os.sep, os.altsep) if sep)
_SEPARATOR = re.compile("[%s]" % re.escape(_SEPARATORS))


class Unlistable(Exception):
    """A directory that is there and could not be listed, or a name in one whose
    presence could not be read. `directory` is its path; `reason` is the system's.

    Not an `OSError`, on purpose. This package is full of readers that skip one
    file they cannot read (`except OSError: continue`), and a listing that failed
    must not be skipped along with it.

    The message is one line whatever the path holds: every caller prints it, and a
    directory named with a newline or an escape sequence would otherwise write a
    second line, or move the cursor, in the operator's terminal. `directory` stays
    the path itself."""

    def __init__(self, directory, error):
        self.directory = directory
        self.reason = getattr(error, "strerror", None) or str(error)
        super().__init__("%s could not be listed: %s" % (shown(directory), _spelled(self.reason)))


def shown(directory):
    """`directory` as a diagnostic prints it: each control character spelled out
    (`scripts.inert`), so the path stays on its one line. No two names are printed
    alike. A backslash is doubled first, so the four characters `\\x0a` are not a
    newline's spelling. A lone surrogate, which is what a byte that is not UTF-8
    becomes in a file name, is spelled `\\udcNN` here: `scripts.inert` writes it
    `U+DCNN` with no backslash, for readers of a path, and that is also six
    characters a name can simply hold."""
    return _spelled(os.fspath(directory))


_SURROGATE = re.compile("[%c-%c]" % (inert.SURROGATES[0], inert.SURROGATES[-1]))


def _spelled(text):
    text = text.replace("\\", "\\\\")
    text = _SURROGATE.sub(lambda found: "\\u%04x" % ord(found.group()), text)
    return inert.inert_spelling(text)


def under(directory, *pattern):
    """The paths under `directory` that match `pattern`, unsorted. `directory` is
    literal, whatever characters it holds. `pattern` is one or more path parts,
    each of which may hold wildcards, in the syntax `glob` reads without
    `recursive`: `under(run_dir, "findings-*.json")`,
    `under(home, "sessions", "*", "wire.jsonl")`.

    The contract, which `iter_under` shares:

    - A directory that is not there matches nothing. One that is there and
      cannot be listed raises `Unlistable`, and so does a name whose presence
      cannot be read. Nothing is returned for the part that could be read.
    - Every match is under `directory`. `directory` is not empty, there is at
      least one pattern part, and no part is empty, absolute, `.` or `..`. A
      part may hold separators (`"*/skills/x"` is three parts). No part holds a
      backslash or starts with a drive (`C:`), on any platform: both leave the
      directory where they are read as path syntax, and no caller needs either.
      Anything else is a `ValueError`, raised at the call.
    - A name the caller builds a pattern part from is the caller's to vouch
      for: the run tag in `<tag>-report*.json` is alphanumerics and hyphens by
      construction."""
    return list(iter_under(directory, *pattern))


def iter_under(directory, *pattern):
    """`under`, one match at a time, for a caller that asks whether anything
    matches: `next(iter_under(target, "requirements*.txt"), None)`. A directory
    is listed when the walk reaches it, so the first match costs the directories
    on the way to it. The arguments are checked here, at the call."""
    directory = os.fspath(directory)
    if not directory:
        raise ValueError("safe_glob: the directory is empty")
    return _walk(directory, _parts(pattern))


def _parts(pattern):
    if not pattern:
        raise ValueError("safe_glob: no pattern, which would return the directory itself")
    parts = []
    for given in pattern:
        given = os.fspath(given)
        for part in _SEPARATOR.split(given):
            if part in ("", os.curdir, os.pardir):
                raise ValueError("safe_glob: a pattern part is empty, absolute, %r or %r: %r"
                                 % (os.curdir, os.pardir, given))
            if "\\" in part or ntpath.splitdrive(part)[0]:
                raise ValueError("safe_glob: a pattern part holds a backslash or a drive: %r"
                                 % (given,))
            parts.append(part)
    return parts


def _walk(directory, parts):
    part, rest = parts[0], parts[1:]
    wild = bool(_MAGIC.search(part))
    if wild:
        names = fnmatch.filter(_names(directory), part)
        if not part.startswith("."):
            names = [name for name in names if not name.startswith(".")]
    else:
        names = [part]
    for name in names:
        path = os.path.join(directory, name)
        if rest:
            yield from _walk(path, rest)
        elif wild or _present(directory, path):
            yield path


def _names(directory):
    """What `directory` holds, or nothing when no directory is there."""
    try:
        with os.scandir(directory) as entries:
            return [entry.name for entry in entries]
    except (FileNotFoundError, NotADirectoryError, ValueError):
        return []
    except OSError as error:
        raise Unlistable(directory, error) from error


def _present(directory, path):
    """Whether the literal `path` is there, as `os.path.lexists` asks it."""
    try:
        os.lstat(path)
    except (FileNotFoundError, NotADirectoryError, ValueError):
        return False
    except OSError as error:
        raise Unlistable(directory, error) from error
    return True
