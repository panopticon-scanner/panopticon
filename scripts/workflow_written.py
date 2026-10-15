#!/usr/bin/env python3
"""A file the step writes with its own printer and then runs is read as the writer's text (#3027).

`echo 'curl … | sh' > s.sh` ⏎ `sh s.sh` ran the download under every parent and read CLEAN: the
reader bound a `<(…)` FILE operand to the printer that fills it (`workflow_printers._filed`,
`substituted`), and a fetched file to the run that uses it (`workflow_fetch`), but nothing bound a
path the step itself WROTE -- with `echo`, `printf`, a `cat` and its heredoc, or `tee` -- to the
later run of that path. `bind_written` does, in statement order: each stage's literal written paths
are recorded with their writer, and a later stage whose FILE operand (`file_operand`, a shell's or
`source`'s) names a recorded path has that word replaced in place by a token carrying `written` --
a script the printers spell as ONE printer's text (`substituted`), so `stdin_scripts` reads the file
as it reads a `<(…)` FILE: the writers' texts joined in order under `printf '%s'`, or, where a writer
cannot be spelled, that writer's command as written, which `unsubstituted` reports (fail-closed).

Rules, fail-closed where the reader cannot know: every write is read as an APPEND (the stage keeps
the written words, not the `>`/`>>` operator), so a benign re-write after the payload still reads
the payload (a price); a write under a condition counts; a write in a function body counts where
the definition stands before the run (a never-called or later-called body over-reports); a write
after the run binds nothing; a `$` word, a marker, or a pattern as the path binds nothing. The word
keeps no marker entry: `is_marker` words are dropped by other readers, and this path is a plain word.
"""
import os
import shlex

import shell_reader
from workflow_printers import ANY, _PRINTERS, file_operand, producer, spellings

_DEPTH = 64                 # writers kept per path; past it the text is unspelled (fail-closed)


def _path(word):
    """The literal path a written word names, or None for a value, a marker or a pattern."""
    if word is None or shell_reader.is_marker(word) or any(c in word for c in "$`*?["):
        return None
    return os.path.normpath(str(word))


def _writer(stage, before):
    """`(argv, stage)` of the printer whose text lands where `stage` writes, or None: `stage` itself
    with its own `echo`/`printf` or a `cat` alone with its heredoc, or the intact printer piped into
    a `tee` (`producer`) -- each read once, unwrapped, where the one call below stands."""
    chosen = stage
    for _hop in range(2):
        argv = shell_reader.acted(chosen.argv)
        name = os.path.basename(argv[0]) if argv else ""
        if name in _PRINTERS or name == "cat" and chosen.stdin_heredoc is not None and len(argv) == 1:
            return argv, chosen
        if name != "tee" or chosen is not stage:
            return None
        chosen, intact = producer(stage, before)
        if chosen is None or not intact:
            return None
    return None


def _paths(stage):
    """The literal paths this stage writes: descriptor 1's final sink, and a `tee`'s file operands."""
    argv = shell_reader.acted(stage.argv)
    words = list(stage.stdout_writes or ())
    if argv and os.path.basename(argv[0]) == "tee":
        words += [w for w in argv[1:] if not str(w).startswith("-")]
    return [p for p in (_path(w) for w in words) if p is not None]


def _literal_heredoc(stage):
    """The body of a `cat`'s EXPANDING heredoc where nothing in it expands -- no `$`, no backquote --
    which the shell writes as written, or None."""
    here = stage.stdin_heredoc
    return here[0] if here is not None and here[1] and not any(c in here[0] for c in "$`") else None


def _rendered(word):
    """`word` as a shell spells it: a lifted substitution restored around its own script (`$(…)`,
    `<(…)`), so the printers read the word again as they read it where it stood; a `$` word double-
    quoted, live (the reader keeps no quote: fail-closed); any other word quoted as written."""
    text = str(word)
    for key, (kind, value) in shell_reader._markers(word).items():
        if kind == "subst":
            opener = getattr(value, "direction", None) or "$"
            text = text.replace(key, "%s(%s)" % (opener if opener in "<>" else "$", value))
    if "$" in text or "(" in text and shell_reader.is_marker(word):
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return shlex.quote(text)


def _heredoc(text):
    """A `cat` printing `text` from an EXPANDING heredoc: the script `_filed` hands on is read as `. <(cat <<EOF …)`
    is -- the guard's expanding-body reading, reported where a shell takes it as its program."""
    end = "EOF_%d" % len(text)
    while end in text:
        end += "_"
    return "cat <<%s\n%s\n%s\n" % (end, text, end)


def _script(writers):
    """A script `substituted` spells as ONE printer's text: the writers' texts joined, or the first
    unspelled writer's command as written (reported, never read as text)."""
    texts = []
    for argv, stage in writers[:_DEPTH]:
        readings = [r for r in spellings(argv, stage, ANY) if r is not None]
        text = readings[0] if readings else _literal_heredoc(stage)
        if text is None:
            if os.path.basename(argv[0]) == "cat":
                return _heredoc(stage.stdin_heredoc[0])          # read as `. <(cat <<EOF …)` is
            return " ".join(_rendered(w) for w in argv)
        texts.append(text if text.endswith("\n") else text + "\n")
    if len(writers) > _DEPTH:
        return 'printf "%s" "$UNSPELLED_PAST_DEPTH"'
    return "printf '%s' " + "'" + "".join(texts).replace("'", "'\\''") + "'"


def _bind(stage, path):
    """`stage.argv` with its FILE operand `path` replaced by a token carrying `written`, in place."""
    for at, word in enumerate(stage.argv):
        if not shell_reader.is_marker(word) and _path(word) == path:
            token = shell_reader._Token(str(word), {})
            token.__dict__.update(getattr(word, "__dict__", {}))
            stage.argv[at] = token
            return token
    return None


def bind_written(stmts):
    """Mark, in place and in statement order, every FILE operand that names a path an earlier stage of
    the step wrote with a printer; return `stmts`."""
    files: dict[str, list] = {}
    for statement in stmts:
        for position, stage in enumerate(statement.stages):
            argv = shell_reader.acted(stage.argv)
            operand = file_operand(argv) if argv else None
            path = _path(operand) if operand is not None else None
            if path is not None and path in files and (token := _bind(stage, path)) is not None:
                setattr(token, "written", _script(files[path]))
            writer = _writer(stage, statement.stages[:position])
            if writer is not None:
                for written in _paths(stage):
                    files.setdefault(written, []).append(writer)
    return stmts
