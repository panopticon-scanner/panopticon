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
from workflow_printers import (ANY, _PRINTERS, SpelledOutput, StatementFront, _grouped,
                               _printer_of, file_operand, producer, spellings)

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


def _writers(stage, before, statements, index):
    """The writers whose texts land where `stage` writes, in order: `_writer`'s one; or, where `stage` closes a
    `{ ...; }` or `( ...; )` group (#3110), the printer of each pipeline of the group `_grouped` hands back
    (`_printer_of`), as #3026 reads a group piped to a shell -- a pipeline that is no printer's stands in as a
    writer the printers cannot spell, so `_script` hands the group on LOUD (fail-closed); a group with no printer
    in it binds nothing, as the file it writes is no printer's text."""
    one = _writer(stage, before)
    if one is not None:
        return [one]
    if list(stage.argv) != ["}"] and not stage.group_close:
        return []
    pipelines = _grouped(stage, before, StatementFront(statements, index)) or []
    printers = [_printer_of(pipeline) for pipeline in pipelines]
    if not any(printers):
        return []
    return [(shell_reader.command(printer.argv), printer) if printer is not None   # by its words, as
            else (["}"] + list(shell_reader.command(pipeline[-1].argv)), pipeline[-1])  # `_printer_of` read
            for printer, pipeline in zip(printers, pipelines)]                          # it; none: unspellable


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


def _restored(word):
    """`word`'s text with each lifted substitution restored around its own script (`$(…)`, `<(…)`)."""
    text = str(word)
    for key, (kind, value) in shell_reader._markers(word).items():
        if kind == "subst":
            opener = getattr(value, "direction", None) or "$"
            text = text.replace(key, "%s(%s)" % (opener if opener in "<>" else "$", value))
    return text


def _rendered(word):
    """`word` as a shell spells it, its substitutions restored (`_restored`), so the printers read the word
    again as they read it where it stood; a `$` word double-quoted, live (the reader keeps no quote:
    fail-closed); any other word quoted as written."""
    text = _restored(word)
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
    """What `substituted` spells as the writers' texts joined in order.

    Fully spelled writers return a tagged output directly, without reparsing one synthetic `printf`
    whose single argument is the whole file. One writer the printers cannot spell, alone, is handed on as its own command (a `cat`'s body as
    `_heredoc`), so the printers read it as they read it where it stood. Among others, or past `_DEPTH`
    writers, every text is kept -- an unspelled writer's as its words read, substitutions restored -- in an
    expanding heredoc behind a live `$` line, which the guard reports as it reports any expanding body a
    shell runs: a spelled payload beside an unspelled line is never dropped (fail-closed)."""
    texts, unspelled = [], len(writers) > _DEPTH
    for argv, stage in writers[:_DEPTH]:
        readings = [r for r in spellings(argv, stage, ANY) if r is not None]
        text = readings[0] if readings else _literal_heredoc(stage)
        if text is None:
            if len(writers) == 1:
                if os.path.basename(argv[0]) == "cat":
                    return _heredoc(stage.stdin_heredoc[0])  # read as `. <(cat <<EOF …)` is
                return " ".join(_rendered(w) for w in argv)
            unspelled = True
            text = (stage.stdin_heredoc[0] if os.path.basename(argv[0]) == "cat"
                    else " ".join(_restored(w) for w in argv[1:]))
        texts.append(text if text.endswith("\n") else text + "\n")
    if unspelled:
        return _heredoc(': "$UNSPELLED_WRITER"\n' + "".join(texts))
    return SpelledOutput("".join(texts))


def _bind(stage, path):
    """`stage.argv` with its FILE operand `path` replaced by a token carrying `written`, in place."""
    for at, word in enumerate(stage.argv):
        if not shell_reader.is_marker(word) and _path(word) == path:
            token = shell_reader._Token(str(word), {})
            token.__dict__.update(getattr(word, "__dict__", {}))
            stage.argv[at] = token
            return token
    return None


def _descriptor_script(stage, operand):
    """A one-printer script of the body the stage's own heredoc or here-string puts on the descriptor its FILE
    operand's path names (`. /dev/stdin <<'EOF'`, `sh /dev/fd/3 3<<'EOF'`, #2972), or None: a quoted body as
    written, an expanding one as `_heredoc` hands it on."""
    fd = shell_reader.input_alias_fd(str(operand)) if not shell_reader.is_marker(operand) else None
    body = stage.stdin_heredoc if fd == "0" else next(
        ((text, expands) for number, text, expands in stage.fd_bodies if number == fd), None)
    if body is None:
        return None
    text, expands = body
    if expands and any(c in text for c in "$`"):
        return _heredoc(text)
    end = "EOF_%d" % len(text)
    while end in text:
        end += "_"
    return "cat <<'%s'\n%s\n%s\n" % (end, text, end)


def bind_written(stmts):
    """Mark, in place and in statement order, every FILE operand that names a path an earlier stage of
    the step wrote with a printer; return `stmts`."""
    files: dict[str, list] = {}
    for index, statement in enumerate(stmts):
        for position, stage in enumerate(statement.stages):
            argv = shell_reader.acted(stage.argv)
            operand = file_operand(argv) if argv else None
            path = _path(operand) if operand is not None else None
            if operand is not None and (script := _descriptor_script(stage, operand)) is not None:
                if (token := _bind(stage, path)) is not None:
                    setattr(token, "written", script)
                    continue
            if path is not None and path in files and (token := _bind(stage, path)) is not None:
                setattr(token, "written", _script(files[path]))
            written = _paths(stage)         # a stage that writes no file has no writers to look up (round 1)
            for writer in _writers(stage, statement.stages[:position], stmts, index) if written else ():
                for path in written:
                    files.setdefault(path, []).append(writer)
    return stmts
