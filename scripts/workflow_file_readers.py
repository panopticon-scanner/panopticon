#!/usr/bin/env python3
"""Bind files read inside substitutions to the shell program their bytes become (#2428).

This layer sits beside `workflow_printers`: it recognizes the bounded file readers (`cat`,
`head`, `tail`, `sed`, `tr`, and Bash's `$(< file)` shorthand), identifies substitutions used as
an `eval`/`-c` string, a printer's stdin program, or a shell's process-substitution file operand,
and names the reader's exact path for `workflow_uses`. It does not decide whether that path is a
download or whether a checksum clears it; those remain the use and guard layers' jobs.
"""
from dataclasses import dataclass
import os
import re

import shell_lex
import shell_reader
from shell_text import Process
from workflow_options import _MAINS
from workflow_program_strings import (_added_strings, _program_words, _script,
                                      dynamic_program)
from workflow_printers import _PRINTERS, _piped, file_operand


@dataclass(frozen=True)
class FileHandoff:
    """A substitution whose stdout becomes the program `runner` reads."""

    kind: str
    runner: str


_HEAD_VALUE_OPTIONS = ("-c", "-n", "--bytes", "--lines")
_TAIL_VALUE_OPTIONS = _HEAD_VALUE_OPTIONS + (
    "--max-unchanged-stats", "--pid", "--sleep-interval",
)


def _argv(stage):
    """The ordinary command after its wrappers."""
    return shell_reader.command(stage.argv)


def _option_operands(argv, value_options=(), plus_count=False):
    """Operands after ordinary options, omitting values owed by `value_options`."""
    out, owed, options = [], False, True
    for word in argv[1:]:
        text = str(word)
        if owed:
            owed = False
            continue
        if options and text == "--":
            options = False
            continue
        if options and text.startswith("-") and text != "-":
            option = text.split("=", 1)[0]
            owed = "=" not in text and option in value_options
            continue
        if options and plus_count and re.fullmatch(r"\+\d+", text):
            continue
        out.append(word)
    return out


def _sed_operands(argv):
    """Input files of a bounded sed argv; its expression and `-f` file are not input."""
    out, owed, scripted, options = [], None, False, True
    for word in argv[1:]:
        text = str(word)
        if owed is not None:
            scripted = True
            owed = None
            continue
        if options and text == "--":
            options = False
            continue
        if options and text.startswith("-") and text != "-":
            option = text.split("=", 1)[0]
            short = text[:2]
            if option in ("-e", "--expression") or short == "-e":
                scripted = True
                owed = ("expression" if text in ("-e", "--expression") else None)
            elif option in ("-f", "--file") or short == "-f":
                scripted = True
                owed = ("script-file" if text in ("-f", "--file") else None)
            continue
        if not scripted:
            scripted = True
        else:
            out.append(word)
    return out


def _sed_in_place(argv):
    """Whether sed is asked to replace a file instead of printing its program text."""
    return any(text == "-i" or text.startswith("-i") or text == "--in-place"
               or text.startswith("--in-place=") for text in map(str, argv[1:]))


def _stdin_file(stage):
    """A sole redirection that feeds descriptor 0, excluding other opened descriptors."""
    return (list(stage.reads) if stage.stdin_heredoc is None
            and not stage.stdin_from_pipe and len(stage.reads) == 1 else [])


def reader_files(stage, argv=None):
    """Files a supported stdout reader contributes to a substitution's output.

    An empty command with `< file` is parsed separately as Bash's `$(< file)` shorthand. A stage
    whose stdout is redirected contributes none of its bytes to the substitution result.
    """
    if not stage.stdout_to_pipe:
        return []
    argv = _argv(stage) if argv is None else argv
    name = os.path.basename(argv[0]) if argv else ""
    if name not in ("cat", "head", "tail", "sed", "tr") and argv:
        return []
    stdin = _stdin_file(stage)
    if not argv:
        return stdin
    if name == "cat":
        operands = _option_operands(argv)
    elif name == "head":
        operands = _option_operands(argv, _HEAD_VALUE_OPTIONS)
    elif name == "tail":
        operands = _option_operands(argv, _TAIL_VALUE_OPTIONS, plus_count=True)
    elif name == "sed":
        if _sed_in_place(argv):
            return []
        operands = _sed_operands(argv)
    else:
        return stdin                     # `tr` reads only stdin
    files = [word for word in operands if word != "-"]
    return files + (stdin if not operands or "-" in operands else [])


def _redirect_only_file(text):
    """The file in Bash's bounded `$(< file)` shorthand, or None."""
    match = re.fullmatch(r"\s*(?:0)?<\s*([^\s;&|<>]+)\s*", str(text))
    return match[1] if match else None


def _substitution_files(text):
    """Files whose bytes a supported reader contributes to this substitution's stdout."""
    try:
        parsed = list(shell_reader.statements(text))
    except shell_lex.Unreadable:
        return []
    files = [file for statement in parsed
             if statement.stages and statement.stages[-1].stdout_to_pipe
             for stage in statement.stages for file in reader_files(stage)]
    shorthand = _redirect_only_file(text) if not parsed else None
    return files + ([shorthand] if shorthand is not None else [])


def _substitution_reads_file(text):
    return bool(_substitution_files(text))


def _marked_file_handoffs(words, handoff):
    """The command substitutions in `words` that read a file into `handoff`."""
    out = {}
    for word in words:
        for _key, (kind, text) in getattr(word, "markers", {}).items():
            if (kind == "subst" and not isinstance(text, Process)
                    and _substitution_reads_file(text)):
                out[id(text)] = handoff
    return out


def _source_words(stage, before):
    """A directly piped echo/printf source and the words whose values reach `stage`."""
    source = before[-1] if before and _piped(stage, before[-1]) else None
    argv = _argv(source) if source is not None else []
    words = argv[1:] if argv and os.path.basename(argv[0]) in _PRINTERS else []
    return source, words


def _direct_program_words(argv):
    """Program words this reader can execute directly.

    `eval` joins and executes each of its program words, including a substitution embedded in
    literal text.  For a shell's `-c` operand, keep this binding to the all-expansion word: a
    substitution spliced into a larger `-c` string remains #2693's separately pinned gap.
    """
    words = _program_words(argv) + ([] if _MAINS.get() else _added_strings(argv))
    _how, bare = dynamic_program(argv)
    name = os.path.basename(argv[0]) if argv else ""

    if name != "eval":
        return [bare] if bare is not None else []

    def runnable(word):
        text = shell_reader.readable(getattr(word, "spelled", word)).strip()
        refused = text.startswith((";", "&&", "||", "|", "&")) or text.endswith(";;")
        return not refused and (_script(word) is not None or word is bare)

    return [word for word in words if runnable(word)]


def file_handoffs(argv, stage, before=None):
    """File-reading substitutions whose output this command executes as shell text."""
    name = os.path.basename(argv[0]) if argv else ""
    direct = _direct_program_words(argv)
    runner = name if name == "eval" else "%s -c" % name
    out = _marked_file_handoffs(direct, FileHandoff("command substitution", runner))

    file = file_operand(argv)
    entry = file is not None and getattr(file, "markers", {}).get(file)
    if (entry and isinstance(entry[1], Process) and entry[1].direction == "<"
            and _substitution_reads_file(entry[1])):
        out[id(entry[1])] = FileHandoff("process substitution", name)

    source, words = _source_words(stage, before)
    if source is not None:
        out.update(_marked_file_handoffs(
            words,
            FileHandoff("command substitution", name),
        ))
    return out


def redirection_handoffs(argv, stage, before=None):
    """Bash `$(< file)` paths handed directly to this command as programs."""
    name = os.path.basename(argv[0]) if argv else ""
    runner = name if name == "eval" else "%s -c" % name
    sources = [(_direct_program_words(argv), FileHandoff("command substitution", runner))]
    source, words = _source_words(stage, before)
    if source is not None:
        sources.append((words, FileHandoff("command substitution", name)))
    out = []
    for words, handoff in sources:
        for word in words:
            for _key, (kind, text) in getattr(word, "markers", {}).items():
                file = _redirect_only_file(text)
                if kind == "subst" and not isinstance(text, Process) and file is not None:
                    out.append((file, handoff))
    return out


def statement_file_handoffs(statement):
    """Every file-reading substitution a stage of `statement` hands to an executor."""
    out = {}
    for position, stage in enumerate(statement.stages):
        out.update(file_handoffs(_argv(stage), stage, statement.stages[:position]))
    return out


def _bounded_file_words(words):
    """The input files where every dynamic part is a supported file-reading substitution."""
    files: list[str] = []
    for word in words:
        text = str(getattr(word, "spelled", word))
        for key, (kind, value) in getattr(word, "markers", {}).items():
            read = ([] if kind != "subst" or isinstance(value, Process)
                    else _substitution_files(value))
            if not read or any("$" in str(path) or "`" in str(path)
                               or shell_reader.has_substitution(path) for path in read):
                return ()
            files.extend(read)
            text = text.replace(key, "")
        if "$" in text or "`" in text:
            return ()
    return tuple(files)


def file_program_files(word):
    """The bounded file inputs of a dynamic program word, or an empty tuple."""
    return _bounded_file_words([word]) if word else ()


def file_stdin_files(stage, before=None):
    """The bounded file inputs of a printer's otherwise-unread stdin program."""
    source, words = _source_words(stage, before)
    return _bounded_file_words(words) if source is not None else ()
