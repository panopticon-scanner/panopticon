#!/usr/bin/env python3
r"""A step's own literal values read into the two words its readers key on (#2468, #2600, #2601).

`workflow_uses.static_values` reads a USE through the values the step itself assigns (#2425,
#2489). Two readers sit where no use is asked and see only a stage or its pipeline: the printer
rules (`workflow_printers.printed`), which weigh the text `echo "$X" | sh` hands the shell, and
the stdin-program rules (`workflow_programs.stdin_program`, `workflow_forms.flattened`), which
read `$CMD <<'EOF'` as a hand-off to a word no table places, its body read as shell with no
check credited. `annotate` runs ONCE over a step's raw statements, before `flattened` reads them
(`workflow_guard.read`), and marks two kinds of word IN PLACE through the table live at each
statement, so no reader below it changes:

    a command word  the first word `shell_reader.command` keeps (prefix assignments and wrappers
                    off) that is ONE whole reference (`workflow_uses._WHOLE`: `$CMD`, `${CMD}`,
                    `"$CMD"`, as the reader drops quotes) becomes `shell_wrappers.Defaulted`,
                    #2337's marker of a command word read as the NAME it holds: `CMD=sh; $CMD
                    <<'EOF'` reads as `sh <<'EOF'`, gated under its `-e`, and `CMD=true`,
                    `CMD=cat`, `PYTHON=python3` or `NODE=node` as their literal twins (#2600,
                    #2601), behind a wrapper too (`env $CMD`)
    a printer word  a word of an `echo` or `printf` stage (`workflow_printers._PRINTERS`, read
                    after the command word above) that is ONE whole reference gets the reader's
                    `spelled` attribute with the value's text, as `shell_reader._stage` gives a
                    `\$` word one, the word itself kept as written so every other reader sees what
                    it saw: `X='curl … | sh'; echo "$X" | sh` reads as the literal `echo 'curl …
                    | sh' | sh` does (#2468)

Each only where the name holds EXACTLY ONE candidate, not empty, and the word resolves to ONE
literal text (`workflow_values.valued`): no lifted `$(...)`, and nothing a shell expands -- no `$`
(a reference, `$Y` or the stand-in `$X`, an operator expansion `${Y//a/b}`, a `$(...)`, a GitHub
`${{ … }}` the runner fills in), no backquote, no `<(` or `>(`. The shell a printer feeds runs
those where the reader, its quotes gone, reads text: `X='$(echo sh) tool'` after a download keeps
the base's unspelled-printer answer, where its spelled program names no command and reads CLEAN.
A command word's text is a plain name (`_PLAIN`: bash splits and globs an unquoted value, so
`CMD='sh -e'` and `CMD='s*'` are no one command) that `command()` still keeps as the command: an
assignment, keyword or wrapper text (`CMD=X=1`, `W=env`) is left to `workflow_uses` at the use.
Nor is a word marked that the reader keeps as a command where bash runs none: a `case` subject,
or a word of an array literal the reader left unfolded (`a=("$X")` in a `case` arm, #2348).
Anywhere else -- two candidates, the stand-in, `""`, a name the step never assigns, a value that
expands -- the word stays AS WRITTEN and the step reads byte for byte as it did: `Idle`, the
`$CMD` hand-off, the gates-off body, fail-closed.

The prices. Quotes are gone to the reader: a single-quoted printer word `echo '$X' | sh`, which
bash prints as `$X` for a child that holds no `X`, is spelled as the value and over-reports (the
table's quoting price); and a value that expands reads as the base, so `X='echo $(curl … | sh)'`
before `echo "$X" | sh`, which bash runs, stays `Idle` and CLEAN, the base's gap (its literal
twin is reported, unspelled). A value is spelled wherever a printer prints it, the stream going
nowhere too (`echo "$X" > f`); `printed` is asked only where a shell reads a program, so no
answer moves there. A command word read through a value is #2337's `Defaulted`, whose rules come
with it: no option letter is read as its refusal, and a printer in its body reads both ways, so
`X=sh; $X -cK '…'` and `CMD=bash; $CMD <<'EOF'` around `echo 'sh\ttool' | sh` over-report where
the literal twins read CLEAN (the base reported both). The table's own prices carry over: a value
the shell may not assign stays a second candidate, so the word stays as written (`if c; then
X=other; fi`), and `T+=x` on a name the step never assigned holds the known suffix alone. Not
read: a `$(...)` child `workflow_guard._walk` parses, and a `-c`, `eval` or heredoc script
`flattened` parses, are read after `annotate` and inherit no mark -- a first cut, a filed
follow-up; an empty value, which bash drops so the next word runs (`CMD=; $CMD sh <<'EOF'`); a
`${X:-sh}` command word, #2337's default, which `command()` reads before any value; and a whole
`"${a[@]}"`, no one word.

Stdlib only, like everything under it.
"""
import os
import re

import shell_reader
from shell_reader import command
from shell_wrappers import Defaulted
from workflow_printers import _PRINTERS
from workflow_uses import _WHOLE, static_values
from workflow_values import _OPENER, Values, valued

# The name a whole reference reads; what makes a value no literal -- a `$`, a backquote or a
# process substitution, each expanded by the shell that reads it or by the runner; and the plain
# name a command word's value must be, with no blank, pattern, quote or operator in it.
_NAMED = re.compile(r"\$\{?([A-Za-z_]\w*)", re.A)
_EXPANDS = re.compile(r"[$`]|[<>]\(")
_PLAIN = re.compile(r"[\w./+-]+", re.A)


def annotate(stmts):
    """Mark `stmts` in place, in order, through the step's own values, and return them: a command
    word that is one whole reference the table resolves to one literal becomes `Defaulted(text)`,
    and a printer's whole-reference word gets `spelled` (the module docstring has the rule). The
    table at a statement is built only where one of its stages holds such a word."""
    for index, statement in enumerate(stmts):
        table: Values | None = None     # the table at this statement, once a word asks
        for stage in statement.stages:
            argv = command(stage.argv)
            if argv and not _printer(argv):
                for at, word in _references(stage, argv[:1]):
                    table = table or static_values(stmts, index)
                    text = _literal(word, table)
                    if text is not None and _commands(stage, at, text):
                        stage.argv[at] = Defaulted(text)
                argv = command(stage.argv)
            if argv and _printer(argv):
                for at, word in _references(stage, argv[1:]):
                    table = table or static_values(stmts, index)
                    text = _literal(word, table)
                    if text is not None:        # the word as written, its markers kept
                        stage.argv[at] = shell_reader._Token(str(word), shell_reader._markers(word))
                        setattr(stage.argv[at], "spelled", text)
    return stmts


def _printer(argv):
    """Whether `argv` (a command as `command()` keeps it) is an `echo` or a `printf`."""
    return os.path.basename(str(argv[0])) in _PRINTERS


def _references(stage, words):
    """(place in `stage.argv`, word) for each of `words` that is ONE whole reference, found by
    identity in the stage's own argv -- one `command()` made itself (`env -S`) is none -- where
    bash runs the stage's command: not a `case` subject, nor a word of an array literal the
    reader left unfolded (`a=` and its words in an opened group, #2348), which bash assigns."""
    for word in words:
        if _WHOLE.fullmatch(str(word)) and not hasattr(word, "spelled"):
            at = next((at for at, item in enumerate(stage.argv) if item is word), None)
            if at is None or stage.argv[at - 1:at] == ["case"] or stage.group_open and any(
                    _OPENER.match(str(item)) for item in stage.argv[:at]):
                continue
            yield at, word


def _literal(word, table):
    """The ONE literal text whole reference `word` stands for through `table`, or None: its name
    holds one candidate, not empty, and the word resolves to one text with no lifted `$(...)`, no
    `$`, no backquote and no process substitution (`_EXPANDS`)."""
    named = _NAMED.match(str(word))
    name = named[1] if named else ""
    held = [*table.scalars.get(name, []), *table.arrays.get(name, [])]
    if len(held) != 1 or not held[0]:
        return None
    texts = valued(word, table)
    if len(texts) != 1:
        return None
    text = texts[0]
    if not text or shell_reader.is_marker(text) or _EXPANDS.search(text):
        return None
    return str(text)


def _commands(stage, at, text):
    """Whether `text` in place of the command word at `stage.argv[at]` is one command bash runs
    and the reader keeps as the command: a plain name (`_PLAIN`: no blank, pattern, quote or
    operator), and not a word `command()` reads past (an assignment, a keyword, a wrapper)."""
    if not _PLAIN.fullmatch(text):
        return False
    trial = list(stage.argv)
    trial[at] = marked = Defaulted(text)
    kept = command(trial)
    return bool(kept) and kept[0] is marked
