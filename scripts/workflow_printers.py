#!/usr/bin/env python3
"""What a printer writes, read as the text a shell is piped (#2333).

Split out of `scripts/workflow_programs.py` (#2331's follow-ups) the way `workflow_posture.py` was
split out of `workflow_gating.py`: `workflow_programs` sits at the 700-line flat-module ceiling once
batch V-a (PR #2681) lands, and the printer rules still pending on this epic -- a `cat` with a
heredoc on its stdin (#2467), a pass-through stage between the printer and the shell (#2478), an
`echo` whose escapes the step's shell decides (#2476), a printer reaching a shell through a
substitution (#2487, #2495) -- grow this part and no other. Two pure functions of a stage and its
argv, and the table they share, moved byte for byte; `workflow_programs` re-exports them so its
callers do not move:

    `_piped`     whether a stage's descriptor 0 finally reads what the stage before it writes
    `_PRINTERS`  the commands whose output is the text of their words
    `printed`    that text, where the words spell it out, or None

Stdlib only, like everything under it.
"""
import os
import re

import shell_reader


def _piped(stage, before):
    """Whether this stage's descriptor 0 finally reads what `before` writes."""
    return before is not None and before.stdout_to_pipe and stage.stdin_from_pipe


# The commands whose output is the text of their words (#2333).
_PRINTERS = ("echo", "printf")


def printed(argv):
    """The text this `echo` or `printf` writes where its words spell it out,
    or None: `echo` of words no expansion changes (a `spelled` one's, #2342),
    after the `-n`, `-e` and `-E` bash's `echo` takes, or `printf` of such a
    format with no `%`, or of `%s`, `%s\\n` or `%b` and one such word. A
    backslash is left unspelled where the printer may read it as an escape
    (dash's `echo` does), but a format's `\\n`."""
    if not argv or os.path.basename(argv[0]) not in _PRINTERS or any(
            shell_reader.dynamic(w, shell_reader.has_substitution) and not hasattr(w, "spelled")
            for w in argv[1:]):
        return None
    words = [getattr(w, "spelled", w) for w in argv[1:]]
    if os.path.basename(argv[0]) == "echo":
        options = 0
        while options < len(words) and re.fullmatch("-[neE]+", words[options]):
            options += 1
        end = "" if any("n" in word for word in words[:options]) else "\n"
        text = " ".join(words[options:])
        return None if "\\" in text else text + end
    words = words[1:] if words[:1] == ["--"] else words
    if not words or words[0][:1] == "-":
        return None
    if words[0] in ("%s", "%s\\n") and len(words) == 2:
        return words[1] + words[0][2:].replace("\\n", "\n")
    if "%" in words[0] and not (words[0] == "%b" and len(words) == 2):
        return None
    text = (words[1] if "%" in words[0] else words[0]).replace("\\n", "\n")
    return None if "\\" in text else text
