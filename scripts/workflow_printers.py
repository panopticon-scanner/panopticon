#!/usr/bin/env python3
"""What a printer writes, read as the text a shell is piped (#2333).

Split out of `scripts/workflow_programs.py` (#2331's follow-ups) the way `workflow_posture.py` was
split out of `workflow_gating.py`, so the printer rules grow here and nowhere else: first a pure
move (PR #2699 -- `_piped`, `_PRINTERS` and `printed` byte for byte), then a `cat` with a heredoc or
here-string on its stdin (#2467) and an `echo`/`printf` read the way the step's own shell prints it
(#2476). A pass-through stage between the printer and the shell (#2478) and a printer reaching a
shell through a substitution (#2487, #2495) are still owed. `workflow_programs` re-exports every
name so its callers do not move:

    `_piped`     whether a stage's descriptor 0 finally reads what the stage before it writes
    `_PRINTERS`  the commands whose output is the text of their words
    `printed`    that text, where the words spell it out under the step's shell, or None
    `handed`     the heredoc or here-string a `cat` printer in front hands a stage down the pipe
    `_decoded`   the backslash and `\\0nnn` escapes `echo`/`printf` agree on, decoded, or None
    `_ECHO`      the option words and the default decoding of each shell's `echo` (#2476)

Stdlib only, like everything under it.
"""
import os
import re

import shell_reader


def _piped(stage, before):
    """Whether this stage's descriptor 0 finally reads what `before` writes."""
    return before is not None and before.stdout_to_pipe and stage.stdin_from_pipe


# The commands whose output is the text of their words (#2333). A heredoc-fed
# `cat` is a producer too (#2467), but its text comes from the stage it reads,
# not its words, so it is answered in `printed` and `handed` and never added
# here: every caller that asks "is this a printer" by table membership alone
# (`unprinted`'s `_PRINTERS` half) is right to leave it out.
_PRINTERS = ("echo", "printf")

# echo per shell (#2476): the option words it reads, and whether it decodes escapes by default.
# bash (the GitHub default, `shell=None`) and zsh take `-n`/`-e`/`-E`; bash decodes only with an
# `-e` among them, an `-E` after it turning decoding back off (last letter wins); zsh decodes unless
# an `-E` turns it off. Every OTHER shell (`sh` -- dash on an ubuntu runner -- dash, ash, ksh) takes
# only `-n` and decodes regardless, so `-e`/`-E` are TEXT there (measured: `echo -e x` prints `-e x`
# under dash).
_ECHO_OPTIONS = re.compile("-[neE]+")
_ECHO = {"bash": (_ECHO_OPTIONS, False), "zsh": (_ECHO_OPTIONS, True)}
_ECHO_ELSE = (re.compile("-n+"), True)

# The table `_decoded` reads: a backslash followed by one of these decodes to the byte shown; `\0`
# followed by one to three octal digits decodes to that byte instead (checked separately, below);
# `\c` ends the text there; any OTHER escape -- `\x..`, `\e`, `\u`, `\'`, a trailing lone `\` -- is
# unspelled (fail-closed): dash's `echo` knows no `\x`, bash's `-e` does (measured, b04).
_ESCAPES = {"\\": "\\", "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
_OCTAL = re.compile("[0-7]{1,3}")


def _decoded(text):
    """`text` with the escapes `_ESCAPES` and `\\0nnn` (one to three octal digits) table decode, or
    None where an escape in it is outside that table -- unspelled, fail-closed."""
    out, at, end = [], 0, len(text)
    while at < end:
        char = text[at]
        if char != "\\":
            out.append(char)
            at += 1
            continue
        nxt = text[at + 1:at + 2]
        if nxt == "c":                      # ends the text here; drop it and what follows
            return "".join(out)
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            at += 2
            continue
        if nxt == "0":
            octal = _OCTAL.match(text, at + 2)
            if not octal:
                return None
            out.append(chr(int(octal.group(), 8)))
            at = octal.end()
            continue
        return None                         # `\x`, `\e`, `\u`, `\'`, a trailing lone `\`
    return "".join(out)


def _cat_reads_stdin(argv):
    """Whether `argv` is `cat` reading its own stdin with no option and no file operand (R-P5): a
    bare `cat` or `cat -`; `cat -n` and `cat notes.txt` are no printer."""
    return (bool(argv) and os.path.basename(argv[0]) == "cat"
            and all(getattr(w, "spelled", w) == "-" for w in argv[1:]))


def printed(argv, stage=None, shell=None):
    """The text this `echo`, `printf` or heredoc-fed `cat` writes where its words spell it out
    under the step's shell `shell` (None: the GitHub default, bash), or None.

    `echo` (#2476): the words after the options `_ECHO` gives this shell, joined, and decoded with
    `_decoded` only where that shell decodes by default or an `-e` among the options turns it on
    (`-E` after it turns it back off). Where it does NOT decode, the text comes back exactly as
    written, backslashes and all -- the next reader's to read, as a real shell's word-splitting
    would (`statements("sh\\\\ttool")` reads the one word `shttool`). `printf`: the FORMAT is always
    decoded, in every shell (measured, b10), `%%` first to a literal `%`; a format with no other `%`
    is that decoded text; `%s`/`%s\\n` or `%b`/`%b\\n` with exactly one more word is that word --
    LITERAL for `%s`, decoded with `_decoded` for `%b` -- plus the decoded tail; any other `%` is
    None. `cat` (#2467): a bare `cat` or `cat -` (`_cat_reads_stdin`) with a heredoc or here-string
    on ITS OWN stdin (`stage.stdin_heredoc`) is that body where it is QUOTED; an EXPANDING one is
    None here -- `handed` carries it to `_unread_stdin` instead. None too where `stage` is absent or
    carries no such body, or where a word expands unpredictably (a `$(...)`, a pattern) and is not
    already spelled out (#2342)."""
    if not argv:
        return None
    name = os.path.basename(argv[0])
    if name == "cat":
        if stage is None or stage.stdin_heredoc is None or not _cat_reads_stdin(argv):
            return None
        body, expands = stage.stdin_heredoc
        return None if expands else body
    if name not in _PRINTERS or any(
            shell_reader.dynamic(w, shell_reader.has_substitution) and not hasattr(w, "spelled")
            for w in argv[1:]):
        return None
    words = [getattr(w, "spelled", w) for w in argv[1:]]
    if name == "echo":
        pattern, decode = _ECHO.get(os.path.basename((shell or "bash").split()[0]), _ECHO_ELSE)
        options = 0
        while options < len(words) and pattern.fullmatch(words[options]):
            options += 1
        opts = "".join(words[:options])
        for letter in opts:
            if letter in "eE":
                decode = letter == "e"
        end = "" if "n" in opts else "\n"
        text = " ".join(words[options:])
        text = _decoded(text) if decode else text
        return None if text is None else text + end
    words = words[1:] if words[:1] == ["--"] else words
    if not words or words[0][:1] == "-":
        return None
    fmt = words[0]
    if "%" not in fmt.replace("%%", ""):
        return _decoded(fmt.replace("%%", "%"))
    if fmt[:2] in ("%s", "%b") and fmt[2:] in ("", "\\n") and len(words) == 2:
        tail = _decoded(fmt[2:])
        word = words[1] if fmt[:2] == "%s" else _decoded(words[1])
        return None if tail is None or word is None else word + tail
    return None


def handed(stage, before):
    """The `(body, expands)` a `cat` printer in front hands `stage` down the pipe (#2467), or None:
    `before` must pipe straight into `stage` (`_piped`), read a heredoc or here-string on ITS OWN
    stdin, and be a bare `cat` or `cat -` (`_cat_reads_stdin`, R-P5). The EXPANDING case is what
    `_unread_stdin` reports; `printed` answers only the QUOTED one."""
    if not _piped(stage, before) or before.stdin_heredoc is None:
        return None
    return (before.stdin_heredoc if _cat_reads_stdin(shell_reader.command(before.argv))
            else None)
