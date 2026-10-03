#!/usr/bin/env python3
"""What a printer writes, read as the text a shell is piped (#2333).

Split out of `scripts/workflow_programs.py` (#2331's follow-ups) the way `workflow_posture.py` was
split out of `workflow_gating.py`, so the printer rules grow here and nowhere else: first a pure
move (PR #2699 -- `_piped`, `_PRINTERS` and `printed` byte for byte), then a `cat` with a heredoc or
here-string on its stdin (#2467) and an `echo`/`printf` read the way the step's own shell prints it
(#2476), then fix round 1's `ANY` reading for a runner no row measures (#2467, #2476, review R-F1).
A pass-through stage between the printer and the shell (#2478) and a printer reaching a shell
through a substitution (#2487, #2495) are still owed. `workflow_programs` re-exports every name its
callers use:

    `_piped`     whether a stage's descriptor 0 finally reads what the stage before it writes
    `_PRINTERS`  the commands whose output is the text of their words
    `printed`    that text under ONE reading, where the words spell it out, or None
    `spellings`  the DISTINCT texts `printed` gives under the readings a runner may be (#2476 R-F1)
    `handed`     the heredoc or here-string a `cat` printer in front hands a stage down the pipe
    `ANY`        a runner this module has not measured `echo` under: read both readings, not one

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

# A runner this module has not measured `echo` under (review R-F1): `eval` (which runs in no shell
# of its own), a `$` command word, ksh, ash, busybox, or any other `shell:` -- a lookup miss in
# `_ECHO` below. `spellings` reads such a runner's `echo` under BOTH readings instead of guessing one.
ANY = "any"

# echo per shell (#2476, fix round 1 R-F1/R-F5/M1): the option word(s) it reads, the cap on how many
# may stand (None: as many consecutive ones as match), and whether it decodes by default. Bash
# (GitHub's default, `shell=None`) and zsh (measured here too: `echo -e 'a\tb'` decodes, `echo -E
# 'a\tb'` does not, plain `echo 'a\tb'` decodes) take `-n`/`-e`/`-E`, several together or apart; bash
# decodes only with an `-e` among them, an `-E` after it turning decoding back off (last letter
# wins), zsh decodes unless an `-E` turns it off. `sh` (dash on an ubuntu runner) and dash take
# exactly ONE leading `-n` (M1: measured, `echo -nn x` and `echo -n -n x` both print it) and decode
# regardless, so `-e`/`-E` are TEXT there (measured: `echo -e x` prints `-e x` under dash). A name
# outside this table is `ANY`: unmeasured, read under both rows (`spellings`).
_ECHO_OPTIONS = re.compile("-[neE]+")
_ECHO_N = re.compile("-n")
_ECHO = {"bash": (_ECHO_OPTIONS, False, None), "zsh": (_ECHO_OPTIONS, True, None),
         "sh": (_ECHO_N, True, 1), "dash": (_ECHO_N, True, 1)}

# The table `_decoded` reads in EITHER mode: a backslash followed by one of these decodes to the
# byte shown. A trailing lone `\`, or one followed by anything else outside this table and the
# octal/`\c` rules `_decoded` reads separately, is unspelled (fail-closed): dash's `echo` knows no
# `\x`, bash's `-e` does (measured, b04).
_ESCAPES = {"\\": "\\", "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}
_OCTAL = re.compile("[0-7]{1,3}")


def _decoded(text, fmt=False):
    """`text` with `_ESCAPES` and an octal escape decoded, or None where one outside those is in it
    -- unspelled, fail-closed. In `echo`/`%b` mode (`fmt` False, as both read octal, review C2): an
    octal escape is `\\0` plus up to three MORE digits (`\\0101` decodes whole, one byte); `\\c` ends
    the text there, dropping it and what follows. In a `printf` FORMAT (`fmt` True, review R-F3):
    `\\c` is kept LITERAL, two characters, and does not end the text; an octal escape is `\\` plus ONE
    to THREE digits counting a leading `0` (`\\0043` decodes `\\004`, leaving `3` as text; `\\163`
    decodes whole, both shells read a leading `1`-`7` as one too). Either mode: a decoded NUL is
    DROPPED, as the shell drops it from the script it reads (review R-F4), and a decoded value past
    0x7F is unspelled (the shell emits a raw byte this reader cannot hold, review M2/R-F3)."""
    out, at, end = [], 0, len(text)
    while at < end:
        char = text[at]
        if char != "\\":
            out.append(char)
            at += 1
            continue
        nxt = text[at + 1:at + 2]
        if nxt == "c":
            if not fmt:                     # `echo`/`%b`: ends the text here
                return "".join(out)
            out.append("\\c")               # a printf FORMAT: `\c` prints literally
            at += 2
            continue
        if nxt in _ESCAPES:
            out.append(_ESCAPES[nxt])
            at += 2
            continue
        octal = (_OCTAL.match(text, at + 1) if fmt and nxt in "01234567"
                 else _OCTAL.match(text, at + 2) if not fmt and nxt == "0" else None)
        if not octal:
            return None                      # `\x`, `\e`, `\u`, `\'`, a trailing lone `\`
        value = int(octal.group(), 8)
        if value > 0x7F:
            return None                      # a raw byte past ASCII: unspelled, fail-closed
        if value:                            # a decoded NUL is dropped, as the shell drops it
            out.append(chr(value))
        at = octal.end()
    return "".join(out)


def _cat_reads_stdin(argv):
    """Whether `argv` is a bare `cat` reading its own stdin (R-P5, R-F5): no option word, and
    either no operand at all or a `-` standing among its operands -- `cat -n` is no printer (an
    option), but `cat - f` and `cat f -` both still read stdin, among `f`'s own text (fail-closed
    for the body; `f` stays unread unless it is itself a download, as `cat f | sh` already is)."""
    words = [getattr(w, "spelled", w) for w in argv[1:]]
    return (bool(argv) and os.path.basename(argv[0]) == "cat"
            and not any(w.startswith("-") and w != "-" for w in words)
            and (not words or "-" in words))


def printed(argv, stage=None, shell=None):
    """The text this `echo`, `printf` or heredoc-fed `cat` writes under ONE reading -- `shell`'s,
    where its words spell it out, or None. `spellings` is the one to ask where the runner may be
    more than one shell (#2476 R-F1); this answers a single, already-chosen reading.

    `echo` (#2476): the words after the options `_ECHO` gives this shell (`ANY`, a lookup miss,
    always None here), joined, and decoded with `_decoded` only where that shell decodes by default
    or an `-e` among the options turns it on (`-E` after it turns it back off). Where it does NOT
    decode, the text comes back exactly as written, backslashes and all -- the next reader's to
    read, as a real shell's word-splitting would (`statements("sh\\\\ttool")` reads the one word
    `shttool`). `printf`: the FORMAT is always decoded, in every shell (measured, b10), in FORMAT
    mode (review R-F3), `%%` first to a literal `%`; a format with no other `%` is that decoded
    text; `%s`/`%s\\n` or `%b`/`%b\\n` with exactly one more word is that word -- LITERAL for `%s`,
    decoded in `echo`/`%b` mode for `%b` -- plus the decoded tail; any other `%` is None. `cat`
    (#2467): a bare `cat` or one reading stdin among operands (`_cat_reads_stdin`) with a heredoc or
    here-string on ITS OWN stdin (`stage.stdin_heredoc`) is that body where it is QUOTED; an
    EXPANDING one is None here -- `handed` carries it to `_unread_stdin` instead. None too where
    `stage` is absent or carries no such body, or where a word expands unpredictably (a `$(...)`, a
    pattern) and is not already spelled out (#2342)."""
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
        pattern, decode, cap = _ECHO.get(os.path.basename((shell or "bash").split()[0]),
                                         (None, None, None))
        if pattern is None:
            return None                     # `ANY`, or an unmeasured name asked for directly
        options = 0
        while (options < len(words) and (cap is None or options < cap)
               and pattern.fullmatch(words[options])):
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
        return _decoded(fmt.replace("%%", "%"), fmt=True)
    if fmt[:2] in ("%s", "%b") and fmt[2:] in ("", "\\n") and len(words) == 2:
        tail = _decoded(fmt[2:], fmt=True)
        word = words[1] if fmt[:2] == "%s" else _decoded(words[1])
        return None if tail is None or word is None else word + tail
    return None


def spellings(argv, stage=None, shell=None):
    """The DISTINCT texts `printed` gives this `argv` and `stage` under the readings `shell` may be
    (#2476 fix round 1, R-F1): one, under a shell this module has measured (`_ECHO`'s keys), or for
    `cat`/`printf`/anything that is no `echo`, which read only one way regardless of shell; up to
    two for `echo` under every OTHER runner -- `eval`, a `$` command word, ksh, ash, busybox, any
    `shell:` this module does not model (`ANY`, a lookup miss) -- `printed`'s bash reading and its
    decoding row's (`"sh"`): a download either reading spells is caught, text stays unspelled only
    where BOTH are, and the two collapse to one where they happen to agree. A None reading is kept
    in the list as None: the caller's to know some reading is unspelled, never dropped silently."""
    name = os.path.basename(argv[0]) if argv else ""
    if name != "echo" or os.path.basename((shell or "bash").split()[0]) in _ECHO:
        return [printed(argv, stage, shell)]
    bash, decoding = printed(argv, stage, "bash"), printed(argv, stage, "sh")
    return [bash] if bash == decoding else [bash, decoding]


def handed(stage, before):
    """The `(body, expands)` a `cat` printer in front hands `stage` down the pipe (#2467), or None:
    `before` must pipe straight into `stage` (`_piped`), read a heredoc or here-string on ITS OWN
    stdin, and read its own stdin (`_cat_reads_stdin`, R-P5, R-F5). The EXPANDING case is what
    `_unread_stdin` reports; `printed` answers only the QUOTED one."""
    if not _piped(stage, before) or before.stdin_heredoc is None:
        return None
    return (before.stdin_heredoc if _cat_reads_stdin(shell_reader.command(before.argv))
            else None)
