#!/usr/bin/env python3
"""What a printer writes, read as the text a shell is piped (#2333).

Split out of `scripts/workflow_programs.py` (#2331's follow-ups) the way `workflow_posture.py` was
split out of `workflow_gating.py`, so the printer rules grow here and nowhere else: first a pure
move (PR #2699 -- `_piped`, `_PRINTERS` and `printed` byte for byte), then a `cat` with a heredoc
or here-string on its stdin (#2467) and an `echo`/`printf` read the way the shell that RUNS the
printer prints it (`ANY`/`Named` where that is not one measured shell) (#2476), then fix round 1's
`ANY` reading for a runner no row measures (#2467, #2476, review R-F1), then a pass-through stage
between the printer and the shell (#2478), then a printer reaching a shell through a substitution:
a `$(...)` in a `-c` or `eval` string, a `<(...)` a shell or `source` reads as its FILE (#2487,
#2495). `workflow_programs` re-exports the names its callers use, bar `fed` and `operand`, which
`workflow_guard` imports from here:

    `_piped`     whether a stage's descriptor 0 finally reads what the stage before it writes
    `_PRINTERS`  the commands whose output is the text of their words
    `printed`    that text under ONE reading, where the words spell it out, or None
    `spellings`  the DISTINCT texts `printed` gives under the readings a runner may be (#2476 R-F1)
    `producer`   the printer a stage's pipeline feeds it from, and whether every stage between is
                 a pass-through (`_passes_through`: `tee` writing plain files, a bare `cat`)
                 handing it on unchanged -- unknown (None) where the walk stops at `_DEPTH`
    `handed`     the heredoc or here-string a `cat` printer in front hands a stage down the pipe
    `unspelled`  what `unprinted` hands `unread_program`: a name, then texts it weighs each apart
                 (N-1) -- an unspelled printer's words, or, where a stage between rewrites the
                 text, that text and the stage's words (I-1), or past `_DEPTH` a LOUD stand-in
                 (`_PAST_DEPTH`, fix round 1b)
    `substituted`  the text a substitution's script prints where it is ONE printer and every
                 reading agrees on it (R-P3), or None; `rendered`, a word with each such `$(...)`
                 replaced by that text -- no backquote whose text escapes `$`, `` ` ``, `"`, `\\` or
                 a newline, and none where the reader refuses the result -- beside which
                 `dynamic_program` still reports a word all substitution (review C-1 to C-3);
                 `file_operand`, the word a shell or `source` reads its program from as a FILE, and
                 `operand`, the script of a `<(...)` there
    `unsubstituted`  the `echo`/`printf` alone in such a script that `substituted` cannot spell,
                 as `unspelled` names one; `fed`, the heredoc a `cat` alone in it prints
    `ANY`        a runner this module has not measured `echo` under: read both readings, not one
    `Named`      a holder's NAME, read as `ANY` for the printers alone (R-F7)

Stdlib only, like everything under it.
"""
import os
import re

import shell_lex
import shell_reader
import shell_text


def _piped(stage, before):
    """Whether this stage's descriptor 0 finally reads what `before` writes."""
    return before is not None and before.stdout_to_pipe and stage.stdin_from_pipe


# The commands whose output is the text of their words (#2333). A heredoc-fed `cat` prints a text
# too (#2467), but from its stdin, not its words, so it is never added here: `printed`, `handed`
# and `producer` answer it beside this table. A caller asking "is this a printer" of the table
# alone is right to leave it out -- `unspelled` (for `unprinted`) asks it of a source whose text
# arrives intact, where only an `echo` or `printf` can be unspelled; where a stage between
# rewrites the text, it returns that stage whatever the source, and weighs a `cat`'s body too.
_PRINTERS = ("echo", "printf")

# A runner this module has not measured `echo` under (review R-F1): `eval` (which runs in no shell
# of its own), a `$` command word, ksh, ash, busybox, or any other `shell:` -- a lookup miss in
# `_ECHO` below. `spellings` reads such a runner's `echo` under BOTH readings instead of guessing one.
ANY = "any"


class Named(str):
    """A runner's NAME as `workflow_forms.flattened`'s sentences print it (`_UNGATED` and kin name the
    holder: `bash`, `eval`, `$CMD`), whose `echo` the printers read as `runner` instead: `ANY` where the
    holder's `-c`/`eval` string names the shell that reads the body (`bash -c 'sh'`, #2500, R-F7)."""
    runner: str = ANY


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
    """Whether `argv` is a `cat` reading its own stdin (R-P5, R-F5, R-F14): no operand, or a `-`
    among its operands -- every word after the FIRST `--` (R-F10: it ends the options, itself none),
    and before it each `-` or word not beginning with `-`. So `cat - f` and `cat f -` read stdin
    among `f`'s own text (fail-closed for the body; `f` stays unread unless it is itself a download,
    as `cat f | sh` already is), and an option word changes nothing: the body is read whole, as
    `-u`, `-s` and `-v` (ASCII) print it. The price, over-reported: `-n`/`-b` number each line, so
    its first command never runs, `-e` (GNU's `-E`/`-A`) ends it with `$`, spoiling its last word,
    BSD's `cat` prints nothing given `-E`, `-T`, `-A` or a piped `-l`, and GNU refuses `-l` too;
    `--help`/`--version` print their own text and read nothing (GNU; BSD refuses them)."""
    words = [getattr(w, "spelled", w) for w in argv[1:]]
    at = words.index("--") if "--" in words else len(words)
    operands = [w for w in words[:at] if w == "-" or not w.startswith("-")] + words[at + 1:]
    return bool(argv) and os.path.basename(argv[0]) == "cat" and (not operands or "-" in operands)


def _reading(shell):
    """The `_ECHO` row a runner is read under: `shell`'s basename (None: bash, GitHub's default), or the
    `runner` a `Named` one carries for the printers (`ANY` where a string names the shell, R-F7)."""
    shell = getattr(shell, "runner", shell)
    return os.path.basename((shell or "bash").split()[0])


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
    (#2467): one reading its own stdin, options or not (`_cat_reads_stdin`), with a heredoc or
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
        pattern, decode, cap = _ECHO.get(_reading(shell), (None, None, None))
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
    if name != "echo" or _reading(shell) in _ECHO:
        return [printed(argv, stage, shell)]
    bash, decoding = printed(argv, stage, "bash"), printed(argv, stage, "sh")
    return [bash] if bash == decoding else [bash, decoding]


# The options a `tee` takes that leave the text it hands on as it read it (#2478): append to the
# files rather than truncate them, and what to do on a write error or an interrupt.
_TEE_OPTIONS = ("-a", "-p", "-i", "--append")


def _passes_through(argv, stage):
    """Whether this stage hands what its stdin reads on to its stdout UNCHANGED (#2478): a `tee`
    whose words are all plain -- no marker, no `$` value, no pattern (`shell_reader.dynamic`: a
    `>(...)` operand may write into the stream too) -- each a FILE operand or one of
    `_TEE_OPTIONS`, `--output-error` or `--output-error=…`, and no operand the pipe itself
    (`shell_reader._STDOUT_ALIASES`: `tee /dev/stdout` hands the text on twice, review I-3a); or
    a `cat` reading its own stdin (`_cat_reads_stdin`) with no heredoc or here-string there and no
    OPTION word -- only `-` and the `--` that ends the options (R-P5): `cat -n` numbers the lines
    it hands on. Neither behind `xargs` (`shell_reader.wrapper_words`, review I-2), which hands
    `cat` the piped words as FILE operands: of the wrappers the reader strips it alone changes WHAT
    the command reads, where `sudo tee f`, `nice cat` or `stdbuf -oL tee f` changes only how it
    runs, and passes (fix round 1b). Any other stage that reads the pipe -- `tr`, `sed`,
    `base64 -d`, `tee -x`, `tee >(...)`, `cat file` -- rewrites or adds to the text, and a shell
    after it reads a program no printer's words spell out."""
    name = os.path.basename(argv[0]) if argv else ""
    # A `tee` or `cat` is no wrapper, so where `shell_reader.command` hands back the stage's own
    # first word, nothing stood in front of it and there is no wrapper to ask `wrapper_words`
    # about (asking at every stage made a long `cat` chain 1.5x slower). Not a length test:
    # `command` can SPLICE as well as strip -- `env -S 'xargs cat - -'` (`--split-string=`) gives
    # back as many words as the stage has, `xargs` among the wrappers (review N-2).
    if name not in ("tee", "cat") or (argv[:1] != stage.argv[:1] and any(
            os.path.basename(w) == "xargs" for w in shell_reader.wrapper_words(stage.argv))):
        return False
    if any(shell_reader.dynamic(w, shell_reader.has_substitution) or shell_reader.is_marker(w)
           for w in argv[1:]):
        return False
    words = [getattr(w, "spelled", w) for w in argv[1:]]
    if name == "tee":
        return all((not w.startswith("-") and w not in shell_reader._STDOUT_ALIASES)
                   or w in _TEE_OPTIONS or w == "--output-error"
                   or w.startswith("--output-error=") for w in words)
    if stage.stdin_heredoc is not None or not _cat_reads_stdin(argv):
        return False
    at = words.index("--") if "--" in words else len(words)
    return all(w == "-" for w in words[:at] + words[at + 1:])


# How many stages `producer` walks back before it stops looking (#2478), as `_stdin` reads 64
# strings deep (final review F1): every stage of a pipeline asks, so an unbounded walk made a long
# one quadratic -- 2 s for 800 `cat`s, which the guard read in 0.04 s before the walk.
_DEPTH = 64

# What `unspelled` hands `unread_program` where `producer` stopped at `_DEPTH` (fix round 1b): the
# sentence names the reason, and the text weighed is a program named by a value and run behind a
# wrapper -- one `workflow_guard._walk` "cannot read" -- so the answer is LOUD alone. The program
# may come from any stage further back, a printer whose text fetches or none at all, so it is
# never `_Quiet` there, and never CLEAN for want of a printer further back.
_PAST_DEPTH = ("a pipeline longer than the %d stages this guard follows" % _DEPTH,
               'exec "$PROGRAM"')


def producer(stage, before):
    """`(source, intact)`: the printer whose text reaches `stage`'s stdin down its pipeline, and
    whether every stage between hands that text on unchanged (#2478) -- or `(None, False)`.
    `before` is the LIST of stages in front of `stage` in its pipeline, in order (None or `[]`:
    nothing in front). The walk goes back from the last: each stage in front must pipe into the
    one after it (`_piped`, pairwise), or the walk ends with no source. A PRINTER in front -- an
    `echo` or `printf` (`_PRINTERS`), or a `cat` reading its own stdin with a heredoc or
    here-string there (#2467) -- is the source. A PASS-THROUGH (`_passes_through`: `tee f`,
    `tee -a f`, a bare `cat` or `cat -`) keeps `intact`, so `echo 'sh tool' | tee log | sh` reads
    as `echo 'sh tool' | sh`; any other stage clears it, and the walk goes on through it, so a
    printer behind `base64 -d` is still found: its program is UNREAD (`unprinted`), never read as
    the printer's words (R-P4), though a fetch in them is weighed (`unspelled`, review I-1).
    Running out of stages is no source. Past `_DEPTH` stages the walk stops, fail-closed: the
    stage it reached stands as the source with `intact` None -- neither intact nor rewritten, but
    unknown -- which `handed` and `stdin_scripts` read as not intact and `unspelled` answers LOUD
    (`_PAST_DEPTH`): never read, and never CLEAN for want of a printer further back."""
    intact, current = True, stage
    for walked, front in enumerate(reversed(before or [])):
        if not _piped(current, front):
            return None, False
        if walked == _DEPTH:
            return front, None              # too far back to look: unknown, fail-closed
        argv = shell_reader.command(front.argv)
        if ((bool(argv) and os.path.basename(argv[0]) in _PRINTERS)
                or (front.stdin_heredoc is not None and _cat_reads_stdin(argv))):
            return front, intact
        intact = intact and _passes_through(argv, front)
        current = front
    return None, False


def handed(stage, before):
    """The `(body, expands)` a `cat` printer hands `stage` down the pipe (#2467), or None: the
    source `producer` finds behind `before` (the stages in front, through pass-throughs, #2478),
    with `intact` True, must read a heredoc or here-string on ITS OWN stdin, and read its own
    stdin, options or not (`_cat_reads_stdin`, R-P5, R-F5, R-F14). The EXPANDING case is what
    `_unread_stdin` reports; `printed` answers only the QUOTED one."""
    source, intact = producer(stage, before)
    if not intact or source.stdin_heredoc is None:
        return None
    return (source.stdin_heredoc if _cat_reads_stdin(shell_reader.command(source.argv))
            else None)


def unspelled(stage, before, shell=None):
    """What `workflow_forms.unread_program` weighs for the program `stage` (a shell's) reads down
    its pipeline where no printer's words spell it out, or [] -- the answer of
    `workflow_programs.unprinted` once it knows the stage is a shell reading stdin (#2478): the
    NAME the sentence gives, then the TEXTS `unread_program` walks, each on its own, so a quote or
    an open `case` in one cannot hide another (review N-1):

    * the source `producer` finds behind `before` arrives INTACT: where it is an `echo` or
      `printf` some reading `spellings` gives does not spell out (`echo "$X" | sh`, an escape
      outside `_decoded`'s table, either reading of a `Named`/`ANY` runner: #2333, #2476 R-F1),
      its name and its words as ONE text, else [] -- a heredoc-fed `cat` is never unspelled:
      `printed` spells its QUOTED body whole and `_unread_stdin` reports its EXPANDING one (#2467,
      R-F13);
    * a stage between REWRITES it (`base64 -d`, R-P4): the name of the stage the shell reads from
      -- the one the sentence names -- then what the source put on the pipe (#2478 fix round 1,
      review I-1), each reading `spellings` gives of an `echo` or `printf` a text of its own (its
      words where a reading spells none, as an unspelled printer's are weighed), or a `cat`'s
      heredoc or here-string body; LAST, that stage's other words as one text. A fetch in either
      makes the answer LOUD: `echo 'curl … | sh' | tr -d X | sh` is reported alone, and so is
      `echo "it's" | w curl … | sh` behind a function `w` (rr09), where the `_Quiet` answer for
      `echo 'sh tool' | tr a-z A-Z | sh` stands only beside a reported download. The gap: that
      stage's words are joined as the reader hands them, quotes removed, so a quote or a space
      inside one of them can hide a fetch after it (`w env 'A=say "hi' curl …`, fy01);
    * the walk stopped at `_DEPTH` (`intact` None): `_PAST_DEPTH`, LOUD alone (fix round 1b) --
      the price is a harmless printer that far back (`echo 'echo hi'` behind 64 `cat`s), and a
      second row beside a stream's own sentence (a `curl … | sh` stream through 70 `cat`s).

    A stage with no command word in front (`echo x | X=1 | sh`) prints nothing: []."""
    source, intact = producer(stage, before)
    if source is None:
        return []
    words = shell_reader.command(source.argv)
    printer = bool(words) and os.path.basename(words[0]) in _PRINTERS
    if intact:
        return ([words[0], " ".join(words[1:])]
                if printer and None in spellings(words, source, shell) else [])
    front = shell_reader.command(before[-1].argv)
    if not front:
        return []
    if intact is None:
        return list(_PAST_DEPTH)
    if printer:
        texts = [" ".join(words[1:]) if t is None else t for t in spellings(words, source, shell)]
    else:
        texts = [source.stdin_heredoc[0]]       # not a printer: a heredoc-fed `cat` (`producer`)
    return front[:1] + texts + [" ".join(front[1:])]


def _printer(value):
    """`(argv, stage)` of the ONE printer the script `value` is -- one statement of one stage, an
    `echo` or `printf` (`_PRINTERS`) or a `cat` reading a heredoc or here-string on its own stdin
    (#2467), whose descriptor 1 still writes what the substitution hands on (`stdout_to_pipe`:
    `echo x >&2` or `echo x > f` hands on nothing) -- or None. `value` is a lifted substitution's
    text (`shell_text.Lifted` carries its heredocs back to the parse, #2336); a text the reader
    refuses is no printer."""
    try:
        parsed = shell_reader.statements(value) if value is not None else []
    except shell_lex.Unreadable:
        return None
    if len(parsed) != 1 or len(parsed[0].stages) != 1:
        return None
    stage = parsed[0].stages[0]
    argv = shell_reader.command(stage.argv)
    name = os.path.basename(argv[0]) if argv else ""
    if name not in _PRINTERS and (stage.stdin_heredoc is None or not _cat_reads_stdin(argv)):
        return None
    return (argv, stage) if stage.stdout_to_pipe else None


def substituted(value):
    """The text the ONE printer a substitution's script `value` is writes (`_printer`, #2487,
    #2495), or None: the same text under every reading `spellings` gives (R-P3), since what runs a
    substitution's printer is not followed here -- the step's shell for `eval "$(…)"`, bash for a
    `<(…)`. So `echo 'sh tool'`, a `printf` format (decoded in every shell) and a QUOTED heredoc on
    a `cat` are spelled; `echo 'sh\\ttool'`, which bash prints as written and dash decodes, is not,
    and neither is an EXPANDING heredoc (`fed` has it) nor anything `printed` cannot spell."""
    found = _printer(value)
    readings = spellings(found[0], found[1], ANY) if found else [None]
    return readings[0] if len(readings) == 1 else None


def unsubstituted(value):
    """The name and text `workflow_programs.unprinted` hands `unread_program` for the `echo` or
    `printf` alone in the script `value` where `substituted` cannot spell it, its words as ONE
    text as `unspelled` weighs an unspelled printer's (`sh <(echo "$X")`), else []. Never a `cat`:
    `substituted` spells its QUOTED heredoc, and `fed` hands the guard its EXPANDING one."""
    found = _printer(value)
    if not found or os.path.basename(found[0][0]) not in _PRINTERS:
        return []
    return [] if substituted(value) is not None else [found[0][0], " ".join(found[0][1:])]


def fed(value):
    """The `(body, expands)` of the heredoc or here-string a `cat` alone in the script `value`
    prints (`_printer`, #2495), or None: `workflow_guard._unread_stdin` reports an EXPANDING one a
    shell reads as its FILE (`bash <(cat <<EOF …)`) as it reports `cat <<EOF | sh`."""
    found = _printer(value)
    return (found[1].stdin_heredoc
            if found and os.path.basename(found[0][0]) not in _PRINTERS else None)


def rendered(word):
    """`word`'s text with each lifted `$(...)` or backquote whose script is one printer
    `substituted` spells replaced by that text, its trailing newlines dropped as a command
    substitution drops them, and every other substitution -- a `<(...)` or `>(...)` always, which
    hands a FILE, never its text -- rendered `$(...)`, as `shell_reader.readable` renders them all.
    `eval "$(echo 'sh tool')"` and `eval "sh $(echo tool)"` are both `sh tool`. A backquote whose
    text escapes `$`, `` ` ``, `"`, `\\` or a newline is not replaced: bash removes that backslash
    (a newline with it) before it runs the text, which the reader lifts raw (review C-2) -- the one
    before `"` only inside double quotes, but the marker keeps no quoting, so it counts in both. Any
    other backslash stays, so `` `printf 'sh tool\\n'` `` is read (re-review N-1). Where the reader
    refuses the text so written, the word is `readable`'s (C-1). The reader keeps no quoting for a
    lifted substitution, so an unquoted one is rendered as a quoted one is, unsplit, though bash
    splits its text into fields: `eval` joins them with spaces, so a newline or tab in it is read
    where bash reads a space, and `-c` runs only the first, the rest its `$0`, `$1`, …, so
    `sh -c $(echo 'curl … | sh')` over-reports (C-2(b), documented). No read here stands alone --
    `workflow_programs.dynamic_program` still reports a word all substitution beside it, the
    catch-all (C-1 to C-3), so the design's "no `Idle` row beside the read" is overruled."""
    text = word
    for key, (kind, value) in getattr(word, "markers", {}).items():
        if kind == "subst":
            spelled = (substituted(value)
                       if shell_reader.yields_words(shell_reader.derived(key, word))
                       and (isinstance(value, shell_text.Lifted)
                            or not re.search(r'\\[$`"\\\n]', value)) else None)
            text = text.replace(key, "$(...)" if spelled is None else spelled.rstrip("\n"))
    try:
        shell_reader.statements(text)
    except shell_lex.Unreadable:
        return shell_reader.readable(word)
    return text


def file_operand(argv):
    """The word this command reads its PROGRAM from as a FILE (#2487, #2495), or None: `source`'s
    or `.`'s first word, or a literal shell's (`sh`, `bash`, `dash`, `ash`, `ksh`, `zsh`) first
    operand past its option words and the value each `o` or `O` in one owes (`bash -o pipefail
    f`) -- None where `-c` or `-s` among its letters, a `-` or `--`, or a word that is a value
    (`$X`, a lifted `$(...)`) stands first, or no operand does."""
    name = os.path.basename(argv[0]) if argv else ""
    if name in ("source", "."):
        return argv[1] if argv[1:] else None
    owed = 0
    for word in argv[1:] if name in shell_reader._SHELLS else []:
        if owed:
            owed -= 1
        elif word in ("-", "--"):
            return None
        elif word[:1] in ("-", "+"):
            letters = "" if word[:2] in ("--", "++") else word[1:]
            if "c" in letters or "s" in letters:
                return None
            owed = sum(letter in "oO" for letter in letters)
        else:
            return None if _filed(word) is None and shell_reader.dynamic(
                word, shell_reader.has_substitution) else word
    return None


def _filed(word):
    """The script of `word` where it is ONE lifted `<(...)`, whole -- what bash runs to fill the
    file it hands the command -- or None. A `>(...)` is taken for one: the reader keeps no
    direction (`shell_text.Process`), so `sh >(echo 'sh tool')` over-reports (review m-3)."""
    entry = getattr(word, "markers", {}).get(word)
    return (entry[1] if entry and entry[0] == "subst" and not shell_reader.yields_words(word)
            else None)


def operand(argv):
    """The script of the `<(...)` that is `argv`'s whole FILE operand (`file_operand`, `_filed`):
    what bash runs to fill the file a shell or `source` then reads its program from, or None."""
    return _filed(file_operand(argv))
