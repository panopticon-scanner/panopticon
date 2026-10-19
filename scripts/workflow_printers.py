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
    `group_reading`  BESIDE `producer`'s answer, never instead of it (#3026): what a `{ ...; }` or `( ...; )`
                 group closing in front of a stage writes from the statements `producer`'s walk never
                 reaches -- read back through the statements in front (`_grouped`) -- spelled per reading,
                 an unspelled printer's words, or, where a statement there is no printer, LOUD
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

`_decoded` with its tables, and what an unspelled printer WRITES (`_written`, `_formatted`, `_echoed`
and their tables, #2955), live in `scripts/workflow_printer_writes.py` (#3013), split out at this
module's size and imported back here, so no caller moved; the walk back through a group piped to a
shell (#3026, #3117) and the pipe's plumbing it rests on (`_piped`, `_passes_through`) live in
`scripts/workflow_groups.py` (#3117), split out the same way.

Stdlib only, like everything under it.
"""
import os
import re

import shell_lex
import shell_reader
import shell_text
from workflow_options import _MAINS
from workflow_groups import (_CALL_REACH as _CALL_REACH, _GROUP_LINES as _GROUP_LINES, _Header as _Header,
                             _PAST_GROUP as _PAST_GROUP, _PastGroup as _PastGroup, _TEE_OPTIONS as _TEE_OPTIONS,
                             _behind as _behind, _cat_reads_stdin as _cat_reads_stdin, _closing as _closing,
                             _fed as _fed, _function_body as _function_body, _grouped as _grouped, _kin as _kin,
                             _own as _own, _passes_through as _passes_through, _past as _past, _piped as _piped,
                             _silent as _silent, _stopped as _stopped, _stripped as _stripped,
                             _structure as _structure, _walk as _walk, piped_group_member as piped_group_member)
from workflow_printer_writes import (_CONVERSION as _CONVERSION, _COUNT as _COUNT,
                                     _ESCAPE as _ESCAPE, _ESCAPES as _ESCAPES, _KNOWN as _KNOWN,
                                     _LONG as _LONG, _OCTAL as _OCTAL, _PAD as _PAD,
                                     _PLAIN as _PLAIN, _WRITERS as _WRITERS, _decoded as _decoded,
                                     _echoed as _echoed, _formatted as _formatted,
                                     _written as _written)


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


class SpelledOutput(str):
    """A written file's already-spelled printer output.

    The file binder has already run ``spellings`` over every writer. Keeping
    that result tagged avoids parsing one synthetic ``printf`` with the whole
    file in a single shell word before the actual file text is parsed.
    """


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
    pattern) and is not already spelled out (#2342; a `$(...)` never is, #2466)."""
    if not argv:
        return None
    name = os.path.basename(argv[0])
    if name == "cat":
        if stage is None or stage.stdin_heredoc is None or not _cat_reads_stdin(argv):
            return None
        body, expands = stage.stdin_heredoc
        return None if expands else body
    if name not in _PRINTERS or any(
            shell_reader.has_substitution(w) or shell_reader.dynamic(
                w, shell_reader.has_substitution) and not hasattr(w, "spelled") for w in argv[1:]):
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


_GROUPED = ("a group of statements whose text no one printer spells out",
            'exec "$PROGRAM"')


class StatementFront:
    """A statement prefix, iterable both ways without a list slice.

    The program readers ask once per stage; copying every growing prefix made
    a large handed script quadratic even when no stage consumed the prefix.
    """

    __slots__ = ("stmts", "end")

    def __init__(self, stmts, end):
        self.stmts, self.end = stmts, end

    def __reversed__(self):
        return (self.stmts[at] for at in range(self.end - 1, -1, -1))

    def __iter__(self):
        return (self.stmts[at] for at in range(self.end))

    def __len__(self):
        return self.end

    def __getitem__(self, index):
        if index < 0:
            index += self.end
        if not 0 <= index < self.end:
            raise IndexError(index)
        return self.stmts[index]


def _printer_of(pipeline):
    """The printer stage whose text leaves this pipeline, back through pass-through stages, or None: an `echo`
    or `printf` by the stage's own words (`shell_reader.command`), or a `cat` reading its own heredoc."""
    for at in range(len(pipeline) - 1, -1, -1):
        stage = pipeline[at]
        argv = shell_reader.command(stage.argv)
        if argv and (os.path.basename(argv[0]) in _PRINTERS
                     or stage.stdin_heredoc is not None and _cat_reads_stdin(argv)):
            return stage
        if not at or not _passes_through(argv, stage) or not _piped(stage, pipeline[at - 1]):
            return None
    return None


def group_reading(stage, before, shell=None, statements=None):
    """`(texts, words)` a group closing in front of `stage` adds BESIDE `producer`'s answer (#3026), or None.

    `_grouped` gives the group's pipelines `producer` does not reach; with none a printer, the group is no
    printer's (a download in it is the stream reader's, #2430): None. Where every one ends in a printer, `texts`
    are their texts joined in order, one per reading the runner `shell` may be -- all the printers of one group
    run under one shell, so a reading is taken for them all, never mixed, and two at most -- and `words`, where a
    reading spells none, what `unspelled` weighs for an unspelled printer: the first one's name, then each one's
    words as one text and apart. Where one is no printer (`{ echo ok; cat f; } | sh`), `words` is `_GROUPED`,
    LOUD, fail-closed: its text is not read. A compound header's own test command (`if echo P; then :; fi | sh`,
    a `_Header`, #3153 item 2) is read BESIDE that answer, never instead: the group read with it (`_beside`)."""
    front = before[-1] if before else None
    if front is None or not _piped(stage, front):
        return None
    at = len(before) - 1            # back through pass-through stages to the closer (`} | cat | sh`, #3117)
    while at and _passes_through(shell_reader.command(before[at].argv), before[at]) and _piped(before[at], before[at - 1]):
        at -= 1
    front = before[at]
    pipelines = _grouped(front, before[:at + 1], statements, True)
    if _stopped(pipelines):
        return [], list(_PAST_GROUP)        # bounded, fail-closed: never read, never CLEAN (#3117)
    body = [p for p in pipelines or () if not isinstance(p, _Header)]
    found = _group_texts(body, shell)
    if len(body) == len(pipelines or ()):
        return found
    return _beside(found, _group_texts([p for p in pipelines if not _noop(p)], shell))


_NOOPS = (":", "true", "false")         # what writes nothing, whatever its words


def _noop(pipeline):
    """Whether `pipeline` is one stage that writes nothing (`_NOOPS`): passed over where a header's test command
    is read beside the body (#3153 item 2), so `if echo P; then :; fi | sh` reads as `{ echo P; } | sh` does."""
    argv = shell_reader.command(pipeline[0].argv) if len(pipeline) == 1 else []
    return bool(argv) and str(argv[0]) in _NOOPS          # a bare name: the builtin, never a file of that name


def _group_texts(pipelines, shell):
    """`group_reading`'s answer for these pipelines of a group: None where none ends in a printer, `_GROUPED`
    where one does not, else their texts, one per reading, and the words `unspelled` weighs where one spells none
    -- `main`'s words, then the values a weighed word holds as the printer writes them (`_inherited`, #3153)."""
    printers = [_printer_of(p) for p in pipelines]
    if not any(printers):
        return None
    if not all(printers):
        return [], list(_GROUPED)
    argvs = [shell_reader.command(p.argv) for p in printers]
    echoes = any(os.path.basename(a[0]) == "echo" for a in argvs)
    readings = ["bash", "sh"] if echoes and _reading(shell) not in _ECHO else [shell]
    texts, unread = [], False
    for reading in readings:
        parts = [printed(a, p, reading) for a, p in zip(argvs, printers)]
        if None in parts:
            unread = True
        elif "".join(parts) not in texts:
            texts.append("".join(parts))
    words = ([argvs[0][0]] + [" ".join(a[1:]) for a in argvs] + [t for a in argvs for t in _apart(a, shell)]
             + [t for a in argvs for t in _inherited(a, shell)] if unread else [])
    return texts, words


def _beside(found, more):
    """`group_reading`'s answer `found` and the one `more` the group gives with its headers' test commands read
    (#3153 item 2), together: `found`'s texts and words first and as they stand, then `more`'s not among them --
    BESIDE, never instead, so a reading `found` gives is never lost to `more`'s LOUD one; None where both are."""
    if found is None or more is None:
        return more if found is None else found
    texts = found[0] + [t for t in more[0] if t not in found[0]]
    name = found[1][:1] or more[1][:1]
    rest = found[1][1:] + [w for w in more[1][1:] if w not in found[1][1:]]
    return texts, (name + rest if name else [])


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
        argv = shell_reader.acted(front.argv)
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
    return (source.stdin_heredoc if _cat_reads_stdin(shell_reader.acted(source.argv))
            else None)


def unspelled(stage, before, shell=None, statements=None):
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

    BESIDE all this (#3026), never instead of it: what `group_reading` weighs for a group closing in front --
    its unspelled printers' words, or `_GROUPED` -- after this answer's texts, or alone where it has none.

    A stage with no command word in front (`echo x | X=1 | sh`) prints nothing: []."""
    group = group_reading(stage, before, shell, statements)
    if group and group[1]:
        mains = unspelled(stage, before, shell)
        return mains + group[1][1:] if mains else group[1]
    source, intact = producer(stage, before)
    if source is None:
        return []
    words = shell_reader.acted(source.argv)
    printer = bool(words) and os.path.basename(words[0]) in _PRINTERS
    if intact:
        return ([words[0], " ".join(words[1:])] + _apart(words, shell) + _inherited(words, shell)
                if printer and None in spellings(words, source, shell) else [])
    front = shell_reader.command(before[-1].argv)
    if not front:
        return []
    if intact is None:
        return list(_PAST_DEPTH)
    if printer:
        read = spellings(words, source, shell)
        texts = [" ".join(words[1:]) if t is None else t for t in read]
        texts += _apart(words, shell) + _inherited(words, shell) if None in read else []    # as above (#2955)
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
    argv = shell_reader.acted(stage.argv)
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
    if isinstance(value, SpelledOutput):
        return str(value)
    found = _printer(value)
    if found is None:
        return _group_substituted(value)
    readings = spellings(found[0], found[1], ANY)
    return readings[0] if len(readings) == 1 else None


def _group_substituted(value):
    """The text a substitution's script writes where it is ONE group of printers (#3117: `sh <({ P; })`), the
    same under every reading, else None: the script's statements must open a `{ ... }` or `( ... )` group and
    close it with their last statement, and every pipeline in it end in a spelled printer."""
    try:
        parsed = shell_reader.statements(value) if value is not None else []
    except shell_lex.Unreadable:
        return None
    if len(parsed) < 2 or not parsed[-1].stages:
        return None
    front = parsed[-1].stages[-1]
    pipelines = _grouped(front, [front], parsed)
    if not pipelines or _stopped(pipelines):
        return None
    printers = [_printer_of(p) for p in pipelines]
    if not all(printers):
        return None
    texts = set()
    for reading in ("bash", "sh"):
        parts = [printed(shell_reader.command(p.argv), p, reading) for p in printers]
        if None in parts:
            return None
        texts.add("".join(parts))
    return texts.pop() if len(texts) == 1 else None


def unsubstituted(value):
    """The name and text `workflow_programs.unprinted` hands `unread_program` for the `echo` or
    `printf` alone in the script `value` where `substituted` cannot spell it, its words as ONE
    text as `unspelled` weighs an unspelled printer's (`sh <(echo "$X")`), else []. Never a `cat`:
    `substituted` spells its QUOTED heredoc, and `fed` hands the guard its EXPANDING one."""
    if isinstance(value, SpelledOutput):
        return []
    found = _printer(value)
    if not found:
        return _group_unsubstituted(value)
    if os.path.basename(found[0][0]) not in _PRINTERS:
        return []
    return [] if substituted(value) is not None else [
        found[0][0], " ".join(found[0][1:])] + _apart(found[0])


def _group_unsubstituted(value):
    """`unsubstituted` for a script that is one group of printers (#3117): where `_group_substituted` spells it,
    []; where every pipeline ends in a printer and one is unspelled, the first printer's name, then each one's
    words as one text and apart; where one is no printer, `_GROUPED`, LOUD."""
    if _group_substituted(value) is not None:
        return []
    try:
        parsed = shell_reader.statements(value) if value is not None else []
    except shell_lex.Unreadable:
        return []
    if len(parsed) < 2 or not parsed[-1].stages:
        return []
    front = parsed[-1].stages[-1]
    pipelines = _grouped(front, [front], parsed) or []
    printers = [_printer_of(p) for p in pipelines]
    if not pipelines or not any(printers):
        return []
    if not all(printers):
        return list(_GROUPED)
    argvs = [shell_reader.command(p.argv) for p in printers]
    return [argvs[0][0]] + [" ".join(a[1:]) for a in argvs] + [t for a in argvs for t in _apart(a)]


def _inherited(words, shell=ANY):
    """BESIDE `main`'s texts for an unspelled printer, never instead (#3153 item 1): where a word of it is
    `weighed` (`workflow_annotate._spell`: the value a forked child inherits, or one holding a lifted `$(...)`
    written as a text it cannot know), what it writes with each such value in place -- its words as one text,
    then as `_apart` writes them -- so a value that fetches makes the weighed answer LOUD, as a literal word
    that fetches does; [] where no word is weighed, and in `main`'s pass (`_MAINS`)."""
    if _MAINS.get() or not any(hasattr(word, "weighed") for word in words[1:]):
        return []
    valued = [words[0]] + [_valued(word) for word in words[1:]]
    joined = " ".join(str(getattr(word, "spelled", word)) for word in valued[1:])
    return [joined] + [text for text in _apart(valued, shell) if text != joined]


def _valued(word):
    """`word` with its `weighed` value as the text `_apart` writes for it (`spelled`), or `word` itself."""
    if not hasattr(word, "weighed"):
        return word
    token = shell_reader._Token(str(word), shell_reader._markers(word))
    setattr(token, "spelled", getattr(word, "weighed"))
    return token


def _apart(words, shell=ANY):
    """More texts for an unspelled printer's words, in the second walk (#2955), beside the ONE text
    `main` weighs, which begins with the printer's first word: `printf '%s\\n' WORD` prints WORD as a
    line and `echo -n WORD` prints WORD, but that text reads WORD as an argument of `%s\\n` or of
    `-n`, never as a command. So the texts weighed too are what the printer WRITES with each word as
    written, a `$` word left as it stands, one a family of the shell `shell` reads it by, or of both
    rows `spellings` reads where that is no measured one: a `printf`'s format with its words in
    place (`_formatted`), after a `--`, and each word on its own too where the format holds a `$`
    (`printf "$F" WORD`: what it makes of the words is not written), but nothing where an option
    stands in the format's place (`-v NAME`: no shell prints then); an `echo`'s (`_echoed`). A text
    equal to `main`'s is not said twice, and one `_formatted` does not follow is `_PAST_DEPTH`'s
    LOUD stand-in."""
    if _MAINS.get():
        return []
    rest, reading = [getattr(word, "spelled", word) for word in words[1:]], _reading(shell)
    rows = [reading] if reading in _ECHO else ["bash", "sh"]
    families = [(row, kinds) for row in rows
                for kinds in _WRITERS.get(row, _WRITERS["bash"] + _WRITERS["sh"])]
    if os.path.basename(words[0]) != "printf":
        texts = [_echoed(rest, _ECHO[row], kinds) for row, kinds in families]
    else:
        option = rest[:1] != ["--"] and rest[:1] != ["-"] and rest[0][:1] == "-" if rest else True
        rest = rest[rest[:1] == ["--"]:]
        fmt = words[len(words) - len(rest)] if rest else ""
        texts = [_formatted(rest[0], rest[1:], kinds)
                 for _row, kinds in families if rest and not option]
        texts = [_PAST_DEPTH[1] if text is None else text for text in texts]
        dollar = (shell_reader.has_substitution(fmt)
                  or shell_reader.dynamic(fmt, shell_reader.has_substitution))
        if texts and dollar and not hasattr(fmt, "spelled"):
            texts += rest[1:]
    return [text for at, text in enumerate(texts)
            if text != " ".join(words[1:]) and text not in texts[:at]]


def worded(word):
    """What `unread_program`'s last resort weighs for a program word that is ALL one `$(...)`, in
    the second walk (#2955): the texts `unsubstituted` gives the `echo` or `printf` alone in its
    script where no reading spells it (`eval "$(echo "$X")"`), else []."""
    entry = getattr(word, "markers", {}).get(word)
    if _MAINS.get() or not entry or not shell_reader.yields_words(word):    # one marker, and a `$(...)`
        return []
    return unsubstituted(entry[1])[1:]


def fed(value):
    """The `(body, expands)` of the heredoc or here-string a `cat` alone in the script `value`
    prints (`_printer`, #2495), or None: `workflow_guard._unread_stdin` reports an EXPANDING one a
    shell reads as its FILE (`bash <(cat <<EOF …)`) as it reports `cat <<EOF | sh`."""
    if isinstance(value, SpelledOutput):
        return None
    found = _printer(value)
    return (found[1].stdin_heredoc
            if found and os.path.basename(found[0][0]) not in _PRINTERS else None)


def rendered(word):
    """`word`'s text with each lifted `$(...)` or backquote whose script is one printer
    `substituted` spells replaced by that text, its trailing newlines dropped as a command
    substitution drops them, and every other substitution -- a `<(...)` or `>(...)` always, which
    hands a FILE, never its text -- rendered `$(...)`, as `shell_reader.readable` renders them all.
    The text starts as bash hands it on where the word holds a double-quoted `\\$` or `` \\` ``
    (`shell_reader._stage`'s `spelled`, #2466): `bash -c "sh \\$(echo tool) $(true)"` renders as
    `sh $(echo tool) $(...)`, the inner shell's own substitution read as one by the parse of it.
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
    text = getattr(word, "spelled", word)       # bash's text: a `\$` without its backslash (#2466)
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
            else getattr(word, "written", None))      # a FILE the step wrote: its writer's script (#3027)


def operand(argv):
    """The script of the `<(...)` that is `argv`'s whole FILE operand (`file_operand`, `_filed`):
    what bash runs to fill the file a shell or `source` then reads its program from, or None."""
    return _filed(file_operand(argv))
