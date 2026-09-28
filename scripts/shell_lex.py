#!/usr/bin/env python3
"""What bash settles about a script's TEXT before it reads a command out of it.

Split out of `scripts/shell_reader.py` (#1793, COD-3418139920), which settled
it in three line-oriented passes that ran before any quote tracking: whole-line
comments dropped, `\\`-newlines joined, then `<<WORD` found by a regex and the
lines down to `WORD` swallowed. Each pass read text that bash reads as
something else -- a `#` line inside a multi-line string, a `<<true` inside
quotes, in a comment or at the tail of a `<<<`, a backslash ending a comment or
a quoted heredoc line -- and each swallowed a statement bash then RUNS, so the
guard reading the result reported the step clean. Bash decides all three in
one forward pass, from the state it is in, and so does `lex`:

    quoting        '...', "..." and $'...' (whose `\\'` does not end it), a
                   backslash outside them, and `$(...)`, `${...}`, `$((...))`,
                   `$[...]` and backquotes nested the way bash nests them
    comments       a `#` that starts a word, up to the newline; a backslash
                   inside one continues nothing
    continuations  `\\`-newline folded away in code, inside "..." and in an
                   unquoted heredoc body; never in '...' or $'...', a comment
                   or a quoted heredoc body
    heredocs       `<<`/`<<-` in code -- not the tail of `<<<`, not a shift in
                   arithmetic, not inside backquotes (bash reads their text
                   later, as a script of its own); the delimiters queue, and
                   their bodies are read one after another from the next
                   newline

Two readings are not bash's. A `<<` with no terminator line below it is left
as text rather than swallowing the rest of the script: bash runs nothing below
it, so reading it as code can only report more. And a heredoc inside `$(...)`
is lifted into the enclosing parse, so the text that substitution is re-read
from holds a marker instead of the body -- a gap `scripts/workflow_guard.py`
documents. A delimiter bash has to PARSE to spell -- a `$(...)`, `${...}`,
`$[...]` or backquote in the word, an escape `$'...'` decodes, an extglob
pattern -- has no reading short of bash's: a body ended at a guessed spelling
swallows what bash runs, and a body read as code hides it behind a quote left
open there (#2224). So `lex` reads it as a word and, at the metacharacter
ending it, raises `Unreadable` naming it; a script that ends inside the word
leaves no line below it for a body to hide.

A command's `((` is decided the way bash decides it. Its first group is read
to its close -- through quotes, backquotes, escapes and `$(...)`, not
comments, and through `${` and `$[` as characters, as arithmetic reads them --
and the character after it settles the rest: `)` makes an arithmetic command;
anything else, two subshells, read again from the first `(` as code, so the
heredocs in them are real. (`$((...))` needs no such choice: it is always
arithmetic, read the same way. A `$(...)` in it, as in `((...))` and
`$[...]`, is a command substitution, comments and heredocs and all.) Reading
a group again is what nesting costs -- `((((` N deep is read N times -- so
`lex` stops at `_REREAD` times the script's length of it and raises
`Unreadable`. An exception rather than a reading, because the reader has no
channel for a step it cannot read: `workflow_guard.job_defects` catches it
and reports that step by name, accepting nothing in it.

A heredoc whose `$(...)`, `<(...)` or `>(...)` closes before the newline its
body would follow -- `echo "$(cat <<EOF)"` -- raises `Unreadable` too. Bash
3.2 reads the lines below it as code; 5.2 warns, reads them as that body and
runs what follows its terminator. Read as code, a quote in them hides what
5.2 runs; read as a body, they hide what 3.2 runs. A body on the lines inside
a substitution still open is read there, as any other.

A name and `[` open an array subscript -- arithmetic, `a[1<<2]=x`, up to its
`]` however many lines on -- only where bash reads an assignment: at the head
of a command, after assignments or (bash 5.2) nothing but redirections before
its name, and at a word's start inside `name=(...)`. Among a command's
arguments, `echo a[1<<X]` is the word `a[1` and a heredoc. So `lex` tracks
where each word stands, as bash's parser does (`_HEADS`), which also settles
where a reserved word starts a command. Where bash 3.2 and 5.2 part -- a
redirection before an assignment, `time -p --`, `coproc`, `{fd}>`, `|&`,
`function f ((` -- it reads what 5.2, the CI runners' bash, reads.

Stdlib only. `lex(script, heredoc)` is the entry point; `closing(text, i)` is
the `$(...)` matcher `shell_reader` lifts substitutions with.
"""
import re
from typing import Callable

# bash's metacharacters: a word ends at any of them, and a `#` right after one
# begins a comment.
_BREAK = " \t\n;&|()<>"
# The frames that read code: the script itself, and `$(...)`, `<(...)`,
# `>(...)`. Only these hold comments and heredocs.
_CODE = ("top", "(")
# What each opener starts: its text, the frame it opens, the brackets it opens.
# `$((` and `$[` are arithmetic, where `<<` is a shift; longest spellings first.
_OPENERS = (("$((", "$((", 2), ("$(", "(", 1), ("<(", "(", 1), (">(", "(", 1),
            ("$[", "[", 1), ("${", "{", 0), ("$'", "$'", 0), ('$"', '"', 0),
            ("'", "'", 0), ('"', '"', 0), ("`", "`", 0))
# The brackets a frame counts, and the character that ends each other frame.
# "((" is a command's `((...))`; "a[" the subscript of an array assignment,
# `a[1<<2]=x`: arithmetic too.
_PAIRS = {"(": "()", "((": "()", "$((": "()", "[": "[]", "a[": "[]"}
_CLOSE = {"'": "'", "$'": "'", '"': '"', "`": "`", "{": "}"}
# The openers a frame reads as text: "..." every quote but the `"` that ends
# it, and bash's arithmetic -- `((...))`, `$((...))` and `$[...]` -- the `${`
# and `$[` whose brackets it counts as its own. A `$(` in arithmetic opens a
# command substitution, as bash's arithmetic parse does (parse.y: P_ARITH).
_PLAIN = {'"': ("'", '"', "$'", '$"'), "((": ("${", "$["), "[": ("${", "$["),
          "$((": ("${", "$[")}
# How many times over the script a `((` decided as two subshells may be read
# again before `lex` stops (`Unreadable`).
_REREAD = 8
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Where the next word stands, as bash's parser tracks it: at the head of a
# command -- "head", or after a pipe ("|", "|\n"), where `time` names a program
# -- after nothing but redirections ("redirected", bash 5.2) or assignments
# ("assigned"), as the name `function`, `coproc`, `for` and `select` take
# ("named"), or among the arguments ("argument"). `name[` opens a subscript
# anywhere but among the arguments; a reserved word starts a command only at
# a head, and `-p` and `--` only after `time`.
_HEADS = ("head", "|", "|\n")
_STARTERS = ("!", "{", "coproc", "do", "elif", "else", "for", "function", "if",
             "select", "then", "time", "until", "while")
_NAMERS = ("coproc", "for", "function", "select")
_TIMED = (("time", "-p"), ("time", "--"), ("-p", "--"))
_ASSIGNS = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_COMPOUND = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[.*\])?\+?=", re.S)  # then `(`
_IO_NUMBER = re.compile(r"[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\}")
# The state a word is read in: saved around a `$(...)`, and at a `((`.
_STATE = ("word", "named", "at", "target", "last", "compound", "assigned")
# A quoted part of a heredoc's delimiter word, and the escapes "..." removes.
_QUOTED = re.compile(r"'([^']*)'|\$'((?:[^'\\]|\\.)*)'|\$?\"((?:[^\"\\]|\\.)*)\"",
                     re.S)
_DQ_ESCAPE = re.compile(r'\\([$`"\\])|\\\n')
# What bash has to PARSE, not just unquote, to spell a delimiter: a `$(`,
# `${`, `$[` or backquote in the word, or an escape `$'...'` decodes (`\x41`).
_PARSED = re.compile(r"`|\$[({\[]")
_ANSI_ESCAPE = re.compile(r"\\(.)", re.S)


class Unreadable(Exception):
    """A script `lex` does not read: it nests `((` so deep that deciding each
    one, as bash does, would read it more than `_REREAD` times over, a
    substitution closes over a heredoc, or a heredoc's delimiter is a word
    bash parses to spell. `workflow_guard.job_defects` reports its step."""


def lex(script: str, heredoc: Callable[[str, bool, str], str]) -> str:
    """`script` with its comments removed, its continuations folded, and each
    heredoc -- operator, word and body -- replaced by the marker
    `heredoc(body, expands, fd)` returns, spaced off as a word of its own.
    Raises `Unreadable` rather than guess, past the cap on reading `((`
    again, at a heredoc its substitution closes over and at a delimiter bash
    parses to spell."""
    return _Lexer(script, heredoc).run()


def closing(text: str, opening: int) -> int | None:
    """Index just past the `)` that closes the group opening at `opening`.

    Quotes are read as `shell_reader._split` reads them: a backslash takes the
    next character everywhere but inside '...', so `\\"` does not end a "..."
    (COD-3636110933 -- a nested `"a\\")b"` used to close its `$(...)` a paren
    early), and `$'...'` ends only at a `'` no backslash takes.
    """
    depth, i, quote = 0, opening, ""
    while i < len(text):
        ch = text[i]
        if ch == "\\" and quote != "'":
            i += 2
            continue
        if quote:
            quote = "" if ch == quote[-1] else quote
        elif text.startswith("$'", i):
            quote, i = "$'", i + 1
        elif ch in "'\"":
            quote = ch
        elif ch in "()":
            depth += 1 if ch == "(" else -1
            if not depth:
                return i + 1
        i += 1
    return None


class _Frame:
    """One level of nesting: code (the script, or a `$(...)`), a quote, a
    `${...}`, arithmetic or backquotes. A paren or bracket frame counts the
    ones still open; a code frame holds the heredocs waiting for its next
    newline, each as (output slot, delimiter, quoted, `<<-`, descriptor). A
    command's `((`, until its first group closes, holds the lexer's state
    from before it (`undo`), to go back to if the group makes it subshells."""

    def __init__(self, kind: str, depth: int = 0, undo: tuple = ()):
        self.kind, self.depth, self.undo = kind, depth, undo
        self.queue: list[tuple[int, str, bool, bool, str]] = []
        self.saved: dict = {}           # a `$(...)`: the state around it


class _Lexer:
    def __init__(self, text: str, heredoc: Callable[[str, bool, str], str]):
        self.text, self.heredoc = text, heredoc
        self.out: list[str] = []
        self.frames = [_Frame("top")]
        self.word = 0                   # where in `out` the current word began
        self.named = -1                 # the last word whose first `[` was read
        self.at, self.target, self.last = "head", False, ""     # `_HEADS`
        self.compound = ""              # in `name=(...)`: `at` from before it
        self.assigned = -1              # the last word a `[...]=` assigns in
        self.lines: dict[bool, _Lines] = {}
        self.plain = -1                 # a `((` decided as two subshells
        self.reread = 0                 # the characters read again for them
        self.unspelled = (0, 0)         # a heredoc word bash parses: frames, start

    def run(self) -> str:
        text, out, frames = self.text, self.out, self.frames
        i = 0
        while i < len(text):
            frame, ch = frames[-1], text[i]
            if ch == "\\" and frame.kind != "'":
                if text.startswith("\n", i + 1) and frame.kind != "$'":
                    i += 2              # a continuation: gone, and the word goes on
                    continue
                out.append(text[i:i + 2])
                i += 2
            elif ch == _CLOSE.get(frame.kind):
                frames.pop()
                out.append(ch)
                i += 1
            elif frame.kind in ("'", "$'", "`"):
                out.append(ch)
                i += 1
            else:
                i = self.open(i, frame.kind) or self.step(i, frame)
        # Queues still waiting here never met their newline: their operators
        # stay in the output as written, which is the unterminated reading.
        return "".join(out)

    def open(self, i: int, kind: str) -> int | None:
        """Past the opener at `i` -- its frame pushed -- if `kind` nests one."""
        for opener, inner, depth in _OPENERS:
            if (self.text.startswith(opener, i) and opener not in _PLAIN.get(kind, ())
                    and (kind in _CODE or opener not in ("<(", ">("))):
                return self.push(i, opener, inner, depth)
        return None

    def push(self, i: int, opener: str, kind: str, depth: int) -> int:
        self.out.append(opener)
        self.frames.append(_Frame(kind, depth))
        if kind in _CODE:               # a `$(...)` holds commands of its own
            self.frames[-1].saved = self.saved()
            vars(self).update(word=len(self.out), at="head", target=False, last="",
                              compound="")
        return i + len(opener)

    def saved(self) -> dict:
        return {name: getattr(self, name) for name in _STATE}

    def step(self, i: int, frame: _Frame) -> int:
        """Read the character at `i`, which opens nothing; the index after it."""
        text, out = self.text, self.out
        ch, start = text[i], len(out) == self.word
        if frame.kind in _CODE:
            if ch == "#" and start:     # a comment: gone, up to its newline
                end = text.find("\n", i)
                return len(text) if end < 0 else end
            if text.startswith("((", i) and start and i != self.plain:
                undo = (i, len(self.frames), len(out), self.saved())
                i = self.push(i, "((", "((", 2)
                self.frames[-1].undo = undo
                return i
            if ch in _BREAK:
                if self.unspelled[0] == len(self.frames):
                    self.refuse(i)
                self.token(i)
            if text.startswith("<<<", i):
                out.append("<<<")
                self.word = len(out)
                return i + 3
            if text.startswith("<<", i):
                return self.operator(i, frame)
            if ch == "[" and self.named != self.word:  # only a word's first `[`
                self.named = self.word
                if start and self.compound or self.at != "argument" and _NAME.fullmatch(
                        "".join(out[self.word:])):
                    return self.push(i, "[", "a[", 1)
        out.append(ch)
        pair = _PAIRS.get(frame.kind, "")
        if ch in pair:
            frame.depth += 1 if ch == pair[0] else -1
            if frame.undo and frame.depth == 1:     # its first group closed
                if not text.startswith(")", i + 1):
                    return self.rewind(frame.undo, i + 1)
                frame.undo = ()         # `))`: an arithmetic command
            if not frame.depth:
                if frame.queue:         # a substitution closing over a heredoc
                    raise Unreadable("a heredoc inside a `$(...)`, `<(...)` or `>(...)` "
                                     "that closes before the newline its body would follow: "
                                     "bash 5.2 reads that body from the lines below and runs "
                                     "what follows its terminator, bash 3.2 reads those "
                                     "lines as code")
                self.frames.pop()
                if frame.kind == "(":
                    vars(self).update(frame.saved)
                elif frame.kind == "a[" and text.startswith(("=", "+="), i + 1):
                    self.assigned = self.word
                return i + 1
        if ch in _BREAK and frame.kind in _CODE:
            self.word = len(out)
            if ch == "\n" and frame.queue:
                return self.bodies(frame, i + 1)
        return i + 1

    def rewind(self, undo: tuple, i: int) -> int:
        """Back to the command's `((` whose state `undo` holds, to read it as
        the two subshells bash makes of it; the index it is at. The group was
        read to `i` for nothing, so past `_REREAD` times the script's length
        of such re-reading, `Unreadable` -- the cap on nesting them deep."""
        at, frames, size, saved = undo
        self.reread += i - at
        if self.reread > _REREAD * len(self.text):
            raise Unreadable("this script nests `((` so deep that reading it the way "
                             "bash does costs over %d times its length" % _REREAD)
        del self.frames[frames:], self.out[size:]
        vars(self).update(saved)
        self.plain = at
        return at

    def token(self, i: int) -> None:
        """Move `self.at` past the word the metacharacter at `i` ends -- none,
        if it is an IO number -- and past that metacharacter."""
        text, ch, before = self.text, self.text[i], self.text[i - 1:i]
        word = "".join(self.out[self.word:])
        if word and not (ch in "<>" and _IO_NUMBER.fullmatch(word)):
            self.at = self.stood(word)
        if ch in "<>":
            self.target = True
        elif ch == "(" and _COMPOUND.fullmatch(word):
            self.compound = self.at
        elif ch == ")" and self.compound:
            self.at, self.compound = self.compound, ""
        elif ch in "\n;()" or ch == "|" and before != ">" or ch == "&" and not (
                before in ("<", ">", "|") or text.startswith("&>", i)):
            self.at = ("|" if ch == "|" and before != "|" else
                       "|\n" if ch == "\n" and self.at == "|" else "head")
            self.last, self.target = "", False

    def stood(self, word: str) -> str:
        """Where the word after `word` stands, `word` having stood at `self.at`."""
        at, last, self.last = self.at, self.last, word
        if self.target:                 # a redirection's word: 5.2's rule
            self.target = False
            return ("argument" if at == "assigned" else
                    at if at in ("named", "argument") else "redirected")
        if at == "named":
            return "head"
        if at in _HEADS and (word in _STARTERS and (word != "time" or at == "head")
                             or (last, word) in _TIMED):
            return "named" if word in _NAMERS else "head"
        if at != "argument" and (self.assigned == self.word or _ASSIGNS.match(word)):
            return "assigned"
        return "argument"

    def operator(self, i: int, frame: _Frame) -> int:
        """Queue the heredoc whose `<<` is at `i`; the index after its word.

        The operator stays in the output as written until a body is found
        for it -- with no terminator below, that is what it remains. A word
        bash parses to spell is read on as a word, never a subscript, and
        refused where it ends (`refuse`).
        """
        text, out = self.text, self.out
        after = i + 3 if text.startswith("-", i + 2) else i + 2
        word = _word(text, after)
        if not isinstance(word, tuple):     # no word follows, or none `_word` spells
            if word is not None:
                after, self.unspelled = word, (len(self.frames), word)
                self.at, self.compound = "argument", ""
            out.append(text[i:after])
            self.word = len(out)
            return after
        delimiter, quoted, end = word
        fd = "".join(out[self.word:])   # an IO number is a word of bare digits
        if fd.isascii() and fd.isdigit():
            del out[self.word:]
        else:
            fd = ""
        out.append(fd + text[i:end])
        frame.queue.append((len(out) - 1, delimiter, quoted, after > i + 2, fd or "0"))
        self.word, self.at = len(out), self.stood(delimiter)
        return end

    def refuse(self, i: int) -> None:
        """Raise `Unreadable` at `i`, the metacharacter ending the heredoc
        word `_word` would not spell, naming the word -- through the pattern
        an extglob's `(` there opens."""
        start, text = self.unspelled[1], self.text
        end = (closing(text, i) or i) if text.startswith("(", i) else i
        word = text[start:end]
        if len(word) > 60 or "\n" in word:  # named by its start
            word = word.partition("\n")[0][:57] + "..."
        # A Markdown code span: fenced by more backquotes than any run in the word.
        tick = "`" * (1 + max(map(len, re.findall("`+", word)), default=0))
        shown = tick + word + tick if len(tick) == 1 else "%s %s %s" % (tick, word, tick)
        raise Unreadable("the heredoc delimiter %s is a word bash parses to spell: a "
                         "guessed spelling would end its body at a decoy line, and a "
                         "body read as code hides what follows its terminator behind "
                         "a quote left open in it" % shown)

    def bodies(self, frame: _Frame, i: int) -> int:
        """Read the heredocs `frame` queued, one after another from the line
        starting at `i`; the index where its code resumes."""
        for slot, delimiter, quoted, strip, fd in frame.queue:
            expands = not quoted        # and folds `\`-newline, as bash reads it
            if expands not in self.lines:
                self.lines[expands] = _Lines(self.text, folded=expands)
            found = self.lines[expands].body(i, delimiter, strip)
            if found:
                body, i = found
                self.out[slot] = " %s " % self.heredoc(body, expands, fd)
        frame.queue.clear()
        return i


def _word(text: str, i: int) -> tuple[str, bool, int] | int | None:
    """(delimiter, quoted, end) for the heredoc word after an operator ending
    at `i`: the word as bash compares lines with it -- quotes removed, quoted
    if any part of it was. None when no word follows, a `#` there starts a
    comment, or a quote in it never closes. Where the word starts, when bash
    has to PARSE it to spell it (`_PARSED`, or the `(` of an extglob pattern
    after it)."""
    while text.startswith((" ", "\t", "\\\n"), i):  # a `\`-newline: gone, as in code
        i += 2 if text[i] == "\\" else 1
    start, quoted = i, False
    parts: list[str] = []
    while i < len(text) and text[i] not in _BREAK:
        match = _QUOTED.match(text, i)
        if _PARSED.match(text, i) or (match and _PARSED.search(match[3] or "")):
            return start
        if match:
            single, ansi, double = match.groups()
            if single is not None:
                parts.append(single)
            elif ansi is not None:      # the four escapes that are the character
                if set(_ANSI_ESCAPE.findall(ansi)) - set("\\'\"?"):
                    return start
                parts.append(_ANSI_ESCAPE.sub(r"\1", ansi))
            else:
                parts.append(_DQ_ESCAPE.sub(lambda m: m[1] or "", double))
            quoted, i = True, match.end()
        elif text[i] in "'\"" or text.startswith(("$'", '$"'), i):
            return None
        elif text[i] == "\\":
            if not text.startswith("\n", i + 1):
                parts.append(text[i + 1:i + 2])
                quoted = True
            i += 2
        else:
            parts.append(text[i])
            i += 1
    if i == start or text[start] == "#":
        return None
    return start if text.startswith("(", i) else ("".join(parts), quoted, i)


class _Lines:
    """`text`'s lines the way bash compares a heredoc terminator with them.

    A QUOTED delimiter's body is read verbatim, one physical line at a time;
    an unquoted one has `\\`-newline folded first, so its lines are LOGICAL
    ones -- `E\\` + `OF` ends it where `x \\` + `EOF` does not. `index` is what
    keeps a `<<` with no terminator below it cheap: whether any later line
    ends it is one lookup, where the pass this replaced scanned to the end of
    the script once per operator, which is quadratic in the operators.
    """

    def __init__(self, text: str, folded: bool):
        self.size = len(text)
        self.starts = [0] + [match.end() for match in re.finditer("\n", text)]
        self.number = {start: k for k, start in enumerate(self.starts)}
        self.texts: list[str] = []      # this reading's lines
        self.of: list[int] = []         # physical line -> the line it is part of
        self.offset: list[int] = []     # physical line -> where it starts there
        self.last: list[int] = []       # line -> its last physical line
        self.keys: dict[bool, tuple[list[str], dict[str, int]]] = {}
        self.leads: dict[int, int] = {}
        physical = text.split("\n")
        run: list[str] = []
        length = 0
        for k, line in enumerate(physical):
            more = (folded and k + 1 < len(physical)
                    and (len(line) - len(line.rstrip("\\"))) % 2 == 1)
            self.of.append(len(self.texts))
            self.offset.append(length)
            run.append(line[:-1] if more else line)
            length += len(run[-1])
            if not more:
                self.texts.append("".join(run))
                self.last.append(k)
                run, length = [], 0

    def body(self, at: int, word: str, strip: bool) -> tuple[str, int] | None:
        """(body, where code resumes) for a heredoc whose body starts at offset
        `at`, or None when no line from there on ends it."""
        k = self.number.get(at)
        if k is None:                   # the script ended on the last terminator
            return None
        n, offset = self.of[k], self.offset[k]
        text = self.texts[n]
        # `<<-` strips leading tabs, but bash tries the line unstripped first,
        # which is the only way a delimiter that starts with a tab can match.
        raw = not strip or word.startswith("\t")
        begin = len(text) - len(word)
        if begin >= offset and text.endswith(word) and begin == (
                offset if raw else self.lead(at, text, offset)):
            end = n                     # a body can start mid-line after a `\`
        else:
            keys, last = self.index(not raw)
            if last.get(word, -1) <= n:
                return None
            end = keys.index(word, n + 1)
        lines = [text[offset:]] + self.texts[n + 1:end] if end > n else []
        if strip:
            lines = [line.lstrip("\t") for line in lines]
        after = self.last[end] + 1
        return "\n".join(lines), self.starts[after] if after < len(self.starts) else self.size

    def lead(self, at: int, text: str, offset: int) -> int:
        """Where the line starting at `at` begins once `<<-` strips its tabs --
        counted once, however many operators queued on one line wait on it."""
        if at not in self.leads:
            self.leads[at] = len(text) - len(text[offset:].lstrip("\t"))
        return self.leads[at]

    def index(self, stripped: bool) -> tuple[list[str], dict[str, int]]:
        """Every line as compared, and the last place each text occurs."""
        if stripped not in self.keys:
            keys = [line.lstrip("\t") for line in self.texts] if stripped else self.texts
            self.keys[stripped] = keys, {key: n for n, key in enumerate(keys)}
        return self.keys[stripped]
