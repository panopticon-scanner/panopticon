#!/usr/bin/env python3
"""What bash settles about script text before it reads commands from it.

This was split from `shell_reader.py` (#1793). Its old whole-line comment,
continuation, and heredoc passes each confused code with quoted or redirected
text and swallowed commands bash runs. `lex` instead makes one stateful pass:

    quoting        shell quotes, escapes, substitutions, arithmetic, and backquotes
    comments       `#` at a word start through its newline
    continuations  `\\`-newline in code, double quotes, and expanding heredocs
    heredocs       queued `<<`/`<<-` bodies, excluding strings and arithmetic shifts
    here-strings   a static `<<<` word outside `$(...)`, spelled by `_string`

Two conservative deviations prevent swallowed code. An unterminated heredoc
stays text because bash runs nothing below it. A delimiter bash must parse to
spell is refused: guessing could end its body at a decoy or hide later code
behind a body quote (#2224). Substitution bodies and their heredocs travel as
`shell_text.Lifted` markers to their own parse (#2336).

A command's `((` is arithmetic only when its first group is followed by `)`;
otherwise it is two subshells and is reread as code. Arithmetic escapes every
pattern character, while a nested `$(` is still code. Deep ambiguous groups
stop at `_REREAD` times the source length and become a named `Unreadable`.

Bash 5.2 governs heredocs whose substitution closes before their body and
queued bodies after an `EOF)` line; Bash 3.2 reads those lines differently.
The lexer files each body before parsing saved close-line code. Two `EOF)`
ends in one queue remain refused. `shell_heredoc` documents the evidence.

Word position (`_HEADS`) decides assignments, redirections, reserved words,
array subscripts, and Bash 3.2/5.2 disagreements. Arithmetic commands,
conditionals, and array literals run no patterned words, so their glob syntax
is escaped. Extglobs instead stay one marked pattern word outside those forms.

A `case` pattern list is one word through its arm-closing `)`. Bash and dash
discard spaces around `|` and inside optional `( ... )`; `casing` does too
(#2345). `closing` shares that grammar when locating a substitution's `)`.

Stdlib only. `lex(script, heredoc)` is the entry point. Pattern marks come
from `shell_patterns`; `shell_heredoc._Lines` indexes heredoc bodies."""
import re
from typing import Callable

from shell_heredoc import _Lines
from shell_patterns import GLOB, MARK

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
# `a[1<<2]=x`: arithmetic too; "x(" an extglob group.
_PAIRS = {"(": "()", "((": "()", "$((": "()", "[": "[]", "a[": "[]", "x(": "()"}
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
# What opens an extglob group before a word's `(` -- `*` and `?` as `lex`
# escapes them in `[[` and an array literal -- and the frames it escapes in.
_EXTGLOB = ("@", "+", "!", "*", "?", "\\*", "\\?")
_QUIET = ("top", "(", "x(")
_ASSIGNS = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")
_COMPOUND = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\[.*\])?\+?=", re.S)  # then `(`
_IO_NUMBER = re.compile(r"[0-9]+|\{[A-Za-z_][A-Za-z0-9_]*\}")
# The state a word is read in: saved around a `$(...)`, and at a `((`.
_STATE = ("word", "named", "at", "target", "last", "compound", "assigned", "cond", "cases")
# Where each `case` open in a frame stands (`casing`), innermost last: its
# word or its `in` due, a pattern list due or begun, or an arm's body.
_SUBJECT, _IN, _PATTERN, _ARM, _BODY = "subject", "in", "pattern", "arm", "body"
# A quoted part of a heredoc's delimiter word, and the escapes "..." removes.
_QUOTED = re.compile(r"'([^']*)'|\$'((?:[^'\\]|\\.)*)'|\$?\"((?:[^\"\\]|\\.)*)\"",
                     re.S)
_DQ_ESCAPE = re.compile(r'\\([$`"\\])|\\\n')
# What bash has to PARSE, not just unquote, to spell a delimiter: a `$(`,
# `${`, `$[` or backquote in the word, or an escape `$'...'` decodes (`\x41`).
_PARSED = re.compile(r"`|\$[({\[]")
_ANSI_SIMPLE = dict(zip("abefnrtv\\'\"?E", "\a\b\x1b\f\n\r\t\v\\'\"?\x1b"))
_ANSI_ESCAPE = re.compile(
    r"\\(?:([abefnrtv\\'\"?E])|([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|"
    r"u([0-9A-Fa-f]{1,4})|U([0-9A-Fa-f]{1,8})|c(.)|\n|(.)|(\Z))", re.S)
# `<<`, `<<-` or `<<<` as bash reads it: past the `\`-newlines it folds away
# first, which leave `<` + `\`-newline + `<EOF` the operator `<<` (#2291).
_HERE = re.compile(r"<(?:\\\n)*<(?:(?:\\\n)*([-<]))?")


def ansi_c(body: str) -> str | None:
    """Bash's ASCII text for `$'body'`; None for an unknown escape (#2470)."""
    stopped = unknown = False

    def decoded(match: re.Match[str]) -> str:
        nonlocal stopped, unknown
        if stopped:
            return ""
        simple, octal, hexa, short, long, control, other, ended = match.groups()
        if simple is not None:
            return _ANSI_SIMPLE[simple]
        if other is not None or ended is not None:
            unknown = True
            return ""
        if control is not None:
            if not control.isascii():
                raise Unreadable("an ANSI-C escape decodes outside ASCII")
            value = 127 if control == "?" else ord(control.upper()) & 31
        else:
            digits = octal or hexa or short or long
            if digits is None:               # A backslash-newline is gone.
                return ""
            value = int(digits, 8 if octal is not None else 16)
        if value > 127:
            raise Unreadable("an ANSI-C escape decodes outside ASCII")
        stopped = not value                # Bash truncates this quoted part at NUL.
        return chr(value)
    text = _ANSI_ESCAPE.sub(decoded, body).partition("\0")[0]
    return None if unknown else text


class Unreadable(Exception):
    """A script `lex` does not read: it nests `((` so deep that deciding each
    one, as bash does, would read it more than `_REREAD` times over, a
    substitution closes over a heredoc or queues one after an `EOF)`, a case
    arm cannot be attributed, or a heredoc delimiter needs a shell parse.
    `workflow_guard.job_defects` reports its step."""


def lex(script: str, heredoc: Callable[[str, bool, str], str]) -> str:
    """`script` with its comments removed, its continuations folded, and each
    heredoc -- operator, word and body -- replaced by the marker
    `heredoc(body, expands, fd)` returns, spaced off as a word of its own; a
    here-string's word too, after its `<<<`, when bash hands it over as
    written (`_string`) and no `$(...)` holds it: `heredoc(text, False, "0")`,
    whose descriptor the reader reads off the operator; and the pattern
    characters of an arithmetic command, a conditional and an array literal
    escaped, and an extglob group's metacharacters -- its word, outside those,
    marked a pattern (`shell_patterns.MARK`) -- the words unchanged. Raises
    `Unreadable` rather than guess, past the cap on reading `((` again, at a
    heredoc its substitution closes over or queues after an `EOF)`, and at a
    delimiter bash parses to spell."""
    return _Lexer(script, heredoc).run()


def closing(text: str, opening: int) -> int | None:
    """Index just past the `)` that closes the group opening at `opening`.

    Quotes are read as `shell_reader._split` reads them: a backslash takes the
    next character everywhere but inside '...', so `\\"` does not end a "..."
    (COD-3636110933 -- a nested `"a\\")b"` used to close its `$(...)` a paren
    early), and `$'...'` ends only at a `'` no backslash takes. A case arm's
    pattern-closing `)` is not the close of the surrounding substitution."""
    depth, i, quote, word, head, target = 0, opening, "", -1, True, False
    cases: list[tuple[int, str, bool, bool]] = []
    heads: list[bool] = []
    unread = "a `case` inside `$(...)` has an arm this guard cannot attribute"
    while i < len(text):
        ch = text[i]
        if (not quote and cases and cases[-1][1] == _PATTERN
                and not cases[-1][3] and ch not in " \t\n;&|"):
            base, state, _wrapped, _started = cases[-1]
            cases[-1] = base, state, ch == "(", True
        if ch == "\\" and quote != "'":
            word = i if word < 0 else word
            i += 2
            continue
        if quote:
            quote = "" if ch == quote[-1] else quote
            i += 1
            continue
        elif text.startswith("$'", i):
            word, quote, i = (i if word < 0 else word), "$'", i + 2
            continue
        elif ch in "'\"":
            word, quote, i = (i if word < 0 else word), ch, i + 1
            continue
        if ch in _BREAK and word >= 0:
            token, word = text[word:i], -1
            state = cases[-1][1] if cases else ""
            if cases and token == "esac" and head and state in (_PATTERN, _BODY):
                cases.pop()
                head = False
            elif state == _SUBJECT:
                if ch == "(":
                    raise Unreadable(unread)
                base, _state, wrapped, started = cases[-1]
                cases[-1] = base, _IN, wrapped, started
            elif state == _IN:
                if token != "in":
                    raise Unreadable(unread)
                base, _state, _wrapped, _started = cases[-1]
                cases[-1], head = (base, _PATTERN, False, False), True
            elif state != _PATTERN and token == "case" and head:
                cases.append((depth, _SUBJECT, False, False))
                head = False
            elif state != _PATTERN:
                if target:
                    target = False
                elif not (head and ch in "<>" and token.isdigit()):
                    head = token in _STARTERS or bool(_ASSIGNS.match(token))
        pattern = bool(cases and cases[-1][1] == _PATTERN)
        if ch in "<>":
            target = True
        if ch in "()":
            if ch == ")" and pattern:
                base, _state, wrapped, started = cases[-1]
                if started and depth == base + int(wrapped):
                    cases[-1], head = (base, _BODY, False, False), True
                    if not wrapped:
                        i += 1
                        continue
            if ch == "(":
                heads.append(head)
                depth, head = depth + 1, True
            else:
                if cases and depth == 1:
                    raise Unreadable(unread)
                depth -= 1
                if not depth:
                    return i + 1
                head = heads.pop()
        elif not pattern and ch in "\n;&|":
            if (cases and cases[-1][1] == _BODY and depth == cases[-1][0]
                    and text.startswith((";;&", ";;", ";&"), i)):
                base = cases[-1][0]
                cases[-1] = base, _PATTERN, False, False
            head = True
        elif ch not in _BREAK and word < 0:
            word = i
        i += 1
    if cases:
        raise Unreadable(unread)
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
        self.drop: tuple[int, int] | None = None  # boundary and depth for one omitted `;`
        self.split = False              # queued heredocs span more than one command


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
        self.cond = 0                   # inside `[[ ... ]]`: 1 + the `(` open in it
        self.cases: tuple[str, ...] = ()    # the `case`s open here (`casing`)
        self.lines: dict[bool, _Lines] = {}
        self.jumps: dict[int, int] = {}  # body source -> code that follows it
        self.body_next: dict[int, int] = {}  # next body below an early-close line
        self.plain = -1                 # a `((` decided as two subshells
        self.reread = 0                 # the characters read again for them
        self.unspelled = (0, 0)         # a heredoc word bash parses: frames, start

    def run(self) -> str:
        text, out, frames = self.text, self.out, self.frames
        i = 0
        while i < len(text):
            i = self.past(i)
            if i >= len(text):
                break
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

    def past(self, i: int) -> int:
        """Past bodies already read before code that follows them."""
        while i in self.jumps:
            i = self.jumps.pop(i)
        return i

    def below(self, frame: _Frame, i: int) -> None:
        """File bodies below a line that closes their substitution early."""
        newline = self.text.find("\n", i)
        if newline < 0:
            raise Unreadable("a heredoc whose substitution closes before its body has no "
                             "following line: bash 5.2 runs nothing from it")
        following = newline + 1
        source = self.body_next.get(following, following)
        resume, self.body_next[following] = self.bodies(frame, source, required=True)
        self.jumps[source] = resume

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
                              compound="", cond=0, cases=())
        return i + len(opener)

    def saved(self) -> dict:
        return {name: getattr(self, name) for name in _STATE}

    def extglob(self, i: int) -> bool:
        """Whether the `(` at `i` opens an extglob group: right after one of
        `_EXTGLOB` in a word, and not closing at once (`f@() {` defines `f@`).
        A `!(` where a command starts is one: with `extglob` on, bash 3.2 and
        5.2 both expand `!(x) -c …` to the files not named `x`."""
        out = self.out
        return len(out) > self.word and out[-1] in _EXTGLOB and not self.text.startswith(")", i + 1)

    def step(self, i: int, frame: _Frame) -> int:
        """Read the character at `i`, which opens nothing; the index after it."""
        text, out = self.text, self.out
        ch, start = text[i], len(out) == self.word
        if frame.drop and i >= frame.drop[0]:
            frame.drop = None           # the compatibility parse ends with its logical line
        if ch == ";" and frame.drop and frame.depth == frame.drop[1]:
            if re.match(r"[ \t]*(?:then|do)(?=[ \t\n;&|()<>]|$)", text[i + 1:]):
                raise Unreadable("Bash 5.2 preserves this compound command's required separator")
            frame.drop = None
            self.token(i, " ")          # omit the token, while keeping its word boundary
            out.append(" ")
            self.word = len(out)
            return i + 1
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
                before = text[i - 1:i]
                if frame.queue and (ch == ";" or ch == "|" and before != ">" or ch == "&" and not (
                        before in ("<", ">", "|") or text.startswith("&>", i))):
                    frame.split = True
                if ch == "(" and self.extglob(i):   # one word with the text around it
                    if not (self.cond or self.compound) and out[-1] in "@+!":
                        out[-1] = MARK + out[-1]    # one bash expands, as `*(` is
                    out.append("\\(")
                    self.frames.append(_Frame("x(", 1))
                    return i + 1
                self.token(i)
                if ch in " \t" and self.cases[-1:] == (_ARM,):
                    self.word = len(out)            # `a | x)` is the arm `a|x)` (#2345)
                    return i + 1
            here = _HERE.match(text, i) if ch == "<" else None
            if here and here[1] == "<":         # a here-string
                out.append("<<<")
                self.word = len(out)
                # Spelled at the top only: a `$(...)` is read again as a script
                # of its own, and spelled there, not as a marker it cannot read.
                spelled = _string(text, here.end()) if frame.kind == "top" else None
                if spelled is None:             # a word bash expands: read on
                    return here.end()
                out.append(" %s " % self.heredoc(spelled[0], False, "0"))
                self.word, self.at = len(out), self.stood(spelled[0])
                return spelled[1]
            if here:
                return self.operator(i, frame, here.end(), here[1] == "-")
            if ch == "[" and self.named != self.word:  # only a word's first `[`
                self.named = self.word
                if start and self.compound or self.at != "argument" and _NAME.fullmatch(
                        "".join(out[self.word:])):
                    i = self.push(i, "[", "a[", 1)
                    out[-1] = "\\[" if self.cond or self.compound else "["
                    return i
        # Bash expands no pattern in an arithmetic command (review N-1), and no
        # command runs the words of `[[ ... ]]` or an array literal (re-review
        # I-5): what `patterned` would mark comes out escaped, the word it spells
        # the same; so do an extglob group's metacharacters, which are its word's.
        quiet = frame.kind == "((" or (self.cond or self.compound) and frame.kind in _QUIET
        out.append("\\" + ch if ch in GLOB and quiet or frame.kind == "x(" and ch in _BREAK
                   else ch)
        pair = _PAIRS.get(frame.kind, "")
        if ch in pair:
            frame.depth += 1 if ch == pair[0] else -1
            if frame.undo and frame.depth == 1:     # its first group closed
                if not text.startswith(")", i + 1):
                    return self.rewind(frame.undo, i + 1)
                frame.undo = ()         # `))`: an arithmetic command
            if not frame.depth:
                if frame.queue:         # a substitution closing over a heredoc
                    self.below(frame, i)
                self.frames.pop()
                if frame.kind == "(":
                    vars(self).update(frame.saved)
                elif frame.kind == "a[" and text.startswith(("=", "+="), i + 1):
                    self.assigned = self.word
                return i + 1
        if ch in _BREAK and frame.kind in _CODE:
            self.word = len(out)
            if ch == "\n" and frame.queue:
                return self.bodies(frame, self.past(i + 1))[0]
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

    def token(self, i: int, ch: str | None = None) -> None:
        """Move `self.at` past the word the metacharacter at `i` ends -- none,
        if it is an IO number -- and past that metacharacter; the `case`s open
        here too (`casing`)."""
        text, actual, before = self.text, self.text[i], self.text[i - 1:i]
        ch = actual if ch is None else ch
        word = "".join(self.out[self.word:])
        self.casing(word, ch, ch == actual and text.startswith((";;", ";&"), i))
        if word == "[[" and self.at in _HEADS or word == "]]" and self.cond:
            self.cond = int(word == "[[")       # a conditional expands no pattern
        if self.cond and ch in "()":            # and ends at a `)` it did not open
            self.cond += 1 if ch == "(" else -1
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

    def casing(self, word: str, ch: str, arm_end: bool) -> None:
        """Move the `case`s open here past `word` and the metacharacter `ch`
        ending it, `arm_end` if that is a `;;`, `;&` or `;;&`: `case` where a
        command starts, its word and `in`, then a pattern list -- begun by its
        first word or `(`, ended by its `)` -- and the arm's body, to the end
        of the arm, where a pattern list is due again; `esac` closes it where a
        pattern list or a command is due."""
        state, rest = (self.cases or ("",))[-1], self.cases[:-1]
        if word and state == _SUBJECT:
            self.cases = rest + (_IN,)
        elif word and state == _IN:
            self.cases = rest + (_PATTERN,) if word == "in" else rest
        elif word == "esac" and (state == _PATTERN or state == _BODY and self.at in _HEADS):
            self.cases = rest
        elif word == "case" and self.at in _HEADS and state not in (_PATTERN, _ARM):
            self.cases += (_SUBJECT,)
        elif state == _PATTERN and (word or ch in "(|"):
            self.cases = rest + (_ARM,)
        if ch == ")" and self.cases[-1:] == (_ARM,) or arm_end and self.cases[-1:] == (_BODY,):
            self.cases = self.cases[:-1] + ((_BODY,) if ch == ")" else (_PATTERN,))

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

    def operator(self, i: int, frame: _Frame, after: int, strip: bool) -> int:
        """Queue the heredoc whose `<<` -- `<<-` if `strip` -- is at `i` and
        ends at `after`; the index after its word.

        The operator stays in the output as written until a body is found
        for it -- with no terminator below, that is what it remains. A word
        bash parses to spell is read on as a word, never a subscript, and
        refused where it ends (`refuse`)."""
        text, out = self.text, self.out
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
        frame.queue.append((len(out) - 1, delimiter, quoted, strip, fd or "0"))
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

    def bodies(self, frame: _Frame, i: int, required: bool = False) -> tuple[int, int]:
        """Read the heredocs `frame` queued, one after another from the line
        starting at `i`; where code resumes and where their source ends."""
        saved: tuple[int, int, int] | None = None
        compatible = not frame.split
        consumed = i
        for number, (slot, delimiter, quoted, strip, fd) in enumerate(frame.queue):
            expands = not quoted        # and folds `\`-newline, as bash reads it
            if expands not in self.lines:
                self.lines[expands] = _Lines(self.text, folded=expands)
            found = self.lines[expands].body(i, delimiter, strip, frame.kind == "(")
            if found:
                body, resume, cut, drop, rejected, following = found
                consumed = following
                if rejected and compatible:
                    raise Unreadable("a substitution heredoc's `EOF)`-line rest begins with "
                                     "`;`: bash 5.2 rejects it, while bash 3.2 may run code "
                                     "after the substitution closes")
                if cut and saved:
                    raise Unreadable("two heredocs queued in one substitution end at lines like "
                                     "`EOF)`: bash 5.2 reports a syntax error after reading them")
                self.out[slot] = " %s " % self.heredoc(body, expands, fd)
                if cut and number + 1 < len(frame.queue):
                    saved = resume, following, drop if compatible else 0
                    i = following
                else:
                    i = resume
                    if cut and drop and compatible:
                        frame.drop = drop, frame.depth
            elif saved:
                raise Unreadable("a heredoc queued after an `EOF)` end has no terminator: bash "
                                 "5.2 reads no code after its body")
            elif required:
                raise Unreadable("a heredoc whose substitution closes before its body has no "
                                 "terminator: bash 5.2 runs nothing after it")
        frame.queue.clear()
        frame.split = False
        if saved:
            rest, following, drop = saved
            self.jumps[following] = i
            if drop:
                frame.drop = drop, frame.depth
            return rest, consumed
        return i, consumed


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
            elif ansi is not None:      # Bash's ASCII ANSI-C escapes
                if (decoded := ansi_c(ansi)) is None:
                    return start
                parts.append(decoded)
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


def _string(text: str, i: int) -> tuple[str, int] | None:
    """(text, end) for the word after a `<<<` ending at `i` when bash hands
    it to the command as written (#2293): its quotes and escapes removed, and
    nothing left that bash expands -- no `$` or backquote outside '...' and
    $'...' that no backslash escapes, no unquoted `~`, no `$'...'` escape
    outside Bash's ASCII table, no `$"..."`. Glob and brace characters
    are text to it. None for an unquoted `[`, which may open a subscript, a
    word no quote closes, no word and a comment: those are read as code."""
    while text.startswith((" ", "\t", "\\\n"), i):
        i += 2 if text[i] == "\\" else 1
    start, parts = i, []
    while i < len(text) and text[i] not in _BREAK:
        match = _QUOTED.match(text, i)
        if match:
            single, ansi, double = match.groups()
            if single is not None:
                parts.append(single)
            elif ansi is not None and (decoded := ansi_c(ansi)) is not None:
                parts.append(decoded)
            elif (double is not None and match[0][0] == '"'
                  and not set("$`") & set(re.sub(r"\\.", "", double, flags=re.S))):
                parts.append(_DQ_ESCAPE.sub(lambda m: m[1] or "", double))
            else:
                return None
            i = match.end()
        elif text[i] in "$`~[\"'":
            return None
        else:
            parts.append(text[i + 1:i + 2].replace("\n", "") if text[i] == "\\" else text[i])
            i += 2 if text[i] == "\\" else 1
    if i == start or text[start] == "#" or text.startswith("(", i):
        return None
    return "".join(parts), i
