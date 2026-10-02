#!/usr/bin/env python3
"""Where a heredoc's body ends, once `shell_lex` has queued its delimiter.

Split out of `scripts/shell_lex.py` (#2331's follow-ups, #2496), which sat
at the 700-line flat-module ceiling with no room left for the next lexer
fix. `_Lines` is the index through which `shell_lex._Lexer.bodies` reads a
queued heredoc's body; `shell_lex` still decides whether a heredoc is
queued at all and refuses what it cannot read -- this module only decides
where a queued body stops and what text it holds.

A later line equal to the delimiter ends a body everywhere; inside a
`$(...)`, `<(...)` or `>(...)` still open, a line that only STARTS with the
delimiter and holds a `)` somewhere after it ends one too (bar a `<<-`
delimiter that starts with a tab, which only its exact line ends), as bash
5.2 ends it (#2343): the rest of that line past its delimiter is left as
code, read as written, where 5.2.21 drops that rest's first `;` and rejects
a rest that starts with one. The omission ends with that LOGICAL line and is
a token boundary, not mere character deletion. `<<-` strips each candidate
line's leading tabs before comparing it with the delimiter, except where the
delimiter itself starts with a tab, the only case that still matches
unstripped. An unquoted delimiter's body has `\\`-newline folded away first,
so its lines are the LOGICAL ones compared with it -- `E\\` + `OF` ends it
where `x \\` + `EOF` does not; a quoted delimiter's body is compared physical
line by physical line.

A body inside a substitution that finds no end line by line leaves its heredoc's
operator in the output as written and marks the reading `unended`. A later
body is scanned only when its exact delimiter exists below it, which bounds
that scan while still finding an earlier `EOF)` line. Bash 5.2 runs nothing
past the first unterminated body either, but bash 3.2 can run code after that
later `EOF)`; the exact-line bound keeps reading those bodies linear rather
than quadratic in the heredocs queued.

Stdlib only."""
import bisect
import re


class _Lines:
    """`text`'s lines the way bash compares a heredoc terminator with them.

    A QUOTED delimiter's body is read verbatim, one physical line at a time;
    an unquoted one has `\\`-newline folded first, so its lines are LOGICAL
    ones -- `E\\` + `OF` ends it where `x \\` + `EOF` does not. `index` is what
    keeps a `<<` with no terminator below it cheap: whether any later line
    ends it is one lookup, where the pass this replaced scanned to the end of
    the script once per operator, which is quadratic in the operators. In a
    substitution, where bash 5.2 ends a body at a line its delimiter starts
    with a `)` after it too (#2343), a body is found line by line. After one
    finds no end (`unended`), a later scan starts only if `index` proves its
    exact delimiter bounds it."""

    def __init__(self, text: str, folded: bool):
        self.size = len(text)
        self.starts = [0] + [match.end() for match in re.finditer("\n", text)]
        self.unended = False            # a body in a substitution found no end
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

    def body(
        self, at: int, word: str, strip: bool, sub: bool
    ) -> tuple[str, int, bool, int, bool, int] | None:
        """Body, resume, `EOF)` end, drop boundary, rejection and next line."""
        k = bisect.bisect(self.starts, at) - 1
        n, offset = self.of[k], self.offset[k] + at - self.starts[k]
        text = self.texts[n]
        # `<<-` strips leading tabs, but bash tries the line unstripped first,
        # which is the only way a delimiter that starts with a tab can match.
        raw = not strip or word.startswith("\t")
        begin, cut = len(text) - len(word), -1
        if sub and not (strip and raw):
            if self.unended and self.index(not raw)[1].get(word, -1) <= n:
                return None             # no exact line bounds a fallback scan
            for end in range(n, len(self.texts)):
                lead = self.texts[end][offset if end == n else 0:].lstrip("\t" if strip else "")
                if lead == word or lead.startswith(word) and ")" in lead[len(word):]:
                    break
            else:
                self.unended = True
                return None
            cut = -1 if lead == word else len(self.texts[end]) - len(lead) + len(word)
        elif begin >= offset and text.endswith(word) and begin == (
                offset if raw else self.lead(at, text, offset)):
            end = n                     # a body can start mid-line after a `\`
        else:
            keys, last = self.index(not raw)
            if last.get(word, -1) <= n:
                return None
            end = keys.index(word, n + 1)
        lines = [text[offset:]] + self.texts[n + 1:end] if end > n else []
        body = "\n".join(line.lstrip("\t") if strip else line for line in lines)
        after = self.last[end] + 1
        following = self.starts[after] if after < len(self.starts) else self.size
        if cut >= 0:                    # code resumes on the line that ended it
            ended = self.texts[end]
            rest = ended[cut:]
            first = cut + len(rest) - len(rest.lstrip(" \t"))
            rejected = ended[first:first + 1] == ";"
            return body, self.source(end, cut), True, following, rejected, following
        return body, following, False, 0, False, following

    def source(self, line: int, offset: int) -> int:
        """Source offset for `offset` in one logical line."""
        first = self.last[line - 1] + 1 if line else 0
        after = self.last[line] + 1
        physical = bisect.bisect(self.offset, offset, first, after) - 1
        return self.starts[physical] + offset - self.offset[physical]

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
