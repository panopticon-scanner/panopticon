"""The understood subset of shell (#3141): what a step a download reaches may run for the guard to vouch for it.

The guard is this repo's own lint over its own workflows (the owner's decision on #3141), so the subset is the small
one those workflows use where a download reaches -- in the step that fetches and in every step after it in the job --
and it is derived from them: the commands of `COMMANDS` (wrappers such as `sudo` and `timeout` taken off by
`shell_command.command`), the keywords of `SYNTAX` (`if` and `case` with their arms, `{ }` groups), assignments,
pipes and lists, and command substitutions held to the same rule. `fully_read` names the first construct outside it,
a private-use character anywhere in the step first, and `workflow_guard.job_defects(steps, subset=True)` reports such
a step UNVERIFIED. A workflow that needs more widens `COMMANDS` or `SYNTAX` here, by name, in the PR that needs it."""
import collections
import re

import shell_command
import shell_reader
from shell_text import Process
from shell_tokens import _markers

# The first construct of a step outside the subset, and the 1-based line of the step's script it stands on: None where
# the text does not show its word (one the reader spelled anew).
Unread = collections.namedtuple("Unread", "construct line")

# Every command a download-reachable step in `.github/workflows/` runs: docker-build-pr.yml's hadolint steps and
# nvd-cache.yml's sync and image steps.
COMMANDS = frozenset({
    "[", "apt-get", "chmod", "curl", "docker", "echo", "exit", "hadolint", "mkdir", "mv", "printf", "set",
    "sha256sum", "stat", "test", "unzip",
    "./dependency-check/bin/dependency-check.sh",       # nvd-cache.yml runs what it unpacked from the checked dc.zip
})
# The keywords their syntax stands on, each the first word of a statement; any other keyword there is outside.
SYNTAX = frozenset({"if", "then", "elif", "else", "fi", "case", "esac", "{", "}"})
# The characters the reader marks its words with (`shell_reader._MARKS`) and the rest of the private-use area.
_PRIVATE = re.compile("[%s-%s]" % (chr(0xE000), chr(0xF8FF)))


def fully_read(statements, script):
    """The first construct of a step outside the subset, or None: a private-use character in `script`, the step's text
    as written, first; then each of `statements`, as `workflow_guard.read` gives them, in order."""
    mark = _PRIVATE.search(script)
    if mark:
        return Unread("a private-use character", script.count("\n", 0, mark.start()) + 1)
    return next(_outside(statements, _Lines(script)), None)


def _outside(statements, lines):
    """Every construct of `statements` outside the subset, in order, and in each command substitution's text."""
    for statement in statements:
        for stage in statement.stages:
            words = [word for word in stage.argv if not shell_reader.is_arm(word)]
            lead = words[0] if words else ""
            line = lines.find(lead)              # where the stage stands: each one's line follows its last
            if lead == "case":                   # its subject is a word, not a command
                continue
            if lead.endswith("()") or lead in shell_command.KEYWORDS and lead not in SYNTAX:
                yield Unread("a function definition" if lead.endswith("()") else "the keyword `%s`" % lead, line)
            run = shell_command.command(stage.argv)
            if run and (not isinstance(run[0], str) or shell_reader.is_marker(run[0]) or run[0] not in COMMANDS):
                word = shell_reader.readable(str(run[0]))
                yield Unread("the command `%s`" % word, lines.find(word) or line)
            if any(kind == "subst" and isinstance(value, Process)
                   for word in (*stage.argv, *stage.reads, *stage.writes) for kind, value in _markers(word).values()):
                yield Unread("a process substitution", line)
            for text in stage.substitutions:
                yield from _outside(shell_reader.statements(text), lines)


class _Lines:
    """The line a word stands on. Tokens carry none, so it is where the word next stands whole, outside a comment, past
    the last word found -- or else from the start of the line the last word found stands on, for the holder of a
    statement the reader spliced in from its string, which stands before it. Each search starts there and counts the
    lines it passes, so a step is read in one pass. Best effort: None where the word is not found, or is a lifted
    substitution's marker, which the text never holds."""

    def __init__(self, script):
        self.script, self.start, self.line, self.after = script, 0, 1, 0

    def find(self, word):
        if not word or shell_reader.is_marker(word):
            return None
        whole = re.compile(r"(?<![\w./-])%s(?![\w./-])" % re.escape(word))
        for start in (self.after, self.start):
            for found in whole.finditer(self.script, start):
                line_start = self.script.rfind("\n", self.start, found.start()) + 1 or self.start
                if not re.search(r"(?:^|\s)#", self.script[line_start:found.start()]):
                    self.line += self.script.count("\n", self.start, line_start)
                    self.start, self.after = line_start, found.end()
                    return self.line
        return None
