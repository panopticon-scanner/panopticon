#!/usr/bin/env python3
"""A call of a function the step defines, read as its body's fetches and its body's reading of the call's input.

Split out of `scripts/workflow_called.py` at that module's size (686 of its 700 lines), byte for byte (#3112): the
call reading `CalledFetches` (#3050, #2973) with `_Fixed`, its view of a substitution's statements; the call's own
input a body's stage reads (`with_call_stdin`, #2982); the positional parameters a body's word spells whole and the
call's words that stand for them (`_POSITIONAL`, `_positional`, `_with_arguments`); the words of a statement's
command from the one it starts with (`_rest`); and the depth the calls are followed to (`_DEPTH`).
`workflow_called` imports every name back under its own, so nothing that read `workflow_called.CalledFetches` or
`workflow_called.with_call_stdin` moved; this module imports nothing from `workflow_called`, so the layers still
run one way.
"""
import re

import shell_reader
from shell_command import _heads
from shell_tokens import is_arm
from workflow_programs import stdin_reader
from workflow_use_scopes import _body_end, _function_ranges

_DEPTH = 8          # calls followed inside a body, in all


def _rest(argv):
    """The words of a statement's command from the one it starts with (`_head`) on."""
    rest = list(argv)
    while True:
        if rest and is_arm(rest[0]):
            rest = rest[1:]             # `x) f;;`, `x) { f; };;`: the arm stands before all
        rest = rest[len(list(_heads(rest))):]
        if not rest or str(rest[0]) not in ("time", "eval"):
            break
        word, rest = str(rest[0]), rest[1:]
        # One `-p` after `time`, then one `--` after either, as bash 5.2.21 reads them: a
        # second `-p`, or a `-p` past the `--`, is the command (`time -- -p f` runs `-p`).
        if word == "time" and rest and str(rest[0]) == "-p":
            rest = rest[1:]
        if rest and str(rest[0]) == "--":
            rest = rest[1:]
    return rest


# A positional parameter a body's word spells whole: `$1`, `${1}`, `"$1"`. In single quotes it spells
# none (`'$1'`: the reader's `double` is False). `$@` and `$*` are left as written: a body that runs
# its arguments (`w() { "$@"; }`) is #3047's, and a fetcher given them reads them as a `$` word.
_POSITIONAL = re.compile(r"^\$(?:\{([1-9][0-9]*)\}|([1-9][0-9]*))$")


def _positional(word):
    """The number of the positional `word` spells whole, else None."""
    if getattr(word, "double", True) is False:
        return None
    match = _POSITIONAL.match(str(word))
    return int(match[1] or match[2]) if match else None


def _with_arguments(words, arguments):
    """`words` with each positional they spell whole given the call's `arguments` -- `$1` the first
    -- and one the call did not pass as it is written, unsure."""
    out = []
    for word in words:
        which = _positional(word)
        out.append(word if which is None or which > len(arguments) else arguments[which - 1])
    return out


def with_call_stdin(call, stage):
    """`stage`, a body's, reading the standard input its `call` has -- the file, the heredoc or here-string,
    the descriptors the call's redirections leave -- where it reads none of its own and the call gives one;
    else the stage itself, so a reader may tell the two apart (#2973)."""
    if stage.stdin_reads or stage.stdin_heredoc is not None or not (
            call.reads or call.stdin_reads or call.stdin_heredoc is not None or call.heredoc is not None):
        return stage                    # its own input, or a call that gives none: the stage as it is
    return stage._replace(reads=tuple(dict.fromkeys((*call.reads, *stage.reads))), stdin_reads=call.stdin_reads,
                          stdin_heredoc=call.stdin_heredoc, heredoc=call.heredoc if stage.heredoc is None else stage.heredoc,
                          stdin_from_pipe=call.stdin_from_pipe, pipe_input_fds=call.pipe_input_fds)


class CalledFetches:
    """What a step's function calls run where the call stands (#3050). For a call of a function the
    step defines before it, `at` gives the last stage of each statement of its body, and of the
    bodies that body calls in turn, `_DEPTH` functions deep: its words with the call's in their
    positionals (`_with_arguments`; `$@` stays as written, #3047's), and whether its output LEAVES on
    the call's standard output --
    `stdout_to_pipe` at every link, so `f() { curl … > /dev/null; }` leaves nothing, nor does `f` in
    `g() { f > /dev/null; }`. The guard reads a fetcher among them as a fetch of the call's stage,
    where its pipe or its redirect is the consumer (`f | sh`, `sh <(f)`, `f > t`); one that writes
    elsewhere keeps its own stage. Either is read again at the call where the call gave a positional
    a word (`dl URL t`, `changed`): the walk read it as written at its definition. A wrapper in front
    of the name runs no function (`env f`, as `_head` reads it); a definition after the call is no
    function yet; a subshell body is read to its parentheses (`_body_end`). A body's stage that pipes
    on inside the body is not read here -- the walk reads it at its definition -- so `f() { curl … |
    tee t; }`, `f | sh` reads the file and not the stream, a limit."""

    def __init__(self, stmts):
        self.stmts, self.defined = stmts, {}   # type: tuple | list, dict[str, list[tuple[int, int]]]
        ranges, self.occupied = _function_ranges(stmts)
        for entries in ranges.values():
            for name, head, close in entries:
                self.defined.setdefault(name, []).append((head, _body_end(stmts, head, close)[0]))

    def fixed(self, position):
        """This reader for a substitution's statements, each call in them read at `position`."""
        return _Fixed(self, position)

    def at(self, position, argv):
        """[(stage, its words, leaves, changed)] for the call the statement's `argv` -- as written,
        its wrappers in place -- makes at `position`, else []."""
        rest = _rest(argv)
        head = str(rest[0]) if rest else None
        if head is None or head not in self.defined:
            return []
        found, queue, seen = [], [(head, list(rest[1:]), True)], set[str]()
        while queue and len(seen) < _DEPTH:
            name, arguments, leaves = queue.pop(0)
            seen.add(name)
            for head_at, end in self.defined[name]:
                if name == head and head_at >= position:
                    continue
                for statement in self.stmts[head_at:end + 1]:
                    stage = statement.stages[-1] if statement.stages else None
                    if stage is None:
                        continue
                    inner = _rest(_with_arguments(list(stage.argv), arguments))
                    called = str(inner[0]) if inner else None
                    if called is not None and called in self.defined and len(statement.stages) == 1:
                        if called not in seen and all(called != queued for queued, _a, _l in queue):
                            queue.append((called, list(inner[1:]), bool(leaves and stage.stdout_to_pipe)))
                        continue
                    written = shell_reader.acted(stage.argv)
                    words = _with_arguments(written, arguments)
                    if words and (leaves and stage.stdout_to_pipe or words != written):
                        found.append((stage, words, leaves and stage.stdout_to_pipe, words != written))
        return found


    def consumers(self, position, following):
        """`following`, the stages behind a fetch in its statement, with the stage that reads the fetch's
        output as a shell put where a call of a function the step defines before `position` stands --
        or a bare `{`/`(` that opens a group on its own (#2973). The body's statements in order, or the
        group's, and the bodies they call in turn (`_DEPTH`): the first stage whose command reads stdin
        as a shell (`workflow_programs.stdin_reader`) -- where a stage pipes on, the first such stage
        behind it in its pipeline -- given the call's own standard input (`with_call_stdin`); one that
        reads a file or a heredoc of its own reads nothing of the call's, and the walk goes on,
        fail-closed: a stage in front that is no shell is read as leaving stdin to the next. A statement
        inside a definition in the group runs only when called. A body with no such stage leaves the
        call as written (`f() { wc -l; }`: nothing runs). The stages behind the call stay."""
        out = list(following)
        for at, stage in enumerate(out):
            rest = _rest(stage.argv)
            head = str(rest[0]) if rest else None
            raw = [str(word) for word in stage.argv]
            if raw == ["{"] or stage.group_open and not raw:            # a bare `{` or `(`, as written
                found = self._reading(self._group(position), stage, position, [])
            elif head is not None and head in self.defined:
                found = self._reading([], stage, position, [(head, position)])
            else:
                continue
            if found is not None:
                out[at] = found
                return out
        return out

    def consumer_words(self, position, stage, argv):
        """The words of the stage that reads `stage`'s standard input, a call's, as `consumers` puts it
        -- as a reader that unwraps a `find`'s action reads them (`shell_reader.acted`) -- or `argv`, the
        stage's own words read so already: what a substitution the stage holds is handed to (`f <<<
        "$(curl …)"`, #2973). A stage that is no call is read once, by the caller."""
        read = self.consumers(position, [stage])[0]
        return argv if read is stage else shell_reader.acted(read.argv)

    def _group(self, position):
        """The indices of the statements of the group a bare opener ends statement `position` with."""
        depth, inner = 1, []
        for at in range(position + 1, len(self.stmts)):
            for stage in self.stmts[at].stages:
                depth += stage.group_open - stage.group_close
            if depth <= 0:
                break
            inner.append(at)
        return inner

    def _reading(self, group, call, position, queue):
        """The first stage -- among the group's statements `group` (a definition's skipped), then those of
        each body `queue` names with the index its call stands at, and the bodies they call -- that reads
        `call`'s standard input as a shell, given that input (`with_call_stdin`); None where none does."""
        pending, skipping, seen = list(group), True, set[str]()
        while pending or queue:
            if not pending:
                name, called_at = queue.pop(0)
                seen.add(name)
                pending = [at for head_at, end in self.defined[name] if head_at < called_at
                           for at in range(head_at, end + 1)]
                skipping = False
                continue
            at, pending = pending[0], pending[1:]
            if skipping and at in self.occupied:
                continue
            for inner in self.stmts[at].stages:
                words = shell_reader.acted(inner.argv)
                if not words:
                    continue
                if inner.stdin_reads or inner.stdin_heredoc is not None:
                    continue
                if stdin_reader(list(map(str, words))) is not None:
                    return with_call_stdin(call, inner)
                rest = _rest(inner.argv)
                named = str(rest[0]) if rest else None
                if named in self.defined and named not in seen and all(named != q for q, _a in queue) and len(seen) < _DEPTH:
                    queue.append((named, at))
                if not inner.stdout_to_pipe:
                    break
        return None

class _Fixed:
    """`CalledFetches` for the statements of a substitution: every call read at the step's statement
    that holds it, so a definition after that statement is no function to them either."""

    def __init__(self, reader, position):
        self.reader, self.position = reader, position

    def fixed(self, _position):
        return self

    def at(self, _position, argv):
        return self.reader.at(self.position, argv)

    def consumers(self, _position, following):
        return self.reader.consumers(self.position, following)

    def consumer_words(self, _position, stage, argv):
        return self.reader.consumer_words(self.position, stage, argv)
