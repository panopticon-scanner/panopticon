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
from shell_command import _FUNCTION, _heads
from shell_folds import _CALLED
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


# What a call stands for in the fold `shell_folds._CALLED` reads (#3047, #3091): the step grows by `_INLINED`
# statements at most from its calls' bodies, past which the rest read as written. A word that spells the call's words
# whole -- `"$@"`, `$@`, `$*`, and `"$*"` (one word, read spliced too: an over-read, named) -- and an assignment of
# one positional to a name (`c="$1"`, `local` or not), the body's copy of the call's word.
_INLINED = 64
_SPLICED = re.compile(r"^\$(?:@|\*|\{@\}|\{\*\})$")
_SPELLS = re.compile(r"\$\{?[1-9@*#]")     # a word spelling a positional, `$@`, `$*` or `$#`: the body reads its call's words
_COPIED = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=\$(?:\{([1-9][0-9]*)\}|([1-9][0-9]*))$")


def _bound(words, arguments):
    """`words`, a body's, as the call's `arguments` make them: each positional they spell whole given the call's
    word (`_positional`), `"$@"` or `$*` the call's words spliced in, `NAME=$N` the name set to the call's word; a
    positional the call did not pass or one gone stale (None: a relative word behind a `cd` of the body's own,
    `_expanded`), one single-quoted (`'$1'`, `c='$1'`: no `$` of it live) and every other word, as written."""
    out = []
    for word in words:
        which = _positional(word)
        if which is not None:
            out.append(word if which > len(arguments) or arguments[which - 1] is None else arguments[which - 1])
        elif getattr(word, "live_dollar", True) is False:     # a `$` single-quoted or escaped: no word of the call's
            out.append(word)
        elif _SPLICED.match(str(word)):
            out.extend(given for given in arguments if given is not None)
        elif (copy := _COPIED.match(str(word))) and int(copy[2] or copy[3]) <= len(arguments) and (
                given := arguments[int(copy[2] or copy[3]) - 1]) is not None:
            out.append(shell_reader.derived("%s=%s" % (copy[1], given), given))
        else:
            out.append(word)
    return out


def _header_end(argv):
    """The index past a function header's words in `argv` -- the keywords in front, then `function NAME`, `NAME()`
    or `NAME ()`, then a `{` -- or 0 where it starts with none."""
    at = 0
    while at < len(argv) and argv[at] in shell_reader.KEYWORDS and argv[at] != "function":
        at += 1
    if at < len(argv) and argv[at] == "function" and at + 1 < len(argv):
        at += 2 + (at + 2 < len(argv) and argv[at + 2] == "()")
    elif at < len(argv) and _FUNCTION.match(argv[at]):
        at += 1
    elif at + 1 < len(argv) and argv[at + 1] == "()":
        at += 2
    else:
        return 0
    return at + (at < len(argv) and argv[at] == "{")


def _body(stmts, head, end):
    """[(index, statement)] for the body defined at `head` through `end`: the header's words off its first statement
    (`f() {`, a line of its own dropped), its `}` closer dropped -- what a call of it stands for."""
    out = []
    for at in range(head, end + 1):
        stages = list(stmts[at].stages)
        if at == head and stages:
            argv = list(stages[0].argv)
            del argv[:_header_end(argv)]
            if not argv and len(stages) == 1:
                continue
            stages[0] = stages[0]._replace(argv=argv)
        if [str(word) for stage in stages for word in stage.argv] == ["}"]:
            continue
        out.append((at, stmts[at]._replace(stages=stages)))
    return out


def _call(reader, statement, position, gone=frozenset()):
    """(stage index, name, the words in front, the call's words) where a stage of `statement` calls a function
    `reader` has defined before `position` and no `unset -f` took away (`gone`) -- its command word, past the
    keywords and assignments in front (`_rest`) -- else None."""
    for at, stage in enumerate(statement.stages):
        rest = _rest(stage.argv)
        name = str(rest[0]) if rest else None
        if name in reader.defined and name not in gone and any(head < position for head, _end in reader.defined[name]):
            return at, name, list(stage.argv[:len(stage.argv) - len(rest)]), list(rest[1:])
    return None


def _body_reads(reader, name, position, depth=1):
    """(words, input): whether the body `name` last got before `position` reads its call's words -- a word
    spelling a positional, `$@`, `$*` or `$#` (`_SPELLS`), or a `shift` -- and whether, one stage, it reads its
    call's standard input as a shell (`workflow_programs.stdin_reader`), or calls a function whose body does,
    `_DEPTH` deep. A body that reads neither is read where it stands, as `main` reads it, and its call as
    written: the carries, the checks and the gates of a call keep their readings (#3047)."""
    entries = [entry for entry in reader.defined.get(name, ()) if entry[0] < position]
    if not entries or depth > _DEPTH:
        return False, False
    body = [item for _at, item in _body(reader.stmts, *entries[-1])]
    words = any(_SPELLS.search(str(word)) for item in body for stage in item.stages for word in stage.argv) or any(
        str(rest[0]) == "shift" for item in body for stage in item.stages if (rest := _rest(stage.argv)))
    if len(body) != 1 or len(body[0].stages) != 1:
        return words, False
    rest = _rest(body[0].stages[0].argv)
    named = str(rest[0]) if rest else None
    if named is not None and stdin_reader(list(map(str, rest))) is not None:
        return words, True
    return words, named in reader.defined and _body_reads(reader, named, position, depth + 1)[1]


def _certain(stmts):
    """The indices of the statements that run where the step does: outside every `if`, `for`, `while`, `until`
    and `case`, and not behind `&&` or `||`. A definition or an `unset -f` elsewhere may never run: `main`
    installs no function from it (`workflow_uses._functions_before`), and the fold stands for none."""
    out, depth = set(), 0
    for index, statement in enumerate(stmts):
        opened = closed = 0
        for stage in statement.stages:
            for token in _heads(stage.argv):
                opened += token in ("if", "for", "while", "until", "case")
                closed += token in ("fi", "done", "esac")
        header = bool(statement.stages) and _header_end(list(statement.stages[0].argv)) > 0   # `f() { for …`: the body's
        if depth == 0 and (header or not opened) and not (index and stmts[index - 1].separator in ("&&", "||")):
            out.add(index)
        depth = max(0, depth + opened - closed)
    return out


def _inlined(reader, statement, position, gone=frozenset()):
    """`_call` where the call stands for its body in the fold: the body reads the call's words, or its input where
    the call gives one -- a pipe, a file, a heredoc or a here-string (`_body_reads`); else None."""
    call = _call(reader, statement, position, gone)
    if call is None:
        return None
    at, name, _heads, _arguments = call
    words, reads = _body_reads(reader, name, position)
    stage = statement.stages[at]
    given = at > 0 or bool(stage.stdin_reads) or stage.stdin_heredoc is not None or bool(stage.reads)
    return call if words or (reads and given) else None


def _with_call(call, stage, heads):
    """`stage`, a one-statement body's, where its `call` stands: behind the call's `heads`, reading the call's
    standard input where it reads none of its own (`with_call_stdin`), writing the call's standard output where
    it writes none, the call's substitutions beside its own."""
    read = with_call_stdin(call, stage)
    read = read._replace(reads=list(read.reads))         # a list, as every stage's: the checks reader adds to it
    if not stage.writes and not stage.stdout_writes:
        read = read._replace(writes=call.writes, stdout_writes=call.stdout_writes, stdout_to_pipe=call.stdout_to_pipe,
                             pipe_output_fds=call.pipe_output_fds, redirected=stage.redirected or call.redirected)
    return read._replace(argv=[*heads, *read.argv], substitutions=[*stage.substitutions, *call.substitutions])


def _expanded(reader, stmts, statement, position, depth, room, gone=frozenset(), used=None):
    """`statement` as the statements its call stands for (`_inlined`) -- the body the name last got before
    `position` (`_body`), its words as the call makes them (`_bound`), a `shift` of its own dropping the call's
    words for the statements after it, a `set --` giving them its own, a `cd` (`pushd`, `popd`) leaving only the
    absolute ones, a `~` or a `$` word, live (a relative one named a file where the call stood, as the use reader
    reads a body's `cd`), each call among them followed in turn to `_DEPTH` and `room` statements. A one-stage
    body takes the call's place in its pipeline, with its input and output (`_with_call`); a longer one the call's
    words in front and its separator behind, where the call is a statement of its own with no redirection;
    else, past the depth or the room, or where the header's line opens a group (`f() ( … )`), the statement as
    written. The (head, end) of each definition stood for, here and in the bodies followed, goes into `used`; one
    inside the body stood for in turn is emptied in the copy (`_emptied`), as `called` empties one the step holds."""
    call = _inlined(reader, statement, position, gone)
    if call is None or depth > _DEPTH or room < 1:
        return [statement]
    at, name, heads, arguments = call
    head, end = [entry for entry in reader.defined[name] if entry[0] < position][-1]
    if stmts[head].stages and stmts[head].stages[0].group_open:
        return [statement]
    out, origins = [], []            # the body's statements as the call makes them, each with its index in `stmts`
    for origin, item in _body(stmts, head, end):
        words = [str(word) for word in _rest(item.stages[0].argv)] if item.stages else []
        if len(item.stages) == 1 and words[:1] == ["shift"] and len(words) < 3 and (len(words) == 1 or words[1].isdigit()):
            del arguments[:int(words[1]) if len(words) == 2 else 1]
            continue
        if len(item.stages) == 1 and words[:2] == ["set", "--"]:
            arguments = _bound(list(item.stages[0].argv), arguments)[2:]
            continue
        if len(item.stages) == 1 and words[:1] in (["cd"], ["pushd"], ["popd"]):
            arguments = [given if given is None or str(given).startswith(("/", "~", "$")) or shell_reader.has_substitution(given)
                         else None for given in arguments]
        out.append(item._replace(stages=[stage._replace(argv=_bound(stage.argv, arguments)) for stage in item.stages]))
        origins.append(origin)
    stage = statement.stages[at]
    if len(out) == 1 and len(out[0].stages) == 1:
        stages = list(statement.stages)
        stages[at] = _with_call(stage, out[0].stages[0], heads)
        out = [statement._replace(stages=stages)]
    elif out and len(statement.stages) == 1 and not stage.redirected and stage.stdin_heredoc is None:
        first = out[0].stages[0]
        out[0] = out[0]._replace(stages=[first._replace(argv=[*heads, *first.argv]), *out[0].stages[1:]])
        out[-1] = out[-1]._replace(separator=statement.separator)
    else:
        return [statement]
    used = set() if used is None else used
    used.add((head, end))
    parts: list[list] = []
    grown = 0
    for item in out:
        parts.append(_expanded(reader, stmts, item, position, depth + 1, room - grown, gone, used))
        grown += len(parts[-1])
    emptied = _emptying(pair for pair in used if head <= pair[0] <= end and pair != (head, end))
    followed: list = []
    for origin, item, part in zip(origins, out, parts):
        if origin not in emptied:
            followed.extend(part)
        elif emptied[origin][0] == origin:
            followed.extend(_emptied(item, stmts[emptied[origin][1]]))
    return followed


def _emptied(header, closer):
    """A definition with its body gone: `header`, the statement its header's words start, with those words alone,
    then `closer`, the statement of its `}`, where that is another -- what stands where a definition stood in the
    fold, a call of it standing for its body (`called`). The step still defines the name, as `workflow_annotate`'s
    rule 7 and `_function_ranges` read it; the body is read at its calls, not where it stands too (that reading
    is `main`'s, kept beside the fold's)."""
    first = header.stages[0]
    heads = list(first.argv[:_header_end(list(first.argv))])
    stage = first._replace(argv=heads, writes=[], reads=[], heredoc=None, substitutions=[], stdout_writes=[],
                           stdin_heredoc=None, stdin_reads=(), fd_bodies=(), redirected=False)
    return [header._replace(stages=[stage]), *([closer] if closer is not None else [])]


def _emptying(pairs):
    """Each statement of the definitions `pairs` -- (head, end) each -- to the pair it is emptied with: the outer
    one where two share a head (`outer() { inner() {`, one statement), which takes the inner one's statements."""
    out: dict[int, tuple[int, int]] = {}
    for head, end in sorted(pairs, key=lambda pair: (pair[0], -pair[1])):
        for at in range(head, end + 1):
            out.setdefault(at, (head, end))
    return out


def called(stmts):
    """`stmts` with each call of a function the step defines before it -- a statement not inside a definition --
    standing for its body as the call makes it (`_expanded`), in the fold `shell_folds._CALLED` reads -- a
    definition that surely ran (`_certain`), the last before the call -- and each definition stood for emptied
    (`_emptied`): the fold reads a body at its calls, not where it stands too, so a body that fetches after it
    runs is no run of its own fetch where one call makes it (two are). Outside the fold, `stmts` as they are, the
    fold asked for where such a call stands (`met`). `main`'s reading of the definition and of the call is kept
    beside the fold's, so a check a body credits in the fold alone takes no report away (#3047, #3091)."""
    stmts = list(stmts)
    reader = CalledFetches(stmts)
    if not reader.defined:
        return stmts
    # The statements the definitions hold, each body read to its end (`_body_end`): `_function_ranges` takes a
    # parenthesised body (`h() (…)`) to reach the step's end, and would take every call after it for a body's.
    occupied = {at for entries in reader.defined.values() for head, end in entries for at in range(head, end + 1)}
    certain = _certain(stmts)
    reader.defined = {name: kept for name, entries in reader.defined.items()
                      if (kept := [entry for entry in entries if entry[0] in certain])}
    stood: dict[int, list] = {}         # the statements each call stands for, by the call's index
    used: set[tuple[int, int]] = set()  # (head, end) of each definition stood for, there and in the bodies followed
    gone: set = set()                   # the names a certain `unset -f` took away, until defined again
    added = 0                           # the statements the step grew by, against `_INLINED`
    for index, statement in enumerate(stmts):
        gone -= {name for name, entries in reader.defined.items() if any(head == index for head, _end in entries)}
        words = [str(word) for word in _rest(statement.stages[0].argv)] if len(statement.stages) == 1 else []
        if words[:2] == ["unset", "-f"] and index in certain:
            gone.update(words[2:])
        if index in occupied or _inlined(reader, statement, index, gone) is None:
            continue
        if not _CALLED["on"]:
            _CALLED["met"] = True
            continue
        stood[index] = _expanded(reader, stmts, statement, index, 1, _INLINED - added, frozenset(gone), used)
        added += len(stood[index]) - 1
    if not stood:
        return stmts
    emptied = _emptying(used)
    out: list = []
    for index, statement in enumerate(stmts):
        if index in stood:
            out.extend(stood[index])
        elif index not in emptied:
            out.append(statement)
        elif emptied[index][0] == index:
            out.extend(_emptied(statement, stmts[emptied[index][1]] if emptied[index][1] != index else None))
    return out
