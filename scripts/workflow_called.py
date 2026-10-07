#!/usr/bin/env python3
"""What a called function may leave in the caller's value table (#2664 fix rounds, #2785).

`static_values` walks the step's statements into a `Values` table and skips every function
body where it is written -- a body runs only when called -- and it recorded nothing at the
CALL either, so `T=/dev/null; f() { T=/tmp/payload; }; f; sh "$T"` held the caller's old `T`
at the use while bash ran the payload. Carrying the body's VALUE out surely was tried and read
past what the shells do (a `return` the body takes, a wrapper that never runs a function, a
later redefinition, a stand-in, a `declare -g` the shell lacks), so the carry is fail-closed:
a call to a function whose body assigns NAME -- any definition of it before the call, and any
function the body calls, to a bounded depth -- adds what the body may assign as UNSURE
candidates at every later use and keeps the caller's own, so a use reads both and the guard
reports where either is the download (`record_called`); past the value table's cap a use
reads its stand-in as every download, whatever a call added (`workflow_values.PAST`, round 7).
Not read as a call: a word behind a wrapper (`env f`, `timeout 5 f`, `command f`: none runs a
shell function), unless the step defines a function of that name (`sudo() { … }; sudo x`).
Not carried: a name the body makes `local` (it dies with the call in bash and dash alike), a
subshell body (`f() ( T=x )`), and a call run in a child the use is not in -- the step's `f &`,
or a body's call in a list it backgrounds (`g() { f & wait; }`); a one-line `( f )` is still
carried, fail-closed. The prices, named in the CHANGELOG with the rest (a body's `( T=P )`,
read as the step's own is; a `{ f; } &` group in a body; a call behind `&>` under dash):
`T=P; f() { T=/dev/null; }; f; sh "$T"` is reported though no shell runs `P`; and `eval -p f` or
`eval -- -- f` reads as a call of `f`, since the guard's `eval` reader keeps the words not led by
`-` as the program, though bash rejects `-p` and dash runs `--` as a command. A call site
carries once per step from each state of the names its bodies spell or set (`_named`; of the
whole table where a body may set any name, `_record_any`), and past `_BUDGET` such states each
name they may set gains the cap's stand-in, a price named there too. The sure carry is #2785's
own PR.

Beside `scripts/workflow_values.py`, which is at its ceiling; imports nothing above it.
"""
import os
import re

from shell_command import _ASSIGNMENT, _heads
from shell_tokens import is_arm
from workflow_function_calls import _function_syntax
from workflow_values import PAST, Values, _update, emptied, record

_DEPTH = 8          # calls followed inside a body, in all
# A call site's carry is kept per step (`_carried`), keyed on the state of the names its bodies
# spell or set alone (`_named`): `static_values` rebuilds the table at each statement that reads
# one, and carrying every earlier call's bodies again there made a step cubic where `main` is
# quadratic -- as keyed on the whole table it still was, where a loop changes a name between
# calls or a step holds many names (rounds 8 and 9, B5). Past `_BUDGET` states at one call site
# (a body reading a name its loop changes), each name its bodies may set gains the cap's
# stand-in instead, unsure: fail-closed, a price. The last few steps are kept, each with its
# statements, so an id is never reused while its entry stands.
_BUDGET = 8
_CARRIED: dict[int, tuple[list, int, dict]] = {}
_SPELLED = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _head(argv):
    """The word a statement's command starts with, past the `case` arm, keywords, assignments
    and function header in front of it (`_heads`), and past `time` (with `-p`, `--`) and
    `eval`, each read again after (`time { f; }`, `time X=1 f`, `x) time ! f`, `eval time f`):
    bash runs the function behind them (rounds 3 and 4). A wrapper there is the word itself:
    `env f` calls no function unless the step defines one named `env` (`sudo() {…}; sudo x`)."""
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
    return str(rest[0]) if rest else None


def _calls(stmts, head, close):
    """The functions the body `stmts[head:close + 1]` calls: a single-stage statement whose
    head word is bare and no assignment, in a list the body does not send to the background
    (`g() { f & wait; }`: as at the top level, what the child assigns dies with it) -- each
    list's end read once, walking the body backwards (round 8, B3)."""
    found, backgrounded = set(), False
    for at in range(close, head - 1, -1):
        statement = stmts[at]
        if at == close or statement.separator not in ("&&", "||"):
            backgrounded = statement.separator == "&"      # this statement ends its list
        if len(statement.stages) == 1 and not backgrounded:
            word = _head(list(statement.stages[0].argv))
            if word and not _ASSIGNMENT.match(word):
                found.add(word)
    return found


def _carry(table, stmts, head, close):
    """Add what the body `stmts[head:close + 1]` may assign to `table`, unsure: each
    assignment as an uncertain one (`record`), an `unset` or bare `local` as a "maybe unset",
    a `read` as the stand-in -- and nothing for a name the body makes `local`."""
    inner = table.copy()
    local: set[str] = set()
    for statement in stmts[head:close + 1]:
        stage = statement.stages[-1] if statement.stages else None
        if stage is None:
            continue
        word = _head(list(stage.argv))
        argv = [str(w) for w in stage.argv]
        name = os.path.basename(word) if word else ""
        words = [w for w in argv[argv.index(word) + 1:] if not w.startswith("-")] if word in argv else []
        if name in ("local", "declare", "typeset") and not any(
                w.startswith("-") and "g" in w for w in argv):
            local.update(w.split("=", 1)[0].split("[", 1)[0] for w in words)
            for w in words:
                if "=" not in w:
                    emptied(inner, w, False)
        elif name == "read" or name == "unset" and "-f" not in argv:
            for w in words:
                emptied(inner, w, False, name == "read")
        record(inner, stage, False)
    # What the body adds goes after the caller's own candidates, never in place of one; past
    # the cap a use reads the cap's stand-in, whatever the order (`workflow_values.PAST`).
    for kind in ("scalars", "arrays"):
        before, after = getattr(table, kind), getattr(inner, kind)
        for name in set(after) - local:
            own = before.get(name, [])
            before[name] = own + [candidate for candidate in after[name] if candidate not in own]


def _state(table, names):
    """The state of `names` in `table` -- all of it where None -- as a key: each text with the
    lifted markers `derived` carries."""
    def texts(values):
        return tuple((str(text), tuple(sorted(getattr(text, "markers", {})))) for text in values)

    def held(kind):
        return kind if names is None else {name: kind[name] for name in names if name in kind}
    return (tuple(sorted((name, texts(values)) for name, values in held(table.scalars).items())),
            tuple(sorted((name, tuple(map(texts, lists))) for name, lists in held(table.arrays).items())))


def _carried(stmts):
    """The call sites already read in the step `stmts`: {position: (bodies, names, written,
    anything, {state: what the carry left})}, the last a list of (table, what the carry left)
    where a body may set any name."""
    entry = _CARRIED.get(id(stmts))
    if entry is None or entry[0] is not stmts or entry[1] != len(stmts):
        _CARRIED[id(stmts)] = entry = (stmts, len(stmts), {})
        while len(_CARRIED) > 8:
            _CARRIED.pop(next(iter(_CARRIED)))
    return entry[2]


def _reached(stmts, position, starts):
    """The bodies a single-stage call at `position` carries, in order, as (head, close): every
    definition of its name before it, and every function those bodies call, `_DEPTH` functions
    deep; a definition after the call is no function yet, and a subshell body reaches nothing."""
    stage = stmts[position].stages[0] if stmts[position].stages else None
    head = _head(list(stage.argv)) if stage else None
    defined: dict[str, list[tuple[int, int, int]]] = {}
    for at, entries in starts.items():
        for name, start, close in entries:
            defined.setdefault(name, []).append((at, start, close))
    if head is None or head not in defined:
        return []
    bodies, queue, seen = [], [head], set[str]()
    while queue and len(seen) < _DEPTH:
        name = queue.pop(0)
        seen.add(name)
        for at, start, close in defined.get(name, []):
            if name == head and at >= position or _subshell(stmts, start, close):
                continue
            bodies.append((start, close))
            queue.extend(call for call in _calls(stmts, start, close)
                         if call in defined and call not in seen and call not in queue)
    return bodies


def _subshell(stmts, start, close):
    """Whether the body defined at `start` runs in a subshell: its header's stage opens a `(`
    that no `{` follows (`f() ( T=x )`, `f() ( echo { ; T=x )`) or that the body's `}` does not
    close (`f() ( { T=x; } )`), where `f() { ( T=x ); }` closes it first. The reader keeps no
    place for a `(`, so its depth says which came first (round 9, F2)."""
    first = stmts[start].stages[0] if stmts[start].stages else None
    if first is None or not first.group_open:
        return False
    if "{" not in _function_syntax(first.argv)[1]:
        return True
    depth = 0
    for statement in stmts[start:close]:
        depth += sum(stage.group_open - stage.group_close for stage in statement.stages)
        if depth <= 0:
            return False
    return True


def _named(stmts, bodies):
    """(names, written, anything) for `bodies`: `names`, every name they spell -- a name a body
    reads or sets is spelled, as `valued` reads no `${!T}` -- and every name a dry carry, each
    spelled name held without a candidate, shows them set (`REPLY` behind a bare `read`), which
    are `written`; `anything` where one may set a name it does not spell (`eval`, `source`, a
    name taken from a value), as a held name none of them spells then shows."""
    spelled = {name for start, close in bodies for statement in stmts[start:close + 1]
               for stage in statement.stages for word in stage.argv
               for name in _SPELLED.findall(str(word))}
    probe = "_" * (2 + max(map(len, spelled), default=0))      # a name no body spells
    dry = Values({name: [] for name in spelled | {probe}})
    for start, close in bodies:
        _carry(dry, stmts, start, close)
    written = {name for name, texts in dry.scalars.items() if texts} | set(dry.arrays)
    return frozenset(spelled | written) - {probe}, frozenset(written - {probe}), probe in written


def record_called(table, stmts, position, starts):
    """At statement `position`, a single-stage call of a function the step defines before it,
    add what its body may assign to `table` as unsure candidates, the caller's own kept
    (`_carry`): the bodies `_reached` lists, every definition of the name before the call and
    every function the body calls. `starts` maps a definition's index to (name, head, close). A
    call site carries once per step from each state of the names its bodies spell or set
    (`_named`), and a later visit from that state takes what the carry left, exactly as a carry
    makes it; past `_BUDGET` states, each name its bodies may set gains the cap's stand-in."""
    sites = _carried(stmts)
    if position not in sites:
        bodies = _reached(stmts, position, starts)
        names, written, anything = _named(stmts, bodies)
        sites[position] = (bodies, names, written, anything, [] if anything else {})
    bodies, names, written, anything, carries = sites[position]
    if not bodies:
        return
    if anything:
        _record_any(table, stmts, bodies, written, carries)
        return
    key = _state(table, names)
    if key in carries:
        scalars, arrays = carries[key]
        for name in names:
            table.scalars.pop(name, None)
            table.arrays.pop(name, None)
        table.scalars.update((name, list(texts)) for name, texts in scalars.items())
        table.arrays.update((name, [list(words) for words in lists]) for name, lists in arrays.items())
    elif len(carries) < _BUDGET:
        for start, close in bodies:
            _carry(table, stmts, start, close)
        carries[key] = ({name: list(table.scalars[name]) for name in names if name in table.scalars},
                        {name: [list(words) for words in table.arrays[name]]
                         for name in names if name in table.arrays})
    else:
        for name in written:
            _update(table, name, [PAST], False)


def _record_any(table, stmts, bodies, written, carries):
    """`record_called` where a body may set any name (`eval`, `source`, a name taken from a
    value): every held name gains its stand-in at each call, so the whole table is the state,
    compared and restored as the dicts it is -- a held list is replaced, never changed in place,
    so a kept one is shared -- and a call costs one pass over the held names, as the carry's own
    pass does. Past `_BUDGET` states, every held name and each the bodies set gains the cap's
    stand-in."""
    state = (table.scalars, table.arrays)
    for before, after in carries:
        if before == state:
            for kind, kept in zip(state, after or ()):
                kind.clear()
                kind.update(kept)
            return
    if len(carries) >= _BUDGET:
        for name in {*written, *table.scalars, *table.arrays}:
            _update(table, name, [PAST], False)
        return
    before = (dict(table.scalars), dict(table.arrays))
    for start, close in bodies:
        _carry(table, stmts, start, close)
    after = (dict(table.scalars), dict(table.arrays))
    carries.append((before, None if after == before else after))
