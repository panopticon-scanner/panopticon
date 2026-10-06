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
reports where either is the download (`record_called`). What a call adds is marked carried,
so the value table's cap drops it before any candidate the caller's own walk holds, for a
scalar and an array alike (round 6). Not read as a call: a word behind a wrapper (`env f`,
`timeout 5 f`, `command f`: none runs a shell function), unless the step defines a function
of that name (`sudo() { … }; sudo x`). Not carried: a name the body makes `local` (it dies
with the call in bash and dash alike), a subshell body (`f() ( T=x )`), and a call the step
runs in a child the use is not in (`f &`; a one-line `( f )` is still carried, fail-closed).
The one price, named in the CHANGELOG: `T=P; f() { T=/dev/null; }; f; sh "$T"` is reported
though no shell runs `P`. The sure carry is #2785's own PR.

Beside `scripts/workflow_values.py`, which is at its ceiling; imports nothing above it.
"""
import os

from shell_command import _ASSIGNMENT, _heads
from shell_tokens import is_arm
from workflow_values import emptied, record

_DEPTH = 8          # calls followed inside a body, in all


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
    head word is bare and no assignment."""
    found = set()
    for statement in stmts[head:close + 1]:
        if len(statement.stages) == 1:
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
    # What the body adds goes after the caller's own candidates, never in place of one (a name
    # the body overflows keeps the caller's in `after` too), and is marked carried, so the cap
    # drops it before any of the caller's (`workflow_values._update`, PR #2855 round 6).
    carried = vars(table).setdefault("carried", {})
    for kind in ("scalars", "arrays"):
        before, after = getattr(table, kind), getattr(inner, kind)
        for name in set(after) - local:
            own = before.get(name, [])
            added = [c for c in after[name] if c not in own]
            marks = carried.setdefault(name, [])
            marks.extend(c for c in added if c not in marks)
            before[name] = own + added


def record_called(table, stmts, position, starts):
    """At statement `position`, a single-stage call of a function the step defines before it,
    add what its body may assign to `table` as unsure candidates, the caller's own kept
    (`_carry`): every definition of the name before the call counts, and every function the
    body calls, `_DEPTH` functions deep; a definition after the call is no function yet, and a
    subshell body reaches nothing. `starts` maps a definition's index to (name, head, close)."""
    stage = stmts[position].stages[0] if stmts[position].stages else None
    head = _head(list(stage.argv)) if stage else None
    if head is None:
        return
    defined: dict[str, list[tuple[int, int, int]]] = {}
    for at, entries in starts.items():
        for name, start, close in entries:
            defined.setdefault(name, []).append((at, start, close))
    if head not in defined:
        return
    queue, seen = [head], set[str]()
    while queue and len(seen) < _DEPTH:
        name = queue.pop(0)
        seen.add(name)
        for at, start, close in defined.get(name, []):
            if name == head and at >= position:
                continue
            if any(s.group_open for s in stmts[start].stages):
                continue
            _carry(table, stmts, start, close)
            queue.extend(call for call in _calls(stmts, start, close)
                         if call in defined and call not in seen and call not in queue)
