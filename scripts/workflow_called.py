#!/usr/bin/env python3
"""What a called function leaves in the caller's value table (#2664 fix round, #2785).

`static_values` walks the step's statements into a `Values` table and skips every function
body where it is written -- a body runs only when called -- but it recorded nothing at the
CALL either, so `f() { T=/tmp/payload; }; f; sh "$T"` held the caller's old `T` at the use
while bash ran the payload. `record_called` walks the body from the table at the call and
carries out what it assigns: the names it makes `local` die with the call, `declare -g` and
`export` assign globally, a sure assignment replaces the caller's candidates only where the
call is sure and the body statement is unconditional, and anything else is added as an
uncertain assignment is. One call deep: a call made inside the body is not followed, as
`_function_use` does not follow one, and a body that is a subshell (`f() ( T=x )`) or a
bare compound carries nothing, bash running it in a child or this module not reading its
end. A function defined after the call is the caller's to leave out (bash has not defined
it at call time: `_functions_before`).

Beside `scripts/workflow_values.py`, which is at its ceiling; imports nothing above it.
"""
import os

from shell_reader import command
from workflow_values import _DECLARATIONS, emptied, record


def record_called(table, stmts, position, starts, certain, kinds_of, certainty, defined):
    """At statement `position`, a single-stage call of a function the step defines, carry what
    its body assigns into `table`: sure only where `certain` (the call) holds, the function is
    among those `defined()` surely before the call (`_functions_before`), and the body statement
    is unconditional (`certainty`, over `kinds_of(body)`); the last definition before the call
    otherwise, unsure. `starts` maps a definition's index to its (name, head, close) entries."""
    argv = command(stmts[position].stages[0].argv)
    head = str(argv[0]) if argv else ""
    if not head or not any(entry[0] == head for at in starts for entry in starts[at] if at < position):
        return
    surely = defined()
    found = surely.get(head) or next((entry[1:] for at in range(position - 1, -1, -1)
                                      for entry in starts.get(at, []) if entry[0] == head), None)
    if found is None:
        return
    body = stmts[found[0]:found[1] + 1]
    kinds = kinds_of(body)
    _carry(table, body, [certainty(body, at, kinds)[0] for at in range(len(body))],
           certain and head in surely)


def _carry(table, body, certainties, certain):
    """Carry what the function body `body` (its statements, header to close) assigns into
    `table`, as sure as `certain` (the call) and `certainties` (per body statement) say."""
    header = body[0].stages[0].argv if body and body[0].stages else []
    opener = body[1].stages[0].argv[:1] if len(body) > 1 and body[1].stages else []
    if any(stage.group_open for stage in body[0].stages) or (
            "{" not in header and opener != ["{"]):
        return                  # a subshell (`g() (`) or compound body: nothing reaches the caller
    inner = table.copy()
    local: set[str] = set()
    for statement, sure in zip(body, certainties):
        stage = statement.stages[-1] if statement.stages else None
        if stage is None:
            continue
        sure = certain and sure and len(statement.stages) == 1
        argv = command(stage.argv)
        name = os.path.basename(str(argv[0])) if argv else ""
        words = [str(word) for word in argv[1:] if not str(word).startswith("-")]
        if name in _DECLARATIONS and name != "export" and "-g" not in map(str, argv[1:]):
            local.update(word.split("=", 1)[0].split("[", 1)[0] for word in words)
            for word in words:
                if "=" not in word:
                    emptied(inner, word, sure)
        elif name == "read" or name == "unset" and "-f" not in map(str, argv):
            for word in words:
                emptied(inner, word, sure, name == "read")
        record(inner, stage, sure)
    for kind in ("scalars", "arrays"):
        before, after = getattr(table, kind), getattr(inner, kind)
        for name in set(before) | set(after):
            if name in local:
                continue
            if name in after:
                before[name] = after[name]
            else:
                before.pop(name, None)
