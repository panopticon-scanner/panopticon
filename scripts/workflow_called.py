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
carries its bodies `_BUDGET` times a step, walking only the statements that may write
(`_writes`); past that, each name they may set -- where one may set any name, each name the table
holds -- gains the cap's stand-in on both sides, a price named there too. The sure carry is
#2785's own PR.

Beside `scripts/workflow_values.py`, which is at its ceiling; imports nothing above it.
"""
import os
import re

from shell_command import _ASSIGNMENT, _heads, command
from shell_tokens import is_arm
from workflow_function_calls import _function_syntax
from workflow_values import _CANDIDATES, PAST, Values, emptied, record, stand_in

_DEPTH = 8          # calls followed inside a body, in all
# `static_values` rebuilds the table at each statement that reads one, and carrying every earlier
# call's bodies again there made a step cubic where `main` is quadratic (round 8, B5); a memo of
# the carries, keyed on the state of their names, grew again where those names were many (round
# 10, B3). So a call site carries `_BUDGET` times a step (`_carried`), walking only the statements
# that may write (`_writes`), and past that each name its bodies may set gains the cap's stand-in
# instead, unsure: fail-closed, a price. A carry costs the statements it walks and the names it
# copies, and one costing more than `_WORK` counts as more than one, so a site's carries cost at
# most `_BUDGET` times `_WORK` (round 12, the round-11 B2: a body setting K names, called K times,
# cost eight walks of K statements a site). The last few steps are kept, each with its statements,
# so an id is never reused while its entry stands.
_BUDGET = 8
_WORK = 128
_CARRIED: dict[int, "_Step"] = {}
_SPELLED = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Where bash may write a name the carry's own step does not read: an assignment inside `${…}`
# (`${X:=v}`, `${X=v}`), arithmetic (`$(( X=1 ))`, `$[ … ]`, `(( i++ ))` and `(( a += 1 ))`, whose
# words the reader keeps without their parentheses), in a word, a redirect's target or a heredoc's
# text; `let` too. Unsure, a carry walks it (`_writes`): a long option or a test's `=` costs a walk.
_UNSURE = re.compile(r"\$\{[^}]*=|\$\(\(|\$\[|\+\+|--|^(?:[-+*/%&|^]|<<|>>)?=$")


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


def _carry(table, stmts, head, close, positions=None, names=None):
    """Add what the body `stmts[head:close + 1]` may assign to `table`, unsure: each
    assignment as an uncertain one (`record`), an `unset` or bare `local` as a "maybe unset",
    a `read` as the stand-in -- and nothing for a name the body makes `local`. `positions`, where
    given, are the body's statements that may do any of that (`_effects`): the rest leave it alone;
    `names`, where given, the names it reads or sets (`record_called`'s `spelled`): it copies
    and merges back only those, and a body that may set any other name gives each its stand-in
    there."""
    inner = table.copy() if names is None else Values(
        {name: list(table.scalars[name]) for name in names if name in table.scalars},
        {name: [list(words) for words in table.arrays[name]] for name in names if name in table.arrays})
    local: set[str] = set()
    for at in range(head, close + 1) if positions is None else positions:
        _carry_one(inner, local, stmts[at])
    # What the body adds goes after the caller's own candidates, never in place of one; past
    # the cap a use reads the cap's stand-in, whatever the order (`workflow_values.PAST`).
    for kind in ("scalars", "arrays"):
        before, after = getattr(table, kind), getattr(inner, kind)
        for name in set(after) - local:
            own = before.get(name, [])
            before[name] = own + [candidate for candidate in after[name] if candidate not in own]


def _carry_one(inner, local, statement):
    """One statement of `_carry`'s body, into `inner`, its `local` names into `local`."""
    stage = statement.stages[-1] if statement.stages else None
    if stage is None:
        return
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


class _Step:
    """What the step `stmts` has carried (`_carried`): its call sites, {position: [bodies, the names
    they may set, whether one may set any name, the statements each carry walks, the names they
    spell, carries made]}, what each bodies may set read once for every site of theirs
    (`effects`); the names each statement may set (`set_at`); and, for each bodies -- None for
    every body that may set any name, "own" for its carry -- where the last stand-in left a table
    (`last`)."""

    def __init__(self, stmts):
        self.stmts, self.size, self.sites, self._set, self.last = stmts, len(stmts), {}, {}, {}
        self.effects: dict[tuple, tuple] = {}
        self.probe = "_" * (2 + max((len(name) for statement in stmts for stage in statement.stages
                                     for word in stage.argv for name in _SPELLED.findall(str(word))), default=0))

    def set_at(self, at):
        """The names statement `at` may set -- its plain ones where it may also set any name (`export
        "$K=v" X=P` sets `X`): such a statement gives every held name its stand-in last of all it
        does (`record`'s `_unread`), which takes no stand-in away (round 11, the round-10 verdict's B1)
        -- and each name a `read`, `unset` or `local` names behind a wrapper, which the walk's `_cleared`
        reads through `command` (`command read T`, `nohup unset T`) where `_carry_one` stops at the
        wrapper: names alone, so a wrapped `unset` empties nothing here (round 12, the round-11 B1)."""
        if at not in self._set:
            names = _written(self.stmts[at], self.probe) - {self.probe}
            for stage in self.stmts[at].stages[-1:]:
                argv = command(stage.argv)
                if argv and os.path.basename(str(argv[0])) in ("read", "unset", "local"):
                    names |= {str(word).split("[", 1)[0] for word in argv[1:] if not str(word).startswith("-")}
            self._set[at] = names
        return self._set[at]

    def since(self, key, table, position):
        """The names that may have changed in `table` since the last stand-in for `key` left it --
        what the statements between may set, and for a body that may set any name what the bodies
        called there may set (a carry can bring in a name the table did not hold) and the names that
        last one's bodies spell (one it made `local` kept its value) -- or None where none left this
        table before `position`. A stand-in is never taken away but by a write, so the rest keep it."""
        last = self.last.get(key)
        if last is None or last[0] is not table or last[1] >= position:
            return None
        names = set(last[2])
        for at in range(last[1] + 1, position):
            names |= self.set_at(at)
            site = self.sites.get(at)
            if key in (None, "own") and site and site[0]:
                names |= site[1]
        return names


def _carried(stmts):
    """The step `stmts`' `_Step`, kept for the last few steps, each with its statements."""
    step = _CARRIED.get(id(stmts))
    if step is None or step.stmts is not stmts or step.size != len(stmts):
        _CARRIED[id(stmts)] = step = _Step(stmts)
        while len(_CARRIED) > 8:
            _CARRIED.pop(next(iter(_CARRIED)))
    return step


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


def _effects(stmts, bodies):
    """(written, anything, active, spelled) for `bodies`: `written`, the names a dry carry shows them set --
    each name they spell held without a candidate, so `REPLY` behind a bare `read` shows too, and
    the plain names of a statement that may also set any name (`export "$K=v" X=P`); `anything`
    where one may set a name it does not spell (`eval`, `source`, a name taken from a value), as a
    held name none of them spells then shows; and per body, the statements a carry walks
    (`_writes`); and `spelled`, every name they spell or set."""
    spelled = {name for start, close in bodies for statement in stmts[start:close + 1]
               for stage in statement.stages for word in stage.argv
               for name in _SPELLED.findall(str(word))}
    probe = "_" * (2 + max(map(len, spelled), default=0))      # a name no body spells
    dry = Values({name: [] for name in spelled | {probe}})
    for start, close in bodies:
        _carry(dry, stmts, start, close)
    written = {name for name, texts in dry.scalars.items() if texts} | set(dry.arrays)
    active = tuple(tuple(at for at in range(start, close + 1) if _writes(stmts[at], probe))
                   for start, close in bodies)
    return frozenset(written - {probe}), probe in written, active, frozenset(spelled | written) - {probe}


def _written(statement, probe):
    """The names `_carry_one` may set at `statement`, `probe` among them where it may set any:
    what it sets is the statement's words' and whether the names it spells are held, never their
    values, so one dry step over those names, held without a candidate, and `probe` shows them.
    A declaration that makes a name `local` sets it there too (a bare name empties)."""
    spelled = {name for stage in statement.stages for word in stage.argv
               for name in _SPELLED.findall(str(word))}
    dry = Values({name: [] for name in spelled | {probe}})
    _carry_one(dry, set(), statement)
    return frozenset(name for name, texts in dry.scalars.items() if texts) | frozenset(dry.arrays)


def _writes(statement, probe):
    """Whether a carry walks `statement`: where bash may write a name the step does not read
    (`_UNSURE`, `let`), and where `_carry_one` may set one (`_written`)."""
    texts = [str(text) for stage in statement.stages
             for text in (*stage.argv, *stage.writes, *stage.reads, stage.heredoc or "")]
    return any(map(_UNSURE.search, texts)) or "let" in texts or bool(_written(statement, probe))


def record_called(table, stmts, position, starts):
    """At statement `position`, a single-stage call of a function the step defines before it,
    add what its body may assign to `table` as unsure candidates, the caller's own kept
    (`_carry`): the bodies `_reached` lists, every definition of the name before the call and
    every function the body calls. `starts` maps a definition's index to (name, head, close).
    A call site carries `_BUDGET` times a step; past that, each name its bodies may set gains the
    cap's stand-in on both sides (`stand_in`) -- where one may set any name, each name the table
    holds too -- every one at a walk's first such site, then what changed since (`_Step.since`)."""
    step = _carried(stmts)
    site = step.sites.get(position)
    if site is None:
        bodies = tuple(_reached(stmts, position, starts))
        if bodies not in step.effects:
            step.effects[bodies] = _effects(stmts, bodies) if bodies else (frozenset(), False, (), frozenset())
        site = step.sites[position] = [bodies, *step.effects[bodies], 0]
    bodies, written, anything, active, spelled, made = site
    if not any(active):                 # no body that may write: a carry leaves the table as it is
        return
    if made < _BUDGET * _WORK // max(_WORK, sum(map(len, active)) + len(active) * len(spelled)):
        site[5] += 1
        if anything:
            # A carry gives each name it does not spell its own stand-in alone (`record`'s
            # `_unread`): given here, once a walk and then to what changed since, and the carry
            # walks the names the bodies spell.
            since = step.since("own", table, position)
            for name in _held(table) if since is None else since:
                if name not in spelled and (name in table.scalars or name in table.arrays):
                    _own(table, name)
            step.last["own"] = (table, position, spelled)
        # Each carry copies and merges back only the names its bodies spell or set: any other
        # name stays the caller's as it is, where a copy of the whole table cost K names a carry.
        for (start, close), positions in zip(bodies, active):
            _carry(table, stmts, start, close, positions, spelled)
        return
    key = None if anything else bodies
    since = step.since(key, table, position)
    if anything:    # every name the table holds -- after the first, those that changed and any not held
        names = [*_held(table), *(name for name in written if name not in table.scalars and name not in
                                  table.arrays)] if since is None else {
            name for name in since if name in written or name in table.scalars or name in table.arrays} | {
            name for name in written if name not in table.scalars and name not in table.arrays}
    else:
        names = written if since is None else written & since
    for name in names:
        _stood(table, name)
    step.last[key] = (table, position, ())


class _Shared(list):
    """A candidate list `_stood` gives every name that holds nothing on that side, one list for them
    all: read-only, so no write changes it under another name -- the table's writers build a new
    list (`_update`, `_carry`), and a mutator here raises."""


def _read_only(*args):
    raise TypeError("a stand-in's shared list is read-only")


for _mutator in ("append", "extend", "insert", "remove", "pop", "clear", "sort", "reverse", "__setitem__",
                 "__delitem__", "__iadd__", "__imul__"):
    setattr(_Shared, _mutator, _read_only)


# What `stand_in` leaves a name that held nothing -- scalars `PAST` and the "maybe unset" `""`,
# word-lists one holding `PAST` -- and the word-lists it leaves a name that held scalars alone.
_NOTHING, _LISTS = _Shared([PAST, ""]), _Shared([_Shared([PAST])])


def _held(table):
    """Every name `table` holds, each once, in the table's own order: a walk's first visit stands in
    or gives its own stand-in to each, without a set of K names built to do it."""
    return [*table.scalars, *(name for name in table.arrays if name not in table.scalars)]


def _own(table, name):
    """`emptied(table, name, False, True)` -- a held name given its own reference, `$NAME`, unsure --
    as it leaves `table`, making no list but the one it keeps where the name holds fewer scalars
    than `_CANDIDATES` (round 12, the round-11 B2: a walk gives every held name one)."""
    texts, reference = table.scalars.get(name), "$" + name
    if texts is None or len(texts) >= _CANDIDATES:
        emptied(table, name, False, True)
    elif reference not in texts:
        table.scalars[name] = texts + [reference]


def _stood(table, name):
    """`stand_in`, as it leaves `table`, making no list it needs not: a name that held nothing takes
    the shared lists, and one that held scalars alone keeps them, `PAST` added past the first
    `_CANDIDATES`, beside the shared word-list -- so the stand-ins a walk gives K names make no K
    lists that outlive them for the collector to walk (round 12, the round-11 B2)."""
    texts, lists = table.scalars.get(name), table.arrays.get(name)
    if texts is None and lists is None:
        table.scalars[name], table.arrays[name] = _NOTHING, _LISTS
    elif lists is None and texts is not None and (PAST not in texts or len(texts) <= _CANDIDATES):
        if PAST not in texts:
            table.scalars[name] = texts[:_CANDIDATES] + [PAST]
        table.arrays[name] = _LISTS
    else:
        stand_in(table, name)
