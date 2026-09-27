"""One owner for the run's PERSISTED RETRY BUDGETS (#1767 / ARC-655791509).

A retry budget is a counter file under `.panopticon/` in the reviewed tree that
bounds a re-dispatch loop: the scout's shape-validation rounds, discovery's
malformed rounds, the verify reconciliation rounds, the per-cell review
dispatches. Five phase modules kept the same read-bump-write by hand, with five
key schemes and -- on a value that is not a count -- three different answers:
`coverage`, `discovery` and `verify` raised a bare `ValueError` out of `int()`,
`review` RESET the tally to 1, and `persist` silently skipped the key. Only the
READ was consolidated (the #1809 round put all five behind
`runio._load_state_json`, which refuses a present-but-torn document); the
arithmetic on top of it was not, so the contract the repo wrote down was
contradicted in two of the five copies.

The rule, in one place: a value that is not a non-negative `int` is
UNREADABLE, exactly like a torn document, and unreadable REFUSES -- the same
`runio.DriverError`, the same actionable shape, naming the file, the offending
key and `--reset`. Never reset (that refunds every attempt the run really
spent, which is the one outcome the file exists to prevent), never skip past
it, never a message an operator cannot act on. `bool` is excluded on purpose:
`isinstance(True, int)` is True, so a planted `true` would otherwise bump to 2
and read as a tally nobody spent.

Each caller keeps its own file name, key scheme and `what` string, because
those are the on-disk contract a RESUMED run reads back; what moves here is
the arithmetic. Reads go through `runio._load_state_json` and writes through
`runio._write_json`, so both halves of the #1809 pair stay in force (the write
refuses a symlink at the artifact path) and there is no second implementation
of either behind this module's names.
"""
from typing import NoReturn

from . import runio


def _refuse(path, key, what) -> NoReturn:
    """The #1809 refusal, with the key that is not a count named. Same class
    and same remedy as the torn-document read one call away, so an operator
    sees one message for one file whichever half of it is broken."""
    raise runio.DriverError(
        "%s at %s is present but unreadable (key %s is not a count); "
        "delete it or re-run with --reset" % (what, path, key))


def _count_in(data, path, key, what):
    """One key's spent count out of an already-loaded document. An absent key
    is 0 -- a cell that was never dispatched is not an error -- and anything
    that is not a non-negative int refuses."""
    value = data.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _refuse(path, key, what)
    return value


def count(path, key, what):
    """How much of `key`'s budget is spent: 0 when the file or the key is
    absent, and a refusal when either the document or the value is unreadable."""
    return _count_in(runio._load_state_json(path, what), path, key, what)


def bump(path, key, what):
    """Charge one attempt against `key`; returns the new count."""
    return bump_many(path, [key], what)[key]


def bump_many(path, keys, what):
    """Charge one attempt against each of `keys` in ONE write, returning
    {key: new count}. A key listed twice is charged twice: review's fan-out
    counts one charge per dispatched ENTRY, so two entries for one cell are two
    attempts. (`give_back` is the asymmetric half -- see its own note.) The
    whole document is written back, so keys this call never named keep their
    counts."""
    data = runio._load_state_json(path, what)
    charged = {}
    for key in keys:
        charged[key] = data[key] = _count_in(data, path, key, what) + 1
    runio._write_json(path, data)
    return charged


def give_back(path, keys, what):
    """Refund one attempt to each DISTINCT key in `keys`, returning the keys
    actually changed (persist's `rollback_markers` semantics).

    Deduplicated, unlike `bump_many`: the charge being undone is exactly one
    per cell per checkpoint, so a key that appears twice in a cancelled batch
    still gets one attempt back. A key that is absent or already at zero is
    left alone -- there is nothing to refund and a budget must never go
    negative -- and a document nothing was refunded from is not rewritten. A
    value that is not a count still refuses: persist's copy skipped it, which
    made a planted value indistinguishable from an untouched key."""
    data = runio._load_state_json(path, what)
    cleared = []
    for key in keys:
        if key in cleared:
            continue
        used = _count_in(data, path, key, what)
        if used <= 0:
            continue
        data[key] = used - 1
        cleared.append(key)
    if cleared:
        runio._write_json(path, data)
    return cleared
