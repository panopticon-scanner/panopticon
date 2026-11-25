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
import os
from typing import NoReturn

from . import runio


def _refuse(path, key, what, kind="a count") -> NoReturn:
    """The #1809 refusal, with the key that is not a count named. Same class
    and same remedy as the torn-document read one call away, so an operator
    sees one message for one file whichever half of it is broken."""
    raise runio.DriverError(
        "%s at %s is present but unreadable (key %s is not %s); "
        "delete it or re-run with --reset" % (what, path, key, kind))


def _is_count(value):
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _is_id_list(value):
    """A recorded list of ids: at least one, each a non-empty string, and nothing
    else (#3695). An empty list is refused here because its reader
    (`synth/backups._scope`) takes it for no record at all."""
    return (isinstance(value, list) and bool(value)
            and all(isinstance(i, str) and i for i in value))


def _count_in(data, path, key, what):
    """One key's spent count out of an already-loaded document. An absent key
    is 0 -- a cell that was never dispatched is not an error -- and anything
    that is not a non-negative int refuses."""
    value = data.get(key, 0)
    if not _is_count(value):
        _refuse(path, key, what)
    return value


def count(path, key, what):
    """How much of `key`'s budget is spent: 0 when the file or the key is
    absent, and a refusal when either the document or the value is unreadable."""
    return _count_in(runio._load_state_json(path, what), path, key, what)


def bump(path, key, what):
    """Charge one attempt against `key`; returns the new count."""
    return bump_many(path, [key], what)[key]


def bump_many(path, keys, what, record=None):
    """Charge one attempt against each of `keys` in ONE write, returning
    {key: new count}. A key listed twice is charged twice: review's fan-out
    counts one charge per dispatched ENTRY, so two entries for one cell are two
    attempts. (`give_back` is the asymmetric half -- see its own note.) The
    whole document is written back, so keys this call never named keep their
    counts. An empty batch with nothing to record charges nothing and writes nothing.

    `record` SETS keys in the same write: a fact recorded at dispatch beside the
    charge. A value is a count (a backup cell's part count, #3679) or a non-empty
    list of non-empty strings (the claim ids that backup was handed, #3695), and
    nothing else. A present value of the other kind still refuses, as for a charge.
    It is written with no key charged too (#3740: an entry emitted again is not
    charged, and what it was handed is still recorded)."""
    if not keys and not record:
        return {}
    data = runio._load_state_json(path, what)
    charged = {}
    for key in keys:
        charged[key] = data[key] = _count_in(data, path, key, what) + 1
    for key, value in (record or {}).items():
        if _is_count(value):
            _count_in(data, path, key, what)
        elif _is_id_list(value):
            if key in data and not _is_id_list(data[key]):
                _refuse(path, key, what, "a list of ids")
        else:
            raise ValueError("a recorded value must be a count or a non-empty list of "
                             "non-empty strings: %r" % (value,))
        data[key] = value
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
    seen = set()
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        used = _count_in(data, path, key, what)
        if used <= 0:
            continue
        data[key] = used - 1
        cleared.append(key)
    if cleared:
        runio._write_json(path, data)
    return cleared


# ---------------------------------------------------------------------------
# #3740: which dispatches have been handed out and have not ended.
#
# A retry budget (above) bounds how many times one cell, verify stage or tool
# item is dispatched. The charge was made at PLANNING: every `driver.run` that found
# an entry pending charged it, whether or not anything was then launched. So a run
# stopped before its launch (a `--max-budget-usd` already reached, `--max-iterations`,
# a refused request), and a session host that re-ran the loop before its agents had
# finished, each spent a dispatch for nothing. Three of those and every pending cell
# read as exhausted with no agent ever run; only `--reset` recovered.
#
# The rule now: a dispatch is charged when its entry is handed out and it is not a
# re-emission of a hand-out that has not ended. The marks below are the record that
# tells the two apart. Per dispatch entry id it keeps a MARK: the state of that entry's
# output on disk when it was handed out, and how many times it has since been emitted
# again unchanged.
#
# - Planning (`new_handouts`, then the phase's own charge, then `mark_handouts`)
#   charges an entry that has no mark, or whose state on disk differs from its mark:
#   something landed since it was handed out, and the entry is still pending, so that
#   attempt failed.
# - An entry whose mark matches the disk is the same hand-out, emitted again. It is not
#   charged; the mark counts the re-emission.
# - A budget whose last dispatch is still handed out is not spent yet (`outstanding`),
#   whatever its count: the dispatch has not failed, it has not ended.
# - `handouts_ended` drops a mark. The headless loop calls it for every entry it
#   launched and recorded a result for, whatever the result (a child that fails and
#   writes nothing is charged again next time), and a give-back of the charge
#   (`persist.rollback_markers`: a pause, an outage, an interrupt) drops it too.
#
# The state is the out_file's path, its size, modification time and inode (or its
# absence), and the number of the newest reply kept under `rejected/` for the entry: a findings file
# the controller would not take, and a reply `driver persist` refused, both change it.
# (The inode because a reply is written beside the file and moved over it: the same
# bytes written again within one tick of the clock are still a different file.)
#
# What this cannot see: an agent in SESSION mode that returns and writes nothing. On
# disk that is an agent that has not finished, so it is never charged, and the retry
# budget does not bound it; the session host's own loop does. The re-emission count is
# in the `dispatch` status so that such an entry is visible.
#
# The file is in the reviewed tree like the counters, and gets their rule: present but
# unreadable refuses, naming the file and `--reset` (above). A run folder written
# before this file existed has none, so nothing is outstanding and the next planning
# charges once and marks, as that build would have charged that emission.

MARKS_FILE = "dispatch-handouts.json"
MARKS_WHAT = "the record of dispatches handed out"


def _marks_path(review_root):
    return runio._pano(review_root, MARKS_FILE)


def _refuse_mark(review_root, entry_id):
    raise runio.DriverError(
        "%s at %s is present but unreadable (entry %s is not a mark); "
        "delete it or re-run with --reset" % (MARKS_WHAT, _marks_path(review_root), entry_id))


def _is_state(value):
    """`{"file": path, "out": None | [size, mtime_ns, inode], "rejected": count}` and
    nothing else."""
    if not isinstance(value, dict) or set(value) != {"file", "out", "rejected"}:
        return False
    out = value["out"]
    return (isinstance(value["file"], str) and _is_count(value["rejected"])
            and (out is None or (isinstance(out, list) and len(out) == 3
                                 and all(_is_count(part) for part in out))))


def _marks(review_root):
    """The whole document, every mark checked: {} with no file. A mark that is not
    one refuses. Read as "no mark" it would charge again, which a planted file could
    use to exhaust a cell; read as "outstanding" it would never charge."""
    data = runio._load_state_json(_marks_path(review_root), MARKS_WHAT)
    for entry_id, mark in data.items():
        if not (isinstance(mark, dict) and set(mark) == {"key", "state", "reemitted"}
                and isinstance(mark["key"], str) and mark["key"]
                and _is_state(mark["state"]) and _is_count(mark["reemitted"])):
            _refuse_mark(review_root, entry_id)
    return data


def _rejected(review_root, entry_id):
    """The number of the newest reply kept under `rejected/` for this entry; 0 for none."""
    from . import persist, rejected_replies     # both import the phases that import this
    return rejected_replies.highest_attempt(persist.run_dir(review_root), entry_id)


def handout_state(review_root, entry):
    """What is on disk for `entry` now: which file it is to write, what is there, and
    its newest refused reply.

    WHICH file, because one entry id can be handed out for two: a tool advisor's
    second ask (#3231, the `missing_evidence` lift) has the id of the first and writes
    beside its answer. Neither file has changed when the second is handed out, and it
    is a new dispatch all the same."""
    path, out = str(entry.get("out_file") or ""), None
    try:
        found = os.lstat(path)
        out = [found.st_size, found.st_mtime_ns, found.st_ino]
    except OSError:
        pass
    return {"file": path, "out": out, "rejected": _rejected(review_root, entry.get("id"))}


def _entries(entries):
    return [entry for entry in entries or []
            if isinstance(entry, dict) and isinstance(entry.get("id"), str) and entry["id"]]


def new_handouts(review_root, entries):
    """The entries of this emission that are NEW hand-outs, and so are charged: each
    one with no mark, or whose state on disk is not its mark's. The rest are the same
    hand-out emitted again. Reads only; `mark_handouts` writes, after the charge."""
    marks = _marks(review_root)
    return [entry for entry in _entries(entries)
            if entry["id"] not in marks
            or marks[entry["id"]]["state"] != handout_state(review_root, entry)]


def mark_handouts(review_root, entries, charged, key_of):
    """Mark this emission, AFTER its charge is on disk: a crash between the two leaves
    a charge with no mark, which charges again, never a mark with no charge. Each of
    `charged` (what `new_handouts` returned) is marked afresh; every other entry has been
    emitted once more, unchanged.

    `key_of(entry)` names the budget the entry is charged to (`outstanding` asks by
    it); an entry it gives no key for is charged to none, and gets no mark."""
    marks = _marks(review_root)
    fresh = {entry["id"] for entry in _entries(charged)}
    written = False
    for entry in _entries(entries):
        key = key_of(entry)
        if not key:
            continue
        written = True
        if entry["id"] in fresh or entry["id"] not in marks:
            marks[entry["id"]] = {"key": key, "state": handout_state(review_root, entry),
                                  "reemitted": 0}
        else:
            marks[entry["id"]]["reemitted"] += 1
    if written:
        runio._write_json(_marks_path(review_root), marks)


def outstanding(review_root, key):
    """Whether a dispatch charged to budget `key` is handed out and has not ended: a
    mark with that key whose state on disk is still the one it was handed out at.

    For "has this budget been spent": a cell at its cap whose last dispatch is still
    out has not failed three times yet. It was read as exhausted on the count alone,
    so a run stopped after planning the third dispatch, and a session re-entered while
    the third agent was running, dropped the cell with one dispatch never ended."""
    return any(mark["key"] == key and mark["state"] == handout_state(
        review_root, {"id": entry_id, "out_file": mark["state"]["file"]})
        for entry_id, mark in _marks(review_root).items())


def handouts_ended(review_root, entries):
    """These hand-outs are over: the entry was launched and its result recorded, or
    its charge was given back. The next emission of any of them is a new hand-out.
    Returns the ids whose mark was dropped."""
    marks = _marks(review_root)
    dropped = [entry["id"] for entry in _entries(entries) if entry["id"] in marks]
    for entry_id in dropped:
        del marks[entry_id]
    if dropped:
        runio._write_json(_marks_path(review_root), marks)
    return dropped


def handouts_reemitted(review_root, entries):
    """{entry id: times emitted again unchanged since it was handed out}, for the
    entries of `entries` that have a mark."""
    marks = _marks(review_root)
    return {entry["id"]: marks[entry["id"]]["reemitted"]
            for entry in _entries(entries) if entry["id"] in marks}
