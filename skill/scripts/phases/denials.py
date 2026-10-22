"""#3220: a batch whose EVERY self-writing entry was denied its own out_file.

Nothing read `RunResult.denials`: the ledger records the rows, and that was
all. So on a host whose permission layer refused every granted Write (the 5.2
redteam box, #3218), each cell came back with the same denial three times over
-- `review.MAX_CELL_ATTEMPTS` identical, paid rounds -- before the run ended
`complete` with an empty review axis. One fully denied batch already proves
the next one will be denied too, so the loop stops after it.

The rule is narrow on purpose: EVERY landed self-writing entry, each with its
own file absent and a denial row that names that file. One cell that landed,
a denial naming only a peer's path, or a failure with no denial row is left to
the paths that already own it. Only claude reports a Write denial by path
(`tool_input.file_path`); codex's rows are its read broker's failures and kimi
reports none, so on those families this rule cannot fire.
"""
import os

from . import persist


def _denied_paths(result):
    """The absolute `file_path` of every denial row the host reported."""
    rows = getattr(result, "denials", None)
    paths = []
    for row in rows if isinstance(rows, list) else []:
        tool_input = row.get("tool_input") if isinstance(row, dict) else None
        path = tool_input.get("file_path") if isinstance(tool_input, dict) else None
        # A relative path is relative to the CHILD's cwd, which is not ours.
        if isinstance(path, str) and os.path.isabs(path):
            paths.append(path)
    return paths


def _self_writes(entry):
    return bool(entry.get("out_file")) and entry.get("delivery") != "return_json"


def own_write_denied(entry, result):
    """True when `entry`'s own out_file is not done and a denial row names it."""
    if not _self_writes(entry) or persist.is_done(entry):
        return False
    own = os.path.realpath(entry["out_file"])
    return any(os.path.realpath(path) == own for path in _denied_paths(result))


def every_own_write_denied(landed):
    """The loop's `error` message when every self-writing entry in `landed`
    (`(entry, result)` pairs, in landing order) was denied its own out_file;
    None otherwise, including for a batch with no self-writing entry."""
    writers = [(entry, result) for entry, result in landed if _self_writes(entry)]
    if not writers or not all(own_write_denied(e, r) for e, r in writers):
        return None
    entry = writers[0][0]
    return ("driver loop: every self-writing entry of this batch (%d) was DENIED "
            "a Write to its own out_file -- first %r, at %s; stopped after this attempt "
            "rather than re-dispatching a batch the host's permission layer refuses in "
            "full (#3220). Check what the host's own permission settings allow (#3218), "
            "then re-run" % (len(writers), entry.get("id"), entry["out_file"]))
