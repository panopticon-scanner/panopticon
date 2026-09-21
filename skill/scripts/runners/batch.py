"""The batch manifest (#1662): what one checkpoint's batch is about to write,
so a Ctrl-C can take it back as a unit.

The owner's ruling on an interrupted `driver loop` is complete stoppage,
cancellation and ROLLBACK to the last checkpoint: the interrupted phase is
re-run from scratch on the next invocation rather than recovered from disk
(whole-run rollback stays `--reset`). Rolling a phase back means deleting
exactly the per-entry artifacts THIS batch was responsible for -- and
"exactly" is the whole of it. A glob over the run folder would sweep up a
prior phase's outputs, which the ruling leaves untouched, and on a redteam
target it would sweep up whatever the tree had planted with a matching name.
So the loop writes the list down BEFORE its first submit, and the rollback
deletes that list and nothing else.

The document lives at `runs/<tag>/batch-<n>.json`, beside the ledger and the
guard files; a batch that finishes -- cleanly or rolled back -- deletes it, so
a manifest on disk means a batch that did neither: a run killed outright
(SIGKILL, a power loss), which reaches no teardown at all.

Such a leftover is a RECORD, not an instruction. Nothing applies it on a later
invocation -- a rollback nobody is watching is what `--reset` is for -- and it
is not durable either: `<n>` is the loop's iteration counter, so the next
`driver loop` on this run opens batch 1 again and `open()` OVERWRITES it. An
operator who wants to know what a killed run had in flight has to read the
file BEFORE re-running. Keeping it across runs means naming manifests so they
cannot collide and deciding what a resume owes a stale one; that is a
follow-up, and deliberately not smuggled in here.

It lives in `runners/` rather than in `phases/` because `tests/test_layout.py`
forbids `runners/* -> phases` imports and the loop is what calls both halves
of the rollback: the artifact half here, and the interrupted phase's
per-dispatch marker in `phases.persist.rollback_markers`.
"""
import os
import time
from typing import TypedDict

import scripts.write_guard_hook as write_guard_hook

# The manifest's file-name prefix. One owner: the loop writes these, the
# operator greps for them, and the suite asserts a clean batch leaves none.
MANIFEST_PREFIX = "batch-"


def manifest_path(run_dir, number):
    return os.path.join(run_dir, "%s%s.json" % (MANIFEST_PREFIX, int(number)))


class BatchEntry(TypedDict):
    id: str | None
    artifacts: list[str]


class Batch:
    """One checkpoint's batch, and the artifacts it is about to produce.

    `entries` is the loop's PENDING set for this checkpoint. Each entry
    contributes its `out_file` -- the phase's per-entry artifact, whether the
    loop persists it from a returned reply or the agent self-writes it under
    the write guard; both are what the phase's done predicate reads, so both
    are what a rollback has to take back.
    """

    def __init__(self, run_dir, number, checkpoint, entries):
        self.path = manifest_path(run_dir, number)
        self.number = int(number)
        self.checkpoint = checkpoint
        self.opened_at = None
        self.entries: list[BatchEntry] = [
            {"id": e.get("id"),
             "artifacts": [os.path.abspath(e["out_file"])] if e.get("out_file") else []}
            for e in entries or [] if isinstance(e, dict)]

    def document(self):
        return {"schema_version": 1, "batch": self.number,
                "checkpoint": self.checkpoint, "opened_at": self.opened_at,
                "entries": self.entries}

    def open(self):
        """Write the manifest. Called BEFORE the first submit, so an interrupt
        that lands on the very first entry still has the list."""
        self.opened_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._write()
        return self

    def _write(self):
        # Through the write guard's own atomic writer, which refuses to follow
        # a symlink planted at `<name>.tmp`: this path is INSIDE the scanned
        # tree, so on a redteam target that link is the target's to plant --
        # the same reason `runners/claude.py` writes host-settings.json with it.
        write_guard_hook._atomic_write_json(self.path, self.document(), indent=2)

    def add_artifact(self, entry_id, path):
        """Record a file the batch wrote that `open` could not have known
        about -- `persist.retain_rejected` names the record only once it has
        written it. Kept in the manifest so the rollback stays a LIST and
        never becomes a glob over the rejected folder."""
        if not path:
            return
        full = os.path.abspath(path)
        for row in self.entries:
            if row["id"] == entry_id and full not in row["artifacts"]:
                row["artifacts"].append(full)
                self._write()
                return

    def entry_ids(self):
        return [row["id"] for row in self.entries]

    def artifacts(self):
        return [path for row in self.entries for path in row["artifacts"]]

    def roll_back(self):
        """Delete exactly the artifacts this manifest lists, then the manifest
        itself. Returns `(removed, problems)`.

        `os.remove` unlinks a SYMLINK rather than following it, so a link
        planted at an artifact path costs the run its link and never the file
        at the other end. A path that was never written is not a problem --
        most of a cancelled batch never got that far -- but anything else is
        reported rather than raised: the loop is already on its way out with
        an interrupt to explain, and a rollback that could not finish is
        something the operator has to be told, not something that should
        replace the interrupt's own message.
        """
        removed, problems = [], []
        for path in self.artifacts():
            try:
                os.remove(path)
                removed.append(path)
            except FileNotFoundError:
                continue
            except OSError as exc:
                problems.append("%s: %s" % (path, exc))
        problems += self.close()
        return removed, problems

    def close(self):
        """Delete the manifest; the clean path's "this batch is over". Returns
        a list of problems, empty when there were none."""
        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            return ["%s: %s" % (self.path, exc)]
        return []
