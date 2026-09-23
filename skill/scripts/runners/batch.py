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

A later loop validates a leftover against the bound dispatch request and
rolls it back BEFORE a phase can read a partial artifact as complete. Opening
an existing manifest is refused, so the recovery record cannot be overwritten.

TODO (#1698, follow-up): this document is NOT hash-bound to the run the way
`dispatch-request.json` has been since #1727 -- serialise, hash, write, and
record the sha256 in the run manifest, so every reader can ask whether the
file it just read is the one the driver wrote. It lives inside the reviewed
tree, so everything it carries is target-writable, the owner stamp below
included: `owner_state` is a LIVENESS check (is the process that wrote this
still running?) and never an authenticity one. Two things make the binding
more than the one-line mirror it looks like. `Batch` is in `runners/`, which
may not import `scripts.phases.*` (tests/test_layout.py rule 3), so it cannot
reach `requests.record_request_hash` -- and that helper is where the two
namespaces are told apart (`--setup` anchors in its own manifest, #1507), so
the recorder would have to be threaded in from `loop_batch`. And the record
is rewritten three times, not once (`open`, `add_artifact` per retained
reply, `begin_recovery`), so each rewrite owes the manifest a new hash and
each one opens a window where the two disagree. What is defended today is
what the rollback ACTS on: every artifact path is re-derived from the bound
request before a single file is deleted (`loop_batch.recover_stale`).

It lives in `runners/` rather than in `phases/` because `tests/test_layout.py`
forbids `runners/* -> phases` imports and the loop is what calls both halves
of the rollback: the artifact half here, and the interrupted phase's
per-dispatch marker in `phases.persist.rollback_markers`.
"""
import os
import re
import socket
import stat
import time
from typing import TypedDict

import scripts.write_guard_hook as write_guard_hook

# The manifest's file name. One owner: the loop writes these, the operator
# greps for them, the `--setup --reset` sweep deletes them and the suite
# asserts a clean batch leaves none. The PATTERN is shared too, not just the
# prefix (#1698 round 2): `recover_stale` reads the iteration number back out
# of the name, so a file that carries none is not a record at all -- and a
# sweep matching on prefix-and-suffix alone would delete it anyway.
MANIFEST_PREFIX = "batch-"
MANIFEST_RE = re.compile(r"%s([0-9]+)\.json" % re.escape(MANIFEST_PREFIX))

# #1698: what `owner_state` can conclude about the process that wrote a
# record. Only ONE of the four clears it for recovery.
OWNER_DEAD = "dead"
OWNER_LIVE = "live"
OWNER_FOREIGN = "foreign"
OWNER_UNSTAMPED = "unstamped"


def manifest_path(run_dir, number):
    return os.path.join(run_dir, "%s%s.json" % (MANIFEST_PREFIX, int(number)))


class BatchEntry(TypedDict):
    id: str | None
    artifacts: list[str]


def host_id():
    """This machine, as the record names it."""
    return socket.gethostname()


def owner_state(doc):
    """Whether the process that wrote `doc` is still running (#1698).

    A manifest on disk is a CRASHED batch only if the process that opened it
    is gone; a loop that is still running has one on disk for as long as its
    batch is in flight. Nothing in the record used to say which: a second
    `driver loop` on the same run folder read the first's LIVE manifest as a
    crash, deleted the artifacts it was still producing, wrote CANCELLED rows
    for its entries, refunded their attempts and unlinked the manifest -- so
    the first loop's own Ctrl-C then found nothing to take back. `opened_at`
    cannot tell the two apart, because a batch may legitimately run for hours.
    So the record names its process, and this asks the operating system:

    * `dead` -- stamped by THIS host and the pid is gone. A crash, and the
      only answer recovery acts on.
    * `live` -- stamped by this host and still running. `PermissionError`
      counts as live: the signal was refused BECAUSE something is there to
      refuse it.
    * `foreign` -- stamped by another host. A pid number from over there
      names some unrelated local process here, so nothing may be concluded
      from it in either direction.
    * `unstamped` -- no usable stamp. The record lives inside the REVIEWED
      tree, so an absent or malformed owner is either a manifest from before
      this field existed or one the target wrote; neither is evidence that a
      crash happened. Fail closed.

    `isinstance(pid, bool)` is excluded on purpose -- `True` is an `int` and
    `os.kill(True, 0)` asks about pid 1, which is always alive.
    """
    if not isinstance(doc, dict):
        return OWNER_UNSTAMPED
    pid, host = doc.get("pid"), doc.get("host")
    if (not isinstance(host, str) or not host or isinstance(pid, bool)
            or not isinstance(pid, int) or pid <= 0):
        return OWNER_UNSTAMPED
    if host != host_id():
        return OWNER_FOREIGN
    try:
        os.kill(pid, 0)
    except PermissionError:
        return OWNER_LIVE
    except OSError:                       # ProcessLookupError, and nothing else lands here
        return OWNER_DEAD
    return OWNER_LIVE


class Batch:
    """One checkpoint's batch, and the artifacts it is about to produce.

    `entries` is the loop's PENDING set for this checkpoint. Each entry
    contributes its `out_file` -- the phase's per-entry artifact, whether the
    loop persists it from a returned reply or the agent self-writes it under
    the write guard; both are what the phase's done predicate reads, so both
    are what a rollback has to take back.
    """

    def __init__(self, run_dir, number, checkpoint, entries):
        if not isinstance(run_dir, str) or not run_dir or "\0" in run_dir:
            raise ValueError("invalid batch run folder")
        self.run_dir = os.path.abspath(run_dir)
        self._root_real = os.path.realpath(self.run_dir)
        try:
            root_stat = os.lstat(self.run_dir)
        except OSError as exc:
            raise ValueError("invalid batch run folder: %s" % exc) from exc
        if not stat.S_ISDIR(root_stat.st_mode):
            raise ValueError("invalid batch run folder: not a directory")
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)
        self._parents: dict[str, dict[str, tuple[int, int]]] = {}
        self.path = manifest_path(self.run_dir, number)
        self.number = int(number)
        self.checkpoint = checkpoint
        self.opened_at = None
        self.recovering = False
        self.entries: list[BatchEntry] = []
        for entry in entries or []:
            if isinstance(entry, dict):
                out_file = entry.get("out_file")
                paths = ([self._confine(out_file, remember=True)]
                         if out_file is not None and out_file != "" else [])
                self.entries.append({"id": entry.get("id"), "artifacts": paths})

    def _confine(self, path, *, remember=False):
        """Validate one destination without following its final symlink.

        The selected spelling may pass through a system alias such as /tmp;
        only links at the run root or below it can redirect this batch's work.
        Existing parent identities are also pinned for live entries so a
        directory exchanged after registration cannot redirect a later unlink.
        """
        if not isinstance(path, str) or not path or "\0" in path:
            raise ValueError("invalid batch artifact path")
        full = os.path.abspath(path)
        try:
            inside = os.path.commonpath((self.run_dir, full)) == self.run_dir
        except ValueError as exc:
            raise ValueError("batch artifact escapes the run folder") from exc
        if not inside or full == self.run_dir:
            raise ValueError("batch artifact escapes the run folder")
        try:
            root_stat = os.lstat(self.run_dir)
        except OSError as exc:
            raise ValueError("batch run folder changed: %s" % exc) from exc
        if (not stat.S_ISDIR(root_stat.st_mode)
                or (root_stat.st_dev, root_stat.st_ino) != self._root_identity
                or os.path.realpath(self.run_dir) != self._root_real):
            raise ValueError("batch run folder changed")
        known = self._parents.get(full, {})
        observed = {}
        parent = os.path.dirname(full)
        relative = os.path.relpath(parent, self.run_dir)
        current = self.run_dir
        for component in (() if relative == "." else relative.split(os.sep)):
            current = os.path.join(current, component)
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ValueError("batch artifact parent changed: %s" % exc) from exc
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("batch artifact parent is a symlink: %s" % current)
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("batch artifact parent is not a directory: %s" % current)
            identity = (info.st_dev, info.st_ino)
            if current in known and known[current] != identity:
                raise ValueError("batch artifact parent changed: %s" % current)
            observed[current] = identity
        if remember:
            self._parents[full] = observed
        return full

    def _validated_artifacts(self):
        paths = []
        for row in self.entries:
            if not isinstance(row, dict) or not isinstance(row.get("artifacts"), list):
                raise ValueError("invalid batch artifact list")
            for path in row["artifacts"]:
                paths.append(self._confine(path))
        return paths

    def document(self):
        """The record, stamped with the process WRITING it (#1698).

        Whoever last wrote the record owns it: a recovery that rewrites a
        crashed batch's manifest to flag it takes the record over, so a
        second loop arriving mid-recovery asks about the RECOVERING process
        rather than the long-dead one it is finishing for.
        """
        return {"schema_version": 1, "batch": self.number,
                "checkpoint": self.checkpoint, "opened_at": self.opened_at,
                "pid": os.getpid(), "host": host_id(),
                "entries": self.entries,
                **({"recovering": True} if self.recovering else {})}

    def begin_recovery(self):
        """Mark before any rollback EFFECT -- the ledger row, the artifact,
        the refund -- so a rollback that stops partway is never re-ledgered.

        The ledger and the attempt counters are separate files, so a recovery
        replayed from scratch writes one entry's rollback row twice and
        refunds one attempt twice. A flagged record says "somebody has already
        accounted for this": `loop_batch.recover_stale` finishes the file
        removals it names and writes nothing (#1698).
        """
        self.recovering = True
        self._write()

    def open(self):
        """Write the manifest. Called BEFORE the first submit, so an interrupt
        that lands on the very first entry still has the list."""
        # Reserve this name exclusively: a crash record belongs to recovery,
        # never to the next batch with the same iteration number.
        self._confine(self.path)
        self._validated_artifacts()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        self.opened_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self._write()
        return self

    def _write(self):
        # Through the write guard's own atomic writer, which refuses to follow
        # a symlink planted at `<name>.tmp`: this path is INSIDE the scanned
        # tree, so on a redteam target that link is the target's to plant --
        # the same reason `runners/claude.py` writes host-settings.json with it.
        self._confine(self.path)
        self._validated_artifacts()
        write_guard_hook._atomic_write_json(self.path, self.document(), indent=2)

    def add_artifact(self, entry_id, path):
        """Record a file the batch wrote that `open` could not have known
        about -- `persist.retain_rejected` names the record only once it has
        written it. Kept in the manifest so the rollback stays a LIST and
        never becomes a glob over the rejected folder."""
        if path is None or path == "":
            return
        for row in self.entries:
            if row["id"] == entry_id:
                full = self._confine(path, remember=True)
                if full in row["artifacts"]:
                    return
                row["artifacts"].append(full)
                self._write()
                return

    def entry_ids(self):
        return [row["id"] for row in self.entries]

    def artifacts(self):
        return [path for row in self.entries for path in row["artifacts"]]

    def roll_back(self, *, close=True):
        """Delete exactly the artifacts this manifest lists, then the manifest
        itself. Returns `(removed, problems)`.

        The manifest goes LAST and only when everything before it went: a
        record whose artifacts are still on disk is the one thing that says
        so. `close=False` leaves it to the caller, which has its own work to
        finish -- the ledger rows and the refund -- before this batch is over.

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
        try:
            self._confine(self.path)
            paths = self._validated_artifacts()
        except ValueError as exc:
            return [], ["unsafe batch artifact: %s" % exc]
        for path in paths:
            try:
                self._confine(path)
                os.remove(path)
                removed.append(path)
            except ValueError as exc:
                problems.append("unsafe batch artifact: %s" % exc)
                break
            except FileNotFoundError:
                continue
            except OSError as exc:
                problems.append("%s: %s" % (path, exc))
        if close and not problems:
            problems += self.close()
        return removed, problems

    def close(self):
        """Delete the manifest; the clean path's "this batch is over". Returns
        a list of problems, empty when there were none."""
        try:
            self._confine(self.path)
            os.remove(self.path)
        except ValueError as exc:
            return ["unsafe batch manifest: %s" % exc]
        except FileNotFoundError:
            pass
        except OSError as exc:
            return ["%s: %s" % (self.path, exc)]
        return []
