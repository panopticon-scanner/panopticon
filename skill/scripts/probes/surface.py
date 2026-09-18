"""The bounded resolver behind the `target-discovery-surface` probe (#1657).

`probes/common` owns the probe itself -- `CONTROLS`, the registry reading, the
verdict and its sentences. What lives HERE is the part with no host knowledge
at all: turning one `HostSpec.Surface` pattern into candidate paths under a
review root, within caps, without following a link or opening a file.

Its own module because `common` was 742 lines with it inline, past
tests/test_layout.py's LINE_CEILING (spec §10 says exactly this: "if it
crosses LINE_CEILING, the scan moves to a new `probes/surface.py`"). It
imports nothing from `common`, so the import runs one way and `common` can
read it as `surface.<name>` -- one definition, one patch target (layout rule
1). Stdlib only, and every name here is pure path arithmetic plus `lstat`.
"""
import os
import stat

from scripts import codex_read_tools


# The walk's bounds, per pattern (§5.1). A tree deeper than DEPTH_CAP or
# wider than ENTRY_CAP is not scanned to the end -- and reaching either cap
# REFUTES, exactly as an unreadable directory does: a planted deep tree is not
# a way to make this scan give up quietly.
DEPTH_CAP = 12
ENTRY_CAP = 20_000
# Directory NAMES the walk prunes. `codex_read_tools.EXCLUDED_DIRECTORIES` is
# `discovery.EXCLUDE_DIRS` plus `.panopticon` and `.worktrees`, pinned equal to
# it by tests/test_codex_read_tools.py -- so this is the discovery list the
# spec names, reached through the stdlib-only copy rather than through
# `discovery.py`, which is a CLI-shaped module that rewrites `sys.path` on
# import. A third copy of the same list is what the parity test exists to
# prevent.
PRUNED_DIRS = frozenset(codex_read_tools.EXCLUDED_DIRECTORIES)


class Walk:
    """One pattern's bookkeeping: what could not be read, and whether a cap
    stopped the scan before it had seen everything.

    A pattern's scan is bounded but never SILENTLY bounded: `unreadable` and
    `capped` are what turn a partial answer into a refusal, because a tree the
    probe could not finish reading is not a tree it found nothing in.
    """

    def __init__(self, pattern):
        self.pattern = pattern
        self.entries = 0
        self.unreadable = []           # sentences, already operator-facing
        self.capped = None             # the cap that stopped us, or None

    def failed(self, exc):
        """`os.walk`'s `onerror`, and `listdir`'s except clause.

        An ABSENT directory is not a fault -- essentially every target lacks
        most of these paths, and folding that into "unreadable" would refuse
        every ordinary run. Anything else is a place we could not LOOK.
        """
        if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
            return
        self.unreadable.append("could not read %s (%s)"
                               % (exc.filename or "the reviewed tree",
                                  exc.strerror or exc))

    def listdir(self, directory):
        """The names in `directory`, counted against the entry cap."""
        try:
            names = sorted(os.listdir(directory))
        except OSError as exc:
            self.failed(exc)
            return ()
        return self.count(names)

    def count(self, names):
        self.entries += len(names)
        if self.entries > ENTRY_CAP:
            self.cap("%d entries" % ENTRY_CAP)
        return names

    def cap(self, what):
        self.capped = self.capped or what

    def stop(self):
        return self.capped is not None


def _depth(root, directory):
    """How many levels below `root` this directory sits. 0 is `root` itself."""
    relative = os.path.relpath(directory, root)
    return 0 if relative == os.curdir else relative.count(os.sep) + 1


def walk_tree(root, walk):
    """(directory, entry names) for every directory at or under `root`.

    `os.walk(followlinks=False)` (R3), so a symlinked directory is listed --
    and therefore reportable as a hit by the caller -- but never descended:
    a link back to the review root would otherwise be an endless walk that
    only the entry cap ended, turning an ordinary tree into a refusal.

    Pruning is by NAME, on the same list discovery prunes, and both caps stop
    the walk here rather than inside the caller's loop: `dirnames[:] = []` is
    what `os.walk` reads back, so a cap reached mid-tree stops the descent
    instead of merely being noticed afterwards.
    """
    for directory, dirnames, filenames in os.walk(root, onerror=walk.failed,
                                                  followlinks=False):
        if _depth(root, directory) >= DEPTH_CAP:
            walk.cap("%d levels" % DEPTH_CAP)
            dirnames[:] = []
        else:
            dirnames[:] = [name for name in dirnames if name not in PRUNED_DIRS]
        yield directory, walk.count(sorted(dirnames) + sorted(filenames))
        if walk.stop():
            dirnames[:] = []
            return


def candidates(review_root, segments, walk):
    """Absolute paths one pattern's segments name, under `review_root` (R2).

    Three shapes and no others: a literal segment is joined, a `*` segment is
    one `listdir`, and `**` -- at the head or at the tail -- is the bounded
    walk above. Nothing here stats a candidate; that is the caller's job,
    because the RULE for what counts as a hit (R3) is one rule for all three.
    """
    if walk.stop():
        return
    if not segments:
        yield review_root
        return
    head, rest = segments[0], segments[1:]
    if head == "**":
        for directory, names in walk_tree(review_root, walk):
            if rest:
                # `**` at the HEAD: the rest of the pattern, resolved at every
                # depth. It cannot contain a second `**` -- the registry's
                # `supported_surface_pattern` rejects that shape -- so this
                # recursion never re-enters the walk.
                yield from candidates(directory, rest, walk)
            else:
                # `**` at the TAIL: every entry under here, at any depth. The
                # walk has already listed them, so nothing is read twice.
                for name in names:
                    yield os.path.join(directory, name)
        return
    if head == "*":
        for name in walk.listdir(review_root):
            yield from candidates(os.path.join(review_root, name), rest, walk)
        return
    yield from candidates(os.path.join(review_root, head), rest, walk)


def hit_identity(path):
    """(dev, ino) when this path is something the host would LOAD, else None.

    R3: a regular file counts, and so does a SYMLINK -- the CLI follows it, so
    the target gets its content in either case -- while a FIFO, a directory or
    a socket is skipped. `os.lstat`, never `os.stat`: a symlink is counted
    from the link itself and is never followed, so a link pointing at a named
    pipe cannot block this scan the way `open()` on the pipe would.

    The identity, rather than a bare True, is what de-duplicates a file two
    patterns both name -- `AGENTS.md` and `**/AGENTS.md`, or `AGENTS.md` and
    `agents.md` on a case-insensitive filesystem, which are one inode and
    must be one sentence.
    """
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISLNK(info.st_mode) or stat.S_ISREG(info.st_mode):
        return (info.st_dev, info.st_ino)
    return None


