"""The ONE walk behind a directory read grant (#1683).

A directory grant is matched by NAME, and nothing resolves a hard link,
because the link IS the file: a link planted inside the granted subtree,
naming an inode outside it, is in scope under every path test there is. The
three read brokers refuse such a file when the read's argument is the FILE
(`codex_read_tools`, `read_guard_hook._hard_link_reason` and its Kimi twin) --
but a `Grep` or `Glob` whose argument is the granted DIRECTORY is adjudicated
once, by path, and then traversed by the HOST's own tool, which opens whatever
it finds.

A PreToolUse hook can allow or deny a call, not rewrite it, and it may not
`os.walk` the reviewed tree on every Grep. So the walk happens HERE: once, on
the driver side, when the grant is built (`phases/setup.py` issues the only
directory grant the driver has), and its result rides in the entry's scope as
`hard_linked`. The hooks then answer from a list instead of from the
filesystem.

What that buys and what it does not: the list is a snapshot of the tree AT
GRANT TIME. A link planted after the grant is issued is not in it -- the tree
is static for the length of a run, and a target that can write into it during
one has already won more than this. The rule is about the tree the driver
measured, honestly stated, not about a race it cannot win.
"""
import os
import stat


# Enough for a normally-shaped tree's accidents (a `cp -al` fixture, a pnpm
# store) and small enough that the scope file stays a scope file. Past it the
# caller fails CLOSED -- see `phases/setup.py`, which records the granted
# directory itself -- rather than truncating the list and adjudicating against
# a half-measured tree.
CAP = 256


def _absent(exc):
    """True for the one OSError that is a MEASUREMENT rather than a failure to
    measure: there is no inode at that name (ENOENT/ENOTDIR, a dangling
    symlink included). `_hard_link_reason`'s fix round 2 (N2) draws the same
    line for the same reason -- nothing at a name is nothing to confine, and a
    walk that cannot find the tree at all has not been blinded, it has been
    pointed somewhere empty."""
    return isinstance(exc, (FileNotFoundError, NotADirectoryError))


def hard_links_under(root, cap=CAP):
    """(paths, overflowed): the multiply-linked regular files beneath `root`.

    `paths` is sorted and realpath-normalised. `overflowed` is True when the
    walk REACHED `cap` and stopped, in which case `paths` holds those `cap`
    entries and says nothing about the rest of the tree -- including the tree
    that held exactly `cap` and no more, which is indistinguishable from the
    inside of a walk that stopped there, and is reported the same way.

    Three rules, and the last two are the ones worth stating:

    * a REGULAR file with `st_nlink > 1` is recorded. Directories are not the
      subject (a directory's link count is its subdirectory count) and
      symlinks are skipped -- `os.lstat`, no follow, because realpath is what
      resolves those and it does so at every other point in the fence.
    * an entry that cannot be MEASURED is recorded as if it were linked, and
      a directory that cannot be DESCENDED is recorded whole. A fence that
      cannot measure denies (`_hard_link_reason` fix round 1, F4); the
      alternative is answering "nothing to see" about a subtree nobody looked
      at. Recording the directory itself denies every Grep at or beneath it,
      which is the same answer its unreadable contents would have produced.
    * nothing is pruned -- not `.git`, not `node_modules`. A `git clone
      --local` object store is exactly a set of links to inodes outside the
      tree, so the most likely planting ground is the one a prune would skip.

    A `root` that does not exist walks nothing and returns `([], False)`: that
    is a successful measurement of an empty tree, and the caller's own
    not-found is the honest answer (the N2 rule, restated).
    """
    root = os.path.realpath(os.path.abspath(root))
    found = set()

    def unreadable(exc):
        # os.walk's onerror: the scandir that failed names the directory it
        # could not open. Record THAT, so the denial covers everything under a
        # subtree nothing could look inside -- unless it has no inode at all
        # (N2), which is the one failure that is a measurement.
        path = getattr(exc, "filename", None)
        if isinstance(path, str) and path and not _absent(exc):
            found.add(os.path.realpath(path))

    for dirpath, dirnames, filenames in os.walk(root, onerror=unreadable,
                                                followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            try:
                info = os.lstat(path)
            except OSError as exc:
                if not _absent(exc):
                    found.add(os.path.realpath(path))
            else:
                if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                    found.add(os.path.realpath(path))
            if len(found) >= cap:
                break
        if len(found) >= cap:
            break
    return sorted(found), len(found) >= cap
