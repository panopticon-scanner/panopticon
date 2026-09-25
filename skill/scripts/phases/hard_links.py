"""Read-scope grants and the ONE walk behind a directory grant (#1683).

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


# Enough for a normally-shaped tree's real fence-crossers and small enough that
# the scope file stays a scope file. Past it the caller fails CLOSED -- see
# `phases/setup.py`, which records the granted directory itself -- rather than
# truncating the list and adjudicating against a half-measured tree. A tree's
# ordinary accidents (a `cp -al` fixture, a pnpm store) no longer spend it at
# all: their links are all INSIDE the tree, and #1917's count drops them before
# the cap is applied.
CAP = 256


def scope(files=(), dirs=(), reads=(), hard_linked=None):
    """An entry's read scope: absolute, byte-exact paths the read guard
    matches after realpath. `files` duplicates entry["files"] on purpose (the
    guard reads one key of one shape); `dirs` is a directory scope (setup-
    scan); `reads` is the extra-file allowance -- whatever the builder grants
    beyond the entry's files (the SEC cell's security checklist,
    `review._cell_reads`), plus the entry's own `prompt_file` once
    `requests._materialize_prompts` stamps one, so a host that dispatches from
    the file (marker line first, pointer second) is not denied its own prompt
    by the read guard.

    `hard_linked` belongs to `dirs` (#1683): the files beneath the granted
    directory that carry a link OUTSIDE it, found by `hard_links_under` ONCE
    because a PreToolUse hook may not walk the tree on every Grep. The hooks
    refuse a directory-argument Grep/Glob that would traverse one.

    A `dirs` grant must ANSWER for it: omitting the keyword raises, an empty
    list is the answer for a clean tree. That the one builder issuing such a
    grant calls the walker was a fact about today's code; this makes it a
    property of the shape (fix round 1), because a directory grant whose
    links nobody looked for is the hole #1683 is about."""
    if dirs and hard_linked is None:
        raise ValueError(
            "a directory grant must record its hard links: pass "
            "hard_linked=hard_links_under(...) (an empty list is the answer "
            "for a clean tree)")
    return {"files": list(files), "dirs": list(dirs), "reads": list(reads),
            "hard_linked": list(hard_linked or ())}


def _absent(exc):
    """True for the one OSError that is a MEASUREMENT rather than a failure to
    measure: there is no inode at that name (ENOENT/ENOTDIR, a dangling
    symlink included). `_hard_link_reason`'s fix round 2 (N2) draws the same
    line for the same reason -- nothing at a name is nothing to confine, and a
    walk that cannot find the tree at all has not been blinded, it has been
    pointed somewhere empty."""
    return isinstance(exc, (FileNotFoundError, NotADirectoryError))


def hard_links_under(root, cap=CAP):
    """(paths, overflowed): beneath `root`, the regular files with a link
    OUTSIDE it.

    `paths` is sorted and realpath-normalised. `overflowed` is True when MORE
    than `cap` files were recorded, in which case `paths` holds the first `cap`
    of them and the caller fails closed on the whole grant (`phases/setup.py`).
    A tree holding exactly `cap` is fully described by its list and is not an
    overflow.

    Four rules, and the last three are the ones worth stating:

    * a REGULAR file whose `st_nlink` EXCEEDS the number of names for that
      inode found INSIDE `root` is recorded: some other name for its content
      lies outside the tree the driver measured, which is the whole point of
      the rule. A `cp -al` tree, a pnpm store or any other set of links that
      all sit inside the tree is left alone -- every name for that inode is in
      scope, so denying the Greps above it bought nothing (#1917). A `git
      clone --local` store is NOT cleared by this and must not be: its links
      name the SOURCE repository's objects, outside the tree, which is exactly
      the class this fence exists for.
    * that count is why the walk is always COMPLETE and the filter runs at the
      end: whether a file belongs in the list is unknown until its inode's
      in-tree names have all been seen. `CAP` therefore bounds the FINDINGS,
      not the files walked (nor the paths held while walking) -- a clean
      million-file target pays the whole walk on every `driver setup`, which is
      disclosed here rather than bounded.
    * directories are not the subject (a directory's link count is its
      subdirectory count) and symlinks are skipped -- `os.lstat`, no follow,
      because realpath is what resolves those and it does so at every other
      point in the fence. So are multiply-linked NON-regular files (a FIFO, a
      socket) -- and that is deliberate, not an oversight of `S_ISREG`: no
      out-of-tree CONTENT rides on one, there being nothing at the far end of
      the link to read, and ripgrep skips them too.
    * an entry that cannot be MEASURED is recorded as if it were linked, and
      a directory that cannot be DESCENDED is recorded whole -- both whatever
      any count says, since there is no count to take. A fence that cannot
      measure denies (`_hard_link_reason` fix round 1, F4); the alternative is
      answering "nothing to see" about a subtree nobody looked at. Recording
      the directory itself denies every Grep at or beneath it, which is the
      same answer its unreadable contents would have produced.
    * nothing is pruned -- not `.git`, not `node_modules`. A `git clone
      --local` object store is exactly a set of links to inodes outside the
      tree, so the most likely planting ground is the one a prune would skip.

    A `root` that does not exist walks nothing and returns `([], False)`: that
    is a successful measurement of an empty tree, and the caller's own
    not-found is the honest answer (the N2 rule, restated).
    """
    root = os.path.realpath(os.path.abspath(root))
    found = set()
    # (st_dev, st_ino) -> [st_nlink, [in-tree names]]. One entry per multiply-
    # linked inode; a singly-linked file is nobody's candidate and is never
    # held here.
    candidates: dict[tuple[int, int], list] = {}

    def unreadable(exc):
        # os.walk's onerror: the scandir that failed names the directory it
        # could not open. Record THAT, so the denial covers everything under a
        # subtree nothing could look inside -- unless it has no inode at all
        # (N2), which is the one failure that is a measurement.
        path = getattr(exc, "filename", None)
        if isinstance(path, str) and path and not _absent(exc):
            found.add(os.path.realpath(path))

    # No per-directory sort: the RESULT is sorted below, and that is what makes
    # it deterministic. Sorting every directory's names was for the early stop
    # this no longer has, and on a large tree it is pure cost.
    for dirpath, _dirnames, filenames in os.walk(root, onerror=unreadable,
                                                 followlinks=False):
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                info = os.lstat(path)
            except OSError as exc:
                if not _absent(exc):
                    found.add(os.path.realpath(path))
            else:
                if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                    seen = candidates.setdefault((info.st_dev, info.st_ino),
                                                 [info.st_nlink, []])
                    seen[1].append(os.path.realpath(path))
    for nlink, names in candidates.values():
        # Strictly greater: `nlink == len(names)` accounts for every link to
        # that inode inside the tree. Fewer names than links means at least one
        # of them is somewhere this grant does not cover.
        if nlink > len(names):
            found.update(names)
    ordered = sorted(found)
    return ordered[:cap], len(ordered) > cap
