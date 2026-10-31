"""Which argv shapes `safe_git.probe` will run (#3256).

Defense in depth: every production caller already passes one of these, read-only, and a write has
its own door, `safe_git.mutate`. Kept beside `safe_git` rather than in it, which is at its ceiling.
"""

# #3256: what `probe` will run, as defense in depth. Every production caller already passes one of
# these, read-only; a write has its own door, `mutate`. Each value says which argv shapes of that
# subcommand are reads: None for every shape, else a predicate over the tokens after it.
PROBE_SHAPES = {
    "rev-parse": None, "ls-files": None, "status": None, "check-ignore": None,
    "merge-base": None, "rev-list": None, "diff": None, "log": None, "show": None,
    "worktree": lambda rest: rest[:1] == ["list"],
    "config": lambda rest: any(t in ("--list", "-l") or t.startswith("--get") for t in rest),
    "symbolic-ref": lambda rest: (not any(t in ("-d", "--delete", "-m") for t in rest)
                                  and len([t for t in rest if not t.startswith("-")]) <= 1),
}


def refusal(args, index):
    """Why `probe` will not run `args`, or None. `index` is where `safe_git` found the subcommand,
    None when it could not. An unidentified subcommand is refused (fail closed),
    and so is `--output`, the one option that lets a read-only diff or log write a file."""
    name = None if index is None else args[index]
    if name not in PROBE_SHAPES:
        return "safe Git probe: %r is not a read-only subcommand; a write goes through mutate" % (
            name,)
    rest = list(args[index + 1:])
    shape = PROBE_SHAPES[name]
    if (shape is not None and not shape(rest)) or any(t.startswith("--output") for t in rest):
        return "safe Git probe: this %s is not a read; a write goes through mutate" % name
    return None
