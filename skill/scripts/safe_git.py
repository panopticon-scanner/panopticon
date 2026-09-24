"""Trusted, bounded Git probes for every git call made against the TARGET.

This prevents the known status fsmonitor/filter command paths, not arbitrary Git
sandboxing. Config/index files must remain stable during preflight and status.

The preflight is the DEFAULT, not a special case for one argv (#2006). #1985
gated it on `args == ["status", "--porcelain", "-z"]`, so a reordered flag, a
pathspec or `--porcelain=v1` -- any spelling a later caller happened to use --
silently skipped the filter refusal and the submodule bound. The gate is now a
capability question ("can this subcommand run a repository-configured
command?") answered from an explicit allowlist of plumbing that cannot, so an
unknown or unenumerated spelling fails CLOSED into the preflight.
"""
from typing import TYPE_CHECKING
import os
import subprocess
import time

# Same dual-import seam as `diff_map`, on the same module: `discovery.py` runs
# as a standalone CLI with only skill/scripts on sys.path, where `scripts` does
# not resolve as a package. Under pytest (conftest) and under driver.py's own
# bootstrap the try arm wins and binds the SAME module object every other
# caller patches.
if TYPE_CHECKING:
    from scripts import executable
else:
    try:
        from scripts import executable
    except ImportError:
        import executable

_MAX_REPOSITORIES = 64


class RepositoryRefused(OSError):
    """The TARGET's own configuration or repository shape was refused.

    Distinct from "git failed" and from "no trusted git is available" (both
    also OSError, and both legitimate reasons to fall back), because only this
    one is a hostile-target finding the operator has to SEE: something in the
    reviewed tree asked us to run its commands, or presented a submodule shape
    we cannot bound, and we declined. Subclasses OSError so every existing
    `except OSError` handler keeps catching it unchanged (#2006 fix round 1).
    """

# Git subcommands that cannot run a repository-configured command, mapped to
# the flags that would make them able to. Anything NOT named here -- including
# every spelling of `status`, every content-reading command (`diff`, `stash`,
# `archive`, `checkout`), and any subcommand nobody has classified yet -- takes
# the preflight. The value is the exclusion list: a listed flag sends that
# spelling back to the preflight.
#
# - `rev-parse`: parses revisions and prints paths/SHAs. It opens no worktree
#   content, so no clean/textconv filter, no diff or merge driver and no
#   fsmonitor query is reachable from it.
# - `ls-files`: reports index and worktree NAMES. `--eol` is the one mode that
#   reads file content through the attribute machinery (and so through a
#   configured filter), so it is excluded by flag rather than assumed absent.
# - `symbolic-ref`: reads or writes one ref name; no worktree content.
# - `rev-list`: walks commit history. Its `--filter=` is an object filter, not
#   a command, and no worktree file is opened.
_NO_CONFIGURED_COMMAND = {
    "rev-parse": (),
    "ls-files": ("--eol",),
    "symbolic-ref": (),
    "rev-list": (),
}
# Global options that take a separate value, so the token after them is that
# value and never the subcommand. Any OTHER leading option is unclassified,
# which means the subcommand cannot be identified and the call preflights.
_VALUED_GLOBAL_OPTIONS = ("-c", "-C", "--git-dir", "--work-tree", "--namespace",
                          "--exec-path", "--config-env")


def _checkout_boundary(start):
    """Exclude enclosing checkout code before the first Git executable runs.

    Walk real filesystem ancestors without interpreting target gitfiles or
    invoking Git. Use the outermost metadata boundary conservatively, so a
    nested checkout cannot make an enclosing checkout's bin/ trusted again.
    This boundary only selects executables; the probe keeps its requested cwd.
    """
    boundary = directory = os.path.realpath(os.path.abspath(start))
    while True:
        try:
            os.lstat(os.path.join(directory, ".git"))
        except FileNotFoundError:
            pass
        else:
            boundary = directory
        parent = os.path.dirname(directory)
        if parent == directory:
            return boundary
        directory = parent


def _subcommand(args):
    """The git subcommand in `args`, or None when it cannot be identified.

    None is the fail-closed answer: a leading global option this does not know
    how to consume could be hiding anything behind it, so the caller treats an
    unidentified subcommand exactly like an unenumerated one.
    """
    rest = list(args)
    while rest and rest[0].startswith("-"):
        option = rest.pop(0)
        if option in _VALUED_GLOBAL_OPTIONS:
            if not rest:
                return None
            rest.pop(0)
        elif "=" in option:
            continue                   # `--git-dir=x`: value attached, no token
        else:
            return None
    return rest[0] if rest else None


def _encoded(value):
    """`value` as bytes, losslessly, or unchanged when it already is."""
    return value.encode("utf-8", "surrogateescape") if isinstance(value, str) else value


def _needs_preflight(args):
    """Whether this argv may reach a repository-configured command."""
    name = _subcommand(args)
    if name not in _NO_CONFIGURED_COMMAND:
        return True
    excluded = _NO_CONFIGURED_COMMAND[name]
    return any(token.split("=", 1)[0] in excluded for token in args)


def probe(root, args, runner=subprocess.run, timeout=15, text=True):
    """Run a captured probe with one shared `timeout`-second deadline.

    `text` and `timeout` are the CALLER's contract for the command it asked
    for; the preflight always reads text, because it parses config and index
    records. Preflighting reads effective config and tracked submodules rather
    than disabling content normalization or hiding submodule dirt. Unsupported
    command filters fail closed; their values are never included in errors.
    """
    def preflight_failure(proc):
        """A failed ROOT preflight, in the type the CALLER asked for.

        The preflight always reads text (it parses config and index records),
        so a `text=False` caller handed this object straight back would get
        `str` where its own contract says bytes (#2006 concern 3).
        """
        if text:
            return proc
        return subprocess.CompletedProcess(proc.args, proc.returncode,
                                           _encoded(proc.stdout), _encoded(proc.stderr))

    resolved = executable.resolve("git", _checkout_boundary(root), os.environ.get("PATH", ""))
    env = {"PATH": resolved.path_env, "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
           "GIT_CONFIG_GLOBAL": os.devnull}
    if not _needs_preflight(args):
        return runner([resolved.path, "-C", root, "-c", "core.fsmonitor=false", *args],
                      capture_output=True, text=text, timeout=timeout, env=env)

    deadline = time.monotonic() + timeout

    def run(directory, command, as_text=True):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("trusted git probe", timeout)
        return runner([resolved.path, "-C", directory, "-c", "core.fsmonitor=false", *command],
                      capture_output=True, text=as_text, timeout=remaining, env=env)

    root_real = os.path.realpath(root)
    pending = [root_real]
    seen = set()
    while pending:
        directory = pending.pop()
        if directory in seen:
            raise RepositoryRefused("safe Git status: cyclic submodule worktree")
        seen.add(directory)
        if len(seen) > _MAX_REPOSITORIES:
            raise RepositoryRefused("safe Git status: submodule traversal exceeds 64 repositories")
        if directory != root_real:
            top = run(directory, ["rev-parse", "--show-toplevel"])
            if top.returncode != 0 or os.path.realpath(top.stdout.strip()) != directory:
                raise RepositoryRefused("safe Git status: submodule worktree root cannot be verified")
        config = run(directory, ["config", "--null", "--list", "--includes"])
        if config.returncode != 0:
            if directory != root_real:
                raise RepositoryRefused("safe Git status: submodule config probe failed")
            return preflight_failure(config)
        settings = {}
        for record in config.stdout.split("\0"):
            key, _, value = record.partition("\n")
            settings[key] = value
        for key, value in settings.items():
            if (key.startswith("filter.") and key.endswith((".clean", ".process"))
                    and value):
                # The key is repository-authored too; repr escapes control bytes.
                raise RepositoryRefused("safe Git status: unsupported command filter setting %r" % key)
        index = run(directory, ["ls-files", "--stage", "-z"])
        if index.returncode != 0:
            if directory != root_real:
                raise RepositoryRefused("safe Git status: submodule index probe failed")
            return preflight_failure(index)
        for record in index.stdout.split("\0"):
            if not record.startswith("160000 "):
                continue
            _metadata, separator, rel = record.partition("\t")
            if (not separator or os.path.isabs(rel)
                    or any(part in ("", ".", "..") for part in rel.split("/"))):
                raise RepositoryRefused("safe Git status: unsafe submodule path")
            child = os.path.realpath(os.path.join(directory, rel))
            if os.path.commonpath([directory, child]) != directory or child == directory:
                raise RepositoryRefused("safe Git status: unsafe submodule path")
            # An absent/uninitialized checkout has no local commands to invoke.
            if os.path.lexists(os.path.join(child, ".git")):
                if child in pending or child in seen:
                    raise RepositoryRefused("safe Git status: cyclic or duplicate submodule worktree")
                pending.append(child)
                if len(seen) + len(pending) > _MAX_REPOSITORIES:
                    raise RepositoryRefused("safe Git status: submodule traversal exceeds 64 repositories")
    final = list(args)
    if _subcommand(args) == "status":
        # A status that hides submodule dirt is not an integrity baseline; every
        # OTHER subcommand keeps the argv the caller asked for, because this is
        # a `status` flag and appending it elsewhere would change or break the
        # command.
        final.append("--ignore-submodules=none")
    return run(root, final, as_text=text)
