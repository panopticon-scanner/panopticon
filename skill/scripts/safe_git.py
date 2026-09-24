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
import tempfile
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
#   NOT unconditionally safe: it refreshes the index, and on a tree with
#   `core.fsmonitor` set to a command it DID run that command (measured) --
#   `_launch_argv`'s `-c core.fsmonitor=false` is what makes this entry true,
#   so do not remove it (#2006 fix round 2, M2).
# - `symbolic-ref`: reads or writes one ref name; no worktree content. The
#   WRITE mode is a ref transaction, so it fires `reference-transaction` from
#   the default `.git/hooks` -- measured, and reachable with no config at all.
#   This entry is therefore true ONLY because `_launch_argv` suppresses hooks
#   on every launch (#2006 fix round 2, C2); no caller writes a ref today, and
#   one that did would depend on that suppression, not on this reason.
# - `rev-list`: walks commit history. Its `--filter=` is an object filter, not
#   a command, and no worktree file is opened.
_NO_CONFIGURED_COMMAND = {
    "rev-parse": (),
    "ls-files": ("--eol",),
    "symbolic-ref": (),
    "rev-list": (),
}
# Subcommands that can produce a diff, and so can reach an external diff
# driver or a textconv filter, and the flags that take those paths away. Belt
# and braces beside the config refusal below: a driver reachable through a
# config mechanism the `--includes` sweep cannot see still cannot run. `status`
# is deliberately NOT here -- it rejects both flags (rc=129).
_DIFF_PRODUCING = ("diff", "log", "show")
_NO_DRIVERS = ("--no-ext-diff", "--no-textconv")

# Global options that take a separate value, so the token after them is that
# value and never the subcommand. Any OTHER leading option is unclassified,
# which means the subcommand cannot be identified and the call preflights.
_VALUED_GLOBAL_OPTIONS = ("-c", "-C", "--git-dir", "--work-tree", "--namespace",
                          "--exec-path", "--config-env")


_HOOKS_PATH = None


def _no_hooks_path():
    """An empty directory THIS process owns, for `core.hooksPath`.

    `.git/hooks` is git's default, so this vector needs no configuration at
    all and no config refusal can ever reach it: a `post-index-change` hook
    fires on the preflighted `status` (which is #1985's own baseline path) and
    a `reference-transaction` hook on a `symbolic-ref` write. Pointing git at a
    directory we create and never write to is what closes it (#2006 fix round
    2, C2).

    A real empty directory rather than `/dev/null` (which this git accepts, but
    only via the ENOTDIR path) or a nonexistent path (which a future git could
    reasonably call a configuration error). Created on first use, never at
    import, and left for the OS temp sweep: it is empty, and removing it
    mid-process would re-expose every later launch.
    """
    global _HOOKS_PATH
    if _HOOKS_PATH is None:
        _HOOKS_PATH = tempfile.mkdtemp(prefix="panopticon-no-hooks-")
    return _HOOKS_PATH


def _launch_argv(resolved, directory, command):
    """The argv for one probe launch: trusted git, cwd, both suppressions.

    ONE place, so a new launch site cannot forget one of them -- the fsmonitor
    `-c` is what makes several allowlist entries safe (see the allowlist), and
    the hooksPath `-c` is what makes all of them safe.
    """
    return [resolved.path, "-C", directory,
            "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=" + _no_hooks_path(), *command]


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
    index = _subcommand_index(args)
    return None if index is None else args[index]


def _subcommand_index(args):
    """Where the subcommand sits in `args`, or None when it cannot be found."""
    position = 0
    while position < len(args) and args[position].startswith("-"):
        option = args[position]
        position += 1
        if option in _VALUED_GLOBAL_OPTIONS:
            if position >= len(args):
                return None
            position += 1
        elif "=" in option:
            continue                   # `--git-dir=x`: value attached, no token
        else:
            return None
    return position if position < len(args) else None


def _encoded(value):
    """`value` as bytes, losslessly, or unchanged when it already is."""
    return value.encode("utf-8", "surrogateescape") if isinstance(value, str) else value


def _is_command_setting(key):
    """Whether `key` names a COMMAND LINE the repository authored.

    Each of these is executed by some subcommand the probe can run:
    `filter.*.clean/.process` by `status` (and anything that compares worktree
    content), `diff.external` and `diff.<driver>.command/.textconv` by every
    diff-producing subcommand -- and an external driver's output REPLACES
    git's, so obeying one silently emptied the hunk map as well as running
    target code (#2006 fix round 2, C1).

    `merge.<driver>.driver` is deliberately absent: no subcommand the probe
    runs performs a merge or a checkout, the one exempt path that does
    (`diff_map.acquire_pr`'s `worktree add`) does not go through here, and
    refusing it would make targets that ship a merge driver unreviewable for a
    command we never invoke. Revisit if a probe ever merges.
    """
    if key.startswith("filter.") and key.endswith((".clean", ".process")):
        return True
    return key == "diff.external" or (
        key.startswith("diff.") and key.endswith((".command", ".textconv")))


def _with_options(args, options):
    """`args` with `options` inserted immediately AFTER its subcommand.

    Never appended (#2006 fix round 2, I1): in `git status … -- <pathspec>` an
    appended flag is parsed as a PATH, so `--ignore-submodules=none` after a
    `--` silently became a filename -- rc=0, no error, and #1985's
    submodule-dirt guarantee gone. Inserting after the subcommand is correct
    for every spelling, since a global option can only precede it.
    """
    index = _subcommand_index(args)
    if index is None:
        raise ValueError("safe Git: no subcommand to place %s after" % (list(options),))
    return [*args[:index + 1], *options, *args[index + 1:]]


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
    name = _subcommand(args)
    prepared = list(args)
    if name in _DIFF_PRODUCING:
        prepared = _with_options(prepared, _NO_DRIVERS)
    if not _needs_preflight(args):
        return runner(_launch_argv(resolved, root, prepared),
                      capture_output=True, text=text, timeout=timeout, env=env)

    deadline = time.monotonic() + timeout

    def run(directory, command, as_text=True):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("trusted git probe", timeout)
        return runner(_launch_argv(resolved, directory, command),
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
            if value and _is_command_setting(key):
                # The key is repository-authored too; repr escapes control bytes.
                raise RepositoryRefused(
                    "safe Git probe: unsupported repository command setting %r" % key)
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
    if name == "status":
        # A status that hides submodule dirt is not an integrity baseline; every
        # OTHER subcommand keeps the argv the caller asked for, because this is
        # a `status` flag and placing it elsewhere would change or break the
        # command.
        prepared = _with_options(prepared, ["--ignore-submodules=none"])
    return run(root, prepared, as_text=text)
