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

A repository-configured command is SUPPRESSED, not refused (#2013). #2006
refused the target, which made every git-lfs (`git lfs install --local`) or
git-crypt checkout unreviewable on every path that touches git -- discovery's
dirty check, the manifest's provenance, the delta map, validate's baseline --
with no override. The preflight now collects each such key and empties it with
a `-c <key>=` override on every later launch, proves each override took, and
discloses the pairs it neutralized. The refusal survives exactly where the
proof fails: a key that still reads non-empty is never run.

WHAT SUPPRESSION COSTS, measured (#2013 fix round 1): a clean filter is what
makes the index blob equal the worktree, so emptying it leaves git comparing
RAW worktree bytes against a FILTERED index blob. Paths under a suppressed
driver therefore compare as MODIFIED: dirtiness for them is unknown and a delta
may include them. Measured on the canonical git-lfs shape -- index blob
`ptr payload`, worktree `BIG payload`, plain `git status` clean, this probe's
`status` reporting ` M big.bin`. That is why the suppression is disclosed
rather than silent, and why a DELTA-scoped run over a suppressed comparison
cannot certify its coverage (`synth/tool_axis.reconcile`).

`mutate` is the ONE entry point here allowed to WRITE to the target repository
(#2012): the same fresh environment, hooks pin and driver neutralization as
`probe`, an unskippable preflight, and an allowlist of exactly three subcommand
shapes (`worktree add`, `worktree remove`, `update-ref -d`) -- the `--pr`
worktree lifecycle and nothing else. It exists because `git worktree add` is a
CHECKOUT: it runs the target's smudge filters and its `post-checkout` hook, so
`diff_map.acquire_pr` used to execute target-authored code on the operator's
machine on every `--pr` run.
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

# Global options that would send the FINAL call at a different repository, or
# at different code, than the one the preflight just validated. REFUSED rather
# than parsed past (#2006 fix round 2, M3): the preflight checks `root`, so an
# argv carrying one of these would be cleared against one repository and run
# against another, which is the one failure mode this module exists to prevent.
# No caller passes them; a caller that needs a different repository passes a
# different `root`.
_REDIRECTING_GLOBAL_OPTIONS = ("-C", "--git-dir", "--work-tree", "--namespace",
                               "--exec-path", "--config-env", "--super-prefix")
# `-c <key>=<value>` is the one global option with a separate value that the
# probe itself uses, so it stays legal and its value is never a subcommand.
_VALUED_GLOBAL_OPTIONS = ("-c",)


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
    import, and left for the OS temp sweep. Deleting it mid-process does NOT
    re-expose hooks -- git treats a missing `core.hooksPath` as "no hooks"
    (measured in the #2006 review) -- so keeping it is only about never
    handing a future git a path it might call a configuration error.
    """
    global _HOOKS_PATH
    if _HOOKS_PATH is None:
        _HOOKS_PATH = tempfile.mkdtemp(prefix="panopticon-no-hooks-")
    return _HOOKS_PATH


def no_hooks_path():
    """`_no_hooks_path()` for the ONE caller that cannot use `probe`/`mutate`.

    `diff_map.acquire_pr`'s `git fetch` keeps the operator's environment,
    because the credential helper lives there (#2012), so it cannot be a probe
    launch -- but a fetch is a REF TRANSACTION, and `reference-transaction`
    fires from the target's `core.hooksPath` on it (measured: a repository whose
    contributing docs say `git config core.hooksPath .githooks`, which is the
    common real shape, ran its own committed hook on the acquisition's fetch).
    That caller pins the same directory this module pins on every launch, rather
    than inventing a second empty directory nobody has proved is empty.
    """
    return _no_hooks_path()


def _launch_argv(resolved, directory, command, drivers=()):
    """The argv for one probe launch: trusted git, cwd, every suppression.

    ONE place, so a new launch site cannot forget one of them -- the fsmonitor
    `-c` is what makes several allowlist entries safe (see the allowlist), and
    the hooksPath `-c` is what makes all of them safe.

    `drivers` is the `-c <key>=` run of tokens the preflight composed for the
    repository-configured commands it found (#2013), empty until it has read a
    config. They sit in the GLOBAL position, before the subcommand, like the
    other two -- and because git exports `-c` through `GIT_CONFIG_PARAMETERS`,
    they reach the `git status --porcelain=2` child that runs inside each
    submodule as well (measured; nothing else in this module does).
    """
    return [resolved.path, "-C", directory,
            "-c", "core.fsmonitor=false",
            "-c", "core.hooksPath=" + _no_hooks_path(), *drivers, *command]


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


# Settings `_launch_argv` pins on every launch. A caller's own `-c key=...`
# comes AFTER the probe's in argv and would win (measured in the #2006
# review: `-c core.hooksPath=<evil>` ran the planted hook), so the probe
# refuses them rather than trusting every future caller to know that.
_PROBE_PINNED_CONFIG = ("core.fsmonitor", "core.hookspath")


def _undoes_a_pin(key):
    """A caller `-c` for a pinned key -- or for `include.path` / `includeIf.*`,
    which pull in a file whose settings come AFTER the pins in argv and win
    (#2012 review M2, measured: an included `core.hooksPath` ran the hook)."""
    lowered = key.lower()
    return (lowered in _PROBE_PINNED_CONFIG or lowered == "include.path"
            or lowered.startswith("includeif."))


# Likewise the flags that would re-enable the diff drivers `_NO_DRIVERS`
# turns off (a later flag wins in git).
_DRIVER_ENABLING_OPTIONS = ("--ext-diff", "--textconv")


def _reject_redirection(args):
    """Refuse an argv that could move the final call off the validated root,
    or undo a setting the probe pins on every launch."""
    previous = None
    for token in args:
        if token.split("=", 1)[0] in _REDIRECTING_GLOBAL_OPTIONS:
            raise ValueError(
                "safe Git: %r would redirect the probe off the root it validated; "
                "pass a different root instead" % token)
        if previous == "-c":
            key = token.split("=", 1)[0]
            if _undoes_a_pin(key):
                raise ValueError(
                    "safe Git: %r would override a setting the probe pins itself" % token)
            if _is_suppressible(key):
                # #2013 ruling 5: the probe's own driver overrides are internal
                # and not subject to this, but a CALLER's come later in argv and
                # would win -- re-enabling exactly what the preflight emptied.
                raise ValueError(
                    "safe Git: %r would re-enable a repository command setting the "
                    "probe neutralizes" % token)
        if token in _DRIVER_ENABLING_OPTIONS:
            raise ValueError(
                "safe Git: %r would re-enable a diff driver the probe disables" % token)
        previous = token


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

    `filter.<driver>.smudge` was added by #2013 for completeness, when nothing
    here checked out; #2012 made it load-bearing for a real caller. `mutate`'s
    `worktree add` IS a checkout, so `.smudge` and `.process` (the long-running
    filter protocol serves smudge too) are the ones in this set that the target
    gets to run on the `--pr` route -- emptying them is what stops it.

    AVAILABILITY (#2006 fix round 2, M6, resolved by #2013): these are
    REPO-LOCAL keys, so global-config git-lfs is unaffected
    (`GIT_CONFIG_GLOBAL=/dev/null`), but `git-crypt init` and
    `git lfs install --local` write `filter.*.clean` into `.git/config`. Such a
    target used to be unreviewable; it is now scanned with these keys emptied
    and the suppression disclosed in the run manifest and the report -- at the
    cost the module docstring names: paths under a suppressed driver compare as
    modified.

    `merge.<driver>.driver` is deliberately absent: no subcommand `probe` or
    `mutate` runs performs a MERGE. `mutate`'s `worktree add --detach` is a
    plain checkout of one commit -- filters yes, merge driver never -- and
    overriding a key would claim a suppression for a command we never invoke.
    Revisit if either entry point ever merges (`worktree add` of a branch that
    needs one, `checkout -m`), which the mutating allowlist would have to admit
    first.
    """
    if key.startswith("filter.") and key.endswith((".clean", ".process", ".smudge")):
        return True
    return key == "diff.external" or (
        key.startswith("diff.") and key.endswith((".command", ".textconv")))


def _is_transport_command_setting(key):
    """Whether `key` makes a FETCH run a command the CHECKOUT's config named.

    `diff_map.acquire_pr`'s fetch is the one git call that keeps the operator's
    environment (a private repository's PR head is only fetchable through their
    credential helper), so it is the one call a repo-local setting can still
    reach. It is REFUSED there rather than emptied (#2041 owner ruling: "refuse
    with remedy"), which is why these keys are deliberately absent from
    `_is_command_setting`/`_driver_keys`: those are the keys the probe EMPTIES
    on every launch, and emptying `core.sshCommand` would break the private
    repository the fetch exemption exists for. The remedy is the operator's own
    GLOBAL config, which the fetch still honours.

    MEASURED on git 2.50 (#2012's review, with both of the fetch's pins
    applied): a repo-local `core.sshCommand` ran on the fetch of an `ssh://`
    remote, and `remote.<name>.uploadpack` ran on the fetch of a local-path
    remote. The rest are the same class by git's own documentation rather than
    by measurement -- `core.gitProxy` is the proxy command for `git://`,
    `remote.<name>.vcs` selects the remote-helper program `git-remote-<vcs>`,
    `credential.helper` and `credential.<url>.helper` are command lines (a
    leading `!` makes one an outright shell line) run on an https auth
    challenge, and `protocol.allow`/`protocol.ext.allow` unlock the `ext::`
    helper -- git's default for `ext` is `never` -- that a repo-local
    `remote.<name>.url` is free to name. Other `protocol.<scheme>.allow` keys
    are NOT here: `protocol.file.allow=always` is the documented way to keep
    local-path submodules working since git 2.38.1, and no other scheme hands
    a command line to git.

    Normalizes first, so a hand-written key answers the way git would compare
    it (`_canonical_key`: section and variable lowered, subsection kept). The
    keys the caller reads out of `config --list` are canonical already.
    """
    parts = _canonical_key(key).split(".")
    if len(parts) < 2:
        return False
    section, variable = parts[0], parts[-1]
    if section == "core":
        return len(parts) == 2 and variable in ("sshcommand", "gitproxy")
    if section == "remote":
        # A subsection is mandatory: `remote.uploadpack` names no remote and
        # git runs nothing for it.
        return len(parts) > 2 and variable in ("uploadpack", "vcs")
    if section == "credential":
        return variable == "helper"        # bare, or per-URL (dots and all)
    if section == "protocol":
        # Bare (`protocol.allow`) or the `ext` scheme only; see the docstring.
        return variable == "allow" and parts[1:-1] in ([], ["ext"])
    return False


def transport_command_keys(settings):
    """The keys in `settings` a fetch would execute, sorted; empty ones ignored.

    The public face of `_is_transport_command_setting`, for
    `diff_map.acquire_pr`: it reads the checkout's LOCAL config immediately
    before the one unconfined call and refuses when this is not empty (#2041).

    A key set and then emptied (`git config core.sshCommand ""`) runs nothing,
    so it does not refuse. A GLOBAL or system value never appears here at all,
    because the caller's read is `--local`-scoped -- moving the setting there is
    the remedy the refusal names, so refusing on it would refuse the fix.
    """
    return sorted(key for key, value in settings.items()
                  if value and _is_transport_command_setting(key))


def _filter_driver(key):
    """The driver name in a `filter.<driver>.<setting>` key, or None.

    Subsection-aware: git's subsection is everything between the first and the
    last dot, so `filter.a.b.clean` is the driver `a.b`, not `a`.
    """
    parts = key.split(".")
    if len(parts) < 3 or parts[0] != "filter":
        return None
    return ".".join(parts[1:-1])


def _is_required_flag(key):
    """Whether `key` is a `filter.<driver>.required` flag.

    Emptying a required driver's command line is not enough: git dies
    (`fatal: clean filter 'x' failed`, rc 128 -- measured) when a required
    driver produces no filtered content, so the flag has to come off with the
    command. `-c filter.<d>.required=` reads as false (git parses the empty
    string as a false boolean).
    """
    return _filter_driver(key) is not None and key.endswith(".required")


def _canonical_key(key):
    """`key` with its section and variable name lowercased, as `config --list`
    prints them. The SUBSECTION keeps its case, because git compares that half
    case-sensitively -- so this normalizes exactly what git normalizes."""
    parts = key.split(".")
    if len(parts) < 2:
        return key.lower()
    return ".".join([parts[0].lower(), *parts[1:-1], parts[-1].lower()])


def _is_suppressible(key):
    """Whether `key` is one the preflight would empty (#2013 ruling 5).

    Read by `_reject_redirection` against a CALLER's `-c`, so it normalizes
    case first: a caller's `-c FILTER.lfs.CLEAN=...` names the same setting
    git would, and re-enabling a driver the probe empties is the same hole as
    undoing `core.hooksPath`.
    """
    canonical = _canonical_key(key)
    return _is_command_setting(canonical) or _is_required_flag(canonical)


def _driver_keys(settings):
    """The keys in `settings` this probe must empty, sorted.

    Every command line the repository authored, plus the `required` flag of
    each filter driver that carries one -- that flag alone is not a command and
    is left alone (the probe must not claim a suppression it did not make, and
    a required driver with no command at all is the target's own breakage, not
    ours).
    """
    keys = sorted(key for key, value in settings.items()
                  if value and _is_command_setting(key))
    drivers = {_filter_driver(key) for key in keys}
    keys += sorted(key for key, value in settings.items()
                   if value and _is_required_flag(key)
                   and _filter_driver(key) in drivers)
    return keys


def _settings(stdout):
    """`config --null --list` output as {key: value}, the LAST value winning.

    Last wins because git enumerates command-line `-c` config AFTER the files
    (measured), which is what makes an override visible to the confirmation
    read: the repository's value is listed first and the empty override
    second.
    """
    settings = {}
    for record in stdout.split("\0"):
        key, _, value = record.partition("\n")
        settings[key] = value
    return settings


def settings(stdout):
    """`_settings` for the ONE caller that reads a config for itself.

    `diff_map.acquire_pr` reads the checkout's local config through `probe` and
    asks `transport_command_keys` about it (#2041), so it needs the same
    last-value-wins parse every preflight in here uses rather than a second,
    subtly different one on the far side of a module boundary. The public face
    of `_settings`, exactly as `no_hooks_path` is of `_no_hooks_path`.
    """
    return _settings(stdout)


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


# The only subcommand shapes `mutate` will run (#2012), matched as a prefix of
# the argv from its subcommand onward: the verb is pinned, the flags and paths
# after it stay the caller's business. This is an allowlist of one lifecycle --
# `diff_map`'s `--pr` worktree acquire and release -- not a general write
# permit, so `worktree prune`, `checkout`, `reset`, `clean`, `gc`, `commit` and
# every other way to write to a repository fail CLOSED here rather than
# depending on a reviewer noticing a new call site. None of them is in
# `_NO_CONFIGURED_COMMAND`, and a mutating call never consults it anyway: a
# write to the repository always takes the preflight.
_MUTATING_SHAPES = (("worktree", "add"), ("worktree", "remove"), ("update-ref", "-d"))


def _mutating_shape(args):
    """The `_MUTATING_SHAPES` entry `args` matches, or None for "not one of them".

    None is also the answer when the subcommand cannot be identified at all,
    which is the same fail-closed reading `_needs_preflight` gives it.
    """
    index = _subcommand_index(args)
    if index is None:
        return None
    for shape in _MUTATING_SHAPES:
        if tuple(args[index:index + len(shape)]) == shape:
            return shape
    return None


def _guarded(root, args, runner, timeout, text, suppressed, mutating):
    """The shared body of `probe` and `mutate`; see both for the contract.

    ONE implementation on purpose (#2012): a mutating call needs every
    suppression a read-only one needs and one more besides (it checks out), so a
    second copy of this machinery would be a second place to forget the
    fsmonitor `-c`, the hooks pin, the redirection refusal or the confirmation
    re-read. `mutating` changes exactly two things: the subcommand must match
    `_MUTATING_SHAPES`, and the preflight is not optional.
    """
    def preflight_failure(proc):
        """A failed ROOT preflight, as a result for the command the caller asked for.

        Two things the raw preflight result got wrong. The preflight always
        reads text (it parses config and index records), so a `text=False`
        caller handed this object straight back got `str` where its own contract
        says bytes (#2006 concern 3). And its `args` were the PREFLIGHT's argv,
        so `discovery._git` raised `CalledProcessError` naming `config --null
        --list --includes` and the operator read "git diff failed: ... config"
        for a command they never issued (#2006 fix round 2, M5). The
        returncode and stderr stay the preflight's: that is the real cause.
        """
        return subprocess.CompletedProcess(
            _launch_argv(resolved, root, prepared, drivers), proc.returncode,
            proc.stdout if text else _encoded(proc.stdout),
            proc.stderr if text else _encoded(proc.stderr))

    _reject_redirection(args)
    if mutating and _mutating_shape(args) is None:
        # After `_reject_redirection`, so a `-C`/`--git-dir` argv is named as the
        # redirection it is rather than as an unrecognized verb.
        raise ValueError(
            "safe Git: %r is not one of the mutating shapes this entry point "
            "runs (%s); every other write to a repository is refused"
            % (list(args), ", ".join(" ".join(s) for s in _MUTATING_SHAPES)))
    resolved = executable.resolve("git", _checkout_boundary(root), os.environ.get("PATH", ""))
    env = {"PATH": resolved.path_env, "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
           "GIT_CONFIG_GLOBAL": os.devnull}
    name = _subcommand(args)
    prepared = list(args)
    if name in _DIFF_PRODUCING:
        prepared = _with_options(prepared, _NO_DRIVERS)
    # A MUTATING call never asks: writing to the repository is the one case
    # where skipping the config read would be trading the whole guarantee for
    # two saved launches, and `worktree add` reaches a smudge command that no
    # read-only subcommand does.
    if not mutating and not _needs_preflight(args):
        return runner(_launch_argv(resolved, root, prepared),
                      capture_output=True, text=text, timeout=timeout, env=env)

    deadline = time.monotonic() + timeout
    # The `-c <key>=` tokens composed so far, and the (repository, key) pairs
    # behind them. Grown as each repository's config is read, so every launch
    # AFTER a collection carries every override collected up to that point.
    drivers: list = []
    overridden: set = set()
    neutralized: list = []
    collected_in: list = []

    def run(directory, command, as_text=True, overrides=None):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("trusted git probe", timeout)
        return runner(_launch_argv(resolved, directory, command,
                                   drivers if overrides is None else overrides),
                      capture_output=True, text=as_text, timeout=remaining, env=env)

    def read_config(directory, overrides=None):
        """One `config --null --list --includes` read of `directory`.

        The COLLECTING read passes `overrides=()`: an override already composed
        would make the same key read empty here, and a second repository
        setting it would then go uncollected and undisclosed. Reading raw is
        safe -- `config --list` runs no repository-configured command, which is
        why the preflight could read it before refusing anything in #2006 --
        and the confirmation read passes the overrides on purpose.
        """
        return run(directory, ["config", "--null", "--list", "--includes"],
                   overrides=overrides)

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
        config = read_config(directory, overrides=())
        if config.returncode != 0:
            if directory != root_real:
                raise RepositoryRefused("safe Git status: submodule config probe failed")
            return preflight_failure(config)
        found = _driver_keys(_settings(config.stdout))
        if found:
            where = os.path.relpath(directory, root_real)
            for key in found:
                if key not in overridden:
                    overridden.add(key)
                    drivers.extend(("-c", key + "="))
                neutralized.append((where, key))
            collected_in.append(directory)
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
    if overridden:
        # Ruling 3: prove the override took, in every repository that carried
        # one and at the root the final command runs in, BEFORE running it. A
        # key that still reads non-empty is the fail-closed case the owner kept
        # -- the one thing left that refuses a target.
        for directory in dict.fromkeys([root_real, *collected_in]):
            confirmed = read_config(directory)
            if confirmed.returncode != 0:
                raise RepositoryRefused(
                    "safe Git probe: the repository command settings this probe "
                    "overrides could not be re-read to confirm the override")
            live = _settings(confirmed.stdout)
            for key in sorted(overridden):
                # KNOWN CASE (#2013 fix round 1, review M3): a subsection
                # containing `=` -- `[filter "a=b"] clean = ...`, the key
                # `filter.a=b.clean` -- cannot be overridden at all, because git
                # parses the token `-c filter.a=b.clean=` as the key `filter.a`
                # with the value `b.clean=`. The real key stays set, this read
                # sees it, and the target is REFUSED (measured). A target can
                # choose to be unreviewable that way; it can never choose to be
                # obeyed. Pinned by
                # test_an_unoverridable_subsection_refuses_rather_than_running.
                if live.get(key):
                    # The key is repository-authored; repr escapes control bytes.
                    # The VALUE is a command line and is never named.
                    raise RepositoryRefused(
                        "safe Git probe: the override for repository command setting "
                        "%r did not take effect" % key)
        if suppressed is not None:
            # Sorted, so the manifest can be diffed across runs: submodule
            # traversal order is an index-order artifact, not a fact.
            suppressed.extend(sorted(neutralized))
    if name == "status":
        # A status that hides submodule dirt is not an integrity baseline; every
        # OTHER subcommand keeps the argv the caller asked for, because this is
        # a `status` flag and placing it elsewhere would change or break the
        # command.
        prepared = _with_options(prepared, ["--ignore-submodules=none"])
    return run(root, prepared, as_text=text)


def probe(root, args, runner=subprocess.run, timeout=15, text=True, suppressed=None):
    """Run a captured, READ-ONLY probe with one shared `timeout`-second deadline.

    `text` and `timeout` are the CALLER's contract for the command it asked
    for; the preflight always reads text, because it parses config and index
    records. Preflighting reads effective config and tracked submodules rather
    than disabling content normalization or hiding submodule dirt.

    `suppressed` (#2013) is the disclosure channel: an optional list the caller
    passes, to which the probe appends one `(repository, key)` pair per
    repository-configured command it emptied -- `"."` for the root, else the
    submodule's path relative to it. A caller that passes nothing is suppressed
    SILENTLY, because the run manifest is the disclosure of record and every
    other caller only needs a working probe. Values are never disclosed and
    never appear in an error: they are command lines the target authored.

    A caller that CARES what the answer means should pass the list: paths under
    a suppressed driver compare as modified, so dirtiness for them is unknown
    and a delta may include them (see the module docstring).

    Read-only is not enforced by argv here, because the allowlist that matters
    is the other way round: a subcommand nobody classified takes the preflight,
    and a caller that means to WRITE must say so by calling `mutate`.
    """
    return _guarded(root, args, runner, timeout, text, suppressed, mutating=False)


def mutate(root, args, runner=subprocess.run, timeout=15, text=True, suppressed=None):
    """The ONLY call in this module allowed to WRITE to the target repository.

    Same contract as `probe` -- fresh allowlisted environment, trusted git
    resolved outside the checkout, `core.fsmonitor=false`, `core.hooksPath`
    pinned to a directory this process owns and never writes to, every
    repository-configured `filter.*`/`diff.*` command emptied and re-read to
    prove the override took, caller redirection refused, one shared deadline --
    plus two differences (#2012):

    - The subcommand must be one of `_MUTATING_SHAPES`: `worktree add`,
      `worktree remove`, `update-ref -d`. Anything else is a `ValueError`
      before any git runs. This is the `--pr` worktree lifecycle, not a write
      permit; a new mutation has to be argued for in that list.
    - The preflight is never skipped.

    WHY it exists rather than the caller keeping its own environment:
    `git worktree add` CHECKS OUT the fetched tree, so on the old path the
    target's `filter.*.smudge` command ran (against PR content, with the
    operator's environment) and its `post-checkout` hook ran from whatever
    `core.hooksPath` the repository asked for. Both measured; see
    `tests/test_diff_map.py::TestPrAcquisitionIsConfined`.

    What it does NOT promise: that the write itself is safe to lose. A target
    whose config cannot be neutralized is still REFUSED
    (`RepositoryRefused`), which for a teardown means the caller's tolerance
    (#1082) leaves a worktree behind -- a leaked temporary directory, traded
    for never running target code. `release_worktree` documents that choice.
    """
    return _guarded(root, args, runner, timeout, text, suppressed, mutating=True)
