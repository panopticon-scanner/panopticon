"""Resolve host executables without trusting the reviewed tree."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass


class ExecutableResolutionError(FileNotFoundError):
    """No executable could be proven to live outside the reviewed tree."""


class EnvironmentCanonicalizationError(ValueError):
    """Environment names collide after lossless platform decoding."""


# #3270 (owner ruling D2): one line naming the entry AND the fix. The likeliest
# real trigger is an operator who activated the target's own virtualenv, or a
# direnv `.envrc` from the target that ran.
TARGET_PATH_ENTRY = ("PATH entry %s is inside the target; remove it (deactivate the "
                     "target's virtualenv or direnv) and re-run")
# D2: an entry outside the target whose program is a symlink into it.
TARGET_PATH_PROGRAM = ("PATH entry %s holds %s, which resolves inside the target; "
                       "remove it (deactivate the target's virtualenv or direnv) and re-run")


class TargetPathEntry(ValueError):
    """A PATH entry, or a program it holds, resolves inside the reviewed tree
    (#3270). That is hostility or a badly broken machine, so it HALTS:
    deliberately not a FileNotFoundError, which callers read as "absent"."""

    def __init__(self, entry, program=None):
        super().__init__(TARGET_PATH_ENTRY % entry if program is None
                         else TARGET_PATH_PROGRAM % (entry, program))
        self.entry = entry


@dataclass(frozen=True)
class ResolvedExecutable:
    path: str
    path_env: str


_STARTUP_ENV = (
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONUSERBASE",
    "PYTHONPLATLIBDIR", "PYTHONEXECUTABLE", "NODE_OPTIONS", "NODE_PATH", "BASH_ENV", "ENV",
)
_STARTUP_ENV_PREFIXES = ("LD_", "DYLD_")


def sanitize_startup_environment(env):
    """Copy an environment without process-startup injection controls.

    Names and values are first decoded losslessly with the platform filesystem
    codec, giving filtering and PATH rewriting one canonical representation.
    Ambiguous duplicate names are rejected without reporting either value.
    Shell and interpreter controls are removed by exact name. The LD_ and DYLD_
    namespaces are reserved here as a policy: native loaders expose several
    library, search and audit hooks, so trusted CLI launches must not depend on
    which loader hook a reviewed tree selects. Unrelated variables, including
    names that merely contain those strings, remain intact.
    """
    clean = {}
    for raw_name, raw_value in env.items():
        name = os.fsdecode(raw_name)
        if name in clean:
            raise EnvironmentCanonicalizationError(
                "duplicate canonical environment names")
        clean[name] = os.fsdecode(raw_value)
    for name in _STARTUP_ENV:
        clean.pop(name, None)
    for name in tuple(clean):
        if name.startswith(_STARTUP_ENV_PREFIXES):
            clean.pop(name)
    clean["PYTHONNOUSERSITE"] = "1"
    clean["PYTHONSAFEPATH"] = "1"
    return clean


def _inside(root, candidate):
    """Whether candidate is rooted at root, including filesystem aliases."""
    try:
        if os.path.commonpath([root, candidate]) == root:
            return True
    except ValueError:
        return False
    current = candidate
    while True:
        if os.path.exists(current):
            try:
                if os.path.samefile(root, current):
                    return True
            except OSError:
                # An unverifiable boundary is untrusted: fail closed.
                return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def resolve(command, review_root, path=None):
    """Return an absolute executable and the PATH safe to give its child.

    Empty and relative PATH entries are discarded. Absolute entries are
    resolved before the reviewed root comparison. #3270: an entry inside the
    target -- a directory symlink into it included -- and a PATH candidate
    whose real destination is in the target both raise TargetPathEntry. They
    used to be skipped silently, so an activated target virtualenv was
    invisible. An absolute `command` inside the target is still refused as
    unresolvable: it names no PATH entry.
    """
    root = os.path.realpath(os.path.abspath(review_root))
    raw_path = os.environ.get("PATH", "") if path is None else path
    safe_dirs = []
    for entry in str(raw_path or "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        directory = os.path.realpath(entry)
        if _inside(root, directory):
            raise TargetPathEntry(entry)
        if directory in safe_dirs:
            continue
        safe_dirs.append(directory)

    candidates: list[tuple[str, str | None]]
    if os.path.isabs(command):
        candidate = command
        candidate_dir = os.path.realpath(os.path.dirname(command))
        if candidate_dir not in safe_dirs and not _inside(root, candidate_dir):
            safe_dirs.append(candidate_dir)
        candidates = [(candidate, None)]
    elif os.sep in command or (os.altsep and os.altsep in command):
        candidates = []
    else:
        candidates = []
        for directory in list(safe_dirs):
            found = shutil.which(command, path=directory)
            if found:
                candidates.append((found, directory))

    for candidate, source_dir in candidates:
        real = os.path.realpath(candidate)
        if source_dir is not None and _inside(root, real):
            raise TargetPathEntry(source_dir, candidate)
        if not os.path.isabs(candidate) or _inside(root, real):
            continue
        if os.path.isfile(real) and os.access(real, os.X_OK):
            return ResolvedExecutable(real, os.pathsep.join(safe_dirs))

    raise ExecutableResolutionError(
        "%s is not available on a trusted PATH outside review root %s"
        % (command, root))


def refuse_target_path(target, path=None):
    """Raise TargetPathEntry when any absolute PATH entry resolves inside
    `target` (#3270): the run's first-contact check, made before anything is
    resolved or launched. Empty and relative entries are ignored, as `resolve`
    discards them."""
    root = os.path.realpath(os.path.abspath(target))
    raw_path = os.environ.get("PATH", "") if path is None else path
    for entry in str(raw_path or "").split(os.pathsep):
        if entry and os.path.isabs(entry) and _inside(root, os.path.realpath(entry)):
            raise TargetPathEntry(entry)
