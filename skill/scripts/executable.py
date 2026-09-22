"""Resolve host executables without trusting the reviewed tree."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass


class ExecutableResolutionError(FileNotFoundError):
    """No executable could be proven to live outside the reviewed tree."""


@dataclass(frozen=True)
class ResolvedExecutable:
    path: str
    path_env: str


_STARTUP_ENV = (
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONUSERBASE",
    "PYTHONPLATLIBDIR", "PYTHONEXECUTABLE", "NODE_OPTIONS", "NODE_PATH",
)


def sanitize_startup_environment(env):
    """Copy an environment without interpreter-controlled startup imports."""
    clean = dict(env)
    for name in _STARTUP_ENV:
        clean.pop(name, None)
    clean["PYTHONNOUSERSITE"] = "1"
    clean["PYTHONSAFEPATH"] = "1"
    return clean


def _inside(root, candidate):
    try:
        return os.path.commonpath([root, candidate]) == root
    except ValueError:
        return False


def resolve(command, review_root, path=None):
    """Return an absolute executable and the PATH safe to give its child.

    Empty and relative PATH entries are discarded. Absolute entries are
    resolved before the reviewed root comparison, so a directory symlink into
    the target is discarded too. A candidate symlink whose real destination
    is in the target poisons its directory for this launch; lookup continues
    in later directories, but that directory is also absent from the PATH the
    child inherits.
    """
    root = os.path.realpath(os.path.abspath(review_root))
    raw_path = os.environ.get("PATH", "") if path is None else path
    safe_dirs = []
    for entry in str(raw_path or "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        directory = os.path.realpath(entry)
        if _inside(root, directory) or directory in safe_dirs:
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
        if not os.path.isabs(candidate) or _inside(root, real):
            if source_dir in safe_dirs:
                safe_dirs.remove(source_dir)
            continue
        if os.path.isfile(real) and os.access(real, os.X_OK):
            return ResolvedExecutable(real, os.pathsep.join(safe_dirs))

    raise ExecutableResolutionError(
        "%s is not available on a trusted PATH outside review root %s"
        % (command, root))
