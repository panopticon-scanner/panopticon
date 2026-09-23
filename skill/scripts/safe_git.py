"""Trusted, bounded Git probes for validation and initial root resolution.

This prevents the known status fsmonitor/filter command paths, not arbitrary Git
sandboxing. Config/index files must remain stable during preflight and status.
"""
import os
import subprocess
import time

from scripts import executable

_MAX_REPOSITORIES = 64


def probe(root, args, runner=subprocess.run):
    """Run a captured text probe with one 15-second subprocess deadline.

    Status preflights effective config and tracked submodules rather than
    disabling content normalization or hiding submodule dirt. Unsupported
    command filters fail closed; their values are never included in errors.
    """
    resolved = executable.resolve("git", root, os.environ.get("PATH", ""))
    env = {"PATH": resolved.path_env, "LC_ALL": "C",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
           "GIT_CONFIG_GLOBAL": os.devnull}
    if args != ["status", "--porcelain", "-z"]:
        return runner([resolved.path, "-C", root, "-c", "core.fsmonitor=false", *args],
                      capture_output=True, text=True, timeout=15, env=env)

    deadline = time.monotonic() + 15

    def run(directory, command):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired("trusted git status probe", 15)
        return runner([resolved.path, "-C", directory, "-c", "core.fsmonitor=false", *command],
                      capture_output=True, text=True, timeout=remaining, env=env)

    root_real = os.path.realpath(root)
    pending = [root_real]
    seen = set()
    while pending:
        directory = pending.pop()
        if directory in seen:
            raise OSError("safe Git status: cyclic submodule worktree")
        seen.add(directory)
        if len(seen) > _MAX_REPOSITORIES:
            raise OSError("safe Git status: submodule traversal exceeds 64 repositories")
        if directory != root_real:
            top = run(directory, ["rev-parse", "--show-toplevel"])
            if top.returncode != 0 or os.path.realpath(top.stdout.strip()) != directory:
                raise OSError("safe Git status: submodule worktree root cannot be verified")
        config = run(directory, ["config", "--null", "--list", "--includes"])
        if config.returncode != 0:
            if directory != root_real:
                raise OSError("safe Git status: submodule config probe failed")
            return config
        settings = {}
        for record in config.stdout.split("\0"):
            key, _, value = record.partition("\n")
            settings[key] = value
        for key, value in settings.items():
            if (key.startswith("filter.") and key.endswith((".clean", ".process"))
                    and value):
                # The key is repository-authored too; repr escapes control bytes.
                raise OSError("safe Git status: unsupported command filter setting %r" % key)
        index = run(directory, ["ls-files", "--stage", "-z"])
        if index.returncode != 0:
            if directory != root_real:
                raise OSError("safe Git status: submodule index probe failed")
            return index
        for record in index.stdout.split("\0"):
            if not record.startswith("160000 "):
                continue
            _metadata, separator, rel = record.partition("\t")
            if (not separator or os.path.isabs(rel)
                    or any(part in ("", ".", "..") for part in rel.split("/"))):
                raise OSError("safe Git status: unsafe submodule path")
            child = os.path.realpath(os.path.join(directory, rel))
            if os.path.commonpath([directory, child]) != directory or child == directory:
                raise OSError("safe Git status: unsafe submodule path")
            # An absent/uninitialized checkout has no local commands to invoke.
            if os.path.lexists(os.path.join(child, ".git")):
                if child in pending or child in seen:
                    raise OSError("safe Git status: cyclic or duplicate submodule worktree")
                pending.append(child)
                if len(seen) + len(pending) > _MAX_REPOSITORIES:
                    raise OSError("safe Git status: submodule traversal exceeds 64 repositories")
    return run(root, [*args, "--ignore-submodules=none"])
