"""Name every external app a run launches: path, version and sha256 (#3270).

The #3173 armor audit's rule is that the apps on the operator's machine are
traced and named, not trusted blindly. Every record has one shape, and it is
the contract #3271 (I3) and #3272 (I5) read -- I5 keys its probe cache on
`sha256` and `version` together, because a launcher shim (an npm-installed
`codex` resolves to a script that execs the real binary) can keep its sha
across a version bump:

    {"name": "claude", "path": <realpath>, "version": <first line of
     `<app> --version`, bounded>, "sha256": <hex>, "size": <bytes>}

A field the machine could not answer is None, and `reason` then says which
step failed. Nothing is ever filled in from a table or a guess.

The app is found through `executable.resolve`, so a PATH entry inside the
target HALTS here as everywhere else (TargetPathEntry propagates), and the
version is read through the hardened launcher, never a bare name.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess

import scripts.executable as executable
import scripts.hosts as hosts
from scripts.runners import children

# The seam tests/conftest.py swaps for its refusal, as every launch seam is.
DEFAULT_RUNNER = children.launch
VERSION_TIMEOUT = 15
MAX_VERSION = 200
_CHUNK = 1 << 20
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_VERSION = re.compile(r"[ -~]{1,%d}\Z" % MAX_VERSION)
_PRINTABLE = re.compile(r"[ -~]+\Z")
_MAX_PATH = 4096
_MAX_REASON = 200
_MAX_APPS = 8
KEYS = ("name", "path", "version", "sha256", "size")


def _digest(path):
    """(sha256 hex, size) of the regular file at `path`, streamed."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("not a regular file")
        h, size = hashlib.sha256(), 0
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                return h.hexdigest(), size
            h.update(chunk)
            size += len(chunk)
    finally:
        os.close(fd)


def _version(path, runner, launch_kwargs):
    """The first line `<path> --version` prints, or None."""
    proc = runner([path, "--version"], capture_output=True, text=True,
                  timeout=VERSION_TIMEOUT, **launch_kwargs)
    out = proc.stdout or ""
    lines = (out.decode("utf-8", "replace") if isinstance(out, bytes) else out).strip().splitlines()
    first = lines[0].strip()[:MAX_VERSION] if lines else ""
    return first if proc.returncode == 0 and _VERSION.match(first) else None


def trace(name, path, runner=None, **launch_kwargs):
    """The record for the app at `path`, an executable `resolve` returned.
    `runner` is `subprocess.run`-shaped; `launch_kwargs` (an `env`) go to it."""
    runner = runner or DEFAULT_RUNNER
    real = os.path.realpath(path)
    record = {"name": name, "path": real, "version": None, "sha256": None, "size": None}
    reasons = []
    try:
        record["sha256"], record["size"] = _digest(real)
    except OSError as exc:
        reasons.append("unreadable: %s" % (exc.strerror or type(exc).__name__))
    try:
        record["version"] = _version(path, runner, launch_kwargs)
        if record["version"] is None:
            reasons.append("`--version` printed no version")
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as exc:
        reasons.append("`--version` failed: %s" % type(exc).__name__)
    if reasons:
        record["reason"] = "; ".join(reasons)
    return record


def trace_command(name, review_root, runner=None):
    """Resolve `name` off a trusted PATH and trace it. An app that is not on
    one is recorded as such; an in-target PATH entry raises TargetPathEntry."""
    try:
        resolved = executable.resolve(name, review_root, os.environ.get("PATH", ""))
    except executable.ExecutableResolutionError:
        return {"name": name, "path": None, "version": None, "sha256": None,
                "size": None, "reason": "not on a trusted PATH"}
    return trace(name, resolved.path, runner)


def host_apps(host, review_root):
    """[the host CLI's record] for `host-capabilities.json`, or [] for a host
    the registry does not know. A module attribute, so the suite can stand it
    in (tests/conftest.py) rather than hash the operator's real CLI."""
    spec = hosts.spec(host)
    binary = getattr(spec, "cli_binary", None)
    return [trace_command(binary, review_root)] if binary else []


def home_relative(apps):
    """The rows with a path under the operator's home spelled `~/...` (#3271
    S2): the report is published, the manifests keep the full path."""
    home = os.path.expanduser("~").rstrip("/")
    out = []
    for app in apps:
        path = app.get("path")
        if home and isinstance(path, str) and path.startswith(home + "/"):
            app = dict(app, path="~" + path[len(home):])
        out.append(app)
    return out


def repair(value):
    """The `apps` list as a report may carry it: every row's five keys in
    shape or None, at most `_MAX_APPS` rows, anything else dropped. The
    manifests it comes from are target-writable."""
    if not isinstance(value, list):
        return []
    out = []
    for row in value[:_MAX_APPS]:
        if not isinstance(row, dict) or not isinstance(row.get("name"), str) \
                or not _NAME.match(row["name"]):
            continue
        path, version, sha, size = (row.get(k) for k in KEYS[1:])
        clean = {
            "name": row["name"],
            "path": path if isinstance(path, str) and path.startswith("/")
            and len(path) <= _MAX_PATH and _PRINTABLE.match(path) else None,
            "version": version if isinstance(version, str) and _VERSION.match(version) else None,
            "sha256": sha if isinstance(sha, str) and _SHA256.match(sha) else None,
            "size": size if isinstance(size, int) and not isinstance(size, bool)
            and size >= 0 else None}
        reason = row.get("reason")
        if isinstance(reason, str) and _PRINTABLE.match(reason[:_MAX_REASON]):
            clean["reason"] = reason[:_MAX_REASON]
        out.append(clean)
    return out

