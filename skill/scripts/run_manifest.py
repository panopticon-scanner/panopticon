"""The 5.0 driver run-manifest: the written-once record of a run's parameters.

Params live here (target, review_root, host, security_mode, base, flags, run_id,
scope);
PROGRESS never does — the driver re-derives the phase cursor from artifact
presence. The manifest is written once by the first `driver run`; a conflicting
flag on re-invocation is refused. See
docs/superpowers/specs/2026-08-15-panopticon-5.0-driver-skeleton-design.md §3.
"""
import json
import os
import uuid

MANIFEST_NAME = "run-manifest.json"
SCHEMA_VERSION = 1

# The flag keys whose drift across re-invocations must be refused (anti-drift).
_FLAG_KEYS = ("fail_on", "severity", "gate_scope", "diff_context", "tools",
              "include_fixtures")


def manifest_path(review_root):
    return os.path.join(review_root, ".panopticon", MANIFEST_NAME)


def new_run_id():
    return uuid.uuid4().hex


def build_manifest(*, target, review_root, host, security_mode, base=None,
                   flags=None, run_id=None, worktree=None, scope=None):
    flags = flags or {}
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id or new_run_id(),
        "target": os.path.abspath(target),
        "review_root": os.path.abspath(review_root),
        "base": base,
        "security_mode": security_mode,
        "host": host,
        "worktree": worktree,   # PR worktree to release at validate; None otherwise
        "flags": {k: flags.get(k) for k in _FLAG_KEYS},
        "scope": scope or {"mode": "repo", "target": None},
    }


def write_manifest(review_root, manifest):
    """Write the manifest ONCE. Raise FileExistsError if one already exists —
    callers reset explicitly (reset_run) before re-writing."""
    path = manifest_path(review_root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        raise FileExistsError(path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    return path


def load_manifest(review_root):
    """Return the manifest dict, or None if absent/unparseable."""
    try:
        with open(manifest_path(review_root), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def conflicting_flags(manifest, *, host=None, security_mode=None, base=None,
                      flags=None, scope=None):
    """Human-readable conflicts between an existing manifest and re-invocation
    params. Empty list = no drift. A None incoming value never conflicts (a bare
    `driver run` re-invocation passes nothing and always matches)."""
    conflicts = []

    def check(name, existing, incoming):
        if incoming is not None and incoming != existing:
            conflicts.append(
                f"{name}: run started with {existing!r}, got {incoming!r}")

    check("host", manifest.get("host"), host)
    check("security_mode", manifest.get("security_mode"), security_mode)
    check("base", manifest.get("base"), base)
    check("scope", manifest.get("scope"), scope)
    existing_flags = manifest.get("flags") or {}
    incoming_flags = flags or {}
    for k in _FLAG_KEYS:
        check(f"flags.{k}", existing_flags.get(k), incoming_flags.get(k))
    return conflicts


def reset_run(review_root):
    """Remove the manifest so a fresh `driver run` can start over. Returns True
    if a manifest was removed. The driver's --reset path also clears the derived
    artifacts; this only owns the manifest."""
    try:
        os.remove(manifest_path(review_root))
        return True
    except OSError:
        return False
