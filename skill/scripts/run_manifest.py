"""The 5.0 driver run-manifest: the written-once record of a run's parameters.

Params live here (target, review_root, host, security_mode, base, flags, run_id,
scope, pr);
PROGRESS never does — the driver re-derives the phase cursor from artifact
presence. The manifest is written once by the first `driver run`; a conflicting
flag on re-invocation is refused.

TWO deliberate exceptions rewrite it, both through the one atomic `_rewrite`,
and neither is an anti-drift key:

1. `flags.tools` may be relaxed to False on a run already in flight —
   `record_tools_downgrade` (#1637 P08 F2) — because the alternative was
   `--reset`, i.e. discarding every paid scout, as the only exit from a scanner
   environment that moved mid-run. It is recorded, not silent: the previous
   value and a timestamp land in `flag_changes`, and the report discloses it.
   The reverse (False -> True) is still refused as drift. See
   docs/superpowers/specs/2026-08-15-panopticon-5.0-driver-skeleton-design.md §3.
2. `posture_disclosed` records that this run's full host-posture block has been
   printed — `record_posture_disclosure` (#1596). It is the one `.panopticon`
   file with an anti-forgery guard, which is why the decision reads off it and
   not off `host-capabilities.json`; it holds what the operator has been TOLD,
   not a run parameter, so the manifest is a record here rather than config.
   The nearest thing to PROGRESS this file carries, and deliberately not it: a
   lost value costs one repeated disclosure, never a re-run phase.
"""
import datetime
import json
import os
import subprocess
import re
import sys
import uuid

from scripts import hosts

MANIFEST_NAME = "run-manifest.json"
SCHEMA_VERSION = 1


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def _slug(value, default):
    """Filesystem-safe component for the run tag (alphanumerics only)."""
    s = re.sub(r"[^A-Za-z0-9]+", "", str(value or ""))
    return s or default


def validate_host(host):
    """Refuse a host the registry does not know.

    The manifest's host key drives the per-run folder name and every posture
    decision downstream; a typo that reaches this far would silently produce
    an unenforced run under a plausible-looking directory (#1344).
    """
    if hosts.spec(host) is None:
        raise ValueError("unknown host %r (known: %s)"
                         % (host, "|".join(hosts.known_hosts())))
    return host


def run_tag(manifest):
    """The stable per-run folder name: ``<host>-<mode>-<scope>-<yyyymmdd>-<runid8>``.

    Derived entirely from the write-once manifest, so it is byte-identical across
    every resume of the same run (the per-run folder never moves mid-run). Returns
    None for a falsy/None manifest so callers fall back to the flat top-level.

    PURE SLUGGING -- this never raises, and must not. `phases/runio._run_tag`
    calls it on EVERY artifact path resolution (`_pano`, `_report_out`,
    `_ensure_run_symlinks`), including `driver._clear_run_artifacts`, which is
    the --reset RECOVERY path. A host check here turned a poisoned
    `run-manifest.json` on disk into an uncaught ValueError in the middle of
    path computation that --reset could not clear. The registry check lives on
    the two paths that can act on the answer instead: `build_manifest` (the
    write path, where the host comes from CLI args) and `load_manifest` (the
    read path, which discards an unusable manifest exactly like a corrupt one).
    """
    if not manifest:
        return None
    host = _slug(manifest.get("host"), "host")
    mode = _slug(manifest.get("security_mode"), "standard")
    scope = _slug((manifest.get("scope") or {}).get("mode"), "repo")
    stamp = (manifest.get("created") or "")[:10].replace("-", "") or "00000000"
    rid = _slug(manifest.get("run_id"), "")[:8] or "00000000"
    return f"{host}-{mode}-{scope}-{stamp}-{rid}"

# The flag keys whose drift across re-invocations must be refused (anti-drift).
_FLAG_KEYS = ("fail_on", "severity", "gate_scope", "diff_context", "tools",
              "include_fixtures", "max_per_group", "allow_unenforced",
              "max_verify")


def manifest_path(review_root):
    return os.path.join(review_root, ".panopticon", MANIFEST_NAME)


def new_run_id():
    return uuid.uuid4().hex


def _target_provenance(target, runner=subprocess.run):
    """(commit, dirty) for the tree being scanned, or (None, None) if not git.

    #1492: nothing in the run record established WHICH code a run saw. `base`
    and `pr_base` are the delta-review base REF, not the scanned HEAD, and both
    are null on a full-repo run -- so every cross-run comparison the calibration
    apparatus rests on (the cap series, the same-cap overlap result, the per-cell
    yield curve) assumed tree-identity it could not verify. Comparing fzf's
    cap-15 and cap-48 runs required inferring it from the fact that their group
    files union to 155 paths, which would catch a changed file SET and never a
    changed file's CONTENTS.

    Recorded, never enforced: a resumed run must not be refused because the tree
    moved under it. This is provenance, not an anti-drift flag.
    """
    try:
        head = runner(["git", "-C", target, "rev-parse", "HEAD"],
                      capture_output=True, text=True, timeout=15)
        if head.returncode != 0:
            return None, None
        status = runner(["git", "-C", target, "status", "--porcelain"],
                        capture_output=True, text=True, timeout=15)
        if status.returncode != 0:
            return head.stdout.strip() or None, None
        return head.stdout.strip() or None, bool(status.stdout.strip())
    except (subprocess.SubprocessError, OSError):
        return None, None


def build_manifest(*, target, review_root, host, security_mode, base=None,
                   flags=None, run_id=None, worktree=None, scope=None, pr=None,
                   pr_base=None, created=None):
    # The WRITE path: this host came from CLI args, so a host the registry does
    # not know is a programming error and raising is both correct and the only
    # place it is reachable from (#1344).
    validate_host(host)
    flags = flags or {}
    _commit, _dirty = _target_provenance(os.path.abspath(target))
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id or new_run_id(),
        # Stamped once at manifest creation (write-once); the run tag derives its
        # yyyymmdd from here, so the per-run folder name is stable across resumes.
        "created": created or _now_iso(),
        "target": os.path.abspath(target),
        "review_root": os.path.abspath(review_root),
        "base": base,
        "security_mode": security_mode,
        "host": host,
        "worktree": worktree,   # PR worktree to release at validate; None otherwise
        "flags": {k: flags.get(k) for k in _FLAG_KEYS},
        "scope": scope or {"mode": "repo", "target": None},
        "pr": pr,
        # DERIVED (like worktree): the gh-detected PR base, threaded to
        # orchestrator's --pr-base for origin/<base> preference (#947). NOT an
        # anti-drift key -- a PR's base is fixed by the PR, not a user knob.
        "pr_base": pr_base,
        # #1492: provenance of the tree that was scanned. Recorded so a
        # cross-run comparison can be VERIFIED rather than assumed; never an
        # anti-drift key (see _target_provenance).
        "target_commit": _commit,
        "target_dirty": _dirty,
    }


def write_manifest(review_root, manifest):
    """Write the manifest ONCE. Raise FileExistsError if one already exists —
    callers reset explicitly (reset_run) before re-writing."""
    path = manifest_path(review_root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # #1033: mode "x" is exclusive-create — it raises FileExistsError ATOMICALLY
    # at the syscall, closing the check-then-open TOCTOU window and never
    # truncating an existing manifest (which "w" would).
    with open(path, "x", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    return path


def load_manifest(review_root):
    """Return the manifest dict, or None if absent/unparseable/unusable.

    A host the registry does not know makes the manifest UNUSABLE, which is
    what "corrupt" already means here: every posture decision downstream reads
    that key, so resuming on it would produce an unenforced run under a
    plausible-looking directory name. An ABSENT host key is a different thing
    and is left alone: every consumer reads it as `get("host", "claude")`, so a
    manifest written before the key existed still resolves -- unknown is not
    absent. Returning None puts it on the path the
    driver already has for a corrupt manifest -- clear the derived artifacts
    and rebuild from the real CLI args -- instead of raising from a path
    helper (#1344). Announced on stderr, never silently.
    """
    try:
        with open(manifest_path(review_root), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("host") is not None and hosts.spec(data["host"]) is None:
        print("driver: discarding run-manifest.json naming unknown host %r "
              "(known: %s)" % (data.get("host"), "|".join(hosts.known_hosts())),
              file=sys.stderr, flush=True)
        return None
    return data


def conflicting_flags(manifest, *, host=None, security_mode=None, base=None,
                      flags=None, scope=None, pr=None):
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
    check("pr", manifest.get("pr"), pr)
    existing_flags = manifest.get("flags") or {}
    incoming_flags = flags or {}
    for k in _FLAG_KEYS:
        if k == "tools" and is_tools_downgrade(manifest, flags):
            # #1637 P08 F2: `--no-tools` on an IN-FLIGHT run is an allowed
            # DOWNGRADE, not drift. Anti-drift exists so a resumed run cannot
            # quietly change what the entries already dispatched were built
            # under; switching tools OFF only ever removes an input from the
            # entries still to come, and the choice is disclosed in
            # tools-ran.json, meta.tools.disabled_mid_run and the report body.
            # Refusing it left `--reset` -- discard every paid scout -- as the
            # only exit from an environment that moved mid-run, which is the
            # loss the readiness checkpoint exists to prevent.
            #
            # ONE WAY ONLY. False -> True stays drift: panels already
            # dispatched saw no scanner evidence, and no later flag can change
            # what they were shown.
            continue
        check(f"flags.{k}", existing_flags.get(k), incoming_flags.get(k))
    return conflicts


def is_tools_downgrade(manifest, flags):
    """True when `flags` switches an in-flight run's tools OFF (#1637 P08 F2).

    `None` incoming means the operator passed neither `--tools` nor
    `--no-tools`, which is not a request to change anything.
    """
    return ((flags or {}).get("tools") is False
            and (manifest.get("flags") or {}).get("tools") is not False)


# Keys `driver.run` attaches to the IN-MEMORY manifest that must never reach
# disk: they describe this invocation, not the run. `session_dir` names where
# the host session runs (I2); `invocation` is the per-call token `tools_done`
# reads back off the tools marker (#1637 P08 F1). Persisting either would make
# a resume inherit a fact about a process that has exited.
_EPHEMERAL_KEYS = ("session_dir", "invocation")

# #1596: {"digest": <host_disclosure.disclosure_digest>, "at": <probed_at>} --
# the posture this run has already disclosed IN FULL on stderr, and when. The
# stamp lives here rather than beside the evidence in
# `runs/<tag>/host-capabilities.json` because it decides whether a disclosure
# is PRINTED, and this is the one `.panopticon` file with an anti-forgery
# guard: `driver.run` discards a manifest that is git-tracked in the reviewed
# tree or stamped for another checkout (`runio._foreign_manifest`) and rebuilds
# from argv. A target that force-commits an artifact matching what the probe
# is about to find could otherwise silence surface 1 on the first invocation.
POSTURE_DISCLOSED = "posture_disclosed"


def _rewrite(review_root, manifest):
    """Write the manifest back through a temp file + `os.replace`.

    The manifest is otherwise write-once, and stays so for every anti-drift
    key -- the two callers below are the deliberate exceptions and each says
    why. Atomic because this is the one artifact that anchors the run tag: an
    interrupt mid-write would leave every `_pano` path unresolvable. The
    ephemeral keys are stripped here, once, rather than at each caller.
    """
    body = {k: v for k, v in manifest.items() if k not in _EPHEMERAL_KEYS}
    path = manifest_path(review_root)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(body, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return manifest


def record_tools_downgrade(review_root, manifest):
    """Persist `--no-tools` on an in-flight run, and say when it happened.

    Recorded rather than silent -- `flag_changes` keeps the previous value and
    the timestamp, so a reader of the run record can see that this run did not
    start the way it finished. `meta.tools.disabled_mid_run` is derived from it.
    """
    previous = (manifest.get("flags") or {}).get("tools")
    manifest.setdefault("flags", {})["tools"] = False
    manifest["flag_changes"] = list(manifest.get("flag_changes") or []) + [
        {"flag": "tools", "from": previous, "to": False, "at": _now_iso()}]
    return _rewrite(review_root, manifest)


def record_posture_disclosure(review_root, manifest, digest, at=None):
    """Remember that this run's FULL posture block has now been printed (#1596).

    Not an anti-drift key and never read as one: it records what an operator
    has been TOLD, so the worst a lost or corrupted value can do is print the
    block again. Written only on the invocations that print it in full -- the
    first, and any on which the disclosure actually changed -- so a resumable
    loop rewrites this file once per run rather than once per turn.
    """
    manifest[POSTURE_DISCLOSED] = {"digest": digest, "at": at or _now_iso()}
    return _rewrite(review_root, manifest)


def posture_disclosed_at(manifest, digest):
    """When this exact disclosure was last printed in full, or None.

    None is the fail-loud answer: no stamp, an unreadable one, or one for a
    DIFFERENT disclosure all mean "say the whole thing", which is the
    behaviour spec 5.1 had before #1596 collapsed the repeats.
    """
    stamp = (manifest or {}).get(POSTURE_DISCLOSED)
    if not isinstance(stamp, dict) or stamp.get("digest") != digest:
        return None
    at = stamp.get("at")
    return at if isinstance(at, str) and at else None


def tools_downgraded_mid_run(manifest):
    """Did this run have its tool scan switched off after it started?

    Read off the manifest's own `flag_changes` record rather than inferred
    from `flags.tools` being False, which is equally true of a run that was
    `--no-tools` from its first invocation -- a different, weaker statement.
    """
    return any(isinstance(change, dict) and change.get("flag") == "tools"
               and change.get("to") is False
               for change in (manifest or {}).get("flag_changes") or [])


def reset_run(review_root):
    """Remove the manifest so a fresh `driver run` can start over. Returns True
    if a manifest was removed. The driver's --reset path also clears the derived
    artifacts; this only owns the manifest."""
    try:
        os.remove(manifest_path(review_root))
        return True
    except FileNotFoundError:
        # #1033: only "already absent" is a benign no-op -> False. A real removal
        # failure (PermissionError, IsADirectoryError, ...) must propagate: a
        # manifest that exists but can't be removed would otherwise report False
        # and wedge run()'s next write_manifest with an uncaught FileExistsError.
        return False
