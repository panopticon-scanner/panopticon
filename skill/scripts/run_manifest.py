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
# #1735: the no-follow artifact open. It lives in a leaf module rather than in
# `phases/runio`, where it was written, precisely so THIS module can reach it:
# `phases/*` imports `run_manifest`, and layout rule 3 keeps that arrow
# pointing one way.
from scripts import safe_write
# #2006: the target-facing git probe. A leaf module like `safe_write` above, so
# this import crosses no layout boundary.
from scripts import safe_git

MANIFEST_NAME = "run-manifest.json"
SETUP_MANIFEST_NAME = "setup-manifest.json"
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
    if not isinstance(manifest, dict) or not manifest:
        return None
    # Bound each untrusted part, leaving ordinary existing tags byte-identical.
    host = _slug(manifest.get("host"), "host")[:60]
    mode = _slug(manifest.get("security_mode"), "standard")[:60]
    scope_value = manifest.get("scope")
    scope_mode = scope_value.get("mode") if isinstance(scope_value, dict) else None
    scope = _slug(scope_mode, "repo")[:60]
    created = manifest.get("created")
    stamp_text = created[:10].replace("-", "") if isinstance(created, str) else ""
    stamp = _slug(stamp_text, "00000000")[:10]
    rid = _slug(manifest.get("run_id"), "")[:8] or "00000000"
    return f"{host}-{mode}-{scope}-{stamp}-{rid}"

# The flag keys whose drift across re-invocations must be refused (anti-drift).
_FLAG_KEYS = ("fail_on", "severity", "gate_scope", "diff_context", "tools",
              "include_fixtures", "max_per_group", "allow_unenforced",
              "max_verify", "online")


def manifest_path(review_root, namespace=None):
    """The parameter record for a review run or the independent setup flow."""
    if namespace not in (None, "setup"):
        raise ValueError("unknown manifest namespace: %r" % namespace)
    name = SETUP_MANIFEST_NAME if namespace == "setup" else MANIFEST_NAME
    return os.path.join(review_root, ".panopticon", name)


def new_run_id():
    return uuid.uuid4().hex


def _target_provenance(target, runner=subprocess.run, suppressed=None):
    """(commit, dirty) for the tree being scanned, or (None, None) if not git.

    `suppressed` (#2013) is the probe's disclosure list, appended to in place:
    one `(repository, key)` pair per repository-configured Git driver the probe
    emptied for this scan. This is the DISCLOSURE OF RECORD -- the manifest
    carries it, and one stderr line names the keys (never their values, which
    are command lines the target authored) and what emptying them COSTS: paths
    under a suppressed driver compare as modified, so dirtiness for them is
    unknown and a delta may include them. `target_dirty` on such a target is
    therefore an upper bound, not a fact about what anybody edited.

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
    drivers = [] if suppressed is None else suppressed
    commit, dirty = _provenance_probes(target, runner, drivers)
    if drivers:
        # Keys only, and `%r` per key for the same reason the refusal used it:
        # a config subsection is repository-authored and may carry control
        # bytes. One line, printed whatever the probes concluded.
        print("run manifest: target Git drivers SUPPRESSED for this scan: %s "
              "-- paths under a suppressed driver compare as modified: "
              "dirtiness for them is unknown and a delta may include them"
              % ", ".join(sorted({repr(key) for _repo, key in drivers})),
              file=sys.stderr, flush=True)
    return commit, dirty


def _provenance_probes(target, runner, suppressed):
    """The two probes behind `_target_provenance`, without its disclosure."""
    # #2006: `target` is the reviewed tree, so both calls go through
    # `safe_git.probe` -- a trusted git resolved outside the target's outermost
    # checkout, a fresh allowlisted environment (these two ran with NO `env=`
    # at all, so an inherited `GIT_DIR`/`GIT_CONFIG_*` could redirect the very
    # provenance this records), `core.fsmonitor=false`, and a config preflight
    # that EMPTIES a `filter.*.clean` rather than running it (#2013).
    try:
        head = safe_git.probe(target, ["rev-parse", "HEAD"], runner=runner)
        if head.returncode != 0:
            return None, None
        commit = head.stdout.strip() or None
    except (subprocess.SubprocessError, OSError):
        return None, None
    try:
        # `-z`, the preflighted spelling: one probe for this and for validate's
        # baseline, rather than a second unpreflighted `--porcelain` shape.
        # The collecting call: `rev-parse` is allowlisted plumbing and reads no
        # config, so this is the only one of the two that can suppress anything.
        status = safe_git.probe(target, ["status", "--porcelain", "-z"], runner=runner,
                                suppressed=suppressed)
        if status.returncode != 0:
            return commit, None
        # NUL-framed, like `_worktree_dirty` (#1989): any non-empty record is
        # dirt. Dirtiness is recorded, never enforced, so a REFUSED status
        # leaves it unknown (None) and keeps the commit we did establish --
        # a fact obtained by running the target's own command would be worse
        # than no fact at all.
        return commit, any(record.strip() for record in status.stdout.split("\0"))
    except safe_git.RepositoryRefused as exc:
        # #2006 fix round 1: provenance is RECORDED, never enforced, so a
        # refused tree must not abort the run -- but it must not be silent
        # either. Same shape validate and discovery print, naming the setting.
        # After #2013 a driver command no longer reaches here: what does is a
        # target whose shape cannot be bounded, or whose override could not be
        # proved effective.
        print("run manifest: target Git probe REFUSED (%s); the reviewed tree's "
              "own Git configuration is not trusted to run, so this run's "
              "dirtiness is recorded as unknown" % exc, file=sys.stderr, flush=True)
        return commit, None
    except (subprocess.SubprocessError, OSError):
        return commit, None


def build_manifest(*, target, review_root, host, security_mode, base=None,
                   flags=None, config=None, run_id=None, worktree=None,
                   scope=None, pr=None, pr_base=None, created=None):
    # The WRITE path: this host came from CLI args, so a host the registry does
    # not know is a programming error and raising is both correct and the only
    # place it is reachable from (#1344).
    validate_host(host)
    flags = flags or {}
    _suppressed: list = []
    _commit, _dirty = _target_provenance(os.path.abspath(target), suppressed=_suppressed)
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
        # #1681 Plan 2: what the TARGET's committed config asked for and what
        # the trust classes let through, recorded beside the flags they fed.
        # Duck-typed off `config_schema.Settings` so this module keeps its
        # dependency-free shape; `{}`/`[]` when no config was resolved.
        # NOT anti-drift keys -- `_FLAG_KEYS` is the anti-drift surface and
        # compares EFFECTIVE values, which is what `flags` already holds.
        "config_requested": dict(getattr(config, "requested", None) or {}),
        "config_effective": dict(getattr(config, "effective", None) or {}),
        "config_refused": [dict(r) for r in (getattr(config, "refused", None) or [])],
        "config_clamped": [dict(c) for c in (getattr(config, "clamped", None) or [])],
        "config_disclosures": [str(s) for s in
                               (getattr(config, "disclosures", None) or [])],
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
        # #2013: which of the TARGET's own Git driver commands this scan ran
        # with emptied -- `[{"repo": ".", "key": "filter.lfs.clean"}, ...]`,
        # `[]` when there were none. Always present, because the absence of a
        # suppression has to mean "measured and did not happen", not "this run
        # had no opinion". The values are not here, and never leave the
        # target's own config.
        #
        # Recorded, never enforced HERE -- but not inert: paths under a
        # suppressed driver compare as modified, so `target_dirty` above is an
        # upper bound on such a target, and a DELTA-scoped run over that
        # comparison cannot certify its coverage (the caveat is raised at
        # synthesis, in `synth/tool_axis.reconcile`).
        "git_drivers_suppressed": [{"repo": repo, "key": key}
                                   for repo, key in _suppressed],
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
    if data.get("host") is not None and (
            not isinstance(data["host"], str) or hosts.spec(data["host"]) is None):
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

# #1727: {"checkpoint": <runio.CHECKPOINT_KINDS member>, "sha256": <hex>,
# "at": <iso>} -- the integrity anchor for the dispatch request this run last
# wrote. Spelled once here because the SETUP namespace keeps the same key in
# its own `setup-manifest.json` (phases/setup.record_dispatch_request) and two
# spellings of one key is how a reader silently stops finding it.
DISPATCH_REQUEST = "dispatch_request"

# SEC-377944137 (#1832): {"sha256": <canonical plan hash>, "at": <iso>} -- the
# durable record that this run WROTE `dispatch-plan-driver.json`, and
# {"cells": <n>, "at": <iso>} for `out-file-hashes.json`. Each artifact carries
# its OWN stamp: one shared stamp would make the snapshot's legitimate first
# take at synthesize (the #5.0-16 fallback for a vacuously-done verify phase)
# read as a deletion.
#
# These replaced an inference off DISPATCH_REQUEST above, which cannot answer
# the question: that slot is ROLLING (overwritten per checkpoint), so the last
# recorded kind on any run that verified anything is `verify`, and -- worse --
# the tamper itself can roll it BACKWARD. Deleting `coverage-<group>.json`
# makes `coverage_done` False, the coverage phase re-dispatches scout, and the
# slot goes back to `scout` on a run that had dispatched every review cell.
# These keys are written by the WRITER of each artifact and are MONOTONE: once
# stamped, never re-stamped, so nothing a later phase does can un-owe them.
DRIVER_PLAN = "driver_plan"
OUT_FILE_SNAPSHOT = "out_file_snapshot"
ARTIFACT_STAMPS = (DRIVER_PLAN, OUT_FILE_SNAPSHOT)

# #1912: [{"batch": <n>, "at": <iso>}, ...] -- the batch records this run's
# operator accepted the loss of with `--discard-batch`. The count is the fact
# worth surfacing (a run that threw one record away is not the run its report
# describes, the way an `--allow-unenforced` one is not), and the list carries
# it without flattening two acceptances into one.
DISCARDED_BATCHES = "discarded_batches"


def _rewrite(review_root, manifest, *, namespace=None):
    """Write the manifest back through a temp file + `os.replace`.

    The manifest is otherwise write-once, and stays so for every anti-drift
    key -- the two callers below are the deliberate exceptions and each says
    why. Atomic because this is the one artifact that anchors the run tag: an
    interrupt mid-write would leave every `_pano` path unresolvable. The
    ephemeral keys are stripped here, once, rather than at each caller.

    #1735 (SEC-D1C): the STAGING file is as exposed as the artifact. `.panopticon/`
    is inside the reviewed tree and `run-manifest.json.tmp` is a fixed name, so a
    redteam target can commit it as a symlink to any file the invoking user can
    write; the plain `open(tmp, "w")` this used followed the link, replaced that
    file's contents with the manifest JSON, and then `os.replace` renamed the LINK
    over `run-manifest.json` (rename does not dereference), so every later
    `load_manifest` read through it. `write_manifest` escaped only because mode "x"
    is O_EXCL. The staging write now goes through the same no-follow open every
    other `.panopticon` writer uses, and refuses LOUDLY rather than writing
    somewhere else -- the two fixes this class already had (#1577, and the guard
    hooks' own `_atomic_write_json`) fail the same way.
    """
    body = {k: v for k, v in manifest.items() if k not in _EPHEMERAL_KEYS}
    path = manifest_path(review_root, namespace)
    tmp = path + ".tmp"
    with safe_write.open_w_nofollow(tmp) as fh:
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


def record_posture_disclosure(review_root, manifest, digest, at=None, *, namespace=None):
    """Remember that this run's FULL posture block has now been printed (#1596).

    Not an anti-drift key and never read as one: it records what an operator
    has been TOLD, so the worst a lost or corrupted value can do is print the
    block again. Written only on the invocations that print it in full -- the
    first, and any on which the disclosure actually changed -- so a resumable
    loop rewrites this file once per run rather than once per turn.
    """
    manifest[POSTURE_DISCLOSED] = {"digest": digest, "at": at or _now_iso()}
    return _rewrite(review_root, manifest, namespace=namespace)


def record_dispatch_request(review_root, manifest, checkpoint, sha256, at=None):
    """Record the sha256 of the dispatch request the driver JUST wrote (#1727).

    The THIRD deliberate rewrite, and -- like the two above -- not an
    anti-drift key. `.panopticon/dispatch-request.json` lives inside the
    REVIEWED tree, so every field on it is a value a target can choose; the
    hash of the bytes the driver wrote is anchored here, and
    `phases/requests.load_bound_request` refuses a file that no longer
    matches. It records what this driver itself wrote, is overwritten on every
    write (the request is rolling -- regenerated each iteration), and a lost
    or stale value fails CLOSED: the readers refuse rather than trust.

    This file is inside the reviewed tree too -- the claim is NOT that it is
    out of reach. It is the better-defended of the two: on a host whose write
    guard mediates `Write`, no dispatched agent may write it (the write guard's allowlist is the entries' out_files) and
    `runio._foreign_manifest` discards a manifest that is git-tracked in the
    tree or stamped for another checkout, while the request is rewritten by
    the driver every iteration and read by every family. Forging the record
    as well is a second, harder write -- and one the loop's in-memory
    `request_sha256` cross-check still catches.

    `manifest` may be None, in which case the on-disk one is loaded. A tree
    with no manifest at all records nothing and does not raise: the
    pre-manifest window is real (unit callers, and `--setup`, which anchors in
    its own manifest via `phases/setup.record_dispatch_request`), and the
    reader's "no recorded hash" refusal is the fail-closed answer for it.
    """
    if manifest is None:
        manifest = load_manifest(review_root)
    if manifest is None:
        return None
    manifest[DISPATCH_REQUEST] = {"checkpoint": checkpoint, "sha256": sha256,
                                  "at": at or _now_iso()}
    return _rewrite(review_root, manifest)


def record_discarded_batch(review_root, manifest, number, at=None, *, namespace=None):
    """Record that this run discarded batch `number` on the operator's word (#1912).

    The FOURTH deliberate rewrite, and not an anti-drift key either: a resume
    may not un-discard a record, and the value is read by nobody -- it is the
    run's own account of a batch of paid cells that was thrown away because the
    loop could not tell whether its owner was alive. Appended, never replaced:
    a long run may have to do this more than once.

    `manifest` may be None (the on-disk one is loaded) and a tree with no
    manifest records nothing rather than raising, exactly as
    `record_dispatch_request` does -- the acceptance is also written in the run
    folder beside the record it applied to (`runners/batch.record_discard`),
    which is where the detail lives; this is the count, where a reader of the
    run's parameters will look for it.

    The read-back is TYPE-CHECKED before it is appended to (review round 1,
    finding 7). This manifest lives inside the reviewed tree, so the key is a
    value a target can choose: `list(...)` over a planted string yields one
    entry per character, over a dict one per key, and over an int raises
    TypeError out of a recorder that must not be able to fail the run. A value
    that is not a list is treated as absent -- it was never this driver's, so
    it was never the count of anything.
    """
    # `load_manifest` reads the REVIEW manifest and has no namespace of its
    # own, so only the review namespace may fall back to it: loading it for
    # `--setup` would rewrite setup's manifest out of the wrong document.
    if manifest is None and namespace is None:
        manifest = load_manifest(review_root)
    if manifest is None:
        return None
    existing = manifest.get(DISCARDED_BATCHES)
    manifest[DISCARDED_BATCHES] = (existing if isinstance(existing, list) else []) + [
        {"batch": int(number), "at": at or _now_iso()}]
    return _rewrite(review_root, manifest, namespace=namespace)


def record_artifact_stamp(review_root, manifest, key, at=None, **fields):
    """Record that this run WROTE the owed-once artifact `key` (SEC-377944137).

    The FIFTH deliberate rewrite, and the only MONOTONE one: an existing stamp
    is never replaced. `dispatch-plan-driver.json` and `out-file-hashes.json`
    are each written once and are one-way by design -- re-hashing the snapshot
    after a substitution would mask it -- so a second stamp could only ever be
    a laundering of the first.

    Not an anti-drift key: it records what this driver DID, not what the
    operator asked for, and `conflicting_flags` never reads it -- so nothing
    notices a stamp that VANISHES, which on a host whose write guard does not
    mediate `Write` (`--host generic --allow-unenforced`) is one unmediated
    write away. Better-defended than the artifact it anchors, not out of reach:
    the same qualification #1727's `record_dispatch_request` makes above.

    A tree with no manifest on disk records NOTHING and does not raise. The
    pre-manifest window is real (unit callers, and `--setup`, which keeps its
    own manifest), and a recorder that CREATED one here would be worse than
    useless: `runio._run_tag` derives the per-run folder from `created`, so
    conjuring a manifest mid-run would move every `_pano` path under a run
    folder the artifacts already written are not in.

    `fields` is the stamp's evidence -- `sha256=` for the plan (the canonical
    `synth.integrity._plan_hash` of the entries, so a REPLACED plan is caught
    as well as a deleted one) and `cells=` for the snapshot.
    """
    if key not in ARTIFACT_STAMPS:
        raise ValueError("unknown run artifact: %r" % key)
    if manifest is None:
        manifest = load_manifest(review_root)
    if manifest is None or not os.path.isfile(manifest_path(review_root)):
        return None
    if artifact_stamp(manifest, key):
        return manifest                  # monotone -- see above
    manifest[key] = dict(fields, at=at or _now_iso())
    return _rewrite(review_root, manifest)


def artifact_stamp(manifest, key):
    """This run's stamp for `key`, or None when it never wrote that artifact.

    TYPE-CHECKED at the boundary: the manifest lives inside the reviewed tree,
    so the key is a value a target can choose. A non-dict (or an empty one) was
    never this driver's stamp, so it reads as absent -- the same benign "this
    run owes nothing" a run that never wrote the artifact gets, which is the
    property every other key in `meta.integrity` has.
    """
    stamp = (manifest or {}).get(key)
    return stamp if isinstance(stamp, dict) and stamp else None


def claim_artifact(review_root, manifest, key, path, write, **fields):
    """Write the owed-once artifact `path` under its claim (SEC-377944137, #1832).

    Returns whatever `write` returned once the artifact is on disk, and None
    without calling it at all when this run already wrote `path` and it is GONE
    -- the caller must then REPORT that absence rather than repair it.

    Re-creating is how the guards built on these two artifacts were erased.
    `synthesize_execute` opens by calling both writers, so after a findings
    substitution + one `rm` the snapshot was re-taken OVER THE SUBSTITUTED BYTES
    -- the tampered file became its own baseline, `content_mismatched_files`
    went empty and #1208's owed-but-absent reading never fired -- and the plan
    was re-created, so its deletion left no trace either. Absence is evidence.

    The WRITE happens here, rather than in the caller after a yes/no answer,
    because the stamp must follow it and nothing may let a caller get that
    order wrong (fix round 2, NEW-1). Stamped first, a write that never landed
    -- `OSError` on a full disk or a read-only mount, a SIGKILL, the #1575
    process-group kill, or a snapshot that simply produced no file -- left the
    manifest saying "this run wrote it" with no file, and every later pass then
    refused to write it: an honest run reported deleted evidence for ever, and
    for the snapshot that window opens only after every review cell has been
    paid for. The stamp therefore follows the FILE (`os.path.exists`), not the
    call. A crash in the other direction -- written, not yet stamped -- leaves
    the artifact present and un-owed, which is a re-creatable fail-OPEN rather
    than a wedge, and is unreachable by a dispatched agent: both writes happen
    inside a driver pass, with no reviewer live.

    The refusal is announced on the DRIVER's stderr, which an operator actually
    sees (the synthesize child's streams are captured by `child._run_child`),
    and names `--reset`: a run folder cleared on purpose is a NEW run, not a
    repair of this one.
    """
    # Loaded when the caller has none: `artifact_stamp(None, ...)` is falsy, so
    # skipping this would make the guard fail OPEN for a caller that passes None.
    if manifest is None:
        manifest = load_manifest(review_root)
    if artifact_stamp(manifest, key) and not os.path.exists(path):
        print("driver: this run wrote %s and it is GONE -- reporting the absence, "
              "NOT re-creating it (SEC-377944137): a re-created artifact would "
              "erase the evidence it exists to carry. This run will report "
              "uncertified integrity; use --reset to start a fresh one."
              % os.path.basename(path), file=sys.stderr, flush=True)
        return None
    written = write()
    if os.path.exists(path):
        record_artifact_stamp(review_root, manifest, key, **fields)
    return written


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
