"""Dispatch requests: prompt materialization, dispatch-request.json, the driver plan."""
import json
import os
import re
import sys

import scripts.dispatch as dispatch
import scripts.group_runner as group_runner
import scripts.synth.integrity as integrity_mod
import scripts.synth.plan as plan_mod
from . import runio
from . import coverage


_PROMPT_FILE_SAFE = re.compile(r"[^A-Za-z0-9._-]")

def _prompt_file_path(review_root, entry_id):
    """Where one entry's prompt is materialized: `_prompts/<entry-id>.txt`.

    The id is sanitized to a single flat filename -- an entry id embeds a group
    name, which is operator-supplied, so a `/` or `..` in it must not steer the
    write out of the prompts directory."""
    safe = _PROMPT_FILE_SAFE.sub("_", str(entry_id)) or "entry"
    return runio._pano(review_root, "_prompts", "%s.txt" % safe)

def _materialize_prompts(review_root, entries):
    """Write each entry's prompt to its own file and stamp `prompt_file` on the
    entry (#run10 B2).

    A dispatch entry carried its prompt ONLY inline, averaging 13.3 KB for review
    cells and 19.6 KB for verify cells -- so a controller dispatching 120 review
    cells had to reproduce ~1.6 MB of prompt text it had just read from disk, into
    its own context. Run-10 worked around this by hand-materializing 4.22 MB of
    prompts and pointing each agent at its file; that worked, but every host has
    to reinvent it, and one that doesn't blows its context on the review
    checkpoint alone.

    `prompt` stays inline (unchanged contract, no host is forced to migrate);
    `prompt_file` is the addressable alternative. Best-effort: if the prompts
    directory cannot be written, entries keep their inline prompt and the run
    proceeds -- this is an ergonomic affordance, never a dispatch precondition."""
    out = []
    for entry in entries:
        entry = dict(entry)
        prompt = entry.get("prompt")
        eid = entry.get("id")
        if isinstance(prompt, str) and prompt and eid:
            path = _prompt_file_path(review_root, eid)
            try:
                runio._confine_artifact_path(path)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with runio._open_w_nofollow(path) as fh:
                    fh.write(prompt)
                entry["prompt_file"] = os.path.abspath(path)
            except (OSError, ValueError) as exc:
                print("driver: could not materialize prompt for %s (%s); the "
                      "inline prompt still stands" % (eid, exc),
                      file=sys.stderr, flush=True)
        out.append(entry)
    return out

def write_dispatch_request(review_root, run_id, checkpoint, group, entries):
    """Write the single per-(group, checkpoint) dispatch-request.json and return
    its ABSOLUTE path. Host-agnostic: entries carry only neutral fields and any
    paths inside them must already be absolute (spec §4). The request is rolling
    — the durable state is the entries' out_files, not this file.

    Each entry also gets a `prompt_file` (#run10 B2) — the same text, addressable
    — so a host can hand an agent a path instead of echoing the whole prompt."""
    if checkpoint not in runio.CHECKPOINT_KINDS:
        raise ValueError("unknown checkpoint kind: %r" % checkpoint)
    entries = _materialize_prompts(review_root, entries)
    request = {"schema_version": 1, "run_id": run_id, "checkpoint": checkpoint,
               "group": group, "entries": list(entries)}
    path = runio._pano(review_root, "dispatch-request.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with runio._open_w_nofollow(path) as fh:
        json.dump(request, fh, indent=2)
    return os.path.abspath(path)

def load_dispatch_request(review_root):
    """The parsed .panopticon/dispatch-request.json (or None if absent/invalid).
    The host reads req['entries'] to install the write-guard
    (write_guard_hook.install(entries)) and to dispatch the checkpoint's cells."""
    return runio._load_json(runio._pano(review_root, "dispatch-request.json"))

def _driver_plan_entries(review_root, manifest):
    """The declared review cells as a matrix domain-cell dispatch plan
    (#5.0-16). Computed DETERMINISTICALLY from groups.json (each discovered
    group) x its effective domains -- the SAME two sources review_execute
    dispatches from (_discovered_groups x _effective_domains) -- with the EXACT
    out_file spelling _cell_entry uses, so synth.integrity.reconcile_findings_files
    sees no missing/unexpected on a clean run. `enforced` mirrors _cell_entry so
    plan_mod.derive_tool_policy_mode reports the run's real posture rather than
    defaulting to "advisory". No `files`/`role` -- this is a declaration of
    which out_files must exist, not a scope grant or a cost row."""
    enforced = manifest.get("host", "claude") == "claude"
    entries = []
    for group, _files in coverage._discovered_groups(review_root):
        for domain in coverage._effective_domains(review_root, group):
            entries.append({
                "group": group, "domain": domain, "enforced": enforced,
                "out_file": os.path.abspath(
                    runio._pano(review_root, "findings-%s-%s.json" % (group, domain)))})
    return entries

def _write_driver_plan(review_root, manifest):
    """Write .panopticon/dispatch-plan-driver.json declaring every review cell
    (#5.0-16 H2), so synthesize's reconcile_findings_files (undeclared-file
    detection) is live on the driver path. Idempotent: written once, only when
    cells exist; a later call is a no-op if the file is already present (the
    cell set is fixed once coverage completes, which gates the review phase).
    An empty target (no cells) writes NO plan -- reconcile then stays a correct
    no-op rather than flagging an empty plan."""
    path = runio._pano(review_root, plan_mod.DRIVER_DISPATCH_PLAN)
    entries = _driver_plan_entries(review_root, manifest)
    if not entries:
        return None
    # Before any write-capable cell is dispatched, on EVERY pass -- a resume
    # dispatches cells too, so gating only the first write would let a run that
    # was refused come back without the flag and proceed (#1519).
    require_unenforced_ack(review_root, manifest, entries)
    if os.path.isfile(path):
        return path
    return runio._write_json(path, entries)

UNENFORCED_ACK = "unenforced-ack.json"


def write_capable_roles():
    """Roles whose SHIPPED TEMPLATE grants Write, read from the templates.

    Deliberately derived rather than listed: a role that gains Write must not
    be able to slip past the gate below by nobody remembering to add it to a
    hardcoded set (#1519)."""
    return [role for role, role_file in dispatch.ROLE_FILES.items()
            if "Write" in (dispatch.load_template(role_file)[0]
                           ["tool_policy"].get("allowed") or [])]


def require_unenforced_ack(review_root, manifest, entries):
    """Refuse to dispatch write-capable reviewers on a host that cannot mediate
    Write, unless the operator accepted the risk explicitly (#1519, AGT-B1A).

    `enforced` is `host == "claude"` throughout the driver, because the
    write-guard is a Claude Code PreToolUse hook and `dispatch.emit_host_agents`
    can only build a scoped shell for claude/kimi/codex. So on `--host generic`
    or `--host gemini` -- both first-class CLI values -- a domain-panel or
    domain-advisor `Write` has NO mediation whatsoever: no registered shell, no
    hook, nothing but the advisory prose `_tool_policy_line` appends. And a
    write that lands OUTSIDE review_root is invisible to every integrity check
    here, because validate's clean-tree diff is scoped to review_root.

    dispatch.py used to refuse exactly this by default, with --allow-unenforced
    as the explicit, recorded opt-in. That flag and its ack writer were retired
    in run-10 while write_guard_hook.py's docstring went on citing them as the
    compensating control -- so the residual risk has been taken silently and
    unconditionally ever since. The READER survived intact
    (synth.integrity.read_unenforced_ack, including its #493 plan-hash
    staleness binding); this restores its writer and the refusal.

    Interim, per the approved 5.2 strategy: real per-host write mediation is
    #1344. This makes the unenforced path loud again, not safe.

    Returns the ack path when one was written, else None.
    """
    if manifest.get("host", "claude") == "claude":
        return None                    # the hook mediates Write for this host
    if not entries:
        return None                    # no cells declared: no risk to accept
    if not (manifest.get("flags") or {}).get("allow_unenforced"):
        raise runio.DriverError(
            "host %r cannot enforce the reviewer tool policy: %s are granted "
            "Write, and on this host there is no registered agent shell and no "
            "PreToolUse hook to confine it to the declared out_file -- only "
            "prompt text. A write outside the reviewed tree would also be "
            "invisible to the clean-tree check. Re-run with --allow-unenforced "
            "to accept that explicitly (it is recorded in %s), or use "
            "--host claude."
            % (manifest.get("host"), ", ".join(sorted(write_capable_roles())),
               UNENFORCED_ACK))
    path = runio._pano(review_root, UNENFORCED_ACK)
    if os.path.isfile(path):
        return path                    # idempotent across resumes
    return runio._write_json(path, {
        "acknowledged": True,
        "host": manifest.get("host"),
        # Binds the ack to THIS run's plan (#493 R2): a stale ack from an
        # earlier run must not mark a later run acknowledged.
        "plan_sha256": integrity_mod._plan_hash(entries),
        "roles": sorted(write_capable_roles()),
        "write_guard_covers_bash": False,
        "note": "Reviewer Write is unmediated on this host: no registered "
                "shell, no PreToolUse hook. The operator accepted this with "
                "--allow-unenforced.",
    })


def _snapshot_review_out_files(review_root, manifest):
    """Snapshot a sha256 per declared review cell at the review->verify boundary
    (#5.0-16 H3), so synthesize's verify_out_file_hashes (content-substitution
    detection) is live on the driver path. Runs after review_done (every cell
    written) and before any verify-phase agent can touch a findings file, so a
    later substitution -- e.g. by a rogue advisor on the unenforced generic host
    -- is caught. Idempotent AND one-way: if the snapshot already exists it is
    NOT rewritten -- re-hashing after a substitution would mask it."""
    path = runio._pano(review_root, "out-file-hashes.json")
    if os.path.isfile(path):
        return path
    entries = _driver_plan_entries(review_root, manifest)
    if not entries:
        return None
    group_runner.snapshot_out_files(entries, out_path=os.path.abspath(path))
    return path if os.path.isfile(path) else None
