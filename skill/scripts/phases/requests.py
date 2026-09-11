"""Dispatch requests: prompt materialization, dispatch-request.json, the driver plan."""
import json
import os
import re
import sys

import scripts.dispatch as dispatch
import scripts.group_runner as group_runner
import scripts.synth.integrity as integrity_mod
import scripts.synth.plan as plan_mod
from scripts import hosts
from scripts import model_resolver
from . import runio
from . import coverage


_PROMPT_FILE_SAFE = re.compile(r"[^A-Za-z0-9._-]")

def bound_model(host, role):
    """The model this entry REQUESTS, as a string, from the one resolver.

    #1344 F4 (b). Every builder used to write the literal `"model": None`, which
    docs/PANOPTICON.md defines as "inherit the session's model" -- so the
    session's model, not the role's policy, was what an UNENFORCED dispatch
    ran on, and the registry's `model_binding` capability had nothing on the
    entry to be a claim about. `resolve_model` honours PANOPTICON_MODEL_*
    overrides; the registered shell (registration_model) does not, and that
    gap is exactly what host_probes.probe_entry_model_bound measures.

    The string, not the whole config dict: a family that needs more than a
    model id on the entry (kimi's tier aliases and context sizes) adds it in
    its own PR. A host with no model policy resolves to None -- gemini and
    generic today -- which is the value they already dispatch with.
    """
    return model_resolver.resolve_model(host, role).get("model")


# #1344 F4 (a). The ONE wording for the return-persist instruction. Two builders
# prepend it; neither may compose its own (the host_disclosure lesson: two
# copies of one rule drift, and each surface's own test keeps passing).
# It is PREPENDED by the builder, exactly as _verify_entry prepends the #975
# repo-root pin -- spec 7.4 forbids editing the templates, and this edits none.
RETURN_PERSIST_PREAMBLE = (
    "DELIVERY: return-persist. This host has not proven it can confine your "
    "Write to %(out_file)s, so do NOT write that file. Produce exactly the JSON "
    "object the Output section below describes and return it as your final "
    "message; the controller persists it to that path after confirming it "
    "parses.\n\n")


def delivery(host, evidence, role_file, out_file):
    """(mode, prefix): how this entry's output reaches its out_file.

    `mode` is "return_json" -- the HOST persists what the agent returns -- or
    None, meaning the agent self-writes under the write guard. `prefix` is the
    preamble to prepend to the prompt, or "".

    Three cases, derived rather than declared per builder:
      * the role's template grants no Write (advisor.md): return_json, no
        preamble -- the template already says "return", nothing to override;
      * the template grants Write and the host has PROVEN artifact_write_guard:
        self-write, exactly as today;
      * the template grants Write and the guard is NOT proven (refuted or
        unknown -- gemini, generic, or a claude run that took
        --allow-unenforced): return_json WITH the preamble, because the
        template's own instruction says "Write your findings to {out_file}" and
        an agent that obeys it self-writes unguarded while the controller waits
        for JSON that never comes.

    This does NOT bypass require_unenforced_ack (spec 10). The shell still
    grants Write, so an agent asked to return may still write; the gate is
    the operator's acceptance of that, and it stays.
    """
    allowed = dispatch.load_template(role_file)[0]["tool_policy"].get("allowed") or []
    if "Write" not in allowed:
        return "return_json", ""
    if hosts.posture(host, evidence)[hosts.ARTIFACT_WRITE_GUARD] == hosts.PROVEN:
        return None, ""
    return "return_json", RETURN_PERSIST_PREAMBLE % {"out_file": out_file}


def _prompts_dir(namespace=None):
    """`_prompts/` for a run, `<namespace>-prompts/` otherwise (#1507)."""
    return "_prompts" if not namespace else "%s-prompts" % namespace


def _prompt_file_path(review_root, entry_id, namespace=None):
    """Where one entry's prompt is materialized: `_prompts/<entry-id>.txt`.

    The id is sanitized to a single flat filename -- an entry id embeds a group
    name, which is operator-supplied, so a `/` or `..` in it must not steer the
    write out of the prompts directory."""
    safe = _PROMPT_FILE_SAFE.sub("_", str(entry_id)) or "entry"
    return runio._pano(review_root, _prompts_dir(namespace), "%s.txt" % safe)

def _materialize_prompts(review_root, entries, namespace=None):
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
            path = _prompt_file_path(review_root, eid, namespace)
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

def request_path(review_root, namespace=None):
    """The dispatch-request path for a run, or for a namespace like `setup`.

    #1507: a run's request is per-run (`runs/<tag>/dispatch-request.json`), but
    SETUP is not a run -- routing it through the per-run resolver put it in
    whatever `runs/latest` happened to point at and clobbered that run's own
    request. A namespace keeps setup's request beside its other artifacts."""
    if namespace:
        return runio._pano(review_root, "%s-dispatch-request.json" % namespace)
    return runio._pano(review_root, "dispatch-request.json")


def write_dispatch_request(review_root, run_id, checkpoint, group, entries,
                           namespace=None):
    """Write the single per-(group, checkpoint) dispatch-request.json and return
    its ABSOLUTE path. Host-agnostic: entries carry only neutral fields and any
    paths inside them must already be absolute (spec §4). The request is rolling
    — the durable state is the entries' out_files, not this file.

    Each entry also gets a `prompt_file` (#run10 B2) — the same text, addressable
    — so a host can hand an agent a path instead of echoing the whole prompt."""
    if checkpoint not in runio.CHECKPOINT_KINDS:
        raise ValueError("unknown checkpoint kind: %r" % checkpoint)
    entries = _materialize_prompts(review_root, entries, namespace)
    request = {"schema_version": 1, "run_id": run_id, "checkpoint": checkpoint,
               "group": group, "entries": list(entries)}
    path = request_path(review_root, namespace)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with runio._open_w_nofollow(path) as fh:
        json.dump(request, fh, indent=2)
    return os.path.abspath(path)

def load_dispatch_request(review_root, namespace=None):
    """The parsed .panopticon/dispatch-request.json (or None if absent/invalid).
    The host reads req['entries'] to install the write-guard
    (write_guard_hook.install(entries)) and to dispatch the checkpoint's cells."""
    return runio._load_json(request_path(review_root, namespace))

def _driver_plan_entries(review_root, manifest):
    """The declared review cells as a matrix domain-cell dispatch plan
    (#5.0-16). Computed DETERMINISTICALLY from groups.json (each discovered
    group) x its effective domains -- the SAME two sources review_execute
    dispatches from (_discovered_groups x _effective_domains) -- with the EXACT
    out_file spelling _cell_entry uses, so synth.integrity.reconcile_findings_files
    sees no missing/unexpected on a clean run. `enforced` mirrors _cell_entry so
    plan_mod.derive_tool_policy_mode reports the run's real posture rather than
    defaulting to "advisory". No `files`/`role`/`model` -- this is a
    declaration of which out_files must exist, not a scope grant or a cost row;
    the dispatch entries carry scope (F4) and this deliberately does not."""
    enforced = (hosts.posture(manifest.get("host", "claude"),
                              runio.host_evidence(review_root))
                [hosts.TOOL_POLICY_ENFORCED] == hosts.PROVEN)
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


# Refreshed on every invocation rather than written once: these describe what
# the CURRENT probe found, not what the operator agreed to. See the merge below.
_ACK_DISCLOSURE = (hosts.TOOL_POLICY_ENFORCED, "tool_policy_detail")


def require_unenforced_ack(review_root, manifest, entries):
    """Refuse to dispatch write-capable reviewers on a host that cannot mediate
    Write, unless the operator accepted the risk explicitly (#1519, AGT-B1A).

    The gate reads one capability: the host's ARTIFACT_WRITE_GUARD -- can its
    hook mediate a reviewer's `Write` and confine it to the declared out_file?
    That is a NARROWER question than whether the host enforces a reviewer tool
    policy at all (TOOL_POLICY_ENFORCED), and it is the only one that matters
    here: the write-guard is a Claude Code PreToolUse hook, so a host can
    enforce a registered shell's tool list perfectly well and still have
    nothing standing between a domain-panel `Write` and the filesystem. The
    two questions were extensionally identical over today's hosts, which is
    exactly why the distinction has to be written down.

    On a host that does not declare it -- `--host generic` and `--host gemini`,
    both first-class CLI values -- a domain-panel or domain-advisor `Write` has
    NO mediation whatsoever: no hook, nothing but the advisory prose
    `_tool_policy_line` appends. And a write that lands OUTSIDE review_root is
    invisible to every integrity check here, because validate's clean-tree diff
    is scoped to review_root.

    dispatch.py used to refuse exactly this by default, with --allow-unenforced
    as the explicit, recorded opt-in. That flag and its ack writer were retired
    in run-10 while write_guard_hook.py's docstring went on citing them as the
    compensating control -- so the residual risk has been taken silently and
    unconditionally ever since. The READER survived intact
    (synth.integrity.read_unenforced_ack, including its #493 plan-hash
    staleness binding); this restores its writer and the refusal.

    Interim, per the approved 5.2 strategy: real per-host write mediation is
    #1344. This makes the unenforced path loud again, not safe.

    I4, and it is a DISCLOSURE rather than a second gate: §7.3 promises that
    `--allow-unenforced` "papers over nothing ... and the ack file records the
    shadowing paths". It did not. This function returned at its first line
    whenever ARTIFACT_WRITE_GUARD is PROVEN -- the normal Claude case -- so an
    operator who overrode a §7.3 refusal on a shadowed target left NOTHING
    durable behind saying so. Now, when the flag is set and
    TOOL_POLICY_ENFORCED is REFUTED, the ack is written (or extended) with the
    refuting detail.

    It must NEVER become a refusal on TOOL_POLICY_ENFORCED. That capability is
    REFUTED on every machine that has not run `driver setup` -- there is no
    registration directory to find shells in -- so raising on it would refuse
    ordinary runs everywhere. Adding disclosure is in scope; adding a gate is
    not. `test_an_unregistered_machine_without_the_flag_still_runs` pins that.

    Returns the ack path when one was written, else None.
    """
    evidence = runio.host_evidence(review_root)
    posture = hosts.posture(manifest.get("host", "claude"), evidence)
    allow = bool((manifest.get("flags") or {}).get("allow_unenforced"))
    # An explicit override of a §7.3 refusal. `entries` is required for the
    # same reason the write-guard branch requires it: with no cell declared no
    # reviewer runs, so there is nothing to disclose and no plan to bind to.
    overrode_tool_policy = bool(
        allow and entries
        and posture[hosts.TOOL_POLICY_ENFORCED] == hosts.REFUTED)
    if posture[hosts.ARTIFACT_WRITE_GUARD] == hosts.PROVEN:
        # The hook mediates Write for this host -- no write-guard risk to
        # accept. The §7.3 override, if there was one, still gets recorded.
        if not overrode_tool_policy:
            return None
        return _record_unenforced_ack(review_root, manifest, entries, evidence,
                                      posture, guard_mediates=True)
    if not entries:
        return None                    # no cells declared: no risk to accept
    if not allow:
        # declares(), NOT posture(): this asks which hosts CLAIM the guard, to
        # build the "or use one of: --host claude" hint. We have no evidence
        # for a host we are not running, so posture() would answer unknown for
        # all of them and the hint would go empty.
        guarded = [name for name in hosts.driver_hosts()
                   if hosts.declares(name, hosts.ARTIFACT_WRITE_GUARD)]
        row = evidence.get(hosts.ARTIFACT_WRITE_GUARD) or {}
        raise runio.DriverError(
            "%s is %s on host %r -- probe %s: %s. %s are granted Write, and "
            "nothing would confine that Write to the declared out_file; a "
            "write outside the reviewed tree is invisible to the clean-tree "
            "check too. Re-run with --allow-unenforced to accept that "
            "explicitly (it is recorded in %s), or use one of: %s."
            % (hosts.ARTIFACT_WRITE_GUARD, posture[hosts.ARTIFACT_WRITE_GUARD],
               manifest.get("host"), row.get("by") or "none ran",
               row.get("detail") or "no evidence",
               ", ".join(sorted(write_capable_roles())), UNENFORCED_ACK,
               ", ".join("--host " + n for n in guarded)))
    return _record_unenforced_ack(review_root, manifest, entries, evidence,
                                  posture, guard_mediates=False)


def _record_unenforced_ack(review_root, manifest, entries, evidence, posture,
                           guard_mediates):
    """Write the ack, or ADD to one that is already there. Never overwrite.

    Additive by construction: a key the stored ack already carries is left
    exactly as written -- the #493 R2 `plan_sha256` binding above all, which
    must keep naming the plan that was actually acknowledged. Only disclosures
    the earlier write did not carry are added, which is what makes this safe
    to call on a resume that has learned something new (a shadow file planted
    mid-run) without invalidating the ack's binding to this run.
    """
    body = {
        "acknowledged": True,
        "host": manifest.get("host"),
        # Binds the ack to THIS run's plan (#493 R2): a stale ack from an
        # earlier run must not mark a later run acknowledged.
        "plan_sha256": integrity_mod._plan_hash(entries),
        "roles": sorted(write_capable_roles()),
        "write_guard_covers_bash": False,
        "note": ("Tool policy enforcement is REFUTED for this run and the "
                 "operator overrode the spec 7.3 refusal with "
                 "--allow-unenforced. The host's write guard DOES mediate "
                 "reviewer Write; the refuting detail is recorded below."
                 if guard_mediates else
                 "Reviewer Write is unmediated on this host: no registered "
                 "shell, no PreToolUse hook. The operator accepted this with "
                 "--allow-unenforced."),
        hosts.TOOL_POLICY_ENFORCED: posture[hosts.TOOL_POLICY_ENFORCED],
    }
    if posture[hosts.TOOL_POLICY_ENFORCED] == hosts.REFUTED:
        # §7.3's "the ack file records the shadowing paths". The detail is the
        # probe's own sentence, which names every scope-directory hit.
        body["tool_policy_detail"] = (
            (evidence.get(hosts.TOOL_POLICY_ENFORCED) or {}).get("detail")
            or "refuted, but the artifact recorded no detail")
    path = runio._pano(review_root, UNENFORCED_ACK)
    stored = runio._load_json(path)
    if isinstance(stored, dict):
        merged = dict(stored)
        # Never-overwrite protects the BINDING -- plan_sha256 above all, whose
        # whole job (#493 R2) is to stay as the earlier invocation wrote it so a
        # changed plan reads as stale. It must not also freeze the DISCLOSURE.
        # A second shadowing file appearing after the first ack leaves the state
        # alone (refuted -> refuted), so capabilities_of() sees no drift and the
        # run continues; if the detail were pinned to the first write, the ack
        # would name one path forever while the tree shipped several -- losing
        # the exact fact 7.3 requires it to record.
        merged.update({k: v for k, v in body.items() if k not in stored})
        merged.update({k: body[k] for k in _ACK_DISCLOSURE if k in body})
        if merged == stored:
            return path                # idempotent across resumes
        body = merged
    return runio._write_json(path, body)


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
