"""Dispatch requests: prompt materialization, dispatch-request.json, the driver plan."""
import hashlib
import json
import os
import re
import sys

import scripts.dispatch as dispatch
import scripts.group_runner as group_runner
# #1720: the loop re-derives `enforced` to CHECK the dispatch request against
# this run's evidence; this module derives it to WRITE that request. One
# function, so the two can never disagree about what the run's posture is.
import scripts.loop_batch as loop_batch
import scripts.run_manifest as run_manifest
import scripts.synth.integrity as integrity_mod
import scripts.synth.plan as plan_mod
from scripts import hosts
from scripts import model_resolver
from scripts import read_guard_hook
from . import coverage
# D10 ruling 2: the retry prompt carries the last refusal, and `persist` owns
# both the records and the run-folder resolver. A mutual pair like
# coverage<->requests: read by module attribute, at call time only.
from . import persist
from . import runio


_PROMPT_FILE_SAFE = re.compile(r"[^A-Za-z0-9._-]")
_SAFE_ENTRY_ID = re.compile(r"[A-Za-z0-9._-]{1,160}\Z")


def entry_file_component(entry_id):
    """A bounded, unambiguous filename component for an original entry ID.

    Safe existing names stay byte-for-byte stable. ``~`` cannot start a safe
    name, so hashed names cannot collide with them or with lossy old names.
    """
    original = str(entry_id)
    if _SAFE_ENTRY_ID.fullmatch(original):
        return original
    return "~" + hashlib.sha256(original.encode("utf-8")).hexdigest()

def bound_model(host, role):
    """The model this entry REQUESTS, as a string, from the one resolver.

    #1344 F4 (b). Every builder used to write the literal `"model": None`, which
    docs/PANOPTICON.md defines as "inherit the session's model" -- so the
    session's model, not the role's policy, was what an UNENFORCED dispatch
    ran on, and the registry's `model_binding` capability had nothing on the
    entry to be a claim about. `resolve_model` honours PANOPTICON_MODEL_*
    overrides; the registered shell (registration_model) does not, and that
    gap is exactly what probes.claude.probe_entry_model_bound measures.

    The string, not the whole config dict: a family that needs more than a
    model id on the entry (kimi's tier aliases and context sizes) adds it in
    its own PR. A host with no model policy resolves to None -- gemini and
    generic today -- which is the value they already dispatch with.
    """
    return model_resolver.resolve_model(host, role).get("model")


def entry_marker(entry_id):
    """Line 1 of EVERY dispatch entry's prompt, newline included (read-
    confinement design 4.4). Rendered here and prepended by each builder as
    the OUTERMOST wrap -- before the return-persist preamble and before the
    verify builders' `Repo root:` pin -- never by a template. The read guard
    reads it back from the subagent's transcript to bind the agent to this
    entry; `entry["marker"]` carries the same line for a host that dispatches
    from `prompt_file` (R-P5-1)."""
    return read_guard_hook.marker_line(entry_id) + "\n"


def scope(files=(), dirs=(), reads=(), hard_linked=None):
    """An entry's read scope: absolute, byte-exact paths the read guard
    matches after realpath. `files` duplicates entry["files"] on purpose (the
    guard reads one key of one shape); `dirs` is a directory scope (setup-
    scan); `reads` is the extra-file allowance -- whatever the builder grants
    beyond the entry's files (the SEC cell's security checklist,
    `review._cell_reads`), plus the entry's own `prompt_file` once
    `_materialize_prompts` stamps one, so a host that dispatches from the
    file (marker line first, pointer second) is not denied its own prompt by
    the read guard.

    `hard_linked` belongs to `dirs` (#1683): the multiply-linked files beneath
    the granted directory, found by `phases/hard_links` ONCE here because a
    PreToolUse hook may not walk the tree on every Grep. The hooks refuse a
    directory-argument Grep/Glob that would traverse one.

    A `dirs` grant must ANSWER for it: omitting the keyword raises, an empty
    list is the answer for a clean tree. That the one builder issuing such a
    grant calls the walker was a fact about today's code; this makes it a
    property of the shape (fix round 1), because a directory grant whose
    links nobody looked for is the hole #1683 is about."""
    if dirs and hard_linked is None:
        raise ValueError(
            "a directory grant must record its hard links: pass "
            "hard_linked=hard_links_under(...) (an empty list is the answer "
            "for a clean tree)")
    return {"files": list(files), "dirs": list(dirs), "reads": list(reads),
            "hard_linked": list(hard_linked or ())}


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
    safe = entry_file_component(entry_id)
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
    proceeds -- the ENGINE never makes it a dispatch precondition (a host may
    hand the agent `prompt` verbatim). The Claude session-mode template,
    `skill/workflows/dispatch.js`, does require it, because it deliberately
    never carries the inline prompt into the session's context."""
    out = []
    # D10 ruling 2: the ONE chokepoint both modes pass through, so a refusal
    # reaches the next attempt whoever dispatches it. Resolved once, and
    # best-effort: a run folder that cannot be resolved costs the retry note,
    # never the dispatch.
    try:
        run_folder = persist.run_dir(review_root, namespace)
    except (OSError, ValueError):
        run_folder = None
    # D10 F1: does THIS machine's CLI take a constrained-output schema? Read
    # from the run's own evidence artifact, once, and only `True` counts --
    # absent (nobody asked: session mode, a host whose row maps no usage
    # probe) and `False` (asked, not advertised) are the same answer, and it
    # is the answer that leaves a launch exactly as it was before ruling 3.
    # Fail-safe, because the alternative is fatal: a CLI that does not know
    # the flag exits non-zero on it, prints no envelope, and every entry of
    # every checkpoint burns its three launches.
    #
    # #1732: AND the shape. `advertised` is a read of the flag's NAME, from
    # `<cli> --help`; run 14's CLI advertised `--json-schema` and then refused
    # what the driver put after it (the schema's path, where it wants the
    # text), and every return_json entry of every checkpoint burned its three
    # launches -- 309 of them. `refuted` is the one verdict that takes the
    # flag back off; `proven`, `unmeasured` and an absent key all stamp
    # exactly as before, because a fact nobody could measure may not remove a
    # capability.
    fact = runio.host_cli_flags(review_root).get(hosts.OUTPUT_SCHEMA, {})
    advertised = (fact.get("advertised") is True
                  and fact.get(hosts.SHAPE) != hosts.SHAPE_REFUTED)
    for entry in entries:
        entry = dict(entry)
        # D10 ruling 3: the published schema this entry's reply is accepted
        # against, for a host CLI that can constrain its output to one. Neutral
        # like `delivery` and `prompt_file`: a family with no such flag ignores
        # it, and a role with no published schema carries no key at all.
        #
        # RETURN-PERSIST only, because that is what the schema describes: the
        # object the CONTROLLER will persist. A self-writing reviewer put its
        # findings in its own out_file under the write guard and returns a
        # one-line confirmation, so constraining its final message to the
        # findings envelope would demand back the very object the self-write
        # path exists to keep out of the loop.
        schema = (persist.role_schema(entry)
                  if advertised and entry.get("delivery") == "return_json" else None)
        if schema:
            entry["output_schema"] = schema
        prompt = entry.get("prompt")
        eid = entry.get("id")
        if isinstance(prompt, str) and prompt and eid:
            # BEFORE the file is written, so `prompt` and `prompt_file` agree:
            # a host that dispatches from either one hears about the refusal.
            block, prior = persist.retry_block(run_folder, entry)
            if block:
                prompt = entry["prompt"] = prompt + block
                entry["prior_rejection"] = prior
            path = _prompt_file_path(review_root, eid, namespace)
            try:
                runio._confine_artifact_path(path)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with runio._open_w_nofollow(path) as fh:
                    fh.write(prompt)
                entry["prompt_file"] = os.path.abspath(path)
                # The read guard confines a bound agent to its entry's scope,
                # so an agent pointed at `prompt_file` (the documented
                # alternative to echoing the prompt) must be allowed to read
                # it: grant the file through `reads`, the allowance the scope
                # shape reserved for exactly this. Copied, never mutated in
                # place -- the caller's scope dict is not ours -- and
                # idempotent across a re-stamp.
                scope = entry.get("scope")
                if isinstance(scope, dict):
                    reads = [r for r in (scope.get("reads") or []) if isinstance(r, str)]
                    if entry["prompt_file"] not in reads:
                        reads.append(entry["prompt_file"])
                    entry["scope"] = dict(scope, reads=reads)
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


def record_request_hash(review_root, checkpoint, sha256, namespace=None):
    """Anchor `sha256` in THIS namespace's manifest (#1727).

    The one place the two manifests are told apart. `--setup` keeps its own
    request and its own `setup-manifest.json` (#1507), and
    `run_manifest._rewrite` writes `run-manifest.json` unconditionally -- so
    routing setup's hash through the run manifest would stamp whatever review
    run's manifest happens to be on the tree.

    `phases/setup` is imported at CALL time, in the function, exactly as
    `orchestrate._run` imports it: `setup` imports this module at module
    level, and a second module-level cycle here would buy nothing that a
    one-line local import does not (layout rule 1 is satisfied either way --
    the name bound is the MODULE)."""
    if namespace == loop_batch.SETUP_NAMESPACE:
        import scripts.phases.setup as setup_mod
        return setup_mod.record_dispatch_request(review_root, checkpoint, sha256)
    return run_manifest.record_dispatch_request(review_root, None, checkpoint, sha256)


def write_dispatch_request_bound(review_root, run_id, checkpoint, group, entries,
                                 namespace=None):
    """`(absolute path, sha256)` for the request this writes (#1727).

    The hash is taken over the EXACT BYTES about to be written -- serialise,
    hash, write -- never by re-reading the file afterwards: a target that can
    swap the file can swap it between those two operations, and the driver
    would then record the attacker's hash as its own. It is recorded in this
    namespace's manifest, so that every reader can ask whether the file it is
    about to trust is the one this run wrote.

    The manifest is `.panopticon/run-manifest.json` (or `setup-manifest.json`)
    -- INSIDE the reviewed tree, like the request itself. It is not a safe
    place; it is a BETTER-DEFENDED one: the write guard's allowlist is the
    entries' out_files, so no dispatched agent may write it, and
    `runio._foreign_manifest` discards one that is git-tracked in the tree or
    stamped for another checkout. What the record buys is that forging the
    request now costs a second, harder write -- and the loop, which also holds
    `request_sha256` in memory off its own checkpoint status, catches even
    that pair.

    `write_dispatch_request` below is the same call for the callers that want
    only the path. Two names rather than a module-level stash of the last
    hash: a global would be one more piece of mutable state two concurrent
    runs in one process would share."""
    if checkpoint not in runio.CHECKPOINT_KINDS:
        raise ValueError("unknown checkpoint kind: %r" % checkpoint)
    entries = _materialize_prompts(review_root, entries, namespace)
    request = {"schema_version": 1, "run_id": run_id, "checkpoint": checkpoint,
               "group": group, "entries": list(entries)}
    body = json.dumps(request, indent=2)
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    path = request_path(review_root, namespace)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with runio._open_w_nofollow(path) as fh:
        fh.write(body)
    record_request_hash(review_root, checkpoint, digest, namespace)
    return os.path.abspath(path), digest


def write_dispatch_request(review_root, run_id, checkpoint, group, entries,
                           namespace=None):
    """Write the single per-(group, checkpoint) dispatch-request.json and return
    its ABSOLUTE path. Host-agnostic: entries carry only neutral fields and any
    paths inside them must already be absolute (spec §4). The request is rolling
    — the durable state is the entries' out_files, not this file.

    Each entry also gets a `prompt_file` (#run10 B2) — the same text, addressable
    — so a host can hand an agent a path instead of echoing the whole prompt."""
    return write_dispatch_request_bound(review_root, run_id, checkpoint, group,
                                        entries, namespace=namespace)[0]

def load_dispatch_request(review_root, namespace=None):
    """The parsed .panopticon/dispatch-request.json (or None if absent/invalid).
    The host reads req['entries'] to install the write-guard
    (write_guard_hook.install(entries)) and to dispatch the checkpoint's cells.

    #1727: this is the UNBOUND read -- it proves nothing about who wrote the
    file. Every driver reader goes through `load_bound_request` below; this
    stays for the host-facing/inspection callers that only want the document,
    and has NO caller under `skill/scripts/`. That is pinned by an AST test
    (`tests/test_orchestrate.py::TestNoDriverReaderTakesTheUnboundRead`),
    because the way this control comes undone is somebody reaching for the
    shorter name in a new reader.
    """
    return runio._load_json(request_path(review_root, namespace))


# #1727. Printed to an operator's stderr and stored in a status, so: hashes
# only (they are not secrets and they are not attacker text), never a byte of
# the file's own contents -- a refused request is the target's document, and
# quoting it back is how a refusal repaints a terminal or forges a log line.
# Both hashes are abbreviated to _HASH_CHARS: enough to be unambiguous in a
# bug report, short enough to read.
_HASH_CHARS = 12
REQUEST_MISSING = ("dispatch request missing: %s; this run recorded one, so it was "
                   "removed after it was written -- re-run `driver run`/`driver loop` "
                   "to regenerate it")
REQUEST_UNRECORDED = ("dispatch request has no recorded hash in %s; re-run `driver "
                      "run`/`driver loop` to regenerate it")
REQUEST_MISMATCH = ("dispatch-request.json does not match the request this run wrote "
                    "(sha256 %s... != recorded %s...); a target-writable copy was "
                    "altered -- re-run `driver run`/`driver loop` to regenerate it")
RECORD_ALTERED = ("%s's recorded dispatch request hash was altered after it was "
                  "written (recorded %s... != %s... this run wrote); re-run `driver "
                  "run`/`driver loop` to regenerate it")
REQUEST_UNREADABLE = ("%s is not a readable dispatch request; re-run `driver "
                      "run`/`driver loop` to regenerate it")


def recorded_request_hash(review_root, namespace=None):
    """`(sha256_or_None, manifest filename)` for this namespace (#1727).

    The filename travels with the hash because it is what the refusals name,
    and setup anchors in its own manifest (#1507). A record of the wrong shape
    -- anything a target could put there if it reached the manifest -- reads
    as no record at all, which is the fail-closed answer."""
    if namespace == loop_batch.SETUP_NAMESPACE:
        import scripts.phases.setup as setup_mod
        manifest, name = setup_mod.load_setup_manifest(review_root), setup_mod.SETUP_MANIFEST
    else:
        manifest = run_manifest.load_manifest(review_root)
        name = run_manifest.MANIFEST_NAME
    record = (manifest or {}).get(run_manifest.DISPATCH_REQUEST)
    sha = record.get("sha256") if isinstance(record, dict) else None
    return (sha if isinstance(sha, str) and sha else None), name


def previous_request(review_root, namespace=None):
    """The OUTGOING request, for `loop_batch.disarm_previous`, or `{}`.

    A refusal is not fatal here and must not be: this read happens BEFORE
    `_first_run`, which is about to regenerate the file, and its only consumer
    removes grants. But uninstall is keyed by strings that file supplies, so a
    request the run cannot prove it wrote is announced once and read as "no
    previous entries" rather than acted on. An absent file with no record is a
    fresh run and says nothing."""
    req, refusal = load_bound_request(review_root, namespace)
    if refusal:
        print("driver loop: ignoring the previous dispatch request: %s" % refusal,
              file=sys.stderr, flush=True)
    return req or {}


def load_bound_request(review_root, namespace=None, expected_sha256=None):
    """`(request_or_None, refusal_or_None)` -- the read every driver reader uses.

    The request travels through a file in the REVIEWED tree while the hash of
    what the driver wrote travels through the run manifest (and, for the
    loop's own iteration, in memory on the checkpoint status). This is where
    the three are compared, and every disagreement is a refusal: nothing is
    dispatched, armed or persisted from a request this run cannot prove it
    wrote.

    `expected_sha256` is the IN-MEMORY hash the phase handed back on the
    status. It is checked against the RECORD, not against the file, because
    that is the pair no on-disk edit can reconcile: an attacker who rewrites
    both the request and the manifest still cannot reach the value the loop
    is holding. Checked first for exactly that reason -- it names the right
    file.

    The one non-refusal absence is a fresh tree: no file AND no record is "no
    previous request", which is what `driver loop`'s re-entry read sees before
    `_first_run` has written one.
    """
    recorded, manifest_name = recorded_request_hash(review_root, namespace)
    path = request_path(review_root, namespace)
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        raw = None
    if raw is None:
        if recorded is None:
            return None, None
        return None, REQUEST_MISSING % os.path.abspath(path)
    if recorded is None:
        return None, REQUEST_UNRECORDED % manifest_name
    if expected_sha256 is not None and expected_sha256 != recorded:
        return None, RECORD_ALTERED % (manifest_name, recorded[:_HASH_CHARS],
                                       expected_sha256[:_HASH_CHARS])
    digest = hashlib.sha256(raw).hexdigest()
    if digest != recorded:
        return None, REQUEST_MISMATCH % (digest[:_HASH_CHARS], recorded[:_HASH_CHARS])
    try:
        request = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        request = None
    if not isinstance(request, dict):
        # Unreachable through the driver -- it wrote these bytes and they
        # hash-match -- so this is the "the record was forged to match a
        # planted file" corner, and it fails closed like every other.
        return None, REQUEST_UNREADABLE % os.path.abspath(path)
    return request, None

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
    the dispatch entries carry scope (F4 `files`, plan 5 `scope`) and this
    deliberately does not (R-P5-6)."""
    enforced = loop_batch.expected_enforced(review_root, manifest.get("host", "claude"))
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
# #1737: `--setup` has a gate of its own -- `phases/setup.
# require_unenforced_scan_ack`. Same primitive (`_merge_ack` below),
# different capability (TOOL_POLICY_ENFORCED, not the write guard) and a
# separate ack file, for the reasons its docstring gives. It lives beside
# the flow that calls it because this module is at its size ceiling.


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

    On a host that does not declare it -- `--host generic`, the one
    claim-nothing value the CLI still accepts since #1621 retired gemini from
    the selectable set -- a domain-panel or domain-advisor `Write` has
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
                   if name != manifest.get("host", "claude")
                   and hosts.declares(name, hosts.ARTIFACT_WRITE_GUARD)]
        alternative = (", or use one of: " + ", ".join("--host " + n for n in guarded)
                       if guarded else "")
        row = evidence.get(hosts.ARTIFACT_WRITE_GUARD) or {}
        raise runio.DriverError(
            "%s is %s on host %r -- probe %s: %s. %s are granted Write, and "
            "nothing would confine that Write to the declared out_file; a "
            "write outside the reviewed tree is invisible to the clean-tree "
            "check too. Re-run with --allow-unenforced to accept that "
            "explicitly (it is recorded in %s)%s."
            % (hosts.ARTIFACT_WRITE_GUARD, posture[hosts.ARTIFACT_WRITE_GUARD],
               manifest.get("host"), row.get("by") or "none ran",
               row.get("detail") or "no evidence",
               ", ".join(sorted(write_capable_roles())), UNENFORCED_ACK,
               alternative))
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
    return _merge_ack(runio._pano(review_root, UNENFORCED_ACK), body)


def _merge_ack(path, body, refresh=_ACK_DISCLOSURE):
    """Write an ack, or ADD to one already there; never overwrite except the
    keys `refresh` names (#1737 made this shared with the setup gate).

    Never-overwrite protects a BINDING -- plan_sha256 above all, whose whole
    job (#493 R2) is to stay as the earlier invocation wrote it so a changed
    plan reads as stale. It must not also freeze a DISCLOSURE: a second
    shadowing file appearing after the first ack leaves the state alone
    (refuted -> refuted), so capabilities_of() sees no drift and the run
    continues; if the detail were pinned to the first write, the ack would name
    one path forever while the tree shipped several -- losing the exact fact
    7.3 requires it to record.

    So which keys are a binding and which are this invocation's own facts is
    the CALLER's to state, and `refresh` is where it says so. The review ack
    refreshes only its two disclosure keys. Setup's ack (#1737 fix round 1)
    binds nothing downstream and refreshes everything: a stale `host` or
    `plan_sha256` there is not a binding preserved, it is a record of an
    acceptance that was never made.
    """
    stored = runio._load_json(path)
    if isinstance(stored, dict):
        merged = dict(stored)
        merged.update({k: v for k, v in body.items() if k not in stored})
        merged.update({k: body[k] for k in refresh if k in body})
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
