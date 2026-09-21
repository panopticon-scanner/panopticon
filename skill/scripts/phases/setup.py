"""The `driver setup` flow: scan + ingest, its manifest and SETUP_PHASES."""
import json
import os
import subprocess
import sys

from scripts import dispatch
from scripts import hosts
import scripts.loop_batch as loop_batch
from scripts import read_guard_hook
import scripts.synth.integrity as integrity_mod
import scripts.host_disclosure as host_disclosure
import scripts.repo_config as repo_config
import scripts.run_manifest as run_manifest
import scripts.setup_flow as setup_flow
from . import engine
from . import persist
from . import runio
from . import requests


SETUP_MANIFEST = "setup-manifest.json"

def _setup_manifest_path(review_root):
    return runio._pano(review_root, SETUP_MANIFEST)

def load_setup_manifest(review_root):
    return runio._load_json(_setup_manifest_path(review_root))

def record_dispatch_request(review_root, checkpoint, sha256, at=None):
    """`--setup`'s half of #1727: anchor the setup dispatch request's sha256 in
    `setup-manifest.json`, under the SAME key the run manifest uses.

    Setup is not a run (#1507): it keeps its own request
    (`.panopticon/setup-dispatch-request.json`) and its own manifest, and
    `run_manifest._rewrite` writes `run-manifest.json` unconditionally -- so
    recording there would stamp a prior REVIEW run's manifest with setup's
    hash. Same tmp + `os.replace` shape as that helper, through this package's
    own confining opener (the manifest is a `.panopticon` artifact and the
    target may have planted a symlink at either name). A tree with no setup
    manifest records nothing, exactly as the run-manifest side does.
    """
    manifest = load_setup_manifest(review_root)
    if manifest is None:
        return None
    manifest[run_manifest.DISPATCH_REQUEST] = {
        "checkpoint": checkpoint, "sha256": sha256,
        "at": at or run_manifest._now_iso()}
    path = _setup_manifest_path(review_root)
    tmp = path + ".tmp"
    with runio._open_w_nofollow(tmp) as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return manifest

def _read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()

def _setup_scan_entry(review_root, prompt, host):
    """One return-persist dispatch entry for the read-only setup-scan agent
    (mirrors _scout_entry): the host dispatches it, gets proposal JSON back, and
    persists it to out_file. #1608: the entry carries `delivery` saying so.

    #1737 (AGT-B1D): this used to carry `agent: None, enforced: False`
    unconditionally, with a docstring arguing that a plain general-purpose
    dispatch was "sufficient and safe" because the template's tool_policy is
    read-only -- but that policy travelled as PROSE only. Nothing bounded the
    tool set a host hands a general-purpose agent, for the one dispatch that
    reads the WHOLE untrusted tree. `setup_scan` is a registered role now, so
    this entry names its shell and derives `enforced` from this invocation's
    own posture exactly the way the five phase sites do (#1720) -- with
    `--setup`'s own evidence artifact, which `driver loop --setup`'s posture
    step writes flat beside setup's other artifacts.

    When the posture does not prove enforcement -- no shells emitted yet, a
    host that cannot enforce -- the entry falls back to the shell-less shape
    it always had, and `scan_execute` makes the operator acknowledge that
    before it dispatches (`requests.require_unenforced_scan_ack`).

    The MODEL stays None either way: R-F4-2, deliberately unbound, so the
    session's model runs this one-off classification. The registered shell
    binds none either (model_resolver's `setup_scan` row).
    """
    out_file = os.path.abspath(runio._pano(review_root, "setup-proposal.json"))
    enforced = loop_batch.expected_enforced(review_root, host,
                                            namespace=loop_batch.SETUP_NAMESPACE)
    # The all-unknown posture `{}` is deliberate and unrelated to `enforced`
    # above: setup-scan.md grants no Write, so delivery() answers return_json
    # before it ever consults a posture, and handing it one would only invite
    # a reader to think the answer depends on it.
    mode, prefix = requests.delivery(host, {}, "setup-scan.md", out_file)
    entry = {"id": "setup-scan",
             # The role file SPELLED OUT, like the other four builders: the
             # #1727 routing guard reads this constant out of the AST to prove
             # the table names the shell this checkpoint really dispatches.
             "agent": dispatch.registered_agent_name("setup-scan.md") if enforced else None,
             "enforced": enforced,
             # R-F4-2: deliberately unbound -- an explicit `model: null` row in
             # model-profiles.yml, not an omission; see
             # test_setup_scan_is_deliberately_not_model_bound.
             "model": None,
             "prompt": requests.entry_marker("setup-scan") + prefix + prompt,
             "marker": read_guard_hook.marker_line("setup-scan"),
             "out_file": out_file,
             # O2: the scan reads the repository by design -- a DIRECTORY scope
             # over the review root, nothing outside it.
             "scope": requests.scope(dirs=[os.path.abspath(review_root)])}
    if mode:
        entry["delivery"] = mode
    return entry

SETUP_UNENFORCED_ACK = "setup-unenforced-ack.json"

# The operator's fix, not just an escape hatch: the refusal below names the
# command that makes the refusal go away for good -- when there is one.
_EMIT_REMEDY = "python3 skill/scripts/dispatch.py --emit-host-agents %s"
# ...and when what is missing is a MEASUREMENT rather than a registration, the
# invocation that takes it. `driver loop` resolves `--mode` to headless for any
# host with a runner and writes it back onto `args` before the posture step, so
# this is the one entry point that hands the probes a settings path (fix round
# 2; verified against `orchestrate._resolve_mode` and
# `driver._establish_host_posture`). `--mode headless` is spelled out even
# though it is the default for these hosts: a remedy an operator pastes should
# not depend on a resolution rule to be correct.
_MEASURE_REMEDY = "driver loop --setup --host %s --mode headless"


def require_unenforced_scan_ack(review_root, manifest, entries):
    """Refuse to dispatch `setup-scan` SHELL-LESS unless the operator accepted
    it explicitly (#1737, AGT-B1D) -- the setup analogue of
    `requests.require_unenforced_ack`, sharing its never-overwrite writer.

    The capability is TOOL_POLICY_ENFORCED, not ARTIFACT_WRITE_GUARD: this
    dispatch writes nothing (it is return-persist by construction) and the risk
    is the other one. It reads the WHOLE reviewed tree as untrusted content,
    and without a registered shell nothing bounds the tool set the host hands
    it -- the template's Read/Grep/Glob travels as the advisory line
    `dispatch._tool_policy_line` appends to the brief, and that is all. This is
    the acknowledgement every OTHER unenforced dispatch has required since
    #1519 and this one never passed through.

    A refusal is the normal outcome on a machine that has not emitted its
    shells, and the remedy it names FIRST is to emit them -- `--allow-unenforced`
    accepts the residual risk instead, and is recorded in
    `setup-unenforced-ack.json`.

    That record describes THIS invocation and nothing else. Every field is
    refreshed on every write, and once the posture proves enforcement the file
    is DISCARDED: an acceptance that outlives the posture it was about is a
    tree saying `acknowledged: true` over a dispatch that runs in a registered
    shell, which is worse than no record at all. The bootstrap sequence makes
    exactly that transition -- accept once, emit the shells, re-run.

    Its OWN file, beside setup's other artifacts, never the review run's
    `unenforced-ack.json`: that one's `plan_sha256` binds a review plan (#493
    R2) and is never-overwrite, so stamping setup's hash into it would make the
    next review run's ack read as stale -- and `runio._pano` would resolve the
    shared name into an unrelated run's folder besides (#1507).

    Returns the ack path when one was written, else None.
    """
    host = manifest.get("host", "claude")
    path = runio._pano(review_root, SETUP_UNENFORCED_ACK)
    if loop_batch.expected_enforced(review_root, host,
                                    namespace=loop_batch.SETUP_NAMESPACE):
        _discard_scan_ack(path)        # the shell is registered and proven
        return None
    evidence = loop_batch.evidence_for(review_root, loop_batch.SETUP_NAMESPACE)
    posture = hosts.posture(host, evidence)
    row = evidence.get(hosts.TOOL_POLICY_ENFORCED) or {}
    if not (manifest.get("flags") or {}).get("allow_unenforced"):
        # declares(), NOT posture(), for the hint -- the same reason
        # `requests.require_unenforced_ack` gives: we have no evidence for a
        # host we are not running, so posture() would answer unknown for all
        # of them and the hint would go empty.
        enforcing = [n for n in hosts.driver_hosts()
                     if hosts.declares(n, hosts.TOOL_POLICY_ENFORCED)]
        emit = _remedy_clause(host, posture[hosts.TOOL_POLICY_ENFORCED])
        raise runio.DriverError(
            "%s is %s on host %r -- probe %s: %s. The setup-scan agent reads "
            "the whole reviewed tree as untrusted content, and with no "
            "registered shell nothing confines its tools to Read, Grep, Glob "
            "-- the brief's tool policy is advisory prose. %s-run with "
            "--allow-unenforced to accept that explicitly (it is recorded in "
            "%s), or use one of: %s."
            % (hosts.TOOL_POLICY_ENFORCED, posture[hosts.TOOL_POLICY_ENFORCED],
               host, row.get("by") or "none ran", row.get("detail") or "no evidence",
               emit, SETUP_UNENFORCED_ACK,
               ", ".join("--host " + n for n in enforcing)))
    body = {
        "acknowledged": True, "host": host,
        # The launch SHAPE the operator accepted (id, shell, posture,
        # destination), not the brief: that text carries the repository spine
        # and moves with the tree, so hashing it would bind the acceptance to
        # a file listing rather than to the thing being acknowledged.
        "plan_sha256": integrity_mod._plan_hash(
            [{key: entry.get(key) for key in ("id", "agent", "enforced", "out_file")}
             for entry in entries if isinstance(entry, dict)]),
        "roles": ["setup_scan"],
        "note": ("The setup classifier reads the whole reviewed tree with no "
                 "registered shell: its tool grant is whatever this host gives "
                 "a general-purpose agent. The operator accepted this with "
                 "--allow-unenforced."),
        hosts.TOOL_POLICY_ENFORCED: posture[hosts.TOOL_POLICY_ENFORCED],
        "tool_policy_detail": row.get("detail") or "no evidence"}
    # Every key refreshed: see the docstring. Nothing downstream binds to this
    # file, so there is no earlier write to preserve -- only an older set of
    # facts to correct.
    return requests._merge_ack(path, body, refresh=tuple(body))


def _remedy_clause(host, state):
    """The fixing remedy this refusal may honestly name, as a sentence opener
    ending in "re" for the `--allow-unenforced` clause that follows.

    Three answers, and the rule is the capability's STATE, which is what says
    whether a fix EXISTS and which one (fix round 2):

    * REFUTED -- the host measured and said no. Every capability that gates
      here maps to a registration probe, so re-emitting is the fix for its
      ordinary cause, and the refusal quotes the probe's own detail for the
      rest. Name the emit command.
    * UNKNOWN -- NOTHING measured it. No amount of registering changes what
      was never read, and naming the emit command there is the round-1
      Critical one host over: `driver setup --host codex` cannot reach PROVEN
      on any machine, because codex maps `tool_policy_enforced` to
      `codex-effective-tools` and that probe answers UNKNOWN unless it is
      handed a headless settings path, which only `driver loop` produces.
      Name the invocation that can measure.
    * A host that registers no shells at all (`--host generic`, owner ruling
      D1, the permanent unenforced fallback) gets NEITHER: emitting refuses
      and measuring finds nothing to measure, so the acceptance and the host
      switch are the whole truthful list.

    `headless_available` is the one owner of "does this family ship a runner",
    and it is asked rather than assumed -- a host that registers shells and
    ships no runner would otherwise be handed a `--mode headless` that
    `runner_for` refuses, which is the same defect in a third place. Imported
    locally, the way `probes.common.headless_settings_path` reaches the same
    package: `phases` may import `runners` (only the reverse is banned), but
    at call time, not at module import, so the cycle through
    `runners.base -> dispatch` stays broken.
    """
    import scripts.runners.base as runners_base
    row = hosts.spec(host)
    if row is None or not row.shell_format:
        return "Re"
    if state == hosts.REFUTED:
        return "Run %s and re-run `driver setup`, or re" % (_EMIT_REMEDY % host)
    if runners_base.headless_available(host):
        return ("Nothing measured it here -- re-run as `%s`, the invocation "
                "that can, or re" % (_MEASURE_REMEDY % host))
    return "Re"


def _discard_scan_ack(path):
    """Drop a standing acceptance the posture has superseded, and say so.

    Announced rather than silent: the operator passed `--allow-unenforced` at
    some point, and the file going away is the run telling them they no longer
    need to. Never fatal -- the ack lives under `.panopticon`, which the target
    owns, so a read-only directory or a directory planted at the name must not
    take down the ENFORCED path, which needs no acknowledgement anyway.
    """
    try:
        os.remove(path)
    except OSError:
        return None
    print("driver setup: %s discarded -- this host now enforces the setup-scan "
          "shell, so there is nothing left to acknowledge" % SETUP_UNENFORCED_ACK,
          file=sys.stderr)
    return path

def scan_done(review_root, manifest):
    return (runio._json_parses(runio._pano(review_root, "setup-proposal.json"))
            or runio._json_parses(runio._pano(review_root, "setup-complete.json")))

def scan_execute(review_root, manifest):
    """Provision + render the scan brief -> setup-scan checkpoint (vocab present);
    or flat-seed + readiness + a fallback-complete marker (vocab absent, Task 3)."""
    host = manifest.get("host", "claude")
    prov = setup_flow.provision(review_root)
    if prov["stale_config_json"]:
        # #1681: the retired JSON config is never read again. Say so once, here,
        # rather than leaving an operator editing a file nothing consults.
        print("driver setup: " + prov["stale_config_json"], file=sys.stderr, flush=True)
    vocab, present = setup_flow.load_bundled_vocabulary(manifest.get("vocabulary_path"))
    if not present:
        return _scan_fallback(review_root, manifest, host)   # Task 3
    # 5.2 stage 1: the spine is computed once, with the sizes the manifest
    # pinned, persisted for the record and rendered into the brief.
    spine = setup_flow.build_spine(review_root, max_per_group=manifest.get("max_per_group"),
                                   max_groups=manifest.get("max_groups"))
    setup_flow.write_spine(review_root, spine)
    layers, _ = setup_flow.load_bundled_layers()
    brief_path = setup_flow.render_scan_brief(review_root, vocab, layers=layers,
                                              spine=spine, host=host)
    entry = _setup_scan_entry(review_root, _read_text(brief_path), host)
    # Before the entry is written, let alone dispatched: an unenforced
    # setup-scan needs the operator's acknowledgement, and a refusal must
    # leave no dispatch request behind for a resume to pick up (#1737).
    require_unenforced_scan_ack(review_root, manifest, [entry])
    # #1507: setup's own namespace -- never the per-run resolver, which routed
    # this into whatever runs/latest pointed at and clobbered that run's request.
    req, sha = requests.write_dispatch_request_bound(
        review_root, manifest["run_id"], "scan", None, [entry], namespace="setup")
    return engine.PhaseResult(kind="checkpoint", checkpoint="scan", group=None,
                       dispatch_request=req, request_sha256=sha,
                       message="setup-scan checkpoint")

def ingest_done(review_root, manifest):
    return (os.path.isfile(repo_config.draft_path(review_root))
            or runio._json_parses(runio._pano(review_root, "setup-complete.json")))

def ingest_execute(review_root, manifest):
    res = setup_flow.ingest_proposal(review_root,
                                     max_per_group=manifest.get("max_per_group"),
                                     max_groups=manifest.get("max_groups"))
    if not res["ok"]:
        raise runio.DriverError("ingest: " + "; ".join(res["errors"]))
    return engine.PhaseResult(kind="advanced",
                       message="setup: draft written %s; report %s"
                       % (res["draft"], res["report_path"]))

SETUP_PHASES = (
    engine.Phase("scan", "checkpoint", scan_done, scan_execute),
    engine.Phase("ingest", "deterministic", ingest_done, ingest_execute),
)

_SETUP_ARTIFACTS = ("setup-scan-brief.md", "setup-spine.json", "setup-proposal.json",
                    "setup-report.md", "setup-report.json",
                    "setup-complete.json", SETUP_MANIFEST,
                    # #1737: an acceptance is this invocation's, not a
                    # standing one. `--reset` starts over, and starting over
                    # includes being asked again.
                    SETUP_UNENFORCED_ACK)

def _setup_capabilities_path(review_root):
    """The capability evidence `driver loop --setup`'s posture step writes.

    Resolved through `persist.run_dir(review_root, "setup")` -- the flat
    `.panopticon/`, where every other setup artifact lives -- and deliberately
    NOT through `runio._pano`, which is what the rest of this module uses:
    `host-capabilities.json` is not in `runio._TOP_LEVEL`, so `_pano` resolves
    it into `runs/<tag>/` whenever a review run-manifest is on the tree. That
    file is that run's evidence, and a `--setup --reset` deleting it would be
    the same class of accident as the stale-runs-folder writes (#1507).
    """
    return os.path.join(persist.run_dir(review_root, "setup"), runio.HOST_CAPABILITIES)

def _clear_setup_artifacts(review_root):
    """Remove derived setup artifacts + the setup-manifest for --reset. NEVER
    touches the committed root config -- only the DRAFT beside it, which this
    flow derives and rewrites on every ingest (#1681).

    The capability evidence is cleared too (fix round 1, F2): `driver loop
    --setup` reads it back on every later invocation, and `driver.run`'s own
    `--reset` cannot reach it -- that one clears the REVIEW namespace, i.e. the
    per-run folder. A file the verb consults with no way to discard it is a
    remedy the refusal message names and does not deliver."""
    draft = repo_config.draft_path(review_root)
    for path in ([runio._pano(review_root, name) for name in _SETUP_ARTIFACTS]
                 + [_setup_capabilities_path(review_root)]
                 + ([draft] if os.path.isfile(draft) else [])):
        try:
            os.remove(path)
        except OSError:
            pass

# #1601. Every limitation carried a full remedy and they were all joined into
# ONE line: on gemini that line measured 1847 characters, up ~17x from ~110,
# because a host that claims nothing legitimately has seven of them. Nothing
# gating moved (shell-less hosts produce 7 rows and 0 gaps), which is the
# reason it needed fixing rather than a reason to leave it -- §5.1's "LOUDLY
# declare them" is about being READ, and a 1847-character line is a disclosure
# in the letter and not in the fact.
#
# One remedy per line, under the column bar, and a bounded list: the full,
# untruncated text of every limitation is in `setup-complete.json`'s
# `limitations` array either way, so the message is an index into it rather
# than a second copy of it.
_LIMITATION_LINE = 119          # strictly under the 120-column bar
_LIMITATION_MAX = 12            # remedies shown before the "and N more" tail
_TRUNCATED = "..."


def _limitation_line(name, detail):
    """One limitation on one line, no longer than `_LIMITATION_LINE` -- unless
    the NAME alone is longer than that, in which case the name wins.

    The name is never what gets cut: it is the key `setup-complete.json`
    stores the untruncated detail under, and the string an operator greps the
    readiness rows for. A line whose name has been sliced in half identifies
    nothing and points at nothing. Only the detail is trimmed, and it says so.

    R1 Minor 4: this used to slice the whole rendered line, so the docstring
    above asserted a guarantee the code did not make -- measured, a 156-char
    name came back cut mid-name. Every check name this repo emits is
    code-controlled and far under the bar (the longest,
    `host-capability:tool_policy_enforced`, is 36 characters), so the
    name-wins branch is a promise kept rather than a trade-off anyone meets.
    """
    detail = str(detail)     # read off setup-complete.json: any JSON shape
    line = "  - %s (%s)" % (name, detail)
    if len(line) <= _LIMITATION_LINE:
        return line
    head = "  - %s (" % name
    room = _LIMITATION_LINE - len(head) - len(_TRUNCATED) - 1   # the ")"
    return head + (detail[:room] if room > 0 else "") + _TRUNCATED + ")"


def _limitations_clause(limitations):
    """Render the readiness checks that gate nothing (`ok is None`).

    Spec §5.1: "If there are limitations by host then we should LOUDLY declare
    them", and "absence of warnings must mean 'measured and proven', never
    'nobody looked'". A check whose `ok` is None was never measured against a
    pass/fail bar -- gemini registering no enforcement shells is a FACT, not a
    fault. So it must not join `gaps` (those gate READY and carry a remedy),
    and it must not be swallowed either: `readiness OK` on a host that cannot
    enforce is exactly the ambiguity §5.1 forbids. Its own clause, carrying the
    check's own detail, which already names the capability and the host.
    """
    rows = list(limitations)
    shown = rows[:_LIMITATION_MAX]
    out = ["limitations:"]
    out.extend(_limitation_line(name, detail) for name, detail in shown)
    if len(rows) > len(shown):
        out.append("  - and %d more -- full text in "
                   ".panopticon/setup-complete.json `limitations`"
                   % (len(rows) - len(shown)))
    return "\n".join(out)

def _stored_limitations(marker):
    """The `limitations` pairs from a setup-complete.json, or []. Tolerates a
    marker written before the key existed, and any row that is not a pair."""
    return [(row[0], row[1]) for row in ((marker or {}).get("limitations") or [])
            if isinstance(row, (list, tuple)) and len(row) == 2]

def _scan_fallback(review_root, manifest, host):
    """Vocab-absent path (parity with orchestrator.run_setup): flat top-dir seed
    + readiness gate, then a fallback-complete marker so both setup phases'
    done-predicates are satisfied -> run_engine completes without a checkpoint
    and without entering ingest."""
    path, created, names = setup_flow.seed_flat_manifest(review_root)
    checks = setup_flow.readiness(review_root, host=host)
    gaps = [c[0] for c in checks if c[1] is False]
    # ok is None is NOT-APPLICABLE, a third answer the renderer used to collapse
    # into "fine". Recorded under its own key so a consumer can tell "not
    # applicable" from "measured and passed" (§5.1).
    limitations = [(c[0], c[2]) for c in checks if c[1] is None]
    runio._write_json(runio._pano(review_root, "setup-complete.json"), {
        "schema_version": 1,
        "mode": "fallback", "seed": path, "created": created, "groups": names,
        "readiness": [[c[0], c[1], c[2]] for c in checks],
        "gaps": gaps, "limitations": [[n, d] for n, d in limitations],
        "run_id": manifest["run_id"]})
    msg = ("setup: vocab-absent fallback — flat seed %s; readiness %s"
           % (path, "OK" if not gaps else "gaps: " + ", ".join(gaps)))
    # LAST, and on its own lines (#1601): the clause is a list now, so
    # anything appended after it would land on the final remedy's line.
    if limitations:
        msg += "\n" + _limitations_clause(limitations)
    return engine.PhaseResult(kind="advanced", message=msg)

def _drop_stale_fallback_marker(review_root):
    """A vocab-absent run wrote a mode:"fallback" setup-complete.json. Once the
    vocabulary is available again, that marker is stale — a real scan should
    supersede the flat seed. Remove it so the engine re-scans (self-healing; no
    --reset needed). No-op when there is no fallback marker or vocab is still
    absent."""
    marker = runio._load_json(runio._pano(review_root, "setup-complete.json"))
    if not (isinstance(marker, dict) and marker.get("mode") == "fallback"):
        return
    _vocab, present = setup_flow.load_bundled_vocabulary(None)
    if present:
        try:
            os.remove(runio._pano(review_root, "setup-complete.json"))
        except OSError:
            pass

def run_setup_flow(args, runner=subprocess.run, phases=SETUP_PHASES, posture=None):
    """The `driver setup` entrypoint: a separate two-phase flow (NOT a run
    phase). Resolves the review root, pins a minimal setup-manifest once, and
    advances scan->ingest through run_engine. Writes a draft; the owner reviews
    and commits it.

    `posture` (#1616 item 3) is the capability step `driver run` performs on
    every invocation -- `driver._establish_host_posture` -- passed IN rather
    than imported: `phases/*` may never reach an entry script
    (tests/test_layout.py rule 3), and this flow is driven by two of them.
    Called with this flow's own namespace, so the guard probes measure the
    settings file `driver loop --setup` really arms (the flat
    `.panopticon/host-settings.json`) and the evidence lands beside setup's
    other artifacts rather than in some earlier review run's folder.

    BOTH entrypoints pass it (#1737 fix round 1). `driver loop --setup` always
    did, because that is the path that ARMS both guards headlessly and
    therefore the one whose subject a probe has to have proven. `driver setup`
    now does too, because the evidence that step writes is no longer only a
    record: `_setup_scan_entry` and `require_unenforced_scan_ack` both read it,
    so a run that skipped the probe would gate on an artifact nothing in this
    invocation measured -- absent on a fresh target, or planted by the target.
    `posture=None` is a UNIT seam only: it runs the flow against whatever
    evidence the caller arranged, and no production caller passes it. Its
    refusal -- a posture that moved, a planted shadow shell -- is this verb's
    `error` status, the same one every other refusal here speaks."""
    review_root, _wt, _pr = runio.resolve_review_root(args.target, runner=runner)
    if getattr(args, "reset", False):
        _clear_setup_artifacts(review_root)               # Task 3
    _drop_stale_fallback_marker(review_root)
    manifest = load_setup_manifest(review_root)
    if manifest is not None and runio._foreign_manifest(
            manifest, review_root, _setup_manifest_path(review_root)):
        # #run7/#run8 AGT-C1A: a target repo can force-commit its own
        # .panopticon/setup-manifest.json (gitignored but `git add -f`-able) to
        # preset an attacker-chosen `vocabulary_path` -- which setup_flow reads and
        # embeds verbatim into the classifier scan brief -- or `host`. Mirror the
        # run-manifest guard (#1093): a manifest that is git-tracked in this tree,
        # or whose stamped review_root isn't THIS checkout, is not a legitimate
        # resume state; discard and rebuild from args.
        print("driver: ignoring foreign setup-manifest.json (stamped review_root "
              "%r != %r)" % (manifest.get("review_root"),
                             os.path.abspath(review_root)),
              file=sys.stderr, flush=True)
        manifest = None
    if manifest is None:
        # 5.2 size policy, pinned at scan time so the brief's arithmetic and
        # the ingest's layers agree (anti-drift, like the run manifest's
        # max_per_group). CLI > `settings:`, resolved HERE so a config edit
        # between scan and ingest cannot move the numbers; None = default.
        overrides = setup_flow.config_overrides(review_root)
        manifest = {"schema_version": 1, "run_id": run_manifest.new_run_id(),
                    "review_root": os.path.abspath(review_root),
                    "target": os.path.abspath(args.target),
                    "host": args.host or runio._DEFAULTS["host"],
                    "vocabulary_path": None,
                    "max_per_group": (getattr(args, "max_per_group", None)
                                      or overrides["max_per_group"]),
                    "max_groups": getattr(args, "max_groups", None) or overrides["max_groups"]}
        runio._write_json(_setup_manifest_path(review_root), manifest)
    # #1737: read off THIS invocation's argv, every time, and never off the
    # stored manifest. `setup-manifest.json` sits at a `.panopticon` path a
    # hostile target can force-commit and is written once and reused, so a
    # stored `allow_unenforced` could otherwise grant an acceptance the
    # operator never made -- or withhold one they just made on the command
    # line. Recorded in the manifest so `driver loop --setup`'s phases (which
    # see only the manifest) read the same answer this invocation gave.
    manifest["flags"] = {"allow_unenforced":
                         bool(getattr(args, "allow_unenforced", False))}
    host = manifest.get("host", runio._DEFAULTS["host"])
    if posture is None and hosts.is_unenforced_fallback(host):
        # D1, mirroring driver.run()'s _establish_host_posture: printed from
        # the RESOLVED host (the manifest, whether just minted from args.host
        # or loaded from a prior invocation), once per `driver setup` call,
        # before either setup phase runs. `hosts.is_unenforced_fallback` (not
        # a bare `host == "generic"`) because tests/test_host_posture_wiring.py's
        # AST guard forbids phases/ deciding anything from a host's NAME.
        #
        # `posture is None` (fix round 1, F4): when a posture step is injected
        # it prints this itself, off the same resolved host, and two copies per
        # invocation is not "once". The standalone `driver setup` has no such
        # step, so this stays its own.
        print(host_disclosure.GENERIC_FALLBACK_NOTICE, file=sys.stderr)
    if posture is not None:
        error = posture(review_root, manifest, args, namespace="setup")
        if error:
            return runio._error_status(error)
    try:
        result = engine.run_engine(review_root, manifest, phases)
    except (runio.DriverError, engine.EngineStalled, ValueError) as exc:
        # `ValueError` is item 24 R1-1: since #1577 the five setup artifacts are
        # written through the confined no-follow writers, whose whole-path
        # confinement refuses a planted component with a ValueError. That
        # refusal is the guard WORKING -- an outcome of this verb -- so it
        # belongs in the status protocol beside the two below, not on stderr as
        # a traceback with no JSON behind it.
        # #1637 P08 fix round 2: `driver run` converts the engine's progress
        # guard into an `error` status; this drives the SAME engine and was
        # still letting it escape as a traceback. One named class with two call
        # sites, only one of them converting, teaches the next reader that the
        # guarantee is per-caller rather than per-engine -- and `driver setup`
        # speaks the same status protocol, so a traceback is no more a status
        # here than it is there.
        return runio._error_status(str(exc))
    if result.get("status") == "complete":
        if os.path.isfile(repo_config.draft_path(review_root)):
            result["message"] = (
                "setup complete -- read .panopticon/setup-report.md, then DIFF "
                "%s against %s before moving it over: the draft rebuilds "
                "`groups:`, carries a committed `exclude_paths:` and "
                "`settings:` across and records the sizes you passed, but any "
                "other hand-kept top-level key is yours to re-apply"
                % (repo_config.DRAFT_NAME, repo_config.CONFIG_NAMES[0]))
        else:
            msg = ("setup complete -- vocab-absent fallback seeded a flat %s; "
                   "review, edit, and commit it" % repo_config.CONFIG_NAMES[0])
            marker = runio._load_json(
                runio._pano(review_root, "setup-complete.json")) or {}
            gaps = marker.get("gaps") or []
            if gaps:
                msg += (" — readiness gaps: %s (fix before running a review)"
                       % ", ".join(gaps))
            # This is the message the operator actually reads -- _scan_fallback's
            # is replaced here -- so the limitations clause has to be restated,
            # or declaring it there would be declaring it to nobody (§5.1).
            limitations = _stored_limitations(marker)
            if limitations:
                msg += "\n" + _limitations_clause(limitations)
            result["message"] = msg
    return result
