"""The `driver setup` flow: scan + ingest, its manifest and SETUP_PHASES."""
import os
import subprocess
import sys

import scripts.run_manifest as run_manifest
import scripts.setup_flow as setup_flow
from . import engine
from . import runio
from . import requests


SETUP_MANIFEST = "setup-manifest.json"

def _setup_manifest_path(review_root):
    return runio._pano(review_root, SETUP_MANIFEST)

def load_setup_manifest(review_root):
    return runio._load_json(_setup_manifest_path(review_root))

def _read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()

def _setup_scan_entry(review_root, prompt):
    """One return-persist dispatch entry for the read-only setup-scan agent
    (mirrors _scout_entry): the host dispatches it, gets proposal JSON back, and
    persists it to out_file.

    Unlike scout/panel/advisor roles, setup-scan is NEVER enforced: it is not in
    dispatch.ROLE_FILES, so no `panopticon-setup-scan` shell is ever registered
    for any host — dispatching it as "enforced" would ask the host to invoke a
    subagent that doesn't exist. It is read-only + return-persist by template
    tool_policy (Read/Grep/Glob only), so a plain general-purpose dispatch is
    sufficient and safe.
    """
    return {"id": "setup-scan",
            "agent": None,
            "enforced": False,
            # R-F4-2: deliberately unbound -- no ROLE_FILES entry, no profile;
            # see test_setup_scan_is_deliberately_not_model_bound.
            "model": None,
            "prompt": prompt,
            "out_file": os.path.abspath(runio._pano(review_root, "setup-proposal.json"))}

def scan_done(review_root, manifest):
    return (runio._json_parses(runio._pano(review_root, "setup-proposal.json"))
            or runio._json_parses(runio._pano(review_root, "setup-complete.json")))

def scan_execute(review_root, manifest):
    """Provision + render the scan brief -> setup-scan checkpoint (vocab present);
    or flat-seed + readiness + a fallback-complete marker (vocab absent, Task 3)."""
    host = manifest.get("host", "claude")
    prov = setup_flow.provision(review_root)
    note = prov.get("gitignore_note")   # #1135: groups.yml needs `git add -f`
    vocab, present = setup_flow.load_bundled_vocabulary(manifest.get("vocabulary_path"))
    if not present:
        return _scan_fallback(review_root, manifest, host, note=note)   # Task 3
    # 5.2 stage 1: the spine is computed once, with the sizes the manifest
    # pinned, persisted for the record and rendered into the brief.
    spine = setup_flow.build_spine(review_root, max_per_group=manifest.get("max_per_group"),
                                   max_groups=manifest.get("max_groups"))
    setup_flow.write_spine(review_root, spine)
    layers, _ = setup_flow.load_bundled_layers()
    brief_path = setup_flow.render_scan_brief(review_root, vocab, layers=layers, spine=spine)
    entry = _setup_scan_entry(review_root, _read_text(brief_path))
    # #1507: setup's own namespace -- never the per-run resolver, which routed
    # this into whatever runs/latest pointed at and clobbered that run's request.
    req = requests.write_dispatch_request(review_root, manifest["run_id"], "scan",
                                          None, [entry], namespace="setup")
    msg = "setup-scan checkpoint" + ((" — " + note) if note else "")
    return engine.PhaseResult(kind="checkpoint", checkpoint="scan", group=None,
                       dispatch_request=req, message=msg)

def ingest_done(review_root, manifest):
    return (os.path.isfile(runio._pano(review_root, "groups.yml.draft"))
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
                    "groups.yml.draft", "setup-report.md", "setup-report.json",
                    "setup-complete.json", SETUP_MANIFEST)

def _clear_setup_artifacts(review_root):
    """Remove derived setup artifacts + the setup-manifest for --reset. NEVER
    touches the committed groups.yml."""
    for name in _SETUP_ARTIFACTS:
        try:
            os.remove(runio._pano(review_root, name))
        except OSError:
            pass

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
    return "limitations: " + ", ".join("%s (%s)" % (name, detail)
                                       for name, detail in limitations)

def _stored_limitations(marker):
    """The `limitations` pairs from a setup-complete.json, or []. Tolerates a
    marker written before the key existed, and any row that is not a pair."""
    return [(row[0], row[1]) for row in ((marker or {}).get("limitations") or [])
            if isinstance(row, (list, tuple)) and len(row) == 2]

def _scan_fallback(review_root, manifest, host, note=None):
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
    if limitations:
        msg += " — " + _limitations_clause(limitations)
    if note:   # #1135: surface the "groups.yml needs `git add -f`" note
        msg += " — " + note
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

def run_setup_flow(args, runner=subprocess.run, phases=SETUP_PHASES):
    """The `driver setup` entrypoint: a separate two-phase flow (NOT a run
    phase). Resolves the review root, pins a minimal setup-manifest once, and
    advances scan->ingest through run_engine. Writes a draft; the owner reviews
    and commits it."""
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
        # max_per_group). CLI > config.json, resolved HERE so a config edit
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
    try:
        result = engine.run_engine(review_root, manifest, phases)
    except runio.DriverError as exc:
        return runio._error_status(str(exc))
    if result.get("status") == "complete":
        if os.path.isfile(runio._pano(review_root, "groups.yml.draft")):
            result["message"] = (
                "setup complete — read .panopticon/setup-report.md, then DIFF "
                ".panopticon/groups.yml.draft against .panopticon/groups.yml "
                "before moving it over: the draft rebuilds `groups:` and "
                "carries a committed `exclude_paths:` across, but any other "
                "hand-kept top-level key is yours to re-apply")
        else:
            msg = ("setup complete — vocab-absent fallback seeded a flat "
                  ".panopticon/groups.yml; review, edit, and commit it")
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
                msg += " — " + _limitations_clause(limitations)
            result["message"] = msg
    return result
