"""Phase 3 -- tools: run the SAST/SCA adapters and ingest their findings."""
import os
import sys

from . import engine
from . import runio


# The exact note `--no-tools` writes. Matched by equality, never by substring:
# `tools_done` reads this back off a file a hostile target could pre-commit,
# and a scanner's stderr that happened to quote the flag must not spell "the
# operator chose this".
NO_TOOLS_NOTE = "tools disabled (--no-tools)"


def tools_done(review_root, manifest):
    """The scan RAN, CRASHED, or was switched off on purpose -- never merely
    "a marker parsed" (#1637 P08 ruling 4).

    The old predicate made an ENVIRONMENTAL skip -- Docker down, or the image
    absent -- done for ever. Run-13 skipped the scan on a missing image and
    then dispatched 85 panels with no scanner evidence; installing the image
    mid-run could not have retried it, because the marker already said done.
    An environmental skip now re-evaluates on the next `driver run`, which
    costs one `docker image inspect` and keeps every scout/review artifact
    already on disk.

    A CRASH still counts as done, deliberately: it is disclosed loudly and
    gated by the adapter manifest (#1033), and re-running a broken scanner on
    every invocation would wedge the run rather than fix it.

    With `readiness` failing closed ahead of this phase, the environmental
    branch is now only reachable when the environment changed MID-RUN -- the
    daemon stopped, or the image was pruned, between readiness and here.
    """
    marker = runio._load_json(runio._pano(review_root, "tools-ran.json"))
    if not isinstance(marker, dict):
        return False
    if marker.get("ran") or marker.get("crashed"):
        return True
    if marker.get("note") == NO_TOOLS_NOTE:
        # F5: flag-aware, exactly as `readiness_done` is. A marker that records
        # the operator's own `--no-tools` is done only while the manifest still
        # says so; a run switched back to tools-enabled must re-run the scan
        # rather than inherit the decision it just reversed.
        return (manifest.get("flags") or {}).get("tools") is False
    # The environmental skip. Done FOR THIS INVOCATION once this invocation has
    # already attempted it, and not-done for the next `driver run` -- which is
    # the cadence ruling 4 names. A bare "not done" was step-scoped, not
    # invocation-scoped: `run_engine` recomputes the cursor on every step, so
    # it re-selected `tools` immediately and spun until max_steps.
    #
    # Equality against the CURRENT invocation's token, so a `tools-ran.json` a
    # hostile target pre-commits cannot claim to have been written by this
    # invocation -- the token is a fresh uuid per `driver.run` call and is
    # never persisted in the manifest.
    #
    # Fail CLOSED on a marker with no token at all: `None == None` would make
    # an environmental skip done for ever the moment a caller of `run_engine`
    # forgot to mint one, which is run-13's regression verbatim. The cost of
    # the strict form is one retry by the next minted invocation -- exactly
    # what a pre-#1637 marker already gets.
    attempt = marker.get("attempt_invocation")
    return attempt is not None and attempt == manifest.get("invocation")

def partial_audit_note(review_root, finding):
    """The prompt preamble telling a tool advisor that its scanner's coverage
    was PARTIAL, or "" when it was not (#1646).

    pip-audit is handed a GENERATED requirements list -- resolving an editable,
    local, VCS or URL requirement would run the reviewed repository's PEP 517
    build backend -- so the dependency audit can be incomplete. advisor.md tells
    the advisor to "verify the package and version are actually present" before
    confirming a dependency claim, and an advisor reasoning from an audit it
    believes to be complete will read a package's absence from it as evidence.
    It is not. This says so, with the count off THIS run's manifest.

    Scoped to the adapter the claim came from: a bandit advisor has no use for
    pip-audit's coverage, and a prompt that tells every advisor everything is a
    prompt nobody reads. Silent when nothing was dropped, when there is no
    manifest, and on every shape that is not the one the field promises -- the
    file is target-writable, so a malformed block costs the note, never the
    dispatch.
    """
    source = finding.get("source") if isinstance(finding, dict) else None
    if not isinstance(source, str) or not source.startswith("tool:"):
        return ""
    tool = source[len("tool:"):]
    sanitized = (runio._load_json(runio._pano(review_root, "tools-manifest.json"))
                 or {}).get("sanitized")
    row = sanitized.get(tool) if isinstance(sanitized, dict) else None
    dropped = row.get("dropped") if isinstance(row, dict) else None
    if not isinstance(dropped, list) or not dropped:
        return ""
    return ("Scanner coverage: %s audited a GENERATED dependency list, not this "
            "repository's own file -- %s: %d requirement lines not audited "
            "(editable/local/VCS). A package's ABSENCE from that audit is not "
            "evidence the repository does not require it; `tools-manifest.json` "
            "lists every line under `sanitized`.\n\n" % (tool, tool, len(dropped)))

def tools_execute(review_root, manifest):
    if (manifest.get("flags") or {}).get("tools") is False:
        runio._write_json(runio._pano(review_root, "tools-ran.json"),
                    {"schema_version": 1, "ran": False, "skipped": True, "crashed": False,
                     "note": NO_TOOLS_NOTE,
                     "returncode": None, "run_id": manifest["run_id"],
                     "attempt_invocation": manifest.get("invocation")})
        return engine.PhaseResult(kind="advanced", message="tools: skipped (--no-tools)")
    out_dir = runio._pano(review_root, "tools")
    # #1031: --manifest records the deterministic adapter set (selected/produced/
    # missing) so synthesize can certify tool coverage against what the runner
    # actually resolved, not the scout's advisory tool list.
    manifest_path = runio._pano(review_root, "tools-manifest.json")
    cmd = [sys.executable, runio._script("run_tools.py"), "--target", review_root,
           "--out", out_dir, "--deps",
           "--run-id", manifest.get("run_id") or "",   # #17: manifest self-identifies
           "--manifest", manifest_path]
    proc = runio._run_child(cmd, review_root, "tools")
    # The runner's own report of what it did with the captures it wrote (#1639
    # P11 F5). Tolerant: a crash before the manifest was written leaves nothing
    # to copy, and the marker then claims nothing.
    #
    # THIS run's manifest, or none (N2). `run_tools.main()` writes the manifest
    # only after the scan returns, so a runner that lands captures and then dies
    # leaves the PREVIOUS invocation's file in place -- and copying its claim
    # would vouch for captures this run never passed through the choke point,
    # which is the overstatement F5 exists to kill. Same `run_id` rule #17
    # already applies to the manifest's coverage numbers.
    tool_manifest = runio._load_json(manifest_path)
    if (not isinstance(tool_manifest, dict)
            or tool_manifest.get("run_id") != manifest.get("run_id")):
        tool_manifest = {}
    produced = os.path.isdir(out_dir) and bool(os.listdir(out_dir))
    # #1033: a real scanner/runner CRASH (non-zero exit + no output) is NOT a
    # benign Docker-absent skip (exit 0 + no output). Distinguish them: record a
    # `crashed` marker + a loud stderr line, but still advance -- tools are
    # best-effort and #1031's manifest gate already fails certification when a
    # selected adapter produces nothing, so the run stays honest without a hard
    # stop that a missing Docker image doesn't deserve.
    crashed = (not produced) and proc.returncode not in (0, None)
    raw_err = (proc.stderr or "").strip()[:300]
    note = "" if produced else (runio._redact_output(raw_err)
                                or ("tool scan crashed" if crashed
                                    else "no tool output produced"))
    runio._write_json(runio._pano(review_root, "tools-ran.json"),
                {"schema_version": 1, "ran": produced, "skipped": not produced, "crashed": crashed,
                 "note": note, "returncode": proc.returncode,
                 "run_id": manifest["run_id"],
                 # #1639 P11: whether the raw captures under `.panopticon/tools/`
                 # went through run_tools' redaction choke point, so a reader
                 # about to copy that directory into a CI artifact learns it from
                 # the run's own marker. COPIED from the runner's manifest, never
                 # asserted here (F5): the runner is what observed the pass, and
                 # a literal in this module would keep claiming it after the
                 # choke point was removed. No manifest, no claim. Additive, and
                 # only on the branch that ran a scan -- the `--no-tools` marker
                 # above writes no capture and so says nothing about files it did
                 # not produce.
                 "redacted": bool(tool_manifest.get("redacted")),
                 # F1: which INVOCATION attempted this scan. `tools_done` reads
                 # it back to decide whether an environmental skip has already
                 # been retried on this pass.
                 "attempt_invocation": manifest.get("invocation")})
    if crashed:
        sys.stderr.write("driver: tool scan CRASHED (rc=%s) — %s\n"
                         % (proc.returncode, note))
    elif not produced:
        sys.stderr.write("driver: tool scan produced no output — %s\n" % note)
    return engine.PhaseResult(kind="advanced",
                       message="tools: %s" % (
                           "produced output" if produced
                           else ("CRASHED — " + note if crashed
                                 else "SKIPPED — " + note)))
