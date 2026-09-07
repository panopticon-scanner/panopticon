"""Phase 3 -- tools: run the SAST/SCA adapters and ingest their findings."""
import os
import sys

from . import engine
from . import runio


def tools_done(review_root, manifest):
    return runio._json_parses(runio._pano(review_root, "tools-ran.json"))

def tools_execute(review_root, manifest):
    if (manifest.get("flags") or {}).get("tools") is False:
        runio._write_json(runio._pano(review_root, "tools-ran.json"),
                    {"schema_version": 1, "ran": False, "skipped": True, "crashed": False,
                     "note": "tools disabled (--no-tools)",
                     "returncode": None, "run_id": manifest["run_id"]})
        return engine.PhaseResult(kind="advanced", message="tools: skipped (--no-tools)")
    out_dir = runio._pano(review_root, "tools")
    # #1031: --manifest records the deterministic adapter set (selected/produced/
    # missing) so synthesize can certify tool coverage against what the runner
    # actually resolved, not the scout's advisory tool list.
    cmd = [sys.executable, runio._script("run_tools.py"), "--target", review_root,
           "--out", out_dir, "--deps",
           "--run-id", manifest.get("run_id") or "",   # #17: manifest self-identifies
           "--manifest", runio._pano(review_root, "tools-manifest.json")]
    proc = runio._run_child(cmd, review_root, "tools")
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
                 "run_id": manifest["run_id"]})
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
