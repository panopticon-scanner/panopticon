"""Phase 6 -- synthesize: run synthesize.py as a child and collect host usage."""
import glob as _glob
import datetime
import os
import sys

from scripts import hosts
from . import engine
from . import runio
from . import requests
from . import verify


def synthesize_done(review_root, manifest):
    # §5.1: gate on the durable tag-named report, not the convenience symlink, so
    # resume never depends on symlink creation having succeeded.
    return runio._json_parses(runio._report_out(review_root))

def _collect_host_usage(review_root, manifest):
    """Write `<run_dir>/usage.json` just before synthesize, so meta.cost.tokens
    is populated without the operator having to remember (#calibration-1).

    The D4 channel is host-supplied by design: the driver is a subprocess and
    cannot see per-dispatch token usage. collect_usage.py reads it out of the
    Claude host's own transcripts -- but it only lands in the report if it runs
    BETWEEN the last dispatch and synthesize. On the first external calibration
    run that ordering was left to the operator, who got it wrong, and the run
    reported `tokens: null` until synthesize was re-run by hand.

    Best-effort and non-fatal in every direction: a non-claude host, no
    transcript, a crash, or a timeout all leave usage.json absent, and
    synthesize's `load_run_usage` then reports null exactly as before. An
    absent number stays absent -- this must never be able to fail a run, and
    must never invent a figure.
    """
    if not hosts.declares(manifest.get("host"), hosts.USAGE_LEDGER):
        return None          # other hosts write their own usage.json, or none
    if os.path.isfile(runio._pano(review_root, "usage.json")):
        return None          # already collected (resume) -- never overwrite
    # dirname of a non-top-level artifact IS the per-run folder -- the same
    # directory synthesize resolves as run_dir (dirname of --groups).
    run_dir = os.path.dirname(runio._pano(review_root, "usage.json"))
    # --project-dir locates the HOST SESSION's transcript, so it is the directory
    # the session runs in -- NOT the review root. #calibration-2: these are the
    # same path for a self-scan (every run 1-10), so passing review_root worked
    # until the first EXTERNAL target, where it resolved a transcript slug for
    # the scanned repo, found nothing, and silently reported `tokens: null`
    # again -- reintroducing exactly the gap this wiring removed. The driver
    # process is launched from the session cwd (only its children are chdir'd
    # to review_root), so getcwd() here is that directory.
    # #calibration-4 (gotify): getcwd() is only the session dir when the operator
    # launched the driver FROM it (`driver run <target>`). The equally natural
    # `cd <target> && driver run .` makes getcwd() the scanned repo again, which
    # resolves a transcript slug that does not exist -- rc 1, and meta.cost.tokens
    # silently stays null on a 612M-token run. The driver cannot infer the session
    # root, so let the operator state it; getcwd() remains the default because it
    # is right for the documented invocation.
    session_dir = manifest.get("session_dir") or os.getcwd()
    cmd = [sys.executable, runio._script("collect_usage.py"),
           "--run-dir", run_dir,
           "--project-dir", session_dir]
    # Pass the window explicitly. run-manifest.json is a _TOP_LEVEL artifact, so
    # it does NOT live in run_dir and collect_usage's own manifest lookup would
    # miss it -- falling back to counting the entire session transcript, which
    # bills every earlier run in the same session to this one. The driver holds
    # the manifest, so it is the authoritative source for the start stamp.
    created = manifest.get("created")
    if created:
        cmd += ["--since", created]
    # #1494: bound the window's END too. A floor alone only makes the number
    # reproducible until the NEXT run in the same session -- re-collecting an
    # earlier run afterwards silently bills it for the later run's tokens (fzf
    # read 0.443 B in-run and 0.751 B once ripgrep had run in the same session).
    # Usage is collected at synthesize, after every agent has finished, so "now"
    # is this run's true ceiling and freezes the ledger permanently.
    cmd += ["--until", datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")]
    try:
        proc = runio._run_child(cmd, review_root, "usage", timeout=120)
    except runio.DriverError as exc:
        print("driver: usage collection skipped (%s); meta.cost.tokens stays null"
              % exc, file=sys.stderr, flush=True)
        return None
    if proc.returncode != 0:
        # rc 1 is the documented "no transcript found, wrote nothing" path. Name
        # the directory that was searched and the flag that changes it: the most
        # likely cause is that it is the scanned repo rather than the session,
        # and that is not deducible from "produced nothing".
        print("driver: usage collection produced nothing (rc %d); "
              "meta.cost.tokens stays null. Searched host transcripts for "
              "project-dir %s -- if that is the SCANNED REPO rather than the "
              "directory your host session runs in, re-run with "
              "--session-dir <session root> (or from that directory)."
              % (proc.returncode, session_dir),
              file=sys.stderr, flush=True)
    return proc

def synthesize_execute(review_root, manifest):
    # #5.0-16 fallback: guarantee both integrity artifacts exist once, after
    # review and before synthesize, even when the verify phase was vacuously
    # done (no engaged cell -> verify_execute never ran, so no agent ran either
    # -- the snapshot here still captures authentic post-review bytes). Both are
    # idempotent no-ops when review_execute/verify_execute already wrote them.
    requests._write_driver_plan(review_root, manifest)
    requests._snapshot_review_out_files(review_root, manifest)
    _collect_host_usage(review_root, manifest)
    findings = sorted(_glob.glob(runio._pano(review_root, "findings-*.json")))
    verdicts_dir = runio._pano(review_root, "verdicts")
    os.makedirs(verdicts_dir, exist_ok=True)   # empty in P3 (verify is a no-op)
    report = runio._report_out(review_root)   # §5.1: durable, top-level, tag-named
    flags = manifest.get("flags") or {}
    cmd = [sys.executable, runio._script("synthesize.py"),
           "--out", report,
           "--groups", runio._pano(review_root, "groups.json"),
           "--security", manifest.get("security_mode", "standard"),
           "--run-id", manifest.get("run_id") or "",   # §5.1: X0X report provenance
           "--verdicts-dir", verdicts_dir]
    if (runio._load_json(runio._pano(review_root, "tools-ran.json")) or {}).get("ran"):
        cmd += ["--tools-dir", runio._pano(review_root, "tools")]
        # Pin synthesize's fixture posture to the tool-verify queue's
        # (#5.0-03): both must ingest the SAME tool findings or synthesize
        # could queue one the driver never dispatched a verdict for. Also
        # closes the latent gap where the manifest captured include_fixtures
        # but synthesize_execute never forwarded it.
        if verify._tools_include_fixtures(manifest):
            cmd += ["--include-fixtures"]
    for flag, key in (("--fail-on", "fail_on"), ("--severity", "severity"),
                      ("--gate-scope", "gate_scope")):
        if flags.get(key):
            cmd += [flag, str(flags[key])]
    diff_hunks = runio._pano(review_root, "diff-hunks.json")
    if os.path.isfile(diff_hunks):
        cmd += ["--diff-hunks", diff_hunks]
    if flags.get("diff_context") is not None:
        cmd += ["--diff-context", str(flags["diff_context"])]
    cmd += findings
    proc = runio._run_child(cmd, review_root, "synthesize")
    # A failing gate exits non-zero but still writes the report — that is a valid
    # outcome, not a driver error. Only an ABSENT report is a failure.
    if not runio._json_parses(report):
        raise runio.DriverError("synthesize produced no report.json (rc=%s): %s"
                          % (proc.returncode, runio._redact_output((proc.stderr or proc.stdout)[:400])))
    # §5.1: point the flat compat paths at the latest tag-named report, so every
    # existing reader of report.json / report.json.html resolves it unchanged, and
    # refresh runs/latest. The tag-named files are the durable top-level outputs;
    # the run folder can be cleared without touching them.
    tag = runio._run_tag(review_root)
    if tag:
        try:   # compat symlinks are best-effort; the tag-named report is authoritative
            runio._relink(runio._pano(review_root, "report.json"), f"{tag}-report.json")
            if os.path.exists(f"{report}.html"):
                runio._relink(runio._pano(review_root, "report.json.html"),
                        f"{tag}-report.json.html")
        except OSError:
            pass
        runio._ensure_run_symlinks(review_root)
    return engine.PhaseResult(kind="advanced", message="synthesize: report.json written")
