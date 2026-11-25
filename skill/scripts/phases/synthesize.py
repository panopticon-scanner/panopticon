"""Phase 6 -- synthesize: run synthesize.py as a child and collect host usage."""
import datetime
import json
import os
import stat
import sys

from scripts import hosts
import scripts.config_schema as config_schema
import scripts.loop_progress as loop_progress
import scripts.run_manifest as run_manifest
import scripts.synth.validate_schema as validate_schema_mod
import scripts.redact as redact
import scripts.safe_write as safe_write
import scripts.x0x_report as x0x_report
from . import child
from . import engine
from . import runio
from . import requests
from . import verify_tools


_PENDING = "synthesize-pending.json"


def _usable_report(review_root):
    # §5.1: gate on the durable tag-named report, not the convenience symlink, so
    # resume never depends on symlink creation having succeeded.
    #
    # #1643 ruling 3: and on the report SHAPE, not merely on JSON. This phase
    # validates its own artifact against the published schema and turns a
    # failure into `error` -- but only when it RUNS, and a parse-only predicate
    # let any parseable file at that path skip it entirely. `summary` is the
    # minimum: it is what the gate, certification and every CI consumer read,
    # and build_report writes it on every report it has ever produced.
    report = runio._load_json(runio._report_out(review_root))
    return isinstance(report, dict) and isinstance(report.get("summary"), dict)


def synthesize_done(review_root, manifest):
    # #2930: failed/interrupted attempts can leave a usable-looking old report
    # or an invalid sibling. Presence alone refuses completion, even if the
    # marker is malformed, unreadable, or a dangling link.
    try:
        os.lstat(runio._pano(review_root, _PENDING))
    except FileNotFoundError:
        return _usable_report(review_root)
    except OSError:
        return False  # An unsearchable directory does not establish absence.
    return False


def x0x_failure_disclosure(report_path):
    """Return the bounded status facts for a non-empty X0X failure log."""
    stem = report_path[:-len(".json")] if report_path.endswith(".json") else report_path
    x0x_path = stem + "-x0x.json"
    failure_path = x0x_report.failure_log_path(x0x_path)
    document = runio._load_json(failure_path)
    discarded = document.get("discarded_findings") if isinstance(document, dict) else None
    if not isinstance(discarded, list) or not discarded:
        return None
    count = len(discarded)
    return {
        "count": count,
        "path": failure_path,
        "message": ("X0X discarded %d locus-free catalog-gap finding(s); "
                    "failure log: %s" % (count, failure_path)),
    }


def _regular_file(path):
    """A host acts on what `artifacts` names, so: a regular file, never through a symlink."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except (OSError, ValueError):        # ValueError: a NUL or a lone surrogate in a name
        return False


def _sibling(report_path, name):
    """`name` beside the report, or None. A name out of the report's own meta that is not a bare
    file name is left out, never resolved."""
    if not isinstance(name, str) or not name or "/" in name or "\\" in name or os.sep in name:
        return None
    path = os.path.join(os.path.dirname(report_path), name)
    return path if _regular_file(path) else None


def completion_artifacts(report_path):
    """What a host reading `complete` may open, without a `stat` of its own (#3367): absolute paths
    of the files that exist. Parts and the discarded sibling are the ones the report itself names,
    not a glob, so a file planted beside it is not named."""
    out: dict = {}
    report_path = os.path.abspath(report_path)
    if not _regular_file(report_path):
        return out
    out["report"] = report_path
    report = runio._load_json(report_path)
    meta = report.get("meta") if isinstance(report, dict) else None
    meta = meta if isinstance(meta, dict) else {}
    named = meta.get("parts")
    parts = [path for path in (_sibling(report_path, name)
                               for name in (named if isinstance(named, list) else [])) if path]
    if parts:
        out["parts"] = parts
    discarded = _sibling(report_path, meta.get("discarded_claims_file"))
    if discarded:
        out["discarded"] = discarded
    stem = report_path[:-len(".json")] if report_path.endswith(".json") else report_path
    for key, path in (("x0x", stem + "-x0x.json"), ("html", report_path + ".html")):
        if _regular_file(path):
            out[key] = path
    return out


def complete_status(status, review_root, manifest):
    """The terminal `complete` status, for `driver.run` and so for the loop: what it produced, and
    the manifest's `completed_at` for a reader who has only the manifest. It marks success alone,
    so a run that ended `error` or `paused` still reads as unfinished there. Neither step can mask
    the status: a name that can't be a file is left out, and a failed write goes in its message."""
    report_path = runio._report_out(review_root)
    status = attach_x0x_failure_status(status, report_path)
    if status.get("status") != "complete":
        return status
    status = dict(status, artifacts=completion_artifacts(report_path))
    try:
        run_manifest.record_completed_at(review_root, manifest)
    except (OSError, ValueError) as exc:
        status["message"] = "%s; completed_at not recorded: %s" % (
            status.get("message"), redact.redact_diagnostic(str(exc), 200))
    return status


def attach_x0x_failure_status(status, report_path):
    """Persist a completed synthesize disclosure in the terminal run status."""
    if status.get("status") != "complete":
        return status
    disclosure = x0x_failure_disclosure(report_path)
    if not disclosure:
        return status
    return dict(
        status,
        x0x_discarded=disclosure["count"],
        x0x_failure_log=disclosure["path"],
        message="%s; %s" % (status.get("message"), disclosure["message"]),
    )

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
    # NO "claude" default, deliberately -- unlike the six other posture sites,
    # which read `manifest.get("host", "claude")`. A manifest with no host key
    # is one this driver did not write, and collecting a token ledger off the
    # local Claude transcripts for a run whose host is unstated would invent a
    # figure rather than report one. Add the default and such a run silently
    # starts billing itself against transcripts that may not be its own;
    # test_a_host_less_manifest_does_not_collect_usage pins the absence,
    # because the suite alone will not.
    if (hosts.posture(manifest.get("host"), runio.host_evidence(review_root))
            [hosts.USAGE_LEDGER] != hosts.PROVEN):
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
    # runio.session_dir is the SINGLE source (C2): probes.claude.probe_usage_source
    # gates this collection off the same expression, so the two cannot drift
    # into asking about different transcripts again.
    session_dir = runio.session_dir(manifest)
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
        proc = child._run_child(cmd, review_root=review_root, phase="usage", timeout=120)
    except runio.DriverError as exc:
        print("driver: usage collection skipped (%s); meta.cost.tokens stays null"
              % exc, file=sys.stderr, flush=True)
        return None
    if proc.returncode == 0 and proc.stderr:
        print(proc.stderr, file=sys.stderr,
              end="" if proc.stderr.endswith("\n") else "\n", flush=True)
    if proc.returncode not in (0, 1):
        # #3706: any other exit is the collector's own refusal, and it said why. The
        # advice below is for "no transcript found" and would be the wrong remedy.
        print("driver: usage collection failed (rc %d): %s; meta.cost.tokens stays null"
              % (proc.returncode, redact.redact_diagnostic(str(proc.stderr or "").strip(), 400)),
              file=sys.stderr, flush=True)
    elif proc.returncode != 0:
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

def _plan_owed(manifest):
    """Did this run's driver WRITE a dispatch plan (SEC-377944137, #1832)?

    If it did, an absent `dispatch-plan-driver.json` at synthesis is DELETED
    EVIDENCE, not an unmeasured run -- which is #1208's reasoning for the
    fan-out snapshot, applied to the file that decides whether the snapshot is
    owed at all. Deleting the plan silenced every check keyed on it at once
    (the planned-vs-ingested reconciliation, the out_file-collision check, the
    snapshot obligation and the fan-out accounting), so one more `rm` turned a
    DETECTED findings substitution back into `integrity_ok=True`.

    Read off `run_manifest.DRIVER_PLAN` -- the MONOTONE stamp
    `requests._write_driver_plan` writes as it writes the plan. Fix round 1
    replaced an inference off the rolling `dispatch_request` slot, which could
    not answer this: that slot is overwritten per checkpoint, so it read
    `verify` on every run that verified anything; the tamper itself could roll
    it BACKWARD to `scout` (deleting `coverage-<group>.json` makes
    `coverage_done` False and the coverage phase re-dispatches scout); and it
    could not tell a tool-advisor `verify` dispatch from a review one, so an
    honest ZERO-CELL run that verified a tool finding read INCONCLUSIVE.

    The manifest is the anchor rather than the plan, because a plan cannot
    attest to its own existence, and this is the better-defended of the two
    files (#1727) -- better-defended, NOT out of reach. It lives in the
    reviewed tree, and the "no dispatched agent may write `run-manifest.json`"
    half is host-conditional: it holds where the write guard mediates `Write`
    (its allowlist is the entries' out_files), so on `--host generic
    --allow-unenforced` -- the unmediated host whose rogue advisor
    `_snapshot_review_out_files` names as its own threat -- deleting the stamp
    is one unmediated `Write` and restores the benign reading. What is
    unconditional is that forging it is a SECOND, separate write, and that
    first contact halts on a manifest that is git-tracked in the reviewed
    tree or not stamped by this machine for it (#3271). The same is true of #1727's
    own `dispatch_request` anchor.

    Fails OPEN by design in exactly one case, which is the same case every
    other key in `meta.integrity` treats as "not measured": no stamp at all.
    That is a direct `synthesize.py` invocation over hand-collected findings, a
    run that never declared a cell, or one resumed across this upgrade --
    none of them ever wrote a plan under this rule. It must NOT be inferred
    from the findings files present: that would let the same writer manufacture
    the obligation away.
    """
    return run_manifest.artifact_stamp(manifest, run_manifest.DRIVER_PLAN) is not None


#: What the synthesize child exits with when it has published a report: the three gate
#: outcomes (PASS, FAIL, INCONCLUSIVE) and an artifact that failed its own validation,
#: which this phase reports beside the report it points at (#1639 P15).
_PUBLISHED_STATUSES = (0, 1, 2, validate_schema_mod.ARTIFACT_INVALID)


_LINE_BOUND = 400
_CUT = " [...] "


def _last_line(*streams):
    """The last line a child printed, redacted and bounded: its reason for stopping.
    The lines before it are whatever it had to say on the way there. From the first
    of `streams` that holds a line.

    The line WHOLE when it fits. Over the bound its middle is cut and marked, never its
    start: the start says who is speaking and why, and the end is where a path-heavy
    line puts its reason (#3741; a tail of the stream began mid-word when the path was
    long).

    The STREAM is redacted first, and the line is taken from what is left. A secret can
    span lines (a private key), and redacting only the last line would publish its
    last line: the key's own text, with no header beside it to mask it by."""
    for stream in streams:
        text = str(stream or "")
        lines = [line for line in redact.redact_diagnostic(
            text, len(text) + _LINE_BOUND).splitlines() if line.strip()]
        if lines:
            line = lines[-1].strip()
            if len(line) <= _LINE_BOUND:
                return line
            keep = _LINE_BOUND - len(_CUT)
            return line[:keep - keep // 2] + _CUT + line[len(line) - keep // 2:]
    return "it said nothing"


def link_flat_names(review_root, report=None):
    """Point `.panopticon/report.json` and `report.json.html` at this run's tag-named
    report, and `runs/latest` at its folder (§5.1). Best-effort, as it always was: the
    tag-named report is the authoritative one. Returns whether the flat names now lead
    to this run's report (True with no tag, where the report IS the flat name).

    #3741: called again by a run that finds itself already complete. A link that failed
    when synthesis ended (a full disk) was never retried, so the documented path stayed
    missing, or stayed on an older run's report, while every later run said "already
    complete". A name that is already right is not written again."""
    tag = runio._run_tag(review_root)
    if not tag:
        return True
    report = report or runio._report_out(review_root)
    wanted = [("report.json", f"{tag}-report.json")]
    if os.path.exists(f"{report}.html"):
        wanted.append(("report.json.html", f"{tag}-report.json.html"))
    linked = True
    for name, target in wanted:
        link = runio._pano(review_root, name)
        try:   # compat symlinks are best-effort; the tag-named report is authoritative
            if not (os.path.islink(link) and os.readlink(link) == target):
                runio._relink(link, target)
        except OSError:
            linked = False
    runio._ensure_run_symlinks(review_root)
    return linked


#: Where an earlier attempt's published files go, in the run folder (#3769).
_EARLIER = "earlier-attempt"
#: The two flat names a reader of "the latest report" opens (§5.1).
_FLAT = ("report.json", "report.json.html")


def _published_at(report):
    """Every name the child publishes at whenever it publishes `report`: the report, its
    page, the X0X and the X0X failure log."""
    stem = report[:-len(".json")] if report.endswith(".json") else report
    x0x = stem + "-x0x.json"
    return (report, report + ".html", x0x, x0x_report.failure_log_path(x0x))


def _what_is_at(path):
    """`path`'s own `lstat`, or None when nothing is there. Only "no such file" is
    nothing: any other failure to look stops the attempt (#3774). Read as absent, one
    EIO left an earlier report where it was, to be taken for this attempt's."""
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise runio.DriverError("synthesize could not look at %s: %s" % (
            os.path.basename(path), redact.redact_diagnostic(str(exc), 400))) from exc


def _not_set_aside(path, reason):
    return runio.DriverError("synthesize could not set aside an earlier attempt's %s: %s"
                             % (os.path.basename(path), redact.redact_diagnostic(reason, 400)))


def _clear_for_this_attempt(review_root, report):
    """Leave nothing at the names a report is read from, before the child runs. A report
    found afterwards is then this child's: the child can die with any status, a gate's
    1 or 2 included, and leave nothing to be taken for its own (#3769).

    First the flat links go, whatever they point at: another run's report (#3778) or
    an earlier attempt's. They go before anything is moved, so a move that fails
    leaves no flat path on an old verdict (#3774). Then what an earlier attempt
    published, and a regular file at a flat name, are moved into the run folder: kept,
    under names no reader takes for a report. Anything that cannot be looked at,
    removed or moved, or is still there afterwards, stops the attempt before the child.

    Only a regular file is an attempt's. A link, a directory or a FIFO at a name the
    child publishes at is left as it is for the child, which refuses it by name, and
    `synthesize_execute` takes no report through one."""
    published = _published_at(report)
    # Without a manifest the flat names are the child's own, and it judges them.
    flat = [path for path in (runio._pano(review_root, name) for name in _FLAT)
            if path not in published]
    for link in flat:
        found = _what_is_at(link)
        if found is not None and stat.S_ISLNK(found.st_mode):
            try:
                safe_write.remove_artifact(link)
            except OSError as exc:
                raise runio.DriverError("synthesize could not remove the flat %s: %s" % (
                    os.path.basename(link), redact.redact_diagnostic(str(exc), 400))) from exc
    aside = runio._pano(review_root, _EARLIER)
    for path in (*flat, *published):
        found = _what_is_at(path)
        if found is None or not stat.S_ISREG(found.st_mode):
            continue
        safe_write.confine_artifact_path(aside)
        try:
            os.makedirs(aside, exist_ok=True)
            os.replace(path, os.path.join(aside, os.path.basename(path)))
        except OSError as exc:
            raise _not_set_aside(path, str(exc)) from exc
        if _what_is_at(path) is not None:
            raise _not_set_aside(path, "it is still there after the move to %s" % aside)


def synthesize_execute(review_root, manifest):
    # #5.0-16 fallback: guarantee both integrity artifacts exist once, after
    # review and before synthesize, even when the verify phase was vacuously
    # done (no engaged cell -> verify_execute never ran, so no agent ran either
    # -- the snapshot here still captures authentic post-review bytes). Both are
    # idempotent no-ops when review_execute/verify_execute already wrote them.
    #
    # SEC-377944137 (#1832) C1: a FIRST write only. Once this run has written
    # either artifact the manifest stamps it, and both writers then REPORT its
    # absence instead of repairing it (`run_manifest.claim_artifact`) -- these
    # two lines re-created a deleted plan and re-took the snapshot over
    # substituted findings bytes, which is how the substitution became its own
    # baseline and #1208's guard stopped firing. `_plan_owed` below is the same
    # stamp, so what this phase declines to repair is exactly what it reports.
    requests._write_driver_plan(review_root, manifest)
    requests._snapshot_review_out_files(review_root, manifest)
    _collect_host_usage(review_root, manifest)
    # #1681 Plan 2: the config resolution, copied out of the manifest into the
    # run folder so the synthesize CHILD can read it. run-manifest.json is a
    # _TOP_LEVEL artifact and therefore not under the `--run-dir` every other
    # run artifact resolves against, and a direct `synthesize.py` invocation
    # legitimately has no driver to ask -- the same reasoning that threads
    # `--tools-disabled-mid-run` through instead of re-reading the manifest.
    runio._write_json(runio._pano(review_root, config_schema.RESOLUTION_NAME),
                      config_schema.resolution_document(manifest))
    findings = runio._findings_files(review_root)
    verdicts_dir = runio._pano(review_root, "verdicts")
    os.makedirs(verdicts_dir, exist_ok=True)   # empty in P3 (verify is a no-op)
    report = runio._report_out(review_root)   # §5.1: durable, top-level, tag-named
    flags = manifest.get("flags") or {}
    # Keep the operator's original target for PR scans: review_root can be a
    # temporary worktree with a different name. abspath normalizes trailing
    # separators and dot paths without probing the target or exposing its path.
    target_path = manifest.get("target") or review_root
    target_name = os.path.basename(os.path.abspath(target_path)) or os.path.sep
    cmd = [sys.executable, runio._script("synthesize.py"),
           "--out", report,
           "--groups", runio._pano(review_root, "groups.json"),
           "--target=" + target_name,  # = keeps leading '-' in the value
           "--root=" + review_root,
           "--security", manifest.get("security_mode", "standard"),
           "--run-id", manifest.get("run_id") or "",   # §5.1: X0X report provenance
           "--verdicts-dir", verdicts_dir]
    # #1740 fix round 1: the committed `exclude_paths:` policy reaches the
    # TOOL ingest too, not only discovery -- under `--security redteam` a
    # fixture-corpus or vendored drop is counted toward THIS report's gate, so
    # without this the committed policy could not scope that gate at all. The
    # tools phase passes the same globs to `run_tools --exclude`.
    for glob in runio.committed_exclude_paths(review_root):
        cmd += ["--tools-exclude", glob]
    tool_marker = (runio._load_json(
        runio._pano(review_root, "tools-ran.json")) or {})
    if tool_marker.get("ran") or "outputs" in tool_marker:
        cmd += ["--tools-dir", runio._pano(review_root, "tools")]
        # Pin synthesize's fixture posture to the tool-verify queue's
        # (#5.0-03): both must ingest the SAME tool findings or synthesize
        # could queue one the driver never dispatched a verdict for. Also
        # closes the latent gap where the manifest captured include_fixtures
        # but synthesize_execute never forwarded it.
        if verify_tools._tools_include_fixtures(manifest):
            cmd += ["--include-fixtures"]
    elif flags.get("tools") is False:
        # #3197: the operator's `--no-tools` -- off the controller's manifest,
        # never the target-writable marker. A scan that DID run keeps its
        # marker (`tools_done` stops at `ran`), so it takes the branch above
        # even after a mid-run downgrade; this one has no output of its own on
        # disk, so whatever is there is listed as unbound, never ingested.
        cmd += ["--tools-dir", runio._pano(review_root, "tools"), "--tools-skipped"]
    # #1637 P08 F2: the mid-run `--no-tools` rescue is a real downgrade of what
    # this run's later panels were shown, so the report says so. Threaded from
    # the manifest the driver is already holding rather than re-read from disk
    # by the child: run-manifest.json is a TOP_LEVEL artifact, so it is not
    # under the `--run-dir` every other run artifact resolves against, and a
    # direct `synthesize.py` invocation legitimately has no driver to ask.
    if run_manifest.tools_downgraded_mid_run(manifest):
        cmd += ["--tools-disabled-mid-run"]
    # #3271 (ruling D2): first contact found a stamped run by ANOTHER host here.
    prior = (manifest.get("first_contact") or {}).get("prior_run")
    if isinstance(prior, dict):
        cmd += ["--prior-run", "%s:%s" % (prior.get("host"), prior.get("run_id"))]
    # #3560: the scanned tree's provenance (#1492), threaded for the same reason, so a
    # cross-run comparison can check it off the report. Each is passed only when recorded.
    if isinstance(manifest.get("target_commit"), str):
        cmd += ["--target-commit", manifest["target_commit"]]
    if isinstance(manifest.get("target_dirty"), bool):
        cmd += ["--target-dirty", "true" if manifest["target_dirty"] else "false"]
    # #3651: where the matrix came from, by the same route and for the same reason. Each is
    # passed only when recorded; the child pins every value to its vocabulary.
    matrix = manifest.get(run_manifest.MATRIX)
    if isinstance(matrix, dict):
        for flag, key in (("--matrix-origin", "origin"),
                          ("--matrix-config-sha256", "config_sha256"),
                          ("--matrix-setup-draft", "setup_draft")):
            if isinstance(matrix.get(key), str) and matrix[key]:
                cmd += [flag, matrix[key]]
    # #3582: whether this run's model fallbacks were off, for the report's disclosure.
    if isinstance(manifest.get("model_strict"), bool):
        cmd += ["--model-strict", "true" if manifest["model_strict"] else "false"]
    # SEC-377944137 (#1832): threaded rather than re-read by the child for the
    # reason above, and for one more -- `synth/` must not import
    # `scripts.run_manifest`, so the stamp's two facts cross the seam, not the
    # manifest. The hash only STRENGTHENS the boolean (a present-but-replaced
    # plan is tamper too), so a stamp without one still owes the plan -- the
    # #493 R2 unenforced ack reads its own `plan_sha256` exactly that way.
    if _plan_owed(manifest):
        cmd += ["--plan-owed"]
        stamped = run_manifest.artifact_stamp(manifest, run_manifest.DRIVER_PLAN)
        if isinstance(stamped.get("sha256"), str) and stamped["sha256"]:
            cmd += ["--plan-sha256", stamped["sha256"]]
    # #2115: the snapshot cannot attest to its own bytes. Its writer returned
    # this digest to the manifest stamp; the child compares the on-disk file.
    snapshot = run_manifest.artifact_stamp(manifest, run_manifest.OUT_FILE_SNAPSHOT) or {}
    if isinstance(snapshot.get("sha256"), str) and snapshot["sha256"]:
        cmd += ["--snapshot-sha256", snapshot["sha256"]]
    # #2013: which of the TARGET's own Git driver commands the probe emptied for
    # this scan, threaded rather than re-read for the reason above --
    # run-manifest.json is a _TOP_LEVEL artifact, outside the `--run-dir` the
    # child resolves against. Omitted when there is nothing to disclose. A
    # manifest predating the field and a clean target are therefore
    # INDISTINGUISHABLE downstream (both `[]`, review M4) -- the collapse is
    # reachable only on a run resumed across this upgrade, and the published
    # field's description says what it does and does not claim rather than
    # pretending the two are told apart.
    drivers = manifest.get("git_drivers_suppressed")
    if drivers:
        cmd += ["--git-drivers-suppressed", json.dumps(drivers)]
    # #3736: a committed `gate_scope:` and a `diff-hunks.json` left in the run folder
    # reach no child. Delta review is gone, and the child would refuse both flags.
    for flag, key in (("--fail-on", "fail_on"), ("--severity", "severity")):
        if flags.get(key):
            cmd += [flag, str(flags[key])]
    if flags.get("max_verify") is not None:
        cmd += ["--max-verify", str(flags["max_verify"])]
    cmd += findings
    pending = runio._pano(review_root, _PENDING)
    try:
        runio._write_json(pending, {"run_id": manifest.get("run_id")})
    except OSError as exc:
        raise runio.DriverError("synthesize could not write pending marker: %s" %
                               redact.redact_diagnostic(str(exc), 400)) from exc
    # #3769: after the marker, so an attempt stopped here is still owed.
    _clear_for_this_attempt(review_root, report)
    proc = child._run_child(cmd, review_root=review_root, phase="synthesize")
    # #3706: a status the child returns only when it has published a report is the one
    # kind this phase may look for a report after. Any other (3 is "invalid input": a
    # scope it refuses, a directory it could not list) is a child that wrote none.
    # Raised before the relink below, with the marker left: the attempt is still owed.
    if proc.returncode not in _PUBLISHED_STATUSES:
        raise runio.DriverError("synthesize wrote no report (rc=%s): %s"
                                % (proc.returncode, _last_line(proc.stderr, proc.stdout)))
    # Gate failures still publish usable reports. Keep the report-shape check
    # shared with done(), but independent of the pending marker: a successful
    # retry must validate its output before clearing that marker (#2930).
    written = _what_is_at(report)
    if not (written is not None and stat.S_ISREG(written.st_mode)
            and _usable_report(review_root)):
        # #3741: the LAST LINE it said. The first 400 characters are its warnings; its
        # reason for stopping is the last thing it printed.
        raise runio.DriverError("synthesize produced no usable report.json (rc=%s): %s"
                          % (proc.returncode, _last_line(proc.stderr, proc.stdout)))
    loop_progress.relay_summary(proc.stdout)      # #3232: `loop` only; the child stdout is captured
    # §5.1: point the flat compat paths at the latest tag-named report, so every
    # existing reader of report.json / report.json.html resolves it unchanged, and
    # refresh runs/latest. The tag-named files are the durable top-level outputs;
    # the run folder can be cleared without touching them.
    #
    # #1639 P15 I3: this runs for ANY run that produced a parseable report --
    # before the artifact-invalid raise below, not after. Raising first left
    # `.panopticon/report.json`, the documented backward-compat path, pointing
    # at the PREVIOUS run's report: complete, valid, possibly PASS. A CI
    # consumer reading that path after a failed run read someone else's result
    # and had no way to tell. This run's report is on disk and is the honest
    # thing to point at; the `error` status beside it, carrying the schema-error
    # COUNT, is what says not to trust it. (The count is the discriminator, not
    # `meta.schema_errors`: an x0x-only failure leaves that field at 0 in a
    # report.json that is itself valid -- the invalid artifact is the other
    # file, and only the status says so.)
    link_flat_names(review_root, report)
    # #1639 P15 / #2952: the one non-gate non-zero status. The report parses —
    # that is why the guard above cannot see this — but an artifact could not
    # be published/removed or the report, hydrated parts, or X0X sibling does
    # not satisfy its schema. Artifact validity is not coverage certification
    # and not a gate verdict, so it ends the run in `error` rather than being
    # absorbed as one.
    if proc.returncode == validate_schema_mod.ARTIFACT_INVALID:
        raise runio.DriverError(
            "synthesize could not publish or validate an artifact "
            "(rc=%s): %s" % (proc.returncode,
                             redact.redact_diagnostic(proc.stderr or proc.stdout, 400, tail=True)))
    disclosure = x0x_failure_disclosure(report)
    message = "synthesize: report.json written"
    if disclosure:
        print("driver: %s" % disclosure["message"], file=sys.stderr, flush=True)
        message += "; " + disclosure["message"]
    try:
        safe_write.remove_artifact(pending)  # confines the parent before unlink
    except OSError as exc:
        raise runio.DriverError("synthesize could not clear pending marker: %s" %
                               redact.redact_diagnostic(str(exc), 400)) from exc
    return engine.PhaseResult(kind="advanced", message=message)
