"""The 5.0 resumable driver: a table-driven phase state machine.

`driver run` advances through PHASES, executing deterministic work itself and
STOPPING at each dispatch checkpoint (writing dispatch-request.json). The phase
cursor is never stored — it is recomputed from disk (`first not-done phase`)
every invocation, so a crash/compaction/interrupt resumes identically. See
docs/superpowers/specs/2026-08-15-panopticon-5.0-driver-skeleton-design.md.
"""
import argparse
import glob as _glob
import os
import shutil
import subprocess
import sys


# #5.0-01: when run directly (`python3 skill/scripts/driver.py run ...`, the
# documented entrypoint) the package roots are not on sys.path, so the
# `import scripts.*` below crash with ModuleNotFoundError. Bootstrap the same
# roots _child_env() puts on PYTHONPATH for subprocesses. Idempotent under
# pytest, whose conftest already provides them.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))                   # skill/scripts
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # skill


import scripts.diff_map as diff_map  # noqa: E402
import scripts.plan_contract as plan_contract  # noqa: E402
import scripts.run_manifest as run_manifest  # noqa: E402
import scripts.phases.engine as engine
import scripts.phases.runio as runio
import scripts.phases.coverage as coverage
import scripts.phases.discovery as discovery
import scripts.phases.tools as tools
import scripts.phases.review as review
import scripts.phases.verify as verify
import scripts.phases.setup as setup
import scripts.phases.synthesize as synthesize
import scripts.phases.validate as validate


_RESET_GLOBS = ("groups.json", "coverage-*.json", "scout-*.json", "tools-ran.json",
                "validate.json",
                "report.json", "dispatch-request.json", "tree-baseline.txt",
                "verify-queue.json", "findings-*.json",
                # #5.0-07: stale delta artifacts must not survive a --reset and
                # silently delta-scope (or content-check) the next run.
                # #5.0-16: the driver's own dispatch plan clears too, so a
                # --reset run re-declares cells from fresh coverage.
                "diff-hunks.json", "out-file-hashes.json",
                "dispatch-plan-driver.json",
                # #1513: the per-cell retry budget is run-scoped -- a --reset
                # must not start with a cell already exhausted.
                "cell-attempts.json")


PHASES = (
    engine.Phase("discovery", "deterministic", discovery.discovery_done, discovery.discovery_execute),
    engine.Phase("coverage", "mixed", coverage.coverage_done, coverage.coverage_execute),
    engine.Phase("tools", "deterministic", tools.tools_done, tools.tools_execute),
    engine.Phase("review", "checkpoint", review.review_done, review.review_execute),
    engine.Phase("verify", "mixed", verify.verify_done, verify.verify_execute),
    engine.Phase("synthesize", "deterministic", synthesize.synthesize_done, synthesize.synthesize_execute),
    engine.Phase("validate", "deterministic", validate.validate_done, validate.validate_execute),
)


def _cli_flags(args):
    if getattr(args, "tools", False) and getattr(args, "no_tools", False):
        raise ValueError("cannot specify both --tools and --no-tools")
    # not `tools`: that name is bound to scripts.phases.tools at module scope,
    # and shadowing it here would make any later use of the module in this
    # function an UnboundLocalError.
    tools_flag = False if getattr(args, "no_tools", False) else (
        True if getattr(args, "tools", False) else None)
    values = {"fail_on": getattr(args, "fail_on", None),
              "severity": getattr(args, "severity", None),
              "gate_scope": getattr(args, "gate_scope", None),
              "diff_context": getattr(args, "diff_context", None),
              "tools": tools_flag,
              "include_fixtures": True if getattr(args, "include_fixtures", False) else None,
              "max_per_group": getattr(args, "max_per_group", None),
              "allow_unenforced": True if getattr(args, "allow_unenforced", False) else None,
              "max_verify": getattr(args, "max_verify", None)}
    return {k: values.get(k) for k in run_manifest._FLAG_KEYS}


def _scope_from_args(args):
    """The {mode,target} scope implied by -f/-d/-g, or None if none was given
    (a bare re-invocation with no scope opinion — mirrors host/security_mode/
    base/flags: None never conflicts in conflicting_flags, and build_manifest
    defaults a None scope to {"mode":"repo","target":None} itself)."""
    if getattr(args, "scope_file", None):
        return {"mode": "file", "target": args.scope_file}
    if getattr(args, "scope_dir", None):
        return {"mode": "directory", "target": args.scope_dir}
    if getattr(args, "scope_group", None):
        return {"mode": "group", "target": args.scope_group}
    if getattr(args, "scope_changed", False):
        return {"mode": "changed", "target": None}
    if getattr(args, "scope_files", None):
        return {"mode": "files", "target": list(args.scope_files)}
    return None


def _clear_run_artifacts(review_root):
    """--reset: clear the current run's working folder (findings / verdicts /
    coverage / scouts / dispatch / ...) so a fresh run starts, while KEEPING the
    durable top-level tag-named report — reset reclaims the scratch, not the
    deliverable (§5.1). NEVER touches groups.yml (the committed matrix) or another
    run's folder/report. MUST run BEFORE the manifest is removed, so the tag still
    resolves; with no/corrupt manifest it degrades to the legacy flat sweep."""
    base = os.path.join(review_root, ".panopticon")
    tag = runio._run_tag(review_root)
    if tag:
        shutil.rmtree(os.path.join(base, "runs", tag), ignore_errors=True)
        # runs/latest now dangles (its target folder is gone) — drop the pointer;
        # report.json is left pointing at the kept durable report.
        try:
            os.remove(os.path.join(base, "runs", "latest"))
        except OSError:
            pass
    # Migration safety: sweep any legacy FLAT run artifacts a pre-5.1 run may have
    # left at top-level. The report.json SYMLINK points at the durable tag-named
    # report and is kept; only a STALE FLAT report.json (a real file — pre-5.1 or
    # a corrupt/orphaned state) is swept, preserving the I1 no-resume-on-stale-data
    # invariant. The tag-named reports themselves are never in _RESET_GLOBS.
    for pat in _RESET_GLOBS:
        for path in _glob.glob(os.path.join(base, pat)):
            if os.path.basename(path) == "report.json" and os.path.islink(path):
                continue
            try:
                os.remove(path)
            except OSError:
                pass
    for sub in ("tools", "verdicts"):
        shutil.rmtree(os.path.join(base, sub), ignore_errors=True)


def build_parser():
    parser = argparse.ArgumentParser(prog="driver")
    sub = parser.add_subparsers(dest="verb", required=True)
    # #1033: `next` was a silent, undifferentiated alias of `run` (run() is
    # already idempotent + resumes from disk), so it's removed rather than kept
    # as a confusing second spelling.
    for verb in ("run",):
        p = sub.add_parser(verb)
        p.add_argument("target", nargs="?", default=".")
        p.add_argument("--host", default=None, choices=["claude", "generic", "gemini"])
        p.add_argument("--security", default=None, choices=["standard", "redteam"])
        p.add_argument("--base", default=None)
        p.add_argument("--pr", type=int, default=None)
        p.add_argument("--reset", action="store_true")
        p.add_argument("--fail-on", default=None)
        p.add_argument("--severity", default=None)
        p.add_argument("--gate-scope", default=None)
        p.add_argument("--diff-context", type=int, default=None)
        tools_group = p.add_mutually_exclusive_group()
        tools_group.add_argument("--tools", action="store_true")
        tools_group.add_argument("--no-tools", action="store_true")
        p.add_argument("--include-fixtures", action="store_true")
        # #1519: on a host that cannot mediate the reviewer Write grant (today,
        # anything but claude), dispatching write-capable cells is refused
        # unless the operator accepts the residual risk here. Anti-drift, so a
        # resume cannot quietly drop the acceptance.
        p.add_argument("--allow-unenforced", action="store_true",
                       help="accept that reviewer Write is unmediated on a "
                            "non-claude host; recorded in unenforced-ack.json")
        # The directory the HOST SESSION runs in, used only to locate its
        # transcripts for the cost ledger. Defaults to cwd (#calibration-4).
        p.add_argument("--session-dir", default=None)
        # Files per review subgroup. Fewer, larger cells cost less in total
        # (per-cell overhead is amortized) at the price of a wider lens per
        # reviewer. Anti-drift: use --reset to change it on an existing run.
        p.add_argument("--max-per-group", type=_positive_int, default=None)
        # AGT-679033153: synthesize has had --max-verify since 5.0, but the
        # driver never registered it and never put it in the flags dict, so
        # `manifest["flags"].get("max_verify")` was None BY CONSTRUCTION on
        # every real run -- the tool-verify cap was reachable only from a
        # hand-built test manifest. The DEFAULT stays uncapped (#18: capping
        # starved tool findings); this only makes it settable.
        p.add_argument("--max-verify", type=_positive_int, default=None)
        scope = p.add_mutually_exclusive_group()
        scope.add_argument("-f", "--file", dest="scope_file", default=None)
        scope.add_argument("-d", "--directory", dest="scope_dir", default=None)
        scope.add_argument("-g", "--group", dest="scope_group", default=None)
        scope.add_argument("-c", "--changes", dest="scope_changed",
                           action="store_true")
        scope.add_argument("--files", dest="scope_files", nargs="+", default=None)
    sp = sub.add_parser("setup")
    sp.add_argument("target", nargs="?", default=".")
    sp.add_argument("--host", default=None, choices=["claude", "generic", "gemini"])
    sp.add_argument("--reset", action="store_true")
    # 5.2 size policy (spec §5.3): files per dispatch unit and the leaf
    # ceiling. Unset = .panopticon/config.json (max_per_group / max_groups),
    # else the defaults (48; max(4, 2 x ceil(code_files / cap))).
    sp.add_argument("--max-per-group", type=_positive_int, default=None)
    sp.add_argument("--max-groups", type=_positive_int, default=None)
    return parser


def _positive_int(text):
    """argparse type for the size flags: `0` would silently fall through to
    the config/default and a negative cap breaks the ceiling formula."""
    try:
        value = int(text)
    except ValueError:
        value = 0
    if value < 1:
        raise argparse.ArgumentTypeError("expected a positive integer, got %r" % text)
    return value


def run(args, runner=subprocess.run, phases=PHASES):
    # #5.0-14: resolving the review root can fail loudly for a --pr run (gh
    # auth/network, a bad PR number, worktree acquisition) — keep it inside the
    # status protocol instead of letting a raw RuntimeError escape run().
    try:
        review_root, worktree, pr_base = runio.resolve_review_root(
            args.target, base=args.base, pr=args.pr, runner=runner)
    except (RuntimeError, ValueError, OSError) as exc:
        return runio._error_status("could not resolve review root: %s" % exc)
    if args.pr is not None:
        # A PR is a changed-files delta by definition. manifest["base"] holds the
        # user's EXPLICIT override only (anti-drift key); the gh-detected PR base
        # flows separately via manifest["pr_base"] -> orchestrator --pr-base, so
        # resolve_base applies its origin/<base> preference (#947 / spec §4 L51).
        base = args.base
        scope = {"mode": "changed", "target": None}
    else:
        base = args.base
        scope = _scope_from_args(args)
    # #5.0-09: verify .panopticon is a real in-repo directory BEFORE any write or
    # delete under it. A committed .panopticon symlink in a hostile target (or PR
    # fork checkout) would otherwise redirect the driver's own reset/manifest/
    # baseline writes outside the repo, because discovery's artifact_root guard
    # runs only later, inside the discovery subprocess.
    try:
        plan_contract.artifact_root(review_root)
    except ValueError as exc:
        if worktree:
            diff_map.release_worktree(worktree, repo=args.target)
        return runio._error_status("unsafe artifact root: %s" % exc)
    if args.reset:
        _clear_run_artifacts(review_root)   # §5.1: resolve the tag before the manifest goes
        run_manifest.reset_run(review_root)
    manifest = run_manifest.load_manifest(review_root)
    if runio._foreign_manifest(manifest, review_root, run_manifest.manifest_path(review_root)):
        # #1093: a target-committed run-manifest.json (foreign review_root) could
        # preset flags to skip tools / force gate:PASS. Drop it and rebuild from
        # the real CLI args, exactly like a corrupt manifest below.
        print("driver: ignoring foreign run-manifest.json (stamped review_root "
              "%r != %r)" % (manifest.get("review_root"), os.path.abspath(review_root)),
              file=sys.stderr, flush=True)
        manifest = None
    if manifest is None:
        # I1: no manifest means no prior run should count — clear any stale
        # derived artifacts so done()-predicates never resume on another run's
        # data (a lost/corrupt manifest, a partially-failed reset, or a
        # pre-existing 4.x groups.json).
        # #5.0-13: load_manifest also returns None for a CORRUPT (present-but-
        # unparseable) manifest — remove it first so write_manifest (write-once)
        # can't raise an uncaught FileExistsError and wedge the run.
        _clear_run_artifacts(review_root)
        run_manifest.reset_run(review_root)
        manifest = run_manifest.build_manifest(
            target=args.target, review_root=review_root,
            host=args.host or runio._DEFAULTS["host"],
            security_mode=args.security or runio._DEFAULTS["security"],
            base=base, flags=_cli_flags(args), worktree=worktree,
            scope=scope, pr=args.pr, pr_base=pr_base)
        run_manifest.write_manifest(review_root, manifest)
    else:
        conflicts = run_manifest.conflicting_flags(
            manifest, host=args.host, security_mode=args.security,
            base=base, flags=_cli_flags(args), scope=scope, pr=args.pr)
        if conflicts:
            return runio._error_status("flag drift (use --reset to start over): "
                                 + "; ".join(conflicts))
    # In-memory only, and deliberately NOT a manifest field: it names where the
    # HOST SESSION runs, which is a property of this invocation rather than of
    # the run, and it feeds nothing but the cost-ledger transcript lookup. Not
    # persisted means it is also not an anti-drift key -- resuming from a
    # different session is normal and must not be reported as drift. A resume
    # that needs it simply passes it again (#calibration-4).
    if getattr(args, "session_dir", None):
        manifest["session_dir"] = os.path.abspath(args.session_dir)
    # #1: a bare re-invocation of an ALREADY-complete run matches every manifest
    # field (conflicting_flags treats a None incoming value as no-conflict), so it
    # would advance straight to "complete" and hand back a possibly-stale report as
    # though it were a fresh scan -- the worst failure mode for a review tool.
    # Refuse loudly and name --reset instead; the durable report stays on disk.
    # (Guarded by `not args.reset`: a --reset run just cleared its derived
    # artifacts, so it can never be already-complete at this point.)
    if not args.reset and engine._first_not_done(phases, review_root, manifest) is None:
        report = runio._pano(review_root, "report.json")
        loc = report if os.path.exists(report) else review_root
        return runio._error_status(
            "run already complete (report at %s) -- use `--reset` to start a new "
            "run" % loc)
    # §5.1: point runs/latest at the active run folder now that the manifest (hence
    # the tag) is established — so the pointer exists throughout the run, not just
    # after synthesize writes the report.
    runio._ensure_run_symlinks(review_root)
    # I2: capture the clean-tree baseline unconditionally and BEFORE the engine
    # runs. Idempotent (returns the existing baseline if present) -> no-op on a
    # normal resume, but self-heals a baseline that a mid-first-run interrupt
    # left missing (which had silently disabled the clean-tree guard).
    validate.capture_tree_baseline(review_root, runner=runner)
    try:
        result = engine.run_engine(review_root, manifest, phases)
    except runio.DriverError as exc:
        return runio._error_status(str(exc))
    if result.get("status") == "complete":
        validate._finalize_worktree(review_root, manifest)
    return result


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.verb == "setup":
        return engine.emit_status(setup.run_setup_flow(args))
    return engine.emit_status(run(args))


if __name__ == "__main__":
    sys.exit(main())
