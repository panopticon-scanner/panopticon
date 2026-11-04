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
import re
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


import scripts.config_schema as config_schema  # noqa: E402
import scripts.diff_map as diff_map  # noqa: E402
import scripts.first_contact as first_contact  # noqa: E402
import scripts.run_manifest as run_manifest  # noqa: E402
from scripts import hosts, loop_progress, plan_contract, procgroup  # noqa: E402
from scripts.host_posture import (  # noqa: E402,F401 -- compatibility names for #3402
    _carry_output_schema_shape, _disclose_posture, _emit_posture_disclosure,
    _establish_host_posture, _gating_states, _posture_drift, _surface_refusal,
)
import scripts.money as money  # noqa: E402
import scripts.model_resolver as model_resolver  # noqa: E402
import scripts.setup_config as setup_config  # noqa: E402
import scripts.phases.engine as engine
import scripts.phases.runio as runio
import scripts.phases.coverage as coverage
import scripts.phases.discovery as discovery
import scripts.phases.readiness as readiness
import scripts.phases.tools as tools
import scripts.phases.review as review
import scripts.phases.verify as verify
import scripts.phases.setup as setup
import scripts.phases.synthesize as synthesize
import scripts.phases.validate as validate


_RESET_GLOBS = ("groups.json", "coverage-*.json", "scout-*.json", "tools-ran.json",
                "validate.json",
                "report.json", "dispatch-request.json",
                # #1809: the trailing `*` sweeps a `tree-baseline.txt.tmp` orphaned by a SIGKILL
                # between the staging open and the replace -- --reset is the corrupt-baseline remedy.
                "tree-baseline.txt*",
                "verify-queue.json", "findings-*.json",
                # #5.0-07: stale delta artifacts must not survive a --reset and silently delta-scope
                # (or content-check) the next run. #5.0-16: the driver's own dispatch plan clears
                # too, so a --reset run re-declares cells from fresh coverage.
                "diff-hunks.json", "out-file-hashes.json",
                "dispatch-plan-driver.json",
                # #1637 P08: the readiness verdict and the per-cell
                # scanner-context tally are both run-scoped facts -- a --reset
                # must not resume on the previous run's answer to either.
                "readiness.json", "panel-tools-context.json",
                # #1638 P13: the per-group test-inventory verdict is derived
                # from THIS run's assignment, so a --reset that re-discovers
                # must not resume on the previous run's answer either.
                "panel-test-inventory.json",
                # #1513: the per-cell retry budget is run-scoped -- a --reset
                # must not start with a cell already exhausted.
                # #1809: its three siblings are run-scoped for the same
                # reason, and an unreadable one now names --reset as the
                # remedy, so the legacy flat sweep has to actually clear them
                # (`scout-*.json` already covers the scout counter, and
                # discovery-attempts.json's own docstring already claimed it).
                "cell-attempts.json", "verify-attempts.json",
                "discovery-attempts.json")


# How many exhausted cells the terminal `complete` message names before it
# says "and N more" (the count beside it is always exact).
_EXHAUSTED_NAMED = 10


# #1637 P08 (owner ruling D7): `readiness` leads. `coverage` is the first
# checkpoint that SPENDS anything, and everything before it is deterministic
# and cheap -- so the one place a scanner-environment verdict can be both
# authoritative and free is at the head of this table, ahead of `discovery`.
PHASES = (
    engine.Phase("readiness", "deterministic", readiness.readiness_done, readiness.readiness_execute),
    engine.Phase("discovery", "deterministic", discovery.discovery_done, discovery.discovery_execute),
    engine.Phase("coverage", "mixed", coverage.coverage_done, coverage.coverage_execute),
    engine.Phase("tools", "deterministic", tools.tools_done, tools.tools_execute),
    engine.Phase("review", "checkpoint", review.review_done, review.review_execute),
    engine.Phase("verify", "mixed", verify.verify_done, verify.verify_execute),
    engine.Phase("synthesize", "deterministic", synthesize.synthesize_done, synthesize.synthesize_execute),
    engine.Phase("validate", "deterministic", validate.validate_done, validate.validate_execute),
)


def _resolve_config(args, review_root=None):
    """This invocation's `settings:` resolution (#1681 Plan 2, spec §4).

    One read, one ratchet, one printing: `run()` calls this ONCE and hands
    the result to both `_cli_flags` and `build_manifest`, so the operator
    sees each refusal exactly once and the manifest records the same answer
    the run acts on.

    The two store_true flags need translating before the ratchet can compare
    them: argparse spells "the operator said nothing" as False for
    `--tools` / `--no-tools` / `--include-fixtures`, and False is a VALUE to
    `resolve_settings` (it means "the command line chose"), so an untouched
    flag has to arrive as None.
    """
    if not review_root:
        return config_schema.EMPTY
    cli = {key: getattr(args, key, None) for key in config_schema.CLASS_OF}
    cli["tools"] = (False if getattr(args, "no_tools", False)
                    else True if getattr(args, "tools", False) else None)
    cli["include_fixtures"] = True if getattr(args, "include_fixtures", False) else None
    resolution = config_schema.resolve_settings(
        cli, runio.committed_settings(review_root))
    for line in resolution.disclosures:
        print("driver: %s" % line, file=sys.stderr, flush=True)
    return resolution


def _cli_flags(args, review_root=None, resolution=None):
    if getattr(args, "tools", False) and getattr(args, "no_tools", False):
        raise ValueError("cannot specify both --tools and --no-tools")
    # not `tools`: that name is bound to scripts.phases.tools at module scope,
    # and shadowing it here would make any later use of the module in this
    # function an UnboundLocalError.
    tools_flag = False if getattr(args, "no_tools", False) else (
        True if getattr(args, "tools", False) else None)
    # #1681 Plan 2: CLI > the config's EFFECTIVE contribution > the engine's
    # default. `cfg` holds only what survived the trust classes -- a clamped
    # grain value, a gate value at least as strict as the built-in default --
    # so an operator-only key or a loosening gate key cannot reach a flag at
    # all. The manifest's anti-drift keys compare EFFECTIVE values, which is
    # what this records: a config edit mid-run drifts exactly like a flag edit.
    cfg = (resolution if resolution is not None
           else _resolve_config(args, review_root)).effective
    values = {"fail_on": getattr(args, "fail_on", None) or cfg.get("fail_on"),
              "severity": getattr(args, "severity", None) or cfg.get("severity"),
              "gate_scope": getattr(args, "gate_scope", None) or cfg.get("gate_scope"),
              "diff_context": getattr(args, "diff_context", None),
              "tools": tools_flag if tools_flag is not None
                       else (True if cfg.get("tools") else None),
              "online": True if getattr(args, "online", False) else None,
              "allow_target_build": True if getattr(args, "allow_target_build", False) else None,
              "include_fixtures": True if (getattr(args, "include_fixtures", False)
                                           or cfg.get("include_fixtures")) else None,
              "max_per_group": getattr(args, "max_per_group", None)
                               if getattr(args, "max_per_group", None) is not None
                               else cfg.get("max_per_group"),
              "allow_unenforced": True if getattr(args, "allow_unenforced", False) else None,
              "max_verify": getattr(args, "max_verify", None)
                            if getattr(args, "max_verify", None) is not None
                            else cfg.get("max_verify")}
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
    deliverable (§5.1). NEVER touches the committed root config — since #1681
    the matrix lives outside `.panopticon/` entirely — or another run's
    folder/report. MUST run BEFORE the manifest is removed, so the tag still
    resolves; with no/corrupt manifest it degrades to the legacy flat sweep.
    Both callers run after first contact (#3271), which vetted `.panopticon/`
    and every manifest in it."""
    base = os.path.join(os.path.abspath(review_root), plan_contract.ARTIFACT_DIR)
    manifest = run_manifest.load_manifest(review_root)
    tag = run_manifest.run_tag(manifest) if manifest else None
    # Defense at the deletion boundary, independent of the tag producer.
    if tag is not None and (not isinstance(tag, str) or
                            re.fullmatch(r"[A-Za-z0-9-]{1,220}", tag) is None):
        raise runio.DriverError("refusing cleanup with unsafe run tag")

    # Collect and vet EVERY destination before the first removal. A linked
    # `runs` parent must never redirect the active folder or `latest` unlink.
    run_dir = os.path.join(base, "runs", tag) if tag else None
    latest = os.path.join(base, "runs", "latest")
    paths = []
    # Migration safety: sweep any legacy FLAT run artifacts a pre-5.1 run may have left at top-level.
    # The report.json SYMLINK points at the durable tag-named report and is kept; only a STALE FLAT
    # report.json (a real file -- pre-5.1 or a corrupt/orphaned state) is swept, preserving the I1
    # no-resume-on-stale-data invariant. The tag-named reports themselves are never in _RESET_GLOBS.
    for pat in _RESET_GLOBS:
        for path in _glob.glob(os.path.join(base, pat)):
            if os.path.basename(path) == "report.json" and os.path.islink(path):
                continue
            paths.append(path)
    dirs = [os.path.join(base, sub) for sub in ("tools", "verdicts")]
    candidates = [run_dir, latest] + paths + dirs if run_dir else paths + dirs
    for path in candidates:
        runio._confine_link_parent(path)

    def remove_dir(path):
        if os.path.islink(path):
            os.unlink(path)  # remove only the final link, never its referent
        elif os.path.isdir(path):
            shutil.rmtree(path)

    if run_dir:
        remove_dir(run_dir)
        if os.path.lexists(latest):
            os.unlink(latest)
    for path in paths:
        if os.path.isdir(path) and not os.path.islink(path):   # #2095: the tree's, never ours
            print("driver: --reset left %s alone: a directory is never a run artifact of ours"
                  % path, file=sys.stderr, flush=True)
            continue
        os.remove(path)
    for path in dirs:
        remove_dir(path)


def hosts_runner_modes():
    """The `--mode` choices for `driver loop`: a literal tuple, not derived by
    importing scripts.runners.base at driver module scope (that package is
    host machinery loaded lazily; driver.py's own import graph must not gain a
    dependency on it merely to spell two strings). Pinned against
    runners_base.MODES by a parity test in Task 6."""
    return ("headless", "session")


def _host_choice(text):
    """argparse `type` for every `--host`: a remedy instead of a word list.

    argparse runs `type` BEFORE `choices`, so this sees the raw value first.
    Three rows are registered-but-unselectable -- kimi (#1620), codex (#1619)
    and, since its family PR failed the gate, gemini (#1621) -- and an
    operator who spells one has named a host this repo genuinely knows, with
    something to do about it. `choices` alone answers that with the list of
    hosts that are NOT what was asked for.

    A name the registry has never heard of is a typo, and argparse's own
    invalid-choice list is the right answer for it, so this returns the value
    untouched and lets `choices` do the rejecting. The decision reads
    `known_hosts()`/`driver_hosts()` and never a host-name literal; `generic`
    appears only inside the remedy PROSE, which is naming a command rather
    than testing a name.
    """
    if text in hosts.known_hosts() and text not in hosts.driver_hosts():
        raise argparse.ArgumentTypeError(
            "--host %s is registered but not driver-selectable (it proves no "
            "enforcement capability); use --host generic (session mode, "
            "unenforced, ack-gated)" % text)
    return text


def build_parser():
    parser = argparse.ArgumentParser(prog="driver")
    sub = parser.add_subparsers(dest="verb", required=True)
    # #1033: `next` was a silent, undifferentiated alias of `run` (run() is
    # already idempotent + resumes from disk), so it's removed rather than kept
    # as a confusing second spelling. `loop` (plan 6) drives the SAME `run`
    # shape headlessly -- see the loop-only flags appended after scope below.
    # #3233: and `readiness` takes the same flags, so one argv serves `driver readiness &&
    # driver loop`; it reports on them and acts on none.
    for verb in ("run", "loop", "readiness"):
        p = sub.add_parser(verb)
        p.add_argument("target", nargs="?", default=".")
        p.add_argument("--host", default=None, type=_host_choice,
                       choices=list(hosts.driver_hosts()))
        p.add_argument("--security", default=None, choices=["standard", "redteam"])
        p.add_argument("--base", default=None)
        p.add_argument("--pr", type=int, default=None)
        p.add_argument("--reset", action="store_true")
        # Match synthesize's accepted values and case handling at the entry
        # point, before a review can spend work on an invalid child argument.
        # None means the CLI supplied no opinion; committed settings still win.
        p.add_argument("--fail-on", type=str.lower,
                       choices=["critical", "high", "medium", "low"], default=None)
        p.add_argument("--severity", type=str.lower,
                       choices=["all", "medium", "high", "critical"], default=None)
        p.add_argument("--gate-scope", choices=["on-diff", "all"], default=None)
        p.add_argument("--diff-context", type=int, default=None)
        tools_group = p.add_mutually_exclusive_group()
        tools_group.add_argument("--tools", action="store_true")
        tools_group.add_argument("--no-tools", action="store_true")
        p.add_argument("--online", action="store_true", default=None,
                       help="allow dependency auditors through the restricted egress proxy")
        p.add_argument("--allow-target-build", action="store_true", default=None,
                       help="run roslyn-secguard, which executes the target's build (#3265)")
        p.add_argument("--include-fixtures", action="store_true")
        # #1519/#1622: refuse an unproven reviewer artifact-write boundary
        # unless the operator accepts it here. Keyed on measured capability,
        # never host name or delivery mode. Anti-drift: a resume cannot quietly
        # drop the acceptance.
        p.add_argument("--allow-unenforced", action="store_true",
                       help="accept an unproven reviewer-write boundary when "
                            "artifact_write_guard is not proven, on any host; "
                            "recorded in unenforced-ack.json")
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
        if verb == "readiness":
            p.add_argument("--json", action="store_true",
                           help="the document as JSON instead of the human table")
        if verb in ("loop", "readiness"):
            # Plan 6, spec 4.3/5.4: the in-process headless loop's own knobs.
            # None of these become manifest anti-drift keys (_cli_flags/
            # run_manifest._FLAG_KEYS never read them) -- a resume may freely
            # change concurrency/budget/timeouts without tripping flag drift.
            # Default None, resolved in `orchestrate.loop` (I8, spec 4.4):
            # headless when the resolved host has a runner, session when it
            # does not. A literal "headless" default here made `driver loop`
            # on a runner-less host an error instead of the documented degrade.
            p.add_argument("--mode", default=None, choices=list(hosts_runner_modes()))
            p.add_argument("--concurrency", type=_positive_int, default=None)
            p.add_argument("--max-iterations", type=_positive_int, default=None)
            # #1648: an exact Decimal, and `nan`/`inf`/a negative amount refused
            # HERE. `type=float` accepted all three, and a NaN budget made every
            # `spent >= budget` comparison False -- the gate accepted, then off.
            p.add_argument("--max-budget-usd", type=money.budget_arg, default=None)
            p.add_argument("--max-turns", type=_positive_int, default=None)
            p.add_argument("--entry-timeout", type=_positive_int, default=None)
            # `setup`'s own leaf-ceiling knob (see the `setup` verb below),
            # exposed here too since `driver loop --setup` runs that flow on
            # rails instead of a review.
            p.add_argument("--max-groups", type=_positive_int, default=None)
            p.add_argument("--setup", action="store_true",
                           help="run `driver setup`'s flow on rails instead of a review")
            # #1912: the narrow remedy for a batch record whose owner cannot be
            # checked for liveness (a hostname that moved, a stamp the target
            # mangled). `--reset` was the only escape and it throws the whole
            # run of paid cells away; this throws away ONE record. The loop's
            # alone: `driver run` writes no batch records, so on that verb the
            # flag would name a file it never reads. Refused together with
            # `--reset` in `parse_cli` -- see there for why not a mutually
            # exclusive group.
            p.add_argument("--discard-batch", type=_positive_int, default=None,
                           metavar="N",
                           help="roll back batch record N and continue the run, "
                                "accepting that its owner is gone (only for a "
                                "foreign/unstamped owner -- a restarted container reads "
                                "its old record as foreign; recorded in discarded-batches.json)")
    sp = sub.add_parser("setup")
    sp.add_argument("target", nargs="?", default=".")
    sp.add_argument("--host", default=None, type=_host_choice,
                    choices=list(hosts.driver_hosts()))
    sp.add_argument("--reset", action="store_true")
    # 5.2 size policy (spec §5.3): files per dispatch unit and the leaf
    # ceiling. Unset = `settings:` in the root config (max_per_group /
    # max_groups), else the defaults (48; max(4, 2 x ceil(code_files / cap))).
    sp.add_argument("--max-per-group", type=_positive_int, default=None)
    sp.add_argument("--max-groups", type=_positive_int, default=None)
    # #1737: `driver setup` dispatches too -- one agent, over the whole
    # untrusted tree -- so it needs the same explicit acceptance `run`/`loop`
    # take when that dispatch cannot be enforced. Without it the refusal names
    # a remedy the verb does not accept, which is a refusal with no way out.
    sp.add_argument("--allow-unenforced", action="store_true",
                    help="accept a shell-less setup-scan dispatch when "
                         "tool_policy_enforced is not proven; recorded in "
                         "setup-unenforced-ack.json")
    pp = sub.add_parser("persist")
    pp.add_argument("entry_id")
    pp.add_argument("target", nargs="?", default=".")
    pp.add_argument("--file", default=None, help="the reply text; stdin when absent")
    pp.add_argument("--setup", action="store_true",
                    help="the entry belongs to `driver setup`'s scan checkpoint")
    # I6: the same two flags `run`/`loop` take, for the same reason. A `--pr`
    # run's review root is the PR WORKTREE, so a persist that resolved
    # `target` alone read the dispatch request out of the operator's own
    # checkout and refused every entry as unknown. Threaded verbatim into
    # resolve_review_root.
    pp.add_argument("--base", default=None)
    pp.add_argument("--pr", type=int, default=None)
    # #1681 Task 7: the one-shot legacy-tree migrator. No `--host`/scope flags
    # -- it writes one file and says what it wrote, it is not a review.
    mp = sub.add_parser("migrate-config")
    mp.add_argument("target", nargs="?", default=".")
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


def run(args, runner=subprocess.run, phases=PHASES, resolved=None):
    try:
        model_resolver.validate_env_overrides()
    except ValueError as exc:
        return runio._error_status(str(exc))
    # `resolved` is `runio.resolve_review_root`'s own (review_root, worktree,
    # pr_base), already computed by a caller that holds it (#1616 item 6, fix
    # round 1): `orchestrate.loop` calls this once per ITERATION, and on a
    # `--pr` run every resolution is a `gh pr view` and a worktree
    # acquisition. Default None keeps the standalone `driver run` entrypoint
    # resolving exactly as it did -- including its injected `runner`, which is
    # how the failure path below is tested.
    #
    # #5.0-14: resolving the review root can fail loudly for a --pr run (gh
    # auth/network, a bad PR number, worktree acquisition) — keep it inside the
    # status protocol instead of letting a raw RuntimeError escape run().
    try:
        review_root, worktree, pr_base = resolved if resolved is not None else (
            runio.resolve_review_root(args.target, base=args.base, pr=args.pr,
                                      runner=runner))
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
    # #5.0-09 / #3271: first contact BEFORE any write or delete under .panopticon/ --
    # a tracked or unstamped one, a symlinked one or one holding a stray link, and
    # an out-of-tree hard link all halt here, on every tree this run writes to.
    try:
        first = first_contact.assess(review_root, "run-manifest.json", reset=args.reset,
                                     host=args.host, other_roots=(args.target,) if args.pr else ())
    except first_contact.FirstContactHalt as exc:
        if worktree:
            diff_map.release_worktree(worktree, repo=args.target)
        return runio._error_status(str(exc))
    if args.reset:
        try:
            _clear_run_artifacts(review_root)  # resolve the tag before the manifest goes
        except (runio.DriverError, OSError) as exc:
            return runio._error_status("unsafe reset cleanup: %s" % exc)
        run_manifest.reset_run(review_root)
    # #1681 Plan 2: ONE resolution per invocation -- both branches below read
    # it, so the disclosures print once and the manifest records exactly what
    # the flags were composed from.
    resolution = _resolve_config(args, review_root)
    # #1093's foreign manifest (a target-committed or another tree's) halts at first
    # contact above (#3271), so what loads here is this machine's, for this tree.
    manifest = run_manifest.load_manifest(review_root)
    if manifest is None:
        # I1: no manifest means no prior run should count — clear any stale
        # derived artifacts so done()-predicates never resume on another run's
        # data (a lost/corrupt manifest, a partially-failed reset, or a
        # pre-existing 4.x groups.json).
        # #5.0-13: load_manifest also returns None for a CORRUPT (present-but-
        # unparseable) manifest — remove it first so write_manifest (write-once)
        # can't raise an uncaught FileExistsError and wedge the run.
        try:
            _clear_run_artifacts(review_root)
        except (runio.DriverError, OSError) as exc:
            return runio._error_status("unsafe fresh-manifest cleanup: %s" % exc)
        run_manifest.reset_run(review_root)
        manifest = run_manifest.build_manifest(
            target=args.target, review_root=review_root,
            host=args.host or runio._DEFAULTS["host"],
            security_mode=(args.security or resolution.effective.get("security")
                           or runio._DEFAULTS["security"]),
            base=base, flags=_cli_flags(args, review_root=review_root,
                                        resolution=resolution),
            config=resolution,
            worktree=worktree,
            scope=scope, pr=args.pr, pr_base=pr_base)
        manifest["first_contact"] = first or {}
        run_manifest.write_manifest(review_root, first_contact.bind(review_root, manifest))
    else:
        cli_flags = _cli_flags(args, review_root=review_root, resolution=resolution)
        conflicts = run_manifest.conflicting_flags(
            manifest, host=args.host,
            # The RESOLVED opinion, not the raw flag: a config that changed
            # `security:` mid-run is drift exactly as `--security` would be.
            # Still None when neither the CLI nor the file has an opinion --
            # `conflicting_flags` reads None as "no opinion", which is what
            # keeps a bare `driver run` resume from conflicting with itself.
            security_mode=args.security or resolution.effective.get("security"),
            base=base, flags=cli_flags, scope=scope, pr=args.pr)
        if conflicts:
            return runio._error_status("flag drift (use --reset to start over): "
                                 + "; ".join(conflicts))
        # #1: a bare re-invocation of an ALREADY-complete run matches every
        # manifest field (conflicting_flags treats a None incoming value as
        # no-conflict), so it would advance straight to "complete" and hand
        # back a possibly-stale report as though it were a fresh scan -- the
        # worst failure mode for a review tool. Refuse loudly and name --reset
        # instead; the durable report stays on disk.
        #
        # #1637 P08 F3: decided on the TERMINAL phase's artifact, not on "every
        # predicate says done". The two agreed until an environmental tool skip
        # became legitimately not-done (F1): a finished run then re-entered,
        # re-ran the scan, found every later phase done, and handed back the
        # PREVIOUS report as though it were fresh -- with the new tool findings
        # never ingested. A run whose last phase has its artifact is complete,
        # whatever an earlier phase would like to retry.
        #
        # Fix round 2 N1: this now stands AHEAD of the downgrade below, and inside the branch that
        # has a manifest at all. It used to follow it, so a `--no-tools` aimed at a FINISHED run
        # flipped `flags.tools` and appended a `flag_changes` entry before refusing -- a durable
        # record of a rescue that never happened, on a run with nothing left to rescue. Lose the
        # terminal artifacts and resume, and the regenerated report says `disabled_mid_run: true`
        # beside panels that all saw scanner evidence: the run record and the report contradicting
        # each other on the very surface this work added. A --reset run never reaches here -- it has
        # no manifest to load -- so the old `not args.reset` clause is now structural.
        if phases and phases[-1].done(review_root, manifest):
            report = runio._pano(review_root, "report.json")
            loc = report if os.path.exists(report) else review_root
            return runio._error_status(
                "run already complete (report at %s) -- use `--reset` to start "
                "a new run" % loc)
        # #1637 P08 F2: `--no-tools` on an IN-FLIGHT run is the non-destructive
        # rescue from a scanner environment that moved after the scouts were
        # paid for -- the alternative was `--reset`, which throws that work
        # away. Recorded in the manifest (flags + flag_changes), so readiness
        # re-evaluates on its own (its done predicate keys on flags.tools), the
        # tools phase rewrites its marker as the operator's own skip, and
        # synthesis discloses it as meta.tools.disabled_mid_run.
        if run_manifest.is_tools_downgrade(manifest, cli_flags):
            try:
                manifest = run_manifest.record_tools_downgrade(review_root, manifest)
            except ValueError as exc:     # #1735: the same refusal, the same protocol
                return runio._error_status(str(exc))
    # In-memory only, and deliberately NOT a manifest field: it names where the HOST SESSION runs,
    # a property of this invocation rather than of the run, and feeds only the cost-ledger
    # transcript lookup. Not persisted, so not an anti-drift key: resuming from another session is
    # normal, and a resume that needs it passes it again (#calibration-4).
    if getattr(args, "session_dir", None):
        manifest["session_dir"] = os.path.abspath(args.session_dir)
    # #1637 P08 F1: ONE token per invocation, carried on the in-memory manifest -- which is the
    # context object every phase already receives -- and deliberately never written to disk
    # (run_manifest._EPHEMERAL_KEYS). It is what makes an environmental tool skip retried once per
    # `driver run` rather than once per ENGINE STEP: `run_engine` recomputes the cursor every step,
    # so a phase that is simply "not done" after executing is re-selected immediately and spins to
    # max_steps. `driver loop` gets a fresh token per iteration by construction, since every
    # iteration calls this function.
    manifest["invocation"] = run_manifest.new_run_id()
    # #3226: ephemeral too. Only a headless loop's launch argv takes Bash from a reviewer.
    manifest["dispatch_mode"] = "headless" if getattr(args, "mode", None) == "headless" else "session"
    # Both writes below land inside the REVIEWED tree, and each can refuse a
    # planted component -- `_ensure_run_symlinks` with DriverError, the baseline
    # write with the confinement's ValueError -- or meet a full disk (OSError,
    # #2094). Outside every `except` on this path, they ended the invocation with a
    # traceback and no JSON (#1735). Same rule as `run_engine` below: refusing is
    # the guard working, and it speaks this verb's status protocol.
    baseline = False
    try:
        # §5.1: point runs/latest at the active run folder now that the manifest
        # (hence the tag) is established — so the pointer exists throughout the run.
        runio._ensure_run_symlinks(review_root)
        # I2: capture the clean-tree baseline unconditionally and BEFORE the engine
        # runs. Idempotent (an existing baseline is returned) -> no-op on a normal
        # resume, but self-heals one a mid-first-run interrupt left missing (which
        # had silently disabled the guard) -- only before the first dispatch, #3255.
        baseline = True
        validate.capture_tree_baseline(review_root, runner=runner, manifest=manifest)
    except (runio.DriverError, ValueError) as exc:
        return runio._error_status(str(exc))
    except OSError as exc:
        return runio._error_status(validate.start_write_failure(review_root, baseline, exc))
    # 5.2: establish this host's capability posture BEFORE any phase can build
    # a dispatch entry, and re-establish it on every resume. Not an
    # engine.Phase: phases are skipped once their done-predicate holds, which
    # is exactly the resume where re-probing matters.
    posture_error = _establish_host_posture(review_root, manifest, args)
    if posture_error:
        return runio._error_status(posture_error)
    try:
        result = engine.run_engine(review_root, manifest, phases)
    except (runio.DriverError, ValueError) as exc:   # R1-1: confinement refusal
        return runio._error_status(str(exc))
    except engine.EngineStalled as exc:
        # #1637 P08 F1b: the progress guard fired. Converted here rather than
        # left to escape: `driver run` speaks a status protocol, and a
        # traceback is not a status -- the host gets no JSON at all, after the
        # spin has already burned the run's wall clock. The engine's own
        # message is carried verbatim, so the phase that could not advance is
        # still named.
        return runio._error_status(str(exc))
    if result.get("status") == "complete":
        # #1809: both calls below READ the run's own artifacts -- the worktree state, and
        # `exhausted_cells` -> `cell-attempts.json` -- and this block sat outside every `try` above,
        # so a refusal here escaped `main()` as a traceback and a host parsing stdout got no status
        # JSON at all: the exact failure `engine.EngineStalled`'s conversion exists to prevent.
        try:
            validate._finalize_worktree(review_root, manifest)
            # #1616 item 2: `review_done` counts an exhausted cell as done -- which is what stops
            # one unrecoverable cell wedging the run -- so a run that lost cells to their retry
            # budget completes with the same status and the same message as one where every cell
            # answered. Name them, here rather than in `orchestrate._finish`, because `driver run`
            # reaches `complete` on its own too and the loop's terminal `complete` IS this status:
            # one place, both entrypoints. Added ONLY when there are any, so a clean run's status
            # stays byte-for-byte what every host parses today.
            exhausted = review.exhausted_cells(review_root, manifest)
            empty = len(exhausted) == review.cell_count(review_root)  # #3220: none answered
        except (runio.DriverError, ValueError) as exc:
            return runio._error_status(str(exc))
        if exhausted:
            # The COUNT is exact; the NAMED list is bounded (fix round 1, N2). A run that loses 100
            # cells would otherwise put 100 `group/domain` pairs into one status line that hosts and
            # CI parse, and the per-cell detail is on disk either way (`cell-attempts.json`, and the
            # report's missing floor cells).
            named, more = exhausted[:_EXHAUSTED_NAMED], len(exhausted) - _EXHAUSTED_NAMED
            result = dict(result, cells_exhausted=len(exhausted), message=(
                "%s; cells_exhausted: %d (%s%s) -- these review cells spent their "
                "retry budget without returning an acceptable findings file, so "
                "the run completed with them missing from the review axis"
                % (result.get("message"), len(exhausted), ", ".join(named),
                   " and %d more" % more if more > 0 else "")))
            if empty:
                result = dict(result, review_axis_empty=True,
                              message=result["message"] + review.AXIS_EMPTY_CLAUSE)
    return synthesize.complete_status(result, review_root, manifest)


def parse_cli(argv=None):
    """`build_parser().parse_args`, plus one portability rule for `persist`:
    a single trailing bare word after the options is the `target`.

    argparse before 3.12 binds an optional positional (`target`, nargs="?")
    the moment it consumes `entry_id`, so `driver persist ID --file F TARGET`
    -- the documented order -- fails with "unrecognized arguments: TARGET"
    on Python 3.11 while 3.12+ accept it. Folding exactly one leftover word
    into `target` makes both orders parse on every supported interpreter;
    anything else left over is still the parser's own error.

    ...and one contradiction refused, #1912's `--discard-batch N --reset`. Not
    an `add_mutually_exclusive_group`: `--reset` is declared for `run` and
    `loop` together and `--discard-batch` for `loop` alone, and argparse cannot
    put an action that already belongs to a parser into a group afterwards.
    Refusing it HERE keeps both declarations where they belong and still exits
    2 with the parser's own usage line."""
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)
    if (extra and args.verb == "persist" and len(extra) == 1
            and not extra[0].startswith("-") and args.target == "."):
        args.target = extra[0]
        extra = []
    if extra:
        parser.error("unrecognized arguments: %s" % " ".join(extra))
    if getattr(args, "discard_batch", None) is not None and getattr(args, "reset", False):
        # One keeps the run and throws a record away; the other throws the run
        # away and skips batch recovery altogether -- so accepting both would
        # let `--reset` win in silence, which is the opposite of what the
        # narrower flag was typed for.
        parser.error("--discard-batch and --reset are contradictory: "
                     "--discard-batch keeps the run and rolls back one batch "
                     "record, --reset discards the whole run folder")
    return args


def main(argv=None):
    args = parse_cli(argv)
    if args.verb == "readiness":
        # Its own exit code, not `emit_status`': the verb speaks no status protocol, and
        # `driver readiness && driver loop` is the reason it exists (#1637 P10).
        root = runio.resolve_review_root(args.target)[0]
        resolution = _resolve_config(args, root)
        return readiness.emit_preflight(args.target, host=args.host, as_json=args.json,
                                        online=args.online, plan={
            "flags": _cli_flags(args, root, resolution), "scope": _scope_from_args(args),
            "security": args.security or resolution.effective.get("security"),
            "reset": args.reset, "base": args.base, "pr": args.pr})
    if args.verb == "setup":
        # #1737 fix round 1: WITH the posture step, exactly as
        # `orchestrate.loop --setup` passes it. `driver setup` dispatches an
        # agent over the whole untrusted tree, and since #1737 that dispatch
        # is gated on this host's measured `tool_policy_enforced` -- so a verb
        # that probed nothing read whatever `.panopticon/host-capabilities.json`
        # happened to be lying on the tree (or nothing at all, on a fresh
        # target) and refused the bootstrap with a remedy that could not
        # change the answer. The step is namespace-aware: it writes setup's
        # own flat artifact and skips the drift COMPARISON, which is a
        # statement about one run and this is not one.
        return engine.emit_status(
            setup.run_setup_flow(args, posture=_establish_host_posture))
    if args.verb == "migrate-config":
        # Its own exit code, like `readiness`: this verb writes one file and
        # says what it wrote, it is not a review and speaks no status protocol.
        try:
            _path, message = setup_config.migrate_config(os.path.abspath(args.target))
        except ValueError as exc:
            print("driver migrate-config: %s" % exc, file=sys.stderr)
            return 1
        print(message)
        return 0
    if args.verb in ("loop", "persist"):
        if args.verb == "loop":
            try:
                model_resolver.validate_env_overrides()
            except ValueError as exc:
                return engine.emit_status(runio._error_status(str(exc)))
        import scripts.orchestrate as orchestrate   # R-P6-2: lazy, no cycle
        return loop_progress.stamped_call(args.verb == "loop", orchestrate.main_verb, args)
    return engine.emit_status(run(args))


if __name__ == "__main__":
    sys.exit(procgroup.sigterm_as_interrupt(main))  # #2199: every verb; never at import
