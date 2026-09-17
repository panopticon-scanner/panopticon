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
from scripts import hosts  # noqa: E402
import scripts.host_disclosure as host_disclosure  # noqa: E402
import scripts.host_probes as host_probes  # noqa: E402
import scripts.money as money  # noqa: E402
import scripts.probes.common as probes_common  # noqa: E402
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
                "report.json", "dispatch-request.json", "tree-baseline.txt",
                "verify-queue.json", "findings-*.json",
                # #5.0-07: stale delta artifacts must not survive a --reset and
                # silently delta-scope (or content-check) the next run.
                # #5.0-16: the driver's own dispatch plan clears too, so a
                # --reset run re-declares cells from fresh coverage.
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
                "cell-attempts.json")


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
    for verb in ("run", "loop"):
        p = sub.add_parser(verb)
        p.add_argument("target", nargs="?", default=".")
        p.add_argument("--host", default=None, type=_host_choice,
                       choices=list(hosts.driver_hosts()))
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
        # #1519: when this invocation's MEASURED artifact_write_guard posture
        # is not proven, dispatching write-capable cells is refused unless the
        # operator accepts the residual risk here. Keyed on the capability, NOT
        # on the host's name (#1344 F3a): a claude run on a machine where the
        # probe refutes -- no settings file at the path the host would arm --
        # is refused on identical terms. Anti-drift, so a resume cannot quietly
        # drop the acceptance.
        p.add_argument("--allow-unenforced", action="store_true",
                       help="accept unmediated reviewer Write when "
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
        if verb == "loop":
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
    sp = sub.add_parser("setup")
    sp.add_argument("target", nargs="?", default=".")
    sp.add_argument("--host", default=None, type=_host_choice,
                    choices=list(hosts.driver_hosts()))
    sp.add_argument("--reset", action="store_true")
    # 5.2 size policy (spec §5.3): files per dispatch unit and the leaf
    # ceiling. Unset = .panopticon/config.json (max_per_group / max_groups),
    # else the defaults (48; max(4, 2 x ceil(code_files / cap))).
    sp.add_argument("--max-per-group", type=_positive_int, default=None)
    sp.add_argument("--max-groups", type=_positive_int, default=None)
    # #1637 P10: the read-only preflight. It shares `run`/`loop`'s `target` and
    # `--host` and NOTHING else on purpose -- it is not a run, so a flag that
    # configures one (`--no-tools`, `--pr`, `--reset`, ...) would either have
    # to be ignored or have to mean something new here, and both are worse than
    # refusing it. The rendering lives in `phases/readiness.py` beside the
    # checkpoint whose checks and remedy text it reuses; driver.py stays the
    # argparse wiring and one dispatch line.
    rp = sub.add_parser("readiness")
    rp.add_argument("target", nargs="?", default=".")
    rp.add_argument("--host", default=None, type=_host_choice,
                    choices=list(hosts.driver_hosts()))
    rp.add_argument("--json", action="store_true",
                    help="the document as JSON instead of the human table")
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


def _emit_posture_disclosure(envelope, since=None):
    """5.1 surface 1: stderr, before anything dispatches.

    Same channel and register as phases/tools.py's "driver: tool scan CRASHED
    (rc=...)" -- `driver: ` prefixed lines on stderr. `host_disclosure`
    composes the sentence; this picks the channel and writes it, once per
    call, and nothing else -- see host_disclosure.py's module docstring on
    why no caller is allowed to write its own wording. A named function
    (rather than the write inlined at the call site) so a cross-surface
    consistency test can call it directly with a hand-built envelope, without
    also having to fake a whole `_establish_host_posture` invocation.

    `since` (#1596) is the stamp at which this exact disclosure was already
    printed in full; passing it collapses the block to ONE line. The default
    is the full block, so the surface a caller gets by asking for nothing is
    the whole disclosure.

    `envelope` is a `run_probes()`-shaped dict; `host_disclosure.headline`/
    `lines` already degrade an unreadable envelope to NO_EVIDENCE / no lines
    rather than raising, so this function does not re-validate it.
    """
    if since:
        sys.stderr.write("driver: host capabilities: %s\n"
                         % host_disclosure.unchanged_headline(envelope, since))
        return
    sys.stderr.write("driver: host capabilities: %s\n" % host_disclosure.headline(envelope))
    for line in host_disclosure.lines(envelope) + host_disclosure.notes(envelope):
        sys.stderr.write("driver:   %s\n" % line)


def _disclose_posture(review_root, manifest, fresh):
    """Surface 1, in full once per posture and as a headline thereafter (#1596).

    `driver run` is a resumable loop and this runs on every invocation, so a
    self-scan printed the same 5-line block 100+ times -- roughly 120 KB of
    stderr that is byte-identical BY CONSTRUCTION, since F3a refuses the run
    outright if the posture moves. Full block when the posture has not been
    disclosed yet, or when what it SAYS has changed since it was (the digest
    covers the detail and the operational notes too, not just the states);
    one headline otherwise.

    Decided from the RUN MANIFEST's stamp, never from `host-capabilities.json`.
    That file lives on a `.panopticon` path a hostile target can pre-commit,
    so a target able to guess its own posture could suppress the first
    disclosure; the manifest is the one artifact `driver.run` refuses to
    inherit from the tree (`runio._foreign_manifest`).

    The stamp is only recorded when a manifest already exists on disk. Every
    production caller has one -- `driver.run` writes it before this runs --
    and MINTING one here would be worse than not recording: `runio._pano`
    resolves the per-run folder off the manifest, so creating one mid-flow
    would move `host-capabilities.json` out from under this very function.
    """
    digest = host_disclosure.disclosure_digest(fresh)
    since = run_manifest.posture_disclosed_at(manifest, digest)
    _emit_posture_disclosure(fresh, since=since)
    if since is None and os.path.isfile(run_manifest.manifest_path(review_root)):
        try:
            run_manifest.record_posture_disclosure(review_root, manifest, digest,
                                                   fresh.get("probed_at"))
        except OSError as exc:
            # The stamp is EXPENDABLE, and a stamp that cannot be written must
            # not be the thing that kills an invocation. Losing it costs one
            # repeated block next time; raising costs the whole call -- and on
            # the shadow-refusal path below this is the only write in this
            # function (the artifact write is past the refusal), so an
            # unwrapped OSError turned a clean "refusing to run" status into a
            # traceback with no JSON behind it. Said on stderr rather than
            # swallowed: a run directory that has stopped accepting writes is
            # something the operator wants to know before synthesis tries.
            sys.stderr.write(
                "driver: could not record the posture disclosure stamp (%s: %s)"
                " -- the full block will print again next invocation\n"
                % (type(exc).__name__, exc))


def _establish_host_posture(review_root, manifest, args, *, registration_dir=None):
    """Probe this host now; write the evidence, or refuse if it moved.

    Spec 5.2. Runs on EVERY invocation, not once per run: `driver run` is a
    resumable loop, and setup-time-only evidence is unbounded in age -- a
    write-guard hook uninstalled after setup would read `proven` forever.

    First invocation writes `runs/<tag>/host-capabilities.json`. Every later
    one re-probes and COMPARES. Any difference refuses the run in both
    directions: a posture that degraded is alarming, and one that improved
    still leaves the entries already dispatched under the weaker posture, so
    the honest answer to both is a fresh run.

    `registration_dir` (#1609) is a TEST SEAM: None -- the default, and what
    every production caller passes -- keeps the registration probes reading the
    real registry row, which is what production must do. F4 pinned every direct
    `run_probes("claude", ...)` call in tests to a temp dir and could not pin
    the ones that come through here, because this argument did not exist.

    `args` is accepted and deliberately READ FOR NOTHING TREE-SHAPED. It is
    kept as a test seam: `args.target` is the operator's own checkout, which
    under `--pr` is emphatically not the tree being reviewed, and passing it
    to the shadow scan is C1. The regression test hands this function a
    `target` that DIFFERS from `review_root` and requires the refusal to fire
    off `review_root`, which is only a test that can fail while the parameter
    is still here to get wrong.

    Also prints the `--host generic` deprecation notice (spec D4) when the
    resolved host is deprecated -- this is the one place the manifest's host
    is resolved before any phase dispatches, so it is the only call site that
    can print it once per invocation regardless of entrypoint or resume state.

    Returns an error message when the run must stop, else None.
    """
    host = manifest.get("host", "claude")
    # #1624: refuse a run whose manifest names a host the registry still knows
    # but the driver may no longer pick -- BEFORE the deprecation notice and
    # before any probe, because nothing about this run may proceed. On a
    # resume the manifest is authoritative (`--host` is omitted; a
    # contradicting one is refused as flag drift), so the parser's
    # `choices`/`type=` -- this file's only other read of the selectable set
    # -- never sees the name, and a run started under a row that has since
    # lost `driver_selectable` (gemini, #1621) probed to all-unknown and went
    # on emitting dispatch entries for a host `--host` refuses to name.
    # `driver loop` has refused it since #1621; this is the same refusal, in
    # the same words, on the primitive the loop is built out of.
    #
    # Read off the registry, never a host-name literal, so a family PR that
    # flips its own row needs no edit here (`tests/test_host_posture_wiring.py`
    # bans the literal form under `phases/`; this file follows the same rule).
    # A host the registry has NEVER heard of is a different failure with a
    # different remedy and is deliberately not handled here.
    if host in hosts.known_hosts() and host not in hosts.driver_hosts():
        return hosts.unselectable_host_message(host, "run")
    if hosts.is_deprecated(host):
        # D4: printed from the RESOLVED host, not from argv, so a resumed run
        # (--host absent, the manifest authoritative) prints it too. Every
        # invocation reaches here before any phase dispatches (spec 10: a
        # notice, not a gate -- nothing about the run below this line changes).
        print(host_disclosure.GENERIC_DEPRECATION, file=sys.stderr)
    # THREE trees, three arguments -- see run_probes' docstring. `review_root`
    # is the REVIEWED tree (the --pr worktree, or the git toplevel), which is
    # what the shadow scan must read; `args.target` is the operator's own
    # checkout and scanning it left a hostile PR's planted shell unread (C1).
    # The session root comes from runio.session_dir, the single expression
    # synthesize._collect_host_usage also reads, so the probe that GATES the
    # token ledger and the collector that BUILDS it cannot drift apart (C2).
    # session_dir is read off the MANIFEST rather than args because driver.run()
    # assigns it there (in memory, after write_manifest) -- but it is NOT
    # persisted, so a resume without the flag legitimately falls back to cwd.
    # `_posture_drift` names --session-dir when that is what moved.
    session_root = runio.session_dir(manifest)
    # Probed directly, and ONCE (Minor 4): _shadow_refusal may not read the
    # verdict back off the artifact's `by` field (see its docstring), and
    # running the scan a second time inside run_probes was both duplicate work
    # and a window in which the artifact and the refusal could disagree about
    # the same tree.
    shadow = probes_common.probe_shadow_shells(host, review_root)
    # Plan 6 (spec 5.4): in headless mode the guards are armed into the run
    # folder's host-settings.json, never the session root -- so that file,
    # not the session's, is what the guard probes must prove. `mode` is a
    # `driver loop` flag; `driver run` has none and probes the session root.
    settings_path = (probes_common.headless_settings_path(review_root)
                     if getattr(args, "mode", None) == "headless" else None)
    # N2: the live runner's scratch home, when the loop has one. `driver run`
    # on its own never does, and neither does the first invocation of a loop
    # (posture is established before `prepare`), so a probe that measures this
    # run's children legitimately falls back until a child has run.
    fresh = host_probes.run_probes(host, review_root, session_root=session_root,
                                   registration_dir=registration_dir,
                                   shadow=shadow, settings_path=settings_path,
                                   run_home=getattr(args, "run_home", None))
    # 5.1 surface 1. Emitted here -- after `fresh` is computed, before the
    # artifact is written or compared, and before the shadow refusal below --
    # rather than at the dispatch sites, because 5.2 already puts this step
    # before `coverage` dispatches the scout (so it runs before anything
    # dispatches, satisfying the "at the first dispatch" half of spec 5.1),
    # and because emitting once per INVOCATION here (not once per dispatched
    # cell) is what "once per run" rules out. A resumed invocation
    # re-announces deliberately: the operator resuming needs the posture they
    # are resuming under -- as a HEADLINE once it has already had the whole
    # thing for this posture (#1596). Emitted even when the shadow refusal
    # below is about to stop the run, so the operator sees the posture the
    # refusal is about.
    _disclose_posture(review_root, manifest, fresh)
    # I6 / spec 5.2: evaluated on EVERY invocation, not only the first. When
    # tool_policy_enforced is already REFUTED for an unrelated reason -- no
    # registration directory, i.e. every machine that has not run `driver
    # setup` -- a shadow file planted mid-run gives refuted -> refuted, no
    # mismatch, and a refusal evaluated only under `stored is None` would never
    # look at it again.
    refusal = _shadow_refusal(shadow, manifest)
    if refusal:
        return refusal
    path = runio._pano(review_root, runio.HOST_CAPABILITIES)
    stored = runio._load_json(path)
    if stored is None:
        runio._write_json(path, fresh)
        return None
    was, now = host_probes.capabilities_of(stored), host_probes.capabilities_of(fresh)
    gating_was, gating_now = _gating_states(was), _gating_states(now)
    if gating_was != gating_now:
        return _posture_drift(gating_was, gating_now, manifest)
    # The GATING states agree, so the run continues. An operational
    # capability may still have moved (#1626 I1) and the write below records
    # it -- state and reason both -- which is exactly the point: disclosure
    # stays current, the run does not stop. The REASON may also have moved -- a capability refuted for "no shell at X" on
    # invocation 1 and for "grants forbidden tool Bash" on invocation 5 is
    # refuted both times. F3b renders `detail` on three surfaces, so a stale
    # reason is now a wrong disclosure rather than a cosmetic one. Refresh the
    # record; do NOT refuse, because the operator can do nothing about a reason
    # that changed underneath an unchanged verdict.
    #
    # Gated on the CAPABILITIES map, not the whole artifact: `fresh["probed_at"]`
    # is stamped fresh on every call (run_manifest._now_iso(), second
    # resolution), so comparing whole dicts degenerates to "always write" on
    # essentially every real invocation -- rewriting, on every turn of a
    # resumable loop, the very artifact the mid-run refusal above reads, which
    # widens rather than shrinks the window in which a killed process could
    # leave it truncated. `was`/`now` above are STATE-only and already equal
    # by construction here, so gating on those instead would mean `detail`
    # never refreshes -- defeating this whole fix. `capabilities` carries the
    # per-capability state/by/detail triples and excludes probed_at/
    # schema_version/host, which is exactly the "did anything an operator
    # cares about change" question.
    #
    # `cli_flags` is on the REWRITE trigger and deliberately NOT on the drift
    # comparison above (D10 S1). The two ask different questions: drift asks
    # "may this run continue", and a CLI upgraded between two turns of a
    # resumable loop must never refuse a resume over a flag that gates
    # nothing; the rewrite asks "is the record still true", and a fact that
    # moved and was not written back is a stale fact the NEXT dispatch reads.
    # That was F1's failure class exactly: invocation 2 measured
    # `advertised: false`, disclosed it on stderr, and then
    # `requests._materialize_prompts` stamped `output_schema` off the stored
    # `true` -- putting the flag on the argv of a CLI just measured not to take
    # it, which exits non-zero and takes every entry's launch budget with it.
    if (stored.get("capabilities") != fresh.get("capabilities")
            or stored.get(hosts.CLI_FLAGS) != fresh.get(hosts.CLI_FLAGS)):
        # Write the FULL fresh payload (not just the capabilities key) so
        # `probed_at` on disk stays honest about when the record was last
        # actually written.
        runio._write_json(path, fresh)
    return None


def _gating_states(states):
    """`states` minus the capabilities that are operational rather than
    security (#1626 I1, `hosts.OPERATIONAL_CAPABILITIES`).

    `_posture_drift` halts a run in flight, and the remedy it names discards
    everything already dispatched. That is the right answer when the thing
    that moved is enforcement -- the report would otherwise disagree with
    itself about what was confined -- and the wrong answer for `usage_ledger`
    and `model_binding`, which gate nothing.

    `usage_ledger` is the case that made this structural rather than
    theoretical. It is the only probe whose subject the run itself PRODUCES:
    `probe_usage_source` reads back `runs/<tag>/dispatch-ledger.jsonl`, which
    the loop appends to after every batch. Two failures followed. A `claude
    --help` that does not answer inside CLI_HELP_TIMEOUT under a full
    concurrency pool reads UNKNOWN for one invocation and aborted the loop.
    And a CLI release whose envelope stops carrying `usage` completes batch 1,
    refutes from invocation 2 on, and refuses EVERY re-invocation from then
    on -- permanently, since the stored artifact still says proven -- leaving
    `--reset` (throw the paid-for batches away) as the only exit. A token
    counter going quiet must not cost a run.

    Filtered rather than merely tolerated: `_posture_drift`'s message lists
    what moved, and naming a capability that did not cause the refusal next
    to a remedy about capabilities that did is a worse message, not a fuller
    one.
    """
    return {name: state for name, state in states.items()
            if name not in hosts.OPERATIONAL_CAPABILITIES}


# The capabilities whose probes resolve off the SESSION root rather than the
# reviewed tree, so a difference in either can be explained by a --session-dir
# that was passed on one invocation and omitted on the next. read_scope_confined
# joins the other two here because probes.claude.probe_read_guard_armed resolves
# off session_root exactly like probe_write_guard_armed does (I3).
_SESSION_DERIVED = (hosts.ARTIFACT_WRITE_GUARD, hosts.USAGE_LEDGER, hosts.READ_SCOPE_CONFINED)


def _posture_drift(was, now, manifest):
    """The mid-run posture-change refusal, naming the likeliest remedy first.

    I2: `session_dir` is deliberately NOT a manifest field (driver.run() sets
    it in memory after write_manifest), so a run started with `--session-dir /s`
    and resumed WITHOUT it re-resolves the write-guard and transcript probes
    against cwd -- a perfectly ordinary operator slip that flips those two
    capabilities and lands here. Telling that operator to discard the run with
    --reset, while naming neither the flag nor the option of simply passing it
    again, is a worse answer than the mistake. So when a session-derived
    capability moved and this invocation carries no --session-dir, that remedy
    goes first. Otherwise --reset stands: an improved posture still leaves
    entries dispatched under the weaker one.
    """
    moved = ["%s: %s -> %s" % (name, was.get(name), now.get(name))
             for name in sorted(set(was) | set(now))
             if was.get(name) != now.get(name)]
    message = ("host posture changed mid-run (%s). Entries already dispatched "
               "were built under the previous posture, so this run's report "
               "would disagree with itself about what was enforced."
               % "; ".join(moved))
    session_moved = sorted(name for name in _SESSION_DERIVED
                           if was.get(name) != now.get(name))
    if session_moved and not (manifest or {}).get("session_dir"):
        return ("%s If the earlier invocation ran with --session-dir, pass the "
                "same --session-dir again: %s resolve off the session root, "
                "which defaults to the current directory (%s) when the flag is "
                "absent, and the flag is deliberately not stored in the "
                "manifest. Otherwise start a fresh run with --reset."
                % (message, ", ".join(session_moved), os.getcwd()))
    return "%s Start a fresh run with --reset." % message


def _shadow_refusal(shadow, manifest):
    """Spec 7.3: a target shipping panopticon-* agent files refuses the run.

    `shadow` is `probes.common.probe_shadow_shells`'s OWN `(state, by, detail)`
    result -- never the artifact's `capabilities[tool_policy_enforced]` row.
    That row's `by` names whichever probe `run_probes` recorded FIRST among
    those that reached the resolved state, so on a host whose
    registered-shell-tools probe ALSO refutes (no registration directory at
    all -- every machine that has not run `driver setup`), `by` would read
    "registered-shell-tools" even though shadow-shell-scan is the one that
    found the hostile file. Keying this refusal off `by` silently dropped the
    shadow finding on exactly the machines a hostile target is most likely to
    be pointed at: an unregistered first run. Deciding from the probe's own
    result is immune to whatever else ties with it.

    `--allow-unenforced` downgrades rather than silences: the run proceeds with
    tool_policy_enforced REFUTED (resolve_state ranks refuted over proven), so
    the report says plainly it was not enforced. Both REFUTED reasons a shadow
    probe can return -- a shadowing file was found, or a scope directory could
    not be read so shadowing could not be ruled out -- refuse the same way.
    """
    state, _by, detail = shadow
    if state != hosts.REFUTED:
        return None
    if (manifest.get("flags") or {}).get("allow_unenforced"):
        return None
    return ("refusing to run: %s. A project-scoped agent file takes precedence "
            "over the registered enforcement shell, so this target would be "
            "reviewing itself with reviewers it supplied. Remove the file(s), "
            "or re-run with --allow-unenforced to proceed with enforcement "
            "explicitly refuted." % detail)


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
        cli_flags = _cli_flags(args)
        conflicts = run_manifest.conflicting_flags(
            manifest, host=args.host, security_mode=args.security,
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
        # Fix round 2 N1: this now stands AHEAD of the downgrade below, and
        # inside the branch that has a manifest at all. It used to follow it,
        # so a `--no-tools` aimed at a FINISHED run flipped `flags.tools` and
        # appended a `flag_changes` entry before refusing -- a durable record
        # of a rescue that never happened, on a run with nothing left to
        # rescue. Lose the terminal artifacts and resume, and the regenerated
        # report says `disabled_mid_run: true` beside panels that all saw
        # scanner evidence: the run record and the report contradicting each
        # other on the very surface this work added. A --reset run never
        # reaches here -- it has no manifest to load -- so the old
        # `not args.reset` clause is now structural.
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
            manifest = run_manifest.record_tools_downgrade(review_root, manifest)
    # In-memory only, and deliberately NOT a manifest field: it names where the
    # HOST SESSION runs, which is a property of this invocation rather than of
    # the run, and it feeds nothing but the cost-ledger transcript lookup. Not
    # persisted means it is also not an anti-drift key -- resuming from a
    # different session is normal and must not be reported as drift. A resume
    # that needs it simply passes it again (#calibration-4).
    if getattr(args, "session_dir", None):
        manifest["session_dir"] = os.path.abspath(args.session_dir)
    # #1637 P08 F1: ONE token per invocation, carried on the in-memory manifest
    # -- which is the context object every phase already receives -- and
    # deliberately never written to disk (run_manifest._EPHEMERAL_KEYS). It is
    # what makes an environmental tool skip retried once per `driver run`
    # rather than once per ENGINE STEP: `run_engine` recomputes the cursor
    # every step, so a phase that is simply "not done" after executing is
    # re-selected immediately and spins to max_steps. `driver loop` gets a
    # fresh token per iteration by construction, since every iteration calls
    # this function.
    manifest["invocation"] = run_manifest.new_run_id()
    # §5.1: point runs/latest at the active run folder now that the manifest (hence
    # the tag) is established — so the pointer exists throughout the run, not just
    # after synthesize writes the report.
    runio._ensure_run_symlinks(review_root)
    # I2: capture the clean-tree baseline unconditionally and BEFORE the engine
    # runs. Idempotent (returns the existing baseline if present) -> no-op on a
    # normal resume, but self-heals a baseline that a mid-first-run interrupt
    # left missing (which had silently disabled the clean-tree guard).
    validate.capture_tree_baseline(review_root, runner=runner)
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
        validate._finalize_worktree(review_root, manifest)
    return result


def parse_cli(argv=None):
    """`build_parser().parse_args`, plus one portability rule for `persist`:
    a single trailing bare word after the options is the `target`.

    argparse before 3.12 binds an optional positional (`target`, nargs="?")
    the moment it consumes `entry_id`, so `driver persist ID --file F TARGET`
    -- the documented order -- fails with "unrecognized arguments: TARGET"
    on Python 3.11 while 3.12+ accept it. Folding exactly one leftover word
    into `target` makes both orders parse on every supported interpreter;
    anything else left over is still the parser's own error."""
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)
    if (extra and args.verb == "persist" and len(extra) == 1
            and not extra[0].startswith("-") and args.target == "."):
        args.target = extra[0]
        extra = []
    if extra:
        parser.error("unrecognized arguments: %s" % " ".join(extra))
    return args


def main(argv=None):
    args = parse_cli(argv)
    if args.verb == "readiness":
        # Its own exit code, not `emit_status`': the verb speaks no status
        # protocol, and `driver readiness && driver loop` is the reason it
        # exists (#1637 P10).
        return readiness.emit_preflight(args.target, host=args.host,
                                        as_json=args.json)
    if args.verb == "setup":
        return engine.emit_status(setup.run_setup_flow(args))
    if args.verb in ("loop", "persist"):
        import scripts.orchestrate as orchestrate   # R-P6-2: lazy, no cycle
        return orchestrate.main_verb(args)
    return engine.emit_status(run(args))


if __name__ == "__main__":
    sys.exit(main())
