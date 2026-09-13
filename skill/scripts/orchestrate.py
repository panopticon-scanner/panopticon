"""The orchestrator on rails (spec 4): `driver loop` and `driver persist`.

`loop` calls driver.run in-process and, at every checkpoint, does the host
duties itself: recompute the pending set from disk, arm both guards, run the
batch through the host's runner, persist return-persist replies, ledger every
launch, tear the guards down, and call driver.run again. The engine's done
predicates are the only way forward (O2); a runner's claim advances nothing.
"""
import json
import os
import sys
import time

import scripts.driver as driver
import scripts.host_probes as host_probes
import scripts.phases.engine as engine
import scripts.phases.persist as persist
import scripts.phases.requests as requests
import scripts.phases.runio as runio
import scripts.read_guard_hook as read_guard_hook
import scripts.run_manifest as run_manifest
import scripts.runners.base as runners_base
import scripts.write_guard_hook as write_guard_hook

PHASE_OF_CHECKPOINT = {"scout": "scout", "review": "review", "verify": "verify",
                       "scan": "unattributed"}          # R-P6-9: collect_usage.PHASES keys
USAGE_FIELDS = ("input_tokens", "output_tokens",
                "cache_creation_input_tokens", "cache_read_input_tokens")
DEFAULT_MAX_ITERATIONS = 50


def _after_first_run(review_root):
    """Test seam: called once, after the first driver.run of a loop. Returns
    whether `loop` must re-derive `status` with another `driver.run` call
    before entering the while loop.

    Production always returns False -- a no-op, never patched outside
    tests/test_orchestrate.py. This is load-bearing, not decorative: a resume
    whose very first `driver.run` already lands on the `review` checkpoint
    (coverage was established by an earlier, now-dead process) would, with an
    UNCONDITIONAL second call here, re-run `review_execute` a second time with
    ZERO launches in between -- and `review_execute` bumps
    `cell-attempts.json` on every call that finds a cell pending, launch or
    no launch. That burns one third of a cell's `MAX_CELL_ATTEMPTS` retry
    budget for nothing, on every single resume that happens to land on
    `review`. Only the test seam, which mutates review_root BETWEEN the two
    calls (seeding coverage so the checkpoint the test observes is `review`
    rather than `scout`), has a reason to ask for the second derive."""
    return False


class Guards:
    """Arm and disarm both guards for one mode (spec 5.1)."""

    def __init__(self, mode, run_dir=None, session_root=None):
        self.mode = mode
        # I4: the union of entries THIS process armed, in arm() order. Session
        # mode is the only mode whose grants outlive an invocation (a
        # `dispatch` exit returns without disarming, by design), so an
        # invocation that errors must drop exactly what it armed -- nothing,
        # when it never got that far -- and leave the previous fan-out's
        # grants standing. `complete` still disarms totally (spec 5.1).
        self.armed_entries = []
        if mode == "headless":
            self.settings_path = os.path.join(run_dir, runners_base.SETTINGS_FILE)
            self.allowlist_path = os.path.join(run_dir, runners_base.ALLOWLIST_FILE)
            self.scope_path = os.path.join(run_dir, runners_base.SCOPE_FILE)
        else:
            self.session_root = session_root
            self.settings_path, self.allowlist_path, _ = write_guard_hook._resolve(None, None, session_root)
            _s, self.scope_path, _ = read_guard_hook._resolve(None, None, session_root)

    def arm(self, entries):
        if not entries:
            return
        armed = {e.get("id") for e in self.armed_entries}
        self.armed_entries += [e for e in entries
                               if isinstance(e, dict) and e.get("id") not in armed]
        if self.mode == "headless":
            write_guard_hook.install(entries, settings_path=self.settings_path,
                                     allowlist_path=self.allowlist_path)
            read_guard_hook.install(entries, settings_path=self.settings_path,
                                    scope_path=self.scope_path)
        else:
            write_guard_hook.install(entries, session_root=self.session_root)
            read_guard_hook.install(entries, session_root=self.session_root)

    def disarm(self, entries=None):
        """Scoped to `entries` when given (another fan-out may still be live), else total."""
        if self.mode == "headless":
            write_guard_hook.uninstall(plan=entries, settings_path=self.settings_path,
                                       allowlist_path=self.allowlist_path)
            read_guard_hook.uninstall(plan=entries, settings_path=self.settings_path,
                                      scope_path=self.scope_path)
        else:
            write_guard_hook.uninstall(plan=entries, session_root=self.session_root)
            read_guard_hook.uninstall(plan=entries, session_root=self.session_root)

    def env_for(self, entry):
        return {runners_base.ENV_ENTRY_ID: entry["id"],
                runners_base.ENV_WRITE_ALLOWLIST: os.path.abspath(self.allowlist_path),
                runners_base.ENV_READ_SCOPE: os.path.abspath(self.scope_path)}


class Ledger:
    """runs/<tag>/dispatch-ledger.jsonl: one line per runner call (spec 4.3)."""

    def __init__(self, run_dir):
        self.path = os.path.join(run_dir, "dispatch-ledger.jsonl")

    def record(self, entry, checkpoint, result, mode, host, duration_ms):
        line = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "entry_id": entry.get("id"), "checkpoint": checkpoint,
                "phase": PHASE_OF_CHECKPOINT.get(checkpoint, "unattributed"),
                "mode": mode, "host": host, "model": result.model, "ok": result.ok,
                "usage": {k: int(result.usage.get(k, 0) or 0) for k in USAGE_FIELDS} if result.usage else {},
                "cost_usd": result.cost_usd, "duration_ms": duration_ms,
                "session_id": result.session_id, "denials": result.denials, "error": result.error}
        # #1095, plan 6 review round 1: the ledger path is a `.panopticon`
        # artifact like any other; a plain `open(path, "a")` bypasses the
        # symlink confinement every other run-folder write goes through.
        with runio._open_a_nofollow(self.path) as fh:
            fh.write(json.dumps(line, sort_keys=True) + "\n")

    def lines(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                return [json.loads(x) for x in fh if x.strip()]
        except (OSError, ValueError):
            return []

    def total_cost(self):
        return sum(float(row.get("cost_usd") or 0) for row in self.lines())

    def usage_document(self):
        by_phase = {p: 0 for p in ("scout", "review", "verify", "unattributed")}
        by_field = {k: 0 for k in USAGE_FIELDS}
        for row in self.lines():
            if not row.get("ok"):
                continue
            usage = row.get("usage") or {}
            n = sum(int(usage.get(k, 0) or 0) for k in USAGE_FIELDS)
            by_phase[row.get("phase") or "unattributed"] = by_phase.get(row.get("phase") or "unattributed", 0) + n
            for k in USAGE_FIELDS:
                by_field[k] += int(usage.get(k, 0) or 0)
        return {"schema_version": 1, "total": sum(by_phase.values()), "by_phase": by_phase,
                "by_field": by_field, "source": "dispatch-ledger.jsonl",
                "definition": "every token the host's envelope reported for each successful "
                              "entry launch, summed over the four usage fields"}


def write_usage(review_root, ledger, namespace=None):
    """R-P6-4: rewritten after every batch so synthesize (which runs inside the
    engine, before `complete`) finds it; never estimated.

    `namespace` mirrors `host_probes.headless_settings_path`'s namespace-aware
    resolution (Task 6 fix round 1, item 2): `runio._pano(review_root,
    "usage.json")` alone follows whatever run-manifest.json happens to be on
    review_root, and for `namespace == "setup"` that can be a STALE review
    run's manifest, routing usage.json into that prior run's `runs/<tag>/`
    folder and clobbering it. Deriving the directory from
    `headless_settings_path` instead -- the SAME helper `loop`'s `run_dir`
    and the guard probes consult -- keeps this write in the one folder
    everything else for this invocation already agrees on: the flat
    `.panopticon/` for setup, the per-run tag folder for a review."""
    run_dir = os.path.dirname(host_probes.headless_settings_path(review_root, namespace))
    runio._write_json(os.path.join(run_dir, "usage.json"), ledger.usage_document())


def _pending(entries):
    """The resume set, from disk: every entry whose out_file is not yet good."""
    return [e for e in entries if isinstance(e, dict) and not persist.is_done(e)]


def _status(kind, message, **extra):
    st = {"status": kind, "phase": None, "checkpoint": None, "group": None,
          "dispatch_request": None, "advanced": [], "message": message}
    st.update(extra)
    return st


def _disarm_previous(guards, prev_req):
    """R-P6-6 (session mode): on re-entry, drop the PREVIOUS request's grants
    before arming the current pending set. Uninstall is scoped by id/out_file
    and install unions, so an entry still pending is re-armed a few lines
    below (this iteration's own `guards.arm(pending)`, computed from the
    FRESH request `_first_run` just wrote) and only a FINISHED entry actually
    falls away -- no bookkeeping file needed to tell the two apart.

    `prev_req` must be the dispatch request as it stood BEFORE this
    invocation's own `driver.run`/`run_setup_flow` call rewrote
    dispatch-request.json (`loop` reads it first thing, before `_first_run`)
    -- reading it fresh here instead would see the very request this same
    invocation just produced, never the previous one, and disarm nothing.

    I4: CALLED only once this invocation has a live checkpoint of its own. An
    invocation that lands on complete/error instead never reaches here, so an
    errored re-entry (flag drift, a bad --pr) leaves the previous fan-out's
    grants exactly as it found them -- that fan-out is still running under
    them. Deferring the teardown past `_first_run`'s posture probe changes
    nothing that probe measures: probe_write_guard_armed proves the MECHANISM
    and the settings file, explicitly not live arming."""
    entries = [e for e in (prev_req or {}).get("entries") or [] if isinstance(e, dict)]
    if entries:
        guards.disarm(entries)


def _resolve_host(args, review_root):
    """Which host this invocation dispatches for (I5).

    `--host` when given; otherwise the RUN's own host, off its manifest.
    `driver.run` is manifest-authoritative about this -- it refuses a `--host`
    that contradicts the manifest as flag drift -- so a resume WITHOUT the flag
    is still a gemini (or kimi, or generic) run. Resolving off
    `runio._DEFAULTS["host"]` instead dispatched claude agents into it, with
    no refusal anywhere on the path.

    A `--reset` run re-mints the manifest from argv, so the OUTGOING manifest
    must not steer this invocation: fall through to the default, which is what
    `driver.run` is about to write.
    """
    if getattr(args, "host", None):
        return args.host
    if not getattr(args, "reset", False):
        host = (run_manifest.load_manifest(review_root) or {}).get("host")
        if host:
            return host
    return runio._DEFAULTS["host"]


def _resolve_mode(args, host):
    """(mode, stderr_note) -- spec 4.4 (I8).

    `--mode` when the operator gave one. Otherwise headless when this host has
    a runner and session when it does not: "A host with no headless runner
    registered gets session mode with a stderr line saying so; `--mode
    headless` on such a host is an error." That last case is left to
    `runner_for`, which refuses with the sentence naming `--mode session`.
    """
    mode = getattr(args, "mode", None)
    if mode:
        return mode, None
    if runners_base.headless_available(host):
        return "headless", None
    return "session", (
        "driver loop: no headless runner for host %r (no skill/scripts/runners/%s.py); "
        "running in session mode -- the loop will print each batch for you to "
        "dispatch. Pass --mode headless to require a runner instead." % (host, host))


def loop(args):
    """spec 4.3. Returns the final status dict; never exits (the CLI owns exit)."""
    max_iterations = getattr(args, "max_iterations", None) or DEFAULT_MAX_ITERATIONS
    budget = getattr(args, "max_budget_usd", None)
    namespace = "setup" if getattr(args, "setup", False) else None
    guards = ledger = None
    # R-P6-6: review_root resolved ONCE, up front -- BEFORE `_first_run` below
    # calls driver.run()/run_setup_flow(), which rewrites dispatch-request.json
    # for whatever checkpoint this invocation lands on. A fresh run has no
    # manifest/run folder yet, so load_dispatch_request (just below) reads
    # back None -- "no previous entries", never an error (Task 6 ruling 3). A
    # resolve failure (a bad --pr, e.g.) is reported the same way driver.run()
    # itself reports it rather than raising out of loop(), which must never
    # raise.
    try:
        review_root = _review_root(args)
    except (RuntimeError, ValueError, OSError) as exc:
        return _status("error", "driver loop: could not resolve review root: %s" % exc)
    # I5 then I8: the mode fallback asks whether THIS host has a runner, so the
    # host has to be resolved first.
    host = _resolve_host(args, review_root)
    mode, note = _resolve_mode(args, host)
    if note:
        print(note, file=sys.stderr, flush=True)
    # Both are resolved BEFORE `_first_run`, and the resolved mode is written
    # back onto `args`, deliberately. `driver._establish_host_posture` reads
    # `args.mode` to decide WHICH settings file the guard probes measure (spec
    # 5.4: the run folder's in headless mode, the session root's otherwise),
    # and it runs on EVERY `driver.run` call. Leaving `args.mode` at None for
    # the first call and resolving afterwards would probe the session root once
    # and the run folder from then on -- and on any machine whose session root
    # has no settings file (the #1493 case) those two disagree about
    # artifact_write_guard, so the run would refuse ITSELF as mid-run posture
    # drift on its second invocation. This is why host resolution reads the
    # manifest here rather than after `_first_run`; `--reset` is handled in
    # `_resolve_host` so the outgoing manifest cannot steer a re-minted run.
    args.mode = mode
    try:
        runner = runners_base.runner_for(host, mode)
    except ValueError as exc:
        return _status("error", str(exc))
    # R-P6 Task 5 ruling 1: the SAME rule driver.run() applies to
    # manifest["session_dir"] -- never read off the on-disk manifest, which
    # never persists it (driver.run() sets it in memory, post write-manifest,
    # precisely so a resume that omits --session-dir legitimately falls back
    # to cwd). Re-deriving it from run_manifest.load_manifest(...) here would
    # silently resolve the OPERATOR's real session root in session mode.
    session_root = (os.path.abspath(args.session_dir) if getattr(args, "session_dir", None)
                    else os.getcwd())
    # The OUTGOING dispatch request, read BEFORE `_first_run` rewrites it
    # (R-P6-6): reading it afterwards would see the very request this same
    # invocation just produced and disarm nothing. Read in every mode -- it is
    # one JSON load -- so that the READ and the ACT can sit on opposite sides
    # of `_first_run`, which I4 requires.
    prev_req = requests.load_dispatch_request(review_root, namespace) or {}
    if mode == "session":
        # Guards constructed HERE, before `_first_run`, and unconditionally --
        # not only once this invocation reaches a fresh checkpoint. Session
        # mode is the only mode whose guards can stay armed ACROSS
        # invocations (a `dispatch` exit returns before ever disarming, by
        # design -- the host has not run anything yet), so an invocation
        # whose OWN `_first_run` lands directly on complete -- the run's last
        # checkpoint having been finished externally, with no `while`
        # iteration of THIS call to disarm it -- would otherwise leave the
        # PREVIOUS invocation's grants armed forever: `_finish` can only
        # disarm a `guards` it was handed, and building one only after a
        # checkpoint survives skips exactly this case. `run_dir` is not
        # needed here: `Guards` ignores it outside headless mode, and the
        # settings/allowlist/scope paths it resolves depend only on
        # `session_root`, which does not change across a run.
        guards = Guards(mode, session_root=session_root)
    status = _first_run(args, namespace)
    if status.get("status") != "checkpoint":
        return _finish(status, args, guards, ledger, namespace, mode)
    if mode == "session":
        # I4: only now. This invocation has a live checkpoint of its own, so
        # its pending set is the authority on what is still running. An entry
        # now done falls away here; one still pending is re-armed below by
        # this iteration's own `guards.arm(pending)`, computed from the FRESH
        # request `_first_run` just wrote (Task 6 ruling 3).
        _disarm_previous(guards, prev_req)
    if _after_first_run(review_root):
        status = _run(args, namespace)                # re-derive after the seam
    iterations = 0
    try:
        # M8: the pre-loop setup lives INSIDE the try. `loop` never raises
        # (review round 1, item 3), but every line of it touches the
        # filesystem -- resolving the run folder, writing host-settings.json,
        # resolving the guard paths -- and an OSError (a read-only run folder,
        # an unwritable settings path) escaped as a traceback rather than the
        # reported `error` status every other failure here produces.
        #
        # Task 6 fix round 1, item 2: derived through host_probes.headless_settings_path
        # (namespace-aware), never a bare `runio._pano(review_root, SETTINGS_FILE)`
        # -- for namespace == "setup" that would follow whatever run-manifest.json
        # a PRIOR review run left on review_root and route setup's own
        # host-settings.json/dispatch-ledger.jsonl/usage.json into that run's
        # runs/<tag>/ folder.
        run_dir = os.path.dirname(host_probes.headless_settings_path(review_root, namespace))
        runner.prepare(run_dir, review_root)
        # C2/M4: the session runner prints the batch itself, so it needs the
        # two facts only the loop holds -- which request file these entries
        # came from, and whether this is the setup namespace (which every
        # command it hints at must carry as `--setup`). Set unconditionally: a
        # headless runner simply carries two attributes it never reads.
        runner.dispatch_request = os.path.abspath(
            requests.request_path(review_root, namespace))
        runner.namespace = namespace
        for attr in ("max_turns", "entry_timeout"):
            if getattr(args, attr, None):
                setattr(runner, attr, getattr(args, attr))
        if mode != "session":
            guards = Guards(mode, run_dir=run_dir, session_root=session_root)
        ledger = Ledger(run_dir)
        while status.get("status") == "checkpoint":
            iterations += 1
            req = requests.load_dispatch_request(review_root, namespace) or {}
            entries = [e for e in req.get("entries") or [] if isinstance(e, dict)]
            pending = _pending(entries)
            pending_ids = ", ".join(e.get("id") for e in pending)
            if iterations > max_iterations:
                return _finish(_status("error", "driver loop: %d iterations without "
                                       "completing; still pending: %s"
                                       % (max_iterations, pending_ids)),
                               args, guards, ledger, namespace, mode)
            if budget is not None and ledger.total_cost() >= float(budget):
                return _finish(_status("error", "driver loop: --max-budget-usd %s reached; "
                                       "ledger at %s; still pending: %s"
                                       % (budget, ledger.path, pending_ids)),
                               args, guards, ledger, namespace, mode)
            guards.arm(pending)
            results = runner.run_batch(pending, getattr(args, "concurrency", None), guards.env_for)
            if results is None:                                 # session mode (Task 6)
                return _dispatch_exit(review_root, req, pending, namespace)
            for entry, result in zip(pending, results):
                ledger.record(entry, req.get("checkpoint"), result, mode, runner.host, None)
                if result.ok and entry.get("delivery") == "return_json":
                    ok, reason = persist.write_reply(entry, result.text)
                    if not ok:
                        print("driver loop: %s" % reason, file=sys.stderr, flush=True)
                elif not result.ok:
                    print("driver loop: entry %s failed: %s" % (entry.get("id"), result.error),
                          file=sys.stderr, flush=True)
            write_usage(review_root, ledger, namespace)
            guards.disarm(pending)
            status = _run(args, namespace)
    except KeyboardInterrupt:
        status = _status("error", "interrupted (Ctrl-C); guards disarmed; re-run to resume from disk")
    except Exception as exc:                # noqa: BLE001 -- `loop` never raises (review round 1, item 3)
        status = _status("error", "driver loop: %s: %s" % (type(exc).__name__, exc))
    return _finish(status, args, guards, ledger, namespace, mode)


def _review_root(args):
    review_root, _wt, _pr = runio.resolve_review_root(args.target, base=args.base, pr=args.pr)
    return review_root


def _run(args, namespace):
    if namespace == "setup":
        import scripts.phases.setup as setup
        return setup.run_setup_flow(args)
    return driver.run(args)


def _first_run(args, namespace):
    return _run(args, namespace)


def _dispatch_exit(review_root, req, pending, namespace):
    """Session mode: the runner printed the batch; exit with a dispatch status
    and leave the guards armed (spec 4.3).

    C2: `dispatch_request` comes from `requests.request_path` -- the one
    accessor that knows a review's request is per-run
    (`runs/<tag>/dispatch-request.json`) while setup keeps its own top-level
    file (#1507). It used to be read off the request DOCUMENT, which carries
    no such key (schema_version, run_id, checkpoint, group, entries), so the
    field was None on every dispatch and the host had no path to
    cross-reference the printed entries against.

    M4: the hints carry `--setup` in the setup namespace. Without it both
    `driver persist <id>` and the follow-up `driver loop` resolve the REVIEW
    namespace, where the entry does not exist.
    """
    setup = " --setup" if namespace == "setup" else ""
    return _status("dispatch", "session mode: run the printed entries, persist each "
                   "return-persist reply with `driver persist <id>%s`, then re-run "
                   "`driver loop%s --mode session`" % (setup, setup),
                   dispatch_request=os.path.abspath(
                       requests.request_path(review_root, namespace)),
                   pending=[e.get("id") for e in pending],
                   checkpoint=req.get("checkpoint"))


def _finish(status, args, guards, ledger, namespace, mode="headless"):
    """The terminal teardown, executed for every non-checkpoint status. Disarm
    first, then attempt a final write_usage on BOTH `complete` and `error`
    (review round 2): the `except Exception` catch-all (round 1, item 3) can
    land here after a batch already recorded a ledger line but before that
    iteration's own in-loop write_usage ran, and a `complete`-only write would
    leave usage.json stale against the ledger. Wrapped so a failure here can
    never mask the real status -- it is appended to the message instead."""
    if guards is not None:
        if status.get("status") == "complete":
            guards.disarm()                          # total (spec 5.1)
        elif status.get("status") == "error" and guards.armed_entries:
            # I4: exactly what THIS invocation armed, and nothing else. In
            # session mode the grants outlive an invocation, so a total
            # teardown here would revoke a fan-out the PREVIOUS invocation
            # started and that is still running. An invocation that armed
            # nothing (an errored re-entry) disarms nothing.
            guards.disarm(guards.armed_entries)
    # M9: the ledger-derived usage.json belongs to headless runs only. In
    # session mode the loop launches nothing, so the ledger is empty and this
    # document is all zeros -- while the run's REAL figures come from the
    # host's own transcripts via collect_usage, which synthesize wires in and
    # which deliberately never overwrites an existing usage.json. Writing here
    # would replace the real counts with zeros.
    if mode == "headless" and status.get("status") in ("complete", "error") and ledger is not None:
        try:
            write_usage(_review_root(args), ledger, namespace)
        except Exception as exc:      # noqa: BLE001 -- must not mask the original status
            status["message"] = "%s; usage.json not written: %s: %s" % (
                status.get("message"), type(exc).__name__, exc)
    if namespace == "setup" and status.get("status") == "complete":
        # spec 4.6, R-P6-10: `driver loop --setup` names its own artifacts and
        # the promotion command, superseding whatever message run_setup_flow's
        # own `complete` branch composed (that wording is for `driver setup`
        # run directly, not for `driver loop --setup`'s on-rails contract).
        #
        # Fix round 1, item 1: ONLY when a draft actually exists -- the
        # vocab-absent fallback (phases/setup.py's _scan_fallback) seeds
        # groups.yml directly and writes NEITHER setup-report.md NOR
        # groups.yml.draft, so unconditionally naming them here would send
        # the operator to files that were never written and a promotion `mv`
        # that would fail. run_setup_flow's own `complete` branch already
        # composed the right message for that path (readiness gaps and
        # limitations included) -- leave `status["message"]` exactly as it
        # is when there is no draft to promote.
        review_root = _review_root(args)
        draft = runio._pano(review_root, "groups.yml.draft")
        if os.path.isfile(draft):
            status = dict(status, message=(
                "setup complete: read %s, review %s, then promote it: mv %s %s (setup never "
                "overwrites a committed groups.yml)" % (
                    runio._pano(review_root, "setup-report.md"), draft, draft,
                    runio._pano(review_root, "groups.yml"))))
    return status


def persist_cli(args):
    """`driver persist ENTRY_ID [--file PATH] [--setup] [target]` -> exit code."""
    review_root, _wt, _pr = runio.resolve_review_root(args.target)
    entry = persist.find_entry(review_root, args.entry_id,
                               namespace="setup" if args.setup else None)
    if entry is None:
        print("driver persist: no entry %r in the current dispatch request"
              % args.entry_id, file=sys.stderr)
        return 1
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()
    ok, reason = persist.write_reply(entry, text)
    if not ok:
        print("driver persist: %s" % reason, file=sys.stderr)
        return 1
    print(os.path.abspath(entry["out_file"]))
    return 0


def main_verb(args):
    if args.verb == "persist":
        return persist_cli(args)
    return engine.emit_status(loop(args))
