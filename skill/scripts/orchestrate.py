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
import scripts.phases.engine as engine
import scripts.phases.persist as persist
import scripts.phases.requests as requests
import scripts.phases.runio as runio
import scripts.read_guard_hook as read_guard_hook
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
        if mode == "headless":
            self.settings_path = os.path.join(run_dir, runners_base.SETTINGS_FILE)
            self.allowlist_path = os.path.join(run_dir, "write-allowlist.json")
            self.scope_path = os.path.join(run_dir, "read-scope.json")
        else:
            self.session_root = session_root
            self.settings_path, self.allowlist_path, _ = write_guard_hook._resolve(None, None, session_root)
            _s, self.scope_path, _ = read_guard_hook._resolve(None, None, session_root)

    def arm(self, entries):
        if not entries:
            return
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
        kw = ({"settings_path": self.settings_path} if self.mode == "headless"
              else {"session_root": self.session_root})
        if self.mode == "headless":
            write_guard_hook.uninstall(plan=entries, allowlist_path=self.allowlist_path, **kw)
            read_guard_hook.uninstall(plan=entries, scope_path=self.scope_path, **kw)
        else:
            write_guard_hook.uninstall(plan=entries, **kw)
            read_guard_hook.uninstall(plan=entries, **kw)

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


def write_usage(review_root, ledger):
    """R-P6-4: rewritten after every batch so synthesize (which runs inside the
    engine, before `complete`) finds it; never estimated."""
    runio._write_json(runio._pano(review_root, "usage.json"), ledger.usage_document())


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
    invocation just produced, never the previous one, and disarm nothing."""
    entries = [e for e in (prev_req or {}).get("entries") or [] if isinstance(e, dict)]
    if entries:
        guards.disarm(entries)


def loop(args):
    """spec 4.3. Returns the final status dict; never exits (the CLI owns exit)."""
    mode = getattr(args, "mode", "headless")
    try:
        runner = runners_base.runner_for(args.host or runio._DEFAULTS["host"], mode)
    except ValueError as exc:
        return _status("error", str(exc))
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
    # R-P6 Task 5 ruling 1: the SAME rule driver.run() applies to
    # manifest["session_dir"] -- never read off the on-disk manifest, which
    # never persists it (driver.run() sets it in memory, post write-manifest,
    # precisely so a resume that omits --session-dir legitimately falls back
    # to cwd). Re-deriving it from run_manifest.load_manifest(...) here would
    # silently resolve the OPERATOR's real session root in session mode.
    session_root = (os.path.abspath(args.session_dir) if getattr(args, "session_dir", None)
                    else os.getcwd())
    if mode == "session":
        # Guards constructed HERE, before `_first_run`, and unconditionally --
        # not only once this invocation reaches a fresh checkpoint. Session
        # mode is the only mode whose guards can stay armed ACROSS
        # invocations (a `dispatch` exit returns before ever disarming, by
        # design -- the host has not run anything yet), so an invocation
        # whose OWN `_first_run` lands directly on complete/error -- the
        # run's last checkpoint having been finished externally, with no
        # `while` iteration of THIS call to disarm it -- would otherwise
        # leave the PREVIOUS invocation's grants armed forever: `_finish` can
        # only disarm a `guards` it was handed, and building one only after a
        # checkpoint survives skips exactly this case. `run_dir` is not
        # needed here: `Guards` ignores it outside headless mode, and the
        # settings/allowlist/scope paths it resolves depend only on
        # `session_root`, which does not change across a run.
        #
        # `_disarm_previous` reads the request as it stood BEFORE the
        # `_first_run` call below rewrites it (R-P6-6): an entry now done
        # falls away; one still pending is re-armed a few lines later by this
        # same iteration's own `guards.arm(pending)`, computed from the FRESH
        # request `_first_run` just wrote (Task 6 ruling 3).
        guards = Guards(mode, session_root=session_root)
        prev_req = requests.load_dispatch_request(review_root, namespace) or {}
        _disarm_previous(guards, prev_req)
    status = _first_run(args, namespace)
    if status.get("status") != "checkpoint":
        return _finish(status, args, guards, ledger, namespace)
    if _after_first_run(review_root):
        status = _run(args, namespace)                # re-derive after the seam
    run_dir = os.path.dirname(runio._pano(review_root, runners_base.SETTINGS_FILE))
    runner.prepare(run_dir, review_root)
    for attr in ("max_turns", "entry_timeout"):
        if getattr(args, attr, None):
            setattr(runner, attr, getattr(args, attr))
    if mode != "session":
        guards = Guards(mode, run_dir=run_dir, session_root=session_root)
    ledger = Ledger(run_dir)
    iterations = 0
    try:
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
                               args, guards, ledger, namespace)
            if budget is not None and ledger.total_cost() >= float(budget):
                return _finish(_status("error", "driver loop: --max-budget-usd %s reached; "
                                       "ledger at %s; still pending: %s"
                                       % (budget, ledger.path, pending_ids)),
                               args, guards, ledger, namespace)
            guards.arm(pending)
            results = runner.run_batch(pending, getattr(args, "concurrency", None), guards.env_for)
            if results is None:                                 # session mode (Task 6)
                return _dispatch_exit(req, pending, namespace)
            for entry, result in zip(pending, results):
                ledger.record(entry, req.get("checkpoint"), result, mode, runner.host, None)
                if result.ok and entry.get("delivery") == "return_json":
                    ok, reason = persist.write_reply(entry, result.text)
                    if not ok:
                        print("driver loop: %s" % reason, file=sys.stderr, flush=True)
                elif not result.ok:
                    print("driver loop: entry %s failed: %s" % (entry.get("id"), result.error),
                          file=sys.stderr, flush=True)
            write_usage(review_root, ledger)
            guards.disarm(pending)
            status = _run(args, namespace)
    except KeyboardInterrupt:
        status = _status("error", "interrupted (Ctrl-C); guards disarmed; re-run to resume from disk")
    except Exception as exc:                # noqa: BLE001 -- `loop` never raises (review round 1, item 3)
        status = _status("error", "driver loop: %s: %s" % (type(exc).__name__, exc))
    return _finish(status, args, guards, ledger, namespace)


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


def _dispatch_exit(req, pending, namespace):
    """Session mode: the runner printed the batch; exit with a dispatch status
    and leave the guards armed (spec 4.3)."""
    return _status("dispatch", "session mode: run the printed entries, persist each "
                   "return-persist reply with `driver persist <id>`, then re-run driver loop",
                   dispatch_request=req.get("dispatch_request"), pending=[e.get("id") for e in pending],
                   checkpoint=req.get("checkpoint"))


def _finish(status, args, guards, ledger, namespace):
    """The terminal teardown, executed for every non-checkpoint status. Disarm
    first, then attempt a final write_usage on BOTH `complete` and `error`
    (review round 2): the `except Exception` catch-all (round 1, item 3) can
    land here after a batch already recorded a ledger line but before that
    iteration's own in-loop write_usage ran, and a `complete`-only write would
    leave usage.json stale against the ledger. Wrapped so a failure here can
    never mask the real status -- it is appended to the message instead."""
    if status.get("status") in ("complete", "error") and guards is not None:
        guards.disarm()
    if status.get("status") in ("complete", "error") and ledger is not None:
        try:
            write_usage(_review_root(args), ledger)
        except Exception as exc:      # noqa: BLE001 -- must not mask the original status
            status["message"] = "%s; usage.json not written: %s: %s" % (
                status.get("message"), type(exc).__name__, exc)
    if namespace == "setup" and status.get("status") == "complete":
        # spec 4.6, R-P6-10: `driver loop --setup` names its own artifacts and
        # the promotion command, superseding whatever message run_setup_flow's
        # own `complete` branch composed (that wording is for `driver setup`
        # run directly, not for `driver loop --setup`'s on-rails contract).
        review_root = _review_root(args)
        status = dict(status, message=(
            "setup complete: read %s, review %s, then promote it: mv %s %s (setup never "
            "overwrites a committed groups.yml)" % (
                runio._pano(review_root, "setup-report.md"), runio._pano(review_root, "groups.yml.draft"),
                runio._pano(review_root, "groups.yml.draft"), runio._pano(review_root, "groups.yml"))))
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
