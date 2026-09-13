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
    """Test seam: called once, after the first driver.run of a loop. A no-op
    in production; never patched outside tests/test_orchestrate.py."""


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
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
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
    status = _first_run(args, namespace)
    if status.get("status") != "checkpoint":
        return _finish(status, args, guards, ledger, namespace)
    review_root = _review_root(args)
    _after_first_run(review_root)
    status = _run(args, namespace)                    # re-derive after the seam
    run_dir = os.path.dirname(runio._pano(review_root, runners_base.SETTINGS_FILE))
    runner.prepare(run_dir, review_root)
    for attr in ("max_turns", "entry_timeout"):
        if getattr(args, attr, None):
            setattr(runner, attr, getattr(args, attr))
    # R-P6 Task 5 ruling 1: the SAME rule driver.run() applies to
    # manifest["session_dir"] -- never read off the on-disk manifest, which
    # never persists it (driver.run() sets it in memory, post write-manifest,
    # precisely so a resume that omits --session-dir legitimately falls back
    # to cwd). Re-deriving it from run_manifest.load_manifest(...) here would
    # silently resolve the OPERATOR's real session root in session mode.
    session_root = (os.path.abspath(args.session_dir) if getattr(args, "session_dir", None)
                    else os.getcwd())
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
            # `>=`, not `>`: a cell's own retry budget (MAX_CELL_ATTEMPTS) can
            # exhaust and let the ENGINE reach `complete` on its own after
            # `max_iterations` launches of one stuck entry -- checking after
            # incrementing but before spending this iteration's launch stops
            # us one launch short of that race, so `--max-iterations N`
            # reliably reports N iterations without completing rather than
            # occasionally losing to the engine's own exhaustion path.
            if iterations >= max_iterations:
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
    if status.get("status") == "complete" and guards is not None:
        guards.disarm()                                          # the terminal teardown, executed
        if ledger is not None:
            write_usage(_review_root(args), ledger)
    elif status.get("status") == "error" and guards is not None:
        guards.disarm()
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
