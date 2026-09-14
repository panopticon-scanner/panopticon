"""The Claude headless runner (spec 4.4): one `claude -p` per entry, hooks
supplied by a run-specific --settings file, usage from the JSON envelope."""
import json
import os
import subprocess

import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.write_guard_hook as write_guard_hook


# The launcher, as a MODULE attribute rather than a default argument, for the
# reason spelled out in runners/codex.py: a default argument is bound at import
# and no monkeypatch can swap it, so the suite's autouse guard cannot refuse an
# un-injected launch of the real `claude` binary through this seam.
DEFAULT_RUNNER = subprocess.run


class Runner(base.HostRunner):
    CLI = "claude"
    mode = "headless"
    default_concurrency = 8

    def __init__(self, host="claude", runner=None):
        super().__init__(host)
        self.runner = DEFAULT_RUNNER if runner is None else runner
        self.settings_path = None
        self.allowlist_path = None
        self.scope_path = None
        self.review_root = None
        self.max_turns = 60
        self.entry_timeout = 1800          # seconds per entry; a stuck agent is a failed entry

    def prepare(self, run_dir, review_root):
        """Write <run_dir>/host-settings.json: both guards' PreToolUse entries
        with absolute allowlist/scope paths baked in, nothing else (D3)."""
        self.review_root = os.path.abspath(review_root)
        self.settings_path = os.path.join(run_dir, base.SETTINGS_FILE)
        self.allowlist_path = os.path.join(run_dir, base.ALLOWLIST_FILE)
        self.scope_path = os.path.join(run_dir, base.SCOPE_FILE)
        settings = {"hooks": {"PreToolUse": [
            write_guard_hook._hook_entry(self.allowlist_path),
            read_guard_hook._hook_entry(self.scope_path)]}}
        os.makedirs(run_dir, exist_ok=True)
        # I7: through the write guard's own atomic writer, which refuses to
        # follow a symlink planted at `host-settings.json.tmp`. That path is
        # INSIDE the scanned tree, so on a redteam target the link is the
        # attacker's to plant; this module already imports the hook for
        # `_hook_entry`, so there is one hardened writer rather than a second
        # open()/replace() pair here to keep in step with it.
        write_guard_hook._atomic_write_json(self.settings_path, settings, indent=2)

    def command(self, entry, settings_path, max_turns):
        """The argv for one entry. No per-entry budget arm (M5, final review):
        `--max-budget-usd` is a WHOLE-RUN knob the loop enforces itself off
        the dispatch ledger (spec 4.3), and the per-entry parameter this used
        to carry was set by nobody -- a flag that could never reach a launch,
        reading like a live cap."""
        cmd = [self.CLI, "-p", "--settings", settings_path, "--output-format", "json",
               "--no-session-persistence", "--max-turns", str(int(max_turns))]
        if entry.get("enforced") and entry.get("agent"):
            cmd += ["--agent", entry["agent"]]
        elif entry.get("model"):
            cmd += ["--model", entry["model"]]
        cmd.append(entry["prompt"])
        return cmd

    def parse_envelope(self, entry_id, stdout, returncode):
        try:
            data = json.loads(stdout or "")
        except ValueError:
            return base.RunResult.failed(entry_id, "claude -p printed no JSON envelope (exit %s)" % returncode)
        if not isinstance(data, dict):
            return base.RunResult.failed(entry_id, "claude -p envelope is not an object")
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        model_usage = data.get("modelUsage") if isinstance(data.get("modelUsage"), dict) else {}
        model = next(iter(model_usage), None)
        denials = data.get("permission_denials") if isinstance(data.get("permission_denials"), list) else []
        text = data.get("result") if isinstance(data.get("result"), str) else ""
        error = None
        if returncode != 0:
            error = "claude -p exited %s: %s" % (returncode, text[:200])
        elif data.get("is_error"):
            error = "claude -p reported is_error: %s" % text[:200]
        return base.RunResult(entry_id=entry_id, ok=error is None, text=text if error is None else "",
                               usage=usage, cost_usd=data.get("total_cost_usd"), model=model,
                               session_id=data.get("session_id"), denials=denials, error=error)

    def run_entry(self, entry, env):
        # C1 (final review): `env` is the loop's three-key BINDING OVERLAY
        # (spec 4.4), never a whole environment -- so the child inherits this
        # process's os.environ and the overlay goes ON TOP. Replacing the
        # environment with the overlay alone left the child with no PATH and
        # no HOME, and `claude` was then unfindable: every entry of every run
        # failed with FileNotFoundError.
        #
        # A nested `claude -p` refuses to start inside a Claude Code session,
        # so the marker that says "you're already inside one" must not survive
        # into the child's environment -- dropped AFTER the merge, since it is
        # os.environ that carries it.
        run_env = dict(os.environ)
        run_env.update(env)
        run_env.pop("CLAUDECODE", None)
        cmd = self.command(entry, self.settings_path, self.max_turns)
        try:
            proc = self.runner(cmd, cwd=self.review_root, env=run_env, capture_output=True,
                                text=True, timeout=self.entry_timeout)
        except subprocess.TimeoutExpired:
            return base.RunResult.failed(entry.get("id"), "claude -p timed out after %ss" % self.entry_timeout)
        except OSError as exc:
            return base.RunResult.failed(entry.get("id"), "could not launch %s: %s" % (self.CLI, exc))
        except Exception as exc:          # run_entry never raises (spec 4.4): anything else is a failed entry
            return base.RunResult.failed(entry.get("id"),
                                          "claude -p launch raised %s: %s" % (type(exc).__name__, exc))
        return self.parse_envelope(entry.get("id"), proc.stdout, proc.returncode)
