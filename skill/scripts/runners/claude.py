"""The Claude headless runner (spec 4.4): one `claude -p` per entry, hooks
supplied by a run-specific --settings file, usage from the JSON envelope."""
import json
import os
import subprocess

import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.write_guard_hook as write_guard_hook


class Runner(base.HostRunner):
    CLI = "claude"
    mode = "headless"
    default_concurrency = 8

    def __init__(self, host="claude", runner=subprocess.run):
        super().__init__(host)
        self.runner = runner
        self.settings_path = None
        self.allowlist_path = None
        self.scope_path = None
        self.review_root = None
        self.max_turns = 60
        self.entry_timeout = 1800          # seconds per entry; a stuck agent is a failed entry
        self.per_entry_budget_usd = None

    def prepare(self, run_dir, review_root):
        """Write <run_dir>/host-settings.json: both guards' PreToolUse entries
        with absolute allowlist/scope paths baked in, nothing else (D3)."""
        self.review_root = os.path.abspath(review_root)
        self.settings_path = os.path.join(run_dir, base.SETTINGS_FILE)
        self.allowlist_path = os.path.join(run_dir, "write-allowlist.json")
        self.scope_path = os.path.join(run_dir, "read-scope.json")
        settings = {"hooks": {"PreToolUse": [
            write_guard_hook._hook_entry(self.allowlist_path),
            read_guard_hook._hook_entry(self.scope_path)]}}
        os.makedirs(run_dir, exist_ok=True)
        tmp = self.settings_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(settings, fh, indent=2)
        os.replace(tmp, self.settings_path)

    def command(self, entry, settings_path, max_turns, budget_usd=None):
        cmd = [self.CLI, "-p", "--settings", settings_path, "--output-format", "json",
               "--no-session-persistence", "--max-turns", str(int(max_turns))]
        if entry.get("enforced") and entry.get("agent"):
            cmd += ["--agent", entry["agent"]]
        elif entry.get("model"):
            cmd += ["--model", entry["model"]]
        if budget_usd is not None:
            cmd += ["--max-budget-usd", str(budget_usd)]
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
        # A nested `claude -p` refuses to start inside a Claude Code session,
        # so the marker that says "you're already inside one" must not survive
        # into the child's environment.
        run_env = {k: v for k, v in dict(env).items() if k != "CLAUDECODE"}
        cmd = self.command(entry, self.settings_path, self.max_turns, self.per_entry_budget_usd)
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
