"""The Claude headless runner (spec 4.4): one `claude -p` per entry, hooks
supplied by a run-specific --settings file, usage from the JSON envelope."""
import json
import os
import subprocess

import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.write_guard_hook as write_guard_hook


# The launcher a Runner built without an injected `runner=` uses. Read at
# CONSTRUCTION, never bound as a default argument: tests/conftest.py swaps it
# for a refusal for the whole suite (family guardrails section 3, #1616), so
# forgetting `runner=<fake>` in a test costs one failed RunResult rather than a
# real `claude -p` launch and the money it spends.
DEFAULT_RUNNER = subprocess.run


class Runner(base.HostRunner):
    CLI = "claude"
    # The two argv tokens that make a launch print the JSON envelope `usage`
    # is read from (`command` below puts both on every argv). The usage probe
    # asks the CLI it finds on PATH to advertise exactly these, so any
    # executable that happens to be called `claude` no longer proves the
    # ledger; the rest of the argv (`--max-turns`, e.g.) is not in `--help`
    # and not the envelope's business.
    ENVELOPE_FLAGS = ("-p", "--output-format")
    # D10 ruling 3: `claude -p --json-schema <file>` ("JSON Schema for
    # structured output"). Appended only for an entry whose role publishes one.
    OUTPUT_SCHEMA_FLAG = ("--json-schema",)
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
        cmd += base.schema_argv(self.OUTPUT_SCHEMA_FLAG, entry)
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
        # D10 ruling 3: under `--json-schema` the CLI may return the object in
        # `structured_output` ALONGSIDE or INSTEAD OF the `result` text, and
        # the loop has to persist the object either way. Serialised, because
        # everything downstream of a runner takes the reply as text and
        # `persist._parse_reply` parses it back -- the same round trip a fenced
        # `result` makes, minus the fence. `result` stays the fallback: an
        # entry with no schema, or a CLI build that ignores the flag, is
        # exactly what it was.
        structured = data.get("structured_output")
        text = (json.dumps(structured) if structured
                else (data.get("result") if isinstance(data.get("result"), str) else ""))
        error = None
        if returncode != 0:
            error = "claude -p exited %s: %s" % (returncode, text[:200])
        elif data.get("is_error"):
            error = "claude -p reported is_error: %s" % text[:200]
        return base.RunResult(entry_id=entry_id, ok=error is None, text=text if error is None else "",
                               usage=usage, cost_usd=data.get("total_cost_usd"), model=model,
                               session_id=data.get("session_id"), denials=denials, error=error)

    def launch_env(self, overlay=None):
        """The seam's preparation (`base.HostRunner.launch_env`) plus this
        family's one rule: a nested `claude -p` refuses to start inside a
        Claude Code session, so the marker that says "you are already inside
        one" must not survive into the child.

        Dropped AFTER the merge, since it is `os.environ` that carries it and
        the overlay never does -- the order the inline version used, kept.

        Called by `run_entry` for every launch AND by the usage probe's
        `--help` interrogation (#1626 I2), which is the point: the probe asks
        the CLI what it advertises under the same environment a real entry
        gets, not under the caller's.
        """
        run_env = super().launch_env(overlay)
        run_env.pop("CLAUDECODE", None)
        return run_env

    def run_entry(self, entry, env):
        # C1 (final review): `env` is the loop's three-key BINDING OVERLAY
        # (spec 4.4), never a whole environment -- so the child inherits this
        # process's os.environ and the overlay goes ON TOP. Replacing the
        # environment with the overlay alone left the child with no PATH and
        # no HOME, and `claude` was then unfindable: every entry of every run
        # failed with FileNotFoundError. `launch_env` is where that merge --
        # and this family's CLAUDECODE pop -- now lives, once.
        run_env = self.launch_env(env)
        cmd = self.command(entry, self.settings_path, self.max_turns)
        try:
            proc = self.runner(cmd, cwd=self.review_root, env=run_env, capture_output=True,
                                text=True, timeout=self.entry_timeout)
        except subprocess.TimeoutExpired as exc:
            # D10 ruling 5: keep what the killed child printed. No usage with
            # it: `claude -p` prints its envelope once, at the end, so a
            # partial stdout carries no figure to read -- recorded as the empty
            # truth rather than a fabricated zero.
            return base.RunResult.failed(entry.get("id"), "claude -p timed out after %ss" % self.entry_timeout,
                                          text=base.partial_output(exc))
        except OSError as exc:
            return base.RunResult.failed(entry.get("id"), "could not launch %s: %s" % (self.CLI, exc))
        except Exception as exc:          # run_entry never raises (spec 4.4): anything else is a failed entry
            return base.RunResult.failed(entry.get("id"),
                                          "claude -p launch raised %s: %s" % (type(exc).__name__, exc))
        return self.parse_envelope(entry.get("id"), proc.stdout, proc.returncode)
