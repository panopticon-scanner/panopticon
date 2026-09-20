"""The Claude headless runner (spec 4.4): one `claude -p` per entry, hooks
supplied by a run-specific --settings file, usage from the JSON envelope."""
import json
import os
import subprocess

import scripts.runners.base as base
import scripts.runners.outage as outage


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
    # D10 ruling 3: `claude -p --json-schema <schema>` ("JSON Schema for
    # structured output") -- the schema's TEXT, not a file (MEASURED on
    # 2.1.276; see base.inline_schema). Appended only for an entry whose role
    # publishes one.
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
        """Resolve this run's three guard paths and make sure the folder the
        loop writes them into exists.

        It does NOT write host-settings.json (#1616 item 5). `prepare` used to
        compose both guards' PreToolUse entries there, and
        `orchestrate.Guards.arm` then rewrote the same file -- through
        `write_guard_hook.install` / `read_guard_hook.install`, which register
        exactly the same two entries -- before the first launch of every
        batch. So the file this wrote was replaced without ever being read,
        and two writers meant two definitions of the contract to keep in step.
        Arming is the one that survives: it is what the guards themselves
        maintain, and it happens per batch rather than once per run.

        The FOLDER is still this method's business -- `probe_write_guard_armed`
        proves the run folder is writable, and the ledger lands here -- and so
        is `review_root`, which is the cwd every child is launched in.
        """
        self.review_root = os.path.abspath(review_root)
        self.settings_path = os.path.join(run_dir, base.SETTINGS_FILE)
        self.allowlist_path = os.path.join(run_dir, base.ALLOWLIST_FILE)
        self.scope_path = os.path.join(run_dir, base.SCOPE_FILE)
        os.makedirs(run_dir, exist_ok=True)

    def command(self, entry, settings_path, max_turns):
        """The argv for one entry. No per-entry budget arm (M5, final review):
        `--max-budget-usd` is a WHOLE-RUN knob the loop enforces itself off
        the dispatch ledger (spec 4.3), and the per-entry parameter this used
        to carry was set by nobody -- a flag that could never reach a launch,
        reading like a live cap.

        THE THREE DISCOVERY FLAGS (#1657 step 2). The child is launched in the
        REVIEWED TREE, which is exactly where `claude` looks for
        `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json`,
        `.claude/skills/*/SKILL.md` and `.claude/commands/**`. A hostile target
        ships any of those and they arrive as configuration, not as data:

        * `--setting-sources user` drops the project and local settings, and
          with them any hooks those files declare. `--settings` is a SEPARATE
          channel that still applies under it -- MEASURED 2026-09-18: on a real
          launch carrying all three flags, a PreToolUse hook registered only in
          the `--settings` file fired and denied a `Read`, and the envelope's
          `permission_denials` named it (`--restricted`'s own help text says
          the same in as many words). So THIS run's `host-settings.json`, where
          `Guards.arm` registers the read and write hooks, still arms. The
          standing regression check is the `denials` field of
          `runs/<tag>/dispatch-ledger.jsonl`: it is fed from that same
          `permission_denials` array, so a run whose rows are all `[]` while
          the replies carry findings is an unarmed guard.
        * `--strict-mcp-config` -- the loop passes no `--mcp-config`, so this
          leaves the reviewer with no MCP servers at all rather than the
          target's.
        * `--disable-slash-commands` -- "Disable all skills" (`claude --help`),
          so it is what closes the target's `.claude/skills/*/SKILL.md` as well
          as `.claude/commands/**`. Reviewers run registered `--agent` shells
          and invoke neither, so it costs nothing.

        NEVER `--bare` or `--safe-mode`: both disable hooks, so either one
        would silently un-arm both guards while reading like hardening.
        """
        cmd = [self.CLI, "-p", "--settings", settings_path,
               "--setting-sources", "user", "--strict-mcp-config",
               "--disable-slash-commands", "--output-format", "json",
               "--no-session-persistence", "--max-turns", str(int(max_turns))]
        # #1720: the allowlisted name, never the entry's raw string. `--agent`
        # resolves among the OPERATOR's user-scope agents, so a foreign value
        # is a shell swap rather than a traversal -- still a reviewer running
        # under instructions and tool grants nobody in this run chose.
        # `run_entry` refuses such an entry outright; this call is what keeps
        # the value on the argv and the value that was checked the same one.
        # The fall-through is gated on `not enforced` rather than left as a
        # bare `elif` (fix round 1, item 2): an ENFORCED entry whose agent is
        # not registered gets the registered shell or no launch -- never a
        # `--model`-only argv, which is an unenforced launch. Latent behind
        # `run_entry` today; a second caller is all it would take.
        agent = base.registered_agent(entry)
        if entry.get("enforced") and agent:
            cmd += ["--agent", agent]
        elif not entry.get("enforced") and entry.get("model"):
            cmd += ["--model", entry["model"]]
        # `--json-schema <schema>` takes the JSON text, not a file (see
        # base.inline_schema for the measurement and the run it cost).
        cmd += base.schema_argv(self.OUTPUT_SCHEMA_FLAG, entry, inline=True)
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
        # #1623: the HOST's own error surface, kept apart from the message
        # above -- which quotes 200 characters of `text`, i.e. the AGENT's
        # reply, so a cell whose finding is about a 403 handler would be read
        # as a 403. The envelope's own error object when the CLI emits one;
        # otherwise the `result` string ONLY when it is the CLI's own error
        # rendering (`outage.cli_error` anchors on the prefix), never the free
        # text of a finding.
        host_error = data.get("error") if isinstance(data.get("error"), (dict, str)) else None
        if host_error is None and error is not None:
            host_error = outage.cli_error(text)
        return base.RunResult(entry_id=entry_id, ok=error is None, text=text if error is None else "",
                               usage=usage, cost_usd=data.get("total_cost_usd"), model=model,
                               session_id=data.get("session_id"), denials=denials, error=error,
                               host_error=host_error)

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
        # #1720, before the environment is built and before anything is spent:
        # an enforced entry whose `agent` is not one of this driver's four
        # registered shells is REFUSED, never downgraded. The old
        # `enforced and agent` gate in `command` sent both an absent agent and
        # a foreign one to the `--model` branch -- a bare launch, ledgered as
        # the enforced entry it was dispatched as.
        if entry.get("enforced") and base.registered_agent(entry) is None:
            return base.refuse_unregistered_agent(entry)
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
