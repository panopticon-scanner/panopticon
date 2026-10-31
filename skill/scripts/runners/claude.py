"""The Claude headless runner (spec 4.4): one `claude -p` per entry, hooks
supplied by a run-specific --settings file, usage from the JSON envelope."""
import json
import math
import os
import subprocess

import scripts.dispatch as dispatch
import scripts.probes.common as probes_common
import scripts.runners.base as base
import scripts.runners.outage as outage
import scripts.runners.schema as schema_argv_rules


# The launcher a Runner built without an injected `runner=` uses. Read at
# CONSTRUCTION, never bound as a default argument: tests/conftest.py swaps it
# for a refusal for the whole suite (family guardrails section 3, #1616), so
# forgetting `runner=<fake>` in a test costs one failed RunResult rather than a
# real `claude -p` launch and the money it spends.
#
# #1575: None is the SENTINEL for "this runner's own `HostRunner.launch`" --
# a process-group-aware Popen that registers its child, so a family-side
# timeout and an operator's Ctrl-C reach the workers `claude` spawns and not
# just its own pid. The attribute stays here, at module level and under this
# name, because that is what tests/conftest.py's `LAUNCH_SEAMS` swaps and what
# tests/test_host_launch_guard.py walks the AST for; only its VALUE changed.
DEFAULT_RUNNER = None

# #1753 (AGT-4053314873). The tool surface of an UNENFORCED launch -- every
# argv that binds no `--agent` shell, the `--model` launch and the model-less
# fall-through alike, and therefore has no host-enforced `tools:` grant behind
# it. `claude -p` denies a tool that needs
# permission when no allow rule matches (that is what feeds
# `permission_denials`), but `--setting-sources user` deliberately KEEPS the
# OPERATOR's user-scope `permissions.allow`, where a `Bash(*)` convenience rule
# is ordinary -- so without this the operator's own shortcuts reach a reviewer
# whose whole job is reading hostile content. Deny rules beat allow rules, which
# is the point. Kimi closes the same case from the other side
# (`runners/kimi_home.disabled_tools`): its config offers a deny-list and no
# allow-list, so it denies the CLI's whole vocabulary minus the templates'
# grants.
#
# WHY AN EXPLICIT LIST rather than a derived one. Claude's CLI publishes no
# machine-readable tool vocabulary to subtract the grants FROM -- `--help`
# documents flags, not tool names -- so a derived list would be a hand-kept
# vocabulary wearing a computation's clothes. Named here instead, grouped by
# what each name would hand a reviewer, every one of them present in the 2.1.276
# bundle:
#   * code execution: Bash, BashOutput, KillShell, PowerShell, REPL, Workflow
#     (`--restricted`'s own help names the first and the middle two as the
#     "code-running tools"; Workflow runs a script)
#   * delegation, i.e. a second agent under nobody's tool policy: Agent, Task,
#     TaskStop, Monitor, SendMessage
#   * egress and off-machine publication: WebFetch, WebSearch, Artifact,
#     ArtifactComments, ArtifactData, ArtifactCheck
#   * write tools no reviewer role is granted: MultiEdit and TodoWrite sit
#     outside the write guard's `Write|Edit|NotebookEdit` matcher; NotebookEdit
#     sits inside it and is denied anyway, since no role needs it and this list
#     must not rely on how the host folds a matcher
#   * READS the read guard never sees: LS, NotebookRead. The sharp ones. The
#     guard's matcher is `Read|Grep|Glob`, and a read-only builtin needs no
#     permission, so an allow rule is not even required to reach one -- this is
#     the Claude analogue of the ReadMediaFile hole `kimi_home.disabled_tools`
#     was written to close.
#   * worktrees: EnterWorktree, ExitWorktree
#
# THE RESIDUAL, stated plainly: a tool name that is NOT in this tuple and that
# the operator has allowed at user scope is still reachable by an unenforced
# reviewer -- a list cannot deny what it has not heard of, and a CLI upgrade is
# exactly how a new name arrives. MCP tools are not part of that residual:
# `command` passes `--strict-mcp-config` with no `--mcp-config`, so an
# unenforced reviewer has no MCP servers at all. The ENFORCED launch needs none
# of this: `--agent` resolves a registered `panopticon-*` shell whose `tools:`
# frontmatter is the host-enforced allow-list, and an allow-list closes the
# names nobody has thought of yet.
UNENFORCED_DENIED_TOOLS = (
    "Bash", "BashOutput", "KillShell", "PowerShell", "REPL", "Workflow",
    "Agent", "Task", "TaskStop", "Monitor", "SendMessage",
    "WebFetch", "WebSearch", "Artifact", "ArtifactComments", "ArtifactData",
    "ArtifactCheck",
    "MultiEdit", "NotebookEdit", "TodoWrite",
    "LS", "NotebookRead",
    "EnterWorktree", "ExitWorktree",
)
# ONE argv token, and the `=` is load-bearing. MEASURED on 2.1.276:
# `--disallowedTools` is VARIADIC ("Comma or space-separated list of tool names
# to deny"), so the space form eats every following non-flag token -- and the
# prompt is the last token on this argv. `claude -p --output-format json
# --max-turns 2 --disallowedTools Bash "<prompt>"` exits 1 with no envelope at
# all ("Error: Input must be provided either through stdin or as a prompt
# argument when using --print"), and so does a comma list passed as a second
# token. `--disallowedTools=Bash,Glob "<prompt>"` runs, and the reviewer
# reports "I have Read available; Bash and Glob are not in my current tool
# set." A single token cannot swallow a neighbour wherever it is placed, which
# is also what keeps a later argv reordering from silently re-opening the
# surface. Same class of shape bug as `--json-schema` taking the schema TEXT
# and not a file (#1731, which cost run 14 a checkpoint): the `--help` probe
# reads a flag's NAME and cannot see its arity. The CLI's own option table
# spells it `--disallowedTools, --disallowed-tools <tools...>` with no
# argParser and no choices: variadic by declaration, not only by measurement,
# and no parse-time tool vocabulary for a name in the tuple to fail against.
DENY_FLAG = "--disallowedTools=%s"

# #2060: the unenforced launch's ALLOW-list, the templates' grants
# (`dispatch.allowed_tool_union`) as ONE `--tools=` token -- variadic like
# `--disallowedTools`, so the same `=` form. MEASURED on 2.1.304 (stream-json
# init `tools`): today's unenforced argv exposed 15 tools, eleven of them names
# the deny-list above has never heard of (CronCreate, CronDelete, CronList,
# RemoteTrigger, ScheduleWakeup, PushNotification, DesignSync, ListAgents,
# ReportFindings, ToolSearch, Edit); with this token exactly Glob, Grep, Read,
# Write remain, and the `--settings` PreToolUse guard still fired. An allow
# rule grants PERMISSION for a tool, and cannot add one the session lacks, so
# this closes the operator's user-scope allow rules by construction. The
# deny-list stays as belt and braces: deny beats allow, and it holds if a CLI
# ever ignores `--tools`. `--restricted` measured too (record only): it took
# away only CronCreate and RemoteTrigger, and confines writes to the cwd.
TOOLS_FLAG = "--tools=%s"
TOOLS_FLAG_NAME = "--tools"
# #2061: the two controls above leave no run-time trace, so every unenforced
# argv is checked against them (probes/common.CONTROLS) before it launches.
UNENFORCED_CONTROLS = ("claude:unenforced-tools-allow-list", "claude:unenforced-tool-deny-list")


# #3218: the ENFORCED launch's write PERMISSION, one `=`-form token naming that
# entry's own out_file. `claude -p` auto-denies a Write nothing approved, and
# `--setting-sources user` leaves only the operator's user scope to approve it,
# so on a box whose user settings grant no Write every enforced cell was denied
# its own out_file (a 5.2 redteam run: 498/498 review rows). MEASURED on
# 2.1.305, an enforced-style launch with no `permissions` key in user scope:
# `Edit(//<abs>)` allows the create and still denies a peer path; `Write(//<abs>)`
# and `Write(/<abs>)` grant nothing (Edit is the rule name for a create), and
# `Edit(/<abs>)` is relative. It holds for a path with a space, a comma or a
# parenthesis and for an unresolved symlink. Never `--permission-mode
# acceptEdits`: that approves every edit in the reviewed tree. The write guard
# still denies first; this is the CLI's own per-entry path check after it.
GRANT_PREFIX = "--allowedTools="
GRANT_FLAG = GRANT_PREFIX + "Edit(/%s)"
# The rule is a gitignore-style PATTERN, so these are not literal in a path.
# MEASURED: an unescaped `*` granted a PEER (`a*b/` let `aXb/` through), `[x]`
# granted the peer and not the file, and the backslash escape is partial --
# `\*`, `\[` and `\{` work, `\?` and `\\` grant nothing. Such a path is
# refused, never escaped and never launched without the grant.
GRANT_UNSAFE = frozenset("*?[]{}\\")


def own_out_file_grant(entry):
    """(the enforced entry's grant token, None), or (None, why it has none)."""
    out_file = entry.get("out_file") if isinstance(entry, dict) else None
    if not isinstance(out_file, str) or not out_file:
        return None, "the enforced entry names no out_file to grant its Write"
    path = os.path.abspath(out_file)
    unsafe = sorted(set(path) & GRANT_UNSAFE)
    if unsafe:
        return None, ("its out_file %r holds %s, which the CLI reads as a pattern, "
                      "so no grant can name only that file; move the target to a "
                      "path without them" % (path, " ".join(unsafe)))
    return GRANT_FLAG % path, None


def enforced_argv_problem(entry, cmd):
    """Why this enforced argv may not launch, or None (#3218): an `--agent`
    launch must carry exactly one grant token, the one `own_out_file_grant`
    derives. Without it every Write to the entry's own out_file is denied on a
    box whose user settings approve none; with any other it is a wider grant."""
    if "--agent" not in cmd:
        return None
    token, why = own_out_file_grant(entry)
    if why:
        return why
    if [a for a in cmd if a.startswith(GRANT_PREFIX)] != [token]:
        return "the enforced launch's `--allowedTools` token is not its own out_file's grant"
    return None


def unenforced_argv_problem(cmd):
    """Why this argv may not launch, or None (#2061). An `--agent` launch is the
    registered shell's to confine and answers None. Every other argv must carry
    both tool controls (`probes.common.control_is_on`), each exactly once and
    with exactly the value this module derives -- the templates' union for
    `--tools=`, `UNENFORCED_DENIED_TOOLS` for `--disallowedTools=` -- since a
    removed tool shows in no envelope and a lost or altered token would look
    like a run that kept it."""
    if "--agent" in cmd:
        return None
    expected = {"--tools=": TOOLS_FLAG % ",".join(sorted(dispatch.allowed_tool_union())),
                "--disallowedTools=": DENY_FLAG % ",".join(UNENFORCED_DENIED_TOOLS)}
    for control in UNENFORCED_CONTROLS:
        if not probes_common.control_is_on(control, cmd):
            return "the unenforced launch lost its `%s` control" % control
    for prefix, token in expected.items():
        carried = [a for a in cmd if a.startswith(prefix)]
        if carried != [token]:
            return "the unenforced launch's `%s` token is not the derived one" % prefix.rstrip("=")
    return None


def _measured_number(details, field):
    """A usable host measurement, never a malformed value or inferred zero."""
    value = details.get(field) if isinstance(details, dict) else None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return value if not isinstance(value, float) or math.isfinite(value) else None


def _primary_model(model_usage):
    """Attribute the turn by measured output, then cost, then a stable name."""
    ranked = []
    for name, details in model_usage.items():
        if not isinstance(details, dict):
            continue
        output = _measured_number(details, "outputTokens")
        cost = _measured_number(details, "costUSD")
        ranked.append((-(output if output is not None else 0),
                       -(cost if cost is not None else 0), name))
    return min(ranked)[2] if ranked else None


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
    # 2.1.276; see runners/schema.py). Appended only for an entry whose role
    # publishes one.
    OUTPUT_SCHEMA_FLAG = ("--json-schema",)
    mode = "headless"
    default_concurrency = 8

    def __init__(self, host="claude", runner=None):
        super().__init__(host)
        self.runner = self.launcher(runner, DEFAULT_RUNNER)
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
        self.require_tools_flag(run_dir)

    def require_tools_flag(self, cwd=None):
        """Refuse the run when this CLI does not offer `--tools` (#2060): every
        unenforced launch carries the template allow-list as that flag, and a
        CLI that cannot take it would launch the reviewer UNCONFINED -- halt
        loudly instead. One `--help` read per run, through the runner's own
        launcher (`probes.common._cli_help`, the seam the suite guards)."""
        text, _verdict, why = probes_common._cli_help(self.runner, self.CLI, cwd=cwd)
        if text is None or not probes_common._flag_advertised(TOOLS_FLAG_NAME, text):
            raise ValueError(
                "claude: this CLI does not offer `%s` (%s), so an unenforced reviewer could not be held "
                "to the role templates' tool grant; refusing the run rather than launch it unconfined "
                "(#2060). Upgrade the claude CLI." % (TOOLS_FLAG_NAME, why or "not in `claude --help`"))

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

        THE UNENFORCED BRANCH's tool surface (#1753). An `--agent` launch gets
        its tool grant from the registered shell's `tools:` frontmatter, which
        the host enforces; every other argv here gets
        `UNENFORCED_DENIED_TOOLS` (above) as one `--disallowedTools=` token
        instead, because `--setting-sources user` keeps the OPERATOR's
        user-scope allow rules and those must not reach a reviewer that reads
        hostile content. The enforced argv's tool surface is its shell's; it
        gains only the #3218 grant (`GRANT_FLAG`), a PERMISSION for the one
        file the entry owns.

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
        agent = base.registered_agent(entry, roles=self.roles)
        if entry.get("enforced") and agent:
            cmd += ["--agent", agent]
            grant, _why = own_out_file_grant(entry)
            if grant:                   # #3218; `run_entry` refuses the entry without one
                cmd.append(grant)
        else:
            # Everything that is NOT an `--agent` launch is unenforced, and the
            # deny-list covers all of it -- including the fall-through that
            # binds no model either (an entry with no `model`, or the latent
            # enforced-without-a-registered-shell case `run_entry` refuses
            # before it can get here). "No shell" is what makes a launch
            # unenforced; whether a model was named is a different question,
            # and the branch that answers it is nested here rather than
            # deciding the tool surface.
            if not entry.get("enforced") and entry.get("model"):
                cmd += ["--model", entry["model"]]
            cmd.append(TOOLS_FLAG % ",".join(sorted(dispatch.allowed_tool_union())))
            cmd.append(DENY_FLAG % ",".join(UNENFORCED_DENIED_TOOLS))
        # `--json-schema <schema>` takes the JSON text, not a file (see
        # `runners/schema.py` for the measurement and the run it cost).
        cmd += schema_argv_rules.schema_argv(self.OUTPUT_SCHEMA_FLAG, entry,
                                             inline=True)
        cmd.append(entry["prompt"])
        return cmd

    def parse_envelope(self, entry_id, stdout, returncode, stderr=None):
        """The envelope, plus (#1732) whatever the CLI said on `stderr`.

        `stderr` is kept on the result only when the result FAILED, and only
        as `base.stderr_head` characters of it. This family read `proc.stdout`
        and nothing else, so every one of run 14's 309 failed launches was
        ledgered as "printed no JSON envelope (exit 1)" while the CLI's own
        sentence -- the one that named the wrong argv -- went to a stream
        nobody kept. The message below is UNCHANGED: it is the symptom, and
        the new field is the diagnosis beside it.
        """
        diagnosis = base.stderr_head(stderr)
        try:
            data = json.loads(stdout or "")
        except ValueError:
            return base.RunResult.failed(
                entry_id, "claude -p printed no JSON envelope (exit %s)" % returncode,
                stderr=diagnosis)
        if not isinstance(data, dict):
            return base.RunResult.failed(entry_id, "claude -p envelope is not an object",
                                         stderr=diagnosis)
        raw_usage = data.get("usage")
        usage = raw_usage if isinstance(raw_usage, dict) else {}
        raw_model_usage = data.get("modelUsage")
        model_usage = raw_model_usage if isinstance(raw_model_usage, dict) else {}
        model = _primary_model(model_usage)
        raw_denials = data.get("permission_denials")
        denials = raw_denials if isinstance(raw_denials, list) else []
        # D10 ruling 3: under `--json-schema` the CLI may return the object in
        # `structured_output` ALONGSIDE or INSTEAD OF the `result` text, and
        # the loop has to persist the object either way. Serialised, because
        # everything downstream of a runner takes the reply as text and
        # `persist._parse_reply` parses it back -- the same round trip a fenced
        # `result` makes, minus the fence. `result` stays the fallback: an
        # entry with no schema, or a CLI build that ignores the flag, is
        # exactly what it was.
        structured = data.get("structured_output")
        result_text = data.get("result")
        text = (json.dumps(structured) if structured
                else (result_text if isinstance(result_text, str) else ""))
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
                               host_error=host_error, models=model_usage,
                               stderr=diagnosis if error is not None else None,
                               reply_via="structured_output" if structured else "result")

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
        if entry.get("enforced") and base.registered_agent(
                entry, roles=self.roles) is None:
            return base.refuse_unregistered_agent(entry, roles=self.roles)
        run_env = self.launch_env(env)
        cmd = self.command(entry, self.settings_path, self.max_turns)
        problem = unenforced_argv_problem(cmd)
        if problem:                     # #2061: never launch an unenforced reviewer unconfined
            return base.RunResult.failed(entry.get("id"), "refused before launch: %s (#2061)" % problem)
        problem = enforced_argv_problem(entry, cmd)
        if problem:                     # #3218: never launch an enforced reviewer that cannot write
            return base.RunResult.failed(entry.get("id"), "refused before launch: %s (#3218)" % problem)
        try:
            proc = self.runner(cmd, cwd=self.review_root, env=run_env, capture_output=True,
                                text=True, timeout=self.entry_timeout)
        except subprocess.TimeoutExpired as exc:
            # D10 ruling 5: keep what the killed child printed. No usage with
            # it: `claude -p` prints its envelope once, at the end, so a
            # partial stdout carries no figure to read -- recorded as the empty
            # truth rather than a fabricated zero.
            # ...but stderr IS kept (#1732 fix round 2): a killed child's
            # complaint is the only diagnosis a timeout ever ledgers.
            return base.RunResult.failed(entry.get("id"), "claude -p timed out after %ss" % self.entry_timeout,
                                          text=base.partial_output(exc),
                                          stderr=base.stderr_head(getattr(exc, "stderr", None)))
        except OSError as exc:
            return base.RunResult.failed(entry.get("id"), "could not launch %s: %s" % (self.CLI, exc))
        except Exception as exc:          # run_entry never raises (spec 4.4): anything else is a failed entry
            return base.RunResult.failed(entry.get("id"),
                                          "claude -p launch raised %s: %s" % (type(exc).__name__, exc))
        return self.parse_envelope(entry.get("id"), proc.stdout, proc.returncode,
                                   stderr=proc.stderr)
