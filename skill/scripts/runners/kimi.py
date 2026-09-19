"""The Kimi headless runner (spec 4.4): one `kimi -p` per entry, a per-run
KIMI_CODE_HOME carrying the guard hooks, usage from the session's wire file.

THE PER-RUN HOME -- why it exists, what the regenerated `config.toml` holds
and what is stripped from it on the way out -- is `runners/kimi_home.py`.
`prepare`/`teardown` below are its only callers here; PR evidence must
quote capabilities, never that directory.

MODEL BINDING. Entry models are the primary/secondary TIERS
(phases/requests.bound_model via model_resolver). Kimi agent files cannot bind
a model (unknown frontmatter fields are ignored), so the runner binds ``-m
<alias>`` on every entry -- enforced or not -- resolving tier -> profile alias
-> the full alias the installed config's [models] table defines (``k3`` ->
``kimi-code/k3``). An unresolvable model is a failed entry, never a silent
session-model fallback. The alias that REALLY ran is read back from the
session's wire file, which is also the usage ledger's source:
``usage.record{usageScope: "turn"}`` events, one per LLM request, summed.

Residuals, stated plainly: Kimi hooks fail open if the guard's interpreter
cannot start (kimi_guard_hook.py's docstring); and `kimi -p` gives no USD
metering on an OAuth plan, so cost_usd is None -- the ledger's token figures
are the honest cost signal.
"""
import atexit
import glob
import json
import os
import shutil
import signal
import subprocess
import sys

import scripts.dispatch as dispatch
import scripts.hosts as hosts
import scripts.model_resolver as model_resolver
import scripts.redact as redact
import scripts.runners.base as base
# `kimi_home_mod`, not `kimi_home`: `wire_path`'s first parameter and
# `Runner.kimi_home` already own that name in this file.
import scripts.runners.kimi_home as kimi_home_mod

# I3 (gate review): the launcher is a MODULE ATTRIBUTE, never a default argument, and every spawn
# resolves it inside the body. A default argument binds `subprocess.run` at import time, where
# `monkeypatch.setattr` cannot reach it -- so tests/conftest.py's autouse `_no_live_host_launches`
# can only refuse a real `kimi` launch if the name is looked up per call, here. The sibling family
# PRs bind their own module attribute the same way.
DEFAULT_RUNNER = subprocess.run
# N1, done: the rebase step this class's docstring asked for. There is ONE
# LaunchRefused, `base.LaunchRefused`, raised by the suite's guard through
# every seam and re-raised by every launch path; no alias is bound here
# because layout rule 4 bans a package module re-exporting a SIBLING's name.


# Session markers of an enclosing Kimi session. A nested `kimi -p` launches
# fine with them set (measured on 0.42.0), but they are dropped so no future
# version can read the child as attached to the parent session.
_NESTED_MARKERS = ("KIMI_SESSION_ID", "KIMI_CODE_VERSION")


# --- model aliases ------------------------------------------------------------

def _tier_aliases():
    """{tier: profile alias} from the one resolver, over every driver role --
    {primary: kimi-for-coding, secondary: k3} today. Derived, never hand-kept:
    model-profiles.yml is the source of truth and a profile change must not
    strand this runner on a stale table."""
    out = {}
    for role in dispatch.ROLE_FILES:
        cfg = model_resolver.resolve_model("kimi", role)
        tier, alias = cfg.get("model"), cfg.get("alias")
        if tier and alias:
            out.setdefault(tier, alias)
    return out


def resolve_cli_alias(model, configured, tier_aliases=None):
    """The full alias the installed CLI knows for an entry's model, or None.

    `model` is what the entry carries: a tier (primary|secondary), a profile
    alias (k3), or a full configured alias (kimi-code/k3). `configured` is the
    set of alias names the installed config's [models] table defines. No
    guessing: anything that does not resolve is None, and the runner fails
    the entry rather than letting the session's default model silently win.
    """
    if not model or not isinstance(model, str):
        return None
    tier_aliases = _tier_aliases() if tier_aliases is None else tier_aliases
    alias = tier_aliases.get(model, model)
    candidates = (alias, "kimi-code/%s" % alias)
    for candidate in candidates:
        if candidate in configured:
            return candidate
    return None


def configured_models(real_home=None):
    """The alias names the installed config's [models] table defines."""
    real_home = real_home or os.environ.get("KIMI_CODE_HOME") or os.path.expanduser("~/.kimi-code")
    source, _path = kimi_home_mod._read_source_config(real_home)
    models = source.get("models")
    return set(models) if isinstance(models, dict) else set()


# --- wire file ----------------------------------------------------------------

USAGE_RECORD = "usage.record"
_LLM_REQUEST = "llm.request"


def wire_path(kimi_home, session_id):
    """The child session's wire file under the per-run home, or None."""
    if not session_id or "/" in session_id or os.sep in session_id:
        return None
    pattern = os.path.join(glob.escape(kimi_home), "sessions", "*",
                           session_id, "agents", "main", "wire.jsonl")
    found = sorted(glob.glob(pattern))
    return found[0] if found else None


def parse_wire(path):
    """(usage, model) from a session wire file.

    usage: one `usage.record` per LLM request (`usageScope: "turn"`, measured
    on 0.42.0), summed into the ledger's four fields. Other scopes are not
    summed -- an unmeasured record shape is unknown data, not a figure.
    model: the alias the last `usage.record`/`llm.request` names, i.e. what
    REALLY ran, never what was requested.
    """
    usage = {"input_tokens": 0, "output_tokens": 0,
             "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
    model = None
    found = False
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(record, dict):
                    continue
                if record.get("type") == _LLM_REQUEST and record.get("modelAlias"):
                    model = record["modelAlias"]
                if record.get("type") != USAGE_RECORD or record.get("usageScope") != "turn":
                    continue
                body = record.get("usage")
                if not isinstance(body, dict):
                    continue
                found = True
                if record.get("model"):
                    model = record["model"]
                usage["input_tokens"] += int(body.get("inputOther") or 0)
                usage["output_tokens"] += int(body.get("output") or 0)
                usage["cache_read_input_tokens"] += int(body.get("inputCacheRead") or 0)
                usage["cache_creation_input_tokens"] += int(body.get("inputCacheCreation") or 0)
    except OSError:
        return {}, None
    return (usage if found else {}), model


class Runner(base.HostRunner):
    CLI = "kimi"
    mode = "headless"
    default_concurrency = 4        # the managed gateway rate-limits; 8 bursted into exit-1s (measured)

    def __init__(self, host="kimi", runner=None):
        super().__init__(host)
        # None means "the module's DEFAULT_RUNNER, resolved at launch time"
        # (I3); an injected fake stays exactly what the caller passed.
        self.runner = runner
        self.kimi_home = None
        self.run_home = None           # the seam's name for it (base.HostRunner)
        self.skills_dir = None         # the empty run-owned dir `--skills-dir` names
        self.home_pointer = None
        self._crash_strip = None       # the atexit callback, while one is armed
        self._signal_handlers = {}     # {signum: our wrapper}; it carries what was there
        self.review_root = None
        self.configured = None
        self.max_turns = 60
        self.entry_timeout = 1800          # seconds per entry; a stuck agent is a failed entry

    def prepare(self, run_dir, review_root):
        """Build the per-run Kimi home (idempotent) and snapshot the installed
        CLI's model table for alias resolution.

        The home lives under the temp root (C1); `run_dir` -- inside the
        reviewed tree -- gets a pointer file naming it, which nothing reads
        back (N2). Every prepare, a resume's included, mints a FRESH home:
        reuse would re-derive the path from that untrusted file, and
        `mkdtemp`'s exclusivity is the only thing that makes "this directory is
        ours" true. The probes get the live path in-process (`run_home`).
        """
        self.review_root = os.path.abspath(review_root)
        # C3: a Kimi hook whose interpreter cannot start fails OPEN, so a
        # missing guard script is a SILENT un-confinement -- the one residual
        # the hook cannot catch. `loop` turns this into a reported `error`.
        if not os.path.isfile(kimi_home_mod._GUARD):
            raise RuntimeError(
                "the kimi guard hook is absent at %s; refusing to launch "
                "reviewers whose read/write confinement would be unarmed"
                % kimi_home_mod._GUARD)
        scope_path = os.path.join(run_dir, base.SCOPE_FILE)
        allowlist_path = os.path.join(run_dir, base.ALLOWLIST_FILE)
        self.kimi_home = kimi_home_mod.build_kimi_home(
            kimi_home_mod.new_kimi_home(), scope_path, allowlist_path)
        # KM-1 (#1657): with no `--skills-dir` the CLI auto-discovers its USER
        # and PROJECT skill roots, and the project ones are inside the tree
        # under review -- `.kimi-code/skills/*/SKILL.md`, `.agents/skills/
        # */SKILL.md` -- so a hostile target ships instructions straight into a
        # reviewer. One explicit directory replaces both roots, and this one is
        # empty, run-owned and thrown away with the home.
        self.skills_dir = kimi_home_mod.new_skills_dir(self.kimi_home)
        # `run_home` is the seam's own name for it: the loop reads it off the
        # runner and hands it to the probes, so an effective-surface probe can
        # find this run's children without opening anything in the target.
        self.run_home = self.kimi_home
        self.home_pointer = kimi_home_mod.pointer_path(run_dir)
        os.makedirs(run_dir, exist_ok=True)
        kimi_home_mod._write_text(self.home_pointer, self.kimi_home + "\n")
        self._arm_crash_strippers()
        self.configured = configured_models()

    def _strip_on_exit(self):
        """Take the credential files out of THIS process's home. Idempotent and
        bounded by `is_temp_home` exactly as `teardown` is; it touches no other
        home, so two runs on one machine cannot interfere."""
        home = self.kimi_home
        if home and kimi_home_mod.is_temp_home(home):
            kimi_home_mod.strip_secrets(home)

    def _arm_crash_strippers(self):
        """Strip the secrets on the ways out that never reach `teardown` (R2-2):
        `teardown` runs from orchestrate._finish, so a `kill`, an OOM kill or a
        power loss leaves the home behind -- and since N2 removed reuse, no
        later run adopts it. `atexit` covers a normal-ish exit and an unhandled
        exception; SIGTERM goes on top, CHAINING to whatever was there -- safe
        on this side of the drain because its chain ends in SIG_DFL, which ends
        the process: nothing launches after it. SIGINT is deliberately NOT here
        (R3-1, as amended by #1662): KeyboardInterrupt is already routed by
        orchestrate.loop to teardown("error") AFTER `iter_batch` has cancelled
        the queue and terminated what was running, and a handler would strip
        BEFORE that -- the entries the interrupt catches mid-flight would
        finish against a home with no config.toml, i.e. no guard hooks. SIGKILL nobody
        can catch: that residual is in docs/PANOPTICON.md."""
        if self._crash_strip is not None:
            return
        self._crash_strip = self._strip_on_exit
        atexit.register(self._crash_strip)
        for name in ("SIGTERM",):
            signum = getattr(signal, name, None)
            if signum is None:
                continue
            try:
                previous = signal.getsignal(signum)
                handler = self._signal_stripper(previous)
                signal.signal(signum, handler)
            except (ValueError, OSError, RuntimeError):
                continue          # not the main thread, or no such signal here
            self._signal_handlers[signum] = handler

    def _signal_stripper(self, previous):
        def handler(signum, frame):
            self._strip_on_exit()
            previous = handler.previous       # R3-3: read live, a disarm may have relinked it
            if callable(previous):
                previous(signum, frame)       # chained: the loop still sees it
            elif previous == signal.SIG_DFL or previous is None:   # R3-4: None = C-installed
                signal.signal(signum, signal.SIG_DFL)
                os.kill(os.getpid(), signum)  # die as we would have
        handler.previous = previous
        return handler

    def _disarm_crash_strippers(self):
        """The run is over: take ours back off (and the atexit callback, so a
        torn-down Runner does not pin itself). R3-3: ours may no longer be on
        top -- a later `prepare` chains to it -- so it is unlinked from
        whichever wrapper holds it rather than left installed for good."""
        if self._crash_strip is not None:
            atexit.unregister(self._crash_strip)
            self._crash_strip = None
        for signum, ours in list(self._signal_handlers.items()):
            try:
                node = signal.getsignal(signum)
                if node is ours:      # NEW-6: None (C-installed) means the default
                    signal.signal(signum, signal.SIG_DFL if ours.previous is None else ours.previous)
                while callable(node) and hasattr(node, "previous") and node is not ours:
                    if node.previous is ours:
                        node.previous = ours.previous
                    node = node.previous
            except (ValueError, OSError, RuntimeError):
                pass
        self._signal_handlers.clear()

    def teardown(self, status=None):
        """Drop the per-run home on a clean finish; keep it, stripped, on an error.
        Bounded by `is_temp_home` on the path THIS process built (never on the
        pointer file's contents, which the reviewed tree could have rewritten
        between prepare and teardown). N6: a run that ends any other way than
        `complete` keeps its home so the children's wire files can be read
        afterwards -- but the SECRETS go anyway. Nothing prunes a kept home, so
        its config.toml (`api_key` verbatim) and its OAuth symlinks would
        otherwise accumulate under a path every process of that uid can see.
        The debugging value is in the transcripts, not the credential surface."""
        home = self.kimi_home
        if home and kimi_home_mod.is_temp_home(home):
            if status == "complete":
                shutil.rmtree(home, ignore_errors=True)
                self._drop_pointer()
                # skills_dir too: it lives inside the tree just removed, and
                # a runner holding a deleted path beside two honest `None`s is
                # how a later `--skills-dir=<gone>` would get built (R1-7).
                self.kimi_home = self.run_home = self.skills_dir = None
            else:
                removed = kimi_home_mod.strip_secrets(home)   # R3-6: fixed text below, never the names it returned
                note = ("its config.toml and credential links were removed, so nothing left "
                        "there carries a credential" if removed else "it held no credential files")
                print("driver loop: the kimi run home is kept for debugging at %s; %s"
                      % (home, note), file=sys.stderr, flush=True)
        self._disarm_crash_strippers()    # LAST (#1662): a Ctrl-C above leaves the exit stripper armed

    def _drop_pointer(self):
        """A pointer that outlives the home it names is a lie in the run
        folder."""
        try:
            if self.home_pointer:
                os.unlink(self.home_pointer)
        except OSError:
            pass

    def _shell_path(self, entry):
        """The registered shell this entry names, or None when there is no
        such shell inside the registration directory (#1720).

        Two gates, because the value comes out of
        `.panopticon/dispatch-request.json` inside the reviewed tree and is
        the ONE entry-derived path this family puts on an argv --
        `--agent-file=` is the reviewer's governing instructions, so a target
        that chose it would be writing the reviewer's charter:

        * the name must be one of `base.REGISTERED_AGENT_NAMES` (that alone
          stops `../../tmp/evil` and `/tmp/x`);
        * the path it RESOLVES to must still be under the registration
          directory -- `base.published_schema`'s realpath containment, second
          application -- so a registered name symlinked out of that directory
          fails closed too.
        """
        name = base.registered_agent(entry)
        if name is None:
            return None
        directory = hosts.spec(self.host).registration_dir
        root = os.path.realpath(directory)
        real = os.path.realpath(os.path.join(directory, "%s.md" % name))
        return real if real.startswith(root + os.sep) else None

    def command(self, entry, alias):
        """The argv for one entry. `--agent-file=<abs shell>` (equals form:
        0.42.0 misparses the space form after -p) gives the shell EXPLICIT
        precedence over any project-scoped shadow file in the reviewed tree,
        which is the point of registering enforcement shells. `-m` binds the
        model on EVERY entry that names one.

        `--skills-dir=<dir>` ("Load skills from this directory instead of
        auto-discovered user and project directories", `kimi --help`) points
        the CLI at THIS run's empty directory, so neither the operator's
        skills nor the reviewed tree's are loaded (KM-1, #1657). Equals form
        for the same 0.42.0 reason as `--agent-file=`, and before `-p`, which
        takes the prompt."""
        if not self.skills_dir:
            # LOUD, not silent: an argv without this flag is a launchable one
            # whose skill discovery falls back to the auto-discovered user AND
            # project roots -- the target's `.kimi-code/skills/*/SKILL.md`
            # back in play. Same refusal shape as `prepare`'s missing-guard
            # check: a control that cannot be armed stops the launch.
            raise RuntimeError(
                "the kimi runner was not prepared; refusing to launch a reviewer whose "
                "skill discovery would fall back to the target's project roots (KM-1, #1657)")
        cmd = [self.CLI, "--output-format", "stream-json",
               "--skills-dir=%s" % self.skills_dir]
        if entry.get("enforced"):
            shell = self._shell_path(entry)
            if shell is None:
                # LOUD, like the `--skills-dir` refusal above and for the same
                # reason: an enforced entry whose shell does not resolve has no
                # legal argv, and the one thing that must NOT happen is the
                # `--agent-file=` flag quietly falling off -- that is a bare,
                # unenforced launch reported as an enforced one. `run_entry`
                # refuses such an entry before it ever gets here; this is the
                # second wall, for any other caller.
                raise RuntimeError(base.UNREGISTERED_AGENT
                                   % redact.redact(str(entry.get("agent"))[:200]))
            cmd.append("--agent-file=%s" % shell)
        if alias:
            cmd += ["-m", alias]
        cmd += ["-p", entry["prompt"]]
        return cmd

    def parse_envelope(self, entry_id, stdout, returncode, stderr=None):
        """stream-json lines: the last assistant content is the reply; the
        session.resume_hint meta names the session id the wire file keys on.
        A failed launch's reason lives on stderr (an empty stdout tail reads as
        'exited 1: ' and diagnoses nothing -- the 2026-09-13 burst rate-limit
        failure was invisible until stderr was included)."""
        text, session_id = "", None
        for line in (stdout or "").splitlines():
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, dict):
                continue
            if record.get("role") == "assistant" and isinstance(record.get("content"), str):
                text = record["content"]
            elif (record.get("role") == "meta"
                  and record.get("type") == "session.resume_hint"
                  and isinstance(record.get("session_id"), str)):
                session_id = record["session_id"]
        if returncode != 0:
            host = (stderr or "").strip()      # #1623: the HOST's surface; `text` is the AGENT's
            return base.RunResult.failed(entry_id, "kimi -p exited %s: %s"
                                         % (returncode, (text or host)[:200]), host_error=host or None)
        return text, session_id

    def launch_env(self, overlay=None):
        """The seam's preparation plus this family's three rules: point the child
        at THIS run's Kimi home, cap its steps, drop the markers saying it is
        already inside a Kimi session. Extracted from run_entry unchanged (#1626
        I2) so one method answers for every launch, a probe's included."""
        run_env = super().launch_env(overlay)
        run_env["KIMI_CODE_HOME"] = self.kimi_home
        run_env["KIMI_LOOP_MAX_STEPS_PER_TURN"] = str(int(self.max_turns))
        for marker in _NESTED_MARKERS:
            run_env.pop(marker, None)
        return run_env

    def run_entry(self, entry, env):
        # `env` is the loop's three-key BINDING OVERLAY (spec 4.4), never a
        # whole environment -- the child inherits os.environ and the overlay
        # goes ON TOP (C1: an overlay-only child has no PATH and cannot start).
        # `launch_env` above is where that merge and this family's own go, once.
        entry_id = entry.get("id")
        if entry.get("enforced"):
            # #1720, in order: is the NAME one of ours, does the path it
            # resolves to stay inside the registration directory, and only
            # then is there a file there. `enforced and entry.get("agent")`
            # used to gate all three -- so an enforced entry with no agent,
            # or with one this driver never registers, skipped the check and
            # launched bare.
            if base.registered_agent(entry) is None:
                return base.refuse_unregistered_agent(entry)
            shell = self._shell_path(entry)
            if shell is None:
                return base.RunResult.failed(
                    entry_id, "entry's enforcement shell resolves outside the registered "
                    "shell directory %s: %r"
                    % (hosts.spec(self.host).registration_dir,
                       redact.redact(str(entry.get("agent"))[:200])))
            if not os.path.isfile(shell):
                return base.RunResult.failed(
                    entry_id, "enforcement shell not registered at %s "
                    "(run dispatch.py --emit-host-agents kimi)" % shell)
        alias = None
        if entry.get("model"):
            alias = resolve_cli_alias(entry["model"], self.configured or set())
            if alias is None:
                return base.RunResult.failed(
                    entry_id, "entry model %r does not resolve to a model alias "
                    "the installed Kimi CLI has configured" % entry["model"])
        launcher = DEFAULT_RUNNER if self.runner is None else self.runner
        try:
            # Inside the try on purpose: `command()` refuses an unprepared
            # runner (no `--skills-dir`), and that refusal is a launch failure
            # like any other -- a failed RunResult, never an exception out of
            # run_entry (spec 4.4; codex's "not prepared" raise sits in its
            # try for the same reason).
            run_env = self.launch_env(env)
            cmd = self.command(entry, alias)
            proc = launcher(cmd, cwd=self.review_root, env=run_env, capture_output=True,
                            text=True, timeout=self.entry_timeout)
        except base.LaunchRefused:        # I3: the suite's guard, never a run state
            raise                         # (first, so no later clause can absorb it)
        except subprocess.TimeoutExpired as exc:
            # D10 ruling 5: the stream it printed is kept; usage is not, because
            # this family reads it from the session wire file, not from stdout.
            return base.RunResult.failed(entry_id, "kimi -p timed out after %ss" % self.entry_timeout,
                                          text=base.partial_output(exc))
        except OSError as exc:
            return base.RunResult.failed(entry_id, "could not launch %s: %s" % (self.CLI, exc))
        except Exception as exc:          # run_entry never raises (spec 4.4)
            return base.RunResult.failed(entry_id,
                                          "kimi -p launch raised %s: %s" % (type(exc).__name__, exc))
        parsed = self.parse_envelope(entry_id, proc.stdout, proc.returncode,
                                     stderr=proc.stderr)
        if isinstance(parsed, base.RunResult):
            return parsed
        text, session_id = parsed
        usage, model = {}, None
        wire = wire_path(self.kimi_home, session_id)
        if wire:
            usage, model = parse_wire(wire)
        return base.RunResult(entry_id=entry_id, ok=True, text=text,
                              usage=usage, cost_usd=None, model=model,
                              session_id=session_id, denials=[], error=None)
