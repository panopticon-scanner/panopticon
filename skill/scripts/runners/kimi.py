"""The Kimi headless runner (spec 4.4): one `kimi -p` per entry, a per-run
KIMI_CODE_HOME carrying the guard hooks, usage from the session's wire file.

WHY A PER-RUN KIMI HOME. Kimi Code registers hooks only in
``$KIMI_CODE_HOME/config.toml`` -- there is no ``--settings`` flag and no
project-level hooks file -- and it discovers credentials under the same root.
So `prepare` builds ``<run_dir>/kimi-home/``: the operator's OAuth stores
(`credentials`, `oauth`) are SYMLINKED in (never copied: no secret bytes enter
the run tree), and `config.toml` is regenerated from the operator's own with
three deltas --

  * the two guard hooks (kimi_guard_hook.py read/write) with this run's
    scope/allowlist paths baked into their commands;
  * ``merge_all_available_skills = false`` and ``builtin_product_skills =
    false``, so neither the operator's nor a hostile TARGET's skills can
    inject into a reviewer;
  * ``tools.disabled = ["Bash", "Agent", "AgentSwarm"]``: no shell grants
    them (the templates forbid them), and this closes them for UNENFORCED
    entries too, where the child runs as the default agent.

The source config's other values are carried verbatim -- including any
plaintext `api_key` the operator keeps there (stripping it would break
api_key-authenticated installs). The home lives under the gitignored
``.panopticon/runs/<tag>/`` and is chmod 700; PR evidence must quote
capabilities, never this directory.

MODEL BINDING. Entry models are the primary/secondary TIERS
(phases/requests.bound_model via model_resolver). Kimi agent files cannot
bind a model (unknown frontmatter fields are ignored), so the runner binds
with ``-m <alias>`` on every entry -- enforced or not -- resolving tier ->
profile alias -> the full alias the installed config's [models] table
actually defines (e.g. ``k3`` -> ``kimi-code/k3``). An unresolvable model is a
failed entry, never a silent session-model fallback. The alias the child
REALLY ran is read back from the session's wire file (`llm.request` /
`usage.record` records), which is also the usage ledger's source:
``usage.record{usageScope: "turn"}`` events, one per LLM request, summed.

Residuals, stated plainly: Kimi hooks fail open if the guard's interpreter
cannot start (kimi_guard_hook.py's docstring); and `kimi -p` gives no USD
metering on an OAuth plan, so cost_usd is None -- the ledger's token figures
are the honest cost signal.
"""
import glob
import json
import os
import subprocess
import tomllib

import scripts.dispatch as dispatch
import scripts.hosts as hosts
import scripts.kimi_guard_hook as kimi_guard_hook
import scripts.model_resolver as model_resolver
import scripts.runners.base as base

KIMI_HOME_DIRNAME = "kimi-home"
_GUARD = os.path.abspath(kimi_guard_hook.__file__)
# Symlinked into the per-run home: the OAuth credential stores (file + dir).
# Config itself is regenerated, not linked -- the hooks have to merge into it.
_CREDENTIAL_ITEMS = ("credentials", "oauth")
# No fan-out template grants these; disabling them globally confines the
# UNENFORCED entries (default agent surface) as well.
_DISABLED_TOOLS = ["Agent", "AgentSwarm", "Bash"]
# Session markers of an enclosing Kimi session. A nested `kimi -p` launches
# fine with them set (measured on 0.42.0), but they are dropped so no future
# version can read the child as attached to the parent session.
_NESTED_MARKERS = ("KIMI_SESSION_ID", "KIMI_CODE_VERSION")


# --- TOML emission ----------------------------------------------------------
# Stdlib has tomllib for reading but no writer. This emits the subset TOML a
# config.toml uses: scalars, string arrays, tables, and arrays of tables.

def _toml_key(key):
    if key and all(c.isalnum() or c in "_-" for c in key):
        return key
    return json.dumps(key)


def _toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[%s]" % ", ".join(_toml_value(v) for v in value)
    raise TypeError("cannot emit TOML for %r" % (value,))


def _emit_table(lines, table, path):
    scalars = {k: v for k, v in table.items() if not isinstance(v, dict)}
    arrays = {k: v for k, v in table.items() if isinstance(v, dict)}
    for key, value in scalars.items():
        if isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
            for item in value:                      # [[array.of.tables]]
                lines.append("\n[[%s]]" % path)
                _emit_table(lines, item, path)
        else:
            lines.append("%s = %s" % (_toml_key(key), _toml_value(value)))
    for key, sub in arrays.items():
        subpath = "%s.%s" % (path, _toml_key(key))
        lines.append("\n[%s]" % subpath)
        _emit_table(lines, sub, subpath)


def dump_toml(config):
    """Serialize a tomllib-produced dict back to TOML text."""
    lines = []
    scalars = {k: v for k, v in config.items() if not isinstance(v, dict)}
    for key, value in scalars.items():
        if isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
            for item in value:
                lines.append("\n[[%s]]" % _toml_key(key))
                _emit_table(lines, item, _toml_key(key))
        else:
            lines.append("%s = %s" % (_toml_key(key), _toml_value(value)))
    for key, sub in config.items():
        if isinstance(sub, dict):
            lines.append("\n[%s]" % _toml_key(key))
            _emit_table(lines, sub, _toml_key(key))
    return "\n".join(lines) + "\n"


def _hook_entry(matcher, mode, data_path):
    return {"event": "PreToolUse", "matcher": matcher,
            "command": 'python3 "%s" %s "%s"' % (_GUARD, mode, os.path.abspath(data_path)),
            "timeout": 30}


def build_merged_config(source, scope_path, allowlist_path):
    """The operator's config dict plus the per-run deltas (see module docstring)."""
    merged = dict(source)
    merged["merge_all_available_skills"] = False
    merged["builtin_product_skills"] = False
    tools = dict(merged.get("tools") or {})
    disabled = sorted(set(tools.get("disabled") or []) | set(_DISABLED_TOOLS))
    tools["disabled"] = disabled
    merged["tools"] = tools
    hooks = [h for h in (merged.get("hooks") or []) if isinstance(h, dict)]
    hooks.append(_hook_entry("Read|Grep|Glob", "read", scope_path))
    hooks.append(_hook_entry("Write|Edit", "write", allowlist_path))
    merged["hooks"] = hooks
    return merged


def _read_source_config(real_home):
    path = os.path.join(real_home, "config.toml")
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh), path
    except FileNotFoundError:
        return {}, path


def build_kimi_home(run_dir, scope_path, allowlist_path, real_home=None):
    """Create <run_dir>/kimi-home (idempotent) and return its path."""
    real_home = real_home or os.environ.get("KIMI_CODE_HOME") or os.path.expanduser("~/.kimi-code")
    home = os.path.join(run_dir, KIMI_HOME_DIRNAME)
    os.makedirs(home, exist_ok=True)
    os.chmod(home, 0o700)
    for item in _CREDENTIAL_ITEMS:
        source = os.path.join(real_home, item)
        link = os.path.join(home, item)
        if os.path.islink(link):
            os.unlink(link)
        if os.path.exists(source):
            os.symlink(source, link)
    source, _path = _read_source_config(real_home)
    merged = build_merged_config(source, scope_path, allowlist_path)
    tmp = os.path.join(home, "config.toml.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(dump_toml(merged))
    os.replace(tmp, os.path.join(home, "config.toml"))
    return home


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
    source, _path = _read_source_config(real_home)
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
    default_concurrency = 8

    def __init__(self, host="kimi", runner=subprocess.run):
        super().__init__(host)
        self.runner = runner
        self.kimi_home = None
        self.review_root = None
        self.configured = None
        self.max_turns = 60
        self.entry_timeout = 1800          # seconds per entry; a stuck agent is a failed entry

    def prepare(self, run_dir, review_root):
        """Build the per-run Kimi home (idempotent) and snapshot the installed
        CLI's model table for alias resolution."""
        self.review_root = os.path.abspath(review_root)
        scope_path = os.path.join(run_dir, base.SCOPE_FILE)
        allowlist_path = os.path.join(run_dir, base.ALLOWLIST_FILE)
        self.kimi_home = build_kimi_home(run_dir, scope_path, allowlist_path)
        self.configured = configured_models()

    def _shell_path(self, entry):
        directory = hosts.spec(self.host).registration_dir
        return os.path.join(directory, "%s.md" % entry["agent"])

    def command(self, entry, alias):
        """The argv for one entry. `--agent-file=<abs shell>` (equals form:
        0.42.0 misparses the space form after -p) gives the shell EXPLICIT
        precedence -- above any project-scoped shadow file in the reviewed
        tree, which is the whole point of registering enforcement shells.
        `-m` binds the model on EVERY entry that names one: Kimi agent files
        cannot bind one themselves."""
        cmd = [self.CLI, "--output-format", "stream-json"]
        if entry.get("enforced") and entry.get("agent"):
            cmd.append("--agent-file=%s" % self._shell_path(entry))
        if alias:
            cmd += ["-m", alias]
        cmd += ["-p", entry["prompt"]]
        return cmd

    def parse_envelope(self, entry_id, stdout, returncode):
        """stream-json lines: the last assistant content is the reply; the
        session.resume_hint meta names the session id the wire file keys on."""
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
            return base.RunResult.failed(
                entry_id, "kimi -p exited %s: %s" % (returncode, text[:200]))
        return text, session_id

    def run_entry(self, entry, env):
        # `env` is the loop's three-key BINDING OVERLAY (spec 4.4), never a
        # whole environment -- the child inherits os.environ and the overlay
        # goes ON TOP (C1: an overlay-only child has no PATH and cannot start).
        entry_id = entry.get("id")
        if entry.get("enforced") and entry.get("agent"):
            shell = self._shell_path(entry)
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
        run_env = dict(os.environ)
        run_env.update(env)
        run_env["KIMI_CODE_HOME"] = self.kimi_home
        run_env["KIMI_LOOP_MAX_STEPS_PER_TURN"] = str(int(self.max_turns))
        for marker in _NESTED_MARKERS:
            run_env.pop(marker, None)
        cmd = self.command(entry, alias)
        try:
            proc = self.runner(cmd, cwd=self.review_root, env=run_env, capture_output=True,
                               text=True, timeout=self.entry_timeout)
        except subprocess.TimeoutExpired:
            return base.RunResult.failed(entry_id, "kimi -p timed out after %ss" % self.entry_timeout)
        except OSError as exc:
            return base.RunResult.failed(entry_id, "could not launch %s: %s" % (self.CLI, exc))
        except Exception as exc:          # run_entry never raises (spec 4.4)
            return base.RunResult.failed(entry_id,
                                          "kimi -p launch raised %s: %s" % (type(exc).__name__, exc))
        parsed = self.parse_envelope(entry_id, proc.stdout, proc.returncode)
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
