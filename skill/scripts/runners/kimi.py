"""The Kimi headless runner (spec 4.4): one `kimi -p` per entry, a per-run
KIMI_CODE_HOME carrying the guard hooks, usage from the session's wire file.

WHY A PER-RUN KIMI HOME. Kimi Code registers hooks only in
``$KIMI_CODE_HOME/config.toml`` -- there is no ``--settings`` flag and no
project-level hooks file -- and it discovers credentials under the same root.
So `prepare` builds a per-run home: the operator's OAuth stores (`credentials`,
`oauth`) are SYMLINKED in (never copied: no secret bytes are duplicated), and
`config.toml` is regenerated from the operator's own with three deltas --

  * the two guard hooks (kimi_guard_hook.py read/write) with this run's
    scope/allowlist paths baked into their commands;
  * ``merge_all_available_skills = false`` and ``builtin_product_skills =
    false``, so neither the operator's nor a hostile TARGET's skills can
    inject into a reviewer;
  * ``tools.disabled``, DERIVED as the CLI's whole tool vocabulary minus the
    union of the role templates' allowed lists -- an allow-list expressed in
    the only form Kimi's config takes. That closes the default-agent surface
    for UNENFORCED entries too (the setup scan is always one), where a
    three-name deny-list left an unguarded read tool, two egress tools and a
    persistence tool live.

The source config's other values are carried verbatim -- including any
plaintext `api_key` the operator keeps there (stripping it would break
api_key-authenticated installs). BECAUSE it carries that surface, the home is
built under the operator's temp root (``$XDG_RUNTIME_DIR`` where the platform
has one), mode 700, with `config.toml` mode 600 -- never inside the tree under
review, where the always-unenforced setup-scan reviewer's own scope would
admit it, an archived run folder would embed it, and the children's verbatim
`wire.jsonl` transcripts would land beside the code being reviewed (C1). The
run folder keeps one pointer file, ``kimi-home-path``, so a resume finds the
same home; `teardown` removes it on `complete` and keeps it, loudly, on an
error. PR evidence must quote capabilities, never this directory.

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
import datetime
import glob
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib

import scripts.dispatch as dispatch
import scripts.hosts as hosts
import scripts.kimi_guard_hook as kimi_guard_hook
import scripts.model_resolver as model_resolver
import scripts.runners.base as base

# I3 (gate review): the launcher is a MODULE ATTRIBUTE, never a default
# argument, and every spawn resolves it inside the body. A default argument
# binds `subprocess.run` at import time, where `monkeypatch.setattr` cannot
# reach it -- so tests/conftest.py's autouse `_no_live_kimi_launches` can only
# refuse a real `kimi` launch if the name is looked up per call, here. The
# sibling family PRs bind their own module attribute the same way.
DEFAULT_RUNNER = subprocess.run


class LaunchRefused(RuntimeError):
    """The suite's structural guard refused a real `kimi` launch.

    Raised only by the fake tests/conftest.py installs over `DEFAULT_RUNNER`
    (and over host_probes.DEFAULT_RUNNER). It is deliberately NOT an OSError:
    every `except OSError` on a launch path would otherwise swallow it and
    report a probe state, hiding the fact that the suite reached for the real
    binary. Nothing in production raises it.

    REBASE STEP (N1). #1619 ships the same class as
    `scripts.codex_host.LaunchRefused`, and its guard test asserts one class
    for the whole suite (`assertRaises(codex_host.LaunchRefused)` through
    every seam). When that lands, this name becomes an alias of it -- one
    class, two spellings -- or both move to `runners/base.py`; keep the
    subclass-of-RuntimeError contract either way, since that is what keeps
    `except OSError` on the launch paths from swallowing it.
    """


# C1 (gate review): the per-run home is built under the OPERATOR's temp root,
# never under `<run_dir>` inside the reviewed tree. What lands in it is the
# operator's credential surface -- the OAuth stores symlinked in and a
# config.toml carrying whatever the source config holds, `api_key` included --
# and a run folder inside the target is readable by the always-unenforced
# setup-scan reviewer (its scope is the whole review root), embedded by any
# `zip -r` of the run folder, and reachable by the target's own tooling.
# chmod 700 does not help there: every one of those readers is the same uid.
# The run folder keeps only POINTER_FILE so a resume and the probes can find
# the home again.
HOME_PREFIX = "panopticon-kimi-"
POINTER_FILE = "kimi-home-path"
_GUARD = os.path.abspath(kimi_guard_hook.__file__)
# Symlinked into the per-run home: the OAuth credential stores (file + dir).
# Config itself is regenerated, not linked -- the hooks have to merge into it.
_CREDENTIAL_ITEMS = ("credentials", "oauth")
# The CLI's builtin tool vocabulary by major.minor, measured from a live
# session's `llm.tools_snapshot` wire record on 0.42.0. It lives HERE, with the
# runner that must deny them, rather than with the probe that reports on them:
# Kimi's config offers a deny-list (`tools.disabled`) and no allow-list, so
# turning the templates' allow-list into a closed surface requires knowing
# every name the CLI ships. A version this table does not cover still gets the
# union below (denying a name the CLI does not have is inert); the PROBE is
# what refuses to bless an uncovered version.
TOOL_VOCABULARY = {
    "0.42": frozenset({
        "Agent", "AgentSwarm", "AskUserQuestion", "Bash", "CreateGoal",
        "CronCreate", "CronDelete", "CronList", "Edit", "EnterPlanMode",
        "ExitPlanMode", "FetchURL", "GetGoal", "Glob", "Grep", "Read",
        "ReadMediaFile", "SetGoalBudget", "Skill", "TaskList", "TaskOutput",
        "TaskStop", "TodoList", "UpdateGoal", "WaitFor", "WebSearch", "Write",
    }),
}
# The two PreToolUse matchers the guard registers under. Named here because
# the arming PROBE reads them back out of the generated config (C3): one
# owner, so a matcher the runner stops emitting is a refutation rather than a
# probe that quietly looks for the wrong string. ReadMediaFile is named
# explicitly rather than left to a prefix match (I1): it is a read tool, the
# hook adjudicates it, and the matcher has to deliver it.
READ_MATCHER = "Read|ReadMediaFile|Grep|Glob"
WRITE_MATCHER = "Write|Edit"


def allowed_tool_union():
    """Every tool name the driver's role templates grant, across all roles.

    Derived from the shipped templates (dispatch.load_template's `tool_policy`),
    which are also what `--emit-host-agents kimi` renders into each shell's
    `tools:` block -- so the deny-list below cannot drift from the grants.
    """
    allowed = set()
    for role_file in dispatch.ROLE_FILES.values():
        meta, _body = dispatch.load_template(role_file)
        allowed |= set(meta["tool_policy"]["allowed"] or [])
    return allowed


def disabled_tools(vocabulary=None):
    """The tools the per-run config turns off for every child.

    I1: an ALLOW-LIST expressed as a deny-list -- the CLI's whole vocabulary
    minus what the templates grant -- not a hand-kept three-name deny-list.
    The old ["Agent", "AgentSwarm", "Bash"] closed 3 of 24 tools and left every
    UNENFORCED entry (the setup scan is ALWAYS unenforced) holding
    ReadMediaFile (a read tool the guard did not know), FetchURL and WebSearch
    (egress, the other half of C1's exfiltration path) and
    CronCreate/CronDelete (persistence on the operator's machine, from a review
    of a hostile repo). For an ENFORCED entry the shell's `tools:` grant is the
    control and this is belt-and-braces.
    """
    names = (set(vocabulary) if vocabulary is not None
             else set().union(*TOOL_VOCABULARY.values()))
    return sorted(names - allowed_tool_union())
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


def _toml_value(value, key=None):
    """One TOML scalar. `key` is carried only so a value this writer cannot
    emit names the key it came from -- a bare "cannot emit TOML for None" in
    the middle of `prepare` says nothing about which config line to look at.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    # datetime BEFORE date: every datetime is also a date (C2). tomllib hands
    # these back for any TOML date-time, and a CLI config that carries one
    # (`last_update_check`, an install stamp) used to abort the whole run.
    if isinstance(value, datetime.datetime):
        return value.isoformat()               # offset or local date-time
    if isinstance(value, datetime.date):
        return value.isoformat()               # local date
    if isinstance(value, datetime.time):
        return value.isoformat()               # local time
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[%s]" % ", ".join(_toml_value(v, key) for v in value)
    raise TypeError("cannot emit TOML for the value at %r: %r"
                    % (key if key is not None else "<root>", value))


def _split(table):
    """(scalars, arrays_of_tables, tables) -- the three things a TOML table
    holds, separated so the emitter can order them. TOML binds every bare
    `key = value` line to the LAST header above it, so a parent's scalars have
    to be written before any `[[...]]` or `[...]` header of its own."""
    scalars, arrays, tables = {}, {}, {}
    for key, value in table.items():
        if isinstance(value, dict):
            tables[key] = value
        elif isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
            arrays[key] = value
        else:
            scalars[key] = value
    return scalars, arrays, tables


def _emit_table(lines, table, path):
    """Emit one table's body under `path` (a dotted key path, already quoted)."""
    scalars, arrays, tables = _split(table)
    for key, value in scalars.items():
        lines.append("%s = %s" % (_toml_key(key), _toml_value(value, key)))
    for key, items in arrays.items():
        # C2: the header is the array's OWN path -- `[[mcp.servers]]`, not the
        # parent's `[[mcp]]` -- and it comes after the parent's scalars.
        subpath = "%s.%s" % (path, _toml_key(key)) if path else _toml_key(key)
        for item in items:
            lines.append("\n[[%s]]" % subpath)
            _emit_table(lines, item, subpath)
    for key, sub in tables.items():
        subpath = "%s.%s" % (path, _toml_key(key)) if path else _toml_key(key)
        lines.append("\n[%s]" % subpath)
        _emit_table(lines, sub, subpath)


def dump_toml(config):
    """Serialize a tomllib-produced dict back to TOML text."""
    lines = []
    _emit_table(lines, config, "")
    return "\n".join(lines) + "\n"


def _hook_entry(matcher, mode, data_path):
    return {"event": "PreToolUse", "matcher": matcher,
            "command": 'python3 "%s" %s "%s"' % (_GUARD, mode, os.path.abspath(data_path)),
            "timeout": 30}


_SOURCE_DEFAULT = "~/.kimi-code/config.toml"


def _expect(source_path, key, value, kinds, what):
    """M3: the operator's config is THEIR file. A key this merge reads whose
    shape it does not expect must say so in those terms -- `dict()` on an
    array raised "dictionary update sequence element #0 has length 4", which
    is loud (orchestrate reports it as an error status) but tells the operator
    nothing about which line of which file to look at."""
    if value is not None and not isinstance(value, kinds):
        raise ValueError("%s: expected %s at `%s`, found %s"
                         % (source_path or _SOURCE_DEFAULT, what, key,
                            type(value).__name__))


def build_merged_config(source, scope_path, allowlist_path, source_path=None):
    """The operator's config dict plus the per-run deltas (see module docstring)."""
    _expect(source_path, "config.toml", source, dict, "a table")
    tools_in = source.get("tools")
    _expect(source_path, "tools", tools_in, dict, "a table")
    if isinstance(tools_in, dict):
        _expect(source_path, "tools.disabled", tools_in.get("disabled"), list, "an array")
    # `[hooks]` rather than `[[hooks]]` used to iterate the dict's KEYS, drop
    # them all as non-dicts, and arm a config whose operator hooks had silently
    # vanished. Name it instead.
    _expect(source_path, "hooks", source.get("hooks"), list, "an array of tables")
    merged = dict(source)
    merged["merge_all_available_skills"] = False
    merged["builtin_product_skills"] = False
    tools = dict(merged.get("tools") or {})
    disabled = sorted(set(tools.get("disabled") or []) | set(disabled_tools()))   # I1: derived
    tools["disabled"] = disabled
    merged["tools"] = tools
    hooks = [h for h in (merged.get("hooks") or []) if isinstance(h, dict)]
    hooks.append(_hook_entry(READ_MATCHER, "read", scope_path))
    hooks.append(_hook_entry(WRITE_MATCHER, "write", allowlist_path))
    merged["hooks"] = hooks
    return merged


def _read_source_config(real_home):
    path = os.path.join(real_home, "config.toml")
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh), path
    except FileNotFoundError:
        return {}, path


def _temp_roots():
    """The directories a per-run home may legally live under."""
    roots = [os.environ.get("XDG_RUNTIME_DIR"), tempfile.gettempdir()]
    return [os.path.realpath(r) for r in roots if r]


def is_temp_home(path):
    """True when `path` is one of OUR per-run homes under a temp root.

    The predicate every destructive step is bounded by (`teardown`), and the
    one a pointer file's contents must satisfy before `prepare` will reuse
    them: that file sits in the reviewed tree, so on a hostile target its
    contents are the attacker's, and a `shutil.rmtree` of whatever it names
    would be the attacker's delete. A symlink is refused outright (lstat, not
    stat): it names one path and resolves to another.
    """
    if not path or not os.path.basename(os.path.normpath(path)).startswith(HOME_PREFIX):
        return False
    try:
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            return False
    except OSError:
        return False
    real = os.path.realpath(path)
    return any(real == root or real.startswith(root + os.sep) for root in _temp_roots())


def new_kimi_home():
    """A fresh per-run home under $XDG_RUNTIME_DIR (when the platform has one)
    or the temp root, mode 700. `mkdtemp` creates it exclusively, so there is
    no window in which someone else's file or link holds the name."""
    home = tempfile.mkdtemp(prefix=HOME_PREFIX,
                            dir=os.environ.get("XDG_RUNTIME_DIR") or None)
    os.chmod(home, 0o700)
    return home


def build_kimi_home(home, scope_path, allowlist_path, real_home=None):
    """Populate `home` with the per-run config and credential links; idempotent.

    `home` is a directory this process owns -- `new_kimi_home()`'s, or the one
    a previous `prepare` recorded and `is_temp_home` re-admitted. It is never
    derived from the reviewed tree.
    """
    real_home = real_home or os.environ.get("KIMI_CODE_HOME") or os.path.expanduser("~/.kimi-code")
    # I2: lstat BEFORE the chmod. `makedirs(exist_ok=True)` is happy with a
    # symlink to a directory and `chmod` follows it, so a link planted at this
    # name (on a resume, where the path is re-derived rather than freshly
    # minted) would relax someone else's directory to 700 and then take the
    # merged config -- api_key included -- through the link.
    if os.path.islink(home):
        raise OSError("refusing to build the kimi home through a symlink: %s" % home)
    os.makedirs(home, exist_ok=True)
    os.chmod(home, 0o700)
    for item in _CREDENTIAL_ITEMS:
        source = os.path.join(real_home, item)
        link = os.path.join(home, item)
        if os.path.islink(link):
            os.unlink(link)
        if os.path.exists(source):
            os.symlink(source, link)
    source, source_path = _read_source_config(real_home)
    merged = build_merged_config(source, scope_path, allowlist_path,
                                 source_path=source_path)
    _write_text(os.path.join(home, "config.toml"), dump_toml(merged))
    return home


def _write_text(path, text):
    """Stage at `<path>.tmp` and rename, mode 0o600, never writing THROUGH a
    symlink planted at the staging name (I2).

    A private mirror of `write_guard_hook._atomic_write_json`'s flags rather
    than a call into it: runners/claude.py routes its settings file through
    that helper because it ALREADY imports the hook for `_hook_entry` ("one
    hardened writer rather than a second open()/replace() pair here to keep in
    step with it"), and this module imports no part of it -- kimi's guard is
    kimi_guard_hook.py. The rule the two share is the flags: O_EXCL refuses a
    stale leftover, O_NOFOLLOW refuses the link, and 0o600 is the mode the
    merged config must land in whatever the umask says.
    """
    tmp = path + ".tmp"
    if os.path.islink(tmp) or os.path.exists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def pointer_path(run_dir):
    return os.path.join(run_dir, POINTER_FILE)


def read_home_pointer(run_dir):
    """The per-run home a previous `prepare` recorded under `run_dir`, or None.

    Untrusted input -- the file lives in the reviewed tree -- so the caller
    must put it through `is_temp_home` before doing anything with it.
    """
    try:
        with open(pointer_path(run_dir), encoding="utf-8") as fh:
            return fh.read().strip() or None
    except OSError:
        return None


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
    default_concurrency = 4        # the managed gateway rate-limits; 8 bursted into exit-1s (measured)

    def __init__(self, host="kimi", runner=None):
        super().__init__(host)
        # None means "the module's DEFAULT_RUNNER, resolved at launch time"
        # (I3); an injected fake stays exactly what the caller passed.
        self.runner = runner
        self.kimi_home = None
        self.review_root = None
        self.configured = None
        self.max_turns = 60
        self.entry_timeout = 1800          # seconds per entry; a stuck agent is a failed entry

    def prepare(self, run_dir, review_root):
        """Build the per-run Kimi home (idempotent) and snapshot the installed
        CLI's model table for alias resolution.

        The home lives under the temp root (C1); `run_dir` -- inside the
        reviewed tree -- keeps only the pointer file that names it, so a
        resume of this run finds the same home and the probes can read the
        children's wire files. A resume REUSES the pointed-at home only when
        `is_temp_home` still admits it; anything else (a removed home, a
        pointer an untrusted target rewrote) rebuilds from scratch.
        """
        self.review_root = os.path.abspath(review_root)
        # C3: a Kimi hook whose interpreter cannot start fails OPEN, so a
        # missing guard script is a SILENT un-confinement -- the one residual
        # the hook itself cannot catch. Refuse the run instead; `loop` turns
        # this into a reported `error` status naming the absent file.
        if not os.path.isfile(_GUARD):
            raise RuntimeError(
                "the kimi guard hook is absent at %s; refusing to launch "
                "reviewers whose read/write confinement would be unarmed" % _GUARD)
        scope_path = os.path.join(run_dir, base.SCOPE_FILE)
        allowlist_path = os.path.join(run_dir, base.ALLOWLIST_FILE)
        recorded = read_home_pointer(run_dir)
        home = recorded if is_temp_home(recorded) else new_kimi_home()
        self.kimi_home = build_kimi_home(home, scope_path, allowlist_path)
        os.makedirs(run_dir, exist_ok=True)
        _write_text(pointer_path(run_dir), self.kimi_home + "\n")
        self.configured = configured_models()

    def teardown(self, status=None):
        """Drop the per-run home on a clean finish; keep it on an error.

        Bounded by `is_temp_home` on the path THIS process built (never on the
        pointer file's contents, which the reviewed tree could have rewritten
        between prepare and teardown): a run that ends any other way than
        `complete` keeps its home so the wire files and the armed config can
        be read afterwards, and says once where it is.
        """
        home = self.kimi_home
        if not home or not is_temp_home(home):
            return
        if status == "complete":
            shutil.rmtree(home, ignore_errors=True)
            self.kimi_home = None
            return
        print("driver loop: the kimi run home is kept for debugging at %s" % home,
              file=sys.stderr, flush=True)

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

    def parse_envelope(self, entry_id, stdout, returncode, stderr=None):
        """stream-json lines: the last assistant content is the reply; the
        session.resume_hint meta names the session id the wire file keys on.
        A failed launch's reason lives on stderr (an empty stdout tail reads
        as 'exited 1: ' and diagnoses nothing -- the 2026-09-13 burst-rate
        limit failure was invisible until stderr was included)."""
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
            detail = text or (stderr or "").strip()
            return base.RunResult.failed(
                entry_id, "kimi -p exited %s: %s" % (returncode, detail[:200]))
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
        launcher = DEFAULT_RUNNER if self.runner is None else self.runner
        try:
            proc = launcher(cmd, cwd=self.review_root, env=run_env, capture_output=True,
                            text=True, timeout=self.entry_timeout)
        except LaunchRefused:             # I3: the suite's guard, never a run state
            raise                         # (first, so no later clause can absorb it)
        except subprocess.TimeoutExpired:
            return base.RunResult.failed(entry_id, "kimi -p timed out after %ss" % self.entry_timeout)
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
