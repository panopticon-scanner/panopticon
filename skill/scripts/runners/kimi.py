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
api_key-authenticated installs). BECAUSE it carries that surface the home is
built under the operator's temp root (``$XDG_RUNTIME_DIR`` where there is one),
mode 700, `config.toml` mode 600 -- never inside the tree under review, where
the always-unenforced setup scan's own scope would admit it, an archived run
folder would embed it, and the children's verbatim `wire.jsonl` would land
beside the code being reviewed (C1). It is removed on `complete`, and stripped
of its credential files on every other way out (N6, R2-2).
PR evidence must quote capabilities, never this directory.

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
import stat
import subprocess
import sys
import tempfile
import tomllib

import scripts.dispatch as dispatch
import scripts.hosts as hosts
import scripts.kimi_toml as kimi_toml
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
    (and over host_probes.DEFAULT_RUNNER). Deliberately NOT an OSError: an
    `except OSError` on a launch path would swallow it and report a probe
    state, hiding that the suite reached for the real binary.

    REBASE STEP (N1): #1619 ships the same class as
    `scripts.codex_host.LaunchRefused` and asserts ONE class through every
    seam, so this name becomes an alias of it (or both move to
    `runners/base.py`). Keep the RuntimeError base either way.
    """


# C1 (gate review): the per-run home is built under the OPERATOR's temp root,
# never under `<run_dir>` inside the reviewed tree. What lands in it is the
# operator's credential surface -- the OAuth stores symlinked in and a
# config.toml carrying whatever the source config holds, `api_key` included --
# and a run folder inside the target is readable by the always-unenforced
# setup-scan reviewer (its scope is the whole review root), embedded by any
# `zip -r` of the run folder, and reachable by the target's own tooling.
# chmod 700 does not help there: every one of those readers is the same uid.
# The run folder keeps only POINTER_FILE, INFORMATIONAL ONLY (N2): an operator
# debugging an errored run needs to know where the home is, but nothing here or
# in the probes reads it back. It sits in the reviewed tree, so reading it
# would make an untrusted file an input to where this run's credential surface
# is written and to what the probes call evidence. Every `prepare` mints a
# fresh home; nothing is reused.
HOME_PREFIX = "panopticon-kimi-"
POINTER_FILE = "kimi-home-path"
_GUARD = os.path.abspath(kimi_guard_hook.__file__)
# Symlinked into the per-run home: the OAuth credential stores (file + dir).
# Config itself is regenerated, not linked -- the hooks have to merge into it.
_CREDENTIAL_ITEMS = ("credentials", "oauth")
# The CLI's builtin tool vocabulary by major.minor, measured from a live
# session's `llm.tools_snapshot` on 0.42.0. It lives with the runner that must
# DENY these names, not with the probe that reports on them: Kimi's config
# offers `tools.disabled` and no allow-list, so closing the surface needs every
# name the CLI ships. An uncovered version gets the union below (denying a name
# the CLI lacks is inert); the PROBE is what refuses to bless one.
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
    """The tools the per-run config turns off for every child. I1: an
    ALLOW-LIST expressed as a deny-list -- the CLI's whole vocabulary minus
    what the templates grant. The old three-name list closed 3 of 24 and left
    every UNENFORCED entry (the setup scan is always one) holding ReadMediaFile
    (a read tool the guard did not know), FetchURL/WebSearch (egress, the other
    half of C1) and CronCreate/CronDelete (persistence on the operator's
    machine). For an ENFORCED entry the shell's `tools:` grant is the control
    and this is belt-and-braces."""
    names = (set(vocabulary) if vocabulary is not None
             else set().union(*TOOL_VOCABULARY.values()))
    return sorted(names - allowed_tool_union())
# Session markers of an enclosing Kimi session. A nested `kimi -p` launches
# fine with them set (measured on 0.42.0), but they are dropped so no future
# version can read the child as attached to the parent session.
_NESTED_MARKERS = ("KIMI_SESSION_ID", "KIMI_CODE_VERSION")


def _hook_entry(matcher, mode, data_path):
    return {"event": "PreToolUse", "matcher": matcher,
            "command": 'python3 "%s" %s "%s"' % (_GUARD, mode, os.path.abspath(data_path)),
            "timeout": 30}


_SOURCE_DEFAULT = "~/.kimi-code/config.toml"


def _expect(source_path, key, value, kinds, what, items=None):
    """M3: the operator's config is THEIR file. A key this merge reads whose
    shape it does not expect must say so in those terms -- `dict()` on an array
    raised "dictionary update sequence element #0 has length 4", loud but
    naming neither file nor key. N5: `items` checks what is IN an array, not
    only that it is one -- `tools.disabled = [1, 2]` passed the array test and
    then raised "'<' not supported between instances of 'str' and 'int'" from
    the merge."""
    if value is not None and not isinstance(value, kinds):
        raise ValueError("%s: expected %s at `%s`, found %s"
                         % (source_path or _SOURCE_DEFAULT, what, key,
                            type(value).__name__))
    if items is None or not isinstance(value, list):
        return
    for element in value:
        if not isinstance(element, items):
            raise ValueError("%s: expected %s at `%s`, found %s in it"
                             % (source_path or _SOURCE_DEFAULT, what, key,
                                type(element).__name__))


def build_merged_config(source, scope_path, allowlist_path, source_path=None):
    """The operator's config dict plus the per-run deltas (see module docstring)."""
    _expect(source_path, "config.toml", source, dict, "a table")
    tools_in = source.get("tools")
    _expect(source_path, "tools", tools_in, dict, "a table")
    if isinstance(tools_in, dict):
        _expect(source_path, "tools.disabled", tools_in.get("disabled"), list,
                "an array of strings", items=str)
    # `[hooks]` rather than `[[hooks]]` used to iterate the dict's KEYS, drop
    # them all as non-dicts, and arm a config whose operator hooks had silently
    # vanished. Name it instead.
    _expect(source_path, "hooks", source.get("hooks"), list, "an array of tables",
            items=dict)                                 # R2-3: and what is IN it
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

    The bound on every destructive step (`teardown`): an `rmtree` of a path
    this does not admit would be someone else's delete. A symlink is refused
    outright (lstat, not stat): it names one path and resolves to another.
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
    """A fresh per-run home under $XDG_RUNTIME_DIR (where there is one) or the
    temp root, mode 700. `mkdtemp` creates it exclusively: no window in which
    someone else's file or link holds the name."""
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
    # R3-2: the credential links go in BEFORE the merge can refuse the
    # operator's config, and a home `prepare` never got to record is one no
    # teardown reclaims -- so a failure past this point takes the home with it.
    try:
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
        _write_text(os.path.join(home, "config.toml"), kimi_toml.dump_toml(merged))
    except BaseException:
        shutil.rmtree(home, ignore_errors=True)
        raise
    return home


def _write_text(path, text):
    """Stage at `<path>.tmp` and rename, mode 0o600, never writing THROUGH a
    symlink planted at the staging name (I2). A private mirror of
    `write_guard_hook._atomic_write_json`'s flags rather than a call into it:
    runners/claude.py uses that helper because it ALREADY imports the hook for
    `_hook_entry`, and this module imports no part of it (kimi's guard is
    kimi_guard_hook.py). The shared rule is the flags -- O_EXCL refuses a stale
    leftover, O_NOFOLLOW the link, 0o600 whatever the umask says."""
    tmp = path + ".tmp"
    if os.path.islink(tmp) or os.path.exists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


def strip_secrets(home):
    """Remove the credential-bearing files from a per-run home, leaving the
    children's transcripts; returns the names removed (N6). `config.toml`
    carries whatever the operator's config holds, `api_key` included;
    `credentials`/`oauth` are SYMLINKS, so unlinking drops the handle, never
    the store."""
    removed = []
    for name in ("config.toml",) + _CREDENTIAL_ITEMS:
        path = os.path.join(home, name)
        try:
            if os.path.islink(path) or os.path.isfile(path):
                os.unlink(path)
                removed.append(name)
        except OSError:
            pass
    return removed


def pointer_path(run_dir):
    """Where the run folder records this run's home. Write-only, by design
    (N2): there is deliberately no reader in this module."""
    return os.path.join(run_dir, POINTER_FILE)


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
        self.run_home = None           # the seam's name for it (base.HostRunner)
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
        if not os.path.isfile(_GUARD):
            raise RuntimeError(
                "the kimi guard hook is absent at %s; refusing to launch "
                "reviewers whose read/write confinement would be unarmed" % _GUARD)
        scope_path = os.path.join(run_dir, base.SCOPE_FILE)
        allowlist_path = os.path.join(run_dir, base.ALLOWLIST_FILE)
        self.kimi_home = build_kimi_home(new_kimi_home(), scope_path, allowlist_path)
        # `run_home` is the seam's own name for it: the loop reads it off the
        # runner and hands it to the probes, so an effective-surface probe can
        # find this run's children without opening anything in the target.
        self.run_home = self.kimi_home
        self.home_pointer = pointer_path(run_dir)
        os.makedirs(run_dir, exist_ok=True)
        _write_text(self.home_pointer, self.kimi_home + "\n")
        self._arm_crash_strippers()
        self.configured = configured_models()

    def _strip_on_exit(self):
        """Take the credential files out of THIS process's home. Idempotent and
        bounded by `is_temp_home` exactly as `teardown` is; it touches no other
        home, so two runs on one machine cannot interfere."""
        home = self.kimi_home
        if home and is_temp_home(home):
            strip_secrets(home)

    def _arm_crash_strippers(self):
        """Strip the secrets on the ways out that never reach `teardown` (R2-2):
        `teardown` runs from orchestrate._finish, so a `kill`, an OOM kill or a
        power loss leaves the home behind -- and since N2 removed reuse, no
        later run adopts it. `atexit` covers a normal-ish exit and an unhandled
        exception; SIGTERM goes on top, CHAINING to whatever was there -- safe
        on this side of the drain because its chain ends in SIG_DFL, which ends
        the process: nothing launches after it. SIGINT is deliberately NOT here
        (R3-1): KeyboardInterrupt is already routed by orchestrate.loop to
        teardown("error") AFTER run_batch's pool has drained, and a handler
        strips BEFORE the drain -- every entry still queued would then launch
        against a home with no config.toml, i.e. no guard hooks. SIGKILL nobody
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
                if node is ours:
                    signal.signal(signum, ours.previous)
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
        self._disarm_crash_strippers()
        home = self.kimi_home
        if not home or not is_temp_home(home):
            return
        if status == "complete":
            shutil.rmtree(home, ignore_errors=True)
            self._drop_pointer()
            self.kimi_home = self.run_home = None
            return
        removed = strip_secrets(home)
        note = ("its %s removed, so nothing left there carries a credential"
                % " and ".join(removed)) if removed else "it holds no credential files"
        print("driver loop: the kimi run home is kept for debugging at %s; %s"
              % (home, note), file=sys.stderr, flush=True)

    def _drop_pointer(self):
        """A pointer that outlives the home it names is a lie in the run
        folder."""
        try:
            if self.home_pointer:
                os.unlink(self.home_pointer)
        except OSError:
            pass

    def _shell_path(self, entry):
        directory = hosts.spec(self.host).registration_dir
        return os.path.join(directory, "%s.md" % entry["agent"])

    def command(self, entry, alias):
        """The argv for one entry. `--agent-file=<abs shell>` (equals form:
        0.42.0 misparses the space form after -p) gives the shell EXPLICIT
        precedence over any project-scoped shadow file in the reviewed tree,
        which is the point of registering enforcement shells. `-m` binds the
        model on EVERY entry that names one."""
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
