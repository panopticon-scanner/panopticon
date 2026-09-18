"""The per-run Kimi home: the sandboxed ``$KIMI_CODE_HOME`` every
`kimi -p` child runs under, and the config that arms its guard hooks.

Split out of `runners/kimi.py` (a pure move) so neither module sits on the
700-line ceiling. `Runner.prepare` mints one home per run and `teardown`
disposes of it; nothing else here knows about entries, aliases or the wire
file.

WHY A PER-RUN KIMI HOME. Kimi Code registers hooks only in
``$KIMI_CODE_HOME/config.toml`` -- there is no ``--settings`` flag and no
project-level hooks file -- and it discovers credentials under the same root.
So `prepare` builds a per-run home: the operator's OAuth stores (`credentials`,
`oauth`) are SYMLINKED in (never copied: no secret bytes are duplicated), and
`config.toml` is regenerated from the operator's own with four deltas --

  * the two guard hooks (kimi_guard_hook.py read/write) with this run's
    scope/allowlist paths baked into their commands;
  * ``merge_all_available_skills = false`` and ``builtin_product_skills =
    false``, which keep the OPERATOR's own skills out of a reviewer. They do
    NOT stop a hostile target's (measured, #1657 spike): the launch's
    ``--skills-dir=<per-run home>/no-skills`` is what does that, by replacing
    both auto-discovered roots with one empty run-owned directory
    (`new_skills_dir` below, `runners/kimi.py::command`);
  * ``tools.disabled``, DERIVED as the CLI's whole tool vocabulary minus the
    union of the role templates' allowed lists -- an allow-list expressed in
    the only form Kimi's config takes. That closes the default-agent surface
    for UNENFORCED entries too (the setup scan is always one), where a
    three-name deny-list left an unguarded read tool, two egress tools and a
    persistence tool live;
  * ``[mcp]``, REPLACED rather than carried: `enabled = false` and no servers,
    whatever the operator's config holds. It is a SECOND LAYER, not the
    mechanism: 0.42.0's config schema does not know those keys. How many were
    dropped is said on stderr (#1640; `kimi_toml.mediated_mcp` says why).

WHAT ACTUALLY NEUTRALISES TARGET-PLANTED MCP: KIMI'S WORKSPACE-TRUST GATE ON A
FRESH HOME (measured 2026-09-18, one real launch). The 0.42.0 CLI reads
``<git root>/.mcp.json`` and ``<cwd>/.kimi-code/mcp.json`` only when the
WORKSPACE-TRUST record for cwd exists under ``KIMI_CODE_HOME`` (the
``workspace-trust/`` document scope): `configLoader.loadMcpServersDetailed`
takes `includeProject` from `this.trust.isTrusted()`. The per-run home is a
fresh `mkdtemp` that links only `_CREDENTIAL_ITEMS`, so no such record exists,
cwd is untrusted, and those files are never read -- two planted stdio servers
neither spawned. Link the trust scope in, or copy the operator's home
wholesale, and they would: the reviewer would hold tools no `tools.disabled`
entry and no guard hook can see. That is why `_CREDENTIAL_ITEMS` is pinned by
a test naming this gate (tests/runners/test_kimi_surface.py).

Every other value in the source config is carried verbatim -- including any
plaintext `api_key` the operator keeps there (stripping it would break
api_key-authenticated installs). BECAUSE it carries that surface the home is
built under the operator's temp root (``$XDG_RUNTIME_DIR`` where there is one),
mode 700, `config.toml` mode 600 -- never inside the tree under review, where
the always-unenforced setup scan's own scope would admit it, an archived run
folder would embed it, and the children's verbatim `wire.jsonl` would land
beside the code being reviewed (C1). It is removed on `complete`, and stripped
of its credential files on every other way out (N6, R2-2).
PR evidence must quote capabilities, never this directory.
"""

import os
import shutil
import stat
import sys
import tempfile
import tomllib

import scripts.dispatch as dispatch
import scripts.kimi_toml as kimi_toml
import scripts.kimi_guard_hook as kimi_guard_hook


# C1 (gate review): the per-run home is built under the OPERATOR's temp root, never under
# `<run_dir>` inside the reviewed tree. What lands in it is the operator's credential surface --
# the OAuth stores symlinked in and a config.toml carrying whatever the source config holds,
# `api_key` included -- and a run folder inside the target is readable by the always-unenforced
# setup-scan reviewer (its scope is the whole review root), embedded by any `zip -r` of the run
# folder, and reachable by the target's own tooling. chmod 700 does not help there: every one of
# those readers is the same uid. The run folder keeps only POINTER_FILE, INFORMATIONAL ONLY (N2):
# an operator debugging an errored run needs to know where the home is, but nothing here or in the
# probes reads it back. It sits in the reviewed tree, so reading it would make an untrusted file
# an input to where this run's credential surface is written and to what the probes call evidence.
# Every `prepare` mints a fresh home; nothing is reused.
HOME_PREFIX = "panopticon-kimi-"
POINTER_FILE = "kimi-home-path"
_GUARD = os.path.abspath(kimi_guard_hook.__file__)
# Symlinked into the per-run home: the OAuth credential stores (file + dir).
# Config itself is regenerated, not linked -- the hooks have to merge into it.
# NOT a list to extend casually: what is absent from the per-run home is what
# keeps a target's MCP out of it. `workspace-trust` above all -- see the module
# docstring's gate paragraph, and the pin in tests/runners/test_kimi_surface.py.
_CREDENTIAL_ITEMS = ("credentials", "oauth")
# The CLI's builtin tool vocabulary by major.minor, measured from a live session's
# `llm.tools_snapshot` on 0.42.0. It lives with the runner that must DENY these names, not with
# the probe that reports on them: Kimi's config offers `tools.disabled` and no allow-list, so
# closing the surface needs every name the CLI ships. An uncovered version gets the union below
# (denying a name the CLI lacks is inert); the PROBE is what refuses to bless one.
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

def _hook_entry(matcher, mode, data_path):
    # #1633: a SHELL STRING Kimi runs through `sh -c` -- quote every element.
    return {"event": "PreToolUse", "matcher": matcher,
            "command": kimi_guard_hook.hook_command(
                "python3", _GUARD, mode, os.path.abspath(data_path)),
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
    # `[hooks]` rather than `[[hooks]]` used to iterate the dict's KEYS, drop them all
    # as non-dicts, and arm a config whose operator hooks had silently vanished. Name it instead.
    _expect(source_path, "hooks", source.get("hooks"), list, "an array of tables",
            items=dict)                                 # R2-3: and what is IN it
    merged = dict(source)
    merged["mcp"] = kimi_toml.mediated_mcp(source, disclose=sys.stderr)   # #1640
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
    # I2: lstat BEFORE the chmod. `makedirs(exist_ok=True)` is happy with a symlink to a
    # directory and `chmod` follows it, so a link planted at this name (on a resume, where
    # the path is re-derived rather than freshly minted) would relax someone else's
    # directory to 700 and then take the merged config -- api_key included -- through it.
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

def new_skills_dir(home):
    """An empty, mode-700 skill root inside the per-run home, for the launch's
    `--skills-dir` (KM-1, #1657).

    INSIDE the home rather than beside it so `teardown` disposes of both at
    once, and so the directory a reviewer's skill discovery is pointed at is
    one this run created and nothing else can reach by name. Idempotent: a
    second `prepare` on the same home gets the same empty directory.
    """
    path = os.path.join(home, "no-skills")
    os.makedirs(path, exist_ok=True)
    os.chmod(path, 0o700)
    return path


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
