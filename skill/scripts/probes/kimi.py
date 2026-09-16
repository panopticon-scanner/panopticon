"""The kimi family's probes: what a Kimi host proves about itself.

Split out of `host_probes.py` (#1627); the probes themselves arrived with the
kimi family PR (#1344). The kimi runner confines reviewers through a per-run
KIMI_CODE_HOME whose config registers kimi_guard_hook.py (see
runners/kimi.py's docstring for the whole design). These probes prove the
pieces: the shells' tool surface, the two guard round-trips through the REAL
hook protocol (a subprocess, exactly as the CLI invokes it), the model-alias
binding, and the wire-file usage channel.

What every family shares is reached by module attribute (`common.<name>`), so
each of those names still has exactly one definition and one patch target.
The probe-id -> function registry stays in `host_probes.py`.
"""
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib

from scripts import dispatch, hosts, kimi_toml, model_resolver, write_guard_hook

from . import common



# I3 (gate review): every spawn of a REAL host binary in this module resolves
# its launcher from this ONE module attribute, inside the call, so
# tests/conftest.py's autouse guard can swap it for a refusal.
#
# N1 (re-review): the name is per MODULE, not per family. #1619's launch guard
# finds seams by AST walk and then asserts `hasattr(module, "DEFAULT_RUNNER")`
# and refuses through it. #1627 split the probes by family, and this is the
# only probe module that starts a host CLI (`kimi --version`, `kimi doctor`),
# so it is the module that carries the launcher and the module
# tests/conftest.py's LAUNCH_SEAMS names. Reading a sibling's launcher instead
# would leave this module without the attribute the guard asserts on -- and a
# family module that grows a spawn of its own grows its own DEFAULT_RUNNER and
# joins that tuple, because the walk turns red until it does.
#
# The guard-hook round-trip below is NOT routed through it: that subprocess is
# `sys.executable`, the hook's own protocol, and refusing it would delete the
# proof rather than protect it.
DEFAULT_RUNNER = subprocess.run

KIMI_SHELL_SURFACE = "kimi-shell-surface"
KIMI_READ_GUARD = "kimi-read-guard-armed"
KIMI_WRITE_GUARD = "kimi-write-guard-armed"
KIMI_MODEL_ALIAS = "kimi-model-alias-bound"
KIMI_USAGE_WIRE = "kimi-usage-wire"

# The CLI's builtin tool vocabulary lives with the RUNNER
# (runners.kimi.TOOL_VOCABULARY), because the runner is what has to deny it:
# Kimi's config offers a deny-list and no allow-list, so the per-run
# `tools.disabled` is derived from that table minus the templates' grants (I1).
# The probe reads the same table back. A version it does not cover resolves
# UNKNOWN, never a guess: a tool name that matches nothing in the installed CLI
# is warned about and restricts NOTHING (FAMILY-PR-GUARDRAILS, the recorded
# kimi finding), so a stale table must not wave the shells through.


def _kimi_version(runner=None):
    """The installed CLI's major.minor ("0.42"), or None."""
    import scripts.runners.base as runners_base
    runner = DEFAULT_RUNNER if runner is None else runner
    try:
        proc = runner(["kimi", "--version"], capture_output=True, text=True, timeout=15)
    except runners_base.LaunchRefused:  # I3: the suite's guard propagates --
        raise                           # never reported as "version unknown"
    except Exception:  # noqa: BLE001 -- a probe reports, never raises
        return None
    text = (proc.stdout or "") + (proc.stderr or "")
    match = re.search(r"(\d+)\.(\d+)\.\d+", text)
    return "%s.%s" % (match.group(1), match.group(2)) if match else None


_TOOLS_SNAPSHOT = "llm.tools_snapshot"


def _kimi_wire_snapshot(run_home):
    """(tools, agent, wire) from the most recent child's `llm.tools_snapshot`
    under THIS run's per-run home, or (None, None, why).

    I5: the effective tool surface of a child that really ran, which is the
    only thing that answers "did the shell restrict it". `run_home` is handed
    in by the loop, off the live runner instance (N2). It is deliberately NOT
    read back from the run folder's pointer file: that file sits in the
    reviewed tree, and a target that could rewrite it could point this probe
    at a directory it had planted -- turning `host-capabilities.json` into a
    record of a child that never ran.

    The record's shape is read tolerantly: `tools` as names or as objects with
    a `name`, and the agent under any of the spellings a snapshot has been
    seen to use. A record this cannot read is "no snapshot", never a
    refutation -- an unrecognised shape is unknown data, not evidence.
    """
    home = run_home
    if not home or not os.path.isdir(home):
        return None, None, "this run has no per-run kimi home yet"
    pattern = os.path.join(glob.escape(home), "sessions", "*", "*", "agents", "*", "wire.jsonl")
    try:
        wires = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    except OSError as exc:        # a file that vanished between glob and stat
        return None, None, "the per-run home's wire files could not be listed: %s" % exc
    for wire in wires:
        tools, agent = None, None
        try:
            with open(wire, encoding="utf-8") as fh:
                for line in fh:
                    try:
                        record = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(record, dict) or record.get("type") != _TOOLS_SNAPSHOT:
                        continue
                    names = record.get("tools")
                    if not isinstance(names, list):
                        continue
                    tools = {n if isinstance(n, str) else n.get("name")
                             for n in names if isinstance(n, (str, dict))}
                    tools.discard(None)
                    for key in ("agent", "agentName", "agent_file", "agentFile"):
                        value = record.get(key)
                        if isinstance(value, str) and value:
                            agent = os.path.basename(value)
                            agent = agent[:-3] if agent.endswith(".md") else agent
                            break
        except OSError:
            continue
        if tools is not None and agent:
            return tools, agent, wire
    return None, None, ("no child wire file under %s carries an %s record yet"
                        % (home, _TOOLS_SNAPSHOT))


def probe_kimi_shell_surface(host, registration_dir=None, version=None, runner=None,
                             run_home=None):
    """The registered shells restrict tools on the EFFECTIVE surface.

    Two halves, both required. First the template check the shipped
    `common.probe_registered_shell_tools` already performs (it understands kimi's
    block-list frontmatter): every driver role's shell exists and grants
    exactly its template's tools. Then the kimi-specific half the guardrails
    demand: every tool name those shells ALLOW or FORBID must exist in the
    installed CLI's vocabulary, because a name that matches nothing is warned
    about and restricts nothing. The vocabulary is the measured per-version
    table above; the live run's wire `llm.tools_snapshot` is the effective-
    surface confirmation (a writer-role child measured carrying exactly
    ['Read', 'Write']).
    """
    import scripts.runners.kimi as kimi_runner
    registration_dir = registration_dir or (hosts.spec(host).registration_dir
                                            if hosts.spec(host) else "")
    base_state, base_by, base_detail = common.probe_registered_shell_tools(host, registration_dir)
    if base_state != hosts.PROVEN:
        # A host that registers no shells at all gets the base probe's own
        # (UNKNOWN, None, ...) untouched: nothing ran that can be named.
        return (base_state, base_by if base_by is None else KIMI_SHELL_SURFACE, base_detail)
    if version is None:
        version = _kimi_version(runner)
    if version is None:
        return (hosts.UNKNOWN, KIMI_SHELL_SURFACE,
                "shells match their templates, but the installed kimi version "
                "could not be determined, so its tool vocabulary is unverified")
    vocabulary = kimi_runner.TOOL_VOCABULARY.get(version)
    if vocabulary is None:
        return (hosts.UNKNOWN, KIMI_SHELL_SURFACE,
                "shells match their templates, but the probe's vocabulary table "
                "does not cover kimi %s -- upgrade the table before trusting "
                "the shells' tool surface" % version)
    faults = []
    for role in common.DRIVER_ROLES:
        policy = dispatch.load_template(dispatch.ROLE_FILES[role])[0]["tool_policy"]
        for direction in ("allowed", "forbidden"):
            unknown = sorted(set(policy[direction] or []) - vocabulary)
            if unknown:
                faults.append("%s: %s tool name(s) match nothing in kimi %s: %s"
                              % (role, direction, version, ", ".join(unknown)))
    # I1: the default-agent surface is an ALLOW-LIST, so every name in the
    # CLI's vocabulary must be either granted by a template or disabled by the
    # per-run config. Anything in neither set is live for every UNENFORCED
    # entry -- and the setup scan is always unenforced.
    #
    # N3: the disabled half is read out of a config.toml the RUNNER GENERATES,
    # not recomputed from `disabled_tools()`. Recomputing subtracted the
    # templates' union from a vocabulary it had just subtracted the same union
    # from: empty by construction, an identity wearing a measurement's clothes.
    allowed = kimi_runner.allowed_tool_union()
    disabled, where = _kimi_generated_disabled()
    if disabled is None:
        # R2-4: not a fallback. I5 falls back on an unrecognised record shape --
        # third-party data -- and says so; this is OUR OWN writer failing, and
        # a probe that could not build the artifact it measures has measured
        # nothing. Fail closed rather than report `proven` with the reason
        # tucked into the detail.
        return (hosts.REFUTED, KIMI_SHELL_SURFACE,
                "%s; but the tool surface could not be measured: %s"
                % (base_detail, where))
    unaccounted = sorted(set(vocabulary) - allowed - disabled)
    if unaccounted:
        faults.append("neither granted by a template nor disabled by %s, so "
                      "live for every unenforced entry: %s"
                      % (where, ", ".join(unaccounted)))
    surface = ("all %d of kimi %s's tools are accounted for (%d granted by a "
               "template, %d disabled by %s)"
               % (len(vocabulary), version, len(allowed & set(vocabulary)),
                  len(disabled), where))
    # I5: the EFFECTIVE surface, when a child has already run in this run's
    # home. The table above says what the CLI ships; the snapshot says what a
    # launched child was actually given.
    snapshot, agent, where = _kimi_wire_snapshot(run_home)
    if snapshot is not None:
        grant = common._frontmatter_tools(os.path.join(registration_dir, "%s.md" % agent))
        if grant is None:
            measured = ("%s reports %s for %r, which is not a shell registered in "
                        "%s, so the table above is what this rests on"
                        % (where, sorted(snapshot), agent, registration_dir))
        elif set(grant) != snapshot:
            faults.append("the last child's %s for %r carries %s, its registered "
                          "shell grants %s" % (_TOOLS_SNAPSHOT, agent,
                                               sorted(snapshot), sorted(grant)))
            measured = ""
        else:
            measured = ("the last child's %s for %r carries exactly its shell's "
                        "grant %s (%s)" % (_TOOLS_SNAPSHOT, agent, sorted(grant), where))
    else:
        measured = ("%s, so the effective surface rests on the version table"
                    % where)
    if faults:
        return (hosts.REFUTED, KIMI_SHELL_SURFACE, "; ".join(faults))
    return (hosts.PROVEN, KIMI_SHELL_SURFACE,
            "%s; every tool name exists in kimi %s's builtin vocabulary; %s; %s"
            % (base_detail, version, surface, measured))


def _guard_round_trip(mode, data_path, rows, guard_path=None, runner=None):
    """Drive payloads through the guard as a subprocess -- the real hook
    protocol, not an import. `rows` is (name, payload, env_id, want_allow).
    Returns (ok, detail); the detail names what was driven through what, and
    the probes compose theirs out of it rather than restating a count of their
    own (M1: a literal "(8 rows)" beside this function's own answer drifts the
    moment a row is added). Everything happens inside the caller's tempdir."""
    import scripts.kimi_guard_hook as kimi_guard_hook
    # Plain `subprocess.run`, NOT DEFAULT_RUNNER: what this spawns is
    # `sys.executable <the hook> <mode> <data>`, the hook protocol itself.
    runner = subprocess.run if runner is None else runner
    guard_path = guard_path or os.path.abspath(kimi_guard_hook.__file__)
    for name, payload, env_id, want_allow in rows:
        env = {"PATH": os.environ.get("PATH", "")}
        if env_id:
            env[kimi_guard_hook.ENV_ENTRY_ID] = env_id
        try:
            proc = runner([sys.executable, guard_path, mode, data_path],
                          input=json.dumps(payload), capture_output=True,
                          text=True, timeout=30, env=env)
        except Exception as exc:  # noqa: BLE001 -- report, never raise
            return False, common.failure_detail(
                exc, "the guard-hook subprocess could not run")
        out = (proc.stdout or "").strip()
        denied = '"permissionDecision": "deny"' in out
        if denied == want_allow:
            return False, ("the guard %s: %s" % ("DENIED" if denied else "ALLOWED", name)
                           + (" (stdout: %s)" % out[:160] if out and not denied else ""))
    return True, ("%s round-trip: %d/%d payloads adjudicated as expected through %s"
                  % (mode, len(rows), len(rows), os.path.basename(guard_path)))


def _kimi_armed_home(sandbox):
    """Build the per-run home the RUNNER builds, inside `sandbox`, from a
    minimal fixture operator config. Returns (home, scope_path, allowlist_path).

    The real `build_kimi_home` -- not a re-implementation -- so the file this
    inspects is the file a run arms. C1 puts the runner's own home under the
    temp root; the probe passes a home inside its sandbox instead, so nothing
    survives the probe. The operator's real home is never read.
    """
    import scripts.runners.kimi as kimi_runner
    fixture_home = os.path.join(sandbox, "fixture-home")
    os.makedirs(fixture_home, exist_ok=True)
    with open(os.path.join(fixture_home, "config.toml"), "w", encoding="utf-8") as fh:
        fh.write('default_model = "kimi-code/k3"\n')
    run_dir = os.path.join(sandbox, "run")
    os.makedirs(run_dir, exist_ok=True)
    scope_path = os.path.join(run_dir, "read-scope.json")
    allowlist_path = os.path.join(run_dir, "write-allowlist.json")
    home = kimi_runner.build_kimi_home(os.path.join(sandbox, "kimi-home"),
                                       scope_path, allowlist_path,
                                       real_home=fixture_home)
    return home, scope_path, allowlist_path


def _kimi_generated_disabled():
    """(tools.disabled, where) read out of a config.toml the runner generates,
    or (None, why). The file is built and read inside a sandbox and nothing
    survives the call.

    R2-4: the except list covers every type the writer it drives can raise --
    `build_merged_config` raises ValueError (M3/N5's own mechanism) and
    `dump_toml` raises TypeError (C2's) -- because `run_probes` wraps no probe
    lambda and `_establish_host_posture` is called unwrapped, so an escape here
    would abort posture establishment with a traceback. "A probe reports,
    never raises" is this module's contract, not a tendency.
    """
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            home, _scope, _allowlist = _kimi_armed_home(sandbox)
            with open(os.path.join(home, "config.toml"), "rb") as fh:
                config = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        return None, "the generated config.toml is not valid TOML (%s)" % exc
    except (OSError, ValueError, TypeError) as exc:
        return None, common.failure_detail(
            exc, "the per-run config could not be generated")
    tools = config.get("tools") if isinstance(config.get("tools"), dict) else {}
    names = {t for t in (tools.get("disabled") or []) if isinstance(t, str)}
    return names, "the config.toml the runner generates"


_KIMI_GUARD_PROBE = {"read": "read guard probe", "write": "write guard probe"}


def _kimi_hooks_are_armed(sandbox, mode):
    """(ok, detail): does the config.toml the runner generates REGISTER
    `mode`'s guard? `ok` is None when the home could not be built at all.

    N7: a probe refutes on ITS OWN hook. Both matchers are still inspected --
    the other one's absence is disclosed in the detail, naming the probe that
    owns it -- because over-refutation never blesses anything but it does make
    a reader scanning states alone believe the write guard is broken when only
    read confinement is. What stays shared are the faults that are not
    a hook: a config.toml that will not parse (neither hook registers), a
    `tools.disabled` that no longer covers the derived set, and an `mcp` block
    that is not the inert one the runner writes (#1640) -- MCP tools come from
    another process under names neither guard has heard, so a home that does
    not say they are off is unmediated for BOTH.

    C3: both guard probes are named "...-armed", and both used to prove only
    the adjudication -- payloads through the hook script -- while nothing
    looked at whether the hook was registered anywhere. With
    `build_merged_config` replaced by one that arms no hooks, both still
    returned `proven`. This is the half C2 could break by accident and a
    refactor could break with no test going red, so it is measured here:
    the generated file is parsed with `tomllib` and must carry exactly one
    PreToolUse hook per matcher, each command naming this repo's guard script,
    its own mode and its own data file, with the runner's disabled-tool set
    present in `tools.disabled`.
    """
    import scripts.kimi_guard_hook as kimi_guard_hook
    import scripts.runners.kimi as kimi_runner
    try:
        home, scope_path, allowlist_path = _kimi_armed_home(sandbox)
        with open(os.path.join(home, "config.toml"), "rb") as fh:
            config = tomllib.load(fh)
    except OSError as exc:
        return None, common.failure_detail(
            exc, "the per-run home could not be built")
    except tomllib.TOMLDecodeError as exc:
        return False, ("the config.toml the runner generates is not valid TOML "
                       "(%s), so the run would start with its guard hooks "
                       "unregistered" % exc)
    guard = os.path.abspath(kimi_guard_hook.__file__)
    hooks = [h for h in (config.get("hooks") or []) if isinstance(h, dict)]
    tools = config.get("tools") if isinstance(config.get("tools"), dict) else {}
    disabled = set(tools.get("disabled") or [])
    faults, notes, mine, mine_file = [], [], None, ""
    for matcher, this_mode, data_path in ((kimi_runner.READ_MATCHER, "read", scope_path),
                                          (kimi_runner.WRITE_MATCHER, "write", allowlist_path)):
        problems = []
        matching = [h for h in hooks
                    if h.get("event") == "PreToolUse" and h.get("matcher") == matcher]
        if len(matching) != 1:
            problems.append("%d PreToolUse hooks match %r, expected exactly 1"
                            % (len(matching), matcher))
        else:
            command = matching[0].get("command") or ""
            for needle, what in ((guard, "the guard script %s" % guard),
                                 (" %s " % this_mode, "its %s mode argument" % this_mode),
                                 (os.path.abspath(data_path), "its %s data file" % this_mode)):
                if needle not in command:
                    problems.append("the %r hook's command does not name %s: %r"
                                    % (matcher, what, command[:160]))
        if this_mode == mode:
            mine, mine_file = matcher, os.path.basename(data_path)
            faults.extend(problems)
        elif problems:
            notes.append("%s (the %s owns that one)"
                         % ("; ".join(problems), _KIMI_GUARD_PROBE[this_mode]))
    missing = sorted(set(kimi_runner.disabled_tools()) - disabled)
    if missing:
        faults.append("tools.disabled omits %s" % ", ".join(missing))
    # #1640: read back off the FILE, like every other fault here -- the
    # question is what the home the run arms actually carries, not what
    # `build_merged_config` meant to put in it.
    #
    # Fix round 1 (F2): the block must be PRESENT and be exactly the inert one.
    # This used to coerce a non-dict `mcp` to `{}` and a non-list `servers` to
    # `[]` and then ask whether anything was live -- both coercions fail OPEN,
    # so an ABSENT block, a scalar `mcp`, or a `servers` it could not read all
    # reported `proven`. Those are not evidence that MCP is off; they are the
    # absence of evidence, and they are exactly the shape a refactor that
    # dropped the `merged["mcp"]` assignment would leave behind. Compared
    # against the one definition, so probe and runner cannot drift.
    mcp = config.get("mcp")
    if mcp != kimi_toml.INERT_MCP:
        faults.append("the armed `mcp` block is %.120r, not the inert %r the runner writes: "
                      "MCP tools are served by another process under names neither guard "
                      "adjudicates, so a home that does not say they are off is not proof "
                      "that they are" % (mcp, kimi_toml.INERT_MCP))
    if faults:
        return False, ("the config.toml the runner generates does not arm the %s "
                       "guard: %s" % (mode, "; ".join(faults)))
    detail = ("the config.toml the runner generates registers %s on %r with this "
              "run's %s, and disables %d tool(s)"
              % (os.path.basename(guard), mine, mine_file, len(disabled)))
    if notes:
        detail += "; note: %s" % "; ".join(notes)
    return True, detail


def _kimi_home_arms_and_validates(runner=None):
    """(ok, detail): the generated per-run config arms both guards AND
    `kimi doctor` accepts it. `ok` None means nothing could be measured."""
    runner = DEFAULT_RUNNER if runner is None else runner
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            ok, detail = _kimi_hooks_are_armed(sandbox, "read")
            if ok is not True:
                return ok, detail
            env = dict(os.environ, KIMI_CODE_HOME=os.path.join(sandbox, "kimi-home"))
            proc = runner(["kimi", "doctor"], capture_output=True, text=True,
                          timeout=60, env=env)
    except OSError as exc:
        return None, common.failure_detail(
            exc, "`kimi doctor` could not run over the per-run home")
    if proc.returncode != 0 or "OK config.toml" not in (proc.stdout or ""):
        return False, ("kimi doctor rejected the generated per-run config: %s%s"
                       % (proc.stdout or "", proc.stderr or ""))[:300]
    return True, "%s, and kimi doctor validates it" % detail


def probe_kimi_read_guard(host, runner=None, doctor_runner=None):
    """Kimi can confine a dispatched reviewer's reads to its entry's scope.

    Two halves, both required. ADJUDICATION: the guard subprocess allows an
    in-scope read and denies outside reads, unbound sessions, unknown entries
    and a malformed scope file. ARMING (C3): the config.toml the runner
    generates really registers that script as a PreToolUse hook, with this
    run's scope file bound into its command, in a file `kimi doctor` accepts.
    NOT "armed right now" -- the loop arms the scope file per batch, so at run
    start it is legitimately absent.

    `runner` drives the guard subprocess (plain python; tests use the real
    one). `doctor_runner` drives `kimi doctor` and is resolved separately,
    from DEFAULT_RUNNER, so the suite never launches the real host
    binary (FAMILY-PR-GUARDRAILS, Suite rules; I3): the two spawns are
    different binaries and must not share one default.
    """
    if not hosts.declares(host, hosts.READ_SCOPE_CONFINED):
        return (hosts.UNKNOWN, None,
                "host %r claims no read-scope confinement" % host)
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            inside = os.path.realpath(os.path.join(sandbox, "cell", "a.py"))
            outside = os.path.realpath(os.path.join(sandbox, "elsewhere", "b.py"))
            for p in (inside, outside):
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("")
            scope_path = os.path.join(sandbox, "read-scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({"probe-cell": {"files": [inside], "dirs": [], "reads": []}}, fh)
            rows = (
                ("bound Read inside scope",
                 {"tool_name": "Read", "tool_input": {"path": inside}}, "probe-cell", True),
                ("bound Read outside scope",
                 {"tool_name": "Read", "tool_input": {"path": outside}}, "probe-cell", False),
                ("bound Grep of an in-scope file",
                 {"tool_name": "Grep", "tool_input": {"pattern": "x", "path": inside}}, "probe-cell", True),
                ("bound Grep over a directory",
                 {"tool_name": "Grep", "tool_input": {"pattern": "x", "path": os.path.dirname(inside)}}, "probe-cell", False),
                ("bound Glob",
                 {"tool_name": "Glob", "tool_input": {"pattern": "*.py", "path": os.path.dirname(inside)}}, "probe-cell", False),
                ("unbound session Read",
                 {"tool_name": "Read", "tool_input": {"path": inside}}, None, False),
                ("unknown entry Read",
                 {"tool_name": "Read", "tool_input": {"path": inside}}, "not-armed", False),
            )
            ok, detail = _guard_round_trip("read", scope_path, rows, runner=runner)
            if not ok:
                return (hosts.REFUTED, KIMI_READ_GUARD, detail)
            round_trip_detail = detail
            with open(scope_path, "w", encoding="utf-8") as fh:
                fh.write("not json")
            ok, detail = _guard_round_trip(
                "read", scope_path,
                (("malformed scope file",
                  {"tool_name": "Read", "tool_input": {"path": inside}}, "probe-cell", False),),
                runner=runner)
            if not ok:
                return (hosts.REFUTED, KIMI_READ_GUARD, detail)
            round_trip_detail = "%s; and, with the data file corrupted, %s" % (
                round_trip_detail, detail)
    except OSError as exc:
        return (hosts.UNKNOWN, KIMI_READ_GUARD, common.failure_detail(
            exc, "the read-guard sandbox round-trip could not run"))
    armed, armed_detail = _kimi_home_arms_and_validates(doctor_runner)
    if armed is None:
        return (hosts.UNKNOWN, KIMI_READ_GUARD,
                "%s, but %s" % (round_trip_detail, armed_detail))
    if not armed:
        return (hosts.REFUTED, KIMI_READ_GUARD, armed_detail)
    # M1: composed from what the two halves REPORTED -- no hardcoded row count
    # (the old "(8 rows)" was a literal beside `_guard_round_trip`'s own
    # answer, and drifted the moment a row was added) and no surface this
    # probe did not open.
    return (hosts.PROVEN, KIMI_READ_GUARD, "%s; %s" % (round_trip_detail, armed_detail))


def probe_kimi_write_guard(host, runner=None):
    """Kimi can mediate a self-writing reviewer's Write/Edit.

    Same shape as the read probe: declared out_file allowed, everything else
    denied, symlinks denied, malformed allowlist denied -- and then the arming
    half (C3), which parses the config.toml the runner generates and requires
    the write hook to be registered there. The allowlist is the file the loop
    arms per batch (orchestrate.Guards), so it is legitimately absent at probe
    time.

    #1571: the allowlist is built by `write_guard_hook.allowlist_document` --
    the writer a real arming uses -- and the rows now include the boundary the
    run-13 finding crossed, a bound entry writing a PEER entry's out_file.
    Two data-file refutations follow: a version-1 flat list and a v2 document
    with no `entries`, both of which must deny rather than fall back to a
    batch-wide grant.
    """
    if not hosts.declares(host, hosts.ARTIFACT_WRITE_GUARD):
        return (hosts.UNKNOWN, None,
                "host %r claims no artifact write guard" % host)
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            declared = os.path.realpath(os.path.join(sandbox, "findings-probe.json"))
            other = os.path.realpath(os.path.join(sandbox, "not-declared.json"))
            with open(declared, "w", encoding="utf-8") as fh:
                fh.write("{}")
            peer = os.path.realpath(os.path.join(sandbox, "findings-peer.json"))
            allowlist_path = os.path.join(sandbox, "write-allowlist.json")
            with open(allowlist_path, "w", encoding="utf-8") as fh:
                json.dump(write_guard_hook.allowlist_document(
                    {"probe-cell": [declared], "peer-cell": [peer]}), fh)
            rows = (
                ("Write to the declared out_file",
                 {"tool_name": "Write", "tool_input": {"path": declared, "content": "{}"}}, "probe-cell", True),
                ("Write outside the allowlist",
                 {"tool_name": "Write", "tool_input": {"path": other, "content": "{}"}}, "probe-cell", False),
                ("Edit outside the allowlist",
                 {"tool_name": "Edit", "tool_input": {"path": other}}, "probe-cell", False),
                ("Write to a PEER entry's declared out_file",
                 {"tool_name": "Write", "tool_input": {"path": peer, "content": "{}"}}, "probe-cell", False),
                ("Write bound to an entry the allowlist does not name",
                 {"tool_name": "Write", "tool_input": {"path": declared, "content": "{}"}}, "ghost-cell", False),
                ("unbound session Write",
                 {"tool_name": "Write", "tool_input": {"path": declared, "content": "{}"}}, None, False),
            )
            ok, detail = _guard_round_trip("write", allowlist_path, rows, runner=runner)
            if not ok:
                return (hosts.REFUTED, KIMI_WRITE_GUARD, detail)
            round_trip_detail = detail
            corrupt = (("malformed allowlist", "not json"),
                       ("version-1 flat list", json.dumps([declared])),
                       ("v2 document with no entries",
                        json.dumps({"version": 2, "paths": [declared]})))
            for name, body in corrupt:
                with open(allowlist_path, "w", encoding="utf-8") as fh:
                    fh.write(body)
                ok, detail = _guard_round_trip(
                    "write", allowlist_path,
                    ((name,
                      {"tool_name": "Write", "tool_input": {"path": declared, "content": "{}"}}, "probe-cell", False),),
                    runner=runner)
                if not ok:
                    return (hosts.REFUTED, KIMI_WRITE_GUARD, detail)
                round_trip_detail = "%s; and, with a %s on disk, %s" % (
                    round_trip_detail, name, detail)
            # C3: the ARMING half, in the same sandbox -- the write probe used
            # to build no home at all, so its detail ("the runner arms the hook
            # in the per-run home's config.toml") named a file it never opened.
            armed, armed_detail = _kimi_hooks_are_armed(sandbox, "write")
    except OSError as exc:
        return (hosts.UNKNOWN, KIMI_WRITE_GUARD, common.failure_detail(
            exc, "the write-guard sandbox round-trip could not run"))
    if armed is None:
        return (hosts.UNKNOWN, KIMI_WRITE_GUARD,
                "%s, but %s" % (round_trip_detail, armed_detail))
    if not armed:
        return (hosts.REFUTED, KIMI_WRITE_GUARD, armed_detail)
    return (hosts.PROVEN, KIMI_WRITE_GUARD, "%s; %s" % (round_trip_detail, armed_detail))


def probe_kimi_model_alias(host, configured=None):
    """Every role's entry model resolves to an alias the installed CLI has.

    The runner binds `-m <alias>` on every entry (Kimi agent files cannot
    bind a model), so the question is exactly the runner's: does the tier the
    entry carries resolve through model-profiles.yml to an alias present in
    the installed config's [models] table. An unresolvable role is a
    refutation -- that entry would fail at launch rather than silently run
    the session's default model.
    """
    import scripts.runners.kimi as kimi_runner
    if not hosts.declares(host, hosts.MODEL_BINDING):
        return (hosts.UNKNOWN, None, "host %r claims no model binding" % host)
    if configured is None:
        configured = kimi_runner.configured_models()
    if not configured:
        return (hosts.REFUTED, KIMI_MODEL_ALIAS,
                "no [models] table is readable in the installed kimi config, "
                "so no entry model can bind")
    faults, bound = [], []
    for role in common.DRIVER_ROLES:
        tier = model_resolver.resolve_model(host, role).get("model")
        alias = kimi_runner.resolve_cli_alias(tier, configured)
        if alias is None:
            faults.append("%s: entry model %r resolves to no configured alias" % (role, tier))
        else:
            bound.append("%s->%s" % (role, alias))
    if faults:
        return (hosts.REFUTED, KIMI_MODEL_ALIAS, "; ".join(faults))
    return (hosts.PROVEN, KIMI_MODEL_ALIAS,
            "%d/%d roles bind a configured alias: %s"
            % (len(bound), len(common.DRIVER_ROLES), ", ".join(bound)))


def probe_kimi_usage_wire(host):
    """The usage ledger's channel, end to end on the layout the runner globs.

    I4: the runner reads `wire_path(self.kimi_home, session_id)` -- a file the
    CHILD writes under the PER-RUN home, which its own `KIMI_CODE_HOME`
    override guarantees is not `~/.kimi-code`. The probe therefore builds a
    per-run home, writes a synthetic session at exactly that layout, and
    proves `wire_path` + `parse_wire` together: resolution and summation, the
    two steps a real launch takes between a child finishing and a ledger row
    existing. It refutes when `wire_path` cannot resolve the layout (the
    ledger would report null rather than a figure) and when the parser returns
    anything but the figures the synthetic records carry.

    Everything it writes lives in the tempdir it owns (N4). It deliberately
    takes no `home` parameter: `run_probes`' `home=` means "a stand-in for ~"
    to the transcript probe, and taking the same argument here meant one name
    with two meanings -- and a fixture session left behind in whatever
    directory the caller had in mind.
    """
    import scripts.runners.kimi as kimi_runner
    if not hosts.declares(host, hosts.USAGE_LEDGER):
        return (hosts.UNKNOWN, None, "host %r claims no usage ledger" % host)
    session_id = "session_probe"
    records = [
        {"type": "llm.request", "modelAlias": "kimi-code/k3"},
        {"type": "usage.record", "model": "kimi-code/k3", "usageScope": "turn",
         "usage": {"inputOther": 10, "output": 3, "inputCacheRead": 5, "inputCacheCreation": 2}},
        {"type": "usage.record", "model": "kimi-code/k3", "usageScope": "turn",
         "usage": {"inputOther": 7, "output": 1, "inputCacheRead": 0, "inputCacheCreation": 0}},
        {"type": "usage.record", "model": "kimi-code/k3", "usageScope": "session",
         "usage": {"inputOther": 999, "output": 999, "inputCacheRead": 999, "inputCacheCreation": 999}},
    ]
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            run_home = os.path.join(sandbox, "kimi-home")
            # The layout `wire_path` globs: <home>/sessions/*/<sid>/agents/main/
            wire = os.path.join(run_home, "sessions", "wd_probe", session_id,
                                "agents", "main", "wire.jsonl")
            os.makedirs(os.path.dirname(wire), exist_ok=True)
            with open(wire, "w", encoding="utf-8") as fh:
                for record in records:
                    fh.write(json.dumps(record) + "\n")
            resolved = kimi_runner.wire_path(run_home, session_id)
            usage, model = kimi_runner.parse_wire(resolved) if resolved else ({}, None)
    except OSError as exc:
        return (hosts.UNKNOWN, KIMI_USAGE_WIRE, common.failure_detail(
            exc, "the per-run wire round-trip could not run"))
    if resolved is None:
        return (hosts.REFUTED, KIMI_USAGE_WIRE,
                "a child's wire.jsonl written at the per-run home's own layout "
                "(%s) does not resolve through wire_path, so the cost ledger "
                "would report null rather than a figure" % wire)
    expected = {"input_tokens": 17, "output_tokens": 4,
                "cache_read_input_tokens": 5, "cache_creation_input_tokens": 2}
    if usage != expected or model != "kimi-code/k3":
        return (hosts.REFUTED, KIMI_USAGE_WIRE,
                "wire_path resolved %s but parse_wire returned %r (model %r), "
                "expected %r" % (resolved, usage, model, expected))
    return (hosts.PROVEN, KIMI_USAGE_WIRE,
            "a synthetic session under the run home %s resolves through "
            "wire_path to %s and sums to %d input / %d output tokens, the "
            "turn-scoped records only" % (run_home, resolved,
                                          expected["input_tokens"], expected["output_tokens"]))
