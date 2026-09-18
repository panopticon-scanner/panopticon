"""The two snapshots a kimi probe measures against.

Split out of `probes/kimi.py` (a pure move) so neither module sits on the
700-line ceiling. Both are READINGS, not judgements: each returns what it
found plus where it found it, and the `probe_kimi_*` entry points next door
decide what that means.

* the child's own `llm.tools_snapshot` under THIS run's per-run home
  (`_kimi_wire_snapshot`) -- the effective tool surface of a reviewer that
  really ran;
* the `config.toml` the RUNNER generates (`_kimi_armed_home`,
  `_kimi_generated_disabled`) -- built inside a sandbox from a fixture
  operator config, through the real `runners/kimi_home.build_kimi_home`, so
  what is inspected is what a run arms.

No host CLI is started from here. `probes/kimi.py` is still the only probe
module that spawns one, so it is still the only one carrying a
`DEFAULT_RUNNER` (tests/conftest.py's LAUNCH_SEAMS, and the AST walk in
tests/test_host_launch_guard.py). `_kimi_version` stayed behind with it for
exactly that reason: a second spawn seam here would be a second launcher to
keep refusing, for one `kimi --version`.
"""
import glob
import json
import os
import tempfile
import tomllib

from . import common


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

def _kimi_armed_home(sandbox):
    """Build the per-run home the RUNNER builds, inside `sandbox`, from a
    minimal fixture operator config. Returns (home, scope_path, allowlist_path).

    The real `build_kimi_home` -- not a re-implementation -- so the file this
    inspects is the file a run arms. C1 puts the runner's own home under the
    temp root; the probe passes a home inside its sandbox instead, so nothing
    survives the probe. The operator's real home is never read.
    """
    import scripts.runners.kimi_home as kimi_home
    fixture_home = os.path.join(sandbox, "fixture-home")
    os.makedirs(fixture_home, exist_ok=True)
    with open(os.path.join(fixture_home, "config.toml"), "w", encoding="utf-8") as fh:
        fh.write('default_model = "kimi-code/k3"\n')
    run_dir = os.path.join(sandbox, "run")
    os.makedirs(run_dir, exist_ok=True)
    scope_path = os.path.join(run_dir, "read-scope.json")
    allowlist_path = os.path.join(run_dir, "write-allowlist.json")
    home = kimi_home.build_kimi_home(os.path.join(sandbox, "kimi-home"),
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
