"""#3218: a granted Write through the REAL `claude -p` permission layer.

`probe_write_guard_armed`'s round-trip drives `write_guard_hook.adjudicate`
in-process, so it proves what the hook decides and nothing about the CLI's own
permission layer, which runs after it. On a box whose user settings approve no
Write, that layer denied every enforced cell its own out_file (a 5.2 redteam
run: 498/498 review rows) while `host-capabilities.json` said
`artifact_write_guard` was PROVEN. This canary is the missing half: ONE launch
of the runner's own enforced argv (`runners.claude.Runner.command`, so the
`#3218` grant and every other flag are the ones a reviewer gets), with the
write guard armed in a sandbox, asked to write its own out_file and then a
peer's. Only "own written, peer not" proves the capability.

The one difference from a reviewer's launch is the shell: `--agent` names a
session-only shell defined by `--agents` (the same four tools as a reviewer's,
on the cheapest model), because the registered shells live in the operator's
user scope, may not be registered yet when the probe runs, and bind a
reviewer's model. Measured cost: one haiku turn pair, about $0.0005 and 5-8 s.
"""
import json
import os
import subprocess
import tempfile

from scripts import write_guard_hook
from scripts.runners import base as runner_base
from scripts.runners import claude as claude_runner

CANARY_AGENT = "panopticon-write-canary"
CANARY_MODEL = "haiku"
CANARY_TOOLS = ("Read", "Glob", "Grep", "Write")
CANARY_MAX_TURNS = 6
CANARY_TIMEOUT = 180
OWN_ID, PEER_ID = "canary-cell", "canary-peer"

# The one launcher, so tests replace it and nothing else.
_launch = subprocess.run


def _prompt(own, peer):
    return ("Use the Write tool exactly twice, then stop. First write the text {} to "
            "the file %s . Then write the text {} to the file %s . Do not use any "
            "other tool. Reply DONE." % (own, peer))


def _argv(settings, agents, own, peer):
    """The runner's enforced argv for the canary entry, its registered shell
    swapped for the session-only canary shell."""
    entry = {"id": OWN_ID, "enforced": True, "out_file": own,
             "agent": sorted(runner_base.allowed_agent_names())[0],
             "prompt": _prompt(own, peer)}
    cmd = claude_runner.Runner().command(entry, settings, CANARY_MAX_TURNS)
    at = cmd.index("--agent")
    cmd[at:at + 2] = ["--agents", agents, "--agent", CANARY_AGENT]
    return entry, cmd


def _denied_paths(envelope):
    rows = envelope.get("permission_denials") if isinstance(envelope, dict) else None
    paths = []
    for row in rows if isinstance(rows, list) else []:
        tool_input = row.get("tool_input") if isinstance(row, dict) else None
        if isinstance(tool_input, dict) and isinstance(tool_input.get("file_path"), str):
            paths.append(tool_input["file_path"])
    return paths


# The three answers, kept apart (#3218 review round 1): REFUTED rests on
# evidence only -- the own Write DENIED by a row naming that path, or a peer
# written. Everything else (no envelope, a timeout, a quota or network error,
# a model that never attempted the Write) measured nothing, and the probe says
# UNKNOWN rather than claiming a denial nobody saw.
PROVEN, REFUTED, NOT_MEASURED = "proven", "refuted", "not-measured"
ATTEMPTS = 2   # one retry: a single flaky launch must not decide a run


def _same(a, b):
    return os.path.realpath(a) == os.path.realpath(b)


def _attempt():
    """(verdict, detail) for one canary launch. Never raises."""
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            target = os.path.join(sandbox, "target")
            pano = os.path.join(sandbox, "run")
            os.makedirs(target)
            os.makedirs(pano)
            own = os.path.join(pano, "findings-canary-COD.json")
            peer = os.path.join(pano, "findings-canary-SEC.json")
            settings = os.path.join(sandbox, "settings.json")
            allowlist = os.path.join(sandbox, "allowlist.json")
            write_guard_hook.install([{"id": OWN_ID, "out_file": own},
                                      {"id": PEER_ID, "out_file": peer}],
                                     settings_path=settings, allowlist_path=allowlist)
            agents = os.path.join(sandbox, "agents.json")
            with open(agents, "w", encoding="utf-8") as fh:
                json.dump({CANARY_AGENT: {
                    "description": "panopticon #3218 write canary",
                    "prompt": "You write files when asked, with the Write tool only.",
                    "tools": list(CANARY_TOOLS), "model": CANARY_MODEL}}, fh)
            entry, cmd = _argv(settings, agents, own, peer)
            problem = claude_runner.enforced_argv_problem(entry, cmd)
            if problem:
                return REFUTED, "the canary's enforced argv is refused: %s" % problem
            env = claude_runner.Runner().launch_env({write_guard_hook.ENV_ENTRY_ID: OWN_ID})
            proc = _launch(cmd, cwd=target, env=env, capture_output=True, text=True,
                           timeout=CANARY_TIMEOUT)
            try:
                envelope = json.loads(proc.stdout or "")
            except ValueError:
                return NOT_MEASURED, ("the write canary's `claude -p` printed no JSON "
                                      "envelope (exit %s)" % proc.returncode)
            denied = _denied_paths(envelope)
            own_ok, peer_written = os.path.isfile(own), os.path.exists(peer)
            own_denied = any(_same(path, own) for path in denied)
    except Exception as exc:   # noqa: BLE001 - a probe resolves to a state, never a traceback
        return NOT_MEASURED, "the write canary could not run: %s: %s" % (type(exc).__name__, exc)
    if peer_written:
        return REFUTED, "the write canary wrote a PEER entry's out_file through the real CLI"
    if own_ok:
        return PROVEN, ("a granted Write reached its own out_file through the real CLI and a "
                        "peer's was denied (%d denial(s))" % len(denied))
    if own_denied:
        return REFUTED, ("a granted Write to the entry's own out_file was DENIED through the "
                         "real CLI (a permission_denials row names it), so no enforced reviewer "
                         "could write its findings")
    return NOT_MEASURED, ("the canary's own out_file was not written and no permission_denials "
                          "row names it (%d denial(s)): the model did not attempt the Write"
                          % len(denied))


def round_trip():
    """(verdict, detail): PROVEN, REFUTED or NOT_MEASURED, the canary launched
    at most ATTEMPTS times -- again only while nothing was measured."""
    for attempt in range(1, ATTEMPTS + 1):
        verdict, detail = _attempt()
        if verdict != NOT_MEASURED:
            return verdict, detail
    return NOT_MEASURED, "not measured after %d attempt(s): %s" % (attempt, detail)
