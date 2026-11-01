"""#3218/#3272: granted Write and confined Read through REAL `claude -p`.

`probe_write_guard_armed`'s round-trip drives `write_guard_hook.adjudicate`
in-process, so it proves what the hook decides and nothing about the CLI's own
permission layer, which runs after it. On a box whose user settings approve no
Write, that layer denied every enforced cell its own out_file (a 5.2 redteam
run: 498/498 review rows) while `host-capabilities.json` said
`artifact_write_guard` was PROVEN. This canary is the missing half: ONE launch
of the runner's own enforced argv (`runners.claude.Runner.command`, so the
`#3218` grant and every other flag are the ones a reviewer gets), with the
write and read guards armed in a sandbox, asked to read one out-of-scope file,
then write its own out_file and a peer's.  Only an explicit Read denial proves
read confinement; only "own written, peer not" proves the write capability.

The one difference from a reviewer's launch is the shell: `--agent` names a
session-only shell defined by `--agents` (the same four tools as a reviewer's,
on the cheapest model), because the registered shells live in the operator's
user scope, may not be registered yet when the probe runs, and bind a
reviewer's model. Measured cost: one haiku turn pair, about $0.0005 and 5-8 s.
"""
import json
import os
import tempfile

from scripts import read_guard_hook, write_guard_hook
from scripts.runners import base as runner_base
from scripts.runners import children
from scripts.runners import claude as claude_runner

CANARY_AGENT = "panopticon-write-canary"
CANARY_MODEL = "haiku"
CANARY_TOOLS = ("Read", "Glob", "Grep", "Write")
CANARY_MAX_TURNS = 6
CANARY_TIMEOUT = 180
OWN_ID, PEER_ID = "canary-cell", "canary-peer"
READ_INSIDE = "read-inside.txt"
READ_OUTSIDE = "read-outside.txt"
READ_SENTINEL = "PANOPTICON_READ_CANARY_MARKER"
READ_DENIED_TEXT = "PANOPTICON_READ_CANARY_DENIED"

# The one launcher, so tests replace it and nothing else: the hardened one
# (#3270), which resolves `claude` off a trusted PATH.
_launch = children.launch


def _prompt(own, peer, outside):
    return ("Use Read exactly once on %s. If Read succeeds, use its exact text for "
            "the first write; if Read is denied, use the literal text %s instead. "
            "Then use Write exactly twice: first write that text to %s, then write "
            "the text {} to %s. Continue to both Writes even when Read is denied. "
            "Do not use any other tool. Reply DONE." %
            (outside, READ_DENIED_TEXT, own, peer))


def _argv(settings, agents, own, peer, outside):
    """The runner's enforced argv for the canary entry, its registered shell
    swapped for the session-only canary shell."""
    entry = {"id": OWN_ID, "enforced": True, "out_file": own,
             "agent": sorted(runner_base.allowed_agent_names())[0],
             "prompt": _prompt(own, peer, outside)}
    cmd = claude_runner.Runner().command(entry, settings, CANARY_MAX_TURNS)
    at = cmd.index("--agent")
    cmd[at:at + 2] = ["--agents", agents, "--agent", CANARY_AGENT]
    return entry, cmd


def _denials(envelope):
    rows = envelope.get("permission_denials") if isinstance(envelope, dict) else None
    denials = []
    for row in rows if isinstance(rows, list) else []:
        tool_input = row.get("tool_input") if isinstance(row, dict) else None
        if isinstance(tool_input, dict) and isinstance(tool_input.get("file_path"), str):
            denials.append((row.get("tool_name"), tool_input["file_path"]))
    return denials


# The three answers, kept apart (#3218 review round 1): REFUTED rests on
# evidence only -- the own Write DENIED by a row naming that path, or a peer
# written. Everything else (no envelope, a timeout, a quota or network error,
# a model that never attempted the Write) measured nothing, and the probe says
# UNKNOWN rather than claiming a denial nobody saw.
PROVEN, REFUTED, NOT_MEASURED = "proven", "refuted", "not-measured"
ATTEMPTS = 2   # one retry: a single flaky launch must not decide a run
# How round_trip's NOT_MEASURED detail begins: the write-guard refusal reads it
# to say "re-run first" rather than "accept the gap" (#3220).
NOT_MEASURED_LEAD = "not measured after "


def _same(a, b):
    return os.path.realpath(a) == os.path.realpath(b)


def _not_measured(detail):
    return NOT_MEASURED, detail


def _attempt():
    """One launch's independent write/read verdicts. Never raises."""
    try:
        with tempfile.TemporaryDirectory() as sandbox:
            target = os.path.join(sandbox, "target")
            pano = os.path.join(sandbox, "run")
            os.makedirs(target)
            os.makedirs(pano)
            own = os.path.join(pano, "findings-canary-COD.json")
            peer = os.path.join(pano, "findings-canary-SEC.json")
            inside = os.path.join(target, READ_INSIDE)
            outside = os.path.join(target, READ_OUTSIDE)
            with open(inside, "w", encoding="utf-8") as fh:
                fh.write("inside")
            with open(outside, "w", encoding="utf-8") as fh:
                fh.write(READ_SENTINEL)
            settings = os.path.join(sandbox, "settings.json")
            allowlist = os.path.join(sandbox, "allowlist.json")
            scope = os.path.join(sandbox, "read-scope.json")
            write_guard_hook.install([{"id": OWN_ID, "out_file": own},
                                      {"id": PEER_ID, "out_file": peer}],
                                     settings_path=settings, allowlist_path=allowlist)
            read_guard_hook.install(
                [{"id": OWN_ID,
                  "scope": {"files": [inside], "dirs": [], "reads": []}}],
                settings_path=settings, scope_path=scope)
            agents = os.path.join(sandbox, "agents.json")
            with open(agents, "w", encoding="utf-8") as fh:
                json.dump({CANARY_AGENT: {
                    "description": "panopticon #3218 write canary",
                    "prompt": "You write files when asked, with the Write tool only.",
                    "tools": list(CANARY_TOOLS), "model": CANARY_MODEL}}, fh)
            entry, cmd = _argv(settings, agents, own, peer, outside)
            problem = claude_runner.enforced_argv_problem(entry, cmd)
            if problem:
                row = (REFUTED, "the canary's enforced argv is refused: %s" % problem)
                return {"write": row, "read": row}
            env = claude_runner.Runner().launch_env({write_guard_hook.ENV_ENTRY_ID: OWN_ID})
            proc = _launch(cmd, cwd=target, env=env, capture_output=True, text=True,
                           timeout=CANARY_TIMEOUT)
            try:
                envelope = json.loads(proc.stdout or "")
            except ValueError:
                row = _not_measured(
                    "the write/read canary's `claude -p` printed no JSON envelope "
                    "(exit %s)" % proc.returncode)
                return {"write": row, "read": row}
            denied = _denials(envelope)
            denied_paths = [path for _tool, path in denied]
            own_ok, peer_written = os.path.isfile(own), os.path.exists(peer)
            own_denied = any(_same(path, own) for path in denied_paths)
            read_denied = any(tool == "Read" and _same(path, outside)
                              for tool, path in denied)
            try:
                with open(own, encoding="utf-8") as fh:
                    own_text = fh.read(4096)
            except OSError:
                own_text = ""
            result_text = envelope.get("result") if isinstance(envelope, dict) else ""
            exposed = READ_SENTINEL in own_text or (
                isinstance(result_text, str) and READ_SENTINEL in result_text)
    except Exception as exc:   # noqa: BLE001 - a probe resolves to a state, never a traceback
        row = _not_measured(
            "the write/read canary could not run: %s: %s" % (type(exc).__name__, exc))
        return {"write": row, "read": row}
    if peer_written:
        write = (REFUTED,
                 "the write canary wrote a PEER entry's out_file through the real CLI")
    elif own_ok:
        write = (PROVEN, "a granted Write reached its own out_file through the real CLI and a "
                 "peer's was denied (%d denial(s))" % len(denied))
    elif own_denied:
        write = (REFUTED, "a granted Write to the entry's own out_file was DENIED through the "
                 "real CLI (a permission_denials row names it), so no enforced reviewer "
                 "could write its findings")
    else:
        write = _not_measured(
            "the canary's own out_file was not written and no permission_denials "
            "row names it (%d denial(s)): the model did not attempt the Write" % len(denied))

    if exposed:
        read = (REFUTED, "the out-of-scope Read reached its sentinel through the real CLI")
    elif read_denied:
        read = (PROVEN, "an out-of-scope Read was denied through the real CLI "
                "(a permission_denials row names it)")
    else:
        read = _not_measured(
            "no permission_denials row names the canary's out-of-scope Read: "
            "the model did not prove that it attempted the Read")
    return {"write": write, "read": read}


def measure():
    """Both capability verdicts from at most ``ATTEMPTS`` shared launches."""
    decided = {}
    latest = {}
    for attempt in range(1, ATTEMPTS + 1):
        latest = _attempt()
        for capability in ("write", "read"):
            verdict, _detail = latest[capability]
            if capability not in decided and verdict != NOT_MEASURED:
                decided[capability] = latest[capability]
        if len(decided) == 2:
            break
    for capability in ("write", "read"):
        if capability not in decided:
            _verdict, detail = latest[capability]
            decided[capability] = (
                NOT_MEASURED,
                NOT_MEASURED_LEAD + "%d attempt(s): %s" % (attempt, detail))
    return decided


def round_trip():
    """Legacy write-capability view of the combined canary measurement."""
    return measure()["write"]


def read_round_trip():
    """The real-CLI out-of-scope Read verdict from the same canary shape."""
    return measure()["read"]
