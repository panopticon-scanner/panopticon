"""The driver's child processes: the phase CLIs `driver.py` subprocesses.

Split out of `phases/runio.py` (which owns the rest of the driver's I/O) when
bounding the capture -- #1576's reader threads and #1575's process-group kill --
would have pushed that module past the 700-line ratchet `tests/test_layout.py`
holds it to. One subject, one module: how a phase child is spawned, how long it
may run, how much of what it says is kept, and how it is ended.

`_SCRIPTS_DIR` and `DriverError` stay in `runio` and are reached as module
attributes (tests/test_layout.py rule 1) -- the scripts directory is one
expression for the whole package and the error type is the driver's, not this
module's.
"""
import os
import subprocess

import scripts.phases.runio as runio


def _child_env():
    """Env for subprocessed panopticon CLIs. They do `import scripts.*` (a
    namespace package) plus BARE imports of both skill/scripts modules (e.g.
    `import evidence`) and repo-root scripts/ modules (e.g. `import file_issues`),
    so PYTHONPATH must mirror tests/conftest.py exactly: skill, skill/scripts,
    and <repo>/scripts."""
    scripts_dir = runio._SCRIPTS_DIR                   # .../skill/scripts
    skill_dir = os.path.dirname(scripts_dir)           # .../skill
    repo_root = os.path.dirname(skill_dir)             # .../panopticon
    repo_scripts = os.path.join(repo_root, "scripts")  # .../panopticon/scripts
    env = dict(os.environ)
    parts = [skill_dir, scripts_dir, repo_scripts]
    env["PYTHONPATH"] = os.pathsep.join(
        parts + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    return env

# Hard bound per phase so a wedged discovery/synthesize or a hung tool runner
# cannot block the whole (resumable, CI-automatable) driver indefinitely (#1094).
# discovery/synthesize are fast; the tools phase is a generous backstop above
# run_tools' own per-tool TOOL_TIMEOUT=900 -- it catches a wedged run_tools
# harness, not a single slow scanner.
_CHILD_TIMEOUTS = {"discovery": 600, "tools": 7200, "synthesize": 600}

_CHILD_TIMEOUT_DEFAULT = 600

def _run_child(cmd, review_root, phase, timeout=None):
    """subprocess.run for a deterministic phase, converting a spawn-level OSError
    (ENOENT on the interpreter, EMFILE, a bad cwd, ...) or a phase timeout into a
    DriverError so run()'s handler yields a clean status:error instead of a raw
    traceback or an unbounded hang (#1033; #1094; #1021/5.0-14 covered only the
    --pr acquire path). Returns the CompletedProcess on a normal spawn — a
    non-zero exit is the caller's to interpret, not a spawn error."""
    if timeout is None:
        timeout = _CHILD_TIMEOUTS.get(phase, _CHILD_TIMEOUT_DEFAULT)
    try:
        return subprocess.run(cmd, cwd=review_root, capture_output=True,  # nosec B603
                              text=True, env=_child_env(), timeout=timeout)
    except subprocess.TimeoutExpired:
        raise runio.DriverError("%s: %s timed out after %ss"
                                % (phase, cmd[1] if len(cmd) > 1 else cmd[0], timeout))
    except OSError as exc:
        raise runio.DriverError("%s: could not spawn %s: %s"
                                % (phase, cmd[1] if len(cmd) > 1 else cmd[0], exc))
