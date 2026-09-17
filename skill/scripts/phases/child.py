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
import threading

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

# #1576 (OPS-D1A): how much of a child's stdout/stderr the driver KEEPS.
# `capture_output=True` routes both streams through `Popen.communicate()`, which
# buffers each one entirely in the parent before returning; nothing bounded the
# SIZE, only the wall clock -- and the tools phase allows 7200s of it. A wedged
# run_tools harness, or `discovery.py` over a pathological tree, emits output
# proportional to file/match count, and every byte was a Python string in the
# controller until the child exited.
#
# The HEAD is what a diagnostic needs -- `tools_execute` builds its failure note
# from the first 300 characters of stderr -- so the head is what survives; the
# rest is drained and counted. Draining matters as much as capping: a child whose
# pipe fills blocks on write for ever, which is the hang the timeout exists to
# bound. Both ceilings, because either one alone has a hole: a million short
# lines, or one 50 MB line with no newline in it at all.
CAPTURE_BYTES_MAX = 1 * 1024 * 1024
CAPTURE_LINES_MAX = 20000
_CAPTURE_CHUNK = 65536
# How long `_run_child` waits for a reader thread after the child is gone.
_READER_JOIN_GRACE = 5

def _capture(stream, into, name):
    """Drain `stream` to EOF, leaving its bounded head in `into[name]`.

    The marker names how many characters were dropped rather than merely that
    something was, so a truncated diagnostic can never read as a complete one."""
    kept, size, lines, cut = [], 0, 0, 0
    while True:
        chunk = stream.read(_CAPTURE_CHUNK)
        if not chunk:
            break
        room = CAPTURE_LINES_MAX - lines
        take = chunk[:max(0, CAPTURE_BYTES_MAX - size)] if room > 0 else ""
        if take.count("\n") > room:
            take = "".join(part + "\n" for part in take.split("\n")[:room])
        kept.append(take)
        size += len(take)
        lines += take.count("\n")
        cut += len(chunk) - len(take)
    stream.close()
    into[name] = "".join(kept) + ("\n\u2026 [cut %d bytes]" % cut if cut else "")

def _run_child(cmd, review_root, phase, timeout=None):
    """Run a deterministic phase's child, converting a spawn-level OSError
    (ENOENT on the interpreter, EMFILE, a bad cwd, ...) or a phase timeout into a
    DriverError so run()'s handler yields a clean status:error instead of a raw
    traceback or an unbounded hang (#1033; #1094; #1021/5.0-14 covered only the
    --pr acquire path). Returns a CompletedProcess, so callers are untouched — a
    non-zero exit is the caller's to interpret, not a spawn error.

    #1576: a Popen with reader threads rather than `subprocess.run`, because the
    capture has to be BOUNDED and `capture_output=True` cannot be."""
    if timeout is None:
        timeout = _CHILD_TIMEOUTS.get(phase, _CHILD_TIMEOUT_DEFAULT)
    name = cmd[1] if len(cmd) > 1 else cmd[0]
    try:
        proc = subprocess.Popen(cmd, cwd=review_root, text=True,  # nosec B603
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=_child_env())
    except OSError as exc:
        raise runio.DriverError("%s: could not spawn %s: %s" % (phase, name, exc))
    out = {}
    readers = [threading.Thread(target=_capture, args=(pipe, out, key), daemon=True)
               for key, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr))]
    for reader in readers:
        reader.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        raise runio.DriverError("%s: %s timed out after %ss" % (phase, name, timeout))
    finally:
        # Bounded, and the readers are daemons: a grandchild that inherited the
        # pipes can hold them open past a kill aimed at the direct PID, and the
        # driver must not join on that for ever.
        for reader in readers:
            reader.join(timeout=_READER_JOIN_GRACE)
    return subprocess.CompletedProcess(cmd, proc.returncode,
                                       out.get("stdout", ""), out.get("stderr", ""))
