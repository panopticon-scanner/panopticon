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
import time

import scripts.phases.runio as runio
import scripts.procgroup as procgroup


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
#
# CHARS, not bytes (R1-3). The streams are decoded (`text=True`) because callers
# want `str` and because a diagnostic is only readable decoded, so the ceiling
# counts characters: the same 1,048,576 is 1 MiB of ASCII, 2 MiB of U+00E9 and
# 4 MiB of astral characters in memory. The name says which one it is.
CAPTURE_CHARS_MAX = 1 * 1024 * 1024
CAPTURE_LINES_MAX = 20000
# One read. `readline(n)` returns at the first newline OR after n characters,
# whichever comes first -- NOT `read(n)`, which returns only once it has the
# whole n or EOF. That distinction is the whole of R1-2: a child that writes a
# diagnostic and exits leaves a worker holding the write end of the pipe, EOF
# never arrives, and a `read(n)` reader sits inside one call with the
# diagnostic already in its hands and no way to publish it.
_CAPTURE_CHUNK = 65536
# How long `_run_child` waits for its reader threads after the child is gone --
# ONE deadline for both of them, not one each.
_READER_JOIN_GRACE = 5


class _Head:
    """A child stream's bounded head, readable WHILE it is still being filled.

    A reader thread can be cut off (joined out at `_READER_JOIN_GRACE` because a
    descendant still holds the pipe, so EOF never comes). Publishing only at the
    end of the drain therefore publishes nothing at all in exactly the case
    where the child's own account of why it died is the only evidence there is.
    So the head is live: the reader appends to `parts` and `_run_child` renders
    whatever is there when it asks.

    `parts` is appended to by one thread and joined by another. Under CPython
    both are atomic, and the only race is whether the very last line read makes
    it into a render happening at that instant -- harmless, and strictly better
    than the empty string this replaces.
    """

    def __init__(self):
        self.parts = []
        self.chars = self.lines = self.cut = 0
        self.complete = False

    def text(self):
        """What was kept, plus a marker for anything the reader did not keep.

        Both facts are recorded, because they are different: `cut` is output the
        CEILING dropped, `complete` is whether the stream was read to its end. A
        truncated diagnostic must never read as a whole one either way."""
        kept = "".join(self.parts)
        note = ""
        if self.cut:
            note += "\n\u2026 [cut %d characters]" % self.cut
        if not self.complete and kept:
            # An EMPTY cut-off stream renders as nothing: the `(stderr or stdout)`
            # readers must fall through to the stream that has the diagnostic.
            note += "\n\u2026 [reader cut off: the stream never reached EOF]"
        return kept + note


def _capture(stream, head):
    """Drain `stream` to EOF, keeping its bounded head in `head` as it arrives.

    The ceilings count CHARACTERS off a decoded stream, not bytes off the wire.
    `CAPTURE_CHARS_MAX` characters cost 1 MiB of memory for ASCII, 2 MiB for
    Latin-1 range text and at most **4 MiB** for astral characters -- that 4 MiB
    is the worst case to budget against, not the constant itself."""
    try:
        while True:
            chunk = stream.readline(_CAPTURE_CHUNK)
            if not chunk:
                head.complete = True
                return
            room = CAPTURE_LINES_MAX - head.lines
            take = chunk[:max(0, CAPTURE_CHARS_MAX - head.chars)] if room > 0 else ""
            if take.count("\n") > room:
                take = "".join(part + "\n" for part in take.split("\n")[:room])
            if take:                       # nothing kept means nothing appended
                head.parts.append(take)
            head.chars += len(take)
            head.lines += take.count("\n")
            head.cut += len(chunk) - len(take)
    finally:
        # Whatever happens -- EOF, a decode error, the interpreter tearing the
        # thread down -- the pipe is released. The head needs no publishing
        # step here: it has been live since before this thread started.
        try:
            stream.close()
        except OSError:                    # pragma: no cover - already closed
            pass

# #1575 (OPS-A1A): the group kill itself lives in `scripts.procgroup`, which
# `runners/children.py` calls too -- ONE kill path for every child this repo
# spawns, rather than a group kill here and a handle kill there. Its
# `KILL_GRACE` is the constant this module used to hold, moved unchanged.

def _run_child(cmd, review_root, phase, timeout=None):
    """Run a deterministic phase's child, converting a spawn-level OSError
    (ENOENT on the interpreter, EMFILE, a bad cwd, ...) or a phase timeout into a
    DriverError so run()'s handler yields a clean status:error instead of a raw
    traceback or an unbounded hang (#1033; #1094; #1021/5.0-14 covered only the
    --pr acquire path). Returns a CompletedProcess, so callers are untouched — a
    non-zero exit is the caller's to interpret, not a spawn error.

    #1576: a Popen with reader threads rather than `subprocess.run`, because the
    capture has to be BOUNDED and `capture_output=True` cannot be. #1575: in its
    own session, so the timeout can reach the whole tree (`procgroup`).

    A descendant that outlives the child (or escaped its process group) is
    deliberately LEFT once the readers' shared join grace expires: the child
    itself has already been reaped, so there is no group left to signal, and
    the driver must not stall on a pipe it cannot close. Its output past that
    point is lost and the head says so.
    """
    if timeout is None:
        timeout = _CHILD_TIMEOUTS.get(phase, _CHILD_TIMEOUT_DEFAULT)
    name = cmd[1] if len(cmd) > 1 else cmd[0]
    try:
        proc = subprocess.Popen(cmd, cwd=review_root, text=True,  # nosec B603
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=_child_env(), start_new_session=True)
    except OSError as exc:
        raise runio.DriverError("%s: could not spawn %s: %s" % (phase, name, exc))
    out = {"stdout": _Head(), "stderr": _Head()}
    readers = [threading.Thread(target=_capture, args=(pipe, out[key]), daemon=True)
               for key, pipe in (("stdout", proc.stdout), ("stderr", proc.stderr))]
    for reader in readers:
        reader.start()
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        procgroup.kill_group(proc)     # #1575: the whole tree, not the direct PID
        raise runio.DriverError("%s: %s timed out after %ss" % (phase, name, timeout))
    finally:
        # ONE deadline across both readers, and the readers are daemons.
        # `kill_group` ends everything that inherited the pipes, so EOF normally
        # arrives at once -- but a descendant that escaped its group (or simply
        # outlived a child that exited on its own) must not be able to make the
        # driver wait `_READER_JOIN_GRACE` once per stream, which is the 10 s
        # stall R1-2 measured. Whatever each reader has kept by then is already
        # published; the grace buys the tail, never the head.
        deadline = time.monotonic() + _READER_JOIN_GRACE
        for reader in readers:
            reader.join(timeout=max(0.0, deadline - time.monotonic()))
    return subprocess.CompletedProcess(cmd, proc.returncode,
                                       out["stdout"].text(), out["stderr"].text())
