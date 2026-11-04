"""Execution and bounded output readers shared by tool adapters (#3406)."""
from __future__ import annotations
import collections
import subprocess
import sys
import threading

from .base import (MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_STDERR_BYTES,
                   OUTPUT_WATCH_INTERVAL, _drain, _kill_process_tree,
                   _output_size, _raise_if_output_capped, read_capped)


def drain_stderr_async(proc, cap=MAX_TOOL_STDERR_BYTES):
    """Drain ``proc.stderr`` to EOF on a daemon thread, retaining ``cap`` bytes.

    Both capture paths need this. A child that fills its stderr pipe (64 KB on
    Linux) blocks on write; a parent that reads stdout to EOF *first* is then
    waiting on stdout the blocked child cannot produce, and only the watchdog
    breaks the tie -- at the cost of the whole scan timeout plus that scanner's
    coverage (#1510 / Codex BR-05, and #K2-1 for the inner runner).

    Draining therefore starts at process start and CONTINUES PAST the retention
    cap: once we stop keeping bytes we must still read them, or the pipe backs
    up and the deadlock returns by another door.

    Retention keeps the TAIL. The buffer exists to diagnose "exited N", and a
    scanner puts its error message last; keeping the head would bound memory
    while discarding the only part worth printing. At least one chunk is always
    retained, so a single read larger than `cap` still yields diagnostics.

    Returns a ``join(timeout=2.0) -> bytes`` callable.
    """
    chunks: collections.deque[bytes] = collections.deque()
    kept = [0]

    def _pump():
        try:
            while True:
                chunk = proc.stderr.read(64 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                kept[0] += len(chunk)
                while kept[0] > cap and len(chunks) > 1:
                    kept[0] -= len(chunks.popleft())
        except Exception:
            pass

    thread = threading.Thread(target=_pump)
    thread.daemon = True
    thread.start()

    def join(timeout=2.0):
        thread.join(timeout)
        return b"".join(chunks)

    return join


class _OutputSizeWatcher(threading.Thread):
    """Poll a scanner's output path while it runs; kill it past `cap` (#1576).

    The bound the adapters needed and did not have: a write-time ceiling on a
    report the scanner writes for itself. Polled, so the real ceiling is `cap`
    plus one OUTPUT_WATCH_INTERVAL of the scanner's write throughput -- the
    guarantee is that it STOPS, not that it stops on the exact byte. It announces the kill on stderr as it
    happens -- the operator's only witness that a scan ended for this reason
    rather than any other -- and `run_tool` turns it into OutputCapExceeded.
    """

    def __init__(self, proc, path, cap, label):
        super().__init__(daemon=True)
        self._proc, self._path, self._cap, self._label = proc, path, cap, label
        self._done = threading.Event()
        self.exceeded = False
        self.size = 0

    def run(self):
        while not self._done.wait(OUTPUT_WATCH_INTERVAL):
            size = _output_size(self._path, stop=self._cap)
            if size <= self._cap:
                continue
            self.exceeded, self.size = True, size
            print("tool %s exceeded its write-time output cap: %d bytes at %s "
                  "(cap %d); killing it -- a report this large would be refused "
                  "at read time anyway" % (self._label, size, self._path, self._cap),
                  file=sys.stderr)
            _kill_process_tree(self._proc)
            return

    def stop(self):
        self._done.set()


def run_tool(cmd, timeout, ok_codes=(0, 1), capture_stderr=False,
             watch_path=None, watch_cap=MAX_TOOL_OUTPUT_BYTES, **kwargs):
    """Run a scanner subprocess, preserving failure diagnostics (F-CAL-1).

    Returns (stdout, returncode) by default, or (stdout, stderr, returncode)
    when *capture_stderr* is True. On exit codes outside ok_codes
    (1 == findings for most scanners; brakeman also uses 2/3), a capped
    stderr excerpt is written to our stderr so 'exited N; skipping' is
    diagnosable.

    Bounded capture: stdout is streamed into a bounded buffer so
    adversarial/large target output does not accumulate unbounded in memory
    (#1111). When the byte cap is exceeded the child is terminated, the output
    is truncated with a marker, and a stderr notice is emitted. The partial
    output is still returned so the truncation is visible downstream.

    Stderr is drained concurrently so a child that fills the stderr pipe while
    still writing stdout cannot deadlock the parent (#K2-1).

    `watch_path` (#1576) is for the adapters whose scanner writes its OWN
    report: the path is polled while the child runs and the child is killed at
    the first poll that finds it over `watch_cap`, raising OutputCapExceeded.
    Polling means the effective ceiling is `watch_cap` plus one
    OUTPUT_WATCH_INTERVAL of the scanner's write throughput, not `watch_cap`
    exactly.
    Pass `start_new_session=True` alongside it when the scanner is launched
    through a shell wrapper, so the kill reaches the worker and not just the
    wrapper."""
    popen_kwargs = dict(kwargs)
    popen_kwargs.setdefault("stdout", subprocess.PIPE)
    popen_kwargs.setdefault("stderr", subprocess.PIPE)

    timed_out = {"hit": False}

    def _watchdog():
        # #1576 fix round 1: the GROUP, not just the child. A scanner behind a
        # shell wrapper leaves the real worker as a grandchild holding the
        # inherited stdout pipe; killing the wrapper alone leaves the parent's
        # read blocked on a pipe the orphan still owns, and `timeout=` stops
        # being a bound -- measured at 15 s for a 1-second timeout. Without
        # start_new_session this is exactly proc.kill(), as before.
        timed_out["hit"] = True
        _kill_process_tree(proc)

    proc = subprocess.Popen(cmd, **popen_kwargs)  # nosec B603
    timer = threading.Timer(timeout, _watchdog)
    timer.daemon = True
    timer.start()

    watcher = None
    if watch_path is not None:
        watcher = _OutputSizeWatcher(proc, watch_path, watch_cap, cmd[0])
        watcher.start()

    join_stderr = drain_stderr_async(proc)

    try:
        if proc.stdout is None:
            # `popen_kwargs.setdefault("stdout", PIPE)` above makes this
            # unreachable unless a caller passes stdout=None explicitly. It
            # stays a raise rather than an assert because `python -O` strips
            # the assert, and the next line would be an AttributeError on
            # None instead of this sentence (#1533 review).
            raise RuntimeError("tool stdout must be captured with PIPE")
        chunks: list[bytes] = []
        truncated = read_capped(proc.stdout, MAX_TOOL_OUTPUT_BYTES, chunks)
        if truncated:
            _drain(proc.stdout)

        if truncated:
            _kill_process_tree(proc)      # the group, for the reason above
            stdout = b"".join(chunks)
            marker = (
                "\n\n[TRUNCATED by panopticon: output exceeded %d byte limit; "
                "only the first %d bytes were retained]\n" % (
                    MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_BYTES)
            ).encode("utf-8")
            print(
                "tool %s output exceeded %d byte limit; truncated and retained "
                "with marker" % (cmd[0], MAX_TOOL_OUTPUT_BYTES),
                file=sys.stderr,
            )

        rc = proc.wait()
        stderr = join_stderr()

        if truncated:
            # #1576 fix round 1: this early return sits inside the try, so it
            # used to leave the function BEFORE the write-time check below. An
            # adapter whose scanner blew BOTH caps got (partial output, -9) --
            # a partial result from a scan that was killed -- and its
            # `except OutputCapExceeded` never fired. The write-time cap
            # outranks the truncation: there is no usable report either way.
            _raise_if_output_capped(watcher, watch_path, watch_cap)
            if capture_stderr:
                return stdout + marker, stderr, rc
            return stdout + marker, rc
    except BaseException:                 # #2507: the tree FIRST -- the teardown
        if proc.poll() is None:           # below closes both pipes and waits on the
            _kill_process_tree(proc)      # drain, and a second stop in that window
        raise                             # would leave the container running
    finally:
        timer.cancel()
        if watcher is not None:
            watcher.stop()
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except Exception:
            pass
        # Closing stderr wakes the drain thread if it is still blocked.
        join_stderr(0.5)
        try:
            if proc.stderr is not None:
                proc.stderr.close()
        except Exception:
            pass
        if proc.poll() is None:
            _kill_process_tree(proc)      # the group, for the reason above

    # Checked BEFORE the timeout: when the watchdog and the size watcher both
    # fire, the cap is the specific truth and "timed out" is the consequence.
    _raise_if_output_capped(watcher, watch_path, watch_cap)

    if timed_out["hit"] and rc not in (0, 1):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)

    if rc not in ok_codes:
        excerpt = (stderr or b"")[-1000:].decode("utf-8", errors="replace").strip()
        details = f": {excerpt}" if excerpt else ""
        print(f"tool {cmd[0]} exited {rc}{details}", file=sys.stderr)

    if capture_stderr:
        return b"".join(chunks), stderr, rc
    return b"".join(chunks), rc


def read_capped_report(path, cap=MAX_TOOL_OUTPUT_BYTES):
    """Read a scanner's on-disk report under the same byte ceiling run_tool
    applies to stdout capture (#run8 OPS-D1A).

    Adapters whose scanner writes its report to a file (dependency-check JSON,
    roslyn SARIF) bypass run_tool's MAX_TOOL_OUTPUT_BYTES stdout cap entirely --
    an attacker-influenced report of arbitrary size (a build manifest crafted to
    emit a huge dependency/CVE set, a project that drives a scanner to a giant
    SARIF result set) would otherwise be slurped whole into memory. Reads one
    byte past the cap to detect the overflow, then FAILS CLOSED on an oversize
    report (returns None) instead of handing back a truncated, half-parsed blob.

    Returns the report bytes on success, or None when the file is missing,
    unreadable, or exceeds the cap -- the caller substitutes its own empty/
    failure result so downstream ingest sees "no output" rather than a partial
    one. Mirrors the on-disk cap ingest_tools.py already applies to *.sarif/*.json
    it is pointed at."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read(cap + 1)
    except OSError as exc:
        print("panopticon: cannot read report %s: %s" % (path, exc), file=sys.stderr)
        return None
    if len(raw) > cap:
        print("panopticon: report %s exceeds the %d-byte cap; refusing"
              % (path, cap), file=sys.stderr)
        return None
    return raw
