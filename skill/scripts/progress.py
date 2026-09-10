#!/usr/bin/env python3
"""#1317: make a long tool scan legible while it is still running.

`run_tools` can sit inside a single `docker run` for the better part of an hour
and say nothing at all until it finishes. In a GitHub Actions log a scan that is
working and a scan that has hung produce the identical artifact -- no output --
so the only way to tell them apart is to wait for the timeout and see which one
arrives. That is the observability half of the fail-closed discipline: silence
must not be the only thing a healthy run and a dead one have in common.

Emission goes to STDERR, for two independent reasons:

* stdout is the RESULT. `run_tools.main` prints the produced artifact paths
  there, and a caller reading them must not first have to filter progress out.
* stderr is line-buffered even when it is a pipe rather than a terminal, and
  stdout is not. Measured here on 3.14.5, parent reading both pipes, child
  writing one line to each every 0.3s:

      t= 0.02s  stderr ERR 0        t= 0.92s  stdout OUT 0
      t= 0.32s  stderr ERR 1        t= 0.94s  stdout OUT 1
      t= 0.62s  stderr ERR 2        t= 0.94s  stdout OUT 2

  stderr arrived as it was written; stdout arrived in one gulp at exit. For a
  progress indicator that difference is the whole feature -- on stdout nothing
  would appear until the run was already over, which is precisely the condition
  #1317 exists to fix.

It is OPT-IN, and that is not timidity. `phases/tools.py` builds the driver's
tool-scan failure note from `proc.stderr[:300]`; unconditional progress would
fill that 300-character window with a header and three "started" lines and push
the actual error out of it -- trading a diagnostic the driver depends on for a
progress bar nobody is watching. So CI passes `--progress` and the driver does
not. Both halves of that split are pinned by tests in
`tests/test_run_tools_progress.py`, because it is exactly the kind of asymmetry
a later reader would "tidy up" without knowing what it was protecting.

Stdlib-only, like the rest of the runner.
"""
import os
import sys
import threading
import time

HEARTBEAT_SECONDS = 30
PREFIX = "panopticon:"


def _duration(seconds):
    if seconds < 60:
        return "%.1fs" % seconds
    minutes, secs = divmod(int(seconds), 60)
    return "%dm%02ds" % (minutes, secs)


def _size(path):
    """How big the artifact is -- a 200-byte SARIF and a 40MB one are very
    different results and the log should not make them look alike."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return "size unknown"
    if size < 1024:
        return "%d B" % size
    value = float(size)
    for unit in ("KB", "MB", "GB"):
        value /= 1024.0
        if value < 1024 or unit == "GB":
            return "%.1f %s" % (value, unit)


class _NullStep:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def finish(self, produced_path):
        return produced_path


class NullProgress:
    """The default, and the reason no caller needs an `if progress:` guard.

    A None-check at each of the five call sites is five chances to forget one;
    a null object cannot be forgotten. `enabled` is public so a caller that
    wants to skip building an expensive message can still ask.
    """

    enabled = False

    def header(self, target, total):
        pass

    def footer(self, produced, total):
        pass

    def note(self, message):
        pass

    def tool(self, tool, index, total):
        return _NullStep()


class StderrProgress:
    """One line per event, prefixed so it is greppable and never mistakable for
    a scanner's own output."""

    enabled = True

    def __init__(self, stream=None, clock=time.monotonic,
                 heartbeat=HEARTBEAT_SECONDS):
        self._stream = sys.stderr if stream is None else stream
        self._clock = clock
        self._heartbeat = heartbeat
        self._lock = threading.Lock()
        self._started = None

    def _emit(self, message):
        line = "%s %s\n" % (PREFIX, message)
        with self._lock:
            # One write per line, under a lock: the heartbeat runs on its own
            # thread and two half-lines interleaved would be worse than no
            # progress at all.
            try:
                self._stream.write(line)
                self._stream.flush()
            except (ValueError, OSError):
                # A closed or broken stream is never a reason to fail a scan.
                # Progress is commentary; the artifacts are the product.
                pass

    def header(self, target, total):
        self._started = self._clock()
        self._emit("scanning %s with %d tool%s"
                   % (target, total, "" if total == 1 else "s"))

    def footer(self, produced, total):
        elapsed = ("" if self._started is None
                   else " in " + _duration(self._clock() - self._started))
        self._emit("%d/%d tools produced output%s" % (produced, total, elapsed))

    def note(self, message):
        self._emit(message)

    def tool(self, tool, index, total):
        return _Step(self, tool, index, total)


class _Step:
    """One tool's slice of the run: a start line, a heartbeat while it works,
    and an outcome line naming what it produced."""

    def __init__(self, progress, tool, index, total):
        self._progress = progress
        self._tool = tool
        self._tag = "[%d/%d]" % (index, total)
        self._stop = threading.Event()
        self._thread = None
        self._t0 = None
        self._produced = None

    def __enter__(self):
        self._t0 = self._progress._clock()
        self._progress._emit("%s %s started" % (self._tag, self._tool))
        if self._progress._heartbeat:
            self._thread = threading.Thread(target=self._beat, daemon=True)
            self._thread.start()
        return self

    def _beat(self):
        # A tool with a 900s timeout that prints nothing for 900s is the case
        # this exists for: without a heartbeat the log cannot distinguish it
        # from a hang. Daemon thread, so a crash in the runner can never leave
        # the process waiting on progress output.
        while not self._stop.wait(self._progress._heartbeat):
            self._progress._emit(
                "%s %s still running after %s"
                % (self._tag, self._tool,
                   _duration(self._progress._clock() - self._t0)))

    def finish(self, produced_path):
        """Record the outcome. Returns its argument so a caller can write
        `done = step.finish(_capture_run(...))` in one line."""
        self._produced = produced_path
        return produced_path

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        elapsed = _duration(self._progress._clock() - self._t0)
        if self._produced:
            self._progress._emit("%s %s ok in %s (%s)"
                                 % (self._tag, self._tool, elapsed,
                                    _size(self._produced)))
        else:
            # NOT "done". A selected tool that produced nothing is the #1051
            # fail-closed case, and the log should say so in the same words the
            # manifest will.
            self._progress._emit("%s %s NO OUTPUT after %s"
                                 % (self._tag, self._tool, elapsed))
        return False


def make_progress(enabled, **kwargs):
    """The one constructor callers use, so `--progress` maps to a single call."""
    return StderrProgress(**kwargs) if enabled else NullProgress()
