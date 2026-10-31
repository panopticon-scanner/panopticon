"""What an operator watching `driver loop` sees on stderr (#3232): a timestamp on every
line, phase lines, a heartbeat while a child runs, the repeat lines once, the summary.
Not `progress.py`, which is `run_tools --progress` (#1317), and off in the driver on purpose.

Installed by the `loop` verb alone (`stamped_call`), and every other entry here is a no-op
until then, so `driver run`, `driver persist` and an in-process caller are what they were.
Stderr only: stdout's status JSON and every artifact are not touched from here.

The memory is this process's. A resumed run is a new process, so it prints each repeat line
once more, which is right for whoever is now watching, and there is no state to go stale.
"""
import re
import subprocess
import sys
import threading
import time

from scripts.inert import INERT_ESCAPE_CODE_POINTS, spelled

HEARTBEAT_SECONDS = 60
SUMMARY_LINES_MAX = 400
SUMMARY_PREFIX = "summary: "

# The ONLY lines ever dropped, and only when the WHOLE text repeats, so a changed line always
# prints. Anything else passes every time, which is why no error or refusal may be listed here.
_ONCE_PER_PHASE = re.compile(r"driver: (?:host capabilities: |target ships )")
_ONCE_PER_RUN = re.compile(r"(?:semgrep: partial file coverage|ingest: excluded )")


def _stamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime())


class _Stamped:
    """`sys.stderr`, line-buffered, stamping each line and dropping the allowlisted repeats.
    A fault in here never costs output: the text goes to the real stream as it came."""

    def __init__(self, real):
        self.real = real
        self._lock = threading.RLock()     # reentrant: a signal handler can print mid-write
        self._pending = {}                 # per thread: `print` is two writes, text then newline
        self._mid_line = set()
        self._seen_phase = set()
        self._seen_run = set()

    def __getattr__(self, name):
        return getattr(self.real, name)    # fileno, isatty, encoding: subprocess and friends

    def _repeat(self, line):
        for pattern, seen in ((_ONCE_PER_PHASE, self._seen_phase), (_ONCE_PER_RUN, self._seen_run)):
            if pattern.match(line):
                if line in seen:
                    return True
                seen.add(line)
        return False

    def _render(self, line, thread):
        """`line` as it should appear, or None to drop it. A fault here sends it unstamped."""
        try:
            if thread in self._mid_line or not line:
                return line
            return None if self._repeat(line) else _stamp() + line
        except Exception:  # noqa: BLE001 -- never lose a line to the wrapper's own bookkeeping
            return line

    def write(self, text):
        thread = threading.get_ident()
        try:
            with self._lock:
                *lines, rest = (self._pending.pop(thread, "") + text).split("\n")
                if rest:
                    self._pending[thread] = rest
                for line in lines:
                    rendered = self._render(line, thread)
                    self._mid_line.discard(thread)
                    if rendered is not None:
                        self.real.write(rendered + "\n")
        except Exception:  # noqa: BLE001 -- if this raises too, it is what plain stderr would do
            self.real.write(text)
        return len(text)

    def _send_partial(self, thread):
        pending = self._pending.pop(thread, "")
        if pending:
            self.real.write(self._render(pending, thread) or pending)
            self._mid_line.add(thread)

    def flush(self):
        """This thread's partial line goes out now, and what it writes next continues it."""
        with self._lock:
            self._send_partial(threading.get_ident())
        self.real.flush()

    def drain(self):
        """Every thread's partial line, as the wrapper comes down."""
        with self._lock:
            for thread in list(self._pending):
                self._send_partial(thread)
        self.real.flush()

    def new_phase(self):
        with self._lock:
            self._seen_phase.clear()


class _Run:
    """The installed wrapper and the phase it is in."""

    def __init__(self, stream):
        self.stream = stream
        self.phase = None
        self.since = 0.0


_active = None


def stamped_call(enabled, call, *args):
    """`call(*args)` under the wrapper when `enabled`, always taking it down again: a partial
    line is flushed first, so a traceback printed after this returns is whole."""
    global _active
    if not enabled:
        return call(*args)
    stream = _Stamped(sys.stderr)
    sys.stderr, _active = stream, _Run(stream)
    try:
        return call(*args)
    finally:
        _active = None
        try:
            stream.drain()
        finally:
            if sys.stderr is stream:
                sys.stderr = stream.real


def phase(name):
    """Called as the engine picks a phase, and with None once none is left. Only a change prints,
    because a mixed phase is re-selected once per unit and a loop re-enters per checkpoint."""
    run = _active
    if run is None or name == run.phase:
        return
    if run.phase is not None:
        print("driver: phase %s finished (%d s)" % (run.phase, time.monotonic() - run.since),
              file=sys.stderr, flush=True)
    run.phase, run.since = name, time.monotonic()
    run.stream.new_phase()
    if name is not None:
        print("driver: phase %s started" % name, file=sys.stderr, flush=True)


def wait(proc, timeout, label):
    """`proc.wait(timeout=timeout)`, saying so every `HEARTBEAT_SECONDS` once installed. The same
    two ways out: `TimeoutExpired` at `timeout`, and whatever interrupts the wait passes through.
    The heartbeat shows the child is alive, not that it is getting anywhere."""
    if _active is None:
        return proc.wait(timeout=timeout)
    started = time.monotonic()
    while True:
        elapsed = time.monotonic() - started
        try:
            return proc.wait(timeout=min(HEARTBEAT_SECONDS, max(timeout - elapsed, 0)))
        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - started
            if elapsed >= timeout:
                raise
            print("driver: %s still running (%d s)" % (label, elapsed), file=sys.stderr, flush=True)


def _inert(line):
    return "".join(spelled(ord(ch)) if ord(ch) in INERT_ESCAPE_CODE_POINTS else ch for ch in line)


def relay_summary(text):
    """A child's captured summary, for the operator's terminal. It quotes finding titles and paths
    a reviewed repo can steer, so each line has its control characters spelled out and carries
    `SUMMARY_PREFIX`: a planted title can neither rewrite the terminal nor pass as a driver line."""
    if _active is None or not text:
        return
    lines = text.splitlines()
    for line in lines[:SUMMARY_LINES_MAX]:
        print(SUMMARY_PREFIX + _inert(line), file=sys.stderr)
    if len(lines) > SUMMARY_LINES_MAX:
        print("%s... %d more line(s) in the report" % (SUMMARY_PREFIX, len(lines) - SUMMARY_LINES_MAX),
              file=sys.stderr)
    sys.stderr.flush()
