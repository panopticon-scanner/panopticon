"""What an operator watching `driver loop` sees on stderr (#3232): a timestamp on every
line, phase lines, a heartbeat while a child runs, the repeat lines once, the summary.
Not `progress.py`, which is `run_tools --progress` (#1317), and off in the driver on purpose.

Installed by the `loop` verb alone (`stamped_call`), and every other entry here is a no-op
until then, so `driver run`, `driver persist` and an in-process caller are what they were.
Stderr only: stdout's status JSON and every artifact are not touched from here.

#2108: `--progress` (on `driver run` and `driver loop`, off by default) adds the
`driver: progress: ` lines -- phases found already complete, checkpoint sizes, each settled
entry's ok/failed count, a heartbeat while a batch waits, per-phase and terminal totals -- and
under `run` installs this same wrapper. They carry static phase names, checkpoint kinds, status
words and integers only, never an entry id, a path or a message.

The memory is this process's. A resumed run is a new process, so it prints each repeat line
once more, which is right for whoever is now watching, and there is no state to go stale.
"""
import contextlib
import json
import re
import subprocess
import sys
import threading
import time

from scripts.inert import INERT_ESCAPE_CODE_POINTS, spelled

HEARTBEAT_SECONDS = 60
PROGRESS_PREFIX = "driver: progress: "
# #2108: the batch heartbeat thread and the main thread write, and update the tallies, under this.
_PROGRESS_LOCK = threading.Lock()
_STATUS_WORDS = ("complete", "checkpoint", "paused", "error")
SUMMARY_LINES_MAX = 400
SUMMARY_PREFIX = "summary: "

# The ONLY lines ever dropped, and only when the WHOLE text repeats, so a changed line always
# prints. Anything else passes every time, which is why no error or refusal may be listed here.
_ONCE_PER_PHASE = re.compile(r"driver: (?:host capabilities: |target ships )")
# #3228: scanner coverage facts are derived at several ingest sites in one run;
# changed counts still print, but an identical diagnostic should appear once.
_ONCE_PER_RUN = re.compile(
    r"(?:(?:semgrep|eslint-security): partial file coverage|ingest: excluded )")


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
    """The installed wrapper and the phase it is in; with `progress`, this process's tallies."""

    def __init__(self, stream, progress=False):
        self.stream = stream
        self.phase = None
        self.since = 0.0
        self.progress = progress
        self.first_pass_seen = False
        self.units = {}         # phase -> times executed in this process
        self.entries = {}       # phase -> [ok, failed] settled in this process
        self.total = [0, 0]


_active = None


def stamped_call(enabled, call, *args, progress=False):
    """`call(*args)` under the wrapper when `enabled`, always taking it down again: a partial
    line is flushed first, so a traceback printed after this returns is whole. `progress` adds
    the #2108 lines."""
    global _active
    if not enabled:
        return call(*args)
    stream = _Stamped(sys.stderr)
    sys.stderr, _active = stream, _Run(stream, progress)
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
        if run.progress:
            with _PROGRESS_LOCK:
                units = run.units.get(run.phase, 0)
                ok, failed = run.entries.get(run.phase, (0, 0))
                _emit("phase %s complete: %d unit(s), no entries" % (run.phase, units)
                      if ok + failed == 0 else
                      "phase %s complete: %d unit(s), %d entries (%d ok, %d failed)"
                      % (run.phase, units, ok + failed, ok, failed))
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


def _progress_run():
    run = _active
    return run if run is not None and run.progress else None


def _emit(text):
    """One whole `driver: progress: ` line, flushed. The caller holds `_PROGRESS_LOCK`."""
    sys.stderr.write(PROGRESS_PREFIX + text + "\n")
    sys.stderr.flush()


def first_pass(done_names):
    """G1: the phases this process's FIRST engine pass found already done -- resumed, or finished
    by an earlier invocation. Later passes (a loop re-entering after a checkpoint) say nothing."""
    run = _progress_run()
    if run is None:
        return
    with _PROGRESS_LOCK:
        if run.first_pass_seen:
            return
        run.first_pass_seen = True
        for name in done_names:
            _emit("phase %s already complete" % name)


def unit(name):
    """One execution of `name`'s phase in this process."""
    run = _progress_run()
    if run is not None:
        with _PROGRESS_LOCK:
            run.units[name] = run.units.get(name, 0) + 1


def checkpoint(name, kind, request_path):
    """G2: how many of the request's entries are left, and how many an earlier run settled.
    Counts only: the entries are read for their number and their out_file state, never printed."""
    run = _progress_run()
    if run is None:
        return
    counts = ""
    try:
        from scripts.phases import persist
        with open(request_path, encoding="utf-8") as fh:
            entries = [e for e in json.load(fh).get("entries") or [] if isinstance(e, dict)]
        left = sum(1 for e in entries if not persist.is_done(e))
        counts = ": %d to dispatch, %d already settled earlier" % (left, len(entries) - left)
    except Exception:  # noqa: BLE001 -- a count we cannot take is left out, never guessed
        pass
    with _PROGRESS_LOCK:
        _emit("phase %s checkpoint %s%s" % (name, kind, counts))


def terminal(status):
    """G6: the status this process ends on, and the entries it settled."""
    run = _progress_run()
    if run is None:
        return
    word = status if status in _STATUS_WORDS else "other"
    with _PROGRESS_LOCK:
        ok, failed = run.total
        _emit("run %s: %d entries this process (%d ok, %d failed)" % (word, ok + failed, ok, failed))


class _Batch:
    """G3 and G4 for one batch: a line per settled entry, and a heartbeat thread that speaks
    only when nothing has settled for `HEARTBEAT_SECONDS`."""

    def __init__(self, run, total, clock):
        self.run, self.total, self.clock = run, total, clock
        self.settled_count = self.ok = self.failed = 0
        self.last = clock()
        self.stop = threading.Event()

    def settled(self, ok):
        with _PROGRESS_LOCK:
            self.settled_count += 1
            self.ok, self.failed = self.ok + bool(ok), self.failed + (not ok)
            self.last = self.clock()
            tally = self.run.entries.setdefault(self.run.phase, [0, 0])
            tally[0 if ok else 1] += 1
            self.run.total[0 if ok else 1] += 1
            _emit("batch %d/%d settled: %d ok, %d failed"
                  % (self.settled_count, self.total, self.ok, self.failed))

    def tick(self):
        """One heartbeat check; the thread calls it every `HEARTBEAT_SECONDS`."""
        with _PROGRESS_LOCK:
            since = self.clock() - self.last
            if since >= HEARTBEAT_SECONDS and self.settled_count < self.total:
                _emit("batch %d/%d settled, %d still to settle, %d s since the last"
                      % (self.settled_count, self.total, self.total - self.settled_count, since))

    def beat(self):
        while not self.stop.wait(HEARTBEAT_SECONDS):
            self.tick()


class _NoBatch:
    def settled(self, ok):
        pass


@contextlib.contextmanager
def batch(total, clock=time.monotonic):
    """`with batch(n) as b: ... b.settled(ok)` around one batch. The heartbeat thread is stopped
    and joined however the block ends -- an exception, an interrupt, an abandoned generator."""
    run = _progress_run()
    if run is None:
        yield _NoBatch()
        return
    watch = _Batch(run, total, clock)
    thread = threading.Thread(target=watch.beat, name="driver-progress-heartbeat", daemon=True)
    thread.start()
    try:
        yield watch
    finally:
        watch.stop.set()
        thread.join()
