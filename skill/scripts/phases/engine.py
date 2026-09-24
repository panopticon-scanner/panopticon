"""The phase state machine: Phase, PhaseResult, run_engine."""
import dataclasses
import json
import sys


@dataclasses.dataclass(frozen=True)
class Phase:
    name: str
    kind: str        # "deterministic" | "checkpoint" | "mixed"
    done: object     # callable(review_root, manifest) -> bool
    execute: object  # callable(review_root, manifest) -> PhaseResult

_PHASE_RESULT_KINDS = ("advanced", "checkpoint")


class EngineStalled(RuntimeError):
    """A phase returned "advanced" without ever satisfying its done predicate.

    A RuntimeError subclass, so every existing `assertRaises(RuntimeError)`
    still binds, but NAMED -- `driver.run` converts exactly this into an
    `error` status (#1637 P08 F1b) rather than catching RuntimeError at large
    and turning an unrelated bug in a phase into a tidy-looking status line.
    The progress guard exists to stop a spin; letting it escape as a traceback
    meant the operator got no status JSON at all from the one failure mode
    that has already burned the whole run's wall clock."""

# Emitted with the terminal "complete" status: the call that disarms the
# write-guard once the run needs it no longer. Safe to run unconditionally --
# `uninstall` is a no-op when nothing is installed -- and it must run from the
# SESSION root, since hook registration is session-rooted (#calibration-4).
TEARDOWN_DIRECTIVE = (
    "write_guard_hook.uninstall(); read_guard_hook.uninstall()  "
    "# both from the SESSION root; safe if not armed")

@dataclasses.dataclass
class PhaseResult:
    kind: str                     # "advanced" | "checkpoint"
    checkpoint: str | None = None  # a runio.CHECKPOINT_KINDS member, iff kind == "checkpoint"
    group: str | None = None
    dispatch_request: str | None = None  # absolute path (iff checkpoint)
    # #1727: sha256 of the bytes `requests.write_dispatch_request_bound` just
    # wrote, carried IN PROCESS to the loop. The loop compares it against the
    # manifest's record before it reads a single entry -- two reads of the same
    # tamperable file would compare nothing.
    request_sha256: str | None = None
    message: str = ""

    def __post_init__(self):
        # #1033: reject an unknown kind loudly. run_engine treats anything that
        # isn't "checkpoint" as "advanced", so a typo ("advance") or a status
        # string ("complete"/"error") would be silently mishandled otherwise.
        if self.kind not in _PHASE_RESULT_KINDS:
            raise ValueError("unknown PhaseResult kind: %r" % self.kind)

def _first_not_done(phases, review_root, manifest):
    for phase in phases:
        if not phase.done(review_root, manifest):
            return phase
    return None

def run_engine(review_root, manifest, phases, max_steps=None):
    """Advance the state machine from disk. Repeatedly executes the first
    not-done phase until a checkpoint stops it or every phase is done. Returns a
    status dict; never exits (the CLI owns process exit).

    The cursor is recomputed every iteration, so a mixed phase that advances one
    unit at a time is simply re-selected until its done() is satisfied.
    """
    advanced: list[str] = []
    # Progress guard: a buggy phase that returns "advanced" but never satisfies
    # done() would spin forever. Cap the work and fail loudly. The bound is far
    # above any real (phase-count + group-count) unit total.
    if max_steps is None:
        max_steps = 10000
    for _ in range(max_steps):
        phase = _first_not_done(phases, review_root, manifest)
        if phase is None:
            return {"status": "complete", "phase": None, "checkpoint": None,
                    "group": None, "dispatch_request": None,
                    "request_sha256": None,
                    "advanced": advanced, "message": "all phases complete",
                    # The run is over, so no fan-out still needs write access.
                    # The guard is fail-closed while registered and its
                    # allowlist IS the complete set of permitted writes, so one
                    # left armed denies EVERY later Write/Edit in the session --
                    # the operator's included -- with only the hook's per-write
                    # reason to say why. Teardown was a host duty stated in
                    # prose (docs/guide/driver-run-loop.md) that nothing
                    # signalled at the
                    # one moment it becomes unambiguously safe. Say it here, in
                    # the status the host already parses.
                    "teardown": TEARDOWN_DIRECTIVE}
        result = phase.execute(review_root, manifest)
        if result.kind == "checkpoint":
            return {"status": "checkpoint", "phase": phase.name,
                    "checkpoint": result.checkpoint, "group": result.group,
                    "dispatch_request": result.dispatch_request,
                    "request_sha256": result.request_sha256,
                    "advanced": advanced,
                    "message": result.message or ("%s checkpoint" % result.checkpoint)}
        if phase.name not in advanced:
            advanced.append(phase.name)
    raise EngineStalled(
        "driver engine exceeded %d steps without completing — a phase returned "
        "'advanced' without satisfying its done() predicate" % max_steps)

def emit_status(status, stream=None):
    """Print the status JSON and return the process exit code: 0 for
    checkpoint/complete, 1 for error. The CLI does `sys.exit(emit_status(...))`.

    #1623: `paused` exits non-zero too. A host-wide outage stops the run with
    the review unfinished, and the one reading that CANNOT be allowed is a CI
    job going green over an empty review axis -- which is the failure the
    paused status exists to prevent, not one to re-introduce at the exit code.
    """
    (stream or sys.stdout).write(json.dumps(status) + "\n")
    return 1 if status.get("status") in ("error", "paused") else 0
