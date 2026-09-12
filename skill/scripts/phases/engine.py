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
    checkpoint: str = None        # a runio.CHECKPOINT_KINDS member, iff kind == "checkpoint"
    group: str = None
    dispatch_request: str = None  # absolute path (iff checkpoint)
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
    advanced = []
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
                    "advanced": advanced, "message": "all phases complete",
                    # The run is over, so no fan-out still needs write access.
                    # The guard is fail-closed while registered and its
                    # allowlist IS the complete set of permitted writes, so one
                    # left armed denies EVERY later Write/Edit in the session --
                    # the operator's included -- with only the hook's per-write
                    # reason to say why. Teardown was a host duty stated in
                    # prose (docs/PANOPTICON.md) that nothing signalled at the
                    # one moment it becomes unambiguously safe. Say it here, in
                    # the status the host already parses.
                    "teardown": TEARDOWN_DIRECTIVE}
        result = phase.execute(review_root, manifest)
        if result.kind == "checkpoint":
            return {"status": "checkpoint", "phase": phase.name,
                    "checkpoint": result.checkpoint, "group": result.group,
                    "dispatch_request": result.dispatch_request,
                    "advanced": advanced,
                    "message": result.message or ("%s checkpoint" % result.checkpoint)}
        if phase.name not in advanced:
            advanced.append(phase.name)
    raise RuntimeError(
        "driver engine exceeded %d steps without completing — a phase returned "
        "'advanced' without satisfying its done() predicate" % max_steps)

def emit_status(status, stream=None):
    """Print the status JSON and return the process exit code: 0 for
    checkpoint/complete, 1 for error. The CLI does `sys.exit(emit_status(...))`."""
    (stream or sys.stdout).write(json.dumps(status) + "\n")
    return 1 if status.get("status") == "error" else 0
