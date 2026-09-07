"""Helpers shared by the tests/phases/ modules (WS-0 D5).
"""
import scripts.phases.engine as engine


def _fake_phase(name, *, done_after=1, result_kind="advanced", checkpoint=None):
    """A fake phase backed by an execute counter (stands in for disk state).
    done() flips True once execute has run `done_after` times."""
    state = {"executes": 0}

    def done(root, manifest):
        return state["executes"] >= done_after

    def execute(root, manifest):
        state["executes"] += 1
        if result_kind == "checkpoint":
            return engine.PhaseResult(kind="checkpoint", checkpoint=checkpoint,
                                      group="G", dispatch_request="/abs/req.json",
                                      message="stop")
        return engine.PhaseResult(kind="advanced")

    return engine.Phase(name=name, kind="deterministic", done=done,
                        execute=execute), state
