"""group_runner: resume + coverage primitives for capacity-bound fan-out.

The fan-out phase dispatches each dispatch-plan entry so it writes its own
findings file; this module answers "which entries still need running?" (resume)
and "what did the run actually cover?" (derived at synthesis from the plan and
the files on disk). No agent return is trusted — disk is the truth.
"""
import json
import os

__all__ = ["entry_is_done", "pending_entries"]


def entry_is_done(out_file):
    """True iff out_file exists and parses as a findings file.

    A findings file is a JSON object with a `findings` list (the same shape
    synthesize.load_findings accepts). A missing, truncated, or malformed file
    is NOT done — it is re-run on resume.
    """
    if not out_file or not os.path.isfile(out_file):
        return False
    try:
        with open(out_file, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return False
    return isinstance(data, dict) and isinstance(data.get("findings"), list)


def pending_entries(plan):
    """The plan entries whose out_file is not yet done (the resume set)."""
    return [e for e in plan if not entry_is_done(e.get("out_file"))]
