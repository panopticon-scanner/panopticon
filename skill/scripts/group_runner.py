"""group_runner: resume + coverage primitives for capacity-bound fan-out.

The fan-out phase dispatches each dispatch-plan entry so it writes its own
findings file; this module answers "which entries still need running?" (resume)
and "what did the run actually cover?" (derived at synthesis from the plan and
the files on disk). No agent return is trusted — disk is the truth.
"""
import json
import os
import re

import scripts.evidence as evidence

__all__ = ["entry_is_done", "pending_entries", "fan_out_coverage",
           "verdict_is_done", "pending_verdicts", "resume_stats"]


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
    """The plan entries whose out_file is not yet done (the resume set).

    Non-dict entries in a corrupt plan are skipped, not fatal — tolerant by
    design: a malformed dispatch plan must never abort a run.
    """
    return [e for e in plan
            if isinstance(e, dict) and not entry_is_done(e.get("out_file"))]


_OUTFILE_RE = re.compile(
    r"^findings-(?P<group>.+)-(?P<panel>code|test|security|architecture|database|redteam)-")


def _group_panel(entry):
    if not isinstance(entry, dict):
        return None, None
    group, panel = entry.get("group"), entry.get("panel")
    if group and panel:
        return group, panel
    m = _OUTFILE_RE.match(os.path.basename(entry.get("out_file", "")))
    return (m.group("group"), m.group("panel")) if m else (None, None)


def fan_out_coverage(plan):
    """Planned-vs-executed coverage, derived from the plan and disk state.

    'executed' counts entries whose out_file is done (entry_is_done); a group is
    complete when every one of its entries ran, partial when some did not. This
    is the disclosure axis that makes a truncated run visible instead of
    silently biased toward 'no findings'.
    """
    planned, executed = {}, {}
    by_group = {}
    for e in plan:
        group, panel = _group_panel(e)
        if group is None or panel is None:
            continue
        planned[panel] = planned.get(panel, 0) + 1
        done = entry_is_done(e.get("out_file"))
        if done:
            executed[panel] = executed.get(panel, 0) + 1
        st = by_group.setdefault(group, {"total": 0, "done": 0})
        st["total"] += 1
        st["done"] += 1 if done else 0
    complete = sorted(g for g, s in by_group.items() if s["done"] == s["total"])
    partial = sorted(g for g, s in by_group.items() if 0 <= s["done"] < s["total"])
    return {"planned": planned, "executed": executed,
            "groups_complete": complete, "groups_partial": partial}


def verdict_is_done(queue_id, verdicts_dir):
    """True iff a VALID verdict for queue_id exists — consistent with
    evidence.load_verdicts (a dict whose `verdict` value is in VERDICT_VALUES,
    parsed tolerantly). Missing / truncated / invalid-verdict files are NOT done."""
    return bool(queue_id) and queue_id in evidence.load_verdicts(verdicts_dir)


def pending_verdicts(queue, verdicts_dir):
    """The verify-queue entries whose queue_id has no valid verdict yet — the
    verify resume set. `queue` is the verify-queue dict ({'entries': [...]}) or
    None; non-dict entries are skipped, not fatal."""
    done = evidence.load_verdicts(verdicts_dir)
    entries = queue.get("entries") or [] if isinstance(queue, dict) else []
    return [e for e in entries
            if isinstance(e, dict) and e.get("queue_id") not in done]


def resume_stats(plan, queue, verdicts_dir):
    """Done/pending/total for both phases, for honest resume disclosure.

    fan_out.total counts the dict entries pending_entries walks; verify.total
    counts the queue's dict entries; done = total - pending. Tolerant of
    None/empty/malformed plan or queue (-> zeros)."""
    plan = plan if isinstance(plan, list) else []
    fo_total = len([e for e in plan if isinstance(e, dict)])
    fo_pending = len(pending_entries(plan))
    entries = queue.get("entries") or [] if isinstance(queue, dict) else []
    v_total = len([e for e in entries if isinstance(e, dict)])
    v_pending = len(pending_verdicts(queue, verdicts_dir))
    return {"fan_out": {"total": fo_total, "done": fo_total - fo_pending,
                        "pending": fo_pending},
            "verify": {"total": v_total, "done": v_total - v_pending,
                       "pending": v_pending}}
