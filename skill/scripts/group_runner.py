"""group_runner: resume + coverage primitives for capacity-bound fan-out.

The fan-out phase dispatches each dispatch-plan entry so it writes its own
findings file; this module answers "which entries still need running?" (resume)
and "what did the run actually cover?" (derived at synthesis from the plan and
the files on disk). No agent return is trusted — disk is the truth.
"""
import hashlib
import json
import os
import re

import scripts.evidence as evidence

__all__ = ["entry_is_done", "pending_entries", "fan_out_coverage",
           "verdict_is_done", "pending_verdicts", "resume_stats",
           "verify_plan_entries"]


def entry_is_done(out_file, entry=None):
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
    if not (isinstance(data, dict) and isinstance(data.get("findings"), list)):
        return False
    expected_run = entry.get("run_id") if isinstance(entry, dict) else None
    if expected_run:
        meta = data.get("_panopticon")
        if not isinstance(meta, dict) or meta.get("run_id") != expected_run:
            return False
        for key in ("role", "panel", "lens", "group"):
            if meta.get(key) != entry.get(key):
                return False
    return True


def pending_entries(plan):
    """The plan entries whose out_file is not yet done (the resume set).

    Non-dict entries in a corrupt plan are skipped, not fatal — tolerant by
    design: a malformed dispatch plan must never abort a run.
    """
    return [e for e in plan
            if isinstance(e, dict) and not entry_is_done(e.get("out_file"), e)]


_OUTFILE_RE = re.compile(
    r"^findings-(?P<group>.+)-(?P<panel>%s)-" % "|".join(evidence.PANELS))


def _group_panel(entry):
    if not isinstance(entry, dict):
        return None, None
    # The 5.1 driver's plan entries carry `group` + `domain` (the review axis is
    # the domain, one cell per (group, domain)); the 4.x panel-review entries
    # carried `group` + `panel`. Accept either so fan_out_coverage sees driver
    # cells -- without this the driver's whole plan fell through to the regex
    # below, which only matches the 4.x `findings-<group>-<panel>-...` shape (a
    # panel name + trailing segment), never the driver's `findings-<group>-
    # <domain>.json`, so meta.coverage.fan_out.planned/executed came back {} on
    # every 5.1 run (#run7).
    group = entry.get("group")
    panel = entry.get("panel") or entry.get("domain")
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
        done = entry_is_done(e.get("out_file"), e)
        if done:
            executed[panel] = executed.get(panel, 0) + 1
        st = by_group.setdefault(group, {"total": 0, "done": 0})
        st["total"] += 1
        st["done"] += 1 if done else 0
    complete = sorted(g for g, s in by_group.items() if s["done"] == s["total"])
    partial = sorted(g for g, s in by_group.items() if 0 <= s["done"] < s["total"])
    return {"planned": planned, "executed": executed,
            "groups_complete": complete, "groups_partial": partial}


def _queue_entries(queue):
    """The verify queue's entries list, or [] for a None/non-dict queue or a
    non-list `entries` value — a malformed queue never raises."""
    if not isinstance(queue, dict):
        return []
    entries = queue.get("entries")
    return entries if isinstance(entries, list) else []


def verdict_is_done(queue_id, verdicts_dir, finding_id=None, run_id=None,
                    _done=None):
    """True iff a VALID verdict for queue_id exists — consistent with
    evidence.load_verdicts (a dict whose `verdict` value is in VERDICT_VALUES,
    parsed tolerantly). Missing / truncated / invalid-verdict files are NOT done.

    Pass a pre-loaded verdicts dict as `_done` to avoid re-reading the directory
    on every call when used in a loop."""
    if _done is None:
        _done = evidence.load_verdicts(verdicts_dir)
    if not queue_id or queue_id not in _done:
        return False
    if finding_id is None:
        finding_matches = True
    else:
        finding_matches = str(_done[queue_id].get("finding_id")) == str(finding_id)
    run_matches = run_id is None or _done[queue_id].get("run_id") == run_id
    return finding_matches and run_matches


def pending_verdicts(queue, verdicts_dir, _verdicts=None):
    """The verify-queue entries whose queue_id has no valid verdict yet — the
    verify resume set. `queue` is the verify-queue dict ({'entries': [...]}) or
    None; non-dict entries and entries without a non-empty queue_id are skipped.
    Pass a pre-loaded verdicts dict as `_verdicts` to skip re-reading the
    directory a caller already loaded (same convention as verdict_is_done)."""
    done = _verdicts if _verdicts is not None else evidence.load_verdicts(verdicts_dir)
    entries = _queue_entries(queue)
    run_id = queue.get("run_id") if isinstance(queue, dict) else None
    return [e for e in entries
            if isinstance(e, dict) and e.get("queue_id") and
            not verdict_is_done(
                e["queue_id"], None, (e.get("finding") or {}).get("id"),
                run_id,
                _done=done)]


def resume_stats(plan, queue, verdicts_dir, _verdicts=None):
    """Done/pending/total for both phases, for honest resume disclosure.

    fan_out.total counts the dict entries pending_entries walks; verify.total
    counts only queue dict entries with a non-empty queue_id (matching the
    actionable resume set); done = total - pending. Tolerant of
    None/empty/malformed plan or queue (-> zeros). `_verdicts` threads a
    pre-loaded verdicts dict through to pending_verdicts."""
    plan = plan if isinstance(plan, list) else []
    fo_total = len([e for e in plan if isinstance(e, dict)])
    fo_pending = len(pending_entries(plan))
    entries = _queue_entries(queue)
    v_total = len([e for e in entries if isinstance(e, dict) and e.get("queue_id")])
    v_pending = len(pending_verdicts(queue, verdicts_dir, _verdicts=_verdicts))
    return {"fan_out": {"total": fo_total, "done": fo_total - fo_pending,
                        "pending": fo_pending},
            "verify": {"total": v_total, "done": v_total - v_pending,
                       "pending": v_pending}}


def _sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def snapshot_out_files(plan, out_path=None):
    """#493 R4: record a sha256 per existing plan out_file at fan-out end.

    The write-guard PREVENTS out-of-scope writes on enforced hosts; this is
    the after-the-fact DETECTION layer for content substituted inside a
    legitimately-declared out_file (which set-based reconcile cannot see).
    The orchestrator calls this right after fan-out completes; synthesize
    verifies the ingested bytes still match. Returns the {realpath: sha256}
    mapping; writes it to out_path (default .panopticon/out-file-hashes.json)
    when given a plan with any existing out_file.
    """
    hashes = {}
    for e in plan or []:
        if not isinstance(e, dict):
            continue
        path = e.get("out_file")
        if not isinstance(path, str) or not path or not os.path.isfile(path):
            continue
        digest = _sha256_file(path)
        hashes[os.path.realpath(path)] = digest
    if out_path is None:
        out_path = os.path.join(".panopticon", "out-file-hashes.json")
    if hashes:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(hashes, fh, indent=1, sort_keys=True)
    return hashes


def verify_out_file_hashes(ingested_paths, hashes_path=None):
    """Compare ingested findings files against the fan-out-time snapshot.

    Returns ``(checked, mismatched, snapshot_unreadable)``:
      - ``mismatched`` lists the ORIGINAL path strings whose current bytes no
        longer hash to the recorded value.
      - ``snapshot_unreadable`` is True when the snapshot file EXISTS but cannot
        be read as a non-empty dict. #run7 #1208: snapshot_out_files only writes
        the file when it has entries, so a present-but-corrupt/empty file is NOT a
        legitimate "no snapshot" -- it is a detected tamper/corruption and must
        FAIL the gate, not silently read as ``(None, [])`` (an attacker who
        substitutes a findings file could otherwise also truncate the snapshot to
        erase the evidence, and integrity stayed green).
      - ``(None, [], False)`` when the file is genuinely ABSENT -- an ordinary
        non-fan-out run.
    """
    if hashes_path is None:
        hashes_path = os.path.join(".panopticon", "out-file-hashes.json")
    if not os.path.isfile(hashes_path):
        return None, [], False               # genuinely absent -> no snapshot
    try:
        with open(hashes_path, encoding="utf-8") as fh:
            recorded = json.load(fh)
    except (OSError, ValueError):
        return None, [], True                # present but unreadable -> tamper
    if not isinstance(recorded, dict) or not recorded:
        return None, [], True                # present but malformed/empty -> tamper
    checked = 0
    mismatched = []
    for p in ingested_paths or []:
        rp = os.path.realpath(str(p))
        if rp not in recorded:
            continue
        checked += 1
        try:
            digest = _sha256_file(p)
        except OSError:
            mismatched.append(str(p))
            continue
        if digest != recorded[rp]:
            mismatched.append(str(p))
    return checked, sorted(mismatched), False


def verify_plan_entries(plan, host=None, agents_dir=None):
    """Re-verify pending reviewer entries against live registration.

    The emission-time enforcement flag cannot see an on-disk edit made AFTER
    emission (an enforced:true -> false flip or lost registration). Before
    fan-out, call dispatch.verify_plan on the non-codex subset of pending
    entries so a removed registration is caught (#1087).
    """
    import scripts.dispatch as dispatch
    entries = pending_entries(plan)
    reviewer = [
        e for e in entries
        if isinstance(e, dict) and e.get("execution") != "codex_exec"
    ]
    if not reviewer:
        return []
    return dispatch.verify_plan(reviewer, host=host, agents_dir=agents_dir)
