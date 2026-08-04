#!/usr/bin/env python3
"""Apply remediation-triage dispositions from the triage ledger to GitHub.

The ledger (.panopticon/triage-ledger.jsonl) is written by the triage arc:
one JSON object per line, one line per issue. This tool only ever mutates
GitHub from rows whose status is "approved" (the user's batch gate), and
flips a row to "applied" only when every mutation for it succeeded.

Usage:  python3 scripts/triage.py setup
        python3 scripts/triage.py apply [--dry-run] [--throttle S]
"""
import argparse
import json
import os
import subprocess
import sys
import time

LEDGER = ".panopticon/triage-ledger.jsonl"
MILESTONE = "Remediation 1"
SPEC = "docs/superpowers/specs/2026-08-04-remediation-triage-design.md"
VERDICTS = ("fix", "duplicate", "already-fixed", "reject", "defer")
STATUSES = ("proposed", "approved", "applied", "stale")
# verdict -> (label, color, description)
LABELS = {
    "fix": ("triage:fix", "0e8a16",
            "Triage verdict: real, ranked into the fix queue"),
    "duplicate": ("triage:duplicate", "cfd3d7",
                  "Triage verdict: duplicate of a canonical issue"),
    "already-fixed": ("triage:already-fixed", "6f42c1",
                      "Triage verdict: fixed before triage reached it"),
    "reject": ("triage:rejected", "d93f0b",
               "Triage verdict: advisor rejection confirmed by spot-check"),
    "defer": ("triage:deferred", "fbca04",
              "Triage verdict: parked, out of this remediation arc"),
}
REQUIRED = ("issue", "set", "verdict", "rationale", "status", "batch",
            "triaged_at")


def load_rows(path=LEDGER):
    try:
        fh = open(path, encoding="utf-8")
    except OSError:
        return []
    rows = []
    with fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except ValueError as e:
                raise ValueError("ledger line %d unparseable: %s" % (n, e))
    return rows


def save_rows(rows, path=LEDGER):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    os.replace(tmp, path)


def validate(row):
    problems = []
    missing = [k for k in REQUIRED if k not in row]
    if missing:
        problems.append("missing: %s" % ", ".join(missing))
    if not isinstance(row.get("issue"), int):
        problems.append("issue must be an int")
    if row.get("verdict") not in VERDICTS:
        problems.append("unknown verdict %r" % row.get("verdict"))
    if row.get("status") not in STATUSES:
        problems.append("unknown status %r" % row.get("status"))
    if not str(row.get("rationale") or "").strip():
        problems.append("rationale required")
    v = row.get("verdict")
    if v == "fix" and not isinstance(row.get("rank"), int):
        problems.append("fix needs an integer rank")
    if v == "duplicate" and not row.get("duplicate_of"):
        problems.append("duplicate needs duplicate_of")
    if v == "already-fixed":
        if not row.get("fixed_by"):
            problems.append("already-fixed needs fixed_by")
        if not row.get("spot_check"):
            problems.append("already-fixed needs spot_check")
    if v == "reject" and not row.get("spot_check"):
        problems.append("reject needs spot_check")
    if problems:
        raise ValueError("issue %s: %s" % (row.get("issue"),
                                           "; ".join(problems)))


def comment_for(row):
    v = row["verdict"]
    head = {
        "fix": "**Triage: fix** — milestone %s, rank %s (provisional within "
               "batch %s)" % (MILESTONE, row.get("rank"), row["batch"]),
        "duplicate": "**Triage: duplicate** of #%s — closing; the fix lands "
                     "on the canonical issue" % row.get("duplicate_of"),
        "already-fixed": "**Triage: already fixed** by %s"
                         % row.get("fixed_by"),
        "reject": "**Triage: rejected** — the run-2 advisor rejection was "
                  "spot-checked against the current tree and stands",
        "defer": "**Triage: deferred** — parked, out of the current "
                 "remediation arc",
    }[v]
    lines = [head, "", row["rationale"]]
    if row.get("spot_check"):
        lines += ["", "**Spot-check:** %s" % row["spot_check"]]
    lines += ["", "---",
              "*Remediation triage (batch %s) — spec: `%s`*"
              % (row["batch"], SPEC)]
    return "\n".join(lines)


def plan_mutations(row):
    n = str(row["issue"])
    cmds = [["gh", "issue", "comment", n, "--body", comment_for(row)]]
    edit = ["gh", "issue", "edit", n, "--add-label", LABELS[row["verdict"]][0]]
    if row["verdict"] == "fix":
        edit += ["--milestone", MILESTONE]
    cmds.append(edit)
    close_reason = {"duplicate": "not planned", "reject": "not planned",
                    "already-fixed": "completed"}.get(row["verdict"])
    if close_reason:
        cmds.append(["gh", "issue", "close", n, "--reason", close_reason])
    return cmds


def is_stale(row, issue_state):
    # Both timestamps are UTC ISO-8601 "Z" strings; lexicographic compare.
    if issue_state.get("state") != "OPEN":
        return True
    return str(issue_state.get("updatedAt") or "") > str(row.get("triaged_at") or "")
