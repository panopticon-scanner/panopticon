#!/usr/bin/env python3
"""Run-3 reconciliation, stage 2: act on a diff.json from
skill/scripts/reconcile.py against the run-2 fingerprint-to-issue linkage.

Dry-run by default, always. Mirrors scripts/triage.py's conventions:
injectable runner/sleep for testability, throttle+backoff on gh calls
(reused from triage.gh directly), validate-before-mutate.

Usage:
  python3 scripts/reconcile_apply.py recover-linkage --out linkage.json
  python3 scripts/reconcile_apply.py plan diff.json --ledger linkage.json --out actions.json
  python3 scripts/reconcile_apply.py apply actions.json [--dry-run] [--confirm-close] [--throttle S]
"""
import json
import os
import re
import subprocess

LEDGER = ".panopticon/filed-issues.json"


def load_ledger(path=LEDGER):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def ledger_key(record):
    return "%s|%s|%s|%s" % (record.get("stored_fingerprint") or "",
                            record.get("id") or "",
                            record.get("location_file") or "",
                            record.get("kind") or "")


ISSUE_REPO_URL = "https://github.com/panopticon-scanner/panopticon/issues/%s"

FP_RE = re.compile(r"\*\*Fingerprint:\*\* `([0-9a-f]+)`")
ID_RE = re.compile(r"\*\*Finding id in report:\*\* `([^`]+)`")
LOC_RE = re.compile(r"\*\*Location:\*\* `([^`:]+)(?::\d+)?`")


def recover_linkage_from_github(label="self-scan", runner=subprocess.run):
    """Rebuild the filed-issues ledger from issue bodies when
    .panopticon/filed-issues.json is unavailable. Every field this needs was
    deliberately embedded in the issue body by scripts/file_issues.py.
    """
    r = runner(["gh", "issue", "list", "--label", label, "--state", "all",
               "--json", "number,body,labels", "--limit", "1000"],
              capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError("gh issue list failed (exit %d): %s" % (
            r.returncode, (r.stderr or "").strip()))
    issues = json.loads(r.stdout)
    linkage = {}
    for issue in issues:
        body = issue.get("body") or ""
        fp_m, id_m, loc_m = FP_RE.search(body), ID_RE.search(body), LOC_RE.search(body)
        if not (fp_m and id_m and loc_m):
            continue
        labels = {lbl.get("name") for lbl in issue.get("labels") or []}
        kind = "rejected" if "false-positive" in labels else "finding"
        # body_for() writes the "(no file)" sentinel when location.file is
        # absent, but key_for() keys on an EMPTY location component for that
        # same case — map the sentinel back to "" so the recovered key is
        # byte-identical to the one file_issues.py originally filed under.
        loc = loc_m.group(1)
        loc = "" if loc == "(no file)" else loc
        key = "%s|%s|%s|%s" % (fp_m.group(1), id_m.group(1), loc, kind)
        linkage[key] = ISSUE_REPO_URL % issue["number"]
    return linkage


def save_recovered_ledger(linkage, path=LEDGER):
    tmp = path + ".tmp"
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(linkage, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def resolve_issue(record, ledger):
    return ledger.get(ledger_key(record))


RECUR_COMMENT = ("**Run-3 reconciliation: re-affirmed.** This finding's fingerprint "
                 "(`%s`) recurred in the run-3 self-scan — the underlying content "
                 "identity (panel, category, file, rule/title) matched. Left open.")
GONE_COMMENT = ("**Run-3 reconciliation: not seen in run 3.** This finding's run-2 "
               "fingerprint (`%s`) did not recur in the run-3 self-scan against the "
               "fixed pipeline. Not independently reverified — this states only that "
               "the fingerprint did not reappear, not why.")


def plan_actions(diff, ledger):
    actions = []
    for entry in diff.get("recurring") or []:
        for record in entry["run2"]:
            issue = resolve_issue(record, ledger)
            if issue is None:
                continue
            actions.append({"cohort": "recurring", "fingerprint": entry["fingerprint"],
                           "issue": issue, "comment": RECUR_COMMENT % entry["fingerprint"],
                           "close": False})
    for entry in diff.get("fixed_or_gone") or []:
        for record in entry["run2"]:
            issue = resolve_issue(record, ledger)
            if issue is None:
                continue
            actions.append({"cohort": "fixed_or_gone", "fingerprint": entry["fingerprint"],
                           "issue": issue, "comment": GONE_COMMENT % entry["fingerprint"],
                           "close": True})
    return actions
