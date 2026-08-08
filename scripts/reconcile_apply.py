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
import argparse
import json
import os
import re
import subprocess
import sys
import time

import file_issues
import triage

LEDGER = ".panopticon/filed-issues.json"


def load_ledger(path=LEDGER):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def ledger_key(record):
    # Normalize the location the same way file_issues.key_for does, so a record
    # whose location_file is absolute maps to the same relative key the ledger
    # was filed under (#607/#488). Byte-identical to key_for's three siblings.
    return "%s|%s|%s|%s" % (record.get("stored_fingerprint") or "",
                            record.get("id") or "",
                            file_issues.repo_relative(record.get("location_file") or ""),
                            record.get("kind") or "")


ISSUE_REPO_URL = "https://github.com/panopticon-scanner/panopticon/issues/%s"

FP_RE = re.compile(r"\*\*Fingerprint:\*\* `([0-9a-f]+)`")
ID_RE = re.compile(r"\*\*Finding id in report:\*\* `([^`]+)`")
LOC_RE = re.compile(r"\*\*Location:\*\* `([^`:]+)(?::\d+)?`")


def recover_linkage_from_github(label="self-scan", runner=subprocess.run):
    """Rebuild the filed-issues ledger from issue bodies when
    .panopticon/filed-issues.json is unavailable. Every field this needs was
    deliberately embedded in the issue body by scripts/file_issues.py.

    Path consistency (#607/#488, resolved): issue bodies are scrubbed to
    repo-RELATIVE paths, and file_issues.key_for / this module's ledger_key
    now key on the repo-RELATIVE location too (file_issues.repo_relative). So
    the key reconstructed here from a scrubbed body matches the ledger key
    even for findings whose original location.file was absolute — recovery is
    lossless for anything filed by the fixed key_for. (Ledgers filed BEFORE
    the fix that stored a raw absolute-path key for such a finding are still
    unrecoverable via this fallback; those resolve on the primary path where
    the real ledger is present.) Recovery stays fail-safe regardless — an
    unmatched issue is simply left open, never mis-acted-on.
    .panopticon/filed-issues.json remains the source of truth; preserve it.
    """
    r = runner(["gh", "issue", "list", "--label", label, "--state", "all",
               "--json", "number,url,body,labels", "--limit", "1000"],
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
        linkage[key] = issue.get("url") or (ISSUE_REPO_URL % issue["number"])
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


_ISSUE_URL_RE = re.compile(r"https?://github\.com/([^/]+)/([^/]+)/issues/")


def _issue_number(url):
    return url.rstrip("/").rsplit("/", 1)[-1]


def _owner_repo(url):
    m = _ISSUE_URL_RE.match(url or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def preflight_authorized(owner, repo, runner=subprocess.run):
    """Owner/admin gate for the mutating apply. Uses the AUTHENTICATED gh token
    (`gh api repos/{o}/{r} --jq .permissions`), so it reflects whichever
    GH_CONFIG_DIR/account is active — the loud catch for a wrong-account run.
    (True, "") iff .permissions.admin is truthy; (False, reason) on non-zero exit,
    404, or absent/unparseable permissions. Never infers admin:false from missing
    data, never crashes on it.
    """
    r = runner(["gh", "api", "repos/%s/%s" % (owner, repo), "--jq", ".permissions"],
               capture_output=True, text=True)
    if r.returncode != 0:
        return (False, "gh api repos/%s/%s failed: %s"
                % (owner, repo, (r.stderr or "").strip()))
    body = (r.stdout or "").strip()
    if not body or body == "null":
        return (False, "no .permissions for %s/%s (repo not visible to this token?)"
                % (owner, repo))
    try:
        perms = json.loads(body)
    except ValueError:
        return (False, "unparseable permissions payload for %s/%s" % (owner, repo))
    if isinstance(perms, dict) and perms.get("admin"):
        return (True, "")
    return (False, "authenticated gh user is not an admin of %s/%s" % (owner, repo))


def apply(actions, dry=True, confirm_close=False, throttle=1.5,
         runner=subprocess.run, sleep=time.sleep):
    commented = closed = 0
    repo_slug = None
    if not dry and actions:
        owner, repo = _owner_repo(actions[0]["issue"])
        if any(_owner_repo(a["issue"]) != (owner, repo) for a in actions):
            print("refusing: actions span multiple repos; expected all in %s/%s"
                  % (owner, repo))
            return (0, 0)
        ok, reason = preflight_authorized(owner, repo, runner=runner)
        if not ok:
            print("refusing: authenticated gh user is not an owner/admin of %s/%s — %s"
                  % (owner, repo, reason))
            return (0, 0)
        repo_slug = "%s/%s" % (owner, repo)
    for a in actions:
        n = _issue_number(a["issue"])
        if dry:
            print("DRY comment #%s (%s): %s" % (n, a["cohort"], a["comment"][:60]))
            if a["close"] and confirm_close:
                print("DRY close   #%s" % n)
            commented += 1
            continue
        triage.gh(["gh", "issue", "comment", n, "--repo", repo_slug, "--body", a["comment"]],
                  runner=runner, sleep=sleep)
        sleep(throttle)
        commented += 1
        if a["close"] and confirm_close:
            triage.gh(["gh", "issue", "close", n, "--repo", repo_slug, "--reason", "not planned"],
                      runner=runner, sleep=sleep)
            sleep(throttle)
            closed += 1
    return commented, closed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_rec = sub.add_parser("recover-linkage")
    p_rec.add_argument("--out", required=True)
    p_rec.add_argument("--label", default="self-scan")

    p_plan = sub.add_parser("plan")
    p_plan.add_argument("diff_json")
    p_plan.add_argument("--ledger", default=LEDGER)
    p_plan.add_argument("--out", required=True)

    p_apply = sub.add_parser("apply")
    p_apply.add_argument("actions_json")
    p_apply.add_argument("--dry-run", dest="dry_run", action="store_true", default=True)
    p_apply.add_argument("--no-dry-run", dest="dry_run", action="store_false")
    p_apply.add_argument("--confirm-close", action="store_true")
    p_apply.add_argument("--throttle", type=float, default=1.5)

    a = ap.parse_args(argv)

    if a.cmd == "recover-linkage":
        linkage = recover_linkage_from_github(label=a.label)
        save_recovered_ledger(linkage, path=a.out)
        print("recovered %d linkage entries -> %s" % (len(linkage), a.out))
        return 0

    if a.cmd == "plan":
        with open(a.diff_json, encoding="utf-8") as fh:
            diff = json.load(fh)
        ledger = load_ledger(path=a.ledger)
        actions = plan_actions(diff, ledger)
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(actions, fh, indent=2, sort_keys=True)
        unresolved = (sum(len(e["run2"]) for e in diff.get("recurring") or [])
                     + sum(len(e["run2"]) for e in diff.get("fixed_or_gone") or [])
                     - len(actions))
        print("wrote %d action(s) -> %s (%d record(s) unresolved against the ledger)"
             % (len(actions), a.out, unresolved))
        return 0

    if a.cmd == "apply":
        actions = json.load(open(a.actions_json, encoding="utf-8"))
        commented, closed = apply(actions, dry=a.dry_run, confirm_close=a.confirm_close,
                                  throttle=a.throttle)
        print("%s: commented %d, closed %d"
             % ("DRY RUN" if a.dry_run else "LIVE", commented, closed))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
