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

Live CLI apply saves acknowledgements beside the plan as actions.json.progress.json
(override with --progress). A retry skips acknowledged operations. There is a
small unavoidable window after GitHub accepts an operation but before its local
receipt is saved; a crash then can repeat that operation. This is resume support,
not an exactly-once protocol.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess  # noqa: F401 -- patch target for the dry-run zero-subprocess guard test
import sys
import tempfile
import time
import warnings

import file_issues
import triage

LEDGER = ".panopticon/filed-issues.json"
PROGRESS_VERSION = 1
PROGRESS_MAX_BYTES = 4 * 1024 * 1024


# Same machinery, same default path — file_issues owns the ledger read.
load_ledger = file_issues.load_ledger


def ledger_key(record):
    return file_issues.make_ledger_key(
        record.get("stored_fingerprint"),
        record.get("id"),
        record.get("location_file"),
        record.get("kind")
    )


def legacy_ledger_key(record):
    return "%s|%s|%s|%s" % (record.get("stored_fingerprint") or "",
                            record.get("id") or "",
                            record.get("location_file") or "",
                            record.get("kind") or "")


ISSUE_REPO_URL = f"https://github.com/{file_issues.REPO_SLUG}/issues/%s"

FP_RE = re.compile(r"\*\*Fingerprint:\*\* `([0-9a-f]+)`")
ID_RE = re.compile(r"\*\*Finding id in report:\*\* `([^`]+)`")
LOC_RE = re.compile(r"\*\*Location:\*\* `([^`]+?)(?::\d+)?`")


def recover_linkage_from_github(label="self-scan", runner=None):
    runner = runner or triage.default_gh_runner()
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
    if len(issues) >= 1000:
        warnings.warn(
            "recover_linkage_from_github: gh issue list returned %d issues, "
            "which equals the --limit cap; results may be truncated. "
            "Increase --limit or narrow labels to ensure complete recovery." % len(issues),
            UserWarning,
            stacklevel=2,
        )
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
    key = ledger_key(record)
    if key in ledger:
        return ledger[key]
    legacy_key = legacy_ledger_key(record)
    if legacy_key != key:
        return ledger.get(legacy_key)
    return None


def neutralize(text):
    """Make repo-derived text inert in a GitHub comment (#953).

    Reason strings embed scanned-repo file paths verbatim, and these comments
    are auto-posted by an authenticated identity — a hostile repo controls its
    own paths, so markdown links, @-mentions, and backtick breakouts must not
    activate. Collapse all whitespace/control chars (the CWE-117 convention
    sarif_to_findings uses for titles), strip backticks so nothing escapes the
    span, then wrap the whole value in ONE code span, inside which GitHub
    renders markdown and @-mentions inert.
    """
    s = " ".join(str(text or "").split())
    # str.split() collapses the WHITESPACE class only; other C0/C1 control
    # bytes (ESC, BEL, single-byte CSI \x9b, ...) survive it and would reach
    # anyone reading the comment through gh/terminal pipelines as terminal
    # escape sequences. Strip them outright.
    s = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", s)
    s = s.replace("`", "'")
    return "`%s`" % (s or "(empty)")


def _bare(text):
    """neutralize() minus the wrapping span — for templates that carry their
    own `...` around the interpolant (the fingerprint slots)."""
    return neutralize(text)[1:-1]


RECUR_EXACT_COMMENT = ("**Run-3 reconciliation: re-affirmed.** This finding's fingerprint "
                       "(`%s`) recurred in the run-3 self-scan — the underlying content "
                       "identity (panel, category, file, rule/title) matched. Left open.")
RECUR_COARSE_COMMENT = ("**Run-3 reconciliation: re-affirmed (re-worded).** This finding's "
                        "fingerprint (`%s`) did not recur exactly, but its file, panel, and "
                        "category identity recurred in the new run under a re-worded title; "
                        "treated as the same finding. Left open.")
CLOSED_COMMENT = ("**Reconciliation: fixed (area clear).** This finding did not "
                  "recur and its (file, panel) is clean in the new run: %s. "
                  "Auto-closed. Reopen if this was a re-word we missed.")
AMBIGUOUS_COMMENT = ("**Reconciliation: not seen, but area still active.** This "
                     "finding's exact/coarse identity did not recur, yet %s, so it "
                     "may have been re-worded or re-categorized. Left OPEN, not "
                     "auto-closed.")


def _cohort_actions(entries, cohort, close, comment_fn, ledger):
    """Resolve each run2 record in *entries* to its issue and build the action
    dict for one cohort. comment_fn(entry) -> the comment body for that entry."""
    out = []
    for entry in entries or []:
        for record in entry["run2"]:
            issue = resolve_issue(record, ledger)
            if issue is None:
                continue
            out.append({"cohort": cohort, "fingerprint": entry["fingerprint"],
                        "issue": issue, "comment": comment_fn(entry), "close": close})
    return out


def plan_actions(diff, ledger):
    if not isinstance(diff, dict):
        raise ValueError("diff must be a dictionary")
    if "schema_version" in diff and not isinstance(diff.get("schema_version"), int):
        raise ValueError("diff schema_version must be an integer")
    if "fixed_or_gone" in diff:
        print("diff.json predates the closed/ambiguous split -- re-run reconcile.py diff",
              file=sys.stderr)

    def _recur_comment(entry):
        tpl = (RECUR_COARSE_COMMENT if entry.get("match_tier") == "coarse"
               else RECUR_EXACT_COMMENT)
        return tpl % _bare(entry["fingerprint"])

    actions = []
    actions += _cohort_actions(diff.get("recurring"), "recurring", False,
                               _recur_comment, ledger)
    actions += _cohort_actions(
        diff.get("closed"), "closed", True,
        lambda e: CLOSED_COMMENT % neutralize(e.get("reason", "no run3 match")), ledger)
    actions += _cohort_actions(
        diff.get("ambiguous"), "ambiguous", False,
        lambda e: AMBIGUOUS_COMMENT % neutralize(e.get("reason", "area still active")), ledger)
    return actions


_ISSUE_URL_RE = re.compile(r"https?://github\.com/([^/]+)/([^/]+)/issues/")


def _issue_number(url):
    return url.rstrip("/").rsplit("/", 1)[-1]


def _owner_repo(url):
    m = _ISSUE_URL_RE.match(url or "")
    return (m.group(1), m.group(2)) if m else (None, None)


def preflight_authorized(owner, repo, runner=None):
    runner = runner or triage.default_gh_runner()
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


def _action_key(action, repo_slug):
    """Bind an acknowledgement to the full exact action and target repository."""
    canonical = json.dumps({"repo": repo_slug, "action": action}, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_progress(path, repo_slug):
    progress = {"version": PROGRESS_VERSION, "repo": repo_slug, "actions": {}}
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory) or os.path.islink(directory):
        raise ValueError("unsafe progress directory: %s" % directory)
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return progress
    if not stat.S_ISREG(mode):
        raise ValueError("unsafe progress file (expected regular file): %s" % path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                raise ValueError("unsafe progress file (expected regular file): %s" % path)
            if os.fstat(fh.fileno()).st_size > PROGRESS_MAX_BYTES:
                raise ValueError("progress file too large: %s" % path)
            data = fh.read(PROGRESS_MAX_BYTES + 1)
            if len(data.encode("utf-8")) > PROGRESS_MAX_BYTES:
                raise ValueError("progress file too large: %s" % path)
        loaded = json.loads(data)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid progress file %s: %s" % (path, exc)) from exc
    if (not isinstance(loaded, dict) or set(loaded) != {"version", "repo", "actions"}
            or type(loaded["version"]) is not int or loaded["version"] != PROGRESS_VERSION
            or loaded["repo"] != repo_slug or not isinstance(loaded["actions"], dict)):
        raise ValueError("invalid progress schema or repository: %s" % path)
    for key, receipt in loaded["actions"].items():
        if (not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{64}", key) is None
                or not isinstance(receipt, dict)
                or set(receipt) != {"commented", "closed"}
                or type(receipt["commented"]) is not bool
                or type(receipt["closed"]) is not bool
                or (receipt["closed"] and not receipt["commented"])):
            raise ValueError("invalid progress acknowledgement: %s" % path)
    return loaded


def _save_progress(progress, path):
    """Replace a receipt in its own directory after each successful gh call."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".reconcile-progress-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(progress, fh, sort_keys=True, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def apply(actions, dry=True, confirm_close=False, throttle=1.5,
         runner=None, sleep=time.sleep, progress_path=None):
    """Return counts of operations performed in this invocation.

    With progress_path, live runs resume successful comments/closes. Dry runs
    always display every planned action and never read or write progress.
    A process death between remote success and receipt replacement can still
    repeat the remote operation on retry.
    """
    runner = runner or triage.default_gh_runner()
    commented = closed = 0
    repo_slug = None
    progress = None
    action_keys = []
    if not dry and actions:
        owner, repo = _owner_repo(actions[0]["issue"])
        if any(_owner_repo(a["issue"]) != (owner, repo) for a in actions):
            print("refusing: actions span multiple repos; expected all in %s/%s"
                  % (owner, repo))
            return (0, 0)
        repo_slug = "%s/%s" % (owner, repo)
        if progress_path is not None:
            progress = _load_progress(progress_path, repo_slug)
            action_keys = [_action_key(a, repo_slug) for a in actions]
        ok, reason = preflight_authorized(owner, repo, runner=runner)
        if not ok:
            print("refusing: authenticated gh user is not an owner/admin of %s/%s — %s"
                  % (owner, repo, reason))
            return (0, 0)
    for index, a in enumerate(actions):
        n = _issue_number(a["issue"])
        if dry:
            print("DRY comment #%s (%s): %s" % (n, a["cohort"], a["comment"][:60]))
            if a["close"] and confirm_close:
                print("DRY close   #%s" % n)
            commented += 1
            continue
        receipt = None
        if progress is not None:
            key = action_keys[index]
            receipt = progress["actions"].setdefault(key, {"commented": False, "closed": False})
        if receipt is None or not receipt["commented"]:
            triage.gh(["gh", "issue", "comment", n, "--repo", repo_slug, "--body", a["comment"]],
                      runner=runner, sleep=sleep)
            if receipt is not None:
                receipt["commented"] = True
                _save_progress(progress, progress_path)
            sleep(throttle)
            commented += 1
        if a["close"] and confirm_close and (receipt is None or not receipt["closed"]):
            triage.gh(["gh", "issue", "close", n, "--repo", repo_slug, "--reason", "not planned"],
                      runner=runner, sleep=sleep)
            if receipt is not None:
                receipt["closed"] = True
                _save_progress(progress, progress_path)
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
    p_apply.add_argument("--progress", help="receipt path (default: ACTIONS_JSON.progress.json)")

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
                     + sum(len(e["run2"]) for e in diff.get("closed") or [])
                     + sum(len(e["run2"]) for e in diff.get("ambiguous") or [])
                     - len(actions))
        print("wrote %d action(s) -> %s (%d record(s) unresolved against the ledger)"
             % (len(actions), a.out, unresolved))
        return 0

    if a.cmd == "apply":
        with open(a.actions_json, encoding="utf-8") as fh:
            actions = json.load(fh)
        commented, closed = apply(actions, dry=a.dry_run, confirm_close=a.confirm_close,
                                  throttle=a.throttle,
                                  progress_path=a.progress or a.actions_json + ".progress.json")
        print("%s: commented %d, closed %d"
             % ("DRY RUN" if a.dry_run else "LIVE", commented, closed))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
