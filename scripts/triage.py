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
import functools
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
    triaged_at = row.get("triaged_at")
    if not isinstance(triaged_at, str) or not triaged_at.strip() or not triaged_at.endswith("Z"):
        problems.append("triaged_at must be a UTC ISO-8601 Z timestamp")
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


RATE_HINTS = ("rate limit", "secondary rate", "abuse detection",
              "was submitted too quickly")


CONFIG_PATH = os.path.join(".panopticon", "config.json")


def gh_env(config_path=None):
    """#486: explicit, config-declared gh account selection.

    Reads .panopticon/config.json's "gh_config_dir" and returns an env dict
    with GH_CONFIG_DIR set to it (expanded), so every gh subprocess the tools
    spawn uses the DECLARED account instead of whatever ambient credential the
    shell happens to carry (the thebeamishsociety wrong-account incident:
    default cred lacked push, the 404 was swallowed). Returns None (= inherit
    the ambient environment, backward compatible) when the config or field is
    absent/invalid.
    """
    if config_path is None:
        config_path = CONFIG_PATH   # late-bound so tests/patches can retarget
    try:
        with open(config_path, encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        return None
    d = cfg.get("gh_config_dir") if isinstance(cfg, dict) else None
    if not isinstance(d, str) or not d:
        return None
    env = dict(os.environ)
    env["GH_CONFIG_DIR"] = os.path.expanduser(d)
    return env


def default_gh_runner():
    """subprocess.run partial carrying the config-declared env (#486). Kept as
    a factory so gh_env is re-read per call site construction -- tests inject
    their own runner and never hit this."""
    return functools.partial(subprocess.run, env=gh_env())


def gh(argv, runner=None, sleep=time.sleep):
    if runner is None:
        runner = default_gh_runner()
    for attempt in range(1, 6):
        r = runner(argv, capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout
        err = (r.stderr or "").strip()
        if any(h in err.lower() for h in RATE_HINTS) and attempt < 5:
            backoff = 60 * attempt
            print("rate limited (attempt %d); sleeping %ds"
                  % (attempt, backoff), file=sys.stderr, flush=True)
            sleep(backoff)
            continue
        raise RuntimeError("%s failed: %s" % (" ".join(argv[:4]), err))
    raise RuntimeError("%s failed after retries" % " ".join(argv[:4]))


def apply(rows, dry=False, throttle=1.5, runner=None,
          sleep=time.sleep):
    runner = runner or default_gh_runner()
    for row in rows:              # validate the whole batch before mutating
        if row.get("status") == "approved":
            validate(row)
    applied = stale = 0
    for row in rows:
        if row.get("status") != "approved":
            continue
        if dry:
            for cmd in plan_mutations(row):
                print("DRY #%s: %s" % (row["issue"], " ".join(cmd[:6])))
            continue
        state = json.loads(gh(["gh", "issue", "view", str(row["issue"]),
                               "--json", "state,updatedAt"],
                              runner=runner, sleep=sleep))
        if is_stale(row, state):
            row["status"] = "stale"
            stale += 1
            print("STALE  #%s — changed on GitHub since triage; re-triage"
                  % row["issue"], flush=True)
            continue
        for cmd in plan_mutations(row):
            gh(cmd, runner=runner, sleep=sleep)
            sleep(throttle)
        row["status"] = "applied"
        applied += 1
        print("applied #%s %s" % (row["issue"], row["verdict"]), flush=True)
    return applied, stale


def setup(runner=None):
    runner = runner or default_gh_runner()
    for verdict in VERDICTS:
        name, color, desc = LABELS[verdict]
        gh(["gh", "label", "create", name, "--color", color,
            "--description", desc, "--force"], runner=runner)
        print("label   %s" % name)
    titles = json.loads(gh(["gh", "api",
                            "repos/{owner}/{repo}/milestones?state=all",
                            "--jq", "[.[].title]"], runner=runner) or "[]")
    if MILESTONE in titles:
        print("milestone exists: %s" % MILESTONE)
    else:
        gh(["gh", "api", "-X", "POST", "repos/{owner}/{repo}/milestones",
            "-f", "title=%s" % MILESTONE,
            "-f", "description=Ranked fix queue from the remediation triage "
                  "arc — see %s" % SPEC], runner=runner)
        print("milestone created: %s" % MILESTONE)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup")
    p_apply = sub.add_parser("apply")
    p_apply.add_argument("--dry-run", action="store_true")
    p_apply.add_argument("--throttle", type=float, default=1.5)
    a = ap.parse_args()
    if a.cmd == "setup":
        setup()
        return
    rows = load_rows()
    if not rows:
        sys.exit("no ledger at %s" % LEDGER)
    try:
        applied, stale = apply(rows, dry=a.dry_run, throttle=a.throttle)
    finally:
        if not a.dry_run:
            save_rows(rows)       # persist progress even on mid-run failure
    print("applied %d; stale %d; ledger: %s" % (applied, stale, LEDGER))


if __name__ == "__main__":
    main()
