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
import datetime
import functools
import json
import os
import subprocess
import sys
import time

from sanitize import defang, scrub

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
SCHEMA_VERSION = 1


def load_rows(path=LEDGER):
    try:
        with open(path, encoding="utf-8") as fh:
            rows = []
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    rows.append(json.loads(line))
                except ValueError as e:
                    raise ValueError("ledger line %d unparseable: %s" % (n, e))
            return rows
    except OSError:
        return []


def save_rows(rows, path=LEDGER):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for r in rows:
            if isinstance(r, dict) and "schema_version" not in r:
                r["schema_version"] = SCHEMA_VERSION
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
    else:
        try:
            datetime.datetime.fromisoformat(triaged_at[:-1] + "+00:00")
        except ValueError:
            problems.append("triaged_at must be a UTC ISO-8601 Z timestamp")
    v = row.get("verdict")
    if v == "fix" and not isinstance(row.get("rank"), int):
        problems.append("fix needs an integer rank")
    if v == "duplicate":
        if not row.get("duplicate_of"):
            problems.append("duplicate needs duplicate_of")
        elif not isinstance(row.get("duplicate_of"), int):
            # An issue number, and typed as one so comment_for() can print a
            # LIVE #N link without defanging it.
            problems.append("duplicate_of must be an int")
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
    # Ledger free text reaches a PUBLIC comment, so it gets the same treatment
    # as the rationale below. `duplicate_of` deliberately does NOT: validate()
    # pins it to an int, which cannot carry an injection, and that is what lets
    # its #N cross-link stay live -- defanging would break the link this comment
    # exists to make. `rank` is int-checked by validate() for the one verdict
    # that prints it. #run12 follow-up.
    batch = scrub(defang(str(row["batch"])))
    fixed_by = scrub(defang(str(row.get("fixed_by"))))
    head = {
        "fix": "**Triage: fix** — milestone %s, rank %s (provisional within "
               "batch %s)" % (MILESTONE, row.get("rank"), batch),
        "duplicate": "**Triage: duplicate** of #%s — closing; the fix lands "
                     "on the canonical issue" % row.get("duplicate_of"),
        "already-fixed": "**Triage: already fixed** by %s" % fixed_by,
        "reject": "**Triage: rejected** — the run-2 advisor rejection was "
                  "spot-checked against the current tree and stands",
        "defer": "**Triage: deferred** — parked, out of the current "
                 "remediation arc",
    }[v]
    lines = [head, "", scrub(defang(row["rationale"]))]
    if row.get("spot_check"):
        lines += ["", "**Spot-check:** %s" % scrub(defang(row["spot_check"]))]
    lines += ["", "---",
              "*Remediation triage (batch %s) — spec: `%s`*" % (batch, SPEC)]
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
    the ambient environment, backward compatible) when the config is missing
    or the field is absent/null. Raises on corrupt/unreadable config or
    non-string gh_config_dir values so we fail closed rather than silently
    inherit the wrong credential (#1101).
    """
    if config_path is None:
        config_path = CONFIG_PATH   # late-bound so tests/patches can retarget
    try:
        with open(config_path, encoding="utf-8") as fh:
            cfg = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise ValueError(f"corrupt or unreadable panopticon config ({config_path}): {exc}") from exc
    d = cfg.get("gh_config_dir") if isinstance(cfg, dict) else None
    if d is None:
        return None
    if not isinstance(d, str) or not d:
        raise ValueError(f"invalid gh_config_dir in {config_path!r}: expected string, got {d!r}")
    env = dict(os.environ)
    env["GH_CONFIG_DIR"] = os.path.expanduser(d)
    return env


# Hard bound on each gh invocation so a hung gh (interactive auth prompt on a
# misconfigured GH_CONFIG_DIR, a stalled TLS handshake, a GitHub outage) engages
# the retry/backoff below instead of blocking the unattended pipeline (#1103).
GH_TIMEOUT = 120


def default_gh_runner():
    """subprocess.run partial carrying the config-declared env (#486) and a hard
    timeout (#1103). Kept as a factory so gh_env is re-read per call site
    construction -- tests inject their own runner and never hit this."""
    return functools.partial(subprocess.run, env=gh_env(), timeout=GH_TIMEOUT)


# One retry ladder for every gh subprocess call in the repo. It used to be two:
# this module's gh() and file_issues.create() each carried the same 5-attempt,
# 60*attempt, RATE_HINTS-sniffing loop, and they had ALREADY diverged in
# behaviour (#run11 ARC-A3A / QAL-D1A). file_fixmes.py's own comment records the
# same drift happening once before.
GH_ATTEMPTS = 5


def backoff_seconds(attempt):
    """The project's single retry schedule."""
    return 60 * attempt


def _backoff(message, attempt, sleep):
    seconds = backoff_seconds(attempt)
    print("%s; backing off %ds" % (message, seconds), file=sys.stderr, flush=True)
    sleep(seconds)


def attempt_gh(argv, runner, sleep, retry_empty_stdout=False, on_empty=None,
               what=None):
    """Run `argv` through the shared gh retry ladder.

    Returns (outcome, payload), one of:
      ("ok", stdout) ("adopted", value) ("timeout", None) ("empty", None)
      ("failed", stderr)

    The ladder lives here alone -- attempt cap, backoff schedule, rate-limit
    heuristics, TimeoutExpired handling. What EXHAUSTION MEANS stays with the
    caller, because the two callers genuinely disagree: gh() raises so a caller
    cannot silently continue, while file_issues.create() returns None so the
    finding is left un-ledgered for a resumed run. That is why this reports an
    outcome instead of deciding one.

    `on_empty` is consulted when an attempt exits 0 with NO stdout, before
    backing off: return a value to adopt as the result, or None to keep retrying.
    """
    label = what or " ".join(argv[:4])
    for attempt in range(1, GH_ATTEMPTS + 1):
        final = attempt == GH_ATTEMPTS
        try:
            r = runner(argv, capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            # Without a timeout the retry logic never engages, because
            # subprocess.run never returns; a hang is a retryable failure (#1103).
            if final:
                return "timeout", None
            _backoff("%s timed out (attempt %d)" % (label, attempt), attempt, sleep)
            continue
        if r.returncode == 0:
            if not retry_empty_stdout or (r.stdout or "").strip():
                return "ok", r.stdout
            if on_empty is not None:
                adopted = on_empty()
                if adopted is not None:
                    return "adopted", adopted
            if final:
                return "empty", None
            _backoff("empty stdout on rc=0 (attempt %d)" % attempt, attempt, sleep)
            continue
        err = (r.stderr or "").strip()
        if any(h in err.lower() for h in RATE_HINTS) and not final:
            _backoff("rate limited (attempt %d)" % attempt, attempt, sleep)
            continue
        return "failed", err
    return "failed", "exhausted %d attempts" % GH_ATTEMPTS


def gh(argv, runner=None, sleep=time.sleep):
    if runner is None:
        runner = default_gh_runner()
    outcome, payload = attempt_gh(argv, runner, sleep)
    if outcome == "ok":
        return payload
    label = " ".join(argv[:4])
    if outcome == "timeout":
        raise RuntimeError("%s timed out after retries" % label)
    raise RuntimeError("%s failed: %s" % (label, payload))


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
        raw_view = gh(["gh", "issue", "view", str(row["issue"]),
                        "--json", "state,updatedAt"],
                       runner=runner, sleep=sleep)
        try:
            state = json.loads(raw_view)
            if not isinstance(state, dict):
                state = {}
        except (ValueError, TypeError):
            state = {}
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
        desc = "description=Ranked fix queue from the remediation triage arc — see %s" % SPEC
        gh(["gh", "api", "-X", "POST", "repos/{owner}/{repo}/milestones",
            "-f", "title=%s" % MILESTONE,
            "-f", desc], runner=runner)
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
