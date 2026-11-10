#!/usr/bin/env python3
"""Apply remediation-triage dispositions from the triage ledger to GitHub.

The ledger (.panopticon/triage-ledger.jsonl) is written by the triage arc:
one JSON object per line, one line per issue. This tool only ever mutates
GitHub from rows whose status is "approved" (the user's batch gate), and
flips a row to "applied" only when every mutation for it succeeded.

Live apply writes repository/approval-bound intent and step receipts to a sibling
progress file (or PROGRESS for standalone callers). Keep that file when retrying.
Uncertain responses and crashes require positive remote reconciliation; absence
of a marker never authorizes replay. This is not exactly-once delivery. A definite
rejection may also need operator recovery because the CLI cannot prove whether
GitHub accepted a request before a transport failure. Ledger writes merge using
the original rows under a stable lock; external writers must honor that lock.

Usage:  python3 devtools/triage.py setup
        python3 devtools/triage.py apply [--dry-run] [--throttle S]
"""
import argparse
import datetime
import contextlib
import copy
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

if __name__ == "__main__":  # run by path: puts skill/ on sys.path (#3505)
    import runpy
    runpy.run_path(os.path.join(os.path.dirname(os.path.realpath(__file__)), "_skill_bootstrap.py"))
from sanitize import defang, scrub

# #3404: the gh transport lives in gh_transport.py now (which also puts skill/scripts on
# sys.path, as this module's own bootstrap used to). Re-exported for one release; a patch
# on one of these names must target gh_transport, where the code reads it.
import gh_transport
from gh_transport import (  # noqa: F401
    RATE_HINTS, CONFIG_PATH, TRUSTED_PATH, trusted_path, gh_bin, declared_gh_config_dir,
    _GH_AUTH_PASSTHROUGH, gh_env, GH_TIMEOUT, _run_gh, default_gh_runner, GH_ATTEMPTS,
    backoff_seconds, _backoff, attempt_gh, gh)

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


MAX_STATE_BYTES = 8 * 1024 * 1024
PROGRESS = ".panopticon/triage-progress.json"


def _read_text(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = fh.read(MAX_STATE_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"unreadable state {path}: {exc}") from exc
    if len(data.encode()) > MAX_STATE_BYTES:
        raise ValueError(f"state too large: {path}")
    return data


def _row_map(rows):
    result = {}
    for row in rows:
        if not isinstance(row, dict) or type(row.get("issue")) is not int or row["issue"] <= 0:
            raise ValueError("ledger rows must be objects with positive issue numbers")
        if row["issue"] in result:
            raise ValueError("duplicate ledger issue")
        result[row["issue"]] = row
    return result


def load_rows(path=LEDGER):
    data = _read_text(path)
    rows = []
    for n, line in enumerate((data or "").splitlines(), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except ValueError as exc:
                raise ValueError(f"ledger line {n} unparseable: {exc}") from exc
    _row_map(rows)
    return rows


@contextlib.contextmanager
def _locked(path):
    # Lock a stable sibling inode: replacing the data file cannot release it.
    path = os.fspath(path)
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path + ".lock", "a", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _atomic_write(path, data):
    if len(data.encode()) > MAX_STATE_BYTES:
        raise ValueError("state too large to persist")
    directory = os.path.dirname(os.path.abspath(path))
    fd, temporary = tempfile.mkstemp(prefix=".triage-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_rows(rows, path=LEDGER, expected=None):
    """Merge only changed rows under lock; existing edits need a baseline."""
    proposed = _row_map(rows)
    baseline = _row_map(expected or [])
    with _locked(path):
        current = _row_map(load_rows(path))  # corrupt evidence is never replaced
        for issue, row in proposed.items():
            if row == baseline.get(issue):
                continue
            if current.get(issue) != baseline.get(issue):
                raise ValueError(f"ledger conflict: issue {issue} changed")
            current[issue] = dict(row, schema_version=row.get("schema_version", SCHEMA_VERSION))
        _atomic_write(path, "".join(json.dumps(r, sort_keys=True) + "\n"
                                    for r in current.values()))


def validate(row):
    problems = []
    missing = [k for k in REQUIRED if k not in row]
    if missing:
        problems.append("missing: %s" % ", ".join(missing))
    if type(row.get("issue")) is not int or row["issue"] <= 0:
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


def plan_mutations(row, repo=gh_transport.REPO_SLUG):
    repo = validate_repo(repo)
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
    return [cmd + ["--repo", repo] for cmd in cmds]


def _remote_timestamp(value):
    """Require GitHub UTC freshness evidence, including valid calendar/time values."""
    if not isinstance(value, str) or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value):
        raise ValueError("incomplete remote snapshot: invalid updatedAt UTC timestamp")
    try:
        return datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("incomplete remote snapshot: invalid updatedAt UTC timestamp") from exc


def is_stale(row, issue_state):
    updated_at = _remote_timestamp(issue_state.get("updatedAt"))
    if issue_state.get("state") != "OPEN":
        return True
    # Compare instants: fractional seconds do not sort correctly against a
    # seconds-only Z timestamp. validate() has checked the approval timestamp.
    triaged_at = datetime.datetime.fromisoformat(row["triaged_at"][:-1] + "+00:00")
    return updated_at > triaged_at


def validate_repo(repo):
    if not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+", repo):
        raise ValueError("repository must be OWNER/REPO")
    if repo.split("/")[1] in (".", ".."):
        raise ValueError("repository must be OWNER/REPO")
    return repo


def preflight(repo, runner, sleep=time.sleep):
    raw = gh(["gh", "api", f"repos/{repo}"], runner=runner, sleep=sleep)
    try:
        response = json.loads(raw)
        allowed = (isinstance(response, dict) and response.get("full_name") == repo
                   and isinstance(response.get("permissions"), dict)
                   and response["permissions"].get("admin") is True)
    except (TypeError, ValueError):
        allowed = False
    if not allowed:
        raise ValueError(f"authenticated admin permission required for {repo}")


def _identity(binding):
    return hashlib.sha256(json.dumps(binding, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _binding(row, repo):
    return {"target": repo, "issue": row["issue"], "verdict": row["verdict"],
            "row": copy.deepcopy(row), "comment": comment_for(row),
            "steps": plan_mutations(row, repo)}


def _commands(binding):
    commands = copy.deepcopy(binding["steps"])
    marker = '<!-- panopticon-triage:' + _identity(binding) + ' -->'
    commands[0][commands[0].index("--body") + 1] += "\n\n" + marker
    return commands


def _load_progress(path, repo):
    raw = _read_text(path)
    if raw is None:
        return {"version": 1, "repo": repo, "rows": {}}
    try:
        data = json.loads(raw)
        if (not isinstance(data, dict) or set(data) != {"version", "repo", "rows"}
                or type(data["version"]) is not int or data["version"] != 1
                or data["repo"] != repo or not isinstance(data["rows"], dict)):
            raise ValueError("progress target/schema mismatch")
        for key, record in data["rows"].items():
            if not isinstance(record, dict) or set(record) != {"binding", "identity", "done", "pending", "baseline", "observed"}:
                raise ValueError("invalid progress record")
            binding = record["binding"]
            if not isinstance(binding, dict) or not isinstance(binding.get("row"), dict):
                raise ValueError("invalid progress binding")
            row = binding["row"]
            validate(row)
            if (row["status"] != "approved" or binding != _binding(row, repo)
                    or key != str(row["issue"]) or record["identity"] != _identity(binding)):
                raise ValueError("progress plan mismatch")
            done, pending = record["done"], record["pending"]
            if (type(done) is not int or not 0 <= done <= len(binding["steps"])
                    or (pending is not None and (type(pending) is not int
                        or pending != done or done == len(binding["steps"])))):
                raise ValueError("invalid progress steps")
            _validate_snapshot(record["baseline"])
            _validate_snapshot(record["observed"])
        return data
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"corrupt/mismatched progress {path}: {exc}") from exc


def _persist_progress(path, data):
    _atomic_write(path, json.dumps(data, sort_keys=True) + "\n")


def _validate_snapshot(snapshot):
    if not isinstance(snapshot, dict) or set(snapshot) != {"issue", "comments"}:
        raise ValueError("invalid remote snapshot")
    state = snapshot["issue"]
    if (not isinstance(state, dict) or set(state) != {
            "state", "stateReason", "updatedAt", "title", "body", "labels", "milestone"}
            or state["state"] not in ("OPEN", "CLOSED")
            or state["stateReason"] not in (None, "COMPLETED", "NOT_PLANNED", "REOPENED")
            or not all(isinstance(state[k], str) for k in ("updatedAt", "title", "body"))
            or not isinstance(state["labels"], list)
            or not all(isinstance(label, dict) and isinstance(label.get("name"), str)
                       for label in state["labels"])
            or (state["milestone"] is not None and (not isinstance(state["milestone"], dict)
                or not isinstance(state["milestone"].get("title"), str)))
            or not isinstance(snapshot["comments"], list)
            or not all(isinstance(c, dict) and isinstance(c.get("body"), str)
                       for c in snapshot["comments"])):
        raise ValueError("incomplete remote snapshot")
    _remote_timestamp(state["updatedAt"])


def _snapshot(row, repo, runner, sleep):
    fields = "state,stateReason,updatedAt,title,body,labels,milestone"
    state_raw = gh(["gh", "issue", "view", str(row["issue"]), "--repo", repo,
                    "--json", fields], runner=runner, sleep=sleep)
    if len(state_raw.encode()) > MAX_STATE_BYTES:
        raise ValueError("remote issue observation too large")
    state = json.loads(state_raw)
    raw = gh(["gh", "api", f"repos/{repo}/issues/{row['issue']}/comments?per_page=100",
              "--paginate", "--slurp"], runner=runner, sleep=sleep)
    if len(raw.encode()) > MAX_STATE_BYTES:
        raise ValueError("remote comment observation too large")
    pages = json.loads(raw)
    # gh --paginate must complete successfully, and --slurp must contain pages,
    # never a truncated gh issue view comments connection. Bound local decoding.
    if (not isinstance(pages, list) or not pages
            or len(pages) > 100 or any(not isinstance(p, list) or len(p) > 100 for p in pages)
            or any(len(p) != 100 for p in pages[:-1])):
        raise ValueError("incomplete comment reconciliation")
    snapshot = {"issue": state, "comments": [c for page in pages for c in page]}
    _validate_snapshot(snapshot)
    return snapshot


def _matches(record, snapshot, completed):
    """Compare complete observations, allowing only this plan's own changes."""
    expected = copy.deepcopy(record["baseline"])
    row = record["binding"]["row"]
    comments = snapshot["comments"]
    if completed:
        body = _commands(record["binding"])[0][5]
        own = [c for c in comments if c["body"] == body]
        if len(own) != 1:
            return False
        comments = [c for c in comments if c["body"] != body]
    if comments != expected["comments"]:
        return False
    if completed >= 2:
        label = LABELS[row["verdict"]][0]
        if label not in [v["name"] for v in expected["issue"]["labels"]]:
            expected["issue"]["labels"].append({"name": label})
        if row["verdict"] == "fix":
            expected["issue"]["milestone"] = {"title": MILESTONE}
    if completed >= 3:
        expected["issue"]["state"] = "CLOSED"
        expected["issue"]["stateReason"] = ("COMPLETED" if row["verdict"] == "already-fixed" else "NOT_PLANNED")
    actual = copy.deepcopy(snapshot["issue"])
    wanted = expected["issue"]
    for state in (actual, wanted):
        state["labels"] = sorted(v["name"] for v in state["labels"])
        state["milestone"] = state["milestone"]["title"] if state["milestone"] else None
        if completed:
            state.pop("updatedAt")
    return actual == wanted


def _mutate_once(command, runner):
    # Any uncertain result leaves the prewritten intent pending. A process
    # crash between acceptance and receipt follows the same reconciliation path.
    try:
        result = runner(command, capture_output=True, text=True)
    except (subprocess.TimeoutExpired, OSError) as exc:
        raise RuntimeError("mutation pending; rerun to reconcile before recovery") from exc
    if result.returncode != 0:
        raise RuntimeError(f"mutation pending; reconcile before recovery: {result.stderr}")


def apply(rows, dry=False, throttle=1.5, runner=None, sleep=time.sleep,
          repo=gh_transport.REPO_SLUG, ledger_path=None, progress_path=None):
    repo = validate_repo(repo)
    _row_map(rows)
    approved = [row for row in rows if row.get("status") == "approved"]
    for row in approved:
        validate(row)
    if dry:
        for row in approved:
            for cmd in plan_mutations(row, repo):
                print("DRY #%s: %s" % (row["issue"], " ".join(cmd[:6])))
        return 0, 0
    if not approved:
        return 0, 0
    runner = runner or default_gh_runner()
    preflight(repo, runner, sleep)
    progress_path = progress_path or (os.fspath(ledger_path) + ".progress.json" if ledger_path else PROGRESS)
    applied = stale = 0
    with _locked(progress_path):
        progress = _load_progress(progress_path, repo)
        for row in approved:
            original = copy.deepcopy(row)
            if ledger_path is not None and _row_map(load_rows(ledger_path)).get(row["issue"]) != row:
                raise ValueError(f"ledger conflict: issue {row['issue']} changed")
            binding = _binding(row, repo)
            key = str(row["issue"])
            record = progress["rows"].get(key)
            if record is not None and record["binding"] != binding:
                raise ValueError("progress row/plan mismatch; reconcile old intent first")
            try:
                snapshot = _snapshot(row, repo, runner, sleep)
            except (ValueError, TypeError, RuntimeError) as exc:
                raise RuntimeError("remote observation incomplete; pending reconciliation") from exc
            if record is None:
                if is_stale(row, snapshot["issue"]):
                    row["status"] = "stale"
                    stale += 1
                else:
                    record = {"binding": binding, "identity": _identity(binding),
                              "done": 0, "pending": None, "baseline": snapshot,
                              "observed": snapshot}
                    progress["rows"][key] = record
                    _persist_progress(progress_path, progress)
            else:
                completed = record["done"] + (record["pending"] is not None)
                if (not _matches(record, snapshot, completed)
                        or (record["pending"] is None and snapshot != record["observed"])):
                    raise RuntimeError("remote changes or incomplete match; pending reconciliation, do not replay")
                if record["pending"] is not None:
                    record["done"] += 1
                    record["pending"] = None
                    record["observed"] = snapshot
                    _persist_progress(progress_path, progress)
            if row["status"] == "approved":
                for index, cmd in enumerate(_commands(binding)):
                    if index < record["done"]:
                        continue
                    # Recheck the approval before each public step, not just final save.
                    if ledger_path is not None and _row_map(load_rows(ledger_path)).get(row["issue"]) != original:
                        raise ValueError("ledger conflict: approval changed")
                    record["pending"] = index
                    _persist_progress(progress_path, progress)
                    _mutate_once(cmd, runner)
                    try:
                        observed = _snapshot(row, repo, runner, sleep)
                    except (ValueError, TypeError, RuntimeError) as exc:
                        raise RuntimeError("mutation pending; remote reconciliation incomplete") from exc
                    if not _matches(record, observed, index + 1):
                        raise RuntimeError("remote result differs from intent; pending reconciliation")
                    record["observed"] = observed
                    record["done"] = index + 1
                    record["pending"] = None
                    _persist_progress(progress_path, progress)
                    sleep(throttle)
                row["status"] = "applied"
                applied += 1
                print("applied #%s %s" % (row["issue"], row["verdict"]), flush=True)
            if ledger_path is not None:
                save_rows([row], ledger_path, expected=[original])
    return applied, stale


def setup(runner=None, repo=gh_transport.REPO_SLUG):
    repo = validate_repo(repo)
    runner = runner or default_gh_runner()
    preflight(repo, runner)
    for verdict in VERDICTS:
        name, color, desc = LABELS[verdict]
        _mutate_once(["gh", "label", "create", name, "--color", color,
                      "--description", desc, "--force", "--repo", repo], runner)
        print("label   %s" % name)
    titles = json.loads(gh(["gh", "api", f"repos/{repo}/milestones?state=all",
                            "--jq", "[.[].title]"], runner=runner) or "[]")
    if not isinstance(titles, list) or not all(isinstance(t, str) for t in titles):
        raise ValueError("malformed milestone response")
    if MILESTONE in titles:
        print("milestone exists: %s" % MILESTONE)
    else:
        desc = "description=Ranked fix queue from the remediation triage arc — see %s" % SPEC
        _mutate_once(["gh", "api", "-X", "POST", f"repos/{repo}/milestones",
                      "-f", "title=%s" % MILESTONE, "-f", desc], runner)
        print("milestone created: %s" % MILESTONE)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_setup = sub.add_parser("setup")
    p_setup.add_argument("--repo", default=gh_transport.REPO_SLUG, type=validate_repo)
    p_apply = sub.add_parser("apply")
    p_apply.add_argument("--repo", default=gh_transport.REPO_SLUG, type=validate_repo)
    p_apply.add_argument("--dry-run", action="store_true")
    p_apply.add_argument("--throttle", type=float, default=1.5)
    a = ap.parse_args()
    if a.cmd == "setup":
        setup(repo=a.repo)
        return
    rows = load_rows()
    if not rows:
        sys.exit("no ledger at %s" % LEDGER)
    applied, stale = apply(rows, dry=a.dry_run, throttle=a.throttle,
                           repo=a.repo, ledger_path=LEDGER)
    print("applied %d; stale %d; ledger: %s" % (applied, stale, LEDGER))


if __name__ == "__main__":
    main()
