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

Usage:  python3 scripts/triage.py setup
        python3 scripts/triage.py apply [--dry-run] [--throttle S]
"""
import argparse
import datetime
import contextlib
import copy
import fcntl
import hashlib
import functools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
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


MAX_STATE_BYTES = 8 * 1024 * 1024
REPO_SLUG = "panopticon-scanner/panopticon"
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


def plan_mutations(row, repo=REPO_SLUG):
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


def is_stale(row, issue_state):
    # Both timestamps are UTC ISO-8601 "Z" strings; lexicographic compare.
    if issue_state.get("state") != "OPEN":
        return True
    return str(issue_state.get("updatedAt") or "") > str(row.get("triaged_at") or "")


RATE_HINTS = ("rate limit", "secondary rate", "abuse detection",
              "was submitted too quickly")


CONFIG_PATH = os.path.join(".panopticon", "config.json")


# #1650 / SEC-D1B (CWE-427). The `gh` invoked from this module performs
# authenticated issue comments, edits, closures, label creation and milestone
# mutation as the automation account, so WHICH binary that is may not be
# decided by whoever controls the ambient PATH: prepending one writable
# directory was enough to substitute the CLI, and the substitute inherits the
# credentials. These fixed system directories, plus the one below, are the only
# places looked.
TRUSTED_PATH = "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"


def trusted_path(home=None):
    """TRUSTED_PATH, plus the operator's own `~/.local/bin` -- LAST.

    R1/M2: the four system directories alone did not hold this project's `gh`
    (installed under `~/.local/bin`, as `pip --user` and a release tarball both
    do), so `triage.py apply` and `reconcile_apply.py` refused outright on the
    owner's own workstation -- the triage-apply half of the filing SOP.

    This is a widening, not a loosening: both halves are FIXED strings over a
    HOME this process chose, never `os.environ["PATH"]`, so the CWE-427
    property is unchanged -- an attacker who can prepend a directory to PATH
    still cannot substitute the binary. Appended last so a system install
    always wins over a per-user one.
    """
    home = home if home is not None else os.path.expanduser("~")
    if not home:
        return TRUSTED_PATH          # never a CWD-relative `.local/bin`
    return os.pathsep.join([TRUSTED_PATH, os.path.join(home, ".local", "bin")])


def gh_bin(home=None):
    """The absolute `gh` to launch, resolved against `trusted_path` and nothing else.

    `home` is the HOME the child will run under, so the directory searched is
    the one the launch will actually see; it defaults to this process's.

    Refuses rather than falling back to the bare name: a bare `gh` handed to
    subprocess is resolved by exactly the search this function exists to
    replace, so a fallback would reopen the door on every machine where the
    trusted resolution failed.
    """
    searched = trusted_path(home)
    found = shutil.which("gh", path=searched)
    if not found:
        raise RuntimeError(
            "gh is not on the trusted PATH (%s), and this tool will not resolve "
            "it through the ambient environment: install gh there, or run the "
            "mutation by hand" % searched)
    return found


def declared_gh_config_dir(config_path=None):
    """.panopticon/config.json's `gh_config_dir`, or None when it declares none.

    #486: the DECLARED account, so every gh subprocess the tools spawn uses it
    instead of whatever ambient credential the shell happens to carry (the
    thebeamishsociety wrong-account incident: default cred lacked push, the 404
    was swallowed). Raises on a corrupt/unreadable config or a non-string
    value, so we fail closed rather than silently inherit the wrong credential
    (#1101). A config that is absent, or names no directory, is not a failure
    -- it is the caller saying nothing, and `gh_env` decides what that means.
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
    if not isinstance(cfg, dict):
        raise ValueError(f"invalid config {config_path}: expected object")
    d = cfg.get("gh_config_dir")
    if d is None:
        return None
    if not isinstance(d, str) or not d:
        raise ValueError(f"invalid gh_config_dir in {config_path!r}: expected string, got {d!r}")
    return d


# What gh itself needs to decide WHICH ACCOUNT it is, and nothing else. Both
# are gh's own documented variables; everything else the shell carries
# (credentials for other services, a hostile PATH) stays out.
_GH_AUTH_PASSTHROUGH = ("GH_TOKEN",)


def gh_env(config_path=None):
    """The environment every gh subprocess runs under: BUILT, never copied.

    #1650: this used to return None (inherit everything) when no config
    declared a directory, and otherwise `dict(os.environ)` with one key
    changed -- so PATH passed through untouched in BOTH branches, and PATH is
    what chooses the binary.

    R1/M3: building it must not go so far as to lose the ACCOUNT. The repo's
    own config holds `{"gh_config_dir": null}`, so an operator exporting
    `GH_CONFIG_DIR=~/.config/gh-psyberone` was relying on inheritance; dropping
    it leaves gh on `$HOME/.config/gh`, the DEFAULT credential, which is the
    wrong account for this project -- exactly the incident #486 exists to
    prevent, reintroduced by the hardening meant to protect it. So:
    GH_CONFIG_DIR is declared-in-config first, ambient second, unset last.
    gh's own `GH_TOKEN` is carried through ONLY when no directory is in
    effect: gh lets an ambient token override stored credentials, so carrying
    it beside a declared directory would let the shell's account beat the
    declared one -- the precedence #486 forbids.

    Everything else is built: HOME (gh's own state) and the trusted PATH.
    """
    home = os.path.expanduser("~")
    env = {"HOME": home, "PATH": trusted_path(home)}
    directory = declared_gh_config_dir(config_path) or os.environ.get("GH_CONFIG_DIR")
    if directory:
        env["GH_CONFIG_DIR"] = os.path.expanduser(directory)
        return env
    for name in _GH_AUTH_PASSTHROUGH:
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


# Hard bound on each gh invocation so a hung gh (interactive auth prompt on a
# misconfigured GH_CONFIG_DIR, a stalled TLS handshake, a GitHub outage) engages
# the retry/backoff below instead of blocking the unattended pipeline (#1103).
GH_TIMEOUT = 120


def _run_gh(argv, **kwargs):
    """`subprocess.run` with argv[0] replaced by the trusted absolute `gh`.

    The call sites build `["gh", ...]` because that is what the command reads
    as; the resolution happens HERE, once, so no call site can spell it
    differently (#1650). Resolved against the HOME the child will actually run
    under, so the binary looked for and the binary launched agree.
    """
    home = (kwargs.get("env") or {}).get("HOME")
    return subprocess.run([gh_bin(home)] + list(argv)[1:], **kwargs)


def default_gh_runner():
    """subprocess.run partial carrying the config-declared env (#486), a hard
    timeout (#1103) and the trusted-path resolution (#1650). Kept as a factory
    so gh_env is re-read per call site construction -- tests inject their own
    runner and never hit this."""
    return functools.partial(_run_gh, env=gh_env(), timeout=GH_TIMEOUT)


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
          repo=REPO_SLUG, ledger_path=None, progress_path=None):
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


def setup(runner=None, repo=REPO_SLUG):
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
    p_setup.add_argument("--repo", default=REPO_SLUG, type=validate_repo)
    p_apply = sub.add_parser("apply")
    p_apply.add_argument("--repo", default=REPO_SLUG, type=validate_repo)
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
