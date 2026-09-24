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
(override with --progress). Receipts bind to the unique, ordered, exact-content
plan: retries skip acknowledged operations, including completed plans. Use
--reset-progress to intentionally replay a plan or bind a changed/reordered plan.
Valid v1 receipts migrate by keeping only exact acknowledgements in this plan.
Dry runs preview unique requested actions without receipt I/O (including resets).
Empty live plans are no-ops; explicit live reset requires a nonempty plan to
identify the repository and replacement binding.
Comment intent is durable before one bounded mutation attempt. Unacknowledged
comments require a complete exact remote marker match; inconclusive probes block
replay. Direct live callers must supply progress_path. Close remains idempotent.
This is resume support, not an exactly-once protocol.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess  # noqa: F401 -- patch target for the dry-run zero-subprocess guard test
import sys
import tempfile
import time
from datetime import datetime, timezone

import file_issues
import triage

LEDGER = ".panopticon/filed-issues.json"
PROGRESS_VERSION = 2
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


class IncompleteRecovery(RuntimeError):
    """The fetched evidence cannot establish a complete, lossless ledger."""


def _repo_slug(repo):
    if not isinstance(repo, str) or re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) is None:
        raise ValueError("repo must be an explicit OWNER/REPO slug")
    if any(part in (".", "..") for part in repo.split("/")):
        raise ValueError("invalid repository slug")
    return repo


def _source_records(reports, source_roots):
    # A mapping binds a relocated copy to the exact original artifact pointer.
    items = list(reports.items()) if isinstance(reports, dict) else [(str(p), p) for p in reports]
    roots = list(source_roots or [])
    if roots and len(roots) != len(items):
        raise ValueError("--source-root must be paired with every --report, in order")
    indexed = {}
    for index, (artifact, path) in enumerate(items):
        root = roots[index] if roots else None
        if root is not None and not os.path.isabs(root):
            raise ValueError("source root must be absolute")
        report = file_issues._reconcile.load_report(path)
        pointer = file_issues.scrub(str(artifact))
        if pointer in indexed:
            raise IncompleteRecovery("conflicting source report artifact: " + pointer)
        records = {}
        for rejected, field in ((False, "findings"), (True, "discarded_claims")):
            for original in report[field]:
                if not isinstance(original, dict):
                    raise IncompleteRecovery("malformed source report record")
                record = dict(original)
                location = dict(record.get("location") or {})
                location_file = location.get("file") or ""
                if not isinstance(location_file, str):
                    raise IncompleteRecovery("malformed source location")
                if os.path.isabs(location_file):
                    prefix = (root or file_issues.repo_root()).rstrip("/") + "/"
                    if not location_file.startswith(prefix):
                        raise IncompleteRecovery("absolute source path requires its original --source-root")
                    location["file"] = location_file[len(prefix):]
                    record["location"] = location
                identity = (record.get("fingerprint"), record.get("id"), rejected)
                if (not all(isinstance(v, str) and v for v in identity[:2])
                        or identity in records):
                    raise IncompleteRecovery("missing or conflicting source report identity")
                records[identity] = record
        indexed[pointer] = records
    return indexed


_ARTIFACT_RE = re.compile(r"^\*\*Report artifact:\*\* \[(.*?)\]\(", re.MULTILINE)
_LOCATION_RE = re.compile(r"^\*\*Location:\*\* `([^`]+)`$", re.MULTILINE)


def _recovered_key(body, rejected, sources):
    captures = [pattern.findall(body) for pattern in (FP_RE, ID_RE, _LOCATION_RE)]
    if any(len(values) != 1 for values in captures):
        raise IncompleteRecovery("missing or conflicting issue identity/location")
    fp, finding_id, presented = (values[0] for values in captures)
    pointers = _ARTIFACT_RE.findall(body)
    if len(pointers) > 1:
        raise IncompleteRecovery("conflicting report artifact pointers")
    records = sources.get(pointers[0]) if pointers else None
    if records is not None:
        record = records.get((fp, finding_id, rejected))
        if record is None:
            raise IncompleteRecovery("issue identity missing from source report")
        expected = _LOCATION_RE.findall(file_issues.scrub(file_issues.body_for(record, rejected)))
        if expected != [presented]:
            raise IncompleteRecovery("source report location conflicts with issue presentation")
        return file_issues.key_for(record, rejected)
    # U+200B may be literal or inserted: stripping it is never lossless. Quotes,
    # redaction and numeric colon suffixes likewise have multiple preimages.
    if ("\u200b" in presented or "'" in presented or "[REDACTED" in presented
            or re.search(r":\d+$", presented) or presented == "(no file)"
            or file_issues.defang(presented) != presented):
        raise IncompleteRecovery("ambiguous location requires an authoritative source report")
    return file_issues.key_for({"fingerprint": fp, "id": finding_id,
        "location": {"file": presented}}, rejected)


def recover_linkage_from_github(label="self-scan", runner=None, *,
                                repo=file_issues.REPO_SLUG, reports=(), source_roots=()):
    """Return complete linkage or refuse; issue locations are presentation text."""
    repo = _repo_slug(repo)
    runner = runner or triage.default_gh_runner()
    try:
        sources = _source_records(reports, source_roots)
        result = runner(["gh", "issue", "list", "--repo", repo, "--label", label,
                         "--state", "all", "--json", "number,url,body,labels", "--limit", "1000"],
                        capture_output=True, text=True)
        if result.returncode != 0:
            raise IncompleteRecovery("gh issue list failed: " + (result.stderr or ""))
        # Ordinary issue-list pagination (no --search) has no search envelope;
        # a full requested cap cannot establish completeness.
        issues = json.loads(result.stdout)
        if not isinstance(issues, list) or len(issues) >= 1000:
            raise IncompleteRecovery("malformed or incomplete issue list (1000-item cap)")
        linkage = {}
        seen_urls = set()
        for issue in issues:
            if (not isinstance(issue, dict) or not isinstance(issue.get("body"), str)
                    or type(issue.get("number")) is not int or issue["number"] < 1
                    or not isinstance(issue.get("labels"), list)
                    or any(not isinstance(label, dict) or not isinstance(label.get("name"), str)
                           for label in issue["labels"])):
                raise IncompleteRecovery("malformed issue response")
            url = "https://github.com/%s/issues/%d" % (repo, issue["number"])
            if issue.get("url", url) != url or url in seen_urls:
                raise IncompleteRecovery("conflicting issue URL or repository")
            rejected = any(label["name"] == "false-positive" for label in issue["labels"])
            key = _recovered_key(issue["body"], rejected, sources)
            if key in linkage:
                raise IncompleteRecovery("conflicting recovered identity")
            linkage[key] = url
            seen_urls.add(url)
        return linkage
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError) as exc:
        raise IncompleteRecovery("incomplete recovery: %s" % exc) from exc


@contextlib.contextmanager
def _exclusive_path(path, create_directory=False):
    """Stable sibling lock; open every directory component without symlinks."""
    absolute = os.path.abspath(path)
    directory, name = os.path.split(absolute)
    directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in filter(None, directory.split("/")):
            if create_directory:
                try:
                    os.mkdir(component, dir_fd=directory_fd)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child
        fd = os.open(name + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=directory_fd)
        with os.fdopen(fd, "a") as lock:
            if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
                raise ValueError("unsafe lock file")
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield directory_fd, name
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
    finally:
        os.close(directory_fd)


def save_recovered_ledger(linkage, path=LEDGER, *, replace=False):
    """Create v2 output, or explicitly replace under lock after exact backup."""
    envelope = {"schema_version": file_issues.LEDGER_SCHEMA_VERSION, "entries": linkage}
    file_issues._unwrap_ledger(envelope, str(path))
    data = (json.dumps(envelope, indent=1, sort_keys=True) + "\n").encode("utf-8")
    with _exclusive_path(path, create_directory=True) as (directory, name):
        old = None
        try:
            mode = os.stat(name, dir_fd=directory, follow_symlinks=False).st_mode
        except FileNotFoundError:
            pass
        else:
            if not stat.S_ISREG(mode):
                raise ValueError("unsafe ledger output: expected regular file")
            if not replace:
                raise FileExistsError("ledger exists; use --replace-ledger for backed-up replacement")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            with os.fdopen(fd, "rb") as existing:
                old = existing.read()
        token = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ") + "-" + os.urandom(8).hex()
        if old is not None:
            backup = name + "." + token + ".bak"
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, "wb") as fh:
                fh.write(old)
                fh.flush()
                os.fsync(fh.fileno())
            os.fsync(directory)
        temporary = ".reconcile-ledger-" + token
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            if replace:
                os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            else:
                os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory,
                        follow_symlinks=False)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass


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


def _unique_actions(actions):
    """Validate the whole plan and collapse exact duplicates in original order."""
    if not isinstance(actions, list):
        raise ValueError("actions must be a list")
    unique: dict[str, dict] = {}
    for action in actions:
        if (not isinstance(action, dict)
                or not all(isinstance(action.get(k), str) for k in ("issue", "comment", "cohort"))
                or type(action.get("close")) is not bool
                or re.fullmatch(r"https?://github\.com/[^/]+/[^/]+/issues/[1-9][0-9]*/?",
                                action["issue"]) is None):
            raise ValueError("invalid plan action (expected issue URL, comment, cohort and close)")
        try:
            key = _action_key(action, "")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError("invalid plan action: %s" % exc) from exc
        unique.setdefault(key, action)
    return list(unique.values())


def _plan_hash(repo_slug, action_keys):
    """Hash ordered exact-action identities; duplicates have already collapsed."""
    canonical = json.dumps({"repo": repo_slug, "actions": action_keys}, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_progress(path, repo_slug):
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory) or os.path.islink(directory):
        raise ValueError("unsafe progress directory: %s" % directory)
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return None
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
    if (not isinstance(loaded, dict) or type(loaded.get("version")) is not int
            or loaded["version"] not in (1, PROGRESS_VERSION)
            or loaded.get("repo") != repo_slug or not isinstance(loaded.get("actions"), dict)):
        raise ValueError("invalid progress schema or repository: %s" % path)
    fields = {"version", "repo", "actions"}
    if loaded["version"] == PROGRESS_VERSION:
        fields |= {"plan", "plan_hash"}
    if set(loaded) != fields:
        raise ValueError("invalid progress schema: %s" % path)
    if loaded["version"] == PROGRESS_VERSION:
        plan = loaded["plan"]
        if (not isinstance(plan, list)
                or any(not isinstance(k, str) or re.fullmatch(r"[0-9a-f]{64}", k) is None
                       for k in plan)
                or len(set(plan)) != len(plan)
                or loaded["plan_hash"] != _plan_hash(repo_slug, plan)
                or not set(loaded["actions"]).issubset(plan)):
            raise ValueError("invalid progress plan or extra action keys: %s" % path)
    for key, receipt in loaded["actions"].items():
        if (not isinstance(key, str) or re.fullmatch(r"[0-9a-f]{64}", key) is None
                or not isinstance(receipt, dict)
                or set(receipt) not in ({"commented", "closed"},
                                        {"commented", "closed", "comment_pending"})
                or ("comment_pending" in receipt and (receipt["comment_pending"] is not True
                                                     or receipt.get("commented") is not False))
                or type(receipt["commented"]) is not bool
                or type(receipt["closed"]) is not bool
                or (receipt["closed"] and not receipt["commented"])):
            raise ValueError("invalid progress acknowledgement: %s" % path)
    return loaded


def _bind_progress(loaded, repo_slug, action_keys, reset):
    """Validate old binding before reset; prune history only at migration/reset."""
    plan_hash = _plan_hash(repo_slug, action_keys)
    if loaded is not None and loaded["version"] == PROGRESS_VERSION:
        if not reset:
            if loaded["plan_hash"] != plan_hash:
                raise ValueError("progress belongs to a changed/reordered plan; use --reset-progress")
            return loaded
    acknowledgements = {}
    if loaded is not None and not reset:
        acknowledgements = {key: loaded["actions"][key] for key in action_keys
                            if key in loaded["actions"]}
    return {"version": PROGRESS_VERSION, "repo": repo_slug, "plan": action_keys,
            "plan_hash": plan_hash, "actions": acknowledgements}


def _progress_bytes(progress):
    data = (json.dumps(progress, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(data) > PROGRESS_MAX_BYTES:
        raise ValueError("progress file too large for pending acknowledgements")
    return data


def _reserve_progress(progress, action_keys):
    # Reserve the largest possible intermediate state before any remote call.
    # Pending intent is larger than acknowledgement; reserve it for every
    # unacknowledged comment before auth or mutation. Duplicate keys collapse.
    reserved = dict(progress["actions"])
    for key in action_keys:
        if key not in reserved or not reserved[key]["commented"]:
            reserved[key] = {"commented": False, "closed": False, "comment_pending": True}
    _progress_bytes(dict(progress, actions=reserved))


def _save_progress(progress, path):
    """Replace a receipt in its own directory after each successful gh call."""
    data = _progress_bytes(progress)
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".reconcile-progress-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
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


class _ApplyRefused(ValueError):
    """Execution refusal distinguished from a successful zero-operation apply."""


def apply(actions, dry=True, confirm_close=False, throttle=1.5,
         runner=None, sleep=time.sleep, progress_path=None, reset_progress=False):
    """Return counts of operations performed in this invocation.

    With progress_path, live runs resume successful comments/closes for one
    unique ordered plan. reset_progress clears acknowledgements for deliberate
    replay/rebinding, after validating the existing receipt and authorization.
    Dry runs display unique requested actions and never read or write progress.
    Pending comments require positive remote reconciliation before continuing;
    no automatic replay occurs after a timeout or process death.

    For compatibility, authorization/mixed-repository refusals print a diagnostic
    and return (0, 0). The CLI uses _apply directly to distinguish these refusals
    from completed resumes and empty no-ops.
    """
    try:
        return _apply(actions, dry, confirm_close, throttle, runner, sleep,
                      progress_path, reset_progress)
    except _ApplyRefused as exc:
        print("refusing: %s" % exc)
        return (0, 0)


def _comment_body(action, repo):
    return action["comment"] + "\n\n<!-- panopticon-reconcile:" + _action_key(action, repo) + " -->"


def _comment_present(runner, repo, number, body):
    """A full page or any malformed/conflicting result is inconclusive."""
    try:
        result = runner(["gh", "api", "repos/%s/issues/%s/comments?per_page=100" % (repo, number)],
                        capture_output=True, text=True)
        comments = json.loads(result.stdout) if result.returncode == 0 else None
        if (not isinstance(comments, list) or len(comments) >= 100
                or any(not isinstance(c, dict) or not isinstance(c.get("body"), str)
                       for c in comments)):
            return False
        marker = body.rsplit("\n\n", 1)[1]
        matching = [c["body"] for c in comments if marker in c["body"]]
        return matching == [body]
    except (OSError, subprocess.SubprocessError, ValueError, TypeError):
        return False


def _apply(actions, dry=True, confirm_close=False, throttle=1.5,
           runner=None, sleep=time.sleep, progress_path=None, reset_progress=False):
    actions = _unique_actions(actions)
    # Serialize receipt read, intent, mutation and acknowledgement as one unit.
    # Empty plans and dry runs retain their existing no-I/O behavior.
    if not dry and actions and progress_path is not None:
        _load_progress(progress_path, "%s/%s" % _owner_repo(actions[0].get("issue", "")))
        with _exclusive_path(progress_path):
            return _apply_locked(actions, dry, confirm_close, throttle, runner, sleep,
                                 progress_path, reset_progress)
    return _apply_locked(actions, dry, confirm_close, throttle, runner, sleep,
                         progress_path, reset_progress)


def _apply_locked(actions, dry=True, confirm_close=False, throttle=1.5,
           runner=None, sleep=time.sleep, progress_path=None, reset_progress=False):
    """Execute once, raising on refusal so callers can choose their interface."""
    actions = _unique_actions(actions)
    if reset_progress and not dry and progress_path is None:
        raise ValueError("--reset-progress requires a receipt path for live apply")
    if reset_progress and not dry and not actions:
        raise ValueError("--reset-progress requires a nonempty plan to identify the repository")
    if reset_progress and dry:
        print("DRY reset-progress: previewing replay; receipt unchanged")
    if not dry and actions and progress_path is None:
        raise ValueError("live comments require progress_path for durable intent and recovery")
    runner = runner or triage.default_gh_runner()
    commented = closed = 0
    repo_slug = None
    progress = None
    action_keys = []
    if not dry and actions:
        owner, repo = _owner_repo(actions[0]["issue"])
        if any(_owner_repo(a["issue"]) != (owner, repo) for a in actions):
            raise _ApplyRefused("actions span multiple repos; expected all in %s/%s"
                                % (owner, repo))
        repo_slug = "%s/%s" % (owner, repo)
        if progress_path is not None:
            loaded = _load_progress(progress_path, repo_slug)
            action_keys = [_action_key(a, repo_slug) for a in actions]
            progress = _bind_progress(loaded, repo_slug, action_keys, reset_progress)
            _reserve_progress(progress, action_keys)
        ok, reason = preflight_authorized(owner, repo, runner=runner)
        if not ok:
            raise _ApplyRefused("authenticated gh user is not an owner/admin of %s/%s — %s"
                                % (owner, repo, reason))
        if progress is not None:
            # Persist initial binding, migration or reset only after read-only auth,
            # and before any GitHub mutation. Failure leaves remote state untouched.
            _save_progress(progress, progress_path)
            if loaded is not None and loaded["version"] == 1:
                print("migrated progress receipt v1 -> v2; bound to selected plan")
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
        if receipt is not None and not receipt["commented"]:
            body = _comment_body(a, repo_slug)
            if receipt.get("comment_pending"):
                if not _comment_present(runner, repo_slug, n, body):
                    raise RuntimeError("comment pending; complete exact remote reconciliation required")
                receipt.pop("comment_pending")
                receipt["commented"] = True
                _save_progress(progress, progress_path)
            else:
                receipt["comment_pending"] = True
                _save_progress(progress, progress_path)
                failure = None
                try:
                    result = runner(["gh", "issue", "comment", n, "--repo", repo_slug,
                                     "--body", body], capture_output=True, text=True)
                    if result.returncode != 0:
                        failure = result.stderr or "comment failed"
                except (OSError, subprocess.SubprocessError) as exc:
                    failure = str(exc)
                if failure is not None and not _comment_present(runner, repo_slug, n, body):
                    raise RuntimeError("comment pending; refusing replay: %s" % failure)
                receipt.pop("comment_pending")
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
    p_rec.add_argument("--repo", type=_repo_slug, default=file_issues.REPO_SLUG)
    p_rec.add_argument("--report", action="append", default=[], metavar="[ARTIFACT=]PATH",
                       help="authoritative report; bind a relocated copy with ARTIFACT=PATH")
    p_rec.add_argument("--source-root", action="append", default=[],
                       help="original absolute root, paired with each --report in order")
    p_rec.add_argument("--replace-ledger", action="store_true")

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
    p_apply.add_argument("--reset-progress", action="store_true",
                         help="intentionally replay/rebind the plan after receipt validation; "
                              "dry runs preview replay without receipt I/O")

    a = ap.parse_args(argv)

    if a.cmd == "recover-linkage":
        try:
            reports = {}
            for value in a.report:
                artifact, separator, local = value.partition("=")
                if artifact in reports:
                    raise ValueError("duplicate report artifact")
                reports[artifact] = local if separator else artifact
            linkage = recover_linkage_from_github(label=a.label, repo=a.repo,
                                                  reports=reports, source_roots=a.source_root)
            save_recovered_ledger(linkage, path=a.out, replace=a.replace_ledger)
        except (ValueError, OSError, RuntimeError) as exc:
            print("refusing: %s" % exc, file=sys.stderr)
            return 1
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
        try:
            with open(a.actions_json, encoding="utf-8") as fh:
                actions = json.load(fh)
            commented, closed = _apply(actions, dry=a.dry_run, confirm_close=a.confirm_close,
                                      throttle=a.throttle, reset_progress=a.reset_progress,
                                      progress_path=a.progress or a.actions_json + ".progress.json")
        except (ValueError, OSError, RuntimeError) as exc:
            print("refusing: %s" % exc, file=sys.stderr)
            return 1
        print("%s: commented %d, closed %d"
             % ("DRY RUN" if a.dry_run else "LIVE", commented, closed))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
