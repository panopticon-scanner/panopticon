#!/usr/bin/env python3
"""File panopticon self-scan findings as GitHub issues.

One issue per finding. Every body carries the finding's `fingerprint` (the
cross-run identity) and a pointer to the generating report artifact, or the
round trip does not close. Advisor-rejected claims are filed too, labelled
`evidence:rejected` + `false-positive` — kept so the fleet can be measured
against them rather than silently dropped.

Usage:  python3 .panopticon/file_issues.py [--dry-run] [--limit N]
"""
import argparse
import contextlib
import functools
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from types import ModuleType
from urllib.parse import urlencode

try:
    import fcntl as _fcntl     # POSIX only; the ledger lock degrades without it
    fcntl: ModuleType | None = _fcntl
except ImportError:            # pragma: no cover - not reachable on posix CI
    fcntl = None

import triage
from sanitize import repo_root, repo_relative, scrub, defang

# skill/scripts/reconcile.py owns the part-path confinement. This filer used to
# carry its own copy, which never received the #run9 SEC-D1C realpath hardening
# (#1523) -- so import the one implementation rather than mirroring it again.
_SKILL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "skill")
if _SKILL not in sys.path:
    sys.path.insert(0, _SKILL)
import scripts.reconcile as _reconcile  # noqa: E402

__all__ = ["repo_root", "repo_relative", "scrub", "defang"]

# Defaults describe run 2 (the first filed self-scan). Each subsequent scan —
# the cadence is a fresh self-scan every Saturday — passes its own --report,
# --report-url, --run-label, --run-date, and --run-state-doc, so no code edit
# is needed to file a new run. Defaults are kept only for backward-compatibility
# and to keep body_for() callable with a bare finding in tests.
REPORT = "docs/superpowers/2026-08-04-self-scan-report.json"
REPORT_URL = ("https://github.com/panopticon-scanner/panopticon/blob/main/"
              "docs/superpowers/2026-08-04-self-scan-report.json")
RUN_LABEL = "run 2"
RUN_DATE = "2026-08-04"
RUN_STATE_DOC = "docs/superpowers/2026-08-04-self-scan-run-state.md"

SEV_LABEL = {"CRITICAL": "severity:critical", "HIGH": "severity:high",
             "MEDIUM": "severity:medium", "LOW": "severity:low",
             "INFO": "severity:info"}
EV_LABEL = {"tool_reported": "evidence:tool-reported",
            "tool_confirmed": "evidence:tool-confirmed",
            "advisor_confirmed": "evidence:advisor-confirmed",
            "corroborated": "evidence:corroborated",
            "needs_more_info": "evidence:needs-more-info",
            "unverified": "evidence:unverified",
            "rejected": "evidence:rejected",
            "backup_scope_limited": "evidence:backup-scope-limited"}


def labels_for(f, rejected=False):
    out = ["self-scan"]
    out.append(SEV_LABEL.get(str(f.get("severity", "INFO")).upper(), "severity:info"))
    status = (f.get("evidence") or {}).get("status", "unverified")
    out.append(EV_LABEL.get(status, "evidence:unverified"))
    panel = f.get("panel")
    if panel:
        out.append("panel:%s" % panel)
    if rejected:
        out.append("false-positive")
    # Cosmetic = consistency-only. Filed for completeness, not priority.
    if not rejected and (f.get("category") == "style"
                         or str(f.get("severity")).upper() == "INFO"):
        out.append("cosmetic")
    return out


def title_for(f):
    loc = f.get("location") or {}
    fname = defang((loc.get("file") or "").split("/")[-1])
    t = defang(f.get("short_title") or f.get("title") or "(untitled)")
    suffix = " (%s)" % fname if fname else ""
    room = 240 - len(suffix)
    if len(t) > room:
        t = t[:room - 1].rstrip() + "…"
    return t + suffix


def body_for(f, rejected=False, report=REPORT, report_url=REPORT_URL,
             run_label=RUN_LABEL, run_date=RUN_DATE, run_state_doc=RUN_STATE_DOC):
    loc = f.get("location") or {}
    ev = f.get("evidence") or {}
    prov = f.get("provenance") or {}
    # #run7 COD-C3A: fingerprint + id are the report<->issue round-trip identity
    # (reconcile_apply's FP_RE/ID_RE require a non-empty capture). Rendering an
    # empty value as empty backticks silently breaks recovery -- the issue drops
    # out of the recovered ledger. Fail loud instead of filing an unrecoverable
    # issue. (The normal synthesize path always stamps both, so this only fires on
    # a malformed / hand-built report.)
    if not (f.get("fingerprint") and f.get("id")):
        raise ValueError(
            "cannot file issue %r: missing round-trip identity (fingerprint=%r "
            "id=%r)" % (f.get("title") or "?", f.get("fingerprint"), f.get("id")))
    L = []
    if rejected:
        L.append("> **An advisor refuted this claim.** It is filed for the audit "
                 "trail, not as work to do. Severity below is the *claimed* "
                 "severity — panopticon never rewrites a severity on rejection, "
                 "so that a wrong rejection stays visible.\n")
    where = defang(loc.get("file") or "(no file)").replace("`", "'")
    if loc.get("line_start"):
        where += ":%s" % loc["line_start"]
    L.append("**Location:** `%s`" % where)
    if f.get("occurrences", 1) > 1:
        L.append("**Occurrences:** %d loci of this rule in this file "
                 "(primary above)" % f["occurrences"])
        for a in (f.get("additional_loci") or []):
            L.append("  - `%s:%s`" % (defang(a.get("file") or "").replace("`", "'"),
                                      a.get("line_start")))
    L.append("**Severity (impact if true):** %s   **Evidence:** `%s`   "
             "**Confidence:** %s" % (defang(f.get("severity")), defang(ev.get("status")),
                                     defang(f.get("confidence"))))
    src = defang(prov.get("discovered_by") or f.get("source") or "unknown")
    L.append("**Found by:** %s%s" % (src, "  ·  model: %s" % defang(prov["model"])
                                     if prov.get("model") else ""))
    cites = f.get("citations") or {}
    flat = []
    for k in ("cwe", "owasp", "cve"):
        for c in (cites.get(k) or []):
            cid = defang(c if isinstance(c, str) else c.get("id", str(c))).replace("`", "'")
            flat.append(cid)
    if flat:
        L.append("**Citations:** %s" % ", ".join(flat))
    L.append("\n## What was found\n\n%s" % defang(f.get("description") or "(none)"))
    if f.get("impact"):
        L.append("\n## Impact\n\n%s" % defang(f["impact"]))
    if f.get("exploit_scenario"):
        L.append("\n## Exploit scenario\n\n%s" % defang(f["exploit_scenario"]))
    if f.get("remediation"):
        L.append("\n## Suggested remediation\n\n%s" % defang(f["remediation"]))
    reasoning = ev.get("reasoning") or prov.get("confirmation_reasoning")
    if reasoning and str(reasoning) != str(f.get("category")):
        verb = "Advisor verdict" if not rejected else "Advisor rejection"
        L.append("\n## %s\n\n%s" % (verb, defang(reasoning)))
    if ev.get("verified_by"):
        verified_by = ev["verified_by"]
        # #run11 COD-D3C: derive_evidence returns this as a LIST in some
        # branches and a bare STRING in others ("tool:bandit", "agent:advisor").
        # Iterating a string yields CHARACTERS, so the public issue body read
        # "a, g, e, n, t, :, a, ..." -- one identity is a one-element list.
        if isinstance(verified_by, str):
            verified_by = [verified_by]
        L.append("\n**Corroborating panels:** %s" % ", ".join(
            defang(str(x)) for x in verified_by))
    L.append("\n---\n")
    fp = defang(f.get("fingerprint") or "").replace("`", "'")
    L.append("**Fingerprint:** `%s` — stable cross-run identity; excludes line "
             "numbers and free-text so this issue survives code moves and "
             "re-wordings." % fp)
    fid = defang(f.get("id") or "").replace("`", "'")
    L.append("**Finding id in report:** `%s`" % fid)
    L.append("**Report artifact:** [%s](%s) (self-scan %s, %s, "
             "`tool_policy_mode: enforced`)" % (report, report_url,
                                                run_label, run_date))
    L.append("\n*Filed automatically from a panopticon self-scan. Coverage for "
             "this run is stated in `%s`.*" % run_state_doc)
    return "\n".join(L)


REPO_SLUG = "panopticon-scanner/panopticon"


LEDGER = ".panopticon/filed-issues.json"

# #run11 DAT-F2A: the ledger used to be a bare {key: url} map with no version,
# so a key-format change was detected by COUNTING '|' fields -- and a key the
# heuristic misread (a corrupt one, a future shape, or a sibling filer's
# '|'-free id) was carried through unmigrated and silently orphaned, never again
# recognised as already-filed. v2 states the format instead of sniffing it.
LEDGER_SCHEMA_VERSION = 2


def normalize_ledger(raw_ledger):
    """Normalize legacy ledger keys (e.g. absolute paths) to canonical repo-relative keys (#1124)."""
    migrated = {}
    for k, v in raw_ledger.items():
        parts = k.split("|")
        if len(parts) == 4:
            fp, fid, path_part, kind = parts
            migrated_key = "%s|%s|%s|%s" % (fp, fid, repo_relative(path_part), kind)
            migrated[migrated_key] = v
        else:
            migrated[k] = v
    return migrated


def _unwrap_ledger(data, path):
    """Entries out of either ledger shape.

    v2 states its version, so its keys are taken AS WRITTEN -- no '|'-counting.
    A bare map is the legacy v1 shape and gets the one-time key migration."""
    if not isinstance(data, dict):
        raise RuntimeError(
            "ledger %s must be a JSON object, got %s; refusing to treat a "
            "present ledger as empty. Restore or repair it before filing."
            % (path, type(data).__name__))
    if "schema_version" in data:
        version = data.get("schema_version")
        if type(version) is not int:
            raise RuntimeError(
                "ledger %s has non-integer schema_version %r; restore or repair "
                "it before filing." % (path, version))
        if version != LEDGER_SCHEMA_VERSION:
            raise RuntimeError(
                "ledger %s declares schema_version %r, but this filer speaks %d. "
                "%s Reading it anyway would mis-key the dedup state and re-file "
                "findings as duplicate public issues. Restore a supported ledger "
                "or upgrade this filer."
                % (path, version, LEDGER_SCHEMA_VERSION,
                   "A newer filer wrote it." if version > LEDGER_SCHEMA_VERSION
                   else "This version is unsupported."))
        entries = data.get("entries")
        if not isinstance(entries, dict):
            raise RuntimeError(
                "ledger %s must have an entries object, got %s; restore or "
                "repair it before filing." % (path, type(entries).__name__))
    else:
        entries = data
    for key, url in entries.items():
        if not isinstance(key, str) or not isinstance(url, str):
            raise RuntimeError(
                "ledger %s has an invalid entry at key %r: expected a string "
                "key mapped to an issue URL string; restore or repair it "
                "before filing." % (path, key))
    if "schema_version" in data:
        return dict(entries)
    return normalize_ledger(data)


def load_ledger(path=LEDGER):
    """Filing is resumable: a run that dies partway must not re-file.

    Parameterized on the ledger path so sibling filers (file_fixmes,
    reconcile_apply) share this machinery instead of copying it."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return _unwrap_ledger(data, path)
    except FileNotFoundError:
        return {}                    # no ledger yet -> legitimate first run
    except (OSError, ValueError) as e:
        # #run9 COD-B1A: a CORRUPT or unreadable (but PRESENT) ledger is NOT an
        # empty one. Returning {} reset the dedup state, so main()'s
        # `key_for(f, rej) not in ledger` treated every already-filed finding as
        # new and RE-FILED it -- mass duplicates. Fail loud so the operator
        # restores/repairs the ledger; deleting it deliberately (-> FileNotFound
        # above) is the explicit way to start fresh.
        raise RuntimeError(
            "ledger %s is present but unreadable/corrupt (%s); refusing to proceed "
            "-- treating it as empty would re-file every finding as a duplicate. "
            "Restore it, or delete it deliberately to start fresh." % (path, e)) from e


@contextlib.contextmanager
def _ledger_lock(path):
    """Exclusive lock for one read-modify-write of the ledger.

    Without it two filers each read the ledger at start-up and whichever wrote
    last erased the other's entries (#run11 DAT-F1C) -- and a lost entry is a
    DUPLICATE public issue on the next run. The lock lives beside the ledger
    rather than on it, so it survives the atomic os.replace below."""
    if fcntl is None:                      # pragma: no cover - posix in CI
        yield
        return
    with open(path + ".lock", "a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def record(ledger, key, url, path=LEDGER):
    """Add one entry, merging whatever else reached the file meanwhile.

    The caller's dict is a snapshot taken at start-up; re-reading under the lock
    is what keeps a concurrent filer's entries from being erased by this write.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with _ledger_lock(path):
        try:
            with open(path, encoding="utf-8") as fh:
                merged = _unwrap_ledger(json.load(fh), path)
        except FileNotFoundError:
            merged = {}
        except ValueError as e:
            # A corrupt ledger must not be silently flattened into this write
            # -- that would drop every entry it still holds (#run9 COD-B1A).
            raise RuntimeError(
                "ledger %s is present but unreadable/corrupt (%s); refusing to "
                "overwrite it. Restore or repair it before filing." % (path, e)) from e
        merged = {**ledger, **merged}
        if key in merged and merged[key] != url:
            raise RuntimeError("ledger key already has a different URL; reconcile before filing")
        merged[key] = url
        _atomic_json(path, {"schema_version": LEDGER_SCHEMA_VERSION, "entries": merged})
    ledger.update(merged)


def make_ledger_key(fingerprint, finding_id, location_file, kind):
    """Canonical 4-part ledger key format (#607/#488/#1122)."""
    return "%s|%s|%s|%s" % (
        fingerprint or "",
        finding_id or "",
        repo_relative(location_file or "") if location_file else "",
        kind or ""
    )


# The hardened original (#1122 confinement + #run9 SEC-D1C symlink
# re-confinement), not a copy: this filer publishes to permanent public issues,
# so a part that resolves outside the report directory must not be openable
# here either (#1523).
resolve_part_path = _reconcile._resolve_part_path


def key_for(f, rejected):
    loc = f.get("location") or {}
    return make_ledger_key(
        f.get("fingerprint"),
        f.get("id"),
        loc.get("file"),
        "rejected" if rejected else "finding"
    )


# Hard bound on the network `gh issue create` call so a hung gh (network
# partition, GitHub slowness, auth prompt) cannot block the filing run
# indefinitely (#1104). Ambiguous acceptance must only be reconciled.
GH_CREATE_TIMEOUT = 60


def _gh_bin():
    """The same trusted resolution `scripts/triage.py` uses (#1650 R1).

    This module CREATES public issues as the automation account, so resolving
    its `gh` off the ambient PATH was the same CWE-427 shape triage was
    hardened against -- and it left the odd halfway state of a built env
    beside an unhardened argv[0] in the same `subprocess.run`.
    """
    return triage.gh_bin()


def validate_repo(repo):
    if not isinstance(repo, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*", repo):
        raise ValueError("repository must be an explicit owner/name slug")
    return repo


def _issue_url(url, repo):
    return isinstance(url, str) and re.fullmatch(
        r"https://github\.com/" + re.escape(repo) + r"/issues/[1-9][0-9]*", url) is not None


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _atomic_json(path, value):
    # Every caller holds the stable ledger lock, including pending writes.
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=1, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    fd = os.open(os.path.dirname(path) or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _intent(repo, kind, key, title, body, labels):
    identity = _digest([repo, kind, key])
    marker = "<!-- panopticon-create:%s -->" % _digest(
        [repo, kind, key, title, body, labels])
    return identity, dict(repo=repo, kind=kind, key=key, title=title,
                          content=body, body=body + "\n\n" + marker,
                          labels=labels, marker=marker, state="pending", url=None)


def _load_pending(path):
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise RuntimeError("pending ledger unreadable; restore or reconcile " + path) from exc
    try:
        if (not isinstance(data, dict) or type(data.get("schema_version")) is not int
                or data["schema_version"] != 1 or not isinstance(data.get("entries"), dict)):
            raise ValueError("invalid envelope")
        for identity, entry in data["entries"].items():
            if not isinstance(entry, dict):
                raise ValueError("invalid entry")
            for field in ("repo", "kind", "key", "title", "content", "body", "marker"):
                if not isinstance(entry.get(field), str):
                    raise ValueError("invalid " + field)
            validate_repo(entry["repo"])
            if (entry["kind"] not in ("finding", "fixme") or not entry["key"]
                    or not isinstance(entry.get("labels"), list)
                    or not all(isinstance(label, str) for label in entry["labels"])):
                raise ValueError("invalid identity or labels")
            expected_id, expected = _intent(entry["repo"], entry["kind"], entry["key"],
                                            entry["title"], entry["content"], entry["labels"])
            if identity != expected_id or any(entry.get(k) != v for k, v in expected.items()
                                               if k not in ("state", "url")):
                raise ValueError("intent content or identity mismatch")
            if entry.get("state") == "complete":
                if not _issue_url(entry.get("url"), entry["repo"]):
                    raise ValueError("invalid completion URL")
            elif entry.get("state") != "pending" or entry.get("url") is not None:
                raise ValueError("invalid pending state")
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeError("malformed pending ledger; restore or reconcile " + path) from exc
    return data["entries"]


def load_filing_ledger(path, repo):
    """Validate both files and the target before CLI filtering can skip a key."""
    ledger = load_ledger(path)
    pending = _load_pending(path + ".pending.json")
    if any(not _issue_url(url, repo) for url in ledger.values()):
        raise RuntimeError("ledger contains a URL outside the selected repository; reconcile ledger")
    # Complete a receipt whose primary write survived a previous process crash.
    if any(entry["state"] == "pending" and entry["key"] in ledger
           and entry["repo"] == repo for entry in pending.values()):
        with _ledger_lock(path):
            ledger = load_ledger(path)
            pending = _load_pending(path + ".pending.json")
            for entry in pending.values():
                url = ledger.get(entry["key"])
                if entry["state"] == "pending" and entry["repo"] == repo and url:
                    if not _issue_url(url, repo):
                        raise RuntimeError("ledger changed repository during completion")
                    entry.update(state="complete", url=url)
            _save_pending(path + ".pending.json", pending)
    return ledger


def _save_pending(path, entries):
    _atomic_json(path, {"schema_version": 1, "entries": entries})


def _preflight(repo, runner):
    try:
        result = runner([_gh_bin(), "api", "repos/" + repo], capture_output=True, text=True)
        data = json.loads(result.stdout)
        if (result.returncode != 0 or not isinstance(data, dict)
                or data.get("full_name") != repo or not isinstance(data.get("permissions"), dict)
                or data["permissions"].get("admin") is not True):
            raise ValueError("missing admin permission or wrong repository")
    except (OSError, subprocess.SubprocessError, ValueError, TypeError) as exc:
        raise RuntimeError("authenticated admin preflight failed for " + repo) from exc


def find_existing_issue(title, runner, repo=REPO_SLUG, *, intent=None):
    """Adopt one exact operation marker only from a complete bounded response.

    Legacy title-only calls retain their positional/keyword interface and
    return None without querying: a title cannot prove operation identity.
    Explicit intent enables strict reconciliation and raises if unresolved.
    Search indexing may lag acceptance. Even an empty result cannot authorize
    replay. A full page, malformed row, or duplicate marker is inconclusive.
    """
    if intent is None:
        return None
    validate_repo(repo)
    if intent["title"] != title or intent["repo"] != repo:
        raise ValueError("probe title/repository does not match the bound intent")
    marker = intent["marker"]
    try:
        query = urlencode({"q": "repo:" + repo + " is:issue "
                           + marker.split(":")[1].split()[0] + " in:body", "per_page": 100})
        result = runner([_gh_bin(), "api", "search/issues?" + query],
                        capture_output=True, text=True)
        data = json.loads(result.stdout)
        if (result.returncode != 0 or not isinstance(data, dict)
                or data.get("incomplete_results") is not False
                or type(data.get("total_count")) is not int
                or not isinstance(data.get("items"), list)):
            raise ValueError("invalid marker query envelope")
        rows = data["items"]
        if data["total_count"] != len(rows) or len(rows) >= 100:
            raise ValueError("incomplete marker query")
        matches = []
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("body"), str)
                    or not isinstance(row.get("title"), str) or "pull_request" in row
                    or not _issue_url(row.get("html_url"), repo)):
                raise ValueError("invalid marker query row")
            if marker in row["body"].splitlines():
                if row["body"] != intent["body"] or row["title"] != intent["title"]:
                    raise ValueError("marker content changed")
                matches.append(row["html_url"])
        if len(matches) == 1:
            return matches[0]
    except (OSError, subprocess.SubprocessError, ValueError, TypeError) as exc:
        raise RuntimeError("pending create marker query inconclusive; reconcile before replay") from exc
    raise RuntimeError("pending create unresolved; rerun to reconcile its marker; do not delete intent")


def create(title, body, labels, dry, throttle=0.0, env=None, repo=REPO_SLUG,
           operation_id=None, ledger_path=None, kind="finding"):
    """One durable create attempt; subsequent calls can only adopt its marker.

    A direct caller without a canonical key gets a content-derived key. Primary
    ledger keys stay unchanged, so selecting a different repo with the same
    ledger/key refuses instead of adopting a foreign URL.
    """
    validate_repo(repo)
    if kind not in ("finding", "fixme"):
        raise ValueError("unknown filing kind")
    if dry:
        print("\n" + "=" * 78)
        print("TITLE : %s" % title)
        print("LABELS: %s" % ",".join(labels))
        print("-" * 78)
        print(body[:900])
        return None
    path = LEDGER if ledger_path is None else os.fspath(ledger_path)
    key = operation_id if operation_id is not None else _digest([repo, kind, title, body, labels])
    if not isinstance(key, str) or not key:
        raise ValueError("operation identity must be a nonempty string")
    identity, intent = _intent(repo, kind, key, title, body, labels)
    pending_path = path + ".pending.json"
    # Refuse corruption before permission queries, parent creation, or mutation.
    load_ledger(path)
    _load_pending(pending_path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if fcntl is None:  # pragma: no cover - fail closed without ownership locking
        raise RuntimeError("durable issue creation requires a ledger lock")
    with _ledger_lock(path):
        ledger = load_ledger(path)
        pending = _load_pending(pending_path)
        if key in ledger:
            if not _issue_url(ledger[key], repo):
                raise RuntimeError("recorded key belongs to a different repository; reconcile ledger")
            # Resume a crash after the primary write and before completion.
            if identity in pending:
                pending[identity].update(state="complete", url=ledger[key])
                _save_pending(pending_path, pending)
            return ledger[key]
    if env is None:
        env = triage.gh_env()
    runner = functools.partial(subprocess.run, env=env, timeout=GH_CREATE_TIMEOUT)
    _preflight(repo, runner)
    with _ledger_lock(path):
        ledger = load_ledger(path)
        pending = _load_pending(pending_path)
        if key in ledger:
            if not _issue_url(ledger[key], repo):
                raise RuntimeError("recorded key belongs to a different repository")
            return ledger[key]
        owner = identity not in pending
        if owner:
            pending[identity] = intent
            _save_pending(pending_path, pending)
        else:
            existing = pending[identity]
            if any(existing[k] != v for k, v in intent.items() if k not in ("state", "url")):
                raise RuntimeError("pending operation content changed; reconcile original intent")
            intent = existing
    url = None
    if owner:
        try:
            result = runner([_gh_bin(), "issue", "create", "--repo", repo,
                             "--title", title, "--body", intent["body"],
                             "--label", ",".join(labels)], capture_output=True, text=True)
            candidate = result.stdout.strip()
            if result.returncode == 0 and _issue_url(candidate, repo):
                url = candidate
        except (OSError, subprocess.SubprocessError):
            pass  # Acceptance is unknown; the durable intent forbids retry.
    if url is None:
        url = find_existing_issue(title, runner, repo, intent=intent)
    record({}, key, url, path)
    with _ledger_lock(path):
        pending = _load_pending(pending_path)
        pending[identity].update(state="complete", url=url)
        _save_pending(pending_path, pending)
    print("%s  %s" % (url, title[:70]), flush=True)
    if throttle:
        time.sleep(throttle)
    return url


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--repo", type=validate_repo, default=REPO_SLUG)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--only", choices=["findings", "rejected"])
    ap.add_argument("--throttle", type=float, default=1.5,
                    help="seconds between creates; GitHub throttles bursts")
    ap.add_argument("--report", default=REPORT,
                    help="path to the self-scan report JSON to file from")
    ap.add_argument("--report-url", default=REPORT_URL,
                    help="public URL of the report artifact, embedded in each issue")
    ap.add_argument("--run-label", default=RUN_LABEL,
                    help="human label for the run, e.g. 'run 3'")
    ap.add_argument("--run-date", default=RUN_DATE,
                    help="date of the run, e.g. '2026-08-08'")
    ap.add_argument("--run-state-doc", default=RUN_STATE_DOC,
                    help="path to the run's coverage/run-state doc, linked in each issue")
    a = ap.parse_args()

    # Load every continuation before any issue creation or ledger access. The
    # shared loader confines both parts and the rejected-claim spill file.
    report = _reconcile.load_report(a.report)
    findings = report["findings"]
    print("loaded %d finding(s) and %d rejected claim(s)" % (
        len(findings), len(report["discarded_claims"])), file=sys.stderr)

    work = []
    if a.only != "rejected":
        for f in findings:
            work.append((f, False))
    if a.only != "findings":
        for f in report["discarded_claims"]:
            work.append((f, True))
    if a.limit:
        work = work[:a.limit]

    ledger = {} if a.dry_run else load_filing_ledger(LEDGER, a.repo)
    todo = [(f, rej) for f, rej in work if key_for(f, rej) not in ledger]
    skipped = len(work) - len(todo)
    print("filing %d issue(s)%s%s" % (
        len(todo), " (DRY RUN)" if a.dry_run else "",
        "; %d already filed, skipping" % skipped if skipped else ""))

    created = 0
    env = None if a.dry_run else triage.gh_env()  # read once per run, not per issue
    for f, rej in todo:
        body = body_for(f, rej, report=a.report, report_url=a.report_url,
                        run_label=a.run_label, run_date=a.run_date,
                        run_state_doc=a.run_state_doc)
        url = create(scrub(title_for(f)), scrub(body),
                     labels_for(f, rej), a.dry_run, a.throttle, env=env, repo=a.repo,
                     operation_id=key_for(f, rej), ledger_path=LEDGER, kind="finding")
        if url:
            record(ledger, key_for(f, rej), url)
            created += 1
    if not a.dry_run:
        print("\ncreated %d of %d; ledger: %s" % (created, len(todo), LEDGER))
        if created < len(todo):
            print("re-run the same command to file the remainder", file=sys.stderr)


if __name__ == "__main__":
    main()
