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
import json
import os
import shutil
import subprocess
import sys
import time

import triage
from sanitize import repo_root, repo_relative, scrub, defang

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
            "rejected": "evidence:rejected"}


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
        L.append("\n**Corroborating panels:** %s" % ", ".join(
            defang(str(x)) for x in ev["verified_by"]))
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


def normalize_ledger(raw_ledger):
    """Normalize legacy ledger keys (e.g. absolute paths) to canonical repo-relative keys (#1124)."""
    if not isinstance(raw_ledger, dict):
        return {}
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


def load_ledger(path=LEDGER):
    """Filing is resumable: a run that dies partway must not re-file.

    Parameterized on the ledger path so sibling filers (file_fixmes,
    reconcile_apply) share this machinery instead of copying it."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
            return normalize_ledger(data)
    except (OSError, ValueError):
        return {}


def record(ledger, key, url, path=LEDGER):
    ledger[key] = url
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(ledger, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def make_ledger_key(fingerprint, finding_id, location_file, kind):
    """Canonical 4-part ledger key format (#607/#488/#1122)."""
    return "%s|%s|%s|%s" % (
        fingerprint or "",
        finding_id or "",
        repo_relative(location_file or "") if location_file else "",
        kind or ""
    )


def resolve_part_path(base_dir, part):
    """Resolve and validate a report part continuation path within base_dir (#1122)."""
    part = str(part)
    base_norm = os.path.normpath(base_dir or ".")
    ppath = os.path.normpath(os.path.join(base_norm, part))
    if os.path.isabs(part) or not (ppath == base_norm or ppath.startswith(base_norm + os.sep)):
        raise ValueError("invalid meta.parts entry: %r" % part)
    return ppath


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
# indefinitely (#1104). A timeout is treated as a retryable failed attempt.
GH_CREATE_TIMEOUT = 60


def create(title, body, labels, dry, throttle=0.0, env=None):
    if dry:
        print("\n" + "=" * 78)
        print("TITLE : %s" % title)
        print("LABELS: %s" % ",".join(labels))
        print("-" * 78)
        print(body[:900])
        return None
    if env is None:
        env = triage.gh_env()
    gh_bin = shutil.which("gh") or "gh"
    for attempt in range(1, 6):
        try:
            r = subprocess.run([gh_bin, "issue", "create", "--title", title,  # nosec B603
                                "--body", body, "--label", ",".join(labels)],
                               capture_output=True, text=True,
                               env=env, timeout=GH_CREATE_TIMEOUT)
        except subprocess.TimeoutExpired:
            # A hung gh must not block the run indefinitely (#1104): back off
            # and retry, else leave un-ledgered for a later resume like the
            # empty-stdout path below, rather than halting the whole run.
            if attempt < 5:
                backoff = 60 * attempt
                print("gh create timed out after %ds (attempt %d); backing off %ds"
                      % (GH_CREATE_TIMEOUT, attempt, backoff),
                      file=sys.stderr, flush=True)
                time.sleep(backoff)
                continue
            print("FAILED (gh create timed out): %s" % title,
                  file=sys.stderr, flush=True)
            return None
        if r.returncode == 0:
            out = r.stdout.strip().splitlines()
            if out:
                url = out[-1]
                print("%s  %s" % (url, title[:70]), flush=True)
                if throttle:
                    time.sleep(throttle)
                return url
            # rc==0 but nothing on stdout. Observed under GitHub secondary rate
            # limits, where `gh issue create` exits 0 without printing the URL
            # (and, empirically, without creating the issue). Back off and retry
            # rather than crashing on splitlines()[-1]; if a URL never appears,
            # return None so this finding is left un-ledgered for a later resume
            # instead of halting the whole run.
            if attempt < 5:
                backoff = 60 * attempt
                print("empty stdout on rc=0 (attempt %d); backing off %ds"
                      % (attempt, backoff), file=sys.stderr, flush=True)
                time.sleep(backoff)
                continue
            print("FAILED (rc=0, no url returned): %s" % title,
                  file=sys.stderr, flush=True)
            return None
        err = (r.stderr or "").strip()
        if any(h in err.lower() for h in triage.RATE_HINTS) and attempt < 5:
            backoff = 60 * attempt
            print("rate limited (attempt %d); sleeping %ds" % (attempt, backoff),
                  file=sys.stderr, flush=True)
            time.sleep(backoff)
            continue
        print("FAILED: %s\n%s" % (title, err), file=sys.stderr, flush=True)
        return None
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
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

    with open(a.report, encoding="utf-8") as fh:
        report = json.load(fh)
    findings = list(report["findings"])
    # A large report is split; meta.parts names the continuation files, resolved
    # beside the main artifact. Reading only the first part silently under-files.
    for part in (report.get("meta") or {}).get("parts") or []:
        ppath = resolve_part_path(os.path.dirname(a.report), part)
        try:
            with open(ppath, encoding="utf-8") as fh:
                pdata = json.load(fh)
        except (OSError, json.JSONDecodeError) as e:
            print("FAILED to load report part %s (%s)" % (ppath, e), file=sys.stderr)
            raise

        part_findings = pdata.get("findings") or []
        findings.extend(part_findings)
        print("loaded %d finding(s) from part %s" % (len(part_findings), part), file=sys.stderr)

    work = []
    if a.only != "rejected":
        for f in findings:
            work.append((f, False))
    if a.only != "findings":
        for f in report.get("discarded_claims", []):
            work.append((f, True))
    if a.limit:
        work = work[:a.limit]

    ledger = {} if a.dry_run else load_ledger()
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
                     labels_for(f, rej), a.dry_run, a.throttle, env=env)
        if url:
            record(ledger, key_for(f, rej), url)
            created += 1
    if not a.dry_run:
        print("\ncreated %d of %d; ledger: %s" % (created, len(todo), LEDGER))
        if created < len(todo):
            print("re-run the same command to file the remainder", file=sys.stderr)


if __name__ == "__main__":
    main()
