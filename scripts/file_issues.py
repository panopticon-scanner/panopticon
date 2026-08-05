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
import subprocess
import sys
import time

REPORT = "docs/superpowers/2026-08-04-self-scan-report.json"
REPORT_URL = ("https://github.com/psyberone/panopticon/blob/main/"
              "docs/superpowers/2026-08-04-self-scan-report.json")

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
    fname = (loc.get("file") or "").split("/")[-1]
    t = f.get("short_title") or f.get("title") or "(untitled)"
    suffix = " (%s)" % fname if fname else ""
    room = 240 - len(suffix)
    if len(t) > room:
        t = t[:room - 1].rstrip() + "…"
    return t + suffix


def body_for(f, rejected=False):
    loc = f.get("location") or {}
    ev = f.get("evidence") or {}
    prov = f.get("provenance") or {}
    L = []
    if rejected:
        L.append("> **An advisor refuted this claim.** It is filed for the audit "
                 "trail, not as work to do. Severity below is the *claimed* "
                 "severity — panopticon never rewrites a severity on rejection, "
                 "so that a wrong rejection stays visible.\n")
    where = loc.get("file") or "(no file)"
    if loc.get("line_start"):
        where += ":%s" % loc["line_start"]
    L.append("**Location:** `%s`" % where)
    if f.get("occurrences", 1) > 1:
        L.append("**Occurrences:** %d loci of this rule in this file "
                 "(primary above)" % f["occurrences"])
        for a in (f.get("additional_loci") or []):
            L.append("  - `%s:%s`" % (a.get("file"), a.get("line_start")))
    L.append("**Severity (impact if true):** %s   **Evidence:** `%s`   "
             "**Confidence:** %s" % (f.get("severity"), ev.get("status"),
                                     f.get("confidence")))
    src = prov.get("discovered_by") or f.get("source") or "unknown"
    L.append("**Found by:** %s%s" % (src, "  ·  model: %s" % prov["model"]
                                     if prov.get("model") else ""))
    cites = f.get("citations") or {}
    flat = []
    for k in ("cwe", "owasp", "cve"):
        for c in (cites.get(k) or []):
            flat.append(c if isinstance(c, str) else c.get("id", str(c)))
    if flat:
        L.append("**Citations:** %s" % ", ".join(flat))
    L.append("\n## What was found\n\n%s" % (f.get("description") or "(none)"))
    if f.get("impact"):
        L.append("\n## Impact\n\n%s" % f["impact"])
    if f.get("exploit_scenario"):
        L.append("\n## Exploit scenario\n\n%s" % f["exploit_scenario"])
    if f.get("remediation"):
        L.append("\n## Suggested remediation\n\n%s" % f["remediation"])
    reasoning = ev.get("reasoning") or prov.get("confirmation_reasoning")
    if reasoning and str(reasoning) != str(f.get("category")):
        verb = "Advisor verdict" if not rejected else "Advisor rejection"
        L.append("\n## %s\n\n%s" % (verb, reasoning))
    if ev.get("verified_by"):
        L.append("\n**Corroborating panels:** %s" % ", ".join(
            str(x) for x in ev["verified_by"]))
    L.append("\n---\n")
    L.append("**Fingerprint:** `%s` — stable cross-run identity; excludes line "
             "numbers and free-text so this issue survives code moves and "
             "re-wordings." % f.get("fingerprint"))
    L.append("**Finding id in report:** `%s`" % f.get("id"))
    L.append("**Report artifact:** [%s](%s) (self-scan run 2, 2026-08-04, "
             "`tool_policy_mode: enforced`)" % (REPORT, REPORT_URL))
    L.append("\n*Filed automatically from a panopticon self-scan. Coverage for "
             "this run is stated in "
             "`docs/superpowers/2026-08-04-self-scan-run-state.md`.*")
    return "\n".join(L)


REPO_ROOT = "/Volumes/Mini Vault/untitled_folder/projects/panopticon/"


def scrub(text):
    """Reviewers cite absolute local paths; issues are public and permanent."""
    return str(text).replace(REPO_ROOT, "").replace(REPO_ROOT.rstrip("/"), "the repo root")


LEDGER = ".panopticon/filed-issues.json"


def load_ledger():
    """Filing is resumable: a run that dies partway must not re-file."""
    try:
        with open(LEDGER, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def record(ledger, key, url):
    ledger[key] = url
    tmp = LEDGER + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(ledger, fh, indent=1, sort_keys=True)
    os.replace(tmp, LEDGER)


def key_for(f, rejected):
    loc = f.get("location") or {}
    return "%s|%s|%s|%s" % (f.get("fingerprint") or "", f.get("id") or "",
                            loc.get("file") or "", "rejected" if rejected else "finding")


RATE_HINTS = ("rate limit", "secondary rate", "abuse detection", "was submitted too quickly")


def create(title, body, labels, dry, throttle=0.0):
    if dry:
        print("\n" + "=" * 78)
        print("TITLE : %s" % title)
        print("LABELS: %s" % ",".join(labels))
        print("-" * 78)
        print(body[:900])
        return None
    for attempt in range(1, 6):
        r = subprocess.run(["gh", "issue", "create", "--title", title,
                            "--body", body, "--label", ",".join(labels)],
                           capture_output=True, text=True)
        if r.returncode == 0:
            url = r.stdout.strip().splitlines()[-1]
            print("%s  %s" % (url, title[:70]), flush=True)
            if throttle:
                time.sleep(throttle)
            return url
        err = (r.stderr or "").strip()
        if any(h in err.lower() for h in RATE_HINTS) and attempt < 5:
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
    a = ap.parse_args()

    report = json.load(open(REPORT, encoding="utf-8"))
    findings = list(report["findings"])
    # A large report is split; meta.parts names the continuation files, resolved
    # beside the main artifact. Reading only the first part silently under-files.
    for part in (report.get("meta") or {}).get("parts") or []:
        part = str(part)
        base_dir = os.path.dirname(REPORT)
        ppath = os.path.normpath(os.path.join(base_dir, part))
        base_dir_norm = os.path.normpath(base_dir)
        if os.path.isabs(part) or not (ppath == base_dir_norm or ppath.startswith(base_dir_norm + os.sep)):
            raise ValueError("invalid meta.parts entry: %r" % part)
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
    for f, rej in todo:
        url = create(scrub(title_for(f)), scrub(body_for(f, rej)),
                     labels_for(f, rej), a.dry_run, a.throttle)
        if url:
            record(ledger, key_for(f, rej), url)
            created += 1
    if not a.dry_run:
        print("\ncreated %d of %d; ledger: %s" % (created, len(todo), LEDGER))
        if created < len(todo):
            print("re-run the same command to file the remainder", file=sys.stderr)


if __name__ == "__main__":
    main()
