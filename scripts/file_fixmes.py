#!/usr/bin/env python3
"""File the run-2 FIXMEs as GitHub issues.

The FIXMEs are orchestration defects observed while *running* a scan, so they
never appear in a report artifact and `file_issues.py` cannot see them. They
live as `## FIXME-N — title` sections in the FIXME doc, each followed by a
line of backtick-quoted labels.

Shares file_issues.py's resume discipline: a ledger keyed by FIXME id, written
after each success, so a re-run files only the remainder.

Usage:  python3 scripts/file_fixmes.py [--dry-run] [--limit N] [--throttle S]
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

# Defaults describe run 2's FIXME doc. A later run passes its own --doc,
# --doc-url, --run-label, and --run-date, so filing a new run's FIXMEs needs no
# code edit (#606) — same convention as file_issues.py. Kept only for
# backward-compat and to keep body_for() callable bare in tests.
DOC = "docs/superpowers/2026-08-04-run2-fixmes.md"
DOC_URL = ("https://github.com/panopticon-scanner/panopticon/blob/main/"
           "docs/superpowers/2026-08-04-run2-fixmes.md")
RUN_LABEL = "run-2"
RUN_DATE = "2026-08-04"
LEDGER = ".panopticon/filed-fixmes.json"

HEAD_RE = re.compile(r"^## (FIXME-\d+) — (.+)$")
LABEL_RE = re.compile(r"`([^`]+)`")
RATE_HINTS = ("rate limit", "secondary rate", "abuse detection",
              "was submitted too quickly")


def parse(path):
    """Yield (id, title, labels, body) for each FIXME section.

    Stops at the first horizontal rule that follows the last FIXME: the
    trailing 'Already fixed' / 'Still open' sections are commentary, not
    issues to file.
    """
    lines = open(path, encoding="utf-8").read().splitlines()
    out, cur = [], None
    for i, line in enumerate(lines):
        m = HEAD_RE.match(line)
        if m:
            if cur:
                out.append(cur)
            labels = []
            if i + 1 < len(lines):
                labels = LABEL_RE.findall(lines[i + 1])
            cur = {"id": m.group(1), "title": m.group(2).strip(),
                   "labels": labels, "body": []}
            continue
        if cur is None:
            continue
        if line.strip() == "---":
            out.append(cur)
            cur = None
            continue
        cur["body"].append(line)
    if cur:
        out.append(cur)
    for f in out:
        # Drop the label line itself and any leading/trailing blanks.
        body = [ln for ln in f["body"]
                if re.sub(r"`[^`]+`", "", ln).strip().replace(",", "").strip()]
        while body and not body[0].strip():
            body.pop(0)
        while body and not body[-1].strip():
            body.pop()
        f["body"] = "\n".join(body)
    return out


def body_for(f, doc=DOC, doc_url=DOC_URL, run_label=RUN_LABEL, run_date=RUN_DATE):
    return "\n".join([
        f["body"],
        "",
        "---",
        "",
        "**Source:** `%s` — %s, an orchestration defect observed while running "
        "the scan rather than a finding produced by a reviewer panel." % (f["id"], doc),
        "",
        "Full context, including the other FIXMEs from this run: [%s](%s)"
        % (doc, doc_url),
        "",
        "*Filed from panopticon's %s self-scan (%s, "
        "`tool_policy_mode: enforced`).*" % (run_label, run_date),
    ])


def load_ledger():
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


def create(title, body, labels, dry, throttle):
    if dry:
        print("\n" + "=" * 78)
        print("TITLE : %s" % title)
        print("LABELS: %s" % ",".join(labels))
        print("-" * 78)
        print(body[:700])
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
    ap.add_argument("--throttle", type=float, default=8.0)
    ap.add_argument("--doc", default=DOC, help="path to the run's FIXME doc")
    ap.add_argument("--doc-url", default=DOC_URL,
                    help="public URL of the FIXME doc, embedded in each issue")
    ap.add_argument("--run-label", default=RUN_LABEL, help="e.g. 'run-3'")
    ap.add_argument("--run-date", default=RUN_DATE, help="e.g. '2026-08-08'")
    a = ap.parse_args()

    fixmes = parse(a.doc)
    ledger = {} if a.dry_run else load_ledger()
    todo = [f for f in fixmes if f["id"] not in ledger]
    if a.limit:
        todo = todo[:a.limit]
    skipped = len(fixmes) - len(todo)
    print("parsed %d FIXME(s); filing %d%s%s" % (
        len(fixmes), len(todo), " (DRY RUN)" if a.dry_run else "",
        "; %d already filed" % skipped if skipped and not a.dry_run else ""))

    created = 0
    for f in todo:
        title = "%s — %s" % (f["id"], f["title"])
        body = body_for(f, doc=a.doc, doc_url=a.doc_url,
                        run_label=a.run_label, run_date=a.run_date)
        url = create(title, body, f["labels"] or ["self-scan"],
                     a.dry_run, a.throttle)
        if url:
            record(ledger, f["id"], url)
            created += 1
    if not a.dry_run:
        print("\ncreated %d of %d; ledger: %s" % (created, len(todo), LEDGER))


if __name__ == "__main__":
    main()
