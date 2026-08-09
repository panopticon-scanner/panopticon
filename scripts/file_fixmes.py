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
import re

import file_issues

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
        # Drop the label line: the first non-blank body line that consists
        # entirely of backtick-quoted tokens separated by ", ".
        first_nonblank = next((i for i, ln in enumerate(f["body"]) if ln.strip()), None)
        if first_nonblank is not None:
            candidate = f["body"][first_nonblank]
            if not re.sub(r"`[^`]+`", "", candidate).strip().replace(",", "").strip():
                f["body"].pop(first_nonblank)
        body = f["body"]
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


# The gh-issue-create retry loop and the resumable ledger live in
# file_issues.py — this filer used to carry byte-for-byte copies, which had
# already diverged (file_issues.create gained the rc=0/empty-stdout backoff
# this copy lacked). Delegate instead.
create = file_issues.create


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
    ledger = {} if a.dry_run else file_issues.load_ledger(LEDGER)
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
            file_issues.record(ledger, f["id"], url, LEDGER)
            created += 1
    if not a.dry_run:
        print("\ncreated %d of %d; ledger: %s" % (created, len(todo), LEDGER))


if __name__ == "__main__":
    main()
