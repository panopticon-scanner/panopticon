# Remediation Triage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Disposition every run-2 FIXME, CRITICAL, and HIGH issue (~72) into a
ranked fix queue, with advisor spot-checks and a user gate per batch.

**Architecture:** A small `scripts/triage.py` tool owns the mechanical layer —
ledger IO, verdict validation, gh mutation planning, throttled apply with
staleness guard, and one-time label/milestone setup. The judgment layer is the
operator (Claude, in-session): reading issues, deduping, ranking, dispatching
`panopticon-advisor` spot-checks, writing ledger rows, and running the per-batch
user gate. Spec: `docs/superpowers/specs/2026-08-04-remediation-triage-design.md`.

**Tech Stack:** Python 3 stdlib only (json/subprocess/argparse — matches
`scripts/file_issues.py`), `gh` CLI, unittest-style tests under `tests/`.

## Global Constraints

- Every `gh`/`git` network command needs `export GH_CONFIG_DIR="$HOME/.config/gh-psyberone"` first; the machine's default credential is the wrong account.
- All work on branch `docs/remediation-triage`; nothing merges to main except by PR.
- Ledger path: `.panopticon/triage-ledger.jsonl` (gitignored — local resume state; GitHub + the committed log doc are the durable record).
- Committed log doc: `docs/superpowers/2026-08-04-remediation-triage-log.md`.
- Milestone title: `Remediation 1`. Spec path constant: `docs/superpowers/specs/2026-08-04-remediation-triage-design.md`.
- GitHub mutations only from ledger rows with `status: "approved"` (the user's batch gate). Never mutate from `proposed`.
- Throttle default 1.5s between mutations; on rate-limit hints back off 60s×attempt, max 5 attempts (the `file_issues.py` lesson).
- Timestamps are UTC ISO-8601 with `Z` suffix (`date -u +%Y-%m-%dT%H:%M:%SZ`); staleness compares them lexicographically against GitHub's `updatedAt`.
- Run tests with `python3 -m pytest tests/test_triage.py -q` from the repo root.

## Shared Definitions (used by Tasks 4–7)

**Ledger row schema** (one JSON object per line):

```json
{"issue": 431, "set": "FIXME", "verdict": "fix", "rationale": "one-line why",
 "duplicate_of": null, "fixed_by": null, "spot_check": null, "rank": 3,
 "status": "proposed", "batch": "B1", "triaged_at": "2026-08-04T23:00:00Z"}
```

`set` ∈ {FIXME, CRITICAL, HIGH}; `batch` ∈ {B1, B2, B3a…B3d}; `verdict` ∈
{fix, duplicate, already-fixed, reject, defer}; `status` walks
proposed → approved → applied (or → stale, set by the apply step).
Verdict-specific requirements: `duplicate` needs `duplicate_of` (int issue #);
`already-fixed` needs `fixed_by` (commit/PR ref) **and** `spot_check`;
`reject` needs `spot_check`; `fix` needs integer `rank`.

**Advisor spot-check dispatch** — subagent_type `panopticon-advisor`
(read-only: Read/Grep/Glob), prompt template:

```
Verify one finding against the CURRENT working tree (repo root: the project
home). Do not assume the finding is true or false.

Issue #<N>: <title>
Claimed location: <file>:<line>
Claim: <description, condensed>
Run-2 advisor verdict: <confirmed|rejected>, rationale: <reasoning from issue body>

Determine which one holds NOW:
(a) PRESENT — the claimed defect exists in the current code (cite file:line);
(b) FIXED — the code shows the defect was remediated (cite what changed);
(c) NOT-REAL — the claim misreads the code (explain the misreading).

Return ONLY JSON: {"verdict": "present|fixed|not-real",
"reasoning": "<3-6 sentences citing file:line>", "cited_paths": ["..."]}
```

The agent has no git access; when a spot-check says FIXED, the operator finds
the fixing commit (`git log --oneline -- <file>`) and records it in `fixed_by`.
If a spot-check on an `evidence:rejected` issue returns PRESENT, the verdict
becomes `fix` (ranked) and the overturn is counted for the closing summary's
calibration number. If an advisor dispatch fails, the affected rows stay
`proposed` — a rejected CRITICAL/HIGH never closes without its spot-check.

**Disposition table format** (presented at the gate, then appended verbatim to
the log doc after apply):

```markdown
## Batch <id> — <name> (<date>)

| # | Issue | Verdict | Rank | Rationale |
|---|-------|---------|------|-----------|
| 1 | #443 | fix | 1 | Queue identity bug stranded 13 verdicts; keyed fix per FIXME-13 |
```

(`Rank` column only for fix verdicts; duplicates show `→ #N` in Rationale;
spot-checked rows add a `Spot-check` line under the table.)

**Per-batch procedure** (each batch task instantiates exactly this):

1. Read every issue in the batch: `gh issue view <N> --json title,body,labels,state`.
2. Dispatch advisor spot-checks in parallel for: every `evidence:rejected`
   CRITICAL/HIGH; every candidate `already-fixed`; any confirmed finding whose
   current truth is in doubt.
3. Write proposed rows to the ledger (status `proposed`, stamped `triaged_at`).
4. Present the disposition table to the user. **STOP — user gate.**
5. On approval, flip approved rows to `status: "approved"` in the ledger
   (amendments: edit the row, keep status `proposed` → re-present).
6. `python3 scripts/triage.py apply` (dry-run first if the batch has >20 rows).
7. Verify apply output; append the table to the log doc; commit the log doc.

---

### Task 1: Ledger IO and row validation

**Files:**
- Create: `scripts/triage.py`
- Test: `tests/test_triage.py`

**Interfaces:**
- Produces: `load_rows(path=LEDGER) -> list[dict]`, `save_rows(rows, path=LEDGER) -> None` (atomic tmp+replace), `validate(row) -> None` (raises `ValueError` naming the issue and every problem), constants `LEDGER`, `MILESTONE`, `SPEC`, `VERDICTS`, `STATUSES`, `LABELS`.
- Consumes: nothing prior.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_triage.py
import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import triage


def fix_row(**over):
    row = {"issue": 443, "set": "FIXME", "verdict": "fix",
           "rationale": "queue identity bug", "duplicate_of": None,
           "fixed_by": None, "spot_check": None, "rank": 1,
           "status": "proposed", "batch": "B1",
           "triaged_at": "2026-08-04T23:00:00Z"}
    row.update(over)
    return row


class TestLedger(unittest.TestCase):
    def test_roundtrip_preserves_rows_and_order(self):
        rows = [fix_row(), fix_row(issue=431, rank=2)]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ledger.jsonl")
            triage.save_rows(rows, path=p)
            self.assertEqual(triage.load_rows(path=p), rows)

    def test_load_missing_file_returns_empty(self):
        self.assertEqual(triage.load_rows(path="/nonexistent/x.jsonl"), [])

    def test_load_skips_blank_lines_and_reports_bad_line_number(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ledger.jsonl")
            with open(p, "w") as fh:
                fh.write(json.dumps(fix_row()) + "\n\n{not json\n")
            with self.assertRaisesRegex(ValueError, "line 3"):
                triage.load_rows(path=p)


class TestValidate(unittest.TestCase):
    def test_valid_fix_row_passes(self):
        triage.validate(fix_row())  # must not raise

    def test_fix_requires_integer_rank(self):
        with self.assertRaisesRegex(ValueError, "rank"):
            triage.validate(fix_row(rank=None))

    def test_duplicate_requires_duplicate_of(self):
        with self.assertRaisesRegex(ValueError, "duplicate_of"):
            triage.validate(fix_row(verdict="duplicate", rank=None))

    def test_already_fixed_requires_fixed_by_and_spot_check(self):
        with self.assertRaisesRegex(ValueError, "fixed_by"):
            triage.validate(fix_row(verdict="already-fixed", rank=None,
                                    spot_check="advisor: fixed"))

    def test_reject_requires_spot_check(self):
        with self.assertRaisesRegex(ValueError, "spot_check"):
            triage.validate(fix_row(verdict="reject", rank=None))

    def test_unknown_verdict_and_status_rejected(self):
        with self.assertRaisesRegex(ValueError, "verdict"):
            triage.validate(fix_row(verdict="maybe"))
        with self.assertRaisesRegex(ValueError, "status"):
            triage.validate(fix_row(status="pondering"))

    def test_empty_rationale_rejected(self):
        with self.assertRaisesRegex(ValueError, "rationale"):
            triage.validate(fix_row(rationale="  "))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_triage.py -q`
Expected: collection error / failures — `triage` has no attributes.

- [ ] **Step 3: Write the implementation**

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_triage.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/triage.py tests/test_triage.py
git commit -m "feat(triage): ledger IO and disposition row validation"
```

---

### Task 2: Mutation planning, comments, staleness

**Files:**
- Modify: `scripts/triage.py` (append functions)
- Test: `tests/test_triage.py` (append test classes)

**Interfaces:**
- Consumes: `LABELS`, `MILESTONE`, `SPEC`, `validate` from Task 1.
- Produces: `comment_for(row) -> str`, `plan_mutations(row) -> list[list[str]]` (full argv lists starting `"gh"`), `is_stale(row, issue_state) -> bool` where `issue_state` is `{"state": "OPEN"|"CLOSED", "updatedAt": iso}`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_triage.py`)

```python
class TestMutations(unittest.TestCase):
    def test_fix_comments_labels_milestones_never_closes(self):
        cmds = triage.plan_mutations(fix_row())
        self.assertEqual(cmds[0][:4], ["gh", "issue", "comment", "443"])
        self.assertIn("triage:fix", cmds[1])
        self.assertIn(triage.MILESTONE, cmds[1])
        self.assertFalse(any(c[2] == "close" for c in cmds))

    def test_duplicate_closes_not_planned(self):
        row = fix_row(verdict="duplicate", rank=None, duplicate_of=436)
        cmds = triage.plan_mutations(row)
        self.assertIn("triage:duplicate", cmds[1])
        self.assertEqual(cmds[-1], ["gh", "issue", "close", "443",
                                    "--reason", "not planned"])

    def test_already_fixed_closes_completed(self):
        row = fix_row(verdict="already-fixed", rank=None,
                      fixed_by="PR #447", spot_check="advisor: fixed")
        self.assertEqual(triage.plan_mutations(row)[-1],
                         ["gh", "issue", "close", "443",
                          "--reason", "completed"])

    def test_reject_closes_not_planned_and_defer_stays_open(self):
        rej = fix_row(verdict="reject", rank=None, spot_check="stands")
        self.assertEqual(triage.plan_mutations(rej)[-1][:3],
                         ["gh", "issue", "close"])
        defer = fix_row(verdict="defer", rank=None)
        self.assertFalse(any(c[2] == "close"
                             for c in triage.plan_mutations(defer)))

    def test_comment_carries_rationale_spec_and_spot_check(self):
        row = fix_row(verdict="reject", rank=None,
                      spot_check="advisor: not-real, fixture file")
        body = triage.comment_for(row)
        self.assertIn("queue identity bug", body)
        self.assertIn(triage.SPEC, body)
        self.assertIn("fixture file", body)

    def test_comment_for_duplicate_names_canonical(self):
        row = fix_row(verdict="duplicate", rank=None, duplicate_of=436)
        self.assertIn("#436", triage.comment_for(row))


class TestStale(unittest.TestCase):
    def test_closed_issue_is_stale(self):
        self.assertTrue(triage.is_stale(
            fix_row(), {"state": "CLOSED",
                        "updatedAt": "2026-08-01T00:00:00Z"}))

    def test_updated_after_triage_is_stale(self):
        self.assertTrue(triage.is_stale(
            fix_row(), {"state": "OPEN",
                        "updatedAt": "2026-08-05T00:00:00Z"}))

    def test_untouched_open_issue_is_fresh(self):
        self.assertFalse(triage.is_stale(
            fix_row(), {"state": "OPEN",
                        "updatedAt": "2026-08-04T12:00:00Z"}))
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `python3 -m pytest tests/test_triage.py -q`
Expected: Task 1 classes PASS; new classes ERROR on missing attributes.

- [ ] **Step 3: Implement** (append to `scripts/triage.py`)

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_triage.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/triage.py tests/test_triage.py
git commit -m "feat(triage): mutation planning, closing comments, staleness guard"
```

---

### Task 3: apply/setup subcommands; run setup live

**Files:**
- Modify: `scripts/triage.py` (append gh runner, `apply`, `setup`, `main`)
- Test: `tests/test_triage.py` (append `TestApply`)

**Interfaces:**
- Consumes: everything from Tasks 1–2.
- Produces: `gh(argv, runner=subprocess.run) -> str` (stdout; backoff on rate hints, `RuntimeError` otherwise), `apply(rows, dry=False, throttle=1.5, runner=..., sleep=...) -> (applied, stale)`, `setup(runner=...) -> None`, CLI `setup` / `apply [--dry-run] [--throttle S]`.

- [ ] **Step 1: Write the failing tests** (append)

```python
class FakeRunner:
    """Records argv; returns canned stdout per command prefix."""
    def __init__(self, view_json='{"state": "OPEN", "updatedAt": "2026-08-04T12:00:00Z"}'):
        self.calls, self.view_json = [], view_json

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        class R:
            returncode, stderr = 0, ""
        R.stdout = self.view_json if argv[1:3] == ["issue", "view"] else "{}"
        return R


class TestApply(unittest.TestCase):
    def test_applies_only_approved_rows_and_flips_status(self):
        rows = [fix_row(status="approved"), fix_row(issue=431, rank=2)]
        done, stale = triage.apply(rows, runner=FakeRunner(),
                                   sleep=lambda s: None)
        self.assertEqual((done, stale), (1, 0))
        self.assertEqual(rows[0]["status"], "applied")
        self.assertEqual(rows[1]["status"], "proposed")

    def test_stale_row_is_flagged_not_applied(self):
        runner = FakeRunner(view_json='{"state": "CLOSED", '
                                      '"updatedAt": "2026-08-01T00:00:00Z"}')
        rows = [fix_row(status="approved")]
        done, stale = triage.apply(rows, runner=runner, sleep=lambda s: None)
        self.assertEqual((done, stale), (0, 1))
        self.assertEqual(rows[0]["status"], "stale")
        # nothing beyond the state fetch was run
        self.assertEqual([c[1:3] for c in runner.calls], [["issue", "view"]])

    def test_dry_run_touches_nothing(self):
        runner = FakeRunner()
        rows = [fix_row(status="approved")]
        triage.apply(rows, dry=True, runner=runner, sleep=lambda s: None)
        self.assertEqual(runner.calls, [])
        self.assertEqual(rows[0]["status"], "approved")

    def test_invalid_approved_row_raises_before_any_mutation(self):
        runner = FakeRunner()
        rows = [fix_row(status="approved", rank=None)]
        with self.assertRaises(ValueError):
            triage.apply(rows, runner=runner, sleep=lambda s: None)
        self.assertEqual(runner.calls, [])
```

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `python3 -m pytest tests/test_triage.py -q`
Expected: `TestApply` errors on missing `apply`; earlier classes PASS.

- [ ] **Step 3: Implement** (append)

```python
RATE_HINTS = ("rate limit", "secondary rate", "abuse detection",
              "was submitted too quickly")


def gh(argv, runner=subprocess.run, sleep=time.sleep):
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


def apply(rows, dry=False, throttle=1.5, runner=subprocess.run,
          sleep=time.sleep):
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


def setup(runner=subprocess.run):
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_triage.py -q`
Expected: all PASS. Also run the full suite once (`python3 -m pytest -q`) to
confirm nothing else broke.

- [ ] **Step 5: Run setup live**

```bash
export GH_CONFIG_DIR="$HOME/.config/gh-psyberone"
python3 scripts/triage.py setup
```

Expected: five `label triage:*` lines and `milestone created: Remediation 1`.
Verify: `gh label list | grep triage` shows 5; milestone visible on GitHub.

- [ ] **Step 6: Commit**

```bash
git add scripts/triage.py tests/test_triage.py
git commit -m "feat(triage): apply/setup subcommands with throttle, backoff, staleness"
```

---

### Task 4: Batch B1 — the 15 FIXMEs

**Files:**
- Create: `docs/superpowers/2026-08-04-remediation-triage-log.md` (header + B1 table)
- Ledger: 16 new rows (15 FIXMEs + the #58 duplicate pull), `set: "FIXME"`, `batch: "B1"`

**Interfaces:**
- Consumes: `scripts/triage.py apply`, the Shared Definitions procedure/templates.
- Produces: applied dispositions for #431–#444 and #446; the log doc that Tasks 5–7 append to.

- [ ] **Step 1:** Run the per-batch procedure over issues #431, #432, #433, #434, #435, #436, #437, #438, #439, #440, #441, #442, #443, #444, #446. Known landmarks the triage must resolve (verify, don't assume): FIXME-15 (#446) is the `already-fixed` candidate — its fix shipped in PR #447; spot-check + `fixed_by` required. HIGH #58 duplicates FIXME-6 (#436) — close #58 in this batch as `duplicate` (the one cross-stratum pull B1 makes; it saves B3 a stray). FIXME-12 (#442) rationale should note the fix is now a port of the `file_issues.py` ledger pattern.
- [ ] **Step 2:** Present the disposition table. **STOP — user gate.**
- [ ] **Step 3:** On approval flip rows to `approved`, run `python3 scripts/triage.py apply` (with `GH_CONFIG_DIR` exported), verify every row prints `applied`.
- [ ] **Step 4:** Create the log doc with a header block (arc name, spec link, date) and the B1 table; commit:

```bash
git add docs/superpowers/2026-08-04-remediation-triage-log.md
git commit -m "docs(triage): batch B1 — FIXME dispositions"
```

---

### Task 5: Batch B2 — the 5 CRITICALs

**Files:**
- Modify: `docs/superpowers/2026-08-04-remediation-triage-log.md` (append B2 table)
- Ledger: 5 new rows, `set: "CRITICAL"`, `batch: "B2"`

**Interfaces:**
- Consumes: same as Task 4; log doc exists.
- Produces: applied dispositions for #82, #229, #418, #422, #330.

- [ ] **Step 1:** Per-batch procedure over #82, #229 (advisor-confirmed roslyn `dotnet build` pair — expected `fix`, ranked at/near the top; decide which is canonical and whether the other is `duplicate` or a distinct panel-scoped fix item) and #418, #422, #330 (`evidence:rejected` — advisor spot-check REQUIRED for each before any may close as `reject`; #418/#422 look like fixture-file eval findings, but the spot-check decides, not the smell).
- [ ] **Step 2:** Disposition table. **STOP — user gate.**
- [ ] **Step 3:** Flip approved → `apply` → verify.
- [ ] **Step 4:** Append B2 table to the log doc; commit (`docs(triage): batch B2 — CRITICAL dispositions`).

---

### Task 6: Batches B3a–B3d — the 52 HIGHs

**Files:**
- Modify: `docs/superpowers/2026-08-04-remediation-triage-log.md` (append one table per sub-batch)
- Ledger: ~51 new rows (52 minus #58 if B1 closed it), `set: "HIGH"`, `batch: "B3a"…"B3d"`

**Interfaces:**
- Consumes: same as Task 5.
- Produces: applied dispositions for every open HIGH.

- [ ] **Step 1:** List the set: `gh issue list --label severity:high --state open --limit 100 --json number,title,labels`. Group into ~4 thematic sub-batches (grouping emerges from the titles/bodies — likely clusters: scanner/adapter surface, orchestration/fan-out, supply-chain/Docker, tests/coverage). Record the grouping at the top of the B3 log section.
- [ ] **Step 2:** For each sub-batch in turn, run the full per-batch procedure (read → spot-checks for every `evidence:rejected` row and `already-fixed` candidate → proposed rows → table → **user gate** → flip → `apply` → verify → append table → commit `docs(triage): batch B3<x> — HIGH dispositions`). Landmark: #81 duplicates the #82/#229 roslyn locus — close toward B2's canonical.
- [ ] **Step 3:** After B3d, confirm zero open unlabelled HIGHs remain: `gh issue list --label severity:high --state open --json number,labels --limit 100` — every row must carry a `triage:*` label.

---

### Task 7: Global rank merge, closing summary, PR

**Files:**
- Modify: `docs/superpowers/2026-08-04-remediation-triage-log.md` (closing summary)

**Interfaces:**
- Consumes: the full ledger; all applied batches.
- Produces: the ranked Remediation 1 queue; the arc PR.

- [ ] **Step 1:** Merge per-batch provisional ranks into one global order (severity first, then cross-batch judgment — e.g. the roslyn CRITICAL outranks every HIGH; FIXME-13/#443 sits with the top HIGHs on run-integrity grounds). Record the final ordered list in the closing summary; update each fix row's `rank` in the ledger to the global rank.
- [ ] **Step 2:** Write the closing summary in the log doc: verdict counts per batch, spot-check count and **overturn rate** (spot-checks that reversed an advisor rejection — the calibration number), stale/re-triaged items, and the final ranked queue.
- [ ] **Step 3:** Sanity pass: milestone membership equals the set of `fix` rows (`gh issue list --milestone "Remediation 1" --state open --json number --limit 100`); every in-scope issue carries exactly one `triage:*` label.
- [ ] **Step 4:** Commit the summary, push the branch, open the PR:

```bash
export GH_CONFIG_DIR="$HOME/.config/gh-psyberone"
git add docs/superpowers/2026-08-04-remediation-triage-log.md
git commit -m "docs(triage): closing summary and global fix-queue order"
git -c credential.helper= -c credential.helper='!gh auth git-credential' push -u origin docs/remediation-triage
gh pr create --title "Remediation triage: FIXMEs, CRITICALs, HIGHs dispositioned" --body "..."
```

PR body: link the spec, the log doc, verdict counts, overturn rate, and the
milestone URL. End with the standard generated-with footer.
