# Remediation Triage — FIXMEs, CRITICALs, HIGHs

**Date:** 2026-08-04
**Status:** Approved (pending spec review)
**Scope:** Disposition-only triage of the run-2 backlog's top strata: the 15
FIXME issues, then the 5 open CRITICALs, then the 52 open HIGHs (~72 items).
Fixing is a separate follow-on arc that consumes this arc's output. Mediums and
lows are untouched except where one duplicates an in-scope item.

## Context

Run 2 of the self-scan is complete and fully filed: 401 finding issues plus
FIXMEs 1–15 (see `docs/superpowers/2026-08-04-self-scan-report.json` and the
run-2 FIXME doc). The filing scripts filed *everything*, including the 104
advisor-rejected findings — so the open backlog (416 issues) mixes confirmed
signal, known duplicates, and findings the advisors already refuted. Three of
the five open CRITICALs are `evidence:rejected`; only the roslyn `dotnet build`
pair (#82, #229) is confirmed. Before any fix arc can be ranked honestly, the
top strata need dispositions.

Decisions locked during brainstorming:

1. **Disposition pass, not triage-and-fix.** Every in-scope issue gets a
   recorded verdict; remediation is a separate arc working the resulting queue.
2. **Rejected class: spot-check then close.** Rejected CRITICALs/HIGHs get a
   fresh code-state check before closing; the advisor verdict alone is not
   sufficient grounds at these severities.
3. **Batch review gate.** Nothing mutates GitHub until the user approves the
   batch's disposition table.
4. **Hybrid execution.** Triage judgment (dedup, ranking) is inline and
   sequential; code-state verification fans out to `panopticon-advisor`
   subagents (Read/Grep/Glob only) in parallel.

## Section 1: Scope and batch order

- **B1 — FIXMEs (15):** issues #431–#446 (no #445). Severity mix: 4 high
  (FIXME-5, -10, -12, -13), 7 medium, 4 low. All 15 are triaged regardless of
  severity — "all of the FIXMEs" is the mandate.
- **B2 — CRITICALs (5):** #82, #229 (advisor-confirmed, same roslyn locus);
  #418, #422, #330 (advisor-rejected).
- **B3a–B3d — HIGHs (52):** split into ~4 thematic batches at triage time
  (grouping emerges from reading the issues, not decided up front).

Cross-set duplicates resolve toward the canonical issue: the issue that will
carry the fix stays open; the duplicate closes citing it. Known examples:
HIGH #81 → the #82/#229 roslyn pair; HIGH #58 → FIXME-6 (#436). A medium/low
issue encountered as a duplicate of an in-scope item may be closed as such;
that is the only medium/low mutation this arc makes.

## Section 2: Verdicts and GitHub effects

Five verdicts. Each application = one `triage:*` label + one rationale comment,
plus the state change:

| Verdict | Label | Issue state | Comment cites |
|---|---|---|---|
| fix | `triage:fix` | open, added to milestone **Remediation 1** | rationale + rank |
| duplicate | `triage:duplicate` | closed (not planned) | canonical issue |
| already-fixed | `triage:already-fixed` | closed (completed) | fixing commit/PR |
| reject | `triage:rejected` | closed (not planned) | advisor rationale + spot-check result |
| defer | `triage:deferred` | open | why it's parked, what unblocks it |

The **Remediation 1 milestone is the fix queue**. Rank order lives in the
ledger and the batch summaries (milestones don't order). Ranks assigned during
a batch are provisional within that batch; the closing summary (Section 6)
merges them into one global queue order, which is what the fix arc consumes.

Labels and the milestone are created once, up front, before B1.

## Section 3: Ledger and audit trail

- **Resume state (local, uncommitted):** `.panopticon/triage-ledger.jsonl` —
  `.panopticon/` is gitignored, matching the filing scripts' resume ledgers.
  One row per issue:
  `{issue, set, verdict, rationale, duplicate_of?, fixed_by?, spot_check?,
  rank?, status, batch}` with `status` walking `proposed → approved →
  applied`. Interrupted work resumes from unapplied rows.
- **Audit trail (durable):** the applied labels/comments/closes on GitHub are
  the system of record. Additionally, each approved batch's disposition table
  is appended to a committed log doc,
  `docs/superpowers/2026-08-04-remediation-triage-log.md`, so the arc is
  reviewable as one PR.
- Spec and log commits ride branch `docs/remediation-triage`; PR when the arc
  completes. No direct-to-main commits.

## Section 4: Advisor spot-checks

Dispatched as `panopticon-advisor` subagents (registered, enforced read-only:
Read/Grep/Glob) against the current working tree, in parallel within a batch.
Required for:

- every `evidence:rejected` CRITICAL/HIGH before it may close as `reject`;
- every `already-fixed` verdict (verify the fix actually landed, cite the
  commit);
- any confirmed finding where "is this still true on current main?" is in
  doubt.

The advisor's verdict text lands in the ledger row's `spot_check` field and in
the closing comment. **Overturns are calibration data:** if a spot-check finds
a rejected finding is real, the verdict becomes `fix` and the overturn is
counted; the closing summary reports overturn rate alongside verdict counts.
This is the same evidence axis the 4.0 model exists to measure, pointed at
the advisors themselves.

## Section 5: Per-batch process

1. Read every issue in the batch (inline — dedup and ranking need the
   cross-issue view).
2. Dispatch spot-checks in parallel where Section 4 requires them.
3. Write proposed ledger rows.
4. Present the disposition table (verdict + one-line rationale each).
5. User approves (or amends) → rows flip to `approved`.
6. Apply: labels, comments, closes, milestone adds — throttled, reusing the
   pacing/backoff lesson from `scripts/file_issues.py`.
7. Rows flip to `applied`; append the table to the committed log doc; commit.

## Section 6: Done criteria

- Every in-scope issue has an applied disposition (ledger row `applied`,
  GitHub state matches).
- Milestone **Remediation 1** holds the ranked fix queue.
- Closing summary in the log doc: verdict counts per batch, spot-check
  overturn rate, and the ranked queue the fix arc starts from.

## Error handling

- **Rate limits:** apply-step mutations are throttled with backoff (per
  `file_issues.py` precedent). A mid-apply failure is safe: the ledger resumes
  from unapplied rows.
- **Stale issue state:** if an issue changed on GitHub since triage read it
  (new comments, closed externally), the apply step skips it and flags it for
  re-triage rather than overwriting.
- **Advisor unavailability:** if `panopticon-advisor` dispatch fails, the
  affected verdicts stay `proposed` — no closing a rejected CRITICAL/HIGH
  without its spot-check.
