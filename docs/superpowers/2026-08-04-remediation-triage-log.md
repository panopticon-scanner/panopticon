# Remediation Triage Log

**Arc:** run-2 backlog triage — FIXMEs, then CRITICALs, then HIGHs.
**Spec:** `docs/superpowers/specs/2026-08-04-remediation-triage-design.md`
**Plan:** `docs/superpowers/plans/2026-08-04-remediation-triage.md`
**Started:** 2026-08-04. Dispositions are applied to GitHub only after a
per-batch user gate; this log is the committed record of each approved batch.
Ranks are provisional within a batch until the closing summary merges them
into the global Remediation 1 queue order.

## Batch B1 — FIXMEs (2026-08-04)

16 rows: 14 fix, 1 defer, 1 duplicate. Spot-checks: 1 (advisor), which
**overturned** the expected `already-fixed` on #446 — PR #447 documented
FIXME-15 but changed no code; the defect is present and enters the queue.

| Rank | Issue | Verdict | Rationale |
|---|---|---|---|
| 1 | #443 FIXME-13 | fix | Positional queue_ids stranded 13 verdicts, manufactured a false CRITICAL; build the queue once, key verdicts by fingerprint |
| 2 | #435 FIXME-5 | fix | Orchestrator context caps agentic coverage at 1/10 groups; first-class `group_runner` role (workaround proven in-run) |
| 3 | #442 FIXME-12 | fix | No fan-out resume; `out_file`-exists predicate, ledger pattern proven in `scripts/file_issues.py` |
| 4 | #440 FIXME-10 | fix | Truncation silences security panels first (14% vs 65%); panel-priority dispatch + planned-vs-executed meta, refuse grade on divergence |
| 5 | #446 FIXME-15 | fix | Spot-check overturn: `tool_confirmed` still gate-eligible with no verification path; route through verify queue / `tool_reported` |
| 6 | #436 FIXME-6 | fix | Unbounded sub-orchestrator Write; PreToolUse allowlist from dispatch-plan out_files; carries #58's HIGH signal |
| 7 | #444 FIXME-14 | fix | group_runner contract clauses (no stalling, resume-not-redispatch, tool-measured status); closes with #435's role text |
| 8 | #431 FIXME-1 | fix | Scout returns 0/6 required fields at the assigned tier; inline schema + skeleton in scout.md, advisory validation |
| 9 | #432 FIXME-2 | fix | ONLY-JSON contract unmeasured; compliance counting rides the FIXME-1 validation layer |
| 10 | #434 FIXME-4 | fix | No agent-side fixture exclusion (run-2 excluded a group by hand); one setting honored by discovery + ingest_tools |
| 11 | #441 FIXME-11 | fix | Reviewers read outside their group (three sightings); scope fence + drift counter in meta |
| 12 | #438 FIXME-8 | fix | `--max-verify` ties break on filename sort (starved run-1's best finding); deterministic tie-break |
| 13 | #437 FIXME-7 | fix | `._N` names leak the target basename and hide artifacts as dotfiles (misled the run-2 resume); stable non-dot token |
| 14 | #439 FIXME-9 | fix | Version 3.0.0 vs 4.2.0 across sources; single-source (umbrella for STYLE-008) |
| — | #433 FIXME-3 | defer | One observed spawn-rule violation; mechanism arrives with the #431 package — re-test then, promote if still violated |
| — | #58 | duplicate → #436 | Panel restatement of FIXME-6 at the doc locus; fix lands on the canonical |

**Spot-check record, #446:** advisor (2026-08-04) — PRESENT.
`evidence.py:17` keeps `tool_confirmed` in `GATE_ELIGIBLE_DEFAULT`;
`build_verify_queue` excludes tool-sourced findings (`evidence.py:107-108`,
locked by `tests/test_verify_queue.py:36-41`); no `tool_reported` status; no
tool-axis rejection rate in meta. Overturn count for the closing summary: 1.
