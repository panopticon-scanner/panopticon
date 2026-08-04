# Self-Scan → Issue Tracker — Handoff

**State at handoff (2026-08-04):** branch `feat/evidence-integrity` holds two
commits (afd89f9 PR-A integrity + labels, f16710b PR-B issue fidelity), pushed,
PR not yet opened. Tests 531 passed / 7 skipped, ruff clean. Labels already
applied to the GitHub repo (22 labels, `bash .github/apply-labels.sh`).

## Next steps, in order

1. Open the PR for `feat/evidence-integrity` (both commits, one PR — or split
   if preferred), get CI green, merge.
2. **Re-run the self-scan with tool output fed in from the start** — the whole
   pipeline per SKILL.md, with `--tools-dir .panopticon/tools --tools-exclude
   'tests/fixtures/*'` present in BOTH synthesize passes.
3. File every finding from that run as a GitHub issue — including cosmetic ones.
   Cosmetic/accepted items get `wont-fix` + reasoning in the issue body; nothing
   is silently dropped.

## Issue conventions (decided)

- Labels: `severity:*` × `evidence:*` × `panel:*` + process labels
  (`self-scan`, `wont-fix`, `adjudication-needed`, `cosmetic`,
  `false-positive`). Catalog: `.github/labels.yml`.
- Every issue body carries the finding's `fingerprint` (stable across runs) and
  a pointer to the generating report artifact, or the round trip does not close.
- Severity is the finding's claimed severity; if triage disagrees that is
  recorded as a comment, not by silently rewriting the label.

## Carry-forward items for the issue list

- **Adjudication needed:** `INJ-001` vs `CMD-078` — two advisors returned
  OPPOSITE verdicts on the same locus (`run_fixture_tests.py:53` shell
  injection). One CONFIRMED, one REJECTED on trust-boundary grounds. File one
  issue with `adjudication-needed`, not two.
- **Advisor severity corrections to apply when filing:** both structural HIGHs
  (`STRUCT-001` synthesize.py, `STRUCT-002` orchestrator.py) were confirmed as
  facts but downgraded to LOW/MEDIUM by advisors, and their CWE-1176 citations
  were called misapplied (CWE-1080/1120 correct).
- **Already fixed by PR A/B — do NOT file, or file+close as fixed:** SEC-101
  (HTML XSS), SEC-102 (forgeable source/reinforced), schema-errors silence,
  tool-findings duplication, 438-char titles, `--tools-dir` silent skip.
- **Known gaps to file as issues:** `._N` group naming from basename('.');
  `--max-verify` severity ties break on input order (starved SEC-102 of
  verification); orchestrator context is the fan-out bottleneck under
  enforcement (reviewers are read-only, so all findings transit the
  orchestrator); scout profiled `tests/fixtures/vulnerable-rust` as high-risk
  production code — fixture exclusion exists for tools but not for agents.
- **Coverage gap to state honestly:** the 2026-08-03 scan reviewed 5 of 11
  groups (`._1 ._4 ._5 ._6 ._7`); `._2`/`._3` (25 design docs) and
  `._8`–`._11` (fixtures + adapter tests) were deferred.
- Prior round-3 ledger (unrelated to the scan): `--render-scout`, version
  single-sourcing (pyproject still 3.0.0), sys.path convention, HTML
  evidence-axis rendering, content-verifying registration detection.

## Artifacts

- `docs/superpowers/2026-08-03-self-scan-report.json` — the scan report
  (copied out of gitignored `.panopticon/` so it survives).
- `.panopticon/` — working dir for the run (gitignored, may be wiped).
