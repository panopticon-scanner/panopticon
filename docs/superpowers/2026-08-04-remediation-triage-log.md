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

## Batch B2 — CRITICALs (2026-08-04)

5 rows: 1 fix, 1 duplicate, 3 reject. Spot-checks: 2 advisor runs covering
the 3 rejected issues (#418/#422 share one locus and one check); **both
rejections stand — 0 overturns.**

| Rank | Issue | Verdict | Rationale |
|---|---|---|---|
| 1 | #229 | fix | `dotnet build` on scanned code: arbitrary MSBuild/NuGet execution in the networked scanning container, NVD_API_KEY passthrough; breaks the documented no-execution invariant. Canonical for the roslyn locus |
| — | #82 | duplicate → #229 | Code-panel filing of the same defect; its own advisor verdict declares the duplication |
| — | #418 | reject | Never-executed eslint-security calibration fixture; exclusion mechanism intact (re-verified). Systemic prevention queued as #434 |
| — | #422 | reject | Duplicate filing of #418's claim, same re-verified grounds |
| — | #330 | reject | CRITICAL impact mechanisms nonexistent (no version consumer, no build path — re-verified); kernel queued as #439 |

**Spot-check records:** #418/#422 — advisor NOT-REAL: fixture still two lines,
sole consumer is the static eslint lint (`test_phase1_integration.py:80-93`),
`exclude_globs` intact (`security.yml:62-63`, regression-tested). #330 —
advisor NOT-REAL: no `[build-system]`, zero version consumers; report metadata
already 4.2.0 (`synthesize.py:682`, `evidence.py:126`); only stale literals are
`pyproject.toml:3` and `citations.py:153`.

## Batch B3 — HIGHs

47 issues in four thematic sub-batches: **B3a** adapter execution surface,
**B3b** supply chain / image build, **B3c** orchestration/policy/docs drift,
**B3d** tests & parser-robustness rejected cluster. (The four FIXME HIGHs were
dispositioned in B1; #58 closed there as a duplicate.)

### B3a — adapter execution surface (2026-08-04)

11 rows: 7 fix, 3 duplicate, 1 defer. Spot-checks: 0 (no rejected-class rows;
#218's missing information lives outside the repo, per the run-2 advisor).

| Rank | Issue | Verdict | Rationale |
|---|---|---|---|
| 1 | #86 | fix | copytree symlink dereference into the build workspace; fix = escaping-symlink rejection (not `symlinks=True`); rides the #229 package |
| 2 | #218 | fix | pip-audit PEP 517 execution question; queue the settling (pin + marker-file probe) + fallback hardening in the #229 package |
| 3 | #83 | fix | eslint plugin hijack via target `node_modules` (cwd = scanned repo); pin child cwd or absolute-path plugin config |
| 4 | #210 | fix | SecurityCodeScan findings all stamped HIGH, SARIF level discarded; severity drives the CI gate — deliberate mapping needed |
| 5 | #222 | fix | SpotBugs confidence axis mapped to severity; fix spec + mapping + pinning test (two-axis invariant) |
| 6 | #253 | fix | `locations: []` → IndexError → silent loss of every C# finding; per-result guard + missing tests |
| 7 | #193 | fix | Real CWE-78 in `sh -c` interpolation, advisor-scoped LOW; cheap `shlex.quote` hardening |
| — | #85 | duplicate → #86 | Code-panel filing of the same symlink defect |
| — | #81 | duplicate → #229 | HIGH filing of the roslyn dotnet-build locus |
| — | #194 | duplicate → #193 | Verbatim duplicate; both advisors flagged the pair |
| — | #199 | defer | Untested dev-local helper with no CI/runtime path; revisit if it enters CI |

### B3b — supply chain / image build (2026-08-04)

11 rows: 3 fix, 1 duplicate, 7 reject. Spot-checks: 1 batched advisor run
covering all 7 rejected issues — **all rejections stand, 0 overturns** (every
cited install line unchanged and unpinned; no lockfile appeared; lodash
fixture still spec-mandated with detection tests).

| Rank | Issue | Verdict | Rationale |
|---|---|---|---|
| 1 | #268 | fix | Pin-and-verify umbrella for the tools image: unpinned installs, unchecksummed fetches, both curl\|sh installers, floating base image; published to ghcr, consumed by CI |
| 2 | #62 | fix | Full target read + unrestricted egress in one container; egress allow-list or offline rules/DB; the exfil channel the #229 package assumes closed |
| 3 | #303 | fix | Fixtures image: floating-`main` clones built as root, manifest lacks a ref field, own curl\|sh instance |
| — | #46 | duplicate → #268 | curl\|sh pair = two loci inside #268's umbrella |
| — | #331–#340 (6) | reject | Inverted mechanism (unpinned = most-patched, no CVE named); kernel queued as #268 |
| — | #419 | reject | Documented lodash fixture whose detection two tests assert; systemic fix is #434 |

Calibration note: the advisors rejected six near-identical scanner-style
pinning claims while the panel's correct framing of the same concern (#268)
was independently confirmed — the two-axis model separating noise from the
actionable form of the same underlying hygiene issue.
