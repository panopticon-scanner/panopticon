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
| — | #331, #332, #337, #338, #339, #340 | reject | Inverted mechanism (unpinned = most-patched, no CVE named); kernel queued as #268 |
| — | #419 | reject | Documented lodash fixture whose detection two tests assert; systemic fix is #434 |

Calibration note: the advisors rejected six near-identical scanner-style
pinning claims while the panel's correct framing of the same concern (#268)
was independently confirmed — the two-axis model separating noise from the
actionable form of the same underlying hygiene issue.

### B3c — orchestration, policy, docs drift (2026-08-04)

10 rows: 7 fix, 1 duplicate, 2 reject. Spot-checks: 1 advisor run covering
both rejected issues — **both stand, 0 overturns.**

| Rank | Issue | Verdict | Rationale |
|---|---|---|---|
| 1 | #146 | fix | Clean-tree check exempts `.panopticon/`; add plan-vs-artifact reconciliation; rides the #436 write-scoping package |
| 2 | #275 | fix | Silent advisory degradation on unregistered hosts; make it loud + content-verifying registration |
| 3 | #171 | fix | `secrets_config`/`concurrency` surfaces route nowhere (real run dropped a security panel); scout-contract package |
| 4 | #166 | fix | Scout cheat sheet omits redteam; scout-contract package |
| 5 | #155 | fix | Phantom `-e/--explore` mode documented in three places; implement or excise |
| 6 | #49 | fix | README `--mode` flags exist nowhere; docs alignment with #155 |
| 7 | #154 | fix | Stale spec prescribes removed severity-downgrade; mark superseded |
| — | #38 | duplicate → #439 | Version-literal kernel of FIXME-9; test-pinning detail transfers |
| — | #361 | reject | Confidence defaulted pre-validation (re-verified); residual reviewer-contract kernel → #431/#432 package |
| — | #368 | reject | Zero concurrency in codebase; benign lazy init (re-verified) |

### B3d — tests & parser robustness (2026-08-04)

15 rows: 5 fix, 10 reject. Spot-checks: 1 batched advisor run covering all 10
rejected issues — **all stand, 0 overturns.**

| Rank | Issue | Verdict | Rationale |
|---|---|---|---|
| 1 | #117 | fix | `_cvss_v3_score` untested; swallowed exceptions silently default severity to HIGH |
| 2 | #79 | fix | dependency_check invoke/is_applicable lack effective unit coverage; convention outlier |
| 3 | #114 | fix | `assertTrue(True)` tautology test; replace or delete |
| 4 | #65 | fix | Mid-file `__main__` guard silently skips five tests under direct execution; move to EOF |
| 5 | #106 | fix | Manual global monkey-patching, lone outlier vs `mock.patch` convention |
| — | #353 | reject | Claimed discovery mechanism false; the real narrow defect is queued as #65 |
| — | #333 | reject | `sarif_file` accepts a directory by contract; proposed input doesn't exist |
| — | #344/#345/#346 | reject | FIXTURE_ROOT is the trusted base by design; no boundary asserted |
| — | #394/#398/#399 | reject | Ingest boundary is the documented, tested handler; pattern uniform across adapters |
| — | #378 | reject | Premise false — `TestRunAdapterHelper` covers the named handlers |
| — | #401 | reject | Claimed missing safety net exists and is regression-tested |

Consistency note: the advisors confirmed #253 (silent clean-looking scan) while
rejecting #394/#398/#401 (announced stderr-skip = documented design) — the
degradation-semantics line held across five independent advisor runs.

## Closing summary (2026-08-04)

**68 issues dispositioned, 0 stale, 0 apply failures.**

| Batch | fix | duplicate | reject | defer | spot-checks |
|---|---|---|---|---|---|
| B1 FIXMEs | 14 | 1 | 0 | 1 | 1 run / 1 issue |
| B2 CRITICALs | 1 | 1 | 3 | 0 | 2 runs / 3 issues |
| B3a adapter execution | 7 | 3 | 0 | 1 | 0 |
| B3b supply chain | 3 | 1 | 7 | 0 | 1 run / 7 issues |
| B3c orchestration/docs | 7 | 1 | 2 | 0 | 1 run / 2 issues |
| B3d tests/robustness | 5 | 0 | 10 | 0 | 1 run / 10 issues |
| **Total** | **37** | **7** | **22** | **2** | **6 runs / 23 issues** |

**Calibration numbers.** Advisor-rejection overturn rate: **0 of 22** — every
run-2 rejection re-verified against the current tree survived its spot-check.
The one overturn ran the other direction: the operator's `already-fixed`
hypothesis for #446 (FIXME-15) was refuted by its spot-check (PR #447 shipped
documentation, not code). Advisors also held a consistent degradation-semantics
line (silent failure confirmed, announced failure rejected) across independent
runs. Net: the run-2 evidence axis emerges from triage strengthened on both
sides — its confirmations ranked cleanly, and its rejections closed noise.

**Issue-state effect:** 29 closed (7 duplicates, 22 rejects), 39 remain open
(37 in milestone Remediation 1, 2 parked with `triage:deferred`). Every open
CRITICAL/HIGH now carries exactly one `triage:*` label.

**The Remediation 1 queue, global order** (severity first, then package
cohesion — within-batch provisional ranks were adjusted where subsystem
clustering demanded it):

| # | Issue | Package |
|---|---|---|
| 1 | #229 dotnet-build execution | P1 adapter-execution security |
| 2 | #86 symlink dereference | P1 |
| 3 | #218 pip-audit PEP 517 question | P1 |
| 4 | #62 egress posture | P1 |
| 5 | #443 verify-queue identity (FIXME-13) | P2 run integrity |
| 6 | #446 tool-axis verification (FIXME-15) | P2 |
| 7 | #438 deterministic tie-break (FIXME-8) | P2 |
| 8 | #435 group_runner role (FIXME-5) | P3 fan-out architecture |
| 9 | #442 fan-out resume (FIXME-12) | P3 |
| 10 | #440 panel-priority dispatch (FIXME-10) | P3 |
| 11 | #436 scoped write surface (FIXME-6) | P3 |
| 12 | #444 group_runner contract (FIXME-14) | P3 |
| 13 | #146 plan-vs-artifact reconciliation | P3 |
| 14 | #275 loud enforcement degradation | P3 |
| 15 | #431 scout schema inline (FIXME-1) | P4 scout/reviewer contract |
| 16 | #432 scout compliance measurement (FIXME-2) | P4 |
| 17 | #171 secrets_config routing | P4 |
| 18 | #166 redteam cheat sheet | P4 |
| 19 | #434 fixture exclusion (FIXME-4) | P4 |
| 20 | #441 reviewer scope fence (FIXME-11) | P4 |
| 21 | #268 pin/verify tools image | P5 supply chain |
| 22 | #303 fixtures image | P5 |
| 23 | #83 eslint plugin resolution | P6 adapter fidelity |
| 24 | #210 roslyn severity mapping | P6 |
| 25 | #222 spotbugs axis swap | P6 |
| 26 | #253 locations[] guard | P6 |
| 27 | #117 _cvss_v3_score tests | P6 |
| 28 | #155 phantom explore mode | P7 docs alignment |
| 29 | #49 README flags | P7 |
| 30 | #154 stale spec supersession | P7 |
| 31 | #437 group naming (FIXME-7) | P7 |
| 32 | #439 version single-sourcing (FIXME-9) | P7 |
| 33 | #79 dependency_check tests | P8 test hygiene |
| 34 | #114 tautology test | P8 |
| 35 | #65 __main__ guard | P8 |
| 36 | #106 mock.patch swap | P8 |
| 37 | #193 shlex.quote hardening | P8 |

Deferred, outside the queue: #433 (retest after P4 lands), #199 (revisit if
run_fixture_tests enters CI). The fix arc consumes packages P1→P8 in order;
each package is roughly one PR.
