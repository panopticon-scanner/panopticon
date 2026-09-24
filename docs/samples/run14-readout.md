# Run 14 — claude redteam self-scan with the tool axis (2026-09-19/20)

Run tag `claude-redteam-repo-20260919-fe948cc1`. `driver loop . --host claude --mode headless --security redteam --tools --concurrency 2`, panopticon 5.1.0 skill on main **1d938c9** (after PR #1728: the whole post-run-13 stack — root `panopticon.yml`, Runners layer, trailing-run outage rule, discovery-surface probe, agent allowlist), OCRDb 0.5.0, Claude Code CLI 2.1.276. Started 2026-09-19 05:19 CDT, completed 2026-09-20 05:49 CDT. The full artifact set for this run (`report.json` in eight parts, `-discarded.json`, `-x0x.json`, the 4 MB `report.html` and `host-capabilities.json`) is about 10 MB and is not checked in; two screenshots of the HTML report sit beside this readout.

## Verdict

**CERTIFIED (6th), integrity clean.** `coverage_certified: true`; integrity block all-empty (0 unexpected / missing / malformed / duplicate / mislabeled / cross-domain), 66/66 content hashes, `validate.json` `tree_clean: true`, 1 plan seen, 0 empty. Host capabilities 5/5 proven (write guard, read guard, model binding, usage ledger, discovery surface). Tool axis clean: scout requested 6, 6 ran (bandit 24, eslint-security 1, gitleaks 111, osv-scanner 13, semgrep 280, trivy 37), `pip-audit` requested-unavailable disclosed, all 85 panels had scanner context.

**Grade F, risk HIGH, gate OFF (`fail_on: null`), health 48.37** (135,199 LoC vs weighted defect 144,284).

| population | count |
|---|---|
| active | **1124** — 0 CRITICAL / **13 HIGH** / 466 MEDIUM / 602 LOW / 43 INFO |
| discarded | 127 (94 tool-axis rejections, 33 agentic rejections) |
| total claims | 1251 |

Evidence over the active set: advisor_confirmed 1064, tool_confirmed 6, corroborated 2, needs_more_info 24, unverified 21, backup_scope_limited 7. Tool axis: 103 queued → 6 confirmed / 94 rejected / 3 NMI (94% rejection, same shape as runs 10–12).

## The two numbers that need the owner's eye

1. **Volume.** 1124 active vs run-12's 243 and run-13's 259 on the same repo. The population is 4.6× and the grade fell D→F on it. The advisor confirm rate is the driver: **1064 of ~1150 agentic claims confirmed (≈95%)** where runs 12/13 discarded ~30%. Every one of the 13 HIGHs is `confidence: POSSIBLE`. Candidate causes, none established: the #1657 read-confinement posture (advisors now read only the cited files and cannot refute from context), the 5.2 groups (8 groups / 85 panels vs run-12's smaller matrix), or a genuine drop in advisor scepticism at this tier. Worth a 3-seat spot check on ~20 random MEDIUMs before treating the 466 as real.
2. **Reconcile.** Against run 13: recurring 148 / closed 58 (6 HIGH) / ambiguous 156 / **new 1101**. Against run 12: recurring 153 / closed 26 (4 HIGH) / ambiguous 168 / new 1098. The "new" cohort is the volume above; `ambiguous` is reconcile's fail-closed bucket and needs human adjudication as before.

## The 13 HIGHs (10 defects, all advisor-confirmed, filed as 10 epics)

| code | file | defect | note |
|---|---|---|---|
| COD-C2C | scripts/shell_reader.py:299 | `2>&1` / `2>/dev/null` / `>&2` on a fetch are filed as the download destination → fetch-and-exec guard reports the step clean | MED→HIGH override; sibling of #1714, residual of #1647 |
| SEC-E2A | Dockerfile:46-54 | pip/gem/npm pin only top-level packages; transitive deps unpinned, unhashed | residual of #1641 |
| SEC-D1C (+COD-X0X twin) | skill/scripts/run_manifest.py:289 | `_rewrite` stages `<manifest>.tmp` with plain `open("w")` → follows a planted symlink | corroborated by 2 panels; not migrated to `_open_w_nofollow` (#1577 class) |
| TST-A1A | skill/workflows/dispatch.js:32-95 | session-mode dispatch script has no automated coverage | enforced/agentType branch untested |
| AGT-B1D | skill/scripts/phases/setup.py:30-61 | setup-scan runs as an unregistered, unenforced general-purpose agent over the whole repo | MED→HIGH override; the one role outside #1720's allowlist |
| COD-C2A (+DAT-E1D twin) | skill/scripts/diff_map.py:29-58 | an added line starting `++ ` is parsed as a file header → hunk map forged/erased, later hunks leave the on-diff gate | DAT twin MED→HIGH |
| COD-C2D (+SEC-G2B twin) | skill/scripts/discovery.py:288-317 | delta discovery reads quoted git paths without `-z` → non-ASCII-named changed files silently dropped | both MED→HIGH; whole-repo path already uses `-z` |
| ARC-F2A | skill/scripts/security_gate.py:66-86 | redteam gate re-admits only vendored-segment drops; venv/.worktrees/.panopticon/fixture drops stay silent | direct residual of #1578 |
| COD-X0X | skill/scripts/ingest_tools.py:475-480 | per-adapter cap (2000) runs before the exclusion filters → noise evicts real findings; gate never sees the truncation | catalog gap → X0X candidate |
| SEC-E3A | skill/scripts/tools/cargo_audit.py:21-23 | `cargo audit` with cwd=target honours the target's `.cargo/config.toml` alias → runs target code in the scanner container | panel CRITICAL, advisor HIGH → filed CRITICAL (higher grade wins); the #1646 class on cargo |

Not filed: none of the HIGHs is NMI this time. Cross-panel: 1 integration finding (3 panels on `.github/workflows/tools-image-health.yml`).

## Apparatus ledger (what the run cost to keep alive)

- **Three Claude session-limit walls** (resets 10:10am, 3:10pm, 1:10am), each rendered as an entry-class failure (#1729, now with three data points). Episode 1 hit the REVIEW checkpoint: 19 cells burned 3 attempts each, the phase advanced without them, verify started on a partial set → SIGTERM by PID, attempts given back by hand, resumed. Episodes 2–3 hit verify checkpoints, which held; the driver exited on the consecutive-failure rule and was relaunched after the reset (3 = after a re-login). 225 wasted launches, $0.
- **One real driver bug, found by the run and fixed mid-run:** `claude -p --json-schema` takes the schema TEXT, the shared helper passed the PATH (codex takes a path) → every tool-verify entry failed in 120 ms, 3×103 launches, driver stopped. **PR #1731 merged (main d5dcc9f)** — inline schema, 64 KiB cap, containment inside the helper, docs name both shapes; follow-up **#1732** (the cli-flags probe proves a flag's NAME, not its shape; no whole-batch stop for a uniform instant fail; ledger drops stderr). Resumed on the fixed main; 103/103 tool-verify entries then succeeded (3 prose replies rejected and retried under D10).
- **Three 1800 s timeouts** on Reporting:Synth backup advisors; each had written its verdict before the kill, the re-read accepted them (one needed a second launch).
- Cost: 916 ledger rows, **$633** reported by the envelopes, **481.3M tokens** (429.8M cache reads, 41.2M cache creation, 10.3M output; review 199M, verify 278M, scout 4.7M). Wall clock 24.5 h including ~9 h of quota waits.
- `models_used: []` and `model: null` on every dispatch row — under enforced `--agent` the model is bound by the registered shell and the envelope's `modelUsage` key is what the ledger sees; the report field is empty. Small reporting gap, worth a line on #1732 or its own LOW.

## Filed (2026-09-20, milestone 5.2)

Ten HIGH epics (SOP: one per OCRDb code; twins folded into their primary): #1733 [COD-C2C], #1734 [SEC-E2A], #1735 [SEC-D1C], #1736 [TST-A1A], #1737 [AGT-B1D], #1738 [COD-C2A], #1739 [COD-C2D], #1740 [ARC-F2A], #1741 [COD-X0X], #1742 [SEC-E3A]. #1742 filed `severity:critical` (panel CRITICAL vs advisor HIGH; higher grade wins).

Cross-links: #1578 (residuals #1739/#1740), #1714 (#1733 sibling), #1727 (#1737), #1729 (three session-limit episodes with the launch counts). Apparatus: PR #1731 merged mid-run, #1732 filed.

Not filed: the 466 MEDIUM / 602 LOW / 43 INFO tail — per the volume caveat above, the population needs a confirm-rate spot check before per-code MEDIUM epics are worth opening; owner call.
