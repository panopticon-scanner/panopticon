## Evidence

Findings carry two independent axes: **severity** (impact if true — rewritten only by the two
disclosed caps below) and **evidence.status** (how hard the claim was verified):
- `tool_reported` — a static-analysis tool emitted it (or a tool+agent same-locus merge did); no
  advisor has checked it. NOT gate-eligible.
- `tool_confirmed` — a tool reported it AND an advisor independently confirmed it. Gate-eligible.
- `advisor_confirmed` / `rejected` / `needs_more_info` — advisor verdicts from the verify phase.
  Rejected claims keep their severity and move to `discarded_claims`. A REJECTED verdict is settled
  by one advisor: the adversarial backup round is summoned only for primary-CONFIRMED findings in
  categories whose score reaches `score_gate.BACKUP_FLOOR`, so scepticism is spent on what would
  reach the gate, and the asymmetry is deliberate. The rejection is auditable rather than silent —
  every rejected claim's full advisor prose lands in `discarded_claims`. Tool-sourced findings
  follow the same rule with no backup round at all: one advisor per finding, the first parseable
  verdict is terminal, and it lands as a single-verdict file under `verdicts/<queue_id>.json`. A
  verdict that lands unloadable (a parse/schema failure surfaced at
  `meta.coverage.verdicts.unloadable`, never silently dropped) and forces `INCONCLUSIVE` — lost
  verify coverage never certifies a clean gate (#979). That count includes a bad entry inside a
  loadable bundle (not an object, no known verdict, or no `finding_id` echo; #2990), counted per
  entry.
- `corroborated` — multi-panel agreement (correlated witnesses: prioritized for verification, not
  gate-eligible by default). An agent finding's panel is its review cell's (#3254), never the
  reviewer's own `panel` field, so one cell's findings cannot corroborate each other.
- `unverified` — no verification attempted.
- `backup_scope_limited` — the primary advisor confirmed the claim and the adversarial backup could
  not check it, because the files it needed lay outside the bounded evidence closure it was granted
  (#1638 P16). A confirmed finding wearing a disclosure, not a contested one: gate-eligible, and NOT
  counted as "verified" in the report's coverage line.

Grades and the CI gate count `tool_confirmed`/`advisor_confirmed` findings, plus
`backup_scope_limited` (a primary CONFIRMED stands, #1638) — i.e. only claims an advisor verified,
whatever their source. Run a verify phase (or pass `--gate-unverified`) or the gate has nothing to
fail on.

**Two severity caps (#3231).** The active report caps two kinds of claim at MEDIUM, because nothing
confirms the HIGH they arrived with. Each capped finding says so in `severity_cap`
(`{from, reason, ...}`), and `meta.severity_capped` lists the capped ids per reason; the summary
prints a `**Capped at MEDIUM:**` line.
- `unverified_tool` — a tool-sourced CRITICAL/HIGH whose status is `tool_reported` or
  `needs_more_info`: a scanner pattern hit no advisor confirmed (on a blind advisor, that was 30–40
  semgrep audit HIGHs per run). An advisor `CONFIRMED` (`tool_confirmed`) keeps the scanner's
  severity. Never capped: a secret (a secret adapter, or a credential CWE — 798, 259, 321, 522), a
  dependency advisory (pip-audit, npm-audit, osv-scanner, bundler-audit, cargo-audit,
  dependency-check, or any finding citing a CVE). **Not under `--gate-unverified`:** that flag asks
  for the stricter policy, so there the active severity stays the scanner's and gates as such.
- `unconfirmed_coverage_absence` — an OCRDb TST-A1* ("untested-units") claim that a module has no
  test, made from a cell that cannot see the rest of the repository. It keeps HIGH only when the
  driver confirms no assigned test file anywhere is named after the module (`test_<stem>`) or
  imports it; otherwise it is capped and names up to five of those tests (`referenced_by`). The
  import witness is Python-only, so a module in any other language cannot be confirmed and is capped
  with `measured: false`. This cap applies under every gate policy: it is about the claim's premise,
  not its verification.

Under the default policy the `unverified_tool` cap changes no health, grade or risk number — every
claim it caps is already outside the gate-eligible set those read. A capped coverage-absence finding
an advisor confirmed is gate-eligible, so that cap can move health.

`skill/scripts/evidence_sections.py` owns what the HTML report does with these statuses: the
header's "N verified" counts those same two, the collapsed "Unverified findings" section holds
`tool_reported`/`needs_more_info`/`unverified` plus any status it does not know, and the rest
(`corroborated`, `backup_scope_limited`; `rejected` never reaches the report's findings) are listed
with the findings.

Every finding queues for verification, tool claims included, so `--max-verify N` now caps a queue
holding the whole finding set: each tool finding costs one advisor dispatch, and an unverified tool
HIGH competes with an agent HIGH for the same capped budget. Size N with that in mind — anything cut
stays `unverified` or `tool_reported` and cannot gate. Citations (CWE/OWASP/CVE/EPSS) are audit
metadata — they annotate findings but never decide truth.
