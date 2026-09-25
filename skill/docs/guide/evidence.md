## Evidence

Findings carry two independent axes: **severity** (impact if true — never rewritten) and
**evidence.status** (how hard the claim was verified):
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
  verify coverage never certifies a clean gate (#979).
- `corroborated` — multi-panel agreement (correlated witnesses: prioritized for verification, not
  gate-eligible by default).
- `unverified` — no verification attempted.

Grades and the CI gate count `tool_confirmed`/`advisor_confirmed` findings only — i.e. only claims
an advisor verified, whatever their source. Run a verify phase (or pass `--gate-unverified`) or the
gate has nothing to fail on.

Every finding queues for verification, tool claims included, so `--max-verify N` now caps a queue
holding the whole finding set: each tool finding costs one advisor dispatch, and an unverified tool
HIGH competes with an agent HIGH for the same capped budget. Size N with that in mind — anything cut
stays `unverified` or `tool_reported` and cannot gate. Citations (CWE/OWASP/CVE/EPSS) are audit
metadata — they annotate findings but never decide truth.
