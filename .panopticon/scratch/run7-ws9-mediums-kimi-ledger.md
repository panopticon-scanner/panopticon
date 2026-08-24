# Kimi run-7 MEDIUM remediation ledger

## K1 repo-ops scripts (PR #1385)

### Addressed
- SEC-B2C scripts/file_fixmes.py:137/138 — scrubbed FIXME title/body
- SEC-B1A scripts/triage.py:102 — sanitized triage comment rationale/spot_check
- COD-F1A scripts/file_issues.py:253 — record() creates parent dir
- OPS-E1A scripts/file_issues.py:240 — load_ledger() warns on corruption
- COD-C2C scripts/reconcile_apply.py:53 — LOC_RE handles paths with colons
- ARC-F2D scripts/triage.py:82 — real ISO-8601 timestamp validation

### Dropped / overstated / FP
- TST-A1B scripts/file_issues.py:47 labels_for() coverage — already covered indirectly
- TST-A2D scripts/file_issues.py:64 title_for() truncation — low value
- TST-A3C scripts/file_issues.py:90 body_for() multi-locus branch — low value
- TST-A2B scripts/file_issues.py:351 create() retry branches — low value
- TST-A2D scripts/file_issues.py:271 resolve_part_path() guard — low value
- TST-A2B scripts/file_issues.py:384 main() continuation loading — low value
- TST-A3A scripts/triage.py:229 fully-mocked boundaries — hard to address cheaply
- [None] scripts/file_issues.py:310 subprocess finding — static argv, FP
- [None] scripts/file_issues.py:390 hook path finding — validated by resolve_part_path, FP

### Deferred
- ARC-F1A scripts/reconcile_apply.py:248 live-freshness check — design limitation
