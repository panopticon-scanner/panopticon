# Lens Catalog

Lenses are pluggable focus units. The scout selects which lenses apply to a group
and whether each gets a dedicated subagent (`spawn: true`). Each lens block below
can be copied into a panel prompt as an emphasis area or handed to a dedicated lens
reviewer.

## Code panel
### structure — architecture & boundaries
Coupling, cohesion, responsibility leaks, dependency direction, dead code, duplication.

### correctness — logic & edge cases
Off-by-one, null/undefined handling, race conditions, state mutation, error handling,
resource leaks, algorithmic correctness, empty/max inputs, type conversions, float precision.

### style — maintainability
Naming, readability, comment quality, consistency with surrounding code, magic values.

## Test panel
### coverage — completeness
Untested branches, missing sad paths, uncovered error handling, boundary inputs.

### test_quality — validity
Vacuous/tautological tests, over-mocking, false assertions, flaky/brittle tests,
assertion quality, test-data realism.

### test_design — maintainability
Test structure, shared setup abuse, coupling to implementation detail, CI signal quality.

## Security panel
### known_vulns — OWASP baseline
OWASP Top 10, CWE Top 25, dependency CVEs, known-bad API usage.

### injection — input validation
SQLi, command injection, XSS, template injection, path traversal, deserialization,
SSRF, NoSQL injection, header/CRLF injection.

### novel — contextual attacks
Business-logic flaws, authz/authn edge cases, JWT/session issues, crypto misuse,
TOCTOU, mass assignment, IDOR, cache/CORS/CSP misconfig, supply-chain.

## Architecture panel
### architecture — repo & platform
Repo layout, CI/CD pipeline safety (`.github/workflows`), Dockerfile/container hygiene,
k8s/helm manifests, dependency direction, separation of concerns, deployment risks.

## Database panel
### database — data layer
SQL/ORM query safety, migration correctness, schema design, transaction boundaries,
indexing hints, data leakage, N+1 queries, raw query injection.

## Red-team panel
### redteam — adversarial chains
Assume attacker control of inputs. Hunt multi-step exploit chains, trust-boundary
bypasses, privilege escalation, shadow-IT/config abuse, and novel business-logic attacks.
For HIGH/CRITICAL findings include an exploit scenario.
