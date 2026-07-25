# Lens Catalog

The scout selects lenses per panel; each panel agent receives the relevant lens
blocks as review emphasis. Names map 1:1 to the original 9 reviewers.

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
### quality — validity
Vacuous/tautological tests, over-mocking, false assertions, flaky/brittle tests,
assertion quality, test-data realism.
### design — maintainability
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
