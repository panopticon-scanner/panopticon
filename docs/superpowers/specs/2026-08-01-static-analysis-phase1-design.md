# Panopticon Static-Analysis Expansion — Phase 1 Design

> **Goal:** Add dependency-vulnerability and language-security scanners to panopticon so every finding can cite CVE/CWE/OWASP sources with a clear "discovered by tool, expanded by agent" provenance chain.

## Context

Panopticon currently runs a Docker-based tool suite (`semgrep`, `bandit`, `trivy`, `gitleaks`, `gosec`, `brakeman`, `eslint`) and ingests SARIF output into a normalized `CodeReviewReport`. Citation enrichment already exists for CWE, OWASP, SSVC, CVE, and optional EPSS lookups. The weakest gap relative to other code-review and security-scanning products is **coverage**: they run broader dependency and language-specific scanners and anchor every result with hard citations. This design closes that gap incrementally, starting with the lowest-risk, highest-value expansion.

## Constraints

- **Maximum coverage** over time, delivered in phases.
- **Single fat Docker image** for local and CI runs.
- **SARIF-first, with JSON/XML converters** for tools that do not emit SARIF natively.
- **Open-source friendly**: self-contained adapters, no proprietary services, no API keys required.
- **Read-only reviews**: scanners only parse source; they never execute untrusted code.

## Phase 1 Tool Set

| Tool | Purpose | Native Output | Ecosystem |
|---|---|---|---|
| `pip-audit` | Python dependency CVEs | JSON | Python (`requirements*.txt`, `pyproject.toml`) |
| `npm audit` | Node dependency CVEs | JSON | Node.js (`package-lock.json`, `npm-shrinkwrap.json`) |
| `osv-scanner` | Cross-ecosystem OSV advisories | JSON | Python, Node, Go, Rust, Maven, etc. |
| `eslint-plugin-security` | JS/TS security anti-patterns | JSON (via ESLint) | JavaScript / TypeScript |

These tools were chosen because they:
- Run quickly against source and lockfiles without needing a build.
- Emit structured JSON that can be converted to panopticon findings.
- Produce CVE/CWE/OWASP citations that strengthen the report.
- Add minimal image bloat compared to build-dependent alternatives.

## Architecture

### Adapter modules

Create a `scripts/tools/` package. Each scanner is a self-contained adapter module with two required functions:

```python
def invoke(target: str, config: dict | None = None) -> tuple[bytes, int]:
    """Run the scanner against target and return raw output + exit code."""
    ...

def parse(raw: bytes, tool_name: str, group: str) -> list[dict]:
    """Convert native output into panopticon findings."""
    ...
```

Adapters in Phase 1:
- `scripts/tools/pip_audit.py`
- `scripts/tools/npm_audit.py`
- `scripts/tools/osv_scanner.py`
- `scripts/tools/eslint_security.py`

Each adapter is responsible for:
- Detecting whether the target has the required files (e.g., `package-lock.json`).
- Returning an empty list if the ecosystem is not present.
- Normalizing severities to panopticon's CRITICAL/HIGH/MEDIUM/LOW/INFO scale.
- Populating `citations.cve`, `citations.cwe`, and `citations.owasp` when available.
- Setting `source: "tool:<name>"` on every finding.

### Runner dispatch

`scripts/run_tools.py` becomes a dispatcher:

1. Detect languages and lockfiles in the target repo.
2. Select the relevant adapters.
3. Run each adapter inside the existing `panopticon-tools` Docker container with `/src` mounted read-only.
4. Write raw output to `.panopticon/tools/<tool>.<ext>`.
5. Return the list of raw-output paths.

The existing `TOOL_CMD` map is replaced by adapter registration. Example:

```python
ADAPTERS = {
    "pip-audit": pip_audit,
    "npm-audit": npm_audit,
    "osv-scanner": osv_scanner,
    "eslint-security": eslint_security,
}
```

### Ingestion

`scripts/ingest_tools.py` is simplified:
- It no longer parses SARIF directly for every tool.
- It reads raw output files from `.panopticon/tools/`.
- It routes each file to the matching adapter's `parse()` function.
- It validates that every finding has the required fields and a valid `source` tag.

SARIF ingestion for existing tools (`semgrep`, `bandit`, etc.) is preserved by wrapping them in thin adapters or keeping the current SARIF parser as a legacy adapter.

### Provenance model

Every finding must expose its origin:

| Field | Values | Meaning |
|---|---|---|
| `source` | `"tool:<name>"`, `"agent:<panel>"`, `"hybrid"` | Where the finding originated |
| `reinforced` | boolean | True when both a tool and an agent flagged the same locus |
| `corroborated_by` | list of panel/tool names | Other reviewers/tools that agreed |
| `tool_evidence` | object | Optional raw rule/advisory metadata (rule ID, CVE, affected package, fixed version, advisory URL) |

When an agent expands on a tool finding, the agent's description is kept but the tool's citations and `tool_evidence` are preserved. This produces findings that read like agent-authored analysis but are grounded in scanner data.

### Citation enrichment

The existing `scripts/citations.py` pipeline remains in place:
- Validate CWEs against `reference/cwe-catalog.json`.
- Derive OWASP Top 10 mappings from CWEs.
- Enrich CVEs with EPSS scores when `--epss` is enabled.
- Add SSVC decisioning for HIGH/CRITICAL security findings.

Adapters must emit CWE IDs in the format `CWE-XXX` and CVE IDs in the format `CVE-YYYY-NNNNNN` so enrichment can process them.

### Deduplication

`scripts/synthesize.py` already clusters findings by `(file, line)`. Extend the logic:
- Tool-only findings: dedupe by `(file, line, cve_or_rule_id)`.
- Tool + agent findings at the same locus: reinforce the agent finding with the tool's citations and `source`, rather than creating two separate findings.
- Distinct categories at the same locus are kept separate (e.g., an N+1 query and a missing auth check on the same line).

## Dockerfile Changes

Add to `Dockerfile`:

```dockerfile
# Python dependency audit
RUN pip install --no-cache-dir pip-audit

# OSV scanner (static Go binary)
ARG OSV_SCANNER_VERSION=1.8.2
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in amd64) osv="linux-amd64" ;; arm64) osv="linux-arm64" ;; *) osv="linux-${arch}" ;; esac \
    && curl -sfL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${OSV_SCANNER_VERSION}_${osv}" \
        -o /usr/local/bin/osv-scanner \
    && chmod +x /usr/local/bin/osv-scanner

# eslint-plugin-security is installed alongside existing ESLint packages
RUN npm install -g eslint-plugin-security
```

Target: keep the image build under 15 minutes on a typical CI runner.

## Schema Additions

Extend the finding schema in `reference/report-schema.json`:

```json
"tool_evidence": {
  "type": "object",
  "properties": {
    "rule_id": { "type": "string" },
    "advisory_url": { "type": "string" },
    "package_name": { "type": "string" },
    "vulnerable_versions": { "type": "string" },
    "fixed_version": { "type": "string" },
    "cvss_score": { "type": "number" }
  }
}
```

Add `tool_evidence` to allowed finding properties. It is optional and only populated by tool adapters.

## Testing

Add fixture repos under `tests/fixtures/`:
- `vulnerable-python/` — `requirements.txt` with a known vulnerable package.
- `vulnerable-node/` — `package.json` + `package-lock.json` with a known vulnerable package.
- `insecure-js/` — JS files triggering `eslint-plugin-security` rules.

Tests assert:
- Each adapter detects the expected ecosystem.
- Each adapter produces at least one finding with valid CVE/CWE citations.
- `ingest_tools.py` merges tool findings without dropping citations.
- `synthesize.py` correctly marks tool findings as `source: "tool:<name>"`.

## Evaluation

Create a `benchmarks/` directory with a small set of public vulnerable-by-design repos (e.g., OWASP WebGoat, Juice Shop, or smaller fixtures). Run panopticon before and after Phase 1 and report:
- Number of HIGH/CRITICAL findings.
- Percentage of findings with CVE or CWE citations.
- False-positive rate estimate (manually sampled).

This benchmark becomes the foundation for measuring panopticon's catch rate and citation density over time.

## Phased Roadmap

- **Phase 1** (this spec): Python/JS dependency and security scanners.
- **Phase 2**: Java/Kotlin (`PMD`, `SpotBugs` + FindSecBugs, `detekt`, `OWASP dependency-check`).
- **Phase 3**: Rust, C#, and systems languages (`clippy`, `cargo-audit`, `cargo-deny`, Roslyn analyzers).
- **Phase 4**: Cross-tool intelligence, deduplication scoring, public benchmark corpus.

## Open-Source Considerations

- Adapters are self-contained; a contributor adds a new tool by creating one file in `scripts/tools/` and registering it in `run_tools.py`.
- No proprietary services or API keys are required for Phase 1.
- Tool selection is config-driven; users can opt out of slow or noisy tools via CLI flags.
- Documentation includes how to run individual adapters locally for debugging.

## Success Criteria

- `panopticon-tools` Docker image builds successfully with all Phase 1 tools.
- A scan of a Python + Node repo reports dependency CVEs with CVE/CWE citations.
- A scan of an insecure JS repo reports `eslint-plugin-security` findings with CWE citations.
- The synthesized report clearly distinguishes tool findings from agent findings via `source`.
- All new code is covered by tests.

## Out of Scope

- Build-dependent tools that require a full project build or external server.
- Paid or API-key-dependent services.
- Non-security linters (formatters, style-only tools) unless they produce security-relevant findings.
