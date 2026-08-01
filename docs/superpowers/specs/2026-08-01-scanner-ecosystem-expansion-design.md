# Scanner Ecosystem Expansion — Java/Kotlin, Rust/C#, Ruby/Rails

> **Goal:** Extend panopticon's static-analysis coverage to Java/Kotlin, Rust/C#, and Ruby/Rails by adding self-contained tool adapters that follow the existing adapter pattern and emit standardized findings with CWE/CVE citations.

## Context

Panopticon Phase 1 added Python/Node dependency and language-security scanners (`pip-audit`, `npm audit`, `osv-scanner`, `eslint-plugin-security`) as pluggable adapters in `scripts/tools/`. Each adapter implements `is_applicable()`, `invoke()`, and `parse()` and is registered in `scripts/tools/__init__.py`. Raw outputs land in `.panopticon/tools/` and are routed to the matching adapter by `scripts/ingest_tools.py`.

The weakest remaining gap is **ecosystem coverage**: Java, Kotlin, Rust, C#, and Ruby/Rails projects currently rely only on generic tools (`semgrep`, `trivy`, `gitleaks`) and the legacy SARIF Brakeman path, which loses citation precision. This design closes that gap incrementally.

## Constraints

- **Single fat Docker image** for local and CI runs (image size accepted).
- **SARIF/JSON-first adapters**; tools that do not emit structured output are wrapped.
- **No proprietary services or API keys**.
- **Read-only reviews**: scanners parse source and lockfiles; they do not execute untrusted code.
- **Network-tolerant tests**: public fixture integration tests skip gracefully when the network is unavailable.
- **Zero breaking changes** to the existing `CodeReviewReport` schema or adapter protocol.

## Architecture

Each new scanner is a self-contained adapter module:

```python
class SomeAdapter:
    name = "some-tool"
    prefix = "ST"

    def is_applicable(self, target: str) -> bool: ...
    def invoke(self, target: str) -> tuple[bytes, int]: ...
    def parse(self, raw: bytes, group: str) -> list[dict]: ...
```

Adapters are responsible for:

- Detecting whether the target has the required files.
- Returning empty output (exit 0) when the ecosystem is not present.
- Normalizing severities to panopticon's `CRITICAL/HIGH/MEDIUM/LOW/INFO` scale.
- Populating `citations.cwe`, `citations.cve`, and `citations.owasp` when available.
- Setting `source: "tool:<name>"` on every finding.
- Providing `tool_evidence` (rule ID, advisory URL, package name, affected/fixed versions) for dependency findings.

Registration happens in `scripts/tools/__init__.py` and the active adapter set in `scripts/run_tools.py`.

## Wave 1 — Ruby/Rails

### Tools

| Adapter | Tool | Purpose | Native Output | Detection |
|---|---|---|---|---|
| `brakeman` | Brakeman | Rails security anti-patterns | JSON | `Gemfile`, `*.gemspec`, `config/routes.rb`, `app/` |
| `bundler-audit` | bundler-audit | Ruby dependency CVEs | JSON | `Gemfile.lock` |

### Brakeman adapter

- Invoke: `brakeman --format json --quiet --run-all-checks <target>`.
- Parse warnings array. Map Brakeman confidence (`High` → `HIGH`, `Medium` → `MEDIUM`, `Low` → `LOW`) and warning type to severity.
- Extract `warning_type`, `message`, `file`, `line`, `link`, and `code`.
- CWE mapping: Brakeman categories map to known CWEs (e.g., `SQL` → `CWE-89`, `Cross-Site Scripting` → `CWE-79`, `Mass Assignment` → `CWE-915`). Include a small lookup table; unknown categories omit CWE.
- Location uses `file` and `line` from the warning.

### bundler-audit adapter

- Invoke: `bundle-audit check --format json --update` (update advisory DB before scan).
- Parse top-level `advisories` or `insecure_sources`.
- Per-advisory: gem name, vulnerable versions, patched versions, advisory ID (e.g., `CVE-YYYY-NNNN` or `GHSA-...`), title, url.
- Severity default `HIGH` for known CVEs, else `MEDIUM`.
- Location: `Gemfile.lock`, line 1.

## Wave 2 — Java/Kotlin

### Tools

| Adapter | Tool | Purpose | Native Output | Detection |
|---|---|---|---|---|
| `spotbugs` | SpotBugs + FindSecBugs | Security bugs in JVM bytecode | XML/SARIF | `pom.xml`, `build.gradle`, `build.gradle.kts`, `*.jar` |
| `dependency-check` | OWASP dependency-check | Java dependency CVEs | JSON | `pom.xml`, `build.gradle`, `build.gradle.kts` |

### SpotBugs adapter

- Prefer running against compiled classes if `build/classes` or `target/classes` exists.
- Fallback: if Maven wrapper or Gradle wrapper is present, run `mvn spotbugs:spotbugs` or `gradle spotbugsMain` to produce XML.
- Parse SpotBugs XML (`BugCollection/BugInstance`): `type`, `category`, `priority`, `Class/SourceLine`.
- Map `priority` 1→HIGH, 2→MEDIUM, 3→LOW.
- FindSecBugs bug types map to CWEs via a lookup table.
- Location: `SourceLine@sourcepath` and `@start`.

### OWASP dependency-check adapter

- Invoke: `dependency-check.sh --project panopticon --scan <target> --format JSON --out <tmp>`.
- Parse `dependencies[].vulnerabilities[]`: `name` (CVE), `severity`, `cwes`, `description`, `references`.
- Location: manifest file (`pom.xml` or `build.gradle`), line 1.

## Wave 3 — Rust / C#

### Tools

| Adapter | Tool | Purpose | Native Output | Detection |
|---|---|---|---|---|
| `cargo-audit` | cargo-audit | Rust dependency CVEs | JSON | `Cargo.toml` + `Cargo.lock` |
| `roslyn-secguard` | SecurityCodeScan / Roslyn Security Guard | C# security analyzer warnings | SARIF | `*.csproj`, `*.sln` |

### cargo-audit adapter

- Invoke: `cargo audit --format json`.
- Parse `vulnerabilities.list[]`: `advisory.id`, `advisory.title`, `advisory.cvss`, `advisory.url`, `package.name`, `package.version`, `versions.patched`.
- Severity from CVSS score or advisory keywords; default `HIGH`.
- Location: `Cargo.toml`, line 1.

### Roslyn Security Guard adapter

- Install the `SecurityCodeScan` NuGet analyzer into a temporary build graph or require it in the target repo.
- Invoke: `dotnet build -p:TreatWarningsAsErrors=false` and capture MSBuild binary log, or run the analyzer CLI if available.
- Parse SARIF output from the analyzer.
- Map rule IDs to CWEs via a lookup table.
- Location: `*.cs` file and line from SARIF.

> **Note:** The C# adapter is the most experimental wave. If `dotnet`/SecurityCodeScan proves too brittle inside the fat image, the fallback is to parse SARIF produced by the existing `semgrep` C# rules and emit a narrower adapter.

## Dockerfile Changes

Install language runtimes and scanners into the single `panopticon-tools` image:

```dockerfile
# Ruby + Brakeman + bundler-audit
RUN apt-get update && apt-get install -y ruby ruby-dev build-essential \
    && gem install brakeman bundler-audit

# OpenJDK + SpotBugs + FindSecBugs + OWASP dependency-check
ARG DEBIAN_ZULU_KEY=https://...
RUN apt-get install -y default-jdk
ARG SPOTBUGS_VERSION=4.8.6
RUN curl -sfL "https://github.com/spotbugs/spotbugs/releases/download/${SPOTBUGS_VERSION}/spotbugs-${SPOTBUGS_VERSION}.tgz" \
    | tar -xz -C /opt
ARG DEPENDENCY_CHECK_VERSION=10.0.3
RUN curl -sfL "https://github.com/jeremylong/DependencyCheck/releases/download/v${DEPENDENCY_CHECK_VERSION}/dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip" \
    -o /tmp/dc.zip && unzip /tmp/dc.zip -d /opt/dependency-check
# FindSecBugs plugin downloaded into SpotBugs plugin dir

# Rust + cargo-audit
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-audit

# .NET SDK + SecurityCodeScan
RUN curl -sfL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0
ENV PATH="/root/.dotnet:${PATH}"
```

Target: keep image build under 20 minutes on a typical CI runner; monitor size.

## Integration with Existing Pipeline

- `scripts/tools/__init__.py` registers each new adapter.
- `scripts/run_tools.py` adds the new adapters to a `PHASE2_ADAPTERS` set and includes them in default adapter selection when `select_adapters()` is called.
- `scripts/ingest_tools.py` requires no changes; raw files are routed by basename.
- No changes to `reference/report-schema.json` or `scripts/synthesize.py`.

## Testing

### Unit tests

For each adapter, add `tests/tools/test_<name>.py` with canned raw output fixtures and assert:
- `is_applicable()` returns True/False for the right directory contents.
- `parse()` produces at least one finding with valid fields and CWE/CVE citations.
- Severity normalization works.

### Integration tests

Add `tests/tools/test_<name>_integration.py` for each wave. Each test clones a small public vulnerable-by-design repo into a temporary directory, runs the adapter, and asserts at least one HIGH/CRITICAL finding.

| Adapter | Public fixture |
|---|---|
| Brakeman | `https://github.com/OWASP/railsgoat` |
| bundler-audit | `https://github.com/OWASP/railsgoat` |
| SpotBugs/FindSecBugs | `https://github.com/WebGoat/WebGoat` or a minimal Maven project |
| dependency-check | `https://github.com/WebGoat/WebGoat` |
| cargo-audit | `https://github.com/RustSec/advisory-db` example repo |
| Roslyn SecGuard | `https://github.com/security-code-scan/security-code-scan` sample |

Integration tests must:
- Skip gracefully if the network is unreachable (`pytest.skip("network unavailable")`).
- Skip if the required runtime is missing in the current environment.
- Time-box tool invocations (reuse existing `TOOL_TIMEOUT`).

## Success Criteria

- `panopticon-tools` Docker image builds with all new runtimes installed.
- A scan of a Rails project reports Brakeman findings with CWE citations.
- A scan of a Java Maven/Gradle project reports SpotBugs/FindSecBugs and dependency-check findings with CWE/CVE citations.
- A scan of a Rust project reports `cargo-audit` dependency CVEs.
- A scan of a C# project reports Roslyn analyzer warnings (or skips cleanly if unsupported).
- All new code is covered by unit tests; integration tests exist and skip gracefully offline.
- Full test suite and lint remain green.

## Out of Scope

- Build-dependent dynamic analysis that requires running the target application.
- Proprietary SAST services or API-key-dependent tools.
- IDE-specific analyzers or lint rules that are not security-relevant.
- Splitting the Docker image into per-ecosystem tags.

## Phased Roadmap

- **Wave 1:** Ruby/Rails (Brakeman + bundler-audit).
- **Wave 2:** Java/Kotlin (SpotBugs + FindSecBugs + OWASP dependency-check).
- **Wave 3:** Rust/C# (`cargo-audit` + Roslyn Security Guard).

Each wave is independently testable and can be merged when its tests pass.
