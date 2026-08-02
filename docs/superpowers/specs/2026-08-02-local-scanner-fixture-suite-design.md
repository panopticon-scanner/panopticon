# Local Scanner Fixture Suite — Design

> **Goal:** Provide a self-contained, Docker-based test harness that vets panopticon's language-specific scanners against real vulnerable-by-design applications. External resources are pulled only at image-build time; test runs are fully local and deterministic once the image exists.

## Context

The [Scanner Ecosystem Expansion spec](./2026-08-01-scanner-ecosystem-expansion-design.md) defines adapters for Ruby/Rails, Java/Kotlin, Rust, and C#. Its integration-test strategy relies on cloning public vulnerable repositories at test time. This design is an alternative, local-only path: public fixtures are vendored into a dedicated Docker image at build time, and a `test` command spins up that image to verify the adapters still catch expected findings.

This spec depends on the adapters from the Scanner Ecosystem Expansion spec being implemented; it provides the fixtures and harness that exercise them.

This gives us:

- No network dependency during test runs.
- A stable, reproducible target set that drifts only when we choose to rebuild.
- A way to run comprehensive scanner validation on demand without adding it to CI gates.

## Constraints

- **Local-only at runtime:** no network calls during test execution.
- **External resources OK at image-build time:** cloning GitHub repos and installing language runtimes happens inside the Dockerfile.
- **Separate image:** `panopticon-fixtures` extends `panopticon-tools` but is independent of CI gates.
- **Optional, user-triggered:** invoked via a CLI script/skill hook, not as a merge-blocking gate.
- **Long build times acceptable:** the image is built periodically, not on every test run.
- **Reuses existing adapter protocol:** adapters implement `is_applicable()`, `invoke()`, `parse()` as today.
- **Complements the scanner-ecosystem spec:** this does not replace the adapters; it provides the fixtures that exercise them.

## Fixture Selection

| Language | Fixture | Repository | Scanner(s) exercised |
|---|---|---|---|
| **Ruby / Rails** | OWASP RailsGoat | `https://github.com/OWASP/railsgoat` | `brakeman`, `bundler-audit` |
| **Java** | OWASP WebGoat | `https://github.com/WebGoat/WebGoat` | `spotbugs` + FindSecBugs, `dependency-check` |
| **C# / .NET Core** | AspGoat | `https://github.com/Soham7-dev/AspGoat` | `roslyn-secguard` / SecurityCodeScan |
| **Rust** | Hand-rolled fixture | committed in `tests/fixtures/vulnerable-rust` | `cargo-audit` |

Rationale:

- **RailsGoat** is the canonical Rails OWASP Top 10 target and is actively maintained.
- **WebGoat** is the canonical Java/Spring Boot OWASP target; it exercises both SAST (SpotBugs/FindSecBugs) and SCA (dependency-check).
- **AspGoat** is a modern ASP.NET Core intentionally vulnerable application, easier to build in a Linux container than the older WebGoat.NET.
- **Rust** has no widely-used intentionally vulnerable web application, so we commit a small hand-rolled fixture with known-vulnerable dependencies and deliberate source-level flaws.

## Image Design

### `Dockerfile.fixtures`

```dockerfile
# panopticon-fixtures: vulnerable-by-design applications for scanner validation.
# Build:  docker build -f Dockerfile.fixtures -t panopticon-fixtures:latest .
# Rebuild: docker build --no-cache -f Dockerfile.fixtures -t panopticon-fixtures:$(date +%Y-%m-%d) .
FROM panopticon-tools:latest

USER root

# Ruby runtime and RailsGoat dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        ruby ruby-dev build-essential libsqlite3-dev \
        default-jdk \
    && rm -rf /var/lib/apt/lists/*

# .NET SDK for AspGoat
RUN curl -sfL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0
ENV PATH="/root/.dotnet:${PATH}"

# Rust toolchain for the hand-rolled fixture
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-audit

WORKDIR /opt/panopticon-fixtures

# Clone public fixtures at build time
ARG RAILS_GOAT_REF=main
RUN git clone --depth 1 --branch ${RAILS_GOAT_REF} https://github.com/OWASP/railsgoat.git

ARG WEB_GOAT_REF=main
RUN git clone --depth 1 --branch ${WEB_GOAT_REF} https://github.com/WebGoat/WebGoat.git

ARG ASP_GOAT_REF=main
RUN git clone --depth 1 --branch ${ASP_GOAT_REF} https://github.com/Soham7-dev/AspGoat.git

# Prepare fixture dependencies so scans are fast at runtime
RUN cd /opt/panopticon-fixtures/railsgoat && bundle install --deployment 2>/dev/null || bundle install
RUN cd /opt/panopticon-fixtures/WebGoat && ./mvnw clean compile -DskipTests || mvn clean compile -DskipTests
RUN cd /opt/panopticon-fixtures/AspGoat && dotnet restore && dotnet build --no-restore

# Copy the hand-rolled Rust fixture from the repo.
# The fixture must include a committed Cargo.lock so cargo-audit has a dependency graph to audit.
COPY tests/fixtures/vulnerable-rust /opt/panopticon-fixtures/vulnerable-rust
RUN cd /opt/panopticon-fixtures/vulnerable-rust && cargo build && cargo audit

# Note: scripts/ and tests/ are mounted read-only at runtime so the harness
# always uses the current repo's code; do not COPY them into the image.

ENV PYTHONPATH=/opt/panopticon
ENV FIXTURE_ROOT=/opt/panopticon-fixtures
WORKDIR /opt/panopticon

# The fixtures image runs as root because it installs language toolchains and
# writes build artifacts during image build. It is intended for local test use only.
CMD ["python", "scripts/run_fixture_tests.py"]
```

### Tagging

- Default tag: `panopticon-fixtures:latest`.
- Dated tags: `panopticon-fixtures:YYYY-MM-DD` for periodic snapshots.
- The test script uses `panopticon-fixtures:latest` by default unless `--tag` is passed, and provides `--rebuild` to force a fresh build.

## Skill / CLI Integration

### New script: `scripts/run_fixture_tests.py`

Responsibilities:

1. Detect or build the `panopticon-fixtures` image.
2. Run the container with the current repo's `scripts/` and `tests/` mounted read-only.
3. Execute the pytest integration tests inside the container.
4. Print a summary: adapters tested, findings found, failures.

CLI:

```bash
# Use existing image
python scripts/run_fixture_tests.py

# Force rebuild
python scripts/run_fixture_tests.py --rebuild

# Tag the image
python scripts/run_fixture_tests.py --tag panopticon-fixtures:2026-08-02

# Run only one language/test target
python scripts/run_fixture_tests.py --test rust
```

### `SKILL.md` hook

Add a documented invocation path so users can run it from within Kimi Code (e.g., a `test` subcommand or documented slash-style trigger). The skill delegates to `scripts/run_fixture_tests.py`, forwarding any flags such as `--rebuild`.

## Test Harness

### New integration tests: `tests/tools/test_<lang>_integration.py`

Each test follows the existing tolerant pattern from `tests/test_phase1_integration.py`:

```python
def test_brakeman_finds_railsgoat_issues():
    target = os.path.join(FIXTURE_ROOT, "railsgoat")
    adapter = ADAPTERS["brakeman"]
    if not os.path.isdir(target):
        pytest.skip("railsgoat fixture not vendored")
    if not adapter.is_applicable(target):
        pytest.skip("brakeman not applicable")
    raw, rc = adapter.invoke(target)
    if rc not in (0, 1):
        pytest.skip(f"brakeman failed with {rc}")
    findings = adapter.parse(raw, "g1")
    assert findings, "expected brakeman findings against railsgoat"
    assert any(f.get("citations", {}).get("cwe") for f in findings)
```

Tolerance rules:

- Skip if the fixture directory is missing (image not built or partial).
- Skip if the required runtime/tool is not present.
- Non-zero tool exit codes are skips, not failures, unless the tool clearly crashed.
- Assertions check for the presence of findings and citations, not exact counts.

### Fixture manifest

`tests/fixtures/manifest.json` inside the repo lists expected fixtures and their purposes. The test runner uses it to report which fixtures were found/missing.

```json
{
  "fixtures": [
    {"name": "railsgoat", "language": "ruby", "source": "https://github.com/OWASP/railsgoat"},
    {"name": "WebGoat", "language": "java", "source": "https://github.com/WebGoat/WebGoat"},
    {"name": "AspGoat", "language": "csharp", "source": "https://github.com/Soham7-dev/AspGoat"},
    {"name": "vulnerable-rust", "language": "rust", "source": "local"}
  ]
}
```

## Rebuild Cadence

- **Default:** use the local `panopticon-fixtures:latest` image.
- **Periodic refresh:** recommended monthly, or whenever a scanner adapter is added/changed.
- **`--rebuild`:** forces a fresh clone and build.
- **Drift control:** because fixtures are cloned at image-build time, drift only happens when the image is rebuilt. Pinning `--branch` or commit refs in `Dockerfile.fixtures` is optional for extra stability.

## Success Criteria

- `python scripts/run_fixture_tests.py --rebuild` completes without errors.
- The image contains vendored RailsGoat, WebGoat, AspGoat, and the local Rust fixture.
- Running the integration tests reports findings for:
  - Brakeman against RailsGoat
  - bundler-audit against RailsGoat
  - SpotBugs/FindSecBugs against WebGoat
  - dependency-check against WebGoat
  - cargo-audit against the Rust fixture
  - SecurityCodeScan/Roslyn against AspGoat
- Missing fixtures or tools cause graceful skips, not hard failures.
- The existing unit-test suite and lint remain green.

## Out of Scope

- Adding the fixtures image to CI gates.
- Running the target applications (these are static-analysis fixtures only).
- Dynamic testing or DAST against the fixtures.
- Splitting the image into per-language variants.
- Replacing the Scanner Ecosystem Expansion spec's adapters; this spec only provides the test fixtures.

## Phased Roadmap

1. **Hand-rolled Rust fixture** — commit `tests/fixtures/vulnerable-rust/` with known-vulnerable dependencies and source flaws.
2. **`Dockerfile.fixtures`** — extend `panopticon-tools`, clone public fixtures, install build toolchains, prepare dependencies.
3. **`scripts/run_fixture_tests.py`** — build/run the image and invoke pytest integration tests.
4. **Integration tests** — add `tests/tools/test_ruby_integration.py`, `test_java_integration.py`, `test_rust_integration.py`, `test_csharp_integration.py`.
5. **`SKILL.md` hook** — document `/panopticon test` invocation.
6. **Periodic refresh process** — document rebuild cadence and tagging convention in `DEVELOPMENT.md`.

Each phase can be merged independently once its tests pass.
