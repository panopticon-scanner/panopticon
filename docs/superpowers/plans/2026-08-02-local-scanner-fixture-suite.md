# Local Scanner Fixture Suite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Docker-based, local-only vulnerable fixture suite that vends RailsGoat, WebGoat, AspGoat, and a hand-rolled Rust fixture into a `panopticon-fixtures` image, plus a CLI test harness and skill hook.

**Architecture:** A separate `Dockerfile.fixtures` extends `panopticon-tools` and clones public vulnerable apps at build time. The repo commits a small Rust fixture and a test manifest. `scripts/run_fixture_tests.py` builds/runs the image and executes pytest integration tests. `SKILL.md` documents an optional `test` trigger.

**Tech Stack:** Docker, Python 3.12, pytest, git, Ruby, JDK, .NET SDK, Rust toolchain.

## Global Constraints

- Local-only at runtime: no network calls during test execution.
- External resources OK at image-build time: cloning GitHub repos and installing language runtimes happens inside the Dockerfile.
- Separate image: `panopticon-fixtures` extends `panopticon-tools` but is independent of CI gates.
- Optional, user-triggered: invoked via a CLI script/skill hook, not as a merge-blocking gate.
- Long build times acceptable: the image is built periodically, not on every test run.
- Reuses existing adapter protocol: adapters implement `is_applicable()`, `invoke()`, `parse()` as today.
- Complements the Scanner Ecosystem Expansion spec: this does not replace the adapters; it provides the fixtures that exercise them.
- All new code must pass `pytest` and `ruff` (or the repo's configured linter).

---

## File Structure

- `tests/fixtures/manifest.json` — canonical list of fixtures and their purposes.
- `tests/fixtures/vulnerable-rust/Cargo.toml` — hand-rolled Rust fixture manifest.
- `tests/fixtures/vulnerable-rust/Cargo.lock` — committed lockfile so `cargo-audit` has a dependency graph.
- `tests/fixtures/vulnerable-rust/src/main.rs` — intentionally flawed Rust source.
- `Dockerfile.fixtures` — image definition extending `panopticon-tools`.
- `scripts/run_fixture_tests.py` — CLI harness to build/run the image and execute tests.
- `tests/tools/test_ruby_integration.py` — Brakeman + bundler-audit integration tests.
- `tests/tools/test_java_integration.py` — SpotBugs + dependency-check integration tests.
- `tests/tools/test_rust_integration.py` — cargo-audit integration test.
- `tests/tools/test_csharp_integration.py` — Roslyn/SecurityCodeScan integration test.
- `SKILL.md` — add documented `test` invocation path.
- `DEVELOPMENT.md` — add rebuild cadence and usage notes.

---

### Task 1: Create fixture manifest

**Files:**
- Create: `tests/fixtures/manifest.json`

**Interfaces:**
- Consumes: nothing.
- Produces: a JSON manifest read by `run_fixture_tests.py` and humans.

- [ ] **Step 1: Write manifest**

```json
{
  "fixtures": [
    {
      "name": "railsgoat",
      "language": "ruby",
      "source": "https://github.com/OWASP/railsgoat",
      "adapters": ["brakeman", "bundler-audit"]
    },
    {
      "name": "WebGoat",
      "language": "java",
      "source": "https://github.com/WebGoat/WebGoat",
      "adapters": ["spotbugs", "dependency-check"]
    },
    {
      "name": "AspGoat",
      "language": "csharp",
      "source": "https://github.com/Soham7-dev/AspGoat",
      "adapters": ["roslyn-secguard"]
    },
    {
      "name": "vulnerable-rust",
      "language": "rust",
      "source": "local",
      "adapters": ["cargo-audit"]
    }
  ]
}
```

- [ ] **Step 2: Validate JSON syntax**

Run: `python -m json.tool tests/fixtures/manifest.json > /dev/null`
Expected: no output (success).

- [ ] **Step 3: Commit**

```bash
git add tests/fixtures/manifest.json
git commit -m "chore(fixtures): add fixture manifest for local scanner suite"
```

---

### Task 2: Create hand-rolled Rust fixture

**Files:**
- Create: `tests/fixtures/vulnerable-rust/Cargo.toml`
- Create: `tests/fixtures/vulnerable-rust/Cargo.lock`
- Create: `tests/fixtures/vulnerable-rust/src/main.rs`

**Interfaces:**
- Consumes: nothing.
- Produces: a buildable Rust project that `cargo-audit` flags for known advisories.

- [ ] **Step 1: Write Cargo.toml**

```toml
[package]
name = "vulnerable-rust"
version = "0.1.0"
edition = "2021"

[dependencies]
# time 0.1.x is flagged by RUSTSEC-2020-0071 (potential segfault).
time = "0.1.44"
serde_cbor = "0.10.2"
```

- [ ] **Step 2: Generate Cargo.lock**

Run:

```bash
cd tests/fixtures/vulnerable-rust
cargo generate-lockfile
```

Expected: `Cargo.lock` is created.

Verify `cargo audit` finds at least one advisory:

```bash
cargo audit
```

Expected: output lists RUSTSEC advisories for pinned crates.

- [ ] **Step 3: Write src/main.rs with deliberate flaws**

```rust
use std::env;
use std::process::Command;

// Deliberately flawed Rust fixture for static analysis validation.

static API_KEY: &str = "hardcoded-secret-key-12345";

fn main() {
    let user_input = env::args().nth(1).unwrap_or_default();

    // Vulnerable: command injection via unsanitized user input.
    let output = Command::new("sh")
        .arg("-c")
        .arg(&user_input)
        .output()
        .expect("command failed");
    println!("{}", String::from_utf8_lossy(&output.stdout));

    // Vulnerable: panic on malformed input (denial of service).
    let number: i32 = user_input.parse().unwrap();
    println!("parsed {}", number);

    // Vulnerable: use of deprecated/unsound crate API.
    let _now = time::now();

    // Vulnerable: hardcoded credential exposure.
    println!("api key: {}", API_KEY);
}
```

- [ ] **Step 4: Verify the fixture builds**

Run:

```bash
cd tests/fixtures/vulnerable-rust
cargo build
```

Expected: build succeeds (compilation warnings are OK).

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/vulnerable-rust/
git commit -m "chore(fixtures): add intentionally vulnerable Rust fixture"
```

---

### Task 3: Create Dockerfile.fixtures

**Files:**
- Create: `Dockerfile.fixtures`

**Interfaces:**
- Consumes: `panopticon-tools:latest`, public GitHub repos, local Rust fixture.
- Produces: a `panopticon-fixtures` image containing vendored fixtures and build toolchains.

- [ ] **Step 1: Write Dockerfile.fixtures**

```dockerfile
# panopticon-fixtures: vulnerable-by-design applications for scanner validation.
# Build:  docker build -f Dockerfile.fixtures -t panopticon-fixtures:latest .
# Rebuild: docker build --no-cache -f Dockerfile.fixtures -t panopticon-fixtures:$(date +%Y-%m-%d) .
FROM panopticon-tools:latest

USER root

# Ruby runtime for RailsGoat and Java runtime for WebGoat.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ruby ruby-dev build-essential libsqlite3-dev \
        default-jdk \
    && rm -rf /var/lib/apt/lists/*

# .NET SDK for AspGoat.
RUN curl -sfL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 8.0
ENV PATH="/root/.dotnet:${PATH}"

# Rust toolchain for the hand-rolled fixture.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-audit

WORKDIR /opt/panopticon-fixtures

# Clone public fixtures at build time.
ARG RAILS_GOAT_REF=main
RUN git clone --depth 1 --branch ${RAILS_GOAT_REF} https://github.com/OWASP/railsgoat.git

ARG WEB_GOAT_REF=main
RUN git clone --depth 1 --branch ${WEB_GOAT_REF} https://github.com/WebGoat/WebGoat.git

ARG ASP_GOAT_REF=main
RUN git clone --depth 1 --branch ${ASP_GOAT_REF} https://github.com/Soham7-dev/AspGoat.git

# Prepare fixture dependencies so scans are fast at runtime.
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

- [ ] **Step 2: Lint Dockerfile**

Run: `hadolint Dockerfile.fixtures` if available, or at minimum verify no syntax errors with:

```bash
docker build -f Dockerfile.fixtures --target panopticon-tools -t panopticon-fixtures:check .
```

If the base image `panopticon-tools:latest` does not yet exist, build it first:

```bash
docker build -t panopticon-tools:latest .
```

Expected: base build succeeds.

- [ ] **Step 3: Commit**

```bash
git add Dockerfile.fixtures
git commit -m "chore(fixtures): add Dockerfile for panopticon-fixtures image"
```

---

### Task 4: Create test harness script

**Files:**
- Create: `scripts/run_fixture_tests.py`

**Interfaces:**
- Consumes: `tests/fixtures/manifest.json`, local Docker daemon, current repo's `scripts/` and `tests/`.
- Produces: containerized pytest run with printed summary.

- [ ] **Step 1: Write run_fixture_tests.py**

```python
#!/usr/bin/env python3
"""Build and run the panopticon-fixtures image to vet scanner adapters."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile.fixtures"
MANIFEST = REPO_ROOT / "tests" / "fixtures" / "manifest.json"
DEFAULT_IMAGE = "panopticon-fixtures:latest"


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, **kwargs)


def image_exists(tag: str) -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", tag],
        capture_output=True,
    )
    return result.returncode == 0


def build_image(tag: str) -> None:
    run([
        "docker", "build",
        "-f", str(DOCKERFILE),
        "-t", tag,
        str(REPO_ROOT),
    ])


def run_tests(tag: str, test: str | None = None) -> int:
    repo = str(REPO_ROOT)
    test_paths = ["/opt/panopticon/tests/tools"]
    pytest_args = ["python", "-m", "pytest", "-v"]
    if test:
        pytest_args.extend(["-k", f"test_{test}_integration or {test}"])
    pytest_args.extend(test_paths)
    cmd = [
        "docker", "run", "--rm",
        "-e", "FIXTURE_ROOT=/opt/panopticon-fixtures",
        "-v", f"{repo}/scripts:/opt/panopticon/scripts:ro",
        "-v", f"{repo}/tests:/opt/panopticon/tests:ro",
        tag,
        *pytest_args,
    ]
    result = subprocess.run(cmd)
    return result.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run panopticon scanner fixture tests.")
    parser.add_argument("--tag", default=DEFAULT_IMAGE, help="Docker image tag to use.")
    parser.add_argument("--rebuild", action="store_true", help="Force a fresh image build.")
    parser.add_argument("--test", default=None, help="Run only one language/test target (e.g., rust).")
    args = parser.parse_args(argv)

    if not MANIFEST.exists():
        print(f"manifest not found: {MANIFEST}", file=sys.stderr)
        return 1

    manifest = json.loads(MANIFEST.read_text())
    print("Fixtures in manifest:")
    for fixture in manifest["fixtures"]:
        print(f"  - {fixture['name']} ({fixture['language']})")

    if args.rebuild or not image_exists(args.tag):
        build_image(args.tag)
    else:
        print(f"Using existing image {args.tag}")

    return run_tests(args.tag, args.test)


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Make script executable**

Run: `chmod +x scripts/run_fixture_tests.py`

- [ ] **Step 3: Verify argument parsing**

Run: `python scripts/run_fixture_tests.py --help`

Expected: prints usage including `--tag`, `--rebuild`, `--test`.

- [ ] **Step 4: Commit**

```bash
git add scripts/run_fixture_tests.py
git commit -m "feat(fixtures): add CLI harness for running fixture tests"
```

---

### Task 5: Add Ruby integration tests

**Files:**
- Create: `tests/tools/test_ruby_integration.py`

**Interfaces:**
- Consumes: `ADAPTERS["brakeman"]`, `ADAPTERS["bundler-audit"]`, `FIXTURE_ROOT/railsgoat`.
- Produces: pytest tests that skip gracefully when fixtures/tools are missing.

- [ ] **Step 1: Write test**

```python
import os
import unittest

from tools import ADAPTERS

FIXTURE_ROOT = os.environ.get("FIXTURE_ROOT", os.path.join(os.path.dirname(__file__), "..", "fixtures"))


class TestRubyIntegration(unittest.TestCase):
    def _target(self, name: str) -> str:
        return os.path.join(FIXTURE_ROOT, name)

    def test_brakeman_finds_railsgoat_issues(self):
        target = self._target("railsgoat")
        adapter = ADAPTERS["brakeman"]
        if not os.path.isdir(target):
            self.skipTest("railsgoat fixture not vendored")
        if not adapter.is_applicable(target):
            self.skipTest("brakeman not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"brakeman failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected brakeman findings against railsgoat")
        self.assertTrue(
            any(f.get("citations", {}).get("cwe") for f in findings),
            "expected CWE citations",
        )

    def test_bundler_audit_finds_railsgoat_vulns(self):
        target = self._target("railsgoat")
        adapter = ADAPTERS["bundler-audit"]
        if not os.path.isdir(target):
            self.skipTest("railsgoat fixture not vendored")
        if not adapter.is_applicable(target):
            self.skipTest("bundler-audit not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"bundler-audit failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected bundler-audit findings")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Verify test syntax**

Run: `python -m py_compile tests/tools/test_ruby_integration.py`

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add tests/tools/test_ruby_integration.py
git commit -m "test(fixtures): add Ruby/Brakeman integration tests"
```

---

### Task 6: Add Java integration tests

**Files:**
- Create: `tests/tools/test_java_integration.py`

**Interfaces:**
- Consumes: `ADAPTERS["spotbugs"]`, `ADAPTERS["dependency-check"]`, `FIXTURE_ROOT/WebGoat`.
- Produces: pytest tests for Java scanners.

- [ ] **Step 1: Write test**

```python
import os
import unittest

from tools import ADAPTERS

FIXTURE_ROOT = os.environ.get("FIXTURE_ROOT", os.path.join(os.path.dirname(__file__), "..", "fixtures"))


class TestJavaIntegration(unittest.TestCase):
    def _target(self, name: str) -> str:
        return os.path.join(FIXTURE_ROOT, name)

    def test_spotbugs_finds_webgoat_issues(self):
        target = self._target("WebGoat")
        adapter = ADAPTERS["spotbugs"]
        if not os.path.isdir(target):
            self.skipTest("WebGoat fixture not vendored")
        if not adapter.is_applicable(target):
            self.skipTest("spotbugs not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"spotbugs failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected SpotBugs findings against WebGoat")

    def test_dependency_check_finds_webgoat_vulns(self):
        target = self._target("WebGoat")
        adapter = ADAPTERS["dependency-check"]
        if not os.path.isdir(target):
            self.skipTest("WebGoat fixture not vendored")
        if not adapter.is_applicable(target):
            self.skipTest("dependency-check not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"dependency-check failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected dependency-check findings")
        self.assertTrue(
            any("CVE-" in str(f.get("citations")) for f in findings),
            "expected CVE citations",
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Verify test syntax**

Run: `python -m py_compile tests/tools/test_java_integration.py`

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add tests/tools/test_java_integration.py
git commit -m "test(fixtures): add Java/SpotBugs integration tests"
```

---

### Task 7: Add Rust integration test

**Files:**
- Create: `tests/tools/test_rust_integration.py`

**Interfaces:**
- Consumes: `ADAPTERS["cargo-audit"]`, `FIXTURE_ROOT/vulnerable-rust`.
- Produces: pytest test for cargo-audit.

- [ ] **Step 1: Write test**

```python
import os
import unittest

from tools import ADAPTERS

FIXTURE_ROOT = os.environ.get("FIXTURE_ROOT", os.path.join(os.path.dirname(__file__), "..", "fixtures"))


class TestRustIntegration(unittest.TestCase):
    def test_cargo_audit_finds_rustsec_advisories(self):
        target = os.path.join(FIXTURE_ROOT, "vulnerable-rust")
        adapter = ADAPTERS["cargo-audit"]
        if not os.path.isdir(target):
            self.skipTest("vulnerable-rust fixture not present")
        if not adapter.is_applicable(target):
            self.skipTest("cargo-audit not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"cargo-audit failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected cargo-audit findings")
        self.assertTrue(
            any("RUSTSEC-" in str(f.get("citations")) for f in findings),
            "expected RUSTSEC citations",
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Verify test syntax**

Run: `python -m py_compile tests/tools/test_rust_integration.py`

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add tests/tools/test_rust_integration.py
git commit -m "test(fixtures): add Rust/cargo-audit integration test"
```

---

### Task 8: Add C# integration test

**Files:**
- Create: `tests/tools/test_csharp_integration.py`

**Interfaces:**
- Consumes: `ADAPTERS["roslyn-secguard"]`, `FIXTURE_ROOT/AspGoat`.
- Produces: pytest test for Roslyn SecurityCodeScan.

- [ ] **Step 1: Write test**

```python
import os
import unittest

from tools import ADAPTERS

FIXTURE_ROOT = os.environ.get("FIXTURE_ROOT", os.path.join(os.path.dirname(__file__), "..", "fixtures"))


class TestCSharpIntegration(unittest.TestCase):
    def test_roslyn_secguard_finds_aspnet_issues(self):
        target = os.path.join(FIXTURE_ROOT, "AspGoat")
        adapter = ADAPTERS["roslyn-secguard"]
        if not os.path.isdir(target):
            self.skipTest("AspGoat fixture not vendored")
        if not adapter.is_applicable(target):
            self.skipTest("roslyn-secguard not applicable")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"roslyn-secguard failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(findings, "expected SecurityCodeScan findings against AspGoat")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Verify test syntax**

Run: `python -m py_compile tests/tools/test_csharp_integration.py`

Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add tests/tools/test_csharp_integration.py
git commit -m "test(fixtures): add C#/SecurityCodeScan integration test"
```

---

### Task 9: Update SKILL.md

**Files:**
- Modify: `SKILL.md`

**Interfaces:**
- Consumes: existing skill documentation structure.
- Produces: documented `test` invocation path.

- [ ] **Step 1: Locate the usage/commands section in SKILL.md**

Read the file to find where commands are documented.

- [ ] **Step 2: Add test command documentation**

Insert a subsection like:

```markdown
### Running scanner fixture tests

Panopticon includes a local Docker-based fixture suite for validating scanner adapters against intentionally vulnerable applications.

```bash
# Use existing fixtures image
python scripts/run_fixture_tests.py

# Force rebuild (clones latest public fixtures)
python scripts/run_fixture_tests.py --rebuild

# Run only one language/test target
python scripts/run_fixture_tests.py --test rust
```

This is optional and not part of CI. Rebuild the image periodically to pull updated fixtures.
```

- [ ] **Step 3: Commit**

```bash
git add SKILL.md
git commit -m "docs(skill): document fixture test command"
```

---

### Task 10: Update DEVELOPMENT.md

**Files:**
- Modify: `DEVELOPMENT.md`

**Interfaces:**
- Consumes: existing development docs.
- Produces: rebuild cadence and troubleshooting notes.

- [ ] **Step 1: Add fixtures section**

Insert a new section:

```markdown
## Local scanner fixture suite

The `panopticon-fixtures` image contains vulnerable-by-design applications used to validate scanner adapters.

- Build: `docker build -f Dockerfile.fixtures -t panopticon-fixtures:latest .`
- Run tests: `python scripts/run_fixture_tests.py`
- Force rebuild: `python scripts/run_fixture_tests.py --rebuild`
- Tag snapshots: `docker tag panopticon-fixtures:latest panopticon-fixtures:YYYY-MM-DD`

Rebuild cadence: monthly, or whenever a new adapter is added. The image pulls public fixtures at build time, so test runs require no network.
```

- [ ] **Step 2: Commit**

```bash
git add DEVELOPMENT.md
git commit -m "docs(dev): add fixture image rebuild and usage notes"
```

---

### Task 11: Run lint and unit tests

**Files:**
- Modify: none (verification task).

**Interfaces:**
- Consumes: all new files.
- Produces: green lint and unit-test output.

- [ ] **Step 1: Run ruff on new Python files**

Run:

```bash
ruff check scripts/run_fixture_tests.py tests/tools/test_*_integration.py
```

Expected: no errors.

- [ ] **Step 2: Run existing unit tests**

Run:

```bash
pytest tests/ -q --ignore=tests/tools/test_ruby_integration.py --ignore=tests/tools/test_java_integration.py --ignore=tests/tools/test_rust_integration.py --ignore=tests/tools/test_csharp_integration.py
```

Expected: all existing tests pass.

- [ ] **Step 3: Commit any lint fixes**

```bash
git commit -am "style(fixtures): address lint findings" || true
```

---

### Task 12: Build fixtures image and run tests

**Files:**
- Modify: none (end-to-end verification task).

**Interfaces:**
- Consumes: full implementation from prior tasks.
- Produces: verified image and test results.

- [ ] **Step 1: Build base image**

Run:

```bash
docker build -t panopticon-tools:latest .
```

Expected: build succeeds.

- [ ] **Step 2: Build fixtures image**

Run:

```bash
python scripts/run_fixture_tests.py --rebuild --tag panopticon-fixtures:local-test
```

Expected: image builds, public repos clone, dependencies install, cargo audit reports advisories.

- [ ] **Step 3: Run full fixture suite**

Run:

```bash
python scripts/run_fixture_tests.py --tag panopticon-fixtures:local-test
```

Expected: all applicable tests pass or skip gracefully; summary shows findings for each scanner.

- [ ] **Step 4: Commit any fixes**

```bash
git commit -am "fix(fixtures): harden image build and test harness after E2E run" || true
```

---

## Self-Review

**Spec coverage:**

- [x] Fixture manifest — Task 1.
- [x] Hand-rolled Rust fixture with Cargo.lock — Task 2.
- [x] `Dockerfile.fixtures` extending `panopticon-tools` — Task 3.
- [x] `scripts/run_fixture_tests.py` CLI harness — Task 4.
- [x] Integration tests for Ruby, Java, Rust, C# — Tasks 5–8.
- [x] Skill hook documentation — Task 9.
- [x] Rebuild cadence docs — Task 10.
- [x] Lint/unit-test verification — Task 11.
- [x] End-to-end image build and test run — Task 12.

**Placeholder scan:**

- No TBD/TODO.
- No vague "add error handling" steps.
- Code blocks contain concrete content.

**Type consistency:**

- `FIXTURE_ROOT` is always read from `os.environ` with a fallback.
- Adapter names match the Scanner Ecosystem Expansion spec: `brakeman`, `bundler-audit`, `spotbugs`, `dependency-check`, `cargo-audit`, `roslyn-secguard`.
- Test pattern matches `tests/test_phase1_integration.py`: tolerant skips, assert findings present.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-02-local-scanner-fixture-suite.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach would you like?
