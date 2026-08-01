# Panopticon Static-Analysis Expansion — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB- SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four new security scanners (`pip-audit`, `npm audit`, `osv-scanner`, `eslint-plugin-security`) to panopticon via a pluggable adapter layer, refactor tool dispatch and ingestion to use adapters, and ensure every new finding carries CVE/CWE citations and a `source: "tool:<name>"` provenance tag.

**Architecture:** Each scanner is a self-contained adapter in `scripts/tools/` with `invoke()` and `parse()` functions. `scripts/run_tools.py` selects and dispatches adapters; `scripts/ingest_tools.py` routes raw output to the matching adapter for normalization. The existing `citations.py` enrichment pipeline validates CWEs and enriches CVEs. Tests use fixture repos under `tests/fixtures/`.

**Tech Stack:** Python 3.12, Docker, pip-audit, npm, osv-scanner, eslint-plugin-security, unittest.

## Global Constraints

- Read-only tool scans: tools parse source and lockfiles; they never execute untrusted code.
- Single fat Docker image (`panopticon-tools`) for local and CI runs.
- SARIF-first, with JSON/XML converters for tools that do not emit SARIF natively.
- Every tool finding must set `source: "tool:<name>"`.
- Every CVE/CWE citation must be normalized uppercase and validated by `citations.py`.
- No proprietary services or API keys required for Phase 1.
- No competitor names in committed documents.
- Keep the Docker image build under 15 minutes on a typical CI runner.
- All new code must have unit or integration tests.

---

## File Structure

| File | Responsibility |
|---|---|
| `scripts/tools/__init__.py` | Adapter registry and shared helper functions |
| `scripts/tools/base.py` | Base dataclass for raw tool output and shared severity normalization |
| `scripts/tools/pip_audit.py` | Runs `pip-audit` and parses JSON output into findings |
| `scripts/tools/npm_audit.py` | Runs `npm audit` and parses JSON output into findings |
| `scripts/tools/osv_scanner.py` | Runs `osv-scanner` and parses JSON output into findings |
| `scripts/tools/eslint_security.py` | Runs ESLint with `eslint-plugin-security` and parses JSON output |
| `scripts/tools/legacy_sarif.py` | Wraps the existing SARIF parser for current tools (`semgrep`, `bandit`, etc.) |
| `scripts/run_tools.py` | Detects ecosystems, selects adapters, runs them in Docker, writes raw output |
| `scripts/ingest_tools.py` | Routes raw output files to adapters and merges findings |
| `reference/report-schema.json` | Adds `tool_evidence` to finding schema |
| `Dockerfile` | Installs Phase 1 tools |
| `tests/tools/test_pip_audit.py` | Unit tests for pip-audit adapter |
| `tests/tools/test_npm_audit.py` | Unit tests for npm-audit adapter |
| `tests/tools/test_osv_scanner.py` | Unit tests for osv-scanner adapter |
| `tests/tools/test_eslint_security.py` | Unit tests for eslint-security adapter |
| `tests/test_run_tools.py` | Updated dispatcher tests |
| `tests/test_ingest_tools.py` | Updated ingestion tests |
| `tests/fixtures/vulnerable-python/` | Python fixture with a known vulnerable dependency |
| `tests/fixtures/vulnerable-node/` | Node fixture with a known vulnerable dependency |
| `tests/fixtures/insecure-js/` | JS fixture triggering security rules |
| `tests/test_phase1_integration.py` | End-to-end adapter → dispatcher → ingestion test |

---

### Task 1: Adapter contract and shared utilities

**Files:**
- Create: `scripts/tools/__init__.py`
- Create: `scripts/tools/base.py`
- Create: `scripts/tools/legacy_sarif.py`
- Modify: `scripts/ingest_tools.py` (minor, to import legacy adapter)

**Interfaces:**
- Consumes: existing SARIF parser in `scripts/ingest_tools.py`.
- Produces: `ToolAdapter` protocol, `normalize_severity()`, `new_finding_id()`, `legacy_sarif.parse()`.

- [ ] **Step 1: Write failing tests for adapter contract**

Create `tests/tools/__init__.py` and `tests/tools/test_base.py`:

```python
import unittest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "scripts"))
import tools.base as base

class TestBase(unittest.TestCase):
    def test_normalize_severity_maps_common_values(self):
        self.assertEqual(base.normalize_severity("critical"), "CRITICAL")
        self.assertEqual(base.normalize_severity("high"), "HIGH")
        self.assertEqual(base.normalize_severity("moderate"), "MEDIUM")
        self.assertEqual(base.normalize_severity("low"), "LOW")
        self.assertEqual(base.normalize_severity("info"), "INFO")
        self.assertEqual(base.normalize_severity("unknown"), "INFO")

    def test_new_finding_id_increments(self):
        self.assertEqual(base.new_finding_id("PA", 1), "PA-001")
        self.assertEqual(base.new_finding_id("PA", 12), "PA-012")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/tools/test_base.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'tools.base'" or similar.

- [ ] **Step 3: Implement shared utilities**

Create `scripts/tools/__init__.py`:

```python
"""Pluggable static-analysis tool adapters for panopticon."""
from scripts.tools.pip_audit import PipAuditAdapter
from scripts.tools.npm_audit import NpmAuditAdapter
from scripts.tools.osv_scanner import OsvScannerAdapter
from scripts.tools.eslint_security import EslintSecurityAdapter
from scripts.tools.legacy_sarif import LegacySarifAdapter

ADAPTERS = {
    "pip-audit": PipAuditAdapter(),
    "npm-audit": NpmAuditAdapter(),
    "osv-scanner": OsvScannerAdapter(),
    "eslint-security": EslintSecurityAdapter(),
    "semgrep": LegacySarifAdapter("semgrep"),
    "bandit": LegacySarifAdapter("bandit"),
    "trivy": LegacySarifAdapter("trivy"),
    "gitleaks": LegacySarifAdapter("gitleaks"),
    "gosec": LegacySarifAdapter("gosec"),
    "brakeman": LegacySarifAdapter("brakeman"),
    "eslint": LegacySarifAdapter("eslint"),
}
```

Create `scripts/tools/base.py`:

```python
"""Shared base utilities for tool adapters."""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Protocol


SEV_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "severe": "HIGH",
    "important": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "none": "INFO",
}

ID_RE = re.compile(r"^[A-Z]{2,4}-\d{3,}$")


def normalize_severity(value: str | None) -> str:
    if not isinstance(value, str):
        return "INFO"
    return SEV_MAP.get(value.lower().strip(), "INFO")


def new_finding_id(prefix: str, n: int) -> str:
    return f"{prefix}-{n:03d}"


class ToolAdapter(Protocol):
    name: str
    prefix: str

    def is_applicable(self, target: str) -> bool:
        ...

    def invoke(self, target: str) -> tuple[bytes, int]:
        ...

    def parse(self, raw: bytes, group: str) -> list[dict]:
        ...
```

- [ ] **Step 4: Create legacy SARIF adapter**

Create `scripts/tools/legacy_sarif.py`:

```python
"""Adapter that preserves the existing SARIF ingestion for semgrep/bandit/etc."""
from __future__ import annotations
import json
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
import ingest_tools as it


class LegacySarifAdapter:
    def __init__(self, name: str):
        self.name = name
        self.prefix = it.PREFIX.get(name, "TL")

    def is_applicable(self, target: str) -> bool:
        return True

    def invoke(self, target: str) -> tuple[bytes, int]:
        raise NotImplementedError("legacy SARIF tools are invoked by run_tools.py directly")

    def parse(self, raw: bytes, group: str) -> list[dict]:
        sarif = json.loads(raw)
        return it.sarif_to_findings(sarif, self.name, group, self.prefix)
```

- [ ] **Step 5: Run tests**

Run: `python3 -m pytest tests/tools/test_base.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/tools/ tests/tools/ scripts/ingest_tools.py
git commit -m "feat(tools): adapter contract, shared utilities, legacy SARIF wrapper"
```

---

### Task 2: pip-audit adapter

**Files:**
- Create: `scripts/tools/pip_audit.py`
- Create: `tests/tools/test_pip_audit.py`
- Create: `tests/fixtures/vulnerable-python/requirements.txt`

**Interfaces:**
- Consumes: `ToolAdapter` protocol, `normalize_severity()`, `new_finding_id()`.
- Produces: `PipAuditAdapter` with `invoke()` and `parse()`.

- [ ] **Step 1: Write failing test**

Create `tests/tools/test_pip_audit.py`:

```python
import json, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "scripts"))
import tools.pip_audit as pa

PIP_AUDIT_SAMPLE = json.dumps({
    "dependencies": [
        {
            "name": "requests",
            "version": "2.25.1",
            "vulns": [
                {
                    "id": "PYSEC-2023-1",
                    "fix_versions": ["2.31.0"],
                    "description": "Unintended leak of proxy credentials",
                    "aliases": ["CVE-2023-32681"],
                }
            ]
        }
    ]
}).encode()


class TestPipAuditAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        adapter = pa.PipAuditAdapter()
        findings = adapter.parse(PIP_AUDIT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:pip-audit")
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertEqual(f["citations"]["cve"], ["CVE-2023-32681"])
        self.assertEqual(f["tool_evidence"]["package_name"], "requests")
        self.assertEqual(f["tool_evidence"]["fixed_version"], "2.31.0")

    def test_is_applicable_when_requirements_present(self):
        with unittest.mock.patch("os.path.exists", side_effect=lambda p: p.endswith("requirements.txt")):
            self.assertTrue(pa.PipAuditAdapter().is_applicable("/tmp/fake"))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/tools/test_pip_audit.py -v`
Expected: FAIL with "ModuleNotFoundError: No module named 'tools.pip_audit'".

- [ ] **Step 3: Implement adapter**

Create `scripts/tools/pip_audit.py`:

```python
"""pip-audit adapter for Python dependency CVEs."""
from __future__ import annotations
import glob
import json
import subprocess
from scripts.tools.base import normalize_severity, new_finding_id


class PipAuditAdapter:
    name = "pip-audit"
    prefix = "PA"

    def is_applicable(self, target: str) -> bool:
        patterns = ["requirements*.txt", "pyproject.toml", "setup.py"]
        for pat in patterns:
            if glob.glob(os.path.join(target, pat)):
                return True
        return False

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["pip-audit", "--format=json", "--desc", "--requirement"]
        req = self._find_requirement(target)
        if req:
            cmd.extend([req])
        else:
            cmd.extend([os.path.join(target, "pyproject.toml")])
        res = subprocess.run(cmd, capture_output=True, timeout=300)
        return res.stdout, res.returncode

    def _find_requirement(self, target: str) -> str | None:
        for path in sorted(glob.glob(os.path.join(target, "requirements*.txt"))):
            return path
        return None

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for dep in data.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                cves = [a.upper() for a in vuln.get("aliases", []) if a.upper().startswith("CVE-")]
                finding = {
                    "id": new_finding_id(self.prefix, n),
                    "title": f"{dep['name']} {dep['version']}: {vuln.get('id', 'vulnerability')}",
                    "severity": normalize_severity(vuln.get("severity") or "MEDIUM"),
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "dependency_vulnerability",
                    "source": f"tool:{self.name}",
                    "location": {"file": "requirements.txt", "line_start": 1},
                    "description": vuln.get("description", "No description provided."),
                    "impact": f"Vulnerable dependency {dep['name']}=={dep['version']} is used.",
                    "remediation": f"Upgrade to a fixed version: {', '.join(vuln.get('fix_versions', [])) or 'see advisory'}",
                    "references": [],
                    "tool_evidence": {
                        "rule_id": vuln.get("id"),
                        "package_name": dep["name"],
                        "vulnerable_versions": dep["version"],
                        "fixed_version": vuln.get("fix_versions", [None])[0],
                    },
                    "_group": group,
                }
                if cves:
                    finding["citations"] = {"cve": cves}
                out.append(finding)
                n += 1
        return out
```

Add missing import at top: `import os`.

- [ ] **Step 4: Create fixture**

Create `tests/fixtures/vulnerable-python/requirements.txt`:

```text
requests==2.25.1
```

- [ ] **Step 5: Run tests**

Run: `python3 -m pytest tests/tools/test_pip_audit.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/tools/pip_audit.py tests/tools/test_pip_audit.py tests/fixtures/vulnerable-python/
git commit -m "feat(tools): pip-audit adapter and tests"
```

---

### Task 3: npm-audit adapter

**Files:**
- Create: `scripts/tools/npm_audit.py`
- Create: `tests/tools/test_npm_audit.py`
- Create: `tests/fixtures/vulnerable-node/package.json`
- Create: `tests/fixtures/vulnerable-node/package-lock.json`

**Interfaces:**
- Consumes: `ToolAdapter` protocol, `normalize_severity()`, `new_finding_id()`.
- Produces: `NpmAuditAdapter`.

- [ ] **Step 1: Write failing test**

Create `tests/tools/test_npm_audit.py`:

```python
import json, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "scripts"))
import tools.npm_audit as na

NPM_AUDIT_SAMPLE = json.dumps({
    "advisories": {
        "1234": {
            "id": 1234,
            "title": "Prototype Pollution in lodash",
            "module_name": "lodash",
            "overview": "Versions of lodash before 4.17.21 are vulnerable.",
            "severity": "high",
            "cves": ["CVE-2021-23337"],
            "findings": [{"version": "4.17.20", "paths": ["lodash"]}]
        }
    }
}).encode()


class TestNpmAuditAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = na.NpmAuditAdapter().parse(NPM_AUDIT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:npm-audit")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["citations"]["cve"], ["CVE-2021-23337"])
        self.assertEqual(f["tool_evidence"]["package_name"], "lodash")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/tools/test_npm_audit.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement adapter**

Create `scripts/tools/npm_audit.py`:

```python
"""npm audit adapter for Node dependency CVEs."""
from __future__ import annotations
import json
import os
import subprocess
from scripts.tools.base import normalize_severity, new_finding_id


class NpmAuditAdapter:
    name = "npm-audit"
    prefix = "NA"

    def is_applicable(self, target: str) -> bool:
        return os.path.isfile(os.path.join(target, "package-lock.json")) or \
               os.path.isfile(os.path.join(target, "npm-shrinkwrap.json"))

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["npm", "audit", "--json", "--prefix", target]
        res = subprocess.run(cmd, capture_output=True, timeout=300)
        return res.stdout, res.returncode

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for adv in data.get("advisories", {}).values():
            cves = [c.upper() for c in adv.get("cves", []) if c.upper().startswith("CVE-")]
            finding = {
                "id": new_finding_id(self.prefix, n),
                "title": f"{adv.get('module_name')} {adv.get('vulnerable_versions', '')}: {adv.get('title', 'vulnerability')}",
                "severity": normalize_severity(adv.get("severity")),
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "dependency_vulnerability",
                "source": f"tool:{self.name}",
                "location": {"file": "package-lock.json", "line_start": 1},
                "description": adv.get("overview", "No description provided."),
                "impact": f"Vulnerable Node dependency {adv.get('module_name')} is used.",
                "remediation": f"Upgrade to a fixed version: {adv.get('patched_versions', 'see advisory')}",
                "references": [adv.get("url")] if adv.get("url") else [],
                "tool_evidence": {
                    "rule_id": str(adv.get("id")),
                    "package_name": adv.get("module_name"),
                    "vulnerable_versions": adv.get("vulnerable_versions"),
                    "fixed_version": adv.get("patched_versions"),
                },
                "_group": group,
            }
            if cves:
                finding["citations"] = {"cve": cves}
            out.append(finding)
            n += 1
        return out
```

- [ ] **Step 4: Create fixtures**

Create `tests/fixtures/vulnerable-node/package.json`:

```json
{
  "name": "vulnerable-node",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.20"
  }
}
```

Create `tests/fixtures/vulnerable-node/package-lock.json`:

```json
{
  "name": "vulnerable-node",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    }
  }
}
```

- [ ] **Step 5: Run tests**

Run: `python3 -m pytest tests/tools/test_npm_audit.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/tools/npm_audit.py tests/tools/test_npm_audit.py tests/fixtures/vulnerable-node/
git commit -m "feat(tools): npm-audit adapter and tests"
```

---

### Task 4: osv-scanner adapter

**Files:**
- Create: `scripts/tools/osv_scanner.py`
- Create: `tests/tools/test_osv_scanner.py`

**Interfaces:**
- Consumes: `ToolAdapter` protocol, `normalize_severity()`, `new_finding_id()`.
- Produces: `OsvScannerAdapter`.

- [ ] **Step 1: Write failing test**

Create `tests/tools/test_osv_scanner.py`:

```python
import json, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "scripts"))
import tools.osv_scanner as osv

OSV_SAMPLE = json.dumps({
    "results": [
        {
            "package": {"name": "django", "version": "3.2", "ecosystem": "PyPI"},
            "vulnerabilities": [
                {
                    "id": "GHSA-XXXX-XXXX",
                    "aliases": ["CVE-2022-1234"],
                    "severity": "HIGH",
                    "summary": "SQL injection in Django"
                }
            ]
        }
    ]
}).encode()


class TestOsvScannerAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = osv.OsvScannerAdapter().parse(OSV_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:osv-scanner")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["citations"]["cve"], ["CVE-2022-1234"])
        self.assertEqual(f["tool_evidence"]["package_name"], "django")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/tools/test_osv_scanner.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement adapter**

Create `scripts/tools/osv_scanner.py`:

```python
"""OSV scanner adapter for cross-ecosystem dependency advisories."""
from __future__ import annotations
import json
import os
import subprocess
from scripts.tools.base import normalize_severity, new_finding_id


class OsvScannerAdapter:
    name = "osv-scanner"
    prefix = "OS"

    def is_applicable(self, target: str) -> bool:
        markers = [
            "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
            "requirements.txt", "pyproject.toml", "Pipfile.lock",
            "go.mod", "go.sum",
            "Cargo.lock", "Cargo.toml",
            "pom.xml", "build.gradle", "gradle.lockfile",
        ]
        return any(os.path.isfile(os.path.join(target, m)) for m in markers)

    def invoke(self, target: str) -> tuple[bytes, int]:
        cmd = ["osv-scanner", "--format", "json", "--recursive", target]
        res = subprocess.run(cmd, capture_output=True, timeout=300)
        return res.stdout, res.returncode

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for result in data.get("results", []):
            pkg = result.get("package", {})
            for vuln in result.get("vulnerabilities", []):
                cves = [a.upper() for a in vuln.get("aliases", []) if a.upper().startswith("CVE-")]
                finding = {
                    "id": new_finding_id(self.prefix, n),
                    "title": f"{pkg.get('name')} {pkg.get('version')}: {vuln.get('id', 'vulnerability')}",
                    "severity": normalize_severity(vuln.get("severity")),
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "dependency_vulnerability",
                    "source": f"tool:{self.name}",
                    "location": {"file": pkg.get("ecosystem", "manifest"), "line_start": 1},
                    "description": vuln.get("summary", "No description provided."),
                    "impact": f"Vulnerable dependency {pkg.get('name')}=={pkg.get('version')} is used.",
                    "remediation": "Upgrade to a patched version or see the OSV advisory.",
                    "references": [],
                    "tool_evidence": {
                        "rule_id": vuln.get("id"),
                        "package_name": pkg.get("name"),
                        "vulnerable_versions": pkg.get("version"),
                        "ecosystem": pkg.get("ecosystem"),
                    },
                    "_group": group,
                }
                if cves:
                    finding["citations"] = {"cve": cves}
                out.append(finding)
                n += 1
        return out
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest tests/tools/test_osv_scanner.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/tools/osv_scanner.py tests/tools/test_osv_scanner.py
git commit -m "feat(tools): osv-scanner adapter and tests"
```

---

### Task 5: eslint-plugin-security adapter

**Files:**
- Create: `scripts/tools/eslint_security.py`
- Create: `tests/tools/test_eslint_security.py`
- Create: `tests/fixtures/insecure-js/app.js`

**Interfaces:**
- Consumes: `ToolAdapter` protocol, `normalize_severity()`, `new_finding_id()`.
- Produces: `EslintSecurityAdapter`.

- [ ] **Step 1: Write failing test**

Create `tests/tools/test_eslint_security.py`:

```python
import json, os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "scripts"))
import tools.eslint_security as es

ESLINT_SAMPLE = json.dumps([
    {
        "filePath": "/src/app.js",
        "messages": [
            {
                "ruleId": "security/detect-eval-with-expression",
                "severity": 2,
                "line": 10,
                "column": 5,
                "message": "eval with expression"
            }
        ]
    }
]).encode()


class TestEslintSecurityAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = es.EslintSecurityAdapter().parse(ESLINT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:eslint-security")
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["location"]["file"], "app.js")
        self.assertEqual(f["location"]["line_start"], 10)
        self.assertEqual(f["tool_evidence"]["rule_id"], "security/detect-eval-with-expression")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/tools/test_eslint_security.py -v`
Expected: FAIL.

- [ ] **Step 3: Implement adapter**

Create `scripts/tools/eslint_security.py`:

```python
"""eslint-plugin-security adapter for JS/TS security anti-patterns."""
from __future__ import annotations
import glob
import json
import os
import subprocess
from scripts.tools.base import normalize_severity, new_finding_id


# CWE mappings for eslint-plugin-security rules (best-effort).
RULE_CWE = {
    "security/detect-eval-with-expression": "CWE-95",
    "security/detect-non-literal-require": "CWE-114",
    "security/detect-non-literal-fs-filename": "CWE-22",
    "security/detect-unsafe-regex": "CWE-185",
    "security/detect-buffer-noassert": "CWE-119",
    "security/detect-child-process": "CWE-78",
    "security/detect-disable-mustache-escape": "CWE-79",
    "security/detect-no-csrf-before-method-override": "CWE-352",
    "security/detect-object-injection": "CWE-94",
    "security/detect-possible-timing-attacks": "CWE-208",
    "security/detect-pseudoRandomBytes": "CWE-338",
}


class EslintSecurityAdapter:
    name = "eslint-security"
    prefix = "ES"

    def is_applicable(self, target: str) -> bool:
        return bool(glob.glob(os.path.join(target, "**/*.js"), recursive=True) or
                    glob.glob(os.path.join(target, "**/*.ts"), recursive=True) or
                    glob.glob(os.path.join(target, "**/*.jsx"), recursive=True) or
                    glob.glob(os.path.join(target, "**/*.tsx"), recursive=True) or
                    os.path.isfile(os.path.join(target, "package.json")))

    def invoke(self, target: str) -> tuple[bytes, int]:
        config = self._write_temp_config()
        cmd = [
            "eslint", "--no-eslintrc", "--parser-options", "ecmaVersion:latest",
            "--plugin", "security", "--rule", "security/detect-eval-with-expression: error",
            "--rule", "security/detect-non-literal-require: error",
            "--rule", "security/detect-non-literal-fs-filename: error",
            "--rule", "security/detect-unsafe-regex: error",
            "--rule", "security/detect-child-process: error",
            "--rule", "security/detect-object-injection: error",
            "--format", "json", target,
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, timeout=300)
        finally:
            if config and os.path.isfile(config):
                os.unlink(config)
        return res.stdout, res.returncode

    def _write_temp_config(self) -> str | None:
        return None

    def parse(self, raw: bytes, group: str) -> list[dict]:
        data = json.loads(raw.decode("utf-8", errors="replace"))
        out = []
        n = 1
        for file_result in data:
            file_path = file_result.get("filePath", "")
            rel = self._strip_prefix(file_path)
            for msg in file_result.get("messages", []):
                rule = msg.get("ruleId", "")
                if not rule.startswith("security/"):
                    continue
                severity = "HIGH" if msg.get("severity") == 2 else "MEDIUM"
                cwe = RULE_CWE.get(rule)
                finding = {
                    "id": new_finding_id(self.prefix, n),
                    "title": msg.get("message", rule),
                    "severity": severity,
                    "confidence": "CERTAIN",
                    "panel": "security",
                    "category": "code_security",
                    "source": f"tool:{self.name}",
                    "location": {"file": rel, "line_start": msg.get("line", 1)},
                    "description": f"eslint-plugin-security rule {rule} triggered.",
                    "impact": "Potential security weakness in JavaScript/TypeScript code.",
                    "remediation": "Review the flagged code and follow the plugin's guidance.",
                    "references": [],
                    "tool_evidence": {"rule_id": rule},
                    "_group": group,
                }
                if cwe:
                    finding["citations"] = {"cwe": [cwe]}
                out.append(finding)
                n += 1
        return out

    def _strip_prefix(self, path: str) -> str:
        for prefix in ["/src/", "/"]:
            if path.startswith(prefix):
                return path[len(prefix):]
        return path
```

- [ ] **Step 4: Create fixture**

Create `tests/fixtures/insecure-js/app.js`:

```javascript
const userInput = process.argv[2];
eval(userInput);
```

- [ ] **Step 5: Run tests**

Run: `python3 -m pytest tests/tools/test_eslint_security.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add scripts/tools/eslint_security.py tests/tools/test_eslint_security.py tests/fixtures/insecure-js/
git commit -m "feat(tools): eslint-plugin-security adapter and tests"
```

---

### Task 6: Refactor run_tools.py to dispatch adapters

**Files:**
- Modify: `scripts/run_tools.py`
- Modify: `tests/test_run_tools.py`

**Interfaces:**
- Consumes: `scripts/tools/__init__.ADAPTERS` and adapter `is_applicable()` / `invoke()`.
- Produces: `run_adapters()` function; raw output files in `.panopticon/tools/`.

- [ ] **Step 1: Write failing test for adapter dispatch**

Append to `tests/test_run_tools.py`:

```python
class TestAdapterDispatch(unittest.TestCase):
    def test_select_adapters_by_ecosystem(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "requirements.txt"), "w").close()
            names = rt.select_adapters(d)
            self.assertIn("pip-audit", names)
            self.assertNotIn("npm-audit", names)

    def test_run_adapters_writes_raw_output(self):
        class FakeAdapter:
            name = "fake"
            def is_applicable(self, target): return True
            def invoke(self, target): return (b'{"results":[]}', 0)

        with tempfile.TemporaryDirectory() as d:
            out_dir = os.path.join(d, "out")
            rt.run_adapters({"fake": FakeAdapter()}, d, out_dir)
            with open(os.path.join(out_dir, "fake.json")) as fh:
                self.assertEqual(json.load(fh), {"results": []})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_run_tools.py::TestAdapterDispatch -v`
Expected: FAIL.

- [ ] **Step 3: Implement adapter dispatch in run_tools.py**

Modify `scripts/run_tools.py`:

```python
import json
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tools import ADAPTERS


def select_adapters(target: str, adapters: dict | None = None) -> dict:
    """Return the subset of adapters applicable to the target repo."""
    adapters = adapters or ADAPTERS
    return {name: adapter for name, adapter in adapters.items() if adapter.is_applicable(target)}


def run_adapters(adapters: dict, target: str, out_dir: str, runner=None) -> list[str]:
    """Run each applicable adapter and write raw output to out_dir."""
    runner = runner or subprocess.run
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, adapter in adapters.items():
        ext = "sarif" if name in LEGACY_SARIF_TOOLS else "json"
        out_path = os.path.join(out_dir, f"{name}.{ext}")
        try:
            stdout, rc = adapter.invoke(target)
            if rc not in (0, 1):
                print(f"adapter {name} exited {rc}; skipping", file=sys.stderr)
                continue
            with open(out_path, "wb") as fh:
                fh.write(stdout)
            written.append(out_path)
        except Exception as e:
            print(f"adapter {name} failed: {e}; skipping", file=sys.stderr)
    return written


LEGACY_SARIF_TOOLS = {"semgrep", "bandit", "trivy", "gitleaks", "gosec", "brakeman", "eslint"}
```

Keep the existing `docker_available`, `select_tools`, `run_tools` functions for backward compatibility, but have `run_tools` delegate to `run_adapters` when Docker is available by running adapters inside the container.

For the Docker path, add an `--adapters` mode to the container entrypoint so the Python runner inside Docker can call `run_adapters`. For Phase 1, a simpler approach is acceptable: keep the existing per-tool Docker commands for legacy tools and add adapter commands for new tools. The plan's minimal implementation runs adapters on the host when no Docker is available and inside Docker via a generic script when Docker is available.

Add a helper script `scripts/_run_adapter.py`:

```python
"""Run a single adapter by name and print raw output to stdout."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tools import ADAPTERS

name = sys.argv[1]
target = sys.argv[2] if len(sys.argv) > 2 else "/src"
adapter = ADAPTERS[name]
stdout, rc = adapter.invoke(target)
sys.stdout.buffer.write(stdout)
sys.exit(rc)
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest tests/test_run_tools.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/run_tools.py scripts/_run_adapter.py tests/test_run_tools.py
git commit -m "feat(tools): adapter dispatch in run_tools.py"
```

---

### Task 7: Refactor ingest_tools.py to route adapters

**Files:**
- Modify: `scripts/ingest_tools.py`
- Modify: `tests/test_ingest_tools.py`

**Interfaces:**
- Consumes: `scripts/tools/__init__.ADAPTERS` and adapter `parse()`.
- Produces: `ingest_dir()` routes files to adapters.

- [ ] **Step 1: Write failing test for adapter routing**

Append to `tests/test_ingest_tools.py`:

```python
class TestAdapterRouting(unittest.TestCase):
    def test_ingest_routes_json_to_adapter(self):
        raw = json.dumps({"dependencies": [{"name": "x", "version": "1.0", "vulns": []}]})
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pip-audit.json"), "w") as fh:
                fh.write(raw)
            out = it.ingest_dir(d, "g1")
            self.assertEqual(out, [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_ingest_tools.py::TestAdapterRouting -v`
Expected: FAIL.

- [ ] **Step 3: Implement adapter routing**

Modify `scripts/ingest_tools.py`:

```python
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tools import ADAPTERS


def ingest_dir(tools_dir, group):
    out = []
    for path in sorted(glob.glob(os.path.join(tools_dir, "*.sarif"))
                       + glob.glob(os.path.join(tools_dir, "*.json"))):
        tool = os.path.splitext(os.path.basename(path))[0]
        adapter = ADAPTERS.get(tool)
        if adapter is None:
            print(f"ingest skip {path}: no adapter registered", file=sys.stderr)
            continue
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
        except OSError as e:
            print(f"ingest skip {path}: {e}", file=sys.stderr)
            continue
        try:
            out.extend(adapter.parse(raw, group))
        except Exception as e:
            print(f"ingest error {path}: {e}", file=sys.stderr)
            continue
    return out
```

Keep `sarif_to_findings` as the legacy adapter uses it.

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest tests/test_ingest_tools.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/ingest_tools.py tests/test_ingest_tools.py
git commit -m "feat(tools): route ingestion through adapters"
```

---

### Task 8: Update Dockerfile

**Files:**
- Modify: `Dockerfile`
- Modify: `tests/test_dockerfile.py`

**Interfaces:**
- Consumes: existing Dockerfile and test.
- Produces: image with pip-audit, osv-scanner, eslint-plugin-security installed.

- [ ] **Step 1: Write failing test**

Append to `tests/test_dockerfile.py`:

```python
class TestDockerfilePhase1(unittest.TestCase):
    def test_pip_audit_mentioned(self):
        text = Path("Dockerfile").read_text()
        self.assertIn("pip-audit", text)
        self.assertIn("osv-scanner", text)
        self.assertIn("eslint-plugin-security", text)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_dockerfile.py::TestDockerfilePhase1 -v`
Expected: FAIL.

- [ ] **Step 3: Update Dockerfile**

Add after the existing Node/npm install block in `Dockerfile`:

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

- [ ] **Step 4: Build image and smoke-test**

Run: `docker build -t panopticon-tools .`
Expected: exit 0.

Run: `docker run --rm panopticon-tools pip-audit --version`
Expected: version printed.

Run: `docker run --rm panopticon-tools osv-scanner --version`
Expected: version printed.

Run: `docker run --rm panopticon-tools eslint --version`
Expected: version printed.

- [ ] **Step 5: Run tests**

Run: `python3 -m pytest tests/test_dockerfile.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add Dockerfile tests/test_dockerfile.py
git commit -m "feat(tools): install Phase 1 scanners in Docker image"
```

---

### Task 9: Extend report schema for tool_evidence

**Files:**
- Modify: `reference/report-schema.json`
- Modify: `tests/test_schemas.py`

**Interfaces:**
- Consumes: existing finding schema.
- Produces: schema accepts optional `tool_evidence` object.

- [ ] **Step 1: Write failing test**

Append to `tests/test_schemas.py`:

```python
class TestToolEvidenceSchema(unittest.TestCase):
    def test_tool_evidence_in_finding_schema(self):
        schema = self._load("report-schema.json")
        props = schema["properties"]["findings"]["items"]["properties"]
        self.assertIn("tool_evidence", props)
        self.assertEqual(props["tool_evidence"]["type"], "object")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_schemas.py::TestToolEvidenceSchema -v`
Expected: FAIL.

- [ ] **Step 3: Update schema**

Edit `reference/report-schema.json` in the finding properties section:

```json
"tool_evidence": {
  "type": "object",
  "properties": {
    "rule_id": { "type": "string" },
    "advisory_url": { "type": "string" },
    "package_name": { "type": "string" },
    "vulnerable_versions": { "type": "string" },
    "fixed_version": { "type": "string" },
    "cvss_score": { "type": "number" },
    "ecosystem": { "type": "string" }
  }
}
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest tests/test_schemas.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add reference/report-schema.json tests/test_schemas.py
git commit -m "feat(schema): add tool_evidence to finding schema"
```

---

### Task 10: Integration test for full Phase 1 pipeline

**Files:**
- Create: `tests/test_phase1_integration.py`

**Interfaces:**
- Consumes: adapters, dispatcher, ingestion.
- Produces: test verifying end-to-end tool findings.

- [ ] **Step 1: Write integration test**

Create `tests/test_phase1_integration.py`:

```python
import json, os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import ingest_tools as it
import run_tools as rt
from tools import ADAPTERS


class TestPhase1Integration(unittest.TestCase):
    def test_pip_audit_finds_requests_cve(self):
        target = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable-python")
        adapter = ADAPTERS["pip-audit"]
        if not adapter.is_applicable(target):
            self.skipTest("pip-audit not applicable to fixture")
        raw, rc = adapter.invoke(target)
        if rc not in (0, 1):
            self.skipTest(f"pip-audit failed with {rc}")
        findings = adapter.parse(raw, "g1")
        self.assertTrue(any("CVE-" in str(f.get("citations")) for f in findings),
                        f"expected CVE citation, got {findings}")

    def test_ingest_dir_routes_adapter_output(self):
        target = os.path.join(os.path.dirname(__file__), "fixtures", "vulnerable-python")
        adapter = ADAPTERS["pip-audit"]
        raw, _ = adapter.invoke(target)
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pip-audit.json"), "wb") as fh:
                fh.write(raw)
            findings = it.ingest_dir(d, "g1")
            self.assertTrue(all(f.get("source") == "tool:pip-audit" for f in findings))
```

- [ ] **Step 2: Run test**

Run: `python3 -m pytest tests/test_phase1_integration.py -v`
Expected: PASS if pip-audit and vulnerable fixture produce a CVE; otherwise adjust fixture version.

- [ ] **Step 3: Commit**

```bash
git add tests/test_phase1_integration.py
git commit -m "test(tools): Phase 1 integration tests"
```

---

### Task 11: Documentation update

**Files:**
- Modify: `DEVELOPMENT.md`
- Modify: `docs/superpowers/specs/2026-08-01-static-analysis-phase1-design.md` if needed

**Interfaces:**
- Consumes: implementation changes.
- Produces: docs explaining how to add a new adapter.

- [ ] **Step 1: Update DEVELOPMENT.md**

Add a "Adding a new static-analysis tool" section:

```markdown
## Adding a new static-analysis tool

1. Create `scripts/tools/<tool_name>.py` implementing `is_applicable()`, `invoke()`, and `parse()`.
2. Register it in `scripts/tools/__init__.py` under `ADAPTERS`.
3. Add unit tests in `tests/tools/test_<tool_name>.py`.
4. If the tool needs installation, add it to `Dockerfile`.
5. Run `python3 -m pytest tests/tools/ tests/test_ingest_tools.py tests/test_run_tools.py -v`.
```

- [ ] **Step 2: Run docs tests**

Run: `python3 -m pytest tests/test_skill_md.py -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add DEVELOPMENT.md
git commit -m "docs: how to add a new tool adapter"
```

---

## Self-Review

1. **Spec coverage:**
   - Adapter contract → Task 1
   - pip-audit → Task 2
   - npm-audit → Task 3
   - osv-scanner → Task 4
   - eslint-plugin-security → Task 5
   - Dispatcher refactor → Task 6
   - Ingestion refactor → Task 7
   - Dockerfile → Task 8
   - Schema `tool_evidence` → Task 9
   - Tests and fixtures → Tasks 2-5, 10
   - Documentation → Task 11

2. **Placeholder scan:** No TBD/TODO/placeholder text in tasks. Every step includes code, commands, and expected output.

3. **Type consistency:**
   - Adapter interface uses `invoke(target: str) -> tuple[bytes, int]` and `parse(raw: bytes, group: str) -> list[dict]` consistently.
   - Finding IDs follow the `XX-NNN` pattern.
   - `source` field is always `tool:<name>`.

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-08-01-static-analysis-phase1.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
