# Panopticon Kimi Code Port — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port the panopticon Claude Code skill to Kimi Code as a personal skill at `~/.kimi-code/skills/panopticon/`, expanding panels to architecture/database and adding a red-team security mode.

**Architecture:** Keep the proven deterministic scripts (`orchestrator.py`, `synthesize.py`, tool scripts) and rewrite the skill entry point (`SKILL.md`) as a concise Kimi-native orchestration doc. Drive the pipeline with Kimi tools (`AskUserQuestion`, `TodoList`, `AgentSwarm`, `Agent(coder)`), and update prompts/schemas for flexible lenses, new panels, and red-team mode.

**Tech Stack:** Python 3 (stdlib-only scripts), JSON Schema, Markdown, Docker (optional tool container).

## Global Constraints

- Target location: `~/.kimi-code/skills/panopticon/`.
- `SKILL.md` must be concise and Kimi skill-format compliant (frontmatter with `name` + `description` under 1024 chars total; description starts with "Use when...").
- Preserve existing deterministic script behavior unless explicitly changed.
- Keep tests passing; add tests for new behavior.
- Version bump to **3.0.0** in `SKILL.md` frontmatter and `synthesize.build_report`.
- No repo/GitHub writes, no claiming unperformed actions, no materializing secrets.
- Red-team mode replaces baseline security panel when `--security redteam` is set.

---

## File Structure

New files:
- `~/.kimi-code/skills/panopticon/SKILL.md` — rewritten Kimi skill entry point.
- `~/.kimi-code/skills/panopticon/prompts/panel-template.md` — panel dispatch template.

Modified files:
- `~/.kimi-code/skills/panopticon/scripts/orchestrator.py` — detect architecture/database files, accept `--security-mode`.
- `~/.kimi-code/skills/panopticon/scripts/synthesize.py` — handle `architecture`, `database`, `redteam` panels and `security_mode`.
- `~/.kimi-code/skills/panopticon/prompts/scout.md` — add surfaces, lens spawn logic.
- `~/.kimi-code/skills/panopticon/prompts/lenses.md` — flexible lens catalog.
- `~/.kimi-code/skills/panopticon/reference/report-schema.json` — new panel enum + `security_mode`.
- `~/.kimi-code/skills/panopticon/reference/scope-profile-schema.json` — `lenses` + `panels`.

Unchanged files (copied as-is):
- `Dockerfile`, `scripts/citations.py`, `scripts/run_tools.py`, `scripts/ingest_tools.py`, `reference/security-checklists.md`, `reference/cwe-catalog.json`, `reference/code-review-groups.example.yml`, `tests/`.

---

### Task 1: Bootstrap target directory and bump version

**Files:**
- Create: `~/.kimi-code/skills/panopticon/` (directory tree)
- Copy from current project root into that tree.
- Modify: `~/.kimi-code/skills/panopticon/SKILL.md` (full rewrite in Task 2)
- Modify: `~/.kimi-code/skills/panopticon/scripts/synthesize.py:meta.version`

**Interfaces:**
- Consumes: existing panopticon project files.
- Produces: Kimi skill directory tree at target location with version 3.0.0.

- [ ] **Step 1: Create target directory and copy existing files**

```bash
mkdir -p ~/.kimi-code/skills/panopticon
cp -R ~/.claude/skills/panopticon/* ~/.kimi-code/skills/panopticon/
```

- [ ] **Step 2: Update `synthesize.py` version constant**

Find the `build_report` function and change the version string to `"3.0.0"`.

Run:
```bash
grep -n "version" ~/.kimi-code/skills/panopticon/scripts/synthesize.py
```

Expected: a line like `"version": "2.3.0"` inside `build_report`. Edit it to `"version": "3.0.0"`.

- [ ] **Step 3: Verify the tree**

```bash
ls ~/.kimi-code/skills/panopticon/
```

Expected: `SKILL.md`, `DEVELOPMENT.md`, `Dockerfile`, `scripts/`, `prompts/`, `reference/`, `tests/`.

- [ ] **Step 4: Commit**

```bash
git add ~/.kimi-code/skills/panopticon
git commit -m "chore: bootstrap panopticon 3.0.0 kim port"
```

---

### Task 2: Rewrite `SKILL.md` for Kimi Code

**Files:**
- Modify: `~/.kimi-code/skills/panopticon/SKILL.md`

**Interfaces:**
- Consumes: design spec §1–2.
- Produces: Kimi-native skill entry point.

- [ ] **Step 1: Write the new `SKILL.md`**

Overwrite `~/.kimi-code/skills/panopticon/SKILL.md` with:

```markdown
---
name: panopticon
description: "Use when reviewing code, pull requests, branches, security posture, test quality, architecture, or database surfaces in a codebase. Use for repo-wide scans, directory reviews, changed-file reviews, or targeted file/group review. Do not use for writing new code, formatting/linting only, or performance benchmarking."
license: MIT
metadata:
  version: "3.0.0"
---

# panopticon

## Overview
Discovery → scout → fan-out → synthesis code review for Kimi Code. Profiles a target, groups files, dispatches specialized reviewers in parallel, and synthesizes a validated `CodeReviewReport` with CI gating.

## Required sub-skills
- `superpowers:writing-plans` — before repo/PR/directory reviews with >15 files or >10 changes.
- `superpowers:subagent-driven-development` — for panel and lens dispatch.
- `superpowers:verification-before-completion` — before returning the report.

## Modes
Use `AskUserQuestion` when the target is ambiguous. Otherwise map flags directly:
- `-f <path>` / `--file <path>` — single file + related tests + neighbors.
- `-d <dir>` / `--directory <dir>` — directory review.
- `-g <name>` / `--group <name>` — group from `.panopticon/groups.yml`.
- `-c` / `--changes` — branch diff vs merge base (fallback `HEAD~1`).
- `--pr <n>` — PR diff.
- `-e` / `--explore` — discover and catalog groups; no panels unless asked.
- *(none)* — whole-repo scan.

## Global flags
`--full` (force all panels), `--security {standard,redteam}` (default standard), `--fail-on {critical,high,medium,low}`, `--severity {all,medium,high,critical}`, `--out PATH`, `--tools` (require tool scan), `--no-tools` (skip tool scan), `--epss` (enrich CVE citations).

## Pipeline
1. `TodoList`: discovery → scout → tools → panels → lens sub-reviews → synthesis.
2. **Discovery** — run `python3 scripts/orchestrator.py` to produce `groups.json`.
3. **Scout** — dispatch a `coder` subagent per group with `prompts/scout.md`; output `ScopeProfile`.
4. **Plan** — code always; test iff tests/logic present; security iff risky surfaces; architecture iff repo-scope files; database iff `db_sql` surface. `--full` overrides.
5. **Tool scan** — optional Docker container; SARIF ingested by `scripts/ingest_tools.py`.
6. **Fan-out** — `AgentSwarm` of panel reviewers (`coder` subagents with `prompts/panel-template.md`). Each panel spawns lens specialists when the scout flags `spawn: true`.
7. **Synthesize** — `python3 scripts/synthesize.py` merges findings into `CodeReviewReport`.
8. **Validate** — `verification-before-completion`: check gate, print summary, write JSON.

## Output
Terminal markdown summary + JSON artifact at `--out`. CI gate key: `summary.gate`.

## Notes
Reviewers are read-only: no repo/GitHub writes, no claiming unperformed actions, no materializing discovered secrets.
```

- [ ] **Step 2: Validate frontmatter length**

```bash
python3 -c "import yaml; d=yaml.safe_load(open('$HOME/.kimi-code/skills/panopticon/SKILL.md')); s=yaml.dump({'name':d['name'],'description':d['description']}); print(len(s))"
```

Expected: ≤1024 characters.

- [ ] **Step 3: Commit**

```bash
git add ~/.kimi-code/skills/panopticon/SKILL.md
git commit -m "feat(kimi): rewrite SKILL.md for Kimi Code"
```

---

### Task 3: Update `prompts/scout.md`

**Files:**
- Modify: `~/.kimi-code/skills/panopticon/prompts/scout.md`

**Interfaces:**
- Consumes: design spec §4.
- Produces: scout prompt that emits `ScopeProfile` with new surfaces, `lenses`, and `panels`.

- [ ] **Step 1: Rewrite `prompts/scout.md`**

```markdown
# Scout

You are the panopticon scout. Read the assigned files and emit a single
**ScopeProfile** JSON object conforming to `reference/scope-profile-schema.json`.
Do not review the code for defects — only profile it.

## Detect these surfaces
- `db_sql` — SQL, ORM raw queries, migrations, direct DB drivers
- `http_web` — HTTP handlers, routes, controllers, views, templates, client fetch
- `auth` — authentication, sessions, tokens, permission checks
- `crypto` — hashing, encryption, signing, randomness, key handling
- `fs` — file read/write, uploads, path handling
- `concurrency` — threads, async, locks, background jobs, queues
- `external_api` — outbound calls to third-party services
- `money_pii` — payments, PII, financial or regulated data
- `serialization` — (de)serialization of untrusted data
- `templating` — server/client template rendering
- `secrets_config` — secrets, credentials, environment/config handling
- `architecture` — repo layout, CI/CD, Docker/k8s, GitHub configs
- `database` — schema, ORM models, migrations, query builders

## Surface → security lens mapping
- db_sql → injection, database
- http_web, templating → injection, novel
- auth, crypto, money_pii → novel, known_vulns
- serialization, external_api, fs → injection, novel
- architecture → architecture
- database → database

## Facet scoping
If a `facet` is supplied, populate `facet_scope` with the subset of files (and a
one-line rationale) that actually touch that facet. Resolve declared facet keywords
and, for ad-hoc facets, resolve the term semantically.

## Risk
`high` if money_pii/auth/crypto present or a risky surface is untested; `med` for
other code surfaces; `low` for docs/markup/style-only changes.

## Panels
Set `panels` to the panels scheduled for this group:
- `code` always
- `test` if tests or testable logic present
- `security` if auth/crypto/money_pii/serialization/external_api/fs/templating/db_sql/http_web present
- `architecture` if any file is repo-scope (root config, `.github/`, Dockerfile, k8s/helm, docker-compose)
- `database` if `db_sql` surface present

## Lenses
Set `lenses` to an object mapping panel name to a list of `{name, spawn}` objects.
Default lenses:
- code: structure, correctness, style
- test: coverage, test_quality, test_design
- security: known_vulns, injection, novel
- architecture: architecture
- database: database

Set `spawn: true` when the group has ≥5 files or `risk` is `high`; otherwise `spawn: false`.

## Tool selection (v2)
If the container layer is in use, recommend which scanners to run in `tools` and set
`has_deps` true when a dependency manifest is present (requirements.txt, package.json,
go.mod, Gemfile, pom.xml, etc.):
- always: `semgrep`, `gitleaks`
- `has_deps` → add `trivy`
- language-specific: python→`bandit`, ruby→`brakeman`, go→`gosec`, js/ts→`eslint`

Return ONLY the ScopeProfile JSON. No prose.
```

- [ ] **Step 2: Verify JSON example still parses**

No runtime test yet; visually confirm the prompt references valid schema fields.

- [ ] **Step 3: Commit**

```bash
git add ~/.kimi-code/skills/panopticon/prompts/scout.md
git commit -m "feat(kimi): expand scout prompt for architecture, database, redteam surfaces"
```

---

### Task 4: Update `prompts/lenses.md`

**Files:**
- Modify: `~/.kimi-code/skills/panopticon/prompts/lenses.md`

**Interfaces:**
- Consumes: design spec §4.
- Produces: flexible lens catalog with new lenses.

- [ ] **Step 1: Rewrite `prompts/lenses.md`**

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add ~/.kimi-code/skills/panopticon/prompts/lenses.md
git commit -m "feat(kimi): flexible lens catalog with architecture, database, redteam"
```

---

### Task 5: Add `prompts/panel-template.md`

**Files:**
- Create: `~/.kimi-code/skills/panopticon/prompts/panel-template.md`

**Interfaces:**
- Consumes: design spec §3, §6.
- Produces: panel reviewer prompt template.

- [ ] **Step 1: Write the panel template**

```markdown
# Panel Reviewer

You are the {panel} reviewer for panopticon group "{group}".
Files: {file_list}
Security mode: {security_mode}

## Your task
Review ONLY the listed files through the {panel} lens. Emit findings as raw JSON
`{"findings": [...]}` to `.panopticon/findings-{group}-{panel}.json` and return ONLY
the path + count.

## Lenses
{lenses}

## Side-effect boundary
Your ONLY action is writing that one findings file. Perform NO GitHub writes, NO repo
mutations, NO dispatches, NO credential mints. Never report an action you did not
actually perform. Never copy a literal secret value into the finding title,
description, or any output; cite file:line and the secret class only.

## Finding format
Each finding:
- `id`: ^[A-Z]{{2,4}}-\d{{3,}}$
- `severity`: CRITICAL|HIGH|MEDIUM|LOW|INFO
- `panel`: "{panel}"
- `lens`: (lens name, if spawned from a lens)
- `category`: (lens name)
- `location`: {{file, line_start[, line_end, function]}}
- `title`, `description`, `impact`, `remediation`, `references[]`
- Security/Red-team CRITICAL/HIGH: add `cvss` {{score, vector}} and `exploit_scenario`.

Use `Read`, `Grep`, and `Bash` as needed to examine files and cross-references.
```

- [ ] **Step 2: Commit**

```bash
git add ~/.kimi-code/skills/panopticon/prompts/panel-template.md
git commit -m "feat(kimi): add Kimi panel dispatch template"
```

---

### Task 6: Update JSON schemas

**Files:**
- Modify: `~/.kimi-code/skills/panopticon/reference/report-schema.json`
- Modify: `~/.kimi-code/skills/panopticon/reference/scope-profile-schema.json`

**Interfaces:**
- Consumes: design spec §9.
- Produces: schemas validating new panels, lenses, and security_mode.

- [ ] **Step 1: Patch `report-schema.json`**

Change the `meta` required/properties block to include `security_mode`:

```json
"meta": {
  "type": "object",
  "required": ["target", "review_type", "timestamp", "version"],
  "properties": {
    "target": {"type": "string"},
    "review_type": {"type": "string", "enum": ["repo", "file", "directory", "group", "changes", "pr"]},
    "timestamp": {"type": "string"},
    "version": {"type": "string"},
    "security_mode": {"type": "string", "enum": ["standard", "redteam"]},
    "parts": {"type": "array", "items": {"type": "string"}}
  }
}
```

Change the `findings.items.properties.panel` enum:

```json
"panel": {"type": "string", "enum": ["code", "test", "security", "architecture", "database", "redteam"]},
```

Add `lens` to finding properties (optional string):

```json
"lens": {"type": "string"},
```

- [ ] **Step 2: Patch `scope-profile-schema.json`**

Replace the `suggested_lenses` block with:

```json
"lenses": {
  "type": "object",
  "additionalProperties": {
    "type": "array",
    "items": {
      "type": "object",
      "required": ["name", "spawn"],
      "properties": {
        "name": {"type": "string"},
        "spawn": {"type": "boolean"}
      }
    }
  }
},
"panels": {
  "type": "array",
  "items": {
    "type": "string",
    "enum": ["code", "test", "security", "architecture", "database", "redteam"]
  }
},
```

Also add `architecture` and `database` to the `surfaces` enum:

```json
"enum": ["db_sql", "http_web", "auth", "crypto", "fs", "concurrency",
         "external_api", "money_pii", "serialization", "templating", "secrets_config",
         "architecture", "database"]
```

- [ ] **Step 3: Validate schemas**

```bash
python3 -m json.tool ~/.kimi-code/skills/panopticon/reference/report-schema.json > /dev/null
python3 -m json.tool ~/.kimi-code/skills/panopticon/reference/scope-profile-schema.json > /dev/null
```

Expected: no output (valid JSON).

- [ ] **Step 4: Commit**

```bash
git add ~/.kimi-code/skills/panopticon/reference/report-schema.json ~/.kimi-code/skills/panopticon/reference/scope-profile-schema.json
git commit -m "feat(kimi): add architecture/database/redteam panels to schemas"
```

---

### Task 7: Patch `scripts/orchestrator.py`

**Files:**
- Modify: `~/.kimi-code/skills/panopticon/scripts/orchestrator.py`

**Interfaces:**
- Consumes: design spec §3.
- Produces: `orchestrator.py` outputs `groups.json` with optional panel hints and accepts `--security-mode`.

- [ ] **Step 1: Add `--security-mode` argument**

In the argument parser, add:

```python
parser.add_argument("--security-mode", choices=["standard", "redteam"], default="standard",
                    help="Security review mode")
```

- [ ] **Step 2: Detect architecture/database files**

Add a helper near `is_test_file`:

```python
ARCHITECTURE_PATTERNS = [
    r"(^|/)(\.github|\.circleci|\.gitlab)/",
    r"(^|/)Dockerfile",
    r"(^|/)docker-compose",
    r"(^|/)(k8s|kubernetes|helm|charts)/",
    r"(^|/)\.dockerignore$",
    r"(^|/)\.editorconfig$",
    r"(^|/)\.gitignore$",
    r"(^|/)(README|CONTRIBUTING|LICENSE)",
]

DATABASE_PATTERNS = [
    r"\.sql$",
    r"(^|/)(migrations|migrate)/",
    r"(_migration|\.migration)\.",
]


def is_architecture_file(path):
    return any(re.search(p, path) for p in ARCHITECTURE_PATTERNS)


def is_database_file(path):
    return any(re.search(p, path) for p in DATABASE_PATTERNS)
```

- [ ] **Step 3: Pass security mode into groups metadata**

Where `groups.json` is written, include `security_mode` at the top level:

```json
{
  "security_mode": "standard",
  "groups": [...]
}
```

If changing the output shape breaks tests, update the tests in Task 9.

- [ ] **Step 4: Commit**

```bash
git add ~/.kimi-code/skills/panopticon/scripts/orchestrator.py
git commit -m "feat(kimi): orchestrator detects architecture/database files and accepts security-mode"
```

---

### Task 8: Patch `scripts/synthesize.py`

**Files:**
- Modify: `~/.kimi-code/skills/panopticon/scripts/synthesize.py`

**Interfaces:**
- Consumes: `groups.json` with `security_mode`, findings with `panel`/`lens`.
- Produces: `CodeReviewReport` with new panels and `meta.security_mode`.

- [ ] **Step 1: Accept `--security-mode` and load from groups metadata**

Add argument:

```python
parser.add_argument("--security-mode", choices=["standard", "redteam"], default=None,
                    help="Override security mode from groups.json")
```

When loading groups, read `security_mode` from the JSON if not provided by flag:

```python
groups_data = json.load(open(args.groups))
security_mode = args.security_mode or groups_data.get("security_mode", "standard")
```

- [ ] **Step 2: Update `normalize_finding` panel validation**

Change:

```python
if f.get("panel") not in ("code", "test", "security"):
    f["panel"] = "code"
```

to:

```python
VALID_PANELS = {"code", "test", "security", "architecture", "database", "redteam"}
if f.get("panel") not in VALID_PANELS:
    f["panel"] = "code"
```

Also normalize `lens` if present:

```python
f.setdefault("lens", None)
```

- [ ] **Step 3: Include `security_mode` in report meta**

In `build_report`, add `security_mode` to the `meta` dict:

```python
"meta": {
    "target": target,
    "review_type": review_type,
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "version": "3.0.0",
    "security_mode": security_mode,
    "parts": parts,
}
```

- [ ] **Step 4: Update cross-panel corroboration**

Extend the corroboration logic so architecture/database findings can corroborate security findings. Look for `cross_panel_corroboration` and add:

```python
RELATED_PANELS = {
    "security": {"architecture", "database", "redteam"},
    "redteam": {"security", "architecture", "database"},
    "architecture": {"security", "redteam"},
    "database": {"security", "redteam"},
}
```

Use this map when deciding if two findings from different panels should be considered related.

- [ ] **Step 5: Commit**

```bash
git add ~/.kimi-code/skills/panopticon/scripts/synthesize.py
git commit -m "feat(kimi): synthesize supports architecture/database/redteam and security_mode"
```

---

### Task 9: Update and run tests

**Files:**
- Modify: `~/.kimi-code/skills/panopticon/tests/test_orchestrator.py` (if output shape changed)
- Modify: `~/.kimi-code/skills/panopticon/tests/test_schemas.py` (if schema tests need new panels)
- Modify: `~/.kimi-code/skills/panopticon/tests/test_synthesize.py` (panel validation, security_mode)

**Interfaces:**
- Consumes: patched scripts and schemas.
- Produces: passing test suite.

- [ ] **Step 1: Run existing tests to find failures**

```bash
cd ~/.kimi-code/skills/panopticon
python3 -m pytest -q
```

Expected: some failures due to schema/output changes.

- [ ] **Step 2: Fix failing tests**

For each failure:
- If `groups.json` shape changed, update fixture construction in `test_orchestrator.py`.
- If panel enum changed, update `test_schemas.py`.
- If `normalize_finding` changed, add tests for new panels and `security_mode` in `test_synthesize.py`.

Example new test:

```python
def test_normalize_finding_accepts_architecture_panel():
    f = normalize_finding({"panel": "architecture", "title": "x", "description": "y"})
    assert f["panel"] == "architecture"
```

- [ ] **Step 3: Run tests again**

```bash
python3 -m pytest -q
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add ~/.kimi-code/skills/panopticon/tests
git commit -m "test(kimi): update tests for new panels and security_mode"
```

---

### Task 10: Self-review the skill on itself

**Files:**
- Uses: whole `~/.kimi-code/skills/panopticon/` directory.

**Interfaces:**
- Consumes: completed skill.
- Produces: iterated fixes and a clean red-team self-review.

- [ ] **Step 1: Run the skill against itself in standard mode**

From a fresh Kimi session with the skill loaded:

```
/panopticon --directory ~/.kimi-code/skills/panopticon --out ~/.panopticon/self-standard.json
```

Expected: report generates without errors.

- [ ] **Step 2: Run the skill against itself in red-team mode**

```
/panopticon --directory ~/.kimi-code/skills/panopticon --security redteam --out ~/.panopticon/self-redteam.json
```

Expected: report generates; `meta.security_mode` is `"redteam"`; findings include panel `redteam`.

- [ ] **Step 3: Fix any HIGH/CRITICAL findings the skill finds in itself**

Iterate on `scripts/*.py`, `SKILL.md`, and prompts until the self-review is acceptable.

- [ ] **Step 4: Run baseline pressure scenario per writing-skills**

Without the new `SKILL.md` loaded, ask a fresh subagent to "review this directory for security issues" and note what it skips. Then load the skill and rerun; verify it follows the full pipeline.

- [ ] **Step 5: Commit final fixes**

```bash
git add ~/.kimi-code/skills/panopticon
git commit -m "fix(kimi): self-review residuals"
```

---

## Self-Review Checklist

- [ ] **Spec coverage:** Every design section maps to at least one task.
  - Skill structure → Task 2
  - Kimi-native orchestration → Task 2 (SKILL.md pipeline)
  - Panels → Tasks 2, 3, 4, 6, 7, 8
  - Flexible lens model → Tasks 3, 4, 5
  - Red-team mode → Tasks 2, 3, 4, 6, 8
  - Subagent tool autonomy → Task 5 (panel template)
  - Tool container → unchanged, copied in Task 1
  - Synthesis/output → Task 8
  - Schema updates → Task 6
  - Testing → Tasks 9, 10
- [ ] **Placeholder scan:** No TBD/TODO/"implement later"/"fill in details".
- [ ] **Type consistency:** `security_mode` is `"standard"|"redteam"` everywhere; panel enum matches across schema, synthesize, and scout.
