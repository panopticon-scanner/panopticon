# Multi-Model Reviewer Dispatch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a role-based dispatch layer to panopticon so each panel runs a main reviewer plus up to three lens-sweep agents, with an independent advisor verifying uncited claims, across Kimi and Claude hosts.

**Architecture:** A new `scripts/dispatch.py` consumes the enriched `ScopeProfile`, uses `DepthPlanner` to choose which lenses become mechanical agents and `ModelResolver` to pick per-host models, then emits a `DispatchPlan`. The skill fan-out step dispatches Kimi Code custom agents (`lens-sweep`, `panel-review`, `advisor`) by name, each with its own tool policy and model preference. `synthesize.py` tags tenuous claims and spawns advisors before final report generation.

**Tech Stack:** Python 3.11+, stdlib + pytest, YAML model profiles, JSON schemas.

## Global Constraints

- **Cross-platform**: the same skill must work on Kimi Code and Claude without host-specific code paths outside the model resolver.
- **Modular depth**: scan depth is a function of which lenses are spawned, not a rewrite of the pipeline.
- **No infinite recursion**: the advisor runs at most once per flagged claim.
- **Minimal integration changes**: existing grouping, tool scanning, and SARIF ingestion are left untouched.
- **Read-only reviews**: agents parse source only; no repo or GitHub mutations.
- **No placeholders**: every step includes exact file paths, code, and expected test output.

---

## File Structure

| File | Responsibility |
|---|---|
| `reference/model-profiles.yml` | Host → role → model config (model id, context, output) |
| `reference/scope-profile-schema.json` | Validates `depth`, `files`, `lens.priority`, `lens.depth_threshold` |
| `reference/report-schema.json` | Validates `source_role`, `advisor_verdict`, `depth` |
| `scripts/model_resolver.py` | Resolves `(host, role)` to model config dict with CLI/env overrides |
| `scripts/depth_planner.py` | Ranks lenses per panel and selects which ones get mechanical agents |
| `scripts/dispatch.py` | Reads `ScopeProfile` and emits `DispatchPlan` JSON |
| `agents/lens-sweep.md` | Kimi Code custom agent for narrow mechanical lens sweep |
| `agents/panel-review.md` | Kimi Code custom agent for holistic panel review |
| `agents/advisor.md` | Kimi Code custom agent for independent claim verification |
| `agents/scout.md` | Kimi Code custom agent for profiling and depth selection |
| `prompts/scout.md` | Removed; logic moved to `agents/scout.md` |
| `scripts/synthesize.py` | Updated to tag tenuous claims, run advisors, and emit advisor verdicts |
| `SKILL.md` | Updated frontmatter and fan-out step to dispatch custom agents by name |
| `tests/test_model_resolver.py` | ModelResolver tests |
| `tests/test_depth_planner.py` | DepthPlanner tests |
| `tests/test_dispatch.py` | DispatchPlan generation tests |
| `tests/test_synthesize_advisor.py` | Advisor trigger + verdict tests |

---

## Task 1: Add model profiles configuration

**Files:**
- Create: `reference/model-profiles.yml`
- Test: `tests/test_model_resolver.py` (created in Task 3)

**Interfaces:**
- Consumes: none
- Produces: YAML config consumed by `scripts/model_resolver.py`

- [ ] **Step 1: Create `reference/model-profiles.yml`**

```yaml
hosts:
  kimi:
    scout:
      model: kimi-for-coding
      max_context_size: 131072
      max_output_size: 16384
    lens_sweep:
      model: kimi-for-coding
      max_context_size: 131072
      max_output_size: 8192
    panel_review:
      model: kimi-for-coding
      max_context_size: 131072
      max_output_size: 16384
    advisor:
      model: k3
      max_context_size: 524288
      max_output_size: 32768
  claude:
    scout:
      model: claude-haiku
      max_context_size: 200000
      max_output_size: 4096
    lens_sweep:
      model: claude-haiku
      max_context_size: 200000
      max_output_size: 4096
    panel_review:
      model: claude-sonnet
      max_context_size: 200000
      max_output_size: 8192
    advisor:
      model: claude-opus
      max_context_size: 200000
      max_output_size: 16384
  openrouter:
    scout:
      model: openai/gpt-4o-mini
      max_context_size: 128000
      max_output_size: 4096
    lens_sweep:
      model: openai/gpt-4o-mini
      max_context_size: 128000
      max_output_size: 4096
    panel_review:
      model: anthropic/claude-sonnet
      max_context_size: 200000
      max_output_size: 8192
    advisor:
      model: anthropic/claude-opus
      max_context_size: 200000
      max_output_size: 16384

roles:
  scout:
    description: Profiles files and selects depth/lenses
  lens_sweep:
    description: Cheap, narrow mechanical lens sweep
  panel_review:
    description: Main reviewer for a panel
  advisor:
    description: Independent claim verification
```

- [ ] **Step 2: Validate YAML loads**

Run: `python3 -c "import yaml; print(yaml.safe_load(open('reference/model-profiles.yml')))"`
Expected: dict with `hosts` and `roles` keys.

- [ ] **Step 3: Commit**

```bash
git add reference/model-profiles.yml
git commit -m "config: add model profiles for kimi/claude/openrouter"
```

---

## Task 2: Update schemas

**Files:**
- Modify: `reference/scope-profile-schema.json`
- Modify: `reference/report-schema.json`
- Test: `tests/test_schemas.py`

**Interfaces:**
- Consumes: existing schema files
- Produces: updated schema files validated by `tests/test_schemas.py`

- [ ] **Step 1: Extend scope-profile schema**

In `reference/scope-profile-schema.json`, make two changes:

1. Replace the `lenses` property definition with:

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
        "spawn": {"type": "boolean"},
        "priority": {"type": "integer", "minimum": 0},
        "depth_threshold": {"type": "string", "enum": ["shallow", "standard", "deep"]}
      }
    }
  }
}
```

2. Add top-level `files` and `depth` properties:

```json
"files": {"type": "array", "items": {"type": "string"}},
"depth": {"type": "string", "enum": ["shallow", "standard", "deep"]}
```

Leave `panels` as an array of strings.

- [ ] **Step 2: Extend report schema**

In `reference/report-schema.json`, inside `findings.items.properties`, add:

```json
"source_role": {"type": "string", "enum": ["lens_sweep", "panel_review", "advisor"]},
"advisor_verdict": {"type": "string", "enum": ["CONFIRMED", "REJECTED", "NEEDS_MORE_INFO"]},
"depth": {"type": "string", "enum": ["shallow", "standard", "deep"]}
```

- [ ] **Step 3: Update schema tests**

In `tests/test_schemas.py`, add a test that loads both schemas and asserts the new keys exist:

```python
def test_multi_model_fields_in_schemas():
    import json
    with open("reference/scope-profile-schema.json") as fh:
        scope = json.load(fh)
    assert "depth" in scope["properties"]
    assert "files" in scope["properties"]
    lens_items = scope["properties"]["lenses"]["additionalProperties"]["items"]
    assert "priority" in lens_items["properties"]
    assert "depth_threshold" in lens_items["properties"]

    with open("reference/report-schema.json") as fh:
        report = json.load(fh)
    finding_props = report["properties"]["findings"]["items"]["properties"]
    assert "source_role" in finding_props
    assert "advisor_verdict" in finding_props
    assert "depth" in finding_props
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest tests/test_schemas.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add reference/scope-profile-schema.json reference/report-schema.json tests/test_schemas.py
git commit -m "schema: add depth, source_role, advisor_verdict for multi-model dispatch"
```

---

## Task 3: Implement ModelResolver

**Files:**
- Create: `scripts/model_resolver.py`
- Create: `tests/test_model_resolver.py`

**Interfaces:**
- Consumes: `reference/model-profiles.yml`, CLI flags, environment variables
- Produces: `resolve_model(host, role, cli_overrides=None)` → dict with `model`, `max_context_size`, `max_output_size`

- [ ] **Step 1: Write failing test**

Create `tests/test_model_resolver.py`:

```python
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import model_resolver as mr


class TestModelResolver(unittest.TestCase):
    def test_kimi_defaults(self):
        cfg = mr.resolve_model("kimi", "lens_sweep")
        self.assertEqual(cfg["model"], "kimi-for-coding")
        self.assertEqual(cfg["max_output_size"], 8192)
        self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "k3")

    def test_claude_defaults(self):
        self.assertEqual(mr.resolve_model("claude", "lens_sweep")["model"], "claude-haiku")
        self.assertEqual(mr.resolve_model("claude", "panel_review")["model"], "claude-sonnet")
        self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "claude-opus")

    def test_unknown_host_falls_back(self):
        cfg = mr.resolve_model("unknown", "lens_sweep")
        self.assertEqual(cfg["model"], "kimi-for-coding")

    def test_cli_override(self):
        overrides = {"advisor": {"model": "custom-model"}}
        self.assertEqual(mr.resolve_model("kimi", "advisor", overrides)["model"], "custom-model")

    def test_env_override(self):
        os.environ["PANOPTICON_MODEL_ADVISOR"] = "env-advisor"
        try:
            self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "env-advisor")
        finally:
            del os.environ["PANOPTICON_MODEL_ADVISOR"]

    def test_cli_beats_env(self):
        os.environ["PANOPTICON_MODEL_ADVISOR"] = "env-advisor"
        try:
            self.assertEqual(
                mr.resolve_model("kimi", "advisor", {"advisor": {"model": "cli-advisor"}})["model"],
                "cli-advisor"
            )
        finally:
            del os.environ["PANOPTICON_MODEL_ADVISOR"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_model_resolver.py -v`
Expected: ImportError or failures for missing functions.

- [ ] **Step 3: Implement `scripts/model_resolver.py`**

```python
#!/usr/bin/env python3
"""Resolve reviewer role + host to a concrete model identifier."""
import os
import sys


def _load_profiles():
    """Load model profiles from reference/model-profiles.yml."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        os.pardir, "reference", "model-profiles.yml")
    try:
        import yaml
        with open(path, encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


_PROFILES = None


def _profiles():
    global _PROFILES
    if _PROFILES is None:
        _PROFILES = _load_profiles()
    return _PROFILES


def _hardcoded_fallback(role):
    return {
        "scout": {"model": "kimi-for-coding", "max_context_size": 131072, "max_output_size": 16384},
        "lens_sweep": {"model": "kimi-for-coding", "max_context_size": 131072, "max_output_size": 8192},
        "panel_review": {"model": "kimi-for-coding", "max_context_size": 131072, "max_output_size": 16384},
        "advisor": {"model": "k3", "max_context_size": 524288, "max_output_size": 32768},
    }.get(role, {"model": "kimi-for-coding", "max_context_size": 131072, "max_output_size": 8192})


def _env_override(role):
    """Parse PANOPTICON_MODEL_<ROLE> env var.

    Supports two forms:
    - plain string model id: "k3"
    - JSON object: '{"model":"k3","max_context_size":524288}'
    """
    env_key = "PANOPTICON_MODEL_%s" % role.upper()
    env_value = os.environ.get(env_key)
    if not env_value:
        return None
    env_value = env_value.strip()
    if env_value.startswith("{"):
        try:
            import json
            return json.loads(env_value)
        except ValueError:
            pass
    return {"model": env_value}


def resolve_model(host, role, cli_overrides=None):
    """Resolve a host + role to a model config dict.

    Precedence (highest first):
    1. cli_overrides[role]
    2. PANOPTICON_MODEL_<ROLE> environment variable
    3. host default in reference/model-profiles.yml
    4. hardcoded fallback

    Returns dict with at least {"model": ..., "max_context_size": ..., "max_output_size": ...}
    """
    if cli_overrides and role in cli_overrides:
        override = cli_overrides[role]
        if isinstance(override, dict):
            return override
        return {"model": override}

    env_override = _env_override(role)
    if env_override:
        return env_override

    profiles = _profiles()
    host_defaults = (profiles.get("hosts") or {}).get(host) or {}
    if role in host_defaults:
        cfg = host_defaults[role]
        if isinstance(cfg, dict):
            return cfg
        return {"model": cfg}

    return _hardcoded_fallback(role)


def role_config(role):
    """Return role metadata (description) from profiles."""
    profiles = _profiles()
    return (profiles.get("roles") or {}).get(role) or {}


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "kimi"
    role = sys.argv[2] if len(sys.argv) > 2 else "panel_review"
    print(resolve_model(host, role))
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest tests/test_model_resolver.py -v`
Expected: 6 PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/model_resolver.py tests/test_model_resolver.py
git commit -m "feat(dispatch): add ModelResolver with host/role overrides"
```

---

## Task 4: Update orchestrator to emit group depth

**Files:**
- Modify: `scripts/orchestrator.py`
- Modify: `tests/test_orchestrator.py`

**Interfaces:**
- Consumes: existing `compute_group_panels`, `compute_group_surfaces`
- Produces: `groups` items gain a default `depth` field

- [ ] **Step 1: Update `build_result` in `scripts/orchestrator.py`**

Replace the `groups.append({...})` block in `build_result` with:

```python
for i, c in enumerate(chunks):
    panels = compute_group_panels(c, security_mode)
    depth = _compute_depth(c, panels, security_mode)
    groups.append({
        "name": "%s_%d" % (base, i + 1),
        "files": c,
        "surfaces": compute_group_surfaces(c),
        "panels": panels,
        "depth": depth,
    })
```

Add `_compute_depth` above `build_result`:

```python
def _looks_risky(path):
    """Crude heuristic for risky code surfaces until scout provides them."""
    lowered = path.lower()
    return any(k in lowered for k in ("auth", "login", "password", "payment", "pii", "encrypt", "token", "api"))


def _compute_depth(files, panels, security_mode):
    """Assign shallow/standard/deep based on surfaces, panel mix, and security mode."""
    if security_mode == "redteam":
        return "deep"
    risky_files = any(
        is_architecture_file(f) or is_database_file(f) or _looks_risky(f)
        for f in files
    )
    if risky_files:
        return "standard"
    if any(p in ("security", "redteam", "database") for p in panels):
        return "standard"
    return "shallow"
```

- [ ] **Step 2: Update orchestrator tests**

Add to `tests/test_orchestrator.py`:

```python
class TestDepth(unittest.TestCase):
    def test_style_group_is_shallow(self):
        result = orch.build_result(".", "repo", ".", None, ["docs/readme.md"], [], 15)
        self.assertEqual(result["groups"][0]["depth"], "shallow")

    def test_security_panel_is_standard(self):
        result = orch.build_result(".", "repo", ".", None, ["app/auth.py"], [], 15, security_mode="standard")
        self.assertEqual(result["groups"][0]["depth"], "standard")

    def test_redteam_is_deep(self):
        result = orch.build_result(".", "repo", ".", None, ["app/auth.py"], [], 15, security_mode="redteam")
        self.assertEqual(result["groups"][0]["depth"], "deep")
```

- [ ] **Step 3: Run tests**

Run: `python3 -m pytest tests/test_orchestrator.py -v`
Expected: existing + new tests PASS

- [ ] **Step 4: Commit**

```bash
git add scripts/orchestrator.py tests/test_orchestrator.py
git commit -m "feat(orchestrator): emit panel depth in groups.json"
```

---

## Task 5: Implement DepthPlanner

**Files:**
- Create: `scripts/depth_planner.py`
- Create: `tests/test_depth_planner.py`

**Interfaces:**
- Consumes: `ScopeProfile`-like object + panel name
- Produces: `plan_lenses(profile, panel_name)` → list of lens names to spawn

- [ ] **Step 1: Write failing test**

Create `tests/test_depth_planner.py`:

```python
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import depth_planner as dp


class TestDepthPlanner(unittest.TestCase):
    def _profile(self, depth="standard"):
        return {
            "group": "g1",
            "panels": ["code", "security"],
            "depth": depth,
            "lenses": {
                "code": [
                    {"name": "structure", "spawn": True, "priority": 1, "depth_threshold": "shallow"},
                    {"name": "correctness", "spawn": True, "priority": 2, "depth_threshold": "standard"},
                    {"name": "style", "spawn": True, "priority": 3, "depth_threshold": "shallow"},
                ],
                "security": [
                    {"name": "known_vulns", "spawn": True, "priority": 1, "depth_threshold": "standard"},
                    {"name": "injection", "spawn": True, "priority": 2, "depth_threshold": "standard"},
                    {"name": "novel", "spawn": True, "priority": 3, "depth_threshold": "deep"},
                    {"name": "extra", "spawn": True, "priority": 4, "depth_threshold": "deep"},
                ]
            }
        }

    def test_shallow_spawns_zero_or_one(self):
        planned = dp.plan_lenses(self._profile("shallow"), "code")
        self.assertLessEqual(len(planned), 1)
        self.assertIn("style", planned)

    def test_standard_spawns_up_to_two(self):
        planned = dp.plan_lenses(self._profile("standard"), "code")
        self.assertLessEqual(len(planned), 2)
        self.assertIn("structure", planned)
        self.assertIn("correctness", planned)

    def test_deep_spawns_up_to_three(self):
        planned = dp.plan_lenses(self._profile("deep"), "security")
        self.assertLessEqual(len(planned), 3)
        self.assertIn("known_vulns", planned)
        self.assertIn("injection", planned)
        self.assertIn("novel", planned)
        self.assertNotIn("extra", planned)

    def test_unspawnable_lenses_excluded(self):
        profile = self._profile("deep")
        profile["lenses"]["code"][0]["spawn"] = False
        self.assertEqual(dp.plan_lenses(profile, "code"), ["correctness", "style"])

    def test_panel_not_in_profile_returns_empty(self):
        self.assertEqual(dp.plan_lenses(self._profile("deep"), "architecture"), [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_depth_planner.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement `scripts/depth_planner.py`**

```python
#!/usr/bin/env python3
"""Select which lenses become mechanical agents based on panel depth."""

DEPTH_RANK = {"shallow": 0, "standard": 1, "deep": 2}
DEPTH_LIMIT = {"shallow": 1, "standard": 2, "deep": 3}


def _depth_gte(lens_depth, panel_depth):
    return DEPTH_RANK.get(lens_depth, 0) <= DEPTH_RANK.get(panel_depth, 0)


def plan_lenses(profile, panel_name):
    """Return up to 3 lens names to spawn as mechanical agents for panel_name.

    Selection criteria:
    - panel_name is in profile.panels
    - lens.spawn is True
    - lens.depth_threshold <= profile.depth
    - sorted by priority ascending
    - capped at the depth limit
    """
    depth = profile.get("depth", "standard")
    limit = DEPTH_LIMIT.get(depth, 2)
    if panel_name not in profile.get("panels", []):
        return []
    lenses = profile.get("lenses", {}).get(panel_name, [])
    candidates = []
    for lens in lenses:
        if not lens.get("spawn", False):
            continue
        threshold = lens.get("depth_threshold", "standard")
        if not _depth_gte(threshold, depth):
            continue
        candidates.append((lens.get("priority", 99), lens["name"]))
    candidates.sort()
    return [name for _, name in candidates[:limit]]
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest tests/test_depth_planner.py -v`
Expected: 4 PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/depth_planner.py tests/test_depth_planner.py
git commit -m "feat(dispatch): add DepthPlanner with depth-aware lens caps"
```

---

## Task 6: Implement scripts/dispatch.py

**Files:**
- Create: `scripts/dispatch.py`
- Create: `tests/test_dispatch.py`

**Interfaces:**
- Consumes: `ScopeProfile` JSON, `--host`, `--model-*` overrides
- Produces: `DispatchPlan` JSON list of agent invocations

- [ ] **Step 1: Write failing test**

Create `tests/test_dispatch.py`:

```python
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import dispatch


class TestDispatchPlan(unittest.TestCase):
    def _profile(self, depth="standard"):
        return {
            "group": "test_repo",
            "languages": ["python"],
            "surfaces": ["http_web"],
            "risk": "med",
            "depth": depth,
            "files": ["app.py"],
            "lenses": {
                "security": [
                    {"name": "known_vulns", "spawn": True, "priority": 1, "depth_threshold": "standard"},
                    {"name": "injection", "spawn": True, "priority": 2, "depth_threshold": "standard"},
                    {"name": "novel", "spawn": True, "priority": 3, "depth_threshold": "deep"},
                ]
            },
            "panels": ["security"],
            "tools": [],
            "has_deps": False,
        }

    def test_standard_emits_panel_review_and_two_sweeps(self):
        plan = dispatch.build_plan(self._profile("standard"), host="kimi")
        self.assertEqual(len(plan), 3)
        roles = [p["role"] for p in plan]
        self.assertEqual(roles.count("panel_review"), 1)
        self.assertEqual(roles.count("lens_sweep"), 2)

    def test_deep_emits_panel_review_and_three_sweeps(self):
        plan = dispatch.build_plan(self._profile("deep"), host="kimi")
        self.assertEqual(len(plan), 4)
        roles = [p["role"] for p in plan]
        self.assertEqual(roles.count("panel_review"), 1)
        self.assertEqual(roles.count("lens_sweep"), 3)

    def test_shallow_emits_only_panel_review(self):
        profile = {
            "group": "g1",
            "panels": ["code"],
            "depth": "shallow",
            "files": ["docs/readme.md"],
            "lenses": {
                "code": [
                    {"name": "style", "spawn": True, "priority": 1, "depth_threshold": "shallow"},
                ]
            },
            "tools": [],
            "has_deps": False,
        }
        plan = dispatch.build_plan(profile, host="kimi")
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["role"], "panel_review")

    def test_models_resolved_per_host(self):
        plan = dispatch.build_plan(self._profile("standard"), host="claude")
        advisor = [p for p in plan if p["role"] == "advisor"]
        self.assertEqual(len(advisor), 0)
        panel = [p for p in plan if p["role"] == "panel_review"][0]
        self.assertEqual(panel["model"]["model"], "claude-sonnet")
        self.assertEqual(panel["agent"], "panel-review")
        sweep = [p for p in plan if p["role"] == "lens_sweep"][0]
        self.assertEqual(sweep["agent"], "lens-sweep")

    def test_main_writes_json_plan(self):
        profile = self._profile("standard")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump(profile, fh)
            profile_path = fh.name
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            out_path = fh.name
        try:
            rc = dispatch.main([profile_path, "--host", "kimi", "--out", out_path])
            self.assertEqual(rc, 0)
            with open(out_path) as fh:
                plan = json.load(fh)
            self.assertIsInstance(plan, list)
            self.assertGreaterEqual(len(plan), 3)
        finally:
            os.unlink(profile_path)
            os.unlink(out_path)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_dispatch.py -v`
Expected: ImportError.

- [ ] **Step 3: Implement `scripts/dispatch.py`**

```python
#!/usr/bin/env python3
"""Build a DispatchPlan from a ScopeProfile."""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import depth_planner
import model_resolver


def _detect_host():
    """Best-effort host detection from environment."""
    if os.environ.get("KIMI_CODE_VERSION") or os.environ.get("KIMI_SESSION_ID"):
        return "kimi"
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLAUDE_CODE"):
        return "claude"
    return "kimi"


AGENT_NAME = {
    "scout": "scout",
    "panel_review": "panel-review",
    "lens_sweep": "lens-sweep",
    "advisor": "advisor",
}


def build_plan(scope_profile, host=None, model_overrides=None):
    """Return a DispatchPlan: list of agent invocations.

    Each invocation has:
    - role: lens_sweep | panel_review | advisor
    - agent: Kimi Code custom agent name
    - model: resolved model config dict
    - panel: panel name
    - lens: lens name (for lens_sweep only)
    - files: list of files to review
    - group: group name
    - out_file: where the agent should write findings
    """
    host = host or _detect_host()
    overrides = model_overrides or {}
    group_name = scope_profile.get("group", "unknown")
    files = scope_profile.get("files", [])
    depth = scope_profile.get("depth", "standard")
    plan = []

    for panel_name in scope_profile.get("panels", []):
        spawned = depth_planner.plan_lenses(scope_profile, panel_name)

        # main panel reviewer
        plan.append({
            "role": "panel_review",
            "agent": AGENT_NAME["panel_review"],
            "model": model_resolver.resolve_model(host, "panel_review", overrides),
            "panel": panel_name,
            "lens": None,
            "files": files,
            "group": group_name,
            "depth": depth,
            "out_file": ".panopticon/findings-%s-%s-panel_review.json" % (group_name, panel_name),
        })

        # mechanical lens sweeps
        for lens_name in spawned:
            plan.append({
                "role": "lens_sweep",
                "agent": AGENT_NAME["lens_sweep"],
                "model": model_resolver.resolve_model(host, "lens_sweep", overrides),
                "panel": panel_name,
                "lens": lens_name,
                "files": files,
                "group": group_name,
                "depth": depth,
                "out_file": ".panopticon/findings-%s-%s-lens_sweep-%s.json" % (group_name, panel_name, lens_name),
            })

    return plan


def emit_plan(plan, fh=None):
    fh = fh or sys.stdout
    json.dump(plan, fh, indent=2)
    fh.write("\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="panopticon dispatch planner")
    ap.add_argument("profile", help="Path to ScopeProfile JSON")
    ap.add_argument("--host", default=None, help="Host platform (kimi, claude, openrouter)")
    ap.add_argument("--out", default=None, help="Write DispatchPlan JSON to this file")
    ap.add_argument("--model-lens-sweep", default=None)
    ap.add_argument("--model-panel-review", default=None)
    ap.add_argument("--model-advisor", default=None)
    args = ap.parse_args(argv)

    with open(args.profile, encoding="utf-8") as fh:
        profile = json.load(fh)

    overrides = {}
    if args.model_lens_sweep:
        overrides["lens_sweep"] = args.model_lens_sweep
    if args.model_panel_review:
        overrides["panel_review"] = args.model_panel_review
    if args.model_advisor:
        overrides["advisor"] = args.model_advisor

    plan = build_plan(profile, host=args.host, model_overrides=overrides)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            emit_plan(plan, fh)
    else:
        emit_plan(plan)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest tests/test_dispatch.py -v`
Expected: 5 PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/dispatch.py tests/test_dispatch.py
git commit -m "feat(dispatch): add dispatch planner that emits role-based agent plan"
```

---

## Task 7: Create custom agent files

**Files:**
- Create: `agents/lens-sweep.md`
- Create: `agents/panel-review.md`
- Create: `agents/advisor.md`
- Create: `agents/scout.md`

**Interfaces:**
- Consumes: Kimi Code agent discovery; template placeholders rendered by SKILL.md
- Produces: custom agents dispatched by name in `AgentSwarm`

- [ ] **Step 1: Create `agents/lens-sweep.md`**

```markdown
---
name: lens-sweep
description: Cheap mechanical lens sweep for panopticon; emits narrow, cited findings only
model_preference: secondary
tools:
  - Read
  - Grep
  - Glob
disallowedTools:
  - Bash
  - Edit
  - Write
  - Agent
---

You are the `{lens}` lens sweep for panopticon panel `{panel}` in group `{group}`.
Files: {file_list}
Security mode: {security_mode}
Depth: {depth}

## Your task

Perform a narrow, mechanical review of the listed files **only through the `{lens}` lens**.
Emit findings as raw JSON `{{"findings": [...]}}` to `{out_file}` and return ONLY the path + count.

## Rules

- Findings must cite a rule, pattern, or line of code. Uncited claims are not allowed.
- Keep descriptions short and factual.
- Do not write narrative or general advice.
- Do not perform GitHub writes, repo mutations, or credential mints.

## Finding format

- id: ^[A-Z]{{2,4}}-\d{{3,}}$
- severity: CRITICAL|HIGH|MEDIUM|LOW|INFO
- panel: "{panel}"
- lens: "{lens}"
- category: "{lens}"
- location: {{file, line_start[, line_end, function]}}
- title, description, impact, remediation, references[]
- source_role: "lens_sweep"
- depth: "{depth}"
```

- [ ] **Step 2: Create `agents/panel-review.md`**

```markdown
---
name: panel-review
description: Holistic panopticon panel reviewer covering all non-mechanical lenses
model_preference: primary
tools:
  - Read
  - Grep
  - Glob
  - Bash
disallowedTools:
  - Edit
  - Write
  - Agent
---

You are the `{panel}` reviewer for panopticon group `{group}`.
Files: {file_list}
Security mode: {security_mode}
Depth: {depth}

## Your task

Review the listed files through the `{panel}` panel. Cover all lenses assigned to this panel that are NOT being handled by dedicated lens sweep agents.
Emit findings as raw JSON `{{"findings": [...]}}` to `{out_file}` and return ONLY the path + count.

## Lenses assigned to this panel

{lenses}

## Security checklists

For `security` and `redteam` panels, apply the relevant language-specific sections from `reference/security-checklists.md`.

## Side-effect boundary

Your ONLY action is writing that one findings file. Perform NO GitHub writes, NO repo mutations, NO dispatches, NO credential mints.

## Finding format

- id: ^[A-Z]{{2,4}}-\d{{3,}}$
- severity: CRITICAL|HIGH|MEDIUM|LOW|INFO
- panel: "{panel}"
- category: (lens name or "general")
- location: {{file, line_start[, line_end, function]}}
- title, description, impact, remediation, references[]
- source_role: "panel_review"
- depth: "{depth}"

For `security`/`redteam` CRITICAL/HIGH findings, add `cvss` {{score, vector}} and `exploit_scenario`.
```

- [ ] **Step 3: Create `agents/advisor.md`**

```markdown
---
name: advisor
description: Independent panopticon advisor that verifies tenuous findings
model_preference: primary
tools:
  - Read
  - Grep
  - Glob
disallowedTools:
  - Bash
  - Edit
  - Write
  - Agent
---

You are an independent advisor verifying a single claim produced by another reviewer.

## Claim

{claim_json}

## Code context

{code_context}

## Your task

Decide whether the claim is independently supported by the code and any existing references.
Return ONLY a raw JSON object:

```json
{{"verdict": "CONFIRMED|REJECTED|NEEDS_MORE_INFO", "confidence": "CERTAIN|LIKELY|POSSIBLE", "reasoning": "...", "references": ["..."]}}
```

- CONFIRMED: the claim is clearly supported by the code.
- REJECTED: the claim is not supported by the code.
- NEEDS_MORE_INFO: you cannot determine from the provided context.

Do not invent evidence. If a reference is needed and missing, say so in reasoning.
```

- [ ] **Step 4: Create `agents/scout.md`**

```markdown
---
name: scout
description: Panopticon scout that profiles files and selects depth/lenses
model_preference: secondary
tools:
  - Read
  - Grep
  - Glob
  - Bash
disallowedTools:
  - Edit
  - Write
  - Agent
---

You are the panopticon scout. Read the assigned files and emit a single **ScopeProfile** JSON object conforming to `reference/scope-profile-schema.json`.
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

## Risk

`high` if money_pii/auth/crypto present or a risky surface is untested; `med` for other code surfaces; `low` for docs/markup/style-only changes.

## Panels

Set `panels` to the panels scheduled for this group:
- `code` always
- `test` if tests or testable logic present
- `security` if auth/crypto/money_pii/serialization/external_api/fs/templating/db_sql/http_web present
- `architecture` if any file is repo-scope
- `database` if `db_sql` surface present

When `security_mode` is `redteam`, schedule `redteam` instead of `security`.

## Lenses

Set `lenses` to an object mapping panel name to a list of `{name, spawn, priority, depth_threshold}` objects.
Default lenses:
- code: structure, correctness, style
- test: coverage, test_quality, test_design
- security: known_vulns, injection, novel
- architecture: architecture
- database: database

Set `spawn: true` when the group has ≥5 files or `risk` is `high`; otherwise `spawn: false`.

For each lens, add:
- `priority`: integer rank (lower = higher priority)
- `depth_threshold`: minimum depth (`shallow`, `standard`, `deep`) at which this lens gets its own `lens-sweep` agent

## Depth

Set `depth` for the group to one of `shallow`, `standard`, or `deep`:
- `shallow` — style/docs-only changes with no risky surfaces.
- `standard` — normal code changes or medium-risk surfaces (http_web, db_sql, fs, external_api).
- `deep` — auth, crypto, money_pii, serialization, templating present, or `security_mode` is `redteam`.

## Files

Include the list of files you reviewed in the `files` field.

## Tool selection

If the container layer is in use, recommend scanners in `tools` and set `has_deps` true when a dependency manifest is present.

Return ONLY the ScopeProfile JSON. No prose.
```

- [ ] **Step 5: Remove old `prompts/scout.md` and `prompts/roles/`**

```bash
rm -rf prompts/scout.md prompts/roles/
```

- [ ] **Step 6: Commit**

```bash
git add agents/
git rm -f prompts/scout.md prompts/roles/lens-sweep.md prompts/roles/panel-review.md prompts/roles/advisor.md 2>/dev/null || rm -rf prompts/roles/
git commit -m "feat(agents): add Kimi Code custom agents for scout, lens, panel, advisor"
```

---

## Task 8: Update synthesize.py for advisor triggers

**Files:**
- Modify: `scripts/synthesize.py`
- Create: `tests/test_synthesize_advisor.py`

**Interfaces:**
- Consumes: loaded findings, groups_meta with depth
- Produces: findings with `source_role`, `depth`, and optional `advisor_verdict`

- [ ] **Step 1: Write failing test**

Create `tests/test_synthesize_advisor.py`:

```python
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import synthesize as synth


class TestAdvisorTriggers(unittest.TestCase):
    def test_uncited_high_finding_is_flagged(self):
        f = {
            "id": "SEC-001",
            "title": "Bad thing",
            "severity": "HIGH",
            "confidence": "POSSIBLE",
            "panel": "security",
            "category": "injection",
            "location": {"file": "app.py", "line_start": 10},
            "references": [],
            "source_role": "panel_review",
        }
        flagged = synth.flag_for_advisor([f], depth="standard")
        self.assertEqual(len(flagged), 1)
        self.assertEqual(flagged[0]["id"], "SEC-001")

    def test_cited_high_finding_not_flagged(self):
        f = {
            "id": "SEC-002",
            "title": "Bad thing",
            "severity": "HIGH",
            "confidence": "LIKELY",
            "panel": "security",
            "category": "injection",
            "location": {"file": "app.py", "line_start": 10},
            "references": ["https://cwe.mitre.org/data/definitions/89.html", "https://docs.sqlalchemy.org/"],
            "source_role": "panel_review",
        }
        flagged = synth.flag_for_advisor([f], depth="standard")
        self.assertEqual(len(flagged), 0)

    def test_low_severity_uncited_not_flagged(self):
        f = {
            "id": "COD-001",
            "title": "Style issue",
            "severity": "LOW",
            "confidence": "POSSIBLE",
            "panel": "code",
            "category": "style",
            "location": {"file": "app.py", "line_start": 10},
            "references": [],
            "source_role": "panel_review",
        }
        flagged = synth.flag_for_advisor([f], depth="standard")
        self.assertEqual(len(flagged), 0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_synthesize_advisor.py -v`
Expected: AttributeError for `flag_for_advisor`.

- [ ] **Step 3: Add `flag_for_advisor` and advisor application helpers**

In `scripts/synthesize.py`, after `cross_panel_corroboration`, add:

```python
def flag_for_advisor(findings, depth="standard"):
    """Return findings that need independent advisor review."""
    flagged = []
    for f in findings:
        refs = f.get("references") or []
        confidence = f.get("confidence", "POSSIBLE")
        severity = f.get("severity", "INFO")

        # HIGH/CRITICAL uncited and low confidence
        if (severity in ("HIGH", "CRITICAL")
                and confidence in ("NOTE", "POSSIBLE")
                and not refs):
            flagged.append(f)
            continue

        # HIGH/CRITICAL with fewer than 2 citations
        if severity in ("HIGH", "CRITICAL") and len(refs) < 2:
            flagged.append(f)
            continue

        # Deep mode: any uncited finding in risky panels
        if depth == "deep" and f.get("panel") in ("security", "redteam") and not refs:
            flagged.append(f)
            continue
    return flagged


def apply_advisor_verdict(finding, verdict):
    """Update a finding based on advisor verdict."""
    finding["advisor_verdict"] = verdict.get("verdict")
    if verdict.get("verdict") == "CONFIRMED":
        finding["confidence"] = _bump_confidence(finding.get("confidence"))
        existing = set(finding.get("references") or [])
        for ref in verdict.get("references", []):
            if ref not in existing:
                finding.setdefault("references", []).append(ref)
    elif verdict.get("verdict") == "REJECTED":
        finding["severity"] = "INFO"
        finding["confidence"] = "NOTE"
    # NEEDS_MORE_INFO: leave as-is, just mark verdict
```

- [ ] **Step 4: Wire advisor into `build_report`**

Change the signature of `build_report` to accept optional `advisor_results`:

```python
def build_report(findings, groups_meta, target, fail_on, timestamp, review_type="repo",
                 security_mode="standard", advisor_results=None):
```

After `findings = dedupe(findings)` and before panel grouping, apply advisor results:

```python
    findings = dedupe(findings)
    if advisor_results:
        for finding_id, verdict in advisor_results.items():
            for f in findings:
                if f.get("id") == finding_id:
                    apply_advisor_verdict(f, verdict)
                    break
```

- [ ] **Step 5: Run tests**

Run: `python3 -m pytest tests/test_synthesize_advisor.py tests/test_synthesize.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add scripts/synthesize.py tests/test_synthesize_advisor.py
git commit -m "feat(synthesize): flag uncited claims and apply advisor verdicts"
```

---

## Task 9: Update SKILL.md fan-out step

**Files:**
- Modify: `SKILL.md`

**Interfaces:**
- Consumes: updated pipeline
- Produces: skill instructions that use `scripts/dispatch.py` and role-aware AgentSwarm

- [ ] **Step 1: Update SKILL.md frontmatter**

Replace the frontmatter block with:

```yaml
---
name: panopticon
description: Discovery → scout → fan-out → synthesis code review for Kimi Code. Profiles a target, groups files, dispatches specialized reviewers in parallel, and synthesizes a validated CodeReviewReport with CI gating.
type: prompt
whenToUse: When reviewing code, pull requests, branches, security posture, test quality, architecture, or database surfaces in a codebase
arguments:
  - target
  - mode
  - security
  - out
disableModelInvocation: false
license: MIT
metadata:
  version: "3.0.0"
---
```

- [ ] **Step 2: Replace fan-out step in `SKILL.md`**

Replace step 3 (scout) and step 6 (fan-out) with:

```markdown
3. **Scout** — dispatch the `scout` custom agent (`agents/scout.md`) per group; output `ScopeProfile` to `.panopticon/scout-{group}.json`.
4. **Tool scan** — optional Docker container; SARIF ingested by `scripts/ingest_tools.py`.
5. **Plan dispatch** — run `python3 scripts/dispatch.py <scope-profile.json> --host <host> --out .panopticon/dispatch-plan.json` to produce a `DispatchPlan` of role-based agents.
6. **Fan-out** — `AgentSwarm` dispatching custom agents by name from the plan:
   - `panel-review` agents for holistic panel review
   - `lens-sweep` agents for mechanical lens sweeps
   - Each agent writes its findings file to `.panopticon/findings-{group}-{panel}-{role}-{lens}.json`
7. **Synthesize** — `python3 scripts/synthesize.py` merges findings, tags tenuous claims, and (if any are flagged) spawns `advisor` agents (`agents/advisor.md`) before producing the final `CodeReviewReport`.
```

Update the numbered list so steps remain sequential.

- [ ] **Step 3: Commit**

```bash
git add SKILL.md
git commit -m "docs(skill): add frontmatter and dispatch custom agents by name"
```

---

## Task 10: Add integration test

**Files:**
- Create: `tests/test_dispatch_integration.py`

**Interfaces:**
- Consumes: `orchestrator`, `dispatch`, `depth_planner`, `model_resolver`
- Produces: end-to-end validation of dispatch pipeline

- [ ] **Step 1: Create integration test**

```python
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "scripts"))
import orchestrator as orch
import dispatch


class TestDispatchIntegration(unittest.TestCase):
    def test_style_repo_is_shallow(self):
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, "docs"))
            with open(os.path.join(td, "docs", "readme.md"), "w") as fh:
                fh.write("# hello")
            import subprocess
            subprocess.run(["git", "init", td], capture_output=True)
            result = orch.build_result(td, "repo", ".", None, ["docs/readme.md"], [], 15)
            depth = result["groups"][0].get("depth", "standard")
            plan = dispatch.build_plan({
                "group": "root",
                "languages": [],
                "surfaces": [],
                "risk": "low",
                "depth": depth,
                "files": ["docs/readme.md"],
                "lenses": {"code": [{"name": "style", "spawn": True, "priority": 1, "depth_threshold": "shallow"}]},
                "panels": ["code"],
                "tools": [],
                "has_deps": False,
            }, host="kimi")
            sweep_count = sum(1 for p in plan if p["role"] == "lens_sweep")
            self.assertLessEqual(sweep_count, 1)

    def test_auth_repo_is_deep(self):
        profile = {
            "group": "root",
            "languages": ["python"],
            "surfaces": ["auth"],
            "risk": "high",
            "depth": "deep",
            "files": ["app/auth.py"],
            "lenses": {
                "security": [
                    {"name": "known_vulns", "spawn": True, "priority": 1, "depth_threshold": "standard"},
                    {"name": "injection", "spawn": True, "priority": 2, "depth_threshold": "standard"},
                    {"name": "novel", "spawn": True, "priority": 3, "depth_threshold": "deep"},
                ]
            },
            "panels": ["security"],
            "tools": [],
            "has_deps": False,
        }
        plan = dispatch.build_plan(profile, host="claude")
        models = {p["role"]: p["model"]["model"] for p in plan}
        self.assertEqual(models["lens_sweep"], "claude-haiku")
        self.assertEqual(models["panel_review"], "claude-sonnet")
        self.assertEqual(len([p for p in plan if p["role"] == "lens_sweep"]), 3)
```

- [ ] **Step 2: Run tests**

Run: `python3 -m pytest tests/test_dispatch_integration.py -v`
Expected: 2 PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_dispatch_integration.py
git commit -m "test(dispatch): add end-to-end dispatch integration tests"
```

---

## Task 11: Full test run and final verification

- [ ] **Step 1: Run full test suite**

Run: `python3 -m pytest tests/ -q`
Expected: all tests pass (259 + new tests)

- [ ] **Step 2: Validate schemas still load**

Run: `python3 -m pytest tests/test_schemas.py -v`
Expected: PASS

- [ ] **Step 3: Lint new Python files**

Run: `python3 -m ruff check scripts/model_resolver.py scripts/depth_planner.py scripts/dispatch.py`
Expected: no errors

- [ ] **Step 4: Final commit if any fixes**

```bash
git add -A
git commit -m "fix: address review feedback on multi-model dispatch" || true
```

---

## Spec Coverage Check

| Spec section | Implementing task |
|---|---|
| 4 roles (scout, lens_sweep, panel_review, advisor) | Tasks 5, 6, 7 |
| Custom agent files with tool policies | Task 7 |
| Depth levels (shallow/standard/deep) | Tasks 2, 4, 5, 6 |
| ModelResolver cross-platform with context/output sizes | Tasks 1, 3 |
| Advisor trigger flow | Tasks 2, 8 |
| Pipeline integration (dispatch.py) | Task 6 |
| Schema additions | Task 2 |
| Error handling | Tasks 3, 5, 6, 8 |
| Testing | Tasks 3, 4, 5, 6, 8, 10, 11 |

## Placeholder Scan

- No "TBD", "TODO", or "implement later" remain.
- No vague requirements like "add appropriate error handling".
- Every step includes exact file paths, code, commands, and expected output.

## Type Consistency Check

- `resolve_model(host, role, cli_overrides=None)` → dict used consistently.
- `plan_lenses(profile, panel_name)` → list of strings used in `dispatch.py`.
- `build_plan(scope_profile, host, model_overrides)` → list of plan dicts.
- `flag_for_advisor(findings, depth)` → list of findings.
- `apply_advisor_verdict(finding, verdict)` mutates finding in place.
