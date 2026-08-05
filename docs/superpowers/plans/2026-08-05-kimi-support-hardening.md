# Kimi Support Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update and complete Kimi Code CLI support in panopticon without degrading Claude Code support.

**Architecture:** Keep the existing host-neutral templates as the single source of truth; extend `dispatch.py` and `model_resolver.py` to emit richer Kimi enforcement shells, resolve Kimi-native `primary`/`secondary` model identifiers, and bridge the dispatch plan to Kimi `Agent`/`AgentSwarm` calls. Add a concise `reference/kimi-tools.md` and update `SKILL.md`.

**Tech Stack:** Python 3.11+, pytest, ruff, Kimi Code CLI Markdown+YAML agent format.

## Global Constraints

- Do not degrade Claude Code support.
- Preserve all existing Claude tests and default paths.
- Keep the host-neutral template files (`skill/agents/*.md`) as the single source of truth; registration files remain generated artifacts.
- Avoid a full host abstraction refactor — stay scoped to Kimi polish and concrete helpers.

---

## File map

| File | Responsibility |
|------|----------------|
| `skill/scripts/dispatch.py` | Generates registration shells, builds dispatch plans, and now emits Kimi swarm batches. |
| `skill/scripts/model_resolver.py` | Resolves role + host to a model config dict; returns `primary`/`secondary` for Kimi. |
| `skill/reference/model-profiles.yml` | Declarative model mapping per host; Kimi entries use `primary`/`secondary` with optional `alias`. |
| `skill/SKILL.md` | Orchestration spec; Kimi host-dispatch section is expanded. |
| `skill/reference/kimi-tools.md` | Concise Kimi user reference. |
| `tests/test_dispatch.py` | Tests for dispatch plan, agent emission, and swarm helper. |
| `tests/test_model_resolver.py` | Tests for model resolution per host. |

---

### Task 1: Add default Kimi agents directory

**Files:**
- Modify: `skill/scripts/dispatch.py`
- Test: `tests/test_dispatch.py`

**Interfaces:**
- Consumes: existing `CLAUDE_AGENTS_DIR` constant and `--emit-host-agents` CLI argument.
- Produces: new `KIMI_AGENTS_DIR` constant; `main()` defaults `--emit-host-agents kimi` to it.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_dispatch.py`:

```python
    def test_emit_host_agents_kimi_defaults_to_kimi_code_agents_dir(self):
        with tempfile.TemporaryDirectory() as d:
            original = dispatch.KIMI_AGENTS_DIR
            try:
                dispatch.KIMI_AGENTS_DIR = d
                rc = dispatch.main(["--emit-host-agents", "kimi"])
                self.assertEqual(rc, 0)
                for role in ["scout", "panel-review", "lens-sweep", "advisor"]:
                    self.assertTrue(
                        os.path.isfile(os.path.join(d, f"panopticon-{role}.md"))
                    )
            finally:
                dispatch.KIMI_AGENTS_DIR = original
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python -m pytest tests/test_dispatch.py::TestDispatchPlan::test_emit_host_agents_kimi_defaults_to_kimi_code_agents_dir -v
```

Expected: FAIL with `AttributeError: module 'dispatch' has no attribute 'KIMI_AGENTS_DIR'`.

- [ ] **Step 3: Implement the change**

In `skill/scripts/dispatch.py`, after `CLAUDE_AGENTS_DIR`:

```python
KIMI_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".kimi-code", "agents")
```

Update `_registration_dir()`:

```python
def _registration_dir(host, agents_dir):
    """Explicit dir wins; claude defaults to the user-level agents dir; kimi
    defaults to ~/.kimi-code/agents; any other host has no default."""
    if agents_dir:
        return agents_dir
    if host == "claude":
        return CLAUDE_AGENTS_DIR
    if host == "kimi":
        return KIMI_AGENTS_DIR
    return None
```

Update `main()`:

```python
    if args.emit_host_agents:
        out_dir = args.out
        if not out_dir:
            out_dir = CLAUDE_AGENTS_DIR if args.emit_host_agents == "claude" else KIMI_AGENTS_DIR
        if not out_dir:
            print("dispatch: --emit-host-agents kimi requires --out DIR", file=sys.stderr)
            return 2
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_dispatch.py::TestDispatchPlan::test_emit_host_agents_kimi_defaults_to_kimi_code_agents_dir -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skill/scripts/dispatch.py tests/test_dispatch.py
git commit -m "feat(dispatch): default Kimi agents dir to ~/.kimi-code/agents"
```

---

### Task 2: Enrich emitted Kimi agent files

**Files:**
- Modify: `skill/scripts/dispatch.py`
- Test: `tests/test_dispatch.py`

**Interfaces:**
- Consumes: `emit_host_agents()` template frontmatter (`description`, `tool_policy`).
- Produces: Kimi registration files now include `whenToUse`, `override: false`, and `model_preference`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_dispatch.py`:

```python
    def test_kimi_agent_file_includes_model_preference_and_when_to_use(self):
        with tempfile.TemporaryDirectory() as d:
            paths = dispatch.emit_host_agents("kimi", d)
            self.assertEqual(len(paths), 4)
            for p in paths:
                with open(p, encoding="utf-8") as fh:
                    content = fh.read()
                self.assertIn("whenToUse:", content)
                self.assertIn("override: false", content)
                self.assertIn("model_preference:", content)

            # role-specific preferences
            scout = os.path.join(d, "panopticon-scout.md")
            advisor = os.path.join(d, "panopticon-advisor.md")
            with open(scout, encoding="utf-8") as fh:
                self.assertIn("model_preference: primary", fh.read())
            with open(advisor, encoding="utf-8") as fh:
                self.assertIn("model_preference: secondary", fh.read())
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python -m pytest tests/test_dispatch.py::TestDispatchPlan::test_kimi_agent_file_includes_model_preference_and_when_to_use -v
```

Expected: FAIL on missing `model_preference:`.

- [ ] **Step 3: Implement the change**

In `skill/scripts/dispatch.py`, inside `emit_host_agents()`, replace the Kimi frontmatter branch with:

```python
        if host == "claude":
            model = EMIT_MODEL_POLICY.get("claude", {}).get(role)
            fm = ["---", "name: %s" % agent,
                  "description: %s" % meta["description"],
                  "tools: %s" % ", ".join(tp["allowed"])]
            if model:
                fm.append("model: %s" % model)
            fm.append("---")
        else:
            preference = "secondary" if role in ("panel_review", "advisor") else "primary"
            fm = (["---", "name: %s" % agent,
                   "description: %s" % meta["description"],
                   "whenToUse: %s" % meta["description"],
                   "override: false",
                   "model_preference: %s" % preference,
                   "tools:"]
                  + ["  - %s" % t for t in tp["allowed"]]
                  + ["disallowedTools:"]
                  + ["  - %s" % t for t in tp["forbidden"]]
                  + ["---"])
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_dispatch.py::TestDispatchPlan::test_kimi_agent_file_includes_model_preference_and_when_to_use -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skill/scripts/dispatch.py tests/test_dispatch.py
git commit -m "feat(dispatch): richer Kimi enforcement-shell frontmatter"
```

---

### Task 3: Resolve Kimi-native primary/secondary model identifiers

**Files:**
- Modify: `skill/scripts/model_resolver.py`
- Modify: `skill/reference/model-profiles.yml`
- Test: `tests/test_model_resolver.py`

**Interfaces:**
- Consumes: `model-profiles.yml` host entries.
- Produces: `resolve_model("kimi", role)` returns `{"model": "primary" | "secondary", "alias": "...", ...}`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_model_resolver.py` (create if it does not exist):

```python
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import model_resolver


class TestModelResolver(unittest.TestCase):
    def test_kimi_roles_resolve_to_primary_secondary(self):
        self.assertEqual(model_resolver.resolve_model("kimi", "scout")["model"], "primary")
        self.assertEqual(model_resolver.resolve_model("kimi", "lens_sweep")["model"], "primary")
        self.assertEqual(model_resolver.resolve_model("kimi", "panel_review")["model"], "secondary")
        self.assertEqual(model_resolver.resolve_model("kimi", "advisor")["model"], "secondary")

    def test_claude_roles_preserve_concrete_models(self):
        self.assertEqual(model_resolver.resolve_model("claude", "scout")["model"], "haiku")
        self.assertEqual(model_resolver.resolve_model("claude", "panel_review")["model"], "sonnet")
        self.assertEqual(model_resolver.resolve_model("claude", "advisor")["model"], "opus")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python -m pytest tests/test_model_resolver.py -v
```

Expected: FAIL on `AssertionError: 'kimi-for-coding' != 'primary'`.

- [ ] **Step 3: Implement the change**

In `skill/scripts/model_resolver.py`, update `_KIMI_FALLBACK`:

```python
_KIMI_FALLBACK = {
    "scout": {"model": "primary", "alias": "kimi-for-coding",
              "max_context_size": 131072, "max_output_size": 16384},
    "lens_sweep": {"model": "primary", "alias": "kimi-for-coding",
                   "max_context_size": 131072, "max_output_size": 8192},
    "panel_review": {"model": "secondary", "alias": "k3",
                     "max_context_size": 131072, "max_output_size": 16384},
    "advisor": {"model": "secondary", "alias": "k3",
                "max_context_size": 524288, "max_output_size": 32768},
}
```

In `skill/reference/model-profiles.yml`, update the `kimi` host block:

```yaml
  kimi:
    scout:
      model: primary
      alias: kimi-for-coding
      max_context_size: 131072
      max_output_size: 16384
    lens_sweep:
      model: primary
      alias: kimi-for-coding
      max_context_size: 131072
      max_output_size: 8192
    panel_review:
      model: secondary
      alias: k3
      max_context_size: 131072
      max_output_size: 16384
    advisor:
      model: secondary
      alias: k3
      max_context_size: 524288
      max_output_size: 32768
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_model_resolver.py -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skill/scripts/model_resolver.py skill/reference/model-profiles.yml tests/test_model_resolver.py
git commit -m "feat(model_resolver): Kimi roles resolve to primary/secondary"
```

---

### Task 4: Add host-detection fallback warning

**Files:**
- Modify: `skill/scripts/dispatch.py`
- Test: `tests/test_dispatch.py`

**Interfaces:**
- Consumes: `_detect_host()` env-var sniffing.
- Produces: stderr warning when host is inferred from environment.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_dispatch.py`:

```python
    def test_detect_host_warns_when_inferred_from_env(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            with mock.patch.dict(os.environ, {"KIMI_CODE_VERSION": "1.0"}, clear=False):
                host = dispatch._detect_host()
        self.assertEqual(host, "kimi")
        self.assertIn("WARNING", err.getvalue())
        self.assertIn("--host", err.getvalue())
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python -m pytest tests/test_dispatch.py::TestDispatchPlan::test_detect_host_warns_when_inferred_from_env -v
```

Expected: FAIL on missing warning.

- [ ] **Step 3: Implement the change**

In `skill/scripts/dispatch.py`, update `_detect_host()`:

```python
def _detect_host():
    """Best-effort host detection from environment.

    Fallback only — the orchestrating agent should pass --host explicitly.
    """
    warning = "WARNING: host detected from environment; pass --host explicitly for stable behavior"
    if os.environ.get("KIMI_CODE_VERSION") or os.environ.get("KIMI_SESSION_ID"):
        print(warning, file=sys.stderr)
        return "kimi"
    if os.environ.get("CLAUDECODE") or any(
            k.startswith("CLAUDE_CODE_") for k in os.environ):
        print(warning, file=sys.stderr)
        return "claude"
    return "generic"
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_dispatch.py::TestDispatchPlan::test_detect_host_warns_when_inferred_from_env -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skill/scripts/dispatch.py tests/test_dispatch.py
git commit -m "feat(dispatch): warn when host is inferred from environment"
```

---

### Task 5: Add --emit-kimi-swarm helper

**Files:**
- Modify: `skill/scripts/dispatch.py`
- Test: `tests/test_dispatch.py`

**Interfaces:**
- Consumes: a dispatch plan JSON list produced by `build_plan()`.
- Produces: a Kimi swarm manifest JSON with `Agent` singletons and `AgentSwarm` batches.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_dispatch.py`:

```python
    def test_emit_kimi_swarm_groups_entries_by_subagent_type(self):
        plan = [
            {
                "role": "panel_review",
                "agent": "panopticon-panel-review",
                "enforced": True,
                "model": {"model": "secondary"},
                "prompt": "panel prompt 1",
                "out_file": ".panopticon/findings-g-security-panel_review.json",
            },
            {
                "role": "panel_review",
                "agent": "panopticon-panel-review",
                "enforced": True,
                "model": {"model": "secondary"},
                "prompt": "panel prompt 2",
                "out_file": ".panopticon/findings-g-code-panel_review.json",
            },
            {
                "role": "lens_sweep",
                "agent": "lens-sweep",
                "enforced": False,
                "model": {"model": "primary"},
                "prompt": "lens prompt",
                "out_file": ".panopticon/findings-g-security-lens_sweep-injection.json",
            },
        ]
        swarm = dispatch.emit_kimi_swarm(plan)
        batches = swarm["batches"]
        self.assertEqual(len(batches), 2)

        swarm_batches = [b for b in batches if b.get("tool") == "AgentSwarm"]
        agent_batches = [b for b in batches if b.get("tool") == "Agent"]
        self.assertEqual(len(swarm_batches), 1)
        self.assertEqual(len(agent_batches), 1)

        panel_batch = swarm_batches[0]
        self.assertEqual(panel_batch["subagent_type"], "panopticon-panel-review")
        self.assertEqual(panel_batch["model"], "secondary")
        self.assertEqual(panel_batch["prompt_template"], "{{item}}")
        self.assertEqual(len(panel_batch["items"]), 2)
        self.assertEqual(panel_batch["items"][0], "panel prompt 1")

        lens_batch = agent_batches[0]
        self.assertEqual(lens_batch["subagent_type"], "explore")
        self.assertEqual(lens_batch["model"], "primary")
        self.assertEqual(lens_batch["prompt"], "lens prompt")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
python -m pytest tests/test_dispatch.py::TestDispatchPlan::test_emit_kimi_swarm_groups_entries_by_subagent_type -v
```

Expected: FAIL with `AttributeError: module 'dispatch' has no attribute 'emit_kimi_swarm'`.

- [ ] **Step 3: Implement the change**

In `skill/scripts/dispatch.py`, add:

```python
_KIMI_UNENFORCED_PROFILE = {
    "panel_review": "coder",
    "lens_sweep": "explore",
    "scout": "explore",
    "advisor": "plan",
}


def _kimi_subagent_type(entry):
    """Map a plan entry to a Kimi subagent_type.

    Registered/enforced entries use the panopticon-* shell. Unenforced entries
    fall back to a built-in Kimi profile so the dispatch is always valid.
    """
    if entry.get("enforced"):
        return entry.get("agent")
    return _KIMI_UNENFORCED_PROFILE.get(entry.get("role"), "coder")


def _swarm_description(entry):
    parts = [entry.get("role", "review")]
    panel = entry.get("panel")
    lens = entry.get("lens")
    group = entry.get("group", "unknown")
    if panel:
        parts.append(panel)
    if lens:
        parts.append(lens)
    parts.append("for group %s" % group)
    return " ".join(parts)


def emit_kimi_swarm(plan):
    """Convert a DispatchPlan into Kimi Agent/AgentSwarm batches.

    Entries with the same (subagent_type, model) are batched via AgentSwarm;
    singletons become Agent calls. Each entry's fully rendered prompt is
    passed as the task string, using AgentSwarm's {{item}} placeholder.
    """
    grouped = {}
    for entry in plan:
        agent = _kimi_subagent_type(entry)
        model = (entry.get("model") or {}).get("model")
        grouped.setdefault((agent, model), []).append(entry)

    batches = []
    for (agent, model), entries in grouped.items():
        if len(entries) == 1:
            entry = entries[0]
            batches.append({
                "tool": "Agent",
                "subagent_type": agent,
                "model": model,
                "description": _swarm_description(entry),
                "prompt": entry.get("prompt", ""),
            })
        else:
            batches.append({
                "tool": "AgentSwarm",
                "subagent_type": agent,
                "model": model,
                "description": _swarm_description(entries[0]) + " (batch)",
                "prompt_template": "{{item}}",
                "items": [e.get("prompt", "") for e in entries],
            })
    return {"batches": batches}
```

Add the CLI argument in `main()`:

```python
    ap.add_argument("--emit-kimi-swarm", metavar="PLAN", default=None,
                    help="Read a DispatchPlan JSON and emit a Kimi Agent/AgentSwarm manifest to --out")
```

And wire it before the profile handling:

```python
    if args.emit_kimi_swarm:
        if not args.out:
            print("dispatch: --emit-kimi-swarm requires --out", file=sys.stderr)
            return 2
        try:
            with open(args.emit_kimi_swarm, encoding="utf-8") as fh:
                plan = json.load(fh)
        except (OSError, ValueError) as e:
            print("dispatch: cannot read plan %s: %s" % (args.emit_kimi_swarm, e), file=sys.stderr)
            return 1
        swarm = emit_kimi_swarm(plan)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(swarm, fh, indent=2)
            fh.write("\n")
        print("wrote Kimi swarm manifest (%d batch(es)) -> %s" % (len(swarm["batches"]), args.out))
        return 0
```

- [ ] **Step 4: Run test to verify it passes**

```bash
python -m pytest tests/test_dispatch.py::TestDispatchPlan::test_emit_kimi_swarm_groups_entries_by_subagent_type -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add skill/scripts/dispatch.py tests/test_dispatch.py
git commit -m "feat(dispatch): add --emit-kimi-swarm helper"
```

---

### Task 6: Rewrite SKILL.md Kimi host-dispatch section

**Files:**
- Modify: `skill/SKILL.md`

**Interfaces:**
- Consumes: changes from Tasks 1–5.
- Produces: accurate, expanded Kimi instructions in the skill spec.

- [ ] **Step 1: Replace the Kimi paragraph**

Locate this block in `skill/SKILL.md`:

```markdown
- **Kimi Code** — AgentSwarm raw-prompt dispatch (`prompt_template`/`items`);
  select an appropriate profile via `subagent_type`; model overrides are
  experimental-flag-gated. When `entry.enforced` is true, dispatch via the
  registered `panopticon-*` profile (`subagent_type`) instead of raw-prompt —
  raw-prompt dispatch does not honor the shell.
```

Replace it with:

```markdown
- **Kimi Code** — AgentSwarm raw-prompt dispatch (`prompt_template`/`items`)
  or per-entry `Agent` dispatch. Model selection is driven by the registered
  agent file's `model_preference` (`primary` for `scout`/`lens_sweep`,
  `secondary` for `panel_review`/`advisor`); per-dispatch `model` overrides
  require `KIMI_CODE_EXPERIMENTAL_SECONDARY_MODEL=1` or the master
  experimental flag.

  1. Register the enforcement shells once (fresh session required after):
     ```bash
     python3 skill/scripts/dispatch.py --emit-host-agents kimi
     # or explicit:
     python3 skill/scripts/dispatch.py --emit-host-agents kimi --out ~/.kimi-code/agents
     ```
  2. Build the dispatch plan with `--host kimi`.
  3. Fan out: for each plan entry, dispatch via the `Agent` tool with
     `subagent_type: entry.agent` and `prompt: entry.prompt`. To batch,
     generate a Kimi swarm manifest:
     ```bash
     python3 skill/scripts/dispatch.py --emit-kimi-swarm .panopticon/dispatch-plan.json --out .panopticon/kimi-swarm.json
     ```
     Then invoke each batch in the manifest. When `entry.enforced` is true,
     dispatch via the registered `panopticon-*` profile so tool restrictions
     are host-enforced; raw-prompt dispatch does not honor the shell.
  4. Verification phase: render advisors with `--render-advisor` and dispatch
     them the same way as panels/lenses.
```

- [ ] **Step 2: Verify the Markdown renders**

```bash
python -c "import pathlib; print(pathlib.Path('skill/SKILL.md').read_text()[:500])"
```

Expected: the updated Kimi subsection is present in the output.

- [ ] **Step 3: Commit**

```bash
git add skill/SKILL.md
git commit -m "docs(SKILL): expand Kimi host-dispatch instructions"
```

---

### Task 7: Create reference/kimi-tools.md

**Files:**
- Create: `skill/reference/kimi-tools.md`

**Interfaces:**
- Consumes: changes from Tasks 1–5.
- Produces: concise Kimi user reference.

- [ ] **Step 1: Create the file**

Write `skill/reference/kimi-tools.md`:

```markdown
# Kimi Code CLI Quick Reference for Panopticon

## Install the skill

Symlink the installable skill surface into Kimi's skills directory:

```bash
ln -s "$(pwd)/skill" ~/.kimi-code/skills/panopticon
```

## Register the enforcement shells

Kimi supports per-agent tool restrictions only through registered custom-agent
files, not per-dispatch parameters. Generate them once:

```bash
python3 skill/scripts/dispatch.py --emit-host-agents kimi
```

This writes `panopticon-scout.md`, `panopticon-panel-review.md`,
`panopticon-lens-sweep.md`, and `panopticon-advisor.md` to
`~/.kimi-code/agents/`. Start a fresh Kimi session after registration so the
new agent types are discoverable.

## Run a review

Interactive:

```bash
kimi /panopticon --mode repo
```

Manual pipeline:

```bash
# 1. discovery
python3 skill/scripts/orchestrator.py --repo-scan --repo . --out .panopticon/groups.json

# 2. scout each group (dispatched by orchestrating agent)
#    see SKILL.md "Host dispatch" for subagent instructions

# 3. plan
python3 skill/scripts/dispatch.py .panopticon/scout-<group>.json --host kimi --out .panopticon/dispatch-plan.json

# 4. fan out (or generate a Kimi swarm manifest)
python3 skill/scripts/dispatch.py --emit-kimi-swarm .panopticon/dispatch-plan.json --out .panopticon/kimi-swarm.json

# 5. synthesis
python3 skill/scripts/synthesize.py --emit-verify-queue .panopticon/findings-*.json

# 6. verify (advisors)
python3 skill/scripts/dispatch.py --render-advisor .panopticon/verify-queue.json --out .panopticon/advisor-prompts
# dispatch each .panopticon/advisor-prompts/*.md as panopticon-advisor

# 7. final report
python3 skill/scripts/synthesize.py --verdicts-dir .panopticon/verdicts .panopticon/findings-*.json
```

## Model selection

Registered agent files set `model_preference`:

| Role | Preference |
|------|------------|
| `scout` | `primary` |
| `lens_sweep` | `primary` |
| `panel_review` | `secondary` |
| `advisor` | `secondary` |

To override per dispatch, enable the secondary-model experiment:

```bash
KIMI_CODE_EXPERIMENTAL_SECONDARY_MODEL=1 kimi /panopticon --mode repo
```

## Troubleshooting

- **"custom agents not found"** — re-run `--emit-host-agents kimi` and start a
  fresh Kimi session.
- **"model override ignored"** — per-dispatch `model` requires the
  secondary-model experiment flag.
- **Host inferred from environment** — pass `--host kimi` explicitly to
  `dispatch.py` for stable behavior.
```

- [ ] **Step 2: Commit**

```bash
git add skill/reference/kimi-tools.md
git commit -m "docs(reference): add Kimi Code CLI quick reference"
```

---

### Task 8: Full verification

**Files:**
- All modified files.

**Interfaces:**
- Consumes: Tasks 1–7.
- Produces: passing test suite, clean ruff, and a local smoke test of generated Kimi agents.

- [ ] **Step 1: Run the full test suite**

```bash
python -m pytest tests/ -q
```

Expected: all tests pass (existing 627+ new tests).

- [ ] **Step 2: Run the linter**

```bash
python -m ruff check skill/scripts/ tests/
```

Expected: `All checks passed!`

- [ ] **Step 3: Smoke-test generated Kimi agents**

```bash
python3 skill/scripts/dispatch.py --emit-host-agents kimi --out /tmp/panopticon-kimi-agents
ls /tmp/panopticon-kimi-agents
head -20 /tmp/panopticon-kimi-agents/panopticon-panel-review.md
```

Expected: four `.md` files exist; the panel-review file contains `name:`, `description:`, `whenToUse:`, `override: false`, `model_preference: secondary`, `tools:`, and `disallowedTools:`.

- [ ] **Step 4: Smoke-test --emit-kimi-swarm**

```bash
echo '[{"role":"panel_review","agent":"panopticon-panel-review","enforced":true,"model":{"model":"secondary"},"prompt":"p1","out_file":"f1"}]' > /tmp/plan.json
python3 skill/scripts/dispatch.py --emit-kimi-swarm /tmp/plan.json --out /tmp/swarm.json
cat /tmp/swarm.json
```

Expected: a JSON file with `batches` containing one `Agent` entry using `subagent_type: panopticon-panel-review`.

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "test(kimi): full verification suite for Kimi support hardening" || true
```

---

## Spec coverage check

| Spec section | Implementing task |
|--------------|-------------------|
| Section 1: default Kimi agents dir | Task 1 |
| Section 2: richer Kimi agent files | Task 2 |
| Section 3: Kimi-native model identifiers | Task 3 |
| Section 4: dispatch plan → Kimi swarm helper | Task 5 |
| Section 5: reliable host detection | Task 4 |
| Section 6: SKILL.md Kimi rewrite | Task 6 |
| Section 7: Kimi quick-reference doc | Task 7 |
| Section 8: testing | Tasks 1–5, 8 |
| Section 9: migration/rollout | Task 8 |

## Placeholder scan

No placeholders found. Every step contains exact file paths, exact commands, and expected outputs.

## Type consistency check

- `resolve_model("kimi", role)` returns dict with `model` set to `"primary"` or `"secondary"` — consistent across Tasks 3 and 5.
- `emit_kimi_swarm(plan)` consumes the dispatch-plan list shape produced by `build_plan()` and returns `{"batches": [...]}` — consistent with Task 5 test assertions.
- `_kimi_subagent_type(entry)` maps enforced entries to `entry["agent"]` and unenforced entries to valid Kimi built-in profiles — consistent with the spec's fallback mapping.
- `KIMI_AGENTS_DIR` is used both as a module constant and patched in tests — consistent.

---

## Implementation notes (post-review, 2026-08-05)

Recorded after a panopticon review of the shipped branch, so this plan stays
usable as an audit trail rather than describing code that does not exist.

**Test names and classes diverged from the plan.** The pytest node ids in
Tasks 1 and 2 name `TestDispatchPlan`; the tests actually landed in
`TestEmitHostAgents` and the new `TestKimiDefaultAgentsDir`, and two of the
prescribed names were never used. Run the suite by file, not by the node ids
below, or see the design spec's Section 8, which now indexes the tests as
shipped.

**Changes made after review, not present in the task list above:**

1. `emit_kimi_swarm()` now emits `routing` per item (`out_file`, `role`,
   `panel`, `lens`, `group`). Batches group by `(subagent_type, model)` and can
   span panels and groups, so `items[]` alone could not tell the orchestrator
   which result belonged to which `out_file` — the pipeline's core contract.
2. `emit_kimi_swarm()` re-verifies `enforced` against the live registration
   directory (`--agents-dir`), instead of trusting the snapshot in a persisted
   plan file that a later invocation re-reads.
3. `resolve_model()` normalizes Kimi results to the `primary`/`secondary`
   dispatch contract. Every override path could previously inject a concrete
   alias — and `k3` was `panel_review`'s own alias before this change, making
   it the likely operator mistake. Known aliases map back to their tier; an
   unknown value warns and falls back.
4. `emit_host_agents()` reads the Kimi `model_preference` from
   `model_resolver.registration_model()` instead of an inline conditional, so
   the role→tier policy has one source. `registration_model()` is deliberately
   override-free: persisted registration files must never inherit a one-run
   `PANOPTICON_MODEL_*` override.
5. `--emit-kimi-swarm` validates the loaded plan's shape and fails with the
   module's standard `dispatch: <message>` convention rather than a traceback.
6. SKILL.md documents the unenforced-entry `subagent_type` fallback (the
   default state until registration has run), names
   `KIMI_CODE_EXPERIMENTAL_FLAG=1`, and uses the file's `scripts/...` path
   convention.
