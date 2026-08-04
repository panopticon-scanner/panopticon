# Tool-Policy Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make reviewer tool policy host-enforced where possible (generated registered agents), least-privilege everywhere, with the run's posture recorded in the audit artifact.

**Architecture:** All four roles converge on read-only/return-JSON contracts. `dispatch.py` gains `--emit-host-agents` (generates enforcement-shell agent files from the host-neutral templates) and per-role registration detection that stamps `enforced` on plan entries. Synthesize derives `meta.tool_policy_mode` from the plan files. SKILL.md dispatches by `subagent_type` when enforced and adds a clean-tree check.

**Tech Stack:** Python 3 stdlib only in `skill/scripts/`, pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-08-03-tool-policy-enforcement-design.md` — read it first.

## Global Constraints

- Python stdlib only in `skill/scripts/`.
- Role contract (all four roles): `allowed: [Read, Grep, Glob]`, `forbidden: [Bash, Edit, Write, Agent]`; reviewers RETURN JSON; the orchestrator writes every artifact.
- Registered agent files are **enforcement shells**: frontmatter carries name/description/tools/model; body is a short charter; the rendered prompt still arrives as the task message. Registration never changes what an agent is asked to do.
- Registration detection is **per role**: entry enforced iff `panopticon-<role-file-stem>.md` exists in the agents dir. Partial registration → `mixed`.
- Fallback posture: proceed-and-record. Unregistered → advisory, exactly today's behavior; never hard-fail.
- `meta.tool_policy_mode` enum: `enforced` | `advisory` | `mixed`. No plan files → `advisory`.
- Version bump to **4.2.0** in exactly three code locations (SKILL.md `metadata.version`; `synthesize.py` build_report `"version"`, currently line 541; `evidence.py` write_verify_queue `"version"`, currently line 126) plus the tests pinning those outputs. Fixture inputs stay untouched.
- Emitter fail-fast on template errors (ValueError naming the template); idempotent (unchanged templates → byte-identical files).
- Run `python3 -m pytest tests/ -q` and `python3 -m ruff check skill/scripts/ tests/` before every commit.

---

### Task 1: Least-privilege role contracts (templates + SKILL.md + goldens)

**Files:**
- Modify: `skill/agents/panel-review.md` (frontmatter + one task line), `skill/agents/scout.md` (frontmatter only)
- Modify: `skill/SKILL.md` (steps 3 and 6)
- Modify: `tests/test_agent_templates.py` (tool-policy expectations)
- Modify: `tests/test_dispatch.py` + `tests/goldens/*.rendered.txt` (regenerate)
- Test: `tests/test_skill_md.py` (pin the uniform contract)

**Interfaces:**
- Consumes: nothing new.
- Produces: every template's `tool_policy` == `{"allowed": ["Read", "Grep", "Glob"], "forbidden": ["Bash", "Edit", "Write", "Agent"]}` — Task 2's emitter relies on these exact values.

- [ ] **Step 1: Write the failing tests**

In `tests/test_agent_templates.py`, REPLACE the body of `test_tool_policy_values_preserved_this_round` with a uniform check and rename it:

```python
    def test_tool_policy_uniform_least_privilege(self):
        # Round 3a: every role is read-only; reviewers return JSON and the
        # orchestrator writes all artifacts.
        for role_file in ROLES:
            meta, _ = dispatch.load_template(role_file)
            self.assertEqual(meta["tool_policy"]["allowed"],
                             ["Read", "Grep", "Glob"], role_file)
            self.assertEqual(meta["tool_policy"]["forbidden"],
                             ["Bash", "Edit", "Write", "Agent"], role_file)
```

Append to `tests/test_skill_md.py` (inside `TestSkillMd`):

```python
    def test_uniform_return_json_contract(self):
        self.assertIn("every reviewer RETURNS its JSON", self.text)
        self.assertNotIn("their tool policy allows Bash", self.text)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_agent_templates.py tests/test_skill_md.py -v`
Expected: the new/changed tests FAIL (scout/panel still allow Bash; SKILL.md still has the panel-writes special case).

- [ ] **Step 3: Edit the two templates**

`skill/agents/scout.md` frontmatter tool_policy becomes:

```yaml
tool_policy:
  allowed: [Read, Grep, Glob]
  forbidden: [Bash, Edit, Write, Agent]
```

`skill/agents/panel-review.md`: same frontmatter change, AND replace the task line
`Emit findings as raw JSON `{"findings": [...]}` to `{out_file}` and return ONLY the path + count.`
with:
`Return ONLY a raw JSON object `{"findings": [...]}` as your final message — you cannot write files; the orchestrator writes your findings to `{out_file}`.`

- [ ] **Step 4: Edit `skill/SKILL.md`**

Step 3: replace `output `ScopeProfile` to `.panopticon/scout-{group}.json`.` with `the scout RETURNS the ScopeProfile JSON; the orchestrator writes it to `.panopticon/scout-{group}.json`.`

Step 6: replace the sentence block

```
`panel_review` reviewers write their own findings file to
   the entry's `out_file` (their tool policy allows Bash); `lens_sweep`
   reviewers RETURN the findings JSON and the orchestrator writes it to the
   entry's `out_file` (their tool policy is read-only). `panel_review`
   filenames omit `{lens}`.
```

with:

```
Every reviewer role is read-only: every reviewer RETURNS its JSON as the
   final message and the orchestrator writes it to the entry's `out_file`.
   `panel_review` filenames omit `{lens}`.
```

- [ ] **Step 5: Regenerate goldens**

```bash
python3 - <<'EOF'
import os, sys
sys.path.insert(0, os.path.join("skill", "scripts"))
import dispatch
mapping = {"panel": "security", "group": "g1", "file_list": "a.py, b.py",
           "security_mode": "standard", "depth": "standard",
           "lenses": "- known_vulns\n- novel", "lens": "injection"}
out_files = {"panel-review.md": ".panopticon/findings-g1-security-panel_review.json",
             "lens-sweep.md": ".panopticon/findings-g1-security-lens_sweep-injection.json",
             "scout.md": ".panopticon/scout-g1.json"}
for role, of in out_files.items():
    open("tests/goldens/%s.rendered.txt" % role[:-3], "w").write(
        dispatch.render_prompt(role, dict(mapping, out_file=of)))
    print("regenerated", role)
EOF
```

Eyeball each golden: frontmatter gone, tool-policy line last and now reads `Your only tools are Read, Grep, Glob.` for ALL roles, panel-review body carries the return-JSON sentence.

- [ ] **Step 6: Full suite, ruff, commit**

Run: `python3 -m pytest tests/ -q && python3 -m ruff check skill/scripts/ tests/`
Expected: all PASS (dogfood-era tests do not pin the old panel sentence; if any test fails on the old tool lists, update it to the uniform values — report which).

```bash
git add skill/agents/ skill/SKILL.md tests/
git commit -m "feat(agents): uniform least-privilege read-only contract for all roles"
```

---

### Task 2: `--emit-host-agents` — generated enforcement shells

**Files:**
- Modify: `skill/scripts/dispatch.py`
- Test: `tests/test_dispatch.py` (new class `TestEmitHostAgents`)

**Interfaces:**
- Consumes: Task 1's uniform tool_policy values; `load_template(role_file)`; `model_resolver.resolve_model(host, role)`.
- Produces (Task 3 relies on these exact names):
  - `ROLE_FILES = {"scout": "scout.md", "panel_review": "panel-review.md", "lens_sweep": "lens-sweep.md", "advisor": "advisor.md"}`
  - `registered_agent_name(role_file) -> str` — `"panopticon-" + stem` (e.g. `panopticon-panel-review`)
  - `emit_host_agents(host, out_dir) -> list[str]` — paths written; ValueError on unsupported host or template error
  - CLI: `--emit-host-agents {claude,kimi}` with optional `--out DIR` (claude default `~/.claude/agents`; kimi REQUIRES `--out`)

- [ ] **Step 1: Write the failing tests** (append to `tests/test_dispatch.py`)

```python
class TestEmitHostAgents(unittest.TestCase):
    def test_claude_files_written_for_all_roles(self):
        with tempfile.TemporaryDirectory() as d:
            written = dispatch.emit_host_agents("claude", d)
            names = sorted(os.path.basename(p) for p in written)
            self.assertEqual(names, ["panopticon-advisor.md", "panopticon-lens-sweep.md",
                                     "panopticon-panel-review.md", "panopticon-scout.md"])

    def test_claude_frontmatter_is_enforcement_shell(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            text = open(os.path.join(d, "panopticon-panel-review.md")).read()
            self.assertIn("name: panopticon-panel-review", text)
            self.assertIn("tools: Read, Grep, Glob", text)
            self.assertIn("model: sonnet", text)
            self.assertNotIn("Bash", text.split("---")[1])  # no forbidden tool in frontmatter
            body = text.split("---", 2)[2]
            self.assertIn("Follow the dispatched task", body)
            self.assertIn("Bash", body)  # charter names the forbidden list

    def test_claude_models_follow_policy(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            for fname, model in (("panopticon-scout.md", "haiku"),
                                 ("panopticon-lens-sweep.md", "haiku"),
                                 ("panopticon-panel-review.md", "sonnet"),
                                 ("panopticon-advisor.md", "opus")):
                self.assertIn("model: %s" % model,
                              open(os.path.join(d, fname)).read(), fname)

    def test_kimi_dialect_has_disallowed_tools(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("kimi", d)
            text = open(os.path.join(d, "panopticon-lens-sweep.md")).read()
            self.assertIn("disallowedTools:", text)
            self.assertIn("- Bash", text)

    def test_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            first = {p: open(os.path.join(d, p)).read() for p in os.listdir(d)}
            dispatch.emit_host_agents("claude", d)
            second = {p: open(os.path.join(d, p)).read() for p in os.listdir(d)}
            self.assertEqual(first, second)

    def test_unsupported_host_fails_fast(self):
        with self.assertRaises(ValueError):
            dispatch.emit_host_agents("generic", "/tmp/x")

    def test_cli_kimi_requires_out(self):
        rc = dispatch.main(["--emit-host-agents", "kimi"])
        self.assertEqual(rc, 2)

    def test_cli_writes_to_out(self):
        with tempfile.TemporaryDirectory() as d:
            rc = dispatch.main(["--emit-host-agents", "claude", "--out", d])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(os.path.join(d, "panopticon-scout.md")))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_dispatch.py -k EmitHostAgents -v`
Expected: FAIL with `AttributeError: ... no attribute 'emit_host_agents'`

- [ ] **Step 3: Implement in `skill/scripts/dispatch.py`**

```python
ROLE_FILES = {"scout": "scout.md", "panel_review": "panel-review.md",
              "lens_sweep": "lens-sweep.md", "advisor": "advisor.md"}
CLAUDE_AGENTS_DIR = os.path.join(os.path.expanduser("~"), ".claude", "agents")

_CHARTER = (
    "You are panopticon's `%s` reviewer (a registered enforcement shell).\n"
    "Follow the dispatched task message exactly — it contains your full\n"
    "instructions for this run. Your tool restrictions are host-enforced:\n"
    "you may use only %s and must never attempt %s.\n"
    "Return your result as the task message instructs.\n")


def registered_agent_name(role_file):
    """panopticon-<stem>, e.g. scout.md -> panopticon-scout."""
    return "panopticon-" + role_file[:-len(".md")]


def emit_host_agents(host, out_dir):
    """Generate host-native registered agent files (enforcement shells).

    Frontmatter carries the enforceable surface (name, description, tools,
    model); the body is a short charter. The rendered prompt still arrives as
    the task message at dispatch time — registration changes what an agent MAY
    do, never what it is asked to do. Fail-fast on template errors (shipped
    assets); idempotent for unchanged templates.
    """
    if host not in ("claude", "kimi"):
        raise ValueError("emit-host-agents: unsupported host %r (claude|kimi)" % host)
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for role, role_file in sorted(ROLE_FILES.items()):
        meta, _body = load_template(role_file)
        tp = meta["tool_policy"]
        agent = registered_agent_name(role_file)
        charter = _CHARTER % (role, ", ".join(tp["allowed"]),
                              ", ".join(tp["forbidden"]))
        if host == "claude":
            model = model_resolver.resolve_model("claude", role).get("model")
            fm = ["---", "name: %s" % agent,
                  "description: %s" % meta["description"],
                  "tools: %s" % ", ".join(tp["allowed"])]
            if model:
                fm.append("model: %s" % model)
            fm.append("---")
        else:
            fm = (["---", "name: %s" % agent,
                   "description: %s" % meta["description"], "tools:"]
                  + ["  - %s" % t for t in tp["allowed"]]
                  + ["disallowedTools:"]
                  + ["  - %s" % t for t in tp["forbidden"]]
                  + ["---"])
        path = os.path.join(out_dir, agent + ".md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(fm) + "\n\n" + charter)
        written.append(path)
    return written
```

CLI wiring in `main()`: add
`ap.add_argument("--emit-host-agents", metavar="HOST", choices=["claude", "kimi"], default=None)`
and, before the `--render-advisor` branch:

```python
    if args.emit_host_agents:
        out_dir = args.out or (CLAUDE_AGENTS_DIR if args.emit_host_agents == "claude" else None)
        if not out_dir:
            print("dispatch: --emit-host-agents kimi requires --out DIR", file=sys.stderr)
            return 2
        try:
            written = emit_host_agents(args.emit_host_agents, out_dir)
        except ValueError as e:
            print("dispatch: %s" % e, file=sys.stderr)
            return 1
        for p in written:
            print(p)
        return 0
```

(Note: `--out` currently also serves the plan/render-advisor paths; reusing it here is intentional. The `profile` positional stays optional as-is.)

- [ ] **Step 4: Run tests, full suite, ruff, commit**

```bash
python3 -m pytest tests/test_dispatch.py -v && python3 -m pytest tests/ -q
python3 -m ruff check skill/scripts/ tests/
git add skill/scripts/dispatch.py tests/test_dispatch.py
git commit -m "feat(dispatch): --emit-host-agents generates enforcement-shell registrations"
```

---

### Task 3: Per-role registration detection + `enforced` plan entries + SKILL.md conditional dispatch

**Files:**
- Modify: `skill/scripts/dispatch.py` (`build_plan`, `main`)
- Modify: `skill/SKILL.md` (Host dispatch section + step 5)
- Test: `tests/test_dispatch.py`, `tests/test_skill_md.py`

**Interfaces:**
- Consumes: Task 2's `ROLE_FILES`, `registered_agent_name`, `CLAUDE_AGENTS_DIR`.
- Produces: `build_plan(scope_profile, host=None, model_overrides=None, agents_dir=None)` — each entry gains `"enforced": bool`; when enforced, `entry["agent"]` is the registered name. CLI `--agents-dir DIR`. Default agents dir: claude → `CLAUDE_AGENTS_DIR`, all other hosts → None (never enforced without an explicit dir).

- [ ] **Step 1: Write the failing tests** (append to `tests/test_dispatch.py`)

```python
class TestEnforcedPlanEntries(unittest.TestCase):
    def _profile(self):
        return {"group": "g1", "files": ["a.py"], "depth": "standard",
                "panels": ["security"], "security_mode": "standard",
                "lenses": {"security": [
                    {"name": "injection", "spawn": True, "priority": 1,
                     "depth_threshold": "shallow"}]}}

    def test_enforced_true_when_registered(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            plan = dispatch.build_plan(self._profile(), host="claude", agents_dir=d)
        for e in plan:
            self.assertTrue(e["enforced"], e["role"])
        panel = [e for e in plan if e["role"] == "panel_review"][0]
        self.assertEqual(panel["agent"], "panopticon-panel-review")

    def test_enforced_false_without_registration(self):
        with tempfile.TemporaryDirectory() as d:
            plan = dispatch.build_plan(self._profile(), host="claude", agents_dir=d)
        for e in plan:
            self.assertFalse(e["enforced"], e["role"])
        panel = [e for e in plan if e["role"] == "panel_review"][0]
        self.assertEqual(panel["agent"], "panel-review")  # legacy name preserved

    def test_partial_registration_is_per_role(self):
        with tempfile.TemporaryDirectory() as d:
            dispatch.emit_host_agents("claude", d)
            os.remove(os.path.join(d, "panopticon-lens-sweep.md"))
            plan = dispatch.build_plan(self._profile(), host="claude", agents_dir=d)
        by_role = {e["role"]: e for e in plan}
        self.assertTrue(by_role["panel_review"]["enforced"])
        self.assertFalse(by_role["lens_sweep"]["enforced"])

    def test_generic_host_never_enforced_by_default(self):
        plan = dispatch.build_plan(self._profile(), host="generic")
        for e in plan:
            self.assertFalse(e["enforced"])
```

Append to `tests/test_skill_md.py`:

```python
    def test_host_dispatch_is_enforcement_conditional(self):
        for token in ("enforced", "subagent_type", "--agents-dir",
                      "--emit-host-agents"):
            self.assertIn(token, self.text, token)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_dispatch.py -k Enforced -v && python3 -m pytest tests/test_skill_md.py -v`
Expected: FAIL (`build_plan` has no `agents_dir`; entries lack `enforced`).

- [ ] **Step 3: Implement detection in `build_plan`**

Add helper + signature change:

```python
def _registration_dir(host, agents_dir):
    """Explicit dir wins; claude defaults to the user-level agents dir; any
    other host has no default (never enforced without --agents-dir)."""
    if agents_dir:
        return agents_dir
    return CLAUDE_AGENTS_DIR if host == "claude" else None


def _is_registered(reg_dir, role_file):
    return bool(reg_dir) and os.path.isfile(
        os.path.join(reg_dir, registered_agent_name(role_file) + ".md"))
```

In `build_plan(scope_profile, host=None, model_overrides=None, agents_dir=None)`: compute `reg_dir = _registration_dir(host, agents_dir)` once; for the panel_review entry set

```python
            "enforced": _is_registered(reg_dir, ROLE_FILES["panel_review"]),
            "agent": (registered_agent_name(ROLE_FILES["panel_review"])
                      if _is_registered(reg_dir, ROLE_FILES["panel_review"])
                      else AGENT_NAME["panel_review"]),
```

and equivalently for lens_sweep entries (compute the booleans into locals to avoid triple stat calls). CLI: `ap.add_argument("--agents-dir", default=None)` and pass `agents_dir=args.agents_dir` at the `build_plan` call.

- [ ] **Step 4: Edit `skill/SKILL.md`**

Step 5: append to the existing "Pass your host explicitly" line: ` Add --agents-dir DIR when your registered agents live somewhere non-default.`

Host dispatch section — replace the Claude Code bullet with:

```markdown
- **Claude Code** — in parallel via the Agent tool. If `entry.enforced` is
  true, dispatch with `subagent_type: entry.agent` (a registered
  `panopticon-*` enforcement shell — tools and model are host-enforced) and
  `entry.prompt` as the task. If false, dispatch general-purpose with
  `entry.prompt` and the model named by `entry.model.model` (omit when null).
  Register once with `python3 scripts/dispatch.py --emit-host-agents claude`.
```

And replace the advisory paragraph (currently beginning "Tool policy is advisory:") with:

```markdown
Tool policy is host-ENFORCED for entries with `enforced: true` (registered
shells) and prompt-advisory otherwise. The report's `meta.tool_policy_mode`
records which posture a run actually had. When any entry is unenforced, tell
the user in one line before fan-out.
```

- [ ] **Step 5: Run tests, full suite, ruff, commit**

```bash
python3 -m pytest tests/test_dispatch.py tests/test_skill_md.py -v
python3 -m pytest tests/ -q && python3 -m ruff check skill/scripts/ tests/
git add skill/scripts/dispatch.py skill/SKILL.md tests/
git commit -m "feat(dispatch): per-role enforcement detection with subagent_type dispatch contract"
```

---

### Task 4: `meta.tool_policy_mode` + schema + version 4.2.0

**Files:**
- Modify: `skill/scripts/synthesize.py`, `skill/scripts/evidence.py`, `skill/SKILL.md` (version only), `skill/reference/report-schema.json`
- Test: `tests/test_synthesize.py`, `tests/test_schema.py`, `tests/test_verify_queue.py`

**Interfaces:**
- Consumes: plan entries' `enforced` field (Task 3).
- Produces: `derive_tool_policy_mode(panopticon_dir=".panopticon") -> "enforced"|"advisory"|"mixed"` in synthesize; `build_report(..., tool_policy_mode=None)` writes `meta.tool_policy_mode` when provided; `main()` derives and passes it. Version `"4.2.0"` at the three documented locations.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_synthesize.py`)

```python
class TestToolPolicyMode(unittest.TestCase):
    def _write_plan(self, d, flags):
        os.makedirs(os.path.join(d, ".panopticon"), exist_ok=True)
        plan = [{"role": "panel_review", "enforced": f} for f in flags]
        with open(os.path.join(d, ".panopticon", "dispatch-plan.json"), "w") as fh:
            json.dump(plan, fh)

    def test_all_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            self._write_plan(d, [True, True])
            self.assertEqual(
                syn.derive_tool_policy_mode(os.path.join(d, ".panopticon")),
                "enforced")

    def test_none_enforced(self):
        with tempfile.TemporaryDirectory() as d:
            self._write_plan(d, [False, False])
            self.assertEqual(
                syn.derive_tool_policy_mode(os.path.join(d, ".panopticon")),
                "advisory")

    def test_mixed(self):
        with tempfile.TemporaryDirectory() as d:
            self._write_plan(d, [True, False])
            self.assertEqual(
                syn.derive_tool_policy_mode(os.path.join(d, ".panopticon")),
                "mixed")

    def test_no_plan_files_is_advisory(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(syn.derive_tool_policy_mode(d), "advisory")

    def test_report_meta_carries_mode_and_new_version(self):
        f = _agentic()
        report = syn.build_report([f], [], "t", None, "2026-08-03T00:00:00Z",
                                  tool_policy_mode="mixed")
        self.assertEqual(report["meta"]["tool_policy_mode"], "mixed")
        self.assertEqual(report["meta"]["version"], "4.2.0")
```

In `tests/test_verify_queue.py`: change the payload version assertion from `"4.1.0"` to `"4.2.0"`. In `tests/test_schema.py`: add

```python
    def test_schema_declares_tool_policy_mode(self):
        meta_props = self.schema["properties"]["meta"]["properties"]
        self.assertEqual(meta_props["tool_policy_mode"]["enum"],
                         ["enforced", "advisory", "mixed"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_synthesize.py -k ToolPolicyMode -v`
Expected: FAIL (`derive_tool_policy_mode` missing). Also `grep -rn '"4.1.0"' tests/` to enumerate output pins you must flip (verify-queue payload, the schema-theater/meta version asserts, `test_schema.py` build_report validation) versus fixture INPUTS (leave those).

- [ ] **Step 3: Implement**

In `skill/scripts/synthesize.py` (glob is needed — add `import glob` to the imports):

```python
def derive_tool_policy_mode(panopticon_dir=".panopticon"):
    """Derive the run's tool-policy posture from dispatch plan files.

    enforced: every entry across every plan file is enforced; advisory: none
    are (or no plan files exist — nothing was enforced); mixed: some are.
    Tolerant: unreadable/malformed plan files are ignored.
    """
    flags = []
    for path in sorted(glob.glob(os.path.join(panopticon_dir, "dispatch-plan*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                plan = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(plan, list):
            flags.extend(bool(e.get("enforced")) for e in plan if isinstance(e, dict))
    if flags and all(flags):
        return "enforced"
    if any(flags):
        return "mixed"
    return "advisory"
```

`build_report` gains keyword `tool_policy_mode=None`; in the returned `meta` dict add `**({"tool_policy_mode": tool_policy_mode} if tool_policy_mode else {})` (or an explicit conditional insert after construction). `main()` passes `tool_policy_mode=derive_tool_policy_mode()`. Bump `"version": "4.1.0"` → `"4.2.0"` (synthesize.py:541 area) and `evidence.py` write_verify_queue `"version": "4.1.0"` → `"4.2.0"`; `skill/SKILL.md` frontmatter `metadata.version: "4.2.0"`. Schema: add to `meta.properties`:

```json
"tool_policy_mode": {"type": "string", "enum": ["enforced", "advisory", "mixed"]}
```

- [ ] **Step 4: Run tests, full suite, ruff, commit**

```bash
python3 -m pytest tests/test_synthesize.py tests/test_schema.py tests/test_verify_queue.py -v
python3 -m pytest tests/ -q && python3 -m ruff check skill/scripts/ tests/
git add skill/ tests/
git commit -m "feat(synthesize): audit artifact records tool_policy_mode; version 4.2.0"
```

---

### Task 5: Docs — clean-tree check, hostile-corpus guidance, README install step, DEVELOPMENT.md

**Files:**
- Modify: `skill/SKILL.md` (step 9 + Notes), `README.md`, `DEVELOPMENT.md`
- Test: `tests/test_skill_md.py`

- [ ] **Step 1: Write the failing test** (append to `tests/test_skill_md.py`)

```python
    def test_clean_tree_check_and_hostile_guidance(self):
        self.assertIn("git status --porcelain", self.text)
        self.assertIn("treat the run as compromised", self.text)
        self.assertIn("enforcement registered", self.text)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m pytest tests/test_skill_md.py -v`

- [ ] **Step 3: Edit the three docs**

`skill/SKILL.md` step 9 — replace
`9. **Validate** — \`verification-before-completion\`: check gate, print summary, write JSON.`
with:

```markdown
9. **Validate** — `verification-before-completion`: run `git status --porcelain`
   on the target; ANY modification outside `.panopticon/` means a reviewer had
   side effects — treat the run as compromised: discard the findings files,
   report the violation, and re-run. Then check gate, print summary, write JSON.
```

`skill/SKILL.md` Notes section — append:

```markdown
Hostile-content review (redteam mode, deliberately vulnerable corpora, repos
that may contain planted injection payloads) should run with enforcement
registered (`--emit-host-agents`) so `meta.tool_policy_mode` reads `enforced`.
```

`README.md` — after the Claude Code symlink instructions, add:

```markdown
Then register the enforcement shells (one-time; re-run after template changes):

```bash
python3 skill/scripts/dispatch.py --emit-host-agents claude
```
```

`DEVELOPMENT.md` — Current version → 4.2.0; History entry:

```markdown
- **4.2.0** (current) — tool-policy enforcement: uniform read-only/return-JSON
  role contracts; `--emit-host-agents` generates registered enforcement shells
  (claude/kimi dialects) from the host-neutral templates; per-role `enforced`
  plan entries dispatched via `subagent_type`; `meta.tool_policy_mode`
  (enforced/advisory/mixed) in the audit artifact; clean-tree check in the
  validate step. SEC-101 remediation.
```

(Remove "(current)" from the 4.1.0 entry.)

- [ ] **Step 4: Run tests, full suite, commit**

```bash
python3 -m pytest tests/test_skill_md.py -v && python3 -m pytest tests/ -q
python3 -m ruff check skill/scripts/ tests/
git add skill/SKILL.md README.md DEVELOPMENT.md tests/test_skill_md.py
git commit -m "docs(skill): clean-tree check, hostile-corpus guidance, registration install step"
```

---

### Task 6 (controller-executed): live enforcement acceptance on Claude Code

**Run by the controlling session, not a subagent.**

- [ ] **Step 1:** Emit for real: `python3 skill/scripts/dispatch.py --emit-host-agents claude` (writes to `~/.claude/agents/`). Verify the four files' frontmatter by reading them.
- [ ] **Step 2:** Build a plan with default detection (`--host claude`, no `--agents-dir`) against a scope profile; confirm every entry has `enforced: true` and registered agent names.
- [ ] **Step 3:** Dispatch at least one entry via `subagent_type: panopticon-lens-sweep` with its rendered prompt. **Prove enforcement:** instruct-level attempt aside, verify the registered agent's tool surface excludes Bash (the dispatch either exposes no Bash tool to the agent, or a deliberate "run `echo test` via Bash" probe in a follow-up dispatch fails). If the current session cannot see newly registered agent types (registration may require session restart), record that as the documented caveat, verify the emitted files + plan flags only, and note the restart requirement in README.
- [ ] **Step 4:** Run pass-1 → pass-2 on the mini scope and confirm the report carries `meta.tool_policy_mode: "enforced"` and `meta.version: "4.2.0"`.
- [ ] **Step 5:** Record outcomes (including any friction) in the PR description.
