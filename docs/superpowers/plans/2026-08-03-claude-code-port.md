# Claude Code Port & Host-Neutral Dispatch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Claude Code the first-class host by moving all reviewer dispatch to deterministic rendered prompts, with host-neutral templates, correct host detection, and an honest per-host dispatch contract.

**Architecture:** `dispatch.py` gains a template loader/renderer: `DispatchPlan` entries carry fully rendered prompts, and a `--render-advisor` mode renders verify-queue entries the same way. `agents/*.md` frontmatter becomes host-neutral data (`name`, `description`, `tool_policy`). Host selection is explicit (`--host` from the orchestrating agent) with fixed env-sniffing fallback. SKILL.md describes one flow plus a per-host "Host dispatch" mapping.

**Tech Stack:** Python 3 stdlib only in `skill/scripts/`, pytest, ruff.

**Spec:** `docs/superpowers/specs/2026-08-03-claude-code-port-design.md` — read it first. Research citations: `docs/superpowers/specs/2026-08-03-host-portability-research.md`.

## Global Constraints

- Python stdlib only in `skill/scripts/` (no PyYAML dependency in the renderer — frontmatter is parsed with a constrained stdlib parser).
- **Fail-fast for templates** (deliberate exception to tolerant-by-design): missing template, unfilled placeholder, or unknown placeholder aborts with a message naming the template and placeholder. Tolerance remains for external inputs only.
- Placeholder syntax: `{lower_snake_case}` tokens only; detector regex `\{([a-z_]+)\}`. Template bodies contain JSON braces and regex braces — the detector must match ONLY single-word braced tokens.
- Claude model policy (exact values): scout=`haiku`, lens_sweep=`haiku`, panel_review=`sonnet`, advisor=`opus`. `generic` host resolves every role to `{"model": None}` (inherit session).
- Host detection fallback order: Kimi env vars → `kimi`; `CLAUDECODE` or any `CLAUDE_CODE_*` → `claude`; else `generic`. Explicit `--host` always wins. No silent default-to-kimi.
- Tool policy is advisory-by-prompt on all raw-prompt hosts; the injected line must name allowed and forbidden tools. Current tool values preserved verbatim this round.
- Version bump to **4.1.0** (SKILL.md `metadata.version`, `build_report` `meta.version`, `write_verify_queue` payload `version`, and the tests that pin them) — lands in Task 6 only.
- Run `python3 -m pytest tests/ -q` and `python3 -m ruff check skill/scripts/ tests/` before every commit.
- Commit prefixes: `feat(...)`/`fix(...)`/`docs(...)`/`refactor(...)`.

---

### Task 1: Template frontmatter — parser + migration of the four agent files

**Files:**
- Modify: `skill/scripts/dispatch.py` (add `parse_template_frontmatter`, `load_template`, `TEMPLATE_DIR`)
- Modify: `skill/agents/scout.md`, `skill/agents/panel-review.md`, `skill/agents/lens-sweep.md`, `skill/agents/advisor.md` (frontmatter only — bodies unchanged)
- Test: `tests/test_agent_templates.py` (create)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces (Tasks 2–3 rely on these exact names):
  - `TEMPLATE_DIR: str` — absolute path of `skill/agents/`
  - `parse_template_frontmatter(text, source="<template>") -> (meta: dict, body: str)` — meta has `name: str`, `description: str`, `tool_policy: {"allowed": [str], "forbidden": [str]}`; raises `ValueError` naming `source` on any deviation
  - `load_template(role_file) -> (meta, body)` — `role_file` is a basename like `"scout.md"`; raises `ValueError` if the file is missing

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_agent_templates.py
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill", "scripts"))
import dispatch


ROLES = ["scout.md", "panel-review.md", "lens-sweep.md", "advisor.md"]


class TestTemplateFrontmatter(unittest.TestCase):
    def test_all_templates_parse_with_host_neutral_meta(self):
        for role_file in ROLES:
            meta, body = dispatch.load_template(role_file)
            self.assertTrue(meta["name"], role_file)
            self.assertTrue(meta["description"], role_file)
            self.assertIn("allowed", meta["tool_policy"], role_file)
            self.assertIn("forbidden", meta["tool_policy"], role_file)
            self.assertNotIn("---", body.split("\n", 1)[0], role_file)
            self.assertNotIn("model_preference", body, role_file)

    def test_kimi_dialect_fields_are_gone(self):
        for role_file in ROLES:
            raw = open(os.path.join(dispatch.TEMPLATE_DIR, role_file),
                       encoding="utf-8").read()
            self.assertNotIn("model_preference", raw, role_file)
            self.assertNotIn("disallowedTools", raw, role_file)

    def test_tool_policy_values_preserved_this_round(self):
        meta, _ = dispatch.load_template("scout.md")
        self.assertEqual(meta["tool_policy"]["allowed"],
                         ["Read", "Grep", "Glob", "Bash"])
        self.assertEqual(meta["tool_policy"]["forbidden"],
                         ["Edit", "Write", "Agent"])
        meta, _ = dispatch.load_template("lens-sweep.md")
        self.assertEqual(meta["tool_policy"]["allowed"], ["Read", "Grep", "Glob"])
        self.assertEqual(meta["tool_policy"]["forbidden"],
                         ["Bash", "Edit", "Write", "Agent"])
        meta, _ = dispatch.load_template("advisor.md")
        self.assertEqual(meta["tool_policy"]["allowed"], ["Read", "Grep", "Glob"])
        self.assertEqual(meta["tool_policy"]["forbidden"],
                         ["Bash", "Edit", "Write", "Agent"])
        meta, _ = dispatch.load_template("panel-review.md")
        self.assertEqual(meta["tool_policy"]["allowed"],
                         ["Read", "Grep", "Glob", "Bash"])
        self.assertEqual(meta["tool_policy"]["forbidden"],
                         ["Edit", "Write", "Agent"])

    def test_malformed_frontmatter_fails_fast(self):
        with self.assertRaises(ValueError) as ctx:
            dispatch.parse_template_frontmatter("no frontmatter here", source="x.md")
        self.assertIn("x.md", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            dispatch.parse_template_frontmatter(
                "---\nname: a\n---\nbody", source="y.md")
        self.assertIn("y.md", str(ctx.exception))  # missing tool_policy

    def test_missing_template_fails_fast(self):
        with self.assertRaises(ValueError) as ctx:
            dispatch.load_template("nonexistent.md")
        self.assertIn("nonexistent.md", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_agent_templates.py -v`
Expected: FAIL with `AttributeError: module 'dispatch' has no attribute 'load_template'`

- [ ] **Step 3: Add the parser to `skill/scripts/dispatch.py`**

Add after the imports (note `import re` must be added to the imports):

```python
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            os.pardir, "agents")

_FM_SCALAR_RE = re.compile(r"^([a-z_]+):\s*(.*)$")
_FM_LIST_RE = re.compile(r"^\s{2}(allowed|forbidden):\s*\[([^\]]*)\]\s*$")


def parse_template_frontmatter(text, source="<template>"):
    """Parse the constrained host-neutral template frontmatter.

    Expected shape (inline flow lists only):
        ---
        name: scout
        description: ...
        tool_policy:
          allowed: [Read, Grep, Glob]
          forbidden: [Edit, Write, Agent]
        ---
    Fail-fast by design: templates are shipped assets, so any deviation is a
    bug — raise ValueError naming the source rather than degrade.
    """
    if not text.startswith("---"):
        raise ValueError("%s: template has no frontmatter block" % source)
    end = text.find("\n---", 3)
    if end == -1:
        raise ValueError("%s: unterminated frontmatter block" % source)
    header = text[3:end].strip("\n")
    body = text[end + len("\n---"):].lstrip("\n")
    meta = {"tool_policy": {}}
    in_policy = False
    for line in header.splitlines():
        if not line.strip():
            continue
        m = _FM_LIST_RE.match(line)
        if m and in_policy:
            items = [x.strip() for x in m.group(2).split(",") if x.strip()]
            meta["tool_policy"][m.group(1)] = items
            continue
        m = _FM_SCALAR_RE.match(line)
        if not m:
            raise ValueError("%s: cannot parse frontmatter line %r" % (source, line))
        key, value = m.group(1), m.group(2).strip()
        if key == "tool_policy":
            in_policy = True
            continue
        in_policy = False
        meta[key] = value
    for required in ("name", "description"):
        if not meta.get(required):
            raise ValueError("%s: frontmatter missing %r" % (source, required))
    for required in ("allowed", "forbidden"):
        if required not in meta["tool_policy"]:
            raise ValueError("%s: tool_policy missing %r list" % (source, required))
    return meta, body


def load_template(role_file):
    """Load and parse an agent template by basename (e.g. 'scout.md')."""
    path = os.path.join(TEMPLATE_DIR, role_file)
    if not os.path.isfile(path):
        raise ValueError("template not found: %s (looked in %s)" % (role_file, TEMPLATE_DIR))
    with open(path, encoding="utf-8") as fh:
        return parse_template_frontmatter(fh.read(), source=role_file)
```

- [ ] **Step 4: Migrate the four agent files' frontmatter**

Replace each file's frontmatter block (everything between and including the `---` markers) with the host-neutral form; leave every body byte after the closing `---` untouched.

`skill/agents/scout.md`:
```yaml
---
name: scout
description: Profiles files and selects depth/lenses for a review group
tool_policy:
  allowed: [Read, Grep, Glob, Bash]
  forbidden: [Edit, Write, Agent]
---
```

`skill/agents/panel-review.md`:
```yaml
---
name: panel-review
description: Holistic panel reviewer covering all non-mechanical lenses
tool_policy:
  allowed: [Read, Grep, Glob, Bash]
  forbidden: [Edit, Write, Agent]
---
```

`skill/agents/lens-sweep.md`:
```yaml
---
name: lens-sweep
description: Cheap mechanical lens sweep emitting narrow, cited findings only
tool_policy:
  allowed: [Read, Grep, Glob]
  forbidden: [Bash, Edit, Write, Agent]
---
```

`skill/agents/advisor.md`:
```yaml
---
name: advisor
description: Independent advisor that verifies a single finding by exploring the repository
tool_policy:
  allowed: [Read, Grep, Glob]
  forbidden: [Bash, Edit, Write, Agent]
---
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_agent_templates.py tests/test_dispatch.py -v`
Expected: all PASS (existing dispatch tests are unaffected — nothing calls the new functions yet).

- [ ] **Step 6: Ruff, full suite, commit**

```bash
python3 -m ruff check skill/scripts/ tests/ && python3 -m pytest tests/ -q
git add skill/scripts/dispatch.py skill/agents/ tests/test_agent_templates.py
git commit -m "feat(dispatch): host-neutral template frontmatter with fail-fast parser"
```

---

### Task 2: Renderer — plan entries carry rendered prompts

**Files:**
- Modify: `skill/scripts/dispatch.py` (add `render_prompt`, `_tool_policy_line`, wire into `build_plan`)
- Test: `tests/test_dispatch.py` (add a test class), `tests/goldens/` (create, generated in Step 5)

**Interfaces:**
- Consumes: Task 1's `load_template`.
- Produces (Task 3 and SKILL.md rely on these):
  - `PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")`
  - `render_prompt(role_file, mapping) -> str` — fills every `{token}` in the template body from `mapping`, injects the tool-policy line, fail-fast on unfilled/unknown placeholders
  - `build_plan(...)` entries gain `"prompt": str` (all other keys unchanged)

- [ ] **Step 1: Write the failing tests** (append to `tests/test_dispatch.py`)

```python
class TestRenderPrompt(unittest.TestCase):
    def _entry_mapping(self):
        return {
            "panel": "security", "group": "g1",
            "file_list": "a.py, b.py", "security_mode": "standard",
            "depth": "standard", "lenses": "- known_vulns\n- novel",
            "lens": "injection",
            "out_file": ".panopticon/findings-g1-security-panel_review.json",
        }

    def test_rendered_panel_prompt_properties(self):
        p = dispatch.render_prompt("panel-review.md", self._entry_mapping())
        self.assertNotIn("---\nname:", p)               # frontmatter stripped
        self.assertIn("security", p)                     # {panel} filled
        self.assertIn("a.py, b.py", p)                   # {file_list} filled
        self.assertIn(".panopticon/findings-g1-security-panel_review.json", p)
        # tool-policy line injected, naming allowed and forbidden tools
        self.assertIn("Read", p)
        self.assertIn("must not use", p.lower())
        # no known placeholder tokens survive; JSON/regex braces in the body do
        for tok in dispatch.PLACEHOLDER_RE.findall(p):
            self.assertNotIn(tok, self._entry_mapping(), tok)

    def test_unfilled_placeholder_fails_fast(self):
        mapping = self._entry_mapping()
        del mapping["depth"]
        with self.assertRaises(ValueError) as ctx:
            dispatch.render_prompt("panel-review.md", mapping)
        self.assertIn("depth", str(ctx.exception))
        self.assertIn("panel-review.md", str(ctx.exception))

    def test_brace_safety_value_containing_placeholder_syntax(self):
        mapping = self._entry_mapping()
        mapping["file_list"] = "weird-{depth}-name.py"   # value contains {depth}
        p = dispatch.render_prompt("panel-review.md", mapping)
        self.assertIn("weird-{depth}-name.py", p)        # survives literally

    def test_build_plan_entries_carry_prompts(self):
        profile = {"group": "g1", "files": ["a.py"], "depth": "standard",
                   "panels": ["security"],
                   "lenses": {"security": [
                       {"name": "injection", "spawn": True, "priority": 1,
                        "depth_threshold": "shallow"},
                       {"name": "novel", "spawn": False, "priority": 2,
                        "depth_threshold": "standard"}]},
                   "security_mode": "standard"}
        plan = dispatch.build_plan(profile, host="claude")
        self.assertTrue(plan)
        for entry in plan:
            self.assertIn("prompt", entry)
            self.assertNotIn("{file_list}", entry["prompt"])
        sweep = [e for e in plan if e["role"] == "lens_sweep"][0]
        self.assertIn("injection", sweep["prompt"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_dispatch.py -k Render -v`
Expected: FAIL with `AttributeError: ... no attribute 'render_prompt'`

- [ ] **Step 3: Implement in `skill/scripts/dispatch.py`**

```python
PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")


def _tool_policy_line(meta):
    tp = meta["tool_policy"]
    return ("\n## Tool policy\n\nYour only tools are %s. "
            "You must not use %s under any circumstances.\n"
            % (", ".join(tp["allowed"]), ", ".join(tp["forbidden"])))


def render_prompt(role_file, mapping):
    """Render a role template into a dispatchable prompt.

    Brace-safe two-step replacement: placeholders are first swapped for unique
    sentinel tokens, then sentinels for values — so values containing
    '{placeholder}' syntax pass through literally. Fail-fast: any known-token
    placeholder left unfilled, and any {token} in the template that is not in
    mapping, is an error naming the template and token. JSON/regex braces in
    template bodies are ignored because the detector matches only
    single-word lowercase tokens.
    """
    meta, body = load_template(role_file)
    tokens = set(PLACEHOLDER_RE.findall(body))
    missing = sorted(t for t in tokens if t not in mapping)
    if missing:
        raise ValueError("%s: no value for placeholder(s): %s"
                         % (role_file, ", ".join(missing)))
    rendered = body
    sentinels = {}
    for i, tok in enumerate(sorted(tokens)):
        sentinel = "\x00PANOPTICON%d\x00" % i
        sentinels[sentinel] = str(mapping[tok])
        rendered = rendered.replace("{%s}" % tok, sentinel)
    for sentinel, value in sentinels.items():
        rendered = rendered.replace(sentinel, value)
    return rendered + _tool_policy_line(meta)
```

In `build_plan`, extend both entry constructions. For the panel_review entry add:

```python
            "prompt": render_prompt(AGENT_NAME["panel_review"] + ".md", {
                "panel": panel_name, "group": group_name,
                "file_list": ", ".join(files),
                "security_mode": scope_profile.get("security_mode", "standard"),
                "depth": depth,
                "lenses": "\n".join("- %s" % n for n in non_spawned) or "- (all lenses)",
                "out_file": ".panopticon/findings-%s-%s-panel_review.json" % (group_name, panel_name),
            }),
```

and for the lens_sweep entry:

```python
            "prompt": render_prompt(AGENT_NAME["lens_sweep"] + ".md", {
                "panel": panel_name, "group": group_name,
                "file_list": ", ".join(files),
                "security_mode": scope_profile.get("security_mode", "standard"),
                "depth": depth, "lens": lens_name,
                "out_file": ".panopticon/findings-%s-%s-lens_sweep-%s.json" % (group_name, panel_name, lens_name),
            }),
```

(The `out_file` values already exist as entry keys — reuse the same expressions/variables rather than retyping if the implementation assigns them to locals first.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_dispatch.py -v`
Expected: all PASS, including the pre-existing plan tests (entries have one new key; nothing asserts key-set equality — verify that claim against failures if any).

- [ ] **Step 5: Generate and commit golden files**

```bash
python3 - <<'EOF'
import json, os, sys
sys.path.insert(0, os.path.join("skill", "scripts"))
import dispatch
os.makedirs("tests/goldens", exist_ok=True)
mapping = {"panel": "security", "group": "g1", "file_list": "a.py, b.py",
           "security_mode": "standard", "depth": "standard",
           "lenses": "- known_vulns\n- novel", "lens": "injection",
           "out_file": ".panopticon/findings-g1-security-panel_review.json"}
for role in ("panel-review.md", "lens-sweep.md", "scout.md"):
    out = dispatch.render_prompt(role, mapping | {
        "out_file": ".panopticon/scout-g1.json" if role == "scout.md" else mapping["out_file"]})
    open("tests/goldens/%s.rendered.txt" % role[:-3], "w").write(out)
    print("wrote", role)
EOF
```

Manually eyeball each golden for: frontmatter gone, placeholders filled, tool-policy line last. (`scout.md`'s body contains no placeholders — it renders as body + tool-policy line, and the mapping is unused for it; if the generator errors on scout, the template gained a placeholder and the error names it.) Then append the golden regression test to `tests/test_dispatch.py`:

```python
class TestRenderGoldens(unittest.TestCase):
    def test_rendered_output_matches_goldens(self):
        mapping = {"panel": "security", "group": "g1", "file_list": "a.py, b.py",
                   "security_mode": "standard", "depth": "standard",
                   "lenses": "- known_vulns\n- novel", "lens": "injection",
                   "out_file": ".panopticon/findings-g1-security-panel_review.json"}
        gdir = os.path.join(os.path.dirname(__file__), "goldens")
        for role in ("panel-review.md", "lens-sweep.md", "scout.md"):
            m = dict(mapping)
            if role == "scout.md":
                m["out_file"] = ".panopticon/scout-g1.json"
            expected = open(os.path.join(gdir, role[:-3] + ".rendered.txt"),
                            encoding="utf-8").read()
            self.assertEqual(dispatch.render_prompt(role, m), expected, role)
```

- [ ] **Step 6: Full suite, ruff, commit**

```bash
python3 -m pytest tests/ -q && python3 -m ruff check skill/scripts/ tests/
git add skill/scripts/dispatch.py tests/test_dispatch.py tests/goldens/
git commit -m "feat(dispatch): plan entries carry rendered prompts with golden coverage"
```

---

### Task 3: `--render-advisor` mode

**Files:**
- Modify: `skill/scripts/dispatch.py` (`render_advisor_prompts` + CLI wiring in `main`)
- Test: `tests/test_dispatch.py` (add a test class)

**Interfaces:**
- Consumes: Task 2's `render_prompt`; the verify-queue file shape from 4.0.0 (`{"version", "cut_by_max_verify", "entries": [{"queue_id", "priority", "finding"}]}`).
- Produces: `render_advisor_prompts(queue_path, out_dir) -> list[str]` (paths written, one `{queue_id}.md` per entry); CLI `python3 skill/scripts/dispatch.py --render-advisor QUEUE --out DIR` (positional `profile` becomes optional when `--render-advisor` is given).

- [ ] **Step 1: Write the failing tests** (append to `tests/test_dispatch.py`)

```python
import json
import tempfile


class TestRenderAdvisor(unittest.TestCase):
    def _queue(self, tmp):
        queue = {"version": "4.0.0", "cut_by_max_verify": 0, "entries": [
            {"queue_id": "000-SEC-001", "priority": 1,
             "finding": {"id": "SEC-001", "title": "sqli", "severity": "HIGH",
                          "panel": "security", "category": "injection",
                          "location": {"file": "app.py", "line_start": 10},
                          "description": "raw query with {code_context} text"}},
            {"queue_id": "001-CD-002", "priority": 3,
             "finding": {"id": "CD-002", "title": "leak", "severity": "LOW",
                          "panel": "code", "category": "correctness",
                          "location": {"file": "b.py", "line_start": 4}}},
        ]}
        qpath = os.path.join(tmp, "verify-queue.json")
        with open(qpath, "w") as fh:
            json.dump(queue, fh)
        return qpath

    def test_writes_one_prompt_per_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = self._queue(tmp)
            outdir = os.path.join(tmp, "advisor-prompts")
            written = dispatch.render_advisor_prompts(qpath, outdir)
            self.assertEqual([os.path.basename(p) for p in written],
                             ["000-SEC-001.md", "001-CD-002.md"])
            text = open(written[0], encoding="utf-8").read()
            self.assertIn('"id": "SEC-001"', text)        # claim embedded
            self.assertIn("{code_context}", text)          # brace-safe: survives
            self.assertNotIn("{claim_json}", text)         # placeholder filled
            self.assertNotIn("---\nname:", text)           # frontmatter stripped

    def test_malformed_queue_fails_fast(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = os.path.join(tmp, "bad.json")
            open(qpath, "w").write("{not json")
            with self.assertRaises(ValueError):
                dispatch.render_advisor_prompts(qpath, tmp)

    def test_cli_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = self._queue(tmp)
            outdir = os.path.join(tmp, "out")
            rc = dispatch.main(["--render-advisor", qpath, "--out", outdir])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(os.path.join(outdir, "000-SEC-001.md")))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_dispatch.py -k Advisor -v`
Expected: FAIL with `AttributeError: ... no attribute 'render_advisor_prompts'`

- [ ] **Step 3: Implement**

```python
def render_advisor_prompts(queue_path, out_dir):
    """Render one advisor prompt per verify-queue entry to out_dir.

    Deterministic replacement for the orchestrating agent hand-rendering
    claim JSON into the advisor template. The queue is OUR artifact but is
    parsed fail-fast anyway (a corrupt queue means an upstream bug).
    """
    try:
        with open(queue_path, encoding="utf-8") as fh:
            queue = json.load(fh)
    except (OSError, ValueError) as e:
        raise ValueError("cannot read verify queue %s: %s" % (queue_path, e))
    entries = queue.get("entries")
    if not isinstance(entries, list):
        raise ValueError("verify queue %s has no entries list" % queue_path)
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for entry in entries:
        queue_id = entry.get("queue_id")
        finding = entry.get("finding")
        if not queue_id or not isinstance(finding, dict):
            raise ValueError("verify queue %s: malformed entry %r"
                             % (queue_path, entry.get("queue_id")))
        claim = json.dumps(finding, indent=2, ensure_ascii=False)
        prompt = render_prompt("advisor.md", {"claim_json": claim})
        path = os.path.join(out_dir, "%s.md" % queue_id)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(prompt)
        written.append(path)
    return written
```

In `main()`: make the `profile` positional optional (`nargs="?"`), add `--render-advisor METAVAR QUEUE`, and branch before the profile load:

```python
    ap.add_argument("--render-advisor", metavar="QUEUE", default=None,
                    help="Render advisor prompts from a verify-queue JSON into --out DIR")
```

```python
    if args.render_advisor:
        if not args.out:
            print("dispatch: --render-advisor requires --out DIR", file=sys.stderr)
            return 2
        try:
            written = render_advisor_prompts(args.render_advisor, args.out)
        except ValueError as e:
            print("dispatch: %s" % e, file=sys.stderr)
            return 1
        print("rendered %d advisor prompt(s) -> %s" % (len(written), args.out))
        return 0
    if not args.profile:
        ap.error("profile is required unless --render-advisor is given")
```

- [ ] **Step 4: Run tests, full suite, ruff, commit**

```bash
python3 -m pytest tests/test_dispatch.py -v && python3 -m pytest tests/ -q
python3 -m ruff check skill/scripts/ tests/
git add skill/scripts/dispatch.py tests/test_dispatch.py
git commit -m "feat(dispatch): deterministic advisor prompt rendering from the verify queue"
```

---

### Task 4: Host detection + model resolution

**Files:**
- Modify: `skill/scripts/dispatch.py` (`_detect_host`)
- Modify: `skill/scripts/model_resolver.py` (`_hardcoded_fallback` becomes host-aware; `resolve_model` passes host through)
- Modify: `skill/reference/model-profiles.yml` (claude block values)
- Test: `tests/test_dispatch.py`, `tests/test_model_resolver.py` (update + add)

**Interfaces:**
- Consumes: nothing new.
- Produces: `_detect_host() -> "kimi"|"claude"|"generic"`; `resolve_model("generic", role)` → `{"model": None}`; `resolve_model("claude", ...)` → `haiku`/`haiku`/`sonnet`/`opus` per role.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_dispatch.py`:

```python
from unittest import mock


class TestDetectHost(unittest.TestCase):
    def _detect(self, env):
        with mock.patch.dict(os.environ, env, clear=True):
            return dispatch._detect_host()

    def test_kimi_env(self):
        self.assertEqual(self._detect({"KIMI_CODE_VERSION": "1"}), "kimi")
        self.assertEqual(self._detect({"KIMI_SESSION_ID": "x"}), "kimi")

    def test_claude_env(self):
        self.assertEqual(self._detect({"CLAUDECODE": "1"}), "claude")
        self.assertEqual(self._detect({"CLAUDE_CODE_SESSION_ID": "abc"}), "claude")

    def test_no_env_is_generic_not_kimi(self):
        self.assertEqual(self._detect({}), "generic")

    def test_kimi_wins_over_claude_when_both(self):
        self.assertEqual(
            self._detect({"KIMI_SESSION_ID": "x", "CLAUDECODE": "1"}), "kimi")
```

In `tests/test_model_resolver.py`, update `test_claude_defaults` and `test_unknown_host_falls_back`:

```python
    def test_claude_defaults(self):
        self.assertEqual(mr.resolve_model("claude", "scout")["model"], "haiku")
        self.assertEqual(mr.resolve_model("claude", "lens_sweep")["model"], "haiku")
        self.assertEqual(mr.resolve_model("claude", "panel_review")["model"], "sonnet")
        self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "opus")

    def test_unknown_host_falls_back(self):
        self.assertIsNone(mr.resolve_model("generic", "panel_review")["model"])
        self.assertIsNone(mr.resolve_model("someday-host", "scout")["model"])

    def test_kimi_fallback_still_kimi_flavored(self):
        # With profiles unavailable, kimi host keeps its hardcoded models.
        with mock.patch.object(mr, "_PROFILES", {}):
            self.assertEqual(mr.resolve_model("kimi", "advisor")["model"], "k3")

    def test_claude_fallback_matches_policy_without_yaml(self):
        with mock.patch.object(mr, "_PROFILES", {}):
            self.assertEqual(mr.resolve_model("claude", "advisor")["model"], "opus")
```

(Add `from unittest import mock` to the imports if absent. Check how the existing `test_missing_yaml_warns_and_falls_back` neutralizes `_PROFILES` and reuse that file's established pattern instead of `mock.patch.object` if it differs.)

Also update `test_models_resolved_per_host` in `tests/test_dispatch.py`: the assertion `panel["model"]["model"] == "claude-sonnet"` becomes `== "sonnet"`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_dispatch.py -k DetectHost -v && python3 -m pytest tests/test_model_resolver.py -v`
Expected: DetectHost FAILs (no `generic`); claude-defaults FAILs (old names).

- [ ] **Step 3: Implement**

`skill/scripts/dispatch.py`:

```python
def _detect_host():
    """Best-effort host detection from environment.

    Fallback only — the orchestrating agent should pass --host explicitly
    (it knows what it is; these env vars are not all documented contracts).
    """
    if os.environ.get("KIMI_CODE_VERSION") or os.environ.get("KIMI_SESSION_ID"):
        return "kimi"
    if os.environ.get("CLAUDECODE") or any(
            k.startswith("CLAUDE_CODE_") for k in os.environ):
        return "claude"
    return "generic"
```

`skill/scripts/model_resolver.py` — replace `_hardcoded_fallback(role)` with a host-aware version and update its call site in `resolve_model` to `_hardcoded_fallback(host, role)`:

```python
_KIMI_FALLBACK = {
    "scout": {"model": "kimi-for-coding", "max_context_size": 131072, "max_output_size": 16384},
    "lens_sweep": {"model": "kimi-for-coding", "max_context_size": 131072, "max_output_size": 8192},
    "panel_review": {"model": "kimi-for-coding", "max_context_size": 131072, "max_output_size": 16384},
    "advisor": {"model": "k3", "max_context_size": 524288, "max_output_size": 32768},
}
_CLAUDE_FALLBACK = {
    "scout": {"model": "haiku"},
    "lens_sweep": {"model": "haiku"},
    "panel_review": {"model": "sonnet"},
    "advisor": {"model": "opus"},
}


def _hardcoded_fallback(host, role):
    """Last-resort role->model mapping when profiles are unavailable.

    Unknown hosts resolve to model=None, meaning "inherit the session's
    model" — never silently assume kimi.
    """
    if host == "kimi":
        return _KIMI_FALLBACK.get(role, {"model": "kimi-for-coding",
                                         "max_context_size": 131072,
                                         "max_output_size": 8192})
    if host == "claude":
        return _CLAUDE_FALLBACK.get(role, {"model": "sonnet"})
    return {"model": None}
```

`skill/reference/model-profiles.yml` — replace the `claude:` block with:

```yaml
  claude:
    scout:
      model: haiku
    lens_sweep:
      model: haiku
    panel_review:
      model: sonnet
    advisor:
      model: opus
```

(Leave the `kimi:` and `openrouter:` blocks untouched.)

- [ ] **Step 4: Run tests, full suite, ruff, commit**

```bash
python3 -m pytest tests/test_dispatch.py tests/test_model_resolver.py -v
python3 -m pytest tests/ -q && python3 -m ruff check skill/scripts/ tests/
git add skill/scripts/dispatch.py skill/scripts/model_resolver.py skill/reference/model-profiles.yml tests/
git commit -m "feat(hosts): explicit-first host detection and claude model policy"
```

---

### Task 5: SKILL.md rewrite + README honesty pass + test_skill_md extensions

**Files:**
- Modify: `skill/SKILL.md`
- Modify: `README.md`
- Test: `tests/test_skill_md.py`

**Interfaces:**
- Consumes: CLI contracts from Tasks 2–4 (`--host`, plan `prompt` entries, `--render-advisor`).
- Produces: the orchestration spec agents follow on every host.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_skill_md.py`)

```python
    def test_description_is_trigger_only_and_host_neutral(self):
        import re
        m = re.search(r"(?m)^description:\s*(.+)$", self.text)
        self.assertIsNotNone(m)
        desc = m.group(1)
        self.assertTrue(desc.startswith("Use when"), desc)
        self.assertNotIn("Kimi", desc)
        self.assertNotIn("→", desc)  # no workflow summary

    def test_has_host_dispatch_section(self):
        self.assertIn("## Host dispatch", self.text)
        for host in ("Claude Code", "Kimi Code"):
            self.assertIn(host, self.text)

    def test_pins_round1_flags_and_render_advisor(self):
        for token in ["--gate-unverified", "--max-verify", "--render-advisor",
                      "--host"]:
            self.assertIn(token, self.text, token)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_skill_md.py -v`
Expected: the three new tests FAIL against the current SKILL.md.

- [ ] **Step 3: Edit `skill/SKILL.md`**

1. Frontmatter `description` becomes:
   `description: Use when reviewing code, pull requests, branches, security posture, test quality, architecture, or database surfaces in a codebase`
   (`whenToUse` stays as-is; bump nothing else here — version lands in Task 6.)
2. `## Overview` body text: replace the sentence containing "for Kimi Code" with: `Discovery → scout → fan-out → synthesis code review. Profiles a target, groups files, dispatches specialized reviewers in parallel, and synthesizes a validated CodeReviewReport with CI gating.`
3. Pipeline step 3 (Scout): replace "dispatch the `scout` custom agent (`agents/scout.md`) per group" with "dispatch the `scout` role (`agents/scout.md`) per group — its template has no placeholders; dispatch its body plus tool-policy line as the prompt".
4. Pipeline step 5 (Plan dispatch): change the command to
   `python3 scripts/dispatch.py <scope-profile.json> --host <your host: claude|kimi|generic> --out .panopticon/dispatch-plan.json`
   and append: `Pass your host explicitly — env detection is fallback only.`
5. Pipeline step 6 (Fan-out) — replace the whole step with:

```markdown
6. **Fan-out** — for each entry in `.panopticon/dispatch-plan.json`, dispatch
   `entry.prompt` with `entry.model` via your host's agent mechanism (see Host
   dispatch below). Each reviewer writes its findings file to the entry's
   `out_file`; `panel_review` entries omit `{lens}` in the filename.
```

6. Pipeline step 8 (Verify) — replace the rendering sentence: instead of
   "with the entry's `finding` JSON rendered into the agent prompt", use:

```markdown
   Run `python3 scripts/dispatch.py --render-advisor .panopticon/verify-queue.json --out .panopticon/advisor-prompts`,
   then dispatch each `.panopticon/advisor-prompts/{queue_id}.md` file's contents
   as an `advisor` agent (`agents/advisor.md`) in parallel. The advisor RETURNS a
   verdict JSON; write it verbatim to `.panopticon/verdicts/{queue_id}.json`.
   Advisors are read-only; the orchestrator performs the write.
```

7. Add a new section after `## Pipeline`:

```markdown
## Host dispatch

One plan, one prompt per reviewer; each host dispatches with its own mechanism:

- **Claude Code** — Agent tool, general-purpose subagents, in parallel; pass
  `entry.model` (`haiku`/`sonnet`/`opus`); omit the model when it is null.
- **Kimi Code** — AgentSwarm raw-prompt dispatch (`prompt_template`/`items`);
  select an appropriate profile via `subagent_type`; model overrides are
  experimental-flag-gated.
- **Other hosts** — run the entries sequentially in-session with the same
  prompts; expect no parallelism.

Tool policy is enforced by prompt on all raw-prompt hosts: each rendered prompt
ends with the role's allowed/forbidden tool list. Treat it as binding.
```

- [ ] **Step 4: Edit `README.md`**

Replace the "Supported agent platforms" list items with:

```markdown
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code/overview) — first-class: parallel fan-out via the Agent tool
- [Kimi Code CLI](https://code.kimi.com/) — supported: AgentSwarm raw-prompt dispatch
- Other agents that read `SKILL.md` files — degraded: sequential dispatch, same prompts
```

- [ ] **Step 5: Run tests, full suite, commit**

```bash
python3 -m pytest tests/test_skill_md.py -v && python3 -m pytest tests/ -q
python3 -m ruff check skill/scripts/ tests/
git add skill/SKILL.md README.md tests/test_skill_md.py
git commit -m "docs(skill): host-neutral trigger description and per-host dispatch contract"
```

---

### Task 6: panel-template retirement, version 4.1.0, DEVELOPMENT.md, final sweep

**Files:**
- Possibly delete: `skill/prompts/panel-template.md`
- Modify: `skill/SKILL.md` (version), `skill/scripts/synthesize.py` (meta.version), `skill/scripts/evidence.py` (queue payload version), `DEVELOPMENT.md`
- Test: `tests/test_synthesize.py`, `tests/test_verify_queue.py` (version pins), `tests/test_assets.py` (if it references panel-template)

- [ ] **Step 1: Retirement check for `skill/prompts/panel-template.md`**

Run: `grep -rn "panel-template" skill/ tests/ README.md DEVELOPMENT.md docs/superpowers/specs/2026-08-03-claude-code-port-design.md`
Decision rule from the spec: retire it when nothing in the skill surface or tests references it after the renderer lands. If the only hits are DEVELOPMENT.md prose and the spec itself: `git rm skill/prompts/panel-template.md` and update the DEVELOPMENT.md architecture line for `skill/prompts/` to name only `lenses.md`. If a test or skill file references it, KEEP it and add one sentence to DEVELOPMENT.md's 4.1.0 entry naming the blocking reference.

- [ ] **Step 2: Version bump to 4.1.0**

- `skill/SKILL.md` frontmatter: `metadata.version: "4.1.0"`.
- `skill/scripts/synthesize.py`: in `build_report`, `"version": "4.0.0"` → `"4.1.0"`.
- `skill/scripts/evidence.py`: in `write_verify_queue`, `"version": "4.0.0"` → `"4.1.0"`.
- Tests pinning versions: in `tests/test_synthesize.py` update the `meta.version == "4.0.0"` assertion (in the schema-theater test) to `"4.1.0"`; in `tests/test_verify_queue.py` update `payload["version"] == "4.0.0"` to `"4.1.0"`. Find both with `grep -rn '"4.0.0"' tests/` and update every hit that pins OUTPUT versions (do not touch fixture inputs that merely carry a version field into tolerant loaders).

- [ ] **Step 3: DEVELOPMENT.md**

Update the "Current version" line to 4.1.0 and add to History:

```markdown
- **4.1.0** (current) — Claude Code port: all reviewer dispatch moves to
  deterministic rendered prompts (dispatch plan entries carry `prompt`;
  `--render-advisor` renders verify-queue entries). Agent templates get
  host-neutral frontmatter (`tool_policy` as data; advisory-by-prompt on
  raw-prompt hosts). Host selection is explicit (`--host`) with fixed
  env fallback (`CLAUDECODE`; unknown → generic, model inherited). Claude
  model policy: scout/lens=haiku, panel=sonnet, advisor=opus. SKILL.md
  description is trigger-only; Host dispatch section maps the per-host
  mechanisms (research: docs/superpowers/specs/2026-08-03-host-portability-research.md).
```

- [ ] **Step 4: Full verification**

```bash
python3 -m pytest tests/ -q && python3 -m ruff check skill/scripts/ tests/
python3 -m pytest tests/test_skill_md.py tests/test_agent_templates.py -v
```
Expected: all PASS, no lint errors.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(skill): 4.1.0 — host-neutral rendered-prompt dispatch"
```

---

### Task 7 (controller-executed): live dogfood acceptance on Claude Code

**This task is run by the controlling session, not a subagent** — it exercises the real host mechanism the plan exists to serve.

- [ ] **Step 1:** From the Claude Code session, follow `skill/SKILL.md` end-to-end against this repo with `--changes` scope (the port branch has changes vs main): discovery → scout dispatch (haiku) → plan with `--host claude` → fan-out of `entry.prompt` via the Agent tool with `entry.model` → synthesize pass 1 → `--render-advisor` → advisor fan-out (opus) → verdict writes → synthesize pass 2.
- [ ] **Step 2:** Acceptance checks: `.panopticon/dispatch-plan.json` entries contain rendered prompts and correct models; findings files land at the plan's `out_file` paths; the verify queue and rendered advisor prompts correlate by `queue_id`; the final report validates (no SCHEMA errors on stderr) and `meta.version == "4.1.0"`; no step required Kimi-specific knowledge.
- [ ] **Step 3:** Record the dogfood outcome (grade/gate/finding counts + any friction) in the PR description.
