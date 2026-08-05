# P1 Adapter-Execution Containment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Contain roslyn-secguard's target-code execution and drop scan-time
network/secrets to zero, per
`docs/superpowers/specs/2026-08-04-p1-adapter-execution-design.md`.

**Architecture:** `run_tools.py` enforces `--network none` on every docker
dispatch and gates the two online-only adapters behind `--online`; adapters
gain offline flags against assets baked into the tools image at build time;
roslyn-secguard gets a symlink-guarded copy and an SCS-only parse filter;
pip-audit's project fallback becomes a static `tomllib` parse. Closes #229,
#86, #218, #62.

**Tech Stack:** Python 3 stdlib only (`tomllib` needs the 3.11 floor CI
already has), unittest-style tests, Docker/BuildKit for the image.

## Global Constraints

- Branch: `feat/p1-adapter-execution`; nothing merges to main except by PR. `gh`/`git` network commands need `export GH_CONFIG_DIR="$HOME/.config/gh-psyberone"`.
- Python 3 stdlib only in `skill/scripts/`; tests run `python3 -m pytest tests/ -q` from repo root; lint is `ruff check .` (E731: no lambda assignments).
- `--network none` on EVERY `docker run` in both dispatch paths; roslyn-secguard NEVER gets network, including under `--online`.
- No `-e NVD_API_KEY` (or any secret) in any scan-time docker argv.
- `ok_codes`/rc-tolerance semantics (`(0, 1)`) unchanged everywhere.
- Existing tests pin exact argv — update assertions in the same task that changes an argv, never delete them.
- Dockerfile asset steps must keep a secretless local `docker build` succeeding (BuildKit secret optional).
- Spec: `docs/superpowers/specs/2026-08-04-p1-adapter-execution-design.md`. Issue refs: #229, #86, #218, #62.

---

### Task 1: Container policy — `--network none`, no secrets, `--online` gate

**Files:**
- Modify: `skill/scripts/run_tools.py` (docstring lines 1-5; legacy docker argv ~line 130; adapter docker argv ~lines 156-167; `__main__` ~lines 184-206)
- Modify: `skill/scripts/tools/__init__.py` (append constants)
- Test: `tests/test_run_tools.py`

**Interfaces:**
- Consumes: existing `run_tools(target, tools, out_dir, image="panopticon-tools", runner=None)`.
- Produces: `scripts.tools.EXECUTES_TARGET_BUILD = {"roslyn-secguard"}` and `scripts.tools.ONLINE_ONLY = {"pip-audit", "npm-audit"}` (frozensets); `run_tools(..., online=False)` keyword; `rt.filter_online(chosen: list[str], online: bool) -> list[str]`. Task 2 imports `EXECUTES_TARGET_BUILD`; Task 6/7 rely on the argv contract.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_run_tools.py`; also UPDATE `test_run_tools_builds_exact_docker_argv` to expect `["docker", "run", "--rm", "--network", "none", ...]`)

```python
class TestContainment(unittest.TestCase):
    def _calls(self, tools, online=False, env=None):
        calls = []
        class R: returncode = 0; stdout = b'{"runs":[]}'; stderr = b''
        def runner(cmd, **kw):
            calls.append(cmd); return R()
        old = dict(os.environ)
        os.environ.update(env or {})
        try:
            with tempfile.TemporaryDirectory() as d:
                rt.run_tools(d, tools, os.path.join(d, "out"),
                             runner=runner, online=online)
        finally:
            os.environ.clear(); os.environ.update(old)
        return calls

    def test_every_dispatch_has_network_none(self):
        for cmd in self._calls(["semgrep", "cargo-audit"]):
            i = cmd.index("--network")
            self.assertEqual(cmd[i + 1], "none")

    def test_nvd_api_key_never_forwarded(self):
        for cmd in self._calls(["dependency-check"],
                               env={"NVD_API_KEY": "sekrit"}):
            self.assertNotIn("-e", cmd)
            self.assertNotIn("NVD_API_KEY", cmd)

    def test_online_only_adapters_skipped_offline(self):
        calls = self._calls(["pip-audit", "npm-audit", "cargo-audit"])
        joined = [" ".join(c) for c in calls]
        self.assertEqual(len(calls), 1)
        self.assertIn("cargo-audit", joined[0])

    def test_online_flag_dispatches_online_only_with_network(self):
        calls = self._calls(["pip-audit"], online=True)
        self.assertEqual(len(calls), 1)
        self.assertNotIn("--network", calls[0])

    def test_roslyn_never_gets_network_even_online(self):
        calls = self._calls(["roslyn-secguard"], online=True)
        i = calls[0].index("--network")
        self.assertEqual(calls[0][i + 1], "none")

    def test_filter_online_helper(self):
        chosen = ["semgrep", "pip-audit", "npm-audit", "gosec"]
        self.assertEqual(rt.filter_online(chosen, online=False),
                         ["semgrep", "gosec"])
        self.assertEqual(rt.filter_online(chosen, online=True), chosen)
```

- [ ] **Step 2: Run to verify the new tests fail**

Run: `python3 -m pytest tests/test_run_tools.py -q`
Expected: TestContainment errors (`run_tools()` has no `online` kwarg, no `filter_online`); the updated exact-argv test fails on the missing `--network none`.

- [ ] **Step 3: Implement**

In `skill/scripts/tools/__init__.py`, append after `ADAPTERS`:

```python
# Adapters that execute target build logic (contained: no network, no
# secrets, read-only mounts). Recorded in report meta by synthesize.
EXECUTES_TARGET_BUILD = frozenset({"roslyn-secguard"})

# Adapters with no offline mode (live advisory-API clients); dispatched only
# under run_tools --online. Offline substitute: osv-scanner's baked DBs.
ONLINE_ONLY = frozenset({"pip-audit", "npm-audit"})
```

In `skill/scripts/run_tools.py`:

```python
from scripts.tools import ADAPTERS, EXECUTES_TARGET_BUILD, ONLINE_ONLY  # noqa: F401


def filter_online(chosen, online):
    """Drop ONLINE_ONLY adapters unless --online was given, with a notice."""
    if online:
        return list(chosen)
    kept = [t for t in chosen if t not in ONLINE_ONLY]
    for t in chosen:
        if t in ONLINE_ONLY:
            print("adapter %s needs network; skipped (offline substitute: "
                  "osv-scanner). Re-run with --online to include it." % t,
                  file=sys.stderr)
    return kept
```

`run_tools()` gains `online=False` keyword and calls
`tools = filter_online(tools, online)` first. Both docker argv builders become:

```python
docker = ["docker", "run", "--rm"]
if tool not in ONLINE_ONLY:
    docker.extend(["--network", "none"])
```

(ONLINE_ONLY tools only reach dispatch when `online=True`, so no second
condition is needed; roslyn-secguard is not in ONLINE_ONLY, hence always
`--network none`.) Delete the `if os.environ.get("NVD_API_KEY"): docker.extend(["-e", "NVD_API_KEY"])` block entirely. In `__main__`: `ap.add_argument("--online", action="store_true", help="allow pip-audit/npm-audit to reach their advisory APIs")` and pass `online=a.online` to `run_tools`. Rewrite the module docstring lines 1-5:

```python
"""Detect the panopticon-tools Docker image and run selected scanners against a
read-only mount of the target. Scan-time network is DISABLED for all tools
(assets are baked into the image); parse-only adapters never execute target
code; roslyn-secguard executes target build logic inside a no-egress,
no-secret container (recorded in report meta); pip-audit/npm-audit run only
under --online. Degrades gracefully when Docker is absent. Stdlib-only.
"""
```

- [ ] **Step 4: Run the full suite**

Run: `python3 -m pytest tests/ -q && ruff check .`
Expected: all pass (any other test pinning docker argv updated in this step).

- [ ] **Step 5: Commit**

```bash
git add skill/scripts/run_tools.py skill/scripts/tools/__init__.py tests/test_run_tools.py
git commit -m "feat(containment): --network none everywhere, no scan-time secrets, --online gate (#62, #229)"
```

---

### Task 2: `meta.build_executing_tools` in synthesize

**Files:**
- Modify: `skill/scripts/synthesize.py` (`build_report`'s meta dict, ~line 678-696)
- Test: `tests/test_synthesize.py`

**Interfaces:**
- Consumes: `scripts.tools.EXECUTES_TARGET_BUILD` (Task 1). Findings carry `source: "tool:<name>"` already.
- Produces: `meta["build_executing_tools"]: sorted list[str]` — present (possibly empty) in every report.

- [ ] **Step 1: Write the failing test** (append to `tests/test_synthesize.py`, using the file's existing minimal-finding fixture helpers — read neighboring tests first and reuse their construction pattern)

```python
class TestBuildExecutingTools(unittest.TestCase):
    def test_meta_records_build_executing_tool(self):
        f = _finding(source="tool:roslyn-secguard")   # reuse the module's helper
        report = synth.build_report([f], [])
        self.assertEqual(report["meta"]["build_executing_tools"],
                         ["roslyn-secguard"])

    def test_meta_empty_without_executing_tools(self):
        f = _finding(source="tool:bandit")
        report = synth.build_report([f], [])
        self.assertEqual(report["meta"]["build_executing_tools"], [])
```

(If `test_synthesize.py` has no `_finding` helper, use whatever minimal-report
construction its `meta`-asserting tests use — e.g. the ones pinning
`meta.version` at lines ~1194/1479 — and match `build_report`'s real
signature.)

- [ ] **Step 2: Run to verify failure** — `python3 -m pytest tests/test_synthesize.py -q` → KeyError `build_executing_tools`.

- [ ] **Step 3: Implement** — in `build_report`, alongside the existing meta fields:

```python
from scripts.tools import EXECUTES_TARGET_BUILD

tool_names = {str(f.get("source", ""))[5:] for f in findings
              if str(f.get("source", "")).startswith("tool:")}
meta["build_executing_tools"] = sorted(tool_names & EXECUTES_TARGET_BUILD)
```

(Place the import at module top with the existing imports; if importing
`scripts.tools` triggers adapter imports that synthesize's test env lacks,
import the constant from a shared location instead — but adapters are
stdlib-only, so the direct import is expected to work.)

- [ ] **Step 4: Run the full suite** — `python3 -m pytest tests/ -q` → all pass (schema validation is advisory; still check `skill/reference/report-schema.json` — if `meta` has `additionalProperties: false`, add `build_executing_tools` as `{"type": "array", "items": {"type": "string"}}`).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(meta): record build-executing tools in report meta (#229)"`

---

### Task 3: SCS-only parse filter in roslyn-secguard

**Files:**
- Modify: `skill/scripts/tools/roslyn_secguard.py` (`parse()`, lines 109-142)
- Test: `tests/tools/test_roslyn_secguard.py`

**Interfaces:**
- Consumes: nothing new. Produces: `parse()` emits only results whose `ruleId` starts with `"SCS"`.

- [ ] **Step 1: Write the failing test** (append; reuse the file's existing SARIF fixture style)

```python
MIXED_SARIF = json.dumps({
    "runs": [{"results": [
        {"ruleId": "SCS0002",
         "message": {"text": "SQL injection"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "a.cs"},
             "region": {"startLine": 3}}}]},
        {"ruleId": "CS0246",
         "message": {"text": "type not found: leaked /etc/passwd content"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "b.cs"},
             "region": {"startLine": 1}}}]},
    ]}]
}).encode()


class TestScsOnlyFilter(unittest.TestCase):
    def test_non_scs_results_are_dropped(self):
        found = rs.RoslynSecGuardAdapter().parse(MIXED_SARIF, "g")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["tool_evidence"]["rule_id"], "SCS0002")
```

- [ ] **Step 2: Run to verify failure** — `python3 -m pytest tests/tools/test_roslyn_secguard.py -q` → assertion: 2 findings, expected 1.

- [ ] **Step 3: Implement** — in `parse()`'s result loop, immediately after `rule_id = result.get("ruleId", "")`:

```python
                # Only SecurityCodeScan rules are findings. Compiler/restore
                # diagnostics (CS####, NU####, MSB####) are dropped: they are
                # noise from offline builds and can quote file content into
                # the report (the #86 exfiltration channel).
                if not rule_id.startswith("SCS"):
                    continue
```

- [ ] **Step 4: Run** — `python3 -m pytest tests/tools/ -q` → pass (update any existing fixture-based count assertions if they used non-SCS rule ids).

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(roslyn): SCS-only parse filter — drop compiler diagnostics (#86, #229)"`

---

### Task 4: Symlink-guarded copy in roslyn-secguard

**Files:**
- Modify: `skill/scripts/tools/roslyn_secguard.py` (`invoke()`, line 58 area; new module-level helper)
- Test: `tests/tools/test_roslyn_secguard.py`

**Interfaces:**
- Produces: `_safe_copytree(src: str, dst: str) -> int` (returns count of skipped out-of-tree symlinks; copies in-tree links as links; never follows links during traversal). `invoke()` calls it instead of `shutil.copytree(target, tmp, dirs_exist_ok=True)`.

- [ ] **Step 1: Write the failing tests** (append)

```python
class TestSafeCopytree(unittest.TestCase):
    def _tree(self, d):
        os.makedirs(os.path.join(d, "src", "sub"))
        with open(os.path.join(d, "src", "app.csproj"), "w") as fh:
            fh.write("<Project/>")
        with open(os.path.join(d, "outside.txt"), "w") as fh:
            fh.write("SECRET")
        return os.path.join(d, "src")

    def test_out_of_tree_symlink_is_skipped_and_counted(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._tree(d)
            os.symlink(os.path.join(d, "outside.txt"),
                       os.path.join(src, "leak.cs"))
            dst = os.path.join(d, "dst")
            skipped = rs._safe_copytree(src, dst)
            self.assertEqual(skipped, 1)
            self.assertFalse(os.path.lexists(os.path.join(dst, "leak.cs")))
            self.assertTrue(os.path.exists(os.path.join(dst, "app.csproj")))

    def test_in_tree_symlink_copied_as_link(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._tree(d)
            os.symlink("app.csproj", os.path.join(src, "alias.csproj"))
            dst = os.path.join(d, "dst")
            self.assertEqual(rs._safe_copytree(src, dst), 0)
            self.assertTrue(os.path.islink(os.path.join(dst, "alias.csproj")))

    def test_dangling_symlink_does_not_abort(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._tree(d)
            os.symlink(os.path.join(d, "gone.txt"),
                       os.path.join(src, "dangling.cs"))
            dst = os.path.join(d, "dst")
            skipped = rs._safe_copytree(src, dst)   # must not raise
            self.assertEqual(skipped, 1)

    def test_symlink_loop_terminates(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._tree(d)
            os.symlink(src, os.path.join(src, "sub", "loop"))
            dst = os.path.join(d, "dst")
            rs._safe_copytree(src, dst)             # must return, not recurse
            self.assertTrue(os.path.exists(os.path.join(dst, "sub")))
```

- [ ] **Step 2: Run to verify failure** — `python3 -m pytest tests/tools/test_roslyn_secguard.py -q` → AttributeError `_safe_copytree`.

- [ ] **Step 3: Implement** (module level, above the class; then in `invoke()` replace line 58 with `skipped = _safe_copytree(target, tmp)` and after it `if skipped: print("roslyn-secguard: skipped %d out-of-tree symlink(s)" % skipped, file=sys.stderr)` — add `import sys` to the module imports)

```python
def _safe_copytree(src, dst):
    """Copy src into dst without dereferencing symlinks.

    Out-of-tree symlinks (resolved target escapes src, including dangling
    links) are skipped and counted — a scanned repo must not be able to pull
    /etc/passwd or the mounted scripts dir into the build tree (#86).
    In-tree links are preserved as links. Never follows links while walking,
    so link loops cannot recurse.
    """
    root = os.path.realpath(src)
    skipped = 0
    os.makedirs(dst, exist_ok=True)
    for cur, dirs, files in os.walk(src, followlinks=False):
        rel = os.path.relpath(cur, src)
        out_dir = dst if rel == "." else os.path.join(dst, rel)
        os.makedirs(out_dir, exist_ok=True)
        for name in list(dirs) + files:
            s = os.path.join(cur, name)
            d = os.path.join(out_dir, name)
            if os.path.islink(s):
                real = os.path.realpath(s)
                if real == root or real.startswith(root + os.sep):
                    os.symlink(os.readlink(s), d)
                else:
                    skipped += 1
                if name in dirs:
                    dirs.remove(name)   # never walk through a link
            elif name in files:
                shutil.copy2(s, d)
    return skipped
```

- [ ] **Step 4: Run** — `python3 -m pytest tests/tools/ -q` → pass. The existing `test_invoke_builds_in_temp_copy` monkeypatches `rs.shutil.copytree`; repoint its fake at `rs._safe_copytree` (return `0`) in this step.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(roslyn): symlink-guarded copy — skip out-of-tree links, tolerate dangling, no loops (#86)"`

---

### Task 5: pip-audit static pyproject parse

**Files:**
- Modify: `skill/scripts/tools/pip_audit.py` (`invoke()` else-branch, lines 36-42; new helper)
- Test: `tests/tools/test_pip_audit.py`

**Interfaces:**
- Produces: `_deps_from_pyproject(target: str) -> list[str] | None` (PEP 508 strings from `[project.dependencies]` + flattened `[project.optional-dependencies]`; `None` when the file/table is missing or `dependencies` is listed in `project.dynamic`). `invoke()` never passes the target directory positionally.

- [ ] **Step 1: Write the failing tests** (append; match the file's existing mock style)

```python
PYPROJECT_STATIC = b"""
[project]
name = "x"
dependencies = ["requests==2.25.1", "urllib3>=1.26"]
[project.optional-dependencies]
dev = ["pytest"]
"""

PYPROJECT_DYNAMIC = b"""
[project]
name = "x"
dynamic = ["dependencies"]
"""


class TestStaticPyproject(unittest.TestCase):
    def _target(self, content):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "pyproject.toml"), "wb") as fh:
            fh.write(content)
        return d

    def test_static_deps_extracted(self):
        deps = pa._deps_from_pyproject(self._target(PYPROJECT_STATIC))
        self.assertEqual(deps,
                         ["requests==2.25.1", "urllib3>=1.26", "pytest"])

    def test_dynamic_deps_return_none(self):
        self.assertIsNone(
            pa._deps_from_pyproject(self._target(PYPROJECT_DYNAMIC)))

    def test_invoke_uses_requirement_file_not_positional(self):
        target = self._target(PYPROJECT_STATIC)
        captured = {}
        def fake_run_tool(cmd, timeout=0):
            captured["cmd"] = list(cmd)
            with open(cmd[cmd.index("--requirement") + 1]) as fh:
                captured["reqs"] = fh.read()
            return b"{}", 0
        with mock.patch.object(pa, "run_tool", fake_run_tool):
            pa.PipAuditAdapter().invoke(target)
        self.assertNotIn(target, captured["cmd"])
        self.assertIn("requests==2.25.1", captured["reqs"])

    def test_invoke_dynamic_pyproject_returns_empty_without_running(self):
        target = self._target(PYPROJECT_DYNAMIC)
        with mock.patch.object(pa, "run_tool") as rt_mock:
            raw, rc = pa.PipAuditAdapter().invoke(target)
        rt_mock.assert_not_called()
        self.assertEqual((json.loads(raw), rc),
                         ({"dependencies": [], "fixes": []}, 0))
```

- [ ] **Step 2: Run to verify failure** — `python3 -m pytest tests/tools/test_pip_audit.py -q` → AttributeError `_deps_from_pyproject`.

- [ ] **Step 3: Implement** (add `import json`, `import sys`, `import tempfile`, `import tomllib` to the module; replace the `else:` branch of `invoke()`)

```python
def _deps_from_pyproject(target):
    """Static PEP 621 read — never invokes a build backend (#218)."""
    path = os.path.join(target, "pyproject.toml")
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    project = data.get("project")
    if not isinstance(project, dict):
        return None
    if "dependencies" in (project.get("dynamic") or []):
        return None
    deps = list(project.get("dependencies") or [])
    for extra in (project.get("optional-dependencies") or {}).values():
        deps.extend(extra)
    return deps
```

In `invoke()`:

```python
        else:
            # Never pass the project directory positionally: resolving a
            # source tree can invoke its PEP 517 build backend (#218).
            deps = _deps_from_pyproject(target)
            if not deps:
                print("pip-audit: no static [project.dependencies] in %s; "
                      "skipping (osv-scanner covers this target)" % target,
                      file=sys.stderr)
                return b'{"dependencies": [], "fixes": []}', 0
            self._manifest_path = os.path.join(target, "pyproject.toml")
            tmp = tempfile.NamedTemporaryFile(
                "w", suffix=".txt", delete=False)
            try:
                tmp.write("\n".join(deps) + "\n")
                tmp.close()
                cmd.extend(["--requirement", tmp.name])
                return run_tool(cmd, timeout=300)
            finally:
                os.unlink(tmp.name)
        return run_tool(cmd, timeout=300)
```

(The final `return run_tool(...)` serves the `requirements*.txt` branch;
delete the old shared trailing return if restructuring makes it dead. The
existing test pinning the positional argv — `test_pip_audit.py:121-133` per
the run-2 advisor — is UPDATED by this task to expect the new behavior, not
deleted.)

- [ ] **Step 4: Run** — `python3 -m pytest tests/tools/test_pip_audit.py -q && python3 -m pytest tests/ -q` → pass.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(pip-audit): static tomllib parse replaces positional-project fallback (#218)"`

---

### Task 6: Offline flags — TOOL_CMD and per-adapter argv

**Files:**
- Modify: `skill/scripts/tools/legacy_sarif.py` (TOOL_CMD semgrep/trivy entries)
- Modify: `skill/scripts/tools/cargo_audit.py:51`, `skill/scripts/tools/bundler_audit.py:28`, `skill/scripts/tools/osv_scanner.py:35`, `skill/scripts/tools/dependency_check.py` (invoke cmd)
- Test: each adapter's existing test file (argv-pinning tests) + `tests/test_run_tools.py` if it pins TOOL_CMD

**Interfaces:** none new — argv contents only.

- [ ] **Step 1: Update the argv-pinning tests first** (each adapter's test that asserts the exact command; add where missing)

Expected new argvs:

```python
TOOL_CMD["semgrep"] == ["semgrep", "scan", "--config", "/opt/semgrep-rules",
                        "--metrics=off", "--sarif", "--quiet", "/src"]
TOOL_CMD["trivy"]   == ["trivy", "fs", "--skip-db-update", "--offline-scan",
                        "--format", "sarif", "/src"]
# cargo_audit.py:  ["cargo", "audit", "--no-fetch", "--format", "json"]
# bundler_audit.py: ["bundle-audit", "check", "--no-update"]
# osv_scanner.py:  ["osv-scanner", "--format", "json", "--offline",
#                   "--recursive", target]
# dependency_check.py: cmd always contains "--noupdate" and
#                      ["--data", "/opt/odc-data"]
```

- [ ] **Step 2: Run to verify the updated tests fail** — `python3 -m pytest tests/tools/ tests/test_run_tools.py -q`.

- [ ] **Step 3: Implement** — apply exactly the argv changes above. In `dependency_check.py`, make `--noupdate` unconditional and add `--data /opt/odc-data`; remove any NVD-key-dependent branching from the adapter (read the file first — the existing conditional `--noupdate` at ~line 34 collapses into the unconditional form).

- [ ] **Step 4: Run** — `python3 -m pytest tests/ -q && ruff check .` → pass.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(offline): scan-time offline flags for semgrep/trivy/cargo/bundler/osv/odc (#62)"`

---

### Task 7: Image assets, NuGet offline feed, weekly publish

**Files:**
- Modify: `Dockerfile` (asset-bake steps before `USER scanner`, ~line 103)
- Modify: `.github/workflows/docker-publish.yml` (add `schedule` trigger; BuildKit secret)
- Test: `tests/test_dockerfile.py` (substring pins)

**Interfaces:** paths consumed by Task 6's argv: `/opt/semgrep-rules`, `/opt/odc-data`; NuGet feed at `/opt/nuget-packages`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_dockerfile.py`, same substring style as the existing two tests)

```python
class TestOfflineAssets(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), os.pardir,
                               "Dockerfile")) as fh:
            self.text = fh.read()

    def test_offline_assets_baked(self):
        for marker in ["--download-db-only",          # trivy DB
                       "/opt/semgrep-rules",           # vendored rules
                       "advisory-db",                  # rustsec clone
                       "--download-offline-databases", # osv
                       "/opt/odc-data",                # dependency-check
                       "/opt/nuget-packages",          # SCS offline feed
                       "fallbackPackageFolders"]:      # nuget.config wiring
            self.assertIn(marker, self.text)

    def test_nvd_key_is_buildkit_secret_not_env(self):
        self.assertIn("--mount=type=secret,id=nvd_api_key", self.text)
        self.assertNotIn("ENV NVD_API_KEY", self.text)

    def test_publish_cadence_and_tags(self):
        with open(os.path.join(os.path.dirname(__file__), os.pardir,
                               ".github", "workflows",
                               "docker-publish.yml")) as fh:
            wf = fh.read()
        self.assertIn('cron: "0 6 * * *"', wf)      # daily asset refresh
        self.assertIn("workflow_dispatch", wf)
        self.assertIn("promote_weekly", wf)          # emergency weekly bump
        self.assertIn("value=daily", wf)
        self.assertIn("value=weekly", wf)
        self.assertIn("ASSET_REFRESH", wf)           # cache-bust build-arg

    def test_dockerfile_has_asset_refresh_arg(self):
        self.assertIn("ARG ASSET_REFRESH", self.text)
```

- [ ] **Step 2: Run to verify failure** — `python3 -m pytest tests/test_dockerfile.py -q`.

- [ ] **Step 3: Implement the Dockerfile asset block** (insert before the `useradd` block at ~line 103; adjust ownership so the `scanner` user can read; exact tool flags may be corrected against installed versions, but the marker strings in Step 1 must remain literally present)

```dockerfile
# ---- Offline scan assets (P1: zero scan-time egress; spec 2026-08-04) ----
# Cache boundary: everything ABOVE this ARG stays layer-cached across daily
# builds; every asset fetch BELOW rebuilds when the workflow passes a new
# run date. Secretless local builds keep the stable default (cached).
ARG ASSET_REFRESH=local
# Trivy vulnerability DB
RUN TRIVY_CACHE_DIR=/opt/trivy-cache trivy --cache-dir /opt/trivy-cache \
    image --download-db-only && chmod -R a+r /opt/trivy-cache
ENV TRIVY_CACHE_DIR=/opt/trivy-cache

# Semgrep rules: vendor the default registry pack (closest offline
# equivalent of --config auto). Additional packs: none (P1 decision).
RUN mkdir -p /opt/semgrep-rules \
    && semgrep --config p/default --dry-run --metrics=off /tmp \
       > /dev/null 2>&1 || true \
    && cp -r /root/.semgrep/semgrep_rules* /opt/semgrep-rules/ 2>/dev/null \
       || semgrep_rules_fallback=1
# (implementation verifies the cache path inside the image and may replace
#  the cp with the correct vendored location; /opt/semgrep-rules must end up
#  holding runnable rule files)

# RustSec advisory DB for cargo-audit --no-fetch
RUN git clone --depth 1 https://github.com/rustsec/advisory-db \
    /home/scanner/.cargo/advisory-db

# OSV offline databases (ecosystems covered by the fixture corpus)
RUN osv-scanner --download-offline-databases \
    --experimental-download-offline-databases-path /opt/osv-db || \
    osv-scanner --offline --download-offline-databases /tmp/empty || true
ENV OSV_SCANNER_LOCAL_DB_PATH=/opt/osv-db

# dependency-check NVD data (BuildKit secret; build works without it, slower)
RUN --mount=type=secret,id=nvd_api_key \
    KEY="$(cat /run/secrets/nvd_api_key 2>/dev/null || true)"; \
    /opt/dependency-check/bin/dependency-check.sh --updateonly \
      --data /opt/odc-data ${KEY:+--nvdApiKey "$KEY"} \
    && chmod -R a+r /opt/odc-data

# SecurityCodeScan offline NuGet feed: warm a package folder via a throwaway
# project (the root /Directory.Build.props injects the analyzer reference),
# then pin restore to it via fallbackPackageFolders.
RUN mkdir -p /tmp/warm && cd /tmp/warm \
    && dotnet new classlib -o warmproj --no-restore \
    && dotnet restore warmproj --packages /opt/nuget-packages \
    && rm -rf /tmp/warm
RUN printf '%s\n' \
    '<?xml version="1.0" encoding="utf-8"?>' \
    '<configuration>' \
    '  <packageSources><clear /></packageSources>' \
    '  <fallbackPackageFolders>' \
    '    <add key="baked" value="/opt/nuget-packages" />' \
    '  </fallbackPackageFolders>' \
    '</configuration>' > /nuget.config
```

Notes for the implementer, binding: every `RUN` above must leave the asset
readable by uid 1000; verify each tool's real flag spelling inside the built
image (`docker run --rm --network none panopticon-tools <tool> --help`) and
correct the Dockerfile if a flag differs — the unit-test markers in Step 1
are the stable contract, chosen to survive spelling fixes. The `|| true`
fallbacks exist only where a tool's CLI differs across versions; the Section
6 offline fixture check (Task 8) is what proves the assets actually work.

- [ ] **Step 4: Implement the workflow change** — in `docker-publish.yml`:

In the `on:` block, add the daily schedule and extend `workflow_dispatch`
(it already exists — it is the emergency manual push):

```yaml
  schedule:
    - cron: "0 6 * * *"   # daily asset refresh (06:00 UTC)
  workflow_dispatch:
    inputs:
      promote_weekly:
        description: "Also move the :weekly tag"
        type: boolean
        default: false
```

Add a cadence step BEFORE the metadata step:

```yaml
      - name: Compute cadence
        id: cadence
        run: |
          echo "weekly=$([ "$(date -u +%u)" = "1" ] && echo true || echo false)" >> "$GITHUB_OUTPUT"
          echo "date=$(date -u +%F)" >> "$GITHUB_OUTPUT"
```

Replace the metadata-action `tags:` list (consumers choose cadence by tag;
`:latest` stays as the back-compat alias of daily — `security.yml` is
unchanged):

```yaml
          tags: |
            type=raw,value=latest,enable={{is_default_branch}}
            type=raw,value=daily,enable={{is_default_branch}}
            type=raw,value=weekly,enable=${{ (github.event_name == 'schedule' && steps.cadence.outputs.weekly == 'true') || inputs.promote_weekly == true }}
            type=sha,prefix=,suffix=,format=short
```

In the build step add the BuildKit secret and the cache-bust build-arg:

```yaml
          build-args: |
            ASSET_REFRESH=${{ steps.cadence.outputs.date }}
          secrets: |
            nvd_api_key=${{ secrets.NVD_API_KEY }}
```

- [ ] **Step 5: Run** — `python3 -m pytest tests/test_dockerfile.py -q` → pass. Then, if Docker is available locally: `docker build -t panopticon-tools . 2>&1 | tail -5` (secretless build must succeed; report SKIPPED with the reason if Docker is unavailable in the execution environment — do not fake it).

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(image): bake offline scan assets, NuGet fallback feed, weekly publish (#62, #229)"`

---

### Task 8: Hostile C# fixture and invariant docs

**Files:**
- Create: `tests/fixtures/hostile-csproj/evil.csproj`, `tests/fixtures/hostile-csproj/Program.cs`
- Modify: `tests/fixtures/manifest.json` (add entry)
- Create: `tests/tools/test_hostile_csproj.py` (skip-gated integration test, same pattern as `test_csharp_integration.py`)
- Modify: `DEVELOPMENT.md:55-56` (invariant rewrite)

**Interfaces:** none consumed by later tasks (terminal task).

- [ ] **Step 1: Create the fixture**

`tests/fixtures/hostile-csproj/evil.csproj`:

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <OutputType>Library</OutputType>
  </PropertyGroup>
  <!-- Containment probe: this target MUST execute (contained-not-prevented)
       but its egress MUST fail and its marker MUST stay inside the temp
       build tree, never the mounted target. -->
  <Target Name="Hostile" BeforeTargets="Build">
    <Exec Command="curl -s -m 5 https://example.com/ -o /tmp/egress-ok || true" />
    <Exec Command="touch /tmp/hostile-marker" />
  </Target>
</Project>
```

`tests/fixtures/hostile-csproj/Program.cs` (one genuine SCS-detectable flaw —
SCS0005 weak random, no framework dependencies so the offline build compiles):

```csharp
using System;

public static class Hostile
{
    public static int Token()
    {
        var rng = new Random();      // SCS0005: weak random for a token
        return rng.Next();
    }
}
```

Add to `tests/fixtures/manifest.json` (matching the existing entry shape —
read the file first):

```json
{"name": "hostile-csproj", "language": "csharp",
 "path": "tests/fixtures/hostile-csproj"}
```

- [ ] **Step 2: Write the skip-gated integration test**

```python
# tests/tools/test_hostile_csproj.py
"""Containment probe (P1): the hostile fixture's Exec targets run inside the
no-egress container; egress must fail and findings must still parse. Runs
only where the fixture and the roslyn adapter are usable (dev-local, like
test_csharp_integration.py)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                                os.pardir, os.pardir, "skill"))
from scripts.tools import ADAPTERS

FIXTURE = os.path.join(os.path.dirname(__file__), os.pardir,
                       "fixtures", "hostile-csproj")


class TestHostileCsproj(unittest.TestCase):
    def test_contained_build_still_yields_scs_findings(self):
        adapter = ADAPTERS["roslyn-secguard"]
        if not os.path.isdir(FIXTURE):
            self.skipTest("hostile-csproj fixture missing")
        if not adapter.is_applicable(FIXTURE):
            self.skipTest("no csproj visible")
        try:
            raw, rc = adapter.invoke(FIXTURE)
        except FileNotFoundError:
            self.skipTest("dotnet not installed on this host")
        self.assertIn(rc, (0, 1))
        findings = adapter.parse(raw, "g")
        # Every finding is SCS (Task 3 filter); the Exec noise never lands.
        for f in findings:
            self.assertTrue(
                f["tool_evidence"]["rule_id"].startswith("SCS"))


if __name__ == "__main__":
    unittest.main()
```

(The egress/marker assertions are container-level and live in the manual
verification below — this unit-level test proves the parse contract wherever
dotnet exists. On hosts without dotnet it skips, like the other integration
tests.)

- [ ] **Step 3: Manual containment verification** (run where Docker + the rebuilt image exist; record output in the task report — SKIPPED with reason if unavailable, never faked)

```bash
docker build -t panopticon-tools . \
  && python3 skill/scripts/run_tools.py --target tests/fixtures/hostile-csproj \
       --out /tmp/p1-probe --tools roslyn-secguard \
  && python3 - <<'EOF'
import json
d = json.load(open("/tmp/p1-probe/roslyn-secguard.sarif"))
rules = [r.get("ruleId") for run in d.get("runs", []) for r in run.get("results", [])]
print("rules:", rules)
EOF
```

Expected: the run completes with `--network none` (egress curl fails inside),
and the SARIF contains SCS rules only.

Then the spec's Section-2 contract — every baked adapter yields findings
offline — against the in-repo fixtures:

```bash
python3 skill/scripts/run_tools.py --target tests/fixtures/vulnerable-rust \
  --out /tmp/p1-offline --tools cargo-audit
python3 skill/scripts/run_tools.py --target tests/fixtures/vulnerable-node \
  --out /tmp/p1-offline --tools osv-scanner
python3 skill/scripts/run_tools.py --target tests/fixtures/vulnerable-python \
  --out /tmp/p1-offline --tools bandit semgrep trivy
ls -la /tmp/p1-offline   # every named tool wrote a non-empty output file
```

Expected: non-empty outputs for each tool with zero network. Any empty output
means a baked asset is broken — fix the Task 7 Dockerfile step before
proceeding.

- [ ] **Step 4: Rewrite the invariant** — `DEVELOPMENT.md:55-56` becomes:

```markdown
- **Scan-time network is disabled** (`--network none` on every tool run):
  advisory/rules data is baked into the tools image (weekly rebuild).
  Parse-only adapters never execute target code. roslyn-secguard executes
  target build logic inside the no-egress, no-secret, read-only-mount
  container — the report records it in `meta.build_executing_tools`.
  pip-audit/npm-audit run only under `run_tools.py --online`.
```

(Adjust surrounding list formatting to match the file; keep the old line's
anchor position so other references stay valid.)

- [ ] **Step 5: Run everything** — `python3 -m pytest tests/ -q && ruff check .` → pass (new integration test skips without dotnet).

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(fixtures): hostile-csproj containment probe + invariant rewrite (#229, #62)"`
