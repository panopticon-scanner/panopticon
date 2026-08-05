# P2 Run Integrity and Gate Trust Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make verify-queue identity content-addressed instead of positional,
and make only *verified* findings gate — per
`docs/superpowers/specs/2026-08-05-p2-run-integrity-design.md`.

**Architecture:** `finding_fingerprint` moves into `evidence.py` so the queue
can key on it; `derive_evidence` inverts precedence (verdict before source) and
gains a `tool_reported` status; `build_verify_queue` queues every finding,
sorts on content only, and uses the fingerprint as `queue_id`; both synthesize
passes share one `prepare_for_queue` pipeline; `meta` gains `tool_axis` and an
honest `build_executing_tools`.

**Tech Stack:** Python 3 stdlib only, unittest-style tests under `tests/`.

## Global Constraints

- Branch: `feat/p2-run-integrity`; nothing merges to main except by PR. `gh`/`git` network commands need `export GH_CONFIG_DIR="$HOME/.config/gh-psyberone"`; the repo is now `panopticon-scanner/panopticon`.
- Python 3 stdlib only in `skill/scripts/`. Run tests from repo root: `python3 -m pytest tests/ -q`; lint `ruff check .` (no lambda assignments — E731).
- Severity is NEVER mutated by the pipeline. The two-axis invariant stands: `severity` = impact if true, `evidence.status` = how hard it was checked.
- `evidence.status` values after this package: `tool_reported`, `tool_confirmed`, `advisor_confirmed`, `corroborated`, `needs_more_info`, `unverified`, `rejected`.
- `GATE_ELIGIBLE_DEFAULT` stays exactly `frozenset({"tool_confirmed", "advisor_confirmed"})` — the tightening comes from `tool_confirmed` now REQUIRING an advisor CONFIRMED verdict, not from editing the gate set.
- `--gate-unverified` behavior is unchanged; it remains the documented escape hatch.
- Existing tests are UPDATED, never deleted. Any test asserting the old `NNN-FINDING-ID` queue_id format is rewritten to the fingerprint contract.
- Spec: `docs/superpowers/specs/2026-08-05-p2-run-integrity-design.md`. Issues: #443, #446, #450, #438.

---

### Task 1: Move fingerprint identity into `evidence.py`

Pure move, no behavior change. `evidence.build_verify_queue` (Task 3) needs
`finding_fingerprint`, and `evidence.py` cannot import `synthesize.py`
(`synthesize` already imports `evidence` as `evidence_mod` — the reverse would
be circular).

**Files:**
- Modify: `skill/scripts/evidence.py` (add `import hashlib`; add two functions)
- Modify: `skill/scripts/synthesize.py` (delete the two defs at ~515-529 and ~532-553; add aliases)
- Test: `tests/test_synthesize.py` (unchanged — must still pass via the aliases)

**Interfaces:**
- Produces: `evidence.tool_rule_id(finding) -> str | None`, `evidence.finding_fingerprint(finding) -> str` (16 hex chars). `synthesize.tool_rule_id` and `synthesize.finding_fingerprint` remain valid names via module-level aliases.
- Consumes: `evidence.is_tool_sourced` (already present).

- [ ] **Step 1: Write the failing test** (append to `tests/test_evidence.py`)

```python
class TestFingerprintMoved(unittest.TestCase):
    def _f(self, **over):
        f = {"id": "SEC-1", "panel": "security", "category": "injection",
             "title": "SQL injection", "location": {"file": "a.py",
                                                    "line_start": 3}}
        f.update(over)
        return f

    def test_fingerprint_is_stable_hex(self):
        fp = ev.finding_fingerprint(self._f())
        self.assertEqual(len(fp), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in fp))

    def test_fingerprint_ignores_line_number(self):
        a = ev.finding_fingerprint(self._f())
        b = ev.finding_fingerprint(
            self._f(location={"file": "a.py", "line_start": 99}))
        self.assertEqual(a, b)

    def test_tool_rule_id_reads_both_adapter_families(self):
        self.assertEqual(
            ev.tool_rule_id({"tool_evidence": {"rule_id": "B105"}}), "B105")
        self.assertEqual(
            ev.tool_rule_id({"provenance": {"confirmation_reasoning": "SCS0005"}}),
            "SCS0005")
        self.assertIsNone(ev.tool_rule_id({}))

    def test_synthesize_aliases_still_resolve(self):
        import scripts.synthesize as syn
        self.assertIs(syn.finding_fingerprint, ev.finding_fingerprint)
        self.assertIs(syn.tool_rule_id, ev.tool_rule_id)
```

(`tests/test_evidence.py` already imports the module — match its existing
import alias; the tests above assume `ev`. If the file binds a different
name, use that name and keep the assertions identical.)

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_evidence.py -q`
Expected: AttributeError — `evidence` has no `finding_fingerprint`.

- [ ] **Step 3: Implement the move**

In `skill/scripts/evidence.py`, add `import hashlib` to the imports, then add
both functions (place them after `is_tool_sourced`, whose definition they use):

```python
def tool_rule_id(finding):
    """The scanner rule a tool finding came from, wherever its adapter put it.

    Two adapter families disagree: the dependency scanners (pip_audit,
    bundler_audit, dependency_check, eslint_security) set
    `tool_evidence.rule_id`, while everything on the SARIF path (bandit,
    semgrep, trivy, ...) sets no tool_evidence at all and carries the rule id
    in `provenance.confirmation_reasoning` via attach_tool_provenance. Reading
    only the first form made every SARIF finding look rule-less, which silently
    disabled both aggregation and rule-based fingerprint identity for them.
    """
    rule = (finding.get("tool_evidence") or {}).get("rule_id")
    if rule:
        return rule
    return (finding.get("provenance") or {}).get("confirmation_reasoning") or None


def finding_fingerprint(finding):
    """Stable cross-run identity for a finding.

    Keys on panel + category + normalized file + the discriminator that is
    actually stable for that source: a tool's rule_id, or an agent finding's
    title. Deliberately EXCLUDES line numbers (issues survive code moves) and
    free-text description (agent prose is re-worded every run). Also the
    verify-queue's queue_id (P2) — the same identity both passes compute.
    """
    loc = finding.get("location") or {}
    fpath = str(loc.get("file") or "").replace("\\", "/")
    # Strip only a `./` prefix. `lstrip("./")` would eat the leading dot of
    # every dotfile path, collapsing `.github/x` onto `github/x`.
    while fpath.startswith("./"):
        fpath = fpath[2:]
    # Gate on tool-sourcing: on an AGENT finding, confirmation_reasoning holds
    # advisor prose, which would be a disastrous identity discriminator.
    rule = tool_rule_id(finding) if is_tool_sourced(finding) else None
    discriminator = str(rule) if rule else str(finding.get("title") or "")
    payload = "|".join([str(finding.get("panel") or ""),
                        str(finding.get("category") or ""),
                        fpath, discriminator]).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]
```

In `skill/scripts/synthesize.py`: DELETE the existing `def tool_rule_id(...)`
and `def finding_fingerprint(...)` bodies, and add aliases beside the existing
`load_json_tolerant = evidence_mod.load_json_tolerant` line (that alias is the
established precedent for functions that moved to `evidence.py`):

```python
tool_rule_id = evidence_mod.tool_rule_id
finding_fingerprint = evidence_mod.finding_fingerprint
```

Note: synthesize's remaining `_is_tool_sourced` helper stays where it is —
other call sites use it, and it is behaviorally identical to
`evidence.is_tool_sourced` (both test `source` startswith `"tool:"`).

- [ ] **Step 4: Run the full suite**

Run: `python3 -m pytest tests/ -q && ruff check .`
Expected: all pass, unchanged counts — this task adds tests but changes no behavior.

- [ ] **Step 5: Commit**

```bash
git add skill/scripts/evidence.py skill/scripts/synthesize.py tests/test_evidence.py
git commit -m "refactor(evidence): move fingerprint identity into evidence.py (#443)"
```

---

### Task 2: `tool_reported` status and precedence inversion

**Files:**
- Modify: `skill/scripts/evidence.py` (`EVIDENCE_STATUSES`, `derive_evidence`)
- Modify: `skill/reference/report-schema.json` (status enum ~line 113; `evidence_stats` properties ~lines 44-49)
- Modify: `skill/SKILL.md` (evidence-axis list ~lines 120-126)
- Test: `tests/test_evidence.py`

**Interfaces:**
- Consumes: nothing from Task 1 beyond the module.
- Produces: status `"tool_reported"` in `EVIDENCE_STATUSES`; `derive_evidence(finding, verdict=None)` with verdict-first precedence. Task 3 relies on `derive_evidence` no longer short-circuiting on tool-sourcing; Task 5 counts `tool_reported`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_evidence.py`)

```python
class TestToolReported(unittest.TestCase):
    def _tool(self, **over):
        f = {"id": "T-1", "source": "tool:bandit", "severity": "HIGH",
             "panel": "security", "category": "secrets",
             "provenance": {"confirmation_reasoning": "B105"}}
        f.update(over)
        return f

    def test_unverified_tool_finding_is_tool_reported(self):
        ev_obj = ev.derive_evidence(self._tool())
        self.assertEqual(ev_obj["status"], "tool_reported")

    def test_tool_reported_is_not_gate_eligible(self):
        self.assertNotIn("tool_reported", ev.GATE_ELIGIBLE_DEFAULT)

    def test_confirmed_verdict_promotes_tool_finding(self):
        ev_obj = ev.derive_evidence(self._tool(),
                                    {"verdict": "CONFIRMED", "reasoning": "real"})
        self.assertEqual(ev_obj["status"], "tool_confirmed")
        self.assertIn("tool_confirmed", ev.GATE_ELIGIBLE_DEFAULT)

    def test_rejected_verdict_rejects_tool_finding(self):
        # The whole point of #446: an advisor CAN now refute a scanner.
        ev_obj = ev.derive_evidence(self._tool(),
                                    {"verdict": "REJECTED", "reasoning": "CSS class"})
        self.assertEqual(ev_obj["status"], "rejected")

    def test_needs_more_info_verdict_on_tool_finding(self):
        ev_obj = ev.derive_evidence(self._tool(), {"verdict": "NEEDS_MORE_INFO"})
        self.assertEqual(ev_obj["status"], "needs_more_info")

    def test_reinforced_unverified_is_tool_reported_keeping_corroboration(self):
        f = {"id": "R-1", "reinforced": True, "severity": "HIGH",
             "panel": "code", "category": "logic"}
        ev_obj = ev.derive_evidence(f)
        self.assertEqual(ev_obj["status"], "tool_reported")
        self.assertEqual(ev_obj["verified_by"], "tool+agent")

    def test_agent_finding_unaffected(self):
        f = {"id": "A-1", "severity": "HIGH", "panel": "code",
             "category": "logic"}
        self.assertEqual(ev.derive_evidence(f)["status"], "unverified")
        self.assertEqual(
            ev.derive_evidence(f, {"verdict": "CONFIRMED"})["status"],
            "advisor_confirmed")

    def test_status_is_in_schema_enum(self):
        import json as _json
        with open("skill/reference/report-schema.json", encoding="utf-8") as fh:
            schema = _json.load(fh)
        text = _json.dumps(schema)
        self.assertIn("tool_reported", text)
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_evidence.py -q`
Expected: FAIL — unverified tool findings still derive `tool_confirmed`.

- [ ] **Step 3: Implement**

In `skill/scripts/evidence.py`, extend the status tuple:

```python
EVIDENCE_STATUSES = ("tool_reported", "tool_confirmed", "advisor_confirmed",
                     "corroborated", "needs_more_info", "unverified",
                     "rejected")
```

Replace the body of `derive_evidence` with verdict-first precedence:

```python
def derive_evidence(finding, verdict=None):
    """Return the evidence dict for a finding.

    Precedence (P2, #446): an advisor VERDICT decides first, whatever the
    source — previously tool-sourcing short-circuited ahead of verdicts, so an
    advisor could never refute a scanner. Without a verdict, a tool-sourced or
    reinforced finding is `tool_reported`: reported, not verified, and NOT
    gate-eligible. Never mutates the finding. Self-asserted
    provenance.confirmation_status is deliberately ignored — a reviewer cannot
    confirm its own finding.
    """
    quality = finding.get("citation_quality") or "none"
    prov = finding.get("provenance") or {}
    reinforced = bool(finding.get("reinforced"))
    tool_like = is_tool_sourced(finding) or reinforced
    origin = "tool+agent" if reinforced else finding.get("source")

    v = str((verdict or {}).get("verdict", "")).upper()
    if v in VERDICT_VALUES:
        if v == "REJECTED":
            status = "rejected"
        elif v == "NEEDS_MORE_INFO":
            status = "needs_more_info"
        else:
            status = "tool_confirmed" if tool_like else "advisor_confirmed"
        return {"status": status,
                "verified_by": ([origin, "agent:advisor"] if tool_like
                                else "agent:advisor"),
                "reasoning": (verdict or {}).get("reasoning"),
                "citation_quality": quality}

    if tool_like:
        return {"status": "tool_reported", "verified_by": origin,
                "reasoning": ("Same locus reported independently by a tool and "
                              "an agent" if reinforced
                              else prov.get("confirmation_reasoning")
                              or "Reported by static-analysis tool"),
                "citation_quality": quality}

    if finding.get("corroborated"):
        panels = list(finding.get("corroborated_by") or [])
        return {"status": "corroborated", "verified_by": panels,
                "reasoning": "Nearby locus independently flagged by panels: %s"
                % ", ".join(panels),
                "citation_quality": quality}
    return {"status": "unverified", "verified_by": None, "reasoning": None,
            "citation_quality": quality}
```

In `skill/reference/report-schema.json`: add `"tool_reported"` to the
`evidence.status` enum (currently `["tool_confirmed", "advisor_confirmed",
"corroborated", "needs_more_info", "unverified", "rejected"]`) and add
`"tool_reported": {"type": "integer"}` to the `evidence_stats` properties
object.

In `skill/SKILL.md`, update the evidence-axis list so `tool_reported` is
documented and the gate sentence is accurate. Replace the `tool_confirmed`
bullet and the gate sentence with:

```markdown
- `tool_reported` — a static-analysis tool emitted it (or a tool+agent
  same-locus merge did); no advisor has checked it. NOT gate-eligible.
- `tool_confirmed` — a tool reported it AND an advisor independently confirmed
  it. Gate-eligible.
```

and

```markdown
Grades and the CI gate count `tool_confirmed`/`advisor_confirmed` findings
only — i.e. only claims an advisor verified, whatever their source. Run a
verify phase (or pass `--gate-unverified`) or the gate has nothing to fail on.
```

- [ ] **Step 4: Run**

Run: `python3 -m pytest tests/ -q && ruff check .`
Expected: the new tests pass. Existing tests that assert `tool_confirmed` for
an unverified tool finding now fail — UPDATE each to the new contract
(`tool_reported` without a verdict; `tool_confirmed` with a CONFIRMED verdict).
Do not delete them.

- [ ] **Step 5: Commit**

```bash
git add skill/scripts/evidence.py skill/reference/report-schema.json skill/SKILL.md tests/
git commit -m "feat(evidence): tool_reported status; verdicts outrank source (#446)"
```

---

### Task 3: Fingerprint-keyed, content-deterministic queue

**Files:**
- Modify: `skill/scripts/evidence.py` (`build_verify_queue`)
- Test: `tests/test_verify_queue.py`

**Interfaces:**
- Consumes: `evidence.finding_fingerprint` (Task 1), `triage_priority`, `sev_rank` (existing).
- Produces: `build_verify_queue(findings, max_verify=None) -> (entries, cut)` where each entry's `queue_id` is the finding's fingerprint (plus `-<n>` on collision). Task 4 asserts both passes produce identical id sets.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_verify_queue.py`, matching its existing import alias)

```python
class TestQueueIdentity(unittest.TestCase):
    def _f(self, fid, **over):
        f = {"id": fid, "severity": "HIGH", "panel": "code",
             "category": "logic", "title": "t-" + fid,
             "location": {"file": fid + ".py", "line_start": 1}}
        f.update(over)
        return f

    def test_queue_id_is_the_fingerprint(self):
        f = self._f("A")
        entries, _ = ev.build_verify_queue([f])
        self.assertEqual(entries[0]["queue_id"], ev.finding_fingerprint(f))

    def test_tool_findings_are_queued(self):
        tool = self._f("T", source="tool:bandit",
                       provenance={"confirmation_reasoning": "B105"})
        entries, _ = ev.build_verify_queue([tool])
        self.assertEqual(len(entries), 1)

    def test_reinforced_findings_are_queued(self):
        entries, _ = ev.build_verify_queue([self._f("R", reinforced=True)])
        self.assertEqual(len(entries), 1)

    def test_input_order_does_not_change_ids_or_survivors(self):
        findings = [self._f("A"), self._f("B", severity="CRITICAL"),
                    self._f("C", severity="LOW")]
        ids1 = [e["queue_id"] for e in ev.build_verify_queue(findings)[0]]
        ids2 = [e["queue_id"] for e in
                ev.build_verify_queue(list(reversed(findings)))[0]]
        self.assertEqual(ids1, ids2)
        cut1 = [e["queue_id"] for e in
                ev.build_verify_queue(findings, max_verify=2)[0]]
        cut2 = [e["queue_id"] for e in
                ev.build_verify_queue(list(reversed(findings)), max_verify=2)[0]]
        self.assertEqual(cut1, cut2)          # #438: no filename-order luck

    def test_fingerprint_collision_gets_stable_suffix(self):
        # Same panel+category+file+title => same fingerprint, different ids.
        a = self._f("X")
        b = self._f("Y", title=a["title"],
                    location=dict(a["location"]))
        b["category"] = a["category"]
        entries, _ = ev.build_verify_queue([a, b])
        ids = sorted(e["queue_id"] for e in entries)
        self.assertEqual(len(set(ids)), 2)
        base = ev.finding_fingerprint(a)
        self.assertEqual(ids, sorted([base, base + "-1"]))
        again = sorted(e["queue_id"] for e in
                       ev.build_verify_queue([a, b])[0])
        self.assertEqual(ids, again)          # stable across rebuilds
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_verify_queue.py -q`
Expected: FAIL — ids are still `NNN-FINDING-ID`, tool/reinforced findings are excluded.

- [ ] **Step 3: Implement** — replace `build_verify_queue` in `skill/scripts/evidence.py`:

```python
def build_verify_queue(findings, max_verify=None):
    """Return (entries, cut) for ALL findings, priority-sorted.

    Entries hold REFERENCES to the original finding dicts (verdict application
    must mutate the real objects).

    P2 (#446): tool-sourced and reinforced findings queue too — they are claims
    like any other, and `tool_confirmed` now requires an advisor verdict.
    P2 (#443/#438): the sort key and queue_id are pure functions of finding
    CONTENT — no input index anywhere — so both passes of a run compute the
    same ids and a --max-verify cut cannot depend on filename order.
    """
    ordered = sorted(findings, key=lambda f: (triage_priority(f), sev_rank(f),
                                              finding_fingerprint(f),
                                              str(f.get("id") or "")))
    cut = 0
    if max_verify is not None and max_verify >= 0 and len(ordered) > max_verify:
        cut = len(ordered) - max_verify
        ordered = ordered[:max_verify]
    entries = []
    seen = {}
    for f in ordered:
        fp = finding_fingerprint(f)
        n = seen.get(fp, 0)
        seen[fp] = n + 1
        qid = fp if n == 0 else "%s-%d" % (fp, n)
        if n:
            # Two findings with one identity usually means dedupe should have
            # merged them; keep them distinct and say so rather than collide.
            print("evidence: fingerprint collision %s (finding %r) -> %s"
                  % (fp, f.get("id"), qid), file=sys.stderr)
        entries.append({"queue_id": qid, "priority": triage_priority(f),
                        "finding": f})
    return entries, cut
```

- [ ] **Step 4: Run**

Run: `python3 -m pytest tests/ -q && ruff check .`
Expected: new tests pass. Existing `tests/test_verify_queue.py` cases that
assert tool/reinforced findings are EXCLUDED (the run-2 advisor cited
`:36-41` and `:94-103`) now fail — UPDATE them: those findings are expected in
the queue, and their ids are fingerprints. Do not delete them.

- [ ] **Step 5: Commit**

```bash
git add skill/scripts/evidence.py tests/test_verify_queue.py
git commit -m "feat(queue): fingerprint queue_ids, content-only ordering, queue every finding (#443, #438, #446)"
```

---

### Task 4: One shared queue-construction path

This is the actual #443 fix: both passes must feed `build_verify_queue` the
same list. Pass 1 currently skips `aggregate_tool_findings`.

**Files:**
- Modify: `skill/scripts/synthesize.py` (new `prepare_for_queue`; `build_report` ~617-620; `--emit-verify-queue` block ~954-957)
- Test: `tests/test_verify_queue.py`

**Interfaces:**
- Consumes: Task 3's `build_verify_queue`.
- Produces: `synthesize.prepare_for_queue(findings) -> (prepared, integration_findings)` — the single pipeline both passes call.

- [ ] **Step 1: Write the failing test** (append to `tests/test_verify_queue.py`)

```python
class TestBothPassesAgree(unittest.TestCase):
    def _raw(self):
        # Two hits of one rule in one file: pass 2 aggregates these, pass 1
        # historically did not — the exact shape that shifted every id.
        def tool(line):
            return {"id": "T-%d" % line, "source": "tool:bandit",
                    "severity": "HIGH", "panel": "security",
                    "category": "secrets", "title": "hardcoded password",
                    "confidence": "LIKELY",
                    "tool_evidence": {"rule_id": "B105"},
                    "location": {"file": "app.py", "line_start": line}}
        agent = {"id": "A-1", "severity": "MEDIUM", "panel": "code",
                 "category": "logic", "title": "tangled branch",
                 "confidence": "POSSIBLE",
                 "location": {"file": "svc.py", "line_start": 7}}
        return [tool(10), tool(20), agent]

    def test_pass1_and_pass2_build_identical_queue_ids(self):
        import copy
        import scripts.synthesize as syn
        p1, _ = syn.prepare_for_queue(copy.deepcopy(self._raw()))
        p2, _ = syn.prepare_for_queue(copy.deepcopy(self._raw()))
        ids1 = {e["queue_id"] for e in ev.build_verify_queue(p1)[0]}
        ids2 = {e["queue_id"] for e in ev.build_verify_queue(p2)[0]}
        self.assertEqual(ids1, ids2)
        self.assertTrue(ids1)

    def test_aggregation_happens_before_the_queue_is_built(self):
        import copy
        import scripts.synthesize as syn
        prepared, _ = syn.prepare_for_queue(copy.deepcopy(self._raw()))
        b105 = [f for f in prepared
                if (f.get("tool_evidence") or {}).get("rule_id") == "B105"]
        self.assertEqual(len(b105), 1)   # 2 hits collapsed to 1 finding
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_verify_queue.py -q`
Expected: AttributeError — `synthesize` has no `prepare_for_queue`.

- [ ] **Step 3: Implement**

In `skill/scripts/synthesize.py`, add next to `prepare_findings`:

```python
def prepare_for_queue(findings):
    """Aggregate, then prepare — the ONE pipeline both passes must share.

    #443: pass 1 (--emit-verify-queue) used to call prepare_findings alone
    while build_report aggregated first, so the two passes fed
    build_verify_queue different lists and every queue position after the
    first tool merge shifted. Both passes call this now; identity is
    content-addressed on top of it (evidence.build_verify_queue).
    """
    return prepare_findings(aggregate_tool_findings(findings))
```

In `build_report`, replace the two lines

```python
    findings = aggregate_tool_findings(findings)
    findings, integration_findings = prepare_findings(findings)
```

with

```python
    findings, integration_findings = prepare_for_queue(findings)
```

In `main`'s `--emit-verify-queue` block, replace

```python
        prepared, _ = prepare_findings(copy.deepcopy(findings))
```

with

```python
        prepared, _ = prepare_for_queue(copy.deepcopy(findings))
```

- [ ] **Step 4: Run**

Run: `python3 -m pytest tests/ -q && ruff check .`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add skill/scripts/synthesize.py tests/test_verify_queue.py
git commit -m "fix(synthesize): both passes build the queue from one pipeline (#443)"
```

---

### Task 5: `meta.tool_axis` and an honest `build_executing_tools`

**Files:**
- Modify: `skill/scripts/synthesize.py` (`build_report` signature + meta block ~686-690; `main` build_report call ~976-981 and tools-dir handling ~941)
- Modify: `skill/reference/report-schema.json` (meta properties)
- Test: `tests/test_synthesize.py`

**Interfaces:**
- Consumes: `evidence.is_tool_sourced`, `EXECUTES_TARGET_BUILD` (already imported in `synthesize`).
- Produces: `build_report(..., tools_ran=None)`; `meta.tool_axis` dict; `meta.build_executing_tools` derived from `tools_ran` when supplied.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_synthesize.py`, reusing the construction style of the neighbouring meta tests — e.g. the ones asserting `meta.version`)

```python
class TestToolAxisMeta(unittest.TestCase):
    def _tool(self, fid="T-1", **over):
        f = {"id": fid, "source": "tool:bandit", "severity": "HIGH",
             "panel": "security", "category": "secrets",
             "title": "hardcoded password", "confidence": "LIKELY",
             "description": "d", "location": {"file": "a.py", "line_start": 1},
             "provenance": {"confirmation_reasoning": "B105"}}
        f.update(over)
        return f

    def test_tool_axis_counts_unverified_as_unanswered(self):
        r = syn.build_report([self._tool()], [], "t", None,
                             "2026-08-05T00:00:00Z")
        axis = r["meta"]["tool_axis"]
        self.assertEqual(axis["queued"], 1)
        self.assertEqual(axis["unanswered"], 1)
        self.assertEqual(axis["confirmed"], 0)
        self.assertIsNone(axis["rejection_rate"])

    def test_tool_axis_rejection_rate_when_verdicts_exist(self):
        a, b = self._tool("T-1"), self._tool("T-2",
                                             location={"file": "b.py",
                                                       "line_start": 2})
        prepared, _ = syn.prepare_for_queue([a, b])
        queue, _c = syn.evidence_mod.build_verify_queue(prepared)
        verdicts = {}
        for i, e in enumerate(queue):
            verdicts[e["queue_id"]] = {
                "verdict": "REJECTED" if i == 0 else "CONFIRMED",
                "finding_id": e["finding"]["id"], "reasoning": "r"}
        r = syn.build_report([a, b], [], "t", None, "2026-08-05T00:00:00Z",
                             verdicts=verdicts, verdicts_supplied=True)
        axis = r["meta"]["tool_axis"]
        self.assertEqual((axis["confirmed"], axis["rejected"]), (1, 1))
        self.assertEqual(axis["rejection_rate"], 0.5)

    def test_build_executing_tools_reports_a_run_with_zero_findings(self):
        r = syn.build_report([], [], "t", None, "2026-08-05T00:00:00Z",
                             tools_ran={"roslyn-secguard", "bandit"})
        self.assertEqual(r["meta"]["build_executing_tools"],
                         ["roslyn-secguard"])

    def test_build_executing_tools_falls_back_without_tools_ran(self):
        r = syn.build_report([self._tool(source="tool:roslyn-secguard")], [],
                             "t", None, "2026-08-05T00:00:00Z")
        self.assertEqual(r["meta"]["build_executing_tools"],
                         ["roslyn-secguard"])
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_synthesize.py -q`
Expected: KeyError `tool_axis` / TypeError on the unexpected `tools_ran` kwarg.

- [ ] **Step 3: Implement**

Add `tools_ran=None` as the last keyword parameter of `build_report`, and
document it in the docstring as "adapter names that produced output this run;
when omitted, `build_executing_tools` falls back to inferring from findings".

After the loop that assigns `f["evidence"]` (the one that also sets
`f["fingerprint"]`), compute the axis with a nested `def` (never a lambda
assignment — ruff E731):

```python
    tool_like = [f for f in findings
                 if evidence_mod.is_tool_sourced(f) or f.get("reinforced")]

    def _tool_count(status):
        return sum(1 for f in tool_like if f["evidence"]["status"] == status)

    confirmed = _tool_count("tool_confirmed")
    rejected_n = _tool_count("rejected")
    decided = confirmed + rejected_n
    tool_axis = {
        "queued": len(tool_like),
        "confirmed": confirmed,
        "rejected": rejected_n,
        "needs_more_info": _tool_count("needs_more_info"),
        "unanswered": _tool_count("tool_reported"),
        # Share of DECIDED tool claims an advisor refuted — the tool-side
        # mirror of the 27% agentic rejection rate. None when nothing was
        # decided, so an unverified run reports "unmeasured", not "0%".
        "rejection_rate": round(rejected_n / decided, 3) if decided else None,
    }
```

In the `meta` dict, replace the `build_executing_tools` line and add
`tool_axis`:

```python
            "build_executing_tools": sorted(
                (set(tools_ran) if tools_ran is not None else tool_names)
                & EXECUTES_TARGET_BUILD),
            "tool_axis": tool_axis,
```

In `main`, derive the adapter names from the tool-output directory and pass
them through. Immediately after the existing `if args.tools_dir and
os.path.isdir(args.tools_dir):` ingest block, add:

```python
    tools_ran = set()
    if args.tools_dir and os.path.isdir(args.tools_dir):
        for name in os.listdir(args.tools_dir):
            base, ext = os.path.splitext(name)
            if ext in (".json", ".sarif"):
                tools_ran.add(base)
```

and add `tools_ran=tools_ran,` to the `build_report(...)` call.

In `skill/reference/report-schema.json`, add to the `meta` properties:

```json
            "tool_axis": {
              "type": "object",
              "properties": {
                "queued": {"type": "integer"},
                "confirmed": {"type": "integer"},
                "rejected": {"type": "integer"},
                "needs_more_info": {"type": "integer"},
                "unanswered": {"type": "integer"},
                "rejection_rate": {"type": ["number", "null"]}
              }
            },
```

- [ ] **Step 4: Run**

Run: `python3 -m pytest tests/ -q && ruff check .`
Expected: all pass. Update any existing test that asserts the exact set of
`meta` keys.

- [ ] **Step 5: Commit**

```bash
git add skill/scripts/synthesize.py skill/reference/report-schema.json tests/test_synthesize.py
git commit -m "feat(meta): tool_axis rejection rate; build_executing_tools from tools that ran (#446, #450)"
```

---

### Task 6: End-to-end verification and docs

**Files:**
- Modify: `DEVELOPMENT.md` (evidence-axis / gate description)
- Test: `tests/test_e2e.py` (or the existing end-to-end suite — read it first and follow its fixture conventions)

**Interfaces:**
- Consumes: everything above. Terminal task.

- [ ] **Step 1: Write the failing end-to-end test**

Append to the existing end-to-end suite a test that drives the real
two-pass flow through `build_report` and asserts the gate tightened:

```python
class TestStrictGateEndToEnd(unittest.TestCase):
    def _tool_high(self):
        return {"id": "T-1", "source": "tool:bandit", "severity": "HIGH",
                "panel": "security", "category": "secrets",
                "title": "hardcoded password", "confidence": "LIKELY",
                "description": "d",
                "location": {"file": "a.py", "line_start": 1},
                "provenance": {"confirmation_reasoning": "B105"}}

    def test_unverified_tool_high_no_longer_fails_the_gate(self):
        r = syn.build_report([self._tool_high()], [], "t", "high",
                             "2026-08-05T00:00:00Z")
        self.assertEqual(r["summary"]["gate"], "PASS")
        self.assertEqual(
            r["findings"][0]["evidence"]["status"], "tool_reported")

    def test_confirmed_tool_high_fails_the_gate(self):
        f = self._tool_high()
        prepared, _ = syn.prepare_for_queue([dict(f)])
        queue, _c = syn.evidence_mod.build_verify_queue(prepared)
        qid = queue[0]["queue_id"]
        verdicts = {qid: {"verdict": "CONFIRMED",
                          "finding_id": queue[0]["finding"]["id"],
                          "reasoning": "real credential"}}
        r = syn.build_report([f], [], "t", "high", "2026-08-05T00:00:00Z",
                             verdicts=verdicts, verdicts_supplied=True)
        self.assertEqual(r["summary"]["gate"], "FAIL")

    def test_gate_unverified_still_includes_tool_reported(self):
        r = syn.build_report([self._tool_high()], [], "t", "high",
                             "2026-08-05T00:00:00Z", gate_unverified=True)
        self.assertEqual(r["summary"]["gate"], "FAIL")
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_e2e.py -q`
Expected: the first test FAILS before Task 2's change is in effect end to end
(the tool HIGH still gates). If it already passes, confirm by inspection that
it is passing for the right reason (status is `tool_reported`), not because
the fixture never reached the gate.

- [ ] **Step 3: Update `DEVELOPMENT.md`**

Find the section describing the evidence axis / gate policy and update it so
it states the P2 posture: only advisor-verified findings (`tool_confirmed`,
`advisor_confirmed`) are gate-eligible; `tool_reported` is a tool claim nobody
checked; `meta.tool_axis.rejection_rate` reports how often advisors refute
scanners; `--gate-unverified` remains the escape hatch for pipelines that
want every non-rejected finding to gate. Keep the file's existing list
formatting.

- [ ] **Step 4: Run everything**

Run: `python3 -m pytest tests/ -q && ruff check .`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add tests/ DEVELOPMENT.md
git commit -m "test(p2): end-to-end strict-gate coverage; document the posture (#446)"
```
