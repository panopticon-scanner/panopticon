"""#1602: the published schema and the published report cannot drift apart.

`skill/reference/report-schema.json` is the machine-readable contract every
consumer validates a report against. Nothing had ever asserted that the
sections a report *emits* and the sections the schema *describes* are the same
set, so `meta.host_capabilities` -- added by #1344 F3b, documented in prose,
carried in every report since -- went eight task reviews and a whole-branch
review without appearing in the schema at all. Nothing failed: `meta` carried
no `additionalProperties: false`, so an undescribed section validates fine.
That silence is the finding.

This guard closes it from the other side. It builds a report through the REAL
`synthesize.main()` on a fixture that exercises every producer of a report key
-- the agentic and tool findings axes, verdicts (so `discarded_claims` is
populated), the host-capability posture, the scanner-context and test-inventory
counters, the delta classifier, the split writer (`meta.parts`) and the
discarded sibling (`meta.discarded_claims_file`) -- then walks the artifact
against the schema and fails on any key the schema does not describe.

It is deliberately STRICTER than validation. `jsonschema` only rejects an
undescribed key under `additionalProperties: false`; this walk rejects one
wherever the schema names properties at all, so a new section is caught in the
PR that adds it rather than in the release that turns the strictness on.

Vacuity is the obvious failure mode for a guard whose assertion is "nothing was
left out", so `test_the_fixture_exercises_every_producer` pins that the fixture
really did drive each of those producers before the walk below reads them.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest

from conftest import REPO_ROOT
import scripts.hosts as hosts
import scripts.run_tools as run_tools
import scripts.synth.plan as plan_mod
import scripts.synth.render as render_mod
import scripts.synthesize as syn

SCHEMA_PATH = os.path.join(REPO_ROOT, "skill", "reference", "report-schema.json")

# Small enough that the fixture's handful of findings splits into parts and
# spills `discarded_claims` to its sibling -- the two producers that write
# `meta` keys nothing else writes.
SPLIT_BYTES = 4000


def _load_schema():
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _resolve(node, root):
    """Follow local `$ref` pointers (`discarded_claims` -> findings items)."""
    seen = 0
    while isinstance(node, dict) and "$ref" in node:
        ref = node["$ref"]
        assert ref.startswith("#/"), "non-local $ref in the schema: %r" % (ref,)
        target = root
        for part in ref[2:].split("/"):
            target = target[part]
        node = target
        seen += 1
        assert seen < 20, "cyclic $ref chain at %r" % (ref,)
    return node


def _undescribed(value, node, root, path, out):
    """Collect every key in `value` the schema node does not describe.

    Walks `properties` down; an object whose schema names no properties, or
    names `additionalProperties: true`, is a LEAF that the contract
    deliberately leaves open (`groups[].panel_grades`, the free-form
    `meta.coverage.test_inventory` map) and is not descended into.
    """
    node = _resolve(node, root)
    if isinstance(value, dict):
        props = node.get("properties")
        if not props or node.get("additionalProperties") is True:
            return
        for key in sorted(value):
            here = "%s.%s" % (path, key) if path else key
            if key not in props:
                out.append(here)
                continue
            _undescribed(value[key], props[key], root, here, out)
    elif isinstance(value, list):
        items = node.get("items")
        if items is None:
            return
        for entry in value:
            _undescribed(entry, items, root, "%s[]" % path, out)


def _drift(report):
    """The report keys the schema does not describe, in first-seen order."""
    schema = _load_schema()
    found = []
    _undescribed(report, schema, schema, "", found)
    ordered, seen = [], set()
    for key in found:
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


def _agentic(n, sev="HIGH"):
    """A security finding heavy enough that a few of them split the report.

    Distinct title AND distinct location per finding: dedupe/corroborate folds
    same-place same-shape claims into one, and a fixture whose six findings
    collapse to one never reaches the split writer.
    """
    fid = "SE-%03d" % n
    return {
        "id": fid,
        "title": "unsanitized input reaches the query builder at call site %d" % n,
        "severity": sev,
        "confidence": "LIKELY",
        "panel": "security",
        "category": "injection",
        "code": "SEC-A2D",
        "cvss": 7.5,
        "exploit_scenario": "an attacker reaches sink %d with a crafted value" % n,
        "remediation": "parameterize the query at call site %d" % n,
        "location": {"file": "src/app.py", "line_start": 10 * n,
                     "line_end": 10 * n + 1},
        "evidence": {"snippet": "q%d = 'SELECT ' + user" % n,
                     "status": "unverified"},
    }


def _build_report(tmpdir):
    """Drive the real `synthesize.main()` twice and return the paths it wrote.

    Pass 1 is the `--emit-verify-queue` pass (it mints the queue whose run_id a
    verdict must echo to bind); pass 2 ingests the verdicts and writes the
    artifacts. Both passes run in-process against real on-disk artifacts --
    a hand-built `build_report` input would close by construction exactly the
    producer gap this guard exists to catch.
    """
    src = os.path.join(tmpdir, "src")
    run_dir = os.path.join(tmpdir, "run")
    out_dir = os.path.join(tmpdir, "out")
    vdir = os.path.join(tmpdir, "verdicts")
    tools = os.path.join(run_dir, "tools")
    for path in (src, run_dir, out_dir, vdir, tools):
        os.makedirs(path)
    with open(os.path.join(src, "app.py"), "w", encoding="utf-8") as fh:
        fh.write("x = 1\n" * 200)

    groups = os.path.join(run_dir, "groups.json")
    with open(groups, "w", encoding="utf-8") as fh:
        json.dump({"groups": [{"name": "app", "files": ["src/app.py"],
                               "panels": ["SEC", "COD"]}]}, fh)

    findings_path = os.path.join(run_dir, "findings-app-security.json")
    with open(findings_path, "w", encoding="utf-8") as fh:
        json.dump({"findings": [_agentic(n) for n in range(1, 9)]}, fh)

    # The tool axis, through the real writer's own manifest and a real SARIF.
    sarif = {"runs": [{"tool": {"driver": {"name": "bandit", "rules": []}},
                       "results": []}]}
    sarif_path = os.path.join(tools, "bandit.sarif")
    with open(sarif_path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh)
    run_tools.write_manifest(os.path.join(run_dir, "tools-manifest.json"),
                             ["bandit"], [sarif_path], run_id="parity-run")

    # The 5.2 host posture, in the artifact's own shape (state/by/detail).
    with open(os.path.join(run_dir, "host-capabilities.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"host": "claude", "schema_version": 1,
                   "probed_at": "2026-09-16T00:00:00Z",
                   "capabilities": {
                       "tool_policy_enforced": {
                           "state": "proven", "by": "registered-shell-tools",
                           "detail": "4 shells match their templates"},
                       "read_scope_confined": {
                           "state": "refuted", "by": "read-guard-armed",
                           "detail": "outside-Read allowed"}},
                   hosts.CLI_FLAGS: {"claude": ["-p", "--output-format"]}}, fh)

    # The per-cell counters the review phase stamps (#1637 P08, #1638 P13).
    with open(os.path.join(run_dir, plan_mod.PANEL_TOOLS_CONTEXT), "w",
              encoding="utf-8") as fh:
        json.dump({"cells": {"app:SEC": True, "app:COD": False}}, fh)
    with open(os.path.join(run_dir, plan_mod.TEST_INVENTORY), "w",
              encoding="utf-8") as fh:
        json.dump({"groups": {"app": "empty"}}, fh)

    hunks = os.path.join(run_dir, "diff-hunks.json")
    with open(hunks, "w", encoding="utf-8") as fh:
        json.dump({"base": "main", "base_source": "explicit", "diff_context": 5,
                   "files_changed": 1, "hunks": {"src/app.py": [[10, 14]]}}, fh)

    out = os.path.join(out_dir, "report.json")
    common = ["--target", ".", "--groups", groups, "--run-dir", run_dir,
              "--tools-dir", tools, "--security", "redteam",
              "--diff-hunks", hunks, "--gate-scope", "all",
              "--fail-on", "critical"]
    real_write = render_mod.write_report

    def _small_write(report, out_path, max_bytes=SPLIT_BYTES):
        return real_write(report, out_path, max_bytes=max_bytes)

    prev = os.getcwd()
    os.chdir(tmpdir)
    try:
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            syn.main(common + ["--emit-verify-queue", findings_path])
        with open(os.path.join(run_dir, "verify-queue.json"),
                  encoding="utf-8") as fh:
            queue = json.load(fh)
        entries = queue.get("entries") or []
        # Two rejections (so `discarded_claims` and its sibling artifact are
        # populated) and the rest confirmed (so findings[] stays large enough
        # to split).
        verdicts = [{"finding_id": (e.get("finding") or {}).get("id"),
                     "verdict": "REJECTED" if n < 2 else "CONFIRMED",
                     "reasoning": "adjudicated for the parity fixture"}
                    for n, e in enumerate(entries)]
        with open(os.path.join(vdir, "verdicts-app-SEC.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"verdicts": verdicts,
                       "_panopticon": {"run_id": queue["run_id"],
                                       "role": "domain_advisor", "domain": "SEC",
                                       "group": "app", "stage": "primary"}}, fh)
        render_mod.write_report = _small_write
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            syn.main(common + ["--out", out, "--verdicts-dir", vdir,
                               findings_path])
    finally:
        render_mod.write_report = real_write
        os.chdir(prev)
    return out


class TestSchemaParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        path = _build_report(cls._tmp.name)
        # The HYDRATED union -- the main report plus every `_partN.json` and
        # the `-discarded.json` sibling it points at. Validating only the main
        # file would skip precisely the keys the split writer adds.
        cls.report = render_mod._read_json_report(path)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_the_fixture_exercises_every_producer(self):
        # Vacuity guard: "no key is undescribed" is also satisfied by a report
        # that produced nothing. Each assertion below names one producer whose
        # `meta` keys no other producer writes.
        self.assertIsNotNone(self.report, "the fixture wrote no readable report")
        meta = self.report["meta"]
        self.assertTrue(meta.get("parts"), "the split writer did not run")
        self.assertTrue(meta.get("discarded_claims_file"),
                        "the discarded sibling was not written")
        self.assertEqual(meta["host_capabilities"]["host"], "claude")
        self.assertEqual(meta["tools"]["panels_with_scanner_context"],
                         {"with": 1, "without": 1})
        self.assertEqual(meta["coverage"]["test_inventory"], {"app": "empty"})
        self.assertEqual(meta["coverage"]["tools_ran"], ["bandit"])
        self.assertTrue(self.report["discarded_claims"],
                        "no claim was discarded: the verdict axis did not run")
        self.assertTrue(self.report["findings"], "no finding survived")

    def test_no_report_key_is_undescribed_by_the_schema(self):
        drift = _drift(self.report)
        self.assertEqual(
            drift, [],
            "%d report key(s) skill/reference/report-schema.json does not "
            "describe:\n  %s\n"
            "Add them to the schema (with a description saying what the key "
            "means and who writes it) -- a key no schema describes is a "
            "contract no consumer can validate against."
            % (len(drift), "\n  ".join(drift)))


if __name__ == "__main__":
    unittest.main()
