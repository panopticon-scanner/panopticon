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
import scripts.synth.validate_schema as validate_schema_mod
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
        extra = node.get("additionalProperties")
        if not props and isinstance(extra, dict):
            # A map whose KEYS are open but whose VALUES are described --
            # `meta.coverage.test_inventory`, and the per-capability
            # state/by/detail triple #1602 asked for. Walking only `properties`
            # treated these as leaves, so the triple was described and never
            # checked (M3). The keys are free by definition; the values are not.
            for key in sorted(value):
                _undescribed(value[key], extra, root,
                             "%s.<*>" % path if path else "<*>", out)
            return
        if not props or extra is True:
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
        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
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

    # M3: one cross-domain row, so `meta.integrity.cross_domain_findings` is
    # non-empty and the walk descends into its item shape. A SEC cell filing a
    # TST finding is the real shape this section exists to report.
    cross_path = os.path.join(run_dir, "findings-app-SEC.json")
    with open(cross_path, "w", encoding="utf-8") as fh:
        json.dump({"findings": [dict(_agentic(9), domain="TST", code="TST-X0X",
                                     panel="test", category="coverage")]}, fh)

    # M3: one MISSING floor cell, so `meta.coverage.cells.missing_floor` is
    # non-empty for the same reason. The floor names a domain no findings file
    # answers for, which is exactly what a missing floor cell IS.
    with open(os.path.join(run_dir, "coverage-app.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"group": "app", "floor": ["SEC", "ARC"],
                   "effective": ["SEC", "ARC"], "excluded": []}, fh)

    # The tool axis, through the real writer's own manifest and a real SARIF.
    # #1578: the one result sits under `vendor/`, so `meta.coverage.
    # tools_suppressed` is NON-EMPTY -- an empty map leaves the walk stopping
    # at the map instead of reaching the per-segment value it describes.
    # #1701: this fixture runs `--security redteam`, so the drop is counted by
    # the GATE and `tools_suppressed`'s segment value is 0 while the sibling
    # `tools_suppressed_gated` carries the 1. The KEY is what this section's
    # walk needs, and it survives on both -- which is also the point of zeroing
    # rather than dropping the row: the finding is still withheld from
    # `findings[]`, and the two rows sum to what the ingest actually dropped.
    sarif = {"runs": [{"tool": {"driver": {"name": "bandit", "rules": []}},
                       "results": [
                           {"ruleId": "B105", "level": "warning",
                            "message": {"text": "hardcoded password"},
                            "locations": [{"physicalLocation": {
                                "artifactLocation": {"uri": "vendor/lib/legacy.py"},
                                "region": {"startLine": 1}}}]}]}]}
    sarif_path = os.path.join(tools, "bandit.sarif")
    with open(sarif_path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh)
    # M3/#1646: a NON-EMPTY `sanitized` block, so the walk descends into the
    # per-tool row and its `dropped[]` item shape rather than stopping at an
    # empty map. It is written through the real writer, like everything else here.
    # M3/#1645: a NON-EMPTY `network` block for the same reason -- an empty map
    # leaves the per-tool value unwalked. Stated rather than observed here: this
    # fixture writes the manifest without running the scan loop, which is
    # exactly the caller the explicit argument exists for.
    run_tools.write_manifest(os.path.join(run_dir, "tools-manifest.json"),
                             ["bandit"], [sarif_path], run_id="parity-run",
                             network={"bandit": "none",
                                      "pip-audit": "proxied:pypi.org"},
                             sanitized={"pip-audit": {
                                 "source": "requirements.txt", "kept": 2,
                                 "dropped": [{"line": "-e .", "reason": "editable"}],
                                 "hashes_stripped": True,
                                 "truncated": False, "dropped_truncated": 0}})

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
            syn.main(common + ["--emit-verify-queue", findings_path, cross_path])
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
            rc = syn.main(common + ["--out", out, "--verdicts-dir", vdir,
                                    findings_path, cross_path])
    finally:
        render_mod.write_report = real_write
        os.chdir(prev)
    return out, rc


class TestSchemaParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        path, cls.rc = _build_report(cls._tmp.name)
        # The HYDRATED union -- the main report plus every `_partN.json` and
        # the `-discarded.json` sibling it points at. Validating only the main
        # file would skip precisely the keys the split writer adds.
        cls.report = render_mod._read_json_report(path)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_the_fixture_itself_builds_a_VALID_report(self):
        """I1: a fixture that fails validation proves nothing about parity.

        The first version of this file emitted `"cvss": 7.5` -- a bare float
        where the schema pins an object -- so `synthesize.main()` was driven
        into the artifact-invalid exit twice, with both streams redirected and
        the return value discarded, and the flagship "the schema and the report
        cannot drift apart" guard was green on a report the validator rejects.
        The same species of silence #1602 is about. Assert the rc, and assert
        the built artifact is clean, BEFORE reading anything off it.

        The rc is 2, not 0, and that is the point rather than a wrinkle: the
        fixture deliberately leaves one floor cell unanswered, so the GATE is
        INCONCLUSIVE while the ARTIFACT is perfectly valid. Those are the two
        different questions this whole change exists to keep apart, and the
        fixture happens to be a worked example of them."""
        self.assertNotEqual(
            self.rc, validate_schema_mod.ARTIFACT_INVALID,
            "the parity fixture wrote an artifact the validator rejects")
        self.assertEqual(self.rc, 2,
                         "expected INCONCLUSIVE (an unanswered floor cell), got %s"
                         % self.rc)
        errors = validate_schema_mod.schema_errors(self.report)
        self.assertEqual(errors, [],
                         "the fixture's own report fails the schema:\n  %s"
                         % "\n  ".join(errors))

    def test_the_fixture_exercises_every_producer(self):
        # Vacuity guard: "no key is undescribed" is also satisfied by a report
        # that produced nothing. Each assertion below names one producer whose
        # `meta` keys no other producer writes.
        self.assertIsNotNone(self.report, "the fixture wrote no readable report")
        meta = self.report["meta"]
        self.assertEqual(meta["gate_security_mode"], "redteam")
        self.assertTrue(meta.get("parts"), "the split writer did not run")
        self.assertTrue(meta.get("discarded_claims_file"),
                        "the discarded sibling was not written")
        self.assertEqual(meta["host_capabilities"]["host"], "claude")
        self.assertEqual(meta["tools"]["panels_with_scanner_context"],
                         {"with": 1, "without": 1})
        self.assertEqual(meta["coverage"]["test_inventory"], {"app": "empty"})
        self.assertEqual(meta["coverage"]["tools_ran"], ["bandit"])
        # #1578: non-empty, or the per-segment value this section describes is
        # never walked. #1701: 0 under this fixture's `--security redteam` --
        # the count means "suppressed from the GATE", and redteam gates them.
        self.assertEqual(meta["coverage"]["tools_suppressed"], {"vendor": 0})
        # #1701 fix round 1 (F2): the other half of the same tally, and the only
        # thing in the artifact that explains a redteam gate verdict resting on
        # a finding `findings[]` does not hold. Non-empty for its own walk, and
        # the two must sum to the number the ingest and `security_gate` print.
        self.assertEqual(meta["coverage"]["tools_suppressed_gated"], {"vendor": 1})
        self.assertTrue(self.report["discarded_claims"],
                        "no claim was discarded: the verdict axis did not run")
        self.assertTrue(self.report["findings"], "no finding survived")
        # M3: the two sections this PR added must be NON-EMPTY, or the walk
        # stops at the list and never reaches the item shape it describes.
        self.assertTrue(meta["integrity"]["cross_domain_findings"],
                        "no cross-domain row: that section's item shape is unwalked")
        self.assertTrue(meta["coverage"]["cells"]["missing_floor"],
                        "no missing floor cell: that section's item shape is unwalked")
        self.assertTrue(meta["host_capabilities"]["capabilities"],
                        "no capability row: the state/by/detail triple is unwalked")
        # #1646: same reason -- an empty `sanitized` map leaves the per-tool row
        # and its `dropped[]` item shape unwalked.
        self.assertTrue(meta["tools"]["sanitized"]["pip-audit"]["dropped"],
                        "no dropped requirement line: that item shape is unwalked")
        # #1645: same reason -- an empty `network` map leaves the per-tool
        # posture value unwalked.
        self.assertEqual(meta["tools"]["network"]["pip-audit"],
                         "proxied:pypi.org",
                         "no egress posture: that value is unwalked")

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
