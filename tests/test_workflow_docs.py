import json
import os
import shutil
import subprocess
import tempfile
import unittest

from tests._test_helpers import SKILL_ROOT as ROOT, REPO_ROOT
from tests._test_helpers import skip_or_fail
from tests.doc_helpers import (
    _read_doc, _read_skill_md, _section,
)


class TestClaudeSessionModeWorkflowTemplate(unittest.TestCase):
    """Claude family PR (#1344): session-mode dispatch on Claude Code is a
    shipped workflow template, mandated by SKILL.md, not an ad-hoc fan-out."""

    WORKFLOW = os.path.join(ROOT, "workflows", "dispatch.js")
    FAMILY_PR_REVIEW_WORKFLOW = os.path.join(ROOT, "workflows", "family-pr-review.js")
    # The harness these two are checked against the same way; kept as one
    # named constant so a reader (and `_as_workflow_body` below) can find it.
    HARNESS = os.path.join(REPO_ROOT, "tests", "workflows", "dispatch_harness.mjs")

    def test_the_dispatch_workflow_ships_with_its_meta_and_the_binding_rules(self):
        self.assertTrue(os.path.isfile(self.WORKFLOW), self.WORKFLOW)
        with open(self.WORKFLOW, encoding="utf-8") as fh:
            js = fh.read()
        self.assertIn("export const meta = {", js)
        for token in ("name: 'panopticon-dispatch'", "agentType", "prompt_file",
                      "e.marker + '\\n'", "return_json", "missing"):
            with self.subTest(token=token):
                self.assertIn(token, js)

    @staticmethod
    def _as_workflow_body(src):
        """Neither of these two files is a real ES module or a plain script
        (#2024): each ends in a top-level `return`, illegal in a real module
        (module top level is not function-wrapped); family-pr-review.js also
        opens with a top-level `await pipeline(...)`, illegal in a plain
        script. Both are only legal inside the async-function body the
        Workflow host -- and this repo's own `dispatch_harness.mjs`
        (HARNESS above) -- wrap this source in, after textually slicing
        `export const meta = {...}` off the front (a scraped marker, not
        real module syntax any runtime parses in place).

        This mirrors `splitMeta` in HARNESS closely enough that `node
        --check` proves the same thing it would prove there: keep the two in
        sync, or note here why they diverge, if HARNESS's splitMeta changes.
        One deliberate divergence: the wrapper here also names `pipeline`,
        which the Workflow tool provides and family-pr-review.js uses; the
        harness has no `pipeline` global (it only runs dispatch.js), and the
        extra parameter changes nothing `node --check` can see.
        """
        marker = "export const meta = "
        idx = src.index(marker)
        depth, i = 0, idx + len(marker)
        while i < len(src):
            if src[i] == "{":
                depth += 1
            elif src[i] == "}":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
        meta_literal, rest = src[idx + len(marker):i], src[:idx] + src[i:]
        return ("const meta = " + meta_literal + ";\n"
                "async function __workflow_body__(args, agent, parallel, phase, log, pipeline) {\n"
                + rest + "\n}\n")

    @staticmethod
    def _run_node(node, *args):
        return subprocess.run([node, *args], capture_output=True, text=True)

    def test_the_workflow_scripts_parse_the_way_the_harness_evaluates_them(self):
        # #2024: dispatch.js and family-pr-review.js are Workflow-tool
        # scripts, not standalone modules (see their own header comments and
        # HARNESS above) -- a bare `node --check` on either raw file is not a
        # meaningful check: it would assert a module (or script) shape
        # neither has ever had, and would fail on both for a reason
        # unrelated to well-formedness (top-level `return`/`await`, expected
        # here, illegal at real module or script top level). `_as_workflow_body`
        # reproduces the same split-then-wrap HARNESS uses, so this proves
        # what actually has to be true: both parse as JavaScript in the one
        # shape they are ever really evaluated in.
        #
        # skip_or_fail keeps a runner that IS meant to have node from
        # silently passing on a missing binary instead of skipping (#1422).
        node = shutil.which("node")
        if not node:
            skip_or_fail(self, "node is not installed here; CI's runners have it")
        # The harness this mirrors must still exist, or "the way the harness
        # evaluates them" is a claim about nothing.
        self.assertTrue(os.path.isfile(self.HARNESS), self.HARNESS)
        for workflow in (self.WORKFLOW, self.FAMILY_PR_REVIEW_WORKFLOW):
            with self.subTest(workflow=workflow):
                with open(workflow, encoding="utf-8") as fh:
                    body = self._as_workflow_body(fh.read())
                with tempfile.NamedTemporaryFile(
                        "w", suffix=".mjs", delete=False, encoding="utf-8") as fh:
                    fh.write(body)
                    tmp_path = fh.name
                try:
                    proc = self._run_node(node, "--check", tmp_path)
                finally:
                    os.unlink(tmp_path)
                self.assertEqual(0, proc.returncode, proc.stderr)

    def test_family_review_caps_schema_and_runtime_fanout(self):
        node = shutil.which("node")
        if not node:
            skip_or_fail(self, "node is not installed here; CI's runners have it")
        with open(self.FAMILY_PR_REVIEW_WORKFLOW, encoding="utf-8") as fh:
            body = self._as_workflow_body(fh.read())
        harness = r"""
const finderSize = 28
const schemaCaps = []
let verifierCalls = 0
const logs = []
const finding = i => ({
  title: 'finding-' + i,
  file: 'src/file-' + i + '.py',
  line: i + 1,
  severity: 'medium',
  rule: 'rule-' + i,
  evidence: 'evidence-' + i,
})
const agent = async (_prompt, opts) => {
  if (opts.phase === 'Review') {
    schemaCaps.push(opts.schema.properties.findings.maxItems ?? null)
    return { findings: Array.from({ length: finderSize }, (_, i) => finding(i)) }
  }
  verifierCalls += 1
  return { real: true, reason: 'confirmed' }
}
const parallel = async tasks => Promise.all(tasks.map(task => task()))
const pipeline = async (dimensions, find, verify) => {
  const results = []
  for (const dimension of dimensions) {
    results.push(await verify(await find(dimension), dimension))
  }
  return results
}
const result = await __workflow_body__(
  { host: 'codex' }, agent, parallel, () => {}, message => logs.push(message), pipeline)
process.stdout.write(JSON.stringify({ result, schemaCaps, verifierCalls, logs }))
"""
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = os.path.join(directory, "family-review-harness.mjs")
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(body)
                fh.write(harness)
            proc = self._run_node(node, tmp_path)
        self.assertEqual(0, proc.returncode, proc.stderr)
        observed = json.loads(proc.stdout)
        result = observed["result"]
        self.assertEqual([25] * 5, observed["schemaCaps"])
        self.assertEqual(25, result["finding_cap"])
        self.assertEqual(125, len(result["confirmed"]))
        self.assertEqual(0, len(result["dropped"]))
        self.assertEqual([], result["incomplete_review"])
        self.assertEqual(15, result["findings_omitted"])
        self.assertEqual(375, observed["verifierCalls"])
        self.assertEqual(5, len(result["truncation"]))
        self.assertTrue(all(row["received"] == 28 for row in result["truncation"]))
        self.assertTrue(all(row["verified"] == 25 for row in result["truncation"]))
        self.assertTrue(all(row["omitted"] == 3 for row in result["truncation"]))
        self.assertIn("15 omitted by the 25-per-dimension cap", observed["logs"][-1])
        self.assertIn("0 incomplete review facts", observed["logs"][-1])

    def test_family_review_discloses_missing_finder_and_verifier_results(self):
        node = shutil.which("node")
        if not node:
            skip_or_fail(self, "node is not installed here; CI's runners have it")
        with open(self.FAMILY_PR_REVIEW_WORKFLOW, encoding="utf-8") as fh:
            body = self._as_workflow_body(fh.read())
        harness = r"""
let verifierCalls = 0
const logs = []
const finding = dimension => ({
  title: 'finding-' + dimension,
  file: 'src/' + dimension + '.py',
  line: 7,
  severity: 'medium',
  rule: 'rule-' + dimension,
  evidence: 'evidence-' + dimension,
})
const agent = async (_prompt, opts) => {
  if (opts.phase === 'Review') {
    const dimension = opts.label.slice('review:'.length)
    return dimension === 'suite-rules' ? null : { findings: [finding(dimension)] }
  }
  verifierCalls += 1
  return opts.label === 'verify:correctness:2'
    ? null
    : { real: true, reason: 'confirmed' }
}
const parallel = async tasks => Promise.all(tasks.map(task => task()))
const pipeline = async (dimensions, find, verify) => {
  const results = []
  for (const dimension of dimensions) {
    results.push(await verify(await find(dimension), dimension))
  }
  return results
}
const result = await __workflow_body__(
  { host: 'codex' }, agent, parallel, () => {}, message => logs.push(message), pipeline)
process.stdout.write(JSON.stringify({ result, verifierCalls, logs }))
"""
        with tempfile.TemporaryDirectory() as directory:
            tmp_path = os.path.join(directory, "family-review-loss-harness.mjs")
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(body)
                fh.write(harness)
            proc = self._run_node(node, tmp_path)
        self.assertEqual(0, proc.returncode, proc.stderr)
        observed = json.loads(proc.stdout)
        result = observed["result"]
        self.assertEqual(12, observed["verifierCalls"])
        self.assertEqual(3, len(result["confirmed"]))
        self.assertEqual([], result["dropped"])
        self.assertEqual(2, len(result["incomplete_review"]))
        finder, verifier = result["incomplete_review"]
        self.assertEqual(
            {"stage": "finder", "dimension": "suite-rules"},
            finder,
        )
        self.assertEqual("verifier", verifier["stage"])
        self.assertEqual("correctness", verifier["dimension"])
        self.assertEqual(0, verifier["finding_index"])
        self.assertEqual(1, verifier["missing_votes"])
        self.assertEqual("finding-correctness", verifier["finding"]["title"])
        self.assertNotIn(
            "finding-correctness",
            [row["title"] for row in result["confirmed"] + result["dropped"]],
        )
        self.assertIn(
            "incomplete finder result for suite-rules",
            "\n".join(observed["logs"]),
        )
        self.assertIn(
            "incomplete verifier result for correctness finding 1: 1 of 3 votes missing",
            "\n".join(observed["logs"]),
        )

    def test_skill_md_mandates_the_workflow_for_session_mode_on_claude(self):
        skill = _read_skill_md()
        self.assertIn("skill/workflows/dispatch.js", skill)
        self.assertIn("Do not hand-dispatch entries with one-off Agent calls", skill)
        self.assertIn("marker, prompt_file, delivery, out_file", skill)

    def test_the_guide_names_the_workflow_and_grants_the_prompt_file_to_the_read_scope(self):
        doc = _read_doc()
        run_loop = _section(doc, "## Driver run-loop", "## Driver setup")
        self.assertIn("skill/workflows/dispatch.js", run_loop)
        self.assertIn("granted to the entry's read scope (`scope.reads`", run_loop)
