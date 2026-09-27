import os
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
        import shutil
        import subprocess
        import tempfile
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
                    proc = subprocess.run([node, "--check", tmp_path], capture_output=True, text=True)
                finally:
                    os.unlink(tmp_path)
                self.assertEqual(0, proc.returncode, proc.stderr)

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
