"""#1674: raw finding readers must share the controller-field sanitizer.

Report readers consume already assembled reports; the contract checker only
validates shape. Every other access to the findings key must sanitize it. This
AST guard detects direct key access, get/pop/setdefault and constants naming
the key; it deliberately does not attempt general Python data-flow analysis.
"""
import ast
from pathlib import Path
import unittest

from conftest import SKILL_ROOT


RAW_READERS = {
    "synth/plan.py::out_of_scope_findings",
    "synth/findings.py::load_findings_detailed",
    "synth/integrity.py::cross_domain_findings",
    "phases/review.py::_load_cell_findings",
}
OTHER_READERS = {
    "html_report.py::_render_dashboard", "html_report.py::_heatmap_grid",
    "html_report.py::_render_findings", "html_report.py::render",
    "synthesize.py::main", "reconcile.py::load_report",
    "synth/render.py::render_summary", "synth/render.py::write_report",
    "synth/render.py::_read_json_report", "synth/report.py::validate_report",
    "synth/validate_schema.py::finding_item_schema",
    "findings_contract.py::payload_defects",
}


def readers(source):
    tree = ast.parse(source)
    keys = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if isinstance(value, ast.Constant) and value.value == "findings":
            keys.update(t.id for t in targets if isinstance(t, ast.Name))

    def is_key(node):
        return ((isinstance(node, ast.Constant) and node.value == "findings")
                or (isinstance(node, ast.Name) and node.id in keys))

    def accesses(node):
        return ((isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load)
                 and is_key(node.slice))
                or (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("get", "pop", "setdefault")
                    and node.args and is_key(node.args[0])))

    return [node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any(accesses(child) for child in ast.walk(node))]


class TestAgentFindingsBoundary(unittest.TestCase):
    def test_all_raw_readers_use_the_one_sanitizer(self):
        root = Path(SKILL_ROOT) / "scripts"
        found = {}
        for path in root.rglob("*.py"):
            for node in readers(path.read_text(encoding="utf-8")):
                found[f"{path.relative_to(root).as_posix()}::{node.name}"] = node
        self.assertEqual(set(found), RAW_READERS | OTHER_READERS,
                         "Classify every new findings reader before it enters the controller")
        for name in RAW_READERS:
            with self.subTest(reader=name):
                self.assertTrue(any(isinstance(node, ast.Call)
                                    and ((isinstance(node.func, ast.Attribute)
                                          and node.func.attr == "agent_finding")
                                         or (isinstance(node.func, ast.Name)
                                             and node.func.id == "agent_finding"))
                                    for node in ast.walk(found[name])), name)

    def test_detector_catches_key_access_without_requiring_a_loop(self):
        for expression in ('data["findings"]', 'data.get("findings")',
                           'data.pop("findings")', 'data.setdefault("findings", [])',
                           'data[KEY]', 'load(path)["findings"]'):
            with self.subTest(expression=expression):
                source = 'KEY = "findings"\ndef consume(data, path):\n    return ' + expression
                self.assertEqual(["consume"], [node.name for node in readers(source)])
