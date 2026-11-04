"""#3409: a shrink-only ratchet on the `.panopticon` literal under skill/scripts.

The artifact root has one owner, `plan_contract.artifact_root`, but the name
is still spelled across the tree. This counts, per file, the string constants
that contain `.panopticon` (read from the AST: docstrings and comments are not
counted, an f-string piece or an implicitly concatenated literal is), and pins
each file at the count it had on main 72b0083f. A count may only go down, and
the change that lowers it lowers its pin too, so the map stays the list of
sites still owed; a file not listed is pinned at 0, so a new file starts clean.
The sweep onto `artifact_root` lands directory by directory, each PR lowering
the numbers below.
"""
import ast
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "skill" / "scripts"
LITERAL = ".panopticon"

PENDING: dict[str, int] = {
    "build_disclosure.py": 1,
    "claim_scope.py": 1,
    "codex_read_tools.py": 1,
    "discovery.py": 4,
    "dispatch.py": 2,
    "driver.py": 1,
    "first_contact.py": 5,
    "group_runner.py": 2,
    "guard_rules.py": 1,
    "ingest_tools.py": 2,
    "language_detection.py": 1,
    "phases/evidence_scope.py": 1,
    "phases/readiness.py": 3,
    "phases/runio.py": 4,
    "phases/setup.py": 1,
    "phases/setup_readiness.py": 1,
    "phases/validate.py": 9,
    "plan_contract.py": 4,
    "probes/common.py": 1,
    "read_guard_hook.py": 1,
    "repo_config.py": 3,
    "run_manifest.py": 1,
    "run_tools.py": 2,
    "safe_write.py": 2,
    "setup_config.py": 10,
    "setup_flow.py": 3,
    "setup_spine.py": 3,
    "smoke_adapters.py": 1,
    "synth/coverage_io.py": 1,
    "synth/integrity.py": 1,
    "synth/plan.py": 4,
    "synthesize.py": 10,
    "tools/dependency_check.py": 1,
    "tools/legacy_sarif.py": 1,
    "write_guard_hook.py": 1,
}


def literal_count(tree):
    """String constants containing the literal, docstrings excluded."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.body and isinstance(node.body[0], ast.Expr):
                docstrings.add(id(node.body[0].value))
    return sum(1 for node in ast.walk(tree)
               if isinstance(node, ast.Constant) and isinstance(node.value, str)
               and id(node) not in docstrings and LITERAL in node.value)


def _census():
    counts = {}
    for path in sorted(SCRIPTS.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        n = literal_count(ast.parse(path.read_text(encoding="utf-8")))
        if n:
            counts[path.relative_to(SCRIPTS).as_posix()] = n
    return counts


class PanopticonLiteralRatchetTest(unittest.TestCase):
    def test_no_file_spells_the_literal_more_than_its_pin(self):
        grown = ["%s: %d (pinned at %d)" % (rel, n, PENDING.get(rel, 0))
                 for rel, n in sorted(_census().items()) if n > PENDING.get(rel, 0)]
        self.assertEqual(grown, [], "a `%s` literal was added; build the path from "
                         "plan_contract.artifact_root (or a value derived from it) "
                         "instead. The pins only go down." % LITERAL)

    def test_a_shrink_lowers_its_pin(self):
        counts = _census()
        loose = ["%s: %d (pinned at %d)" % (rel, counts.get(rel, 0), pin)
                 for rel, pin in sorted(PENDING.items()) if counts.get(rel, 0) < pin]
        self.assertEqual(loose, [], "lower these pins to the new count (drop the entry "
                         "at 0): a pin left above its count re-permits the sites removed")

    def test_the_counter_reads_the_ast(self):
        source = '''
"""Docstring naming .panopticon/ is not a site."""
# a comment naming .panopticon is not in the AST
ROOT = ".panopticon"
REPORT = os.path.join(root, ".panopticon", "report.json")
JOINED = (".pano" ".panopticon-ish")
PATH = f"{root}/.panopticon/{name}"
def f():
    """Nor is this one: .panopticon."""
    return ".panopticonx"
OTHER = "panopticon.yml"
'''
        # ROOT, REPORT, JOINED (one constant once joined), the f-string's
        # literal piece, and the return value: five. Docstrings, the comment
        # and the bare `panopticon.yml` are not.
        self.assertEqual(literal_count(ast.parse(source)), 5)


if __name__ == "__main__":
    unittest.main()
