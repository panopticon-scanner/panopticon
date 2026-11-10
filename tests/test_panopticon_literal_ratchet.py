"""#3409: a shrink-only ratchet on the `.panopticon` literal under skill/scripts.

The artifact directory's name has one owner, `plan_contract.ARTIFACT_DIR`
(`artifact_root` builds on it). This counts, per file, the string constants
that contain `.panopticon` (read from the AST: docstrings and comments are not
counted, an f-string piece or an implicitly concatenated literal is) and pins
each file's count. A count may only go down, and the change that lowers it
lowers its pin too; a file not listed is pinned at 0, so a new file starts clean.
The #3409 sweep moved every owed site onto the constant, so `PENDING` is empty.
What remains is the owner (`HOME`), the literals that stay by design
(`STANDALONE`, pinned to agree with the constant) and two constants that only
contain the string (`NOT_THE_DIRECTORY`).
"""
import ast
import os
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "skill" / "scripts"
LITERAL = ".panopticon"

PENDING: dict[str, int] = {}   # the sweep is done (#3409): nothing is owed

# The owner itself: `ARTIFACT_DIR` and `artifact_root`'s three refusal messages.
HOME: dict[str, int] = {
    "plan_contract.py": 4,
}

# Sites that keep their literal on purpose, pinned like the rest (shrink-only)
# but not owed. The hooks run as their own `-I` interpreter with no package on
# sys.path, so they cannot import plan_contract, and a bootstrap would be worse
# than the literal; repo_config's two are the retired files' fixed locations;
# build_disclosure stays import-free by design; claim_scope is a
# stdlib-only leaf, which tests/test_claim_scope.py pins (it sits under dispatch
# and so under every runner). `test_the_standalone_literals_agree`
# keeps each from drifting off `plan_contract.ARTIFACT_DIR`.
STANDALONE: dict[str, int] = {
    "build_disclosure.py": 1,    # PRIOR_RUN; import-free by design
    "claim_scope.py": 1,         # _ARTIFACT_DIR; a stdlib-only leaf (tests/test_claim_scope.py)
    "codex_read_tools.py": 1,    # EXCLUDED_DIRECTORIES member (runs under -I)
    "guard_rules.py": 1,         # ARTIFACT_DIR, shared by the hook processes
    "read_guard_hook.py": 1,     # DEFAULT_SCOPE_PATH (hook process)
    "repo_config.py": 2,         # LEGACY_GROUPS_PATH, LEGACY_CONFIG_JSON (fixed locations)
    "write_guard_hook.py": 1,    # DEFAULT_ALLOWLIST_PATH (hook process)
}
# Constants that contain the string but do not name the artifact directory.
NOT_THE_DIRECTORY: dict[str, int] = {
    "repo_config.py": 1,         # ".panopticon.yml", the config's alternate filename
    "smoke_adapters.py": 1,      # ".panopticon-write-probe-%d-%s", a probe file's prefix
}


def _pinned(rel):
    return (PENDING.get(rel, 0) + HOME.get(rel, 0) + STANDALONE.get(rel, 0)
            + NOT_THE_DIRECTORY.get(rel, 0))


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
    def test_the_artifact_dir_name_is_pinned(self):
        # The sweep's sites read this instead of spelling it (#3409): its
        # value is the one every swept path, name and message still has.
        import scripts.plan_contract as plan_contract
        self.assertEqual(plan_contract.ARTIFACT_DIR, ".panopticon")
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(plan_contract.artifact_root(root),
                             os.path.join(os.path.abspath(root), ".panopticon"))

    def test_no_file_spells_the_literal_more_than_its_pin(self):
        grown = ["%s: %d (pinned at %d)" % (rel, n, _pinned(rel))
                 for rel, n in sorted(_census().items()) if n > _pinned(rel)]
        self.assertEqual(grown, [], "a `%s` literal was added; build the path from "
                         "plan_contract.artifact_root (or a value derived from it) "
                         "instead. The pins only go down." % LITERAL)

    def test_a_shrink_lowers_its_pin(self):
        counts = _census()
        files = set(PENDING) | set(HOME) | set(STANDALONE) | set(NOT_THE_DIRECTORY)
        loose = ["%s: %d (pinned at %d)" % (rel, counts.get(rel, 0), _pinned(rel))
                 for rel in sorted(files) if counts.get(rel, 0) < _pinned(rel)]
        self.assertEqual(loose, [], "lower these pins to the new count (drop the entry "
                         "at 0): a pin left above its count re-permits the sites removed")

    def test_the_standalone_literals_agree(self):
        # #3409 ruling: the literals stay, but they cannot drift from the one name.
        import scripts.codex_read_tools as codex_read_tools
        import scripts.guard_rules as guard_rules
        import scripts.plan_contract as plan_contract
        import scripts.read_guard_hook as read_guard_hook
        import scripts.repo_config as repo_config
        import scripts.write_guard_hook as write_guard_hook
        name = plan_contract.ARTIFACT_DIR
        self.assertEqual(guard_rules.ARTIFACT_DIR, name)
        self.assertIn(name, codex_read_tools.EXCLUDED_DIRECTORIES)
        import scripts.claim_scope as claim_scope
        self.assertEqual(claim_scope._ARTIFACT_DIR, name)
        import scripts.build_disclosure as build_disclosure
        self.assertTrue(build_disclosure.PRIOR_RUN.endswith(" in %s/" % name),
                        build_disclosure.PRIOR_RUN)
        for path in (read_guard_hook.DEFAULT_SCOPE_PATH, write_guard_hook.DEFAULT_ALLOWLIST_PATH,
                     repo_config.LEGACY_GROUPS_PATH, repo_config.LEGACY_CONFIG_JSON):
            with self.subTest(path=path):
                self.assertEqual(path.replace(os.sep, "/").split("/")[0], name)
                self.assertGreater(len(path.replace(os.sep, "/").split("/")), 1)

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
