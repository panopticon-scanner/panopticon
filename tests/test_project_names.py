"""#3407: the repo slug and the image/mount names are spelled once.

`gh_transport.REPO_SLUG` is the GitHub repository the filing tools file
against and link into; `tools_image` holds the local tools image, its registry
ref, and the fixtures image and root. The pins below fix each value, and the
guard fails on a new hard-coded spelling anywhere in skill/ or scripts/, read
from the AST so a comment or docstring that names the image is not a hit and a
string split across lines or inside an f-string still is.
"""
import ast
import unittest
from pathlib import Path

import gh_transport
import scripts.tools_image as tools_image

REPO = Path(__file__).resolve().parent.parent
SPELLINGS = ("panopticon-scanner", "panopticon-tools", "panopticon-fixtures")
# The two homes: (file, assigned name) pairs whose own value may spell them.
HOMES = {
    ("scripts/gh_transport.py", "REPO_SLUG"),
    ("skill/scripts/tools_image.py", "LOCAL_NAME"),
    ("skill/scripts/tools_image.py", "REGISTRY_IMAGE"),
    ("skill/scripts/tools_image.py", "FIXTURES_NAME"),
}


class TestPinnedValues(unittest.TestCase):
    def test_repo_slug(self):
        self.assertEqual(gh_transport.REPO_SLUG, "panopticon-scanner/panopticon")

    def test_local_tools_image(self):
        self.assertEqual(tools_image.LOCAL_NAME, "panopticon-tools")

    def test_registry_image(self):
        self.assertEqual(tools_image.REGISTRY_IMAGE,
                         "ghcr.io/panopticon-scanner/panopticon-tools:latest")

    def test_fixtures_image_and_root(self):
        self.assertEqual(tools_image.FIXTURES_NAME, "panopticon-fixtures")
        self.assertEqual(tools_image.FIXTURES_IMAGE, "panopticon-fixtures:latest")
        self.assertEqual(tools_image.FIXTURES_ROOT, "/opt/panopticon-fixtures")

    def test_the_registry_ref_and_the_slug_name_one_org(self):
        # skill/ cannot import scripts/, so the org is spelled in both homes;
        # this is what keeps the two from drifting apart.
        org = gh_transport.REPO_SLUG.split("/")[0]
        self.assertTrue(tools_image.REGISTRY_IMAGE.startswith("ghcr.io/%s/" % org),
                        tools_image.REGISTRY_IMAGE)


def _hard_coded_spellings(tree, rel):
    """(line, value) for each non-docstring string constant spelling a name."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.body and isinstance(node.body[0], ast.Expr):
                docstrings.add(id(node.body[0].value))
    homed = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = {t.id for t in node.targets if isinstance(t, ast.Name)}
            if any((rel, name) in HOMES for name in names):
                homed.update(id(n) for n in ast.walk(node.value))
    return sorted(
        (node.lineno, node.value) for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        and id(node) not in docstrings and id(node) not in homed
        and any(spelling in node.value for spelling in SPELLINGS))


class TestNoNewSpelling(unittest.TestCase):
    def test_nothing_outside_the_homes_spells_the_names(self):
        found = {}
        for top in ("skill", "scripts"):
            for path in sorted((REPO / top).rglob("*.py")):
                rel = path.relative_to(REPO)
                if ".panopticon" in rel.parts or "__pycache__" in rel.parts:
                    continue
                hits = _hard_coded_spellings(ast.parse(path.read_text(encoding="utf-8")),
                                             rel.as_posix())
                if hits:
                    found[rel.as_posix()] = hits
        self.assertEqual(found, {}, "use gh_transport.REPO_SLUG or a tools_image constant")

    def test_the_guard_sees_every_spelling(self):
        source = '''
"""A docstring naming panopticon-tools is prose, not a hit."""
# a comment naming panopticon-fixtures is not in the AST at all
IMAGE = "panopticon-tools"
REMEDY = ("pull it: docker tag x "
          "panopticon-tools:latest")
URL = f"https://github.com/panopticon-scanner/{name}"
ROOT = "/opt/panopticon-fixtures"
def f():
    """Neither is this one: panopticon-scanner."""
    return "ok"
LOCAL_NAME = "panopticon-tools"
'''
        self.assertEqual(_hard_coded_spellings(ast.parse(source), "elsewhere.py"), [
            (4, "panopticon-tools"),
            (5, "pull it: docker tag x panopticon-tools:latest"),
            (7, "https://github.com/panopticon-scanner/"),
            (8, "/opt/panopticon-fixtures"),
            (12, "panopticon-tools"),
        ])
        # the same assignment IS exempt inside its home
        self.assertEqual(_hard_coded_spellings(ast.parse('LOCAL_NAME = "panopticon-tools"\n'),
                                               "skill/scripts/tools_image.py"), [])


if __name__ == "__main__":
    unittest.main()
