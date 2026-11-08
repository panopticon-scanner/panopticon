"""#3405: setup_flow.py split along the #1589 seams.

`setup_preflight` holds the readiness checks, `setup_config` the config
seeding, `setup_spine` the spine and brief, and `setup_flow` keeps the ingest.
A moved name lives in exactly one module and is reached there; nothing is
re-exported through `setup_flow`. These tests pin that, so a stale reference
fails loudly rather than patching an attribute nobody reads.

The standalone start is pinned where it already was:
`tests/test_driver_entry.py::TestDriverEntrypoint` launches `driver.py` as a
fresh process with PYTHONPATH stripped, and importing the driver loads all four
modules, so a cycle among them fails that launch. A second launch here would
only add a subprocess site for the security gate to re-review.
"""
import ast
import re
import unittest
from pathlib import Path

import scripts.setup_config as setup_config
import scripts.setup_flow as setup_flow
import scripts.setup_preflight as setup_preflight
import scripts.setup_spine as setup_spine

REPO = Path(__file__).resolve().parent.parent

OWNED = {
    "setup_preflight": (
        "DEFAULT_RUNNER", "_PROBE_TIMEOUT", "_check_docker", "_check_git_root",
        "_check_groups_manifest", "_check_host_shells", "_check_nvd_key", "_driver_roles",
        "_probe", "readiness", "setup_readiness",
    ),
    "setup_config": (
        "_ALWAYS_IGNORE_ENTRIES", "_BLANKET_PROBE_PATH", "_CHECK_IGNORE_LINE", "_CONFIG_INT_KEYS",
        "_CONTENTS_FORM_RE", "_DRAFT_IGNORE_ENTRY", "_PANOPTICON_ARTIFACT_ENTRIES",
        "_PANOPTICON_BLANKET_RE", "_PANOPTICON_DIR_BLANKET", "_committed_settings",
        "_dir_blanket_ignored", "_draft_settings", "_ensure_gitignore", "_git_blanket_pattern",
        "_seed_groups_manifest", "config_overrides", "config_refusal", "migrate_config",
        "provision", "seed_flat_manifest", "seed_groups_manifest",
    ),
    "setup_spine": (
        "_AFFINITY_PATH", "_EXT_LANG", "_FRAMEWORK_HINTS", "_LAYERS_PATH", "_MANIFEST_NAMES",
        "_MAX_LANGUAGES", "_MAX_MANIFESTS", "_MAX_MANIFEST_BYTES", "_MAX_TEST_TREE_ROWS",
        "_MAX_TREE_ROWS", "_SKILL_DATA", "_SPINE_FILE", "_VOCAB_PATH", "_depth2_rows",
        "_detect_frameworks", "_render_catalog", "_render_catalog_entry", "_sanitize_spine_token",
        "build_spine", "format_budget", "format_spine", "load_bundled_layers",
        "load_bundled_vocabulary", "read_spine", "render_capability_catalog",
        "render_layer_catalog", "render_scan_brief", "write_spine",
    ),
}
MOVED = {name: owner for owner, names in OWNED.items() for name in names}
MODULES = {"setup_flow": setup_flow, "setup_preflight": setup_preflight,
           "setup_config": setup_config, "setup_spine": setup_spine}
# Which siblings each module may import. Lazy imports count: a function-body
# `from scripts import setup_flow` is still a cycle, only a later one.
MAY_IMPORT = {"setup_preflight": set(), "setup_config": set(),
              "setup_spine": {"setup_config"},
              "setup_flow": {"setup_config", "setup_spine"}}


def _top_level_names(module):
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
    return names


class TestOwnership(unittest.TestCase):
    def test_each_moved_name_is_defined_in_its_owner_and_nowhere_else(self):
        defined = {key: _top_level_names(module) for key, module in MODULES.items()}
        for name, owner in sorted(MOVED.items()):
            with self.subTest(name=name):
                self.assertIn(name, defined[owner])
                self.assertEqual([key for key in defined if key != owner and name in defined[key]],
                                 [])

    def test_setup_flow_does_not_re_export_a_moved_name(self):
        # An alias left here is a second patch target: a test patching it
        # would replace an attribute the owner's code never reads.
        self.assertEqual(sorted(name for name in MOVED if hasattr(setup_flow, name)), [])

    def test_the_siblings_import_in_one_direction(self):
        for key, module in MODULES.items():
            tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
            seen = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    seen.update(a.name.rsplit(".", 1)[-1] for a in node.names)
                elif isinstance(node, ast.ImportFrom):
                    seen.update(a.name for a in node.names)
                    seen.add((node.module or "").rsplit(".", 1)[-1])
            with self.subTest(module=key):
                self.assertEqual(seen & set(MODULES), MAY_IMPORT[key])


_STRING_REF = re.compile(r"\bsetup_flow\.(%s)\b" % "|".join(sorted(MOVED, key=len, reverse=True)))


def _references_through_setup_flow(tree):
    """(line, spelling) for each reference to a moved name through setup_flow."""
    aliases = {"setup_flow", "_setup_flow"}
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update(a.asname for a in node.names
                           if a.asname and a.name.endswith("setup_flow"))
        elif isinstance(node, ast.ImportFrom):
            aliases.update(a.asname or a.name for a in node.names if a.name == "setup_flow")
            if (node.module or "").endswith("setup_flow"):
                found.extend((node.lineno, a.name) for a in node.names if a.name in MOVED)

    def via(node):
        return ((isinstance(node, ast.Name) and node.id in aliases)
                or (isinstance(node, ast.Attribute) and node.attr in aliases))

    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.body and isinstance(node.body[0], ast.Expr):
                docstrings.add(id(node.body[0].value))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in MOVED and via(node.value):
            found.append((node.lineno, node.attr))
        elif (isinstance(node, ast.Call) and len(node.args) >= 2 and via(node.args[0])
              and isinstance(node.args[1], ast.Constant) and node.args[1].value in MOVED):
            found.append((node.lineno, node.args[1].value))
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and id(node) not in docstrings):
            found.extend((node.lineno, m.group(0)) for m in _STRING_REF.finditer(node.value))
    return sorted(set(found))


class TestNoStaleReferences(unittest.TestCase):
    def test_nothing_reaches_a_moved_name_through_setup_flow(self):
        # setup_flow no longer has these, so most stale spellings raise; the
        # string patch targets (`mock.patch("scripts.setup_flow.readiness")`)
        # would too, but `create=True`, `setattr(..., raising=False)` and a
        # code string a test hands a subprocess would not.
        stale = {}
        for top in ("skill", "tests", "devtools"):
            for path in sorted((REPO / top).rglob("*.py")):
                if ".panopticon" in path.relative_to(REPO).parts or path == Path(__file__).resolve():
                    continue   # this file's own spelling sample is the one allowed
                hits = _references_through_setup_flow(
                    ast.parse(path.read_text(encoding="utf-8")))
                if hits:
                    stale[str(path.relative_to(REPO))] = hits
        self.assertEqual(stale, {})

    def test_the_scan_sees_every_spelling(self):
        source = '''
setup_flow.readiness(".")
_setup_flow._check_docker
scripts.setup_flow.build_spine(".")
mock.patch.object(setup_flow, "provision")
monkeypatch.setattr(setup_flow, "_VOCAB_PATH", "x", raising=False)
mock.patch("scripts.setup_flow.load_bundled_vocabulary", create=True)
code = "import scripts.setup_flow\\nscripts.setup_flow.migrate_config('.')\\n"
from scripts.setup_flow import config_overrides
import scripts.setup_flow as sf
sf.render_scan_brief
setup_flow.ingest_proposal(".")
mock.patch("scripts.setup_flow.record_readiness")
setup_preflight.readiness(".")
'''
        self.assertEqual([spelling for _, spelling in
                          _references_through_setup_flow(ast.parse(source))], [
            "readiness", "_check_docker", "build_spine", "provision", "_VOCAB_PATH",
            "setup_flow.load_bundled_vocabulary", "setup_flow.migrate_config",
            "config_overrides", "render_scan_brief"])


if __name__ == "__main__":
    unittest.main()
