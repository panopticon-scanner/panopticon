"""#1681 Plan 1 ratchet: only `repo_config.py` may spell a config filename.

`PENDING` is empty: no production module outside `repo_config.py` spells one.
A NEW literal anywhere else fails immediately."""
import os
import re
import tempfile
from pathlib import Path
import unittest

from conftest import REPO_ROOT

RUNTIME_ROOTS = ("skill/scripts", "scripts", "skill/workflows")
RUNTIME_SUFFIXES = frozenset({".py", ".js", ".cjs", ".mjs", ".sh", ".bash", ".zsh"})
OWNER = "skill/scripts/repo_config.py"
LITERALS = re.compile(r"""(?<![\w-])(\.?panopticon\.yml(\.draft)?|groups\.yml(\.draft)?|config\.json)(?![\w-])""")
PENDING = frozenset()


def _offenders(root=REPO_ROOT):
    found = set()
    root = Path(root)
    for surface in RUNTIME_ROOTS:
        for path in sorted((root / surface).rglob("*")):
            relative = path.relative_to(root).as_posix()
            if not path.is_file() or path.suffix not in RUNTIME_SUFFIXES or relative == OWNER:
                continue
            if LITERALS.search(path.read_text(encoding="utf-8")):
                found.add(relative)
    return found


class TestConfigNameLiterals(unittest.TestCase):
    def test_only_the_pending_modules_spell_a_config_name(self):
        extra = _offenders() - PENDING
        self.assertEqual(extra, set(), "spell config names through repo_config: %s" % sorted(extra))

    def test_the_owner_spells_them(self):
        with open(os.path.join(REPO_ROOT, OWNER), encoding="utf-8") as fh:
            self.assertTrue(LITERALS.search(fh.read()))

    def test_pattern_matches_path_embedded_spellings(self):
        self.assertTrue(LITERALS.search(".panopticon/groups.yml"))
        self.assertTrue(LITERALS.search("root/.panopticon/config.json"))
        self.assertFalse(LITERALS.search("tools-config.json"))
        self.assertFalse(LITERALS.search("my-groups.yml"))

    def test_every_runtime_surface_and_extension_is_scanned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = set()
            for surface in ("skill/scripts", "scripts", "skill/workflows"):
                for suffix in (".py", ".js", ".cjs", ".mjs", ".sh", ".bash", ".zsh"):
                    relative = surface + "/nested/offender" + suffix
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('".panopticon.yml"\n')
                    expected.add(relative)
            self.assertEqual(_offenders(root), expected)

    def test_owner_and_nonruntime_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (OWNER, "docs/example.py", "tests/example.py",
                             "skill/workflows/README.md", "scripts/example.json",
                             "skill/scripts/readme.txt"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('".panopticon.yml"\n')
            self.assertEqual(_offenders(root), set())
            # A same-named module elsewhere is not the canonical owner.
            (root / "scripts/repo_config.py").write_text('"config.json"\n')
            self.assertEqual(_offenders(root), {"scripts/repo_config.py"})

    def test_all_config_names_and_filename_boundaries(self):
        for name in (".panopticon.yml", ".panopticon.yml.draft", "panopticon.yml",
                     "panopticon.yml.draft", "groups.yml", "groups.yml.draft",
                     "config.json"):
            with self.subTest(name=name):
                self.assertEqual(LITERALS.search("root/" + name).group(), name)
                self.assertIsNone(LITERALS.search("unrelated-" + name.lstrip(".")))
        for name in ("panopticon.yml", "groups.yml", "config.json"):
            self.assertIsNone(LITERALS.search(name + "backup"))
