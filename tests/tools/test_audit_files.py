"""#3648: each dependency auditor exports the root files it reads, by ecosystem.

`audit_files` is the one list. The adapter's own `is_applicable` reads it, and
`tools_manifest` builds "why was this ecosystem not audited" from it, so a file
an adapter starts or stops reading changes both at once. These tests hold each
adapter's `is_applicable` to its own constant over a small set of trees.
"""
import os
import tempfile
import unittest
from unittest import mock

import scripts.tools_manifest as tools_manifest
from scripts.tools import ADAPTERS

AUDITORS = sorted(tools_manifest.DEPENDENCY_AUDIT_TOOLS)
# What dependency-check needs beside a build file: a resolved artifact to analyse.
ALSO_NEEDED = {"dependency-check": "lib/dep.jar"}
# Dependency manifests no auditor reads: the ecosystem is applicable, the adapter is not.
NOT_READ = ("package.json", "Cargo.toml", "Gemfile", "go.sum", "Pipfile", "setup.py")


def _tree(root, *names):
    for name in names:
        path = os.path.join(root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").close()
    return root


def _example(name):
    """A file name the entry matches: itself, or one instance of a pattern."""
    return name.replace("*", "-dev")


class TestEachAuditorIsSelectedByItsOwnList(unittest.TestCase):
    def test_every_dedicated_auditor_exports_a_list(self):
        for tool in AUDITORS:
            with self.subTest(tool=tool):
                files = ADAPTERS[tool].audit_files
                self.assertTrue(files)
                self.assertLessEqual(set(files),
                                     tools_manifest.DEPENDENCY_AUDIT_ECOSYSTEMS - {"unknown"})
                for names in files.values():
                    self.assertTrue(names and all(isinstance(n, str) and n for n in names))

    def test_each_listed_file_alone_selects_the_adapter(self):
        for tool in AUDITORS:
            for ecosystem, names in ADAPTERS[tool].audit_files.items():
                for name in names:
                    with self.subTest(tool=tool, file=name), tempfile.TemporaryDirectory() as d:
                        needed = [ALSO_NEEDED[tool]] if tool in ALSO_NEEDED else []
                        self.assertTrue(ADAPTERS[tool].is_applicable(
                            _tree(d, _example(name), *needed)))

    def test_a_tree_with_none_of_its_files_does_not(self):
        for tool in AUDITORS:
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as d:
                self.assertFalse(ADAPTERS[tool].is_applicable(d))
                extra = [ALSO_NEEDED[tool]] if tool in ALSO_NEEDED else []
                self.assertFalse(ADAPTERS[tool].is_applicable(_tree(d, *NOT_READ, *extra)))

    def test_the_selection_follows_the_list_and_not_a_copy_of_it(self):
        for tool in AUDITORS:
            adapter = ADAPTERS[tool]
            ecosystem, names = next(iter(adapter.audit_files.items()))
            moved = dict(adapter.audit_files, **{ecosystem: ("moved.lock",)})
            needed = [ALSO_NEEDED[tool]] if tool in ALSO_NEEDED else []
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as old, \
                    tempfile.TemporaryDirectory() as new, \
                    mock.patch.object(type(adapter), "audit_files", moved):
                self.assertTrue(adapter.is_applicable(_tree(new, "moved.lock", *needed)))
                self.assertFalse(adapter.is_applicable(
                    _tree(old, *[_example(n) for n in names], *needed)))

    def test_each_adapter_is_selected_by_its_own_file_test(self):
        # #3699 L1: `has_audit_file` is the test `is_applicable` runs, per file. They
        # differ between adapters (a regular file for some, any path for others), so
        # each is held to its own: a directory with the file's name, and the test
        # patched to say no.
        for tool in AUDITORS:
            adapter = ADAPTERS[tool]
            needed = [ALSO_NEEDED[tool]] if tool in ALSO_NEEDED else []
            for names in adapter.audit_files.values():
                for name in names:
                    with self.subTest(tool=tool, file=name), tempfile.TemporaryDirectory() as d:
                        _tree(d, *needed)
                        os.makedirs(os.path.join(d, _example(name)))
                        self.assertIs(adapter.has_audit_file(d, name), adapter.is_applicable(d))
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(type(adapter), "has_audit_file",
                                      staticmethod(lambda target, name: False)):
                every = [_example(n) for names in adapter.audit_files.values() for n in names]
                self.assertFalse(adapter.is_applicable(_tree(d, *every, *needed)))

    def test_a_regular_file_or_any_path(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("package-lock.json", "pom.xml", "Cargo.lock", "Gemfile.lock",
                         "requirements.txt"):
                os.mkdir(os.path.join(d, name))
            self.assertEqual(
                {"npm-audit": False, "osv-scanner": False, "dependency-check": False,
                 "cargo-audit": True, "bundler-audit": True, "pip-audit": True},
                {tool: ADAPTERS[tool].has_audit_file(d, {
                    "npm-audit": "package-lock.json", "osv-scanner": "package-lock.json",
                    "dependency-check": "pom.xml", "cargo-audit": "Cargo.lock",
                    "bundler-audit": "Gemfile.lock", "pip-audit": "requirements.txt"}[tool])
                 for tool in AUDITORS})

    def test_dependency_check_needs_an_artifact_beside_its_build_file(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(ADAPTERS["dependency-check"].is_applicable(_tree(d, "pom.xml")))
            self.assertTrue(ADAPTERS["dependency-check"].is_applicable(_tree(d, "lib/dep.jar")))


if __name__ == "__main__":
    unittest.main()
