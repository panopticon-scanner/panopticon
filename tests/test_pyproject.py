import os
import unittest

import tomllib
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from conftest import REPO_ROOT

PYPROJECT = os.path.join(REPO_ROOT, "pyproject.toml")


class TestPyproject(unittest.TestCase):
    def _assert_exact_setuptools_pin(self, requires):
        parsed = [Requirement(raw) for raw in requires]
        matches = [req for req in parsed
                   if canonicalize_name(req.name) == "setuptools"]
        self.assertEqual(len(matches), 1, requires)
        specifiers = list(matches[0].specifier)
        self.assertEqual(len(specifiers), 1, requires)
        self.assertEqual(specifiers[0].operator, "==", requires)
        self.assertNotIn("*", specifiers[0].version, requires)
        Version(specifiers[0].version)

    def test_setuptools_is_pinned_exactly(self):
        with open(PYPROJECT, "rb") as fh:
            data = tomllib.load(fh)
        requires = data["build-system"]["requires"]
        self._assert_exact_setuptools_pin(requires)
        self._assert_exact_setuptools_pin(["wheel>=0.40", *requires])
        for invalid in ([], ["wheel>=0.40"],
                        [*requires, "setuptools==83.0.0"],
                        ["setuptools>=84.0.0"], ["setuptools==84.*"],
                        ["setuptools>=84.0.0,<85"]):
            with self.subTest(invalid=invalid), self.assertRaises(AssertionError):
                self._assert_exact_setuptools_pin(invalid)

    def test_test_deps_are_subset_of_dev(self):
        with open(PYPROJECT, "rb") as fh:
            data = tomllib.load(fh)
        test = set(data["project"]["optional-dependencies"]["test"])
        dev = set(data["project"]["optional-dependencies"]["dev"])
        # dev may either inline the test deps or reference the test extra.
        self_references_test = any(
            req.startswith("panopticon[test]") for req in dev
        )
        self.assertTrue(
            test.issubset(dev) or self_references_test,
            f"test deps missing from dev: {test - dev}",
        )
        if self_references_test:
            self.assertTrue(
                any(req.startswith("ruff") for req in dev),
                "dev extra must still include ruff when delegating to test extra",
            )
