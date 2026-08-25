import os
import unittest

import tomllib

from conftest import REPO_ROOT

PYPROJECT = os.path.join(REPO_ROOT, "pyproject.toml")


class TestPyproject(unittest.TestCase):
    def test_setuptools_is_pinned_exactly(self):
        with open(PYPROJECT, "rb") as fh:
            data = tomllib.load(fh)
        req = data["build-system"]["requires"][0]
        self.assertTrue(req.startswith("setuptools=="), req)
        self.assertNotIn(">=", req)

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
