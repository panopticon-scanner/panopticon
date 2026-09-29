"""#2234 (ARC-1496429894 sub-defect): the pin the mirror comment asked for.

`scripts/tools/sarif_utils.py` hand-mirrors the orchestrator's test-fixture
corpus definition -- `FIXTURE_DIR_BASENAMES`, `FIXTURE_PARENT_DIRS` and the
predicate over them -- because the module exists to break the import cycle back
to `ingest_tools` and cannot reach `discovery`. The mirror carried a comment
saying "update both places together" and nothing else: a grep for either name
over `tests/` returned zero hits, so the only guard on the #434 parity was the
comment.

Drift is silent and one-sided. The agentic review path prunes a fixture corpus
in standard mode (`discovery.prune_fixture_files`); the tool scanners walk the
whole repo and report real fixture paths, and `ingest_tools` prunes them here.
A basename added on one side only means the tool axis keeps reporting planted
fixture vulnerabilities that the review axis drops -- run-3 measured 67 such
findings, 11 of them CRITICAL, all planted noise.

So both halves are pinned: the two frozensets, value for value, and the two
PREDICATES over them, on a table of paths that covers each rule (a corpus
basename, a `fixtures` dir under each kind of test parent, ordinary source, and
a test file that is NOT a fixture).
"""
import unittest
from unittest import mock

import scripts.discovery as discovery
import scripts.tools.sarif_utils as su


def _discovery_says(path):
    """`discovery`'s verdict on a FILE path, composed the way discovery asks it.

    The two predicates take different arguments. `su._is_fixture_path` takes the
    file and walks its own ancestors; `discovery._is_fixture_dir` answers about
    ONE directory, and `discovery.prune_fixture_files` is what walks the
    ancestors (`_ancestor_dirs`). Composing those two here asks the same
    question of the same definition, so a disagreement is drift and not a
    difference of calling convention.
    """
    return any(discovery._is_fixture_dir(d) for d in discovery._ancestor_dirs(path))


class TestFixtureCorpusMirror(unittest.TestCase):
    def test_corpus_basenames_mirror_discovery(self):
        self.assertEqual(
            su._FIXTURE_DIR_BASENAMES, discovery.FIXTURE_DIR_BASENAMES,
            "sarif_utils mirrors discovery's fixture-corpus basenames; they "
            "have drifted")

    def test_corpus_parent_dirs_mirror_discovery(self):
        self.assertEqual(
            su._FIXTURE_PARENT_DIRS, discovery.FIXTURE_PARENT_DIRS,
            "sarif_utils mirrors discovery's fixture-corpus parent dirs; they "
            "have drifted")

    def test_both_predicates_agree_on_the_corpus(self):
        for path, fixture in (("tests/fixtures/x.py", True),
                              ("testdata/x.py", True),
                              ("spec/fixtures/x.py", True),
                              ("src/x.py", False),
                              ("tests/x_test.py", False)):
            with self.subTest(path=path):
                self.assertEqual(su._is_fixture_path(path), fixture)
                self.assertEqual(_discovery_says(path), fixture)

    def test_the_comparison_reports_a_divergence(self):
        # The guard is only as good as its detector: prove it fires. With
        # `spec` dropped from discovery's parent dirs, `spec/fixtures/x.py` is a
        # fixture to the tool path and ordinary code to the agentic path --
        # exactly the one-sided drift the mirror comment warns about, and the
        # table above goes red on it.
        with mock.patch.object(discovery, "FIXTURE_PARENT_DIRS",
                               frozenset({"tests", "test"})):
            self.assertTrue(su._is_fixture_path("spec/fixtures/x.py"))
            self.assertFalse(_discovery_says("spec/fixtures/x.py"))


if __name__ == "__main__":
    unittest.main()
