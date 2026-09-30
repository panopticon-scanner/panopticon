"""`scripts.safe_write`: the ONE no-follow `.panopticon` artifact open (#1735).

The primitive lived in `phases/runio`, which `run_manifest` may not import --
`phases/*` imports `run_manifest`, so the arrow only goes one way (layout rule
3) -- and neither may `synth/*`. Depending only on stdlib and the stdlib-only
`claim_scope` makes the guard reachable from all three, so every
`.panopticon`-resident writer can use the same guard.

runio keeps its private spellings as aliases of these functions: ~15 call
sites and the suite's one `mock.patch` target say `runio._open_w_nofollow`,
and a SECOND implementation behind that name is exactly the drift layout rule
4 exists to prevent -- so the identity is pinned here.
"""
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scripts.safe_write as safe_write
from scripts.phases import runio


class TestOneImplementation(unittest.TestCase):
    """runio's names ARE these functions -- not copies of them."""

    def test_runio_aliases_are_this_modules_functions(self):
        self.assertIs(runio._open_w_nofollow, safe_write.open_w_nofollow)
        self.assertIs(runio._open_a_nofollow, safe_write.open_a_nofollow)
        self.assertIs(runio._confine_artifact_path,
                      safe_write.confine_artifact_path)

    def test_flat_consumers_can_import_the_guard_without_the_phases_package(self):
        scripts = os.path.dirname(os.path.abspath(safe_write.__file__))
        probe = ("import sys; sys.path.insert(0, sys.argv[1]); import safe_write; "
                 "safe_write.confine_artifact_path('/repo/.panopticon/report.json'); "
                 "assert not any(m.startswith('scripts.phases') for m in sys.modules)")
        with tempfile.TemporaryDirectory() as root:
            subprocess.run([sys.executable, "-I", "-c", probe, scripts], cwd=root,
                           check=True, capture_output=True, timeout=30)


class TestNoFollowOpen(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.root = self._d.name
        self.addCleanup(self._d.cleanup)
        self.pano = os.path.join(self.root, ".panopticon")
        os.makedirs(self.pano)

    def _victim(self):
        victim = os.path.join(self.root, "victim.txt")
        with open(victim, "w", encoding="utf-8") as fh:
            fh.write("PRECIOUS")
        return victim

    def test_a_planted_symlink_out_of_the_tree_is_refused(self):
        # The plantable attack: the link points at a file the invoking user can
        # write. The whole-path confinement answers it FIRST -- loudly, and
        # before any byte moves -- so the O_NOFOLLOW fallback below is only ever
        # reached by a link that stays inside `.panopticon`.
        victim = self._victim()
        artifact = os.path.join(self.pano, "artifact.json")
        os.symlink(victim, artifact)
        with self.assertRaises(ValueError):
            safe_write.open_w_nofollow(artifact)
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")

    def test_a_planted_symlink_is_replaced_not_written_through(self):
        victim = self._victim()
        artifact = os.path.join(self.root, "artifact.json")   # no .panopticon segment
        os.symlink(victim, artifact)
        with safe_write.open_w_nofollow(artifact) as fh:
            fh.write("{}")
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")
        self.assertFalse(os.path.islink(artifact))
        self.assertTrue(os.path.isfile(artifact))

    def test_append_does_not_follow_a_planted_symlink(self):
        victim = self._victim()
        artifact = os.path.join(self.root, "ledger.jsonl")    # no .panopticon segment
        os.symlink(victim, artifact)
        with safe_write.open_a_nofollow(artifact) as fh:
            fh.write("line\n")
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), "PRECIOUS")
        self.assertFalse(os.path.islink(artifact))

    def test_confine_rejects_a_symlinked_intermediate_component(self):
        outside = os.path.join(self.root, "outside")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(self.pano, "runs"))
        with self.assertRaises(ValueError):
            safe_write.confine_artifact_path(
                os.path.join(self.pano, "runs", "tag", "report.json"))
        # a path with no `.panopticon` segment is not an artifact path
        safe_write.confine_artifact_path(os.path.join(self.root, "elsewhere.json"))

    def test_internal_links_remain_valid_for_writes_but_not_for_relink_parents(self):
        run = os.path.join(self.pano, "runs", "tag")
        os.makedirs(run)
        os.symlink("tag", os.path.join(self.pano, "runs", "latest"))
        artifact = os.path.join(self.pano, "runs", "latest", "report.json")
        safe_write.confine_artifact_path(artifact)
        with self.assertRaises(runio.DriverError):
            runio._confine_link_parent(artifact)

    def test_an_ancestor_link_preserves_the_lexical_anchor_and_resolves_for_relink(self):
        alias = os.path.join(self.root, "alias")
        os.symlink(self.root, alias)
        artifact = os.path.join(alias, ".panopticon", "runs", "report.json")
        safe_write.confine_artifact_path(artifact)
        self.assertEqual(runio._confine_link_parent(artifact),
                         os.path.join(os.path.realpath(self.pano), "runs"))

    def test_a_nested_anchor_cannot_reanchor_an_escaping_intermediate_link(self):
        outside = os.path.join(self.root, "outside")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(self.pano, "escape"))
        artifact = os.path.join(self.pano, "escape", ".panopticon", "report.json")
        with self.assertRaises(ValueError):
            safe_write.confine_artifact_path(artifact)
        with self.assertRaises(runio.DriverError):
            runio._confine_link_parent(artifact)

    def test_publication_stages_every_file_before_publishing_the_main_last(self):
        targets = [(os.path.join(self.pano, name), os.path.join(self.pano, name + ".tmp"),
                    name) for name in ("main.json", "part.json", "discarded.json")]
        real_replace = os.replace
        published = []

        def replace(source, destination):
            for final, temp, text in targets:
                with open(final if final in published else temp, encoding="utf-8") as stream:
                    self.assertEqual(stream.read(), text)
            real_replace(source, destination)
            published.append(destination)

        with mock.patch.object(safe_write.os, "replace", side_effect=replace):
            paths = safe_write.publish_texts(iter(targets))
        self.assertEqual(paths, [target[0] for target in targets])
        self.assertEqual(published, list(reversed(paths)))
        self.assertEqual(sorted(os.listdir(self.pano)),
                         ["discarded.json", "main.json", "part.json"])

    def test_publication_refuses_an_escaping_parent_before_creation_or_cleanup(self):
        outside = os.path.join(self.root, "outside")
        os.makedirs(outside)
        victim = os.path.join(outside, "staging.tmp")
        with open(victim, "w", encoding="utf-8") as stream:
            stream.write("PRECIOUS")
        os.symlink(outside, os.path.join(self.pano, "runs"))
        for suffix in ("staging.tmp", "new/staging.tmp"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                safe_write.publish_texts([(os.path.join(self.pano, "report.json"),
                                           os.path.join(self.pano, "runs", suffix), "{}")])
        with open(victim, encoding="utf-8") as stream:
            self.assertEqual(stream.read(), "PRECIOUS")
        self.assertEqual(os.listdir(outside), ["staging.tmp"])


if __name__ == "__main__":
    unittest.main()
