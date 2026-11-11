"""Setup artifact path safety."""

import contextlib
import io
import json
import os
import tempfile
import unittest


import scripts.driver as driver
import scripts.first_contact as first_contact
import scripts.phases.setup as setup
import scripts.setup_flow as setup_flow
import scripts.setup_config as setup_config
import scripts.setup_spine as setup_spine
import shutil


from tests.setup_helpers import (
    _repo,
)

class TestSetupArtifactWritesDoNotFollowSymlinks(unittest.TestCase):
    """#1577 (SEC-D1C): the five `--setup` artifact writes were plain `open()`
    on paths derived from an untrusted target tree.

    `plan_contract.artifact_root()` validates that the `.panopticon` DIRECTORY
    is not a symlink; it never looks at the LEAF. A target that force-commits
    `.panopticon/setup-report.md -> ~/.bash_profile` (or plain
    `.gitignore -> ~/.ssh/authorized_keys`, which needs no `-f` at all) had
    panopticon's own boilerplate written or appended through the link, as the
    invoking user, on the documented first step for a repo nobody has vetted.

    The fix is the writer this repo already converged on -- `runio`'s confined
    `O_NOFOLLOW` pair -- not a sixth spelling of the check. It answers in two
    ways, and which one fires is a property of the path, not of the caller: a
    leaf under `.panopticon` whose link resolves OUT of it is REFUSED
    (`_confine_artifact_path`, the whole-path guard), while a link the
    confinement has nothing to say about -- `.gitignore` sits in the repo root,
    not the artifact tree -- is neutralized by `O_NOFOLLOW` and replaced by a
    fresh regular file. Either way the link's target is never opened.
    """

    def _victim(self, d, name="victim.txt"):
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("SECRET")
        return path

    def _assert_untouched(self, victim):
        with open(victim, encoding="utf-8") as fh:
            self.assertEqual("SECRET", fh.read(), "the link's target was written")

    def test_ensure_gitignore_does_not_append_through_a_planted_link(self):
        d = _repo(self)
        victim = self._victim(d)
        gi = os.path.join(d, ".gitignore")
        os.symlink(victim, gi)
        setup_config._ensure_gitignore(d)
        self._assert_untouched(victim)
        self.assertFalse(os.path.islink(gi), "the link survived the write")
        with open(gi, encoding="utf-8") as fh:
            self.assertIn(".panopticon/*", fh.read())

    def test_write_spine_does_not_write_through_a_planted_link(self):
        d = _repo(self)
        victim = self._victim(d)
        os.symlink(victim, os.path.join(d, ".panopticon", "setup-spine.json"))
        with self.assertRaises(ValueError):
            setup_spine.write_spine(d, setup_spine.build_spine(d))
        self._assert_untouched(victim)

    def test_render_scan_brief_does_not_write_through_a_planted_link(self):
        d = _repo(self)
        victim = self._victim(d)
        os.symlink(victim, os.path.join(d, ".panopticon", "setup-scan-brief.md"))
        vocab, _present = setup_spine.load_bundled_vocabulary()
        with self.assertRaises(ValueError):
            setup_spine.render_scan_brief(d, vocab)
        self._assert_untouched(victim)

    def test_ingest_proposal_does_not_write_through_planted_links(self):
        d = _repo(self)
        root = os.path.join(d, ".panopticon")
        with open(os.path.join(root, "setup-proposal.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/checkout/**"], "tests": []}]}, fh)
        # #1681: the draft is at the ROOT now, so the two halves of the guard
        # answer differently and BOTH are asserted here. `_confine_artifact_path`
        # raises only for a path that escapes `.panopticon` through a symlinked
        # component, so the ValueError below comes from the REPORT plants; at
        # the root the link is refused by O_NOFOLLOW and then unlinked and
        # replaced with a fresh regular file (#1095's contract, the one
        # `.gitignore` has always had). Either way nothing is written THROUGH a
        # link -- which is what every victim staying SECRET proves.
        draft = setup_flow.repo_config.draft_path(d)
        plants = {setup_flow.repo_config.DRAFT_NAME: draft}
        for name in ("setup-report.md", "setup-report.json"):
            plants[name] = os.path.join(root, name)
        for name, planted in plants.items():
            os.symlink(self._victim(d, "victim-%s" % name), planted)
        with self.assertRaises(ValueError):
            setup_flow.ingest_proposal(d)
        for name in plants:
            self._assert_untouched(os.path.join(d, "victim-%s" % name))
        self.assertFalse(os.path.islink(draft), "the root link survived the write")
        self.assertTrue(os.path.isfile(draft))

    def test_the_writes_still_land_on_an_honest_tree(self):
        # The guard must not be the thing that breaks setup: same artifacts,
        # no plants, all written.
        d = _repo(self)
        with open(os.path.join(d, ".panopticon", "setup-proposal.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"groups": [{"capability": "Checkout",
                                   "match": ["src/checkout/**"], "tests": []}]}, fh)
        setup_config._ensure_gitignore(d)
        setup_spine.write_spine(d, setup_spine.build_spine(d))
        vocab, _present = setup_spine.load_bundled_vocabulary()
        setup_spine.render_scan_brief(d, vocab)
        self.assertTrue(setup_flow.ingest_proposal(d)["ok"])
        for rel in (".gitignore", setup_flow.repo_config.DRAFT_NAME,
                    ".panopticon/setup-spine.json", ".panopticon/setup-scan-brief.md",
                    ".panopticon/setup-report.md", ".panopticon/setup-report.json"):
            self.assertTrue(os.path.isfile(os.path.join(d, rel)), rel)

    def test_a_planted_intermediate_panopticon_directory_is_refused(self):
        # The sibling half of the same plant: a real leaf under a `.panopticon`
        # that is itself a link out of the tree. #3271 B2: `driver setup`'s
        # first contact halts on it (H3) before any of these writes runs, and
        # writes nothing through it.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        outside = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(outside, ignore_errors=True))
        os.symlink(outside, os.path.join(d, ".panopticon"))
        with contextlib.redirect_stderr(io.StringIO()):
            status = setup.run_setup_flow(driver.build_parser().parse_args(["setup", d]))
        self.assertEqual(("error", first_contact.H3 % ""), (status["status"], status["message"]))
        self.assertEqual([], os.listdir(outside))

