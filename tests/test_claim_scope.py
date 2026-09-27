"""`scripts.claim_scope`: the ONE claim-path confinement and advisor root pin.

#1767 ARC-3314534783 (run-14): advisor-prompt assembly existed twice. The
driver's two advisor rounds confined each claim's `location.file` to the review
root and pinned that root (#run8 ARC-F2A); the CLI renderer reachable as
`dispatch.py --render-advisor` embedded the claim JSON verbatim and pinned the
process cwd, so a redteam target's `location.file` of `../../../.ssh/id_rsa`
steered an unconfined advisor on exactly the channel the project had already
ruled closed.

Both pieces therefore had to be reachable from `dispatch`, and `dispatch` is
imported by `runners/*`, which layout rule 3 (tests/test_layout.py) forbids from
reaching `scripts.phases`. So the confinement moved DOWN into a stdlib-only leaf
-- the same move #1735 made for the no-follow artifact open -- and
`phases/runio._confined_to_root` / `phases/verify_tools._confine_claim_location`
keep their private names as aliases of these functions. The identities are
pinned here, because a second implementation behind either name is the drift
layout rule 4 exists to prevent, and is what this issue was.
"""
import ast
import os
import sys
import tempfile
import unittest

import scripts.claim_scope as claim_scope
from scripts.phases import runio
from scripts.phases import verify_tools


# The two paragraphs the driver pinned before the move, byte for byte. A golden
# rather than a reference to the code: what the advisor reads must not drift
# silently, and the singular/plural pair is the only difference between the
# per-finding advisor's prompt and the cell advisor's.
GOLDEN_SINGULAR = (
    "Repo root: /repo\nEvery relative path in the claim below resolves against "
    "this root -- read files THERE, never in your session's default "
    "checkout.\n\n")
GOLDEN_PLURAL = (
    "Repo root: /repo\nEvery relative path in the claims below resolves against "
    "this root -- read files THERE, never in your session's default "
    "checkout.\n\n")


class TestOneImplementation(unittest.TestCase):
    """The driver's private spellings ARE these objects, not copies of them."""

    def test_runio_confinement_predicate_is_this_modules_function(self):
        self.assertIs(runio._confined_to_root, claim_scope.confined_to_root)

    def test_verify_tools_claim_confinement_is_this_modules_function(self):
        self.assertIs(verify_tools._confine_claim_location,
                      claim_scope.confine_claim_location)

    def test_verify_tools_redaction_marker_is_this_modules_constant(self):
        self.assertIs(verify_tools._REDACTED_CLAIM_PATH,
                      claim_scope.REDACTED_CLAIM_PATH)


class TestThisModuleIsALeaf(unittest.TestCase):
    """Nothing of ours is imported here, and that is load-bearing.

    `dispatch` imports this module, `runners/*` import `dispatch`, and layout
    rule 3 forbids `runners/*` from reaching `scripts.phases` -- so a project
    import here would put the phases package in every runner's import graph
    through the back door, which no AST rule would catch.
    """

    def test_claim_scope_imports_only_the_standard_library(self):
        path = os.path.abspath(claim_scope.__file__)
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), path)
        roots = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots += [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                roots.append((node.module or "").split(".")[0])
        outside = sorted(r for r in roots if r not in sys.stdlib_module_names)
        self.assertEqual(outside, [], "claim_scope must import nothing of ours")


class TestConfinedToRoot(unittest.TestCase):
    """The predicate itself, moved whole: absolute, `../` and symlink escapes."""

    def test_in_tree_paths_confine_and_escapes_do_not(self):
        with tempfile.TemporaryDirectory() as outside, \
             tempfile.TemporaryDirectory() as root:
            root = os.path.realpath(root)
            secret = os.path.join(os.path.realpath(outside), "secret.txt")
            open(secret, "w").close()
            os.makedirs(os.path.join(root, "src"))
            os.symlink(secret, os.path.join(root, "src", "evil"))
            self.assertFalse(claim_scope.confined_to_root(root, "src/evil"))
            self.assertFalse(claim_scope.confined_to_root(root, "../../etc/shadow"))
            self.assertFalse(claim_scope.confined_to_root(root, "/etc/passwd"))
            self.assertFalse(claim_scope.confined_to_root(root, ""))
            self.assertFalse(claim_scope.confined_to_root(root, None))
            open(os.path.join(root, "src", "real.py"), "w").close()
            self.assertTrue(claim_scope.confined_to_root(root, "src/real.py"))
            self.assertTrue(claim_scope.confined_to_root(root, "src/new.py"))


class TestConfineClaimLocation(unittest.TestCase):
    def test_an_escaping_relative_file_becomes_the_marker(self):
        loc = claim_scope.confine_claim_location(
            "/repo", {"file": "../../../.ssh/id_rsa", "line_start": 3})
        self.assertEqual(loc["file"], claim_scope.REDACTED_CLAIM_PATH)
        self.assertEqual(loc["line_start"], 3)              # siblings preserved

    def test_an_absolute_file_becomes_the_marker(self):
        loc = claim_scope.confine_claim_location("/repo", {"file": "/etc/passwd"})
        self.assertEqual(loc["file"], claim_scope.REDACTED_CLAIM_PATH)

    def test_a_symlink_that_resolves_outside_becomes_the_marker(self):
        with tempfile.TemporaryDirectory() as outside, \
             tempfile.TemporaryDirectory() as root:
            root = os.path.realpath(root)
            secret = os.path.join(os.path.realpath(outside), "secret.txt")
            open(secret, "w").close()
            os.makedirs(os.path.join(root, "src"))
            os.symlink(secret, os.path.join(root, "src", "evil"))
            loc = claim_scope.confine_claim_location(
                root, {"file": "src/evil", "line_start": 1})
        self.assertEqual(loc["file"], claim_scope.REDACTED_CLAIM_PATH)

    def test_an_in_tree_file_passes_through(self):
        loc = {"file": "src/auth.py", "line_start": 9}
        self.assertEqual(claim_scope.confine_claim_location("/repo", loc), loc)

    def test_absent_and_non_dict_locations_pass_through(self):
        self.assertIsNone(claim_scope.confine_claim_location("/repo", None))
        self.assertEqual(claim_scope.confine_claim_location("/repo", {}), {})
        self.assertEqual(claim_scope.confine_claim_location("/repo", "x"), "x")
        self.assertEqual(claim_scope.confine_claim_location("/repo", {"file": 7}),
                         {"file": 7})

    def test_the_callers_dict_is_not_mutated(self):
        loc = {"file": "../../../.ssh/id_rsa"}
        self.assertEqual(
            claim_scope.confine_claim_location("/repo", loc)["file"],
            claim_scope.REDACTED_CLAIM_PATH)
        self.assertEqual(loc["file"], "../../../.ssh/id_rsa")


class TestRootPinParagraph(unittest.TestCase):
    def test_the_singular_paragraph_is_the_drivers_bytes(self):
        self.assertEqual(claim_scope.root_pin_paragraph("/repo"),
                         GOLDEN_SINGULAR)

    def test_the_plural_paragraph_is_the_drivers_bytes(self):
        self.assertEqual(claim_scope.root_pin_paragraph("/repo", plural=True),
                         GOLDEN_PLURAL)

    def test_the_pinned_root_is_absolute(self):
        pin = claim_scope.root_pin_paragraph(os.path.join(".", "sub"))
        self.assertIn("Repo root: %s\n" % os.path.abspath("sub"), pin)


class TestReviewRootOfArtifactPath(unittest.TestCase):
    """The inverse of the driver's own run-folder path derivation: the review
    root is the directory above the path's `.panopticon` segment, which is the
    anchor the artifact-path guard and the reply placer already use."""

    def test_a_per_run_queue_path_resolves_to_the_review_root(self):
        self.assertEqual(
            claim_scope.review_root_of_artifact_path(
                "/repo/.panopticon/runs/claude-redteam-x/verify-queue.json"),
            "/repo")

    def test_a_top_level_artifact_path_resolves_to_the_review_root(self):
        self.assertEqual(
            claim_scope.review_root_of_artifact_path(
                "/repo/.panopticon/verify-queue.json"), "/repo")

    def test_a_path_with_no_artifact_segment_resolves_to_nothing(self):
        self.assertIsNone(
            claim_scope.review_root_of_artifact_path("/tmp/q/verify-queue.json"))

    def test_a_relative_path_is_resolved_against_the_cwd_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                got = claim_scope.review_root_of_artifact_path(
                    os.path.join(".panopticon", "verify-queue.json"))
            finally:
                os.chdir(cwd)
        self.assertEqual(got, os.path.realpath(tmp))

    def test_an_artifact_dir_at_the_filesystem_root_resolves_to_the_root(self):
        self.assertEqual(
            claim_scope.review_root_of_artifact_path("/.panopticon/q.json"),
            os.sep)


if __name__ == "__main__":
    unittest.main()
