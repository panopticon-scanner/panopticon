"""#2237 (ARC-168995033, part a): no golden may name the operator's checkout.

`tests/goldens/tool-raw/` holds each adapter's raw tool output, and it is the
normalization contract's fixture corpus -- `tests/tools/test_normalization_
contract.py`, `tests/tools/test_legacy_sarif.py` and `tests/test_security_gate.py`
all read this directory. The rule for capturing one is already written down, in
that directory's own README: **mount a corpus, never your own checkout.**
`gitleaks`, `bandit` and `trivy` used to be pinned to `/mnt/panopticon` in
`capture_goldens.TARGETS`, so a refresh scanned the operator's real working tree
-- `.env` included, and run-12 committed a live API key gitleaks found into this
public directory. The code moved those three to `src_root`; the committed
artifacts were never re-captured.

So the contract is pinned to artifacts that assert the operator's layout rather
than the tool's output: `/mnt/panopticon` paths, and one `.worktrees/` segment
naming an operator worktree (`k3-ci-docker-config`) in a public file. The live
secret itself is scrubbed, so this is a provenance defect, not an exposure.

This is the ratchet, on the `tests/test_repo_config_literals.py` pattern: the
two markers may not appear in any golden, with today's three offenders in a
SHRINK-ONLY `PENDING` set. An entry that no longer offends fails as STALE, so
the set cannot record a debt that has been paid, and it empties when part (b)
re-captures the three against a synthetic `/src` corpus -- which needs the
fixtures image and therefore docker, so it is a follow-up and not this test.
"""
import re
import tempfile
from pathlib import Path
import unittest

from tests._test_helpers import REPO_ROOT

GOLDENS = "tests/goldens"

# `/mnt/panopticon` is the operator's checkout root. `.worktrees/` is a path
# SEGMENT (the lookbehind is what keeps `my.worktrees/` out of it), so a scratch
# worktree name cannot reach a public golden either -- run-8's tool-axis
# worktree-exclusion gap is how one got in.
OPERATOR_PATHS = re.compile(r"/mnt/panopticon|(?<![^\s\"'/])\.worktrees/")

# The rule's own documentation has to quote a forbidden path to state the rule.
# One file, named, and checked: `test_the_documentation_exemption_is_not_stale`
# fails if it stops quoting one, so the exemption cannot outlive its reason.
# Nothing else under the directory is exempt, `.md` included.
DOCUMENTED = frozenset({"tests/goldens/tool-raw/README.md"})

# The goldens that offend today. SHRINK-ONLY: an entry is a debt, not a
# permission, and it is removed in the same change that re-captures the file.
PENDING = frozenset({
    "tests/goldens/tool-raw/bandit.raw",
    "tests/goldens/tool-raw/gitleaks.raw",
    "tests/goldens/tool-raw/trivy.raw",
})


def _offenders(root=REPO_ROOT):
    """Every file under `tests/goldens/` naming the operator's checkout.

    Recursive, and every extension: a golden is whatever the capture wrote, so a
    surface restricted to `*.raw` would miss the next format silently. Raw tool
    output is not guaranteed to decode, and an undecodable byte is not a reason
    to skip a file, so it is replaced rather than raised on.
    """
    found = set()
    root = Path(root)
    base = root / GOLDENS
    for path in sorted(base.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if not path.is_file() or relative in DOCUMENTED:
            continue
        if OPERATOR_PATHS.search(path.read_text(encoding="utf-8", errors="replace")):
            found.add(relative)
    return found


class TestGoldensProvenance(unittest.TestCase):
    def test_no_golden_outside_pending_names_the_operators_checkout(self):
        extra = _offenders() - PENDING
        self.assertEqual(
            extra, set(),
            "golden(s) captured against the operator's own checkout: %s -- "
            "capture against a corpus mounted at /src (see "
            "tests/goldens/tool-raw/README.md), never your working tree"
            % sorted(extra))

    def test_every_pending_entry_still_offends(self):
        # The half that makes the set shrink-only. A re-captured golden must
        # LOSE its entry in the same change, or the ratchet records a debt that
        # has been paid and would let the file regress unnoticed.
        stale = sorted(PENDING - _offenders())
        self.assertEqual(
            stale, [],
            "PENDING names golden(s) that no longer offend: %s -- remove the "
            "entr(y/ies); the set only shrinks" % stale)

    def test_every_pending_entry_names_a_file_that_exists(self):
        missing = sorted(p for p in PENDING
                         if not (Path(REPO_ROOT) / p).is_file())
        self.assertEqual(missing, [], "PENDING names absent file(s): %s" % missing)

    def test_the_documentation_exemption_is_not_stale(self):
        for relative in sorted(DOCUMENTED):
            with self.subTest(relative=relative):
                path = Path(REPO_ROOT) / relative
                self.assertTrue(path.is_file(), relative)
                self.assertTrue(
                    OPERATOR_PATHS.search(path.read_text(encoding="utf-8")),
                    "%s no longer quotes a forbidden path, so it no longer "
                    "needs the exemption -- drop it from DOCUMENTED" % relative)

    def test_the_scan_reaches_every_depth_and_extension(self):
        # A must-trip control on a synthetic tree: the guard is only as good as
        # its reach, and a non-recursive walk or an extension filter would fail
        # OPEN on exactly the file someone adds next.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = set()
            for relative, body in (
                ("tests/goldens/a.raw", '{"uri": "file:///mnt/panopticon/"}'),
                ("tests/goldens/tool-raw/b.raw", 'file /src/.worktrees/w/x.py'),
                ("tests/goldens/deep/nested/c.txt", 'at /mnt/panopticon/x'),
                ("tests/goldens/d.json", '"/src/.worktrees/w"'),
                ("tests/goldens/clean.raw", '{"uri": "file:///src/app.py"}'),
                ("tests/goldens/my.worktrees/e.raw", "no marker here"),
                ("tests/goldens/f.raw", "a my.worktrees/ dir is not a segment"),
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
                if OPERATOR_PATHS.search(body):
                    expected.add(relative)
            self.assertEqual(expected, {"tests/goldens/a.raw",
                                        "tests/goldens/tool-raw/b.raw",
                                        "tests/goldens/deep/nested/c.txt",
                                        "tests/goldens/d.json"})
            self.assertEqual(_offenders(root), expected)

    def test_the_documented_exemption_is_by_path_not_by_extension(self):
        # A second `.md` under the directory is scanned like anything else: the
        # exemption is one named file, not a category.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in ("tests/goldens/tool-raw/README.md",
                             "tests/goldens/tool-raw/NOTES.md"):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("pinned to /mnt/panopticon once", encoding="utf-8")
            self.assertEqual(_offenders(root), {"tests/goldens/tool-raw/NOTES.md"})

    def test_undecodable_bytes_do_not_skip_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "tests/goldens/binary.raw"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\xff\xfe /mnt/panopticon/x")
            self.assertEqual(_offenders(root), {"tests/goldens/binary.raw"})


if __name__ == "__main__":
    unittest.main()
