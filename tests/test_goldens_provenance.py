"""#2237 (ARC-168995033, part a): no golden may name the operator's checkout.

`tests/goldens/tool-raw/` holds each adapter's raw tool output, and it is the
normalization contract's fixture corpus -- `tests/tools/test_normalization_
contract.py`, `tests/tools/test_legacy_sarif.py` and `tests/test_security_gate.py`
all read this directory. The rule for capturing one is already written down, in
that directory's own README: **mount a corpus, never your own checkout.**
`gitleaks`, `bandit` and `trivy` used to be pinned to `/mnt/panopticon` in
`capture_goldens.TARGETS`, so a refresh scanned the operator's real working tree
-- `.env` included, and run-12 committed a live API key gitleaks found into this
public directory. The code moved those three to `src_root`, and part (b) (#2313)
re-captured the committed artifacts against a synthetic corpus at `/src`.

Until it did, the contract was pinned to artifacts that asserted the operator's
layout rather than the tool's output: `/mnt/panopticon` paths, and one
`.worktrees/` segment naming an operator worktree (`k3-ci-docker-config`) in a
public file. The live secret itself was scrubbed, so that was a provenance
defect, not an exposure.

This is the ratchet, on the `tests/test_repo_config_literals.py` pattern: the
two markers may not appear in any golden, and the SHRINK-ONLY `PENDING` set
names the ones that still do. It is EMPTY as of this change -- the three
re-captures emptied it -- so the guard now forbids both markers everywhere,
with nothing parked. An entry that no longer offends fails as STALE, so the set
can never record a debt that has been paid: a golden that regresses may be
parked here only while its re-capture is outstanding, and the entry comes OUT
in the same change that re-captures the file.

Every file under `tests/goldens/` is scanned, with no per-file exemption: the
directory's own README used to need one to quote the forbidden path while
stating the rule, and was reworded instead, because an exemption whose reason is
permanent prose is a hole the guard can never close.
"""
import re
import tempfile
from pathlib import Path
import unittest
import unittest.mock

from tests._test_helpers import REPO_ROOT

GOLDENS = "tests/goldens"

# `/mnt/panopticon` is the operator's checkout root (case-sensitive: that is how
# the tools wrote it). `.worktrees/` must START a path segment, which the
# lookbehind spells as "not preceded by a word character, a dot or a dash" --
# admitting whitespace, a quote, a slash, `(`, `=`, `[`, a backslash or nothing
# at all, because a tool writes a path inside argv echo, parentheses and brackets
# as readily as inside quotes, and refusing `my.worktrees/` and `a.worktrees/` is
# the only thing that has to stay out (both pinned below). Run-8's tool-axis
# worktree-exclusion gap is how a worktree name got into a public golden.
OPERATOR_PATHS = re.compile(r"/mnt/panopticon|(?<![\w.-])\.worktrees/")

# The goldens that offend today: none. SHRINK-ONLY -- an entry is a debt, not a
# permission, and it is removed in the same change that re-captures the file.
PENDING = frozenset()


def _offenders(root=REPO_ROOT):
    """Every file under `tests/goldens/` naming the operator's checkout.

    Recursive, every extension, and NO exemption: a golden is whatever the
    capture wrote, so a surface restricted to `*.raw` would miss the next format
    silently, and a per-file skip would stop the guard seeing whatever is added
    to that file next (fix round 1, finding 3 -- the directory's README was
    reworded so it no longer needs one). Raw tool output is not guaranteed to
    decode, and an undecodable byte is not a reason to skip a file, so it is
    replaced rather than raised on.
    """
    found = set()
    root = Path(root)
    base = root / GOLDENS
    for path in sorted(base.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if not path.is_file():
            continue
        if OPERATOR_PATHS.search(path.read_text(encoding="utf-8", errors="replace")):
            found.add(relative)
    return found


def _module():
    import sys
    return sys.modules[__name__]


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

    def test_a_paid_debt_left_in_pending_still_trips(self):
        # Must-trip control for the shrink-only half now that PENDING is empty:
        # a clean golden parked in the set must fail as STALE, or the rule
        # above is asserting over nothing.
        clean = "tests/goldens/tool-raw/semgrep.raw"
        self.assertNotIn(clean, _offenders())
        with unittest.mock.patch.object(_module(), "PENDING", frozenset({clean})), \
                self.assertRaises(AssertionError):
            self.test_every_pending_entry_still_offends()

    def test_every_pending_entry_names_a_file_that_exists(self):
        missing = sorted(p for p in PENDING
                         if not (Path(REPO_ROOT) / p).is_file())
        self.assertEqual(missing, [], "PENDING names absent file(s): %s" % missing)

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
                ("tests/goldens/e.raw", 'bandit(.worktrees/w/x.py)'),
                ("tests/goldens/g.raw", 'gosec --path=.worktrees/w'),
                ("tests/goldens/h.txt", 'trivy [.worktrees/w/x] HIGH'),
                ("tests/goldens/clean.raw", '{"uri": "file:///src/app.py"}'),
                ("tests/goldens/my.worktrees/i.raw", "no marker here"),
                ("tests/goldens/f.raw", "a my.worktrees/ dir is not a segment"),
                ("tests/goldens/j.raw", "nor is a.worktrees/ one"),
            ):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8")
                if OPERATOR_PATHS.search(body):
                    expected.add(relative)
            self.assertEqual(expected, {"tests/goldens/a.raw",
                                        "tests/goldens/tool-raw/b.raw",
                                        "tests/goldens/deep/nested/c.txt",
                                        "tests/goldens/d.json",
                                        "tests/goldens/e.raw",
                                        "tests/goldens/g.raw",
                                        "tests/goldens/h.txt"})
            self.assertEqual(_offenders(root), expected)

    def test_undecodable_bytes_do_not_skip_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "tests/goldens/binary.raw"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"\xff\xfe /mnt/panopticon/x")
            self.assertEqual(_offenders(root), {"tests/goldens/binary.raw"})


if __name__ == "__main__":
    unittest.main()
