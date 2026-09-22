"""Tests for scripts.phases.hard_links: the ONE walk that makes a directory
read grant answerable (#1683).

The hook may not walk per call -- a synchronous PreToolUse hook that os.walks
the reviewed tree on every Grep is not a thing to ship -- so the walk happens
once, driver side, when the grant is built, and the hooks adjudicate against
the list it records. Everything this module has to get right is therefore a
property of the LIST: a multiply-linked regular file is in it, a symlink is
not, an entry that cannot be measured is in it (a fence that cannot measure
denies), and an unbounded tree is reported as overflowed rather than walked
into a scope file of unbounded size.
"""
import os
import tempfile
import unittest

import scripts.phases.hard_links as hard_links


def _write(path, text=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class TestHardLinksUnder(unittest.TestCase):
    def test_a_planted_link_is_listed_and_a_plain_file_is_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            outside = _write(os.path.join(tmp, "elsewhere", "secret.txt"), "s")
            plain = _write(os.path.join(root, "c", "plain.py"), "x")
            planted = os.path.join(root, "a", "b.txt")
            os.makedirs(os.path.dirname(planted), exist_ok=True)
            os.link(outside, planted)
            found, overflowed = hard_links.hard_links_under(root)
        self.assertEqual([planted], found)
        self.assertFalse(overflowed)
        self.assertNotIn(plain, found)

    def test_a_symlink_is_not_listed(self):
        # lstat, no follow: realpath is what resolves a symlink, everywhere
        # else in the read fence. A symlink's own st_nlink is 1 anyway, but
        # following one would report the TARGET's count against a name the
        # guard resolves elsewhere.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            outside = _write(os.path.join(tmp, "elsewhere", "secret.txt"), "s")
            other = os.path.join(tmp, "elsewhere", "also.txt")
            os.link(outside, other)            # target is multiply linked
            os.makedirs(root, exist_ok=True)
            os.symlink(outside, os.path.join(root, "pointer.txt"))
            found, overflowed = hard_links.hard_links_under(root)
        self.assertEqual([], found)
        self.assertFalse(overflowed)

    def test_the_walk_stops_at_the_cap_and_says_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            outside = _write(os.path.join(tmp, "secret.txt"), "s")
            os.makedirs(root, exist_ok=True)
            for i in range(6):
                os.link(outside, os.path.join(root, "l%02d.txt" % i))
            found, overflowed = hard_links.hard_links_under(root, cap=4)
        self.assertTrue(overflowed)
        self.assertEqual(4, len(found))

    def test_the_default_cap_is_256(self):
        self.assertEqual(256, hard_links.CAP)

    def test_a_clean_tree_is_empty_and_not_overflowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.realpath(tmp)
            _write(os.path.join(root, "pkg", "m.py"), "x")
            self.assertEqual(([], False), hard_links.hard_links_under(root))

    def test_a_directory_nothing_can_descend_is_recorded_whole(self):
        # Fix round 1 F4, restated for the walker: a fence that cannot measure
        # denies. Nothing can enumerate a 000 directory, so the DIRECTORY is
        # what gets recorded -- the hook's rule then denies every Grep at or
        # beneath it, which is the same answer its contents would have given.
        if os.geteuid() == 0:
            self.skipTest("root can descend anything")
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            shut = os.path.join(root, "shut")
            _write(os.path.join(shut, "x.txt"), "x")
            os.chmod(shut, 0o000)
            try:
                found, overflowed = hard_links.hard_links_under(root)
            finally:
                os.chmod(shut, 0o755)
        self.assertEqual([shut], found)
        self.assertFalse(overflowed)

    def test_an_entry_that_cannot_be_lstatted_is_recorded_as_if_linked(self):
        # A directory readable but not searchable (r--) yields its names and
        # refuses every lstat of them: measured nothing, so it denies.
        if os.geteuid() == 0:
            self.skipTest("root can stat anything")
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            listable = os.path.join(root, "listable")
            hidden = _write(os.path.join(listable, "x.txt"), "x")
            os.chmod(listable, 0o444)
            try:
                found, overflowed = hard_links.hard_links_under(root)
            finally:
                os.chmod(listable, 0o755)
        self.assertEqual([hidden], found)
        self.assertFalse(overflowed)

    def test_a_missing_root_is_empty_rather_than_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(([], False),
                             hard_links.hard_links_under(os.path.join(tmp, "nope")))

    def test_dot_git_is_not_pruned(self):
        # A `git clone --local` object store is exactly a set of links to
        # inodes outside the tree; pruning .git would walk past the most
        # likely planting ground there is.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            outside = _write(os.path.join(tmp, "secret.txt"), "s")
            planted = os.path.join(root, ".git", "objects", "ab", "cd")
            os.makedirs(os.path.dirname(planted), exist_ok=True)
            os.link(outside, planted)
            found, _ = hard_links.hard_links_under(root)
        self.assertEqual([planted], found)

    def test_results_are_sorted_realpaths(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            outside = _write(os.path.join(tmp, "secret.txt"), "s")
            os.makedirs(os.path.join(root, "z"), exist_ok=True)
            os.makedirs(os.path.join(root, "a"), exist_ok=True)
            os.link(outside, os.path.join(root, "z", "l.txt"))
            os.link(outside, os.path.join(root, "a", "l.txt"))
            # ...reached through a symlinked PARENT, so a caller that passes a
            # link to the root still records names the guard will match.
            alias = os.path.join(tmp, "alias")
            os.symlink(root, alias)
            found, _ = hard_links.hard_links_under(alias)
        self.assertEqual(sorted(found), found)
        self.assertEqual([os.path.join(root, "a", "l.txt"),
                          os.path.join(root, "z", "l.txt")], found)


if __name__ == "__main__":
    unittest.main()
