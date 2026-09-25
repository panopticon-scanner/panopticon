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

    def test_an_in_tree_link_pair_is_not_recorded(self):
        # #1917 ruling: a `cp -al` tree or a pnpm store whose links all sit
        # INSIDE the review root carries no out-of-tree content -- every name
        # for that inode is in the tree the driver measured -- so denying the
        # directory Greps above it bought nothing. The walk counts the in-tree
        # occurrences of each inode and records only the files whose st_nlink
        # EXCEEDS that count.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            original = _write(os.path.join(root, "pkg", "m.py"), "x")
            copy = os.path.join(root, "build", "m.py")
            os.makedirs(os.path.dirname(copy), exist_ok=True)
            os.link(original, copy)
            found, overflowed = hard_links.hard_links_under(root)
        self.assertEqual([], found)
        self.assertFalse(overflowed)

    def test_an_inode_with_two_names_inside_and_one_outside_is_recorded(self):
        # The same count, one link further: three names, two of them in the
        # tree, so one is NOT -- and both in-tree names are a way to reach
        # content the grant never covered. Recorded, both of them.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            first = _write(os.path.join(root, "a.txt"), "x")
            second = os.path.join(root, "sub", "b.txt")
            os.makedirs(os.path.dirname(second), exist_ok=True)
            os.link(first, second)
            elsewhere = os.path.join(tmp, "elsewhere", "c.txt")
            os.makedirs(os.path.dirname(elsewhere), exist_ok=True)
            os.link(first, elsewhere)
            found, overflowed = hard_links.hard_links_under(root)
        self.assertEqual(sorted([first, second]), found)
        self.assertFalse(overflowed)

    def test_more_than_the_cap_recorded_is_reported_as_overflowed(self):
        # #1917 ruling (a) moved this: the walk no longer STOPS at the cap,
        # because whether a file belongs in the list is only known once its
        # inode's in-tree names have all been counted. The walk completes, the
        # filter runs, and the CAP applies to what was recorded.
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
        self.assertEqual(sorted(found), found)

    def test_exactly_the_cap_is_not_an_overflow(self):
        # ...and "more than the cap" means more: a tree holding exactly `cap`
        # recorded files is fully described by the list, so it is not reported
        # as a grant to close. (It used to be, because the walk could not tell
        # the inside of a stopped walk from a tree that ended there.)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            outside = _write(os.path.join(tmp, "secret.txt"), "s")
            os.makedirs(root, exist_ok=True)
            planted = [os.path.join(root, "l%02d.txt" % i) for i in range(3)]
            for path in planted:
                os.link(outside, path)
            self.assertEqual((sorted(planted), False),
                             hard_links.hard_links_under(root, cap=3))
            found, overflowed = hard_links.hard_links_under(root, cap=2)
        self.assertEqual(2, len(found))
        self.assertTrue(overflowed)

    def test_the_cap_bounds_the_recorded_files_not_the_walked_ones(self):
        # The consequence worth pinning: a tree full of BENIGN in-tree links
        # (the `cp -al` fixture the cap was sized for) no longer consumes it.
        # Six in-tree pairs and one planted link, with a cap of two: the one
        # link that leaves the tree is the whole answer, and the grant stays
        # open.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            for i in range(6):
                source = _write(os.path.join(root, "pairs", "f%02d.txt" % i), "x")
                os.link(source, os.path.join(root, "pairs", "f%02d-link.txt" % i))
            outside = _write(os.path.join(tmp, "secret.txt"), "s")
            planted = os.path.join(root, "planted.txt")
            os.link(outside, planted)
            found, overflowed = hard_links.hard_links_under(root, cap=2)
        self.assertEqual([planted], found)
        self.assertFalse(overflowed)

    def test_a_multiply_linked_fifo_is_not_recorded(self):
        # Ruling (d), pinning what the S_ISREG filter has always done: no
        # out-of-tree CONTENT rides on a FIFO or a socket -- there is nothing
        # at the other end of the link to read -- and ripgrep skips them, so a
        # multiply-linked non-regular file is not this rule's subject even when
        # one of its names is outside the tree.
        with tempfile.TemporaryDirectory() as tmp:
            tmp = os.path.realpath(tmp)
            root = os.path.join(tmp, "root")
            os.makedirs(root, exist_ok=True)
            pipe = os.path.join(tmp, "pipe")
            os.mkfifo(pipe)
            try:
                os.link(pipe, os.path.join(root, "pipe-link"))
            except OSError as exc:
                self.skipTest("this volume will not hard-link a FIFO: %s" % exc)
            found, overflowed = hard_links.hard_links_under(root)
        self.assertEqual([], found)
        self.assertFalse(overflowed)

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
        #
        # #1917 ruling (b) rests on this test: the in-tree count clears a `cp
        # -al` tree and does NOT clear a `--local` clone, whose partner inodes
        # live in the SOURCE repository. Such a target still overflows the cap
        # and still loses its directory Greps, with the `--no-hardlinks`
        # remedy on stderr. That is the recorded answer for a fence, not a
        # gap: nothing here can tell a benign source clone from a plant.
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
