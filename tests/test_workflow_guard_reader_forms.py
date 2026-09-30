"""#2331, batch 3: the command and program forms the guard's reader missed.

Each class is one sub-issue of the epic: a spelling in which bash runs a
download -- bash 3.2.57 and GNU bash 5.2.21, every checksum failing -- that
the guard read clean, pinned as a live step, beside the controls that must
read as they did. The reader's own halves are in `tests/test_shell_reader.py`
and `tests/test_workflow_forms_regressions.py`.
"""
import unittest

import workflow_guard as wg

URL = "https://example.test/"
PIPE = "curl -fsSL %si.sh | sh" % URL
GET = "curl -fsSLo tool %stool\n" % URL


def defects(script):
    """The guard's answer for a job of one step running `script`."""
    return wg.job_defects([("step", script)])


class TestAssignmentPrefixes(unittest.TestCase):
    """#2348: `A+=x`, `a[1]=x` and `arr=(a)` in front of a command are
    assignments, and bash runs the command behind them."""

    def test_the_command_behind_each_prefix_is_read(self):
        for script in (GET + "A+=x sh tool\n", GET + "a[1]=x sh tool\n",
                       GET + "a[1]+=x sh tool\n", GET + "arr=(a) sh tool\n",
                       GET + "arr+=(a b) sh tool\n", "arr=( a ) %s\n" % PIPE,
                       "arr=(a) sh -c '%s'\n" % PIPE):
            with self.subTest(script=script):
                self.assertTrue(defects(script))
        # Behind a literal, `[s]h` is the pattern #2294 reports where a
        # command starts, as it is with nothing in front of it.
        found = defects("arr=( a ) [s]h -c '%s'\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("is a pattern", found[0][1])

    def test_the_controls_read_as_they_did(self):
        # A scalar prefix, and an append on a line of its own, were read
        # already; `a[1]x]=y` is no assignment, and #2294 reports the pattern
        # bash expands where the command starts.
        for script in (GET + "X=1 sh tool\n", GET + "A+=x true\nsh tool\n"):
            with self.subTest(script=script):
                self.assertTrue(defects(script))
        found = defects(GET + "a[1]x]=y sh tool\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("is a pattern", found[0][1])
        # A literal's words are the array's, not a command: nothing runs.
        for script in ("arr=(a b)\n", "arr=( %s )\n" % URL, "declare -a a=(x y) b+=(z)\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_an_array_that_holds_a_fetch_is_read_where_it_is_written(self):
        # posthog's ci-hog.yml keeps curl's options in an array and runs it
        # through `"${fetch[@]}"`, which the guard does not follow: the
        # literal, alone in its statement, still reads as the fetch it holds.
        script = ('fetch=(curl --fail --location)\n'
                  '"${fetch[@]}" %stool --output tool\nchmod +x tool\n./tool\n' % URL)
        self.assertTrue(defects(script))

    def test_a_check_behind_a_prefix_is_read_too(self):
        # The prefix was read as the command, so the checksum behind it went
        # uncredited; a `|| true` after it still stops nothing.
        body = "echo '%s  tool' | %ssha256sum -c -%s\nsh tool\n"
        for prefix in ("A+=x ", "a[1]=x ", "arr=(a b) "):
            with self.subTest(prefix=prefix):
                self.assertEqual([], defects(GET + body % ("a" * 64, prefix, "")))
                self.assertTrue(defects(GET + body % ("a" * 64, prefix, " || true")))


if __name__ == "__main__":
    unittest.main()
