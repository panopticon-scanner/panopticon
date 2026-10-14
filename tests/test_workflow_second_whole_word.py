"""#2976: a stage's second `${…}` word before the command word is kept whole too.

`curl -fsSLo t …` ⏎ `${Y:+/usr/bin/env true} ${Z:+/usr/bin/env true} sh t` read CLEAN under every `shell:`
setting while every parent shell ran the download: `shell_split._split` kept a `${…}` with bare blanks whole
only while no word kept whole stood in front of it (#2856 round 8's one command word, the #3002 round's `leads`
flag stopping at a word kept whole: "the second such word of a stage is #2976's"). The first word was read
whole, the second cut at its blanks, and the reading in which both are nothing -- `sh t` -- was never read.

Now a `${…}` word is kept whole wherever it still stands before the command word, behind words bash may make
nothing of, kept whole or not. The round-8 invariant holds: once the command word is set, every later `${…}`
word reaches the other readers as `main`'s split words (`tests/test_shell_reader.py` pins the splitter's side).
`shell_command._command_result` reads the second word as it reads the first: the empty half goes on to the
next word, the W half to its words.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports,
C where it reads the step CLEAN: first the job's, then the main pass's. Truth, in the comments, is what parent
shells do with the step: the kit's eight on the forge (bash 5.2.21, bash 3.2.57, dash; `-e`, `-eo pipefail`,
none) for the K-2856-limit rows, and bash 3.2.57, /bin/sh and zsh 5.9 with and without `-e` for the rest.
"runs" is every parent ran the download; "fetches only" is none ran it.

The price, pinned in `TestThePrice`: the reader reads BOTH halves of every such word whatever the step sets
(#2856 round 13), so `Y=1` in front does not make `${Y:+W}` its W -- `Y=1` ⏎ `${Y:+/usr/bin/env true} sh t`
reported on `main` already, and the two-word twin (the kit's s7.two-set) now reports as it does: an over-report
where nothing runs. A read that knows what the step set for sure before the stage is #3077's.
"""
import unittest

import workflow_guard as wg
import workflow_options as wo

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
U = "https://example.test/"
FETCH = "curl -fsSLo t %st\n" % U
W = "${Y:+/usr/bin/env true}"
W2 = "${Z:+/usr/bin/env true}"
REPORTED = ("RRRRR", "RRRRR")
CLEAN = ("CCCCC", "CCCCC")


def marks(text):
    """(the job's marks, the main pass's) for a job of one step whose `run:` is `text`."""
    job = mains = ""
    for shell in SHELLS:
        step = [wg.Step("step", text + "echo done\n", shell)]
        job += "R" if wg.job_defects(step) else "C"
        with wo.mains_answer():
            mains += "R" if wg._job_defects(step) else "C"
    return job, mains


class TestASecondWordBeforeTheCommandWordIsWhole(unittest.TestCase):
    """The kit's six rows (K-2856-limit: s7.two, s7.three, s7.two-fetch, s7.two-pipe, s7.two-same, s7.two-sudo),
    CLEAN on `main` under every setting while all sixteen parent runs ran the download."""

    def test_two_or_three_alternates_in_front_of_the_run_are_read_empty_together(self):
        # Truth: runs, every one.
        for text in (FETCH + "%s %s sh t\n" % (W, W2),
                     FETCH + "%s %s ${Q:+/usr/bin/env true} sh t\n" % (W, W2),
                     FETCH + "%s %s sh t\n" % (W, W)):
            with self.subTest(text=text.splitlines()[1][:40]):
                self.assertEqual(REPORTED, marks(text))

    def test_in_front_of_the_fetch_too(self):
        # `${Y:+…} ${Z:+…} curl -fsSLo t URL` ⏎ `sh t`, and the fetch piped to a shell. Truth: runs, every one.
        for text in ("%s %s curl -fsSLo t %st\nsh t\n" % (W, W2, U),
                     "%s %s curl -fsSL %st | sh\n" % (W, W2, U)):
            with self.subTest(text=text[:40]):
                self.assertEqual(REPORTED, marks(text))

    def test_a_wrapper_alternate_beside_the_other(self):
        # `${Y:+…} ${SUDO:+sudo -E} sh t`: with both names unset, `sh t`. Truth: runs, every one.
        self.assertEqual(REPORTED, marks(FETCH + "%s ${SUDO:+sudo -E} sh t\n" % W))

    def test_the_second_word_is_read_where_the_first_is_set_after_or_elsewhere(self):
        # The name set after the stage, in a branch not taken, in a subshell, as the stage's own prefix
        # assignment (bash expands the words before the assignment lands), set then unset, set then emptied:
        # the alternate is nothing at the stage and `sh t` runs. Truth: runs, every one.
        for before, after in (("", "Y=1\n"), ("if false; then Y=1; fi\n", ""), ("( Y=1 )\n", ""),
                              ("Y=1\nunset Y\n", ""), ("Y=1\nY=\n", "")):
            with self.subTest(before=before, after=after):
                self.assertEqual(REPORTED, marks(FETCH + before + "%s %s sh t\n" % (W, W2) + after))
        self.assertEqual(REPORTED, marks(FETCH + "Y=1 %s %s sh t\n" % (W, W2)))


class TestWhatReadAsItDid(unittest.TestCase):
    """The kit's controls, and the shapes with no run."""

    def test_one_such_word_and_a_wrapper_in_front_read_as_they_did(self):
        # s7.one, s7.sudo-two and s7.two-default: `main` reported them. Truth: runs, every one.
        for text in (FETCH + "%s sh t\n" % W, FETCH + "${SUDO:+sudo -E} %s sh t\n" % W,
                     FETCH + "%s ${SH:-sh} t\n" % W):
            with self.subTest(text=text.splitlines()[1][:40]):
                self.assertEqual(REPORTED, marks(text))

    def test_two_such_words_in_front_of_the_check_read_as_they_did(self):
        # s7.two-check: `${Y:+…} ${Z:+…} sha256sum -c sums` ⏎ `sh t`. The check stops the step under `-e`
        # and `sh t` runs without it (truth: 6 of 16); `main` reported it, and so does this.
        text = FETCH + "echo '%s  t' > sums\n%s %s sha256sum -c sums\nsh t\n" % ("a" * 64, W, W2)
        self.assertEqual(REPORTED, marks(text))

    def test_nothing_is_reported_where_nothing_runs(self):
        # Two such words in front of a command that runs no download, and a default whose W is harmless
        # (`${Y:-/usr/bin/env true} sh t`: W or the name's value, never nothing). Truth: fetches only.
        for text in (FETCH + "%s %s true t\n" % (W, W2), FETCH + "%s %s echo t\n" % (W, W2),
                     FETCH + "${Y:-/usr/bin/env true} sh t\n", FETCH + "Y=1\n${Y:-/usr/bin/env true} sh t\n"):
            with self.subTest(text=text.splitlines()[-1][:40]):
                self.assertEqual(CLEAN, marks(text))


class TestThePrice(unittest.TestCase):
    """Named limits, pinned as they read."""

    def test_a_name_the_step_set_in_front_does_not_make_its_alternate_its_W(self):
        # s7.two-set (`Y=1` ⏎ `${Y:+…} ${Z:+…} sh t`) read CLEAN on `main` by the same accident that hid the
        # six rows: the second word's first piece was a word the guard does not follow. Both halves of every
        # such word are read whatever the step set (#2856 round 13): the one-word `Y=1` ⏎ `${Y:+…} sh t`
        # reported on `main` already, and the two-word row now reads as it does. Truth: fetches only, every
        # one -- an over-report, #2976's named price; a read that knows a name set for sure before the stage
        # is #3077's, which moves these rows.
        for sets in ("Y=1\n", "Z=1\n", "Y=1\nZ=1\n", "export Y=1\n", 'Y="1"\n'):
            with self.subTest(sets=sets):
                self.assertEqual(REPORTED, marks(FETCH + sets + "%s %s sh t\n" % (W, W2)))
        self.assertEqual(REPORTED, marks(FETCH + "Y=1\n%s sh t\n" % W))


if __name__ == "__main__":
    unittest.main()
