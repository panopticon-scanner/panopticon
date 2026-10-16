"""#2889: an expansion in a shell's option word is text the word does not write.

`X=c; sh -$X 'P'` runs `P` under every parent shell, and read CLEAN: the readers of the programs lane asked an option
word for its letters, and `-$X` writes none of them. #3020 gave a lifted `$(...)` in such a word both readings a
shell may give it; this is the same rule for every other expansion, in four parts.

 1. A parameter reference in an option word (`$X`, `${...}`, `$1`, `$@`, `$-`) is text the word does not write, as a
    lifted substitution is (`workflow_option_words`): the word may spell any cluster, so every reader of #3020 reads
    it both ways. A NAME's letters stop being option letters: `sh -$cmd` writes no `c`. A reference that prints digits
    alone (`$#`, `$?`, `$$`, `$!`, `${#X}`) stays written.
 2. A word that holds an expansion may print an `o` or an `O`, which takes the next word: each word after it that
    may be a NAME may be its value, however many, at every option word the walk passes (`workflow_options._reached`).
    `sh -$(echo oc) errexit 'P'` and `X=o; sh -c -$X errexit 'P'` run `P`.
 3. A tilde alone (`~`, `~+`, `~-`, `~1`) is a value, as `$X` is: `HOME=-c; sh ~ 'P'` runs `P`.
 4. wget handed a whole-word expansion may be handed `-O-`: where its stdout is piped the stream view is added, and
    the file view stays `main`'s.
 5. An expansion in FRONT of an option word may print nothing (#3042): `sh $X-c 'P'` runs `P` with `X` unset, where
    `main` read `$X-c` as the FILE. Such a word is read both ways (`workflow_option_words.uncovered`) -- in a shell's
    words, its program on stdin and a fetcher's words -- under a switch of its own (`as_main`): `main` has had rule
    1 to 4 on since #2889 merged, so where this reading answered the job's floor reads `main`'s whole answer first.

Every new reading stands BESIDE `main`'s, never instead of it (`TestBesideNeverInstead`) -- and since the guard's
readers, handed more words, may choose a quieter reading of a step, the JOB is read both ways wherever the rule
answered in it: what `main` reported is reported (`TestWhatMainReportedIsReported`).

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports, C
where it reads the step CLEAN: first the job's, then the main pass's. Rows that hold a lifted substitution are read
under two pinned markers (`under`), as #3020's are.

Truth, in the comments, is what eight parent shells do with the step in two passes on the forge: bash 5.2.21 and
bash 3.2.57 under `-e` and under `-eo pipefail`, dash under `-e`, then each without `-e`; pass 2 gives each parent a
child shell of its own family. "runs" is all sixteen ran the download, "nothing" is none did.

THE PRICE, ruled before this was built (Krab 2423): the guard follows no value, so a word that MAY spell `-c` is
read as one whatever the step assigns -- `X=e; sh -$X 'P'` is reported and runs nothing, as `X=-e; sh $X 'P'` has
been since #2344. On the 13 grids behind these pins (14,322 rows) 507 rows that run are newly reported and 1,089
that run nothing: 937 of those are steps that fail where they stand (the shell takes the program text for a FILE's
name) and 139 of the rest are the `X=s` rows, whose string is a positional parameter. `TestThePrice` pins the shapes.
Left for other issues, pinned in `TestWhatStays`: the `$CMD` command word whose cluster is not its first word
(#2671, #2900), two shapes of wget (#3033, #3035), the first pass alone, and two families a probe of the rule's
own nouns found open on `main` as well: a substitution in the string's slot (#3043) and the value of a written `-O`
(#3044). #3034's fail-closed file view also reports the two process-substitution rows filed as #3045; their direct
stream binding remains a more precise reading. The fourth family, an expansion in FRONT of a written option word
(#3042), is rule 5.
"""
import ast
import contextlib
import itertools
import os
import random
import re
import secrets
import sys
import unittest
from unittest import mock

import shell_reader
import shell_tokens
import workflow_forms as wf
import workflow_guard as wg
import workflow_option_slots as slots
import workflow_option_words as words
import workflow_options as wo
import workflow_program_strings as ws
import workflow_programs as wp

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
URL = "https://example.test/i.sh"
PIPE = "curl -fsSL %s | sh" % URL
P = "'%s'" % PIPE
GET = "curl -fsSLo tool https://example.test/tool\n"
CHECK = 'echo "%s  tool" | sha256sum -c -' % ("0" * 64)
USE = "chmod +x tool; ./tool"
BODY = "<<'EOF'\n%s\nEOF\n" % PIPE
BOTH = ("RRRRR", "RRRRR")           # the job reports, and so does the main pass
WALK = ("RRRRR", "CCCCC")           # the second walk alone reads it
CLEAN = ("CCCCC", "CCCCC")


@contextlib.contextmanager
def nonce(digit):
    """Every marker a parse in this block mints is all `digit`: its 32 hex and the process's 16."""
    ours = digit * 16
    with mock.patch.object(secrets, "token_hex", lambda n=None: digit * (2 * (n or 32))), \
            mock.patch.object(shell_tokens, "_OURS", ours), \
            mock.patch.object(shell_tokens, "_NONCE", re.compile(r"@@shell-[0-9a-f]+%s-" % ours)):
        wp._parsed.cache_clear()            # a text parsed under another marker is parsed again
        try:
            yield
        finally:
            wp._parsed.cache_clear()


def marks(text):
    """(the job's marks, the main pass's) for a job of one step whose `run:` is `text`."""
    job = mains = ""
    for shell in SHELLS:
        step = [wg.Step("step", text, shell)]
        job += "R" if wg.job_defects(step) else "C"
        with wo.mains_answer():
            mains += "R" if wg._job_defects(step) else "C"
    return job, mains


def under(text, digits="0c"):
    """`marks(text)` under each pinned marker, as a set: one member where the reading is one."""
    found = set()
    for digit in digits:
        with nonce(digit):
            found.add(marks(text))
    return found


def both(read, first, refused=()):
    """The job's two passes as `workflow_option_words.passes` reads them, the floor taken out: the rule's reading alone."""
    with first():
        mains = read()
    found = [mains, read()]
    return found, found


def readings(text):
    """(the job's marks, the rule's reading ALONE -- the job's floor taken out -- and the job's with the rule off)."""
    job = alone = before = ""
    for shell in SHELLS:
        step = [wg.Step("step", text, shell)]
        job += "R" if wg.job_defects(step) else "C"
        with mock.patch.object(wg, "passes", both):
            alone += "R" if wg.job_defects(step) else "C"
        with words.as_before():
            before += "R" if wg.job_defects(step) else "C"
    return job, alone, before


RULED = ("RRRRR", "RRRRR", "CCCCC")         # the rule reads it; with the rule off it is CLEAN, as it is on `main`
FLOOR = ("RRRRR", "CCCCC", "RRRRR")         # `main` reports it and the rule's reading alone does not: the floor's
EITHER = ("RRRRR", "RRRRR", "RRRRR")


def argv(text):
    return shell_reader.statements(text)[-1].stages[0].argv


def texts(found):
    return [str(word) for word in found]


class TestAVariableInAnOptionWord(unittest.TestCase):
    """Rule 1, the string: `X=c; sh -$X 'P'`. CLEAN on `main` (13cdb9f7) wherever no `c` is written in the word or
    in the variable's NAME."""

    def test_a_c_the_variable_holds(self):
        # Truth: runs, every one, written `-` or `+` (#3020's first grid, the 54 rows `main` left open).
        for shell, sign in itertools.product(("sh", "bash", "dash"), "-+"):
            for word in ("%s$X", "%s${X}", '"%s$X"', "%se$X", "%s${X}e", "%sc$X", "%s${X}c", "%s${X:-c}", "%s${X:+c}"):
                with self.subTest(shell=shell, word=word % sign):
                    self.assertEqual(BOTH, marks("X=c\n%s %s %s\n" % (shell, word % sign, P)))

    def test_a_names_letters_are_no_option_letters(self):
        # `main` read the NAME for letters: `-$cmd` was a `-c` and `-$s` none. Truth: runs wherever the VALUE is `c`.
        for name in ("X", "s", "e", "o", "opts", "c", "cmd", "cfg"):
            for form in ("-$%s", "-${%s}", "-x$%s", '"-$%s"'):
                with self.subTest(name=name, form=form):
                    self.assertEqual(BOTH, marks("%s=c\nsh %s %s\n" % (name, form % name, P)))
        # A `c` WRITTEN beside the reference is the word's own, and read as it was.
        self.assertEqual(["P"], texts(ws._after_dash_c(argv("sh -c$opts 'P'"))))
        self.assertEqual(["one"], texts(ws._after_dash_c(argv("sh -c 'one' -$X 'P'"))))

    def test_however_the_step_sets_it(self):
        # Truth: runs, every one (the last, under bash: dash has no `+=`). The guard follows no value here.
        for sets in ("X=c\n", 'X="c"\n', "export X=c\n", "X=$(echo c)\n", ": ${X:=c}\n", "X=${Y:-c}\n",
                     "if true; then X=c; fi\n", "X=x\nX=c\n", "readonly X=c\n", "X=x\nX+=c\n"):
            with self.subTest(sets=sets):
                self.assertEqual({BOTH}, under("%ssh -$X %s\n" % (sets, P)))
        self.assertEqual(BOTH, marks("for X in c; do\nsh -$X %s\ndone\n" % P))

    def test_where_the_word_stands(self):
        # Beside other option words, behind a wrapper, a `$` command word, a default, in a string read again.
        # Truth: runs, every one (after `--norc` under bash alone).
        for row in ("sh -e -$X %s\n", "sh -$X -e %s\n", "sh -o errexit -$X %s\n", "bash --norc -$X %s\n", "env sh -$X %s\n",
                    "sudo sh -$X %s\n", "CMD=sh\n$CMD -$X %s\n", "${Z:-sh} -$X %s\n", "sh -$X$Y %s\n", "sh +$X %s\n"):
            with self.subTest(row=row[:22]):
                self.assertEqual(BOTH, marks("X=c\n" + row % P))
        self.assertEqual(BOTH, marks('X=c\nsh -c "sh -$X %s"\n' % P))
        self.assertEqual(BOTH, marks('X=c\necho "sh -$X %s" | sh\n' % P))

    def test_a_reference_that_prints_digits_alone_stays_written(self):
        # A count, a process id, a length: no digit is an option's letter, and bash and dash refuse a digit in a
        # cluster. Read as `main` read them. Truth: nothing.
        for word in ("-$#", "-$$", "-$!", "-${#X}", "-${#}", "-e$#"):
            with self.subTest(word=word):
                self.assertEqual(CLEAN, marks("sh %s %s\n" % (word, P)))
                self.assertFalse(words.lifted(argv("sh " + word)[1]))
        self.assertEqual(BOTH, marks("sh -c$# %s\n" % P))                      # the `c` is written
        self.assertEqual(BOTH, marks("X=c\nsh -$#$X %s\n" % P))                # a reference beside the count

    def test_the_other_references(self):
        # A positional, the set, a default, a pattern removal; and what only bash spells: an indirection, a slice,
        # an array's member, the last argument. Truth: runs, every one -- the first five under all sixteen, the
        # last four under every bash parent (dash refuses the spelling, or keeps no `$_`).
        for sets, word in (("set -- c\n", "-$1"), ("set -- c\n", "-${1}"), ("set -- c\n", "-$@"), ("", "-${X:-c}"),
                           ("X=xc\n", "-${X#x}"), ("Y=c\nX=Y\n", "-${!X}"), ("X=xc\n", "-${X:1:1}"), ("X=(c)\n", "-${X[0]}"),
                           (": c\n", "-$_")):
            with self.subTest(word=word):
                self.assertEqual(BOTH, marks("%ssh %s %s\n" % (sets, word, P)))
                self.assertTrue(words.lifted(argv("sh " + word)[1]))


class TestAVariableAndTheProgramOnStdin(unittest.TestCase):
    """Rule 1, the body: a name's letters hid it from the first pass. `main` read the `c` of `-$cmd` for the
    cluster and took the body for data; `cmd=x` runs the body, all sixteen."""

    def test_the_body_is_the_program_whatever_the_name(self):
        for name in ("X", "s", "e", "o", "c", "cmd", "cfg"):
            for form in ("-$%s", "-${%s}", "-x$%s", '"-$%s"'):
                with self.subTest(name=name, form=form):
                    self.assertEqual(BOTH, marks("%s=x\nsh %s %s" % (name, form % name, BODY)))

    def test_a_string_beside_the_body(self):
        # `sh -$X true <<EOF`: with `X=s` the body runs and `true` is a parameter, with `X=c` the string does.
        # Both are read. Truth: runs for `s`, nothing for `c`, `x`, `e`.
        for name in ("X", "s", "cmd", "e"):
            with self.subTest(name=name):
                self.assertEqual(BOTH, marks("%s=s\nsh -$%s true %s" % (name, name, BODY)))

    def test_a_check_in_what_the_word_may_hand_over_is_not_counted(self):
        # Truth: `X=x` runs the body, and its check stops the step under `-e`; `X=c` runs the string. The job
        # reports each: the second walk counts no check behind a word that may expand.
        for name in ("X", "s", "o", "cmd"):
            with self.subTest(name=name):
                self.assertEqual(BOTH, marks("%s%s=c\nsh -$%s '%s; %s'\n" % (GET, name, name, CHECK, USE)))
                self.assertEqual(BOTH, marks("%s%s=x\nsh -$%s <<'EOF'\n%s\n%s\nEOF\n" % (GET, name, name, CHECK, USE)))


class TestAValueTheWordMayOwe(unittest.TestCase):
    """Rule 2: an `o` or `O` the expansion prints takes the next word. CLEAN on `main`: its walk counted the values
    a word owes by the letters in its text."""

    def test_the_cluster_owes_a_name(self):
        # Truth: runs, every one.
        for shell in ("sh", "bash", "dash"):
            for words_ in ("-$(echo oc) errexit", "-$(echo o)c errexit", "+$(echo oc) errexit", "-x$(echo oc) errexit"):
                with self.subTest(shell=shell, words=words_):
                    self.assertEqual({BOTH}, under("%s %s %s\n" % (shell, words_, P)))
            for value, words_ in (("oc", "-$X errexit"), ("co", "-$X errexit"), ("oc", "-x$X errexit"), ("ooc", "-$X errexit nounset")):
                with self.subTest(shell=shell, value=value, words=words_):
                    self.assertEqual(BOTH, marks("X=%s\n%s %s %s\n" % (value, shell, words_, P)))

    def test_a_word_after_the_cluster_owes_one(self):
        # The word that holds the expansion stands AFTER the cluster that writes the `c`. Truth: runs, every one.
        for words_ in ("-c -$X errexit", "-c -e$X errexit", "-ec -$X errexit", "-c -x -$X errexit", "-c -$X errexit -x",
                       "-c +$X errexit", "+c -$X errexit"):
            with self.subTest(words=words_):
                self.assertEqual(BOTH, marks("X=o\nsh %s %s\n" % (words_, P)))
                self.assertEqual({BOTH}, under("sh %s %s\n" % (words_.replace("$X", "$(echo o)"), P)))

    def test_however_many(self):
        # Truth: runs, every one.
        for value, names in (("oooc", "errexit nounset xtrace"), ("ooooc", "errexit nounset xtrace pipefail")):
            with self.subTest(value=value):
                self.assertEqual(BOTH, marks("X=%s\nbash -$X %s %s\n" % (value, names, P)))
                self.assertEqual({BOTH}, under("bash -$(echo %s) %s %s\n" % (value, names, P)))
        self.assertEqual(BOTH, marks("X=oooc\nsh -c -$X errexit nounset xtrace %s\n" % P))
        # Each word of the walk that holds an expansion may owe them, the second as the first.
        for words_, found in (("-$X -$Y errexit nounset 'P'", ["errexit", "nounset", "P"]),
                              ("-$X -e$Y errexit nounset 'P' q", ["errexit", "nounset", "P", "q"]),
                              ("-$X -e errexit nounset 'P'", ["errexit"])):                     # a word that holds none owes none
            with self.subTest(words=words_):
                self.assertEqual(found, texts(wo._past_options(argv("bash " + words_), 1)))

    def test_any_word_shaped_as_a_name_may_be_one(self):
        # bash's `-O` takes a shopt name and no table of those is kept. Truth: runs under bash, every one.
        for words_ in ("-$X extglob", "-$X nullglob", "+$X extglob"):
            with self.subTest(words=words_):
                self.assertEqual(BOTH, marks("X=Oc\nbash %s %s\n" % (words_, P)))
        self.assertEqual(BOTH, marks("X=O\nbash -c -$X extglob %s\n" % P))
        self.assertEqual(BOTH, marks("X=Ooc\nbash -$X extglob errexit %s\n" % P))
        self.assertEqual({BOTH}, under("bash -$(echo Oc) extglob %s\n" % P))
        # A name that holds an expansion of its own, or is one.
        self.assertEqual(BOTH, marks("X=oc\nZ=exit\nsh -$X err$Z %s\n" % P))
        self.assertEqual(BOTH, marks("X=oc\nN=errexit\nsh -$X $N %s\n" % P))

    def test_what_is_no_name(self):
        # An option word is no NAME, nor a path, nor a program: the operand is the word itself. Truth: nothing.
        for word, found in (("-x", ["P"]), ("./x.sh", ["./x.sh"]), ("'a b'", ["a b"]), ("a/b", ["a/b"]),
                            ("errexit ./x.sh", ["errexit", "./x.sh"]), ("errexit nounset a/b", ["errexit", "nounset", "a/b"])):
            with self.subTest(word=word):
                self.assertEqual(found, texts(wo._past_options(argv("sh -$X %s 'P' q" % word), 1)))
        # ... and a NAME may be the last word there is.
        self.assertEqual(["errexit"], texts(wo._past_options(argv("sh -$X errexit"), 1)))
        self.assertEqual([], texts(wo._past_options(argv("sh -$X"), 1)))
        # At the guard the names end at the path, whose parameter the string is. Truth: nothing.
        for value in ("c", "oc", "ooc"):
            with self.subTest(value=value):
                self.assertEqual(CLEAN, marks("X=%s\nsh -$X errexit ./x.sh %s\n" % (value, P)))
        self.assertTrue(all(slots._may_be_name(argv("sh " + word)[1]) for word in ("errexit", "interactive-comments", "x_1", "err$X", "$N", "$(echo x)",
                                                                                  "Q", "Zx")))
        self.assertFalse(any(slots._may_be_name(argv("sh " + word)[1]) for word in ("-x", "+x", "./x", "a/b", "$X/y", "'a b'", "a=b")))

    def test_the_search_reads_on_as_mains_walk_does(self):
        # Behind a NAME the search goes on as `main`'s walk goes on behind a cluster: through an option word, to
        # the word behind a `-` or `--` whatever that is, and no further than a long word, which both bashes refuse
        # behind a cluster. The operand `main` found comes first (`errexit`, where the word owes nothing).
        for tail, found in (("-e 'P' q", ["errexit", "P"]), ("-e -x 'P' q", ["errexit", "P"]), ("-- 'P' q", ["errexit", "P"]),
                            ("- 'P' q", ["errexit", "P"]), ("-- -e 'P'", ["errexit", "-e"]), ("- -e 'P'", ["errexit", "-e"]),
                            ("--norc 'P' q", ["errexit"]), ("-e --norc 'P'", ["errexit"]), ("-o nounset 'P' q", ["errexit", "P"]),
                            ("-o 'P' q", ["errexit"]), ("-K 'P' q", ["errexit"])):     # the last two: bash refuses the word
            with self.subTest(tail=tail):
                self.assertEqual(found, texts(wo._past_options(argv("bash -$X errexit %s" % tail), 1)))
        for tail, found in (("-o 'P' q", ["errexit", "q"]), ("-K 'P' q", ["errexit", "P"])):    # zsh: no refusal is measured
            with self.subTest(tail=tail):
                self.assertEqual(found, texts(wo._past_options(argv("zsh -$X errexit %s" % tail), 1)))
        # The same at the guard. Truth: runs, every one.
        for tail in ("-e", "-e -x", "--", "-", "-o nounset"):
            with self.subTest(tail=tail):
                self.assertEqual(BOTH, marks("X=oc\nsh -$X errexit %s %s\n" % (tail, P)))
        self.assertEqual(BOTH, marks("X=o\nsh -c -$X errexit -e %s\n" % P))
        self.assertEqual(BOTH, marks("X=c\nsh -$X - %s\n" % P))
        # Truth: nothing, every one -- the shell runs `-e` for its string, or refuses the long word, the `-o` whose
        # value is no name, the letter `K`; or the words end at the NAME.
        for row in ("X=oc\nsh -$X errexit -- -e %s\n", "X=oc\nsh -$X errexit - -e %s\n", "X=x\nsh -c$X -- -e %s\n",
                    "X=x\nsh -c$X - -e %s\n", "X=oc\nbash -$X errexit --norc %s\n", "X=oc\nbash -$X errexit -e --norc %s\n",
                    "X=c\nbash -$X --norc %s\n", "X=x\nbash -c$X --norc %s\n", "X=oc\nbash -$X errexit -o %s q\n",
                    "X=oc\nbash -$X errexit -K %s q\n"):
            with self.subTest(row=row):
                self.assertEqual(CLEAN, marks(row % P))
        self.assertEqual(CLEAN, marks("X=oc\nsh -$X errexit\n"))

    def test_a_value_then_a_name_then_a_value(self):
        # The walk for a value among the options passes a NAME the word before it may owe. Truth: runs, the first
        # three; nothing for the last (`-x errexit`: the name is a FILE).
        for sets, words_ in (("X=o\nY=-c\n", "-$X errexit $Y"), ("X=oo\nY=-c\n", "-$X errexit nounset $Y"), ("X=x\nY=-c\n", "-$X $Y")):
            with self.subTest(words=words_):
                self.assertEqual(BOTH, marks("%ssh %s %s\n" % (sets, words_, P)))
        self.assertEqual({BOTH}, under("Y=-c\nsh -$(echo o) errexit $Y %s\n" % P))
        self.assertEqual(BOTH, marks("X=x\nY=-c\nsh -$X errexit $Y %s\n" % P))
        # Each pass has its walk, and each passes the NAME: only behind a word that holds an expansion, and not
        # past a long word, which owes none.
        for walk in (ws._candidates, wo._shell_candidates):
            with self.subTest(walk=walk.__name__):
                for words_ in ("-$X errexit $Y", "-$X errexit nounset $Y", "-e -$X errexit $Y"):
                    value, found = walk(argv("sh %s 'P'" % words_))
                    self.assertEqual(("$Y", ["P"]), (str(value), texts(found)), words_)
                for words_ in ("-x errexit $Y", "-$X --norc errexit $Y", "-$X ./f $Y", "errexit $Y", "-- errexit $Y"):
                    self.assertEqual((None, []), walk(argv("sh %s 'P'" % words_)), words_)
                for words_ in ("-o errexit $Y", "-eo errexit $Y", "-oo errexit nounset $Y"):   # a written `o`, as on `main`
                    value, found = walk(argv("sh %s 'P'" % words_))
                    self.assertEqual(("$Y", ["P"]), (str(value), texts(found)), words_)
        # No NAME is passed before an option word: the first operand ends the options whatever it is shaped as.
        # Truth: nothing.
        for row in ("X=-c\nsh tool $X %s\n", "X=-c\nsh errexit $X %s\n", "X=-c\nsh -- errexit $X %s\n"):
            with self.subTest(row=row):
                self.assertEqual(CLEAN, marks(row % P))
        self.assertEqual({CLEAN}, under("sh errexit $(echo -c) %s\n" % P))

    def test_a_refusal_by_name_is_read_before_the_first_expansion_only(self):
        # `X=O; bash -c${X}o extglob errexit 'P'` runs `P` (bash, all of its runs): the `O` takes `extglob`, the
        # written `o` takes `errexit`. `main` read the written `o` to take `extglob`, no `-o` name: refused, CLEAN.
        self.assertEqual(BOTH, marks("X=O\nbash -c${X}o extglob errexit %s\n" % P))
        self.assertEqual({BOTH}, under("bash -c$(echo O)o extglob errexit %s\n" % P))
        self.assertFalse(wo._refused_name(argv("bash -c${X}o extglob errexit 'P'"), 1))
        # An `o` written BEFORE the expansion takes the first word whatever follows: a refusal still. Truth: nothing.
        self.assertTrue(wo._refused_name(argv("sh -co$X bogus 'P'"), 1))
        self.assertEqual(CLEAN, marks("sh -co$X bogus %s\n" % P))
        self.assertEqual(CLEAN, marks("sh -co bogus %s\n" % P))

    def test_a_files_parameters(self):
        # `printf 'exec bash "$@"' > w.sh; X=oc; sh w.sh -$X errexit 'P'` runs `P`: past an operand the words are
        # the FILE's parameters, and a FILE may hand them to a shell. Truth: runs, every one.
        for words_ in ("-$X errexit", "-$(echo oc) errexit"):
            with self.subTest(words=words_):
                self.assertEqual({BOTH}, under("printf 'exec bash \"$@\"\\n' > w.sh\nX=oc\nsh w.sh %s %s\n" % (words_, P)))
        self.assertEqual(["errexit", "P"], texts(wo._operand_past(argv("sh w.sh -$X errexit 'P'"), 2, True)))
        # A long word there is one more parameter and owes no NAME, whatever it holds: no cluster is spelled `--`.
        self.assertEqual(["x"], texts(wo._operand_past(argv("sh f -$i --$n x 'P'"), 2, True)))
        self.assertEqual(["x", "P"], texts(wo._operand_past(argv("sh f -$i x 'P'"), 2, True)))
        # ... and the search goes on past it: behind the NAME `-$i` may owe, the long word is one parameter more.
        self.assertEqual(["n", "P"], texts(wo._operand_past(argv("sh f -$i n --flag 'P'"), 2, True)))
        self.assertEqual(["n"], texts(wo._operand_past(argv("sh f -$i n --flag 'P'"), 2)))      # where the shell parses: refused
        # No word there is refused, in any reading: `-o bogus` is the FILE's to read, and the walk goes on past it.
        self.assertEqual(["a", "P"], texts(wo._operand_past(argv("sh w.sh -o$X bogus a 'P'"), 2, True)))
        self.assertEqual([], texts(wo._operand_past(argv("sh w.sh -o$X bogus a 'P'"), 2)))


class TestATildeWord(unittest.TestCase):
    """Rule 3: `HOME=-c; sh ~ 'P'`. CLEAN on `main`, which read the tilde as the operand it is written as."""

    def test_where_a_shell_reads_its_options(self):
        # Truth: runs, every one (`~+`, `~-`, `~1` under bash: dash expands only `~`).
        for row in ("HOME=-c\n%s ~ {P}\n", "export HOME=-c\n%s ~ {P}\n", "HOME=-c\n%s -e ~ {P}\n", "HOME=-c\n%s ~ -e {P}\n",
                    "HOME=-co\n%s ~ errexit {P}\n", "HOME=-o\n%s ~ errexit -c {P}\n", "HOME=-c\nenv %s ~ {P}\n",
                    "HOME=-x\n%s ~ -c {P}\n"):
            for shell in ("sh", "bash", "dash"):
                with self.subTest(row=row[:24], shell=shell):
                    self.assertEqual(BOTH, marks((row % shell).replace("{P}", P)))
        # After a `-c` that is written the first pass takes the tilde for the string; the second walk reads on past
        # a value there (#2858 round 7), and the job reports. Truth: runs (`sh -c -x 'P'`).
        self.assertEqual(WALK, marks("HOME=-x\nsh -c ~ %s\n" % P))
        for row in ("PWD=-c\nbash ~+ %s\n", "OLDPWD=-c\nbash ~- %s\n", "pushd /tmp >/dev/null\nDIRSTACK[1]=-c\nbash ~1 %s\n"):
            with self.subTest(row=row[:12]):
                self.assertEqual(BOTH, marks(row % P))

    def test_a_command_word_and_a_pipes_reader(self):
        # Truth: runs, every one.
        self.assertEqual(BOTH, marks("HOME=sh\n~ -c %s\n" % P))
        self.assertEqual(BOTH, marks("HOME=sh\ncurl -fsSL %s | ~\n" % URL))
        self.assertEqual(BOTH, marks("HOME=sh\ncurl -fsSL %s | ~ -s\n" % URL))

    def test_what_is_a_path_and_what_is_text(self):
        # `~/x` and `~root` are paths: no shell takes a cluster holding a `/`. `-~` is text. Truth: nothing.
        for word in ("~/x", "~root", "-~", "x=~", "~++", "~+-", "~--1"):     # no shell expands two signs
            with self.subTest(word=word):
                self.assertEqual(CLEAN, marks("HOME=-c\nsh %s %s\n" % (word, P)))
                self.assertFalse(slots._value(argv("sh " + word)[1]))
        for word in ("~", "~+", "~-", "~1", "~+2", "~-0", "~10", "~+12"):       # a directory of the stack, however deep
            with self.subTest(word=word):
                self.assertTrue(slots._value(argv("sh " + word)[1]))

    def test_it_is_read_beside_mains_reading_of_it(self):
        # `main` read a tilde as the FIRST OPERAND, and weighed every word after a later one that may spell an
        # option. As a value it stands before the operand, which is then a later word: read alone, that reading
        # drops a word `main` weighed (the fuzz's row: `main` reports it and the first build of this did not;
        # truth: nothing, `$o` is no option).
        rest = argv("sh $o pipefail ~1 -K$s 'check' 'P'")[2:]
        self.assertEqual(["pipefail", "~1", "check", "P", "-K$s"], texts(slots._reopened(rest)))
        self.assertEqual(BOTH, marks("${X:-sh} $o pipefail ~1 -K$s '%s; %s' %s\n" % (CHECK, USE, P)))
        # and the other way: the word only the value reading weighs. Truth: runs (`sh -x -c 'P'`).
        self.assertEqual(BOTH, marks("X=-x\nHOME=-c\nsh $X ~ %s\n" % P))
        self.assertEqual(["~", "P"], texts(slots._reopened(argv("sh $X ~ 'P'")[2:])))
        # ... and PAST the first operand a tilde may spell an option, as `$Y` may there: the words behind it are
        # weighed. Unmeasured: a FILE that hands its parameters to a shell (`w.sh` an `exec sh "$@"`) would run `P`.
        self.assertEqual(["./f", "P"], texts(slots._reopened(argv("sh $X ./f ~ 'P'")[2:])))
        self.assertEqual(RULED, readings("sh $X ./f ~ %s\n" % P))
        # A `$` word's stdin, after a value: `main` took the tilde for an operand, which leaves stdin the program.
        # Each pass's walk keeps that answer; read as a value alone the tilde is passed, and the `-c` takes it away.
        # Truth: fetched only (the tilde is a directory).
        self.assertEqual(BOTH, marks("CMD=$(command -v sh)\ncurl -fsSL %s | $CMD $V ~ -c true\n" % URL))
        words_ = argv("$CMD $V ~ -c true")
        self.assertEqual([wp.VALUE_PROGRAM, wp.VALUE_PROGRAM], [wp._options(words_, 0)[0], wp._walk(words_, 0)[0]])
        twin = argv("$CMD $V $W -c true")
        self.assertEqual([None, None], [wp._options(twin, 0)[0], wp._walk(twin, 0)[0]])


class TestAFetcherHandedAnExpansion(unittest.TestCase):
    """Rule 4, and rule 1 in a fetcher's option word. `wget $(echo -qO-) URL | sh` and `wget -q$X -O- URL | sh`
    read CLEAN on `main`: the first an operand beside the URL, the second wget's `-X`, which takes the next word."""

    def test_a_variable_among_the_letters_leaves_the_transfer_unread(self):
        # Truth: runs, both, with `X=qO-` and with X never set.
        for fetch in ("wget -q$X -O-", "wget -q${X} -O-", "curl -fsSL$X", "curl -fsS$X -L"):
            with self.subTest(fetch=fetch):
                self.assertEqual(BOTH, marks("%s %s | sh\n" % (fetch, URL)))
        self.assertEqual(BOTH, marks("wget -q$X -O tool %s\nsh tool\n" % URL))

    def test_a_whole_word_expansion_may_be_the_option_that_streams(self):
        # Truth: runs, every one (the wget of the truth runner writes files as wget does).
        for row in ("wget $(echo -qO-) %s | sh\n", "X=-qO-\nwget $X %s | sh\n", 'X=-qO-\nwget "$X" %s | sh\n', "X=-O-\nwget -q $X %s | sh\n",
                    "X=-qO-\nwget %s $X | sh\n".replace("%s $X", "{U} $X").replace("{U}", "%s"), "X=-O-\nwget -O tool $X %s | sh\n",
                    "X=-qO-\nwget $X %s | bash -s\n", "wget $(echo -qO-) %s | cat | sh\n", "HOME=-qO-\nwget ~ %s | sh\n"):
            with self.subTest(row=row[:26]):
                self.assertEqual({BOTH}, under(row % URL))
        # One unquoted and alone may be the option and the URL both; one quoted is ONE word. Truth: runs; fetched only.
        self.assertEqual(BOTH, marks("X='-qO- %s'\nwget $X | sh\n" % URL))
        self.assertEqual(CLEAN, marks("X='-qO- %s'\nwget \"$X\" | sh\n" % URL))

    def test_the_file_view_stays(self):
        # The stream view is added where stdout is piped; the file `main` reads the transfer into stays. Truth: runs,
        # the first two. The third is `main`'s own report, kept: its expansion IS the stream, so nothing lands in
        # `i.sh` (fetched only), and the file view reports the step as it does on `main`.
        self.assertEqual(BOTH, marks("X=-q\nwget $X %s\nsh i.sh\n" % URL))
        self.assertEqual(BOTH, marks("X=-q\nwget $X %s -O tool\nsh tool\n" % URL))
        self.assertEqual({BOTH}, under("wget $(echo -qO-) %s | cat\nsh i.sh\n" % URL))
        # #3034: a whole-word expansion beside a written URL may instead name the destination, so
        # the file view is unread even when nothing is piped or run.
        self.assertEqual(BOTH, marks("wget $OPTS %s\n" % URL))
        self.assertEqual(CLEAN, marks("wget -q \"$A\" \"$B\"\n"))
        # Two URLs written out hand no option on: wget writes two files and the pipe is empty. Truth for these
        # three and for curl's row: fetched only.
        self.assertEqual(CLEAN, marks("wget %s %s2 | sh\n" % (URL, URL)))
        self.assertEqual(BOTH, marks("curl $OPTS %s\n" % URL))

    def test_3034_a_whole_word_expansion_may_name_wgets_destination(self):
        # Each download lands in `tool` under all sixteen truth runners. The guard used to keep the
        # written URL as wget's one operand and therefore bind only its basename, `i.sh`.
        rows = (
            "X='-O tool'\nwget $X %s\nsh tool\n" % URL,
            'X=-Otool\nwget "$X" %s\nsh tool\n' % URL,
            "X=-O\nwget $X tool %s\nsh tool\n" % URL,
        )
        for row in rows:
            with self.subTest(row=row.splitlines()[0]):
                self.assertEqual(BOTH, marks(row))
        self.assertEqual({BOTH}, under("wget $(echo -O tool) %s\nsh tool\n" % URL))

        # The checksum names the basename that wget does not write. It stops the ten `-e` truth
        # runs and the remaining six run `tool`; it must not bless the unresolved transfer.
        checked = ("X='-O tool'\nwget $X %s\n" % URL
                   + 'echo "%s  i.sh" | sha256sum -c -\nsh tool\n' % ("0" * 64))
        self.assertEqual(BOTH, marks(checked))

        # #3034's expansion reading stands beside the pre-#2889 file view, never in its place.
        with words.as_before():
            self.assertEqual(CLEAN, marks(rows[0]))

    def test_3034_controls_keep_their_readings(self):
        # curl already fails closed on the extra operand; wget's benign option still binds the
        # URL basename. With no written URL, two unknown operands remain the bounded clean case.
        self.assertEqual(BOTH, marks("X='-o tool'\ncurl $X %s\nsh tool\n" % URL))
        self.assertEqual(BOTH, marks("X=-q\nwget $X %s\nsh i.sh\n" % URL))
        self.assertEqual(CLEAN, marks('wget -q "$A" "$B"\n'))


class TestAnExpansionInFrontOfAnOptionWord(unittest.TestCase):
    """Rule 5 (#3042). `sh $X-c 'P'` runs `P` with `X` unset, as `sh -c 'P'` does, and read CLEAN on `main`, which took
    `$X-c` for the FILE the shell runs and `P` for that FILE's parameter. A word whose expansions in FRONT of an option
    word may print nothing IS that option word then (`workflow_option_words.uncovered`), so the rule reads the words
    that way too, after reading them as written -- in the search for the `-c` string, the second walk's, the search for
    a value, the second walk's program on stdin and a fetcher's words -- and hands on the step's own words alone; and
    where it answered, the job reads `main`'s whole answer first (`as_main`). `SHELL` is `sh`, then `bash`."""

    def assertRead(self, expected, *rows):
        for row in rows:
            for shell in ("sh", "bash") if "SHELL" in row else ("",):
                for digit in "0c" if "$(" in row or "`" in row else "0":
                    text = row.replace("SHELL", shell)
                    with self.subTest(text=text, digit=digit), nonce(digit):
                        self.assertEqual(expected, readings(text))

    def test_the_issues_rows(self):
        # #3042's shapes. Truth: runs, all sixteen, every one.
        self.assertRead(RULED, *(row % P for row in (
            "SHELL $X-c %s\n", "SHELL $X-ec %s\n", "SHELL ${X}-c %s\n", "SHELL ${X:-}-c %s\n", "SHELL $X$Y-c %s\n",
            'SHELL "$X"-c %s\n', "X=; SHELL $X-c %s\n", "SHELL $(true)-c %s\n", "SHELL $X+c %s\n", "SHELL -c $X-e %s\n",
            "sudo SHELL $X-c %s\n", "SHELL $X-c %s <<'EOF3042'\necho body\nEOF3042\n")))
        self.assertRead(RULED, "wget $X-qO- %s | sh\n" % URL, "wget ${X}-O- %s | sh\n" % URL)

    def test_every_expansion_that_may_print_nothing(self):
        # Truth: runs, all sixteen, every one -- but `${!X}` (bash 3.2.57 alone runs it), `${X:0:0}` and `${X/a/b}`
        # (bash, not dash) and `$-` (dash without `-e` alone): each is read as the others are, as the shell is not known.
        self.assertRead(RULED, *("SHELL %s-c %s\n" % (front, P) for front in (
            "${X-}", "${X:+y}", "${X#*}", "${X%%*}", '"${X}"', "$1", "$@", '"$@"', "$*", '"$*"', "`true`", "$(printf '')",
            '"$(true)"', "${X:-${Y:-}}", "$(true)$X", "${!X}", "$-")))
        self.assertRead(RULED, "bash ${X:0:0}-c %s\n" % P, "bash ${X/a/b}-c %s\n" % P, "X=' '; SHELL $X-c %s\n" % P,
                        "X='-e '; SHELL $X-c %s\n" % P, 'SHELL "$X-c" %s\n' % P, 'SHELL "${X}-c" %s\n' % P)
        # What stands behind them is read as it is in any option word: a marker or a reference there may print a
        # letter too. Truth: runs, all sixteen.
        self.assertRead(RULED, *("SHELL %s %s\n" % (word, P) for word in (
            "$X-c$(echo e)", "$X-$(echo c)", "$(true)-c$(true)", "${X:-$(true)}-c", "$X-c$Y")))

    def test_the_option_word_behind_them(self):
        # Any cluster carrying `c`, of either sign, one that owes a NAME, and one before the `-c`. Truth: runs, all sixteen.
        self.assertRead(RULED, *("SHELL $X%s %s\n" % (word, P) for word in (
            "-xc", "-ce", "-cx", "+xc", "-ic", "-lc", "+ec", "-oc errexit", "-co errexit", "-c -e")))

    def test_where_the_word_stands(self):
        # Behind an option, a long option, a value's name, the cluster; two of them; past a FILE that runs its
        # parameter -- where the second walk alone reads on past a word the shell would refuse (`-K`); in front of a
        # value, and of a word that may vanish (`$Y`) or a FILE the value's search skips. Truth: runs, all sixteen.
        self.assertRead(RULED, *(row % P for row in (
            "SHELL -e $X-c %s\n", "SHELL -o errexit $X-c %s\n", "SHELL -c $X-e $Y-x %s\n", "SHELL -c $X+e %s\n",
            "SHELL $X-e $Y-c %s\n", "SHELL $X-c $Y-e %s\n", "printf 'eval \"$2\"' > ./a; SHELL ./a $X-c %s\n",
            "SHELL -s $X-c %s\n", "Y=-c; SHELL $X-e $Y %s\n", "Y=-c; SHELL $X-o errexit $Y %s\n", "Y=-c\nSHELL $X-e $Y %s\n",
            "bash --norc $X-c %s\n", "bash --rcfile /dev/null $X-c %s\n", "SHELL $X-c $Y %s\n",
            "Y=-c; bash --rcfile f $X-e $Y %s\n", "printf 'eval \"$3\"' > ./a; SHELL ./a $X-c -K %s\n")))

    def test_the_command_around_the_shell(self):
        # Truth: runs, all sixteen, every one -- but `exec -a`, which dash's `exec` refuses.
        self.assertRead(RULED, *(row % P for row in (
            "env SHELL $X-c %s\n", "exec SHELL $X-c %s\n", "command SHELL $X-c %s\n", "nice SHELL $X-c %s\n", "/bin/SHELL $X-c %s\n",
            "/usr/bin/env SHELL $X-c %s\n", "CMD=SHELL; $CMD $X-c %s\n", "${CMD:-SHELL} $X-c %s\n", "( SHELL $X-c %s )\n",
            "if SHELL $X-c %s; then :; fi\n", "true && SHELL $X-c %s\n", "dash $X-c %s\n", "nohup SHELL $X-c %s\n",
            "time SHELL $X-c %s\n", "exec -a x SHELL $X-c %s\n", "echo x | xargs SHELL $X-c %s\n")))
        self.assertRead(RULED, *(row % PIPE for row in (
            "eval 'SHELL $X-c \"%s\"'\n", "bash -c 'SHELL $X-c \"%s\"'\n", "echo 'SHELL $X-c \"%s\"' | sh\n",
            "sh <<'EOF3042'\nSHELL $X-c '%s'\nEOF3042\n")))
        # A wrapper's own option word in front of the shell is the wrapper's, and `main` reports those steps as it did.
        # Truth: runs, all sixteen.
        self.assertRead(EITHER, "sudo $X-E SHELL -c %s\n" % P, "env $X-i SHELL -c %s\n" % P)

    def test_a_fetchers_option_word(self):
        # wget writes the URL's file unless told otherwise, and `$X-qO-` tells it to stream with `X` unset: the
        # transfer the words then name is read, and its stream beside the file `main` read it into. Truth: runs, all
        # sixteen, every one -- but `bash <(...)`, which dash cannot read.
        self.assertRead(RULED, *(row % URL for row in (
            "wget $X-qO- %s | sh\n", "wget ${X}-O- %s | sh\n", "wget $X-O- %s | bash\n", "wget $X-O - %s | sh\n",
            "wget $X-qO - %s | sh\n", "wget -q $X-O- %s | sh\n", "wget $X--output-document=- %s | sh\n",
            "wget $(true)-qO- %s | sh\n", 'wget "$X"-qO- %s | sh\n', "wget $X-qO- %s | tee f | sh\n",
            "wget $X-qO- %s | cat | sh\n", "bash <(wget $X-qO- %s)\n",
            "wget $X-O f %s && sh f\n", "wget $X-qO f %s && sh f\n", "wget $X-Of %s && sh f\n", "wget -O f $X-qO- %s | sh\n")))
        # ... and the stream `main` read stays beside a file the words read so name. Truth: fetched only with `X` unset
        # (the last `-O` wins); with `X=x` the transfer streams, `main`'s reading.
        self.assertRead(EITHER, "wget -qO- $X-O f %s | sh\n" % URL)
        # Where the words read so name no URL (`-l` takes the rest of `-linux.tgz`), `main`'s transfer is the one: and
        # nothing runs these. Truth: fetched only, every one.
        self.assertRead((CLEAN[0],) * 3, "wget ${BASE}-linux.tgz\n", "wget $BASE-linux.tgz | sh\n", "wget $X-O f %s\n" % URL,
                        "wget $X-i urls.txt && sh i.sh\n")
        # curl beside such a word is unread on `main`, and reported; the rule reads the transfer too. Truth: runs. And
        # where the rule's reading alone reads nothing piped, the floor keeps `main`'s report. Truth: fetched only.
        self.assertRead(EITHER, "curl $X-o f %s && sh f\n" % URL, "curl $X-o f %s; sh f\n" % URL)
        self.assertRead(FLOOR, "curl $X-o f %s | sh\n" % URL)

    def test_what_is_no_such_word(self):
        # An expansion that always prints -- a length, a status, a count, an arithmetic, a tilde -- or none in front, a
        # word that is no option word behind them, and such a word where the options have ended. Truth: nothing runs.
        self.assertRead((CLEAN[0],) * 3, *(row % P for row in (
            "SHELL ${#X}-c %s\n", "SHELL $?-c %s\n", "SHELL $#-c %s\n", "SHELL $((0))-c %s\n", "SHELL ~-c %s\n",
            "SHELL $#$X-c %s\n", "SHELL $X/-c %s\n", "SHELL -- $X-c %s\n", "SHELL -c 'true' $X-c %s\n")))
        self.assertRead((CLEAN[0],) * 3, "SHELL -c -- $X-e\n")
        # A `@` writes itself (a marker begins `@@shell-`): a word that begins with one and holds an expansion after
        # it is read from its first character, as every word is, and that character is no `-`. Truth: nothing runs.
        self.assertRead((CLEAN[0],) * 3, "SHELL @$X-c %s\n" % P)

    def test_mains_whole_answer_stands_first(self):
        # `main` has had #2889's rule on since it merged, so where #3042's reading answered, the job's floor reads
        # `main`'s WHOLE answer first -- the job with that reading off (`as_main`), #2889's floor in it. Here the
        # transfer the words read so name lands elsewhere, and `main` reports the step through its own transfer and
        # #2889's string together: the rules' reading alone (the floor taken out) reads it CLEAN, as #2889's switch
        # off does. An independent pre-review found fourteen such rows. Truth: runs, all sixteen, every one.
        for text in ("X=x; Y=c; wget $X-O a https://example.test/install.sh || true; sh -$Y '. ./install.sh'\n", "X=x; Y=c; wget $X-qO- https://example.test/install.sh || true; sh -$Y '. ./install.sh'\n", "X=x; Y=c; wget $X-P d https://example.test/install.sh || true; sh -$Y '. ./install.sh'\n", "X=x; Y=c; wget -q $X-O a https://example.test/install.sh || true; sh -$Y '. ./install.sh'\n", "X=x; wget $X-O a https://example.test/install.sh || true; X=o; sh -c -$X errexit '. ./install.sh'\n", "X=c; wget $X-qO- https://example.test/install.sh || true; sh -$X '. ./install.sh'\n", "X=c; wget $X-O- https://example.test/install.sh || true\nsh -$X 'sh install.sh'\n", "X=c; wget -q $X-O- https://example.test/install.sh || :; bash -$X 'bash ./install.sh'\n"):
            with self.subTest(text=text):
                self.assertEqual(("RRRRR", "CCCCC", "CCCCC"), readings(text))
                step = [wg.Step("step", text, None)]
                with words.as_main():
                    mains, strict = wg.job_defects(step), wg.fetch_exec_defects(text)
                self.assertTrue(mains)
                self.assertEqual(mains, wg.job_defects(step)[:len(mains)])
                self.assertEqual(strict, wg.fetch_exec_defects(text)[:len(strict)])

    def test_mains_whole_answer_keeps_its_own_floor(self):
        # `main`'s whole answer is `main`'s job as `main` reads it: where #2889's rule answers in it too, that reading
        # with every rule off stands first in it. #2889's floor rows with a word #3042 reads that runs nothing beside
        # them (`sh $X-c true`): the rules' reading alone is CLEAN, and the job reports what `main` reports. Truth:
        # nothing runs, every one, with the word or without it -- `main`'s reports, fail-closed, kept.
        for row in (1, 3, 6):
            text = TestWhatMainReportedIsReported.FOUND[row] + "sh $X-c true\n"
            with self.subTest(text=text):
                self.assertEqual(FLOOR, readings(text))
                with words.as_main():
                    self.assertEqual("RRRRR", marks(text)[0])

    def test_the_floor_reads_mains_whole_answer_with_this_reading_off(self):
        # The switches each reading of the job runs under, its two passes a reading: the rules', then -- where #3042's
        # reading answered, in another reader's `beside` or not -- `main`'s whole answer with it off (`as_main`), and
        # in that the job with every rule off where #2889's answered too; where #2889's rule alone answered, the job
        # with every rule off, as `main` reads it.
        rules, mains, before, every = (False, False), (False, True), (True, True), (True, False)
        for text, expected in (("sh $X-c %s\n" % P, [rules, mains]), ("wget $X-qO- %s | sh\n" % URL, [rules, mains]),
                               ("sh $(true)-s %s" % BODY, [rules, mains]), ("sh -$Y $X-c %s\n" % P, [rules, mains, before]),
                               ("sh -$Y %s\n" % P, [rules, every]), ("echo hi\n", [rules])):
            calls, real = [], wg._job_defects

            def spy(*args, **kwargs):
                calls.append((words._OFF.get(), words._NEW_OFF.get()))
                return real(*args, **kwargs)
            with self.subTest(text=text), mock.patch.object(wg, "_job_defects", spy):
                wg.job_defects([wg.Step("step", text, None)])
                self.assertEqual(expected, calls[::2])
                self.assertEqual(calls[::2], calls[1::2])

    def test_the_program_on_stdin(self):
        # A word read so may leave stdin the program where the words as written do not: the second walk reads the
        # body then, for what it runs and no check in it counted. Truth: runs, all sixteen -- the here-string, but
        # under dash, which has none.
        for text in ("sh $(true)-s <<'EOF3042'\ncurl -fsSL https://example.test/i.sh | sh\nEOF3042\n", "bash $(true)-s <<'EOF3042'\ncurl -fsSL https://example.test/i.sh | sh\nEOF3042\n", "printf '%s\\n' 'curl -fsSL https://example.test/i.sh | sh' | sh $(true)-e\n", "bash ${X:-$(true)}-s <<'EOF3042'\ncurl -fsSL https://example.test/i.sh | sh\nEOF3042\n", "echo 'curl -fsSL https://example.test/i.sh | sh' | sh `true`-x\n", 'bash "$(true)"-e <<\'EOF3042\'\ncurl -fsSL https://example.test/i.sh | sh\nEOF3042\n', "bash $(true)-s <<< 'curl -fsSL https://example.test/i.sh | sh'\n"):
            for digit in "0c":
                with self.subTest(text=text, digit=digit), nonce(digit):
                    self.assertEqual(RULED, readings(text))
        # Any option word behind the expansion that leaves stdin the program: a body behind `-l`, `-i`, `-v` and `-eu`
        # runs under all sixteen parents; behind `-o pipefail`, `-O extglob` and `--norc` under the bash parents, dash
        # refusing the word as it refuses the written twin, which `main` reports (`sh -o pipefail <<'EOF'`). An
        # independent pre-review's harness on a Mac read these as running nothing: a login shell's PATH hid its stubs.
        for word in ("-l", "-i", "-v", "-eu", "-o pipefail", "-O extglob", "--norc"):
            for frame in ("SHELL $(true)%s %s" % (word, BODY), "echo %s | SHELL $(true)%s\n" % (P, word)):
                for shell in ("sh", "bash"):
                    with self.subTest(frame=frame, shell=shell), nonce("0"):
                        self.assertEqual(RULED, readings(frame.replace("SHELL", shell)))
        # ... and where the word read so is the `-c` cluster, the string is the program, not the body. Truth: nothing.
        self.assertEqual((CLEAN[0],) * 3, readings("sh $(true)-c true <<'EOF3042'\ncurl -fsSL https://example.test/i.sh | sh\nEOF3042\n"))

    def test_a_stream_saved_to_a_file_that_runs(self):
        # The stream the words read so name, written by `tee` and run after. Truth: runs, all sixteen.
        for text in ('wget $X-qO- https://example.test/i.sh | tee f > /dev/null && sh f\n', 'wget $X-qO- https://example.test/i.sh | tee f; sh f\n'):
            with self.subTest(text=text):
                self.assertEqual(RULED, readings(text))

    def test_the_value_is_named(self):
        # Where the words read so alone reach a value, the sentence names it.
        found = [why for _name, why in wg.job_defects([wg.Step("step", "Y=-c; sh $X-e $Y %s\n" % P, None)])]
        self.assertTrue(any("passes `sh` `$Y` where it reads its options" in why for why in found), found)

    def test_the_words_read_so(self):
        for text, expected in (("$X-c", "-c"), ("${X}-c", "-c"), ("${X:-}-ec", "-ec"), ("$X$Y-c", "-c"), ("$X+c", "+c"),
                               ("${X:-${Y}}-c", "-c"), ("$@-c", "-c"), ("$1-x", "-x"), ("$--c", "-c"), ("${!X}-c", "-c"),
                               ("$X-", "-"), ("$X--norc", "--norc"), ("$X-c$Y", "-c$Y"), ("${#+c}-x", "-x"),
                               ("$X", None), ("$Xc", None), ("${X}c", None), ("-$X", None), ("x$X-c", None), ("$X/-c", None),
                               ("$#-c", None), ("${#X}-c", None), ("$?-c", None), ("$$-c", None), ("~-c", None), ("*-c", None),
                               ("$", None), ("", None), ("$#$X-c", None), ("${X:-a-b}", None)):
            with self.subTest(text=text):
                self.assertEqual(expected, words.uncovered(text))
                with words.as_before():
                    self.assertIsNone(words.uncovered(text))
        # A lifted substitution in front, and one behind: what stands behind is the word's text, its marker in it.
        for text, written in (("$(true)-c", "-c"), ("`true`+c", "+c"), ("$(true)$X-ec", "-ec"), ("${X:-$(true)}-c", "-c"),
                              ("$X-c$(echo e)", "-c"), ("$(echo x)c", None)):
            for digit in "0c":
                with self.subTest(text=text, digit=digit), nonce(digit):
                    found = words.uncovered(argv("sh %s P" % text)[1])
                    self.assertEqual(written, found if found is None else words.written(found))
                    self.assertEqual("$(echo e)" in text, found is not None and words.lifted(found))
                    with words.as_before():
                        self.assertIsNone(words.uncovered(argv("sh %s P" % text)[1]))
        # The words of an argv read so: the command word as written, every other word the step's own where it is no such word.
        words_ = argv("sh $X-c P $Y-e")
        alt = words.uncovered_argv(words_)
        self.assertEqual(["sh", "-c", "P", "-e"], alt)
        self.assertEqual([True, False, True, False], [new is old for new, old in zip(alt, words_)])
        self.assertIsNone(words.uncovered_argv(argv("sh -c P $X")))
        self.assertIsNone(words.uncovered_argv(["$X-c", "P"]))
        with words.as_before():
            self.assertIsNone(words.uncovered_argv(words_))

    def test_the_rule_answers_only_where_it_reads_such_a_word(self):
        # A reading in which the rule found no such word is read once (`beside`): a word with an expansion in front of
        # what is no option word is not one -- so a job that holds it is read as often as `main`'s.
        for text in ("$X", "${X:-make}", "${X:-a-b}", "x$X-c", "$#-c", "-c"):
            with self.subTest(text=text):
                first, second = words.beside(lambda: words.uncovered(text))
                self.assertIs(first, second)
        self.assertEqual((None, "-c"), words.beside(lambda: words.uncovered("$X-c")))
        # A reading inside another tells that one what it heard, and whether it was #3042's reading: the job's floor
        # reads `main`'s whole answer wherever this reading answered, inside a reader's `beside` or not.
        for read, heard in ((lambda: words.uncovered("$X-c"), [True, True]), (lambda: words.ruled(), [True, False]),
                            (lambda: words.uncovered("$X"), [False, False])):
            box = [False, False]
            token = words._HEARD.set(box)
            try:
                words.beside(read)
            finally:
                words._HEARD.reset(token)
            self.assertEqual(heard, box)

    def test_the_floor_leaves_the_box_it_found(self):
        # `passes` and `beside` tell the reading they run inside what they heard -- whether a rule answered, and whether
        # it was #3042's -- in that reading's box, whatever it held, and leave the box where it was: the job's floor is
        # read inside a reader's `beside` or none, and the reading after it starts from what IT found.
        def job():
            return [words.uncovered("$X-c")]            # #3042's reading answers (and so #2889's switch hears it)

        def before():
            return [words.ruled()]                      # #2889's rule alone answers

        def none():
            return [words.uncovered("$X")]              # neither

        for read, heard in ((job, [True, True]), (before, [True, False]), (none, [False, False])):
            for floor in (lambda: words.passes(read, contextlib.nullcontext), lambda: words.beside(read)):
                self.assertIsNone(words._HEARD.get())
                floor()
                self.assertIsNone(words._HEARD.get())
                for held in ([False, False], [False, True]):
                    box = list(held)
                    token = words._HEARD.set(box)
                    try:
                        floor()
                        self.assertIs(box, words._HEARD.get())
                    finally:
                        words._HEARD.reset(token)
                    self.assertEqual([heard[0] or held[0], heard[1] or held[1]], box)

    def test_mains_whole_answer_is_one_reading_where_only_this_rule_answered(self):
        # Where #3042's reading answered and #2889's rule is silent with it off, `main`'s whole answer is the job's two
        # passes read once -- the one list `beside` hands twice -- and this reading's two passes stand beside it.
        def read():
            return ["new"] if words.uncovered("$X-c") else ["main"]

        self.assertEqual(([["main"], ["main"]], [["new"], ["new"]]), words.passes(read, contextlib.nullcontext))

    def test_beside_the_words_as_written(self):
        # Every run of one to three of these words after `sh`: what the search for the string, the search for a value
        # and the shell's two walks hand on with no word read so, they hand on with them -- the searches' first and in
        # their order, the walks' among their strings -- each word they add once, and nothing but the step's own words.
        # With either switch off (`as_before`, `as_main`), what they hand on with no word read so. (The reader hands one object for two words that
        # are one text, so `sh $Y P P` names it twice among the value's words, as `main` did.)
        pool = [argv("sh " + word)[1] for word in ("$X-c", "$X-e", "$(true)+c", "$X-o", "-c", "-e", "--", "errexit", "$Y", "P")]
        readers = (ws._after_dash_c, lambda w: ws.candidates(w)[1], lambda w: ws._program_words(w) + ws._added_strings(w))
        count = more = 0
        for size in (1, 2, 3):
            for tail in itertools.product(pool, repeat=size):
                words_ = ["sh", *tail]
                for at, read in enumerate(readers):
                    with mock.patch.object(ws, "uncovered_argv", lambda w: None):
                        written = read(words_)
                    found = read(words_)
                    for switch in (words.as_before, words.as_main):
                        with switch():
                            off = read(words_)
                            with mock.patch.object(ws, "uncovered_argv", lambda w: None):
                                self.assertEqual(list(map(id, read(words_))), list(map(id, off)), (texts(words_), at))
                    if at < 2:
                        self.assertEqual(list(map(id, written)), list(map(id, found[:len(written)])), (texts(words_), at))
                        added = found[len(written):]
                        self.assertEqual(len(added), len(set(map(id, added)) - set(map(id, written))), (texts(words_), at))
                    else:
                        self.assertTrue(set(map(id, written)) <= set(map(id, found)), (texts(words_), at))
                        self.assertEqual(len(found), len(set(map(id, found))), (texts(words_), at))
                    self.assertTrue(set(map(id, found)) - set(map(id, written)) <= set(map(id, words_)), (texts(words_), at))
                    count, more = count + 1, more + (len(found) > len(written))
        self.assertEqual((3 * (10 + 10 ** 2 + 10 ** 3), True), (count, more > 300))
        # One word handed twice by the reading of the words read so (here an object the argv holds twice) is added once.
        sh, word, value, name, program = argv("sh $W-e $Y $Z P")
        self.assertEqual(["$Z", "P"], texts(ws.candidates([sh, word, value, name, name, program])[1]))


class TestBesideNeverInstead(unittest.TestCase):
    """Each new reading stands beside `main`'s: its two walks past the options and its search for the cluster, kept
    here as they stood on `main`, find nothing the rule's do not, and their words come first -- and with the rule
    off (`as_before`) each reader IS `main`'s, word for word."""

    WORDS = ("-c", "-e", "-x", "-o", "-O", "-co", "-oc", "-$X", "-c$X", "-$Xo", "-o$X", "-$foo", "-$(echo o)", "+$X", "--norc",
             "--", "-", "errexit", "bogus", "extglob", "$Y", "err$Z", "./f", "P", "-K", "-cK")
    # The words a walk turns on: one that owes, one that may, one that refuses, the ends of the options, a NAME, none.
    TURNS = ("-o", "-co", "-$X", "-$Xo", "-$foo", "-$(echo o)", "--norc", "--", "errexit", "bogus", "$Y", "P")

    @staticmethod
    def _mains_past(words_, at, refused=None):
        refused = refused or TestBesideNeverInstead._mains_refused_name
        while True:                             # `_past_options` on 13cdb9f7, word for word
            if wo._refused(words_, at) or refused(words_, at):
                return []
            at += 1 + sum(letter in wo.VALUE_OPTIONS for letter in words_[at][1:])
            if at >= len(words_) or words_[at].startswith("--") and words_[at] != "--":
                return []
            if words_[at] in ("-", "--"):
                return words_[at + 1:at + 2]
            if not words_[at].startswith(("-", "+")):
                return [words_[at]]

    @staticmethod
    def _mains_operand(words_, at, past, refused=None):
        refused = refused or TestBesideNeverInstead._mains_refused_name
        while True:                             # `_operand_past` on 13cdb9f7, word for word
            if not past and (wo._refused(words_, at) or refused(words_, at)):
                return []
            at += 1 + (words_[at][:2] != "--" and sum(letter in wo.VALUE_OPTIONS for letter in words_[at][1:]))
            if at >= len(words_):
                return []
            if not past and (words_[at].startswith("--") and words_[at] != "--" or wo.long_option(words_, at)):
                return []
            if words_[at] in ("-", "--"):
                return words_[at + 1:at + 2]
            if not words_[at].startswith(("-", "+")):
                return [words_[at]]

    @staticmethod
    def _mains_refused_name(words_, at):
        if type(words_[0]) is not str or words_[0] not in wo._MEASURED_SHELLS:   # `_refused_name` on 13cdb9f7
            return False
        value = at
        for letter in words_[at][1:]:
            value += letter in wo.VALUE_OPTIONS
            if letter == "o" and value < len(words_) and words_[value].replace("-", "").isalpha():
                if words_[value] not in wo.SHELL_OPTION_NAMES:
                    return True
        return False

    @staticmethod
    def _at(words_, place):
        return [] if place is None or place >= len(words_) else [words_[place]]

    @staticmethod
    def _mains_after_dash_c(words_, plus=True, start=1):
        past, again = TestBesideNeverInstead._mains_past, TestBesideNeverInstead._mains_after_dash_c
        for position in range(start, len(words_)):          # `_after_dash_c` on 837228ef, word for word
            token = words_[position]
            if token == "--":
                break
            if token[:1] in ("-", "+" if plus else "-") and token[:2] not in ("--", "++") and words.spells(token, "c"):
                found = past(words_, position)
                if "c" not in words.written(token):
                    found = found + [word for word in again(words_, plus, position + 1) if not any(word is seen for seen in found)]
                if token[0] == "-":
                    return found
                return found + [word for word in again(words_, False) if not any(word is seen for seen in found)]
        return []

    def test_the_walks_find_what_mains_found_and_mains_first(self):
        # Every run of one and two of the words behind each cluster, and every run of three of the words a walk turns
        # on, under a shell whose refusals are measured and one whose are not. Each word is read once, as the reader
        # hands it on, and stands in every argv it is part of: a word's reading does not depend on its neighbours.
        # The search's first part (`_mains_operand`) is `main`'s walk word for word but for the refusal by NAME it
        # asks, which rule 2 reads from less of the word: with that one question swapped in, the same operand or none
        # for every one of them. And with the rule off, each walk hands on what `main`'s did and nothing else.
        read = {word: argv("sh " + word)[1] for word in self.WORDS}
        # `-c$foo`: `main` counted the two `o`s of the name, so its operand is one this rule's own reading never reaches.
        clusters = [argv("sh " + cluster)[1] for cluster in ("-c", "-c$X", "-c$foo", "-$X", "-$(echo o)", "-co")]
        self.assertEqual("-$(...)", shell_reader.readable(read["-$(echo o)"]))        # a lifted word, as the reader hands it on
        count = 0
        for shell in ("sh", "zsh"):
            for size, pool in ((1, self.WORDS), (2, self.WORDS), (3, self.TURNS)):
                for tail in itertools.product(pool, repeat=size):
                    for cluster in clusters:
                        count += 1
                        self._holds([shell, cluster] + [read[word] for word in tail])
        self.assertEqual(2 * 6 * (26 + 26 ** 2 + 12 ** 3), count)

    def _holds(self, words_):
        mains = self._mains_past(words_, 1)
        found = wo._past_options(words_, 1)
        self.assertEqual(mains, found[:len(mains)], texts(words_))
        self.assertEqual(self._mains_past(words_, 1, wo._refused_name),
                         self._at(words_, wo._mains_operand(words_, 1, False, False, {})), texts(words_))
        with words.as_before():                 # the rule off: `main`'s walk and no other
            self.assertEqual(mains, wo._past_options(words_, 1), texts(words_))
        for past in (False, True):
            mains = self._mains_operand(words_, 1, past)
            found = wo._operand_past(words_, 1, past)
            self.assertEqual(mains, found[:len(mains)], (texts(words_), past))
            self.assertEqual(self._mains_operand(words_, 1, past, wo._refused_name),
                             self._at(words_, wo._mains_operand(words_, 1, past, True, {})), (texts(words_), past))
            with words.as_before():
                self.assertEqual(mains, wo._operand_past(words_, 1, past), (texts(words_), past))

    def test_the_search_for_the_cluster_hands_on_mains_words_first(self):
        # `_after_dash_c` against `main`'s, which read a row of words that may each be the cluster by calling itself:
        # with the rule off the same words in the same order, each the same object; with it on, those first.
        pool = [argv("sh " + word)[1] for word in ("-c", "+c", "-x", "-$X", "+$X", "-$(echo x)", "-o", "--", "errexit", "$Y", "./f", "P")]
        chain = [pool[3], pool[5], pool[4], pool[0], pool[8], pool[11]]        # `-$X`, `-$(echo x)`, `+$X`, `-c`, a NAME, `P`
        count = more = 0
        for size, among in ((1, pool), (2, pool), (3, pool), (4, chain)):
            for tail in itertools.product(among, repeat=size):
                words_ = ["sh"] + list(tail)
                with words.as_before():
                    mains = self._mains_after_dash_c(words_)
                    self.assertEqual(list(map(id, mains)), list(map(id, ws._after_dash_c(words_))), texts(words_))
                found = ws._after_dash_c(words_)
                self.assertEqual(list(map(id, mains)), list(map(id, found[:len(mains)])), texts(words_))
                self.assertEqual(len(found), len(set(map(id, found))), texts(words_))       # each word once
                count, more = count + 1, more + (len(found) > len(mains))
        self.assertEqual((12 + 12 ** 2 + 12 ** 3 + 6 ** 4, True), (count, more > 400))       # 527: the rule's words are not idle
        # `X=x; sh -$X ./a -c 'P'`: `main` read on past the word and found `P`; the rule's reading finds `./a` first.
        self.assertEqual(["P", "./a"], texts(ws._after_dash_c(argv("sh -$X ./a -c 'P'"))))
        # A `+` cluster that writes its `c` ends the search, and the `-` one after it is read too, as `main` read it
        # (#3019): `sh +c P -c Q` runs `P`, and a FILE may run `Q`.
        for rule in (False, True):
            with self.subTest(rule=rule), (contextlib.nullcontext() if rule else words.as_before()):
                self.assertEqual(["P", "Q"], texts(ws._after_dash_c(argv("sh +c P -c Q"))))

    def test_a_walk_after_others_hands_on_what_it_would_alone(self):
        # The search's walks share what they read (`walked`): a place an earlier walk read is handed on there, and a
        # later walk that meets it reads on past it. `sh -${A}o -${B}o -x P Q`: the first walk reads `-x` (its `o` owes
        # `-${B}o`) and hands on `P`; the walk from `-${B}o` starts its run of NAMEs at that `P` and hands on `Q` too.
        self.assertEqual(["P", "Q"], texts(ws._after_dash_c(argv("sh -${A}o -${B}o -x P Q"))))
        for pool, sizes in ((("-${A}o", "-$X", "+${A}o", "-x", "-co", "errexit", "P", "--"), (1, 2, 3)),
                            (("-${A}o", "-x", "errexit", "P"), (4, 5))):
            for tail in itertools.chain.from_iterable(itertools.product(pool, repeat=size) for size in sizes):
                words_ = argv("sh " + " ".join(tail))             # read whole, as the guard reads a step
                for plus, switch in itertools.product((False, True), (contextlib.nullcontext, words.as_before)):
                    with switch():
                        places, signed = ws._clusters(words_, plus)
                        alone = []
                        for place in places + (ws._clusters(words_, False)[0] if signed else []):
                            for word in wo._past_options(words_, place):
                                alone += [] if any(word is v for v in alone) else [word]
                        self.assertEqual(list(map(id, alone)), list(map(id, ws._strings(words_, plus))), (tail, plus, switch))

    def test_the_first_pass_counts_the_values_as_main_counted_them(self):
        # `main`'s walk for a value counted an `o` or `O` in a word's TEXT, a name's letters among them, and the first
        # pass does still: `-$FOO` owes two there, so `$Y` is the value it finds. Counted by what is written, the
        # walk would end at `./a` -- one answer of `main`'s fewer.
        value, found = ws._candidates(argv("sh -$FOO ./a ./b $Y 'P'"))
        self.assertEqual(("$Y", ["P"]), (str(value), texts(found)))

    def test_the_two_walks_part_at_a_long_word_of_one_dash_as_mains_did(self):
        # `main`'s two walks differ in one thing: to the first a long option spelled with ONE dash is its letters,
        # to the second it is the option, refused behind a cluster. Only a cluster that is such a word itself has
        # one behind it (`bash -rcfile -posix errexit 'P'`: bash reads the one-dash names in its leading run alone),
        # and each walk keeps its reading there -- `main`'s operand first in both, as everywhere.
        words_ = argv("bash -rcfile -posix errexit 'P'")
        self.assertEqual((["P"], []), (texts(wo._past_options(words_, 1)), texts(wo._operand_past(words_, 1))))
        # The rule's own branch of the first walk reads it so too, where `main`'s finds no operand: `-${X:-o}` writes
        # no `o` (`main` counted the one in its text), so past `-posix`, read as its letters, `P` may be the string.
        words_ = argv("bash -c$X -posix errexit -${X:-o} P")
        self.assertEqual((["P"], []), (texts(wo._past_options(words_, 1)), texts(wo._operand_past(words_, 1))))
        with words.as_before():
            self.assertEqual([], texts(wo._past_options(words_, 1)))
        pool = [argv("sh " + word)[1] for word in ("-posix", "-norc", "-rcfile", "--norc", "errexit", "f", "P", "-c", "--", "-$X")]
        parted = 0
        for shell in ("bash", "dash"):
            for size in (1, 2, 3):
                for tail in itertools.product(pool, repeat=size):
                    words_ = [shell, "-rcfile"] + list(tail)
                    self._holds(words_)
                    parted += wo._past_options(words_, 1) != wo._operand_past(words_, 1)
        self.assertGreater(parted, 50)          # 76 of the 2,220: the test is not vacuous

    def test_a_word_is_handed_on_once_and_a_long_run_costs_a_walk(self):
        words_ = argv("sh -$X " + " ".join(["errexit"] * 400) + " 'P'")
        found = wo._past_options(words_, 1)
        self.assertEqual(401, len(found))
        self.assertTrue(all(word is words_[2 + place] for place, word in enumerate(found)))    # each place once, in order
        # One object may stand at two places (Python keeps one `P` for both): each place is handed on.
        twice = argv("sh -$X P P")
        self.assertEqual(["P", "P"], texts(wo._past_options(twice, 1)))

    def test_a_row_of_such_words_is_read_in_a_loop_and_each_word_once(self):
        # Five thousand words that may each be the cluster: a loop, where `main`'s search called itself once a word
        # and ran out of stack at a thousand (`sh -$(true) -$(true) ...`, a RecursionError out of the guard).
        self.assertEqual(["P"], texts(ws._after_dash_c(["sh"] + ["-$X"] * 5000 + ["P"])))
        marker = argv("sh -$(true)")[1]
        with words.as_before():
            self.assertEqual(["P"], texts(ws._after_dash_c(["sh"] + [marker] * 5000 + ["P"])))

        # ... and for the whole JOB twice the words is twice the steps: the search is asked for once a stage,
        # however many scripts the stage hands on (`workflow_forms.flattened`), and each walk reads a word once --
        # the first operand a cluster's walk reaches too, kept for every word (`_first_place`), where a row of
        # such words reaches none. (`sh` and two hundred `-$X errexit` took 178 s before this; each count below
        # was the square of the words.)
        def steps(text):
            asked = {"walks": 0, "searches": 0, "postures": 0}
            after, strings, posture = wo._after, ws._strings, wf._errexit

            def counted(kind, real):
                def ask(*args, **kwargs):
                    asked[kind] += 1
                    return real(*args, **kwargs)
                return ask
            with mock.patch.object(wo, "_after", counted("walks", after)), mock.patch.object(ws, "_strings", counted("searches", strings)), \
                    mock.patch.object(wf, "_errexit", counted("postures", posture)):
                wg.job_defects([wg.Step("step", text, None)])
            return asked
        # ... and a reader's `-e` and `pipefail` are asked once a reader, not once a script the rule hands on: each
        # asking reads the whole command (`sh` and eight thousand `-$Xo`/`errexit` words: 11 s, the second pre-review).
        for shape in (lambda n: "sh" + " -$X errexit" * n + " %s\n" % P,      # a NAME behind each word
                      lambda n: "sh" + " -$X" * n + "\n",                     # no operand at all
                      lambda n: "sh" + " -$X" * n + " -K %s\n" % P,          # a word the shell refuses
                      lambda n: "sh" + " -$Xo" * n + " errexit" * n + " %s\n" % P):   # every word a script handed on
            with self.subTest(row=shape(1)):
                small, large = steps(shape(20)), steps(shape(40))
                self.assertEqual((small["searches"], small["postures"]), (large["searches"], large["postures"]))
                self.assertLess(large["walks"], 2.1 * small["walks"])

    def test_each_word_is_read_once_a_walk_and_a_few_times_a_search(self):
        # What keeps a long command cheap is a standing fact, not a measurement. A walk past the options (`_reached`)
        # asks what follows a word (`_after`) once at most for each word; a search -- for the `-c` cluster (`_strings`),
        # or the second walk's for a value (`_shell_candidates`) -- asks it three times at most: once where a walk
        # reaches the word, and once from each scan that starts a walk at it (a `+` cluster's search reads the `-`
        # ones again), and `main`'s walk (`_refused`, a step of it) once more. A walk asked afresh, or a table not
        # kept, asks it once for every word before it: the square of the words, which no cap stands in for.
        pool = [argv("sh " + word)[1] for word in ("-c", "+c", "-x", "-o", "-co", "-$X", "+$X", "-$foo", "-$Xo", "-$(echo o)",
                                                    "--norc", "--", "-", "errexit", "$Y", "~", "P", "-K", "./f", "$X-c", "$X-o", "$(true)+c")]
        rows = [[argv("sh " + word)[1] for word in tail] for size in (1, 2, 3) for tail in itertools.product(self.TURNS, repeat=size)]
        draw = random.Random(2889)                  # and long ones, drawn: the same draw on every run
        rows += [[draw.choice(pool) for _ in range(draw.randint(10, 80))] for _ in range(300)]
        open_: list = []
        most: dict = {}
        after, refused, reached, strings = wo._after, wo._refused, wo._reached, ws._strings

        def counted(kind, real):
            def ask(words_, at, *rest):
                for level, seen in open_:
                    seen[(kind, at)] = seen.get((kind, at), 0) + 1
                return real(words_, at, *rest)
            return ask

        def level(name, real):
            def run(*args):
                open_.append((name, {}))
                try:
                    return real(*args)
                finally:
                    _name, seen = open_.pop()
                    for (kind, _at), count in seen.items():
                        most[(name, kind)] = max(most.get((name, kind), 0), count)
            return run
        with mock.patch.object(wo, "_after", counted("after", after)), mock.patch.object(wo, "_refused", counted("step", refused)), \
                mock.patch.object(wo, "_reached", level("walk", reached)), mock.patch.object(ws, "_strings", level("search", strings)):
            candidates = level("search", wo._shell_candidates)
            for shell in ("sh", "zsh"):
                for row in rows:
                    ws._after_dash_c([shell] + row)
                    candidates([shell] + row)
        self.assertEqual({("walk", "after"): 1, ("search", "after"): 3, ("search", "step"): 4},
                         {key: count for key, count in most.items() if key != ("walk", "step")})
        self.assertLessEqual(most[("walk", "step")], 2)     # `main`'s step and the walk's own, at the word it starts from
        # The words read with each one `uncovered` (#3042) are one more search, never a longer one: three a search at
        # most -- the words, the words read so, and the words again with the rule off where it answered (`beside`).
        searches = []
        with mock.patch.object(ws, "_strings", wraps=ws._strings) as search:
            for row in rows:
                search.reset_mock()
                ws._after_dash_c(["sh"] + row)
                searches.append(search.call_count)
        self.assertEqual(3, max(searches))

    def test_each_string_is_handed_on_once_whatever_readings_find_it(self):
        # `X=; bash $X -c 'P'` and `X=-e; ...` find `P` in each reading of the word that may expand
        # (`_in_every_reading`): it is handed on once.
        self.assertEqual(["P"], texts(wo._dash_c_strings(argv("bash $X -c 'P'"))))

    def test_the_words_handed_on_are_looked_up_in_a_set(self):
        # Where the rule hands on a word for each place, the readers that keep the step's own words (`_in_every_reading`)
        # and drop the strings `main` found (`_added_strings`) look each word up in a set: a scan of every word for each
        # was the square of them (`sh` and four thousand `-$X errexit`, 13 s: the second pre-review). Counted in the
        # generator steps they take, twice the words is twice the steps.
        def steps(pairs):
            words_, count, before = argv("sh" + " -$X errexit" * pairs + " 'P'"), [0], sys.getprofile()

            def profile(frame, event, _arg):
                if event == "call" and frame.f_code.co_name == "<genexpr>":
                    count[0] += 1
            sys.setprofile(profile)
            try:
                wo._dash_c_strings(words_)
                ws._added_strings(words_)
            finally:
                sys.setprofile(before)
            return count[0], len(words_)
        (small, _), (large, size) = steps(150), steps(300)
        self.assertLess(large, 2.2 * small)
        self.assertLess(large, 100 * size)

    def test_the_first_operand_a_walk_reaches_is_kept_for_every_word(self):
        # `_first_place` is `_operand_past`'s first operand, kept: asked of every word of these argvs, fresh and with
        # one table for all, it gives the place of the word the walk hands on first, wherever `main` reaches none.
        pool = [argv("sh " + word)[1] for word in ("-c", "-o", "-co", "-$X", "-$foo", "-$Xo", "-$(echo o)", "--norc", "--", "-",
                                                    "errexit", "$Y", "P", "-K", "-login", "-x", "+x")]
        asked = 0
        for size in (1, 2, 3):
            for tail in itertools.product(pool, repeat=size):
                words_ = ["bash"] + list(tail)
                firsts: dict = {}
                for at in range(1, len(words_)):
                    if words_[at][:1] not in ("-", "+") or words_[at] in ("-", "--") or words_[at][:2] == "--" or \
                            wo._mains_operand(words_, at, False, True, {}) is not None:
                        continue
                    found = wo._operand_past(words_, at)
                    for table in ({}, firsts):
                        place = wo._first_place(words_, at, table)
                        self.assertIs(found[0] if found else None, None if place is None else words_[place], texts(words_))
                    asked += 1
        self.assertGreater(asked, 1000)
        # ... and it is the one a `-c` cluster's `$Y` is asked for where `main` reaches none: `-$foo` owed `main` two
        # words, by the name's letters, and writes no `o` (`foo=x; sh -c -$foo $Y P` with `Y` empty runs `P`).
        self.assertEqual(3, wo._value_after_dash_c(argv("sh -c -$foo $Y 'P'"), 1, {}, {}))
        # ... only there: where `main` reaches an operand, it is the one asked, a value or not -- `main`'s operand kept
        # for a word the walk passed through, when the search reaches that word again from a later cluster.
        self.assertIsNone(wo._value_after_dash_c(argv("sh -c -$foo $Y Z 'P'"), 1, {}, {}))
        self.assertEqual((None, []), wo._shell_candidates(argv("sh -$X -c -$foo $Y Z 'P'")))
        # The operand is found AFTER its cluster, where one object stands at two places (Python keeps one `~`).
        words_ = argv("zsh --rcfile ~ -co -${X:-o} -$X$Y ~")
        self.assertIs(words_[2], words_[6])
        self.assertEqual(("~", []), wo._shell_candidates(words_))
        with words.as_before():
            self.assertIsNone(wo._value_after_dash_c(argv("sh -c -$foo $Y 'P'"), 1, {}, {}))

    def test_the_words_after_a_value_are_mains_and_more(self):
        # `_reopened` against `main`'s formula (13cdb9f7), over every run of three of these words and every run of
        # four of the ones it turns on: `main`'s words first, and with the rule off those and no other.
        pool = ("-x", "pipefail", "~", "~1", "$Y", "-$Y", "x$Y", "./f", "P", "--", "$(echo -c)")
        more_than_mains = 0
        for size, among in ((3, pool), (4, ("-x", "~", "$Y", "-$Y", "./f", "P", "--"))):
            for rest_text in itertools.product(among, repeat=size):
                rest = argv("sh $V " + " ".join(rest_text))[2:]
                end = next((k for k, after in enumerate(rest, 1) if not slots._before_operand(after)), len(rest))
                more = next((k for k in range(end, len(rest)) if slots._may_spell_option(rest[k])), len(rest))
                mains = rest[:end] + rest[more + 1:]
                found = slots._reopened(rest)
                self.assertEqual(mains, found[:len(mains)], rest_text)
                with words.as_before():
                    self.assertEqual(list(map(id, mains)), list(map(id, slots._reopened(rest))), rest_text)
                more_than_mains += len(found) > len(mains)
        self.assertGreater(more_than_mains, 500)        # the tilde's second reading is not idle


class TestWhatMainReportedIsReported(unittest.TestCase):
    """The floor (`workflow_guard.job_defects`, `workflow_option_words.beside`).

    The rule hands the guard's readers MORE -- strings, candidates, a first word -- and a reader handed more may
    choose a quieter reading of the step: a string that only may exist is the program, so the heredoc is data; a
    candidate is weighed, so the dynamic string behind it is not. An independent pass over the first build of this
    found thirteen such shapes, 122 of its 64,535 generated steps: `main` reported each and the build read it CLEAN.
    Mending each reader would be #2858 again, so the guarantee is structural. The rule has ONE switch (`ruled`), every
    changed reader answers by the rule through it and with it off answers as `main` did; a job in which the rule
    answered anything is read both ways, `main`'s findings first and whole and the rule's beside them. What `main`
    reported is reported, whatever a reader makes of the rule's words."""

    D = '"$(echo "$PRE" %s)"' % P
    FOUND = (
        # A string that only MAY exist replaces the shell's own reading of its stdin.
        "curl -fsSLo \"$Y\" https://example.test/tool\necho \"%s  $Y\" | sha256sum -c\nsh -s$X \"$Y\" %s" % ("0" * 64, BODY),
        'bash -$OPTS "$SCRIPT" <<EOF\n$SETUP\nEOF\n',
        "echo \"$PRE\" %s | sh -$X \"$Y\"\n" % P,
        # A quiet stdin hand-off speaks before the loud reason of the `-c` string.
        "$CMD -${X:-c} %s <<'EOF'\necho hi\nEOF\n" % P,
        "sh $V %s -$X \"$A\" <<'EOF'\necho hi\nEOF\n" % P,
        # Stdin "is the program", so the printer of a FILE is not weighed.
        "sh -$X <(echo \"$PRE\" %s)\n" % P,
        # The second walk ends at the first word that MAY spell `c` among a FILE's parameters.
        "bash w.sh -- -$X ./f2 -c %s\n" % P,
        # A candidate, or a new first word, stands where the dynamic program was reported.
        "sh -${X:-c} %s\n" % D,
        "sh ~ -c %s\n" % D,
        "sh -$X errexit $Y -c %s\n" % D,
        "CMD=sh\n%s$CMD \"$@\" -$X '~'\n" % GET,
        # ... and the mark `workflow_annotate` withdraws from a `$CMD` whose strings are no longer all plain: the
        # one row of 36,000 my own fuzz lost (seed 2890), ruled documented (Krab 2423) and given back here.
        "CMD=sh\n$CMD -$*o -$@K '%s; %s' %s\n" % (CHECK, USE, P),
    )

    def test_a_step_main_reported(self):
        # RED before the floor: every one read CLEAN under every setting (the second, under three of the five).
        for text in self.FOUND + ("bash -c -$X sh foo " + BODY, "sh -$X - \"$A\" -c %s\n" % self.D):
            with self.subTest(text=text):
                self.assertEqual("RRRRR", marks(text)[0])

    def test_which_reading_reports_it(self):
        # The floor's rows: the rule's reading alone does not report them, `main`'s does, the job does.
        for text in self.FOUND[1:]:
            with self.subTest(text=text):
                self.assertEqual(FLOOR, readings(text))
        self.assertEqual(("RRRRR", "CCCRR", "RRRRR"), readings(self.FOUND[0]))
        # Two of the thirteen the rule's own reading keeps now. `bash -c -$X sh foo <<'EOF'`: the strings were joined
        # into `sh foo`, a shell handed a FILE; read apart (`workflow_programs._details`), `main`'s `sh` reads the body.
        self.assertEqual(EITHER, readings("bash -c -$X sh foo " + BODY))
        # `sh -$X - "$A" -c "$(...)"`: `"$A"` stood before the dynamic string `main` found, and one reader weighs the
        # first alone; `main`'s words stand first now (`_after_dash_c`).
        self.assertEqual(EITHER, readings("sh -$X - \"$A\" -c %s\n" % self.D))

    def test_mains_strings_are_read_joined_as_main_joined_them(self):
        # `_details` joins `main`'s strings as `main` did: as bash spells each (`spelled`, #2342) -- `eval`'s words keep
        # theirs, and `eval "\`echo sh\`"` hands its body to the `sh` the backquotes print, where `` \`echo `` read as
        # written would be a command's name -- and with a blank between them: `bash +c env -c sh` reads its body as
        # `env sh`'s, the join #3058 is about. Every reading reports both, the rule's and `main`'s.
        self.assertEqual(EITHER, readings('eval "\\`echo sh\\`" <<\'EOF\'\n%s%s\n%s\nEOF\n' % (GET, CHECK, USE)))
        self.assertEqual(EITHER, readings("bash +c env -c sh " + BODY))

    def test_an_eval_in_an_and_list_runs_with_errexit_off_as_main_read_it(self):
        # `flattened` asks a reader's `-e` once a reader now (#2889), and the text an `eval` runs in this shell keeps
        # `main`'s: in an and-list `-e` is off, so a check that fails there stops nothing and the step is reported --
        # the twin of the guard's own `eval '...' || exit 1` row.
        self.assertEqual(EITHER, readings("eval '%s; %s; %s; echo ok' && echo done\n" % (GET.strip(), CHECK, USE)))

    def test_with_the_rule_off_each_part_reads_as_main_read_it(self):
        # One row for each answer a reader owes the rule (each `ruled` in the scripts): reported by the rule, and
        # CLEAN with it off -- as on `main`, whose own tree reads every one of them CLEAN. A reader that ignored the
        # switch would report its row with the rule off. The whole of it is measured on the forge against `main`'s
        # tree, row for row and finding for finding, over every row set held (the PR's body has the counts).
        for text in ("sh -$X %s\n" % P,                                    # a reference in a word (`_spans`)
                     "sh ~ %s\n" % P,                                      # a tilde is a value (`_value`)
                     "sh $X ~ %s\n" % P,                                   # ... before the operand (`_before_operand`)
                     "sh $X ./f ~ %s\n" % P,                               # ... and past it (`_may_spell_option`)
                     "sh -c -$(echo o) errexit %s\n" % P,                  # a NAME a lifted word may owe (`_may_be_name`)
                     "bash -c$(echo O)o extglob errexit %s\n" % P,         # a refusal read before the expansion (`_refused_name`),
                     "sh -c$(true)o bogus %s\n" % P,                       # ... which `main` read from the whole word
                     "wget $X %s | sh\n" % URL,                            # a wget that may stream (`_parse_fetch`)
                     "$CMD ~ %s" % BODY,                                    # a `$` word's stdin, a tilde after it (`_value`)
                     "$CMD -x ~ %s" % BODY,
                     "echo %s | $CMD ~\n" % P,
                     "sh $X-c %s\n" % P,                                   # an expansion in front of an option word (`uncovered`),
                     "Y=-c; sh $X-e $Y %s\n" % P,                          # ... before a value,
                     "wget $X-O f %s && sh f\n" % URL):                     # ... and a fetcher's
            for digit in "0c":
                with self.subTest(text=text, digit=digit), nonce(digit):
                    self.assertEqual(RULED, readings(text))

    def test_where_the_rule_adds_nothing_the_shared_walks_answer_as_mains(self):
        # The walks the rule shares with `main` answer as `main`'s: its operand past a cluster, where a one-dash long
        # option after `-c` refuses (`-norc`), and its operand kept for every word, where the options end at the last
        # word. These read as `main`'s tree reads them, every way -- each was a one-line change the module did not
        # see before (the second pre-review's mutants). Truth: nothing runs the first two; the third runs the download.
        for text, expected in (("bash -$(echo c) -norc errexit $Y %s\n" % P, "CCCCC"),
                               ('bash -$(echo c) -norc errexit "$Y" %s\n' % P, "CCCCC"), ("sh -c -\n%s\n" % PIPE, "RRRRR")):
            for digit in "0c":
                with self.subTest(text=text, digit=digit), nonce(digit):
                    self.assertEqual((expected,) * 3, readings(text))

    def test_strict_mode_keeps_mains_reading_where_the_rule_alone_meets_a_refusal(self):
        # `fetch_exec_defects` is strict: it raises where the reader refuses a step's text. A string only the rule
        # finds may be such text, which `main` never met: there `main`'s reading of the job is the answer (`beside`'s
        # `refused`), and the guard's own reading, not strict, reports the step unread. The second pre-review found
        # it: 591 of its generated jobs raised where `main` answered.
        refused = "'cat <<$(a b)\nx\n$(a b)'"
        for text in ("%s\nsh -$X %s\n" % (PIPE, refused), "%s\nsudo bash -c -$X o %s\n" % (PIPE, refused),
                     "%s\n${SH:-sh} -c -${X} pipefail 'x=$(cat <<EOF\n)\nEOF\n)'\n" % PIPE):
            with self.subTest(text=text):
                with words.as_before():
                    mains = wg.fetch_exec_defects(text)
                self.assertEqual(1, len(mains))
                self.assertEqual(mains, wg.fetch_exec_defects(text))
                self.assertEqual("RRRRR", marks(text)[0])
        # A text `main` refuses too is refused still.
        with self.assertRaises(wg.shell_lex.Unreadable):
            wg.fetch_exec_defects("sh -c %s\n" % refused)

    def test_mains_findings_stand_first_and_whole(self):
        # Two steps: the first only the rule reports, the second `main` reports too. The job's findings are `main`'s,
        # each as `main` worded it and in its order, then the rule's -- whatever order the steps stand in.
        steps = [wg.Step("one", "sh -$X 'curl -fsSL https://example.test/b.sh | sh'\n", None),
                 wg.Step("two", "curl -fsSL https://example.test/a.sh | sh\n", None)]
        with words.as_before():
            before = wg.job_defects(steps)
        found = wg.job_defects(steps)
        self.assertEqual((["two"], ["two", "one"]), ([name for name, _why in before], [name for name, _why in found]))
        self.assertEqual(before, found[:1])
        self.assertIn("b.sh", found[1][1])
        # `main`'s first pass is what stands first and whole -- each of its findings kept, a repeat too -- and the second
        # walk's findings after it, each once: with the first pass finding A and the walk A then B, the job is A, B. (The
        # passes stood in for, as `main`'s `job_defects` reads them.)
        def passes(steps_, strict=False):
            return [("one", "A"), ("one", "A")] if wo._MAINS.get() else [("one", "A"), ("two", "B"), ("one", "A")]
        with mock.patch.object(wg, "_job_defects", passes):
            self.assertEqual([("one", "A"), ("one", "A"), ("two", "B")], wg.job_defects([]))
        # Inside the switch the job is `main`'s own: read once, and no reading of the rule's beside it.
        with words.as_before(), mock.patch.object(wg, "_job_defects", wraps=wg._job_defects) as passes:
            wg.job_defects(steps)
        self.assertEqual(2, passes.call_count)

    def test_a_job_is_read_twice_only_where_the_rule_answered(self):
        # The price of the floor: the two passes again, for a job that holds a word the rule answers about -- and
        # nothing for any other, a `$` in it or not. Where #3042's reading answered, `main`'s whole answer is read:
        # its two passes, and two more where #2889's rule answers in them.
        for text, passes in (("%s\n" % PIPE, 2), ('echo "$X"\n%s\n' % PIPE, 2), ('curl -fsSL "$URL" | sh -s -- "$A"\n', 2),
                             ('sh -c "$X" -$Y\n', 2),                     # past the string: a parameter, never asked
                             ("sh -$X %s\n" % P, 4), ("sh ~ %s\n" % P, 4), ("wget $X %s | sh\n" % URL, 4),
                             ("curl -fsSL -o$OUT %s\n" % URL, 4),           # asked, though the answer is `main`'s
                             ('sh -c "${X:-make}" ./a\n', 2), ("sh $X-c %s\n" % P, 4),   # no option word behind it; one (#3042)
                             ("sh -$Y $X-c %s\n" % P, 6)):                    # ... and #2889's rule in it
            with self.subTest(text=text), mock.patch.object(wg, "_job_defects", wraps=wg._job_defects) as read:
                wg.job_defects([wg.Step("step", text, None)])
                self.assertEqual(passes, read.call_count)

    def test_the_switch(self):
        self.assertEqual([True, False, False], [words.ruled(), words.ruled(False), words.ruled("")])
        with words.as_before():
            self.assertEqual([False, False], [words.ruled(), words.ruled(True)])
            with words.as_before():
                self.assertFalse(words.ruled())
            self.assertFalse(words.ruled())                                 # the inner one's end leaves the outer on
        self.assertTrue(words.ruled())
        with self.assertRaises(KeyError), words.as_before():                # ... and so does an error
            raise KeyError
        self.assertTrue(words.ruled())

    def test_a_reading_is_read_both_ways_where_the_rule_answered_in_it(self):
        asked = []

        def read(answer=True):
            asked.append(words.ruled(answer))
            return [asked[-1]]
        # The rule answered: `main`'s reading first, then the rule's. Three reads asked it: on, off, never inside.
        self.assertEqual(([False], [True]), words.beside(read))
        self.assertEqual([True, False], asked)
        # It answered nothing: ONE reading, the same object twice.
        mains, found = words.beside(lambda: read(False))
        self.assertIs(mains, found)
        self.assertEqual([True, False, False], asked)
        # With the rule off, one reading, `main`'s.
        with words.as_before():
            mains, found = words.beside(read)
        self.assertEqual(([False], True), (mains, mains is found))
        # A reading inside another tells that one what it heard: the outer is read both ways too, and inside its
        # second reading the inner is read once (both of its parts are that one reading).
        del asked[:]
        self.assertEqual(([False, False], [False, True]), words.beside(lambda: [x for part in words.beside(read) for x in part]))
        self.assertEqual([True, False, False], asked)
        # An error of `refused`'s kind in the rule's reading leaves `main`'s reading alone, the same object twice;
        # where `main`'s reading raises it too, it is raised.
        def refusing():
            if words.ruled():
                raise KeyError
            return ["main"]
        mains, found = words.beside(refusing, KeyError)
        self.assertEqual((["main"], True), (mains, mains is found))
        with self.assertRaises(KeyError), words.as_before():
            words.beside(lambda: {}[0], KeyError)
        with self.assertRaises(KeyError):
            words.beside(lambda: (words.ruled(), {}[0]), KeyError)
        # A reading that raises leaves no note behind: the next reading starts unheard.
        with self.assertRaises(KeyError):
            words.beside(lambda: read() and {}[0])
        mains, found = words.beside(lambda: read(False))
        self.assertIs(mains, found)

    def test_the_switch_is_read_in_one_place(self):
        # The floor's argument: a reader's answer depends on the rule through `ruled` alone, so a reading in which
        # `ruled` was never true IS the reading with the rule off, and needs no second one. So the switches and the
        # note are named in the leaf alone, and read there by these functions alone: #2889's (`as_before`), #3042's
        # (`as_main`), `ruled`, `beside`, and the job's floor (`passes`), which reads `main`'s whole answer with
        # #3042's switch off wherever that reading answered.
        scripts = os.path.dirname(words.__file__)
        named = {}
        for name in sorted(os.listdir(scripts)):
            if name.endswith(".py"):
                with open(os.path.join(scripts, name), encoding="utf-8") as handle:
                    tree = ast.parse(handle.read())
                for function in [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]:
                    used = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)} & {"_OFF", "_NEW_OFF", "_HEARD"}
                    used |= {node.attr for node in ast.walk(function) if isinstance(node, ast.Attribute)} & {"_OFF", "_NEW_OFF", "_HEARD"}
                    if used:
                        named[(name, function.name)] = sorted(used)
        self.assertEqual({("workflow_option_words.py", "as_before"): ["_OFF"],
                          ("workflow_option_words.py", "as_main"): ["_NEW_OFF"],
                          ("workflow_option_words.py", "ruled"): ["_HEARD", "_NEW_OFF", "_OFF"],
                          ("workflow_option_words.py", "beside"): ["_HEARD", "_OFF"],
                          ("workflow_option_words.py", "passes"): ["_HEARD", "_NEW_OFF", "_OFF"]}, named)


    # Round 1 of #3065's review: rows the fetch site loses INSIDE the passes -- the seat's `seat3065.mp.*` rows and
    # the ruling's others. Where the words read `uncovered` name a transfer with a URL, `workflow_fetch._parse_curl_wget`
    # returns that Fetch instead of `main`'s, and `main`'s was the fail-closed one: a download whose file is unsure
    # (`$X-O a`: `main` reads three operands, the file the remote name; `$X-O $Y`: #3034's file view) and then a shell
    # of a file. The job reports every one because its first pass is `main`'s whole answer (`as_main`) and
    # `job_defects` is the only entry point: the pass-level loss is the reason these pins exist. Keeping `main`'s
    # Fetch first at the fetch site and adding the alt beside it, so the passes are monotone too, is #3093's.
    # Truth: runs, every one.
    SEAT = (
        "wget $X-O a %s\nsh i.sh\n" % URL,                                      # seat3065.mp.wget-O-a
        "wget $X-P d %s\nsh i.sh\n" % URL,                                      # seat3065.mp.wget-P
        "wget $X-O a %s\necho \\\"0000000000000000000000000000000000000000000000000000000000000000  i.sh\\\" | sha256sum -c -\nsh i.sh\n" % URL, # seat3065.mp.wget-O-f-chk
        "wget $X-qO- %s > f\nsh i.sh\n" % URL,
        "wget $X-O $Y %s\nsh i.sh\n" % URL,                                     # the delta: #3034's file view, read in the passes
        "Y=tool\nwget $X-O $Y %s\nsh tool\n" % URL,
        "wget $X-O a %s\nsh a\n" % URL,                                         # seat3065.mp.wget-O-a-use-a
    )
    REASON = (                                              # three that lose only the reason in the passes
        "curl $X-fsSL %s | sh\n" % URL,
        "curl $X-o a %s\nsh a\n" % URL,
        "wget $X-qO- %s | sh\nsh i.sh\n" % URL,
    )

    def test_what_the_fetch_site_loses_in_the_passes(self):
        # Pinned at `job_defects`, the five postures (the review's round 1).
        for text in self.SEAT + self.REASON:
            with self.subTest(text=text):
                self.assertEqual("RRRRR", marks(text)[0])

    def test_which_pass_loses_it(self):
        # The first five: the rule's reading alone reads them CLEAN and `main`'s reports them, the floor's rows.
        for text in self.SEAT[:5]:
            with self.subTest(text=text):
                self.assertEqual(FLOOR, readings(text))
        # `Y=tool` set on the line before: with #2889's rule off the row is CLEAN as well (the guard follows that
        # value and reads `tool` as one more operand of `wget`, as it did before #2889); the job's first pass, #2889's
        # rule on, reports it, and this rule's reading alone does not.
        self.assertEqual(("RRRRR", "CCCCC", "CCCCC"), readings(self.SEAT[5]))
        # `wget $X-O a URL` then `sh a`: this rule's own report -- `main` reads `a` as an operand of `wget` and `sh a`
        # as another file's -- the seat's row, kept beside the others.
        self.assertEqual(RULED, readings(self.SEAT[6]))
        for text in self.REASON:
            with self.subTest(text=text):
                self.assertEqual(EITHER, readings(text))


class TestTheLeafKnowsAReference(unittest.TestCase):
    """`workflow_option_words`: a parameter reference stands in a word as a marker does."""

    def test_where_a_reference_stands(self):
        for text, spans in (("-$X", [(1, 3)]), ("-e$X", [(2, 4)]), ("-${X}c", [(1, 5)]), ("-${X:-${Y}}c", [(1, 11)]), ("-$1a", [(1, 3)]),
                            ("-x$@K", [(2, 4)]), ("-$*o", [(1, 3)]), ("-$-", [(1, 3)]), ("-$_x9o", [(1, 6)]), ("-$X$Y", [(1, 3), (3, 5)]),
                            ("-$#$X", [(3, 5)]), ("-${#X}$Y", [(6, 8)]), ("-${", [(1, 3)]), ("-$\\q", [(1, 4)]),
                            ("-$#", []), ("-$?", []), ("-$$", []), ("-$$X", []), ("-$!", []), ("-${#X}", []), ("-${#}", []), ("-e$", []),
                            ("-$", []), ("-c", []), ("", []),
                            # Only a `${` opens a brace to close: `${X:-{}` ends at its one `}`, and the `c` is written.
                            ("-${X:-{}c", [(1, 8)]), ("-${X:-${Y:-{}}c", [(1, 14)]),
                            # A length prints digits: of a name, a member, a positional, the set, a status.
                            ("-${#X[1]}", []), ("-${#X[@]}", []), ("-${#12}", []), ("-${#@}", []), ("-${#*}", []), ("-${#?}", []),
                            ("-${#-}", []), ("-${##}c", []), ("-${#_x9}", []),
                            # ... and any other `${#` is the count under an operator, which prints its word: `${#+c}` is `c`.
                            ("-${#$}", []), ("-${#!}", []), ("-${#X[12]}", []),
                            ("-${#+c}", [(1, 7)]), ("-${#:+o}", [(1, 8)]), ("-${#-o}", [(1, 7)]), ("-${#:-c}x", [(1, 8)]), ("-${#X:-c}", [(1, 9)])):
            with self.subTest(text=text):
                self.assertEqual(spans, words._spans(text))
                self.assertEqual(bool(spans), words.lifted(text))

    def test_a_names_digits_and_each_positional(self):
        # A NAME runs on through every digit (`$X0123456789c` is ONE name), and each of `$0` to `$9`, `$@`, `$*` and
        # `$-` is a reference of two characters whatever stands behind it.
        self.assertEqual([(1, 14)], words._spans("-$X0123456789c"))
        for sign in "0123456789@*-":
            with self.subTest(sign=sign):
                self.assertEqual([(1, 3)], words._spans("-$%sx" % sign))

    def test_written_before_and_spells(self):
        for text, written, before in (("-$X", "-", "-"), ("-e$X", "-e", "-e"), ("-${X}c", "-c", "-"), ("-x$@K", "-xK", "-x"),
                                      ("-o$Xo", "-o", "-o"), ("-$cmd", "-", "-"), ("-c$#", "-c$#", "-c$#"), ("-c", "-c", "-c")):
            with self.subTest(text=text):
                self.assertEqual(written, words.written(text))
                self.assertEqual(before, words.before(text))
        self.assertEqual([True, True], [words.spells("-$X", letter) for letter in "cs"])
        self.assertEqual([False, True], [words.spells("-s$#", letter) for letter in "cs"])
        self.assertEqual([1], [k for k in range(5) if words.lifted("-$Xab", k, k + 1)])

    def test_a_name_is_ascii(self):
        # bash names are ASCII letters, digits and `_`: a `$` before any other letter begins no expansion.
        self.assertEqual([], words._spans("-$" + chr(233) + "x"))
        self.assertEqual([(1, 4)], words._spans("-$Xa" + chr(233)))
        # ... and every one of those letters begins a name and goes on one: `-$QUIET` writes no letter at all.
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_":
            with self.subTest(letter=letter):
                self.assertEqual(["-", "-"], [words.written("-$" + letter), words.written("-$x" + letter)])
        self.assertEqual(RULED, readings("sh -$QUIET %s\n" % P))

    def test_a_marker_inside_a_reference(self):
        # `-${X:-$(echo x)c}`: the lifted text stands inside the braces, and the word writes nothing but its `-`.
        # (Each span cut out in turn, the second ended before the first did and the cut stepped back: `-c}`.)
        for digit in "0c":
            with nonce(digit):
                word = argv("sh -${X:-$(echo x)c}")[1]
                (start, end), (inner, inner_end) = words._spans(word)
                self.assertTrue(start < inner < inner_end < end)
                self.assertEqual(["-", "-"], [words.written(word), words.before(word)])
                self.assertEqual(["-o", "-"], [words.written(argv("sh -${X:-$(echo x)}o")[1]), words.written(argv("sh -${X:-a$(echo x)b$(echo y)c}")[1])])

    @staticmethod
    def _mains_spans(word):
        text, own = str(word), getattr(word, "markers", None)       # `_spans` on 837228ef, word for word
        if not own and "@@" not in text:
            return []
        spans = set()
        for key in own or ():
            at = 0
            for before in text.split(key)[:-1]:
                spans.add((at + len(before), at + len(before) + len(key)))
                at += len(before) + len(key)
        for found in shell_tokens._MARK.finditer(text):
            if shell_tokens._NONCE.match(found.group()):
                spans.add(found.span())
        return sorted(spans)

    def test_with_the_rule_off_a_word_holds_its_markers_alone(self):
        # `main`'s leaf, kept above: with the rule off the word is asked as `main` asked it, a reference its text.
        for digit in "0c":
            with nonce(digit):
                for text in ("-$X", "-c$X", "-$cmd", "-${X:-c}", "-$(echo c)", "-$X$(echo c)e", "-${X:-$(echo x)c}", "-e", "~", "$Y", "-o$1"):
                    word = argv("sh " + text)[1]
                    spans = self._mains_spans(word)
                    mains = "".join(letter for at, letter in enumerate(str(word)) if not any(a <= at < b for a, b in spans))
                    with self.subTest(text=text, digit=digit), words.as_before():
                        self.assertEqual(spans, words._spans(word))
                        self.assertEqual([mains, bool(spans), "c" in mains or bool(spans)],
                                         [words.written(word), words.lifted(word), words.spells(word, "c")])
                    self.assertTrue(set(spans) <= set(words._spans(word)))      # ... and with it on, those and more

    def test_a_reference_beside_a_marker(self):
        for digit in "0c":
            with nonce(digit):
                word = argv("sh -$X$(echo c)e")[1]
                self.assertEqual("-e", words.written(word))
                self.assertEqual("-", words.before(word))
                self.assertEqual(2, len(words._spans(word)))


class TestThePrice(unittest.TestCase):
    """What the rule reports that runs nothing, each shape pinned as it reads (the ruling: Krab 2423)."""

    def test_a_variable_that_spells_no_c(self):
        # Truth: nothing. `X=e`, `x`, `n`, empty, never set: the shell takes the program text for a FILE's name and
        # the step fails (exit 127 or 2); `X=s`: the string is a positional parameter, the shell reads its stdin.
        for sets in ("X=e\n", "X=x\n", "X=n\n", "X=s\n", "X=\n", "", "X=c\nunset X\n", "X=c\nX=x\n"):
            with self.subTest(sets=sets):
                self.assertEqual(BOTH, marks("%ssh -$X %s\n" % (sets, P)))
        # as its whole-word twin has been since #2344
        self.assertEqual(BOTH, marks("X=-e\nsh $X %s\n" % P))
        # ... and so is a reference no step assigns: the shell's flags, its name, a variable of the runner's, and
        # the braced twin of a status (`$?` stays written, `${?}` is read as `${X}` is). Truth: nothing.
        for word in ("-$-", "-$0", "-$GITHUB_REF_NAME", "-${?}"):
            with self.subTest(word=word):
                self.assertEqual(BOTH, marks("sh %s %s\n" % (word, P)))

    def test_a_quoted_dollar_or_tilde_reaches_the_readers_unquoted(self):
        # `sh '-$X' 'P'` hands the shell the text `-$X`. The reader drops the quotes, as it does for `sh '$X' 'P'`,
        # which `main` reports too. Truth: nothing.
        self.assertEqual(BOTH, marks("sh '-$X' %s\n" % P))
        self.assertEqual(BOTH, marks("sh '$X' %s\n" % P))
        self.assertEqual(BOTH, marks('HOME=-c\nsh "~" %s\n' % P))
        # A locale string is read as bash reads it (#3048): `-$"x"` is bash's `-x`, and `P` a file no step wrote --
        # CLEAN, nothing runs (#3048: bash's `-x`; nothing runs). Where `P` IS the download, it runs: reported.
        self.assertEqual(CLEAN, marks('sh -$"x" %s\n' % P))
        self.assertEqual(BOTH, marks('curl -fsSL -o P https://example.test/P\nsh -$"x" P\n'))

    def test_a_word_that_owes_nothing(self):
        # Truth: nothing: `X=c`: `errexit` is the string and `P` its `$0`; `-oc bogus`: no such name.
        self.assertEqual(BOTH, marks("X=c\nsh -$X errexit %s\n" % P))
        self.assertEqual(BOTH, marks("X=oc\nsh -$X bogus %s\n" % P))
        self.assertEqual({BOTH}, under("sh -c$(true) one -c %s\n" % P))
        # ... and a word that is no name is the operand still: `P` is its parameter. Truth: nothing.
        self.assertEqual(CLEAN, marks("X=c\nsh -$X ./x.sh %s\n" % P))

    def test_a_tilde_that_is_no_option(self):
        # Truth: nothing (`sh -s 'P'` reads an empty stdin; a directory is no script).
        for home in ("-s", "-x", "-", "/nonexistent"):
            with self.subTest(home=home):
                self.assertEqual(BOTH, marks("HOME=%s\nsh ~ %s\n" % (home, P)))
        self.assertEqual(BOTH, marks("sh ~ %s\n" % P))

    def test_a_fetchers_letters_that_hold_a_reference_leave_the_transfer_unread(self):
        # Nothing is piped and nothing runs, and the step is reported for a transfer the guard cannot read: as its
        # `$(...)` twin is since #3023 (`wget -q$(true) URL`), and as curl's was on `main`, whose letters are a table.
        # Truth: fetched only.
        for fetch in ("wget -q$X", "wget --quiet$X", "curl -s$X", "wget -q$(true)"):
            with self.subTest(fetch=fetch):
                self.assertEqual({BOTH}, under("%s %s\n" % (fetch, URL)))
        # In an option's VALUE a reference is a value, as it was: the transfer is read, and nothing runs it.
        for fetch in ("wget -O$OUT", 'wget -q -O "$OUT"', "curl -fsSL -o$OUT", 'curl -fsS -H "X: $TOKEN" -o out'):
            with self.subTest(fetch=fetch):
                self.assertEqual(CLEAN, marks("%s %s\n" % (fetch, URL)))

    def test_a_wget_that_streams_nothing(self):
        # Truth: fetched only.
        for row in ("X=qO-\nwget $X %s | sh\n", "wget $X %s | sh\n", "X=-q\nwget $X %s | sh\n", "wget $(true) %s | sh\n"):
            with self.subTest(row=row[:20]):
                self.assertEqual({BOTH}, under(row % URL))


    def test_an_expansion_in_front_that_prints_something(self):
        # #3042's, as rule 1's: the guard follows no value, so `$X-c` is read as `-c` whatever the step sets; a quoted
        # or escaped `$X` reaches the readers unquoted, as `sh '$X' P` does; and the count under an operator always
        # prints its word, which the leaf reads as any reference. Truth: nothing, every one.
        for row in ("X=x; SHELL $X-c %s\n", "X=-; SHELL $X-c %s\n", "X=-e; SHELL $X-c %s\n", "SHELL '$X'-c %s\n", "SHELL ${#+c}-c %s\n"):
            for shell in ("sh", "bash"):
                with self.subTest(row=row, shell=shell):
                    self.assertEqual(RULED, readings(row.replace("SHELL", shell) % P))
        self.assertEqual(RULED, readings("sh %s$X-c %s\n" % (chr(92), P)))
        # ... and the readers of `main` read on past a cluster with a written character no option is (`-ci.sh`,
        # `-backup/run.sh`): such a word read so is one, and a `$` word after it the shell's string, reported where a
        # download stands beside it -- as `main` reports the written twin. Truth: fetched only, every one.
        for text in ('curl -fsSL https://example.test/data.json -o data.json\nbash ${TOOL}-${VERSION}/install.sh "$PREFIX"\n', 'curl -fsSL https://example.test/data.json -o data.json\nsh $HOME-backup/run.sh "$A"\n', 'curl -fsSL https://example.test/data.json -o data.json\nbash $NAME-ci.sh "$ARG"\n', 'curl -fsSL https://example.test/data.json -o data.json\nsh ${APP}-cli "$ENV"\n'):
            with self.subTest(text=text):
                self.assertEqual(RULED, readings(text))
        twin = 'curl -fsSL https://example.test/data.json -o data.json\nbash -${VERSION}/install.sh "$PREFIX"\n'
        self.assertEqual(RULED, readings(twin))                  # #2889's: CLEAN with every rule off, as before it
        with words.as_main():
            self.assertEqual(("RRRRR", "RRRRR"), marks(twin))      # ... and `main` reports it
        # ... and an expansion that always prints is read as any other: the shell's name (`$0`), a process
        # substitution's path (`<(...)`). Truth: nothing, every one. `$_` is empty in dash. Truth: runs under dash.
        for text in ("sh $0-c 'curl -fsSL https://example.test/i.sh | sh'\n", "bash <(true)-c 'curl -fsSL https://example.test/i.sh | sh'\n", "sh $_-c 'curl -fsSL https://example.test/i.sh | sh'\n", 'wget $0-qO- https://example.test/i.sh | sh\n', 'wget <(true)-qO- https://example.test/i.sh | sh\n'):
            for digit in "0c":
                with self.subTest(text=text, digit=digit), nonce(digit):
                    self.assertEqual(RULED, readings(text))
        # ... and a word after them the guard reads as one that may be the string or a value, as it reads their
        # written twins on `main` (`sh -c "$Y" P`, `sh -e $Y $Z $Z P`). Truth: nothing.
        for row in ('SHELL $X-c "$Y" %s\n', "SHELL $W-e $Y $Z $Z %s\n"):
            for shell in ("sh", "bash"):
                with self.subTest(row=row, shell=shell):
                    self.assertEqual(RULED, readings(row.replace("SHELL", shell) % P))


class TestWhatStays(unittest.TestCase):
    """Rows this rule does not move, each pinned as it reads."""

    def test_a_dollar_words_cluster_that_is_not_its_first_word(self):
        # #2671, #2900. Truth: runs, every one.
        for words_ in ("$CMD +x -c", "$CMD -e -$X -c", "$CMD -c $Y"):
            with self.subTest(words=words_):
                self.assertEqual(CLEAN, marks("CMD=$(command -v sh)\nX=x\nY=-c\n%s %s\n" % (words_, P)))

    def test_two_shapes_of_wget(self):
        # #3033: two URLs read as the first. #3035: a stream only an expansion makes, saved to a
        # file. Truth: runs, every one.
        self.assertEqual(CLEAN, marks("wget https://example.test/a https://example.test/tool\nsh tool\n"))
        self.assertEqual({CLEAN}, under("wget $(echo -qO-) %s | tee tool\nsh tool\n" % URL))
        self.assertEqual(CLEAN, marks("X=-qO-\nwget $X %s > tool\nsh tool\n" % URL))

    def test_a_fetchers_word_behind_a_locale_string_or_a_brace(self):
        # #3042's reading of a fetcher's words in two spellings the reader hands on otherwise: a locale string
        # (`$""`, `$"-qO-"`) reaches the readers as `$` and its text, and a brace word is never read so. Open on `main`
        # too. Truth: runs under bash, all eight; dash reads the word as written and fetches only.
        for text in ('wget $""-qO- https://example.test/i.sh | sh\n', 'wget $"-qO-" https://example.test/i.sh | sh\n'):
            with self.subTest(text=text):     # (moved by #3048: the locale string read as bash reads it)
                self.assertEqual(BOTH, marks(text))
        self.assertEqual(CLEAN, marks('wget {,}-qO- https://example.test/i.sh | sh\n'))

    def test_a_cluster_written_after_such_a_word(self):
        # ... and where a cluster is written after a word read so, `main` reads that one, and the rule reads the
        # same: the control the first build of this rule pinned, restored in the review's round 1. Truth: runs.
        self.assertEqual(BOTH, marks("sh $X-e -c %s\n" % P))

    def test_a_substitution_in_the_strings_slot(self):
        # #3043. A `$Y` after the `-c` cluster may be an option word or nothing, so the words after it are weighed
        # (#2858 round 7); a `$(...)` there is `dynamic_program`'s, and the string behind it is not read. Open on
        # `main` too. Truth: runs, every one.
        for word in ("$(true)", "$(echo -e)", "$(nosuchtool)"):
            with self.subTest(word=word):
                self.assertEqual({CLEAN}, under("sh -c %s %s\n" % (word, P)))
        self.assertEqual(WALK, marks("sh -c $X %s\n" % P))

    def test_two_more_shapes_of_a_fetcher(self):
        # #3044: the VALUE of a written `-O` or `-o` may be `-`. Open on `main` too. Truth: runs, all sixteen.
        self.assertEqual(CLEAN, marks("X=-\nwget -q -O $X %s | sh\n" % URL))
        self.assertEqual(CLEAN, marks("X=-\ncurl -fsSL -o $X %s | sh\n" % URL))
        # #3045: a stream only an expansion makes may be read through a `<(...)`. #3034's
        # unresolved-file-view price now reports the two dynamic rows; binding that stream directly
        # remains the more precise reading. Truth: both bashes run them and the written twin.
        self.assertEqual(BOTH, marks("X=-qO-\nbash <(wget $X %s)\n" % URL))
        self.assertEqual(BOTH, marks("X=-qO-\nsh < <(wget $X %s)\n" % URL))
        self.assertEqual(BOTH, marks("bash <(wget -qO- %s)\n" % URL))

    def test_the_first_pass_alone(self):
        # The first pass counts a check in a string it reads; the second walk counts none behind a word that may
        # expand, so the JOB reports. `-$e`: `workflow_posture._errexit` still reads the name's letter for `-e`.
        # Truth: `e=c` runs, all sixteen.
        self.assertEqual(WALK, marks("%se=c\nsh -$e '%s; %s'\n" % (GET, CHECK, USE)))
        self.assertEqual(WALK, marks("%se=x\nsh -$e <<'EOF'\n%s\n%s\nEOF\n" % (GET, CHECK, USE)))


if __name__ == "__main__":
    unittest.main()
