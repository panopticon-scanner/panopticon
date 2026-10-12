"""#3020, #3023: a reader does not ask a parse marker for an option's letters.

A lifted substitution stands in a word as a marker of its parse, `@@shell-<32 hex a parse><16 hex a process>-N@@`.
The readers asked an option word for its letters as TEXT, the marker's among them. So a shell's `-$(echo c) 'P'` was
a `-c` only where the random hex held a `c` -- the same step CLEAN in one call and reported in the next -- and a
fetcher's `-fsSL$(true)` was `curl -h`, which fetches nothing, in every call: the marker's fixed text spells `s`,
`h`, `e` and `l`. Each reader now rules on the word (`workflow_option_words`): a finder of a `-c` cluster takes a
word that holds lifted text for one, which is what it read under a marker with a `c`, and where no `c` is written
in the word it reads on past it too, which is what it read under a marker with none (`TestAWordThatMayPrintNoC`);
a walk for the program on stdin reads `c` as written and `s` as written or lifted, as under a marker with none;
and the fetch reader leaves a transfer unread where lifted text stands among an option's letters or in its name.
So the job reads what `main` reads under either marker, and its reading depends on neither.

A marker is known by the word that carries it, and -- in a text the guard reads AGAIN, whose words carry none -- by
its shape and this process's nonce (`TestAMarkerInATextReadAgain`): `echo "sh -$(echo c) 'P'" | sh` hands the inner
shell's words the first parse's marker as plain text, and read by the word alone they were read for letters still.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports,
C where it reads the step CLEAN: first the job's, then the main pass's. `nonce(d)` makes every marker a block
mints all `d`s, so a row has ONE reading in it; a test that holds a reading holds it under a marker with no letter
(`0`) and under one with the letter the finders ask for (`c`).

Truth, in the comments, is what eight parent shells do with the step in two passes on the forge: bash 5.2.21 and
bash 3.2.57 under `-e` and under `-eo pipefail`, dash under `-e`, then each without `-e`; pass 2 gives each parent
a child shell of its own family. "runs" is all sixteen ran the download, "nothing" is none did.

The price is none that is new: every shell's row reported here was reported on `main` under one marker or the
other -- most under a marker with a `c`, 199 calls in 200 on a row the #2942 seat measured -- and the fetchers'
rows read as `curl -$X URL | sh` reads. Two families this left open are #2889's since, and pinned where that
rule is (`tests/test_workflow_option_expansions.py`): a letter a VARIABLE makes (`X=c; sh -$X 'P'`), and a VALUE a
word may owe for an `o` it prints (`sh -$(echo oc) errexit 'P'`). The pins here that moved with it are each named
where they stand. Left for other issues, pinned in `TestWhatStaysForOtherIssues`: the first pass alone, and the other
readers that ask a marker for letters, which no row here reaches.
"""
import ast
import contextlib
import os
import re
import secrets
import unittest
from unittest import mock

import shell_reader
import shell_tokens
import workflow_fetch
import workflow_guard as wg
import workflow_option_slots
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
BOTH = ("RRRRR", "RRRRR")           # the job reports, and so does the main pass
WALK = ("RRRRR", "CCCCC")           # the second walk alone reads it
CLEAN = ("CCCCC", "CCCCC")
UNREAD = "unresolved transfers"     # the fetch rule's sentence for a transfer it could not parse


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


def sentences(text, digit):
    with nonce(digit):
        return [str(why) for _name, why in wg.job_defects([wg.Step("step", text, None)])]


def argv(text):
    return shell_reader.statements(text)[-1].stages[0].argv


class TestAShellsOptionWordThatHoldsASubstitution(unittest.TestCase):
    """#3020: `sh -$(echo c) 'P'`. On `main` each of these is CLEAN under a marker without a `c`."""

    def test_a_c_the_substitution_prints(self):
        # Truth: runs, every one, written `-` or `+`.
        for shell in ("sh", "bash", "dash"):
            for sign in "-+":
                for word in ("%s$(echo c)", "%s`echo c`", '"%s$(echo c)"', "%se$(echo c)", "%s$(echo c)e", "%sx$(echo c)x",
                             "%s$(echo ec)", "%s$(echo c)$(echo e)", "%sc$(true)", "%s$(true)c"):
                    with self.subTest(shell=shell, word=word % sign):
                        self.assertEqual({BOTH}, under("%s %s %s\n" % (shell, word % sign, P)))

    def test_behind_a_wrapper_a_default_a_dollar_word_and_other_option_words(self):
        # The #2942 seat's twelve standing rows are the second shape. Truth: runs, every one.
        for row in ("env sh -$(echo c) %s\n", "sudo sh -$(echo c) %s\n", "${X:-sh -$(echo c)} %s\n",
                    "CMD=$(command -v sh)\n$CMD -$(echo c) %s\n", "CMD=$(command -v sh)\n$CMD +$(echo c) %s\n",
                    "bash --norc -$(echo c) %s\n", "sh -e -$(echo c) %s\n"):
            with self.subTest(row=row[:24]):
                self.assertEqual({BOTH}, under(row % P))
        # After a one-dash long option's FILE the second walk's finder is alone (#2858). Truth: runs under bash.
        self.assertEqual({WALK}, under("bash -rcfile /dev/null -$(echo c) %s\n" % P))

    def test_a_letter_that_is_not_c_is_reported_too(self):
        # The word MAY spell `-c`, so the string is read; it spells `-x`, `-e` or nothing, and the string is a
        # FILE's name. Truth: nothing, every one. Reported under a marker with a `c` on `main`: no new price.
        for shell in ("sh", "bash", "dash"):
            for word in ("-$(echo x)", "-$(echo e)", "-$(true)", "+$(echo x)", "-e$(echo x)"):
                with self.subTest(shell=shell, word=word):
                    self.assertEqual({BOTH}, under("%s %s %s\n" % (shell, word, P)))
        # A `<(...)` is lifted text too, and what it puts in the word is a path the shell refuses. Truth: nothing.
        self.assertEqual({BOTH}, under("sh -<(echo c) %s\n" % P))

    def test_a_check_in_the_string_is_not_counted(self):
        # The shell is not sure to run the string as its program, so the second walk counts no check in it and
        # the job reports. Truth: the download runs for `-$(echo c)` and `+$(echo c)` (no `-e` in the string);
        # the check stops it for `-e$(echo c)`, reported all the same. The MAIN pass counts the check behind a
        # `-` word under every marker: `workflow_posture._errexit` reads the marker's own `e` for `-e`, one of
        # the readers this fix leaves (see `TestWhatStaysForOtherIssues`).
        for word, reading in (("-$(echo c)", WALK), ("-e$(echo c)", WALK), ("+$(echo c)", BOTH)):
            with self.subTest(word=word):
                self.assertEqual({reading}, under("%ssh %s '%s; %s'\n" % (GET, word, CHECK, USE)))

    def test_the_body_on_stdin_is_read_whatever_the_word_may_print(self):
        # A `c` the word may print does not make the walk drop the body, and an `s` it may print keeps it. Truth:
        # runs for `-$(echo x)` and `-$(echo s)`; nothing for `-$(echo c)`, where bash wants a string.
        for shell in ("sh", "bash", "dash"):
            for word in ("-$(echo x)", "-$(echo s)", "-$(echo c)", "-$(true)", "+$(echo x)"):
                with self.subTest(shell=shell, word=word):
                    self.assertEqual({BOTH}, under("%s %s <<'EOF'\n%s\nEOF\n" % (shell, word, PIPE)))
        # With a word after it: a string if the word prints `c`, a parameter if it prints `s`. Truth: runs for `s`.
        for word in ("-$(echo s)", "-$(echo c)"):
            with self.subTest(word=word, frame="a word and a body"):
                self.assertEqual({BOTH}, under("sh %s true <<'EOF'\n%s\nEOF\n" % (word, PIPE)))

    def test_what_is_written_is_still_read_as_written(self):
        # A `-c` cluster before the word that holds a substitution is the cluster, and the word a parameter.
        self.assertEqual({CLEAN}, under("sh -c 'echo hi' -$(echo c) %s\n" % P))        # truth: nothing
        self.assertEqual({BOTH}, under("bash -o $(echo pipefail) -c %s\n" % P))         # truth: runs; a value
        self.assertEqual({BOTH}, under("sh -c \"$(curl -fsSL %s)\"\n" % URL))           # truth: runs; the string


class TestAWordThatMayPrintNoC(unittest.TestCase):
    """The word MAY spell `-c`, and it may spell `-x`: both are read, the second beside the first, never instead.
    Past a word in which no `c` is WRITTEN the search for the cluster goes on, and so does the walk for a value --
    what `main` read under a marker without a `c`, as the word's own string is what it read under one with."""

    FILE = "printf 'eval \"$2\"\\n' > w.sh\n"          # a FILE that runs a parameter it is handed

    def test_a_dash_c_a_variable_behind_the_word_holds(self):
        # Truth: runs, every one (`-$(true)` aside: `sh - -c P` runs nothing, and reads the same).
        for word in ("-$(echo x)", "-$(echo e)", "+$(echo x)", '"-$(echo x)"', "-`echo x`", "-$(echo c)", "-$(true)"):
            with self.subTest(word=word):
                self.assertEqual({BOTH}, under("Y=-c\nsh %s $Y %s\n" % (word, P)))
        # Two such words, and an `-o` with its name between. Truth: runs, both.
        self.assertEqual({BOTH}, under("Y=-c\nsh -$(echo x) -$(echo e) $Y %s\n" % P))
        self.assertEqual({BOTH}, under("Y=-c\nsh -$(echo x) -o errexit $Y %s\n" % P))

    def test_a_cluster_among_the_parameters_of_a_file(self):
        # `sh -x w.sh -c P`: the FILE runs `P`. Truth: runs, every one.
        for word in ("-$(echo x)", "-$(echo e)", "-x$(true)", "+$(echo x)"):
            with self.subTest(word=word):
                self.assertEqual({BOTH}, under("%ssh %s w.sh -c %s\n" % (self.FILE, word, P)))
        self.assertEqual({BOTH}, under("%ssh -$(echo x) -$(true)e w.sh -c %s\n" % (self.FILE, P)))

    def test_a_word_all_substitution_that_may_print_the_dash_c(self):
        # `sh -o errexit -c P`: the first word's `o` is written and takes the name. Truth: runs.
        self.assertEqual({BOTH}, under("sh -o$(true) errexit $(echo -c) %s\n" % P))

    def test_a_long_options_name_the_word_prints(self):
        # `bash --norc -c P` and `bash --norc --rcfile /dev/null -c P`. Truth: every bash parent runs both. The
        # second walk alone skips a long option's FILE (#2616).
        self.assertEqual({BOTH}, under("Y=-c\nbash -$(echo -norc) $Y %s\n" % P))
        self.assertEqual({WALK}, under("Y=-c\nbash -$(echo -norc) --rcfile /dev/null $Y %s\n" % P))

    def test_the_price_is_what_main_reads_past_dash_x(self):
        # Truth: nothing, each -- a long option behind a short one is refused, and `sh -x 'echo one' -c P` runs a
        # FILE that is not there. Reported on `main` under a marker without a `c`, and as the `-x` twin is.
        for text in ("Y=-c\nsh -$(echo x) --$(echo norc) $Y %s\n" % P, "sh -$(echo x) 'echo one' -c %s\n" % P):
            with self.subTest(text=text[:30]):
                self.assertEqual({BOTH}, under(text))
        self.assertEqual({BOTH}, under("sh -x 'echo one' -c %s\n" % P))

    def test_a_c_that_is_written_ends_the_search(self):
        # `sh -c 'echo one' -c P` runs `echo one`, lifted text beside the `c` or not. Truth: nothing. The first
        # pass stops at the word; the second walk reads on where the whole word may vanish, as it did.
        self.assertEqual({CLEAN}, under("sh -c 'echo one' -c %s\n" % P))
        self.assertEqual({WALK}, under("sh -c$(true) 'echo one' -c %s\n" % P))

    def test_the_finder_reads_both_and_each_word_once(self):
        for digit in "0c":
            with nonce(digit):
                for text, found in (("sh -$(echo x) w.sh -c 'P'", ["w.sh", "P"]), ("sh -x$(true) -c 'P'", ["P"]),
                                    ("sh -$(echo x) -$(echo e) one -c 'P'", ["one", "P"]),
                                    # #2889: the word may print an `o`, `one` may be its NAME, and `P` the string then
                                    ("sh -c$(true) one -c 'P'", ["one", "P"]), ("sh -c$(true) ./one -c 'P'", ["./one"]),
                                    ("sh +$(echo x) w.sh +c 'P'", ["w.sh", "P"]), ("sh -$(echo x) w.sh -- -c 'P'", ["w.sh"])):
                    with self.subTest(digit=digit, text=text):
                        self.assertEqual(found, ws._after_dash_c(argv(text)))
                self.assertEqual([], ws._after_dash_c(argv("sh +$(echo x) w.sh +c 'P'"), False))   # `main`'s sign alone


class TestAFetchersOptionWordThatHoldsASubstitution(unittest.TestCase):
    """#3023: `curl -fsSL$(true) URL | sh`. CLEAN on `main` under every marker: its `h` was `curl -h`."""

    def test_lifted_text_among_the_letters_leaves_the_transfer_unread(self):
        # Truth: runs, every one.
        for fetch in ("curl -fsSL$(true)", "curl -$(echo f)sSL", "curl -f$(true)sSL", "curl -$(echo fsSL)",
                      "curl -`echo fsSL`", 'curl "-fsSL$(true)"', "curl -fsS$(echo L)", "curl -s$(true) -L",
                      "curl -sL -$(echo f)", "wget -q$(true)O-", "wget -$(echo q)O-", "wget -$(echo qO-)"):
            for use in ("%s %s | sh\n", "%s %s | bash -s\n"):
                with self.subTest(fetch=fetch, use=use[6:]):
                    text = use % (fetch, URL)
                    self.assertEqual({BOTH}, under(text))
                    for digit in "0c":
                        self.assertTrue(any(UNREAD in why for why in sentences(text, digit)), sentences(text, digit))

    def test_a_fetch_to_a_file_that_then_runs(self):
        # Truth: runs, every one.
        for fetch in ("curl -fsSL$(true)o tool", "curl -$(echo f)sSLo tool", "curl -fsSL -$(echo o) tool",
                      "curl -fsS$(echo L)o tool"):
            for use in ("chmod +x tool; ./tool", "sh tool"):
                with self.subTest(fetch=fetch, use=use):
                    self.assertEqual({BOTH}, under("%s https://example.test/tool\n%s\n" % (fetch, use)))

    def test_lifted_text_in_an_options_value_is_a_value_as_it_was(self):
        # The same sentences as on `main`: a destination or a count a substitution prints is no option letter.
        for text, sentence in (
                ('curl -fsSL -o "$(mktemp)" https://example.test/tool\n', "unknown destination"),
                ('curl -fsSLo"$(pwd)/tool" https://example.test/tool\n./tool\n', "unknown destination"),
                ("curl --output=$(mktemp) -fsSL https://example.test/tool\n", "unknown destination"),
                ('wget -qO"$(pwd)/tool" https://example.test/tool\nsh tool\n', "unknown destination"),
                ("curl -fsSL --retry $(echo 3) %s | sh\n" % URL, "straight to `sh`"),
                ('curl -fsSL -H "X: $(date)" %s | sh\n' % URL, "straight to `sh`"),
                ("curl -fsSL --retry=$(echo 3) %s | sh\n" % URL, "straight to `sh`"),
                ("curl -fsSL https://example.test/$(echo i.sh) | sh\n", "straight to `sh`")):
            with self.subTest(text=text[:36]):
                self.assertEqual({BOTH}, under(text))
                for digit in "0c":
                    self.assertTrue(any(sentence in why for why in sentences(text, digit)), sentences(text, digit))

    def test_lifted_text_in_a_long_options_name(self):
        # Truth: runs, both. curl's read so on `main`; wget's read as a stream there and is unread now.
        for text in ("curl --$(echo silent) -fL %s | sh\n" % URL, "wget --$(echo quiet) -O- %s | sh\n" % URL):
            with self.subTest(text=text[:24]):
                self.assertEqual({BOTH}, under(text))
                self.assertTrue(any(UNREAD in why for why in sentences(text, "0")))

    def test_the_price_is_the_variable_twins(self):
        # Nothing runs what these fetch. The reader cannot say what the transfer is and says so, as it says of a
        # `$X` among the letters on `main`. Truth: fetched and not run, every one.
        for lifted, twin in (("curl -s$(true) %s\n", "curl -s$X %s\n"), ("curl -fsS$(true) %s | jq .\n", "curl -fsS$X %s | jq .\n"),
                             ("curl -fsSL$(true) -o out.json %s\n", "curl -fsSL$X -o out.json %s\n"),
                             ("wget -q$(true) %s\n", "wget -q$X %s\n")):
            with self.subTest(lifted=lifted[:20]):
                self.assertEqual({BOTH}, under(lifted % URL))
                self.assertEqual({BOTH}, under(twin % URL))
                self.assertTrue(any(UNREAD in why for why in sentences(lifted % URL, "0")))
        # In a VALUE it is a value, CLEAN as on `main`; and a shell's word that may spell `-c` in front of a string
        # that fetches nothing is CLEAN too. Truth: nothing fetched but by the two `curl`s, nothing run.
        for text in ('curl -fsS -H "Authorization: Bearer $(cat token)" %s\n' % URL, 'curl -sX POST -d"$(cat body.json)" %s\n' % URL,
                     "sh -$(echo c) 'echo hi'\n", "bash -$(echo e)x build.sh\n"):
            with self.subTest(text=text[:24]):
                self.assertEqual({CLEAN}, under(text))

    def test_a_written_h_is_curls_help_still(self):
        # curl 8.5.0 prints its help for `-hsSL URL` and fetches nothing: run by hand on the forge, because the
        # runner's stub fetcher knows no options and hands its program over whatever it is given.
        self.assertEqual({CLEAN}, under("curl -hsSL %s | sh\n" % URL))


class TestAMarkerInATextReadAgain(unittest.TestCase):
    """A text the guard reads again -- a printer's words piped to a shell, a candidate behind a `$X` option, what a
    `$(echo ...)` prints, a `<(echo ...)` FILE -- holds the first parse's marker, and the parse of that text hands
    back plain words that carry none (`workflow_forms._weighed` keeps a lifted `$(...)` opaque, #2482). On `main`
    each row here reads as the flat rows did: a shell's by the marker's hex, a fetcher's CLEAN under every marker."""

    SHELLS = ("sh -$(echo c) {P}", "sh +$(echo c) {P}", "bash -e$(echo c) {P}", "sh -`echo c` {P}")
    FETCHES = ("curl -fsSL$(true) {U} | sh", "curl -$(echo f)sSL {U} | sh", "wget -$(echo q)O- {U} | sh")
    FRAMES = ('echo "{T}" | sh\n', 'echo "{T}" | bash -s\n', 'echo "{T}" | tee log | sh\n', 'printf "{T}\\n" | sh\n',
              'X=-c\nsh $X "{T}"\n', 'v=$(echo "{T}" | sh)\n', 'bash <(echo "{T}")\n')
    WALKED = ("printf '%s\\n' \"{T}\" | sh\n", 'sh -c "$(echo "{T}")"\n', 'eval "$(echo "{T}")"\n')

    @staticmethod
    def row(frame, inner):
        return frame.replace("{T}", inner.replace("{P}", P).replace("{U}", URL))

    def test_a_shells_word(self):
        # Truth: runs, every one -- the `<(...)` FILE under the bash parents, which alone read one.
        for frame in self.FRAMES:
            for inner in self.SHELLS:
                with self.subTest(frame=frame[:16], inner=inner[:16]):
                    self.assertEqual({BOTH}, under(self.row(frame, inner)))

    def test_a_fetchers_word(self):
        # #3023 the same way. Truth: runs, every one.
        for frame in self.FRAMES:
            for inner in self.FETCHES:
                with self.subTest(frame=frame[:16], inner=inner[:20]):
                    self.assertEqual({BOTH}, under(self.row(frame, inner)))

    def test_where_the_second_walk_alone_weighs_the_text(self):
        # `printf '%s\n' "..."` and what a `$(echo "...")` prints: the main pass weighs neither where a word of it
        # is lifted, under any marker (#2955 gave them to the second walk). Truth: runs, every one.
        for frame in self.WALKED:
            for inner in self.SHELLS + self.FETCHES:
                with self.subTest(frame=frame[:16], inner=inner[:20]):
                    self.assertEqual({WALK}, under(self.row(frame, inner)))

    def test_a_letter_no_printer_spells_is_reported_too(self):
        # The flat rows' price: the word MAY spell `-c`. `echo "sh -$(echo x) 'P'" | sh` prints `sh -x 'P'`, and `P`
        # is a FILE's name. Truth: nothing, every one. Reported on `main` under a marker with a `c`.
        for inner in ("sh -$(echo x) {P}", "sh -$(true) {P}", "bash -$(echo s) {P}"):
            with self.subTest(inner=inner):
                self.assertEqual({BOTH}, under(self.row('echo "{T}" | sh\n', inner)))
        # A `-c` or `eval` string never came this way: `rendered` writes what a printer spells, and the parse of
        # THAT lifts the rest anew (#2683). `-$(echo x)` is `-x` there; `-$(true)` no printer spells. Truth: nothing.
        self.assertEqual({CLEAN}, under(self.row('sh -c "{T}"\n', "sh -$(echo x) {P}")))
        self.assertEqual({BOTH}, under(self.row('sh -c "{T}"\n', "sh -$(true) {P}")))

    def test_where_no_reader_follows_the_text_the_word_reads_as_its_written_twin(self):
        # A group as the printer, a program a variable holds, a file the step writes and runs: whatever the guard
        # makes of these, it makes the same of the letter lifted and of the letter written.
        for frame in ('{ echo "{T}"; } | sh\n', 'S="{T}"\nsh -c "$S"\n', 'echo "{T}" > run.sh\nsh run.sh\n'):
            for lifted, written in (("sh -$(echo c) {P}", "sh -c {P}"), ("curl -fsSL$(true) {U} | sh", "curl -fsSL {U} | sh")):
                with self.subTest(frame=frame[:16], inner=lifted[:16]):
                    self.assertEqual(under(self.row(frame, written)), under(self.row(frame, lifted)))

    def test_the_readers_one_by_one_on_a_plain_word(self):
        for digit in "0c":
            with nonce(digit):
                key = shell_tokens._Parse("").new("subst")
                word, fetch = "-" + key, "-fsSL" + key
                with self.subTest(digit=digit):
                    self.assertIs(str, type(word))
                    self.assertEqual(["P"], ws._after_dash_c(["sh", word, "P"]))
                    self.assertEqual(["P"], wo._dash_c_strings(["sh", word, "P"]))
                    self.assertEqual(("$CMD", ["P"]), ws._candidates(["$CMD", word, "P"]))
                    self.assertTrue(wo._dash_s(["dash", word, "true"], 1))
                    self.assertEqual(("PROGRAM", None), wo._stdin_walk(["$CMD", word, "x"], "PROGRAM", None, False, True))
                    self.assertIsNotNone(wp._options(["sh", word, "true"], 0)[0])
                    self.assertEqual((workflow_fetch.Fetch("curl", None, None, None), False),
                                     workflow_fetch._parse_fetch("curl", [fetch, URL], None, None))


class TestTheReadingDoesNotDependOnTheMarker(unittest.TestCase):

    ROWS = (("sh -$(echo c) %s\n" % P, BOTH), ("sh +$(echo x) %s\n" % P, BOTH), ("${X:-sh -$(echo c)} %s\n" % P, BOTH),
            ("sh -$(echo x) <<'EOF'\n%s\nEOF\n" % PIPE, BOTH), ("curl -fsSL$(true) %s | sh\n" % URL, BOTH),
            ("wget -q$(true)O- %s | sh\n" % URL, BOTH), ("%ssh -e$(echo c) '%s; %s'\n" % (GET, CHECK, USE), WALK),
            ('echo "sh -$(echo c) %s" | sh\n' % P, BOTH), ('echo "curl -fsSL$(true) %s | sh" | sh\n' % URL, BOTH),
            ('X=-c\nsh $X "sh +$(echo c) %s"\n' % P, BOTH), ("printf '%%s\\n' \"sh -$(echo c) %s\" | sh\n" % P, WALK))

    def test_under_a_marker_of_every_hex_digit(self):
        for row, reading in self.ROWS:
            with self.subTest(row=row[:28]):
                self.assertEqual({reading}, under(row, "0123456789abcdef"))

    def test_under_the_markers_a_process_draws(self):
        # No pin: eighty calls of the guard a row, every parse with a marker of its own. The pinned tests are the
        # pin -- on `main` a process whose own sixteen digits hold a `c` reads every row here one way.
        for row, reading in self.ROWS:
            with self.subTest(row=row[:28]):
                self.assertEqual({reading}, {marks(row) for _ in range(8)})

    WORDS = ("-c", "-x", "-o", "errexit", "+c", "--", "-$(echo c)", "-e$(true)", "+$(echo x)", '"-$(echo s)"', "-c$(true)",
             "$(echo -c)", "$Y", "'P'", "w.sh")

    def test_no_finder_or_walk_asks_the_marker_over_every_run_of_up_to_three_words(self):
        # Every run of one to three words of fifteen, behind `sh` and behind `$CMD`: what each finder, each walk for
        # a value and each walk for stdin answers is the same under a marker without a letter and one with a `c`.
        def answers(text):
            words_ = argv(text)
            shell = not text.startswith("$")
            value, found = ws._candidates(words_)
            more, added = wo._shell_candidates(words_) if shell else (None, [])
            walked = wo._stdin_walk(words_, "PROGRAM", words_, shell, not shell)
            return ([str(word) == "P" for word in ws._after_dash_c(words_)], [words_.index(word) for word in wo._dash_c_strings(words_)],
                    value is not None, len(found), more is not None, len(added), walked[0], walked[1] is words_, walked[1] == (),
                    wp._options(words_, 0)[0])
        runs = [()]
        for _ in range(3):
            runs += [run + (word,) for run in runs if len(run) == max(map(len, runs)) for word in self.WORDS]
        texts = ["%s %s" % (name, " ".join(run)) for name in ("sh", "$CMD") for run in runs if run]
        self.assertEqual(2 * (15 + 15 ** 2 + 15 ** 3), len(texts))
        found = []
        for digit in "0c":
            with nonce(digit):
                found.append([answers(text) for text in texts])
        differ = [text for text, zero, cee in zip(texts, *found) if zero != cee]
        self.assertEqual([], differ[:5])

    def test_the_finders_find_the_string_under_either_marker(self):
        for digit in "0c":
            with nonce(digit):
                for text in ("bash -e$(true) 'P'", "sh +`echo c` 'P'"):
                    with self.subTest(digit=digit, text=text):
                        words_ = argv(text)
                        self.assertEqual(["P"], ws._after_dash_c(words_))
                        self.assertEqual(["P"], wo._dash_c_strings(words_))
                # #2889: a word shaped as a NAME may be the value the word owes, and the word after it the string
                # then. (`P` stands for a program here and is such a word; a program's text never is.)
                self.assertEqual(["P", "x"], ws._after_dash_c(argv("sh -$(echo c) 'P' x")))
                self.assertEqual(["P", "x"], wo._dash_c_strings(argv("sh -$(echo c) 'P' x")))
                self.assertEqual(("$CMD", ["P"]), ws._candidates(argv("$CMD -$(echo c) 'P'")))
                self.assertEqual([], ws._after_dash_c(argv("sh -x 'P'")))
                self.assertEqual([], ws._after_dash_c(argv("sh ++$(echo c) 'P'")))


class TestEachReaderAsksTheWord(unittest.TestCase):
    """The readers one by one, each with one answer under a marker without a letter and under one with a `c` --
    and, for a word built by hand, under a marker that is no hex at all."""

    def both(self, ask):
        found = []
        for digit in "0c":
            with nonce(digit):
                found.append(ask())
        self.assertEqual(found[0], found[1])
        return found[0]

    def test_the_candidates_of_a_value_behind_the_word(self):
        # The word may be the `-c` cluster and may be none: `main`'s walk for a value goes on past it, as past
        # `-x`, and the `$X` behind it names its candidate. A `c` that is WRITTEN ends the walk, lifted text or not.
        self.assertEqual(("$X", ["P"]), self.both(lambda: ws._candidates(argv("sh -$(echo c) $X 'P'"))))
        self.assertEqual((None, []), self.both(lambda: ws._candidates(argv("sh -c$(true) $X 'P'"))))
        # The second walk's reads on past `--` too, where a `$X` may vanish and leave `P` the string (#2858).
        for digit in "0c":
            with nonce(digit):
                value, found = wo._shell_candidates(argv("sh -$(echo c) -- $X 'P'"))
                self.assertEqual(("$X", ["P"]), (str(value), [str(word) for word in found]))
        # Truth: runs, all sixteen, with `X` unset. The second walk alone weighs the word after the `$X`.
        self.assertEqual({WALK}, under("X=\nsh -$(echo c) -- $X %s\n" % P))

    def test_the_stdin_walks(self):
        for text, shell in (("sh -$(echo x) true", True), ("sh -$(echo x)", True), ("sh -$(echo s) -c true", True),
                            ("$CMD -$(echo s) x", False), ("$CMD -$(echo x)", False)):
            with self.subTest(text=text):
                def walked():
                    words_ = argv(text)
                    answer, reader = wo._stdin_walk(words_, "PROGRAM", words_ if shell else None, shell, not shell)
                    mains, mains_reader = wp._options(words_, 0)
                    return answer, reader is words_, reader == (), mains, mains_reader is words_
                answer, _own, _step, mains, _mains_own = self.both(walked)
                self.assertEqual("PROGRAM", answer)                 # stdin stays the program in the walk ...
                self.assertIsNotNone(mains)                         # ... and in `main`'s
        # A `$` word with a word after the one that may spell `-s`: the body is its program. Truth: runs.
        self.assertEqual({BOTH}, under("CMD=$(command -v sh)\n$CMD -$(echo s) x <<'EOF'\n%s\nEOF\n" % PIPE))

    def test_a_marker_that_is_no_hex(self):
        # A word built by hand around a marker of two texts: one with no letter, one that spells `c`, `s`, `h`.
        for key in ("@@1-2@@", "@@cshx@@"):
            word = shell_tokens._Token("-" + key, {key: ("subst", None)})
            with self.subTest(key=key):
                self.assertEqual("-", words.written(word))
                self.assertEqual(["P"], ws._after_dash_c(["sh", word, "P"]))
                self.assertEqual(["P"], wo._dash_c_strings(["sh", word, "P"]))
                self.assertEqual(("$CMD", ["P"]), ws._candidates(["$CMD", word, "P"]))
                self.assertTrue(wo._dash_s(["dash", word, "true"], 1))
                self.assertEqual(("PROGRAM", None), wo._stdin_walk(["$CMD", word, "x"], "PROGRAM", None, False, True))
                self.assertIsNotNone(wp._options(["sh", word, "true"], 0)[0])
                fetch = shell_tokens._Token("-fsSL" + key, {key: ("subst", None)})
                self.assertEqual((workflow_fetch.Fetch("curl", None, None, None), False),
                                 workflow_fetch._parse_fetch("curl", [fetch, URL], None, None))


class TestTheLeaf(unittest.TestCase):
    """`workflow_option_words`: what a word spells, asked of the word."""

    def test_written_is_the_word_without_its_markers(self):
        for digit in "0c":
            with nonce(digit):
                for text, plain in (("sh -e$(echo c)x", "-ex"), ("sh -`echo c`", "-"), ('sh "-fsSL$(true)"', "-fsSL"),
                                    ("sh -c", "-c"), ("sh -$X", "-"), ("sh -<(echo c)", "-")):    # a reference: #2889
                    with self.subTest(digit=digit, text=text):
                        word = argv(text)[1]
                        self.assertEqual(plain, words.written(word))
                        self.assertEqual(plain != str(word), words.lifted(word))
        self.assertEqual("-c", words.written("-c"))
        self.assertFalse(words.lifted("-c"))

    def test_lifted_says_where(self):
        with nonce("c"):
            word = argv("curl -fsSL$(true)o")[1]
            at = len("-fsSL")
            self.assertEqual([at], [k for k in range(len(word)) if words.lifted(word, k, k + 1)])
            self.assertTrue(words.lifted(word, 0, at + 1))
            self.assertFalse(words.lifted(word, 0, at))
            self.assertFalse(words.lifted(word, at + 1))

    def test_spells(self):
        for digit in "0c":
            with nonce(digit):
                word = argv("sh -e$(echo c)")[1]
                self.assertEqual([True, True, True], [words.spells(word, letter) for letter in "ecs"])
        self.assertEqual([True, False, False], [words.spells("-e", letter) for letter in "ecs"])
        self.assertEqual([True, True], [words.spells("-$X", letter) for letter in "cs"])       # a variable may: #2889
        self.assertEqual([False, False], [words.spells("-$#", letter) for letter in "cs"])     # a count prints digits

    def test_a_marker_in_a_plain_word_is_known_by_its_shape_and_this_processs_nonce(self):
        for digit in "0c":
            with nonce(digit):
                key = shell_tokens._Parse("").new("subst")          # as a parse mints one: `_MARK` and `_NONCE` hold
                plain = "-fs" + key + "L"
                with self.subTest(digit=digit):
                    self.assertIs(str, type(plain))
                    self.assertEqual("-fsL", words.written(plain))
                    self.assertEqual([3], [k for k in range(len(plain)) if words.lifted(plain, k, k + 1)])
                    self.assertEqual([True, True], [words.spells(plain, letter) for letter in "cz"])
                    # One of another process, or one the target wrote in the shape, is the target's text: its
                    # letters are letters, and nothing in it is lifted.
                    for look in ("-fs@@shell-%s-0@@L" % ("ab" * 24), "-fs" + key[:-2] + "L", "-fs" + key[2:] + "L"):
                        self.assertEqual(look, words.written(look))
                        self.assertFalse(words.lifted(look))
                        self.assertEqual([True, False], [words.spells(look, letter) for letter in "sz"])

    def test_a_key_that_stands_twice_and_one_of_no_markers_shape(self):
        word = shell_tokens._Token("-KEYxKEY", {"KEY": ("subst", None)})    # the word's own, whatever its shape
        self.assertEqual("-x", words.written(word))
        self.assertEqual([1, 5], [k for k in range(len(word)) if words.lifted(word, k, k + 1)])
        self.assertEqual([False, True, True], [words.lifted(word, 0, 1), words.lifted(word, 2), words.lifted(word, 5)])
        self.assertFalse(words.lifted(word, 6))

    def test_it_is_below_the_readers_and_the_four_ask_it(self):
        with open(words.__file__, encoding="utf-8") as source:
            tree = ast.parse(source.read())
        # It reads `shell_tokens` for a marker's shape and this process's nonce, and nothing that asks it: no
        # module it reaches is one of the workflow's.
        self.assertEqual(["import shell_tokens"], [ast.unparse(node) for node in ast.walk(tree)
                                                   if isinstance(node, (ast.Import, ast.ImportFrom))])
        reached, queue = set(), ["shell_tokens"]
        while queue:
            name = queue.pop()
            path = os.path.join(os.path.dirname(words.__file__), name + ".py")
            if name in reached or not os.path.exists(path):
                continue
            reached.add(name)
            with open(path, encoding="utf-8") as source:
                for node in ast.walk(ast.parse(source.read())):
                    if isinstance(node, ast.Import):
                        queue += [alias.name for alias in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        queue.append(node.module)
        self.assertIn("shell_tokens", reached)
        self.assertEqual([], sorted(name for name in reached if name.startswith("workflow")))
        self.assertEqual(["_references", "_spans", "before", "written", "lifted", "spells"],       # two of #2889's
                         [node.name for node in tree.body if isinstance(node, ast.FunctionDef)])
        for module, names in ((wo, {"before", "lifted", "spells", "written"}), (ws, {"lifted", "spells", "written"}),
                              (wp, {"lifted", "written"}), (workflow_fetch, {"lifted"}), (workflow_option_slots, {"lifted", "written"})):
            with open(module.__file__, encoding="utf-8") as source:
                imported = {alias.name for node in ast.walk(ast.parse(source.read())) if isinstance(node, ast.ImportFrom)
                            and node.module == "workflow_option_words" for alias in node.names}
            with self.subTest(module=module.__name__):
                self.assertEqual(names, imported)
                for name in names:
                    self.assertIs(getattr(words, name), getattr(module, name))


class TestWhatStaysForOtherIssues(unittest.TestCase):
    """Rows this fix does not move, each pinned as it reads."""

    def test_an_arithmetic_stays_text(self):
        # `$((1))` prints a number, and no digit is an option's letter. (A letter a VARIABLE makes was pinned
        # beside this as #2889's, CLEAN: it is reported since, `tests/test_workflow_option_expansions.py`.)
        self.assertEqual({CLEAN}, under("sh -$((1)) %s\n" % P))

    def test_a_value_that_is_written(self):
        # Where the `o` or the `-c` is written, the string is found -- a `-c` after the word the lifted one takes
        # for its string too, since the search reads on past a word that only may print the `c`. Truth: runs, both.
        # (The value a word may OWE for an `o` it only prints was pinned beside these as #2889's, CLEAN: reported since.)
        self.assertEqual({BOTH}, under("sh -o$(echo c) errexit %s\n" % P))
        self.assertEqual({BOTH}, under("sh -$(echo o) errexit -c %s\n" % P))

    def test_the_first_pass_alone_holds_one_reading_of_stdin(self):
        # The first pass returns ONE answer for stdin. `main`'s took the body for data under a marker with a `c` and
        # named the substitution the `-c` program; this one keeps stdin the program, as `main`'s did under a marker
        # without, and counts the check in it. The JOB reports under every marker: the second walk counts no check
        # behind a word that may expand. Truth: the check stops the step; with `-$(echo x)` for `-e$(true)` it runs.
        for word in ("-e$(true)", "-$(echo x)"):
            with self.subTest(word=word):
                self.assertEqual({WALK}, under("%ssh %s $(true) -- <<'EOF'\n%s\n%s\nEOF\n" % (GET, word, CHECK, USE)))
        # The other way round: under a marker without a `c` `main`'s first pass found no string and said the download
        # runs under `sh`; this one reads the string, and the job says the check inside it does not count. Truth:
        # fetched, nothing run.
        self.assertEqual({WALK}, under("%sxargs sh -e$(true) '%s; %s' tool\n" % (GET, CHECK, USE)))

    def test_the_other_readers_that_ask_a_marker_for_letters(self):
        # `workflow_posture._errexit`, `workflow_printers.file_operand` and `workflow_annotate` still read a
        # marker's text; no row here gets a wrong JOB verdict through them. The one trace: the main pass alone
        # counts this check (`test_a_check_in_the_string_is_not_counted`), and reads the step CLEAN under every
        # marker where the job reports it.
        self.assertEqual({WALK}, under("%ssh -$(echo c) '%s; %s'\n" % (GET, CHECK, USE)))


if __name__ == "__main__":
    unittest.main()
