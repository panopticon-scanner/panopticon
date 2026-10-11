"""#3019: a shell handed its `c` in a `+` cluster runs the string, and the reader now reads it.

`sh +c 'curl ... | sh'` and `bash +xc '...'` run the string in bash, dash, zsh, ksh and busybox's ash alike: a `+`
turns an option OFF, and `c` is none to turn. The three finders of a `-c` cluster asked for a leading `-`
(`workflow_program_strings._after_dash_c` and `_candidates`, `workflow_options._dash_c_operand`), so no pass read
the string and the step was CLEAN under every `shell:` setting. Each now takes the sign as it takes the `-`: one
`+`, not two, and a `c` anywhere after it. The first two are `main`'s own finders, so the main pass reads the
string too, and a check inside it counts where a check in a `-c` string does.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports,
C where it reads the step CLEAN: first the job's, then the main pass's. `{S}` in a row is the sign of the cluster
under test, and `signs` reads the row twice, written `+` and written `-`: the two read alike everywhere but
where the sign turns a letter round.

Truth, in the comments, is what eight parent shells do with the step in two passes on the forge: bash 5.2.21 and
bash 3.2.57 under `-e` and under `-eo pipefail`, dash under `-e`, then each without `-e`; pass 2 gives each parent
a child shell of its own family. "runs" is all sixteen ran the download, "nothing" is none did.

The price, pinned in `TestThePrice`. The sign is read as the `-` is, so a `+` word the shell REFUSES is
reported as its `-` twin is on `main`: `+-c` and `+c+x` as `-+c` and `-c+x`, a digit as in `+c7` (which zsh runs),
a cluster after a word the shell refuses or among a FILE's parameters. And one report is lost, rightly: `bash
+norc -c P` ran nothing on `main` either -- the `o` of `+norc` takes `-c` as its name.

Left for other issues, pinned in `TestWhatStaysForOtherIssues` as they read: a `$` command word whose cluster is
not its first word (#2671), a cluster's letter made by an expansion (#2889), zsh's `O`, which takes no value,
`builtin command sh`, `busybox sh`, and a string that is a value, which this guard follows nowhere.
"""
import unittest

import shell_reader
import workflow_guard as wg
import workflow_options as wo
import workflow_program_strings as ws

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
PIPE = "curl -fsSL https://example.test/i.sh | sh"
P = "'%s'" % PIPE
GET = "curl -fsSLo tool https://example.test/tool\n"
CHECK = 'echo "%s  tool" | sha256sum -c -' % ("0" * 64)
USE = "chmod +x tool; ./tool"
BOTH = ("RRRRR", "RRRRR")           # the job reports, and so does the main pass
WALK = ("RRRRR", "CCCCC")           # the second walk's finder alone reads it
CLEAN = ("CCCCC", "CCCCC")
HELD = ("CCCRR", "CCCRR")           # a check that stops the step under `-e`: reported where a step starts without it


def marks(text):
    """(the job's marks, the main pass's) for a job of one step whose `run:` is `text`."""
    job = mains = ""
    for shell in SHELLS:
        step = [wg.Step("step", text, shell)]
        job += "R" if wg.job_defects(step) else "C"
        with wo.mains_answer():
            mains += "R" if wg._job_defects(step) else "C"
    return job, mains


def signs(row):
    """`marks` of the row with its cluster written `+`, then written `-`."""
    return marks(row.replace("{S}", "+")), marks(row.replace("{S}", "-"))


def argv(text):
    return shell_reader.statements(text)[-1].stages[0].argv


class TestAPlusClusterIsRead(unittest.TestCase):
    """The issue's rows: CLEAN on `main` under all five settings while every parent runs the string."""

    def test_each_spelling_of_the_cluster(self):
        # Truth: runs, every one, written `+` or `-`.
        for shell in ("sh", "bash", "dash"):
            for words in ("{S}c", "{S}xc", "{S}ec", "{S}cx", "-e {S}c", "+x {S}c", "{S}c -e", "{S}c +x", "{S}c --",
                          "{S}c -", "-s {S}c", "-l {S}c", "-i {S}c"):
                with self.subTest(shell=shell, words=words):
                    self.assertEqual((BOTH, BOTH), signs("%s %s %s\n" % (shell, words, P)))

    def test_bashs_own_words_beside_it(self):
        # Truth: runs, every one, written `+` or `-`.
        for words in ("--norc {S}c", "--rcfile /dev/null {S}c", "-O extglob {S}c", "+O extglob {S}c",
                      "{S}c -O extglob", "{S}co pipefail", "{S}oc pipefail", "+o pipefail {S}c", "{S}lc", "{S}ic",
                      "{S}rc", "--posix {S}c"):
            with self.subTest(words=words):
                self.assertEqual((BOTH, BOTH), signs("bash %s %s\n" % (words, P)))

    def test_by_a_path_and_behind_a_wrapper(self):
        # Truth: runs, every one, written `+` or `-`.
        for front in ("/bin/sh", "/usr/bin/bash", "env sh", "sudo bash", "command sh", "exec sh", "sudo -E env sh",
                      "timeout 30 sh", "nohup sh", "nice sh", "env A=1 sh", "echo x | xargs sh",
                      "find . -maxdepth 0 -exec sh"):
            with self.subTest(front=front):
                end = " ';'" if front.startswith("find") else ""
                self.assertEqual((BOTH, BOTH), signs("%s {S}c %s%s\n" % (front, P, end)))

    def test_the_other_shell_names(self):
        # zsh runs it, written `+` or `-` (truth: runs, both). The forge has no `ksh` and no `ash`, so those two
        # rows are the reader's alone; ksh 93u+ and busybox's ash take `+c` for `-c` in a run by hand.
        for shell in ("zsh", "/usr/bin/zsh", "ksh", "ash"):
            for cluster in ("{S}c", "{S}xc"):
                with self.subTest(shell=shell, cluster=cluster):
                    self.assertEqual((BOTH, BOTH), signs("%s %s %s\n" % (shell, cluster, P)))

    def test_in_every_statement(self):
        # Truth: runs, every one, written `+` or `-`.
        shell = "sh {S}c %s" % P
        for frame in ("%s || true", "true && %s", "if %s; then echo ok; fi", "! %s", "%s &\nwait", "( %s )",
                      "{ %s; }", "%s | cat", "true | %s", "x=$(%s)", "f() { %s; }\nf", "while %s; do break; done",
                      "for i in 1; do %s; done", "case x in x) %s ;; esac", "%s > /dev/null 2>&1", "A=1 %s"):
            with self.subTest(frame=frame):
                self.assertEqual((BOTH, BOTH), signs(frame % shell + "\n"))

    def test_inside_a_string_and_a_body(self):
        # Truth: runs, every one, written `+` or `-`.
        shell = "sh {S}c %s" % P
        for holder in ('sh -c "%s"\n', 'bash -c "%s"\n', 'eval "%s"\n', 'sh +c "%s"\n',
                       "bash <<'EOF'\n%s\nEOF\n", "sh -s <<'EOF'\n%s\nEOF\n"):
            with self.subTest(holder=holder[:12]):
                self.assertEqual((BOTH, BOTH), signs(holder % shell))


class TestTheStringIsReadAsADashCStringIs(unittest.TestCase):

    def test_what_stands_after_the_string_is_a_parameter(self):
        self.assertEqual((BOTH, BOTH), signs("sh {S}c %s x y\n" % P))                  # truth: runs
        self.assertEqual((CLEAN, CLEAN), signs("sh {S}c 'echo one' %s\n" % P))         # truth: nothing; `$0`
        self.assertEqual((BOTH, BOTH), signs("sh {S}c %s {S}c 'echo second'\n" % P))   # truth: runs

    def test_a_heredoc_or_a_here_string_the_strings_shell_inherits(self):
        # `sh +c 'sh' <<EOF`: the stdin walk read a `+` cluster's letters already and credited the heredoc to no
        # one. Truth: runs, every one, written `+` or `-`; the here-string under bash alone.
        for shell in ("sh", "bash", "dash"):
            for inner in ("sh", "bash -s"):
                with self.subTest(shell=shell, inner=inner):
                    self.assertEqual((BOTH, BOTH), signs("%s {S}c '%s' <<'EOF'\n%s\nEOF\n" % (shell, inner, PIPE)))
            with self.subTest(shell=shell, inner="a here-string"):
                self.assertEqual((BOTH, BOTH), signs("%s {S}c 'sh' <<< %s\n" % (shell, P)))

    def test_a_heredoc_is_no_program_where_the_string_takes_none(self):
        # The string is the shell's program, so a heredoc it does not read is data. Truth: nothing, every one.
        for shell in ("sh", "bash", "dash"):
            for string in ("true", "'cat'"):
                with self.subTest(shell=shell, string=string):
                    self.assertEqual((CLEAN, CLEAN), signs("%s {S}c %s <<'EOF'\n%s\nEOF\n" % (shell, string, PIPE)))

    def test_a_fetched_file_the_string_runs(self):
        # Truth: runs, every one, written `+` or `-`.
        for shell in ("sh", "bash", "dash"):
            for string in ("'. ./tool'", "'sh tool'", "'sh \"$0\"' tool"):
                with self.subTest(shell=shell, string=string):
                    self.assertEqual((BOTH, BOTH), signs("%s%s {S}c %s\n" % (GET, shell, string)))

    def test_a_check_in_the_string_counts_where_one_in_a_dash_c_string_does(self):
        # The check fails and the string's shell exits, so a step under `-e` stops there. Truth: the check runs
        # and nothing else under the five `-e` parents; the download runs under the three without it.
        for shell in ("sh", "bash", "dash"):
            with self.subTest(shell=shell):
                self.assertEqual((HELD, HELD), signs("%s%s {S}c '%s'\n%s\n" % (GET, shell, CHECK, USE)))
            # The same where the string holds a `$` of its own: the option run ends AT the string, so the `$` in
            # it is no word that may expand among the options (`_run`), and the shell is still sure to run it.
            with self.subTest(shell=shell, string="holds a $"):
                self.assertEqual((HELD, HELD),
                                 signs("%s%s {S}c 'echo \"$HOME\"; %s'\n%s\n" % (GET, shell, CHECK, USE)))


class TestTheSignIsReadWhereItTurnsALetterRound(unittest.TestCase):
    """`+e` and `+n` turn the option OFF, and the readers of a shell's posture read them so before this fix: the
    string of a `+` cluster is read under the posture its own letters leave."""

    def test_errexit_in_the_string(self):
        for shell in ("sh", "bash", "dash"):
            for off in ("+ec", "+ce", "+e +c", "+c +e", "+e -c", "-c +e", "+co errexit", "+c +o errexit"):
                with self.subTest(shell=shell, words=off):      # truth: runs, every one: no `-e` in the string
                    self.assertEqual(BOTH, marks("%s%s %s '%s; %s'\n" % (GET, shell, off, CHECK, USE)))
            for on in ("-ec", "-e +c", "+c -e", "+c -o errexit", "-o errexit +c"):
                with self.subTest(shell=shell, words=on):       # truth: the check runs and nothing after it
                    self.assertEqual(CLEAN, marks("%s%s %s '%s; %s'\n" % (GET, shell, on, CHECK, USE)))

    def test_noexec(self):
        for shell in ("sh", "bash", "dash"):
            for runs in ("+nc", "+cn", "+n +c", "+c +n", "-n +nc", "+co noexec", "+c +o noexec", "-n +n +c"):
                with self.subTest(shell=shell, words=runs):     # truth: runs, every one
                    self.assertEqual(BOTH, marks("%s %s %s\n" % (shell, runs, P)))
            for reads in ("-n +c", "+c -n", "+n -n +c", "+c -o noexec"):
                # `main` reads a string its shell only parses, and counts no check in it (#2858). Truth: nothing.
                with self.subTest(shell=shell, words=reads):
                    self.assertEqual((BOTH, BOTH), (marks("%s %s %s\n" % (shell, reads, P)),
                                                    marks("%s %s %s\n" % (shell, reads.replace("+c", "-c"), P))))
            # A check in the string: `+nc` runs it and the step stops there under `-e`; `-nc` runs none of the
            # string, so the download runs unchecked, and the second walk counts no check there (#2858) while the
            # main pass counts it as `main` did. Truth: the check and nothing after it under the five `-e`
            # parents for `+nc`; runs, all sixteen, for `-nc`.
            with self.subTest(shell=shell, words="a check under +nc and under -nc"):
                self.assertEqual((HELD, ("RRRRR", "CCCRR")), signs("%s%s {S}nc '%s'\n%s\n" % (GET, shell, CHECK, USE)))


class TestADollarCommandWord(unittest.TestCase):
    """`$CMD +c P`: a `$` command word handed a cluster may be a shell (#2337), whatever the cluster's sign."""

    def test_a_word_the_guard_does_not_follow(self):
        # Truth: runs, every one, written `+` or `-`.
        for words in ("$CMD {S}c", "$CMD {S}xc", '"$CMD" {S}c', "${CMD} {S}c", "$CMD {S}c -e"):
            with self.subTest(words=words):
                self.assertEqual((BOTH, BOTH), signs("CMD=$(command -v sh)\n%s %s\n" % (words, P)))

    def test_a_word_the_step_assigns_and_one_with_a_default(self):
        # Truth: runs, every one, written `+` or `-`.
        for row in ("CMD=sh\n$CMD {S}c %s\n", "CMD=sh\n$CMD {S}xc %s\n", 'CMD=bash\n"$CMD" {S}c %s\n',
                    "${CMD:-sh} {S}c %s\n", "${CMD:-bash} {S}xc %s\n", "$UNSET sh {S}c %s\n"):
            with self.subTest(row=row[:22]):
                self.assertEqual((BOTH, BOTH), signs(row % P))

    def test_the_candidate_is_the_word_after_the_options(self):
        for cluster in ("+c", "+xc", "+c$X", "+c7", "-c"):
            with self.subTest(cluster=cluster):
                words = argv("$CMD %s -e 'P' x" % cluster)
                self.assertEqual(("$CMD", ["P"]), ws._candidates(words))
        for no_cluster in ("++c", "+x", "+C", "--c"):
            with self.subTest(cluster=no_cluster):
                self.assertEqual((None, []), ws._candidates(argv("$CMD %s 'P'" % no_cluster)))


class TestAClusterAnExpansionOrAQuoteMakes(unittest.TestCase):
    """The sign is read as the `-` is: a `c` anywhere after it, whatever else the word holds."""

    def test_an_expansion_in_the_cluster(self):
        # Truth: runs, every one, written `+` or `-`; the two braces under the bash parents alone (dash expands
        # none and refuses the word).
        for row in ("X=\nsh {S}c$X %s\n", "X=x\nsh {S}c$X %s\n", "X=\nsh {S}${X}c %s\n", "X=e\nsh {S}${X}c %s\n",
                    "sh {S}c${X:-x} %s\n", "sh {S}c${X:+x} %s\n", "sh {S}{c,x} %s\n", "sh {S}c{x,e} %s\n"):
            with self.subTest(row=row[:18]):
                self.assertEqual((BOTH, BOTH), signs(row % P))

    def test_the_cluster_quoted(self):
        # Truth: runs, every one, written `+` or `-`; `$'...'` under the bash parents alone.
        for word in ("'{S}c'", '"{S}c"', chr(92) + "{S}c", "{S}'c'", '{S}x"c"', "$'{S}c'"):
            with self.subTest(word=word):
                self.assertEqual((BOTH, BOTH), signs("sh %s %s\n" % (word, P)))


class TestLettersThatSpellALongOptionsName(unittest.TestCase):
    """bash reads a long option's name with `-` alone. Behind a `+` its letters are a cluster."""

    def test_the_names_that_hold_a_c(self):
        self.assertEqual(BOTH, marks("bash +rcfile %s\n" % P))                 # truth: runs: `r`, `c`, `f`, ...
        self.assertEqual(BOTH, marks("bash +norc pipefail %s\n" % P))          # truth: runs: the `o` takes a name
        self.assertEqual(CLEAN, marks("bash +norc %s\n" % P))                  # truth: nothing: it takes the string
        self.assertEqual(CLEAN, marks("bash +rcfile /dev/null %s\n" % P))      # truth: nothing: `/dev/null` it is
        for name in ("protected", "restricted"):                               # truth: nothing: a `d` bash refuses
            with self.subTest(name=name):
                self.assertEqual(CLEAN, marks("bash +%s %s\n" % (name, P)))

    def test_the_names_that_hold_none(self):
        for name in ("login", "noprofile", "posix", "verbose", "version", "help", "debugger"):
            with self.subTest(name=name):                                      # truth: nothing
                self.assertEqual(CLEAN, marks("bash +%s %s\n" % (name, P)))


class TestTheSecondWalksFinder(unittest.TestCase):
    """`_dash_c_operand` reads a cluster `main`'s finder cannot reach: one after a one-dash long option's FILE,
    which `main` takes for the cluster itself (`-rcfile` holds a `c`) and the FILE for its string (#2858)."""

    def test_a_cluster_after_a_one_dash_long_options_file(self):
        # Truth: runs under bash, written `+` or `-`; under `sh`, where `sh` is bash.
        for words in ("-rcfile /dev/null {S}c", "-rcfile /dev/null {S}xc", "-rcfile /dev/null -e {S}c",
                      "-norc -rcfile /dev/null {S}c", "-rcfile -- {S}c"):
            for shell in ("bash", "sh"):
                with self.subTest(shell=shell, words=words):
                    self.assertEqual((WALK, WALK), signs("%s %s %s\n" % (shell, words, P)))
        # The same with the cluster an expansion completes. Truth: runs, written `+` or `-`.
        for cluster in ("{S}c$X", "{S}${X}c"):
            with self.subTest(cluster=cluster):
                self.assertEqual((WALK, WALK), signs("bash -rcfile /dev/null %s %s\n" % (cluster, P)))
        # `-init-file` holds no `c`, so `main`'s finder passes it and its FILE and finds the cluster itself.
        self.assertEqual((BOTH, BOTH), signs("bash -init-file /dev/null {S}c %s\n" % P))

    def test_the_operand_it_finds(self):
        for words, found in (("bash +c 'P' x", ["P"]), ("bash -rcfile f +xc -e 'P'", ["P"]), ("bash w.sh +c 'P'", ["P"]),
                             ("bash +co pipefail 'P'", ["P"]), ("bash +c -- 'P'", ["P"]), ("bash -c 'P'", ["P"]),
                             ("bash +c$X 'P'", ["P"]), ("bash +c7 'P'", ["P"]), ("bash +-c 'P'", ["P"]),
                             ("bash ++c 'P'", []), ("bash -- +c 'P'", []), ("bash +x 'P'", []), ("bash +C 'P'", []),
                             ("bash +cK 'P'", []), ("bash +co pipefial 'P'", [])):
            with self.subTest(words=words):
                self.assertEqual(found, wo._dash_c_operand(argv(words)))

    def test_mains_finder_finds_the_same_cluster(self):
        for words, found in (("bash +c 'P' x", ["P"]), ("bash +xc -e 'P'", ["P"]), ("sh -e +c 'P'", ["P"]),
                             ("bash +co pipefail 'P'", ["P"]), ("bash +c -- 'P'", ["P"]), ("bash -lc 'P'", ["P"]),
                             ("bash +c$X 'P'", ["P"]), ("bash +c7 'P'", ["P"]), ("bash +-c 'P'", ["P"]),
                             ("bash w.sh +c 'P'", ["P"]),
                             ("bash ++c 'P'", []), ("bash -- +c 'P'", []), ("bash +x 'P'", []), ("bash +C 'P'", []),
                             ("bash +cK 'P'", []), ("bash +co pipefial 'P'", [])):
            with self.subTest(words=words):
                self.assertEqual(found, ws._after_dash_c(argv(words)))


class TestNoCluster(unittest.TestCase):
    """The controls: a `+` word that carries no `c` for the shell, or one it refuses by a letter."""

    def test_no_c_or_no_single_sign(self):
        for shell in ("sh", "bash", "dash"):
            for words in ("++c", "+ c", "+C", "+x", "+e", "-- +c", "+"):       # truth: nothing, every one
                with self.subTest(shell=shell, words=words):
                    self.assertEqual(CLEAN, marks("%s %s %s\n" % (shell, words, P)))

    def test_a_letter_or_a_name_the_shell_refuses(self):
        # `_refused` and `_refused_name` read a `+` cluster as they read a `-` one. Truth: nothing, every one.
        for shell in ("sh", "bash", "dash"):
            for words in ("{S}cK", "{S}Kc", "{S}c -K", "{S}cZ", "{S}co pipefial", "{S}c -o pipefial", "{S}cd"):
                with self.subTest(shell=shell, words=words):
                    self.assertEqual((CLEAN, CLEAN), signs("%s %s %s\n" % (shell, words, P)))


class TestThePrice(unittest.TestCase):
    """What the mirror costs, each row as it reads: fail-closed where the shell refuses the word."""

    def test_a_second_sign_in_the_word_is_reported_as_its_mirror_image_is(self):
        for shell in ("sh", "bash", "dash"):                                   # truth: nothing, every one
            for word, image in (("+-c", "-+c"), ("+c+x", "-c+x"), ("+c-", "-c-")):
                with self.subTest(shell=shell, word=word):
                    self.assertEqual((BOTH, BOTH), (marks("%s %s %s\n" % (shell, word, P)),
                                                    marks("%s %s %s\n" % (shell, image, P))))

    def test_a_character_that_is_no_letter(self):
        # sh, bash and dash refuse a digit; zsh takes one for an option and runs the string, which is why a word
        # that is not all letters is read ON (`_refused`). Truth: nothing under sh; runs under zsh.
        for word in ("{S}c7", "{S}7c", "{S}c=", "{S}c."):
            with self.subTest(word=word):
                self.assertEqual((BOTH, BOTH), signs("sh %s %s\n" % (word, P)))
        for word in ("{S}c7", "{S}7c"):
            with self.subTest(word=word, shell="zsh"):
                self.assertEqual((BOTH, BOTH), signs("zsh %s %s\n" % (word, P)))

    def test_a_cluster_no_shell_reaches(self):
        # After a word the shell refuses, as a lone `-`'s FILE, as an option's value, or a parameter of a FILE
        # that is not there. Truth: nothing, every one, written `+` or `-`.
        for words in ("-K {S}c", "- {S}c", "-o {S}c", "--rcfile {S}c", "x.sh {S}c"):
            with self.subTest(words=words):
                self.assertEqual((BOTH, BOTH), signs("sh %s %s\n" % (words, P)))

    def test_a_files_parameters(self):
        # A FILE may hand its parameters to a shell, so a cluster among them is read. Truth: runs, both.
        for file in ("exec sh \"$@\"", "eval \"$2\""):
            with self.subTest(file=file):
                self.assertEqual((BOTH, BOTH), signs("printf '%s\\n' > w.sh\nsh w.sh {S}c %s\n" % (file, P)))

    def test_a_cluster_after_a_long_name_written_with_a_plus(self):
        # `bash +norc +c P`: the `o` takes `+c` for its name and bash refuses it. Truth: nothing.
        self.assertEqual(BOTH, marks("bash +norc +c %s\n" % P))
        self.assertEqual(BOTH, marks("bash +login +c %s\n" % P))

    def test_the_one_report_that_is_lost(self):
        # `main` took `-c` for the cluster and reported; the `o` of `+norc` takes it as its name. Truth: nothing.
        for shell in ("sh", "bash", "dash"):
            with self.subTest(shell=shell):
                self.assertEqual(CLEAN, marks("%s +norc -c %s\n" % (shell, P)))

    def test_dash_reads_no_stdin_after_a_plus_s(self):
        # `dash -cs true <<EOF` runs the heredoc after the string (#2647); `+cs` turns the `s` off and dash reads
        # none, but the second walk reads the letter whatever its sign, as it did. Truth: nothing for `+`, runs
        # for `-`.
        for words in ("{S}cs", "{S}sc"):
            with self.subTest(words=words):
                self.assertEqual((WALK, WALK), signs("dash %s true <<'EOF'\n%s\nEOF\n" % (words, PIPE)))


class TestWhatStaysForOtherIssues(unittest.TestCase):
    """Rows this fix does not move, each pinned as it reads beside its `-` twin."""

    def test_a_dollar_words_cluster_that_is_not_its_first_word_is_2671(self):
        # Truth: runs, every one, written `+` or `-`.
        for words in ("$CMD -e {S}c", "$CMD +x {S}c"):
            with self.subTest(words=words):
                self.assertEqual((CLEAN, CLEAN), signs("CMD=$(command -v sh)\n%s %s\n" % (words, P)))
        # A word the step assigns reads as its literal twin, but not past a `+` word.
        self.assertEqual((CLEAN, BOTH), signs("CMD=sh\n$CMD -e {S}c %s\n" % P))

    def test_a_letter_an_expansion_makes_is_2889(self):
        self.assertEqual((CLEAN, CLEAN), signs("X=c\nsh {S}$X %s\n" % P))              # truth: runs, both

    def test_zshs_O_takes_no_value(self):
        for words in ("{S}cO", "{S}Oc"):                                               # truth: runs, both
            with self.subTest(words=words):
                self.assertEqual((CLEAN, CLEAN), signs("zsh %s %s\n" % (words, P)))

    def test_builtin_and_busybox_in_front(self):
        for front in ("builtin command sh", "busybox sh", "busybox ash"):              # truth: runs, both
            with self.subTest(front=front):
                self.assertEqual((CLEAN, CLEAN), signs("%s {S}c %s\n" % (front, P)))

    def test_a_string_that_is_a_value(self):
        for shell in ("sh", "bash", "dash"):                                           # truth: runs, both
            with self.subTest(shell=shell):
                self.assertEqual((CLEAN, CLEAN), signs("P=%s\n%s {S}c \"$P\"\n" % (P, shell)))


class TestTheTwoSignsReadAlike(unittest.TestCase):
    """Every letter beside the `c`, before it and after it: the cluster reads the same written `+` and `-`, but
    for `n` -- `-nc` parses the string and runs none of it, `+nc` runs it, and `main` reads both."""

    def test_every_letter_beside_the_c(self):
        letters = [chr(code) for code in range(ord("A"), ord("z") + 1) if chr(code).isalpha() and chr(code) != "c"]
        for letter in letters:
            for cluster in ("{S}c" + letter, "{S}" + letter + "c"):
                with self.subTest(cluster=cluster):
                    plus, minus = signs("sh %s %s\n" % (cluster, P))
                    self.assertEqual(minus, plus)
                    self.assertIn(plus, (BOTH, CLEAN))


if __name__ == "__main__":
    unittest.main()
