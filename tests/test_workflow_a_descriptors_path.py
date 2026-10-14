"""A path that names one of the stage's own descriptors, where a command WRITES it (#2744).

`/dev/stdout`, `/dev/stderr`, `/dev/fd/N`, `/proc/self/fd/N` and `/proc/thread-self/fd/N` are the stage's own
descriptors by a path, and a kernel opens many spellings of each: repeated slashes, `.` and `..` among them, a
climb to the root. `main` knew the two written `/dev/stdout` and `/dev/fd/1`, and descriptor 1 alone, so

    curl -fsSL URL > //dev/stdout | sh          read CLEAN and runs under every shell
    curl -fsSL URL 2>&1 > /dev/stderr | sh      the same: descriptor 2 was made the pipe, then written by its path
    curl -fsSL URL 2> t > /dev/stderr; sh t     the same: the download lands in `t`

`shell_reader.output_alias_fd` reads such a path as the descriptor it names, and what a command writes there
lands where THAT descriptor points when the redirection is read: the pipe, a file, nowhere. Three readers ask
it: the stage's own redirections (`_stage`), a `tee`'s operands (`workflow_printers._passes_through`, by
`writes_pipe` and the stage's `pipe_output_fds`), and a fetcher's `-o` (`workflow_fetch`, by `stdout_named`).

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard
reports, C where it reads the step CLEAN.

Truth, in the comments, is what eight parent shells do with the step in two passes on the forge (Linux): bash
5.2.21 and bash 3.2.57 under `-e` and under `-eo pipefail`, dash under `-e`, then each without `-e`; pass 2 gives
each parent a child of its own family. "runs" is all sixteen; "runs under bash" the twelve bash runs; "the fetch
alone" the download and no run; "nothing" none of either. Which spellings a kernel opens was measured on macOS
26.4.1 too (Apple's bash 3.2.57, dash, bash 5.2.21): it takes `/dev/stdout/` and `/dev/fd/01`, which Linux
refuses, and has no `/proc`.
"""
import unittest

import shell_reader
import workflow_guard as wg
import workflow_options as wo

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
U = "https://example.test/"
STREAM = "curl -fsSL %si.sh" % U
GET = "curl -fsSLo tool %stool\n" % U
# `tee` hands its input on once by its standard output and once more by an operand that is the pipe: the
# doubled text spells `sh tool`, and the download runs (#2478's row rv40).
DOUBLED = GET + "printf 'ool\\nsh t' | tee %s | sh"
BACKSLASH, QUOTE = chr(92), chr(34)
REPORT, CLEAN = "RRRRR", "CCCCC"

# Descriptor 1 by a path, as written and as a kernel reads it. Truth for each: runs.
ONE = ("/dev/stdout", "/dev/fd/1", "//dev/stdout", "/dev//stdout", "/dev/./stdout", "/dev//fd/1", "/dev/fd//1",
       "//dev//fd//1", "///dev/stdout", "/proc/self/fd/1", "/proc/thread-self/fd/1", "/proc//self//fd/1",
       "/proc/self/./fd/1", "/dev/../dev/stdout", "/dev/fd/../fd/1", "/../dev/stdout",
       "../../../../../../../../../../dev/stdout", QUOTE + "//dev/stdout" + QUOTE, "'/dev/fd/1'")
# Spellings Linux refuses -- nothing runs on the forge -- of which macOS opens the first two: read as the
# descriptor, the reading of either kernel.
REFUSED = ("/dev/stdout/", "/dev/fd/01", "/dev/fd/1/")
# No path of the stage's standard output. Truth for each: the fetch alone, or nothing.
FILES = ("out.txt", "/dev/null", "/dev/stdout2", "dev/stdout", "./dev/stdout", "~/dev/stdout", "/proc/self/status",
         "/proc/1/fd/1", "/dev/fd/9", "/dev/stdin", "/dev/fd/0", "d/out.txt")
# Descriptor 2 by a path.
TWO = ("/dev/stderr", "/dev/fd/2", "//dev/stderr", "/proc/self/fd/2", "/proc/thread-self/fd/2")


def marks(text):
    """The job's marks for a job of one step whose `run:` is `text`."""
    return "".join("R" if wg.job_defects([wg.Step("step", text + "\necho done", shell)]) else "C" for shell in SHELLS)


def stage(text, at=0):
    return shell_reader.statements(text)[0].stages[at]


class TestAPathOfDescriptorOne(unittest.TestCase):
    """`> //dev/stdout` leaves descriptor 1 where it was: on the pipe."""

    def test_a_stream_redirected_to_it_still_feeds_the_shell(self):
        for word in ONE:
            for op in ("> ", ">> ", "1> ", ">| ", "1>> ", ">"):
                with self.subTest(word=word, op=op):            # truth: runs
                    self.assertEqual(REPORT, marks("%s %s%s | sh" % (STREAM, op, word)))

    def test_both_passes_read_it(self):
        for word in ("//dev/stdout", "/proc/self/fd/1"):
            step = [wg.Step("step", "%s > %s | sh" % (STREAM, word), None)]
            with wo.mains_answer():
                self.assertTrue(wg._job_defects(step), word)

    def test_a_path_of_nothing_of_its_own_is_a_file(self):
        for word in FILES:
            with self.subTest(word=word):                       # truth: the fetch alone, or nothing
                self.assertEqual(CLEAN, marks("%s > %s | sh" % (STREAM, word)))
                self.assertEqual(CLEAN, marks("%s >> %s | sh" % (STREAM, word)))

    def test_a_spelling_one_kernel_refuses_is_read_as_the_other_reads_it(self):
        for word in REFUSED:
            with self.subTest(word=word):       # truth on the forge: nothing; macOS runs the first two
                self.assertEqual(REPORT, marks("%s > %s | sh" % (STREAM, word)))

    def test_bashs_own_redirections_of_both(self):
        # `&>` and the unnumbered `>&` are bash's. Truth: runs under bash, and dash reads another command;
        # reported under every setting, as `main` reads the two written spellings.
        for op in ("&>", ">&"):
            for word in ("/dev/stdout", "//dev/stdout", "/proc/self/fd/1"):
                with self.subTest(op=op, word=word):
                    self.assertEqual(REPORT, marks("%s %s %s | sh" % (STREAM, op, word)))
            self.assertEqual(CLEAN, marks("%s %s /dev/stdout2 | sh" % (STREAM, op)))    # truth: nothing

    def test_wherever_the_statement_stands(self):
        places = {"a group": "{ %s; } > //dev/stdout | sh", "a subshell": "( %s ) > /proc/self/fd/1 | sh",
                  "inside a group": "{ %s > //dev/stdout; } | sh", "a branch": "if true; then %s > //dev/stdout; fi | sh",
                  "after `&&`": "true && %s > //dev/stdout | sh", "through `tee`": "%s > //dev/stdout | tee log | sh",
                  "through `cat`": "%s > //dev/stdout | cat | sh", "behind `env`": "env %s > //dev/stdout | sh",
                  "into `sudo sh`": "%s > //dev/stdout | sudo sh", "into `bash`": "%s > //dev/stdout | bash",
                  "behind `xargs`": "echo x | xargs -I{} %s > //dev/stdout | sh",
                  "a substitution": "sh -c \"$(%s > //dev/stdout)\"", "an `eval`": "eval \"$(%s > /proc/self/fd/1)\"",
                  "a `-c` string": "sh -c '%s > //dev/stdout | sh'", "a heredoc": "sh <<EOF\n%s > //dev/stdout | sh\nEOF",
                  "the background": "%s > //dev/stdout | sh &\nwait", "behind `!`": "! %s > //dev/stdout | sh",
                  "a `case` arm": "case x in x) %s > //dev/stdout | sh ;; esac",
                  "a loop": "while true; do %s > //dev/stdout | sh; break; done"}
        for place, shape in places.items():                     # truth: runs, every place
            with self.subTest(place=place):
                self.assertEqual(REPORT, marks(shape % STREAM))
        # Truth: runs under bash; dash has no `<(...)`. Reported under every setting.
        self.assertEqual(REPORT, marks("sh <(%s > //dev/stdout)" % STREAM))

    def test_it_is_where_descriptor_one_points_when_it_is_read(self):
        for chain in ("> /dev/stdout > out.txt", "> out.txt > /dev/stdout", "> out.txt > //dev/stdout",
                      "> /dev/null > /dev/fd/1", "> out.txt >> /proc/self/fd/1", ">&2 2>&1 > /dev/stdout", "> /dev/stdin"):
            with self.subTest(chain=chain):                     # truth: the fetch alone
                self.assertEqual(CLEAN, marks("%s %s | sh" % (STREAM, chain)))
        self.assertEqual(REPORT, marks("%s 2> //dev/stdout | sh" % STREAM))     # truth: runs; reported on `main` too

    def test_a_printers_text(self):
        for word in ("//dev/stdout", "/dev/./stdout", "/proc/self/fd/1"):
            with self.subTest(word=word):                       # truth: runs
                self.assertEqual(REPORT, marks("echo '%s | sh' > %s | sh" % (STREAM, word)))
        self.assertEqual(CLEAN, marks("echo '%s | sh' > out.txt | sh" % STREAM))       # truth: nothing


class TestAPathOfAnotherDescriptor(unittest.TestCase):
    """`> /dev/stderr` sends descriptor 1 where descriptor 2 points THEN, as `>&2` does."""

    def test_descriptor_two_made_the_pipe_first(self):
        for word in TWO:
            for shape in ("%s 2>&1 > %s | sh", "%s 2>&1 >> %s | sh", "%s 2>&1 1> %s | sh", "%s 2>/dev/stdout > %s | sh"):
                with self.subTest(word=word, shape=shape):      # truth: runs
                    self.assertEqual(REPORT, marks(shape % (STREAM, word)))
        self.assertEqual(REPORT, marks("%s 3>&1 2>&3 > /dev/stderr | sh" % STREAM))        # truth: runs
        # Truth: runs under bash, whose `&>` it is. Reported under every setting.
        self.assertEqual(REPORT, marks("%s 2>&1 &> /dev/stderr | sh" % STREAM))

    def test_descriptor_two_is_no_pipe(self):
        for word in TWO:
            for shape in ("%s > %s | sh", "%s > %s 2>&1 | sh", "%s 2>/dev/null > %s | sh", "%s 2>&- > %s | sh",
                          "%s > %s |& sh"):
                with self.subTest(word=word, shape=shape):      # truth: the fetch alone, or nothing
                    self.assertEqual(CLEAN, marks(shape % (STREAM, word)))

    def test_a_third_descriptor(self):
        for chain, expected in (("3>&1 > /dev/fd/3", REPORT), ("3>&1 > /proc/self/fd/3", REPORT),       # truth: runs
                                ("3>&1 1>&- > /dev/fd/3", REPORT), ("3<> /dev/stdout >&3", REPORT),
                                ("> /dev/fd/3", CLEAN), ("3>out.txt > /dev/fd/3", CLEAN),       # nothing; the fetch
                                ("3>&1 3>&- > /dev/fd/3", CLEAN), ("3>&1 3> f > /dev/fd/3", CLEAN)):    # nothing; the fetch
            with self.subTest(chain=chain):
                self.assertEqual(expected, marks("%s %s | sh" % (STREAM, chain)))


class TestWhereWhatIsWrittenLands(unittest.TestCase):
    """In the FILE the descriptor holds, where it holds one; in no file named like the path."""

    def test_the_file_the_descriptor_holds(self):
        for lines in ("%s 2> t > /dev/stderr\nsh t", "%s 2> t > /dev/fd/2\nsh t", "%s 2> t > /proc/self/fd/2\nsh t",
                      "%s 2> t >> /dev/stderr\nsh t", "%s 3> t > /dev/fd/3\nsh t", "%s 3> t > //dev//fd/3\nsh t",
                      "%s 2> t > /proc/thread-self/fd/2\nsh t", "%s 3<> t > /dev/fd/3\nsh t",
                      "{ %s > //dev/stdout; } > t\nsh t"):
            with self.subTest(lines=lines):                     # truth: runs
                self.assertEqual(REPORT, marks(lines % STREAM))
        for lines in ("%s > t 2> /dev/stdout\nsh t", "%s > t 2> //dev/stdout\nsh t", "%s 2> t >&2\nsh t", "%s > t\nsh t"):
            with self.subTest(lines=lines):                     # truth: runs; reported on `main` too
                self.assertEqual(REPORT, marks(lines % STREAM))

    def test_no_file_named_like_the_path(self):
        # Truth: the fetch alone -- `sh //dev/stdout` reads the step's standard output, which holds no
        # download. `main` took the path for a saved file and reported the first two.
        for word in ("//dev/stdout", "/proc/self/fd/1", "/dev/stdout", "/dev/stderr"):
            with self.subTest(word=word):
                self.assertEqual(CLEAN, marks("%s > %s\nsh %s" % (STREAM, word, word)))


class TestATeeThatWritesThePipe(unittest.TestCase):
    """The printers' line: a `tee` operand that is the pipe hands the text on once more."""

    def test_an_operand_that_is_descriptor_one(self):
        for word in ONE:
            with self.subTest(word=word):                       # truth: runs
                self.assertEqual(REPORT, marks(DOUBLED % word))
        for operands in ("-a //dev/stdout", "-- //dev/stdout", "log //dev/stdout", "/proc/self/fd/1 log",
                         "//dev/stdout /dev//fd/1", "-i /dev//stdout", "--append //dev/stdout"):
            with self.subTest(operands=operands):               # truth: runs
                self.assertEqual(REPORT, marks(DOUBLED % operands))
        self.assertEqual(REPORT, marks(GET + "printf 'ool\\nsh t' | sudo tee //dev/stdout | sh"))

    def test_an_operand_that_is_a_file(self):
        for word in FILES:
            if word not in ("/dev/stdin", "/dev/fd/0"):         # a `tee` told to write its own input never ends
                with self.subTest(word=word):                   # truth: the fetch alone
                    self.assertEqual(CLEAN, marks(DOUBLED % word))

    def test_a_spelling_one_kernel_refuses(self):
        for word in REFUSED:
            with self.subTest(word=word):       # truth on the forge: the fetch alone; macOS opens the first two
                self.assertEqual(REPORT, marks(DOUBLED % word))

    def test_another_descriptor_the_stage_left_on_the_pipe(self):
        for word in TWO:
            with self.subTest(word=word):
                self.assertEqual(REPORT, marks(DOUBLED % (word + " 2>&1")))                 # truth: runs
                self.assertEqual(REPORT, marks(GET + "printf 'ool\\nsh t' | tee 2>&1 %s | sh" % word))
                self.assertEqual(CLEAN, marks(DOUBLED % word))                              # the fetch alone
                # Truth: runs under bash 5.2.21; bash 3.2.57 and dash have no `|&`. Reported under every setting.
                self.assertEqual(REPORT, marks(GET + "printf 'ool\\nsh t' | tee %s |& sh" % word))
        self.assertEqual(REPORT, marks(DOUBLED % "/dev/fd/3 3>&1"))                         # truth: runs
        self.assertEqual(CLEAN, marks(DOUBLED % "/dev/fd/3"))                               # the fetch alone
        # Descriptor 1 sent to a file takes the operand with it: both copies land in `log`. Truth: the fetch alone.
        self.assertEqual(CLEAN, marks(DOUBLED % "//dev/stdout > log"))


class TestAFetchersDestination(unittest.TestCase):
    """The fetch table's line: `-o` of a spelling of descriptor 1 is a stream."""

    def test_a_destination_that_is_descriptor_one(self):
        for word in ONE:
            with self.subTest(word=word):                       # truth: runs
                self.assertEqual(REPORT, marks("curl -fsSL %si.sh -o %s | sh" % (U, word)))
                self.assertEqual(REPORT, marks("wget -qO %s %si.sh | sh" % (word, U)))
        for fetch in ("curl -fsSLo//dev/stdout %si.sh", "curl -fsSL --output //dev/stdout %si.sh",
                      "wget -q --output-document=//dev/stdout %si.sh", "curl -fsSL -o - %si.sh"):
            with self.subTest(fetch=fetch):                     # truth: runs
                self.assertEqual(REPORT, marks(fetch % U + " | sh"))

    def test_the_destination_follows_descriptor_one_to_a_file(self):
        for fetch in ("curl -fsSL %si.sh -o //dev/stdout", "curl -fsSL %si.sh -o /dev/stdout", "wget -qO /proc/self/fd/1 %si.sh"):
            with self.subTest(fetch=fetch):                     # truth: runs
                self.assertEqual(REPORT, marks(fetch % U + " > f\nsh f"))
        self.assertEqual(CLEAN, marks("curl -fsSL %si.sh -o //dev/stdout > f | sh" % U))    # truth: the fetch alone

    def test_a_destination_that_is_a_file(self):
        for word in FILES + TWO:                                # descriptor 2 with no `2>&1` is the log
            with self.subTest(word=word):                       # truth: the fetch alone
                self.assertEqual(CLEAN, marks("curl -fsSL %si.sh -o %s | sh" % (U, word)))
                self.assertEqual(CLEAN, marks("wget -qO %s %si.sh | sh" % (word, U)))

    def test_a_spelling_one_kernel_refuses(self):
        for word in REFUSED:
            with self.subTest(word=word):       # truth on the forge: the fetch alone; macOS opens the first two
                self.assertEqual(REPORT, marks("curl -fsSL %si.sh -o %s | sh" % (U, word)))

    def test_another_descriptor_the_stage_left_on_the_pipe(self):
        for fetch in ("curl -fsSL %si.sh -o /dev/stderr 2>&1", "curl -fsSL %si.sh -o /dev/fd/2 2>&1",
                      "curl -fsSL %si.sh -o /proc/self/fd/2 2>&1", "wget -qO /dev/stderr %si.sh 2>&1",
                      "curl -fsSL %si.sh 2>&1 -o /dev/stderr", "curl -fsSL %si.sh -o /dev/fd/3 3>&1"):
            with self.subTest(fetch=fetch):                     # truth: runs
                self.assertEqual(REPORT, marks(fetch % U + " | sh"))
        # Truth: runs under bash 5.2.21, which alone has `|&`. Reported under every setting.
        self.assertEqual(REPORT, marks("curl -fsSL %si.sh -o /dev/stderr |& sh" % U))
        for fetch in ("curl -fsSL %si.sh -o /dev/stderr", "curl -fsSL %si.sh -o /dev/stderr > /dev/null 2>&1",
                      "curl -fsSL %si.sh -o /dev/fd/3"):
            with self.subTest(fetch=fetch):                     # truth: the fetch alone
                self.assertEqual(CLEAN, marks(fetch % U + " | sh"))


class TestTheReadersOwnAnswers(unittest.TestCase):

    def test_the_descriptor_a_path_names(self):
        names = shell_reader.output_alias_fd
        for word in ONE:
            with self.subTest(word=word):
                self.assertEqual("1", names(word.strip(QUOTE + "'")))
        for word in REFUSED:
            self.assertEqual("1", names(word), word)
        for word, fd in (("/dev/stdin", "0"), ("/dev/stderr", "2"), ("//dev/stderr", "2"), ("/dev/fd/2", "2"),
                         ("/proc/self/fd/2", "2"), ("/proc/thread-self/fd/2", "2"), ("/dev/fd/3", "3"),
                         ("//dev//fd/3", "3"), ("/proc/self/fd/12", "12"), ("/dev/fd/007", "7"), ("/dev/fd/0", "0")):
            with self.subTest(word=word):
                self.assertEqual(fd, names(word))
        for word in ("out.txt", "", "-", "/dev/null", "/dev/stdout2", "dev/stdout", "./dev/stdout", "~/dev/stdout",
                     "/proc/self/status", "/proc/1/fd/1", "/proc/$$/fd/1", "$O", "${O:-/dev/stdout}", "$D/stdout",
                     "/dev/fd/x", "/dev/fd/", "/dev/fd", "/dev", "/dev/stdout/x", "/proc/self/fd", "/tmp/dev/stdout"):
            with self.subTest(word=word):
                self.assertIsNone(names(word))

    def test_the_descriptors_that_feed_the_next_stage(self):
        for redirections, fds in (("", ("1",)), ("2>&1", ("1", "2")), ("> f", ()), ("2>&1 > f", ("2",)),
                                  ("> f 2>&1", ()), ("3>&1", ("1", "3")), ("3>&1 > f", ("3",)), ("3>&1 3>&-", ("1",)),
                                  ("> /dev/stderr", ()), ("2>&1 > /dev/stderr", ("1", "2")), ("> /dev/stderr 2>&1", ()),
                                  ("2> //dev/stdout", ("1", "2")), ("3> /proc/self/fd/1", ("1", "3")),
                                  ("> //dev/stdout", ("1",)), ("> f > //dev/stdout", ()), ("&> f", ()), ("2>&-", ("1",)),
                                  ("3>&1 > /dev/fd/3", ("1", "3")), ("> /dev/fd/3", ())):
            with self.subTest(redirections=redirections):
                read = stage("tee log %s | sh" % redirections)
                self.assertEqual(fds, read.pipe_output_fds)
                self.assertEqual("1" in fds, read.stdout_to_pipe)
        self.assertEqual(("1", "2"), stage("tee log |& sh").pipe_output_fds)
        self.assertEqual(("1",), shell_reader.Stage([], [], [], None, [], []).pipe_output_fds)   # the legacy shape

    def test_the_file_descriptor_one_ends_in(self):
        for redirections, files in (("> //dev/stdout", []), ("> f > //dev/stdout", ["f"]), ("2> t > /dev/stderr", ["t"]),
                                    ("2> t > /proc/self/fd/2", ["t"]), ("3> t > /dev/fd/3", ["t"]), ("> /dev/stderr", []),
                                    ("> /dev/fd/9", []), ("> /dev/stdout2", ["/dev/stdout2"]), ("> $O", ["$O"])):
            with self.subTest(redirections=redirections):
                self.assertEqual(files, [str(word) for word in stage("curl U %s" % redirections).stdout_writes])
        # Every word written stays among `writes`, a path of a descriptor too, as on `main`.
        self.assertEqual(["t", "/dev/stderr"], [str(word) for word in stage("curl U 2> t > /dev/stderr").writes])

    def test_what_a_command_of_the_stage_writes_to_the_pipe(self):
        plain, both, filed = stage("tee x | sh"), stage("tee x 2>&1 | sh"), stage("tee x > f 2>&1 | sh")
        for word in ("/dev/stdout", "//dev/stdout", "/proc/self/fd/1"):
            self.assertTrue(shell_reader.writes_pipe(word, plain), word)
            self.assertTrue(shell_reader.writes_pipe(word, filed), word)      # descriptor 1, as `main` read it
        for word in ("/dev/stderr", "/proc/self/fd/2"):
            self.assertFalse(shell_reader.writes_pipe(word, plain), word)
            self.assertTrue(shell_reader.writes_pipe(word, both), word)
            self.assertFalse(shell_reader.writes_pipe(word, filed), word)
        for word in ("log", "/dev/null", "$O", "/dev/fd/3"):
            self.assertFalse(shell_reader.writes_pipe(word, both), word)
        self.assertTrue(shell_reader.writes_pipe("/dev/fd/3", stage("tee x 3>&1 | sh")))

    def test_the_listed_name_of_descriptor_one(self):
        plain, both, filed = stage("curl U | sh"), stage("curl U 2>&1 | sh"), stage("curl U 2>&1 > f | sh")
        for word in ONE[:17]:
            for read in (plain, both, filed):
                self.assertEqual("/dev/stdout", shell_reader.stdout_named(word, read), word)
        for word in ("out.txt", "-", "/dev/stderr", "/dev/null", "$O", "", None, "/dev/fd/3"):
            self.assertEqual(word, shell_reader.stdout_named(word, plain))
        # Another descriptor is the listed name where it feeds the next stage and descriptor 1 does too: the
        # table's readers follow descriptor 1, and with it elsewhere the path stays what it is.
        for word in ("/dev/stderr", "/proc/self/fd/2"):
            self.assertEqual("/dev/stdout", shell_reader.stdout_named(word, both), word)
            self.assertEqual(word, shell_reader.stdout_named(word, filed))
        self.assertEqual("/dev/stdout", shell_reader.stdout_named("/dev/fd/3", stage("curl U 3>&1 | sh")))


class TestWhatStaysForOtherIssues(unittest.TestCase):
    """Rows this PR does not move, each pinned as it reads and named with what it waits for."""

    def test_a_path_a_value_or_a_pattern_decides(self):
        # Truth: runs, every one (the pattern: under bash). The reader has the word, not its value.
        for lines in ("O=/dev/stdout\n%s > $O | sh", "O=//dev/stdout\n%s > \"$O\" | sh", "%s > ${O:-/dev/stdout} | sh",
                      "D=/dev\n%s > $D/stdout | sh", "%s > /dev/stdou[t] | sh"):
            with self.subTest(lines=lines):
                self.assertEqual(CLEAN, marks(lines % STREAM))

    def test_a_path_a_cd_or_a_link_gives(self):
        # Truth: runs, every one. The reader reads a written path as written; what a `cd` or a link makes of
        # it, it reads for a path a command READS (#2919) and not for one it writes.
        for lines in ("cd /dev\n%s > stdout | sh", "cd /\n%s > dev/stdout | sh", "ln -s /dev/stdout o\n%s > o | sh"):
            with self.subTest(lines=lines):
                self.assertEqual(CLEAN, marks(lines % STREAM))

    def test_a_group_whose_own_redirection_carries_another_descriptor(self):
        # Truth: runs, every one -- the group's `2>&1` is made first, and the command inside writes descriptor 2.
        # The reader reads a group's redirections behind the ones inside it; CLEAN on `main` too, by a dup.
        for line in ("( %s >&2 ) 2>&1 | sh", "( %s > /dev/stderr ) 2>&1 | sh", "{ %s >&3; } 3>&1 | sh"):
            with self.subTest(line=line):
                self.assertEqual(CLEAN, marks(line % STREAM))
        # The same order read the other way: truth, the fetch alone. Reported by a dup on `main`, and by the
        # path too with this PR.
        self.assertEqual(REPORT, marks("( %s 2>&1 ) >&2 | sh" % STREAM))
        self.assertEqual(REPORT, marks("( %s 2>&1 ) > /dev/stderr | sh" % STREAM))

    def test_a_fetcher_that_writes_the_pipe_or_a_file_by_another_descriptor_alone(self):
        # Truth: runs, every one -- descriptor 2 is the pipe and the download goes there while descriptor 1
        # is elsewhere; or descriptor 2 holds `t`. The fetch table's readers follow descriptor 1.
        for lines in ("curl -fsSL %si.sh -o /dev/stderr 2>&1 > f | sh", "curl -fsSL %si.sh -o /dev/stderr 2>&1 > /dev/null | sh",
                      "curl -fsSL %si.sh 2> t -o /dev/stderr\nsh t"):
            with self.subTest(lines=lines):
                self.assertEqual(CLEAN, marks(lines % U))

    def test_a_tee_whose_operand_alone_is_the_pipe(self):
        # Truth: runs -- the text reaches the shell once, by the operand, while `tee`'s own output is discarded.
        # The pass-through test is asked of a stage whose standard output feeds the next.
        self.assertEqual(CLEAN, marks(GET + "printf 'sh tool\\n' | tee /dev/stderr 2>&1 > /dev/null | sh"))

    def test_a_files_text_through_a_stage_that_hands_it_on(self):
        # Truth: runs, every one. No path of a descriptor in them: found by this PR's fuzz, CLEAN on `main`.
        for lines in ("cat tool | cat | sh", "cat tool | tee log | sh", "printf 'sh tool\\n' > t\nsh t",
                      "printf 'sh tool\\n' | tee //dev/stdout > t\nsh t"):
            with self.subTest(lines=lines):
                self.assertEqual(CLEAN, marks(GET + lines))

    def test_a_function_that_streams_called_in_front_of_a_shell(self):
        # Truth: runs, both. CLEAN on `main` with no redirection at all, the call's stream not followed,
        # until #3050: the call is read as the body's fetch where it stands, so both REPORT (the
        # coordinator's ruling, Krab seq 2797, moved these two rows here).
        for body in ("%s", "%s > //dev/stdout"):
            with self.subTest(body=body):
                self.assertEqual(REPORT, marks("f() { %s; }\nf | sh" % (body % STREAM)))


if __name__ == "__main__":
    unittest.main()
