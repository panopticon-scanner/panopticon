"""#2670, #2836: who runs the word behind a wrapper, and what a builtin's name is to it.

A wrapper that execs (#2670). `env`, `sudo`, `nice`, `nohup`, `exec`, `timeout`, `xargs` and their kind look for a
PROGRAM of the name they are handed, and most builtins have none: `env eval 'curl … | sh'` is a command not found,
and `env unset T` unsets nothing. `main` read the builtin through the wrapper both ways. It reported the first,
where no shell runs anything; and it applied the second, so `T=t; curl -o t U; env unset T; sh $T` read CLEAN
while every shell without `-e` runs the download. The reader now asks who runs the word behind each wrapper
(`shell_wrappers.behind`): the step's own shell, a program a wrapper execs, or a shell handed the words. Behind a
wrapper that execs, a builtin's name that is no program leaves the stage the wrapper's own
(`shell_wrappers.runs_behind`): nothing behind it is read as run, and nothing it would set is set. `echo`,
`printf`, `test`, `[`, `true`, `false`, `pwd` and `kill` are programs too and read as before. `command` and `jobs`
are scripts on macOS (/usr/bin/command, /usr/bin/jobs: `builtin NAME "$@"` under /bin/sh, measured on macOS 26.4)
that hand their words to a shell of their own, so `env command eval 'P'` reports as it did: the forge has no such
file, and there it is a price.

A shell handed the words. `sudo -s`, `-i`, `--shell` and `--login`, and `doas -s`, hand the words to a shell, and a
shell runs a builtin -- in itself. `sudo -s eval 'P'` reports as it did, and `sudo -s unset T` unsets nothing of
the step's. What such a shell's `eval`, `.` or `source` reads, and what its `builtin` or `jobs -x` runs, is read
in the folds that read a `builtin` through (`shell_defaults._through`), and the stage is the wrapper's in the
others, where what the text sets stays in the child: the guard reports where either reading does, and the main pass
reads as `main` did. This is DOC-PINNED, not forge-verified: sudo 1.9's manual says a command given with `-s` or
`-i` "is passed to the shell as a simple command using the -c option", each character but alphanumerics, `_`, `-`
and `$` escaped; the forge's `sudo` is a stand-in written from that sentence, and no sudo was run. doas's manual
gives `-s` no command at all; it is read as sudo's is, the reading that reports more.

`time` is bash's keyword only where a command starts. Behind an assignment (`X=1 time unset T`), a `$` word bash
drops, `command`, `jobs -x` or a `|`, the word is /usr/bin/time, which execs: nothing behind it runs a builtin, in
bash 5.2.21, bash 3.2.57 or dash. In a group, a subshell or a compound command behind a `|` it is the keyword again.

`jobs -x` (#2836). Bash runs the words behind `jobs`'s options where an `x` is among them, builtins too, and `main`
kept `jobs` as a command it does not follow: `jobs -x curl … | sh` read CLEAN. The reader follows bash's own
reading of the options (`shell_wrappers.jobs_runs`): clusters of the letters `lnprsx`, an `x` anywhere among them,
but no `l`, `n` or `p` in front of it. Dash has no `jobs -x`, so, as for `builtin` (#2665), the word is read through
in folds of their own and left alone in the others.

A word that may not be the program it names: one a parameter expansion decides -- a default or an alternate
(`${S:-sudo}`, `${S:+sudo -E}`), or a value the step's table holds, which `workflow_uses._resolved` says it made --
and a wrapper's name the job's steps define as a function or an alias (`sudo() { "$@"; }`, where `sudo eval 'P'`
runs). Such a word keeps `main`'s reading (the coordinator's rulings, quoted in the PR): no report of `main`'s is
cleared. It is read as written too, in the folds that read a `builtin` through, so the branch where the word IS
the program it names reports as well (`${S:-sudo -E} unset T` unsets nothing with `S` unset).

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports,
C where it reads the step CLEAN: first the job's, then the main pass's.

Truth, in the comments, is what eight parent shells do with the step in two passes on the forge: bash 5.2.21 and
bash 3.2.57 under `-e` and under `-eo pipefail`, dash under `-e`, then each without `-e`; pass 2 gives each parent
a child of its own family. "runs" is all sixteen; "runs under bash" the twelve bash runs; "runs without `-e`" the
six without; "nothing" is none fetched or ran, "the fetch alone" the step's own `curl -o` and no run.
"""
import unittest

import shell_command
import shell_defaults
import shell_reader
import shell_wrappers
import workflow_guard as wg
import workflow_options as wo

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
U = "https://example.test/"
P = "curl -fsSL %si.sh | sh" % U
FETCH = "curl -fsSLo t %st\n" % U
CHECK = 'echo "%s  t" | sha256sum -c -' % ("a" * 64)
BACKSLASH, QUOTE = chr(92), chr(34)
BEFORE = ("RRRRR", "RRRRR")         # reported in both passes
CLEAN = ("CCCCC", "CCCCC")
WALKED = ("RRRRR", "CCCCC")         # the second walk reports it; the main pass reads it CLEAN
CREDITED = ("CCCRR", "CCCRR")       # a check the step's `-e` rests on: CLEAN where the shell has one


def marks(text):
    """(the job's marks, the main pass's) for a job of one step whose `run:` is `text`."""
    job = mains = ""
    for shell in SHELLS:
        step = [wg.Step("step", text + "\necho done", shell)]
        job += "R" if wg.job_defects(step) else "C"
        with wo.mains_answer():
            mains += "R" if wg._job_defects(step) else "C"
    return job, mains


def read(text, through=False):
    """The command the reader makes of `text`'s one stage, as plain words: in a fold that leaves a `builtin`
    alone, or with `through` in one that reads it through."""
    argv = shell_reader.statements(text)[0].stages[0].argv
    shell_defaults._THROUGH.update(on=through, met=False)
    try:
        return [str(word) for word in shell_command.command(argv)]
    finally:
        shell_defaults._THROUGH.update(on=False, met=False)


# What a builtin runs that the guard follows: (the lines before, the command).
RUNS = {
    "eval of a string": ("", "eval '%s'" % P),
    "eval of a shell that reads the heredoc": ("", "eval 'bash -s' <<'EOF'\n%s\nEOF" % P),
    "eval of a fetched file's text": (FETCH, 'eval "$(cat t)"'),
    ". ./t": (FETCH, ". ./t"),
    "source ./t": (FETCH, "source ./t"),
    "exec sh t": (FETCH, "exec sh t"),
}
# The wrappers that exec, with their options, in a chain, and behind what bash reads in front of a command.
EXECS = ("env", "sudo", "nice", "nohup", "exec", "setsid", "timeout 5", "stdbuf -o0", "ionice -c 3", "taskset 1", "flock l",
         "chrt -o 0", "doas", "unbuffer", "echo x | xargs", "env X=1", "env -i", "sudo -E", "sudo -u root", "nice -n 5",
         "exec -a x", "/usr/bin/env", "'sudo'", "sudo env", "nohup nice", "env env", "command env", "time env", "! env",
         "X=1 env", "$S env", "echo x | env")
# What hands the words to a shell.
SHELLED = ("sudo -s", "sudo -i", "sudo --shell", "sudo --login", "sudo -Es", "sudo -u root -s", "doas -s", "env sudo -s",
           "sudo -s command", "sudo -s time")
# The lines that set the name a later `sh $T` rests on: behind each, a plain shell runs `sh` of nothing.
SETS = ("unset T", "read T < /dev/null", "eval 'T=x'")


class TestAWrapperThatExecsRunsNoBuiltin(unittest.TestCase):
    """#2670. A program is looked up behind `env`, `sudo` and their kind, and `eval`, `.`, `source`, `exec` and
    `unset` name none."""

    def test_the_issues_steps_and_its_controls(self):
        heredoc = "eval 'bash -s' <<'EOF'\n%s\nEOF" % P
        for front in ("env", "sudo", "nice", "nohup", "exec"):          # truth: nothing, every one (rc 127)
            with self.subTest(front=front):
                self.assertEqual(CLEAN, marks("%s eval '%s'" % (front, P)))
                self.assertEqual(CLEAN, marks("%s %s" % (front, heredoc)))
                self.assertEqual(CLEAN, marks("echo '%s' | %s eval 'bash -s'" % (P, front)))
        # The controls, unmoved: truth runs.
        for text in ("command eval '%s'" % P, "eval '%s'" % P, "command " + heredoc, heredoc, "sudo sh -c '%s'" % P,
                     "env bash -s <<'EOF'\n%s\nEOF" % P):
            with self.subTest(text=text[:24]):
                self.assertEqual(BEFORE, marks(text))

    def test_a_builtin_that_runs_a_text_or_a_file_runs_nothing(self):
        for front in EXECS:                             # truth: nothing; the fetch alone where one stands first
            for name, (before, command) in RUNS.items():
                with self.subTest(front=front, command=name):
                    self.assertEqual(CLEAN, marks("%s%s %s" % (before, front, command)))

    def test_what_it_would_set_is_not_set(self):
        # `main` applied each line, and `sh $T` read as `sh` of nothing. Truth: runs without `-e`; under `-e` the
        # step stops at the command not found, which the guard does not know: the price, named in the PR.
        for front in ("env", "sudo", "nice", "nohup", "timeout 5", "sudo env", "command env", "X=1 env"):
            for line in SETS:
                with self.subTest(front=front, line=line):
                    self.assertEqual(BEFORE, marks("T=t\n%s%s %s\nsh $T" % (FETCH, front, line)))
        for line in SETS:                               # the controls: bash applies each, and nothing runs
            with self.subTest(line=line):
                self.assertEqual(CLEAN, marks("T=t\n%s%s\nsh $T" % (FETCH, line)))
                self.assertEqual(CLEAN, marks("T=t\n%scommand %s\nsh $T" % (FETCH, line)))

    def test_a_check_behind_one_never_runs(self):
        # `main` credited the check. Truth: runs without `-e`; under `-e` the step stops at the 127 (the price).
        for front in ("env", "sudo", "nice", "echo x | xargs"):
            with self.subTest(front=front):
                self.assertEqual(BEFORE, marks("%s%s eval '%s'\nsh t" % (FETCH, front, CHECK)))
                self.assertEqual(BEFORE, marks("%strue; %s || %s exit 1\nsh t" % (FETCH, CHECK, front)))
        self.assertEqual(CREDITED, marks("%seval '%s'\nsh t" % (FETCH, CHECK)))          # the controls
        self.assertEqual(CLEAN, marks("%strue; %s || exit 1\nsh t" % (FETCH, CHECK)))

    def test_what_takes_a_check_away_is_not_done_either(self):
        # `env set +e` turns nothing off: the check behind it still stops the step under `-e`, and `main`
        # reported the row under every setting. Truth: runs without `-e` alone.
        for front in ("env", "sudo", "nohup"):
            with self.subTest(front=front):
                self.assertEqual(CREDITED, marks("%s%s set +e\n%s\nsh t" % (FETCH, front, CHECK)))
        self.assertEqual(BEFORE, marks("%sset +e\n%s\nsh t" % (FETCH, CHECK)))            # the control: truth runs

    def test_a_program_of_the_builtins_name_does_its_work(self):
        for text in ("env echo '%s' | sh" % P, "sudo printf '%%s%sn' '%s' | bash" % (BACKSLASH, P),
                     FETCH + "env test -f t && sh t", FETCH + "nice [ -f t ] && sh t", FETCH + "env true && sh t"):
            with self.subTest(text=text[:40]):          # truth: runs, every one
                self.assertEqual(BEFORE, marks(text))
        self.assertEqual(CLEAN, marks(FETCH + "env true sh t"))                 # truth: the fetch alone
        self.assertEqual({"[", "echo", "false", "kill", "printf", "pwd", "test", "true"}, set(shell_wrappers.PROGRAMS))
        self.assertLessEqual(shell_wrappers.PROGRAMS | shell_wrappers.HANDS_ON | shell_wrappers.READS, shell_wrappers.BUILTINS)

    def test_every_builtin_behind_one(self):
        # `env NAME sh t`: a program of the name is handed the words and runs nothing of them; `command` and
        # `jobs` hand them on where they are scripts (below); every other name is a command not found. `eval`
        # and `exec` were the two `main` read through. Truth on the forge: the fetch alone, every name.
        for name in sorted(shell_wrappers.BUILTINS - {"kill"}):
            with self.subTest(name=name):
                self.assertEqual(BEFORE if name == "command" else CLEAN, marks("%senv %s sh t" % (FETCH, name)))

    def test_command_and_the_keyword_time_run_one(self):
        for front in ("command", "time", "time -p", "time command", "command command", "! time", "if time"):
            for name in ("eval of a string", ". ./t"):
                before, command = RUNS[name]
                with self.subTest(front=front, command=name):   # truth: runs under bash; `command` under dash too
                    tail = "; then :; fi" if front.startswith("if") else ""
                    self.assertEqual(BEFORE, marks("%s%s %s%s" % (before, front, command, tail)))

    def test_the_scripts_macos_ships(self):
        # /usr/bin/command and /usr/bin/jobs are `builtin NAME "$@"` under /bin/sh on macOS 26.4 (measured), so a
        # wrapper that execs finds them and their shell runs the builtin behind: `env command eval 'echo RAN'`
        # prints RAN there. The forge has neither file, and its truth is nothing: reported as `main` reported it.
        for front in ("env command", "nice command", "exec command", "sudo command"):
            with self.subTest(front=front):
                self.assertEqual(BEFORE, marks("%s eval '%s'" % (front, P)))
                self.assertEqual(BEFORE, marks("%s%s sh t" % (FETCH, front)))
        self.assertEqual(WALKED, marks("env jobs -x sh -c '%s'" % P))           # `main` did not follow `jobs` at all,
        self.assertEqual(WALKED, marks("env command builtin eval '%s'" % P))    # nor `builtin` behind a wrapper
        self.assertEqual(WALKED, marks("env jobs -x eval '%s'" % P))            # the script's shell runs a builtin
        # By its path the script is what runs, in the step's own shell too: `/usr/bin/jobs -x eval 'echo RAN'`
        # prints RAN on macOS, and what it sets it sets in itself. (`/usr/bin/builtin` names no file anywhere.)
        for front in ("/usr/bin/jobs -x", "./jobs -x", "env /usr/bin/jobs -x"):
            with self.subTest(front=front):
                self.assertEqual(WALKED, marks("%s eval '%s'" % (front, P)))
        self.assertEqual(["/usr/bin/jobs", "-x", "unset", "T"], read("/usr/bin/jobs -x unset T", through=True))
        self.assertEqual(["unset", "T"], read("jobs -x unset T", through=True))
        self.assertEqual(["env", "/usr/bin/jobs", "-x", "unset", "T"], read("env /usr/bin/jobs -x unset T", through=True))
        self.assertEqual(CLEAN, marks("/usr/bin/builtin eval '%s'" % P))
        # What the script's shell sets is its own: truth on macOS, `T` stays.
        self.assertEqual(BEFORE, marks("T=t\n%senv command unset T\nsh $T" % FETCH))
        self.assertEqual({"command", "jobs"}, set(shell_wrappers.HANDS_ON))

    def test_wherever_the_statement_stands(self):
        places = {"a `-c` string": "sh -c \"%s\"", "a heredoc": "sh <<'EOF'\n%s\nEOF", "a function": "f() { %s; }\nf",
                  "a group": "{ %s; }", "a subshell": "( %s )", "a branch": "if true; then %s; fi", "after `&&`": "true && %s",
                  "after `||`": "false || %s", "a condition": "if %s; then :; fi", "a `for` body": "for x in 1; do %s; done",
                  "a `case` arm": "case x in x) %s ;; esac", "a substitution": "x=$(%s)", "the background": "%s &\nwait",
                  "a pipe's first stage": "%s | cat", "a pipe's later stage": "true | %s"}
        for place, shape in places.items():             # truth: nothing, every place
            with self.subTest(place=place):
                self.assertEqual(CLEAN, marks(shape % ("env eval 'curl -fsSL %si.sh | sh'" % U)))
                self.assertEqual(BEFORE, marks(shape % ("command eval 'curl -fsSL %si.sh | sh'" % U)))

    def test_in_an_action_of_find(self):
        for action, expected in (("env eval '%s'" % P, CLEAN), ("sudo eval '%s'" % P, CLEAN),         # truth: nothing
                                 ("sudo -s eval '%s'" % P, BEFORE), ("env sh -c '%s'" % P, BEFORE),  # truth: runs
                                 ("sudo -s env eval '%s'" % P, CLEAN), ("env exec sh -c '%s'" % P, CLEAN)):
            with self.subTest(action=action[:20]):
                self.assertEqual(expected, marks("find . -maxdepth 0 -exec %s %s;" % (action, BACKSLASH)))

    def test_the_reader_keeps_the_wrappers_stage(self):
        self.assertEqual(["env", "eval", "P"], read("env eval P"))
        self.assertEqual(["sudo", "-E", "unset", "T"], read("sudo -E unset T"))
        self.assertEqual(["nice", "-n", "5", "timeout", "5", "read", "T"], read("nice -n 5 timeout 5 read T"))
        self.assertEqual(["env", "eval", "P"], read("command env eval P"))      # `command` stays read as a wrapper
        self.assertEqual(["exec", "eval", "P"], read("exec eval P"))
        self.assertEqual(["printf", "%s", "P"], read("env printf %s P"))
        self.assertEqual(["sh", "t"], read("exec command sh t"))
        self.assertEqual(["env", "builtin", "eval", "P"], read("env builtin eval P", through=True))
        argv = shell_reader.statements("command env eval P")[0].stages[0].argv
        self.assertEqual(["command"], [str(word) for word in shell_command.wrapper_words(argv)])


class TestAShellHandedTheWords(unittest.TestCase):
    """`sudo -s` and its kind: DOC-PINNED to sudo's manual, not forge-verified (the module's note)."""

    def test_it_runs_what_a_builtin_runs(self):
        for front in SHELLED:                           # truth, by the stand-in: runs, every one
            for name, (before, command) in RUNS.items():
                if name == "eval of a fetched file's text":
                    continue                            # sudo escapes the text's newlines: below
                with self.subTest(front=front, command=name):
                    self.assertEqual("RRRRR", marks("%s%s %s" % (before, front, command))[0])

    def test_the_main_pass_reads_as_main_did(self):
        for front in ("sudo -s", "sudo -i", "doas -s"):
            with self.subTest(front=front):
                self.assertEqual(BEFORE, marks("%s eval '%s'" % (front, P)))
                self.assertEqual(BEFORE, marks("%s%s . ./t" % (FETCH, front)))
                self.assertEqual(WALKED, marks("%s builtin eval '%s'" % (front, P)))        # `main` read it CLEAN
                self.assertEqual(WALKED, marks("%s jobs -x sh -c '%s'" % (front, P)))

    def test_what_it_sets_stays_in_the_child(self):
        for front in ("sudo -s", "sudo -i", "sudo --login", "doas -s", "env sudo -s"):
            with self.subTest(front=front):             # truth, by the stand-in: runs, every one
                self.assertEqual(BEFORE, marks("T=t\n%s%s unset T\nsh $T" % (FETCH, front)))
                self.assertEqual(WALKED, marks("T=t\n%s%s eval 'T=x'\nsh $T" % (FETCH, front)))
                self.assertEqual(WALKED, marks("T=t\n%s%s builtin unset T\nsh $T" % (FETCH, front)))
        # The check behind `set +e` still stops the step: `main` reported it. Truth: runs without `-e` alone.
        self.assertEqual(CREDITED, marks("%ssudo -s set +e\n%s\nsh t" % (FETCH, CHECK)))

    def test_a_wrapper_that_execs_in_it_finds_no_builtin(self):
        for front in ("sudo -s env", "sudo -s exec", "sudo -s nice", "sudo -i command time"):
            with self.subTest(front=front):             # truth: nothing
                self.assertEqual(CLEAN, marks("%s eval '%s'" % (front, P)))
        self.assertEqual(BEFORE, marks("%ssudo -s exec sh t" % FETCH))          # truth: runs

    def test_a_check_its_eval_runs_is_not_credited(self):
        # The price of reading the stage both ways, accepted in the coordinator's ruling: truth is the check
        # run and the step stopped under `-e`, and `main` credited it.
        self.assertEqual(("RRRRR", "CCCRR"), marks("%ssudo -s eval '%s'\nsh t" % (FETCH, CHECK)))
        self.assertEqual(CREDITED, marks("%ssudo -s %s\nsh t" % (FETCH, CHECK.replace("| sha256sum", "| sudo sha256sum"))))

    def test_how_sudo_is_told(self):
        behind = shell_wrappers.behind
        for own in (["-s"], ["-i"], ["--shell"], ["--login"], ["-Es"], ["-sE"], ["-u", "root", "-s"], ["-iu", "root"], ["-H", "-i"]):
            with self.subTest(own=own):
                self.assertEqual(("child", True), behind("own", True, "sudo", own))
        for own in ([], ["-E"], ["-u", "root"], ["-u", "sinbad"], ["--preserve-env"], ["--user=si"], ["--", ], ["-H", "-n"]):
            with self.subTest(own=own):
                self.assertEqual(("exec", False), behind("own", True, "sudo", own))
        self.assertEqual(("child", True), behind("exec", False, "doas", ["-s"]))
        self.assertEqual(("exec", False), behind("own", True, "env", ["-s"]))   # no other wrapper has such a mode
        # A name glued to its option reads as the mode where it holds the letter: more is read, never less.
        self.assertEqual(("child", True), behind("own", True, "sudo", ["-usinbad"]))

    def test_the_reader_reads_the_stage_both_ways(self):
        self.assertEqual(["sudo", "-s", "eval", "P"], read("sudo -s eval P"))
        self.assertEqual(["eval", "P"], read("sudo -s eval P", through=True))
        self.assertEqual(["sudo", "-s", "unset", "T"], read("sudo -s unset T", through=True))
        self.assertEqual(["sh", "t"], read("sudo -s exec sh t"))                # a program: every fold
        self.assertEqual(["sudo", "-s", "env", "eval", "P"], read("sudo -s env eval P", through=True))
        self.assertEqual(["sudo", "eval", "-s", "P"], read("sudo eval -s P", through=True))     # the builtin's own word
        self.assertEqual(["sudo", "X=1", "eval", "-i"], read("sudo X=1 eval -i", through=True))
        self.assertEqual(["eval", "P"], read("env command eval P", through=True))
        self.assertEqual(["env", "command", "eval", "P"], read("env command eval P"))
        self.assertEqual(["env", "command", "unset", "T"], read("env command unset T", through=True))
        with wo.mains_answer():                         # the main pass: `main`'s reading of the word
            self.assertEqual(["eval", "P"], read("sudo -s eval P"))
            self.assertEqual(["sudo", "-s", "unset", "T"], read("sudo -s unset T"))


class TestTimeIsAKeywordOnlyWhereACommandStarts(unittest.TestCase):
    """Measured in bash 5.2.21, bash 3.2.57 (as bash and as `sh`) and dash: `T=t; FRONT time unset T` leaves `T`
    set behind each of these fronts."""

    PROGRAM = ("X=1 time", "$S time", "${S:+sudo} time", "${S:+echo hi} time", "command time", "echo x | time",
               "echo x | cat | time -p", "echo x |& time", "true && echo x | time")

    def test_behind_these_it_is_a_program(self):
        for front in self.PROGRAM:                      # truth: nothing; the fetch alone
            for name in ("eval of a string", ". ./t", "source ./t"):
                before, command = RUNS[name]
                with self.subTest(front=front, command=name):
                    self.assertEqual(CLEAN, marks("%s%s %s" % (before, front, command)))

    def test_and_sets_nothing(self):
        for front in ("X=1 time", "$S time", "${S:+sudo} time", "command time"):
            for line in SETS:                           # truth: runs without `-e`; `main` read each CLEAN
                with self.subTest(front=front, line=line):
                    self.assertEqual(BEFORE, marks("T=t\n%s%s %s\nsh $T" % (FETCH, front, line)))

    def test_where_a_command_starts_it_is_the_keyword(self):
        for text in ("time eval '%s'", "time -p eval '%s'", "time time eval '%s'", "! time eval '%s'", "{ time eval '%s'; }",
                     "( time eval '%s' )", "echo x | ( time eval '%s' )", "echo x | { time eval '%s'; }",
                     "echo x | if time eval '%s'; then :; fi", "true && time eval '%s'", "time eval '%s' | cat"):
            with self.subTest(text=text):               # truth: runs under bash (5.2.21 alone behind `!`, `if`, `time`)
                self.assertEqual(BEFORE, marks(text % P))
        self.assertEqual(CLEAN, marks("T=t\n%stime unset T\nsh $T" % FETCH))    # truth: the fetch alone, under bash

    def test_the_reader_marks_the_word_behind_a_pipe(self):
        later = shell_reader.statements("echo x | time eval P")[0].stages[1].argv
        self.assertTrue(getattr(later[0], "piped", False))
        self.assertEqual(["time", "eval", "P"], [str(word) for word in shell_command.command(later)])
        for text in ("time eval P | cat", "echo x | ( time eval P )", "echo x | { time eval P; }", "echo x | env time eval P"):
            with self.subTest(text=text):
                for stage in shell_reader.statements(text)[0].stages:
                    self.assertFalse(any(getattr(word, "piped", False) for word in stage.argv))


class TestJobsRunsItsWords(unittest.TestCase):
    """#2836. `jobs -x WORDS` runs WORDS in the step's own shell under bash; dash refuses the option."""

    # Bash 5.2.21 and 3.2.57, 50 spellings measured: where `jobs OPTIONS echo RAN` prints RAN, and where not.
    RUN = ("-x", "-x --", "-x -l", "-xl", "-r -x", "-rx", "-xr", "-s -x", "-sx", "-x -r", "-x -s --", "-xp", "-xn", "-x -x",
           "-xx", "-r -s -x", "-xlnprs", "-srx")
    NOT = ("", "-l", "-lx", "-l -x", "-p -x", "-n -x", "-nx", "-px", "-rl -x", "-r -l -x", "-- -x", "-x -z", "-xz", "--x", "+x",
           "-x -1", "-r")

    def test_the_issues_steps_and_its_controls(self):
        self.assertEqual(WALKED, marks("jobs -x %s" % P))                       # truth: runs under bash
        self.assertEqual(WALKED, marks("%sjobs -x sh t" % FETCH))
        self.assertEqual(WALKED, marks("jobs -x eval '%s'" % P))
        self.assertEqual(CLEAN, marks("jobs\ncurl -fsSLo x.sh %sx.sh" % U))     # the controls: no command runs
        self.assertEqual(CLEAN, marks("jobs -l\ncurl -fsSLo x.sh %sx.sh" % U))

    def test_bashs_own_reading_of_the_options(self):
        for options in self.RUN:                        # truth: runs under bash
            with self.subTest(options=options):
                self.assertEqual(WALKED, marks("jobs %s sh -c '%s'" % (options, P)))
                self.assertEqual(["sh", "t"], shell_wrappers.jobs_runs(["jobs", *options.split(), "sh", "t"], lambda word: False))
        for options in self.NOT:                        # truth: nothing
            with self.subTest(options=options):
                self.assertEqual(CLEAN, marks("jobs %s sh -c '%s'" % (options, P)))
                self.assertEqual([], shell_wrappers.jobs_runs(["jobs", *options.split(), "sh", "t"], lambda word: False))
        self.assertEqual([], shell_wrappers.jobs_runs(["jobs", "-x"], lambda word: False))
        self.assertEqual([], shell_wrappers.jobs_runs(["jobs", "-x", "--"], lambda word: False))
        self.assertEqual(["-", "sh"], shell_wrappers.jobs_runs(["jobs", "-x", "-", "sh"], lambda word: False))     # a command named `-`

    def test_behind_what_bash_reads_in_front_of_a_command(self):
        for front in ("command jobs -x", "builtin jobs -x", "time jobs -x", "! jobs -x", "X=1 jobs -x", "'jobs' -x", "$S jobs -x",
                      "${J:-jobs} -x", "$S ${J:-jobs} -x", "jobs -x jobs -x", "jobs -x command", "jobs -x builtin eval"):
            with self.subTest(front=front):             # truth: runs under bash
                self.assertEqual(WALKED, marks("%s '%s'" % (front, P) if front.endswith("eval") else "%s sh -c '%s'" % (front, P)))

    def test_a_word_behind_it_that_is_no_commands_name(self):
        for words in ("X=1 sh -c '%s'", "! sh -c '%s'", "time eval '%s'", "env eval '%s'"):
            with self.subTest(words=words):             # truth: nothing (`X=1: command not found`; /usr/bin/time)
                self.assertEqual(CLEAN, marks("jobs -x " + words % P))
        self.assertEqual(WALKED, marks("jobs -x time sh -c '%s'" % P))          # truth: runs under bash, by the program

    def test_a_word_among_its_options_that_no_grammar_reads(self):
        # It may be the `-x`, or nothing in front of one. Truth with the name unset: `jobs -x …` runs under
        # bash and `jobs sh …` nothing; the reader reads the word as the `-x` it may be.
        for options in ("$O -x", "$O", QUOTE + "$O" + QUOTE, "$(echo -x)", "-r $O --", "-x -$F"):
            with self.subTest(options=options):
                self.assertEqual(WALKED, marks("jobs %s sh -c '%s'" % (options, P)))
        self.assertEqual(CLEAN, marks("jobs -l $O sh -c '%s'" % P))             # an `l` in front: an error either way
        self.assertEqual("RRRRR", marks("jobs -x $S sh -c '%s'" % P)[0])        # behind the `x` it is the command's word

    def test_what_it_sets_is_set_under_bash_alone(self):
        # Truth: the fetch alone under bash; dash refuses `jobs -x`, keeps `T` and, without `-e`, runs `t`. Both
        # readings stand, so the row reports under every setting, as `main` reported it.
        for line in ("jobs -x unset T", "jobs -x -l unset T", "jobs -rx eval 'T=x'"):
            with self.subTest(line=line):
                self.assertEqual(BEFORE, marks("T=t\n%s%s\nsh $T" % (FETCH, line)))
        # And what takes a check away: truth runs under bash, and `main` credited the check.
        self.assertEqual(("RRRRR", "CCCRR"), marks("%sjobs -x set +e\n%s\nsh t" % (FETCH, CHECK)))

    def test_a_pattern_behind_it_reads_as_it_does_alone(self):
        # #2836's fix shape: "a `jobs -x` whose inner word is a pattern or a value reads as the existing
        # 'cannot read command' sentences do".
        found = wg.job_defects([wg.Step("step", "jobs -x {sh,} -c '%s'" % P, None)])
        self.assertTrue(any("cannot read command" in why and "is a pattern" in why for _name, why in found), found)

    def test_the_reader_reads_it_through_in_folds_of_their_own(self):
        self.assertEqual(["jobs", "-x", "sh", "t"], read("jobs -x sh t"))
        self.assertEqual(["sh", "t"], read("jobs -x sh t", through=True))
        self.assertEqual(["jobs", "-lx", "sh", "t"], read("jobs -lx sh t", through=True))
        self.assertEqual(["time", "eval", "P"], read("jobs -x time eval P", through=True))     # no keyword behind it
        self.assertEqual(["sh", "t"], read("env jobs -x sh t", through=True))
        self.assertEqual(["jobs", "-x", "sh", "t"], read("env jobs -x sh t"))
        self.assertEqual(["sh"], shell_defaults._shell_default("${X:-sh}"))
        self.assertIsNone(shell_defaults._shell_default("${J:-jobs}"))          # in a fold that leaves it alone
        with wo.mains_answer():
            self.assertEqual(["jobs", "-x", "sh", "t"], read("jobs -x sh t", through=True))    # never in the main pass


class TestAWordThatMayNotBeTheProgramItNames(unittest.TestCase):
    """The rulings: such a word keeps `main`'s reading, and only a written literal takes the rule alone. Beside
    `main`'s reading the word is read as written, in folds of their own: more is reported, nothing less."""

    def test_a_default_or_an_alternate(self):
        # Truth, with the name unset: a default is its word, and nothing runs; an alternate is NOTHING, and the
        # bare command runs. With the name set the word is whatever it holds. `main` reported each of these,
        # and so does this tree.
        for front in ("${S:-sudo}", "${S-sudo}", "${S:=sudo}", "${S:-env}", "${S:-nohup}"):
            with self.subTest(front=front):
                self.assertEqual(BEFORE, marks("%s%s . ./t" % (FETCH, front)))
        for front in ("${S:-sudo -E}", "${S:-env A=1}"):
            with self.subTest(front=front):
                self.assertEqual(BEFORE, marks("%s eval '%s'" % (front, P)))
                # The other reading, as written: `sudo -E unset T` unsets nothing. Truth: runs without `-e`,
                # and `main` read it CLEAN.
                self.assertEqual(WALKED, marks("T=t\n%s%s unset T\nsh $T" % (FETCH, front)))
        for front in ("${S:+sudo}", "${S+sudo}", "${S:+env}"):
            with self.subTest(front=front):             # truth: runs, by the bare command
                self.assertEqual(WALKED, marks("%s eval '%s'" % (front, P)))
                self.assertEqual(WALKED, marks("%s%s . ./t" % (FETCH, front)))
        self.assertEqual(BEFORE, marks("${S:+sudo -E} eval '%s'" % P))
        self.assertEqual(CLEAN, marks("%ssudo . ./t" % FETCH))                  # the written word: the rule
        # A default that holds the wrapper AND the builtin: nothing else of the line reads the string. With `S`
        # unset it is `sudo eval 'P'` and nothing runs; with `S='sh -c'` the string runs (bash 5.2.21, bash
        # 3.2.57 and dash, measured). `main`'s report is the only one, and it stays.
        for front in ("${S:-sudo eval}", "${S:-env eval}", "${S:+sudo eval}", "${S:-sudo -s eval}"):
            with self.subTest(front=front):
                self.assertEqual(BEFORE, marks("%s '%s'" % (front, P)))
        self.assertEqual(BEFORE, marks("S='sh -c'\n${S:-sudo eval} '%s'" % P))

    def test_a_word_the_steps_table_made(self):
        # `workflow_uses._resolved` hands `command()` the argv it made a new one of, and a word of the new one
        # that is none of the old one's is one the table or a default put there.
        self.assertEqual(BEFORE, marks("E=eval\nsudo $E '%s'" % P))                 # the builtin's name: kept
        self.assertEqual(WALKED, marks("S=sudo\n$S eval '%s'" % P))                 # the wrapper: #2997's reading, kept
        self.assertEqual(BEFORE, marks("S=sudo\n%s$S . ./t" % FETCH))
        # An operand it made is no wrapper and no builtin's name: the written `env eval` takes the rule.
        self.assertEqual(CLEAN, marks("U=%si.sh\nenv eval %scurl -fsSL $U | sh%s" % (U, QUOTE, QUOTE)))
        self.assertEqual(CLEAN, marks("F=./t\n%ssudo . $F" % FETCH))
        # A word is one the reader made where it is none of the written argv's words: the same letters there
        # are another word's. (`"".join` makes each a string of its own, as a parse does.)
        default, operand = "".join(["su", "do"]), "".join(["su", "do"])
        self.assertEqual([".", "sudo"], shell_command.command([default, ".", operand], ["${S:-sudo}", ".", operand]))
        self.assertEqual(["sudo", ".", "sudo"], shell_command.command([default, ".", operand], [default, ".", operand]))
        written = ["sudo", "$E", "P"]
        made = ["sudo", "eval", "P"]
        self.assertEqual(["sudo", "eval", "P"], shell_command.command(made))               # nothing says who wrote it
        self.assertEqual(["eval", "P"], shell_command.command([written[0], "eval", written[2]], written))
        self.assertEqual(["eval", "P"], shell_command.command(["sudo", written[1].replace("$E", "eval"), written[2]], ["env", "x"]))
        self.assertEqual(["sudo", "eval", "P"], shell_command.command(written[:1] + made[1:], written[:1] + made[1:]))

    def test_a_name_the_step_defines(self):
        function = "sudo() { %s$@%s; }" % (QUOTE, QUOTE)
        for define in (function, "sudo () { %s$@%s; }" % (QUOTE, QUOTE), "function sudo { %s$@%s; }" % (QUOTE, QUOTE),
                       "if ! command -v sudo >/dev/null; then %s; fi" % function, "eval '%s'" % function, "alias sudo=''",
                       "alias ll='ls -l' sudo=command"):
            with self.subTest(define=define):           # truth: runs, but an alias under dash alone
                self.assertEqual(BEFORE, marks("%s\nsudo eval '%s'" % (define, P)))
                self.assertEqual(BEFORE, marks("%s\n%ssudo . ./t" % (define, FETCH)))
        self.assertEqual(BEFORE, marks("%s\neval %ssudo eval '%s'%s" % (function, QUOTE, P, QUOTE)))    # the call in an `eval`
        self.assertEqual(BEFORE, marks("env() { %s$@%s; }\nenv eval '%s'" % (QUOTE, QUOTE, P)))
        # What the function then sets is set, and truth is the fetch alone: `main` read it so. The word is read
        # as the program too, which unsets nothing, and the row reports: the price of not reading the body.
        self.assertEqual(WALKED, marks("%s\nT=t\n%ssudo unset T\nsh $T" % (function, FETCH)))
        # A body that runs nothing, or the program itself: truth, `T` stays and `t` runs, and `main` read CLEAN.
        self.assertEqual(WALKED, marks("sudo() { :; }\nT=t\n%ssudo unset T\nsh $T" % FETCH))
        self.assertEqual("RRRRR", marks("sudo() { command sudo %s$@%s; }\nT=t\n%ssudo unset T\nsh $T" % (QUOTE, QUOTE, FETCH))[0])
        # Another name's definition changes nothing, nor does this one for another wrapper. Truth: nothing.
        self.assertEqual(CLEAN, marks("mysudo() { %s$@%s; }\nsudo eval '%s'" % (QUOTE, QUOTE, P)))
        self.assertEqual(CLEAN, marks("%s\nenv eval '%s'" % (function, P)))
        self.assertEqual(CLEAN, marks("python3 - <<'EOF'\nimport time\nprint(time.time())\nEOF\necho x | time eval '%s'" % P))

    def test_the_definition_is_read_for_its_job_and_no_further(self):
        function = "sudo() { %s$@%s; }" % (QUOTE, QUOTE)
        self.assertIsNone(shell_wrappers._SHADOWED["names"])
        self.assertTrue(wg.job_defects([wg.Step("one", function, None), wg.Step("two", "sudo eval '%s'" % P, None)]))
        self.assertIsNone(shell_wrappers._SHADOWED["names"])                    # nothing held behind the job
        self.assertFalse(wg.job_defects([wg.Step("two", "sudo eval '%s'" % P, None)]))
        shell_wrappers.shadows(function)                # outside a job's read nothing is noted
        self.assertIsNone(shell_wrappers._SHADOWED["names"])
        self.assertEqual(["sudo", "eval", "P"], read("sudo eval P"))

    def test_what_spells_a_definition(self):
        names = shell_wrappers.defined
        for text in ("sudo() { :; }", "sudo () { :; }", "sudo ( ) { :; }", "function sudo { :; }", "function sudo() { :; }",
                     "alias sudo=x", "alias -- sudo=x", "alias a=b sudo=c", "alias 'sudo=x'", "x; sudo() { :; }",
                     "eval 'sudo() { :; }'"):
            with self.subTest(text=text):
                self.assertEqual({"sudo"}, names(text))
        for text in ("mysudo() { :; }", "sudo-x() { :; }", "os.sudo()", "sudo(1)", "function sudoers { :; }", "unalias sudo",
                     "alias x=sudo", "alias x=1; sudo=2", "sudo -u root ls", "time.time()", "a.env()", "myalias sudo=1",
                     "alias x=nosudo=1", "alias x=1 | sudo=2", "x.alias sudo=1", "functions sudo"):
            with self.subTest(text=text):
                self.assertEqual(set(), names(text))
        self.assertEqual({"sudo"}, names("alias x='sudo=1'"))   # a value that spells one reads as one: more is kept
        self.assertEqual({"env", "time"}, names("env() { :; }; function time { :; }"))
        self.assertEqual({"sudo", "nice"}, names("alias a=b\tsudo=c 'nice=d'"))
        self.assertEqual(set(), names("alias " * 20000))          # a long line of them is read once, not once each


class TestWhatStaysForOtherIssues(unittest.TestCase):
    """Rows this PR does not move, each pinned as it reads and named with what it waits for."""

    def test_a_keyword_bash_reads_in_one_version_alone(self):
        # Behind `!`, `if`, `while`, a `case` arm or another `time`, bash 5.2.21 reads `time` as its keyword and
        # bash 3.2.57 as a program; dash always as a program. Truth for each line below: bash 3.2.57 and dash
        # leave `T` and run `t` without `-e`. The reader reads bash 5's word under every setting: #3024's class.
        for line in ("time unset T", "! time unset T", "if time unset T; then :; fi", "time time unset T"):
            with self.subTest(line=line):
                self.assertEqual(CLEAN, marks("T=t\n%s%s\nsh $T" % (FETCH, line)))

    def test_a_quoted_time_and_one_behind_a_bang_behind_a_pipe(self):
        # `"time"` and `\time` are /usr/bin/time in every shell, and so is `time` behind `| !`; the reader
        # does not keep a plain word's quotes, nor read a `!` behind a pipe. Truth: nothing; reported, as on `main`.
        for front in (QUOTE + "time" + QUOTE, BACKSLASH + "time", "echo x | ! time"):
            with self.subTest(front=front):
                self.assertEqual(BEFORE, marks("%s eval '%s'" % (front, P)))
        # The same word in front of what would set a name: /usr/bin/time unsets nothing, and without `-e` every
        # shell leaves `T` and runs `t` (measured). Read as the keyword's: CLEAN, as on `main`.
        for front in (QUOTE + "time" + QUOTE, BACKSLASH + "time"):
            with self.subTest(front=front, sets="T"):
                self.assertEqual(CLEAN, marks("T=t\n%s%s unset T\nsh $T" % (FETCH, front)))

    def test_time_in_an_action_of_find(self):
        # `find` looks `time` up as a program, and /usr/bin/time execs: truth, nothing. The reader reads the
        # word `find` looks up as it reads a step's own first word, the keyword: reported, as on `main`.
        self.assertEqual(BEFORE, marks("find . -maxdepth 0 -exec time eval '%s' %s;" % (P, BACKSLASH)))

    def test_a_word_in_doubt_in_front_of_a_shell_handed_the_words(self):
        # Truth: `T` stays and `t` runs -- under every shell for the default, every one but dash under `-e` for
        # the alias, the ones without `-e` for the function. Both readings of such a stage read the `eval`'s
        # text as the step's own; the one where the stage is the wrapper's has no fold of its own behind a word
        # in doubt, as it has behind a written `sudo -s` (`TestAShellHandedTheWords`). CLEAN, as on `main`.
        for define, front in (("alias sudo=''\n", "sudo -s"), ("sudo() { %s$@%s; }\n" % (QUOTE, QUOTE), "sudo -s"),
                              ("", "${S:-sudo -s}")):
            with self.subTest(define=define, front=front):
                self.assertEqual(CLEAN, marks("%sT=t\n%s%s eval 'T=x'\nsh $T" % (define, FETCH, front)))

    def test_a_function_of_a_wrappers_name_in_front_of_builtin(self):
        # Truth: both bashes run it (the function runs `builtin eval 'P'`), and dash has no `builtin`. As
        # written `sudo builtin` runs nothing, and `main`'s reading of the word leaves a `builtin` behind a
        # wrapper unread: neither reads the text. CLEAN, as on `main`. Batch C's limit of a function that hands
        # its words to `builtin` (`test_workflow_in_front_of_a_command`), met by another road.
        self.assertEqual(CLEAN, marks("sudo() { %s$@%s; }\nsudo builtin eval '%s'" % (QUOTE, QUOTE, P)))

    def test_a_text_sudo_escapes_the_newlines_of(self):
        # `sudo -s eval "$(cat t)"`: sudo puts a backslash in front of each newline, the child reads one
        # line, and a script whose first line is a comment runs nothing. Reported, as on `main`.
        self.assertEqual(BEFORE, marks('%ssudo -s eval "$(cat t)"' % FETCH))

    def test_doas_is_read_as_sudo_is(self):
        # doas(1) gives `-s` no command (`doas -s WORDS` is a usage error by its source); read as sudo's `-s`,
        # which reports where sudo's would run. Not forge-verified: there is no doas on the forge.
        self.assertEqual(BEFORE, marks("doas -s eval '%s'" % P))
        self.assertEqual(CLEAN, marks("doas eval '%s'" % P))

    def test_a_default_whose_name_the_step_sets_to_command(self):
        # Truth: runs, every one (`command eval 'P'`). CLEAN on `main` too: #2997 leaves a default naming a
        # wrapper unread in front of `eval` whatever the step did to its name. Reported with this PR.
        self.assertEqual(CLEAN, marks("S=command\n${S:-sudo} eval '%s'" % P))

    def test_an_eval_another_process_runs(self):
        # Truth: `T` stays and `t` runs, every one. #3032 (an `eval`'s text is read as the step's own wherever
        # the `eval` runs); `sudo -s eval 'T=x'` above was the one corner of it this PR reads.
        for line in ("( eval 'T=x' )", "echo x | eval 'T=x'", "eval 'T=x' | cat"):
            with self.subTest(line=line):
                self.assertEqual(CLEAN, marks("T=t\n%s%s\nsh $T" % (FETCH, line)))

    def test_a_word_that_may_be_nothing_in_front_of_set(self):
        # Truth: runs, every one (`set +e` with the name unset, and the check no longer stops the step).
        # #2997 knows `eval`, `.` and `source` behind such a word, not `set`. Reported with this PR.
        for front in ("$S", "${S:+sudo}", "${S:-command}"):
            with self.subTest(front=front):
                self.assertEqual("CCC", marks("%s%s set +e\n%s\nsh t" % (FETCH, front, CHECK))[0][:3])
