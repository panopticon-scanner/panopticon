"""#2665, #2648, #2480: three words in front of a command that the reader took for something else.

`builtin` (#2665). Bash runs `builtin NAME …` as the builtin NAME. `main` left the word where it stood, a command the
guard does not follow, so `builtin eval 'curl … | sh'` read CLEAN while both bashes run the pipe. Dash has no
`builtin`: there the word is a command not found, which stops a step under `-e` and lets it go on without. Neither
reading is the whole truth, so the second walk takes both: it reads a job that holds such a word in every fold it
reads any job in, the word left alone, and then in each of them once more with the word read through
(`shell_command.folds`, `shell_defaults._through`). No reading is lost, and the job reports where either does. The
word is read through in front of a builtin's name alone (`builtin sh tool` runs nothing), past a `--`, behind what
bash itself reads in front of a command -- a keyword, an assignment, `command`, the keyword `time`, a `$` word it
may drop -- and where a one-word default names it (`${S:-builtin}`) or the builtin behind it (`builtin ${E:-eval}`).
Not behind a wrapper that execs (`sudo builtin`, `env builtin`, `command time builtin`), nor as the word an action
of `find` starts with: each looks for a program, and there is none of that name. The main pass reads as `main` does.

A shell started to run nothing (#2648). Bash takes `SHELLOPTS` from its environment and turns each option it lists
on before it reads a line: under `noexec` it runs nothing of its program, under `onecmd` its first command alone,
and it exits 0 either way. So a check in the script `env SHELLOPTS=noexec bash -s` is handed never runs, and `main`
credited it. The reader now marks the shell such an assignment stands in front of, as the step's own prefix or
handed on by `env` or `sudo` (`shell_command._idles`), and no check in a script that shell is handed is the step's
own (`shell_command.unsure`, `sure_reader`): the script is read, since dash ignores the variable and a bash step
refuses to assign it, but nothing in it is credited.

A word that only spells an assignment (#2480). Bash reads an assignment off a word as written: a quote or a
backslash in its name or its operator makes it a command of that name -- `"X=1" sh tool` runs `X=1`, finds none,
and nothing of `tool` runs. The reader took the quotes off first and popped the word, so the row reported. It now
marks such a word where a command word may stand (`shell_reader._named`), and `shell_command._command_result`
reads it as the command. A quote in the value or in a subscript leaves an assignment one, and a wrapper is handed
the word with its quotes off: `env "X=1" sh tool` runs the shell.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports,
C where it reads the step CLEAN: first the job's, then the main pass's, which reads `builtin` as `main` did.

Truth, in the comments, is what eight parent shells do with the step in two passes on the forge: bash 5.2.21 and
bash 3.2.57 under `-e` and under `-eo pipefail`, dash under `-e`, then each without `-e`; pass 2 gives each parent
a child of its own family. "runs under bash" is the twelve bash runs; "runs" is all sixteen; "nothing" is none
fetched or ran, "the fetch alone" the step's own `curl -o` and no run.
"""
import contextlib
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
BACKSLASH = chr(92)
NOW = ("RRRRR", "CCCCC")            # the job reports; the main pass reads it CLEAN, as `main` did
BEFORE = ("RRRRR", "RRRRR")         # `main` reported it already
CLEAN = ("CCCCC", "CCCCC")
# What `compgen -b` prints under bash 5.2.21 on the forge; 3.2.57 prints the same less `compopt`, `mapfile`, `readarray`.
BUILTINS = (". : [ alias bg bind break builtin caller cd command compgen complete compopt continue declare dirs disown echo "
            "enable eval exec exit export false fc fg getopts hash help history jobs kill let local logout mapfile popd printf "
            "pushd pwd read readarray readonly return set shift shopt source suspend test times trap true type typeset ulimit "
            "umask unalias unset wait").split()
CREDITED = ("CCCRR", "CCCRR")       # a check the step's `-e` rests on: CLEAN where the shell has one
UNCREDITED = ("RRRRR", "RRRRR")     # the same check where nothing in its script is the step's own, in either pass


def marks(text):
    """(the job's marks, the main pass's) for a job of one step whose `run:` is `text`."""
    job = mains = ""
    for shell in SHELLS:
        step = [wg.Step("step", text + "\necho done", shell)]
        job += "R" if wg.job_defects(step) else "C"
        with wo.mains_answer():
            mains += "R" if wg._job_defects(step) else "C"
    return job, mains


def reports(text):
    """The job's marks alone."""
    return "".join("R" if wg.job_defects([wg.Step("step", text + "\necho done", shell)]) else "C" for shell in SHELLS)


def read(text):
    """The commands the reader makes of the stages of `text`'s first statement, as plain words, in each fold a
    job is read in: one command where there is one stage."""
    stages = shell_reader.statements(text)[0].stages
    out = [[[str(word) for word in shell_command.command(stage.argv)] for stage in stages]
           for _sure in shell_command.folds(lambda: False)]
    return [fold[0] for fold in out] if len(stages) == 1 else out


@contextlib.contextmanager
def through_alone():
    """The folds with every `builtin` read through and no fold that leaves one alone: what the guard would read
    if the word were simply taken off, and what it must not rest on."""
    def only(unsure):
        shell_defaults._THROUGH.update(on=True, met=False)
        try:
            yield from shell_command._folds(unsure)
        finally:
            shell_defaults._THROUGH.update(on=False, met=False)
    saved = wg.folds
    wg.folds = only
    try:
        yield
    finally:
        wg.folds = saved


# What `builtin` may stand in front of that the guard follows: (the lines before, the command).
RUNS = {
    "eval of a string": ("", "eval '%s'" % P),
    "eval of a fetched file's text": (FETCH, 'eval "$(cat t)"'),
    "eval of an eval": ("", "eval \"eval '%s'\"" % P),
    "eval by a one-word default": ("", "${E:-eval} '%s'" % P),
    "eval of a shell that reads the heredoc": ("", "eval 'bash -s' <<'EOF'\n%s\nEOF" % P),
    ". ./t": (FETCH, ". ./t"),
    "source ./t": (FETCH, "source ./t"),
    "exec sh t": (FETCH, "exec sh t"),
    "command sh t": (FETCH, "command sh t"),
    "echo piped to a shell": ("", "echo '%s' | sh" % P),
    "printf piped to a shell": ("", "printf '%%s\\n' '%s' | bash" % P),
}
# What bash reads in front of a command and still runs the builtin behind: truth for each, runs under bash.
FRONTS = ("builtin", "builtin --", "builtin builtin", "builtin command", "command builtin", "! builtin", "X=1 builtin",
          "'builtin'", "b" + BACKSLASH + "uiltin", "time builtin", "time command builtin", "$S builtin", "$A $B builtin",
          "${S:-builtin}", "$S ${T:-builtin}", "${S:-command} builtin", "${S:+sudo} builtin")


class TestBuiltinIsReadThrough(unittest.TestCase):
    """#2665. CLEAN on `main` under all five settings, and both bashes run the program."""

    def test_the_issues_three_steps_and_its_controls(self):
        for step in ("builtin eval '%s'" % P, "builtin command eval '%s'" % P,
                     "builtin eval 'bash -s' <<'EOF'\n%s\nEOF" % P):            # truth: runs under bash
            with self.subTest(step=step[:24]):
                self.assertEqual(NOW, marks(step))
        for step in ("command eval '%s'" % P, "eval '%s'" % P):                  # truth: runs
            with self.subTest(control=step[:14]):
                self.assertEqual(BEFORE, marks(step))

    def test_in_front_of_each_command_the_guard_follows(self):
        for name, (before, command) in RUNS.items():
            with self.subTest(command=name):
                self.assertEqual(NOW, marks("%sbuiltin %s" % (before, command)))

    def test_behind_what_bash_reads_in_front_of_a_command(self):
        for front in FRONTS:
            for name in ("eval of a string", ". ./t", "exec sh t", "echo piped to a shell"):
                before, command = RUNS[name]
                with self.subTest(front=front, command=name):
                    self.assertEqual(NOW, marks("%s%s %s" % (before, front, command)))

    def test_past_the_words_bash_may_drop_behind_it(self):
        # `builtin $S command sh t`: with `S` unset bash runs `builtin command sh t`. Truth: runs under bash, each.
        for behind in ("$S", "$A $B", "${S:-}", "${S:+sudo}", "${S:+echo}", "-- $S", "-- ${S:+echo}"):
            for name in ("eval of a string", "eval of a fetched file's text", "command sh t"):
                before, command = RUNS[name]
                with self.subTest(behind=behind, command=name):
                    self.assertEqual(NOW, marks("%sbuiltin %s %s" % (before, behind, command)))
        self.assertEqual(NOW, marks("builtin ${S:-command} eval '%s'" % P))      # `command` is a builtin, and runs one
        # A word bash keeps is the name `builtin` looks up, and no builtin: `"$S"` is an empty one, and a default
        # is its word. Truth: nothing, or the fetch alone.
        self.assertEqual(CLEAN, marks("builtin \"$S\" eval '%s'" % P))
        for kept in ("${S:-sudo}", "${S:-nosuch}", "$S ${T:-sudo}"):
            for command in ("sh t", "exec sh t", "command sh t", ". ./t"):
                with self.subTest(kept=kept, command=command):
                    self.assertEqual(CLEAN, marks(FETCH + "builtin %s %s" % (kept, command)))

    def test_wherever_a_command_stands(self):
        step = "builtin eval '%s'" % P
        for place in ('bash -c "%s"', "f() { %s; }\nf", "bash <<'EOF'\n%s\nEOF", "if true; then %s; fi", "( %s )",
                      'eval "%s"', "case x in x)%s ;; esac", "{ %s; }", "false || %s", "%s &\nwait"):
            with self.subTest(place=place[:12]):                                # truth: runs under bash
                self.assertEqual(NOW, marks(place % step))
        self.assertEqual(NOW, marks("builtin eval \"%s\"" % step))               # one inside another
        self.assertEqual(NOW, marks("builtin " * 17 + "eval '%s'" % P))          # as many as bash takes

    def test_each_builtin_reads_as_it_does_with_no_builtin_in_front(self):
        # `builtin NAME sh t` against `NAME sh t`, for every builtin of bash 5.2.21. Truth: the twelve bash runs
        # of each pair agree, run or not (`command`, `eval` and `exec` run the download; no other does).
        self.assertEqual(61, len(BUILTINS))
        self.assertEqual(frozenset(BUILTINS), shell_wrappers.BUILTINS)
        for name in BUILTINS:
            with self.subTest(name=name):
                self.assertEqual(reports(FETCH + "%s sh t" % name), reports(FETCH + "builtin %s sh t" % name))
        for name in ("command", "eval", "exec"):
            with self.subTest(runs=name):
                self.assertEqual(NOW, marks(FETCH + "builtin %s sh t" % name))

    def test_nothing_runs_where_the_word_behind_is_no_builtin(self):
        # Truth: nothing, or the fetch alone -- `builtin: sh: not a shell builtin`, and for `-p` an invalid option.
        for step in (FETCH + "builtin sh t", FETCH + "builtin bash t", FETCH + "builtin env sh t", FETCH + "builtin ./t",
                     FETCH + "builtin time sh t", FETCH + "builtin nosuch t", FETCH + "builtin T=x sh t",
                     "builtin curl -fsSL %si.sh | sh" % U, "builtin -p eval '%s'" % P, "builtin $E '%s'" % P,
                     FETCH + "builtin $S sh t", FETCH + "builtin $S nosuch t",
                     FETCH + "builtin ${E:-sh} t", FETCH + "builtin true sh t", "builtin echo '%s'" % P):
            with self.subTest(step=step[-24:]):
                self.assertEqual(CLEAN, marks(step))

    def test_nothing_behind_it_is_nothing_to_run(self):
        # `builtin` with no word behind it returns 0 and runs nothing, alone or behind what bash reads in front.
        for step in ("builtin", "builtin --", "${S:-builtin}", "${S:+builtin}", "$S builtin", "X=1 builtin", "command builtin",
                     "builtin $S", "builtin -- $S", "builtin builtin", "if builtin; then :; fi"):
            with self.subTest(step=step):
                self.assertEqual(CLEAN, marks(step))
                self.assertEqual(CLEAN, marks(FETCH + step))

    def test_an_exec_with_nothing_to_run_keeps_no_redirection_behind_it(self):
        # `exec 3<>t` keeps descriptor 3 for the lines behind it, and `command exec 3<>t` does. Behind `builtin`
        # bash undoes the redirection when the builtin returns, wherever the word stands: `sh <&3` is a bad
        # descriptor. Truth: the fetch alone, each (bash 5.2.21 and 3.2.57; dash has no `builtin`).
        for front in ("builtin exec", "builtin -- exec", "builtin builtin exec", "builtin command exec", "command builtin exec",
                      "X=1 builtin exec", "$S builtin exec", "builtin $S exec"):
            with self.subTest(front=front):
                self.assertEqual(CLEAN, marks(FETCH + "%s 3<> t\nsh <&3" % front))
        for front in ("exec", "command exec"):                                  # truth: runs
            with self.subTest(control=front):
                self.assertEqual(BEFORE, marks(FETCH + "%s 3<> t\nsh <&3" % front))
        self.assertEqual(NOW, marks(FETCH + "builtin exec sh t"))                # one with a command to run still runs it

    def test_no_wrapper_that_execs_runs_it(self):
        # `sudo`, `env`, `exec`, `nice` and `nohup` look for a program named `builtin`, and so does `time` where
        # `command` runs it; a path names a file. Truth: nothing, each.
        for front in ("sudo builtin", "env builtin", "exec builtin", "nice builtin", "nohup builtin", "command time builtin",
                      "/usr/bin/builtin", "./builtin", "${S:-sudo} builtin", "sudo command builtin"):
            for name in ("eval of a string", ". ./t", "echo piped to a shell"):
                before, command = RUNS[name]
                with self.subTest(front=front, command=name):
                    self.assertEqual(CLEAN, marks("%s%s %s" % (before, front, command)))
        self.assertEqual(CLEAN, marks("${S:-/usr/bin/builtin} eval '%s'" % P))   # a default naming a file
        self.assertEqual(CLEAN, marks("echo x | xargs builtin eval '%s'" % P))
        self.assertEqual(CLEAN, marks("find . -exec builtin eval '%s' %s;" % (P, BACKSLASH)))


    def test_command_by_path_runs_one_as_2997_reads_it(self):
        # macOS has a `/usr/bin/command` that runs a builtin; the forge has no such file. The reader takes
        # `command` by its basename in front of `eval` (#2997), and so in front of `builtin`.
        self.assertEqual(NOW, marks("/usr/bin/command builtin eval '%s'" % P))
        self.assertEqual(BEFORE, marks("/usr/bin/command eval '%s'" % P))


class TestNoReadingOfBuiltinIsLost(unittest.TestCase):
    """#2665. Dash has no `builtin`, so where no `-e` stops the step it goes on as if the line were not there. The
    guard reads the word through in folds of their own, beside the ones that leave it alone."""

    def test_the_folds_read_a_command_both_ways(self):
        self.assertEqual([["builtin", "eval", "P"], ["eval", "P"]], read("builtin eval P"))
        self.assertEqual({"on": False, "met": False}, shell_defaults._THROUGH)   # nothing left on behind the folds:
        argv = shell_reader.statements("builtin eval P")[0].stages[0].argv       # outside them the word is `main`'s
        self.assertEqual(["builtin", "eval", "P"], shell_command.command(argv))
        self.assertEqual([["builtin", "--", "cd", "/"], ["cd", "/"]], read("builtin -- cd /"))
        self.assertEqual([["builtin", "sh", "t"]], read("builtin sh t"))          # no builtin: one reading, one fold
        self.assertEqual([["eval", "P"]], read("eval P"))
        self.assertEqual([[["builtin", "eval", "P"], ["builtin", "eval", "P"]], [["builtin", "eval", "P"], ["eval", "P"]]],
                         read("sudo builtin eval P | builtin eval P"))            # every fold again, for the one it met
        with wo.mains_answer():                                                 # the main pass: `main`'s reading alone
            self.assertEqual([["builtin", "eval", "P"]], read("builtin eval P"))

    def test_the_reading_that_keeps_a_word_in_front_keeps_it_behind_builtin(self):
        # `command_as_written` keeps a `$` word for the step's table to resolve (#2472), and `builtin $S eval P`
        # is then `builtin` in front of a word that is no builtin's name: one reading, and no fold more for it.
        argv = shell_reader.statements("builtin $S eval P")[0].stages[0].argv
        self.assertEqual([["builtin", "$S", "eval", "P"]], [[str(word) for word in shell_command.command_as_written(argv)]
                                                            for _sure in shell_command.folds(lambda: False)])
        self.assertEqual([["builtin", "$S", "eval", "P"], ["eval", "P"]], read("builtin $S eval P"))

    def test_a_reading_kept_for_a_word_is_each_kind_of_folds_own(self):
        # `${X:+sh -c} builtin eval 'P'`: with `X` unset bash runs `builtin eval 'P'`. The reader keeps what it
        # made of such a word's two halves; where the folds read `builtin` through the other half is `eval`, a
        # command of a shell's kind as `sh` is, and the two are one the guard cannot read (#2856 round 13) --
        # which the folds that leave `builtin` alone must not be told, nor those the other way round.
        argv = shell_reader.statements("${X:+sh -c} builtin eval 'P'")[0].stages[0].argv
        why = [shell_command.unresolved_wrapper(argv) for _sure in shell_command.folds(lambda: False)]
        self.assertEqual([None, None], why[:2])
        self.assertEqual(2, len(why[2:]))
        for reason in why[2:]:
            self.assertIn("runs `sh`, or `eval` where it expands to nothing", reason)

    def test_the_words_in_front_are_dropped_in_the_folds_that_read_it_through(self):
        for argv, dropped in ((["$S", "builtin", "eval", "P"], 1), (["$A", "$B", "builtin", "eval", "P"], 2),
                              (["$S", "${T:-builtin}", "eval", "P"], 1), (["${S:-command}", "builtin", "eval", "P"], 1),
                              (["${S:-sudo}", "builtin", "eval", "P"], 0), (["$S", "builtins", "eval", "P"], 0)):
            with self.subTest(argv=argv):
                self.assertEqual([0, dropped], [shell_defaults._optional(argv) for _sure in shell_command.folds(lambda: False)][:2]
                                 if dropped else [0, shell_defaults._optional(argv)])
        self.assertEqual([None, ["builtin"]], [shell_defaults._shell_default("${S:-builtin}")
                                               for _sure in shell_command.folds(lambda: False)])
        self.assertEqual([None], [shell_defaults._shell_default("${S:-/usr/bin/builtin}")      # a file's name: no fold more
                                  for _sure in shell_command.folds(lambda: False)])
        with wo.mains_answer():
            self.assertEqual([0], [shell_defaults._optional(["$S", "builtin", "eval", "P"])
                                   for _sure in shell_command.folds(lambda: False)])

    def test_what_dash_goes_on_past_still_reports(self):
        # Each first line does under bash what would take the report away -- it sets the name, or counts the
        # check and stops -- and the line behind it is one only the second walk reads. Truth: dash without `-e`
        # runs the download, each, and no other parent does. The row reports as on `main`; read through alone it
        # would read CLEAN under `sh {0}`, the one setting whose shell runs it.
        for first, use in (("builtin eval 'T=x'", '${X:-eval} "sh $T"'),
                           ("builtin command read T < /dev/null", '${X:-eval} "sh $T"'),
                           ("builtin builtin read T < /dev/null", '${X:-eval} "sh $T"'),
                           (CHECK + " || builtin exit 1", "$S eval 'sh t'"), (CHECK + " || builtin exit 1", "$S . ./t"),
                           (CHECK + " || builtin command exit 1", "${X:-eval} 'sh t'"),
                           ("builtin eval '%s' || exit 1" % CHECK, "${X:-eval} 'sh t'")):
            step = "T=t\n" + FETCH + first + "\n" + use
            with self.subTest(first=first[-28:], use=use):
                self.assertEqual("RRRRR", reports(step))
                with through_alone():
                    self.assertEqual("CCCCC", reports(step))
        # Where bash leaves the directory, or counts a check its `-e` rests on, the reading through takes the
        # report away under `-e` alone, and there dash stops at the word: no parent runs. As on `main` all the same.
        for first, use in (("builtin cd /", "${X:-eval} 'sh t'"), ("builtin command cd /", "$S eval 'sh t'"),
                           ("builtin eval '%s'" % CHECK, "$S . ./t")):
            step = "T=t\n" + FETCH + first + "\n" + use
            with self.subTest(first=first[-28:], use=use):
                self.assertEqual("RRRRR", reports(step))
                with through_alone():
                    self.assertEqual("CCCRR", reports(step))


    def test_an_alternate_that_names_it_is_nothing_with_its_name_unset(self):
        # `${S:+builtin} sh t` is `sh t` where `S` is unset, and `builtin sh t`, which runs nothing, where it is set.
        # The folds that leave `builtin` alone drop the word (#3003); those that read it through take it for the
        # command. Truth: runs, all sixteen -- and read through alone the row would be CLEAN.
        for step in (FETCH + "${S:+builtin} sh t", "${S:+builtin} " + P):
            with self.subTest(step=step[-20:]):
                self.assertEqual(NOW, marks(step))
                with through_alone():
                    self.assertEqual("CCCCC", reports(step))


class TestAShellStartedToRunNothing(unittest.TestCase):
    """#2648. The check is in a script a bash is handed, and the bash is started so that it runs none of it."""

    FORMS = {"a heredoc": "%s -s <<'EOF'\n" + CHECK + "\nEOF\nsh t", "a string": "%s -c '" + CHECK + "'\nsh t",
             "a pipe": "echo '" + CHECK + "' | %s\nsh t", "a heredoc's second line": "%s -s <<'EOF'\ntrue\n" + CHECK + "\nEOF\nsh t"}

    def form(self, start, name="a heredoc"):
        return FETCH + self.FORMS[name] % start

    def test_the_issues_two_steps_and_its_controls(self):
        # Truth: handed on by `env`, runs; as the step's own prefix, runs under dash and under bash without `-e`
        # (bash refuses to assign the variable and, under `-e`, stops there).
        for start in ("env SHELLOPTS=noexec bash", "SHELLOPTS=noexec bash"):
            with self.subTest(start=start):
                self.assertEqual(UNCREDITED, marks(self.form(start)))
        for start in ("bash", "FOO=1 bash", "env FOO=1 bash", "BASH_ENV=/dev/null bash"):   # truth: the check runs, and stops the step
            with self.subTest(control=start):
                self.assertEqual(CREDITED, marks(self.form(start)))

    def test_however_the_script_is_handed(self):
        for name in self.FORMS:
            with self.subTest(form=name):
                self.assertEqual(UNCREDITED, marks(self.form("env SHELLOPTS=noexec bash", name)))
                self.assertEqual(CREDITED, marks(self.form("env FOO=1 bash", name)))

    def test_however_the_assignment_reaches_the_shell(self):
        # Truth: runs, each -- the check never does.
        for start in ("env X=1 SHELLOPTS=noexec bash", "env SHELLOPTS=errexit:noexec bash", "env SHELLOPTS=noexec:errexit bash",
                      "env -i SHELLOPTS=noexec bash", "env -u X SHELLOPTS=noexec bash", "env 'SHELLOPTS=noexec' bash",
                      "env SHELLOPTS='noexec' bash", "/usr/bin/env SHELLOPTS=noexec bash", "env SHELLOPTS=noexec /bin/bash",
                      "env SHELLOPTS=xtrace SHELLOPTS=noexec bash", "sudo SHELLOPTS=noexec bash", "sudo env SHELLOPTS=noexec bash",
                      "nice env SHELLOPTS=noexec bash", "env SHELLOPTS=noexec nice bash", "env -S 'SHELLOPTS=noexec bash'"):
            with self.subTest(start=start):
                self.assertEqual(UNCREDITED, marks(self.form(start)))

    def test_the_first_command_alone(self):
        # `onecmd`: bash runs the first command it reads and exits. Truth: a check on the second line never
        # runs, and the download does. The guard does not count the lines: no check under it is credited.
        self.assertEqual(UNCREDITED, marks(self.form("env SHELLOPTS=onecmd bash", "a heredoc's second line")))
        self.assertEqual(UNCREDITED, marks(self.form("env SHELLOPTS=errexit:onecmd bash", "a heredoc's second line")))
        self.assertEqual(UNCREDITED, marks(self.form("env SHELLOPTS=onecmd bash")))            # the price: here it runs

    def test_a_value_the_guard_cannot_read(self):
        # Truth: runs where the value is `noexec`, each; with the name unset the check runs (the price).
        for step in ("O=noexec\n" + self.form("env SHELLOPTS=$O bash"), "O=noexec\n" + self.form('env "SHELLOPTS=$O" bash'),
                     self.form("env SHELLOPTS=$(cat opts) bash"), self.form("env SHELLOPTS=$O bash")):
            with self.subTest(step=step[:24]):
                self.assertEqual("RRRRR", reports(step))

    def test_the_last_assignment_decides(self):
        # Truth: the check runs and stops the step, each.
        for start in ("env SHELLOPTS=noexec SHELLOPTS=xtrace bash", "SHELLOPTS=noexec env SHELLOPTS=errexit bash"):
            with self.subTest(start=start):
                self.assertEqual(CREDITED, marks(self.form(start)))
        self.assertEqual(UNCREDITED, marks(self.form("SHELLOPTS=xtrace env SHELLOPTS=noexec bash")))
        # A word `env` hands on is the command's, whatever it spells: here the script's `$1`. And what another
        # wrapper takes for itself is no assignment: `flock` locks a file of that name. Truth: the check runs.
        self.assertEqual(CREDITED, marks(self.form("env bash -s SHELLOPTS=noexec").replace(" -s <<", " <<")))
        self.assertEqual(CREDITED, marks(self.form("flock SHELLOPTS=noexec bash")))

    def test_only_what_turns_the_option_on_and_only_a_shell_that_reads_it(self):
        # Truth: the check runs and stops the step, each: another option, another variable, another spelling;
        # and dash reads no `SHELLOPTS`. `sh` may be bash: there the row reports.
        for start in ("env SHELLOPTS=xtrace bash", "env SHELLOPTS=noexecx bash", "env shellopts=noexec bash",
                      "env BASHOPTS=noexec bash", "env XSHELLOPTS=noexec bash", "SHELLOPTS+=:noexec bash",
                      "env SHELLOPTS=noexec dash", "env SHELLOPTS=noexec ksh"):
            with self.subTest(start=start):
                self.assertEqual(CREDITED, marks(self.form(start)))
        self.assertEqual(UNCREDITED, marks(self.form("env SHELLOPTS=noexec sh")))

    def test_the_script_is_still_read(self):
        # Dash ignores the variable, and a bash step refuses to assign it and runs the shell without: what the
        # script fetches and runs is reported as before. Truth for the prefix: runs under bash without `-e`.
        for start in ("env SHELLOPTS=noexec bash", "SHELLOPTS=noexec bash"):
            with self.subTest(start=start):
                self.assertEqual(BEFORE, marks("%s -c '%s'" % (start, P)))
                self.assertEqual(BEFORE, marks(FETCH + "%s t" % start))

    def test_the_reader_marks_the_shell(self):
        def idle(text):
            argv = shell_command.command(shell_reader.statements(text)[0].stages[0].argv)
            return [str(word) for word in argv], bool(getattr(argv[0], "idle", False))
        self.assertEqual((["bash", "-s"], True), idle("env SHELLOPTS=noexec bash -s"))
        self.assertEqual((["bash", "-s"], True), idle("SHELLOPTS=noexec bash -s"))
        self.assertEqual((["bash", "-s"], False), idle("env SHELLOPTS=xtrace bash -s"))
        self.assertEqual((["bash", "-s"], False), idle("env FOO=1 bash -s"))
        self.assertEqual((["dash", "-s"], False), idle("env SHELLOPTS=noexec dash -s"))
        self.assertEqual((["sha256sum", "-c", "-"], False), idle("env SHELLOPTS=noexec sha256sum -c -"))
        argv = shell_command.command(shell_reader.statements("SHELLOPTS=noexec ${SH:-bash} -s")[0].stages[0].argv)
        self.assertTrue(isinstance(argv[0], shell_reader.Defaulted) and argv[0].idle)       # a word of its own kind still
        stage = shell_reader.statements("SHELLOPTS=noexec bash -s")[0].stages[0]
        self.assertIsNone(shell_command.sure_reader(shell_command.command(stage.argv), ("bash",)))
        self.assertEqual(("bash",), shell_command.sure_reader(["bash", "-s"], ("bash",)))


class TestAWordThatOnlySpellsAnAssignment(unittest.TestCase):
    """#2480. REPORT on `main` under all five settings, and no shell runs anything."""

    QUOTED = ('"X=1"', "'X=1'", '"A+=x"', "A" + BACKSLASH + "+=x", "A+" + BACKSLASH + "=x", 'A+"="x', '"X"=1',
              "X" + BACKSLASH + "=1", 'X"="1', BACKSLASH + "X=1",
              'X"Y"=1', '"a[0]=1"', 'X""=1', '""X=1', "X''=1", '"X"+=x', "$'X=1'", '"X=1" "Y=2"', 'X=1 "Y=2"', '"X=1" Y=2')
    ASSIGNS = ("X=1", "A+=x", 'X="1"', "X='1'", "X=a" + BACKSLASH + " b", 'X=""1', "X=$'1'", "X=" + BACKSLASH + "1", "X=~/t",
               'a["k"]=1', "a['k']=1", "a[" + BACKSLASH + "k]=1", 'a["0"]+=x')
    TAILS = {"a fetched file": (FETCH, "sh t"), "a pipe": ("", P), "a string": ("", "sh -c '%s'" % P), "eval": ("", "eval '%s'" % P)}

    def test_the_issues_three_steps_and_its_controls(self):
        for word in ('"X=1"', '"A+=x"', "A" + BACKSLASH + "+=x"):                   # truth: the fetch alone
            with self.subTest(word=word):
                self.assertEqual(CLEAN, marks(FETCH + "%s sh t" % word))
        for word in ("X=1", "A+=x", 'X="1"'):                                     # truth: runs (`A+=x`: under bash)
            with self.subTest(control=word):
                self.assertEqual(BEFORE, marks(FETCH + "%s sh t" % word))

    def test_a_quote_or_a_backslash_in_the_name_or_the_operator(self):
        for word in self.QUOTED:                                                # truth: nothing, or the fetch alone
            for name, (before, tail) in self.TAILS.items():
                with self.subTest(word=word, tail=name):
                    self.assertEqual(CLEAN, marks("%s%s %s" % (before, word, tail)))

    def test_a_quote_in_the_value_or_in_a_subscript_leaves_an_assignment(self):
        for word in self.ASSIGNS:                                               # truth: runs (an element or `+=`: under bash)
            for name, (before, tail) in self.TAILS.items():
                with self.subTest(word=word, tail=name):
                    self.assertEqual(BEFORE, marks("%s%s %s" % (before, word, tail)))

    def test_wherever_a_command_word_may_stand(self):
        for place in ("if %s sh t; then :; fi", "! %s sh t", "{ %s sh t; }", "( %s sh t )", "f() { %s sh t; }\nf",
                      "function f { %s sh t; }\nf", "case x in x) %s sh t ;; esac", "case x in x)%s sh t ;; esac",
                      ">log %s sh t", "2>&1 >log %s sh t", "<<'EOF' %s sh t\nx\nEOF", "if true; then %s sh t; fi",
                      "for i in 1; do %s sh t; done",
                      "bash -c '%s sh t'", "eval '%s sh t'", "bash <<'EOF'\n%s sh t\nEOF", "true && %s sh t",
                      "true | %s sh t", "true\n%s sh t", "\t%s sh t", "Y=2 %s sh t"):
            for word, expected in (('"X=1"', CLEAN), ("X" + BACKSLASH + "=1", CLEAN), ('"X"=1', CLEAN),
                                   ("X=1", BEFORE), ('X="1"', BEFORE)):
                with self.subTest(place=place[:14], word=word):                 # truth: the fetch alone; the controls run
                    self.assertEqual(expected, marks(FETCH + place % word))

    def test_a_wrapper_is_handed_the_word_with_its_quotes_off(self):
        for wrapper in ("env", "sudo"):                                         # truth: runs, each
            for word in ('"X=1"', "'X=1'", "X" + BACKSLASH + "=1", '"X"=1', "X=1"):
                with self.subTest(wrapper=wrapper, word=word):
                    self.assertEqual(BEFORE, marks(FETCH + "%s %s sh t" % (wrapper, word)))
        self.assertEqual(BEFORE, marks(FETCH + '>"X=1" sh t'))                   # a file of that name, and the shell runs

    def test_the_reader_marks_the_word_and_the_command_is_that_word(self):
        def command(text, at=0):
            stage = shell_reader.statements(text)[at].stages[0]
            return ([str(word) for word in shell_command.command(stage.argv)],
                    [bool(getattr(word, "quoted", False)) for word in stage.argv])
        self.assertEqual((["X=1", "sh", "t"], [True, False, False]), command('"X=1" sh t'))
        self.assertEqual((["X=1", "sh", "t"], [True, False, False]), command("X" + BACKSLASH + "=1 sh t"))
        self.assertEqual((["Y=2", "sh", "t"], [False, True, False, False]), command('X=1 "Y=2" sh t'))
        self.assertEqual((["X=1", "Y=2", "sh", "t"], [True, False, False, False]), command('"X=1" "Y=2" sh t'))
        self.assertEqual((["sh", "t"], [False, False, False]), command('X="1" sh t'))
        self.assertEqual((["sh", "t"], [False, False, False]), command('a["k"]=1 sh t'))
        self.assertEqual((['a[0]=1', "sh", "t"], [True, False, False]), command('a[0]"="1 sh t'))      # past a subscript too
        self.assertEqual((["sh", "t"], [False, False, False, False]), command('env "X=1" sh t'))
        self.assertEqual((["X=1", "sh", "t"], [False, True, False, False]), command('if "X=1" sh t; then :; fi'))
        self.assertEqual("X=1 sh t", shell_reader._named("X=1 sh t", shell_reader._Parse("X=1 sh t")))
        self.assertEqual(shell_reader._NAMED + '"X=1" sh t', shell_reader._named('"X=1" sh t', shell_reader._Parse('"X=1" sh t')))
        self.assertEqual('"X=1 sh t', shell_reader._named('"X=1 sh t', shell_reader._Parse('"X=1 sh t')))   # an unbalanced quote


class TestWhatStaysForOtherIssues(unittest.TestCase):
    """Rows this PR does not move, each pinned as it reads and named with what it waits for."""

    def test_a_wrapper_that_hands_its_words_to_a_shell(self):
        # `sudo -s builtin eval 'P'` hands the words to a shell, which runs the builtin. The reader keeps a
        # wrapper's word and not its options, so it cannot tell this from `sudo builtin`, which runs nothing:
        # #2861's rule, which wrapper runs a builtin, decides both.
        for front in ("sudo -s builtin", "sudo -i builtin", "doas -s builtin"):
            with self.subTest(front=front):
                self.assertEqual(CLEAN, marks("%s eval '%s'" % (front, P)))

    def test_a_function_that_hands_its_words_to_builtin(self):
        # Truth: runs under bash. The word behind `builtin` is `"$@"`, which the reader does not follow.
        self.assertEqual(CLEAN, marks("f() { builtin \"$@\"; }\nf eval '%s'" % P))

    def test_a_step_that_exports_the_variable(self):
        # Truth: runs under dash, which exports it to the bash it starts; bash refuses to assign it. The reader
        # reads an assignment in front of the shell, not one the step made earlier.
        self.assertEqual(CREDITED, marks(FETCH + "export SHELLOPTS=noexec\nbash -s <<'EOF'\n" + CHECK + "\nEOF\nsh t"))

    def test_the_options_that_do_the_same_on_the_command_line(self):
        # `-n` and `-o noexec` read as the second walk reads them since #2647: nothing in the script counts.
        # `-t` and `-o onecmd` are `main`'s gap, filed under #2331 (`test_2500_mains_own_gaps_read_as_on_main`
        # in `tests/test_workflow_guard_reader_forms.py`). Truth: runs, each.
        body = "<<'EOF'\ntrue\n" + CHECK + "\nEOF\nsh t"
        for start, expected in (("bash -n -s", ("RRRRR", "CCCRR")), ("bash -o noexec -s", ("RRRRR", "CCCRR")),
                                ("bash -t -s", CREDITED), ("bash -o onecmd -s", CREDITED)):
            with self.subTest(start=start):
                self.assertEqual(expected, marks(FETCH + "%s %s" % (start, body)))

    def test_a_word_a_wrapper_or_a_keyword_bash_reads_takes(self):
        # `command "X=1" sh t` and `nice "X=1" sh t` run a command named `X=1`, and so do `command X=1 sh t` and
        # `nice X=1 sh t`: only `env` and `sudo` take an assignment. `time "X=1" sh t` runs none either, though
        # `time X=1 sh t` runs the shell. Truth: the fetch alone but for that last. The reader pops a `NAME=`
        # behind every wrapper, as `main` does; not this PR's.
        for front in ("command", "nice", "time"):
            for word in ('"X=1"', "X=1"):
                with self.subTest(front=front, word=word):
                    self.assertEqual(BEFORE, marks(FETCH + "%s %s sh t" % (front, word)))

    def test_a_line_that_is_only_the_word(self):
        # `"X=1"` on a line of its own is a command not found: under `-e` the step stops there. The guard does
        # not know that no program is named so. Truth: runs without `-e`.
        self.assertEqual(BEFORE, marks(FETCH + '"X=1"\nsh t'))


if __name__ == "__main__":
    unittest.main()
