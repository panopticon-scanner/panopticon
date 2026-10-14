"""#2973, #2982: a call of a function the step defines, read as the body's shell on the call's input, and as
the body's use of the file.

`f() { bash -s; }` ⏎ `curl … | f` ran the download under all sixteen parent runs and read CLEAN: the fetch's
consumer is the call's command word, `f`, which names no executor. And `f() { sh tool; }` ⏎ `curl -fsSLo tool …` ⏎
`f` ran it and read CLEAN: the use reader weighed a body's stage as written only on a call that passes the file
(`f tool`), and the body stands before the fetch, where the walk never reaches it (defined after the fetch, the
walk reads the body where it is written, and the row reports).

Now `workflow_called.CalledFetches.consumers` puts, where a call stands behind a fetch -- or a bare `{` or `(`
opening a group on its own -- the stage of the body (the group's statements, and the bodies they call) that reads
the call's standard input as a shell, carrying the call's own input (`with_call_stdin`); `workflow_guard._walk`
hands the fetch's following stages and a stage's substitutions through it. And `workflow_uses._function_use`
weighs each body stage as written on any call, with the call's input.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports,
C where it reads the step CLEAN: first the job's, then the main pass's. Truth, in the comments: the S9 rows are
the #2954-side kit's, eight parents on the forge (bash 5.2.21, bash 3.2.57, dash; `-e`, `-eo pipefail`, none);
Z01/Z02 are the #2942 round-2 kit's; the rows made here ran under bash 3.2.57, /bin/sh and zsh 5.9 with and
without `-e`, a `curl` that writes `echo RAN`. "runs" is every parent ran the download; "nothing" is none did.
"""
import unittest

import shell_reader
import workflow_called
import workflow_guard as wg
import workflow_options as wo

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
U = "https://example.test/i.sh"
PIPE = "curl -fsSL %s | " % U
FETCH = "curl -fsSLo t https://example.test/t\n"
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


class TestABodyReadingTheCallsInput(unittest.TestCase):
    """#2973, the kit's S9 rows: a body that reads its standard input, called as a pipe's consumer, with a
    redirect, a here-string or a process substitution. Truth: runs, all sixteen, for every row here."""

    def test_a_shell_in_the_body_reads_the_pipe(self):
        for body in ("bash -s", "sh", "${SH:-bash -s}", "bash -s -- \"$@\"", "cat | sh", "tee log | sh",
                     "echo installing\n  sh"):
            for shape in ("f() { %s; }\n", "f() {\n  %s\n}\n", "function f {\n  %s\n}\n"):
                if "\n" in body and shape.startswith("f() { "):
                    continue
                text = shape % body + PIPE + "f\n"
                with self.subTest(body=body, shape=shape[:6]):
                    self.assertEqual(REPORTED, marks(text))
        self.assertEqual(REPORTED, marks("f() {\n  bash -s -- \"$@\"\n}\n" + PIPE + "f --yes\n"))

    def test_the_function_defined_and_called_inside_the_piped_group(self):
        for text in (PIPE + "{ f() { bash -s; }; f; }\n", PIPE + "{ f() { ${SH:-bash -s}; }; f; }\n",
                     PIPE + "{\n  f() {\n    bash -s\n  }\n  f\n}\n"):
            with self.subTest(text=text[-40:]):
                self.assertEqual(REPORTED, marks(text))

    def test_a_descriptor_the_call_opens_on_the_file(self):
        # The kit's owntw:AV036: `f() { sh "$@"; }` ⏎ `f /dev/fd/3 3< tool` runs the download under the
        # body's `sh`, the call's descriptor its input. CLEAN on main; truth: runs, every one.
        self.assertEqual(REPORTED, marks("curl -fsSLo tool https://example.test/tool\nf() { sh \"$@\"; }\nf /dev/fd/3 3< tool\n"))

    def test_a_redirect_a_here_string_and_a_process_substitution_into_the_call(self):
        # `f < t` and the own-line body are the use reader's (#2982's hook, with the call's input); the
        # here-string and the process substitution are the substitution walk's. Truth: runs under bash and
        # zsh for the process substitution (/bin/sh has none), every parent for the rest.
        for text in (FETCH + "f() { sh; }\nf < t\n", FETCH + "f() {\n  sh\n}\nf < t\n",
                     "f() {\n  bash -s\n}\nf <<< \"$(curl -fsSL %s)\"\n" % U,
                     "f() {\n  bash -s\n}\nf < <(curl -fsSL %s)\n" % U):
            with self.subTest(text=text[-36:]):
                self.assertEqual(REPORTED, marks(text))

    def test_a_piped_group_on_lines_of_its_own_with_a_plain_shell(self):
        # `curl … | {` ⏎ `bash -s` ⏎ `}` read CLEAN on main by the same cut (the bare opener names no
        # executor); the group's statements are read as a body's now. Truth: runs, every one.
        for opener, closer in (("{", "}"), ("(", ")")):
            with self.subTest(opener=opener):
                self.assertEqual(REPORTED, marks(PIPE + "%s\nbash -s\n%s\n" % (opener, closer)))


class TestABodyUsingTheFile(unittest.TestCase):
    """#2982, Z01: a body that runs the file, defined before the fetch and called after it."""

    def test_defined_before_the_fetch_called_after(self):
        # Z01 (CLEAN on main) and Z02 (defined after the fetch: the walk read the body where written).
        # Truth: runs, every one.
        for text in ("f() {\n  sh tool\n}\ncurl -fsSLo tool https://example.invalid/tool\nf\n",
                     "curl -fsSLo tool https://example.invalid/tool\nf() {\n  sh tool\n}\nf\n",
                     "f() { sh tool; }\ncurl -fsSLo tool https://example.invalid/tool\nf\n"):
            with self.subTest(text=text[:22]):
                self.assertEqual(REPORTED, marks(text))

    def test_a_bound_check_between_credits_the_call_as_it_credits_a_plain_run(self):
        # The checksum names the file and stops the step: nothing runs. The unbound `sha256sum -c sums`
        # (no `sums` written) reports here as it reports before a plain `sh tool` on main: not this PR's.
        bound = "echo \"%s  tool\" > sums\nsha256sum -c sums || exit 1\n" % ("a" * 64)
        self.assertEqual(CLEAN, marks("f() {\n  sh tool\n}\ncurl -fsSLo tool https://example.invalid/tool\n" + bound + "f\n"))
        self.assertEqual(CLEAN, marks("curl -fsSLo tool https://example.invalid/tool\n" + bound + "sh tool\n"))


class TestWhatReadAsItDid(unittest.TestCase):
    """The kit's controls, and the shapes where nothing runs."""

    def test_the_controls_keep_their_marks(self):
        # s9.group-ctl and s9.inline-ctl: `main` reported them. Truth: runs.
        for text in (PIPE + "{ bash -s; }\n", PIPE + "bash -s\n"):
            with self.subTest(text=text[-16:]):
                self.assertEqual(REPORTED, marks(text))

    def test_nothing_is_reported_where_nothing_runs(self):
        # s9.benign: a body that only counts lines; a body whose shell reads a file of its own; a function
        # defined after the group that calls it (no function yet: command not found); a body that holds
        # the fetch itself behind a run of the file, called once (the halves kit's `xr.*.function` rows:
        # the body is read where it stands, in its own order, and not again at the call). Truth: nothing.
        for text in ("f() {\n  wc -l\n}\n" + PIPE + "f\n", "f() { bash -s < /dev/null; }\n" + PIPE + "f\n",
                     PIPE + "{\nf\n}\nf() { bash -s; }\n",
                     "f() {\nsh t\ncurl -fsSLo t https://example.test/t\n}\nf\n",
                     "f() {\nsha256sum -c sums\nbash t\ncurl -fsSLo t https://example.test/t\n}\nf\n"):
            with self.subTest(text=text[:30]):
                self.assertEqual(CLEAN, marks(text))


class TestTheReader(unittest.TestCase):
    """`CalledFetches.consumers` on its own: which stage it puts where the call stands."""

    @staticmethod
    def consumers(text):
        stmts = shell_reader.statements(text)
        calls = workflow_called.CalledFetches(stmts)
        for index, statement in enumerate(stmts):
            for position, stage in enumerate(statement.stages):
                argv = [str(w) for w in shell_reader.acted(stage.argv)]
                if argv[:1] == ["curl"]:
                    out = calls.consumers(index, statement.stages[position + 1:])
                    return [[str(w) for w in shell_reader.acted(s.argv)] for s in out]   # the header words off
        return None

    def test_the_bodys_reading_stage_stands_where_the_call_stood(self):
        self.assertEqual([["bash", "-s"]], self.consumers("f() { bash -s; }\n" + PIPE + "f\n"))
        self.assertEqual([["sh"]], self.consumers("f() {\n  cat | sh\n}\n" + PIPE + "f\n"))
        self.assertEqual([["sh"]], self.consumers("f() {\n  echo installing\n  sh\n}\n" + PIPE + "f\n"))
        self.assertEqual([["bash", "-s"]], self.consumers("g() { bash -s; }\nf() { g; }\n" + PIPE + "f\n"))
        self.assertEqual([["bash", "-s"]], self.consumers(PIPE + "{\nf() {\n  bash -s\n}\nf\n}\n"))
        # Left as written: no shell in the body, a shell reading its own file, a function not yet defined,
        # a name that is no function, and the stages behind the call.
        self.assertEqual([["f"]], self.consumers("f() {\n  wc -l\n}\n" + PIPE + "f\n"))
        self.assertEqual([["f"]], self.consumers("f() { sh < /dev/null; }\n" + PIPE + "f\n"))
        self.assertEqual([["f"]], self.consumers(PIPE + "f\nf() { bash -s; }\n"))
        self.assertEqual([["g"]], self.consumers("f() { bash -s; }\n" + PIPE + "g\n"))
        self.assertEqual([["bash", "-s"], ["tee", "x"]], self.consumers("f() { bash -s; }\n" + PIPE + "f | tee x\n"))

    def test_the_stage_carries_the_calls_input(self):
        stmts = shell_reader.statements(FETCH + "f() { sh; }\nf < t\n")
        call = stmts[-1].stages[0]
        body = stmts[1].stages[0]
        read = workflow_called.with_call_stdin(call, body)
        self.assertEqual([str(w) for w in shell_reader.acted(read.argv)], ["sh"])
        self.assertEqual(read.stdin_reads, call.stdin_reads)
        self.assertIn("t", [str(w) for w in read.reads])
        own = stmts[1].stages[0]._replace(stdin_reads=("own",))
        self.assertIs(workflow_called.with_call_stdin(call, own), own)


if __name__ == "__main__":
    unittest.main()
