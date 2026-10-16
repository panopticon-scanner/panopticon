"""#3048: a locale string `$"..."` is read as bash reads it, the double-quoted string (translated), the `$` dropped.

The reader kept the `$`: `sh $"cuda_1.run"` was read as `sh $cuda_1.run`, a reference to a name the step never sets,
and read CLEAN while bash ran the download. Bash drops the `$` of `$"…"`; dash
keeps it -- so the reader reads both ways: `main`'s fold as it did (dash's), and a fold of its own (`shell_folds.folds`)
bash's, the guard reporting where either reads a run (#2856's union, the review's ruling).

Marks are a letter a `shell:` setting -- unset, `bash`, `sh`, `bash {0}`, `sh {0}` -- R where the guard reports, C where
it reads the step CLEAN: first the job's, then the main pass's. Truth: the #2863 quoting record's kit (eight parents,
two child families): the download runs under the bash parents, 12 of 16; dash keeps the `$`.
"""
import unittest

import shell_reader
import workflow_guard as wg
import workflow_options as wo

SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
FETCH = "curl -fsSLo cuda_1.run https://example.test/cuda_1.run\n"
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


class TestALocaleStringIsTheDoubleQuotedString(unittest.TestCase):

    def test_the_kits_rows_report(self):
        # lo.plain, lo.value, lo.command, lo.c-string: CLEAN on `main`; truth: runs under the bash parents.
        for line in ('sh $"cuda_1.run" || :\n', 'T=cuda_1.run\nsh $"$T" || :\n', '$"sh" cuda_1.run || :\n',
                     'sh -c $"sh cuda_1.run" || :\n'):
            with self.subTest(line=line):
                self.assertEqual(REPORTED, marks(FETCH + line))

    def test_dashs_reading_is_kept_beside_bashs(self):
        # The review seat's rows: dash keeps the `$`, so a file literally named `$NAME` the step downloaded runs under
        # dash -- `main` reported them, and still does: `main`'s fold reads `$"…"` dash's way and the fold of its own
        # bash's (#3048, the union).
        for line in ("curl -fsSLo '$cuda_1.run' URL ; sh $\"cuda_1.run\" || :\n", "curl -fsSLo '$T' URL ; sh $\"T\" || :\n",
                     "curl -fsSLo '$T' URL ; sh $\"T\"\n", "curl -fsSL URL > '$x' ; sh $\"x\"\n"):
            with self.subTest(line=line):
                self.assertEqual(REPORTED, marks(line.replace("URL", "https://example.test/x")))

    def test_the_controls(self):
        # The ANSI-C and double-quoted spellings reported on `main`; a quoted or escaped `$"` is no locale string, and
        # `$$"x"` is the PID glued to `x`: nothing runs.
        for line in ("sh $'cuda_1.run' || :\n", 'sh "cuda_1.run" || :\n'):
            with self.subTest(line=line):
                self.assertEqual(REPORTED, marks(FETCH + line))
        for line in ('echo \\$"cuda_1.run"\n', "echo '$\"x\"'\n", 'sh $$"x" || :\n'):
            with self.subTest(line=line):
                self.assertEqual(CLEAN, marks(FETCH + line))

    def test_the_splitter_reads_each_string_both_ways(self):
        # `main`'s fold keeps the `$` of `$"…"` (dash's reading); the fold `folds` adds where a job met one reads it
        # bash's way: the union. `$'…'` is read bash's way in both, as on `main` (its dash reading is #3115's).
        from shell_folds import _LOCALE

        def words(text):
            return [str(w) for w in shell_reader.statements(text)[0].stages[0].argv]
        self.assertEqual(["sh", "$cuda_1.run"], words('sh $"cuda_1.run"\n'))
        self.assertEqual(["sh", "cuda_1.run"], words("sh $'cuda_1.run'\n"))
        try:
            _LOCALE["on"] = True
            self.assertEqual(["sh", "cuda_1.run"], words('sh $"cuda_1.run"\n'))
            self.assertEqual(["sh", "cuda_1.run"], words("sh $'cuda_1.run'\n"))
            self.assertEqual(["echo", "a b"], words('echo $"a b"\n'))
        finally:
            _LOCALE["on"] = False
        self.assertEqual(["echo", '$"x"'], words("echo '$\"x\"'\n"))



if __name__ == "__main__":
    unittest.main()
