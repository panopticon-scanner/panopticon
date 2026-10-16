"""#3048: a locale string `$"..."` is read as bash reads it, the double-quoted string (translated), the `$` dropped.

The reader kept the `$`: `sh $"cuda_1.run"` was read as `sh $cuda_1.run`, a reference to a name the step never sets,
and read CLEAN while bash ran the download. `shell_split._split` now drops a `$` right before a `"`, so the double
quote opens as bash reads it -- the posture `$'…'` already has: dash keeps the `$` and runs nothing, a price under `sh`.

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

    def test_the_controls(self):
        # The ANSI-C and double-quoted spellings reported on `main`; a quoted or escaped `$"` is no locale string, and
        # `$$"x"` is the PID glued to `x`: nothing runs.
        for line in ("sh $'cuda_1.run' || :\n", 'sh "cuda_1.run" || :\n'):
            with self.subTest(line=line):
                self.assertEqual(REPORTED, marks(FETCH + line))
        for line in ('echo \\$"cuda_1.run"\n', "echo '$\"x\"'\n", 'sh $$"x" || :\n'):
            with self.subTest(line=line):
                self.assertEqual(CLEAN, marks(FETCH + line))

    def test_the_splitter_drops_the_dollar(self):
        def words(text):
            return [str(w) for w in shell_reader.statements(text)[0].stages[0].argv]
        self.assertEqual(["sh", "cuda_1.run"], words('sh $"cuda_1.run"\n'))
        self.assertEqual(["echo", "a b"], words('echo $"a b"\n'))
        self.assertEqual(["echo", '$"x"'], words("echo '$\"x\"'\n"))


if __name__ == "__main__":
    unittest.main()
