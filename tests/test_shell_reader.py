"""#1733 (COD-C2C): `shell_reader._stage`'s redirect parser, on its own.

`_REDIRECT` (`^(\\d*)(>>|>|<)(.*)$`) matched every `>`/`>>`/`<` token and filed
group(3) as a file read or write with no exception for a target that begins
with `&` -- so `2>&1` was recorded as a WRITE to a file named `&1`,
`2>/dev/null` as a write to `/dev/null`, and `>&2` as a write to `&2`,
contradicting this module's own docstring ("`2>&1` is neither").
`workflow_forms.parse_fetch` then took `stage.writes[-1]` as the download
destination unconditionally, so a stderr redirect on a `curl`/`wget` line
silently replaced (or invented) the file the fetch-and-exec guard thought it
was watching -- see `tests/test_workflow_guard.py` for the guard-level cases
that produced.

This file is the parser's own spec: a redirect whose target begins with `&`
(a file-descriptor duplication or close) is neither a read nor a write, and
`Stage.stdout_writes` is the subset of `Stage.writes` that a shell actually
delivers to file descriptor 1 -- the only one `parse_fetch` may treat as the
destination a step downloaded to.
"""
import unittest

import shell_reader


def stage(script):
    """The one stage of the one statement `script` parses to."""
    stmts = shell_reader.statements(script)
    assert len(stmts) == 1, stmts
    assert len(stmts[0].stages) == 1, stmts[0].stages
    return stmts[0].stages[0]


class TestFdDuplicationIsNeitherReadNorWrite(unittest.TestCase):
    """The module docstring's claim ("`2>&1` is neither"), held true by test."""

    def test_2_greater_ampersand_1_is_recorded_nowhere(self):
        s = stage("curl https://example.test/x -o /tmp/x 2>&1\n")
        self.assertEqual([], s.reads)
        self.assertNotIn("&1", s.writes)
        self.assertEqual([], s.stdout_writes)

    def test_greater_ampersand_2_is_recorded_nowhere(self):
        s = stage("curl https://example.test/x >&2\n")
        self.assertEqual([], s.writes)
        self.assertEqual([], s.reads)
        self.assertEqual([], s.stdout_writes)

    def test_fd_close_is_recorded_nowhere(self):
        s = stage("curl https://example.test/x >&-\n")
        self.assertEqual([], s.writes)


class TestStdoutWrites(unittest.TestCase):
    """`writes` still carries every real file a redirect names (the existing
    consumers -- `workflow_guard.py`'s file-tracking -- stay correct);
    `stdout_writes` is only the ones a shell actually sends to file
    descriptor 1, which is the one `parse_fetch` may call the destination."""

    def test_an_explicit_other_fd_is_a_write_but_not_a_stdout_write(self):
        s = stage("curl https://example.test/x 2>err.log\n")
        self.assertEqual(["err.log"], s.writes)
        self.assertEqual([], s.stdout_writes)

    def test_a_bare_redirect_is_a_stdout_write(self):
        s = stage("curl https://example.test/x > out.log\n")
        self.assertEqual(["out.log"], s.writes)
        self.assertEqual(["out.log"], s.stdout_writes)

    def test_an_explicit_fd_1_redirect_is_a_stdout_write(self):
        s = stage("curl https://example.test/x 1>out.log\n")
        self.assertEqual(["out.log"], s.writes)
        self.assertEqual(["out.log"], s.stdout_writes)

    def test_append_form_is_also_a_stdout_write(self):
        s = stage("curl https://example.test/x >> out.log\n")
        self.assertEqual(["out.log"], s.writes)
        self.assertEqual(["out.log"], s.stdout_writes)


if __name__ == "__main__":
    unittest.main()
