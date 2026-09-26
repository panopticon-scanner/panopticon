import contextlib
import errno
import io
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

from _test_helpers import FakePopen, FakeStream, hard_link_or_skip
import scripts.tools.base as base


class _ImmediateTimer:
    """threading.Timer stand-in that fires its callback synchronously when
    start() is called. Lets timeout paths be exercised without real delays."""

    def __init__(self, interval, function, args=None, kwargs=None):
        self.function = function
        self.args = args or ()
        self.kwargs = kwargs or {}

    def start(self):
        self.function(*self.args, **self.kwargs)

    def cancel(self):
        pass

    @property
    def daemon(self):
        return False

    @daemon.setter
    def daemon(self, value):
        pass


class TestSubprocessFakes(unittest.TestCase):
    def test_inert_python_process_characterizes_read_and_exit(self):
        with subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'abcdef')"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ) as proc:
            self.assertEqual(proc.stdout.read(0), b"")
            self.assertEqual(proc.stdout.read(2), b"ab")
            self.assertEqual(proc.stdout.read(2), b"cd")
            self.assertEqual(proc.stdout.read(2), b"ef")
            self.assertEqual(proc.stdout.read(2), b"")
            self.assertEqual(proc.wait(timeout=5), 0)
            self.assertEqual(proc.poll(), 0)
            proc.kill()
            self.assertEqual(proc.returncode, 0)

    def test_stream_reads_obey_bounds_without_losing_unread_bytes(self):
        stream = FakeStream([b"abc", b"def"])
        self.assertEqual(stream.read(0), b"")
        self.assertEqual(stream.read(2), b"ab")
        self.assertEqual(stream.read(2), b"cd")
        self.assertEqual(stream.read(2), b"ef")
        self.assertEqual(stream.read(2), b"")
        self.assertEqual(stream.read(), b"")
        stream.close()
        self.assertTrue(stream.closed)
        with self.assertRaises(ValueError):
            stream.read(1)

    def test_normal_exit_is_published_and_late_kill_preserves_it(self):
        fake = FakePopen(["tool"], returncode=7)
        self.assertIsNone(fake.returncode)
        fake.kill()
        self.assertEqual(fake.wait(), 7)
        self.assertEqual(fake.returncode, 7)
        observed = FakePopen(["tool"], returncode=3)
        self.assertEqual(observed.poll(), 3)
        observed.kill()
        self.assertEqual(observed.returncode, 3)

    def test_pending_wait_times_out_then_kill_reaps(self):
        fake = FakePopen(["tool"], pending=True)
        self.assertIsNone(fake.poll())
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            fake.wait(timeout=3)
        self.assertEqual((raised.exception.cmd, raised.exception.timeout),
                         (["tool"], 3))
        self.assertIsNone(fake.returncode)
        fake.kill()
        self.assertEqual(fake.wait(), -9)
        self.assertEqual(fake.poll(), -9)

    def test_terminate_publishes_a_stable_exit(self):
        fake = FakePopen(pending=True)
        fake.terminate()
        self.assertEqual(fake.wait(), -15)
        fake.kill()
        self.assertEqual(fake.poll(), -15)

    def test_fake_has_no_signalable_real_pid(self):
        fake = FakePopen(pending=True)
        with mock.patch.object(base.os, "getpgid") as getpgid, \
             mock.patch.object(base.os, "killpg") as killpg:
            base._kill_process_tree(fake)
        getpgid.assert_not_called()
        killpg.assert_not_called()
        self.assertEqual(fake.returncode, -9)


class TestHardLinkFixture(unittest.TestCase):
    def test_links_a_managed_file_and_returns_the_link_path(self):
        with tempfile.TemporaryDirectory() as d:
            target, link = Path(d) / "target.txt", Path(d) / "link.txt"
            target.write_text("inert fixture", encoding="utf-8")
            self.assertEqual(str(link), hard_link_or_skip(target, link))
            self.assertTrue(os.path.samefile(target, link))
            self.assertEqual(2, target.stat().st_nlink)
            self.assertEqual("inert fixture", link.read_text(encoding="utf-8"))

    def test_real_missing_target_and_existing_link_are_errors(self):
        with tempfile.TemporaryDirectory() as d:
            target, link = Path(d) / "target.txt", Path(d) / "link.txt"
            with self.assertRaises(OSError) as missing:
                hard_link_or_skip(target, link)
            self.assertEqual(errno.ENOENT, missing.exception.errno)
            target.write_text("source", encoding="utf-8")
            link.write_text("existing", encoding="utf-8")
            with self.assertRaises(OSError) as existing:
                hard_link_or_skip(target, link)
            self.assertEqual(errno.EEXIST, existing.exception.errno)
            self.assertEqual("existing", link.read_text(encoding="utf-8"))

    def test_only_unsupported_link_operations_skip_or_fail_by_mode(self):
        unsupported = (
            OSError(errno.ENOSYS, "API unavailable"),
            OSError(errno.EOPNOTSUPP, "filesystem unsupported"),
            OSError(errno.ENOTSUP, "operation unsupported"),
            NotImplementedError("API unavailable"),
            AttributeError("link API missing"),
        )
        with tempfile.TemporaryDirectory() as d:
            target, link = Path(d) / "target.txt", Path(d) / "link.txt"
            target.write_text("inert fixture", encoding="utf-8")
            for exc in unsupported:
                for strict, expected in (("", unittest.SkipTest),
                                         ("1", AssertionError)):
                    with self.subTest(error=repr(exc), strict=strict), \
                         mock.patch.dict(os.environ,
                                         {"PANOPTICON_REQUIRE_INTEGRATION": strict}), \
                         mock.patch("os.link", side_effect=exc) as link_api:
                        with self.assertRaises(expected) as raised:
                            hard_link_or_skip(target, link)
                    link_api.assert_called_once_with(str(target), str(link))
                    self.assertIn(type(exc).__name__, str(raised.exception))
                    self.assertIs(exc, raised.exception.__cause__)
                    self.assertFalse(link.exists())

    def test_unexpected_os_errors_propagate_unchanged_in_both_modes(self):
        with tempfile.TemporaryDirectory() as d:
            target, link = Path(d) / "target.txt", Path(d) / "link.txt"
            target.write_text("inert fixture", encoding="utf-8")
            for err in (errno.ENOENT, errno.EEXIST, errno.EACCES,
                        errno.EPERM, errno.EXDEV, errno.EIO):
                for strict in ("", "1"):
                    exc = OSError(err, "setup failure")
                    with self.subTest(errno=err, strict=strict), \
                         mock.patch.dict(os.environ,
                                         {"PANOPTICON_REQUIRE_INTEGRATION": strict}), \
                         mock.patch("os.link", side_effect=exc) as link_api:
                        with self.assertRaises(OSError) as raised:
                            hard_link_or_skip(target, link)
                    link_api.assert_called_once_with(str(target), str(link))
                    self.assertIs(exc, raised.exception)
                    self.assertFalse(link.exists())


class TestBase(unittest.TestCase):
    def test_run_tool_rejects_unsafe_args_or_env(self):
        with self.assertRaises(Exception):
            base.run_tool(["tool", ";", "rm", "-rf", "/"], env={"LD_PRELOAD": "malicious.so"})

    def test_normalize_severity_maps_common_values(self):
        self.assertEqual(base.normalize_severity("critical"), "CRITICAL")
        self.assertEqual(base.normalize_severity("high"), "HIGH")
        self.assertEqual(base.normalize_severity("moderate"), "MEDIUM")
        self.assertEqual(base.normalize_severity("low"), "LOW")
        self.assertEqual(base.normalize_severity("info"), "INFO")

    def test_normalize_severity_maps_the_sarif_level_vocabulary(self):
        # #1229: SARIF is the format this pipeline ingests most, and its
        # `level` vocabulary was entirely absent from SEV_MAP -- so every
        # SARIF-native level fell through to the INFO default.
        self.assertEqual(base.normalize_severity("error"), "HIGH")
        self.assertEqual(base.normalize_severity("warning"), "MEDIUM")
        self.assertEqual(base.normalize_severity("note"), "LOW")
        self.assertEqual(base.normalize_severity("none"), "INFO")

    def test_unmapped_severity_is_reported_not_silently_downgraded(self):
        # #1229 (COD-C1B): this test used to assert `"unknown" -> INFO` and
        # nothing else, codifying the silent downgrade as intended behaviour.
        # An unmapped value means OUR MAP has a gap, not that the tool reported
        # something informational -- so the fallback must say so out loud.
        base._warned_severities.clear()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(base.normalize_severity("blocker"), "INFO")
        self.assertIn("blocker", err.getvalue())
        self.assertIn("INFO", err.getvalue())

    def test_each_unmapped_value_is_reported_once(self):
        # One line per distinct gap; a scanner emitting it on every finding
        # must not drown the run log.
        base._warned_severities.clear()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            for _ in range(5):
                base.normalize_severity("blocker")
            base.normalize_severity("showstopper")
        self.assertEqual(err.getvalue().count("blocker"), 1)
        self.assertIn("showstopper", err.getvalue())

    def test_a_missing_severity_is_not_reported_as_a_mapping_gap(self):
        # None/"" is a tool that said nothing, not a vocabulary we failed to
        # map -- warning about it would be noise on every such finding.
        base._warned_severities.clear()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(base.normalize_severity(None), "INFO")
            self.assertEqual(base.normalize_severity("  "), "INFO")
        self.assertEqual(err.getvalue(), "")

    def test_new_finding_id_increments(self):
        self.assertEqual(base.new_finding_id("PA", 1), "PA-001")
        self.assertEqual(base.new_finding_id("PA", 12), "PA-012")

    def test_omit_none_removes_none_values(self):
        self.assertEqual(base.omit_none({"a": 1, "b": None, "c": ""}), {"a": 1, "c": ""})

    def test_omit_none_returns_empty_dict_when_all_none(self):
        self.assertEqual(base.omit_none({"a": None, "b": None}), {})

    def test_omit_none_preserves_zero_and_false(self):
        self.assertEqual(base.omit_none({"a": 0, "b": False, "c": None}), {"a": 0, "b": False})

    def test_attach_tool_provenance_adds_tool_status(self):
        finding = {"id": "TEST-001"}
        base.attach_tool_provenance(finding, "demo", reasoning="rule-123")
        self.assertEqual(finding["provenance"]["discovered_by"], "tool:demo")
        self.assertEqual(finding["provenance"]["confirmation_status"], "TOOL")
        self.assertEqual(finding["provenance"]["confirmation_reasoning"], "rule-123")

    def test_make_finding_sanitizes_untrusted_title_and_description(self):
        # #run9 SEC-B1C: adapter title/description are built from scanned-repo text
        # (package/gem/crate names, tool messages). make_finding must neutralize
        # control chars (ANSI escapes / NUL / BEL -> terminal + CWE-117 log
        # injection) and collapse the title's whitespace -- automatically for
        # every adapter. #1829 SEC-4277410777 replaced the STRIP with an ESCAPE:
        # a stripped ESC leaves "[31m" reading as literal text a tool wrote,
        # while "\x1b[31m" says what actually arrived.
        import types
        ad = types.SimpleNamespace(prefix="XX", name="demo")
        f = base.make_finding(
            ad, 1, "g1",
            title="evil\x1b[31m pkg\nname\twith   spaces", severity="HIGH",
            category="deps", location={"file": "a", "line_start": 1},
            description="line1\x00\x07\nline2\x1b[0m", impact="", remediation="")
        # title: control chars escaped (the ESC that arms the ANSI code cannot
        # reach a terminal), whitespace collapsed to single spaces, single line
        self.assertEqual(f["title"], r"evil\x1b[31m pkg name with spaces")
        self.assertNotIn("\x1b", f["title"])
        self.assertNotIn("\n", f["title"])
        # description: control chars escaped, line structure preserved
        self.assertEqual(f["description"], "line1\\x00\\x07\nline2\\x1b[0m")
        for ch in ("\x00", "\x07", "\x1b"):
            self.assertNotIn(ch, f["description"])

    def test_make_finding_neutralizes_every_untrusted_field(self):
        # #1829 SEC-4277410777 / #2069: the run-9 fix covered title and
        # description only, so category, location.file, impact, remediation and
        # the tool's own rule id reached the artifact -- and the terminal
        # summary -- with live control bytes in them.
        import types
        ad = types.SimpleNamespace(prefix="XX", name="demo")
        hostile = "ok\x1b[2J\x1b[H** clean **\x07"
        f = base.make_finding(
            ad, 1, "g1", title=hostile, severity="HIGH", category="c\x1b[31m",
            location={"file": "a\x1b[2Kb.py", "line_start": 1},
            description=hostile, impact=hostile, remediation=hostile,
            tool_evidence={"rule_id": "r\x1b[31m1"})
        self.assertEqual(f["category"], r"c\x1b[31m")
        self.assertEqual(f["location"]["file"], r"a\x1b[2Kb.py")
        self.assertEqual(f["location"]["line_start"], 1)
        self.assertEqual(f["impact"], r"ok\x1b[2J\x1b[H** clean **\x07")
        self.assertEqual(f["remediation"], r"ok\x1b[2J\x1b[H** clean **\x07")
        self.assertEqual(f["tool_evidence"]["rule_id"], r"r\x1b[31m1")
        self.assertEqual(f["provenance"]["confirmation_reasoning"], r"r\x1b[31m1")

    def test_make_finding_does_not_mutate_the_caller_s_location(self):
        # The adapter may keep its own dict (osv/eslint build one per hit and
        # reuse the path); neutralizing must not reach back into it.
        import types
        ad = types.SimpleNamespace(prefix="XX", name="demo")
        loc = {"file": "a\x07b.py", "line_start": 2}
        f = base.make_finding(ad, 1, "g1", title="t", severity="HIGH",
                              category="c", location=loc, description="d",
                              impact="", remediation="")
        self.assertEqual(loc["file"], "a\x07b.py")
        self.assertEqual(f["location"]["file"], r"a\x07b.py")


    def test_make_finding_stores_empty_text_not_the_word_None(self):
        # Fix round 1, finding 5: `inert_text(None)` coerces to "None", which
        # would read as a remediation an adapter wrote. `normalize_finding`
        # already guarded with `or ""`; the builder now matches it.
        import types
        ad = types.SimpleNamespace(prefix="XX", name="demo")
        f = base.make_finding(ad, 1, "g1", title="t", severity="HIGH",
                              category=None, location={"file": "a", "line_start": 1},
                              description=None, impact=None, remediation=None)
        for key in ("description", "impact", "remediation", "category"):
            with self.subTest(field=key):
                self.assertEqual("", f[key])


class TestInertText(unittest.TestCase):
    r"""#1829 (SEC-4277410777 / SEC-798292895 / SEC-2200312865, #2069): ONE
    neutralizer for untrusted tool/target text, defined once.

    The tree had two: `base`'s STRIP (control chars deleted) and
    `runio._prompt_safe`'s ESCAPE (control chars rendered `\xNN`). The escape is
    the one that survives as evidence -- a stripped `\x1b[2J` reads as the
    literal text "[2J" a scanner supposedly wrote -- so it is the one that
    stayed, and it lives here because both finding builders do.
    """

    HAZARDS = tuple(chr(o) for o in
                    list(range(0x00, 0x20)) + [0x7f]
                    + list(range(0x80, 0xa0)) + [0x2028, 0x2029])

    def test_the_escape_covers_c0_del_c1_and_the_line_separators(self):
        for ch in self.HAZARDS:
            with self.subTest(codepoint=hex(ord(ch))):
                out = base.inert_text("a%sb" % ch)
                self.assertNotIn(ch, out)
                if ch in base.INERT_KEEP:      # \t and \n: collapsed, not escaped
                    self.assertEqual("a b", out)
                elif ord(ch) < 0x100:
                    self.assertEqual("a\\x%02xb" % ord(ch), out)
                else:
                    self.assertEqual("a\\u%04xb" % ord(ch), out)

    def test_ordinary_and_non_ascii_text_is_untouched(self):
        for text in ("app/db.py:12", "paquete-señal 1.0", "日本語のパッケージ",
                     "a-b_c.d+e~f", "**bold**"):
            with self.subTest(text=text):
                self.assertEqual(text, base.inert_text(text))

    def test_a_label_is_single_line_with_collapsed_whitespace(self):
        self.assertEqual("one two three",
                         base.inert_text("one \t two\n\n   three  "))

    def test_a_body_keeps_its_line_structure_but_not_its_carriage_returns(self):
        # \r is the overwrite vector (it moves the cursor to column 0), so it is
        # escaped even in a body; \n and \t carry the document's own structure.
        self.assertEqual("line1\n\tline2\\x0dline3",
                         base.inert_text("line1\n\tline2\rline3", mode="body"))

    def test_a_path_keeps_every_byte_a_real_filename_may_hold(self):
        # Fix round 1, finding 1: the LABEL form collapses on `str.split()`,
        # which splits on EVERY Unicode space -- so `src/a  b.py`, a macOS
        # `Screen\u202fShot.png`, an NBSP and U+3000 were rewritten, and every
        # consumer that resolves `location.file` on disk or by equality missed
        # the file. A path is escaped and bounded and NOTHING else.
        for name in ("src/a  b.py", "Screen\u202fShot.png", "doc/\xa0nbsp.py",
                     "a\u3000b.py", " leading.py", "trailing.py "):
            with self.subTest(name=name):
                self.assertEqual(name, base.inert_text(name, mode="path"))
        # ...but a control char in a filename is still neutralized, tabs and
        # newlines included: those are not path bytes an operator can read.
        self.assertEqual(r"a\x09b\x0ac\x0dd\x1be.py",
                         base.inert_text("a\tb\nc\rd\x1be.py", mode="path"))

    def test_an_unknown_mode_is_loud(self):
        with self.assertRaises(ValueError):
            base.inert_text("x", mode="paths")

    def test_the_length_bound_cuts_and_MARKS_the_cut(self):
        out = base.inert_text("x" * (base.INERT_TEXT_MAX + 50))
        self.assertEqual(base.INERT_TEXT_MAX + 1, len(out))
        self.assertTrue(out.endswith(base.INERT_CUT), repr(out[-5:]))
        # An escape-expanded value is bound AFTER expansion, so no crafted input
        # can widen the field by a factor of six.
        wide = base.inert_text("\x1b" * (base.INERT_TEXT_MAX + 50))
        self.assertEqual(base.INERT_TEXT_MAX + 1, len(wide))
        self.assertTrue(wide.endswith(base.INERT_CUT))

    def test_the_cut_never_splits_an_escape(self):
        # Fix round 1, finding 4: the slice landed mid-`\x1b` and the marker
        # followed a partial escape (`...AAA\x1…`). No raw byte was re-exposed,
        # but a cut must leave every escape it kept whole.
        for filler, ch in ((1997, "\x1b"), (1996, "\u2028"), (1999, "\x07")):
            with self.subTest(filler=filler, codepoint=hex(ord(ch))):
                out = base.inert_text("A" * filler + ch + "B" * 50)
                self.assertTrue(out.endswith(base.INERT_CUT), repr(out[-8:]))
                body = out[:-len(base.INERT_CUT)]
                self.assertIsNone(
                    re.search(r"\\(x[0-9a-f]?|u[0-9a-f]{0,3})?$", body),
                    "the cut split an escape: %r" % out[-8:])
                self.assertLessEqual(len(out), base.INERT_TEXT_MAX + len(base.INERT_CUT))

    def test_a_value_inside_the_bound_is_never_marked(self):
        out = base.inert_text("x" * base.INERT_TEXT_MAX)
        self.assertEqual("x" * base.INERT_TEXT_MAX, out)

    def test_the_escape_spelling_is_the_one_runio_already_writes(self):
        # #1190 AGT-A1A's `runio._prompt_safe` neutralizes the same hazards for
        # the PROMPT, where a newline breaks the bullet structure and so is
        # escaped too. The SPELLING of an inert byte must not differ between the
        # two surfaces: an operator reading `\x1b[2J` in a prompt and in a
        # finding is reading the same fact. Pinned here rather than shared by
        # import so the driver's prompt path does not pull in the 15-adapter
        # registry that importing `scripts.tools` builds.
        import scripts.phases.runio as runio
        for ch in self.HAZARDS:
            if ch in base.INERT_KEEP:
                continue
            with self.subTest(codepoint=hex(ord(ch))):
                self.assertEqual(runio._prompt_safe("a%sb" % ch),
                                 base.inert_escape("a%sb" % ch))

    def test_a_non_string_is_coerced_rather_than_passed_through(self):
        # Every consumer of these fields expects text; the report schema says so.
        self.assertEqual("7", base.inert_text(7))
        self.assertEqual("None", base.inert_text(None))


class TestRunTool(unittest.TestCase):
    """F-CAL-1: adapter failures must not be undiagnosable — run_tool logs a
    capped stderr excerpt whenever the tool exits outside (0, 1).

    OPS-D1A: stdout capture is bounded so adversarial/large output cannot
    exhaust orchestrator memory.
    """

    def test_returns_stdout_and_rc(self):
        fake = FakePopen(stdout=b"{}", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake):
            out, rc = base.run_tool(["tool", "--x"], timeout=5)
        self.assertEqual((out, rc), (b"{}", 0))

    def test_error_exit_logs_stderr_excerpt(self):
        err = io.StringIO()
        fake = FakePopen(stdout=b"", stderr=b"boom: bad flag", returncode=2)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake), \
             contextlib.redirect_stderr(err):
            out, rc = base.run_tool(["tool"], timeout=5)
        self.assertEqual(rc, 2)
        self.assertIn("boom: bad flag", err.getvalue())
        self.assertIn("tool", err.getvalue())

    def test_stderr_excerpt_is_capped(self):
        err = io.StringIO()
        fake = FakePopen(stdout=b"", stderr=b"x" * 5000, returncode=3)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake), \
             contextlib.redirect_stderr(err):
            base.run_tool(["tool"], timeout=5)
        self.assertLess(len(err.getvalue()), 1500)

    def test_stderr_capture_buffer_is_bounded(self):
        # run-8 COD-A2A: a tool flooding stderr must not accumulate unbounded in
        # memory — the drain buffer is capped like stdout. Feed many chunks so the
        # cap engages mid-stream (a real pipe read returns <=64KB per call).
        chunk = b"e" * (64 * 1024)
        n = (base.MAX_TOOL_STDERR_BYTES // len(chunk)) + 40
        fake = FakePopen(stdout=b"{}", stderr=[chunk] * n, returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake):
            out, err, rc = base.run_tool(["tool"], timeout=5, capture_stderr=True)
        self.assertEqual((out, rc), (b"{}", 0))
        self.assertLessEqual(len(err), base.MAX_TOOL_STDERR_BYTES + len(chunk))
        self.assertLess(len(err), n * len(chunk))

    def test_drain_stderr_async_keeps_the_tail_and_reads_past_the_cap(self):
        # #1510: the shared primitive both capture paths use. Two properties:
        # it keeps reading after the retention cap is reached (or the child
        # blocks on a full pipe and deadlocks the parent), and what it RETAINS
        # is the tail -- the buffer exists to diagnose "exited N", and a scanner
        # puts its error message last.
        cap = 4096
        head, tail = b"H" * 8192, b"TAIL-MARKER"

        class _Stream:
            """A pipe hands back at most one buffer per read, never the whole
            stream -- a fake that returns everything at once leaves the deque
            one chunk long and never exercises eviction."""

            def __init__(self, payload, per_read=4096):
                self._buf = io.BytesIO(payload)
                self._per_read = per_read

            def read(self, n=-1):
                return self._buf.read(min(n, self._per_read) if n > 0 else self._per_read)

        stream = _Stream(head + tail)
        proc = mock.Mock(stderr=stream)
        retained = base.drain_stderr_async(proc, cap=cap)()

        self.assertTrue(retained.endswith(tail), "retention dropped the tail")
        self.assertLessEqual(len(retained), cap + 64 * 1024)
        self.assertLess(len(retained), len(head + tail))
        self.assertEqual(stream.read(), b"", "stream was not drained to EOF")

    def test_findings_exit_one_does_not_log(self):
        err = io.StringIO()
        fake = FakePopen(stdout=b"[]", stderr=b"warnings", returncode=1)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake), \
             contextlib.redirect_stderr(err):
            out, rc = base.run_tool(["tool"], timeout=5)
        self.assertEqual(rc, 1)
        self.assertEqual(err.getvalue(), "")

    def test_passes_through_cwd_and_env(self):
        rec = mock.Mock(side_effect=lambda *a, **kw: FakePopen(*a, **kw))
        with mock.patch("scripts.tools.base.subprocess.Popen", rec):
            base.run_tool(["t"], timeout=7, cwd="/x", env={"A": "1"})
        rec.assert_called_once_with(["t"], stdout=base.subprocess.PIPE,
                                    stderr=base.subprocess.PIPE,
                                    cwd="/x", env={"A": "1"})

    def test_timeout_expired_propagates(self):
        fake = FakePopen(["t"], stdout=b"x", stderr=b"", pending=True)
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake), \
             mock.patch("scripts.tools.base.threading.Timer", _ImmediateTimer):
            with self.assertRaises(base.subprocess.TimeoutExpired):
                base.run_tool(["t"], timeout=5)
        self.assertEqual(fake.returncode, -9)
        self.assertTrue(fake.stdout.closed)
        self.assertTrue(fake.stderr.closed)

    def test_output_exceeds_cap_truncates_with_marker_and_nonzero_rc(self):
        err = io.StringIO()
        with mock.patch.object(base, "MAX_TOOL_OUTPUT_BYTES", 1024):
            chunks = [b"x" * 512, b"x" * 512, b"x" * 512]
            fake = FakePopen(stdout=chunks, stderr=b"", pending=True)
            with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake), \
                 contextlib.redirect_stderr(err):
                out, rc = base.run_tool(["tool"], timeout=5)
        marker = (
            b"\n\n[TRUNCATED by panopticon: output exceeded 1024 byte limit; "
            b"only the first 1024 bytes were retained]\n"
        )
        self.assertTrue(out.startswith(b"x" * 1024))
        self.assertTrue(out.endswith(marker))
        self.assertEqual(len(out), 1024 + len(marker))
        self.assertNotEqual(rc, 0)
        self.assertIn("exceeded 1024 byte limit", err.getvalue())

    def test_single_large_read_is_capped_and_late_kill_keeps_exit_status(self):
        fake = FakePopen(stdout=b"z" * 200_000, returncode=4)
        self.assertEqual(fake.poll(), 4)
        with mock.patch.object(base, "MAX_TOOL_OUTPUT_BYTES", 1024), \
             mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake), \
             contextlib.redirect_stderr(io.StringIO()):
            out, rc = base.run_tool(["tool"], timeout=5)
        self.assertEqual(out[:1024], b"z" * 1024)
        self.assertIn(b"[TRUNCATED by panopticon", out)
        self.assertEqual(rc, 4)
        self.assertEqual(fake.returncode, 4)

    def test_concurrent_stdout_stderr_no_deadlock(self):
        # A child that fills the stderr pipe before writing stdout would
        # deadlock if run_tool read stdout to EOF before touching stderr.
        script = textwrap.dedent("""
            import sys
            sys.stderr.write('e' * 200000)
            sys.stderr.flush()
            sys.stdout.write('done')
            sys.stdout.flush()
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py",
                                          delete=False) as fh:
            fh.write(script)
            path = fh.name
        try:
            out, rc = base.run_tool([sys.executable, path], timeout=10)
            self.assertEqual(rc, 0)
            self.assertIn(b"done", out)
        finally:
            os.unlink(path)

    def test_strip_ansi_removes_csi_sequences(self):
        self.assertEqual(base.strip_ansi(b"\x1b[32mhi\x1b[0m"), b"hi")
        self.assertEqual(base.strip_ansi(b"\x1b[?25l\x1b[2Kx"), b"x")

    def test_strip_ansi_leaves_plain_bytes_unchanged(self):
        self.assertEqual(base.strip_ansi(b'{"a": 1}'), b'{"a": 1}')

    def test_parse_json_bytes_plain_json(self):
        self.assertEqual(base.parse_json_bytes(b'{"a": 1}'), {"a": 1})
        self.assertEqual(base.parse_json_bytes(b'[1, 2]'), [1, 2])

    def test_parse_json_bytes_strips_ansi_progress_preamble(self):
        # pip-audit-style ANSI spinner + progress text before the JSON payload
        raw = (b"\x1b[?25l\x1b[32m-\x1b[0m Collecting inputs\r\x1b[2K"
               b'{"dependencies": [], "fixes": []}\n')
        self.assertEqual(base.parse_json_bytes(raw),
                         {"dependencies": [], "fixes": []})

    def test_parse_json_bytes_raises_on_non_json(self):
        with self.assertRaises(ValueError):
            base.parse_json_bytes(b"not json at all")


class TestReadCappedReport(unittest.TestCase):
    """#run8 OPS-D1A: on-disk scanner reports (dependency-check JSON, roslyn
    SARIF) bypass run_tool's stdout cap, so read_capped_report re-imposes it."""

    def _write(self, data):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.addCleanup(os.remove, path)
        return path

    def test_reads_report_within_cap(self):
        path = self._write(b'{"ok": true}')
        self.assertEqual(base.read_capped_report(path, cap=1024), b'{"ok": true}')

    def test_reads_report_exactly_at_cap(self):
        path = self._write(b"x" * 10)
        self.assertEqual(base.read_capped_report(path, cap=10), b"x" * 10)

    def test_oversize_report_fails_closed(self):
        path = self._write(b"x" * 11)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertIsNone(base.read_capped_report(path, cap=10))
        self.assertIn("exceeds", err.getvalue())

    def test_does_not_slurp_more_than_cap_into_memory(self):
        # The read is bounded to cap+1 bytes regardless of the file's true size,
        # so a pathologically large report can't blow up memory before the check.
        m = mock.mock_open(read_data=b"y" * 5000)
        with mock.patch.object(base, "open", m), \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertIsNone(base.read_capped_report("big.json", cap=10))
        m().read.assert_called_once_with(11)   # cap + 1, never the full file

    def test_missing_report_returns_none(self):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertIsNone(base.read_capped_report("/no/such/report.json"))
        self.assertIn("cannot read report", err.getvalue())


class TestWriteTimeOutputCap(unittest.TestCase):
    """#1576 (run-13 OPS-3272189615 / OPS-2007447947): a scanner that writes
    its OWN report bypassed every bound until it had finished writing.

    read_capped_report's 50 MiB ceiling is a READ-time bound on a write that
    already happened: by the time it refuses the report, the temp volume is
    already full and every concurrent scan on that worker is already in
    trouble. run_tool now takes a path to watch while the child runs and kills
    it the moment its output crosses the cap.
    """

    def _writer(self, target, chunks=100, size=65536, pause=0.02):
        """argv for a child that writes `chunks` x `size` bytes into `target`."""
        code = textwrap.dedent("""
            import os, sys, time
            d = sys.argv[1]
            for i in range(%d):
                with open(os.path.join(d, "part%%04d" %% i), "wb") as fh:
                    fh.write(b"x" * %d)
                time.sleep(%r)
        """ % (chunks, size, pause))
        return [sys.executable, "-c", code, target]

    def test_a_scanner_that_overruns_the_cap_is_killed(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report")
            os.makedirs(out)
            err = io.StringIO()
            with mock.patch.object(base, "OUTPUT_WATCH_INTERVAL", 0.05), \
                    contextlib.redirect_stderr(err):
                with self.assertRaises(base.OutputCapExceeded):
                    base.run_tool(self._writer(out), timeout=60,
                                  watch_path=out, watch_cap=256 * 1024,
                                  start_new_session=True)
            written = base._output_size(out)
        # Killed while writing, not after: the tree never reached the 6.4 MB
        # the child wanted to write.
        self.assertLess(written, 3 * 1024 * 1024)
        self.assertIn("write-time output cap", err.getvalue())

    def test_a_scanner_under_the_cap_is_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report")
            os.makedirs(out)
            with mock.patch.object(base, "OUTPUT_WATCH_INTERVAL", 0.05):
                stdout, rc = base.run_tool(
                    self._writer(out, chunks=2, size=1024, pause=0),
                    timeout=60, watch_path=out, watch_cap=1024 * 1024)
        self.assertEqual(rc, 0)
        self.assertEqual(stdout, b"")

    def test_an_absent_watch_path_is_simply_zero(self):
        # roslyn hands the SARIF path before the scanner has created it.
        self.assertEqual(base._output_size("/no/such/path/at/all"), 0)

    def test_output_size_sums_a_tree_without_following_links(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "a", "b"))
            with open(os.path.join(d, "a", "b", "f"), "wb") as fh:
                fh.write(b"x" * 1000)
            with open(os.path.join(d, "top"), "wb") as fh:
                fh.write(b"y" * 24)
            outside = os.path.join(d, "a", "escape")
            os.symlink("/etc", outside)      # never walked through
            self.assertGreaterEqual(base._output_size(d), 1024)
            self.assertLess(base._output_size(d), 10_000)

    def test_the_write_cap_agrees_with_the_read_cap(self):
        # Two bounds on the same report: a report the reader would refuse is
        # not worth letting the scanner finish writing.
        import inspect
        sig = inspect.signature(base.run_tool)
        self.assertEqual(sig.parameters["watch_cap"].default,
                         base.MAX_TOOL_OUTPUT_BYTES)


class _AlreadyExceeded:
    """_OutputSizeWatcher stand-in that has already seen the cap blow.

    Lets the "both caps bound" control path be exercised without racing a real
    0.5 s poll against a stdout flood that takes microseconds.
    """

    def __init__(self, proc, path, cap, label):
        self.exceeded = True
        self.size = cap + 1

    def start(self):
        pass

    def stop(self):
        pass


class TestBothCapsBinding(unittest.TestCase):
    """#1576 fix round 1: the stdout-truncation early return skipped the
    write-time raise.

    `if truncated: return stdout + marker, rc` sits inside the try, so it ran
    the finally and left the function BEFORE the OutputCapExceeded check. A
    scanner that blew the stdout cap and the report cap therefore handed its
    adapter `(partial output, -9)` -- a partial result from a scan that was
    killed -- and the adapter's `except OutputCapExceeded` never fired.
    """

    def test_the_write_cap_still_raises_when_stdout_also_truncated(self):
        flood = [sys.executable, "-c",
                 "import sys; sys.stdout.buffer.write(b'x' * 200000)"]
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(base, "_OutputSizeWatcher", _AlreadyExceeded), \
                    mock.patch.object(base, "MAX_TOOL_OUTPUT_BYTES", 1024), \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(base.OutputCapExceeded):
                    base.run_tool(flood, timeout=30, watch_path=d,
                                  watch_cap=64)

    def test_truncation_alone_still_returns_its_partial_output(self):
        # The raise must not swallow the plain truncation path: no watch_path,
        # no watcher, same marker contract as before.
        flood = [sys.executable, "-c",
                 "import sys; sys.stdout.buffer.write(b'x' * 200000)"]
        with mock.patch.object(base, "MAX_TOOL_OUTPUT_BYTES", 1024), \
                contextlib.redirect_stderr(io.StringIO()):
            stdout, _rc = base.run_tool(flood, timeout=30)
        self.assertIn(b"[TRUNCATED by panopticon", stdout)


@unittest.skipIf(os.name != "posix", "process groups are POSIX-only")  # strict-skip-exempt: process-group signals exist only on POSIX
class TestTimeoutKillReachesTheWholeGroup(unittest.TestCase):
    """#1576 fix round 1: the timeout watchdog killed only the direct child.

    A scanner launched through a shell wrapper leaves the real worker as a
    grandchild holding the inherited stdout pipe. proc.kill() reaps the
    wrapper and nothing else, so the parent's read blocks on a pipe the orphan
    still owns and `timeout=` is not a bound at all -- measured at 60.5 s for a
    2-second timeout. The size watcher already killed the process GROUP; the
    timeout path has to as well.
    """

    # The wrapper waits on its own child, so both are alive when the deadline
    # lands and both must die for the pipe to reach EOF.
    _WRAPPER = textwrap.dedent("""
        import subprocess, sys
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(15)"])
        with open(sys.argv[1], "w") as fh:
            fh.write(str(child.pid))
        child.wait()
    """)

    def _grandchild_pid(self, pidfile, deadline=5.0):
        end = time.time() + deadline
        while time.time() < end:
            try:
                with open(pidfile, encoding="utf-8") as fh:
                    text = fh.read().strip()
            except OSError:
                text = ""
            if text:
                return int(text)
            time.sleep(0.05)
        self.fail("wrapper never reported its grandchild pid")

    def test_a_grandchild_does_not_outlive_the_deadline(self):
        with tempfile.TemporaryDirectory() as d:
            pidfile = os.path.join(d, "pid")
            cmd = [sys.executable, "-c", self._WRAPPER, pidfile]
            started = time.time()
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(subprocess.TimeoutExpired):
                    base.run_tool(cmd, timeout=1, start_new_session=True)
            elapsed = time.time() - started
            pid = self._grandchild_pid(pidfile, deadline=0.5)
        # Without the group kill the orphan holds the pipe for its full 15s.
        self.assertLess(elapsed, 8, "the read blocked on the orphan's pipe")
        end = time.time() + 3
        while time.time() < end:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            except PermissionError:       # reaped and the pid was recycled
                return
            time.sleep(0.05)
        self.fail("grandchild %d survived the timeout kill" % pid)


class TestScratchCwd(unittest.TestCase):
    """#1877: the one helper every adapter uses to name its own working
    directory, so "no cwd" can never mean "the target mount" again."""

    def test_yields_an_existing_empty_directory(self):
        with base.scratch_cwd("unit-test-cwd-") as scratch:
            self.assertTrue(os.path.isdir(scratch))
            self.assertEqual(os.listdir(scratch), [])
            self.assertTrue(os.path.basename(scratch).startswith("unit-test-cwd-"))

    def test_the_directory_is_removed_on_the_way_out(self):
        with base.scratch_cwd("unit-test-cwd-") as scratch:
            pass
        self.assertFalse(os.path.exists(scratch))

    def test_the_directory_is_removed_when_the_body_raises(self):
        seen = {}
        with self.assertRaises(ValueError):
            with base.scratch_cwd("unit-test-cwd-") as scratch:
                seen["path"] = scratch
                raise ValueError("boom")
        self.assertFalse(os.path.exists(seen["path"]))

    def test_a_scanner_that_writes_into_the_scratch_does_not_break_cleanup(self):
        # The #1646 F3 lesson, now the helper's: the scratch exists PRECISELY
        # to be where a scanner's stray writes land, so `rmdir` would raise
        # `Directory not empty` and turn a successful scan into a failed one.
        with base.scratch_cwd("unit-test-cwd-") as scratch:
            os.mkdir(os.path.join(scratch, "junk-dir"))
            with open(os.path.join(scratch, "junk-dir", "spill"), "w") as fh:
                fh.write("x")
        self.assertFalse(os.path.exists(scratch))


if __name__ == "__main__":
    unittest.main()
