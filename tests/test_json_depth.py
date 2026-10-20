"""#2959: the JSON depth bound -- one primitive, `tolerant_json.depth_checked`,
run by every decoder of an agent's or a scanner's document BEFORE it parses.

Nesting past the interpreter's stack used to end the run in a RecursionError
(the codec at 1,000 levels on 3.11, `redact_tree` on 3.12+): a traceback, status
1 and no report. Past MAX_JSON_DEPTH a document now reads exactly as a malformed
one does, so it lands on the disclosure each reader already makes for those.
"""
import json
import os
import shutil
import tempfile
import unittest

import pytest

import scripts.evidence as evidence
import scripts.group_runner as group_runner
import scripts.phases.runio as runio
import scripts.setup_flow as setup_flow
import scripts.synth.artifacts as artifacts
import scripts.tool_capture as tool_capture
import scripts.tolerant_json as tolerant_json
import scripts.tools.base as tools_base
from scripts.tools.legacy_sarif import LegacySarifAdapter
from tests.test_shell_reader import LinearGrowth

TOO_DEEP = "nested deeper than 64 levels"
CRASHED_MAIN = 100_000       # past every supported interpreter's codec


def nest(depth, leaf="1"):
    return "[" * depth + leaf + "]" * depth


def findings_file(depth):
    return '{"findings": [{"code": "COD-A1A", "title": "t", "extra": %s}]}' % nest(depth)


def sarif(depth):
    return ('{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "semgrep"}}, "results": [], '
            '"properties": {"deep": %s}}]}' % nest(depth))


class TestTheBound(unittest.TestCase):
    def test_the_bound_is_kept_and_one_level_past_it_is_refused(self):
        self.assertEqual(64, tolerant_json.MAX_JSON_DEPTH)
        for kept in (nest(64), nest(64).encode(), '{"a": ' * 64 + "1" + "}" * 64):
            self.assertEqual(kept, tolerant_json.depth_checked(kept))
        for refused in (nest(65), nest(65).encode(), '{"a": ' * 65 + "1" + "}" * 65, nest(CRASHED_MAIN)):
            with self.assertRaises(json.JSONDecodeError) as caught:
                tolerant_json.depth_checked(refused)
            # A ValueError, which is what every caller already catches for a malformed document.
            self.assertEqual(TOO_DEEP, caught.exception.msg)

    def test_brackets_inside_a_string_are_not_nesting(self):
        for value in ("[" * 10_000, '"' + "[" * 10_000, "\\" + "{" * 100, '\\"' + "[" * 100):
            text = json.dumps({"title": value, "x": json.loads(nest(60))})
            self.assertEqual(text, tolerant_json.depth_checked(text))

    def test_a_string_ends_only_at_an_unescaped_quote(self):
        # An escaped backslash closes nothing early: the quote after it ends the string, so the brackets that
        # follow are structure, and 65 of them are refused.
        text = '{"t": "\\\\", "u": %s}' % nest(64)
        with self.assertRaises(json.JSONDecodeError):
            tolerant_json.depth_checked(text)

    def test_the_tolerant_reader_digs_no_object_out_of_a_too_deep_reply(self):
        reply = '{"findings": [{"location": {"file": "a.py"}, "extra": %s}]}' % nest(100)
        for wrapped in (reply, "Here you go:\n" + reply + "\nDone.", "```json\n" + reply + "\n```"):
            with self.subTest(wrapped=wrapped[:12]):
                with self.assertRaises(json.JSONDecodeError) as caught:
                    tolerant_json.loads(wrapped)
                self.assertEqual(TOO_DEEP, caught.exception.msg)
                self.assertEqual(TOO_DEEP, tolerant_json.unparsed_reason(wrapped))
        # #2531 holds: deep PROSE braces before a real bundle still give the bundle up.
        bundle = {"verdicts": []}
        self.assertEqual(bundle, tolerant_json.loads("{" * 256 + "x" + "}" * 256 + json.dumps(bundle)))
        self.assertEqual("fence- and prose-wrapped both tried", tolerant_json.unparsed_reason("sorry"))


class TestTheScanIsLinear(LinearGrowth, unittest.TestCase):
    """#2959 review: an unterminated string full of escaped quotes -- a TRUNCATED reply, a scanner killed at its
    timeout -- made the scan quadratic: `finditer` stepped one character past the unclosed quote and each later
    `\\"` opened a "string" that rescanned to the end (64 KB took 5.8 s; at the 16 MiB cap, hours). A lone quote
    now ends the scan: what follows is inside that string, and the parse refuses it as malformed anyway."""

    @staticmethod
    def truncated(n):
        return '{"findings": [{"snippet": "' + 'x=\\"a\\";' * n

    @pytest.mark.serial
    def test_an_unterminated_string_of_escaped_quotes_scans_in_linear_time(self):
        for kind in (str, bytes):
            with self.subTest(kind=kind.__name__):
                make = self.truncated if kind is str else (lambda n: self.truncated(n).encode())
                self.assert_linear_growth(2_000, make, lambda _n, scanned: None,
                                          parser=tolerant_json.depth_checked)
                with self.assertRaises(json.JSONDecodeError):
                    json.loads(tolerant_json.depth_checked(make(10)))

    def test_its_refusal_is_a_named_decode_error(self):
        with self.assertRaises(tolerant_json.TooDeep) as caught:
            tolerant_json.depth_checked(nest(65))
        self.assertIsInstance(caught.exception, json.JSONDecodeError)


class TestEveryDecoderAppliesIt(unittest.TestCase):
    """One row per decoder of an agent's or a scanner's document. 65 levels reads as malformed, observably;
    100,000 raises no RecursionError (main: a traceback on every interpreter)."""

    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)

    def _file(self, name, text):
        path = os.path.join(self.d, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def _rows(self):
        def raises_too_deep(call):
            try:
                call()
            except ValueError as exc:
                return TOO_DEEP in str(exc)
            return False

        def legacy_verdict(depth):
            path = self._file(os.path.join("verdicts-%d" % depth, "q-0001.json"),
                              '{"finding_id": "F1", "verdict": "CONFIRMED", "x": %s}' % nest(depth))
            _out, unloadable = evidence.load_verdicts_detailed(os.path.dirname(path))
            return [row["file"] for row in unloadable] == ["q-0001.json"]

        def setup_proposal(depth):
            result = setup_flow.ingest_proposal(
                repo=self.d, proposal_path=self._file("proposal-%d.json" % depth, '{"x": %s}' % nest(depth)))
            return result["ok"] is False and any(TOO_DEEP in e for e in result["errors"])

        return {
            "runio._load_json reads it as unreadable": lambda depth: runio._load_json(
                self._file("a-%d.json" % depth, nest(depth))) is None,
            "artifacts.read_json raises the bound": lambda depth: raises_too_deep(
                lambda: artifacts.read_json(self._file("b-%d.json" % depth, nest(depth)))),
            "evidence.load_json_tolerant raises the bound": lambda depth: raises_too_deep(
                lambda: evidence.load_json_tolerant(nest(depth))),
            "tools.base.parse_json_bytes raises the bound": lambda depth: raises_too_deep(
                lambda: tools_base.parse_json_bytes(nest(depth).encode())),
            "legacy SARIF parse raises the bound": lambda depth: raises_too_deep(
                lambda: LegacySarifAdapter("semgrep").parse(sarif(depth).encode(), "g")),
            "group_runner.entry_is_done is not done": lambda depth: group_runner.entry_is_done(
                self._file("findings-g-COD-%d.json" % depth, findings_file(depth))) is False,
            "tool_capture leaves the capture untouched": lambda depth: tool_capture._annotate_scanned_files(
                sarif(depth), 3) == sarif(depth),
            "tool_capture redacts it as text": lambda depth: tool_capture._redact_capture(
                "x2959-probe", sarif(depth).encode()) == sarif(depth).encode(),
            "evidence.load_verdicts_detailed lists it unloadable": legacy_verdict,
            "setup_flow.ingest_proposal refuses it": setup_proposal,
        }

    def test_one_level_past_the_bound_reads_as_malformed(self):
        for name, malformed in self._rows().items():
            with self.subTest(decoder=name):
                self.assertTrue(malformed(65))

    def test_no_depth_escapes_as_a_recursion_error(self):
        for name, malformed in self._rows().items():
            with self.subTest(decoder=name):
                self.assertTrue(malformed(CRASHED_MAIN))

    def test_the_bound_itself_is_read_as_before(self):
        self.assertEqual(json.loads(nest(64)), runio._load_json(self._file("ok.json", nest(64))))
        self.assertEqual(json.loads(nest(64)), artifacts.read_json(self._file("ok2.json", nest(64))))
        self.assertTrue(group_runner.entry_is_done(self._file("findings-g-COD.json", findings_file(61))))  # 3 + 61
        self.assertNotEqual(sarif(60), tool_capture._annotate_scanned_files(sarif(60), 3))         # 4 + 60
