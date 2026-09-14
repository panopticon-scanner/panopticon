import io
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.kimi_guard_hook as guard


def _write(path, body):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(body, fh)
    return path


class GuardCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = os.path.realpath(self.tmp.name)
        self.inside = os.path.join(root, "cell", "a.py")
        self.outside = os.path.join(root, "elsewhere", "b.py")
        for p in (self.inside, self.outside):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("")
        self.scope_path = _write(os.path.join(root, "read-scope.json"),
                                 {"entry-1": {"files": [self.inside], "dirs": [], "reads": []}})
        self.allowlist_path = _write(os.path.join(root, "write-allowlist.json"), [self.inside])
        self.env = {guard.ENV_ENTRY_ID: "entry-1"}

    def read(self, tool, **tool_input):
        return guard.adjudicate({"tool_name": tool, "tool_input": tool_input,
                                 "cwd": self.tmp.name},
                                "read", self.scope_path, env=self.env)

    def write(self, tool, **tool_input):
        return guard.adjudicate({"tool_name": tool, "tool_input": tool_input},
                                "write", self.allowlist_path, env=self.env)


class TestReads(GuardCase):
    def test_an_in_scope_read_is_allowed(self):
        self.assertEqual(self.read("Read", path=self.inside), (True, ""))

    def test_an_out_of_scope_read_is_denied_and_names_the_entry(self):
        allow, reason = self.read("Read", path=self.outside)
        self.assertFalse(allow)
        self.assertIn("outside your cell's scope", reason)
        self.assertIn("entry-1", reason)

    def test_a_grep_of_an_in_scope_file_is_allowed(self):
        self.assertEqual(self.read("Grep", pattern="x", path=self.inside), (True, ""))

    def test_a_grep_over_a_directory_is_denied(self):
        allow, reason = self.read("Grep", pattern="x", path=os.path.dirname(self.inside))
        self.assertFalse(allow)
        self.assertIn("directory", reason)

    def test_a_glob_is_denied_in_a_confined_cell(self):
        allow, reason = self.read("Glob", pattern="*.py", path=os.path.dirname(self.inside))
        self.assertFalse(allow)
        self.assertIn("Glob", reason)

    def test_a_pathless_grep_adjudicates_the_working_directory(self):
        # R-P5-7, kimi shape: a pathless Grep defaults to the payload's cwd,
        # which is a directory -- denied unless the entry is dir-scoped.
        allow, reason = self.read("Grep", pattern="x")
        self.assertFalse(allow)

    def test_a_directory_scoped_entry_reads_under_its_dir(self):
        root = os.path.realpath(self.tmp.name)
        scope = _write(os.path.join(root, "dirs-scope.json"),
                       {"scan": {"files": [], "dirs": [os.path.dirname(self.inside)], "reads": []}})
        allow, _ = guard.adjudicate(
            {"tool_name": "Read", "tool_input": {"path": self.inside}},
            "read", scope, env={guard.ENV_ENTRY_ID: "scan"})
        self.assertTrue(allow)
        allow, reason = guard.adjudicate(
            {"tool_name": "Read", "tool_input": {"path": self.outside}},
            "read", scope, env={guard.ENV_ENTRY_ID: "scan"})
        self.assertFalse(allow)

    def test_an_unbound_session_is_denied(self):
        allow, reason = guard.adjudicate(
            {"tool_name": "Read", "tool_input": {"path": self.inside}},
            "read", self.scope_path, env={})
        self.assertFalse(allow)
        self.assertIn("not bound", reason)

    def test_an_entry_the_scope_does_not_name_is_denied(self):
        allow, reason = guard.adjudicate(
            {"tool_name": "Read", "tool_input": {"path": self.inside}},
            "read", self.scope_path, env={guard.ENV_ENTRY_ID: "ghost"})
        self.assertFalse(allow)
        self.assertIn("ghost", reason)

    def test_a_malformed_scope_file_fails_closed(self):
        with open(self.scope_path, "w", encoding="utf-8") as fh:
            fh.write("not json")
        allow, reason = self.read("Read", path=self.inside)
        self.assertFalse(allow)
        self.assertIn("unavailable", reason)

    def test_a_scope_with_a_bad_shape_fails_closed(self):
        _write(self.scope_path, {"entry-1": {"files": "not-a-list"}})
        allow, reason = self.read("Read", path=self.inside)
        self.assertFalse(allow)
        self.assertIn("malformed", reason)

    def test_an_unresolvable_path_is_denied(self):
        allow, _ = self.read("Read", path="")
        self.assertFalse(allow)
        allow, _ = self.read("Read")
        self.assertFalse(allow)


class TestWrites(GuardCase):
    def test_a_write_to_the_declared_out_file_is_allowed(self):
        self.assertEqual(self.write("Write", path=self.inside, content="{}"), (True, ""))

    def test_a_write_elsewhere_is_denied(self):
        allow, reason = self.write("Write", path=self.outside, content="{}")
        self.assertFalse(allow)
        self.assertIn("declared out_file", reason)

    def test_an_edit_elsewhere_is_denied(self):
        allow, _ = self.write("Edit", path=self.outside)
        self.assertFalse(allow)

    def test_a_symlinked_target_is_denied(self):
        link = os.path.join(os.path.dirname(self.inside), "link.json")
        os.symlink(self.inside, link)
        allow, reason = self.write("Write", path=link, content="{}")
        self.assertFalse(allow)
        self.assertIn("symlink", reason)

    def test_a_malformed_allowlist_fails_closed(self):
        with open(self.allowlist_path, "w", encoding="utf-8") as fh:
            fh.write("not json")
        allow, reason = self.write("Write", path=self.inside, content="{}")
        self.assertFalse(allow)
        self.assertIn("unavailable", reason)

    def test_a_non_string_path_is_denied(self):
        allow, _ = self.write("Write", path=42)
        self.assertFalse(allow)


class TestMain(unittest.TestCase):
    def _main(self, argv, payload, env):
        stdin = io.StringIO(json.dumps(payload))
        out = io.StringIO()
        with mock.patch("sys.stdin", stdin), \
             mock.patch("sys.stdout", out):
            code = guard.main(argv, env=env)
        return code, out.getvalue()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = os.path.realpath(self.tmp.name)
        self.inside = os.path.join(root, "a.py")
        with open(self.inside, "w", encoding="utf-8") as fh:
            fh.write("")
        self.scope_path = _write(os.path.join(root, "read-scope.json"),
                                 {"entry-1": {"files": [self.inside], "dirs": [], "reads": []}})

    def test_a_denial_prints_the_json_protocol_and_exits_zero(self):
        # Kimi reads a non-zero exit as fail-OPEN, so every refusal must be
        # a printed deny on stdout with exit code 0.
        code, out = self._main(
            ["read", self.scope_path],
            {"tool_name": "Read", "tool_input": {"path": "/etc/hostname"}},
            {guard.ENV_ENTRY_ID: "entry-1"})
        self.assertEqual(code, 0)
        body = json.loads(out)
        decision = body["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "deny")
        self.assertEqual(decision["hookEventName"], "PreToolUse")
        self.assertTrue(decision["permissionDecisionReason"])

    def test_an_allow_is_silent_and_exits_zero(self):
        code, out = self._main(
            ["read", self.scope_path],
            {"tool_name": "Read", "tool_input": {"path": self.inside}},
            {guard.ENV_ENTRY_ID: "entry-1"})
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_a_crash_in_adjudication_prints_a_deny_never_a_traceback(self):
        # Kimi hooks fail open on a script error, so the hook must never let
        # one escape: a crashed guard is a printed deny, not an open door.
        with mock.patch.object(guard, "adjudicate", side_effect=RuntimeError("boom")):
            code, out = self._main(
                ["read", self.scope_path],
                {"tool_name": "Read", "tool_input": {"path": self.inside}},
                {guard.ENV_ENTRY_ID: "entry-1"})
        self.assertEqual(code, 0)
        self.assertIn("deny", out)
        self.assertIn("crashed", out)

    def test_malformed_payload_and_bad_argv_are_tolerantly_allowed(self):
        with mock.patch("sys.stdin", io.StringIO("not json")):
            self.assertEqual(guard.main(["read", self.scope_path], env={}), 0)
        code, out = self._main(["read"], {"tool_name": "Read"}, {})
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        code, out = self._main(["bogus", self.scope_path], {"tool_name": "Read"}, {})
        self.assertEqual(code, 0)
        self.assertEqual(out, "")

    def test_the_env_overlay_supplies_the_data_path_when_argv_omits_it(self):
        # The baked-in argv path wins; the env var is the fallback. main()
        # requires argv [mode, path], so exercise the resolver directly.
        self.assertEqual(guard._data_path("", guard.ENV_READ_SCOPE,
                                          {guard.ENV_READ_SCOPE: "/s.json"}), "/s.json")
        self.assertEqual(guard._data_path("/baked.json", guard.ENV_READ_SCOPE,
                                          {guard.ENV_READ_SCOPE: "/s.json"}), "/baked.json")


if __name__ == "__main__":
    unittest.main()


class TestReadMediaFileIsScopeChecked(unittest.TestCase):
    """I1: ReadMediaFile is a READ tool. The hook did not know it, so it
    returned (True, "") -- an unconditional read of any file on the machine,
    from an entry whose Read was confined."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.inside = os.path.realpath(os.path.join(self.tmp.name, "in.png"))
        self.outside = os.path.realpath(os.path.join(self.tmp.name, "out.png"))
        for path in (self.inside, self.outside):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("")
        self.scope = os.path.join(self.tmp.name, "read-scope.json")
        with open(self.scope, "w", encoding="utf-8") as fh:
            json.dump({"e1": {"files": [self.inside], "dirs": [], "reads": []}}, fh)

    def _adjudicate(self, path):
        return guard.adjudicate(
            {"tool_name": "ReadMediaFile", "tool_input": {"path": path}},
            "read", self.scope, env={guard.ENV_ENTRY_ID: "e1"})

    def test_an_in_scope_media_read_is_allowed(self):
        allow, _reason = self._adjudicate(self.inside)
        self.assertTrue(allow)

    def test_a_media_read_outside_the_scope_is_denied(self):
        allow, reason = self._adjudicate(self.outside)
        self.assertFalse(allow)
        self.assertIn("outside your cell's scope", reason)
