import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.read_guard_hook as rg


def _scope(files=(), dirs=(), reads=()):
    return {"files": [os.path.realpath(p) for p in files],
            "dirs": [os.path.realpath(p) for p in dirs],
            "reads": [os.path.realpath(p) for p in reads]}


class TestMarker(unittest.TestCase):
    def test_marker_line_is_the_prefix_plus_the_id(self):
        self.assertEqual("panopticon-entry: review-app-SEC", rg.marker_line("review-app-SEC"))

    def test_marker_of_reads_only_the_first_line(self):
        self.assertEqual("review-app-SEC",
                         rg.marker_of("panopticon-entry: review-app-SEC\nDo the work\n"))
        self.assertIsNone(rg.marker_of("Do the work\npanopticon-entry: review-app-SEC\n"))
        self.assertIsNone(rg.marker_of(""))
        self.assertIsNone(rg.marker_of(None))
        self.assertIsNone(rg.marker_of("panopticon-entry:   \nx"))

    def test_marker_line_refuses_an_id_that_cannot_be_one_line(self):
        for bad in ("", "a\nb", "a\rb"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                rg.marker_line(bad)

    def test_marker_round_trips_a_group_name_with_spaces_and_colons(self):
        eid = "review-My Group: v2-SEC"
        self.assertEqual(eid, rg.marker_of(rg.marker_line(eid) + "\nbody"))


class TestScopeFromPlan(unittest.TestCase):
    def test_collects_realpaths_per_entry_id(self):
        with tempfile.TemporaryDirectory() as d:
            a = os.path.join(d, "a.py"); open(a, "w").close()
            out = rg.scope_from_plan([
                {"id": "e1", "scope": {"files": [a, a], "dirs": [d], "reads": []}},
                {"id": "no-scope"},                      # skipped: nothing to confine to
                {"scope": {"files": [a]}},               # skipped: no id
                "junk",                                  # skipped: not an entry
            ])
            self.assertEqual({"e1"}, set(out))
            self.assertEqual([os.path.realpath(a)], out["e1"]["files"])
            self.assertEqual([os.path.realpath(d)], out["e1"]["dirs"])
            self.assertEqual([], out["e1"]["reads"])

    def test_the_request_object_is_rejected_not_iterated(self):
        # #1482 shape: the wrapper's keys are strings and would match nothing.
        for wrapper in ({"entries": []}, "entries", b"entries"):
            with self.subTest(wrapper=wrapper), self.assertRaises(TypeError):
                rg.scope_from_plan(wrapper)

    def test_non_list_scope_value_yields_empty_for_that_key(self):
        # A well-typed-but-malformed dispatch plan must degrade to an empty
        # scope for that key, never raise.
        out = rg.scope_from_plan([{"id": "e", "scope": {"files": 5}}])
        self.assertEqual({"files": [], "dirs": [], "reads": []}, out["e"])


class TestDecide(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.inside = os.path.join(d, "cell", "a.py")
        self.sibling = os.path.join(d, "cell", "b.py")
        self.outside = os.path.join(d, "other", "c.py")
        self.root = os.path.join(d, "root")
        self.root_file = os.path.join(self.root, "x.py")
        self.root_other = os.path.join(d, "root-other", "y.py")
        for p in (self.inside, self.sibling, self.outside, self.root_file, self.root_other):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").close()
        self.cell = _scope(files=[self.inside])
        self.scan = _scope(dirs=[self.root])

    def tearDown(self):
        self.tmp.cleanup()

    def test_read_of_an_in_scope_file_is_allowed(self):
        self.assertEqual((True, ""), rg.decide("Read", {"file_path": self.inside}, self.cell))

    def test_read_outside_scope_is_denied_and_names_the_prompt(self):
        ok, reason = rg.decide("Read", {"file_path": self.sibling}, self.cell)
        self.assertFalse(ok)
        self.assertIn("listed in your prompt", reason)

    def test_read_via_reads_allowance_is_allowed(self):
        scope = _scope(files=[self.inside], reads=[self.outside])
        self.assertTrue(rg.decide("Read", {"file_path": self.outside}, scope)[0])

    def test_unbound_subagent_is_denied_and_names_the_marker(self):
        ok, reason = rg.decide("Read", {"file_path": self.inside}, None)
        self.assertFalse(ok)
        self.assertIn(rg.MARKER_PREFIX, reason)

    def test_grep_of_an_in_scope_file_is_allowed(self):
        self.assertTrue(rg.decide("Grep", {"pattern": "x", "path": self.inside}, self.cell)[0])

    def test_grep_over_a_directory_is_denied_on_a_file_scoped_cell(self):
        ok, reason = rg.decide("Grep", {"pattern": "x", "path": os.path.dirname(self.inside)}, self.cell)
        self.assertFalse(ok)
        self.assertIn("grep a file by its path", reason)

    def test_glob_is_denied_on_a_file_scoped_cell(self):
        for path in (os.path.dirname(self.inside), self.inside):
            with self.subTest(path=path):
                ok, reason = rg.decide("Glob", {"pattern": "*.py", "path": path}, self.cell)
                self.assertFalse(ok)
                self.assertIn("Glob is not available", reason)

    def test_directory_scope_allows_grep_and_glob_inside_it(self):
        self.assertTrue(rg.decide("Grep", {"pattern": "x", "path": self.root}, self.scan)[0])
        self.assertTrue(rg.decide("Glob", {"pattern": "*.py", "path": self.root}, self.scan)[0])
        self.assertTrue(rg.decide("Read", {"file_path": self.root_file}, self.scan)[0])

    def test_directory_scope_is_separator_bounded(self):
        # /root must not admit /root-other.
        self.assertFalse(rg.decide("Read", {"file_path": self.root_other}, self.scan)[0])
        self.assertFalse(rg.decide("Grep", {"pattern": "x", "path": os.path.dirname(self.root_other)}, self.scan)[0])

    def test_symlink_out_of_scope_is_denied_by_realpath(self):
        link = os.path.join(os.path.dirname(self.inside), "link.py")
        os.symlink(self.outside, link)
        # The LINK path is what a hostile prompt would cite; realpath escapes the scope.
        self.assertFalse(rg.decide("Read", {"file_path": link}, self.cell)[0])

    def test_unresolvable_or_non_string_paths_are_denied_not_raised(self):
        for bad in ({"file_path": 7}, {"file_path": ["x"]}, {"file_path": "a\0b"}, {}, "not-a-dict", None):
            with self.subTest(bad=bad):
                self.assertFalse(rg.decide("Read", bad, self.cell)[0])

    def test_grep_without_a_path_is_denied(self):
        # adjudicate() fills `path` from the payload's cwd (R-P5-7); decide()
        # itself never guesses.
        self.assertFalse(rg.decide("Grep", {"pattern": "x"}, self.scan)[0])

    def test_tools_outside_the_matcher_are_not_adjudicated(self):
        for tool in ("Bash", "Write", "WebFetch"):
            with self.subTest(tool=tool):
                self.assertEqual((True, ""), rg.decide(tool, {"file_path": self.outside}, None))

    def test_matcher_and_read_tools_cannot_drift(self):
        self.assertEqual(set(rg._MATCHER.split("|")), rg._READ_TOOLS)
        self.assertEqual({"Read", "Grep", "Glob"}, rg._READ_TOOLS)
        self.assertNotIn("Bash", rg._READ_TOOLS)


def _write_subagent_transcript(parent_transcript, agent_id, first_text, *, workflow=None,
                               agent_id_in_record=None):
    """Lay out a subagent transcript exactly where the spike measured it."""
    stem = parent_transcript[: -len(".jsonl")]
    d = (os.path.join(stem, "subagents") if workflow is None
         else os.path.join(stem, "subagents", "workflows", workflow))
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "agent-%s.jsonl" % agent_id)
    records = [
        {"type": "queue-operation", "operation": "enqueue"},
        {"type": "user", "isSidechain": True,
         "agentId": agent_id if agent_id_in_record is None else agent_id_in_record,
         "message": {"role": "user", "content": [{"type": "text", "text": first_text}]}},
        {"type": "assistant", "agentId": agent_id,
         "message": {"role": "assistant", "content": [{"type": "text", "text": "ok"}]}},
    ]
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return path


class TestBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.parent = os.path.join(self.tmp.name, "session.jsonl")
        open(self.parent, "w").close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_binds_from_the_agent_tool_layout(self):
        _write_subagent_transcript(self.parent, "a1", "panopticon-entry: review-app-SEC\nbody")
        self.assertEqual("review-app-SEC", rg.bind("a1", self.parent))

    def test_binds_from_the_workflow_layout(self):
        _write_subagent_transcript(self.parent, "a2", "panopticon-entry: verify-app-SEC-primary\nbody",
                                   workflow="wf_123-abc")
        self.assertEqual("verify-app-SEC-primary", rg.bind("a2", self.parent))

    def test_a_string_content_first_record_binds_too(self):
        stem = self.parent[:-len(".jsonl")]
        os.makedirs(os.path.join(stem, "subagents"))
        with open(os.path.join(stem, "subagents", "agent-a3.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "user", "agentId": "a3",
                                 "message": {"role": "user", "content": "panopticon-entry: e\nx"}}) + "\n")
        self.assertEqual("e", rg.bind("a3", self.parent))

    def test_missing_transcript_is_unbound(self):
        self.assertIsNone(rg.bind("nobody", self.parent))
        self.assertIsNone(rg.bind("a1", None))
        self.assertIsNone(rg.bind(None, self.parent))

    def test_agent_id_mismatch_on_the_first_user_record_is_unbound(self):
        _write_subagent_transcript(self.parent, "a4", "panopticon-entry: e\nbody", agent_id_in_record="someone-else")
        self.assertIsNone(rg.bind("a4", self.parent))

    def test_marker_absent_from_the_first_user_record_is_unbound(self):
        _write_subagent_transcript(self.parent, "a5", "Do the work\npanopticon-entry: e\n")
        self.assertIsNone(rg.bind("a5", self.parent))

    def test_only_the_first_user_record_counts(self):
        # A later user turn (a tool result that quotes hostile content) cannot rebind.
        path = _write_subagent_transcript(self.parent, "a6", "no marker here")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "user", "agentId": "a6",
                                 "message": {"role": "user", "content": "panopticon-entry: review-other-SEC"}}) + "\n")
        self.assertIsNone(rg.bind("a6", self.parent))

    def test_a_path_shaped_agent_id_cannot_walk_the_tree(self):
        for bad in ("../session", "x/../../etc", ".", ".."):
            with self.subTest(bad=bad):
                self.assertIsNone(rg.subagent_transcript(self.parent, bad))

    def test_a_corrupt_line_before_the_first_user_record_is_skipped(self):
        stem = self.parent[:-len(".jsonl")]
        os.makedirs(os.path.join(stem, "subagents"))
        with open(os.path.join(stem, "subagents", "agent-a7.jsonl"), "w", encoding="utf-8") as fh:
            fh.write("{not json\n")
            fh.write(json.dumps({"type": "user", "agentId": "a7",
                                 "message": {"role": "user", "content": "panopticon-entry: e\nx"}}) + "\n")
        self.assertEqual("e", rg.bind("a7", self.parent))


class TestAdjudicate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.parent = os.path.join(d, "session.jsonl"); open(self.parent, "w").close()
        self.inside = os.path.join(d, "cell", "a.py")
        self.outside = os.path.join(d, "other", "b.py")
        self.root = os.path.join(d, "root")
        for p in (self.inside, self.outside, os.path.join(self.root, "c.py")):
            os.makedirs(os.path.dirname(p), exist_ok=True); open(p, "w").close()
        self.scope_path = os.path.join(d, "read-scope.json")
        with open(self.scope_path, "w", encoding="utf-8") as fh:
            json.dump({"review-app-SEC": _scope(files=[self.inside]),
                       "setup-scan": _scope(dirs=[self.root])}, fh)
        _write_subagent_transcript(self.parent, "cell-agent", "panopticon-entry: review-app-SEC\nbody")
        _write_subagent_transcript(self.parent, "scan-agent", "panopticon-entry: setup-scan\nbody")
        _write_subagent_transcript(self.parent, "stray-agent", "panopticon-entry: nobody-dispatched-this\nbody")

    def tearDown(self):
        self.tmp.cleanup()

    def _payload(self, tool, agent, **tool_input):
        p = {"tool_name": tool, "tool_input": tool_input, "transcript_path": self.parent,
             "cwd": self.root, "session_id": "s"}
        if agent:
            p["agent_id"] = agent; p["agent_type"] = "panopticon-domain-panel"
        return p

    def test_orchestrator_is_never_confined(self):
        self.assertEqual((True, ""), rg.adjudicate(self._payload("Read", None, file_path=self.outside), self.scope_path))

    def test_bound_subagent_is_confined(self):
        self.assertTrue(rg.adjudicate(self._payload("Read", "cell-agent", file_path=self.inside), self.scope_path)[0])
        self.assertFalse(rg.adjudicate(self._payload("Read", "cell-agent", file_path=self.outside), self.scope_path)[0])

    def test_unbound_subagent_is_denied(self):
        self.assertFalse(rg.adjudicate(self._payload("Read", "unknown-agent", file_path=self.inside), self.scope_path)[0])

    def test_bound_to_an_id_the_scope_does_not_name_is_denied_and_says_so(self):
        ok, reason = rg.adjudicate(self._payload("Read", "stray-agent", file_path=self.inside), self.scope_path)
        self.assertFalse(ok)
        self.assertIn("nobody-dispatched-this", reason)

    def test_pathless_grep_takes_the_payload_cwd(self):
        # R-P5-7: cwd is the directory-scoped root here, so the scan agent may grep it.
        self.assertTrue(rg.adjudicate(self._payload("Grep", "scan-agent", pattern="x"), self.scope_path)[0])
        # ...and a file-scoped cell is denied on the same call, with the directory reason.
        ok, reason = rg.adjudicate(self._payload("Grep", "cell-agent", pattern="x"), self.scope_path)
        self.assertFalse(ok); self.assertIn("grep a file by its path", reason)

    def test_missing_or_malformed_scope_file_denies_subagents_only(self):
        for content in (None, "[]", "{not json", '{"e": "x"}'):
            with self.subTest(content=content):
                if content is None:
                    os.remove(self.scope_path)
                else:
                    with open(self.scope_path, "w", encoding="utf-8") as fh:
                        fh.write(content)
                self.assertFalse(rg.adjudicate(self._payload("Read", "cell-agent", file_path=self.inside), self.scope_path)[0])
                self.assertTrue(rg.adjudicate(self._payload("Read", None, file_path=self.inside), self.scope_path)[0])

    def test_non_list_scope_values_deny_not_crash(self):
        # A well-typed-but-malformed scope file (a per-key value that isn't a
        # list) must deny every bound subagent, never raise out of adjudicate.
        for content in ('{"review-app-SEC": {"files": 5, "dirs": [], "reads": []}}',
                        '{"review-app-SEC": {"files": "a.py"}}'):
            with self.subTest(content=content):
                with open(self.scope_path, "w", encoding="utf-8") as fh:
                    fh.write(content)
                self.assertFalse(rg.adjudicate(self._payload("Read", "cell-agent", file_path=self.inside), self.scope_path)[0])
                self.assertTrue(rg.adjudicate(self._payload("Read", None, file_path=self.inside), self.scope_path)[0])

    def test_non_read_tools_pass_through(self):
        self.assertEqual((True, ""), rg.adjudicate(self._payload("Write", "cell-agent", file_path=self.outside), self.scope_path))

    def test_non_dict_payload_passes_through(self):
        self.assertEqual((True, ""), rg.adjudicate(["x"], self.scope_path))


class TestMain(unittest.TestCase):
    def _run(self, payload, argv):
        out = io.StringIO()
        stdin = io.StringIO(payload if isinstance(payload, str) else json.dumps(payload))
        with mock.patch("sys.stdin", stdin), contextlib.redirect_stdout(out):
            rc = rg.main(argv)
        return rc, out.getvalue()

    def test_denied_read_emits_deny_json(self):
        with tempfile.TemporaryDirectory() as d:
            parent = os.path.join(d, "s.jsonl"); open(parent, "w").close()
            scope_path = os.path.join(d, "scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({"e": _scope(files=[os.path.join(d, "a.py")])}, fh)
            _write_subagent_transcript(parent, "a", "panopticon-entry: e\n")
            rc, out = self._run({"tool_name": "Read", "agent_id": "a", "transcript_path": parent,
                                 "tool_input": {"file_path": os.path.join(d, "b.py")}}, [scope_path])
            self.assertEqual(0, rc)
            body = json.loads(out)["hookSpecificOutput"]
            self.assertEqual("deny", body["permissionDecision"])
            self.assertEqual("PreToolUse", body["hookEventName"])

    def test_non_list_scope_value_denies_without_crashing(self):
        with tempfile.TemporaryDirectory() as d:
            parent = os.path.join(d, "s.jsonl"); open(parent, "w").close()
            scope_path = os.path.join(d, "scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({"e": {"files": 5}}, fh)
            _write_subagent_transcript(parent, "a", "panopticon-entry: e\n")
            rc, out = self._run({"tool_name": "Read", "agent_id": "a", "transcript_path": parent,
                                 "tool_input": {"file_path": os.path.join(d, "b.py")}}, [scope_path])
            self.assertEqual(0, rc)
            body = json.loads(out)["hookSpecificOutput"]
            self.assertEqual("deny", body["permissionDecision"])

    def test_allowed_read_emits_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            parent = os.path.join(d, "s.jsonl"); open(parent, "w").close()
            a = os.path.join(d, "a.py"); open(a, "w").close()
            scope_path = os.path.join(d, "scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({"e": _scope(files=[a])}, fh)
            _write_subagent_transcript(parent, "a", "panopticon-entry: e\n")
            rc, out = self._run({"tool_name": "Read", "agent_id": "a", "transcript_path": parent,
                                 "tool_input": {"file_path": a}}, [scope_path])
            self.assertEqual((0, ""), (rc, out))

    def test_malformed_and_non_dict_stdin_are_tolerated(self):
        for raw in ("{not json", "[1, 2]"):
            with self.subTest(raw=raw):
                self.assertEqual((0, ""), self._run(raw, ["/nonexistent/scope.json"]))

    def test_env_override_wins_then_baked_path_then_cwd_walk(self):
        with tempfile.TemporaryDirectory() as d:
            env_file = os.path.join(d, "env.json"); open(env_file, "w").write("{}")
            with mock.patch.dict(os.environ, {"PANOPTICON_READ_SCOPE": env_file}):
                self.assertEqual(env_file, rg._resolve_scope_path("/baked/scope.json"))
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("PANOPTICON_READ_SCOPE", None)
                # a baked path is returned even when absent: fail-closed, never a fallback
                self.assertEqual("/baked/scope.json", rg._resolve_scope_path("/baked/scope.json"))
                walk = os.path.join(d, ".panopticon", "read-scope.json")
                os.makedirs(os.path.dirname(walk)); open(walk, "w").write("{}")
                with mock.patch("os.getcwd", return_value=os.path.join(d, "deep", "er")):
                    self.assertEqual(walk, rg._resolve_scope_path(None))


import scripts.write_guard_hook as wg  # noqa: E402  (coexistence tests)


def _entry(eid, files=(), dirs=()):
    return {"id": eid, "scope": {"files": list(files), "dirs": list(dirs), "reads": []}}


class TestInstallUninstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        self.settings = os.path.join(d, "settings.json")
        self.scope_path = os.path.join(d, "read-scope.json")
        self.a = os.path.join(d, "a.py"); open(self.a, "w").close()
        self.b = os.path.join(d, "b.py"); open(self.b, "w").close()

    def tearDown(self):
        self.tmp.cleanup()

    def _settings(self):
        with open(self.settings, encoding="utf-8") as fh:
            return json.load(fh)

    def test_install_writes_the_scope_and_registers_the_hook(self):
        added = rg.install([_entry("e1", files=[self.a])],
                           settings_path=self.settings, scope_path=self.scope_path)
        self.assertEqual({"e1"}, set(added))
        self.assertEqual({"e1": {"files": [os.path.realpath(self.a)], "dirs": [], "reads": []}},
                         rg._read_scope_file(self.scope_path))
        hooks = self._settings()["hooks"]["PreToolUse"]
        self.assertEqual(1, len(hooks))
        self.assertEqual(rg._MATCHER, hooks[0]["matcher"])
        cmd = hooks[0]["hooks"][0]["command"]
        self.assertTrue(cmd.startswith(rg._HOOK_CMD))
        self.assertIn('"%s"' % os.path.abspath(self.scope_path), cmd)
        self.assertEqual((True, 1), rg.is_armed(settings_path=self.settings, scope_path=self.scope_path))

    def test_install_is_idempotent(self):
        for _ in range(2):
            rg.install([_entry("e1", files=[self.a])], settings_path=self.settings, scope_path=self.scope_path)
        self.assertEqual(1, len(self._settings()["hooks"]["PreToolUse"]))

    def test_uninstall_removes_the_hook_and_the_scope(self):
        rg.install([_entry("e1", files=[self.a])], settings_path=self.settings, scope_path=self.scope_path)
        rg.uninstall(settings_path=self.settings, scope_path=self.scope_path)
        self.assertNotIn("hooks", self._settings())
        self.assertFalse(os.path.exists(self.scope_path))
        self.assertEqual((False, 0), rg.is_armed(settings_path=self.settings, scope_path=self.scope_path))

    def test_uninstall_is_safe_when_nothing_is_installed(self):
        rg.uninstall(settings_path=self.settings, scope_path=self.scope_path)   # no raise
        self.assertFalse(os.path.exists(self.settings))

    def test_reinstall_unions_by_id_and_ours_wins(self):
        # #11: a concurrent fan-out's grant survives; R-P5-4: an id we are
        # dispatching is REPLACED, so a planted entry for a dispatched id is
        # overwritten on arm rather than unioned in.
        rg.install([_entry("e1", files=[self.a]), _entry("e2", files=[self.b])],
                   settings_path=self.settings, scope_path=self.scope_path)
        rg.install([_entry("e2", files=[self.a])], settings_path=self.settings, scope_path=self.scope_path)
        on_disk = rg._read_scope_file(self.scope_path)
        self.assertEqual({"e1", "e2"}, set(on_disk))
        self.assertEqual([os.path.realpath(self.a)], on_disk["e2"]["files"])

    def test_scoped_uninstall_keeps_the_other_fan_out_armed(self):
        rg.install([_entry("e1", files=[self.a])], settings_path=self.settings, scope_path=self.scope_path)
        rg.install([_entry("e2", files=[self.b])], settings_path=self.settings, scope_path=self.scope_path)
        rg.uninstall(settings_path=self.settings, scope_path=self.scope_path, plan=[_entry("e1")])
        self.assertEqual((True, 1), rg.is_armed(settings_path=self.settings, scope_path=self.scope_path))
        self.assertEqual({"e2"}, set(rg._read_scope_file(self.scope_path)))
        rg.uninstall(settings_path=self.settings, scope_path=self.scope_path, plan=[_entry("e2")])
        self.assertEqual((False, 0), rg.is_armed(settings_path=self.settings, scope_path=self.scope_path))

    def test_install_still_refuses_a_plan_with_no_scope_dicts(self):
        # No entry carried a `scope` dict at all -- scope_from_plan(plan) is
        # empty, and arming zero ids is a caller mistake, not a plan that
        # legitimately confines some ids to nothing (C1).
        rg.install([_entry("e1", files=[self.a])], settings_path=self.settings, scope_path=self.scope_path)
        for plan in ([], [{"id": "x"}]):
            with self.subTest(plan=plan), self.assertRaises(ValueError):
                rg.install(plan, settings_path=self.settings, scope_path=self.scope_path)
        self.assertEqual({"e1"}, set(rg._read_scope_file(self.scope_path)))

    def test_install_arms_deny_all_when_every_entry_scope_is_empty(self):
        # A plan whose only entry carries an EMPTY scope dict must still arm
        # (no ValueError) -- decide() denies everything for that id, which is
        # what an intentionally-empty scope means (R-P5-2), not a hole.
        rg.install([_entry("e1")], settings_path=self.settings, scope_path=self.scope_path)
        self.assertEqual((True, 1), rg.is_armed(settings_path=self.settings, scope_path=self.scope_path))
        self.assertEqual({"e1": {"files": [], "dirs": [], "reads": []}},
                         rg._read_scope_file(self.scope_path))

    def test_install_overwrites_a_planted_row_under_a_dispatched_empty_scope_id(self):
        # C1: a row planted on disk under an id the driver is ABOUT TO
        # dispatch with an empty scope (e.g. verify-tool-<fingerprint> for a
        # redacted/absent finding location) must not survive install()'s
        # merge -- otherwise the planted grant silently widens that agent's
        # reads.
        with open(self.scope_path, "w", encoding="utf-8") as fh:
            json.dump({"verify-tool-X": _scope(dirs=[self.tmp.name])}, fh)
        rg.install([_entry("verify-tool-X")], settings_path=self.settings, scope_path=self.scope_path)
        on_disk = rg._read_scope_file(self.scope_path)
        self.assertEqual({"files": [], "dirs": [], "reads": []}, on_disk["verify-tool-X"])
        # ...and adjudicate() actually denies a read of a file that used to be
        # inside the planted grant, for a subagent bound to that id.
        parent = os.path.join(self.tmp.name, "session.jsonl")
        open(parent, "w").close()
        _write_subagent_transcript(parent, "a1", "panopticon-entry: verify-tool-X\nbody")
        payload = {"tool_name": "Read", "agent_id": "a1", "transcript_path": parent,
                   "tool_input": {"file_path": self.a}, "cwd": self.tmp.name}
        self.assertFalse(rg.adjudicate(payload, self.scope_path)[0])

    def test_the_request_object_is_rejected(self):
        with self.assertRaises(TypeError):
            rg.install({"entries": [_entry("e1", files=[self.a])]},
                       settings_path=self.settings, scope_path=self.scope_path)
        with self.assertRaises(TypeError):
            rg.uninstall(settings_path=self.settings, scope_path=self.scope_path, plan={"entries": []})

    def test_install_refuses_to_create_a_settings_file_from_the_wrong_cwd(self):
        # #1493, verbatim from the write guard: a missing settings file at the
        # DEFAULT path means the caller is not at the session root. install()'s
        # check is a RELATIVE-path os.path.exists(".claude/settings.local.json")
        # against the REAL process cwd -- and this repo's root has that file --
        # so this test chdirs into a tempdir rather than mocking os.getcwd
        # (which would arm the guard into the repo's own real settings file).
        #
        # That real file is GITIGNORED (#436), so it may be ABSENT on a fresh
        # clone or in CI -- capture "bytes, or None" rather than assuming it
        # exists, so this test proves non-modification everywhere instead of
        # erroring on a clean checkout.
        def _state(path):
            try:
                with open(path, "rb") as fh:
                    return fh.read()
            except FileNotFoundError:
                return None
        real_settings = os.path.abspath(".claude/settings.local.json")
        before = _state(real_settings)
        original = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            try:
                os.chdir(d)
                self.assertFalse(os.path.exists(rg.DEFAULT_SETTINGS_PATH))
                with self.assertRaises(ValueError) as ctx:
                    rg.install([_entry("e1", files=[self.a])])
                self.assertIn("session root", str(ctx.exception))
                self.assertFalse(os.path.exists(rg.DEFAULT_SETTINGS_PATH))
            finally:
                os.chdir(original)
        self.assertEqual(_state(real_settings), before)

    def test_session_root_resolves_both_paths_under_it(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".claude"))
            open(os.path.join(root, rg.DEFAULT_SETTINGS_PATH), "w").write("{}")
            rg.install([_entry("e1", files=[self.a])], session_root=root)
            state = rg.guard_state(session_root=root)
            self.assertTrue(state["armed"])
            self.assertEqual(os.path.abspath(os.path.join(root, rg.DEFAULT_SETTINGS_PATH)), state["settings_path"])
            self.assertEqual(os.path.abspath(os.path.join(root, rg.DEFAULT_SCOPE_PATH)), state["scope_path"])
            rg.uninstall(session_root=root)
            self.assertFalse(rg.guard_state(session_root=root)["armed"])

    def test_session_root_and_explicit_paths_together_are_refused(self):
        with self.assertRaises(ValueError):
            rg._resolve(self.settings, None, "/some/root")

    def test_corrupt_settings_are_never_overwritten(self):
        with open(self.settings, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        with self.assertRaises(RuntimeError):
            rg.install([_entry("e1", files=[self.a])], settings_path=self.settings, scope_path=self.scope_path)
        self.assertEqual("{not json", open(self.settings, encoding="utf-8").read())

    def test_both_guards_coexist_in_one_settings_file(self):
        # The write guard keys its entry on ITS script path and this guard on
        # its own, so each install/uninstall leaves the other's entry alone.
        allowlist = os.path.join(self.tmp.name, "allowlist.json")
        out_file = os.path.join(self.tmp.name, ".panopticon", "findings-g-D.json")
        os.makedirs(os.path.dirname(out_file)); open(out_file, "w").write("{}")
        wg.install([{"out_file": out_file}], settings_path=self.settings, allowlist_path=allowlist)
        rg.install([_entry("e1", files=[self.a])], settings_path=self.settings, scope_path=self.scope_path)
        hooks = self._settings()["hooks"]["PreToolUse"]
        self.assertEqual(2, len(hooks))
        self.assertEqual({wg._MATCHER, rg._MATCHER}, {h["matcher"] for h in hooks})
        self.assertEqual([True, False], [wg._is_our_entry(h) for h in sorted(hooks, key=lambda h: h["matcher"] != wg._MATCHER)])
        rg.uninstall(settings_path=self.settings, scope_path=self.scope_path)
        self.assertEqual((True, 1), wg.is_armed(settings_path=self.settings, allowlist_path=allowlist))
        wg.uninstall(settings_path=self.settings, allowlist_path=allowlist)
        self.assertNotIn("hooks", self._settings())

    def test_hook_cmd_is_absolute_and_quoted(self):
        self.assertTrue(rg._HOOK_CMD.startswith('python3 "/'))
        self.assertIn(os.path.abspath(rg.__file__), rg._HOOK_CMD)


if __name__ == "__main__":
    unittest.main()
