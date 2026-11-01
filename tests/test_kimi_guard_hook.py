import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.kimi_guard_hook as guard
import scripts.write_guard_hook as wg


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
        self.peer = os.path.join(root, "cell", "findings-peer.json")
        self.allowlist_path = _write(
            os.path.join(root, "write-allowlist.json"),
            wg.allowlist_document({"entry-1": [self.inside], "entry-2": [self.peer]}))
        self.env = {guard.ENV_ENTRY_ID: "entry-1"}

    def read(self, tool, **tool_input):
        return guard.adjudicate({"tool_name": tool, "tool_input": tool_input,
                                 "cwd": self.tmp.name},
                                "read", self.scope_path, env=self.env)

    def write(self, tool, **tool_input):
        return guard.adjudicate({"tool_name": tool, "tool_input": tool_input},
                                "write", self.allowlist_path, env=self.env)


class TestDirectoryGrants(GuardCase):
    """The Kimi copy of the directory-grant rules: this hook's read branch is
    Claude's, with Kimi's `path` field, so the boundary has to move on both."""

    def setUp(self):
        super().setUp()
        self.cell = os.path.dirname(self.inside)
        _write(self.scope_path,
               {"entry-1": {"files": [self.inside], "dirs": [], "reads": []},
                "entry-dir": {"files": [], "dirs": [self.cell], "reads": [],
                              "escapes": {self.cell: []}}})

    def scan(self, tool, **tool_input):
        return guard.adjudicate({"tool_name": tool, "tool_input": tool_input,
                                 "cwd": self.tmp.name}, "read", self.scope_path,
                                env={guard.ENV_ENTRY_ID: "entry-dir"})

    def test_the_files_and_directories_of_that_grant_are_readable(self):
        self.assertEqual((True, ""), self.scan("Read", path=self.inside))
        self.assertEqual((True, ""), self.scan("Grep", pattern="x", path=self.inside))
        self.assertEqual((True, ""), self.scan("Grep", pattern="x", path=self.cell))

    def test_a_glob_pattern_that_climbs_out_of_the_granted_path_is_denied(self):
        # #1917, the Kimi copy: `path` was the only argument adjudicated, and
        # Glob's second one is a PATH pattern, so `../Src/*` over a clean
        # granted directory named entries the `dirs` grant never covered.
        for pattern in ("../Src/*", "..", "pkg/../../out/*", "/etc/*", "~/.ssh/*", None, ""):
            with self.subTest(pattern=pattern):
                arguments = {} if pattern is None else {"pattern": pattern}
                allow, reason = self.scan("Glob", path=self.cell, **arguments)
                self.assertFalse(allow, reason)
                self.assertIn("Glob pattern", reason)
        for pattern in ("**/*.py", "*.py", "..hidden"):
            with self.subTest(pattern=pattern):
                self.assertEqual((True, ""), self.scan("Glob", pattern=pattern, path=self.cell))
        # Grep's pattern is a regex over CONTENT and stays unadjudicated.
        self.assertEqual((True, ""), self.scan("Grep", pattern="../Src/*", path=self.cell))

    def test_the_dirs_grant_itself_is_never_folded(self):
        # Folding a DENIAL can only over-deny; folding the GRANT would ADMIT
        # /REPO/x under a /repo grant on a case-sensitive volume. Strings
        # only, so `isdir` is False and this is the scope test.
        _write(self.scope_path,
               {"entry-dir": {"files": [], "dirs": ["/repo"], "reads": []}})
        allow, reason = self.scan("Grep", pattern="x", path="/REPO/x.py")
        self.assertFalse(allow, reason)
        self.assertIn("outside your cell's scope", reason)

    def test_the_grant_never_covers_its_own_git_store(self):
        # #3271 G-a: first contact does not count <root>/.git, so no grant
        # reads it -- a path COMPONENT, so `.github/` and `.gitignore` still do.
        store = os.path.join(self.cell, ".git", "objects", "ab", "cdef")
        workflow = os.path.join(self.cell, ".github", "workflows", "ci.yml")
        ignore = os.path.join(self.cell, ".gitignore")
        for path in (store, workflow, ignore):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("x")
        for tool in ("Read", "ReadMediaFile", "Grep"):
            with self.subTest(tool=tool):
                allow, reason = self.scan(tool, path=store, pattern="x")
                self.assertFalse(allow, reason)
                self.assertIn("outside your cell's scope", reason)
                self.assertFalse(self.scan(tool, path=os.path.dirname(store), pattern="x")[0])
                self.assertEqual((True, ""), self.scan(tool, path=workflow, pattern="x"))
                self.assertEqual((True, ""), self.scan(tool, path=ignore, pattern="x"))
        for pattern in (".git/**", "a/.git/*", ".git"):
            with self.subTest(pattern=pattern):
                allow, reason = self.scan("Glob", pattern=pattern, path=self.cell)
                self.assertFalse(allow, reason)
                self.assertIn("no directory grant covers the .git store", reason)
        self.assertEqual((True, ""), self.scan("Glob", pattern=".github/**", path=self.cell))

    def test_the_git_store_exclusion_is_not_fooled_by_case_or_an_alias(self):
        # #3284 r1, the Kimi copy: casefolded on every volume, and by identity.
        os.makedirs(os.path.join(self.cell, ".git"), exist_ok=True)
        for alias in (".GIT/config", ".Git/objects/x"):
            with self.subTest(path=alias):
                path = os.path.join(self.cell, alias)
                self.assertFalse(self.scan("Read", path=path)[0])
                self.assertFalse(self.scan("Grep", pattern="x", path=path)[0])
        allow, reason = self.scan("Glob", pattern=".GIT/**", path=self.cell)
        self.assertFalse(allow, reason)
        other = os.path.join(self.cell, "alias", "config")
        os.makedirs(os.path.dirname(other), exist_ok=True)
        with open(other, "w", encoding="utf-8") as fh:
            fh.write("x")
        self.assertEqual((True, ""), self.scan("Read", path=other))
        real = os.path.samefile
        with mock.patch("os.path.samefile",
                        side_effect=lambda a, b: os.path.basename(a) == "alias" or real(a, b)):
            self.assertFalse(self.scan("Read", path=other)[0])

    def test_a_directory_read_keeps_its_previous_answer(self):
        # I3 (fix round 2): the new rule is about a tool that TRAVERSES, and
        # the Kimi hook shares one `isdir` branch across Read/ReadMediaFile/
        # Grep/Glob -- so it was telling a directory `Read` that "this tool
        # traverses the directory itself". Read's answer is unchanged.
        for tool in ("Read", "ReadMediaFile"):
            with self.subTest(tool=tool):
                self.assertEqual((True, ""), self.scan(tool, path=self.cell))

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

    def test_a_write_through_a_symlinked_component_is_denied(self):
        # #1640, the Kimi copy: this hook's write branch is write_guard_hook's,
        # so the nested-component rule has to move on both. The leaf is a real
        # file inside a run folder whose `runs` directory is a link.
        root = os.path.realpath(self.tmp.name)
        elsewhere = os.path.join(root, "elsewhere")
        pano = os.path.join(root, ".panopticon")
        os.makedirs(pano)
        link = os.path.join(pano, "runs")
        os.symlink(elsewhere, link)
        os.makedirs(os.path.join(link, "r1"))
        target = os.path.join(link, "r1", "findings-A-SEC.json")
        # The grant is the REALPATH, because that is what `allowlist_from_plan`
        # stored before #1640 -- which is what made this a fail-open rather than
        # a mismatch: the armed allowlist and this branch agreed on the external
        # destination, and the write was allowed.
        _write(self.allowlist_path,
               wg.allowlist_document({"entry-1": [os.path.realpath(target)]}))
        allow, reason = self.write("Write", path=target, content="{}")
        self.assertFalse(allow)
        self.assertIn("symlinked directory", reason)
        self.assertIn(link, reason)

    def test_a_write_through_a_parent_component_is_denied(self):
        # #1640 fix round 1, the Kimi copy: the grant is what the pre-fix
        # `allowlist_from_plan` would have stored for this declared path -- the
        # normalised escape -- so on the base both ends agreed on a source file.
        root = os.path.realpath(self.tmp.name)
        os.makedirs(os.path.join(root, ".panopticon", "runs", "r1"))
        os.makedirs(os.path.join(root, "src"), exist_ok=True)
        escape = os.path.join(root, ".panopticon", "runs", "r1",
                              "..", "..", "..", "src", "x.json")
        _write(self.allowlist_path,
               wg.allowlist_document({"entry-1": [os.path.realpath(escape)]}))
        allow, reason = self.write("Write", path=escape, content="{}")
        self.assertFalse(allow)
        self.assertIn("findings output cannot contain '..'", reason)
        self.assertIn(escape, reason)              # fix round 2, N1

    def test_an_ordinary_run_folder_write_is_still_allowed(self):
        root = os.path.realpath(self.tmp.name)
        run = os.path.join(root, ".panopticon", "runs", "r1")
        os.makedirs(run)
        target = os.path.join(run, "findings-A-SEC.json")
        _write(self.allowlist_path, wg.allowlist_document({"entry-1": [target]}))
        self.assertEqual(self.write("Write", path=target, content="{}"), (True, ""))

    def test_a_malformed_allowlist_fails_closed(self):
        with open(self.allowlist_path, "w", encoding="utf-8") as fh:
            fh.write("not json")
        allow, reason = self.write("Write", path=self.inside, content="{}")
        self.assertFalse(allow)
        self.assertIn("unavailable", reason)

    def test_a_non_string_path_is_denied(self):
        allow, _ = self.write("Write", path=42)
        self.assertFalse(allow)

    def test_a_write_to_a_peer_entrys_out_file_is_denied(self):
        # #1571, run-13 AGT-2297383423, reproduced against the real code:
        # `adjudicate(..., env={PANOPTICON_ENTRY_ID: "review-A-ARC"})` with a
        # peer's path answered `allowed: true` and an empty reason. This guard
        # already RECEIVES the id -- its read branch selects an entry's scope
        # with it -- and the write branch checked only that it was present.
        allow, reason = self.write("Write", path=self.peer, content="{}")
        self.assertFalse(allow)
        self.assertIn("entry-1", reason)
        self.assertIn("peer", reason)

    def test_a_stale_grant_is_not_reported_as_a_peer_write(self):
        # F1, Kimi's half: bound, named in the allowlist, but the grant is
        # some other run's path. Its own out_file is denied -- and the reason
        # must say the allowlist looks stale, not that it reached for a peer's.
        elsewhere = os.path.join(os.path.realpath(self.tmp.name), "other-run", "f.json")
        _write(self.allowlist_path, wg.allowlist_document({"entry-1": [elsewhere]}))
        allow, reason = self.write("Write", path=self.inside, content="{}")
        self.assertFalse(allow)
        self.assertNotIn("peer", reason)
        self.assertIn("stale", reason)
        self.assertIn("entry-1", reason)

    def test_the_peer_wording_is_kept_for_an_actual_peer_write(self):
        _allow, reason = self.write("Write", path=self.peer, content="{}")
        self.assertIn("a peer entry's artifact is not writable", reason)

    def test_an_entry_the_allowlist_does_not_name_is_denied(self):
        # Mirrors the read branch, which already names the entry it cannot find.
        allow, reason = guard.adjudicate(
            {"tool_name": "Write", "tool_input": {"path": self.inside, "content": "{}"}},
            "write", self.allowlist_path, env={guard.ENV_ENTRY_ID: "ghost"})
        self.assertFalse(allow)
        self.assertIn("ghost", reason)

    def test_the_unbound_bucket_is_not_selectable_by_a_bound_child(self):
        # F2: the Claude guard refuses the reserved key by name and this one
        # treated it as an ordinary id. Unreachable today -- Guards.env_for
        # takes entry["id"] and driver ids cannot spell it -- but
        # write_guard_hook says in as many words that the refusal must not
        # rest on the id grammar, and two guards that fail differently are two
        # guards to reason about.
        _write(self.allowlist_path,
               wg.allowlist_document({guard.UNBOUND_ENTRY: [self.inside]}))
        allow, reason = guard.adjudicate(
            {"tool_name": "Write", "tool_input": {"path": self.inside, "content": "{}"}},
            "write", self.allowlist_path,
            env={guard.ENV_ENTRY_ID: guard.UNBOUND_ENTRY})
        self.assertFalse(allow)
        self.assertIn(guard.UNBOUND_ENTRY, reason)

    def test_a_version_1_allowlist_fails_closed_and_names_the_version(self):
        # A stale flat list carries no attribution: honouring it would restore
        # exactly the batch-wide grant this issue is about.
        _write(self.allowlist_path, [self.inside])
        allow, reason = self.write("Write", path=self.inside, content="{}")
        self.assertFalse(allow)
        self.assertIn("version", reason)
        self.assertIn("1", reason)

    def test_an_allowlist_without_entries_fails_closed(self):
        _write(self.allowlist_path, {"version": 2, "paths": [self.inside]})
        allow, reason = self.write("Write", path=self.inside, content="{}")
        self.assertFalse(allow)
        self.assertIn("malformed", reason)


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

    def test_a_non_hashable_tool_name_denies_instead_of_crashing(self):
        # #2394: the roster test is a set membership, so a list `tool_name`
        # raises TypeError. Here it already runs inside `adjudicate`, INSIDE
        # the envelope; this pins it there -- a deny, never an escaped raise.
        code, out = self._main(
            ["read", self.scope_path],
            {"tool_name": ["Read"], "tool_input": {"path": self.inside}},
            {guard.ENV_ENTRY_ID: "entry-1"})
        self.assertEqual(code, 0)
        body = json.loads(out)["hookSpecificOutput"]
        self.assertEqual(body["permissionDecision"], "deny")
        self.assertIn("crashed", body["permissionDecisionReason"])
        self.assertIn("unhashable", body["permissionDecisionReason"])

    def test_a_payload_too_deep_to_parse_denies_instead_of_crashing_open(self):
        """#3186: a non-zero exit is NON-blocking on Kimi, so the RecursionError that escaped the parse
        failed OPEN. It travels as the printed deny now, rc 0, as every kimi refusal does."""
        def deep(n):
            return '{"tool_name": "ReadFile", "tool_input": {"path": "/tmp/x", "x": %s}}' % ("[" * n + "]" * n)

        def run(raw):
            out = io.StringIO()
            with mock.patch("sys.stdin", io.StringIO(raw)), contextlib.redirect_stdout(out):
                rc = guard.main(["read", self.scope_path], env={})
            return rc, out.getvalue()

        def denied(rc, out, why):
            body = json.loads(out)["hookSpecificOutput"]
            return (rc, body["permissionDecision"], body["permissionDecisionReason"]) == (
                0, "deny", "kimi guard: payload too deep to adjudicate (%s)" % why)

        # A real deep payload never crashes the hook: where this interpreter parses it (the depth that
        # overflows depends on the platform's C stack -- 100,000 parses on CI's x64 3.14), it is adjudicated
        # like any payload; where it cannot, it is the named deny.
        for n in (1_000, 100_000):
            with self.subTest(n=n):
                rc, out = run(deep(n))
                self.assertEqual(0, rc)
                self.assertTrue("too deep" not in out or denied(rc, out, "RecursionError"))
        # The parse failing, whatever the depth that makes it fail here: a deny naming the error.
        for error in (RecursionError, MemoryError):
            with self.subTest(error=error.__name__), mock.patch.object(guard.json, "load", side_effect=error):
                self.assertTrue(denied(*run(deep(1)), error.__name__))

    def test_a_malformed_payload_is_tolerantly_allowed(self):
        # The payload is the CLI's, not the model's -- Claude's hook makes the
        # same call, and denying on it would break legitimate work on a CLI
        # whose payload shape moved.
        out = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO("not json")), \
             contextlib.redirect_stdout(out):
            self.assertEqual(guard.main(["read", self.scope_path], env={}), 0)
        self.assertEqual(out.getvalue(), "")

    def test_a_short_argv_denies_and_names_the_invocation(self):
        # I6: argv is the CONFIG's, not the CLI's. A hook the config invoked
        # wrongly used to allow everything in silence -- exactly the case that
        # must fail closed, and exactly what a mis-generated config produces.
        code, out = self._main(["read"], {"tool_name": "Read"}, {})
        self.assertEqual(code, 0)
        body = json.loads(out)
        self.assertEqual(body["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("['read']", body["hookSpecificOutput"]["permissionDecisionReason"])

    def test_an_unknown_mode_denies_and_names_the_invocation(self):
        code, out = self._main(["bogus", self.scope_path], {"tool_name": "Read"}, {})
        self.assertEqual(code, 0)
        body = json.loads(out)
        self.assertEqual(body["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("bogus", body["hookSpecificOutput"]["permissionDecisionReason"])

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


class TestGlobThroughASymlink(unittest.TestCase):
    """#2063, the Kimi copy: the same shared rule over a scope file `scope_from_plan` wrote."""

    def test_a_glob_through_an_escaping_link_is_denied_and_the_rest_allowed(self):
        import scripts.read_guard_hook as rg
        with tempfile.TemporaryDirectory() as tmp:
            base = os.path.realpath(tmp)
            root, outside = os.path.join(base, "root"), os.path.join(base, "outside")
            os.makedirs(os.path.join(root, "clean"))
            os.makedirs(outside)
            os.symlink(outside, os.path.join(root, "linkdir"))
            scope_path = os.path.join(base, "read-scope.json")
            _write(scope_path, rg.scope_from_plan(
                [{"id": "scan", "scope": {"files": [], "dirs": [root], "reads": []}}]))
            for pattern, allowed in (("linkdir/*", False), ("*/x", False), ("**/*", False),
                                     ("clean/*", True), ("clean/x.py", True)):
                with self.subTest(pattern=pattern):
                    allow, reason = guard.adjudicate(
                        {"tool_name": "Glob", "tool_input": {"pattern": pattern, "path": root},
                         "cwd": base}, "read", scope_path, env={guard.ENV_ENTRY_ID: "scan"})
                    self.assertEqual(allowed, allow, reason)
