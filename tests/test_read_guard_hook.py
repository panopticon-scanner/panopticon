import contextlib
import io
import json
import os
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

from tests._test_helpers import write_host_evidence
from scripts import hosts
import scripts.probes.claude as claude_probes
import scripts.ocrdb as ocrdb
import scripts.phases.coverage as coverage
import scripts.phases.review as review
import scripts.phases.setup as setup
import scripts.phases.verify as verify_phase
import scripts.phases.verify_tools as verify_tools_phase
import scripts.guard_rules as guard_rules
import scripts.read_guard_hook as rg
from scripts import read_guard_hook


def _scope(files=(), dirs=(), reads=()):
    """A scope as `scope_from_plan` builds it, with #2063's arm-time escape walk."""
    grants = [os.path.realpath(p) for p in dirs]
    return {"files": [os.path.realpath(p) for p in files], "dirs": grants,
            "reads": [os.path.realpath(p) for p in reads],
            "escapes": rg.guard_rules.grant_escapes(grants)}


class TestMarker(unittest.TestCase):
    def test_marker_line_is_the_prefix_plus_the_id(self):
        self.assertEqual("panopticon-entry: review-app-SEC", rg.marker_line("review-app-SEC"))

    def test_marker_of_reads_only_the_first_line(self):
        self.assertEqual("review-app-SEC",
                         guard_rules.marker_of("panopticon-entry: review-app-SEC\nDo the work\n"))
        self.assertIsNone(guard_rules.marker_of("Do the work\npanopticon-entry: review-app-SEC\n"))
        self.assertIsNone(guard_rules.marker_of(""))
        self.assertIsNone(guard_rules.marker_of(None))
        self.assertIsNone(guard_rules.marker_of("panopticon-entry:   \nx"))

    def test_marker_line_refuses_an_id_that_cannot_be_one_line(self):
        for bad in ("", "a\nb", "a\rb"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                rg.marker_line(bad)

    def test_marker_round_trips_any_driver_generated_id(self):
        # marker_line is permissive BY DESIGN, not because a real driver id
        # ever needs it: every id the driver actually generates already
        # matches `^[A-Za-z0-9._:-]+$` (groups_schema._GROUP_NAME_RE forbids
        # spaces/colons in a group name), pinned separately by
        # test_entry_ids_match_the_spec_id_grammar below. This proves the
        # MECHANISM round-trips any single-line id, realistic shapes and an
        # adversarial one alike -- so a future id shape needs no change here.
        for eid in ("review-Auth-SEC", "verify-app-SEC-primary-part2",
                   "verify-tool-q1", "scout-Auth", "setup-scan",
                   "review-My Group: v2-SEC"):
            with self.subTest(eid=eid):
                self.assertEqual(eid, guard_rules.marker_of(rg.marker_line(eid) + "\nbody"))


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
        self.assertEqual({"files": [], "dirs": [], "reads": [], "escapes": {}}, out["e"])

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

    def test_a_directory_grant_never_covers_its_own_git_store(self):
        # #3271 G-a: first contact does not count <root>/.git (a work tree's
        # own store), so no grant reads it -- matched as a path COMPONENT, so
        # `.github/` and `.gitignore` still read.
        store = os.path.join(self.root, ".git", "objects", "ab", "cdef")
        workflow = os.path.join(self.root, ".github", "workflows", "ci.yml")
        ignore = os.path.join(self.root, ".gitignore")
        for p in (store, workflow, ignore):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").close()
        for tool, key in (("Read", "file_path"), ("Grep", "path")):
            with self.subTest(tool=tool):
                ok, reason = rg.decide(tool, {key: store, "pattern": "x"}, self.scan)
                self.assertFalse(ok, reason)
                self.assertIn("outside your cell's scope", reason)
                self.assertEqual((True, ""), rg.decide(tool, {key: workflow, "pattern": "x"}, self.scan))
                self.assertEqual((True, ""), rg.decide(tool, {key: ignore, "pattern": "x"}, self.scan))
        for tool in ("Grep", "Glob"):
            with self.subTest(tool=tool, path="store"):
                self.assertFalse(rg.decide(tool, {"pattern": "*", "path": os.path.dirname(store)},
                                           self.scan)[0])
        for pattern in (".git/**", "a/.git/*", ".git"):
            with self.subTest(pattern=pattern):
                ok, reason = rg.decide("Glob", {"pattern": pattern, "path": self.root}, self.scan)
                self.assertFalse(ok, reason)
                self.assertEqual(rg.GIT_STORE_DENIAL % pattern, reason)
        self.assertEqual((True, ""), rg.decide("Glob", {"pattern": ".github/**", "path": self.root},
                                               self.scan))

    def test_the_git_store_exclusion_is_not_fooled_by_case_or_an_alias(self):
        # #3284 r1: APFS and NTFS resolve `.GIT/config` to `.git/config`, and
        # realpath keeps the spelling it was given -- so the component test
        # casefolds, on every volume (a real `.GIT/` on a case-sensitive one is
        # refused too, which is only over-strict).
        os.makedirs(os.path.join(self.root, ".git"), exist_ok=True)
        config = os.path.join(self.root, ".git", "config")
        open(config, "w").close()
        for alias in (".GIT/config", ".Git/objects/x", ".gIt"):
            with self.subTest(path=alias):
                path = os.path.join(self.root, alias)
                self.assertFalse(rg.decide("Read", {"file_path": path}, self.scan)[0])
                self.assertFalse(rg.decide("Grep", {"pattern": "x", "path": path}, self.scan)[0])
        for pattern in (".GIT/**", "a/.Git/*"):
            with self.subTest(pattern=pattern):
                self.assertEqual(rg.GIT_STORE_DENIAL % pattern,
                                 rg.decide("Glob", {"pattern": pattern, "path": self.root}, self.scan)[1])
        if not os.path.exists(os.path.join(self.root, ".GIT", "config")):
            self.skipTest("case-sensitive volume: .GIT is not .git here")
        self.assertTrue(os.path.samefile(config, os.path.join(self.root, ".GIT", "config")))

    def test_any_other_alias_of_the_store_is_refused_by_identity(self):
        # The samefile half: a name the volume resolves to `<root>/.git` that
        # casefolding does not catch. No portable way to make one exists, so
        # the identity answer is supplied; the rule under test is "same file
        # as the store means not granted".
        alias = os.path.join(self.root, "alias", "config")
        os.makedirs(os.path.dirname(alias), exist_ok=True)
        open(alias, "w").close()
        os.makedirs(os.path.join(self.root, ".git"), exist_ok=True)
        self.assertEqual((True, ""), rg.decide("Read", {"file_path": alias}, self.scan))
        real = os.path.samefile
        with mock.patch("os.path.samefile",
                        side_effect=lambda a, b: os.path.basename(a) == "alias" or real(a, b)):
            self.assertFalse(rg.decide("Read", {"file_path": alias}, self.scan)[0])

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

    def test_a_glob_pattern_that_climbs_out_of_the_granted_path_is_denied(self):
        # #1917: `path` was the only argument adjudicated here, and Glob's
        # second one is a PATH pattern -- relative to `path`, so `../Src/*`
        # names entries the `dirs` grant never covered. It leaks names, not
        # content (a following Read still meets the per-file rule), but it is
        # the one read primitive whose second argument nothing looked at.
        for pattern in ("../Src/*", "..", "pkg/../../out/*", "a/..", r"..\Src\*"):
            with self.subTest(pattern=pattern):
                ok, reason = rg.decide("Glob", {"pattern": pattern, "path": self.root}, self.scan)
                self.assertFalse(ok, reason)
                self.assertIn("may not climb out of it", reason)
                self.assertIn(repr(pattern), reason)

    def test_an_absolute_or_home_relative_glob_pattern_is_denied(self):
        for pattern in ("/etc/*", "~/.ssh/*", "~"):
            with self.subTest(pattern=pattern):
                ok, reason = rg.decide("Glob", {"pattern": pattern, "path": self.root}, self.scan)
                self.assertFalse(ok, reason)
                self.assertIn("relative to", reason)

    def test_a_missing_or_unusable_glob_pattern_is_denied(self):
        # Fail closed on the argument the rule is about: nothing here can say
        # what an absent or non-string pattern would expand to.
        for pattern in (None, "", 7, ["*.py"]):
            with self.subTest(pattern=pattern):
                arguments = {"path": self.root}
                if pattern is not None:
                    arguments["pattern"] = pattern
                ok, reason = rg.decide("Glob", arguments, self.scan)
                self.assertFalse(ok, reason)
                self.assertIn("Glob pattern", reason)

    def test_an_ordinary_glob_pattern_is_still_allowed(self):
        # ...and the rule is about climbing, not about dots or stars: a name
        # that merely BEGINS with two dots is a name.
        for pattern in ("**/*.py", "*.py", "src/**/test_*.py", "..hidden", "a..b/*"):
            with self.subTest(pattern=pattern):
                self.assertEqual((True, ""), rg.decide(
                    "Glob", {"pattern": pattern, "path": self.root}, self.scan))

    def test_a_greps_pattern_is_a_regex_and_stays_unadjudicated(self):
        # Grep's second argument searches CONTENT; `../` in it is a regex, not
        # a path, and denying it would deny a legitimate search.
        self.assertEqual((True, ""), rg.decide(
            "Grep", {"pattern": "../Src/*", "path": self.root}, self.scan))
        self.assertEqual((True, ""), rg.decide(
            "Grep", {"pattern": "x", "path": self.root_file}, self.scan))

    def test_directory_scope_is_separator_bounded(self):
        # /root must not admit /root-other.
        self.assertFalse(rg.decide("Read", {"file_path": self.root_other}, self.scan)[0])
        self.assertFalse(rg.decide("Grep", {"pattern": "x", "path": os.path.dirname(self.root_other)}, self.scan)[0])

    def test_a_directory_grants_ordinary_files_and_directories_are_unchanged(self):
        # A directory's st_nlink is its subdirectory count, so the rule is for
        # REGULAR files only: over a grant whose walk recorded NOTHING, Grep
        # and Glob of the granted root stay allowed -- which is every clean
        # tree, and is what #1683 had to keep working.
        self.assertEqual((True, ""), rg.decide("Read", {"file_path": self.root_file}, self.scan))
        self.assertEqual((True, ""), rg.decide("Grep", {"pattern": "x", "path": self.root_file}, self.scan))
        self.assertEqual((True, ""), rg.decide("Grep", {"pattern": "x", "path": self.root}, self.scan))
        self.assertEqual((True, ""), rg.decide("Glob", {"pattern": "*.py", "path": self.root}, self.scan))

    def test_the_dirs_grant_itself_is_never_folded(self):
        # Folding the GRANT would ADMIT /REPO/x under a /repo grant on a
        # case-sensitive volume. Strings only, no filesystem: `isdir` is False,
        # so this is the scope test rather than the directory branch.
        scope = {"files": [], "dirs": ["/repo"], "reads": []}
        ok, reason = rg.decide("Grep", {"pattern": "x", "path": "/REPO/x.py"}, scope)
        self.assertFalse(ok, reason)
        self.assertIn("outside your cell's scope", reason)
        self.assertFalse(rg.decide("Read", {"file_path": "/REPO/x.py"}, scope)[0])

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
        self.assertEqual("review-app-SEC", guard_rules.bind("a1", self.parent))

    def test_binds_from_the_workflow_layout(self):
        _write_subagent_transcript(self.parent, "a2", "panopticon-entry: verify-app-SEC-primary\nbody",
                                   workflow="wf_123-abc")
        self.assertEqual("verify-app-SEC-primary", guard_rules.bind("a2", self.parent))

    def test_a_string_content_first_record_binds_too(self):
        stem = self.parent[:-len(".jsonl")]
        os.makedirs(os.path.join(stem, "subagents"))
        with open(os.path.join(stem, "subagents", "agent-a3.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "user", "agentId": "a3",
                                 "message": {"role": "user", "content": "panopticon-entry: e\nx"}}) + "\n")
        self.assertEqual("e", guard_rules.bind("a3", self.parent))

    def test_missing_transcript_is_unbound(self):
        self.assertIsNone(guard_rules.bind("nobody", self.parent))
        self.assertIsNone(guard_rules.bind("a1", None))
        self.assertIsNone(guard_rules.bind(None, self.parent))

    def test_agent_id_mismatch_on_the_first_user_record_is_unbound(self):
        _write_subagent_transcript(self.parent, "a4", "panopticon-entry: e\nbody", agent_id_in_record="someone-else")
        self.assertIsNone(guard_rules.bind("a4", self.parent))

    def test_marker_absent_from_the_first_user_record_is_unbound(self):
        _write_subagent_transcript(self.parent, "a5", "Do the work\npanopticon-entry: e\n")
        self.assertIsNone(guard_rules.bind("a5", self.parent))

    def test_only_the_first_user_record_counts(self):
        # A later user turn (a tool result that quotes hostile content) cannot rebind.
        path = _write_subagent_transcript(self.parent, "a6", "no marker here")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "user", "agentId": "a6",
                                 "message": {"role": "user", "content": "panopticon-entry: review-other-SEC"}}) + "\n")
        self.assertIsNone(guard_rules.bind("a6", self.parent))

    def test_a_path_shaped_agent_id_cannot_walk_the_tree(self):
        for bad in ("../session", "x/../../etc", ".", ".."):
            with self.subTest(bad=bad):
                self.assertIsNone(guard_rules.subagent_transcript(self.parent, bad))

    def test_a_corrupt_line_before_the_first_user_record_is_skipped(self):
        stem = self.parent[:-len(".jsonl")]
        os.makedirs(os.path.join(stem, "subagents"))
        with open(os.path.join(stem, "subagents", "agent-a7.jsonl"), "w", encoding="utf-8") as fh:
            fh.write("{not json\n")
            fh.write(json.dumps({"type": "user", "agentId": "a7",
                                 "message": {"role": "user", "content": "panopticon-entry: e\nx"}}) + "\n")
        self.assertEqual("e", guard_rules.bind("a7", self.parent))


class TestAdjudicate(unittest.TestCase):
    def setUp(self):
        # These tests call the two-arg adjudicate(payload, scope_path), which
        # defaults `env` to the real os.environ (spec 5.3) -- a stray
        # PANOPTICON_ENTRY_ID in the operator's shell must never leak into
        # what these tests exercise (the transcript-binding path).
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(read_guard_hook.ENV_ENTRY_ID, None)
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


class TestEnvBinding(unittest.TestCase):
    """Spec 5.3: env first, transcript second, agent_type-without-binding
    denied, nothing -> the orchestrator."""

    def _scoped(self, d, entry_id, allowed_file):
        # realpath'd on write, matching _scope() above and scope_from_plan()'s
        # own normalisation -- adjudicate() always realpaths the query path,
        # and on macOS $TMPDIR resolves through a /var -> /private/var symlink.
        scope_path = os.path.join(d, "read-scope.json")
        with open(scope_path, "w", encoding="utf-8") as fh:
            json.dump({entry_id: {"files": [os.path.realpath(allowed_file)],
                                  "dirs": [], "reads": []}}, fh)
        return scope_path

    def test_env_bound_call_is_confined_to_that_entry(self):
        with tempfile.TemporaryDirectory() as d:
            inside = os.path.join(d, "a.py"); open(inside, "w").close()
            outside = os.path.join(d, "b.py"); open(outside, "w").close()
            scope = self._scoped(d, "cell-1", inside)
            env = {read_guard_hook.ENV_ENTRY_ID: "cell-1"}
            ok, _ = read_guard_hook.adjudicate(
                {"tool_name": "Read", "tool_input": {"file_path": inside}}, scope, env=env)
            self.assertTrue(ok)
            ok, reason = read_guard_hook.adjudicate(
                {"tool_name": "Read", "tool_input": {"file_path": outside}}, scope, env=env)
            self.assertFalse(ok)
            self.assertIn("cell-1", reason)

    def test_env_wins_when_agent_type_is_also_present(self):
        # The real headless payload shape: a `claude -p` session reports its
        # own agent_type (e.g. panopticon-domain-panel) AND is env-bound by
        # the runner. The env binding governs exactly as when agent_type is
        # absent -- agent_type only matters when NOTHING else bound the call.
        with tempfile.TemporaryDirectory() as d:
            inside = os.path.join(d, "a.py"); open(inside, "w").close()
            outside = os.path.join(d, "b.py"); open(outside, "w").close()
            scope = self._scoped(d, "cell-1", inside)
            env = {read_guard_hook.ENV_ENTRY_ID: "cell-1"}
            ok, _ = read_guard_hook.adjudicate(
                {"tool_name": "Read", "tool_input": {"file_path": inside},
                 "agent_type": "panopticon-domain-panel"}, scope, env=env)
            self.assertTrue(ok)
            ok, reason = read_guard_hook.adjudicate(
                {"tool_name": "Read", "tool_input": {"file_path": outside},
                 "agent_type": "panopticon-domain-panel"}, scope, env=env)
            self.assertFalse(ok)
            self.assertIn("cell-1", reason)

    def test_env_wins_over_a_transcript_bound_agent_id(self):
        # A subagent spawned INSIDE a headless entry inherits the entry's
        # confinement even though its own transcript would bind elsewhere.
        with tempfile.TemporaryDirectory() as d:
            inside = os.path.join(d, "a.py"); open(inside, "w").close()
            other = os.path.join(d, "c.py"); open(other, "w").close()
            scope_path = os.path.join(d, "read-scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({"cell-1": {"files": [os.path.realpath(inside)], "dirs": [], "reads": []},
                           "cell-2": {"files": [os.path.realpath(other)], "dirs": [], "reads": []}}, fh)
            parent = os.path.join(d, "parent.jsonl"); open(parent, "w").close()
            claude_probes._fake_subagent(parent, "agent-x", "cell-2")
            payload = {"tool_name": "Read", "tool_input": {"file_path": other},
                       "agent_id": "agent-x", "transcript_path": parent}
            ok, _ = read_guard_hook.adjudicate(payload, scope_path, env={})
            self.assertTrue(ok)                       # transcript binds to cell-2
            ok, _ = read_guard_hook.adjudicate(
                payload, scope_path, env={read_guard_hook.ENV_ENTRY_ID: "cell-1"})
            self.assertFalse(ok)                      # env re-binds to cell-1

    def test_agent_type_without_any_binding_is_denied(self):
        with tempfile.TemporaryDirectory() as d:
            inside = os.path.join(d, "a.py"); open(inside, "w").close()
            scope = self._scoped(d, "cell-1", inside)
            ok, reason = read_guard_hook.adjudicate(
                {"tool_name": "Read", "tool_input": {"file_path": inside},
                 "agent_type": "panopticon-domain-panel"}, scope, env={})
            self.assertFalse(ok)
            self.assertIn("agent_type", reason)

    def test_nothing_bound_is_the_orchestrator_and_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            inside = os.path.join(d, "a.py"); open(inside, "w").close()
            scope = self._scoped(d, "cell-1", inside)
            ok, _ = read_guard_hook.adjudicate(
                {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}, scope, env={})
            self.assertTrue(ok)

    def test_env_bound_to_an_unarmed_id_is_denied(self):
        with tempfile.TemporaryDirectory() as d:
            inside = os.path.join(d, "a.py"); open(inside, "w").close()
            scope = self._scoped(d, "cell-1", inside)
            ok, reason = read_guard_hook.adjudicate(
                {"tool_name": "Read", "tool_input": {"file_path": inside}}, scope,
                env={read_guard_hook.ENV_ENTRY_ID: "cell-9"})
            self.assertFalse(ok)
            self.assertIn("cell-9", reason)

    def test_main_reads_the_real_environment(self):
        with tempfile.TemporaryDirectory() as d:
            inside = os.path.join(d, "a.py"); open(inside, "w").close()
            outside = os.path.join(d, "b.py"); open(outside, "w").close()
            scope = self._scoped(d, "cell-1", inside)
            payload = json.dumps({"tool_name": "Read", "tool_input": {"file_path": outside}})
            with mock.patch.dict(os.environ, {read_guard_hook.ENV_ENTRY_ID: "cell-1"}), \
                 mock.patch("sys.stdin", io.StringIO(payload)), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                rc = read_guard_hook.main([scope])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"], "deny")


class TestMain(unittest.TestCase):
    def setUp(self):
        # main() intentionally reads the real os.environ (spec 5.3) via the
        # two-arg adjudicate(payload, path) call inside it -- every test here
        # except test_main_reads_the_real_environment (TestEnvBinding, which
        # patches its own known value) relies on NO env binding applying, so
        # a stray PANOPTICON_ENTRY_ID in the operator's shell must be scrubbed
        # the same way as TestAdjudicate.setUp / TestInstallUninstall.setUp.
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(read_guard_hook.ENV_ENTRY_ID, None)

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

    def test_main_denies_when_adjudication_raises(self):
        # I2: main() must fail CLOSED (a deny response, exit 0 -- a non-2 exit
        # is non-blocking in Claude Code and the tool would proceed) rather
        # than crash out with a bare traceback and an unhandled exit code
        # when adjudicate() raises for any reason.
        with tempfile.TemporaryDirectory() as d:
            scope_path = os.path.join(d, "scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({"e": _scope()}, fh)
            # Real repro: a NUL byte in transcript_path reaches glob.glob /
            # os.path.isfile via subagent_transcript() and raises ValueError.
            payload = {"tool_name": "Read", "agent_id": "a", "transcript_path": "bad\x00path.jsonl",
                       "tool_input": {"file_path": os.path.join(d, "x")}}
            rc, out = self._run(payload, [scope_path])
            self.assertEqual(0, rc)
            body = json.loads(out)["hookSpecificOutput"]
            self.assertEqual("deny", body["permissionDecision"])
            self.assertIn("read guard crashed", body["permissionDecisionReason"])

        # Belt-and-suspenders: any other exception from adjudicate() too.
        with tempfile.TemporaryDirectory() as d:
            parent = os.path.join(d, "s.jsonl"); open(parent, "w").close()
            scope_path = os.path.join(d, "scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({"e": _scope()}, fh)
            _write_subagent_transcript(parent, "a", "panopticon-entry: e\n")
            payload = {"tool_name": "Read", "agent_id": "a", "transcript_path": parent,
                       "tool_input": {"file_path": os.path.join(d, "x")}}
            with mock.patch.object(rg, "adjudicate", side_effect=RuntimeError("boom")):
                rc, out = self._run(payload, [scope_path])
            self.assertEqual(0, rc)
            body = json.loads(out)["hookSpecificOutput"]
            self.assertEqual("deny", body["permissionDecision"])
            self.assertIn("read guard crashed", body["permissionDecisionReason"])
            self.assertIn("boom", body["permissionDecisionReason"])

    def test_a_non_hashable_tool_name_denies_instead_of_crashing(self):
        # #2394: the roster test is a set membership, so a list or dict
        # `tool_name` raises TypeError. Above the envelope that raise escaped
        # main(), and a non-2 exit is NON-blocking -- the Read proceeded.
        with tempfile.TemporaryDirectory() as d:
            parent = os.path.join(d, "s.jsonl"); open(parent, "w").close()
            scope_path = os.path.join(d, "scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({"e": _scope()}, fh)
            _write_subagent_transcript(parent, "a", "panopticon-entry: e\n")
            payload = {"tool_name": ["Read"], "agent_id": "a", "transcript_path": parent,
                       "tool_input": {"file_path": "x"}}
            rc, out = self._run(payload, [scope_path])
            self.assertEqual(0, rc)
            body = json.loads(out)["hookSpecificOutput"]
            self.assertEqual("deny", body["permissionDecision"])
            self.assertIn("read guard crashed", body["permissionDecisionReason"])
            self.assertIn("unhashable", body["permissionDecisionReason"])
            # The relocated roster return is still PERMISSIVE for a non-roster name.
            payload["tool_name"] = "Bash"
            self.assertEqual((0, ""), self._run(payload, [scope_path]))

    def test_malformed_and_non_dict_stdin_are_tolerated(self):
        for raw in ("{not json", "[1, 2]"):
            with self.subTest(raw=raw):
                self.assertEqual((0, ""), self._run(raw, ["/nonexistent/scope.json"]))

    def test_a_payload_too_deep_to_parse_denies_instead_of_crashing_open(self):
        """#3186: the parse sat OUTSIDE the fail-closed envelope and caught ValueError only, so a deep
        payload escaped as RecursionError -- exit 1, which Claude Code treats as NON-blocking: the read
        went ahead unguarded. It denies now, on the hook's own channel (deny JSON, rc 0). Where the
        interpreter parses the payload it is adjudicated like any other."""
        def deep(n):
            return '{"tool_name": "Read", "tool_input": {"file_path": "/tmp/x", "x": %s}}' % ("[" * n + "]" * n)

        def denied(rc, out, why):
            body = json.loads(out)["hookSpecificOutput"]
            return (rc, body["permissionDecision"], body["permissionDecisionReason"]) == (
                0, "deny", "read guard: payload too deep to adjudicate (%s)" % why)

        # A real deep payload never crashes the hook: where this interpreter parses it (the depth that
        # overflows depends on the platform's C stack -- 100,000 parses on CI's x64 3.14), it is adjudicated
        # like any payload; where it cannot, it is the named deny.
        for n in (1_000, 100_000):
            with self.subTest(n=n):
                rc, out = self._run(deep(n), ["/nonexistent/scope.json"])
                self.assertEqual(0, rc)
                self.assertTrue("too deep" not in out or denied(rc, out, "RecursionError"))
        # The parse failing, whatever the depth that makes it fail here: a deny naming the error.
        for error in (RecursionError, MemoryError):
            with self.subTest(error=error.__name__), mock.patch.object(rg.json, "load", side_effect=error):
                self.assertTrue(denied(*self._run(deep(1), ["/nonexistent/scope.json"]), error.__name__))

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
        # test_install_overwrites_a_planted_row_under_a_dispatched_empty_scope_id
        # below calls the two-arg adjudicate(payload, scope_path); guard the
        # same ambient-env leak as TestAdjudicate.setUp.
        patcher = mock.patch.dict(os.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop(read_guard_hook.ENV_ENTRY_ID, None)
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
        self.assertEqual({"e1": {"files": [os.path.realpath(self.a)], "dirs": [],
                                 "reads": [], "escapes": {}}},
                         rg._read_scope_file(self.scope_path))
        hooks = self._settings()["hooks"]["PreToolUse"]
        self.assertEqual(1, len(hooks))
        self.assertEqual(rg._MATCHER, hooks[0]["matcher"])
        cmd = hooks[0]["hooks"][0]["command"]
        self.assertTrue(cmd.startswith(rg._HOOK_CMD))
        # #1633: the command is a shell string, so what it must carry is an
        # ARGUMENT naming the scope file -- whatever quoting that takes.
        self.assertEqual([os.path.realpath(os.sys.executable), "-I", os.path.abspath(rg.__file__),
                          os.path.abspath(self.scope_path)], shlex.split(cmd))
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
        self.assertEqual({"e1": {"files": [], "dirs": [], "reads": [], "escapes": {}}},
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
        self.assertEqual({"files": [], "dirs": [], "reads": [], "escapes": {}},
                         on_disk["verify-tool-X"])
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

    def test_hook_cmd_is_absolute_and_shell_quoted(self):
        # #495: absolute, so the hook resolves under both layouts. #1633: the
        # command is SHELL SOURCE, so the pin is what a shell makes of it --
        # A substring check could pass a command that runs anything a
        # `$(...)` in the checkout path asks for.
        self.assertEqual([os.path.realpath(os.sys.executable), "-I",
                          os.path.abspath(rg.__file__)],
                         shlex.split(rg._HOOK_CMD))

    def test_interpreter_must_be_absolute_and_usable_when_emitting(self):
        for executable in ("python3", "/missing/panopticon-python"):
            with self.subTest(executable=executable), \
                 mock.patch.object(rg.sys, "executable", executable), \
                 self.assertRaisesRegex(RuntimeError, "interpreter"):
                rg._hook_entry(self.scope_path)


class TestEntryIdsMatchTheSpecIdGrammar(unittest.TestCase):
    """M3 / design spec 4.4: "a test pins that every id matches
    `^[A-Za-z0-9._:-]+$`". marker_line() itself is deliberately more
    permissive than this (test_marker_round_trips_any_driver_generated_id
    above) -- this test pins the OTHER half: every id a real builder actually
    produces stays inside that grammar, one entry of each kind."""

    _ID_RE = re.compile(r"^[A-Za-z0-9._:-]+$")

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(os.path.join(self.root, ".panopticon"))
        self.addCleanup(self._t.cleanup)
        write_host_evidence(self.root, {c: hosts.PROVEN for c in hosts.CAPABILITIES})
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}
        self.files = ["a.py"]
        self.bundle = ocrdb.load_bundle()
        self.cell = [{"id": "F1", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
                      "category": "SEC", "location": {"file": "a.py", "line": 1},
                      "description": "d"}]

    def test_entry_ids_match_the_spec_id_grammar(self):
        entries = {
            "scout": coverage._scout_entry(
                self.root, self.manifest, "Auth", self.files, "claude"),
            "cell": review._cell_entry(
                self.root, self.manifest, "Auth", "SEC", self.files, [], "claude", self.bundle),
            "verify": verify_phase._verify_entry(
                self.root, self.manifest, "Auth", "SEC", self.files, self.cell, "claude",
                self.bundle, "primary"),
            "tool-verify": verify_tools_phase._tool_verify_entry(
                self.root, self.manifest, "q1",
                {"id": "T-1", "severity": "HIGH",
                 "location": {"file": "a.py", "line_start": 1}}, "claude"),
            "setup-scan": setup._setup_scan_entry(self.root, "BRIEF", "claude"),
        }
        self.assertEqual({"scout", "cell", "verify", "tool-verify", "setup-scan"}, set(entries))
        for kind, entry in entries.items():
            with self.subTest(kind=kind):
                self.assertRegex(entry["id"], self._ID_RE)


if __name__ == "__main__":
    unittest.main()


class TestAtomicWriteRefusesASymlinkedTmp(unittest.TestCase):
    """I7 (plan 6 final review): `_atomic_write_json` staged every settings,
    allowlist and scope write at `<path>.tmp` with a plain `open(tmp, "w")`.

    A redteam target is untrusted, and the run folder it is scanned in sits
    inside it: a pre-planted `<path>.tmp` symlink pointing anywhere the
    invoking user can write -- a dotfile, authorized_keys -- was FOLLOWED, and
    the guard's own JSON clobbered that file. Same class of bug as #run9
    SEC-X0X, which `runio._open_w_nofollow` closed for `.panopticon`
    artifacts; the hooks must stay standalone (they run as their own
    subprocess and may not import the driver's packages), so they carry the
    os-flag form themselves."""

    def _planted(self, d, name):
        outside = os.path.join(d, "outside.txt")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write("PRECIOUS")
        target = os.path.join(d, name)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("{}")
        os.symlink(outside, target + ".tmp")
        return outside, target

    def test_the_planted_link_is_neutralized_and_its_target_untouched(self):
        with tempfile.TemporaryDirectory() as d:
            outside, target = self._planted(d, "settings.json")
            guard_rules.atomic_write_json(target, {"hooks": {"PreToolUse": []}}, indent=2)
            with open(outside, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "PRECIOUS")
            self.assertFalse(os.path.islink(target))
            self.assertEqual(json.load(open(target, encoding="utf-8")),
                             {"hooks": {"PreToolUse": []}})
            self.assertFalse(os.path.exists(target + ".tmp"))

    def test_the_real_writer_that_arms_the_guard_refuses_it_too(self):
        with tempfile.TemporaryDirectory() as d:
            outside, settings = self._planted(d, "settings.json")
            guard_rules._write_hook_entry(settings, rg.__file__,
                                         rg._hook_entry(os.path.join(d, "read-scope.json")))
            with open(outside, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "PRECIOUS")
            with open(settings, encoding="utf-8") as fh:
                self.assertIn("PreToolUse", fh.read())


class TestTheHookNeverCrashesAtImport(unittest.TestCase):
    """#1996 finding 1: the one raise that sat OUTSIDE the fail-closed envelope.

    `_HOOK_ARGV = _trusted_hook_argv()` ran at module IMPORT, and
    `_trusted_hook_argv` raises when `sys.executable` is empty or relative.
    `main()`'s `except Exception` is the module's never-crash contract and it
    cannot cover an import-time raise -- and in the hook PROCESS a crash is
    fail-OPEN, because Claude Code treats any non-2 exit as a non-blocking
    error and lets the Read proceed. The evaluation is now lazy and happens
    inside main()'s try, so the same condition DENIES.
    """

    SCRIPT = os.path.abspath(rg.__file__)

    def _import_with(self, executable):
        """Import the module in a FRESH interpreter with sys.executable set.

        A fresh process, not `mock.patch`: the defect is what happens while the
        module body runs, which an already-imported module can no longer show.
        `-I` mirrors the registered hook's own launch; the explicit
        `sys.path.insert` stands in for the script directory that `-I <script>`
        puts on the path and `-I -c` does not.
        """
        program = ("import sys; sys.path.insert(0, %r); sys.executable = %r; "
                   "import read_guard_hook; print('imported')"
                   % (os.path.dirname(self.SCRIPT), executable))
        return __import__("subprocess").run(
            [os.path.realpath(os.sys.executable), "-I", "-c", program],
            capture_output=True, text=True, timeout=60)

    def test_importing_with_an_unusable_interpreter_does_not_raise(self):
        for executable in ("", "python3", "/missing/panopticon-python"):
            with self.subTest(executable=executable):
                proc = self._import_with(executable)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertIn("imported", proc.stdout)
                self.assertNotIn("RuntimeError", proc.stderr)

    def test_main_denies_instead_of_crashing_when_the_interpreter_is_unusable(self):
        with tempfile.TemporaryDirectory() as d:
            parent = os.path.join(d, "s.jsonl"); open(parent, "w").close()
            a = os.path.join(d, "a.py"); open(a, "w").close()
            scope_path = os.path.join(d, "scope.json")
            with open(scope_path, "w", encoding="utf-8") as fh:
                json.dump({"e": _scope(files=[a])}, fh)
            _write_subagent_transcript(parent, "a", "panopticon-entry: e\n")
            payload = json.dumps({"tool_name": "Read", "agent_id": "a",
                                  "transcript_path": parent,
                                  "tool_input": {"file_path": a}})   # an ALLOWED read
            out = io.StringIO()
            with mock.patch.object(rg.sys, "executable", ""), \
                 mock.patch("sys.stdin", io.StringIO(payload)), \
                 contextlib.redirect_stdout(out):
                rc = rg.main([scope_path])
            # The module's deny shape: exit 0 plus the deny JSON. A non-2,
            # non-zero exit is exactly the non-blocking error this must not be.
            self.assertEqual(rc, 0)
            body = json.loads(out.getvalue())["hookSpecificOutput"]
            self.assertEqual(body["permissionDecision"], "deny")
            self.assertIn("interpreter", body["permissionDecisionReason"])

    def test_the_lazy_constants_still_answer_as_module_attributes(self):
        self.assertEqual(list(rg._HOOK_ARGV),
                         [os.path.realpath(os.sys.executable), "-I", self.SCRIPT])
        self.assertEqual(shlex.split(rg._HOOK_CMD), list(rg._HOOK_ARGV))
        self.assertEqual(rg._HOOK_ENTRY["matcher"], rg._MATCHER)
        self.assertEqual(rg._HOOK_ENTRY["hooks"][0]["command"], rg._HOOK_CMD)
        with self.assertRaises(AttributeError):
            rg._HOOK_NOT_A_REAL_NAME

    def test_the_docstring_keeps_its_design_provenance(self):
        # #1996 finding 2: the rewrite deleted the only in-tree pointer to the
        # read-confinement design doc, and the fail-closed contract this class
        # tests. Both are load-bearing prose, so pin them.
        doc = rg.__doc__
        for fragment in ("2026-09-12-panopticon-5.2-claude-read-confinement-design.md",
                         "#1070", "first-class-hosts spec 7.2", "R-P5-5",
                         "Never a crash, never a silent allow"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, doc)


class TestGlobThroughASymlink(unittest.TestCase):
    """#2063: the #1917 pattern rule was lexical, so `linkdir/*` -- `linkdir` an in-grant
    symlink to outside the grant -- listed what the grant never covered. The literal prefix is
    realpath'd per call; a wildcard is denied when the arm-time walk recorded an escaping link at
    or under that prefix, at any depth, and wherever the walk was capped or never ran."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = os.path.realpath(self.tmp.name)
        self.root, self.outside = os.path.join(base, "root"), os.path.join(base, "outside")
        for p in (os.path.join(self.root, "pkg", "a.py"), os.path.join(self.root, "clean", "c.py"),
                  os.path.join(self.outside, "secret.txt")):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").close()
        os.symlink(self.outside, os.path.join(self.root, "linkdir"))
        os.symlink(self.outside, os.path.join(self.root, "pkg", "deeplink"))
        os.symlink(os.path.join(self.root, "clean"), os.path.join(self.root, "inner"))
        self.scan = _scope(dirs=[self.root])

    def _glob(self, pattern, scope=None):
        return rg.decide("Glob", {"pattern": pattern, "path": self.root}, scope or self.scan)

    def test_the_walk_records_only_the_links_that_leave_the_grant(self):
        os.makedirs(os.path.join(self.root, ".git"))
        os.symlink(self.outside, os.path.join(self.root, ".git", "planted"))
        self.assertEqual({self.root: [os.path.join(self.root, "linkdir"),
                                      os.path.join(self.root, "pkg", "deeplink")]},
                         rg.guard_rules.grant_escapes([self.root]))

    def test_a_literal_prefix_through_an_escaping_link_is_denied(self):
        for pattern in ("linkdir/*", "linkdir/secret.txt", "linkdir", "pkg/deeplink/*",
                        "./linkdir/*.txt", "linkdir\\secret.txt"):
            with self.subTest(pattern=pattern):
                ok, reason = self._glob(pattern)
                self.assertFalse(ok, reason)
                self.assertIn("resolves outside your directory grant", reason)
                self.assertIn(repr(pattern), reason)

    def test_a_wildcard_with_an_escaping_link_under_its_prefix_is_denied_at_any_depth(self):
        for pattern in ("*/secret.txt", "**/secret.txt", "**/*", "*", "pkg/*", "pkg/**/*.py",
                        "p?g/*"):
            with self.subTest(pattern=pattern):
                ok, reason = self._glob(pattern)
                self.assertFalse(ok, reason)
                self.assertIn("a symlink under it leads outside your directory grant", reason)

    def test_the_rest_of_a_grant_with_an_escape_stays_listable(self):
        for pattern in ("clean/*.py", "clean/**", "inner/*.py", "inner/c.py", "pkg/a.py", "pkg",
                        "clean"):
            with self.subTest(pattern=pattern):
                self.assertEqual((True, ""), self._glob(pattern))

    def test_a_grant_with_no_escapes_allows_its_wildcards(self):
        os.remove(os.path.join(self.root, "linkdir"))
        os.remove(os.path.join(self.root, "pkg", "deeplink"))
        scope = _scope(dirs=[self.root])
        for pattern in ("*/c.py", "**/*.py", "*", "inner/*"):
            with self.subTest(pattern=pattern):
                self.assertEqual((True, ""), self._glob(pattern, scope))

    def test_a_capped_or_missing_walk_denies_wildcards_but_not_literals(self):
        capped = dict(self.scan, escapes=rg.guard_rules.grant_escapes([self.root], cap=1))
        self.assertEqual({self.root: None}, capped["escapes"])
        unwalked = {k: v for k, v in self.scan.items() if k != "escapes"}
        for scope in (capped, unwalked, dict(self.scan, escapes="junk")):
            with self.subTest(scope=sorted(scope)):
                self.assertFalse(self._glob("clean/*.py", scope)[0])
                self.assertEqual((True, ""), self._glob("clean/c.py", scope))

    def test_a_malformed_walk_on_disk_reads_as_no_walk(self):
        scope_path = os.path.join(self.tmp.name, "scope.json")
        with open(scope_path, "w", encoding="utf-8") as fh:
            json.dump({"scan": dict(self.scan, escapes={self.root: "junk"})}, fh)
        payload = {"tool_name": "Glob", "tool_input": {"pattern": "clean/*.py", "path": self.root},
                   "cwd": self.tmp.name}
        self.assertFalse(rg.adjudicate(payload, scope_path, env={rg.ENV_ENTRY_ID: "scan"})[0])
        payload["tool_input"]["pattern"] = "clean/c.py"
        self.assertEqual((True, ""), rg.adjudicate(payload, scope_path,
                                                   env={rg.ENV_ENTRY_ID: "scan"}))

    def test_the_installed_hook_refuses_the_escapes(self):
        settings, scope_path = (os.path.join(self.tmp.name, n) for n in ("s.json", "scope.json"))
        from scripts.probes.claude_read_guard import _fake_subagent
        parent = os.path.join(self.tmp.name, "session.jsonl")
        open(parent, "w").close()
        _fake_subagent(parent, "agent-z", "scan")
        rg.install([{"id": "scan", "scope": {"files": [], "dirs": [self.root], "reads": []}}],
                   settings_path=settings, scope_path=scope_path)
        with open(settings, encoding="utf-8") as fh:
            command = json.load(fh)["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        for pattern, allowed in (("linkdir/*", False), ("**/secret.txt", False),
                                 ("clean/*.py", True)):
            with self.subTest(pattern=pattern):
                payload = {"tool_name": "Glob", "agent_id": "agent-z", "cwd": self.tmp.name,
                           "transcript_path": parent, "hook_event_name": "PreToolUse",
                           "tool_input": {"pattern": pattern, "path": self.root}}
                proc = subprocess.run(shlex.split(command), input=json.dumps(payload),
                                      capture_output=True, text=True, check=False)
                self.assertEqual(allowed, '"deny"' not in proc.stdout, proc.stdout)

    def test_the_codex_broker_still_loads_a_scope_that_carries_escapes(self):
        from scripts import codex_read_tools
        reader = codex_read_tools.Reader(dict(self.scan, files=[], reads=[]), self.root)
        self.assertEqual({self.root}, reader.scope["dirs"])
