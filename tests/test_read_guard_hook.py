import contextlib
import io
import json
import os
import re
import shlex
import tempfile
import unicodedata
import unittest
from unittest import mock

from _test_helpers import hard_link_or_skip
from conftest import write_host_evidence
from scripts import hosts
import scripts.probes.claude as claude_probes
import scripts.ocrdb as ocrdb
import scripts.phases.coverage as coverage
import scripts.phases.review as review
import scripts.phases.setup as setup
import scripts.phases.verify as verify_phase
import scripts.phases.verify_tools as verify_tools_phase
import scripts.read_guard_hook as rg
from scripts import read_guard_hook


def _scope(files=(), dirs=(), reads=(), hard_linked=()):
    return {"files": [os.path.realpath(p) for p in files],
            "dirs": [os.path.realpath(p) for p in dirs],
            "reads": [os.path.realpath(p) for p in reads],
            "hard_linked": [os.path.realpath(p) for p in hard_linked]}


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
        self.assertEqual({"files": [], "dirs": [], "reads": [], "hard_linked": []}, out["e"])

    def test_hard_linked_is_realpathed_like_every_other_key(self):
        # #1683: the walker's result travels in the scope, and the rule that
        # reads it compares realpaths -- so this key is normalised exactly
        # like `files` and `dirs`, and an absent one is an empty list (an old
        # plan, and every entry that never got a directory grant).
        with tempfile.TemporaryDirectory() as d:
            d = os.path.realpath(d)
            planted = os.path.join(d, "root", "a", "b.txt")
            os.makedirs(os.path.dirname(planted), exist_ok=True)
            open(planted, "w").close()
            alias = os.path.join(d, "alias")
            os.symlink(os.path.join(d, "root"), alias)
            out = rg.scope_from_plan([
                {"id": "e1", "scope": {"dirs": [d],
                                       "hard_linked": [os.path.join(alias, "a", "b.txt")]}},
                {"id": "e2", "scope": {"dirs": [d]}}])
            self.assertEqual([planted], out["e1"]["hard_linked"])
            self.assertEqual([], out["e2"]["hard_linked"])
        self.assertIn("hard_linked", rg.SCOPE_KEYS)


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

    def test_a_hard_link_inside_a_directory_grant_is_denied(self):
        # #1642: realpath resolves SYMlinks, not HARD links, and a directory
        # grant is matched by name -- so a link planted inside the granted
        # subtree, naming a file outside it, read as in-scope. It IS the file.
        planted = hard_link_or_skip(self.outside, os.path.join(self.root, "innocent.py"))
        for tool, arguments in (("Read", {"file_path": planted}),
                                ("Grep", {"pattern": "x", "path": planted})):
            with self.subTest(tool=tool):
                ok, reason = rg.decide(tool, arguments, self.scan)
                self.assertFalse(ok, reason)
                self.assertIn("hard-linked", reason)
                self.assertIn("st_nlink=2", reason)

    def test_an_exact_grant_reads_a_hard_linked_file_whatever_its_link_count(self):
        # The other half of the rule: `files`/`reads` name a file the
        # orchestrator chose, and an exact grant has no subtree to hide in --
        # including when a directory grant also covers it (the normal cell
        # shape, a granted file inside the repository the scan is scoped to).
        planted = hard_link_or_skip(self.outside, os.path.join(self.root, "innocent.py"))
        for scope in (_scope(files=[planted]), _scope(reads=[planted]),
                      _scope(files=[planted], dirs=[self.root])):
            with self.subTest(scope=scope):
                self.assertEqual((True, ""), rg.decide("Read", {"file_path": planted}, scope))

    def test_a_path_with_no_inode_passes_through_to_the_tool(self):
        # Fix round 2 (N2): ENOENT/ENOTDIR are not "could not measure" -- they
        # are a successful measurement that there is NO INODE at that name, so
        # there is nothing for a read fence to confine. The scout profiles an
        # unknown tree by probing for absent marker files (go.mod, Cargo.toml),
        # and the setup scan is the only directory grant there is: denying those
        # probes reads as a fence and nudges it toward the #1683 Grep path. The
        # tool reports not-found, as it did before #1642.
        missing = os.path.join(self.root, "go.mod")
        self.assertEqual((True, ""), rg.decide("Read", {"file_path": missing}, self.scan))
        self.assertEqual((True, ""), rg.decide(
            "Grep", {"pattern": "x", "path": missing}, self.scan))
        # ENOTDIR: a path component that is a file, not a directory.
        through_file = os.path.join(self.root_file, "inner.py")
        self.assertEqual((True, ""), rg.decide("Read", {"file_path": through_file}, self.scan))
        # A dangling symlink resolves to a name with no inode: same answer.
        dangling = os.path.join(self.root, "dangling.py")
        os.symlink(os.path.join(self.root, "nowhere.py"), dangling)
        self.assertEqual((True, ""), rg.decide("Read", {"file_path": dangling}, self.scan))

    def test_a_target_the_rule_cannot_stat_is_denied_not_allowed(self):
        # Fix round 1 (F4): the rule used to answer "" -- allow -- when os.stat
        # raised, which is a guard answering "yes" about something it could not
        # measure. It denies now, with the error in the reason, and only inside
        # a directory grant: an exact grant never reaches the stat. Everything
        # except the no-inode errnos above: EACCES, ELOOP, EIO, ENAMETOOLONG.
        with mock.patch.object(os, "stat", side_effect=PermissionError("no stat here")):
            ok, reason = rg.decide("Read", {"file_path": self.root_file}, self.scan)
            self.assertFalse(ok, reason)
            self.assertIn("no stat here", reason)
            self.assertEqual((True, ""), rg.decide(
                "Read", {"file_path": self.root_file}, _scope(files=[self.root_file])))

    def test_a_directory_grants_ordinary_files_and_directories_are_unchanged(self):
        # A directory's st_nlink is its subdirectory count, so the rule is for
        # REGULAR files only: over a grant whose walk recorded NOTHING, Grep
        # and Glob of the granted root stay allowed -- which is every clean
        # tree, and is what #1683 had to keep working.
        self.assertEqual((True, ""), rg.decide("Read", {"file_path": self.root_file}, self.scan))
        self.assertEqual((True, ""), rg.decide("Grep", {"pattern": "x", "path": self.root_file}, self.scan))
        self.assertEqual((True, ""), rg.decide("Grep", {"pattern": "x", "path": self.root}, self.scan))
        self.assertEqual((True, ""), rg.decide("Glob", {"pattern": "*.py", "path": self.root}, self.scan))

    def test_a_directory_grep_above_a_recorded_link_is_denied_and_names_it(self):
        # #1683. The hook adjudicates the PATH ARGUMENT and the HOST's own
        # Grep/Glob does the traversal, so a granted directory used to hand
        # over the very file `_hard_link_reason` refuses by name. The walk is
        # the driver's (phases/hard_links), once, when the grant is built;
        # what is left here is a list test.
        os.makedirs(os.path.join(self.root, "a"), exist_ok=True)
        planted = hard_link_or_skip(self.outside, os.path.join(self.root, "a", "b.txt"))
        scope = _scope(dirs=[self.root], hard_linked=[planted])
        for tool, arguments in (("Grep", {"pattern": "x", "path": self.root}),
                                ("Glob", {"pattern": "*", "path": self.root}),
                                ("Grep", {"pattern": "x", "path": os.path.join(self.root, "a")})):
            with self.subTest(tool=tool, path=arguments["path"]):
                ok, reason = rg.decide(tool, arguments, scope)
                self.assertFalse(ok, reason)
                self.assertIn("b.txt", reason)
                self.assertIn("narrower", reason)

    def test_a_sibling_directory_with_no_recorded_link_is_still_greppable(self):
        # The rule denies exactly the traversals that would cross a link. A
        # profiling scan that may only Read files one at a time is not the
        # same scan, so a clean subtree keeps its Grep and its Glob.
        clean = os.path.join(self.root, "c")
        os.makedirs(clean, exist_ok=True)
        scope = _scope(dirs=[self.root],
                       hard_linked=[os.path.join(self.root, "a", "b.txt")])
        self.assertEqual((True, ""), rg.decide("Grep", {"pattern": "x", "path": clean}, scope))
        self.assertEqual((True, ""), rg.decide("Glob", {"pattern": "*", "path": clean}, scope))

    def test_the_overflow_encoding_denies_every_directory_under_the_grant(self):
        # Past the walker's cap the driver records the granted directory
        # ITSELF, which is why the rule tests both containment directions: a
        # recorded path AT or ABOVE the argument denies it too.
        deep = os.path.join(self.root, "pkg", "sub")
        os.makedirs(deep, exist_ok=True)
        scope = _scope(dirs=[self.root], hard_linked=[self.root])
        for path in (self.root, deep):
            with self.subTest(path=path):
                self.assertFalse(rg.decide("Grep", {"pattern": "x", "path": path}, scope)[0])

    def test_a_recorded_link_denies_a_case_folded_directory_argument(self):
        # B1 (fix round 2). APFS/HFS+/NTFS resolve names case-insensitively,
        # so a byte-exact list test let `Grep <root>/src` through with
        # `<root>/Src/x.txt` recorded -- and the host then opened the very
        # directory the fence had refused. A DENIAL may be folded: the worst a
        # fold can do here is over-deny.
        src = os.path.join(self.root, "src")
        clean = os.path.join(self.root, "clean")
        for d in (src, clean):
            os.makedirs(d, exist_ok=True)
        scope = _scope(dirs=[self.root],
                       hard_linked=[os.path.join(self.root, "Src", "x.txt")])
        ok, reason = rg.decide("Grep", {"pattern": "x", "path": src}, scope)
        self.assertFalse(ok, reason)
        self.assertIn("x.txt", reason)
        self.assertEqual((True, ""), rg.decide("Grep", {"pattern": "x", "path": clean}, scope))

    def test_a_recorded_link_denies_a_differently_normalised_argument(self):
        # The same bypass through Unicode: NFC and NFD "café" are two byte
        # strings and one directory on macOS. Built both ways explicitly, so
        # this measures the fold and not the filesystem's normalisation.
        nfd = os.path.join(self.root, unicodedata.normalize("NFD", "café"))
        os.makedirs(nfd, exist_ok=True)
        nfc = os.path.join(self.root, unicodedata.normalize("NFC", "café"))
        scope = _scope(dirs=[self.root], hard_linked=[os.path.join(nfc, "x.txt")])
        self.assertFalse(rg.decide("Grep", {"pattern": "x", "path": nfd}, scope)[0])

    def test_the_dirs_grant_itself_is_never_folded(self):
        # The asymmetry, pinned. Folding a DENIAL can only over-deny; folding
        # the GRANT would ADMIT /REPO/x under a /repo grant on a case-sensitive
        # volume. Strings only, no filesystem: `isdir` is False, so this is the
        # scope test rather than the directory branch.
        scope = {"files": [], "dirs": ["/repo"], "reads": [], "hard_linked": []}
        ok, reason = rg.decide("Grep", {"pattern": "x", "path": "/REPO/x.py"}, scope)
        self.assertFalse(ok, reason)
        self.assertIn("outside your cell's scope", reason)
        self.assertFalse(rg.decide("Read", {"file_path": "/REPO/x.py"}, scope)[0])

    def test_the_overflow_encoding_says_the_grant_is_closed_not_to_narrow(self):
        # I2 (fix round 2): with the review ROOT recorded, the old wording
        # called it "a hard-linked file beneath" the argument -- it is neither
        # -- and told the agent to grep a narrower directory, which is denied
        # at every depth. A grant closed whole says so, and says what to do.
        deep = os.path.join(self.root, "pkg", "sub")
        os.makedirs(deep, exist_ok=True)
        scope = _scope(dirs=[self.root], hard_linked=[self.root])
        for path in (self.root, deep):
            with self.subTest(path=path):
                ok, reason = rg.decide("Grep", {"pattern": "x", "path": path}, scope)
                self.assertFalse(ok, reason)
                self.assertIn("the whole directory grant is closed", reason)
                self.assertNotIn("narrower", reason)
                self.assertIn("Read files by name", reason)
        # A link genuinely BENEATH the argument keeps the other wording.
        _ok, reason = rg.decide(
            "Grep", {"pattern": "x", "path": self.root},
            _scope(dirs=[self.root], hard_linked=[os.path.join(deep, "b.txt")]))
        self.assertIn("narrower", reason)
        self.assertNotIn("closed", reason)

    def test_a_recorded_path_is_separator_bounded_like_every_other(self):
        # /root/ab recorded must not deny a Grep of /root/a.
        os.makedirs(os.path.join(self.root, "a"), exist_ok=True)
        scope = _scope(dirs=[self.root],
                       hard_linked=[os.path.join(self.root, "ab", "x.txt")])
        self.assertEqual((True, ""), rg.decide(
            "Grep", {"pattern": "x", "path": os.path.join(self.root, "a")}, scope))

    def test_a_recorded_link_leaves_file_arguments_to_the_st_nlink_rule(self):
        # `hard_linked` gates DIRECTORY arguments only. A read whose argument
        # is the file is still answered by `_hard_link_reason` -- which reads
        # the live link count rather than the list, and still lets an EXACT
        # grant through whatever that count is.
        planted = hard_link_or_skip(self.outside, os.path.join(self.root, "innocent.py"))
        scope = _scope(dirs=[self.root], hard_linked=[planted])
        ok, reason = rg.decide("Read", {"file_path": planted}, scope)
        self.assertFalse(ok, reason)
        self.assertIn("st_nlink=2", reason)
        self.assertNotIn("narrower", reason)
        self.assertEqual((True, ""), rg.decide(
            "Read", {"file_path": planted},
            _scope(files=[planted], dirs=[self.root], hard_linked=[planted])))

    def test_a_link_planted_after_the_grant_is_the_stated_residual(self):
        # Honest limit, pinned so it stays visible: the list is a snapshot of
        # the tree AT GRANT TIME. The tree is static for the length of a run,
        # and a target that can write into it mid-run has already won more
        # than this. Nothing recorded -> nothing denied.
        hard_link_or_skip(self.outside, os.path.join(self.root, "innocent.py"))
        self.assertEqual((True, ""), rg.decide("Grep", {"pattern": "x", "path": self.root}, self.scan))

    def test_a_scope_with_no_hard_linked_key_is_read_as_an_empty_list(self):
        # An old scope file (or a hand-built plan) keeps working rather than
        # raising KeyError inside a hook that must never crash.
        legacy = {"files": [], "dirs": [os.path.realpath(self.root)], "reads": []}
        self.assertEqual((True, ""), rg.decide("Grep", {"pattern": "x", "path": self.root}, legacy))

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

    def test_a_hard_link_planted_in_a_directory_grant_is_denied_and_names_the_entry(self):
        planted = hard_link_or_skip(self.outside, os.path.join(self.root, "innocent.py"))
        allow, reason = rg.adjudicate(self._payload("Read", "scan-agent", file_path=planted),
                                      self.scope_path)
        self.assertFalse(allow, reason)
        self.assertIn("hard-linked", reason)
        self.assertIn("setup-scan", reason)

    def test_a_directory_grep_over_a_recorded_link_is_denied_end_to_end(self):
        # #1683 through the real entry point: a link planted in the granted
        # tree, the walk's result armed in the scope file, and the payload the
        # host would send. The denial names the file AND the bound entry.
        planted = hard_link_or_skip(self.outside, os.path.join(self.root, "innocent.py"))
        with open(self.scope_path, "w", encoding="utf-8") as fh:
            json.dump({"setup-scan": _scope(dirs=[self.root], hard_linked=[planted])}, fh)
        for tool, arguments in (("Grep", {"pattern": "x", "path": self.root}),
                                ("Glob", {"pattern": "*", "path": self.root})):
            with self.subTest(tool=tool):
                allow, reason = rg.adjudicate(
                    self._payload(tool, "scan-agent", **arguments), self.scope_path)
                self.assertFalse(allow, reason)
                self.assertIn("innocent.py", reason)
                self.assertIn("setup-scan", reason)

    def test_an_old_scope_file_without_the_key_still_arms(self):
        # The key is additive: a scope file written before #1683 loads with an
        # empty list rather than denying every read in the run.
        with open(self.scope_path, "w", encoding="utf-8") as fh:
            json.dump({"setup-scan": {"files": [], "dirs": [os.path.realpath(self.root)],
                                      "reads": []}}, fh)
        self.assertTrue(rg.adjudicate(
            self._payload("Grep", "scan-agent", pattern="x", path=self.root),
            self.scope_path)[0])

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
                                 "reads": [], "hard_linked": []}},
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
        self.assertEqual({"e1": {"files": [], "dirs": [], "reads": [], "hard_linked": []}},
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
        self.assertEqual({"files": [], "dirs": [], "reads": [], "hard_linked": []},
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
            rg._atomic_write_json(target, {"hooks": {"PreToolUse": []}}, indent=2)
            with open(outside, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "PRECIOUS")
            self.assertFalse(os.path.islink(target))
            self.assertEqual(json.load(open(target, encoding="utf-8")),
                             {"hooks": {"PreToolUse": []}})
            self.assertFalse(os.path.exists(target + ".tmp"))

    def test_the_real_writer_that_arms_the_guard_refuses_it_too(self):
        with tempfile.TemporaryDirectory() as d:
            outside, settings = self._planted(d, "settings.json")
            rg._write_hook_entry(settings, os.path.join(d, "read-scope.json"))
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
