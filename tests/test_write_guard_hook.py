import contextlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scripts.write_guard_hook as wg


class TestDecide(unittest.TestCase):
    def setUp(self):
        self.allow = {os.path.realpath(".panopticon/findings-g1-code-panel_review.json")}

    def test_write_to_allowed_out_file_is_permitted(self):
        ok, _ = wg.decide("Write", ".panopticon/findings-g1-code-panel_review.json", self.allow)
        self.assertTrue(ok)

    def test_write_outside_allowlist_is_blocked(self):
        ok, reason = wg.decide("Write", "skill/scripts/synthesize.py", self.allow)
        self.assertFalse(ok)
        self.assertIn("outside", reason.lower())

    def test_write_to_sibling_findings_not_in_plan_is_blocked(self):
        ok, _ = wg.decide("Edit", ".panopticon/findings-g9-code-panel_review.json", self.allow)
        self.assertFalse(ok)

    def test_non_write_tool_is_permitted(self):
        ok, _ = wg.decide("Read", "/etc/passwd", self.allow)
        self.assertTrue(ok)

    def test_bash_is_not_adjudicated(self):
        # Documented scope (#680): the guard covers only _WRITE_TOOLS; Bash is
        # out of scope by construction (session-wide hook can't distinguish the
        # orchestrator's own shell use). This test pins the STATED behavior so
        # a future reader doesn't mistake the allow for a covered case.
        ok, reason = wg.decide("Bash", "skill/scripts/synthesize.py", self.allow)
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_symlink_at_the_target_itself_is_refused(self):
        # #481: a symlink sitting AT an allowlisted path string authorizes by
        # string match unless refused; decide() must reject the link outright.
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real_elsewhere.json")
            open(real, "w").close()
            link = os.path.join(d, "findings.json")
            os.symlink(real, link)
            # Even if the LINK path is on the allowlist, the write is refused.
            ok, reason = wg.decide("Write", link, {os.path.realpath(link)})
            self.assertFalse(ok)
            self.assertIn("symlink", reason.lower())

    def test_symlinked_parent_dir_is_not_authorized(self):
        # A write whose PARENT directory is a symlink must not pass by string
        # match: realpath(target) escapes the allowlisted location even though
        # abspath(target) equals the allowlisted string and the final component
        # is not itself a link.
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        real_dir = os.path.join(d, "real-elsewhere")
        os.makedirs(real_dir)
        linked_dir = os.path.join(d, "pan")
        os.symlink(real_dir, linked_dir)  # pan -> real-elsewhere
        target = os.path.join(linked_dir, "findings-g1.json")
        allow = {os.path.abspath(target)}  # allowlist built from the STRING path
        ok, reason = wg.decide("Write", target, allow)
        self.assertFalse(ok)
        self.assertIn("outside", reason.lower())

    def test_realpath_allowlist_still_authorizes_legit_write(self):
        # Same path on both sides with no symlinks anywhere must still allow.
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        target = os.path.join(d, "findings-g1.json")
        allow = wg.union_paths(wg.allowlist_from_plan([{"out_file": target}]))
        ok, _ = wg.decide("Write", target, allow)
        self.assertTrue(ok)

    def test_nul_byte_path_is_denied_not_raised(self):
        # os.path.realpath raises ValueError on an embedded NUL byte where
        # abspath/islink tolerate it; decide() must fail closed, not crash.
        ok, reason = wg.decide("Write", "bad\x00path.json", self.allow)
        self.assertFalse(ok)
        self.assertIn("denied", reason.lower())

    def test_non_string_file_path_is_denied_not_raised(self):
        # #768: a Write payload whose file_path is not a string (int/list/dict)
        # made os.path.abspath raise TypeError and crash the hook. It must fail
        # closed instead — a malformed write path is suspicious, never allowed.
        for bad in (123, ["a"], {"x": 1}, 3.14):
            ok, reason = wg.decide("Write", bad, self.allow)
            self.assertFalse(ok, bad)
            self.assertIn("denied", reason.lower())
        # empty/None-ish falsy values resolve to cwd — outside the allowlist,
        # denied, still no crash.
        for empty in ([], {}, None):
            ok, _ = wg.decide("Write", empty, self.allow)
            self.assertFalse(ok, empty)


class TestDecideRefusesTheMapping(unittest.TestCase):
    """F3: `decide` kept its name and signature while the module's natural
    "allowlist" object changed shape (#1571), so the pre-PR call --
    `decide(tool, path, allowlist_from_plan(plan))`, the exact expression this
    change had to rewrite in four call sites -- now tests the path against the
    mapping's KEYS and denies in silence.

    Fail-closed, but the silence is the hazard: it is the same "two
    indistinguishable shapes at one call site" that `allowlist_from_plan`
    itself refuses loudly for #1482, where an empty allowlist shipped and
    nobody noticed. Refuse it the same way."""

    def test_a_mapping_is_refused_loudly_not_denied_silently(self):
        with self.assertRaises(TypeError) as cm:
            wg.decide("Write", ".panopticon/a.json",
                      wg.allowlist_from_plan([{"id": "e", "out_file": ".panopticon/a.json"}]))
        self.assertIn("union_paths", str(cm.exception))

    def test_the_flat_union_is_what_it_takes(self):
        plan = [{"id": "e", "out_file": ".panopticon/a.json"}]
        ok, _ = wg.decide("Write", ".panopticon/a.json",
                          wg.union_paths(wg.allowlist_from_plan(plan)))
        self.assertTrue(ok)

    def test_a_non_write_tool_short_circuits_before_the_check(self):
        # The tool filter comes first, as it always did: a Read is not
        # adjudicated at all, whatever shape the third argument has.
        self.assertEqual(wg.decide("Read", "/etc/passwd", {}), (True, ""))


class TestCwdIndependence(unittest.TestCase):
    """#935: with an ABSOLUTE out_file (phases.review._cell_entry emits these), the guard
    authorizes the reviewer's write regardless of the cwd the hook runs in.
    A relative out_file did not: allowlist_from_plan realpaths against the
    install cwd, decide against the hook's cwd, so a subagent cwd !=
    orchestrator cwd silently denied the write and misplaced the file."""

    @contextlib.contextmanager
    def _in(self, path):
        prev = os.getcwd()
        os.chdir(path)
        try:
            yield
        finally:
            os.chdir(prev)

    def test_absolute_out_file_authorizes_write_from_a_different_cwd(self):
        with tempfile.TemporaryDirectory() as run_root, tempfile.TemporaryDirectory() as elsewhere:
            target = os.path.join(run_root, ".panopticon", "findings-g1-code-panel_review.json")
            allow = wg.union_paths(wg.allowlist_from_plan([{"out_file": target}]))  # install-time
            with self._in(elsewhere):  # subagent cwd
                ok, _ = wg.decide("Write", target, allow)
            self.assertTrue(ok)

    def test_relative_write_from_wrong_cwd_is_denied(self):
        # Documents WHY the plan must carry the absolute path: the same relative
        # name resolved from a different cwd is a different realpath -> denied.
        with tempfile.TemporaryDirectory() as run_root, tempfile.TemporaryDirectory() as elsewhere:
            target = os.path.join(run_root, ".panopticon", "findings-g1-code-panel_review.json")
            allow = wg.union_paths(wg.allowlist_from_plan([{"out_file": target}]))
            with self._in(elsewhere):
                ok, _ = wg.decide("Write", ".panopticon/findings-g1-code-panel_review.json", allow)
            self.assertFalse(ok)

    def test_absolute_out_file_with_spaces_round_trips(self):
        # The Tapestry workspace path contains a space (#935).
        with tempfile.TemporaryDirectory() as base:
            run_root = os.path.join(base, "Mini Vault")
            os.makedirs(os.path.join(run_root, ".panopticon"))
            target = os.path.join(run_root, ".panopticon", "findings-g1-code-panel_review.json")
            allow = wg.union_paths(wg.allowlist_from_plan([{"out_file": target}]))
            ok, _ = wg.decide("Write", target, allow)
            self.assertTrue(ok)


class TestAllowlistFromPlan(unittest.TestCase):
    def test_collects_out_files_absolute(self):
        plan = [{"out_file": ".panopticon/a.json"}, {"out_file": ".panopticon/b.json"}]
        al = wg.allowlist_from_plan(plan)
        self.assertEqual(
            wg.union_paths(al),
            {os.path.realpath(".panopticon/a.json"), os.path.realpath(".panopticon/b.json")}
        )

    def test_skips_non_string_out_file(self):
        plan = [{"out_file": ".panopticon/a.json"}, {"out_file": 123}, {"out_file": None}]
        al = wg.allowlist_from_plan(plan)
        self.assertEqual(wg.union_paths(al), {os.path.realpath(".panopticon/a.json")})

    def test_install_drops_planted_out_of_tree_allowlist_entries(self):
        # #run10 SEC-C1D: the target repo can ship its own
        # .panopticon/write-allowlist.json (the path is inside the scanned tree).
        # install() used to UNION whatever was there, so a planted entry became a
        # writable target for every agent in the fan-out. Entries outside the
        # `.panopticon` tree we are installing into must be dropped.
        with tempfile.TemporaryDirectory() as d:
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano)
            allow = os.path.join(pano, "write-allowlist.json")
            planted = os.path.join(d, "skill", "scripts", "driver.py")
            with open(allow, "w") as fh:
                json.dump(wg.allowlist_document({"planted-cell": [
                    planted, os.path.expanduser("~/.ssh/authorized_keys")]}), fh)
            out_file = os.path.join(pano, "findings-app-SEC.json")
            settings = os.path.join(d, "settings.json")
            wg.install([{"out_file": out_file}],
                       settings_path=settings, allowlist_path=allow)
            with open(allow) as fh:
                final = set(json.load(fh)["paths"])
            self.assertIn(os.path.realpath(out_file), final)   # our own grant stands
            self.assertNotIn(planted, final)                   # planted entry dropped
            self.assertFalse([p for p in final if "authorized_keys" in p])

    def test_install_keeps_a_concurrent_fanouts_in_flight_grant(self):
        # The #11 property must survive SEC-C1D: a REAL in-flight grant from a
        # concurrent fan-out is a findings out_file in the same .panopticon tree,
        # so it is still carried forward and never silently revoked.
        with tempfile.TemporaryDirectory() as d:
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano)
            allow = os.path.join(pano, "write-allowlist.json")
            inflight = os.path.realpath(os.path.join(pano, "findings-other-COD.json"))
            with open(allow, "w") as fh:
                json.dump(wg.allowlist_document({"other-COD": [inflight]}), fh)
            settings = os.path.join(d, "settings.json")
            wg.install([{"out_file": os.path.join(pano, "findings-app-SEC.json")}],
                       settings_path=settings, allowlist_path=allow)
            with open(allow) as fh:
                final = set(json.load(fh)["paths"])
            self.assertIn(inflight, final)     # concurrent fan-out stays armed

    def test_symlinked_panopticon_parent_is_refused(self):
        # TST-A2B (run-9): allowlist_from_plan raises when an out_file's parent dir
        # is named .panopticon AND is itself a symlink -- a target could redirect
        # findings writes by planting that link. The guard existed but no test ever
        # constructed the triggering plan; this pins it.
        #
        # #1640 generalised the rule from "the immediate parent, if it is named
        # .panopticon" to every component, so the wording this asserts is the
        # general one -- the case itself is unchanged and must stay refused.
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real-dir")
            os.mkdir(real)
            link = os.path.join(d, ".panopticon")
            os.symlink(real, link)
            plan = [{"out_file": os.path.join(link, "findings-app-SEC.json")}]
            with self.assertRaises(ValueError) as cm:
                wg.allowlist_from_plan(plan)
            self.assertIn("symlinked directory", str(cm.exception))
            self.assertIn(link, str(cm.exception))


class TestNestedSymlinkComponents(unittest.TestCase):
    """#1640 (run-13 AGT-861284148): every component of a findings path is
    checked, not just the one named `.panopticon`.

    The old rule refused a symlink only when the out_file's IMMEDIATE parent
    was named `.panopticon`, and a real findings path is
    `<root>/.panopticon/runs/<tag>/findings-<group>-<domain>.json` -- whose
    immediate parent is the run folder. A target that commits
    `.panopticon/runs` as a link therefore had `allowlist_from_plan` store the
    EXTERNAL realpath as an allowed destination, and `_resolve_target` resolve
    the reviewer's Write to that same external path: install and enforcement
    agreed on a destination outside the artifact tree, which is what makes it
    a hole rather than a mismatch.
    """

    def _planted(self, component="runs"):
        """(review root, out_file, the symlinked component) -- a review root
        whose `.panopticon/<component>` is a link to somewhere else."""
        root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        elsewhere = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, elsewhere, ignore_errors=True)
        pano = os.path.join(root, ".panopticon")
        os.makedirs(pano)
        link = os.path.join(pano, component)
        os.symlink(elsewhere, link)
        os.makedirs(os.path.join(link, "r1"))
        return root, os.path.join(link, "r1", "findings-A-SEC.json"), link

    def test_an_intermediate_symlink_refuses_the_plan(self):
        _root, out_file, link = self._planted()
        with self.assertRaises(ValueError) as caught:
            wg.allowlist_from_plan([{"id": "A-SEC", "out_file": out_file}])
        self.assertIn("symlinked directory", str(caught.exception))
        self.assertIn(link, str(caught.exception))
        self.assertIn("runs", str(caught.exception))

    def test_enforcement_denies_the_same_path(self):
        # Both halves, because agreeing with the install is exactly the bug.
        _root, out_file, link = self._planted()
        target, reason = wg._resolve_target(out_file)
        self.assertIsNone(target)
        self.assertIn("symlinked directory", reason)
        self.assertIn(link, reason)

    def test_a_deeper_component_is_refused_too(self):
        # The run-tag folder, one level below `runs`.
        root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        elsewhere = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, elsewhere, ignore_errors=True)
        runs = os.path.join(root, ".panopticon", "runs")
        os.makedirs(runs)
        link = os.path.join(runs, "tag")
        os.symlink(elsewhere, link)
        with self.assertRaises(ValueError) as caught:
            wg.allowlist_from_plan([{"out_file": os.path.join(link, "findings-A-SEC.json")}])
        self.assertIn(link, str(caught.exception))

    def test_a_realpath_that_escaped_the_tree_is_refused_by_the_anchor(self):
        # The anchor, not the walk. Every DIRECTORY component here is real; the
        # escape is the out_file itself, a link `allowlist_from_plan` would
        # otherwise follow straight into its `realpath` grant -- the same
        # install-side hole one component lower. Whatever the components look
        # like, the resolved destination must still lie inside THIS review
        # root's artifact tree.
        root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        elsewhere = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, elsewhere, ignore_errors=True)
        run = os.path.join(root, ".panopticon", "runs", "r1")
        os.makedirs(run)
        outside = os.path.join(elsewhere, "target.json")
        open(outside, "w").close()
        out_file = os.path.join(run, "findings-A-SEC.json")
        os.symlink(outside, out_file)
        with self.assertRaises(ValueError) as caught:
            wg.allowlist_from_plan([{"out_file": out_file}])
        self.assertIn("outside", str(caught.exception))
        self.assertIn(outside, str(caught.exception))

    def test_an_ordinary_run_folder_is_still_granted(self):
        # The walk must not refuse the normal shape, or every run stops.
        root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        out_file = os.path.join(root, ".panopticon", "runs", "r1", "findings-A-SEC.json")
        os.makedirs(os.path.dirname(out_file))
        self.assertEqual({"A-SEC": [out_file]},
                         wg.allowlist_from_plan([{"id": "A-SEC", "out_file": out_file}]))
        target, reason = wg._resolve_target(out_file)
        self.assertIsNone(reason)
        self.assertEqual(out_file, target)

    def test_a_run_folder_that_does_not_exist_yet_is_still_granted(self):
        # The plan is written before the run folder is; a component with no
        # inode is not a link, and refusing it would refuse every first run.
        root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        out_file = os.path.join(root, ".panopticon", "runs", "r1", "findings-A-SEC.json")
        self.assertEqual({"A-SEC": [out_file]},
                         wg.allowlist_from_plan([{"id": "A-SEC", "out_file": out_file}]))

    def test_a_parent_component_cannot_strip_the_anchor(self):
        # #1640 fix round 1. `_components` normalises with `abspath`, which
        # collapses `..` LEXICALLY before the `.panopticon` test -- so a
        # declared out_file of `<root>/.panopticon/runs/r1/../../../src/x.json`
        # became `<root>/src/x.json`, carried no segment, and got neither the
        # walk nor the anchor: a grant on a SOURCE FILE. Unreachable today only
        # because `groups_schema._invalid_name` rejects `..` in a group name,
        # and a guard may not rest on an upstream regex.
        root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        os.makedirs(os.path.join(root, ".panopticon", "runs", "r1"))
        os.makedirs(os.path.join(root, "src"))
        escape = os.path.join(root, ".panopticon", "runs", "r1",
                              "..", "..", "..", "src", "x.json")
        with self.assertRaises(ValueError) as caught:
            wg.allowlist_from_plan([{"id": "A-SEC", "out_file": escape}])
        self.assertIn("findings output cannot contain '..'", str(caught.exception))
        # Fix round 2 (N1): and it names WHICH out_file. `install` raises with
        # no context of its own, so a 200-entry fan-out aborting on one bad
        # path used to tell the operator only that a `..` existed somewhere.
        self.assertIn(escape, str(caught.exception))
        target, reason = wg._resolve_target(escape)
        self.assertIsNone(target)
        self.assertIn("findings output cannot contain '..'", reason)
        self.assertIn(escape, reason)

    def test_a_parent_component_that_stays_inside_is_refused_too(self):
        # The rule is the COMPONENT, not where it lands: `runs/r1/../r2/f.json`
        # resolves inside the tree and is still refused. A guard that decided
        # from the destination would have to re-decide at every enforcement,
        # and the declared path has no business carrying one.
        root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        inside = os.path.join(root, ".panopticon", "runs", "r1", "..", "r2", "f.json")
        with self.assertRaises(ValueError) as caught:
            wg.allowlist_from_plan([{"out_file": inside}])
        self.assertIn("findings output cannot contain '..'", str(caught.exception))
        self.assertIn(inside, str(caught.exception))

    def test_a_dotted_name_that_is_not_a_component_is_fine(self):
        # `..` as part of a NAME is not a parent component. Refusing it would
        # be a string match pretending to be a path rule.
        root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        out_file = os.path.join(root, ".panopticon", "runs", "r1", "findings..A-SEC.json")
        os.makedirs(os.path.dirname(out_file))
        self.assertEqual({"<unbound>": [out_file]},
                         wg.allowlist_from_plan([{"out_file": out_file}]))

    def test_a_path_with_no_panopticon_segment_is_left_alone(self):
        # The probes' sandbox plans declare out_files with no artifact tree at
        # all. There is no `.panopticon` to anchor on, so there is no walk --
        # and `_confined_to_artifact_roots` already refuses to carry such a
        # grant forward. Widening the refusal here would break them.
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        out_file = os.path.join(d, "findings-probe.json")
        self.assertEqual({"<unbound>": [out_file]},
                         wg.allowlist_from_plan([{"out_file": out_file}]))


class TestMain(unittest.TestCase):
    """main() plumbing: stdin -> decide -> stdout, and the tolerant fallbacks."""

    def _run_main(self, payload_str, allowlist_paths=None):
        """Run wg.main() with `payload_str` on stdin inside a fresh temp cwd.

        `allowlist_paths`, if a list, is resolved to absolute paths via
        os.path.abspath *after* chdir-ing into the temp dir -- matching what
        main() itself will compute -- then JSON-dumped to
        .panopticon/write-allowlist.json. If it's a str instead, it is written
        verbatim (for malformed/wrong-type allowlist fixtures). If None, no
        allowlist file is created (simulates "not installed"). Returns
        (return_code, captured_stdout).
        """
        old_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            try:
                os.chdir(d)
                if allowlist_paths is not None:
                    os.makedirs(".panopticon", exist_ok=True)
                    if isinstance(allowlist_paths, str):
                        content = allowlist_paths
                    else:
                        content = json.dumps(wg.allowlist_document(
                            {"probe-cell": [os.path.abspath(p) for p in allowlist_paths]}))
                    with open(".panopticon/write-allowlist.json", "w", encoding="utf-8") as fh:
                        fh.write(content)
                buf = io.StringIO()
                with mock.patch("sys.stdin", io.StringIO(payload_str)):
                    with contextlib.redirect_stdout(buf):
                        # [] = a bare invocation, so this exercises the
                        # CWD-walk resolution rather than a baked-in path.
                        rc = wg.main([])
                return rc, buf.getvalue()
            finally:
                os.chdir(old_cwd)

    def test_write_outside_allowlist_emits_deny(self):
        payload = json.dumps(
            {"tool_name": "Write", "tool_input": {"file_path": "skill/scripts/synthesize.py"}}
        )
        rc, out = self._run_main(payload, allowlist_paths=[".panopticon/findings-g1-x.json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_write_in_allowlist_emits_no_deny(self):
        payload = json.dumps(
            {"tool_name": "Write", "tool_input": {"file_path": ".panopticon/findings-g1-x.json"}}
        )
        rc, out = self._run_main(payload, allowlist_paths=[".panopticon/findings-g1-x.json"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_notebookedit_uses_notebook_path_not_file_path(self):
        # #run7 ARC-F2C: NotebookEdit's target is `notebook_path`. An allowlisted
        # notebook passes; one outside the fence is denied.
        allow = [".panopticon/findings-g1-x.ipynb"]
        ok = json.dumps({"tool_name": "NotebookEdit",
                         "tool_input": {"notebook_path": ".panopticon/findings-g1-x.ipynb"}})
        self.assertEqual(self._run_main(ok, allowlist_paths=allow), (0, ""))   # allowed
        bad = json.dumps({"tool_name": "NotebookEdit",
                          "tool_input": {"notebook_path": "skill/scripts/driver.py"}})
        _rc, out = self._run_main(bad, allowlist_paths=allow)
        self.assertEqual(
            json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_notebookedit_decoy_file_path_does_not_bypass_allowlist(self):
        # #run7 ARC-F2C: a decoy allowlisted `file_path` must NOT let an
        # out-of-fence `notebook_path` write slip through (the real bypass).
        payload = json.dumps({"tool_name": "NotebookEdit",
                              "tool_input": {"file_path": ".panopticon/findings-g1-x.ipynb",
                                             "notebook_path": "skill/scripts/driver.py"}})
        _rc, out = self._run_main(payload, allowlist_paths=[".panopticon/findings-g1-x.ipynb"])
        self.assertEqual(
            json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_malformed_syntax_stdin_is_tolerated(self):
        rc, out = self._run_main("{ not json", allowlist_paths="[]")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_non_dict_stdin_is_tolerated(self):
        rc, out = self._run_main("[1,2,3]", allowlist_paths="[]")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_missing_allowlist_file_denies_write(self):
        payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": "anything.py"}})
        rc, out = self._run_main(payload, allowlist_paths=None)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_non_list_allowlist_content_denies_write(self):
        payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": "anything.py"}})
        rc, out = self._run_main(payload, allowlist_paths="null")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_non_string_file_path_payload_denies_without_crashing(self):
        # #768: end-to-end — a Write payload with a non-string file_path must
        # emit a deny (rc 0, deny JSON), never raise out of main().
        payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": 123}})
        rc, out = self._run_main(payload, allowlist_paths=[".panopticon/findings-g1-x.json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")


class TestInstallUninstall(unittest.TestCase):
    def test_install_writes_allowlist_and_registers_hook(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            with open(settings, "w", encoding="utf-8") as fh:
                json.dump({"env": {"X": "1"}}, fh)  # pre-existing settings
            al = os.path.join(d, "allow.json")
            plan = [{"out_file": ".panopticon/f.json"}]
            wg.install(plan, settings, al)
            with open(settings, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertEqual(saved["env"], {"X": "1"})  # preserved
            self.assertIn("PreToolUse", saved["hooks"])  # registered
            with open(al, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["paths"],
                                 [os.path.realpath(".panopticon/f.json")])

    def test_uninstall_removes_hook_and_allowlist(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            with open(settings, "w", encoding="utf-8") as fh:
                json.dump({"env": {"X": "1"}}, fh)
            al = os.path.join(d, "allow.json")
            wg.install([{"out_file": ".panopticon/f.json"}], settings, al)
            wg.uninstall(settings, al)
            with open(settings, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertEqual(saved.get("env"), {"X": "1"})
            self.assertNotIn("PreToolUse", saved.get("hooks", {}))
            self.assertFalse(os.path.exists(al))

    def test_install_is_idempotent(self):
        # Re-installing must not duplicate our hook entry.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            plan = [{"out_file": ".panopticon/f.json"}]
            wg.install(plan, settings, al)
            wg.install(plan, settings, al)
            wg.install(plan, settings, al)
            with open(settings, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertEqual(len(saved["hooks"]["PreToolUse"]), 1)

    def test_the_request_object_is_rejected_not_iterated(self):
        # #1482: `install` takes a SEQUENCE OF ENTRIES. Handed the dispatch
        # request that wraps them, the old code iterated the mapping's keys,
        # matched no out_file, and returned an empty set with no error --
        # which install then wrote over every live grant.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano)
            live = [{"out_file": os.path.join(pano, "findings-App-SEC.json")}]
            wg.install(live, settings, al)
            with open(al, encoding="utf-8") as fh:
                before = json.load(fh)
            with self.assertRaises(TypeError) as ctx:
                wg.install({"entries": live}, settings, al)
            self.assertIn("entries", str(ctx.exception))
            with open(al, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), before)   # grants untouched

    def test_install_that_grants_nothing_refuses_instead_of_wiping(self):
        # The composition that made #1482 destructive rather than merely
        # useless: `added` anchors _confined_to_artifact_roots, so an empty
        # `added` leaves no anchor, every carried grant is dropped as
        # unconfined, and the allowlist is written EMPTY.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano)
            wg.install([{"out_file": os.path.join(pano, "f.json")}], settings, al)
            with open(al, encoding="utf-8") as fh:
                before = json.load(fh)
            self.assertTrue(before)
            with self.assertRaises(ValueError) as ctx:
                wg.install([{"note": "entry with no out_file"}], settings, al)
            self.assertIn("grants nothing", str(ctx.exception))
            with open(al, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), before)

    def test_scoped_uninstall_rejects_the_request_object_too(self):
        # The same wrong shape fails OPEN on the teardown path: subtracting an
        # empty set leaves every grant in place and silently keeps the guard
        # armed, so the type check has to cover uninstall as well.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano)
            plan = [{"out_file": os.path.join(pano, "f.json")}]
            wg.install(plan, settings, al)
            with self.assertRaises(TypeError):
                wg.uninstall(settings, al, plan={"entries": plan})

    def test_a_string_plan_is_rejected(self):
        # A path handed in place of a plan iterates as CHARACTERS.
        with self.assertRaises(TypeError):
            wg.allowlist_from_plan("dispatch-request.json")

    def test_the_11_union_and_scoped_teardown_still_work(self):
        # Guards the guard: the new checks must not disturb the properties
        # they are protecting -- concurrent fan-outs union (#11), and tearing
        # down one leaves the other armed.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano)
            a = [{"out_file": os.path.join(pano, "findings-A-SEC.json")}]
            b = [{"out_file": os.path.join(pano, "findings-B-COD.json")}]
            wg.install(a, settings, al)
            wg.install(b, settings, al)
            with open(al, encoding="utf-8") as fh:
                self.assertEqual(len(json.load(fh)["paths"]), 2)
            wg.uninstall(settings, al, plan=b)
            with open(al, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["paths"],
                                 [os.path.realpath(a[0]["out_file"])])

    def test_is_armed_reports_registration_and_grant_count(self):
        # Teardown is a host duty that nothing verified. `is_armed` makes the
        # state checkable in one call, so a stale guard -- which denies EVERY
        # later Write/Edit in the session -- can be asserted against.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano)
            self.assertEqual(wg.is_armed(settings, al), (False, 0))
            wg.install([{"out_file": os.path.join(pano, "findings-A-SEC.json")},
                        {"out_file": os.path.join(pano, "findings-B-COD.json")}],
                       settings, al)
            self.assertEqual(wg.is_armed(settings, al), (True, 2))
            wg.uninstall(settings, al)
            self.assertEqual(wg.is_armed(settings, al), (False, 0))

    def test_is_armed_says_armed_when_the_allowlist_is_gone(self):
        # The dangerous state, and the one the count must not hide: registered
        # (so fail-closed, denying everything) with nothing granted.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano)
            wg.install([{"out_file": os.path.join(pano, "f.json")}], settings, al)
            os.remove(al)
            self.assertEqual(wg.is_armed(settings, al), (True, 0))

    def test_install_refuses_to_create_a_settings_file_from_the_wrong_cwd(self):
        # #1493: the defaults are CWD-relative, but the settings file a session
        # consults is the one at its SESSION ROOT. Arming "from where the driver
        # runs" (the target repo) wrote a file nothing reads, left the PREVIOUS
        # round's allowlist live, and cost 47 advisors every one of their writes
        # -- while is_armed() reported (True, 47) the whole time. A session root
        # already has a settings file, so being asked to CREATE one is the
        # signature of standing in the wrong directory.
        with tempfile.TemporaryDirectory() as d:
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano)
            plan = [{"out_file": os.path.join(pano, "findings-A-SEC.json")}]
            cwd = os.getcwd()
            try:
                os.chdir(d)
                with self.assertRaises(ValueError) as cm:
                    wg.install(plan)
            finally:
                os.chdir(cwd)
            self.assertIn("session root", str(cm.exception))
            # and it must not have written the decorative file it refused to arm
            self.assertFalse(os.path.exists(
                os.path.join(d, ".claude", "settings.local.json")))

    def test_session_root_resolves_both_paths_under_it(self):
        # The declared-root path: a caller that knows the root (the driver has
        # --session-dir) says so instead of inheriting whatever CWD it was run in.
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".claude"))
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".claude", "settings.local.json"), "w") as fh:
                fh.write("{}")
            out = os.path.join(d, ".panopticon", "findings-A-SEC.json")
            wg.install([{"out_file": out}], session_root=d)
            st = wg.guard_state(session_root=d)
            self.assertTrue(st["armed"])
            self.assertEqual(st["grants"], 1)
            self.assertEqual(st["settings_path"],
                             os.path.abspath(os.path.join(d, ".claude",
                                                          "settings.local.json")))
            wg.uninstall(session_root=d)
            self.assertFalse(wg.guard_state(session_root=d)["armed"])

    def test_session_root_and_explicit_paths_together_are_refused(self):
        # They resolve to different files: the guard would arm in one place and
        # be checked in another, which is the whole #1493 failure restated.
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                wg.install([{"out_file": os.path.join(d, "f.json")}],
                           os.path.join(d, "settings.json"), session_root=d)

    def test_guard_state_names_the_files_it_consulted(self):
        # is_armed()'s (True, N) does not say WHICH guard -- it is true of an
        # inert one too. guard_state must expose the resolved paths so a "armed
        # but every write rejected" case is diagnosable.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            pano = os.path.join(d, ".panopticon")
            os.makedirs(pano)
            wg.install([{"out_file": os.path.join(pano, "f.json")}], settings, al)
            st = wg.guard_state(settings, al)
            self.assertEqual((st["armed"], st["grants"]), (True, 1))
            self.assertEqual(st["settings_path"], os.path.abspath(settings))
            self.assertEqual(st["allowlist_path"], os.path.abspath(al))
            self.assertTrue(st["settings_exists"])

    def test_uninstall_is_safe_when_nothing_is_installed(self):
        # The `complete` status tells the host to tear down unconditionally,
        # so this must never raise on a run that armed no guard.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            wg.uninstall(settings, al)                      # nothing at all
            with open(settings, "w", encoding="utf-8") as fh:
                json.dump({"env": {"X": "1"}}, fh)
            wg.uninstall(settings, al)                      # settings, no hook
            with open(settings, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["env"], {"X": "1"})

    def test_matcher_and_write_tools_cannot_drift(self):
        # #680: the registered PreToolUse matcher must name EXACTLY the tools
        # decide() adjudicates — no more (a matcher tool decide() waves
        # through) and no less (a _WRITE_TOOLS entry the hook never fires for).
        matcher_tools = set(wg._HOOK_ENTRY["matcher"].split("|"))
        self.assertEqual(matcher_tools, wg._WRITE_TOOLS)
        # Bash must NOT be in either — the gap is closed by enforced shells,
        # not by pretending the session-wide guard can adjudicate the shell.
        self.assertNotIn("Bash", wg._WRITE_TOOLS)

    def test_install_uninstall_preserve_a_coexisting_hook(self):
        # An unrelated PreToolUse hook must survive both install and uninstall.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            other = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo other"}]}
            with open(settings, "w", encoding="utf-8") as fh:
                json.dump({"hooks": {"PreToolUse": [other]}}, fh)
            al = os.path.join(d, "allow.json")
            wg.install([{"out_file": ".panopticon/f.json"}], settings, al)
            with open(settings, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertIn(other, saved["hooks"]["PreToolUse"])  # survived install
            self.assertEqual(len(saved["hooks"]["PreToolUse"]), 2)
            wg.uninstall(settings, al)
            with open(settings, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertEqual(saved["hooks"]["PreToolUse"], [other])  # only ours removed

    def test_uninstall_tolerates_absent_files(self):
        with tempfile.TemporaryDirectory() as d:
            # neither settings nor allowlist exist -> must not raise
            wg.uninstall(os.path.join(d, "nope.json"), os.path.join(d, "gone.json"))

    def test_reinstall_unions_allowlist_never_revokes_in_flight(self):
        # #11: a re-arm during an in-flight fan-out must UNION, not replace -- the
        # first fan-out's out_files stay writable while the second's are added
        # (the run-6 leak: a per-group re-arm silently revoked prior agents).
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            wg.install([{"out_file": ".panopticon/a.json"}], settings, al)
            wg.install([{"out_file": ".panopticon/b.json"}], settings, al)
            with open(al, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["paths"],
                                 sorted([os.path.realpath(".panopticon/a.json"),
                                         os.path.realpath(".panopticon/b.json")]))
            with open(settings, encoding="utf-8") as fh:      # still one hook entry
                self.assertEqual(len(json.load(fh)["hooks"]["PreToolUse"]), 1)

    def test_scoped_uninstall_keeps_other_fan_out_armed(self):
        # #11: uninstall(plan=A) drops only A's paths and leaves the guard armed
        # for B; a final uninstall(plan=B) tears everything down.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            plan_a = [{"out_file": ".panopticon/a.json"}]
            plan_b = [{"out_file": ".panopticon/b.json"}]
            wg.install(plan_a, settings, al)
            wg.install(plan_b, settings, al)
            wg.uninstall(settings, al, plan=plan_a)
            with open(al, encoding="utf-8") as fh:            # B still armed
                self.assertEqual(json.load(fh)["paths"],
                                 [os.path.realpath(".panopticon/b.json")])
            with open(settings, encoding="utf-8") as fh:
                self.assertIn("PreToolUse", json.load(fh)["hooks"])
            wg.uninstall(settings, al, plan=plan_b)           # last fan-out gone
            self.assertFalse(os.path.exists(al))
            with open(settings, encoding="utf-8") as fh:
                self.assertNotIn("PreToolUse", json.load(fh).get("hooks", {}))


class TestLoadFailLoud(unittest.TestCase):
    """#1098: _load must distinguish an ABSENT settings file (fine -> {}) from a
    PRESENT-but-unreadable/corrupt one (refuse), so install() can never silently
    overwrite it and destroy the user's permissions.allow/deny and hooks."""

    def test_absent_settings_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(wg._load(os.path.join(d, "settings.local.json")), {})

    def test_corrupt_settings_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "settings.local.json")
            with open(p, "w") as fh:
                fh.write("{not valid json")
            with self.assertRaises(RuntimeError):
                wg._load(p)

    def test_install_will_not_clobber_corrupt_settings(self):
        with tempfile.TemporaryDirectory() as d:
            sp = os.path.join(d, "settings.local.json")
            with open(sp, "w") as fh:
                fh.write("{broken")
            with open(sp, encoding="utf-8") as fh:   # #run7 TST-D1B: no leaked handles
                before = fh.read()
            with self.assertRaises(RuntimeError):
                wg.install([{"out_file": os.path.join(d, "o.json")}],
                           settings_path=sp,
                           allowlist_path=os.path.join(d, "allow.json"))
            with open(sp, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), before)   # left untouched, not overwritten


class TestHookCmdSelfLocating(unittest.TestCase):
    def test_hook_cmd_is_absolute_and_shell_quoted(self):
        # #495: a literal repo-relative command only worked for the self-scan
        # layout; the registered command must locate the module absolutely and
        # survive paths with spaces. #1633: double quotes were how it survived
        # them, and they survive NOTHING else -- so the pin is what a shell
        # makes of the command, not which quote character it starts with.
        self.assertEqual(["python3", os.path.abspath(wg.__file__)],
                         shlex.split(wg._HOOK_CMD))

    def test_resolve_allowlist_path_finds_parent_dir(self):
        with tempfile.TemporaryDirectory() as d:
            pan_dir = os.path.join(d, ".panopticon")
            os.makedirs(pan_dir)
            allow_path = os.path.join(pan_dir, "write-allowlist.json")
            open(allow_path, "w").close()
            sub_dir = os.path.join(d, "src", "nested")
            os.makedirs(sub_dir)
            with mock.patch("os.getcwd", return_value=sub_dir):
                resolved = wg._resolve_allowlist_path()
                self.assertEqual(os.path.abspath(resolved), os.path.abspath(allow_path))


class TestAllowlistBoundAtInstall(unittest.TestCase):
    """#calibration-4: the allowlist must not be resolved from the hook's CWD.

    install() writes `<cwd>/.panopticon/write-allowlist.json`; the hook used to
    find its allowlist by walking up from the CWD of whatever process invoked
    it. Those are the same directory for a self-scan and DIFFERENT for an
    external target -- the controller session's root is not the scanned repo.
    On gotify the guard was armed on the target tree while the hook read the
    session tree's leftover findings-only allowlist, so all 120 verdict writes
    were denied and 44 advisors that had finished adjudicating lost the work.
    """

    def test_install_bakes_the_absolute_allowlist_into_the_command(self):
        with tempfile.TemporaryDirectory() as d:
            sp = os.path.join(d, "settings.json")
            ap = os.path.join(d, "sub", ".panopticon", "write-allowlist.json")
            wg.install([{"out_file": os.path.join(d, "sub", ".panopticon", "f.json")}],
                       settings_path=sp, allowlist_path=ap)
            with open(sp, encoding="utf-8") as fh:
                cmd = json.load(fh)["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            self.assertIn(os.path.abspath(ap), cmd,
                          "hook command does not name the allowlist it installed")
            self.assertIn(os.path.abspath(wg.__file__), cmd)

    def test_hook_reads_the_installed_allowlist_from_a_foreign_cwd(self):
        # The actual regression: arm the guard for a TARGET tree, then run the
        # hook from an unrelated CWD that has its own stale .panopticon. The
        # write must be allowed on the strength of the baked-in path.
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "target")
            session = os.path.join(d, "session")
            out = os.path.join(target, ".panopticon", "runs", "r", "verdicts-a.json")
            os.makedirs(os.path.dirname(out))
            ap = os.path.join(target, ".panopticon", "write-allowlist.json")
            wg.install([{"out_file": out}],
                       settings_path=os.path.join(d, "s.json"), allowlist_path=ap)
            # the session tree carries a DIFFERENT allowlist -- the stale
            # findings-only one that shadowed the real grant on gotify
            os.makedirs(os.path.join(session, ".panopticon"))
            with open(os.path.join(session, ".panopticon", "write-allowlist.json"),
                      "w", encoding="utf-8") as fh:
                json.dump(wg.allowlist_document({"stale-cell": [
                    os.path.join(target, ".panopticon", "runs", "r", "findings-a.json")]}), fh)
            payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": out}})
            old = os.getcwd()
            buf = io.StringIO()
            try:
                os.chdir(session)
                with mock.patch("sys.stdin", io.StringIO(payload)):
                    with contextlib.redirect_stdout(buf):
                        rc = wg.main([os.path.abspath(ap)])
            finally:
                os.chdir(old)
            self.assertEqual(rc, 0)
            self.assertEqual(buf.getvalue(), "",
                             "write was denied against the foreign CWD's allowlist")

    def test_missing_baked_allowlist_denies_rather_than_falling_back(self):
        # Fail-closed: an install that named a file which then vanished must
        # DENY, never quietly resolve some other tree's allowlist and allow the
        # wrong writes -- which is precisely how the gotify failure stayed
        # invisible until 44 agents had already burned their work.
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, ".panopticon"))
            with open(os.path.join(d, ".panopticon", "write-allowlist.json"),
                      "w", encoding="utf-8") as fh:
                json.dump(wg.allowlist_document({"stale-cell": [
                    os.path.join(d, "anything.json")]}), fh)
            payload = json.dumps({"tool_name": "Write",
                                  "tool_input": {"file_path": os.path.join(d, "anything.json")}})
            old, buf = os.getcwd(), io.StringIO()
            try:
                os.chdir(d)
                with mock.patch("sys.stdin", io.StringIO(payload)):
                    with contextlib.redirect_stdout(buf):
                        wg.main([os.path.join(d, "gone", "write-allowlist.json")])
            finally:
                os.chdir(old)
            self.assertIn("deny", buf.getvalue())

    def test_uninstall_removes_both_bare_and_bound_entries(self):
        # Removal matches on the script path, not dict equality, so a settings
        # file written by either version is cleared instead of orphaned.
        for bake in (None, "/tmp/x/.panopticon/write-allowlist.json"):
            with tempfile.TemporaryDirectory() as d:
                sp = os.path.join(d, "settings.json")
                wg._write_hook_entry(sp, bake)
                with open(sp, encoding="utf-8") as fh:
                    self.assertEqual(len(json.load(fh)["hooks"]["PreToolUse"]), 1)
                wg.uninstall(settings_path=sp,
                             allowlist_path=os.path.join(d, "none.json"))
                with open(sp, encoding="utf-8") as fh:
                    self.assertNotIn("hooks", json.load(fh))

    def test_reinstall_does_not_duplicate_the_entry(self):
        with tempfile.TemporaryDirectory() as d:
            sp = os.path.join(d, "settings.json")
            ap = os.path.join(d, ".panopticon", "write-allowlist.json")
            plan = [{"out_file": os.path.join(d, ".panopticon", "f.json")}]
            wg._write_hook_entry(sp, None)                      # legacy entry first
            wg.install(plan, settings_path=sp, allowlist_path=ap)
            wg.install(plan, settings_path=sp, allowlist_path=ap)
            with open(sp, encoding="utf-8") as fh:
                pre = json.load(fh)["hooks"]["PreToolUse"]
            self.assertEqual(len(pre), 1, "stale or duplicate hook entries left behind")
            self.assertIn(os.path.abspath(ap), pre[0]["hooks"][0]["command"])


class TestWriteGuardHookLive(unittest.TestCase):
    """Subprocess-based integration tests for the write-guard hook.

    These exercise the same paths as ``TestMain`` but through the actual
    ``python skill/scripts/write_guard_hook.py`` invocation used in production,
    verifying that stdin/stdout plumbing and return-code behavior work end-to-end.
    """

    def _run_hook(self, payload, allowlist_paths=None):
        """Run the hook script as a subprocess in a fresh temp directory.

        ``allowlist_paths`` is a list of paths (relative to the temp dir) to
        write into ``.panopticon/write-allowlist.json``.
        """
        script = os.path.abspath(wg.__file__)
        with tempfile.TemporaryDirectory() as d:
            # Resolve symlinks in the temp dir so the paths we write into the
            # allowlist match the realpath() computation the hook performs.
            real_d = os.path.realpath(d)
            if allowlist_paths is not None:
                os.makedirs(os.path.join(real_d, ".panopticon"), exist_ok=True)
                allowlist = [os.path.realpath(os.path.join(real_d, p)) for p in allowlist_paths]
                with open(os.path.join(real_d, ".panopticon", "write-allowlist.json"), "w", encoding="utf-8") as fh:
                    json.dump(wg.allowlist_document({"probe-cell": allowlist}), fh)
            return subprocess.run(
                [sys.executable, script],
                input=payload,
                capture_output=True,
                text=True,
                cwd=real_d,
                timeout=30,   # #run7 OPS-A1A/TST-G3B: bound the hook subprocess
            )

    def test_allowed_write_exits_cleanly_with_empty_stdout(self):
        payload = json.dumps(
            {"tool_name": "Write", "tool_input": {"file_path": ".panopticon/findings-g1-x.json"}}
        )
        proc = self._run_hook(payload, allowlist_paths=[".panopticon/findings-g1-x.json"])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")

    def test_denied_write_returns_deny_json(self):
        payload = json.dumps(
            {"tool_name": "Write", "tool_input": {"file_path": "skill/scripts/synthesize.py"}}
        )
        proc = self._run_hook(payload, allowlist_paths=[".panopticon/findings-g1-x.json"])
        self.assertEqual(proc.returncode, 0)
        data = json.loads(proc.stdout)
        self.assertEqual(data["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(proc.stderr, "")

    def test_malformed_payload_is_tolerated(self):
        proc = self._run_hook("{ not json", allowlist_paths=[".panopticon/findings-g1-x.json"])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")

    def test_non_dict_payload_is_tolerated(self):
        proc = self._run_hook("[1, 2, 3]", allowlist_paths=[".panopticon/findings-g1-x.json"])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(proc.stderr, "")


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
            wg._atomic_write_json(target, {"hooks": {"PreToolUse": []}}, indent=2)
            with open(outside, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "PRECIOUS")
            self.assertFalse(os.path.islink(target))
            self.assertEqual(json.load(open(target, encoding="utf-8")),
                             {"hooks": {"PreToolUse": []}})
            self.assertFalse(os.path.exists(target + ".tmp"))

    def test_the_real_writer_that_arms_the_guard_refuses_it_too(self):
        with tempfile.TemporaryDirectory() as d:
            outside, settings = self._planted(d, "settings.json")
            wg._write_hook_entry(settings, os.path.join(d, "write-allowlist.json"))
            with open(outside, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "PRECIOUS")
            with open(settings, encoding="utf-8") as fh:
                self.assertIn("PreToolUse", fh.read())


class TestAllowlistFormatV2(unittest.TestCase):
    """#1571: the allowlist is a per-ENTRY mapping, not a flat union.

    The union was the whole defect (AGT-2052644969 on the Claude guard,
    AGT-2297383423 on Kimi's): one file said "these paths are writable" and
    nothing in it recorded WHOSE grant each path was, so every in-flight
    reviewer was authorized against every other's findings file. Format v2
    keeps the union under `paths` -- `is_armed`'s count, the probes and any
    caller that legitimately wants the batch-wide set read it -- and adds
    `entries`, which is what a BOUND agent is adjudicated against.
    """

    def _plan(self, d, *names):
        pano = os.path.join(d, ".panopticon")
        os.makedirs(pano, exist_ok=True)
        return [{"id": n, "out_file": os.path.join(pano, "findings-%s.json" % n)}
                for n in names]

    def test_allowlist_from_plan_keys_every_out_file_by_its_entry_id(self):
        with tempfile.TemporaryDirectory() as d:
            plan = self._plan(d, "review-A-ARC", "review-A-SEC")
            self.assertEqual(
                wg.allowlist_from_plan(plan),
                {"review-A-ARC": [os.path.realpath(plan[0]["out_file"])],
                 "review-A-SEC": [os.path.realpath(plan[1]["out_file"])]})

    def test_an_entry_that_declares_no_id_lands_in_the_unbound_bucket(self):
        # The probes and much of the suite arm a plan with no ids. Those paths
        # must not be dropped (that would revoke a live grant) and must not be
        # reachable by any BOUND agent either -- they are the orchestrator's.
        with tempfile.TemporaryDirectory() as d:
            target = os.path.join(d, "findings.json")
            self.assertEqual(wg.allowlist_from_plan([{"out_file": target}]),
                             {wg.UNBOUND_ENTRY: [os.path.realpath(target)]})

    def test_union_paths_is_every_entrys_grant(self):
        with tempfile.TemporaryDirectory() as d:
            plan = self._plan(d, "a", "b")
            self.assertEqual(
                wg.union_paths(wg.allowlist_from_plan(plan)),
                {os.path.realpath(e["out_file"]) for e in plan})

    def test_install_writes_the_v2_document(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            al = os.path.join(d, "allow.json")
            plan = self._plan(d, "review-A-ARC")
            wg.install(plan, settings, al)
            with open(al, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertEqual(saved["version"], wg.ALLOWLIST_VERSION)
            self.assertEqual(saved["entries"],
                             {"review-A-ARC": [os.path.realpath(plan[0]["out_file"])]})
            self.assertEqual(saved["paths"], [os.path.realpath(plan[0]["out_file"])])

    def test_overlapping_batches_merge_per_entry_id(self):
        # The #11 property, now per entry: a re-arm while another fan-out is
        # live keeps that fan-out's grant AND keeps it attributed to its own id.
        with tempfile.TemporaryDirectory() as d:
            settings, al = os.path.join(d, "s.json"), os.path.join(d, "a.json")
            a, b = self._plan(d, "A-SEC"), self._plan(d, "B-COD")
            wg.install(a, settings, al)
            wg.install(b, settings, al)
            with open(al, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertEqual(sorted(saved["entries"]), ["A-SEC", "B-COD"])
            self.assertEqual(len(saved["paths"]), 2)

    def test_scoped_uninstall_drops_exactly_the_finished_entrys_grants(self):
        with tempfile.TemporaryDirectory() as d:
            settings, al = os.path.join(d, "s.json"), os.path.join(d, "a.json")
            a, b = self._plan(d, "A-SEC"), self._plan(d, "B-COD")
            wg.install(a, settings, al)
            wg.install(b, settings, al)
            wg.uninstall(settings, al, plan=b)
            with open(al, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertEqual(saved["entries"],
                             {"A-SEC": [os.path.realpath(a[0]["out_file"])]})
            self.assertEqual(saved["paths"], [os.path.realpath(a[0]["out_file"])])

    def test_is_armed_counts_paths_not_entries(self):
        with tempfile.TemporaryDirectory() as d:
            settings, al = os.path.join(d, "s.json"), os.path.join(d, "a.json")
            wg.install(self._plan(d, "A-SEC", "A-ARC"), settings, al)
            self.assertEqual(wg.is_armed(settings, al), (True, 2))

    def test_a_v1_flat_list_on_disk_denies_every_write_and_names_the_version(self):
        # Fail closed on a STALE file: a v1 list carries no attribution, so
        # honouring it would silently restore the batch-wide grant this issue
        # is about. The denial has to say so, or the operator sees only
        # "denied" on a guard that looks armed.
        with tempfile.TemporaryDirectory() as d:
            target = os.path.realpath(os.path.join(d, "findings-A-ARC.json"))
            al = os.path.join(d, "allow.json")
            with open(al, "w", encoding="utf-8") as fh:
                json.dump([target], fh)
            allow, reason = wg.adjudicate(
                {"tool_name": "Write", "tool_input": {"file_path": target}}, al, env={})
            self.assertFalse(allow)
            self.assertIn("version", reason)
            self.assertIn("1", reason)

    def test_a_future_version_on_disk_denies_too(self):
        with tempfile.TemporaryDirectory() as d:
            target = os.path.realpath(os.path.join(d, "findings-A-ARC.json"))
            al = os.path.join(d, "allow.json")
            with open(al, "w", encoding="utf-8") as fh:
                json.dump({"version": 99, "entries": {}, "paths": [target]}, fh)
            allow, reason = wg.adjudicate(
                {"tool_name": "Write", "tool_input": {"file_path": target}}, al, env={})
            self.assertFalse(allow)
            self.assertIn("99", reason)


def _write_subagent_transcript(parent_transcript, agent_id, first_text):
    """Lay out a subagent transcript where Claude Code writes it -- the same
    fixture shape tests/test_read_guard_hook.py uses, because the write guard
    now binds through the same records."""
    stem = parent_transcript[:-len(".jsonl")]
    d = os.path.join(stem, "subagents")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "agent-%s.jsonl" % agent_id)
    records = [
        {"type": "queue-operation", "operation": "enqueue"},
        {"type": "user", "isSidechain": True, "agentId": agent_id,
         "message": {"role": "user", "content": [{"type": "text", "text": first_text}]}},
    ]
    with open(path, "w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return path


class TestPerEntryWriteBinding(unittest.TestCase):
    """#1571, and the run-13 reproduction ported.

    Two entries in one batch, the guard bound to A: A may write its own
    out_file and may NOT write B's. `security_repros.py` built exactly this
    plan, serialised `allowlist_from_plan` over both entries and called the
    real guard with `PANOPTICON_ENTRY_ID=review-A-ARC` and B's path; it
    answered `allowed: true` with an empty reason.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = os.path.realpath(self.tmp.name)
        pano = os.path.join(d, ".panopticon")
        os.makedirs(pano)
        self.a = os.path.join(pano, "findings-A-ARC.json")
        self.b = os.path.join(pano, "findings-A-SEC.json")
        self.plan = [{"id": "review-A-ARC", "out_file": self.a},
                     {"id": "review-A-SEC", "out_file": self.b}]
        self.allowlist_path = os.path.join(pano, "write-allowlist.json")
        with open(self.allowlist_path, "w", encoding="utf-8") as fh:
            json.dump(wg.allowlist_document(wg.allowlist_from_plan(self.plan)), fh)
        self.parent = os.path.join(d, "session.jsonl")
        open(self.parent, "w").close()

    def _write(self, path, env=None, **payload):
        body = {"tool_name": "Write", "tool_input": {"file_path": path}}
        body.update(payload)
        return wg.adjudicate(body, self.allowlist_path, env={} if env is None else env)

    def test_a_bound_reviewer_may_write_its_own_out_file(self):
        self.assertEqual(self._write(self.a, env={wg.ENV_ENTRY_ID: "review-A-ARC"}),
                         (True, ""))

    def test_a_bound_reviewer_may_not_write_a_peer_entrys_out_file(self):
        allow, reason = self._write(self.b, env={wg.ENV_ENTRY_ID: "review-A-ARC"})
        self.assertFalse(allow, "kimi_peer_artifact_write, on the Claude guard")
        self.assertIn("review-A-ARC", reason)
        self.assertIn("peer", reason)

    def test_edit_and_notebookedit_are_bound_too(self):
        for tool, key in (("Edit", "file_path"), ("NotebookEdit", "notebook_path")):
            with self.subTest(tool=tool):
                allow, _ = wg.adjudicate({"tool_name": tool, "tool_input": {key: self.b}},
                                         self.allowlist_path,
                                         env={wg.ENV_ENTRY_ID: "review-A-ARC"})
                self.assertFalse(allow)

    def test_the_transcript_marker_binds_when_no_env_id_is_set(self):
        # Session mode: the child is a subagent, and its dispatch prompt's
        # first line is the only thing that says which cell it is.
        _write_subagent_transcript(self.parent, "ag1", "panopticon-entry: review-A-ARC\nbody")
        self.assertEqual(
            self._write(self.a, agent_id="ag1", agent_type="panopticon-domain-panel",
                        transcript_path=self.parent),
            (True, ""))
        allow, reason = self._write(self.b, agent_id="ag1",
                                    agent_type="panopticon-domain-panel",
                                    transcript_path=self.parent)
        self.assertFalse(allow)
        self.assertIn("review-A-ARC", reason)

    def test_an_agent_transcript_without_a_binding_is_denied(self):
        _write_subagent_transcript(self.parent, "ag2", "no marker at all\nbody")
        allow, reason = self._write(self.a, agent_id="ag2",
                                    agent_type="panopticon-domain-panel",
                                    transcript_path=self.parent)
        self.assertFalse(allow)
        self.assertIn("not bound", reason)

    def test_a_headless_session_with_no_binding_at_all_is_denied(self):
        # Plan 6's second identity: `agent_type` and no `agent_id` is a
        # headless reviewer, never the orchestrator.
        allow, reason = self._write(self.a, agent_type="panopticon-domain-panel")
        self.assertFalse(allow)
        self.assertIn("PANOPTICON_ENTRY_ID", reason)

    def test_an_entry_the_armed_allowlist_does_not_name_is_denied(self):
        allow, reason = self._write(self.a, env={wg.ENV_ENTRY_ID: "review-Z-COD"})
        self.assertFalse(allow)
        self.assertIn("review-Z-COD", reason)

    def test_the_unbound_bucket_is_not_selectable_by_a_bound_agent(self):
        with open(self.allowlist_path, "w", encoding="utf-8") as fh:
            json.dump(wg.allowlist_document({wg.UNBOUND_ENTRY: [os.path.realpath(self.a)]}), fh)
        allow, reason = self._write(self.a, env={wg.ENV_ENTRY_ID: wg.UNBOUND_ENTRY})
        self.assertFalse(allow)
        self.assertIn(wg.UNBOUND_ENTRY, reason)

    def test_a_stale_grant_is_not_reported_as_a_peer_write(self):
        # F1. The #calibration-4 / gotify shape: the guard is armed, this
        # entry IS named, but the grant is another tree's path -- so the
        # reviewer's OWN out_file is denied. Claiming "a peer entry's
        # artifact" there sends the operator after a misbehaving reviewer
        # instead of after a stale allowlist, which is the one thing this
        # module has spent three issues learning to say plainly.
        elsewhere = os.path.join(self.tmp.name, "other-run", "findings-A-ARC.json")
        with open(self.allowlist_path, "w", encoding="utf-8") as fh:
            json.dump(wg.allowlist_document({"review-A-ARC": [elsewhere]}), fh)
        allow, reason = self._write(self.a, env={wg.ENV_ENTRY_ID: "review-A-ARC"})
        self.assertFalse(allow)
        self.assertNotIn("peer", reason)
        self.assertIn("stale", reason)
        self.assertIn("review-A-ARC", reason)

    def test_the_peer_wording_is_kept_for_an_actual_peer_write(self):
        _allow, reason = self._write(self.b, env={wg.ENV_ENTRY_ID: "review-A-ARC"})
        self.assertIn("a peer entry's artifact is not writable", reason)

    def test_a_present_but_unusable_entry_id_denies_rather_than_unioning(self):
        # The read guard's shape: an id that is THERE but not a usable string
        # is an agent we could not bind, never the orchestrator. Degrading it
        # into the batch-wide union is the fail-open this change is about.
        allow, reason = self._write(self.a, env={wg.ENV_ENTRY_ID: 7})
        self.assertFalse(allow)
        self.assertIn("not bound", reason)

    def test_the_orchestrator_keeps_the_union(self):
        # Nothing bound it: it is the driver, it writes the run's own
        # artifacts, and it is trusted here exactly as it always was.
        self.assertEqual(self._write(self.a), (True, ""))
        self.assertEqual(self._write(self.b), (True, ""))
        allow, _ = self._write(os.path.join(self.tmp.name, "src.py"))
        self.assertFalse(allow)

    def test_a_bound_reviewer_still_cannot_write_through_a_symlink(self):
        link = os.path.join(os.path.dirname(self.a), "findings-A-ARC-link.json")
        os.symlink(self.a, link)
        with open(self.allowlist_path, "w", encoding="utf-8") as fh:
            json.dump(wg.allowlist_document({"review-A-ARC": [link]}), fh)
        allow, reason = self._write(link, env={wg.ENV_ENTRY_ID: "review-A-ARC"})
        self.assertFalse(allow)
        self.assertIn("symlink", reason)

    def test_the_hook_binds_end_to_end_through_the_environment(self):
        # main() -> adjudicate, with the allowlist baked into argv exactly as
        # install() registers it, and the id in the environment exactly as
        # orchestrate.Guards.env_for supplies it.
        payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": self.b}})
        proc = subprocess.run(
            [sys.executable, os.path.abspath(wg.__file__), self.allowlist_path],
            input=payload, capture_output=True, text=True, timeout=30,
            env=dict(os.environ, PANOPTICON_ENTRY_ID="review-A-ARC"))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(
            json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")


class TestBindingHelpersAreACopy(unittest.TestCase):
    """The binding resolution is DUPLICATED from read_guard_hook, not shared.

    A guard hook is invoked by absolute path, as its own process, with no
    package on sys.path -- the same constraint that already keeps the read
    guard's settings plumbing (R-P5-5) and `hook_command` (#1633) copies
    rather than imports. A copy that drifts is worse than either, so pin the
    two against each other: same source, compared as ASTs.
    """

    NAMES = ("marker_of", "subagent_transcript", "_first_text", "bind")
    # #1640: the component walk is the same shape of copy -- kimi_guard_hook's
    # write branch IS this module's, with Kimi's `path` field, and the walk it
    # calls has to be the same walk or one of the two guards quietly stops
    # refusing a nested symlink.
    COMPONENT_NAMES = ("_components", "_component_fault", "_escaped_component")

    def _functions(self, module, names=None):
        import ast
        names = self.NAMES if names is None else names
        with open(module.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), module.__file__)
        return {n.name: ast.dump(n) for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name in names}

    def test_the_binding_helpers_are_ast_identical_in_both_guards(self):
        import scripts.read_guard_hook as rg
        mine, theirs = self._functions(wg), self._functions(rg)
        self.assertEqual(sorted(theirs), sorted(self.NAMES))
        for name in self.NAMES:
            with self.subTest(name=name):
                self.assertEqual(mine.get(name), theirs[name],
                                 "%s has drifted from read_guard_hook's copy" % name)

    def test_the_component_walk_is_ast_identical_in_both_write_guards(self):
        import scripts.kimi_guard_hook as kg
        mine = self._functions(wg, self.COMPONENT_NAMES)
        theirs = self._functions(kg, self.COMPONENT_NAMES)
        self.assertEqual(sorted(theirs), sorted(self.COMPONENT_NAMES))
        for name in self.COMPONENT_NAMES:
            with self.subTest(name=name):
                self.assertEqual(mine.get(name), theirs[name],
                                 "%s has drifted from the kimi guard's copy" % name)

    def test_the_component_constants_match_too(self):
        import scripts.kimi_guard_hook as kg
        self.assertEqual(wg.ARTIFACT_DIR, kg.ARTIFACT_DIR)
        self.assertEqual(wg.SYMLINKED_COMPONENT, kg.SYMLINKED_COMPONENT)
        self.assertEqual(wg.UNMEASURABLE_COMPONENT, kg.UNMEASURABLE_COMPONENT)
        self.assertEqual(wg.ESCAPED_ARTIFACT_TREE, kg.ESCAPED_ARTIFACT_TREE)
        self.assertEqual(wg.PARENT_COMPONENT, kg.PARENT_COMPONENT)
        # Fix round 2 (N1): all four carry a `%s`. A refusal that cannot say
        # WHICH path or component it is about sends its reader to grep the
        # plan -- and `allowlist_from_plan` re-raises these with no context of
        # its own, so the constant is the only place the context can come from.
        for name in ("SYMLINKED_COMPONENT", "UNMEASURABLE_COMPONENT",
                     "ESCAPED_ARTIFACT_TREE", "PARENT_COMPONENT"):
            with self.subTest(constant=name):
                self.assertIn("%s", getattr(wg, name))

    def test_the_binding_constants_match_too(self):
        # The names the three hooks agree on by copy rather than by import:
        # the marker prefix and env var the binding reads, and the reserved
        # bucket both write guards must refuse (F2 -- one spelling, or one of
        # them silently stops refusing it).
        import scripts.kimi_guard_hook as kg
        import scripts.read_guard_hook as rg
        self.assertEqual(wg.MARKER_PREFIX, rg.MARKER_PREFIX)
        self.assertEqual(wg.ENV_ENTRY_ID, rg.ENV_ENTRY_ID)
        self.assertEqual(wg.ENV_ENTRY_ID, kg.ENV_ENTRY_ID)
        self.assertEqual(wg.UNBOUND_ENTRY, kg.UNBOUND_ENTRY)
