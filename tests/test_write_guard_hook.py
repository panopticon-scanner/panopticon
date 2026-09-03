import contextlib
import io
import json
import os
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
        allow = wg.allowlist_from_plan([{"out_file": target}])
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


class TestCwdIndependence(unittest.TestCase):
    """#935: with an ABSOLUTE out_file (driver._cell_entry emits these), the guard
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
            allow = wg.allowlist_from_plan([{"out_file": target}])  # install-time
            with self._in(elsewhere):  # subagent cwd
                ok, _ = wg.decide("Write", target, allow)
            self.assertTrue(ok)

    def test_relative_write_from_wrong_cwd_is_denied(self):
        # Documents WHY the plan must carry the absolute path: the same relative
        # name resolved from a different cwd is a different realpath -> denied.
        with tempfile.TemporaryDirectory() as run_root, tempfile.TemporaryDirectory() as elsewhere:
            target = os.path.join(run_root, ".panopticon", "findings-g1-code-panel_review.json")
            allow = wg.allowlist_from_plan([{"out_file": target}])
            with self._in(elsewhere):
                ok, _ = wg.decide("Write", ".panopticon/findings-g1-code-panel_review.json", allow)
            self.assertFalse(ok)

    def test_absolute_out_file_with_spaces_round_trips(self):
        # The Tapestry workspace path contains a space (#935).
        with tempfile.TemporaryDirectory() as base:
            run_root = os.path.join(base, "Mini Vault")
            os.makedirs(os.path.join(run_root, ".panopticon"))
            target = os.path.join(run_root, ".panopticon", "findings-g1-code-panel_review.json")
            allow = wg.allowlist_from_plan([{"out_file": target}])
            ok, _ = wg.decide("Write", target, allow)
            self.assertTrue(ok)


class TestAllowlistFromPlan(unittest.TestCase):
    def test_collects_out_files_absolute(self):
        plan = [{"out_file": ".panopticon/a.json"}, {"out_file": ".panopticon/b.json"}]
        al = wg.allowlist_from_plan(plan)
        self.assertEqual(
            al, {os.path.realpath(".panopticon/a.json"), os.path.realpath(".panopticon/b.json")}
        )

    def test_skips_non_string_out_file(self):
        plan = [{"out_file": ".panopticon/a.json"}, {"out_file": 123}, {"out_file": None}]
        al = wg.allowlist_from_plan(plan)
        self.assertEqual(al, {os.path.realpath(".panopticon/a.json")})

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
                json.dump([planted, os.path.expanduser("~/.ssh/authorized_keys")], fh)
            out_file = os.path.join(pano, "findings-app-SEC.json")
            settings = os.path.join(d, "settings.json")
            wg.install([{"out_file": out_file}],
                       settings_path=settings, allowlist_path=allow)
            with open(allow) as fh:
                final = set(json.load(fh))
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
                json.dump([inflight], fh)
            settings = os.path.join(d, "settings.json")
            wg.install([{"out_file": os.path.join(pano, "findings-app-SEC.json")}],
                       settings_path=settings, allowlist_path=allow)
            with open(allow) as fh:
                final = set(json.load(fh))
            self.assertIn(inflight, final)     # concurrent fan-out stays armed

    def test_symlinked_panopticon_parent_is_refused(self):
        # TST-A2B (run-9): allowlist_from_plan raises when an out_file's parent dir
        # is named .panopticon AND is itself a symlink -- a target could redirect
        # findings writes by planting that link. The guard existed but no test ever
        # constructed the triggering plan; this pins it.
        with tempfile.TemporaryDirectory() as d:
            real = os.path.join(d, "real-dir")
            os.mkdir(real)
            link = os.path.join(d, ".panopticon")
            os.symlink(real, link)
            plan = [{"out_file": os.path.join(link, "findings-app-SEC.json")}]
            with self.assertRaises(ValueError) as cm:
                wg.allowlist_from_plan(plan)
            self.assertIn("symlinked .panopticon", str(cm.exception))


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
                        content = json.dumps([os.path.abspath(p) for p in allowlist_paths])
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
                self.assertEqual(json.load(fh), [os.path.realpath(".panopticon/f.json")])

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
                self.assertEqual(len(json.load(fh)), 2)
            wg.uninstall(settings, al, plan=b)
            with open(al, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh),
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
                self.assertEqual(sorted(json.load(fh)),
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
                self.assertEqual(json.load(fh),
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
    def test_hook_cmd_is_absolute_and_quoted(self):
        # #495: a literal repo-relative command only worked for the self-scan
        # layout; the registered command must locate the module absolutely and
        # survive paths with spaces.
        self.assertIn(os.path.abspath(wg.__file__), wg._HOOK_CMD)
        self.assertTrue(wg._HOOK_CMD.startswith('python3 "'))
        self.assertTrue(wg._HOOK_CMD.endswith('"'))

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
                json.dump([os.path.join(target, ".panopticon", "runs", "r", "findings-a.json")], fh)
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
                json.dump([os.path.join(d, "anything.json")], fh)
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
                    json.dump(allowlist, fh)
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
