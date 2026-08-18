import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
import scripts.write_guard_hook as wg


class TestDecide(unittest.TestCase):
    def setUp(self):
        self.allow = {os.path.realpath(".panopticon/findings-g1-code-panel_review.json")}

    def test_write_to_allowed_out_file_is_permitted(self):
        ok, _ = wg.decide("Write",
                          ".panopticon/findings-g1-code-panel_review.json", self.allow)
        self.assertTrue(ok)

    def test_write_outside_allowlist_is_blocked(self):
        ok, reason = wg.decide("Write", "skill/scripts/synthesize.py", self.allow)
        self.assertFalse(ok)
        self.assertIn("outside", reason.lower())

    def test_write_to_sibling_findings_not_in_plan_is_blocked(self):
        ok, _ = wg.decide("Edit",
                          ".panopticon/findings-g9-code-panel_review.json", self.allow)
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
        os.symlink(real_dir, linked_dir)                    # pan -> real-elsewhere
        target = os.path.join(linked_dir, "findings-g1.json")
        allow = {os.path.abspath(target)}                   # allowlist built from the STRING path
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
    """#935: with an ABSOLUTE out_file (build_plan now emits these), the guard
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
        with tempfile.TemporaryDirectory() as run_root, \
                tempfile.TemporaryDirectory() as elsewhere:
            target = os.path.join(run_root, ".panopticon",
                                  "findings-g1-code-panel_review.json")
            allow = wg.allowlist_from_plan([{"out_file": target}])  # install-time
            with self._in(elsewhere):                               # subagent cwd
                ok, _ = wg.decide("Write", target, allow)
            self.assertTrue(ok)

    def test_relative_write_from_wrong_cwd_is_denied(self):
        # Documents WHY the plan must carry the absolute path: the same relative
        # name resolved from a different cwd is a different realpath -> denied.
        with tempfile.TemporaryDirectory() as run_root, \
                tempfile.TemporaryDirectory() as elsewhere:
            target = os.path.join(run_root, ".panopticon",
                                  "findings-g1-code-panel_review.json")
            allow = wg.allowlist_from_plan([{"out_file": target}])
            with self._in(elsewhere):
                ok, _ = wg.decide(
                    "Write", ".panopticon/findings-g1-code-panel_review.json", allow)
            self.assertFalse(ok)

    def test_absolute_out_file_with_spaces_round_trips(self):
        # The Tapestry workspace path contains a space (#935).
        with tempfile.TemporaryDirectory() as base:
            run_root = os.path.join(base, "Mini Vault")
            os.makedirs(os.path.join(run_root, ".panopticon"))
            target = os.path.join(run_root, ".panopticon",
                                  "findings-g1-code-panel_review.json")
            allow = wg.allowlist_from_plan([{"out_file": target}])
            ok, _ = wg.decide("Write", target, allow)
            self.assertTrue(ok)


class TestAllowlistFromPlan(unittest.TestCase):
    def test_collects_out_files_absolute(self):
        plan = [{"out_file": ".panopticon/a.json"}, {"out_file": ".panopticon/b.json"}]
        al = wg.allowlist_from_plan(plan)
        self.assertEqual(al, {os.path.realpath(".panopticon/a.json"),
                              os.path.realpath(".panopticon/b.json")})

    def test_skips_non_string_out_file(self):
        plan = [{"out_file": ".panopticon/a.json"}, {"out_file": 123}, {"out_file": None}]
        al = wg.allowlist_from_plan(plan)
        self.assertEqual(al, {os.path.realpath(".panopticon/a.json")})


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
                    with open(".panopticon/write-allowlist.json", "w",
                              encoding="utf-8") as fh:
                        fh.write(content)
                buf = io.StringIO()
                with mock.patch("sys.stdin", io.StringIO(payload_str)):
                    with contextlib.redirect_stdout(buf):
                        rc = wg.main()
                return rc, buf.getvalue()
            finally:
                os.chdir(old_cwd)

    def test_write_outside_allowlist_emits_deny(self):
        payload = json.dumps({"tool_name": "Write",
                               "tool_input": {"file_path": "skill/scripts/synthesize.py"}})
        rc, out = self._run_main(payload, allowlist_paths=[".panopticon/findings-g1-x.json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(data["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertEqual(data["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_write_in_allowlist_emits_no_deny(self):
        payload = json.dumps({"tool_name": "Write",
                               "tool_input": {"file_path": ".panopticon/findings-g1-x.json"}})
        rc, out = self._run_main(payload, allowlist_paths=[".panopticon/findings-g1-x.json"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_malformed_syntax_stdin_is_tolerated(self):
        rc, out = self._run_main("{ not json", allowlist_paths="[]")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_non_dict_stdin_is_tolerated(self):
        rc, out = self._run_main("[1,2,3]", allowlist_paths="[]")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_missing_allowlist_file_denies_write(self):
        payload = json.dumps({"tool_name": "Write",
                               "tool_input": {"file_path": "anything.py"}})
        rc, out = self._run_main(payload, allowlist_paths=None)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"],
                         "deny")

    def test_non_list_allowlist_content_denies_write(self):
        payload = json.dumps({"tool_name": "Write",
                               "tool_input": {"file_path": "anything.py"}})
        rc, out = self._run_main(payload, allowlist_paths="null")
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"],
                 "deny")

    def test_non_string_file_path_payload_denies_without_crashing(self):
        # #768: end-to-end — a Write payload with a non-string file_path must
        # emit a deny (rc 0, deny JSON), never raise out of main().
        payload = json.dumps({"tool_name": "Write",
                               "tool_input": {"file_path": 123}})
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
            self.assertEqual(saved["env"], {"X": "1"})            # preserved
            self.assertIn("PreToolUse", saved["hooks"])           # registered
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
            other = {"matcher": "Bash", "hooks": [{"type": "command",
                                                   "command": "echo other"}]}
            with open(settings, "w", encoding="utf-8") as fh:
                json.dump({"hooks": {"PreToolUse": [other]}}, fh)
            al = os.path.join(d, "allow.json")
            wg.install([{"out_file": ".panopticon/f.json"}], settings, al)
            with open(settings, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertIn(other, saved["hooks"]["PreToolUse"])   # survived install
            self.assertEqual(len(saved["hooks"]["PreToolUse"]), 2)
            wg.uninstall(settings, al)
            with open(settings, encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertEqual(saved["hooks"]["PreToolUse"], [other])  # only ours removed

    def test_uninstall_tolerates_absent_files(self):
        with tempfile.TemporaryDirectory() as d:
            # neither settings nor allowlist exist -> must not raise
            wg.uninstall(os.path.join(d, "nope.json"),
                         os.path.join(d, "gone.json"))


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
