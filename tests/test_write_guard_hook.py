import contextlib, io, json, os, shutil, tempfile, unittest, sys
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
        self.assertIn("allowlist", reason.lower())
        # Fan-out findings files may reside outside the repo root (e.g. in a
        # temp directory). A write that is explicitly allowlisted must succeed
        # regardless of whether the realpath is inside or outside the repo root.
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        target = os.path.join(d, "findings-g1.json")
        allow = {os.path.realpath(target)}
        ok, _ = wg.decide("Write", target, allow)
        self.assertTrue(ok)

        # Same path on both sides with no symlinks anywhere, inside the repo root, must allow.
        target = os.path.join(os.getcwd(), ".panopticon", "findings-g1.json")
        allow = wg.allowlist_from_plan([{"out_file": target}])
        ok, _ = wg.decide("Write", target, allow)
        self.assertTrue(ok)

    def test_nul_byte_path_is_denied_not_raised(self):
        # os.path.realpath raises ValueError on an embedded NUL byte where
        # abspath/islink tolerate it; decide() must fail closed, not crash.
        ok, reason = wg.decide("Write", "bad\x00path.json", self.allow)
        self.assertFalse(ok)
        self.assertIn("denied", reason.lower())


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

    def test_missing_allowlist_file_is_tolerated(self):
        payload = json.dumps({"tool_name": "Write",
                               "tool_input": {"file_path": "anything.py"}})
        rc, out = self._run_main(payload, allowlist_paths=None)
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")

    def test_non_list_allowlist_content_is_tolerated(self):
        payload = json.dumps({"tool_name": "Write",
                               "tool_input": {"file_path": "anything.py"}})
        rc, out = self._run_main(payload, allowlist_paths="null")
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")


class TestInstallUninstall(unittest.TestCase):
    def test_install_writes_allowlist_and_registers_hook(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            with open(settings, "w") as fh:
                json.dump({"env": {"X": "1"}}, fh)  # pre-existing settings
            al = os.path.join(d, "allow.json")
            plan = [{"out_file": ".panopticon/f.json"}]
            wg.install(plan, settings, al)
            saved = json.load(open(settings))
            self.assertEqual(saved["env"], {"X": "1"})            # preserved
            self.assertIn("PreToolUse", saved["hooks"])           # registered
            self.assertEqual(json.load(open(al)),
                             [os.path.realpath(".panopticon/f.json")])

    def test_uninstall_removes_hook_and_allowlist(self):
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            with open(settings, "w") as fh:
                json.dump({"env": {"X": "1"}}, fh)
            al = os.path.join(d, "allow.json")
            wg.install([{"out_file": ".panopticon/f.json"}], settings, al)
            wg.uninstall(settings, al)
            saved = json.load(open(settings))
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
            saved = json.load(open(settings))
            self.assertEqual(len(saved["hooks"]["PreToolUse"]), 1)

    def test_install_uninstall_preserve_a_coexisting_hook(self):
        # An unrelated PreToolUse hook must survive both install and uninstall.
        with tempfile.TemporaryDirectory() as d:
            settings = os.path.join(d, "settings.local.json")
            other = {"matcher": "Bash", "hooks": [{"type": "command",
                                                   "command": "echo other"}]}
            with open(settings, "w") as fh:
                json.dump({"hooks": {"PreToolUse": [other]}}, fh)
            al = os.path.join(d, "allow.json")
            wg.install([{"out_file": ".panopticon/f.json"}], settings, al)
            saved = json.load(open(settings))
            self.assertIn(other, saved["hooks"]["PreToolUse"])   # survived install
            self.assertEqual(len(saved["hooks"]["PreToolUse"]), 2)
            wg.uninstall(settings, al)
            saved = json.load(open(settings))
            self.assertEqual(saved["hooks"]["PreToolUse"], [other])  # only ours removed

    def test_uninstall_tolerates_absent_files(self):
        with tempfile.TemporaryDirectory() as d:
            # neither settings nor allowlist exist -> must not raise
            wg.uninstall(os.path.join(d, "nope.json"),
                         os.path.join(d, "gone.json"))
