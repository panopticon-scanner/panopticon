"""#1633 (SEC-A1A, run-13): every hook command panopticon registers is a SHELL
STRING, so every element interpolated into one must be shell-quoted.

Claude Code and Kimi Code both run a registered PreToolUse `command` through
`sh -c`. Three builders interpolate paths into such a string --
`write_guard_hook._hook_entry` (the allowlist), `read_guard_hook._hook_entry`
(the read scope) and `runners/kimi._hook_entry` (the guard script, the mode and
the per-run data file) -- and each of them also interpolates the script path the
command runs. All of them used `"%s"`: double quotes stop a SPACE and nothing
else, so `$(...)`, backticks and a `"` of its own in the path are live shell
syntax that the host then executes on every PreToolUse event.

The tests take a path carrying every payload shape at once, ask the REAL
builder for its command, and let a real shell parse it. The interpreter is
stubbed (see `_test_helpers.argv_through_shell`) so the only thing that can run
is a script printing its argv -- never the hook itself, never a host binary --
and an escape shows up twice over: as a truncated argv, and as a marker file
the shell created in the test's own temporary directory.
"""
import json
import os
import shlex
import tempfile
import tomllib
import unittest
from unittest import mock

from _test_helpers import argv_through_shell
import scripts.kimi_guard_hook as kimi_guard_hook
import scripts.kimi_toml as kimi_toml
import scripts.read_guard_hook as rg
import scripts.runners.kimi as kimi_runner
import scripts.write_guard_hook as wg

MARKER = "PANOPTICON_HOOK_INJECTION_MARKER"
# Quote termination (`"; ... ; #`, the finding's mechanism), command
# substitution (`$(...)`, what the reproduction actually used), a backtick
# substitution, a single quote and a space -- in one legal file name, because a
# fix that handles one shape and not the rest is not a fix.
HOSTILE_NAME = ('allow"; touch %s; #$(touch %s)`touch %s` \'q\'.json'
                % (MARKER, MARKER, MARKER))


class HookCommandCase(unittest.TestCase):

    def assert_no_marker(self, directory):
        self.assertFalse(
            os.path.exists(os.path.join(directory, MARKER)),
            "the hook command ran an extra command out of its own path: a "
            "crafted path is executed on every PreToolUse event")


class TestWriteGuardHookCommand(HookCommandCase):

    def test_a_hostile_allowlist_path_arrives_as_one_argument(self):
        with tempfile.TemporaryDirectory() as d:
            allowlist = os.path.join(d, HOSTILE_NAME)
            command = wg._hook_entry(allowlist)["hooks"][0]["command"]
            argv = argv_through_shell(command, cwd=d)
            self.assertEqual([os.path.abspath(wg.__file__),
                              os.path.abspath(allowlist)], argv,
                             "the allowlist path did not survive the shell intact")
            self.assert_no_marker(d)

    def test_the_bare_entry_survives_a_shell_too(self):
        # The legacy no-allowlist entry runs the same script path through the
        # same shell; it is only safe by accident of where this checkout sits.
        with tempfile.TemporaryDirectory() as d:
            command = wg._hook_entry()["hooks"][0]["command"]
            self.assertEqual([os.path.abspath(wg.__file__)],
                             argv_through_shell(command, cwd=d))


class TestReadGuardHookCommand(HookCommandCase):

    def test_a_hostile_scope_path_arrives_as_one_argument(self):
        with tempfile.TemporaryDirectory() as d:
            scope = os.path.join(d, HOSTILE_NAME)
            command = rg._hook_entry(scope)["hooks"][0]["command"]
            argv = argv_through_shell(command, cwd=d)
            self.assertEqual([os.path.abspath(rg.__file__),
                              os.path.abspath(scope)], argv,
                             "the scope path did not survive the shell intact")
            self.assert_no_marker(d)


class TestKimiPerRunConfigHookCommands(HookCommandCase):
    """The Kimi half: the commands are written into the per-run `config.toml`,
    so they are checked as the CLI reads them -- serialized, parsed back with
    `tomllib`, then handed to a shell."""

    def test_hostile_scope_and_allowlist_paths_arrive_as_arguments(self):
        with tempfile.TemporaryDirectory() as d:
            scope = os.path.join(d, "read-" + HOSTILE_NAME)
            allowlist = os.path.join(d, "write-" + HOSTILE_NAME)
            config = tomllib.loads(kimi_toml.dump_toml(
                kimi_runner.build_merged_config({}, scope, allowlist)))
            commands = {h["matcher"]: h["command"] for h in config["hooks"]}
            guard = os.path.abspath(kimi_guard_hook.__file__)
            for matcher, mode, data in (
                    (kimi_runner.READ_MATCHER, "read", scope),
                    (kimi_runner.WRITE_MATCHER, "write", allowlist)):
                argv = argv_through_shell(commands[matcher], cwd=d)
                self.assertEqual([guard, mode, os.path.abspath(data)], argv,
                                 "the %s hook's argv did not survive the shell"
                                 % mode)
            self.assert_no_marker(d)


def _entry(command, matcher):
    return {"matcher": matcher,
            "hooks": [{"type": "command", "command": command}]}


def _settings_with(directory, entry):
    path = os.path.join(directory, "settings.local.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"hooks": {"PreToolUse": [entry]}}, fh)
    return path


class TestEntriesWrittenByTheUnquotedVersionStillResolve(unittest.TestCase):
    """Uninstall (and `is_armed`) match on the script path, not on dict
    equality, precisely so a settings.local.json written by an earlier version
    is cleared rather than orphaned. Quoting changes the command TEXT, so that
    promise is measured here for both guards."""

    def _legacy_commands(self, module):
        mine = os.path.abspath(module.__file__)
        return ['python3 "%s"' % mine,                      # bare, pre-#1633
                'python3 "%s" "%s"' % (mine, "/tmp/x/.panopticon/data.json")]

    def test_write_guard_recognises_removes_and_reports_legacy_entries(self):
        for command in self._legacy_commands(wg):
            with tempfile.TemporaryDirectory() as d:
                entry = _entry(command, wg._MATCHER)
                self.assertTrue(wg._is_our_entry(entry), command)
                settings = _settings_with(d, entry)
                allowlist = os.path.join(d, "write-allowlist.json")
                armed, _grants = wg.is_armed(settings_path=settings,
                                             allowlist_path=allowlist)
                self.assertTrue(armed, "a guard armed by the previous version "
                                       "reads as disarmed: %r" % command)
                # ... and re-arming over it REPLACES it rather than leaving a
                # second, stale entry behind (what dict equality used to do).
                wg.install([{"out_file": os.path.join(d, ".panopticon", "f.json")}],
                           settings_path=settings, allowlist_path=allowlist)
                with open(settings, encoding="utf-8") as fh:
                    self.assertEqual(1, len(json.load(fh)["hooks"]["PreToolUse"]))
                wg.uninstall(settings_path=settings, allowlist_path=allowlist)
                with open(settings, encoding="utf-8") as fh:
                    self.assertNotIn("hooks", json.load(fh))

    def test_read_guard_recognises_removes_and_reports_legacy_entries(self):
        for command in self._legacy_commands(rg):
            with tempfile.TemporaryDirectory() as d:
                entry = _entry(command, rg._MATCHER)
                self.assertTrue(rg._is_our_entry(entry), command)
                settings = _settings_with(d, entry)
                scope = os.path.join(d, "read-scope.json")
                armed, _entries = rg.is_armed(settings_path=settings,
                                              scope_path=scope)
                self.assertTrue(armed, "a guard armed by the previous version "
                                       "reads as disarmed: %r" % command)
                rg.uninstall(settings_path=settings, scope_path=scope)
                with open(settings, encoding="utf-8") as fh:
                    self.assertNotIn("hooks", json.load(fh))


class TestEntriesWhoseOwnPathNeededEscapingAreStillOurs(unittest.TestCase):
    """The other end of the same promise: once the SCRIPT path is quoted, a
    checkout whose path needs escaping no longer appears verbatim in the
    command, and a substring match would stop recognising our own entry -- so
    the guard could never be torn down. The module's own path is plain here, so
    the awkward one is patched in."""

    ODD = "/tmp/o'dd checkout/%s"

    def _round_trip(self, module):
        path = self.ODD % os.path.basename(module.__file__)
        command = "python3 " + shlex.quote(path)
        self.assertNotIn(path, command,
                         "a path needing escapes cannot appear verbatim")
        with mock.patch.object(module, "__file__", path):
            return module._is_our_entry(_entry(command, module._MATCHER))

    def test_write_guard_recognises_its_own_escaped_entry(self):
        self.assertTrue(self._round_trip(wg))

    def test_read_guard_recognises_its_own_escaped_entry(self):
        self.assertTrue(self._round_trip(rg))

    def test_an_unparseable_foreign_entry_is_not_ours_and_does_not_raise(self):
        # `_is_our_entry` reads EVERY PreToolUse entry in the operator's
        # settings file, including hand-written ones whose quoting is its own
        # business. An unbalanced quote must answer "not mine", never raise.
        for module in (wg, rg):
            self.assertFalse(module._is_our_entry(
                _entry('echo "unterminated', module._MATCHER)))
