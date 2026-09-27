import atexit
import contextlib
import glob
import io
import os
import shutil
import signal
import tempfile
import threading
import tomllib
import unittest
from unittest import mock

import scripts.kimi_guard_hook as kimi_guard_hook
import scripts.runners.base as base
import scripts.runners.kimi as kimi_runner
import scripts.runners.kimi_home as kimi_home
from tests._test_helpers import (kimi_fixture_home as _fixture_home)

from tests.runners.kimi_support import _narrowed_temp_root

class TestPrepare(unittest.TestCase):
    def test_prepare_builds_the_per_run_home_and_it_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            fixture = _fixture_home(d)
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": fixture}):
                r = kimi_runner.Runner("kimi")
                run_dir = os.path.join(d, "run")
                r.prepare(run_dir, review_root=d)
                self.addCleanup(r.teardown, "complete")
                home = r.kimi_home
                # C1: the home is a temp dir outside the reviewed tree; the run
                # folder keeps only the pointer file that names it.
                self.assertTrue(kimi_home.is_temp_home(home))
                self.assertNotIn(os.path.realpath(d), os.path.realpath(home))
                self.assertTrue(os.path.islink(os.path.join(home, "credentials")))
                self.assertEqual(os.readlink(os.path.join(home, "credentials")),
                                 os.path.join(fixture, "credentials"))
                with open(os.path.join(home, "config.toml"), "rb") as fh:
                    config = tomllib.load(fh)
                self.assertFalse(config["merge_all_available_skills"])
                self.assertFalse(config["builtin_product_skills"])
                for tool in ("Bash", "Agent", "AgentSwarm", "FetchURL", "WebSearch"):
                    self.assertIn(tool, config["tools"]["disabled"])   # I1
                hooks = config["hooks"]
                self.assertEqual(len(hooks), 2)
                matchers = sorted(h["matcher"] for h in hooks)
                # I1 widened the read matcher to carry ReadMediaFile.
                self.assertEqual(matchers, [kimi_home.READ_MATCHER,
                                            kimi_home.WRITE_MATCHER])
                for h in hooks:
                    self.assertIn(os.path.abspath(kimi_guard_hook.__file__), h["command"])
                self.assertIn(os.path.join(run_dir, "read-scope.json"),
                              [h["command"] for h in hooks
                               if h["matcher"] == kimi_home.READ_MATCHER][0])
                self.assertIn(os.path.join(run_dir, "write-allowlist.json"),
                              [h["command"] for h in hooks
                               if h["matcher"] == kimi_home.WRITE_MATCHER][0])
                # the fixture's own values survive the merge
                self.assertEqual(config["models"]["kimi-code/k3"]["model"], "k3")
                self.assertEqual(r.configured, {"kimi-code/k3", "kimi-code/kimi-for-coding"})
                # Idempotent in the sense that survived N2: a second prepare
                # arms the same configuration. It does so in a FRESH home --
                # reuse would have to trust the pointer file -- so the first
                # one is this runner's to drop.
                first_home = r.kimi_home
                r.prepare(run_dir, review_root=d)
                self.addCleanup(shutil.rmtree, first_home, True)
                self.assertNotEqual(first_home, r.kimi_home)
                with open(os.path.join(r.kimi_home, "config.toml"), "rb") as fh:
                    self.assertEqual(config, tomllib.load(fh))

    def test_a_source_config_with_hooks_keeps_them(self):
        with tempfile.TemporaryDirectory() as d:
            fixture = _fixture_home(d)
            with open(os.path.join(fixture, "config.toml"), "a", encoding="utf-8") as fh:
                fh.write('\n[[hooks]]\nevent = "Stop"\ncommand = "true"\n')
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": fixture}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
                self.addCleanup(r.teardown, "complete")
                with open(os.path.join(r.kimi_home, "config.toml"), "rb") as fh:
                    config = tomllib.load(fh)
            self.assertEqual(len(config["hooks"]), 3)
            self.assertIn("Stop", [h["event"] for h in config["hooks"]])


class TestHomeLocation(unittest.TestCase):
    """C1 (gate review): the per-run Kimi home carries the operator's
    credential surface -- symlinked OAuth stores and a config.toml holding any
    plaintext api_key -- so it must not live inside the tree being reviewed,
    where a prompt-injected reviewer's in-scope Read and a `zip -r` of the run
    folder both reach it."""

    def _prepare(self, d):
        with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
            r = kimi_runner.Runner("kimi")
            r.prepare(os.path.join(d, ".panopticon", "runs", "t"), review_root=d)
        self.addCleanup(r.teardown, "complete")
        return r

    def test_the_home_is_outside_the_reviewed_tree(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._prepare(d)
            review_root = os.path.realpath(d)
            home = os.path.realpath(r.kimi_home)
            self.assertFalse(home == review_root or home.startswith(review_root + os.sep),
                             "the kimi home is inside the reviewed tree: %s" % home)
            self.assertTrue(os.path.basename(r.kimi_home).startswith("panopticon-kimi-"))
            self.assertTrue(os.path.isfile(os.path.join(r.kimi_home, "config.toml")))

    def test_xdg_runtime_home_is_admitted_and_cleanup_spares_outside_sibling(self):
        with _narrowed_temp_root() as (root, outside):
            xdg = os.path.join(root, "xdg-runtime")
            reviewed = os.path.join(root, "reviewed")
            os.mkdir(xdg)
            os.mkdir(reviewed)
            sibling = os.path.join(outside, "panopticon-kimi-PLANTED")
            os.mkdir(sibling)
            marker = os.path.join(sibling, "keep-me")
            with open(marker, "w", encoding="utf-8") as fh:
                fh.write("outside")
            fixture = _fixture_home(reviewed)
            # _narrowed_temp_root clears XDG on entry; install it inside the
            # context so both allocation and the teardown bound see it.
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": xdg,
                                               "KIMI_CODE_HOME": fixture}):
                r = kimi_runner.Runner("kimi", runner=lambda *args, **kwargs: None)
                try:
                    r.prepare(os.path.join(reviewed, "run"), review_root=reviewed)
                    home = r.kimi_home
                    self.assertEqual(os.path.dirname(home), xdg)
                    self.assertIn(os.path.realpath(xdg), kimi_home._temp_roots())
                    self.assertTrue(kimi_home.is_temp_home(home))
                    self.assertFalse(kimi_home.is_temp_home(sibling))
                    r.teardown("complete")
                    self.assertFalse(os.path.exists(home))
                    self.assertTrue(os.path.isfile(marker))
                finally:
                    r.teardown("complete")

    def test_the_run_dir_keeps_only_a_pointer_file(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._prepare(d)
            run_dir = os.path.join(d, ".panopticon", "runs", "t")
            self.assertEqual(sorted(os.listdir(run_dir)), ["kimi-home-path"])
            with open(os.path.join(run_dir, "kimi-home-path"), encoding="utf-8") as fh:
                self.assertEqual(fh.read().strip(), r.kimi_home)

    def test_the_home_is_0700_and_the_config_0600(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._prepare(d)
            self.assertEqual(0o700, os.stat(r.kimi_home).st_mode & 0o777)
            self.assertEqual(0o600, os.stat(os.path.join(r.kimi_home, "config.toml")).st_mode & 0o777)

    def test_credentials_are_still_symlinked_never_copied(self):
        with tempfile.TemporaryDirectory() as d:
            r = self._prepare(d)
            link = os.path.join(r.kimi_home, "credentials")
            self.assertTrue(os.path.islink(link))

    def test_teardown_removes_the_home_on_complete_and_keeps_it_on_error(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            r.teardown("error")
            self.assertTrue(os.path.isdir(home), "an errored run keeps its home for debugging")
            r.teardown("complete")
            self.assertFalse(os.path.exists(home))

    def test_an_errored_teardown_keeps_the_home_but_strips_its_secrets(self):
        # N6: a kept home holds a config.toml carrying the operator's api_key
        # verbatim and live symlinks into their OAuth stores, and nothing ever
        # prunes it -- on a machine that errors regularly (the PR's own
        # evidence run errored 247 launches) that is a growing set of
        # credential handles, path-visible to every process of that uid. The
        # debugging value is in the wire files, not the secrets.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            self.addCleanup(shutil.rmtree, home, True)
            wire = os.path.join(home, "sessions", "w", "s", "agents", "main", "wire.jsonl")
            os.makedirs(os.path.dirname(wire))
            with open(wire, "w", encoding="utf-8") as fh:
                fh.write("{}\n")
            with contextlib.redirect_stderr(io.StringIO()) as err:
                r.teardown("error")
            self.assertTrue(os.path.isdir(home))                       # kept
            self.assertTrue(os.path.isfile(wire))                      # and useful
            self.assertFalse(os.path.exists(os.path.join(home, "config.toml")))
            for item in ("credentials", "oauth"):
                self.assertFalse(os.path.islink(os.path.join(home, item)))
            line = err.getvalue()
            self.assertIn(home, line)
            self.assertIn("its config.toml and credential links were removed, so nothing "
                          "left there carries a credential", line)
            # R3-6: the names strip_secrets returned are never echoed (CodeQL
            # read the interpolated list as clear-text logging of a credential).
            for name in kimi_home._CREDENTIAL_ITEMS:
                self.assertNotIn(name, line.replace(home, ""))

    def test_an_errored_teardown_after_a_strip_says_it_held_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            self.addCleanup(shutil.rmtree, home, True)
            r._strip_on_exit()                                     # a handler ran first
            with contextlib.redirect_stderr(io.StringIO()) as err:
                r.teardown("error")
            line = err.getvalue()
            self.assertIn(home, line)
            self.assertIn("; it held no credential files", line)
            for name in kimi_home._CREDENTIAL_ITEMS:
                self.assertNotIn(name, line.replace(home, ""))

    def test_a_removed_home_takes_its_pointer_file_with_it(self):
        with tempfile.TemporaryDirectory() as d:
            run_dir = os.path.join(d, "run")
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(run_dir, review_root=d)
            r.teardown("complete")
            self.assertFalse(os.path.exists(r.home_pointer))
            self.assertEqual([], os.listdir(run_dir))

    def test_a_hard_kill_strips_the_secrets_through_the_exit_handler(self):
        # R2-2: `teardown` runs from orchestrate._finish, which a SIGKILL, an
        # OOM kill or a power loss never reaches -- and since N2 removed reuse,
        # nothing ever adopts a crashed run's home again. The exit and signal
        # handlers are what stand between a crash and a permanent orphan
        # holding the api_key and live OAuth symlinks. Exercised through the
        # handler itself: the suite sends no signals.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            self.addCleanup(shutil.rmtree, home, True)
            self.addCleanup(r.teardown, "error")
            wire = os.path.join(home, "sessions", "w", "s", "agents", "main", "wire.jsonl")
            os.makedirs(os.path.dirname(wire))
            with open(wire, "w", encoding="utf-8") as fh:
                fh.write("{}\n")
            r._strip_on_exit()
            self.assertFalse(os.path.exists(os.path.join(home, "config.toml")))
            for item in ("credentials", "oauth"):
                self.assertFalse(os.path.islink(os.path.join(home, item)))
            self.assertTrue(os.path.isfile(wire))       # the transcripts survive
            r._strip_on_exit()                          # idempotent

    def test_the_signal_handler_strips_then_chains_to_the_previous_one(self):
        seen = []
        previous = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, lambda signum, frame: seen.append(signum))
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            self.addCleanup(shutil.rmtree, home, True)
            installed = signal.getsignal(signal.SIGTERM)
            self.assertNotEqual(installed, previous)
            installed(signal.SIGTERM, None)             # no real signal is sent
            self.assertEqual([signal.SIGTERM], seen)    # chained
            self.assertFalse(os.path.exists(os.path.join(home, "config.toml")))
            r.teardown("complete")
            # the run is over: the handlers come back off, so a suite that
            # prepares many runners does not stack wrappers on SIGTERM.
            self.assertIsNone(r._crash_strip)

    def test_an_interrupt_mid_batch_terminates_before_the_guards_come_down(self):
        # R3-1, as amended by #1662. A Ctrl-C raises KeyboardInterrupt in the
        # main thread inside the pool. `config.toml` is the ONLY place this
        # host's guard hooks and derived deny-list are registered, so any
        # child still running when it is stripped runs fail-open -- which is
        # why the ORDER is: cancel what has not started, terminate what is
        # running, and only then let `orchestrate._finish` call
        # teardown("error"). Every entry that did launch must therefore have
        # seen the config; the ones still queued must not have launched at
        # all (before #1662 the pool's `with` drained all four). `prepare`
        # must still leave SIGINT alone: the loop routes the interrupt, and a
        # handler that stripped secrets would strip them before the
        # termination rather than after. Real Runner, real run_batch, fake
        # run_entry; the interrupt is raised the way the driver's own handler
        # raises it -- no signal is sent.
        with tempfile.TemporaryDirectory() as d:
            before = signal.getsignal(signal.SIGINT)
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run"), review_root=d)
            home = r.kimi_home
            self.addCleanup(shutil.rmtree, home, True)
            self.addCleanup(r.teardown, "error")
            self.assertIs(before, signal.getsignal(signal.SIGINT),
                          "prepare must not install a SIGINT handler")
            config = os.path.join(home, "config.toml")
            seen, released = [], threading.Event()
            self.addCleanup(released.set)
            # The in-flight entry stays in flight until the interrupt has been
            # through, so "still queued" means still queued: a fake that
            # returned the moment the Ctrl-C landed would free its worker to
            # pull the next item and the assertion would be a race.
            r.INTERRUPT_GRACE = 0.05          # ...and the bounded wait is short

            def fake_run_entry(entry, env):
                seen.append((entry["id"], os.path.isfile(config)))
                if entry["id"] == "e0":
                    handler = signal.getsignal(signal.SIGINT)
                    if callable(handler):
                        handler(signal.SIGINT, None)      # what a Ctrl-C would run
                    raise KeyboardInterrupt
                released.wait(5)
                return base.RunResult(entry_id=entry["id"], ok=True, text="", usage={},
                                      cost_usd=None, model=None, session_id=None,
                                      denials=[], error=None)

            entries = [{"id": "e%d" % i} for i in range(4)]
            with mock.patch.object(r, "run_entry", fake_run_entry), \
                 self.assertRaises(KeyboardInterrupt):
                base.HostRunner.run_batch(r, entries, 2, lambda e: {})
            released.set()
            launched = [eid for eid, _present in seen]
            self.assertIn("e0", launched)
            self.assertLess(len(seen), 4,
                            "the queued entries were launched anyway: %r" % seen)
            self.assertNotIn("e3", launched,
                             "an entry still queued at the interrupt launched: %r" % seen)
            self.assertEqual([], [eid for eid, present in seen if not present],
                             "an entry ran after the config was stripped: %r" % seen)
            self.assertTrue(os.path.isfile(config),
                            "config.toml must outlive the termination")
            r.teardown("error")        # the loop's path: strip AFTER the termination
            self.assertFalse(os.path.exists(config))

    def test_a_prepare_that_rejects_the_operator_config_leaves_no_home_behind(self):
        # R3-2: build_kimi_home mints the directory and links the two
        # credential stores BEFORE build_merged_config can refuse the
        # operator's config, and prepare assigns self.kimi_home only on
        # success -- so an ordinary operator typo used to leave a
        # panopticon-kimi-* holding live OAuth symlinks that no teardown, exit
        # handler or later run ever reclaimed.
        with _narrowed_temp_root() as (root, _outside), tempfile.TemporaryDirectory() as d:
            fixture = _fixture_home(d)
            config = os.path.join(fixture, "config.toml")
            with open(config, encoding="utf-8") as fh:
                body = fh.read()
            with open(config, "w", encoding="utf-8") as fh:
                fh.write("hooks = [1, 2]\n" + body)      # top level, before any table
            pattern = os.path.join(root, kimi_home.HOME_PREFIX + "*")
            self.assertEqual([], glob.glob(pattern))
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": fixture}):
                r = kimi_runner.Runner("kimi")
                with self.assertRaises(ValueError) as caught:
                    r.prepare(os.path.join(d, "run"), review_root=d)
            self.assertIn("expected an array of tables at `hooks`, found int in it",
                          str(caught.exception))
            self.assertIsNone(r.kimi_home)
            r.teardown("error")
            self.assertEqual([], glob.glob(pattern),
                             "prepare orphaned a home holding credential links")

    def test_runners_torn_down_in_arming_order_leave_the_baseline_handler(self):
        # R3-3: the disarm used to restore its `previous` only when the CURRENT
        # handler was its own wrapper. Two runners armed without a teardown in
        # between, then torn down in arming order, left the first one's wrapper
        # installed for good -- pinning a dead Runner (and its home path) from
        # the process's SIGTERM handler. tests/runners/conftest.py guards the
        # same invariant around every test; this is the case that trips it.
        baseline = signal.getsignal(signal.SIGTERM)
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                first = kimi_runner.Runner("kimi")
                first.prepare(os.path.join(d, "run-1"), review_root=d)
                self.addCleanup(shutil.rmtree, first.kimi_home, True)
                second = kimi_runner.Runner("kimi")
                second.prepare(os.path.join(d, "run-2"), review_root=d)
                self.addCleanup(shutil.rmtree, second.kimi_home, True)
            self.assertIsNot(baseline, signal.getsignal(signal.SIGTERM))   # armed
            armed = [first._crash_strip, second._crash_strip]
            # The atexit side, measured by the call: `atexit._ncallbacks()`
            # never shrinks on an unregister before 3.13 (the slot is NULLed,
            # not compacted), so a count is not a portable measure of it.
            with mock.patch.object(atexit, "unregister", wraps=atexit.unregister) as unregister:
                first.teardown("complete")
                second.teardown("complete")
            self.assertIs(baseline, signal.getsignal(signal.SIGTERM),
                          "a wrapper is still installed after both teardowns")
            self.assertEqual([mock.call(cb) for cb in armed], unregister.call_args_list)
            self.assertEqual([None, None], [first._crash_strip, second._crash_strip])

    def test_an_interrupt_mid_strip_leaves_the_exit_stripper_armed(self):
        # #1662 re-review: `teardown` took the crash strippers off FIRST and
        # only then stripped the home, so a Ctrl-C landing between the two
        # left config.toml (api_key verbatim) behind with no atexit net --
        # a window the base never had, because a second interrupt never
        # reached teardown there. The strippers come off LAST: an interrupt
        # anywhere above leaves the atexit stripper armed to finish the job.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(os.path.join(d, "run-1"), review_root=d)
                self.addCleanup(shutil.rmtree, r.kimi_home, True)
                self.addCleanup(r._disarm_crash_strippers)
            armed = r._crash_strip
            self.assertIsNotNone(armed)
            with mock.patch.object(kimi_home, "strip_secrets", side_effect=KeyboardInterrupt), \
                 mock.patch.object(atexit, "unregister", wraps=atexit.unregister) as unregister:
                with self.assertRaises(KeyboardInterrupt):
                    r.teardown("error")
            self.assertIs(armed, r._crash_strip, "the exit stripper was taken off before the strip ran")
            unregister.assert_not_called()
            self.assertTrue(os.path.isfile(os.path.join(r.kimi_home, "config.toml")))

    def test_a_c_installed_previous_handler_is_treated_as_the_default(self):
        # R3-4: `signal.getsignal` reports a handler installed from C as None.
        # The chain handled a callable and SIG_DFL and let None fall through,
        # so under an embedding host the wrapper stripped the home and then
        # RETURNED: the SIGTERM that would have ended the process did nothing.
        # None must behave as SIG_DFL: restore the default and re-raise the
        # signal. Measured on the wrapper directly, with the two calls that
        # would end the process replaced -- nothing is sent to the test process.
        r = kimi_runner.Runner("kimi")                 # no home: the strip is a no-op
        handler = r._signal_stripper(None)
        with mock.patch.object(signal, "signal") as install, \
             mock.patch.object(os, "kill") as kill:
            handler(signal.SIGTERM, None)
        install.assert_called_once_with(signal.SIGTERM, signal.SIG_DFL)
        kill.assert_called_once_with(os.getpid(), signal.SIGTERM)

    def test_a_disarm_restores_the_default_for_a_c_installed_previous_handler(self):
        # NEW-6 (round-4 re-review): the disarm handed `ours.previous` straight
        # to `signal.signal`, and for the C-installed case R3-4 exists for that
        # value is None, which `signal.signal` rejects with a TypeError the
        # except tuple does not catch -- so `teardown` aborted BEFORE stripping
        # the home. None means "the default" here exactly as it does in the
        # wrapper's own chain. The real `signal.signal` is not touched: the
        # fake mirrors only its documented refusal of None.
        r = kimi_runner.Runner("kimi")
        ours = r._signal_stripper(None)
        r._signal_handlers = {signal.SIGTERM: ours}
        installed = []

        def fake_signal(signum, handler):
            if handler is None:
                raise TypeError("signal handler must be signal.SIG_IGN, "
                                "signal.SIG_DFL, or a callable object")
            installed.append((signum, handler))

        with mock.patch.object(signal, "getsignal", return_value=ours), \
             mock.patch.object(signal, "signal", side_effect=fake_signal):
            r._disarm_crash_strippers()
        self.assertEqual([(signal.SIGTERM, signal.SIG_DFL)], installed)
        self.assertEqual({}, r._signal_handlers)

    def test_teardown_refuses_a_path_that_is_not_a_temp_home(self):
        with tempfile.TemporaryDirectory() as d:
            planted = os.path.join(d, "not-a-temp-home")
            os.makedirs(planted)
            r = kimi_runner.Runner("kimi")
            r.kimi_home = planted
            r.teardown("complete")
            self.assertTrue(os.path.isdir(planted), "teardown deleted a path outside the temp root")

    def test_every_prepare_mints_a_fresh_home_even_on_a_resume(self):
        # N2: nothing is reused. The only record of a previous home is the
        # pointer file, which lives in the reviewed tree, and reading it back
        # would make an attacker's file an input to where this run's
        # credential surface gets written.
        with tempfile.TemporaryDirectory() as d:
            run_dir = os.path.join(d, "run")
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                first = kimi_runner.Runner("kimi")
                first.prepare(run_dir, review_root=d)
                self.addCleanup(first.teardown, "complete")
                second = kimi_runner.Runner("kimi")
                second.prepare(run_dir, review_root=d)         # resume: same run dir
                self.addCleanup(second.teardown, "complete")
            self.assertNotEqual(first.kimi_home, second.kimi_home)
            self.assertTrue(kimi_home.is_temp_home(second.kimi_home))
            self.assertTrue(os.path.isfile(os.path.join(second.kimi_home, "config.toml")))
            with open(os.path.join(run_dir, "kimi-home-path"), encoding="utf-8") as fh:
                self.assertEqual(second.kimi_home, fh.read().strip())

    def test_prepare_never_reads_the_pointer_file(self):
        # The hostile target is prefix-matching AND pre-created OUTSIDE the
        # temp root, so nothing about it can be waved through by a name check.
        with _narrowed_temp_root() as (_root, outside), \
             tempfile.TemporaryDirectory() as d:
            hostile = os.path.join(outside, "panopticon-kimi-EVIL")
            os.makedirs(hostile)
            run_dir = os.path.join(d, "run")
            os.makedirs(run_dir)
            with open(os.path.join(run_dir, "kimi-home-path"), "w", encoding="utf-8") as fh:
                fh.write(hostile)
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(run_dir, review_root=d)
                self.addCleanup(r.teardown, "complete")
            self.assertNotEqual(os.path.realpath(hostile), os.path.realpath(r.kimi_home))
            self.assertEqual([], os.listdir(hostile))       # no config, no credential links

    def test_teardown_refuses_a_prefix_matching_path_outside_the_temp_root(self):
        # The root half of `is_temp_home`, which the round-1 test did not
        # reach: its "hostile" path was inside a TemporaryDirectory, i.e.
        # under the temp root, so the NAME refused it.
        with _narrowed_temp_root() as (_root, outside):
            planted = os.path.join(outside, "panopticon-kimi-PLANTED")
            os.makedirs(planted)
            with open(os.path.join(planted, "keep-me"), "w", encoding="utf-8") as fh:
                fh.write("x")
            self.assertFalse(kimi_home.is_temp_home(planted))
            r = kimi_runner.Runner("kimi")
            r.kimi_home = planted
            r.teardown("complete")
            self.assertTrue(os.path.isfile(os.path.join(planted, "keep-me")))


class TestHardenedWrites(unittest.TestCase):
    """I2: `<run_dir>` is inside the scanned tree and the home is a path a
    resume re-derives, so every file this runner writes goes out through a
    staging writer that refuses to follow a planted symlink -- the same rule
    runners/claude.py states for `host-settings.json`."""

    def test_a_symlinked_home_is_refused_rather_than_chmodded_through(self):
        with tempfile.TemporaryDirectory() as d:
            elsewhere = os.path.join(d, "elsewhere")
            os.makedirs(elsewhere)
            os.chmod(elsewhere, 0o755)
            home = os.path.join(d, "kimi-home")
            os.symlink(elsewhere, home)
            with self.assertRaises(OSError) as caught:
                kimi_home.build_kimi_home(home, os.path.join(d, "s.json"),
                                          os.path.join(d, "a.json"),
                                          real_home=_fixture_home(d))
            self.assertIn(home, str(caught.exception))
            self.assertEqual(0o755, os.stat(elsewhere).st_mode & 0o777)
            self.assertFalse(os.path.exists(os.path.join(elsewhere, "config.toml")))

    def test_a_symlink_planted_at_the_staging_name_is_not_written_through(self):
        with tempfile.TemporaryDirectory() as d:
            home = os.path.join(d, "kimi-home")
            os.makedirs(home)
            victim = os.path.join(d, "victim")
            with open(victim, "w", encoding="utf-8") as fh:
                fh.write("untouched")
            os.symlink(victim, os.path.join(home, "config.toml.tmp"))
            kimi_home.build_kimi_home(home, os.path.join(d, "s.json"),
                                      os.path.join(d, "a.json"),
                                      real_home=_fixture_home(d))
            with open(victim, encoding="utf-8") as fh:
                self.assertEqual("untouched", fh.read())
            self.assertEqual(0o600, os.stat(os.path.join(home, "config.toml")).st_mode & 0o777)

    def test_the_pointer_file_is_written_through_the_same_writer(self):
        with tempfile.TemporaryDirectory() as d:
            run_dir = os.path.join(d, "run")
            os.makedirs(run_dir)
            victim = os.path.join(d, "victim")
            with open(victim, "w", encoding="utf-8") as fh:
                fh.write("untouched")
            os.symlink(victim, os.path.join(run_dir, "kimi-home-path.tmp"))
            with mock.patch.dict(os.environ, {"KIMI_CODE_HOME": _fixture_home(d)}):
                r = kimi_runner.Runner("kimi")
                r.prepare(run_dir, review_root=d)
            self.addCleanup(r.teardown, "complete")
            with open(victim, encoding="utf-8") as fh:
                self.assertEqual("untouched", fh.read())
            with open(os.path.join(run_dir, "kimi-home-path"), encoding="utf-8") as fh:
                self.assertEqual(r.kimi_home, fh.read().strip())
