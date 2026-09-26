import json, os, shutil, tempfile, unittest
from pathlib import Path
import subprocess
import sys
from unittest import mock

import pytest

import sanitize
import triage


@pytest.fixture(autouse=True)
def isolated_progress(tmp_path, monkeypatch):
    monkeypatch.setattr(triage, "PROGRESS", str(tmp_path / "progress.json"))


def fix_row(**over):
    row = {"issue": 443, "set": "FIXME", "verdict": "fix",
           "rationale": "queue identity bug", "duplicate_of": None,
           "fixed_by": None, "spot_check": None, "rank": 1,
           "status": "proposed", "batch": "B1",
           "triaged_at": "2026-08-04T23:00:00Z",
           "schema_version": 1}
    row.update(over)
    return row


class TestLedger(unittest.TestCase):
    def test_roundtrip_preserves_rows_and_order(self):
        rows = [fix_row(), fix_row(issue=431, rank=2)]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ledger.jsonl")
            triage.save_rows(rows, path=p)
            self.assertEqual(triage.load_rows(path=p), rows)

    def test_save_rows_adds_schema_version_if_absent(self):
        row_without_version = {
            "issue": 100, "set": "FIXME", "verdict": "fix",
            "rationale": "test", "status": "proposed", "batch": "B1",
            "triaged_at": "2026-08-04T23:00:00Z", "rank": 1
        }
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ledger.jsonl")
            triage.save_rows([row_without_version], path=p)
            loaded = triage.load_rows(path=p)
            self.assertEqual(loaded[0].get("schema_version"), 1)

    def test_load_missing_file_returns_empty(self):
        self.assertEqual(triage.load_rows(path="/nonexistent/x.jsonl"), [])

    def test_load_skips_blank_lines_and_reports_bad_line_number(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ledger.jsonl")
            with open(p, "w") as fh:
                fh.write(json.dumps(fix_row()) + "\n\n{not json\n")
            with self.assertRaisesRegex(ValueError, "line 3"):
                triage.load_rows(path=p)


class TestValidate(unittest.TestCase):
    def test_valid_fix_row_passes(self):
        self.assertIsNone(triage.validate(fix_row()))

    def test_fix_requires_integer_rank(self):
        with self.assertRaisesRegex(ValueError, "rank"):
            triage.validate(fix_row(rank=None))

    def test_duplicate_requires_duplicate_of(self):
        with self.assertRaisesRegex(ValueError, "duplicate_of"):
            triage.validate(fix_row(verdict="duplicate", rank=None))

    def test_already_fixed_requires_fixed_by_and_spot_check(self):
        with self.assertRaisesRegex(ValueError, "fixed_by"):
            triage.validate(fix_row(verdict="already-fixed", rank=None,
                                    spot_check="advisor: fixed"))

    def test_reject_requires_spot_check(self):
        with self.assertRaisesRegex(ValueError, "spot_check"):
            triage.validate(fix_row(verdict="reject", rank=None))

    def test_unknown_verdict_and_status_rejected(self):
        with self.assertRaisesRegex(ValueError, "verdict"):
            triage.validate(fix_row(verdict="maybe"))
        with self.assertRaisesRegex(ValueError, "status"):
            triage.validate(fix_row(status="pondering"))

    def test_empty_rationale_rejected(self):
        with self.assertRaisesRegex(ValueError, "rationale"):
            triage.validate(fix_row(rationale="  "))


class TestMutations(unittest.TestCase):
    def test_fix_comments_labels_milestones_never_closes(self):
        cmds = triage.plan_mutations(fix_row())
        self.assertEqual(cmds[0][:4], ["gh", "issue", "comment", "443"])
        self.assertIn("triage:fix", cmds[1])
        self.assertIn(triage.MILESTONE, cmds[1])
        self.assertFalse(any(c[2] == "close" for c in cmds))

    def test_duplicate_closes_not_planned(self):
        row = fix_row(verdict="duplicate", rank=None, duplicate_of=436)
        cmds = triage.plan_mutations(row)
        self.assertIn("triage:duplicate", cmds[1])
        self.assertEqual(cmds[-1], ["gh", "issue", "close", "443",
                                    "--reason", "not planned", "--repo", triage.REPO_SLUG])

    def test_already_fixed_closes_completed(self):
        row = fix_row(verdict="already-fixed", rank=None,
                      fixed_by="PR #447", spot_check="advisor: fixed")
        self.assertEqual(triage.plan_mutations(row)[-1],
                         ["gh", "issue", "close", "443",
                          "--reason", "completed", "--repo", triage.REPO_SLUG])

    def test_reject_closes_not_planned_and_defer_stays_open(self):
        rej = fix_row(verdict="reject", rank=None, spot_check="stands")
        self.assertEqual(triage.plan_mutations(rej)[-1][:3],
                         ["gh", "issue", "close"])
        defer = fix_row(verdict="defer", rank=None)
        self.assertFalse(any(c[2] == "close"
                             for c in triage.plan_mutations(defer)))

    def test_comment_carries_rationale_spec_and_spot_check(self):
        row = fix_row(verdict="reject", rank=None,
                      spot_check="advisor: not-real, fixture file")
        body = triage.comment_for(row)
        self.assertIn("queue identity bug", body)
        self.assertIn(triage.SPEC, body)
        self.assertIn("fixture file", body)

    def test_comment_for_duplicate_names_canonical(self):
        row = fix_row(verdict="duplicate", rank=None, duplicate_of=436)
        self.assertIn("#436", triage.comment_for(row))

    def test_comment_for_handles_mentions_and_markdown(self):
        row = fix_row(verdict="reject", rank=None,
                      rationale="Testing @everyone and <script>alert(1)</script> injection",
                      spot_check="advisor: checked @channel [link](https://example.com)")
        comment = triage.comment_for(row)
        self.assertIn("@\u200beveryone", comment)
        self.assertIn("<script>alert(1)</script>", comment)
        self.assertIn("@\u200bchannel", comment)
        self.assertIn("]\u200b(", comment)
        self.assertIn("h\u200bttps://", comment)


class TestStale(unittest.TestCase):
    def test_closed_issue_is_stale(self):
        self.assertTrue(triage.is_stale(
            fix_row(), {"state": "CLOSED",
                        "updatedAt": "2026-08-01T00:00:00Z"}))

    def test_updated_after_triage_is_stale(self):
        self.assertTrue(triage.is_stale(
            fix_row(), {"state": "OPEN",
                        "updatedAt": "2026-08-05T00:00:00Z"}))

    def test_untouched_open_issue_is_fresh(self):
        self.assertFalse(triage.is_stale(
            fix_row(), {"state": "OPEN",
                        "updatedAt": "2026-08-04T12:00:00Z"}))


class FakeRunner:
    """Records argv; returns canned stdout per command prefix."""
    def __init__(self, view_json='{"state": "OPEN", "updatedAt": "2026-08-04T12:00:00Z"}'):
        self.calls, self.view_json = [], view_json
        self.comments, self.labels = [], []

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        class R:
            returncode, stderr = 0, ""
        if argv[1:3] == ["issue", "view"]:
            try:
                state = json.loads(self.view_json)
                state.update(title='title', body='body', labels=self.labels,
                             milestone={'title': triage.MILESTONE} if self.labels else None, stateReason=None)
                R.stdout = json.dumps(state)
            except ValueError:
                R.stdout = self.view_json
        elif argv[1:3] == ["api", "repos/" + triage.REPO_SLUG]:
            R.stdout = json.dumps({'full_name': triage.REPO_SLUG, 'permissions': {'admin': True}})
        elif argv[1] == 'api' and '/comments' in argv[2]:
            R.stdout = json.dumps([self.comments])
        else:
            if argv[1:3] == ['issue', 'comment']:
                self.comments.append({'body': argv[argv.index('--body') + 1]})
            if argv[1:3] == ['issue', 'edit']:
                self.labels.append({'name': argv[argv.index('--add-label') + 1]})
            R.stdout = '{}'

        return R


class TestApply(unittest.TestCase):
    def test_applies_only_approved_rows_and_flips_status(self):
        rows = [fix_row(status="approved"), fix_row(issue=431, rank=2)]
        done, stale = triage.apply(rows, runner=FakeRunner(),
                                   sleep=lambda s: None)
        self.assertEqual((done, stale), (1, 0))
        self.assertEqual(rows[0]["status"], "applied")
        self.assertEqual(rows[1]["status"], "proposed")

    def test_stale_row_is_flagged_not_applied(self):
        runner = FakeRunner(view_json='{"state": "CLOSED", '
                                      '"updatedAt": "2026-08-01T00:00:00Z"}')
        rows = [fix_row(status="approved")]
        done, stale = triage.apply(rows, runner=runner, sleep=lambda s: None)
        self.assertEqual((done, stale), (0, 1))
        self.assertEqual(rows[0]["status"], "stale")
        # nothing beyond the state fetch was run
        self.assertEqual([c[1:3] for c in runner.calls if c[1] == "issue"], [["issue", "view"]])

    def test_dry_run_touches_nothing(self):
        runner = FakeRunner()
        rows = [fix_row(status="approved")]
        triage.apply(rows, dry=True, runner=runner, sleep=lambda s: None)
        self.assertEqual(runner.calls, [])
        self.assertEqual(rows[0]["status"], "approved")

    def test_invalid_approved_row_raises_before_any_mutation(self):
        runner = FakeRunner()
        rows = [fix_row(status="approved", rank=None)]
        with self.assertRaises(ValueError):
            triage.apply(rows, runner=runner, sleep=lambda s: None)
        self.assertEqual(runner.calls, [])

    def test_apply_handles_malformed_gh_json(self):
        runner = FakeRunner(view_json="not valid json")
        rows = [fix_row(status="approved")]
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            triage.apply(rows, runner=runner, sleep=lambda s: None)
        self.assertEqual(rows[0]["status"], "approved")


class SequencingFakeRunner:
    """Returns scripted sequence of (returncode, stdout, stderr) results."""
    def __init__(self, results):
        self.results = results  # list of (returncode, stdout, stderr)
        self.calls = []
        self.call_index = 0

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        if self.call_index >= len(self.results):
            raise RuntimeError("SequencingFakeRunner: exhausted results")
        rc, stdout, stderr = self.results[self.call_index]
        self.call_index += 1
        class R:
            pass
        R.returncode = rc
        R.stdout = stdout
        R.stderr = stderr
        return R


class TestGhRetry(unittest.TestCase):
    def test_rate_limit_retry_and_succeed(self):
        """Rate limit on first call, success on second."""
        sleep_calls = []
        def fake_sleep(s):
            sleep_calls.append(s)
        runner = SequencingFakeRunner([
            (1, "", "rate limit exceeded"),  # first call fails with rate limit
            (0, "success output", ""),        # second call succeeds
        ])
        result = triage.gh(["gh", "test"], runner=runner, sleep=fake_sleep)
        self.assertEqual(result, "success output")
        self.assertEqual(runner.call_index, 2)  # called twice
        self.assertEqual(sleep_calls, [60])     # slept once with 60

    def test_non_rate_limit_failure_raises_immediately(self):
        """Non-rate-limit failure raises RuntimeError without retry."""
        sleep_calls = []
        def fake_sleep(s):
            sleep_calls.append(s)
        runner = SequencingFakeRunner([
            (1, "", "not found"),  # failure without rate limit hint
        ])
        with self.assertRaises(RuntimeError):
            triage.gh(["gh", "test"], runner=runner, sleep=fake_sleep)
        self.assertEqual(runner.call_index, 1)  # called only once
        self.assertEqual(sleep_calls, [])       # never slept

    def test_all_five_attempts_rate_limited_then_fail(self):
        """All 5 attempts rate-limited, raises RuntimeError on 5th attempt."""
        sleep_calls = []
        def fake_sleep(s):
            sleep_calls.append(s)
        runner = SequencingFakeRunner([
            (1, "", "rate limit exceeded"),    # attempt 1
            (1, "", "secondary rate limit"),   # attempt 2
            (1, "", "abuse detection active"), # attempt 3
            (1, "", "was submitted too quickly"), # attempt 4
            (1, "", "rate limit"),             # attempt 5 - raises since attempt < 5 is false
        ])
        with self.assertRaises(RuntimeError) as cm:
            triage.gh(["gh", "test"], runner=runner, sleep=fake_sleep)
        # On attempt 5, rate limit doesn't trigger retry (since attempt < 5 is false)
        # so it raises immediately with the error message
        self.assertIn("failed", str(cm.exception))
        self.assertEqual(runner.call_index, 5)  # all 5 attempts made
        self.assertEqual(sleep_calls, [60, 120, 180, 240])  # sleeps before attempts 2-5

    def test_timeout_engages_retry_then_succeeds(self):
        # #1103: a hung gh must engage the retry/backoff, not block forever.
        sleep_calls = []
        calls = {"n": 0}
        def runner(argv, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise triage.subprocess.TimeoutExpired(argv, triage.GH_TIMEOUT)
            return type("R", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()
        result = triage.gh(["gh", "test"], runner=runner, sleep=sleep_calls.append)
        self.assertEqual(result, "ok")
        self.assertEqual(calls["n"], 2)      # retried after the timeout
        self.assertEqual(sleep_calls, [60])  # backed off once

    def test_persistent_timeout_raises_after_retries(self):
        def runner(argv, **kw):
            raise triage.subprocess.TimeoutExpired(argv, triage.GH_TIMEOUT)
        with self.assertRaises(RuntimeError):
            triage.gh(["gh", "test"], runner=runner, sleep=lambda s: None)

    def test_default_runner_carries_timeout(self):
        # #1103: the real runner bakes in the hard timeout.
        self.assertEqual(triage.default_gh_runner().keywords.get("timeout"),
                         triage.GH_TIMEOUT)


class TestGhRealBoundary(unittest.TestCase):
    """#run7 TST-A3A: every other gh test injects a fake runner. These
    exercises use an actual subprocess.run via default_gh_runner() with a fake
    `gh` executable, so the integration boundary is exercised end-to-end (argv
    construction, env wiring, capture, timeout wiring).

    #1650: the stub is found on the TRUSTED path, by absolute path -- never by
    a directory prepended to the ambient PATH, which is the substitution this
    module now refuses.
    """

    def _make_fake_gh(self, tmpdir, script, name="gh"):
        path = os.path.join(tmpdir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\n%s\n" % script)
        os.chmod(path, 0o755)
        return path

    def test_default_runner_invokes_real_gh_process(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_fake_gh(tmpdir, 'echo "{\\"login\\":\\"fake-user\\"}"')
            with mock.patch.object(triage, "TRUSTED_PATH", tmpdir):
                result = triage.gh(["gh", "api", "user"])
            self.assertIn("fake-user", result)

    def test_default_runner_surfaces_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self._make_fake_gh(tmpdir, 'echo "not found" >&2; exit 1')
            with mock.patch.object(triage, "TRUSTED_PATH", tmpdir):
                with self.assertRaises(RuntimeError) as ctx:
                    triage.gh(["gh", "issue", "view", "123"])
            self.assertIn("not found", str(ctx.exception))

    # ---- #1650 / SEC-D1B / CWE-427 --------------------------------------
    #
    # `gh` here performs authenticated issue comments, edits, closures, label
    # creation and milestone mutation as the automation account. Which binary
    # that is may not be decided by whoever controls the ambient PATH.

    def test_a_fake_gh_first_on_the_ambient_path_is_never_launched(self):
        with tempfile.TemporaryDirectory() as trusted, \
                tempfile.TemporaryDirectory() as hostile:
            log = os.path.join(hostile, "launched.log")
            self._make_fake_gh(hostile, 'echo launched >> "%s"; echo "{}"' % log)
            self._make_fake_gh(trusted, 'echo "{\\"login\\":\\"trusted\\"}"')
            ambient = hostile + os.pathsep + os.environ.get("PATH", "")
            with mock.patch.object(triage, "TRUSTED_PATH", trusted), \
                    mock.patch.dict(os.environ, {"PATH": ambient}):
                result = triage.gh(["gh", "api", "user"])
            self.assertIn("trusted", result)
            self.assertFalse(os.path.exists(log),
                             "the ambient PATH's `gh` was launched")

    def test_the_resolved_gh_is_launched_by_absolute_path(self):
        with tempfile.TemporaryDirectory() as trusted:
            stub = self._make_fake_gh(trusted, 'echo ok')
            with mock.patch.object(triage, "TRUSTED_PATH", trusted), \
                    mock.patch.object(triage.subprocess, "run") as m:
                m.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
                triage.gh(["gh", "api", "x"])
        self.assertEqual([stub, "api", "x"], list(m.call_args.args[0]))

    def test_a_gh_absent_from_the_trusted_path_refuses_with_a_clear_message(self):
        with tempfile.TemporaryDirectory() as empty:
            with mock.patch.object(triage, "TRUSTED_PATH", empty):
                with self.assertRaises(RuntimeError) as ctx:
                    triage.gh(["gh", "api", "user"])
        self.assertIn("gh", str(ctx.exception))
        self.assertIn(empty, str(ctx.exception))

    def test_the_child_env_carries_only_what_gh_needs_to_pick_the_account(self):
        # gh's OWN auth variables and nothing else. A hardened env that drops
        # GH_CONFIG_DIR/GH_TOKEN picks the default credential -- the
        # wrong-account incident #486 exists to prevent -- and one that copies
        # os.environ hands an authenticated mutation whatever the shell carried.
        with tempfile.TemporaryDirectory() as trusted, tempfile.TemporaryDirectory() as d:
            self._make_fake_gh(trusted, 'echo ok')
            cfg = os.path.join(d, "config.json")
            with open(cfg, "w", encoding="utf-8") as fh:
                json.dump({"gh_config_dir": d}, fh)
            with mock.patch.object(triage, "TRUSTED_PATH", trusted), \
                    mock.patch.object(triage, "CONFIG_PATH", cfg), \
                    mock.patch.dict(os.environ, {"GH_TOKEN": "ambient-token",
                                                 "AWS_SECRET_ACCESS_KEY": "nope"}), \
                    mock.patch.object(triage.subprocess, "run") as m:
                m.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
                triage.gh(["gh", "api", "x"])
                env = m.call_args.kwargs["env"]
                # inside the patch: TRUSTED_PATH is the stub dir here
                expected_path = triage.trusted_path(env["HOME"])
        # A DECLARED directory names the account; gh lets an ambient GH_TOKEN
        # override stored credentials, so carrying the token here would let
        # the shell's account beat the declared one -- exactly the wrong-way
        # precedence #486 is about. The token travels only when NO directory
        # is in effect (next test).
        self.assertEqual({"HOME", "PATH", "GH_CONFIG_DIR"}, set(env))
        self.assertEqual(expected_path, env["PATH"])
        self.assertEqual(d, env["GH_CONFIG_DIR"])

    def test_an_ambient_token_travels_only_when_no_directory_names_the_account(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "config.json")
            with open(cfg, "w", encoding="utf-8") as fh:
                json.dump({"gh_config_dir": None}, fh)     # the repo's own shape
            if True:
                with mock.patch.dict(os.environ, {"GH_TOKEN": "ambient-token"}, clear=False):
                    os.environ.pop("GH_CONFIG_DIR", None)
                    env = triage.gh_env(config_path=cfg)
                    self.assertEqual("ambient-token", env["GH_TOKEN"])
                    self.assertNotIn("GH_CONFIG_DIR", env)
                with mock.patch.dict(os.environ, {"GH_TOKEN": "ambient-token",
                                                  "GH_CONFIG_DIR": "/tmp/gh-x"}):
                    env = triage.gh_env(config_path=cfg)
                    self.assertEqual("/tmp/gh-x", env["GH_CONFIG_DIR"])
                    self.assertNotIn("GH_TOKEN", env)

    def test_an_empty_home_does_not_put_a_relative_dir_on_the_trusted_path(self):
        # trusted_path("") would otherwise yield a CWD-relative `.local/bin`.
        self.assertEqual(triage.TRUSTED_PATH, triage.trusted_path(""))

    def test_the_operators_own_bin_dir_is_on_the_trusted_path(self):
        # #1650 R1/M2: gh is commonly installed under ~/.local/bin (pip --user,
        # a release tarball). Resolving only the four system directories made
        # `triage.py apply` and reconcile_apply refuse outright on the owner's
        # own workstation. It is still not PATH-controlled: both halves are
        # fixed strings over a HOME this process chose.
        # The system half is pinned to an EMPTY dir: CI runners ship a real
        # /usr/bin/gh, which would (correctly) win and turn this into a test
        # of the runner image.
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as empty:
            local_bin = os.path.join(home, ".local", "bin")
            os.makedirs(local_bin)
            self._make_fake_gh(local_bin, 'echo ok')
            with mock.patch.dict(os.environ, {"HOME": home}), \
                    mock.patch.object(triage, "TRUSTED_PATH", empty):
                self.assertEqual(os.path.join(local_bin, "gh"), triage.gh_bin())

    def test_the_operators_bin_dir_is_searched_after_the_system_ones(self):
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as system:
            local_bin = os.path.join(home, ".local", "bin")
            os.makedirs(local_bin)
            self._make_fake_gh(local_bin, 'echo local')
            self._make_fake_gh(system, 'echo system')
            with mock.patch.object(triage, "TRUSTED_PATH", system):
                self.assertEqual(os.path.join(system, "gh"), triage.gh_bin(home))

    def test_a_gh_only_on_the_ambient_path_is_still_not_resolved(self):
        # The whole point of M2's widening is that it must not widen to PATH.
        with tempfile.TemporaryDirectory() as home, \
                tempfile.TemporaryDirectory() as hostile, \
                tempfile.TemporaryDirectory() as empty:
            os.makedirs(os.path.join(home, ".local", "bin"))
            self._make_fake_gh(hostile, 'echo hostile')
            with mock.patch.dict(os.environ, {"HOME": home,
                                              "PATH": hostile + os.pathsep
                                              + os.environ.get("PATH", "")}), \
                    mock.patch.object(triage, "TRUSTED_PATH", empty):
                with self.assertRaises(RuntimeError):
                    triage.gh_bin()


class TestGhEnv(unittest.TestCase):
    """#486: config-declared gh account selection."""

    def test_config_field_sets_expanded_gh_config_dir(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "config.json")
            with open(cfg, "w") as fh:
                json.dump({"gh_config_dir": "~/gh-panopticon"}, fh)
            env = triage.gh_env(config_path=cfg)
        self.assertIsNotNone(env)
        self.assertEqual(env["GH_CONFIG_DIR"],
                         os.path.expanduser("~/gh-panopticon"))
        self.assertEqual(triage.trusted_path(env["HOME"]), env["PATH"])   # #1650, never ambient

    def _undeclared_configs(self):
        """Every way the config can decline to name a directory."""
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        paths = ["/nonexistent/c.json"]
        for name, body in (("no-field.json", {"other": 1}),
                           ("null-field.json", {"gh_config_dir": None})):
            path = os.path.join(d, name)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(body, fh)
            paths.append(path)
        return paths

    def test_an_undeclared_config_carries_no_config_dir_when_none_is_ambient(self):
        # #1650: no longer None-meaning-inherit. The env is always BUILT, so
        # PATH cannot pass through; GH_CONFIG_DIR is simply absent when nothing
        # names one.
        for path in self._undeclared_configs():
            with self.subTest(config=path):
                with mock.patch.dict(os.environ, {}, clear=False) as _env:
                    os.environ.pop("GH_CONFIG_DIR", None)
                    env = triage.gh_env(config_path=path)
                self.assertNotIn("GH_CONFIG_DIR", env)
                self.assertEqual(triage.trusted_path(env["HOME"]), env["PATH"])

    def test_an_undeclared_config_carries_the_ambient_config_dir_through(self):
        # R1/M3. The repo's own .panopticon/config.json holds
        # {"gh_config_dir": null}, so before the hardening an operator's
        # GH_CONFIG_DIR=~/.config/gh-psyberone reached gh by inheritance.
        # Building the env from scratch dropped it -- and gh with no
        # GH_CONFIG_DIR uses $HOME/.config/gh, the DEFAULT credential, which is
        # the wrong account for this project: the thebeamishsociety incident
        # #486 exists to prevent, reintroduced by the hardening meant to
        # protect it.
        for path in self._undeclared_configs():
            with self.subTest(config=path):
                with mock.patch.dict(os.environ,
                                     {"GH_CONFIG_DIR": "/tmp/ambient-gh-config"}):
                    env = triage.gh_env(config_path=path)
                self.assertEqual("/tmp/ambient-gh-config", env["GH_CONFIG_DIR"])

    def test_a_declared_config_dir_beats_an_ambient_one(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = os.path.join(d, "config.json")
            with open(cfg, "w", encoding="utf-8") as fh:
                json.dump({"gh_config_dir": d}, fh)
            with mock.patch.dict(os.environ,
                                 {"GH_CONFIG_DIR": "/tmp/ambient-gh-config"}):
                env = triage.gh_env(config_path=cfg)
        self.assertEqual(d, env["GH_CONFIG_DIR"])

    def test_default_runner_carries_declared_env(self):
        with tempfile.TemporaryDirectory() as trusted, tempfile.TemporaryDirectory() as d:
            with open(os.path.join(trusted, "gh"), "w", encoding="utf-8") as fh:
                fh.write("#!/bin/sh\necho ok\n")
            os.chmod(os.path.join(trusted, "gh"), 0o755)
            cfg = os.path.join(d, "config.json")
            with open(cfg, "w") as fh:
                json.dump({"gh_config_dir": d}, fh)
            with mock.patch.object(triage, "TRUSTED_PATH", trusted), \
                    mock.patch.object(triage, "CONFIG_PATH", cfg), \
                    mock.patch.object(triage.subprocess, "run") as m:
                m.return_value = mock.Mock(returncode=0, stdout="ok", stderr="")
                triage.gh(["gh", "api", "x"])
        self.assertEqual(m.call_args.kwargs["env"]["GH_CONFIG_DIR"], d)

    def test_injected_runner_bypasses_env_resolution(self):
        calls = []
        def fake(argv, capture_output, text):
            calls.append(argv)
            return mock.Mock(returncode=0, stdout="ok", stderr="")
        triage.gh(["gh", "api", "x"], runner=fake)
        self.assertEqual(len(calls), 1)     # signature unchanged for fakes


def test_gh_env_raises_on_corrupt_config(tmp_path):
    cfg = tmp_path / ".panopticon" / "config.json"
    cfg.parent.mkdir()
    cfg.write_text("{ not valid json")
    with pytest.raises(ValueError, match="corrupt"):
        triage.gh_env(str(cfg))


class TestCommentSanitization(unittest.TestCase):
    def test_comment_for_scrubs_and_defangs_rationale(self):
        root = sanitize.repo_root()
        row = fix_row(
            verdict="reject",
            rank=None,
            spot_check="advisor: checked",
            rationale="See %ssrc/x.py and ping @maintainer" % root)
        comment = triage.comment_for(row)
        self.assertNotIn(root, comment)
        self.assertIn("src/x.py", comment)
        self.assertNotIn("@maintainer", comment)


class TestLedgerFieldSanitization(unittest.TestCase):
    """comment_for() scrubbed `rationale` and `spot_check` but interpolated
    `fixed_by` and `batch` raw, and validate() checked `duplicate_of` only for
    truthiness. All three reach a PUBLIC GitHub comment.

    The two get different treatment on purpose: free text is scrubbed and
    defanged, while `duplicate_of` is pinned to an int -- an issue number cannot
    carry an injection, and validating it is what lets the #N cross-link stay
    LIVE. Defanging it would break the very link the comment exists to make."""

    def test_fixed_by_is_scrubbed_and_defanged(self):
        root = sanitize.repo_root()
        row = fix_row(verdict="already-fixed", rank=None, spot_check="checked",
                      fixed_by="%ssrc/x.py by @maintainer" % root)
        c = triage.comment_for(row)
        self.assertNotIn(root, c)
        self.assertNotIn("@maintainer", c)

    def test_a_secret_in_fixed_by_is_masked(self):
        secret = "ghp_" + "A" * 36
        row = fix_row(verdict="already-fixed", rank=None, spot_check="checked",
                      fixed_by="fixed in %s" % secret)
        self.assertNotIn(secret, triage.comment_for(row))

    def test_batch_is_scrubbed_and_defanged(self):
        row = fix_row(batch="B1 @everyone")
        self.assertNotIn("@everyone", triage.comment_for(row))

    def test_batch_is_sanitized_in_the_footer_too(self):
        row = fix_row(verdict="reject", rank=None, spot_check="checked",
                      batch="B1 @everyone")
        self.assertNotIn("@everyone", triage.comment_for(row))

    def test_duplicate_of_must_be_an_int(self):
        row = fix_row(verdict="duplicate", rank=None, status="approved",
                      duplicate_of="1 and something else")
        with self.assertRaises(ValueError) as e:
            triage.validate(row)
        self.assertIn("duplicate_of", str(e.exception))

    def test_a_valid_duplicate_of_keeps_a_live_issue_reference(self):
        row = fix_row(verdict="duplicate", rank=None, duplicate_of=1234)
        self.assertIn("#1234", triage.comment_for(row))

    def test_an_int_duplicate_of_passes_validation(self):
        row = fix_row(verdict="duplicate", rank=None, status="approved",
                      duplicate_of=1234)
        triage.validate(row)          # must not raise


class TestValidateTimestamp(unittest.TestCase):
    def test_valid_utc_iso8601_passes(self):
        self.assertIsNone(triage.validate(fix_row()))

    def test_invalid_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            triage.validate(fix_row(triaged_at="not-a-dateZ"))

    def test_missing_trailing_z_rejected(self):
        with self.assertRaises(ValueError):
            triage.validate(fix_row(triaged_at="2026-08-04T23:00:00"))


if __name__ == "__main__":
    unittest.main()


@pytest.mark.parametrize('config', [[], None, 42, 'token'])
def test_non_object_config_fails_closed(tmp_path, config):
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(config))
    with mock.patch.dict(os.environ, {'GH_TOKEN': 'ambient'}):
        with pytest.raises(ValueError, match='object'):
            triage.gh_env(path)


class DurableRunner:
    def __init__(self):
        self.calls = []
        self.comments = []
        self.labels = []
        self.closed = False
        self.permission = {'full_name': 'owner/project', 'permissions': {'admin': True}}
        self.fail = None
        self.accept = False
        self.probe = None
        self.newer = False
        self.hook = None

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        payload = {}
        if argv[1:3] == ['api', 'repos/owner/project']:
            payload = self.permission
        elif argv[1:3] == ['issue', 'view']:
            payload = {'state': 'CLOSED' if self.closed else 'OPEN',
                       'updatedAt': '2026-08-05T00:00:00Z' if self.comments or self.newer
                       else '2026-08-04T12:00:00Z',
                       'labels': [{'name': label} for label in self.labels],
                       'milestone': {'title': triage.MILESTONE},
                       'stateReason': 'NOT_PLANNED' if self.closed else None,
                       'title': 'title', 'body': 'body'}
        elif argv[1] == 'api' and '/comments' in argv[2]:
            payload = self.probe if self.probe is not None else [self.comments]
        elif argv[1:3] in (['issue', 'comment'], ['issue', 'edit'], ['issue', 'close']):
            operation = argv[2]
            if operation != self.fail or self.accept:
                if operation == 'comment':
                    self.comments.append({'body': argv[argv.index('--body') + 1]})
                elif operation == 'edit':
                    self.labels.append(argv[argv.index('--add-label') + 1])
                else:
                    self.closed = True
            if self.hook:
                self.hook()
            if operation == self.fail:
                raise triage.subprocess.TimeoutExpired(argv, 120)
        return mock.Mock(returncode=0, stdout=json.dumps(payload), stderr='')


def durable_apply(tmp_path, rows, runner, **kwargs):
    return triage.apply(rows, runner=runner, sleep=lambda _: None,
                        repo='owner/project', progress_path=tmp_path / 'progress.json', **kwargs)


def test_two_row_failure_persists_first_and_reconciles_second(tmp_path):
    first = fix_row(issue=443, rank=1, status='approved')
    second = fix_row(issue=444, rank=2, status='approved')
    ledger = tmp_path / 'ledger.jsonl'
    triage.save_rows([first, second], ledger)
    issues = {443: DurableRunner(), 444: DurableRunner()}
    issues[444].fail = 'edit'
    issues[444].accept = True
    calls = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if argv[1:3] == ['api', 'repos/owner/project']:
            return issues[443](argv, **kwargs)
        issue = next((number for number in issues if str(number) in argv
                      or any('/%s/' % number in part for part in argv)), None)
        assert issue is not None, argv
        return issues[issue](argv, **kwargs)

    with pytest.raises(RuntimeError, match='mutation pending'):
        durable_apply(tmp_path, [first, second], runner, ledger_path=ledger)
    saved = triage.load_rows(ledger)
    assert [row['status'] for row in saved] == ['applied', 'approved']
    progress = json.loads((tmp_path / 'progress.json').read_text())['rows']
    assert progress['443']['pending'] is None
    assert progress['444']['pending'] == 1
    assert len(issues[443].comments) == len(issues[444].comments) == 1
    public_first = [call for call in calls if call[1:3] in
                    (['issue', 'comment'], ['issue', 'edit']) and call[3] == '443']
    issues[444].fail = None
    assert durable_apply(tmp_path, saved, runner, ledger_path=ledger) == (1, 0)
    assert [row['status'] for row in triage.load_rows(ledger)] == ['applied', 'applied']
    assert len(issues[443].comments) == 1
    assert [call for call in calls if call[1:3] in
            (['issue', 'comment'], ['issue', 'edit']) and call[3] == '443'] == public_first


@pytest.mark.parametrize('permission', [{}, [], {'permissions': {'admin': False}},
    {'full_name': 'other/project', 'permissions': {'admin': True}},
    {'full_name': 'owner/project', 'permissions': {'admin': 'true'}}])
@pytest.mark.parametrize('entry', ['apply', 'setup'])
def test_preflight_refuses_wrong_or_malformed_permission(tmp_path, permission, entry):
    runner = DurableRunner()
    runner.permission = permission
    with pytest.raises((ValueError, RuntimeError)):
        if entry == 'apply':
            durable_apply(tmp_path, [fix_row(status='approved')], runner)
        else:
            triage.setup(runner=runner, repo='owner/project')
    assert len(runner.calls) == 1


def test_resume_partial_comment_without_stale_or_duplicate(tmp_path):
    runner = DurableRunner()
    runner.fail, runner.accept = 'edit', True
    row = fix_row(status='approved', verdict='reject', spot_check='confirmed')
    with pytest.raises(RuntimeError, match='pending|reconcil'):
        durable_apply(tmp_path, [row], runner)
    runner.fail = None
    assert durable_apply(tmp_path, [row], runner) == (1, 0)
    assert len(runner.comments) == 1
    assert row['status'] == 'applied'


def test_timeout_comment_reconciles_only_positive_complete_marker(tmp_path):
    runner = DurableRunner()
    runner.fail, runner.accept = 'comment', True
    row = fix_row(status='approved')
    with pytest.raises(RuntimeError, match='pending|reconcil'):
        durable_apply(tmp_path, [row], runner)
    runner.fail = None
    runner.probe = [[{'body': 'unrelated'}]]
    with pytest.raises(RuntimeError, match='pending|reconcil'):
        durable_apply(tmp_path, [row], runner)
    assert len(runner.comments) == 1
    runner.probe = None
    assert durable_apply(tmp_path, [row], runner) == (1, 0)
    assert len(runner.comments) == 1


def test_changed_row_cannot_adopt_pending_progress(tmp_path):
    runner = DurableRunner()
    runner.fail, runner.accept = 'comment', True
    row = fix_row(status='approved')
    with pytest.raises(RuntimeError):
        durable_apply(tmp_path, [row], runner)
    row['rationale'] = 'new approval'
    with pytest.raises(ValueError, match='mismatch|changed'):
        durable_apply(tmp_path, [row], runner)
    assert len(runner.comments) == 1


@pytest.mark.parametrize('body', ['null', '[]', '{broken', '{"version": 1}'])
def test_corrupt_progress_preserved(tmp_path, body):
    path = tmp_path / 'progress.json'
    path.write_text(body)
    runner = DurableRunner()
    with pytest.raises(ValueError):
        durable_apply(tmp_path, [fix_row(status='approved')], runner)
    assert path.read_text() == body
    assert not runner.comments


def test_durable_dry_run_writes_nothing(tmp_path):
    runner = DurableRunner()
    durable_apply(tmp_path, [fix_row(status='approved')], runner, dry=True)
    assert not runner.calls
    assert list(tmp_path.iterdir()) == []


def test_save_rows_merges_unrelated_change_and_refuses_same_row(tmp_path):
    path = tmp_path / 'ledger'
    original = [fix_row(status='approved'), fix_row(issue=444)]
    triage.save_rows(original, path)
    changed = [dict(row) for row in original]
    changed[1]['rationale'] = 'concurrent approval'
    path.write_text(''.join(json.dumps(row) + '\n' for row in changed))
    desired = [dict(original[0], status='applied'), original[1]]
    triage.save_rows(desired, path, expected=original)
    assert triage.load_rows(path)[1] == changed[1]
    before = path.read_bytes()
    with pytest.raises(ValueError, match='changed|conflict'):
        triage.save_rows(desired, path, expected=original)
    assert path.read_bytes() == before


@pytest.mark.parametrize('body', ['null\n', '[]\n', '{broken\n'])
def test_corrupt_ledger_never_overwritten(tmp_path, body):
    path = tmp_path / 'ledger'
    path.write_text(body)
    with pytest.raises(ValueError):
        triage.save_rows([fix_row()], path)
    assert path.read_text() == body


def test_all_commands_bind_explicit_target(tmp_path):
    runner = DurableRunner()
    assert durable_apply(tmp_path, [fix_row(status='approved')], runner) == (1, 0)
    assert runner.calls[0] == ['gh', 'api', 'repos/owner/project']
    for call in runner.calls:
        if call[1] in ('issue', 'label'):
            assert call[call.index('--repo') + 1] == 'owner/project'
        elif call[1] == 'api':
            assert call[2].startswith('repos/owner/project')
    body = runner.comments[0]['body']
    progress = json.loads((tmp_path / 'progress.json').read_text())
    identity = progress['rows']['443']['identity']
    assert body.endswith('<!-- panopticon-triage:' + identity + ' -->')


def test_setup_preflight_and_target_binding():
    calls = []
    def runner(argv, **kw):
        calls.append(argv)
        payload = {'full_name': 'owner/project', 'permissions': {'admin': True}}
        if 'repos/owner/project/milestones?state=all' in argv:
            payload = []
        return mock.Mock(returncode=0, stdout=json.dumps(payload), stderr='')
    triage.setup(runner=runner, repo='owner/project')
    assert calls[0] == ['gh', 'api', 'repos/owner/project']
    label_calls = [call for call in calls if call[1:3] == ['label', 'create']]
    assert label_calls == [
        ['gh', 'label', 'create', name, '--color', color, '--description', desc,
         '--force', '--repo', 'owner/project']
        for name, color, desc in triage.LABELS.values()
    ]
    assert [call for call in calls if call[1:4] == ['api', '-X', 'POST']] == [
        ['gh', 'api', '-X', 'POST', 'repos/owner/project/milestones',
         '-f', 'title=' + triage.MILESTONE,
         '-f', 'description=Ranked fix queue from the remediation triage arc — see ' + triage.SPEC]
    ]
    for command in calls[1:]:
        if command[1] == 'label':
            assert command[-2:] == ['--repo', 'owner/project']
        else:
            assert any(arg.startswith('repos/owner/project/milestones') for arg in command)
            assert not any('{owner}' in arg for arg in command)


def test_setup_existing_milestone_suppresses_post():
    calls = []
    def runner(argv, **kw):
        calls.append(argv)
        payload = ([triage.MILESTONE] if 'repos/owner/project/milestones?state=all' in argv
                   else {'full_name': 'owner/project', 'permissions': {'admin': True}})
        return mock.Mock(returncode=0, stdout=json.dumps(payload), stderr='')
    triage.setup(runner=runner, repo='owner/project')
    assert not any(call[1:4] == ['api', '-X', 'POST'] for call in calls)


@pytest.mark.parametrize('response', ['{}', 'null', '[1]', 'not-json'])
def test_setup_rejects_malformed_milestone_response(response):
    calls = []
    def runner(argv, **kw):
        calls.append(argv)
        payload = (response if 'repos/owner/project/milestones?state=all' in argv
                   else json.dumps({'full_name': 'owner/project',
                                    'permissions': {'admin': True}}))
        return mock.Mock(returncode=0, stdout=payload, stderr='')
    with pytest.raises((ValueError, json.JSONDecodeError)):
        triage.setup(runner=runner, repo='owner/project')
    assert not any(call[1:4] == ['api', '-X', 'POST'] for call in calls)


@pytest.mark.parametrize('value', [0, False, [], {}, ''])
def test_gh_env_rejects_declared_invalid_directory_before_command(tmp_path, value):
    path = tmp_path / 'config.json'
    path.write_text(json.dumps({'gh_config_dir': value}))
    with mock.patch.object(triage.subprocess, 'run') as run:
        with pytest.raises(ValueError, match='gh_config_dir'):
            triage.gh_env(config_path=path)
    run.assert_not_called()


@pytest.mark.parametrize('repo', ['x', '../repo', 'owner/../repo', 'owner/repo?x', 'owner/repo#x', '-x/repo'])
def test_invalid_repository_precedes_runner(tmp_path, repo):
    runner = DurableRunner()
    with pytest.raises(ValueError):
        triage.apply([fix_row(status='approved')], runner=runner, repo=repo,
                     progress_path=tmp_path / 'progress')
    assert runner.calls == []


def test_fresh_unrelated_update_is_stale(tmp_path):
    runner = DurableRunner()
    runner.newer = True
    row = fix_row(status='approved')
    assert durable_apply(tmp_path, [row], runner) == (0, 1)
    assert row['status'] == 'stale'
    assert not runner.comments
    assert not (tmp_path / 'progress.json').exists()


@pytest.mark.parametrize('change', ['comment', 'label', 'title', 'body'])
def test_resume_refuses_unrelated_remote_changes(tmp_path, change):
    runner = DurableRunner()
    runner.fail, runner.accept = 'edit', True
    row = fix_row(status='approved')
    with pytest.raises(RuntimeError):
        durable_apply(tmp_path, [row], runner)
    runner.fail = None
    if change == 'comment':
        runner.comments.append({'body': 'new unreviewed comment'})
    elif change == 'label':
        runner.labels.append('unreviewed')
    def altered(argv, **kwargs):
        result = runner(argv, **kwargs)
        if argv[1:3] == ['issue', 'view'] and change in ('title', 'body'):
            payload = json.loads(result.stdout)
            payload[change] = 'unreviewed'
            result.stdout = json.dumps(payload)
        return result
    before = len([c for c in runner.calls if c[1:3] == ['issue', 'edit']])
    with pytest.raises(RuntimeError, match='pending reconciliation'):
        durable_apply(tmp_path, [row], altered)
    assert len([c for c in runner.calls if c[1:3] == ['issue', 'edit']]) == before
    assert row['status'] == 'approved'


@pytest.mark.parametrize('probe', [[], {}, [[{'body': None}]], [[{'body': 'x'}], []]])
def test_incomplete_comment_probe_leaves_pending_bytes(tmp_path, probe):
    runner = DurableRunner()
    runner.fail, runner.accept = 'comment', True
    row = fix_row(status='approved')
    with pytest.raises(RuntimeError):
        durable_apply(tmp_path, [row], runner)
    before = (tmp_path / 'progress.json').read_bytes()
    runner.probe, runner.fail = probe, None
    with pytest.raises(RuntimeError, match='incomplete|pending'):
        durable_apply(tmp_path, [row], runner)
    assert (tmp_path / 'progress.json').read_bytes() == before
    assert len(runner.comments) == 1


def test_crash_after_acceptance_before_receipt_resumes(tmp_path, monkeypatch):
    runner = DurableRunner()
    row = fix_row(status='approved')
    persist = triage._persist_progress
    def crash(path, data):
        if data['rows']['443']['done'] == 1:
            raise OSError('simulated disk failure after remote acceptance')
        persist(path, data)
    with monkeypatch.context() as scoped:
        scoped.setattr(triage, '_persist_progress', crash)
        with pytest.raises(OSError):
            durable_apply(tmp_path, [row], runner)
    assert json.loads((tmp_path / 'progress.json').read_text())['rows']['443']['pending'] == 0
    assert durable_apply(tmp_path, [row], runner) == (1, 0)
    assert len(runner.comments) == 1


def test_persist_intent_failure_makes_zero_mutations(tmp_path, monkeypatch):
    runner = DurableRunner()
    def fail(*args):
        raise OSError('disk full')
    monkeypatch.setattr(triage, '_persist_progress', fail)
    with pytest.raises(OSError):
        durable_apply(tmp_path, [fix_row(status='approved')], runner)
    assert not runner.comments


def test_acknowledged_comment_survives_next_step_intent_failure(tmp_path, monkeypatch):
    runner = DurableRunner()
    row = fix_row(status='approved')
    persist = triage._persist_progress
    def fail(path, data):
        if data['rows']['443']['pending'] == 1:
            raise OSError('disk full before label')
        persist(path, data)
    with monkeypatch.context() as scoped:
        scoped.setattr(triage, '_persist_progress', fail)
        with pytest.raises(OSError):
            durable_apply(tmp_path, [row], runner)
    assert durable_apply(tmp_path, [row], runner) == (1, 0)
    assert len(runner.comments) == 1


@pytest.mark.parametrize('same_row', [False, True])
def test_apply_preserves_concurrent_ledger_edits(tmp_path, same_row):
    runner = DurableRunner()
    path = tmp_path / 'ledger'
    row = fix_row(status='approved')
    triage.save_rows([row], path)
    def concurrent_edit():
        current = triage.load_rows(path)
        current.append(fix_row(issue=444, rationale='new concurrent row'))
        if same_row:
            current[0]['rationale'] = 'newer approval'
        path.write_text(''.join(json.dumps(r) + '\n' for r in current))
        runner.hook = None
    runner.hook = concurrent_edit
    if same_row:
        with pytest.raises(ValueError, match='conflict'):
            durable_apply(tmp_path, [row], runner, ledger_path=path)
        assert triage.load_rows(path)[0]['rationale'] == 'newer approval'
        assert not runner.labels
    else:
        assert durable_apply(tmp_path, [row], runner, ledger_path=path) == (1, 0)
        assert triage.load_rows(path)[0]['status'] == 'applied'
    assert triage.load_rows(path)[1]['rationale'] == 'new concurrent row'


def test_pending_target_mismatch_and_plan_tamper_preserve_evidence(tmp_path):
    runner = DurableRunner()
    runner.fail, runner.accept = 'comment', True
    row = fix_row(status='approved')
    with pytest.raises(RuntimeError):
        durable_apply(tmp_path, [row], runner)
    path = tmp_path / 'progress.json'
    state = json.loads(path.read_text())
    for mutate in (lambda x: x.update(repo='wrong/repo'),
                   lambda x: x['rows']['443']['binding']['steps'][0].append('--bad')):
        changed = json.loads(json.dumps(state))
        mutate(changed)
        path.write_text(json.dumps(changed))
        before = path.read_bytes()
        with pytest.raises(ValueError, match='mismatch|corrupt'):
            durable_apply(tmp_path, [row], runner)
        assert path.read_bytes() == before
    assert len(runner.comments) == 1


def test_nonzero_mutation_is_not_retried(tmp_path):
    runner = DurableRunner()
    def failed(argv, **kwargs):
        if argv[1:3] == ['issue', 'edit']:
            return mock.Mock(returncode=1, stdout='', stderr='connection reset')
        return runner(argv, **kwargs)
    row = fix_row(status='approved')
    with pytest.raises(RuntimeError, match='pending'):
        durable_apply(tmp_path, [row], failed)
    with pytest.raises(RuntimeError, match='pending'):
        durable_apply(tmp_path, [row], runner)
    assert len(runner.comments) == 1
    assert runner.labels == []


def test_close_timeout_after_acceptance_is_reconciled(tmp_path):
    runner = DurableRunner()
    runner.fail, runner.accept = 'close', True
    row = fix_row(status='approved', verdict='reject', spot_check='confirmed')
    with pytest.raises(RuntimeError, match='pending'):
        durable_apply(tmp_path, [row], runner)
    runner.fail = None
    assert durable_apply(tmp_path, [row], runner) == (1, 0)
    assert len([c for c in runner.calls if c[1:3] == ['issue', 'close']]) == 1
    assert len(runner.comments) == 1


def test_acknowledged_step_does_not_hide_later_timestamp_only_change(tmp_path, monkeypatch):
    runner = DurableRunner()
    row = fix_row(status='approved')
    persist = triage._persist_progress
    def fail(path, data):
        if data['rows']['443']['pending'] == 1:
            raise OSError('simulated crash')
        persist(path, data)
    with monkeypatch.context() as scoped:
        scoped.setattr(triage, '_persist_progress', fail)
        with pytest.raises(OSError):
            durable_apply(tmp_path, [row], runner)
    def unrelated(argv, **kwargs):
        result = runner(argv, **kwargs)
        if argv[1:3] == ['issue', 'view']:
            payload = json.loads(result.stdout)
            payload['updatedAt'] = '2026-08-06T00:00:00Z'
            result.stdout = json.dumps(payload)
        return result
    with pytest.raises(RuntimeError, match='pending reconciliation'):
        durable_apply(tmp_path, [row], unrelated)
    assert runner.labels == []


@pytest.mark.parametrize('duplicate', [False, True])
def test_marker_alone_or_multiple_matches_cannot_be_adopted(tmp_path, duplicate):
    runner = DurableRunner()
    runner.fail, runner.accept = 'comment', True
    row = fix_row(status='approved')
    with pytest.raises(RuntimeError):
        durable_apply(tmp_path, [row], runner)
    if duplicate:
        runner.comments.append(dict(runner.comments[0]))
    else:
        runner.comments[0]['body'] = 'different content\n' + runner.comments[0]['body'].split('\n')[-1]
    runner.fail = None
    with pytest.raises(RuntimeError, match='pending'):
        durable_apply(tmp_path, [row], runner)
    assert not runner.labels


def test_progress_size_limit_preserves_bytes(tmp_path, monkeypatch):
    path = tmp_path / 'progress.json'
    path.write_text(' ' * 1025)
    monkeypatch.setattr(triage, 'MAX_STATE_BYTES', 1024)
    with pytest.raises(ValueError, match='too large'):
        durable_apply(tmp_path, [fix_row(status='approved')], DurableRunner())
    assert path.read_text() == ' ' * 1025


def test_unreadable_existing_ledger_is_not_empty(tmp_path, monkeypatch):
    path = tmp_path / 'ledger'
    path.write_text(json.dumps(fix_row()) + '\n')
    real_open = open
    def unreadable(file, *args, **kwargs):
        if os.fspath(file) == os.fspath(path):
            raise PermissionError('denied')
        return real_open(file, *args, **kwargs)
    with monkeypatch.context() as scoped:
        scoped.setattr('builtins.open', unreadable)
        with pytest.raises(ValueError, match='unreadable'):
            triage.save_rows([fix_row(status='applied')], path)
    assert json.loads(path.read_text())['status'] == 'proposed'


def test_cli_target_is_forwarded_and_dry_run_preserves_ledger(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    path = tmp_path / '.panopticon' / 'triage-ledger.jsonl'
    path.parent.mkdir()
    path.write_text(json.dumps(fix_row(status='approved')) + '\n')
    before = path.read_bytes()
    with mock.patch.object(triage, 'apply', wraps=triage.apply) as apply_call:
        monkeypatch.setattr(triage.sys, 'argv', ['triage.py', 'apply', '--dry-run', '--repo', 'owner/project'])
        triage.main()
    assert apply_call.call_args.kwargs['repo'] == 'owner/project'
    assert path.read_bytes() == before
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize('timestamp', ['', '0', '2026-02-30T12:00:00Z',
    '2026-08-04', '2026-08-04T12:00:00', '2026-08-04T12:00:00+00:00',
    '2026-08-04 12:00:00Z', '2026-08-04T25:00:00Z'])
@pytest.mark.parametrize('resume', [False, True])
def test_invalid_remote_freshness_preserves_approval_and_evidence(tmp_path, timestamp, resume):
    runner = DurableRunner()
    row = fix_row(status='approved')
    ledger = tmp_path / 'ledger'
    progress = tmp_path / 'progress.json'
    triage.save_rows([row], ledger)
    if resume:
        runner.fail, runner.accept = 'comment', True
        with pytest.raises(RuntimeError, match='pending'):
            durable_apply(tmp_path, [row], runner, ledger_path=ledger)
        runner.fail = None
    else:
        progress.write_text(json.dumps({'version': 1, 'repo': 'owner/project', 'rows': {}}))
    before = {path: path.read_bytes() for path in (ledger, progress)}
    runner.calls.clear()
    def malformed(argv, **kwargs):
        result = runner(argv, **kwargs)
        if argv[1:3] == ['issue', 'view']:
            payload = json.loads(result.stdout)
            payload['updatedAt'] = timestamp
            result.stdout = json.dumps(payload)
        return result
    with pytest.raises(RuntimeError, match='incomplete|reconciliation'):
        durable_apply(tmp_path, [row], malformed, ledger_path=ledger)
    assert row['status'] == 'approved'
    assert {path: path.read_bytes() for path in before} == before
    assert not any(call[1:3] in (['issue', 'comment'], ['issue', 'edit'], ['issue', 'close'])
                   for call in runner.calls)


@pytest.mark.parametrize(('timestamp', 'expected'), [
    ('2026-08-04T22:59:59Z', (1, 0)),
    ('2026-08-04T23:00:00Z', (1, 0)),
    ('2026-08-04T22:59:59.999999Z', (1, 0)),
    ('2026-08-04T23:00:00.000001Z', (0, 1)),
    ('2026-08-04T23:00:01Z', (0, 1)),
])
def test_valid_remote_freshness_compares_instants(tmp_path, timestamp, expected):
    runner = DurableRunner()
    def timed(argv, **kwargs):
        result = runner(argv, **kwargs)
        if argv[1:3] == ['issue', 'view']:
            payload = json.loads(result.stdout)
            payload['updatedAt'] = timestamp
            result.stdout = json.dumps(payload)
        return result
    row = fix_row(status='approved')
    assert durable_apply(tmp_path, [row], timed) == expected
    assert len(runner.comments) == expected[0]


class TestStandaloneImports(unittest.TestCase):
    def test_help_without_site_packages_from_unrelated_cwd(self):
        script = Path(triage.__file__).resolve()
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ)
            env.pop("PYTHONPATH", None)
            result = subprocess.run(
                [sys.executable, "-S", str(script), "--help"],
                cwd=directory, env=env, capture_output=True, text=True, timeout=15,
                check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage:", result.stdout)
            self.assertIn("apply", result.stdout)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_config_path_preserves_the_legacy_value(self):
        self.assertEqual(triage.CONFIG_PATH, os.path.join(".panopticon", "config.json"))
