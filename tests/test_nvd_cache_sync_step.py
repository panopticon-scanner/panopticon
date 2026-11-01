"""#3224: the keyed NVD sync step verifies the DependencyCheck zip FAIL-CLOSED.

The step ran under `set -uo pipefail` -- no `-e`, so that the sync's status
could be captured -- which meant a failed download or a `sha256sum -c`
mismatch did not stop it: the unverified zip was unpacked and its
`dependency-check.sh` run with `NVD_API_KEY` in the environment, after the
GHCR login had written a `packages: write` token to the runner. The pinned
digest checked nothing.

These tests run the step's real `run:` script with stub commands first on
PATH, so they pin what the shell DOES, not how the script is spelled.
"""
import os
import subprocess
import tempfile
import unittest

import yaml

from tests._test_helpers import REPO_ROOT

WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "nvd-cache.yml")
STEP = "Sync NVD database (keyed)"


def _sync_script():
    with open(WORKFLOW, encoding="utf-8") as fh:
        wf = yaml.safe_load(fh)
    for job in wf["jobs"].values():
        for step in job.get("steps", []):
            if step.get("name") == STEP:
                return step["run"]
    raise AssertionError("no %r step in nvd-cache.yml" % STEP)


def _run(curl_rc=0, sha_rc=0, sync_rc=0, db_row=None, java_rc=0, age_seconds=0, bad_date=False):
    """(returncode, output, launched): the step run with stubbed tools.
    `launched` is True when the step reached the dependency-check launch.

    The stubs are shell FUNCTIONS, which bash resolves before PATH, not
    executables written to disk: a stub written and exec'd at once can fail
    with ETXTBSY on Linux when a sibling process forks in between.

    `db_row` makes the sync leave a database over the size floor, whose
    last-modified row reads as that text ("" for no row)."""
    with tempfile.TemporaryDirectory() as tmp:
        marker = os.path.join(tmp, "launched")
        stubs = ("sudo() { return 0; }\n"
                 "curl() { : > dc.zip; return %d; }\n"
                 # Drain stdin as the real one does: a stub that returns
                 # unread can SIGPIPE the `echo` feeding it, which `pipefail`
                 # and `-e` turn into a silent exit before the launch.
                 "sha256sum() { cat > /dev/null; return %d; }\n"
                 "unzip() { return 0; }\n"
                 "timeout() { : > '%s'; return %d; }\n"
                 % (curl_rc, sha_rc, marker, sync_rc))
        if db_row is not None:
            now = 1800000000
            row = "nvd.api.last.modified | %s\\n" % db_row if db_row else ""
            stubs += ("timeout() { : > '%s'; : > odc-data/odc.mv.db; return %d; }\n"
                      "stat() { echo 104857601; }\n"
                      "java() { printf 'ID | VALUE\\n%s'; return %d; }\n"
                      "date() { if [ \"$2\" = -d ]; then %s; else echo %d; fi; }\n"
                      % (marker, sync_rc, row, java_rc,
                         "return 1" if bad_date else "echo %d" % (now - age_seconds), now))
        env = {"PATH": os.environ.get("PATH", ""), "HOME": tmp,
               "DC_VERSION": "12.1.0", "DC_SHA256": "0" * 64}
        # The script goes in on stdin: a fixed argv, and the same bash parse.
        proc = subprocess.run(["bash"], input=stubs + _sync_script(), cwd=tmp, env=env,
                              capture_output=True, text=True, timeout=60)
        return proc.returncode, proc.stdout + proc.stderr, os.path.exists(marker)


class TestTheKeyedSyncVerifiesFailClosed(unittest.TestCase):
    def test_a_digest_mismatch_stops_the_step_before_the_launch(self):
        rc, out, launched = _run(sha_rc=1)
        self.assertNotEqual(rc, 0, out)
        self.assertFalse(launched, "an unverified zip reached dependency-check.sh")

    def test_a_failed_download_stops_the_step_before_the_launch(self):
        rc, out, launched = _run(curl_rc=22)
        self.assertNotEqual(rc, 0, out)
        self.assertFalse(launched, "a failed download reached dependency-check.sh")

    def test_a_tolerated_sync_status_still_reaches_the_db_check(self):
        # `set -e` must not swallow the #2508 status capture: a per-record
        # error (rc 1) is tolerated and the DB is verified -- and here there
        # is none, so the step fails THERE, by name.
        rc, out, launched = _run(sync_rc=1)
        self.assertTrue(launched, out)
        self.assertNotEqual(rc, 0)
        self.assertIn("per-record errors are tolerated", out)
        self.assertIn("odc.mv.db) was not produced", out)

    def test_a_killed_sync_still_fails_by_its_own_message(self):
        rc, out, launched = _run(sync_rc=124)
        self.assertTrue(launched, out)
        self.assertNotEqual(rc, 0)
        self.assertIn("killed by the 3000 s deadline", out)


class TestTheStepRefusesAnUnfinishedOrStaleDatabase(unittest.TestCase):
    """#3251: a database over the size floor was published on size alone."""

    HOUR = 3600

    def test_a_failed_sync_leaving_no_timestamp_is_not_published(self):
        rc, out, _ = _run(sync_rc=1, db_row="")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("the update did not finish", out)

    def test_a_failed_sync_leaving_a_stale_database_is_not_published(self):
        rc, out, _ = _run(sync_rc=1, db_row="2026-01-01T00:00:00Z", age_seconds=73 * self.HOUR)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("73 h old (limit 72)", out)

    def test_a_clean_exit_does_not_excuse_a_stale_database(self):
        rc, out, _ = _run(sync_rc=0, db_row="2026-01-01T00:00:00Z", age_seconds=73 * self.HOUR)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("not publishing stale data", out)

    def test_a_database_at_the_limit_passes(self):
        rc, out, _ = _run(sync_rc=0, db_row="2026-01-01T00:00:00Z", age_seconds=72 * self.HOUR)
        self.assertEqual(rc, 0, out)
        self.assertIn("(72 h old)", out)

    def test_a_tolerated_sync_status_with_a_fresh_database_passes(self):
        # #2508 still holds: per-record errors don't fail a sync that finished.
        rc, out, _ = _run(sync_rc=1, db_row="2026-01-01T00:00:00Z", age_seconds=self.HOUR)
        self.assertEqual(rc, 0, out)
        self.assertIn("per-record errors are tolerated", out)

    def test_an_unreadable_database_fails_by_name(self):
        rc, out, _ = _run(db_row="2026-01-01T00:00:00Z", java_rc=1)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("could not read nvd.api.last.modified", out)

    def test_a_value_that_is_not_a_timestamp_fails_by_name(self):
        rc, out, _ = _run(db_row="soon", bad_date=True)
        self.assertNotEqual(rc, 0, out)
        self.assertIn("is not a timestamp: soon", out)


if __name__ == "__main__":
    unittest.main()
