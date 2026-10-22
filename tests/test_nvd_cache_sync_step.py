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


def _run(curl_rc=0, sha_rc=0, sync_rc=0):
    """(returncode, output, launched): the step run with stubbed tools.
    `launched` is True when the step reached the dependency-check launch.

    The stubs are shell FUNCTIONS, which bash resolves before PATH, not
    executables written to disk: a stub written and exec'd at once can fail
    with ETXTBSY on Linux when a sibling process forks in between."""
    with tempfile.TemporaryDirectory() as tmp:
        marker = os.path.join(tmp, "launched")
        stubs = ("sudo() { return 0; }\n"
                 "curl() { : > dc.zip; return %d; }\n"
                 "sha256sum() { return %d; }\n"
                 "unzip() { return 0; }\n"
                 "timeout() { : > '%s'; return %d; }\n"
                 % (curl_rc, sha_rc, marker, sync_rc))
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


if __name__ == "__main__":
    unittest.main()
