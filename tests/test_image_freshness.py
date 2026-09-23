import datetime
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml

from conftest import REPO_ROOT   # #run7 TST-G1B: shared path anchor

SCRIPT = os.path.join(REPO_ROOT, ".github", "scripts", "image-freshness.sh")
WORKFLOW = os.path.join(REPO_ROOT, ".github", "workflows", "tools-image-health.yml")


class TestImageFreshness(unittest.TestCase):
    def _run(self, updated_at, max_age_days):
        return subprocess.run(
            ["bash", SCRIPT, updated_at, str(max_age_days)],
            capture_output=True, text=True, timeout=30)   # #run7 TST-G3B: bound the shell-out

    def test_fresh_image_emits_ok(self):
        recent = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).isoformat()
        proc = self._run(recent, 3)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("fresh", proc.stdout.lower())
        self.assertNotIn("::error::", proc.stdout)
        self.assertIn("::notice::", proc.stdout)
        self.assertNotIn("::warning::", proc.stdout)

    def test_stale_image_emits_error(self):
        old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).isoformat()
        proc = self._run(old, 3)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("::error::", proc.stdout)
        self.assertIn("old", proc.stdout.lower())
        self.assertNotIn("::notice::", proc.stdout)

    def test_empty_updated_at_emits_warning(self):
        proc = self._run("", 3)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("::warning::", proc.stdout)
        self.assertNotIn("::notice::", proc.stdout)
        self.assertNotIn("::error::", proc.stdout)

    def test_invalid_timestamp_emits_error(self):
        proc = self._run("not-a-date", 3)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("::error::", proc.stdout)
        self.assertNotIn("::notice::", proc.stdout)

    def test_zero_age_limit_accepts_current_publish_time(self):
        proc = self._run(datetime.datetime.now(datetime.timezone.utc).isoformat(), "0")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("::notice::", proc.stdout)

    def test_leading_zero_limit_is_decimal(self):
        old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).isoformat()
        proc = self._run(old, "08")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("::error::", proc.stdout)
        self.assertIn("old", proc.stdout.lower())

    def test_invalid_age_limits_fail_even_without_publish_time(self):
        old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).isoformat()
        for limit in ("", "abc", "-1", "+1", "1.5", " 3", "3 ",
                      "9223372036854775808", "999999999999999999999999999"):
            for timestamp in ("", old):
                with self.subTest(limit=limit, timestamp=timestamp):
                    proc = self._run(timestamp, limit)
                    self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
                    self.assertIn("::error::", proc.stdout)
                    self.assertIn("maximum age", proc.stdout.lower())
                    self.assertNotIn("::warning::", proc.stdout)
                    self.assertNotIn("::notice::", proc.stdout)

    def test_age_limit_can_have_many_leading_zeroes(self):
        recent = datetime.datetime.now(datetime.timezone.utc).isoformat()
        proc = self._run(recent, "0" * 40 + "3")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("::notice::", proc.stdout)


class TestFreshnessWorkflow(unittest.TestCase):
    def setUp(self):
        with open(WORKFLOW, encoding="utf-8") as fh:
            self.job = yaml.safe_load(fh)["jobs"]["freshness"]

    def test_checkout_precedes_every_script_call_with_least_privilege(self):
        self.assertEqual({"contents": "read", "packages": "read"},
                         self.job["permissions"])
        steps = self.job["steps"]
        script_steps = [i for i, step in enumerate(steps)
                        if "image-freshness.sh" in step.get("run", "")]
        self.assertTrue(script_steps)
        for index in script_steps:
            checkouts = [step for step in steps[:index]
                         if step.get("uses", "").startswith("actions/checkout@")]
            self.assertTrue(checkouts, "script runs before checkout")
            checkout = checkouts[-1]
            self.assertRegex(checkout["uses"], r"^actions/checkout@[0-9a-f]{40}$")
            self.assertIs(checkout["with"]["persist-credentials"], False)
            self.assertIn(".github/scripts", checkout["with"]["sparse-checkout"])

    def _run_with_fake_gh(self, gh_body, max_age_days="3"):
        run = next(step["run"] for step in self.job["steps"]
                   if "image-freshness.sh" in step.get("run", ""))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / ".github" / "scripts" / "image-freshness.sh"
            script.parent.mkdir(parents=True)
            script.write_bytes(Path(SCRIPT).read_bytes())
            script.chmod(0o755)
            fake_gh = root / "gh"
            fake_gh.write_text("#!/bin/sh\n" + gh_body)
            fake_gh.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}",
                       MAX_AGE_DAYS=max_age_days, IMAGE_NAME="panopticon-tools",
                       OWNER="example", GH_TOKEN="unused")
            return subprocess.run(["bash", "-c", run], cwd=root, env=env,
                                  capture_output=True, text=True, timeout=30)

    def test_gh_failure_reports_diagnostic_and_skips_as_warning(self):
        proc = self._run_with_fake_gh(
            "printf 'lookup denied: token unavailable\\n::error::injected\\n' >&2\nexit 42\n")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("gh api diagnostic:", proc.stderr)
        self.assertIn("lookup", proc.stderr)
        self.assertIn("unavailable", proc.stderr)
        self.assertNotIn("\n::error::", proc.stderr)
        self.assertIn("::warning::", proc.stdout)
        self.assertIn("Failed to look up", proc.stdout)
        self.assertNotIn("::notice::", proc.stdout)

    def test_missing_latest_timestamp_has_distinct_warning(self):
        proc = self._run_with_fake_gh("printf '[]\\n'\n")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("::warning::Could not determine", proc.stdout)
        self.assertNotIn("Failed to look up", proc.stdout)
        self.assertNotIn("::notice::", proc.stdout)

    def test_gh_failure_does_not_hide_invalid_age_limit(self):
        proc = self._run_with_fake_gh("exit 42\n", max_age_days="")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("::error::Invalid maximum age", proc.stdout)
        self.assertNotIn("::notice::", proc.stdout)
