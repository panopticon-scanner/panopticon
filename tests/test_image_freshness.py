import datetime
import os
import subprocess
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, ".github", "scripts", "image-freshness.sh")


class TestImageFreshness(unittest.TestCase):
    def _run(self, updated_at, max_age_days):
        return subprocess.run(
            ["bash", SCRIPT, updated_at, str(max_age_days)],
            capture_output=True, text=True)

    def test_fresh_image_emits_ok(self):
        recent = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).isoformat()
        proc = self._run(recent, 3)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("fresh", proc.stdout.lower())
        self.assertNotIn("::error::", proc.stdout)

    def test_stale_image_emits_error(self):
        old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).isoformat()
        proc = self._run(old, 3)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("::error::", proc.stdout)
        self.assertIn("old", proc.stdout.lower())

    def test_empty_updated_at_emits_warning(self):
        proc = self._run("", 3)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("::warning::", proc.stdout)

    def test_invalid_timestamp_emits_error(self):
        proc = self._run("not-a-date", 3)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("::error::", proc.stdout)
