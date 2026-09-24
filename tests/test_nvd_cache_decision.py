import os
import subprocess
import tempfile
import unittest

from conftest import REPO_ROOT

SCRIPT = os.path.join(REPO_ROOT, ".github", "scripts", "nvd-cache-decision.sh")


TAG = "ghcr.io/example/repo-tools-nvd:dc-9.0.0"


def _run_decision(event_name, tag, docker_rc=0, expected_tag=TAG):
    """Run the decision script with a mock `docker` in PATH."""
    with tempfile.TemporaryDirectory() as tmp:
        docker_path = os.path.join(tmp, "docker")
        calls_path = os.path.join(tmp, "docker-calls")
        with open(docker_path, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$DOCKER_CALLS\"\n"
                "if [ \"$#\" -eq 3 ] && [ \"$1\" = manifest ] && "
                "[ \"$2\" = inspect ] && [ \"$3\" = \"$EXPECTED_TAG\" ]; then\n"
                "    exit \"$DOCKER_RC\"\n"
                "fi\n"
                "exit 127\n"
            )
        os.chmod(docker_path, 0o755)
        env = {**os.environ, "PATH": tmp + os.pathsep + os.environ.get("PATH", ""),
               "DOCKER_CALLS": calls_path, "EXPECTED_TAG": expected_tag,
               "DOCKER_RC": str(docker_rc)}
        proc = subprocess.run(
            ["bash", SCRIPT, event_name, tag],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(
                "nvd-cache-decision.sh failed (rc=%d): %s" % (proc.returncode, proc.stderr)
            )
        calls = []
        if os.path.exists(calls_path):
            with open(calls_path, encoding="utf-8") as f:
                calls = f.read().splitlines()
        return proc.stdout.strip(), calls


class TestNvdCacheDecision(unittest.TestCase):
    def test_non_push_event_syncs(self):
        result, calls = _run_decision("schedule", TAG)
        self.assertEqual(result, "sync=true")
        self.assertEqual(calls, [])

    def test_push_with_existing_tag_skips(self):
        result, calls = _run_decision("push", TAG, docker_rc=0)
        self.assertEqual(result, "sync=false")
        self.assertEqual(calls, ["manifest inspect " + TAG])

    def test_push_with_missing_tag_syncs(self):
        result, calls = _run_decision("push", TAG, docker_rc=1)
        self.assertEqual(result, "sync=true")
        self.assertEqual(calls, ["manifest inspect " + TAG])

    def test_nearby_wrong_tag_does_not_count_as_existing(self):
        wrong = "ghcr.io/example/repo-tools-nvd:dc-9.0.1"
        result, calls = _run_decision("push", wrong, expected_tag=TAG)
        self.assertEqual(result, "sync=true")
        self.assertEqual(calls, ["manifest inspect " + wrong])


if __name__ == "__main__":
    unittest.main()
