import os
import subprocess
import tempfile
import unittest

from conftest import REPO_ROOT

SCRIPT = os.path.join(REPO_ROOT, ".github", "scripts", "nvd-cache-decision.sh")


def _run_decision(event_name, tag, docker_rc=0):
    """Run the decision script with a mock `docker` in PATH."""
    with tempfile.TemporaryDirectory() as tmp:
        docker_path = os.path.join(tmp, "docker")
        with open(docker_path, "w", encoding="utf-8") as f:
            f.write(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"manifest\" ] && [ \"$2\" = \"inspect\" ]; then\n"
                "    exit %d\n"
                "fi\n"
                "exit 127\n" % docker_rc
            )
        os.chmod(docker_path, 0o755)
        env = {**os.environ, "PATH": tmp + os.pathsep + os.environ.get("PATH", "")}
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
        return proc.stdout.strip()


class TestNvdCacheDecision(unittest.TestCase):
    def test_non_push_event_syncs(self):
        result = _run_decision("schedule", "ghcr.io/example/repo-tools-nvd:dc-9.0.0")
        self.assertEqual(result, "sync=true")

    def test_push_with_existing_tag_skips(self):
        result = _run_decision(
            "push", "ghcr.io/example/repo-tools-nvd:dc-9.0.0", docker_rc=0
        )
        self.assertEqual(result, "sync=false")

    def test_push_with_missing_tag_syncs(self):
        result = _run_decision(
            "push", "ghcr.io/example/repo-tools-nvd:dc-9.0.0", docker_rc=1
        )
        self.assertEqual(result, "sync=true")


if __name__ == "__main__":
    unittest.main()
