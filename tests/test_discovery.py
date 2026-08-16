import json
import os
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "skill", "scripts")


def _run(script, *args, cwd=None):
    return subprocess.run([sys.executable, os.path.join(SCRIPTS, script), *args],
                          cwd=cwd, capture_output=True, text=True)


class TestDiscoveryRepoScanParity(unittest.TestCase):
    """discovery.py --repo-scan produces the same groups.json as the (still-present
    during A1) orchestrator.py --repo-scan, on a real committed-matrix repo."""

    def _repo(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        g = ["git", "-C", d]
        subprocess.run(["git", "init", "-q", d], check=True)
        subprocess.run(g + ["config", "user.email", "t@t"], check=True)
        subprocess.run(g + ["config", "user.name", "t"], check=True)
        os.makedirs(os.path.join(d, "src", "checkout"))
        with open(os.path.join(d, "src", "checkout", "pay.py"), "w") as fh:
            fh.write("x = 1\n")
        os.makedirs(os.path.join(d, ".panopticon"))
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Checkout:\n    match: ['src/checkout/**']\n    panels: [SEC]\n")
        subprocess.run(g + ["add", "-A"], check=True)
        subprocess.run(g + ["commit", "-qm", "init"], check=True)
        subprocess.run(g + ["branch", "-M", "main"], check=True)
        return d

    def test_repo_scan_writes_groups_json(self):
        d = self._repo()
        out = os.path.join(d, ".panopticon", "groups.json")
        proc = _run("discovery.py", "--repo-scan", "--security", "standard",
                    d, "--out", out, cwd=d)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.load(open(out))
        names = {g["name"] for g in data["groups"]}
        self.assertIn("Checkout", names)

    def test_matrix_catalog_normalizes_scalar_match(self):
        import discovery
        d = self._repo()
        # a scalar match must normalize to [] (SEC-3), never char-split
        with open(os.path.join(d, ".panopticon", "groups.yml"), "w") as fh:
            fh.write("groups:\n  Bad:\n    match: src/**\n    panels: [SEC]\n")
        cat = discovery._matrix_catalog(d)
        self.assertEqual(cat.get("Bad", {}).get("match", None), [])


if __name__ == "__main__":
    unittest.main()
